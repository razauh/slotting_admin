package com.slotting.admin.gameprovider

import org.springframework.stereotype.Component
import java.math.BigDecimal
import java.math.RoundingMode
import java.nio.charset.StandardCharsets
import java.security.MessageDigest

/**
 * Independent verifier that can be used by internal systems, third-party auditors,
 * regulatory bodies, or public verification tools to independently validate round fairness.
 *
 * Implements Spribe Aviator 3-Client-Seed Provably Fair consensus verification.
 */
@Component
class IndependentFairnessVerifier(
    private val store: FairnessEvidenceStore? = null,
) {
    /**
     * Standalone, dependency-free verification method accepting
     * (serverSeed, clientSeed1, clientSeed2, clientSeed3) and returning
     * the exact crash multiplier down to 2 decimal places.
     */
    fun verify(
        serverSeed: String,
        clientSeed1: String,
        clientSeed2: String,
        clientSeed3: String,
    ): BigDecimal {
        return AviatorAlgorithmRegistry.compute(
            algorithmVersion = AviatorAlgorithmRegistry.VERSION_1_0_0,
            serverSeed = serverSeed,
            clientSeed1 = clientSeed1,
            clientSeed2 = clientSeed2,
            clientSeed3 = clientSeed3,
        )
    }

    /**
     * Standalone verification alias matching Spribe outcome verification contract.
     */
    fun verifyOutcome(
        serverSeed: String,
        clientSeed1: String,
        clientSeed2: String,
        clientSeed3: String,
    ): BigDecimal {
        return AviatorAlgorithmRegistry.compute(
            algorithmVersion = AviatorAlgorithmRegistry.VERSION_1_0_0,
            serverSeed = serverSeed,
            clientSeed1 = clientSeed1,
            clientSeed2 = clientSeed2,
            clientSeed3 = clientSeed3,
        )
    }

    fun verifyHistoricalRound(query: VerifyHistoricalRoundQuery): HistoricalVerificationResult {
        ProvablyFairOutcomeBinding.checkBound()
        val evidenceStore = store ?: throw IllegalStateException("FairnessEvidenceStore is required for historical round verification")

        val commitment = evidenceStore.findCommitment(query.tenantId, query.gameId, query.roundId)
            ?: return HistoricalVerificationResult(
                isVerified = false,
                roundId = query.roundId,
                commitmentHash = null,
                revealedSecretSeed = null,
                publicSalt = null,
                derivedMultiplier = null,
                algorithmVersion = null,
                rulesVersion = null,
                failureCode = "ROUND_NOT_FOUND",
                failureDetail = "No pre-bet commitment record found for round ${query.roundId}",
            )

        if (!AviatorAlgorithmRegistry.isSupported(commitment.algorithmVersion)) {
            return HistoricalVerificationResult(
                isVerified = false,
                roundId = query.roundId,
                commitmentHash = commitment.commitmentHash,
                revealedSecretSeed = null,
                publicSalt = commitment.publicSalt,
                derivedMultiplier = null,
                algorithmVersion = commitment.algorithmVersion,
                rulesVersion = commitment.rulesVersion,
                failureCode = AviatorAlgorithmRegistry.UNSUPPORTED_VERSION_FAILURE_CODE,
                failureDetail = "Recorded algorithm version ${commitment.algorithmVersion} is not registered",
            )
        }

        val reveal = evidenceStore.findReveal(query.tenantId, query.gameId, query.roundId)
            ?: return HistoricalVerificationResult(
                isVerified = false,
                roundId = query.roundId,
                commitmentHash = commitment.commitmentHash,
                revealedSecretSeed = null,
                publicSalt = commitment.publicSalt,
                derivedMultiplier = null,
                algorithmVersion = commitment.algorithmVersion,
                rulesVersion = commitment.rulesVersion,
                failureCode = "ROUND_NOT_YET_REVEALED",
                failureDetail = "Round ${query.roundId} secret has not yet been revealed; unrevealed secrets cannot be leaked",
            )

        // 1. Rules & Algorithm version check
        if (commitment.algorithmVersion != query.expectedAlgorithmVersion ||
            commitment.rulesVersion != query.expectedRulesVersion
        ) {
            return HistoricalVerificationResult(
                isVerified = false,
                roundId = query.roundId,
                commitmentHash = commitment.commitmentHash,
                revealedSecretSeed = reveal.revealedSecretSeed,
                publicSalt = commitment.publicSalt,
                derivedMultiplier = reveal.derivedMultiplier,
                algorithmVersion = commitment.algorithmVersion,
                rulesVersion = commitment.rulesVersion,
                failureCode = "RULES_VERSION_MISMATCH",
                failureDetail = "Recorded rules (${commitment.rulesVersion}) or algorithm (${commitment.algorithmVersion}) does not match expected (${query.expectedRulesVersion} / ${query.expectedAlgorithmVersion})",
            )
        }

        // 2. Secret seed hash verification: SHA-256(revealedSeed) must equal published commitmentHash
        val computedHash = sha256(reveal.revealedSecretSeed)
        if (computedHash != commitment.commitmentHash) {
            return HistoricalVerificationResult(
                isVerified = false,
                roundId = query.roundId,
                commitmentHash = commitment.commitmentHash,
                revealedSecretSeed = reveal.revealedSecretSeed,
                publicSalt = commitment.publicSalt,
                derivedMultiplier = reveal.derivedMultiplier,
                algorithmVersion = commitment.algorithmVersion,
                rulesVersion = commitment.rulesVersion,
                failureCode = "COMMITMENT_HASH_MISMATCH",
                failureDetail = "Revealed secret seed hashes to $computedHash, which does NOT match pre-bet commitment ${commitment.commitmentHash}",
            )
        }

        // 3. Resolve client seeds
        val cs1 = commitment.clientSeed1 ?: sha256("${commitment.commitmentHash}:fallback:1:${query.roundId}")
        val cs2 = commitment.clientSeed2 ?: sha256("${commitment.commitmentHash}:fallback:2:${query.roundId}")
        val cs3 = commitment.clientSeed3 ?: sha256("${commitment.commitmentHash}:fallback:3:${query.roundId}")

        // 4. Mathematical outcome derivation re-computation
        val computedMultiplier = AviatorAlgorithmRegistry.compute(
            algorithmVersion = commitment.algorithmVersion,
            serverSeed = reveal.revealedSecretSeed,
            clientSeed1 = cs1,
            clientSeed2 = cs2,
            clientSeed3 = cs3,
        )

        if (computedMultiplier.compareTo(reveal.derivedMultiplier) != 0) {
            return HistoricalVerificationResult(
                isVerified = false,
                roundId = query.roundId,
                commitmentHash = commitment.commitmentHash,
                revealedSecretSeed = reveal.revealedSecretSeed,
                publicSalt = commitment.publicSalt,
                derivedMultiplier = reveal.derivedMultiplier,
                algorithmVersion = commitment.algorithmVersion,
                rulesVersion = commitment.rulesVersion,
                failureCode = "OUTCOME_MULTIPLIER_TAMPERED",
                failureDetail = "Derived multiplier in evidence (${reveal.derivedMultiplier}) does not match reproducible formula calculation ($computedMultiplier)",
            )
        }

        return HistoricalVerificationResult(
            isVerified = true,
            roundId = query.roundId,
            commitmentHash = commitment.commitmentHash,
            revealedSecretSeed = reveal.revealedSecretSeed,
            publicSalt = commitment.publicSalt,
            derivedMultiplier = computedMultiplier,
            algorithmVersion = commitment.algorithmVersion,
            rulesVersion = commitment.rulesVersion,
            failureCode = null,
            failureDetail = null,
        )
    }

    companion object {
        fun sha256(input: String): String {
            val md = MessageDigest.getInstance("SHA-256")
            val bytes = md.digest(input.toByteArray(StandardCharsets.UTF_8))
            return bytes.joinToString("") { "%02x".format(it) }
        }

        fun sha512(input: String): String {
            val md = MessageDigest.getInstance("SHA-512")
            val bytes = md.digest(input.toByteArray(StandardCharsets.UTF_8))
            return bytes.joinToString("") { "%02x".format(it) }
        }

        /**
         * Standalone, dependency-free verification method accepting
         * (serverSeed, clientSeed1, clientSeed2, clientSeed3) and returning
         * the exact crash multiplier down to 2 decimal places.
         *
         * Derivation:
         * 1. combinedString = serverSeed + clientSeed1 + clientSeed2 + clientSeed3
         * 2. combinedHash = SHA-512(combinedString)
         * 3. Bit slicing: extract first 13 hex chars (52 bits) -> h in [0, e - 1], where e = 2^52
         * 4. House edge (exact 3% instant crash): if (h % 100) < 3 -> 1.00x
         * 5. Fair multiplier: M_raw = e / (e - h)
         * 6. Truncate to 2 decimal places: M_final = max(1.01, floor(M_raw * 100.0) / 100.0)
         */
        fun calculateCrashMultiplier(
            serverSeed: String,
            clientSeed1: String,
            clientSeed2: String,
            clientSeed3: String,
        ): BigDecimal {
            val combinedString = serverSeed + clientSeed1 + clientSeed2 + clientSeed3
            val combinedHash = sha512(combinedString)

            val hex52 = combinedHash.substring(0, 13)
            val h = hex52.toLong(16)
            val e = 4503599627370496.0 // 2^52

            val isInstantCrash = (h % 100L) < 3L
            val finalMultiplier = if (isInstantCrash) {
                1.00
            } else {
                val mRaw = e / (e - h.toDouble())
                val truncated = Math.floor(mRaw * 100.0) / 100.0
                Math.max(1.01, truncated)
            }
            return BigDecimal.valueOf(finalMultiplier).setScale(2, RoundingMode.FLOOR)
        }
    }
}
