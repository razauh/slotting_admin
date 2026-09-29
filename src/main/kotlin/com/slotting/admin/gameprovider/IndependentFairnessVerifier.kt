package com.slotting.admin.gameprovider

import org.springframework.stereotype.Component

/**
 * Independent verifier that can be used by internal systems, third-party auditors,
 * regulatory bodies, or public verification tools to independently validate round fairness.
 */
@Component
class IndependentFairnessVerifier(
    private val store: FairnessEvidenceStore
) {
    fun verifyHistoricalRound(query: VerifyHistoricalRoundQuery): HistoricalVerificationResult {
        ProvablyFairOutcomeBinding.checkBound()

        val commitment = store.findCommitment(query.tenantId, query.gameId, query.roundId)
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

        val reveal = store.findReveal(query.tenantId, query.gameId, query.roundId)
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
        val computedHash = ProvablyFairOutcomeAuthority.sha256(reveal.revealedSecretSeed)
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

        // 3. Mathematical outcome derivation re-computation
        val computedMultiplier = ProvablyFairOutcomeAuthority.computeMultiplier(
            secretSeed = reveal.revealedSecretSeed,
            publicSalt = commitment.publicSalt,
            roundId = query.roundId,
            rulesVersion = commitment.rulesVersion,
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
}
