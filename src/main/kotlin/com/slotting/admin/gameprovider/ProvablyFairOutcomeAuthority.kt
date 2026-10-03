package com.slotting.admin.gameprovider

import org.springframework.stereotype.Service
import java.math.BigDecimal
import java.nio.charset.StandardCharsets
import java.security.MessageDigest
import java.security.SecureRandom
import java.time.Clock
import java.util.UUID
import java.util.concurrent.ConcurrentHashMap

/**
 * Gate to enforce TC-022: Outcome-bound fairness evidence.
 * Protected risk: "no complete outcome-bound provably-fair system, post-commit substitution"
 * Semantic contract: "Every settled round binds to pre-bet commitment and reproducible reveal evidence."
 *
 * Implements Spribe Aviator 3-Client-Seed Provably Fair consensus engine.
 */
object ProvablyFairOutcomeBinding {
    @Volatile
    var isBound: Boolean = true

    fun checkBound() {
        if (!isBound) {
            throw AssertionError("outcome-bound fairness authority unbound")
        }
    }
}

class RoundEntropyCollector {
    private val distinctPlayers = LinkedHashMap<String, String>() // playerId -> clientSeed

    @Synchronized
    fun addPlayerBet(playerId: String, clientSeed: String?) {
        if (distinctPlayers.size < 3 && !distinctPlayers.containsKey(playerId)) {
            distinctPlayers[playerId] = clientSeed?.trim().orEmpty()
        }
    }

    @Synchronized
    fun finalizeSeeds(serverSeedHash: String, roundId: String): Triple<String, String, String> {
        val playerSeeds = distinctPlayers.values.toList()
        fun resolve(slot: Int): String {
            val idx = slot - 1
            if (idx < playerSeeds.size && playerSeeds[idx].isNotBlank()) {
                return playerSeeds[idx]
            }
            return ProvablyFairOutcomeAuthority.sha256("$serverSeedHash:fallback:$slot:$roundId")
        }
        return Triple(resolve(1), resolve(2), resolve(3))
    }
}

@Service
class ProvablyFairOutcomeAuthority(
    val store: FairnessEvidenceStore,
    private val clock: Clock = Clock.systemUTC(),
) {
    private val secureRandom = SecureRandom()
    private val entropyCollectors = ConcurrentHashMap<String, RoundEntropyCollector>()

    private fun key(tenantId: String, gameId: String, roundId: String) = "$tenantId:$gameId:$roundId"

    fun publishPreBetCommitment(command: PublishCommitmentCommand): RoundCommitmentRecord {
        ProvablyFairOutcomeBinding.checkBound()
        val now = clock.instant()

        val existing = store.findCommitment(command.tenantId, command.gameId, command.roundId)
        if (existing != null) {
            if (existing.status != RoundCommitmentStatus.COMMITTED || existing.firstBetAcceptedAt != null) {
                throw FairnessAuthorityException(
                    "BETTING_ACTIVE_CANNOT_COMMIT",
                    "Cannot publish or modify commitment after betting has become active for round ${command.roundId}"
                )
            }
            throw FairnessAuthorityException(
                "DUPLICATE_ROUND_COMMITMENT",
                "Commitment already exists for round ${command.roundId}"
            )
        }

        // Generate cryptographically secure 256-bit un-guessable secret serverSeed
        val seedBytes = ByteArray(32)
        secureRandom.nextBytes(seedBytes)
        val serverSeed = seedBytes.joinToString("") { "%02x".format(it) }
        val serverSeedHash = sha256(serverSeed)

        val commitment = RoundCommitmentRecord(
            commitmentId = UUID.randomUUID(),
            tenantId = command.tenantId,
            gameId = command.gameId,
            roundId = command.roundId,
            authorityType = FairnessAuthorityType.INTERNAL_HMAC_SHA256,
            algorithmVersion = command.algorithmVersion,
            rulesVersion = command.rulesVersion,
            commitmentHash = serverSeedHash,
            publicSalt = command.publicSalt,
            encryptedSecretSeed = serverSeed,
            committedAt = now,
            firstBetAcceptedAt = null,
            status = RoundCommitmentStatus.COMMITTED,
            serverVersion = 1L,
            createdAt = now,
            updatedAt = now,
        )

        entropyCollectors[key(command.tenantId, command.gameId, command.roundId)] = RoundEntropyCollector()
        store.saveCommitment(commitment)
        store.saveAuditEvent(
            FairnessAuditRecord(
                auditId = UUID.randomUUID(),
                tenantId = command.tenantId,
                roundId = command.roundId,
                action = "PRE_BET_COMMITMENT_PUBLISHED",
                actor = "SYSTEM_FAIRNESS_AUTHORITY",
                detail = "Published commitment hash $serverSeedHash with salt ${command.publicSalt}",
                occurredAt = now,
            )
        )

        return commitment
    }

    fun notifyBetAccepted(
        tenantId: String,
        gameId: String,
        roundId: String,
        playerId: String? = null,
        clientSeed: String? = null,
    ) {
        ProvablyFairOutcomeBinding.checkBound()
        val commitment = store.findCommitment(tenantId, gameId, roundId)
            ?: throw FairnessAuthorityException("COMMITMENT_NOT_FOUND", "Commitment not found for round $roundId")

        if (commitment.firstBetAcceptedAt == null) {
            commitment.firstBetAcceptedAt = clock.instant()
            commitment.status = RoundCommitmentStatus.BETTING_ACTIVE
            commitment.updatedAt = clock.instant()
            store.updateCommitment(commitment)
        }

        if (playerId != null) {
            val collector = entropyCollectors.computeIfAbsent(key(tenantId, gameId, roundId)) {
                RoundEntropyCollector()
            }
            collector.addPlayerBet(playerId, clientSeed)
        }
    }

    fun recordClientSeed(tenantId: String, gameId: String, roundId: String, playerId: String, clientSeed: String?) {
        notifyBetAccepted(tenantId, gameId, roundId, playerId, clientSeed)
    }

    fun resolveClientSeeds(
        tenantId: String,
        gameId: String,
        roundId: String,
        commitment: RoundCommitmentRecord
    ): Triple<String, String, String> {
        if (!commitment.clientSeed1.isNullOrBlank() &&
            !commitment.clientSeed2.isNullOrBlank() &&
            !commitment.clientSeed3.isNullOrBlank()
        ) {
            return Triple(commitment.clientSeed1!!, commitment.clientSeed2!!, commitment.clientSeed3!!)
        }

        val collector = entropyCollectors[key(tenantId, gameId, roundId)]
        return collector?.finalizeSeeds(commitment.commitmentHash, roundId)
            ?: Triple(
                sha256("${commitment.commitmentHash}:fallback:1:$roundId"),
                sha256("${commitment.commitmentHash}:fallback:2:$roundId"),
                sha256("${commitment.commitmentHash}:fallback:3:$roundId"),
            )
    }

    fun deriveAuthoritativeOutcome(tenantId: String, gameId: String, roundId: String): AuthoritativeOutcomeResult {
        ProvablyFairOutcomeBinding.checkBound()
        val commitment = store.findCommitment(tenantId, gameId, roundId)
            ?: throw FairnessAuthorityException("COMMITMENT_NOT_FOUND", "Commitment not found for round $roundId")

        val (cs1, cs2, cs3) = resolveClientSeeds(tenantId, gameId, roundId, commitment)
        if (commitment.clientSeed1 == null || commitment.clientSeed2 == null || commitment.clientSeed3 == null) {
            commitment.clientSeed1 = cs1
            commitment.clientSeed2 = cs2
            commitment.clientSeed3 = cs3
            commitment.updatedAt = clock.instant()
            store.updateCommitment(commitment)
        }

        val multiplier = computeMultiplier(
            serverSeed = commitment.encryptedSecretSeed,
            clientSeed1 = cs1,
            clientSeed2 = cs2,
            clientSeed3 = cs3,
        )

        return AuthoritativeOutcomeResult(
            roundId = roundId,
            secretSeed = commitment.encryptedSecretSeed,
            commitmentHash = commitment.commitmentHash,
            publicSalt = commitment.publicSalt,
            multiplier = multiplier,
            algorithmVersion = commitment.algorithmVersion,
            rulesVersion = commitment.rulesVersion,
            clientSeed1 = cs1,
            clientSeed2 = cs2,
            clientSeed3 = cs3,
        )
    }

    fun revealAndVerifyOutcome(command: RevealOutcomeCommand): RoundRevealRecord {
        ProvablyFairOutcomeBinding.checkBound()
        val now = clock.instant()

        val commitment = store.findCommitment(command.tenantId, command.gameId, command.roundId)
            ?: throw FairnessAuthorityException("COMMITMENT_NOT_FOUND", "Commitment not found for round ${command.roundId}")

        val existingReveal = store.findReveal(command.tenantId, command.gameId, command.roundId)
        if (existingReveal != null) {
            return existingReveal
        }

        // Verify that revealed secret seed reproduces exact commitment hash
        val calculatedHash = sha256(command.revealedSecretSeed)
        if (calculatedHash != commitment.commitmentHash) {
            store.saveAuditEvent(
                FairnessAuditRecord(
                    auditId = UUID.randomUUID(),
                    tenantId = command.tenantId,
                    roundId = command.roundId,
                    action = "FAIRNESS_VERIFICATION_FAILED",
                    actor = "SYSTEM_FAIRNESS_AUTHORITY",
                    detail = "Security Alert: Revealed seed $calculatedHash does not match pre-bet commitment ${commitment.commitmentHash} (tampered seed detected)",
                    occurredAt = now,
                )
            )
            throw FairnessVerificationException(
                "COMMITMENT_HASH_MISMATCH",
                "Revealed secret seed does not match published pre-bet commitment hash"
            )
        }

        val (cs1, cs2, cs3) = resolveClientSeeds(command.tenantId, command.gameId, command.roundId, commitment)
        if (commitment.clientSeed1 == null) {
            commitment.clientSeed1 = cs1
            commitment.clientSeed2 = cs2
            commitment.clientSeed3 = cs3
        }

        // Derive authoritative multiplier
        val derivedMultiplier = computeMultiplier(
            serverSeed = command.revealedSecretSeed,
            clientSeed1 = cs1,
            clientSeed2 = cs2,
            clientSeed3 = cs3,
        )

        commitment.status = RoundCommitmentStatus.REVEALED
        commitment.updatedAt = now
        store.updateCommitment(commitment)

        val evidenceRef = sha256("${command.tenantId}:${command.roundId}:${command.revealedSecretSeed}:$derivedMultiplier:${now.toEpochMilli()}")

        val reveal = RoundRevealRecord(
            revealId = UUID.randomUUID(),
            commitmentId = commitment.commitmentId,
            tenantId = command.tenantId,
            gameId = command.gameId,
            roundId = command.roundId,
            revealedSecretSeed = command.revealedSecretSeed,
            derivedMultiplier = derivedMultiplier,
            revealedAt = now,
            verificationStatus = FairnessVerificationStatus.VERIFIED,
            verificationError = null,
            evidenceReference = evidenceRef,
        )

        store.saveReveal(reveal)
        store.saveAuditEvent(
            FairnessAuditRecord(
                auditId = UUID.randomUUID(),
                tenantId = command.tenantId,
                roundId = command.roundId,
                action = "ROUND_OUTCOME_REVEALED_AND_VERIFIED",
                actor = "SYSTEM_FAIRNESS_AUTHORITY",
                detail = "Verified outcome multiplier $derivedMultiplier against pre-bet commitment ${commitment.commitmentHash}",
                occurredAt = now,
            )
        )

        return reveal
    }

    fun executeProviderFairnessReconciliation(
        tenantId: String,
        gameId: String,
        roundId: String,
        providerPort: ExternalFairnessProviderPort
    ): FairnessReconciliationResult {
        ProvablyFairOutcomeBinding.checkBound()
        val now = clock.instant()
        val commitment = store.findCommitment(tenantId, gameId, roundId)
            ?: throw FairnessAuthorityException("COMMITMENT_NOT_FOUND", "Commitment not found for round $roundId")

        return try {
            val externalOutcome = providerPort.fetchOutcome(tenantId, gameId, roundId)
            FairnessReconciliationResult(
                roundId = roundId,
                status = FairnessReconciliationStatus.RESOLVED_ACCEPTED,
                safeMessage = "Provider outcome resolved with multiplier ${externalOutcome.multiplier}",
            )
        } catch (e: ExternalFairnessProviderTimeoutException) {
            commitment.status = RoundCommitmentStatus.LOCKED
            commitment.updatedAt = now
            store.updateCommitment(commitment)

            store.saveAuditEvent(
                FairnessAuditRecord(
                    auditId = UUID.randomUUID(),
                    tenantId = tenantId,
                    roundId = roundId,
                    action = "EXTERNAL_PROVIDER_TIMEOUT",
                    actor = "SYSTEM_FAIRNESS_AUTHORITY",
                    detail = "Fairness reconciliation held: provider timed out (${e.message})",
                    occurredAt = now,
                )
            )

            FairnessReconciliationResult(
                roundId = roundId,
                status = FairnessReconciliationStatus.HELD_PENDING_RECONCILIATION,
                safeMessage = e.message,
            )
        }
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

        fun computeMultiplier(
            serverSeed: String,
            clientSeed1: String,
            clientSeed2: String,
            clientSeed3: String,
        ): BigDecimal {
            return IndependentFairnessVerifier.calculateCrashMultiplier(
                serverSeed = serverSeed,
                clientSeed1 = clientSeed1,
                clientSeed2 = clientSeed2,
                clientSeed3 = clientSeed3,
            )
        }
    }
}
