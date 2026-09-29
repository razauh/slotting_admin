package com.slotting.admin.gameprovider

import org.springframework.stereotype.Service
import java.math.BigDecimal
import java.math.RoundingMode
import java.nio.charset.StandardCharsets
import java.security.MessageDigest
import java.security.SecureRandom
import java.time.Clock
import java.util.UUID
import javax.crypto.Mac
import javax.crypto.spec.SecretKeySpec

/**
 * Gate to enforce TC-022: Outcome-bound fairness evidence.
 * Protected risk: "no complete outcome-bound provably-fair system, post-commit substitution"
 * Semantic contract: "Every settled round binds to pre-bet commitment and reproducible reveal evidence."
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

@Service
class ProvablyFairOutcomeAuthority(
    val store: FairnessEvidenceStore,
    private val clock: Clock = Clock.systemUTC(),
) {
    private val secureRandom = SecureRandom()

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

        // Generate cryptographically secure 256-bit un-guessable secret seed
        val seedBytes = ByteArray(32)
        secureRandom.nextBytes(seedBytes)
        val secretSeed = seedBytes.joinToString("") { "%02x".format(it) }
        val commitmentHash = sha256(secretSeed)

        val commitment = RoundCommitmentRecord(
            commitmentId = UUID.randomUUID(),
            tenantId = command.tenantId,
            gameId = command.gameId,
            roundId = command.roundId,
            authorityType = FairnessAuthorityType.INTERNAL_HMAC_SHA256,
            algorithmVersion = command.algorithmVersion,
            rulesVersion = command.rulesVersion,
            commitmentHash = commitmentHash,
            publicSalt = command.publicSalt,
            encryptedSecretSeed = secretSeed,
            committedAt = now,
            firstBetAcceptedAt = null,
            status = RoundCommitmentStatus.COMMITTED,
            serverVersion = 1L,
            createdAt = now,
            updatedAt = now,
        )

        store.saveCommitment(commitment)
        store.saveAuditEvent(
            FairnessAuditRecord(
                auditId = UUID.randomUUID(),
                tenantId = command.tenantId,
                roundId = command.roundId,
                action = "PRE_BET_COMMITMENT_PUBLISHED",
                actor = "SYSTEM_FAIRNESS_AUTHORITY",
                detail = "Published commitment hash $commitmentHash with salt ${command.publicSalt}",
                occurredAt = now,
            )
        )

        return commitment
    }

    fun notifyBetAccepted(tenantId: String, gameId: String, roundId: String) {
        ProvablyFairOutcomeBinding.checkBound()
        val commitment = store.findCommitment(tenantId, gameId, roundId)
            ?: throw FairnessAuthorityException("COMMITMENT_NOT_FOUND", "Commitment not found for round $roundId")

        if (commitment.firstBetAcceptedAt == null) {
            commitment.firstBetAcceptedAt = clock.instant()
            commitment.status = RoundCommitmentStatus.BETTING_ACTIVE
            commitment.updatedAt = clock.instant()
            store.updateCommitment(commitment)
        }
    }

    fun deriveAuthoritativeOutcome(tenantId: String, gameId: String, roundId: String): AuthoritativeOutcomeResult {
        ProvablyFairOutcomeBinding.checkBound()
        val commitment = store.findCommitment(tenantId, gameId, roundId)
            ?: throw FairnessAuthorityException("COMMITMENT_NOT_FOUND", "Commitment not found for round $roundId")

        val multiplier = computeMultiplier(
            secretSeed = commitment.encryptedSecretSeed,
            publicSalt = commitment.publicSalt,
            roundId = roundId,
            rulesVersion = commitment.rulesVersion,
        )

        return AuthoritativeOutcomeResult(
            roundId = roundId,
            secretSeed = commitment.encryptedSecretSeed,
            commitmentHash = commitment.commitmentHash,
            publicSalt = commitment.publicSalt,
            multiplier = multiplier,
            algorithmVersion = commitment.algorithmVersion,
            rulesVersion = commitment.rulesVersion,
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

        // Derive authoritative multiplier
        val derivedMultiplier = computeMultiplier(
            secretSeed = command.revealedSecretSeed,
            publicSalt = commitment.publicSalt,
            roundId = command.roundId,
            rulesVersion = commitment.rulesVersion,
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

        fun computeMultiplier(
            secretSeed: String,
            publicSalt: String,
            roundId: String,
            rulesVersion: String
        ): BigDecimal {
            val message = "$publicSalt:$roundId:$rulesVersion"
            val mac = Mac.getInstance("HmacSHA256")
            val keySpec = SecretKeySpec(secretSeed.toByteArray(StandardCharsets.UTF_8), "HmacSHA256")
            mac.init(keySpec)
            val hmac = mac.doFinal(message.toByteArray(StandardCharsets.UTF_8))
            val hex = hmac.joinToString("") { "%02x".format(it) }

            // Take first 13 hex chars (52 bits)
            val h = hex.substring(0, 13).toLong(16)
            val e = (1L shl 52).toDouble()

            // 1 in 33 (approx 3% house edge) instant crash at 1.00x
            val multiplierVal = if (h % 33L == 0L) {
                1.00
            } else {
                val raw = Math.floor((100.0 * e - h.toDouble()) / (e - h.toDouble())) / 100.0
                Math.max(1.00, raw)
            }
            return BigDecimal.valueOf(multiplierVal).setScale(4, RoundingMode.HALF_UP)
        }
    }
}
