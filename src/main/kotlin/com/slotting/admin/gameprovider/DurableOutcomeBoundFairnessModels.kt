package com.slotting.admin.gameprovider

import java.math.BigDecimal
import java.time.Instant
import java.util.UUID

enum class FairnessAuthorityType {
    INTERNAL_HMAC_SHA256,
    EXTERNAL_CERTIFIED_PROVIDER
}

enum class RoundCommitmentStatus {
    COMMITTED,
    BETTING_ACTIVE,
    LOCKED,
    REVEALED,
    INVALIDATED
}

enum class FairnessVerificationStatus {
    VERIFIED,
    FAILED,
    TAMPERED,
    PENDING_AUDIT
}

enum class FairnessReconciliationStatus {
    RESOLVED_ACCEPTED,
    HELD_PENDING_RECONCILIATION,
    RECONCILED_FAILED
}

open class FairnessAuthorityException(
    val errorCode: String,
    override val message: String
) : RuntimeException(message)

class FairnessVerificationException(
    val errorCode: String,
    override val message: String
) : RuntimeException(message)

class ExternalFairnessProviderTimeoutException(
    override val message: String
) : RuntimeException(message)

data class RoundCommitmentRecord(
    val commitmentId: UUID,
    val tenantId: String,
    val gameId: String,
    val roundId: String,
    val authorityType: FairnessAuthorityType,
    val algorithmVersion: String,
    val rulesVersion: String,
    val commitmentHash: String,
    val publicSalt: String,
    val encryptedSecretSeed: String,
    val committedAt: Instant,
    var firstBetAcceptedAt: Instant? = null,
    var status: RoundCommitmentStatus,
    var serverVersion: Long = 1L,
    val createdAt: Instant,
    var updatedAt: Instant,
    var clientSeed1: String? = null,
    var clientSeed2: String? = null,
    var clientSeed3: String? = null,
)

data class RoundRevealRecord(
    val revealId: UUID,
    val commitmentId: UUID,
    val tenantId: String,
    val gameId: String,
    val roundId: String,
    val revealedSecretSeed: String,
    val derivedMultiplier: BigDecimal,
    val revealedAt: Instant,
    val verificationStatus: FairnessVerificationStatus,
    val verificationError: String? = null,
    val evidenceReference: String,
)

data class FairnessAuditRecord(
    val auditId: UUID,
    val tenantId: String,
    val roundId: String,
    val action: String,
    val actor: String,
    val detail: String,
    val occurredAt: Instant,
)

data class PublishCommitmentCommand(
    val tenantId: String,
    val gameId: String,
    val roundId: String,
    val publicSalt: String,
    val algorithmVersion: String = "1.0.0",
    val rulesVersion: String = "1.0.0",
)

data class RevealOutcomeCommand(
    val tenantId: String,
    val gameId: String,
    val roundId: String,
    val revealedSecretSeed: String,
)

data class AuthoritativeOutcomeResult(
    val roundId: String,
    val secretSeed: String,
    val commitmentHash: String,
    val publicSalt: String,
    val multiplier: BigDecimal,
    val algorithmVersion: String,
    val rulesVersion: String,
    val clientSeed1: String? = null,
    val clientSeed2: String? = null,
    val clientSeed3: String? = null,
)

data class VerifyHistoricalRoundQuery(
    val tenantId: String,
    val gameId: String,
    val roundId: String,
    val expectedAlgorithmVersion: String = "1.0.0",
    val expectedRulesVersion: String = "1.0.0",
)

data class HistoricalVerificationResult(
    val isVerified: Boolean,
    val roundId: String,
    val commitmentHash: String?,
    val revealedSecretSeed: String?,
    val publicSalt: String?,
    val derivedMultiplier: BigDecimal?,
    val algorithmVersion: String?,
    val rulesVersion: String?,
    val failureCode: String? = null,
    val failureDetail: String? = null,
)

data class ExternalOutcomeResult(
    val outcomeId: String,
    val externalReference: String,
    val multiplier: BigDecimal,
    val providerSignature: String,
)

data class FairnessReconciliationResult(
    val roundId: String,
    val status: FairnessReconciliationStatus,
    val safeMessage: String,
)

interface ExternalFairnessProviderPort {
    fun fetchOutcome(tenantId: String, gameId: String, roundId: String): ExternalOutcomeResult
}
