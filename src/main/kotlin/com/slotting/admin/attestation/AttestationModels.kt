package com.slotting.admin.attestation

import java.time.Instant
import java.util.UUID

enum class ProtectedOperation {
    WAGER,
    WITHDRAWAL,
    DEPOSIT,
    NEW_GAME_SESSION,
}

enum class AttestationDecision {
    ALLOW,
    STEP_UP,
    HOLD,
    DENY,
}

enum class AttestationFailureReason {
    CHALLENGE_VALID,
    CHALLENGE_NOT_FOUND,
    CHALLENGE_EXPIRED,
    CHALLENGE_ALREADY_CONSUMED,
    SESSION_MISMATCH,
    OPERATION_MISMATCH,
    USER_MISMATCH,
    TENANT_MISMATCH,
    PACKAGE_MISMATCH,
    SIGNER_DIGEST_MISMATCH,
    MALFORMED_PAYLOAD,
    CLOCK_SKEW_EXCESSIVE,
    RATE_LIMIT_EXCEEDED,
    EXTERNAL_PROVIDER_UNAVAILABLE,
    EXTERNAL_PROVIDER_FAILED,
    ELEVATED_RISK_SIGNAL,
    UNAPPROVED_TEST_ADAPTER_IN_PRODUCTION,
}

data class OperationChallengeRecord(
    val challengeId: UUID = UUID.randomUUID(),
    val tenantId: String,
    val userId: String,
    val sessionId: String,
    val operation: ProtectedOperation,
    val nonceValue: String,
    val issuedAt: Instant,
    val expiresAt: Instant,
    val consumed: Boolean = false,
    val consumedAt: Instant? = null,
    val consumedByOperationRef: String? = null,
    val createdAt: Instant = issuedAt,
) {
    init {
        require(tenantId.isNotBlank()) { "tenantId must not be blank" }
        require(userId.isNotBlank()) { "userId must not be blank" }
        require(sessionId.isNotBlank()) { "sessionId must not be blank" }
        require(nonceValue.isNotBlank()) { "nonceValue must not be blank" }
        require(expiresAt.isAfter(issuedAt)) { "expiresAt must be after issuedAt" }
    }
}

data class OperationAttestationPayload(
    val nonceValue: String,
    val clientReportedPackageName: String? = null,
    val clientReportedSignerDigest: String? = null,
    val clientReportedVersionCode: Long? = null,
    val clientTimestamp: Instant? = null,
    val externalAttestationToken: String? = null,
    val clientRiskSignals: Map<String, String> = emptyMap(),
)

data class AttestationVerificationResult(
    val verificationId: UUID = UUID.randomUUID(),
    val tenantId: String,
    val userId: String,
    val sessionId: String,
    val operation: ProtectedOperation,
    val decision: AttestationDecision,
    val reason: AttestationFailureReason,
    val evaluatedAt: Instant,
    val evidenceReference: String,
    val detailsRedacted: String,
)

data class OperationAttestationAuditRecord(
    val auditId: UUID = UUID.randomUUID(),
    val tenantId: String,
    val userId: String,
    val sessionId: String,
    val operation: ProtectedOperation,
    val nonceValue: String,
    val decision: AttestationDecision,
    val reason: AttestationFailureReason,
    val appPackageName: String?,
    val appVersionCode: Long?,
    val clientReportedFingerprint: String?,
    val occurredAt: Instant,
    val idempotencyKey: String,
    val correlationId: String,
    val causationId: String,
    val evidenceReference: String,
    val detailsRedacted: String,
)

data class AttestationAppIdentityConfig(
    val expectedPackageName: String = "com.slotting.game.connected", // XREP-004 fix
    val allowedSignerDigests: Set<String> = emptySet(),
    val allowedVersionCodes: Set<Long> = emptySet(),
    val requireSignerVerification: Boolean = false,
    val enforceExternalAttestation: Boolean = false,
    val maxActiveChallengesPerUserSession: Int = 5,
)
