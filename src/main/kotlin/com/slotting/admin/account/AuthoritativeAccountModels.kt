package com.slotting.admin.account

import com.fasterxml.jackson.annotation.JsonProperty
import com.slotting.admin.auth.AuthenticatedPrincipal
import java.time.Instant
import java.util.UUID

// =============================================================================
// Profile DTOs
// =============================================================================

data class PlayerProfileDto(
    val userId: String,
    val username: String,
    val maskedEmail: String,
    val maskedPhone: String,
    val kycStatus: String,
    val accountStatus: String,
    val accountTier: String = "STANDARD",
    val serverVersion: Long = 1L,
    val createdAtEpochMillis: Long = 0L,
    val updatedAtEpochMillis: Long = 0L,
)

// =============================================================================
// Support Case Models
// =============================================================================

enum class SupportCaseStatus {
    SUBMITTED,
    UNDER_REVIEW,
    RESOLVED,
    CLOSED,
}

data class SupportCaseRecord(
    val caseId: UUID,
    val tenantId: String,
    val ownerUserId: UUID,
    val category: String,
    val subject: String,
    val description: String,
    val roundId: String?,
    val status: SupportCaseStatus,
    val resolutionSummary: String?,
    val idempotencyKey: String,
    val requestFingerprint: String,
    val correlationId: String,
    val serverVersion: Long = 1L,
    val createdAt: Instant,
    val updatedAt: Instant,
)

data class SupportCaseDto(
    val caseId: String,
    val ownerUserId: String,
    val category: String,
    val subject: String,
    val description: String,
    val roundId: String?,
    val idempotencyKey: String,
    val correlationId: String,
    val status: String,
    val resolutionSummary: String?,
    val createdAtEpochMs: Long,
)

data class CreateSupportCaseRequest(
    val category: String,
    val subject: String,
    val description: String,
    val roundId: String? = null,
    val idempotencyKey: String,
    val correlationId: String? = null,
)

data class CreateSupportCaseCommand(
    val principal: AuthenticatedPrincipal?,
    val tenantId: String,
    val ownerUserId: UUID,
    val category: String,
    val subject: String,
    val description: String,
    val roundId: String? = null,
    val idempotencyKey: String,
    val correlationId: String = "corr-supp-${UUID.randomUUID()}",
)

// =============================================================================
// Account Closure Models
// =============================================================================

enum class ClosureStatus {
    PENDING_SETTLEMENT,
    LEGAL_HOLD,
    CLOSED,
    REJECTED,
}

data class AccountClosureRecord(
    val closureId: UUID,
    val tenantId: String,
    val ownerUserId: UUID,
    val reason: String,
    val reasonDetails: String,
    val status: ClosureStatus,
    val pendingBalanceMinorUnits: Long,
    val settlementAcknowledged: Boolean,
    val hasPendingFinancialOps: Boolean,
    val hasLegalHold: Boolean,
    val retentionPolicyReference: String,
    val serverReceipt: String,
    val idempotencyKey: String,
    val requestFingerprint: String,
    val correlationId: String,
    val closedAt: Instant?,
    val serverVersion: Long = 1L,
    val createdAt: Instant,
    val updatedAt: Instant,
)

data class AccountClosureRequest(
    val ownerUserId: UUID? = null,
    val reason: String,
    val reasonDetails: String,
    val settlementAcknowledgment: Boolean = false,
    val idempotencyKey: String,
    val correlationId: String? = null,
)

data class SubmitAccountClosureCommand(
    val principal: AuthenticatedPrincipal?,
    val tenantId: String,
    val ownerUserId: UUID,
    val reason: String,
    val reasonDetails: String,
    val settlementAcknowledgment: Boolean,
    val idempotencyKey: String,
    val correlationId: String = "corr-close-${UUID.randomUUID()}",
)

data class AccountClosureResultDto(
    val closureId: String,
    val ownerUserId: String,
    val reason: String,
    val reasonDetails: String,
    val idempotencyKey: String,
    val correlationId: String,
    val status: String,
    val pendingBalanceMinorUnits: Long = 0L,
    val settlementAcknowledgment: Boolean = false,
    val hasPendingFinancialOps: Boolean = false,
    val hasLegalHold: Boolean = false,
    val retentionPolicyReference: String,
    val serverReceipt: String,
    val closedAtEpochMs: Long? = null,
    val createdAtEpochMs: Long,
)

// =============================================================================
// Restrictions / RG Summary
// =============================================================================

data class AccountRestrictionsSummaryDto(
    val userId: String,
    val tenantId: String,
    @get:JsonProperty("isRestricted")
    val isRestricted: Boolean,
    val accountStatus: String,
    val restrictionTypes: List<String>,
    val coolingOffUntil: Instant? = null,
    val selfExcludedUntil: Instant? = null,
    val realityCheckIntervalMinutes: Int? = null,
    val serverTime: Instant,
    val serverVersion: Long = 1L,
)

// =============================================================================
// Domain Exceptions
// =============================================================================

class PositiveBalanceUnacknowledgedException(message: String) : RuntimeException(message)
class AccountAlreadyClosedException(message: String) : RuntimeException(message)
