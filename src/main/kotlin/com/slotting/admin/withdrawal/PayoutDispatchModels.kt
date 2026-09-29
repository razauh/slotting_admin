package com.slotting.admin.withdrawal

import com.slotting.admin.auth.AuthenticatedPrincipal
import java.time.Instant
import java.util.UUID

enum class PayoutDispatchStatus {
    APPROVED,
    RESERVED,
    DISPATCH_READY,
    SENT_PENDING,
    SUCCEEDED,
    FAILED_FINAL,
    AMBIGUOUS_RECONCILING,
    MANUAL_REVIEW,
}

enum class OperatorResolutionAction {
    FORCE_SUCCESS,
    FORCE_FAILURE,
}

data class PayoutDispatchIntentRecord(
    val intentId: UUID,
    val tenantId: String,
    val requestId: UUID,
    val ownerId: UUID,
    val reservationId: UUID,
    val methodId: String,
    val providerId: String,
    val destinationReference: String,
    val grossAmountMinorUnits: Long,
    val feeMinorUnits: Long,
    val netPayoutAmountMinorUnits: Long,
    val currencyCode: String,
    val idempotencyKey: String,
    val providerReference: String? = null,
    val status: PayoutDispatchStatus,
    val leaseWorkerId: String? = null,
    val leaseExpiresAt: Instant? = null,
    val attemptCount: Int = 0,
    val ledgerTransactionReference: String? = null,
    val failureReason: String? = null,
    val serverVersion: Long = 1L,
    val createdAt: Instant,
    val updatedAt: Instant,
)

data class PayoutReconciliationAuditRecord(
    val auditId: UUID,
    val tenantId: String,
    val intentId: UUID,
    val actionType: String,
    val previousStatus: PayoutDispatchStatus,
    val newStatus: PayoutDispatchStatus,
    val operatorId: String,
    val notes: String? = null,
    val occurredAt: Instant,
)

data class StagePayoutDispatchCommand(
    val tenantId: String,
    val requestId: UUID,
    val providerId: String,
    val idempotencyKey: String,
)

data class PayoutDispatchResult(
    val intentId: UUID,
    val requestId: UUID,
    val status: PayoutDispatchStatus,
    val providerReference: String?,
    val ledgerTransactionReference: String?,
    val failureReason: String? = null,
    val completedAt: Instant,
)

data class PayoutDispatchReconciliationResult(
    val intentId: UUID,
    val previousStatus: PayoutDispatchStatus,
    val newStatus: PayoutDispatchStatus,
    val actionTaken: String,
    val ledgerTransactionReference: String?,
)

data class OperatorPayoutResolutionCommand(
    val principal: AuthenticatedPrincipal?,
    val sessionId: String,
    val tenantId: String,
    val intentId: UUID,
    val resolution: OperatorResolutionAction,
    val notes: String,
)
