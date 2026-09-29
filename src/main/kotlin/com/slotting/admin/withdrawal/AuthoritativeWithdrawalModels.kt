package com.slotting.admin.withdrawal

import com.slotting.admin.auth.AdminPermission
import com.slotting.admin.auth.AuthenticatedPrincipal
import com.slotting.admin.auth.DualControlReceipt
import java.time.Instant
import java.util.UUID

// =============================================================================
// Typed Exceptions for Authoritative Withdrawal Workflow
// =============================================================================

class InvalidFeeBoundaryException(message: String) : RuntimeException(message)
class DestinationMismatchException(message: String) : RuntimeException(message)
class StepUpReplayException(message: String) : RuntimeException(message)
class StepUpBindingMismatchException(message: String) : RuntimeException(message)
class RestrictedAccountException(message: String) : RuntimeException(message)

// =============================================================================
// Domain Models
// =============================================================================

data class AuthoritativeWithdrawalQuote(
    val quoteId: UUID,
    val tenantId: String,
    val ownerId: UUID,
    val currencyCode: String,
    val methodId: String,
    val destinationId: UUID,
    val destinationReference: String,
    val grossAmountMinorUnits: Long,
    val fixedFeeMinorUnits: Long,
    val percentageFeeBps: Long,
    val totalFeeMinorUnits: Long,
    val netPayoutMinorUnits: Long,
    val stepUpRequired: Boolean,
    val status: WithdrawalQuoteStatus,
    val quotedAt: Instant,
    val expiresAt: Instant,
    val consumedAt: Instant? = null,
    val idempotencyKey: String,
    val serverVersion: Long = 1L,
)

data class StepUpAssertionRecord(
    val assertionId: UUID,
    val tenantId: String,
    val ownerId: UUID,
    val sessionId: String,
    val destinationReference: String,
    val grossAmountMinorUnits: Long,
    val currencyCode: String,
    val methodId: String,
    val operationType: String = "WITHDRAWAL",
    val boundDigest: String,
    val token: String,
    val isConsumed: Boolean = false,
    val issuedAt: Instant,
    val expiresAt: Instant,
    val consumedAt: Instant? = null,
)

enum class AuthoritativeReservationStatus {
    RESERVED,
    COMMITTED,
    RELEASED,
}

data class AuthoritativeWithdrawalReservation(
    val reservationId: UUID,
    val tenantId: String,
    val ownerId: UUID,
    val requestId: UUID,
    val amountMinorUnits: Long,
    val currencyCode: String,
    val status: AuthoritativeReservationStatus,
    val ledgerJournalReference: String? = null,
    val serverVersion: Long = 1L,
    val createdAt: Instant,
    val updatedAt: Instant,
)

data class AuthoritativeWithdrawalRequest(
    val requestId: UUID,
    val tenantId: String,
    val ownerId: UUID,
    val quoteId: UUID,
    val reservationId: UUID,
    val methodId: String,
    val destinationId: UUID,
    val destinationReference: String,
    val grossAmountMinorUnits: Long,
    val feeMinorUnits: Long,
    val netPayoutAmountMinorUnits: Long,
    val currencyCode: String,
    val stepUpAssertionId: UUID?,
    val immutableDigest: String,
    val status: WithdrawalRequestStatus,
    val reviewState: WithdrawalReviewState = WithdrawalReviewState.QUEUED,
    val denialReasonCode: String? = null,
    val denialMessage: String? = null,
    val dualControlReceiptId: UUID? = null,
    val idempotencyKey: String,
    val requestVersion: Long = 1L,
    val createdAt: Instant,
    val updatedAt: Instant,
)

data class AuthoritativeWithdrawalRequestResult(
    val requestId: UUID,
    val tenantId: String,
    val ownerId: UUID,
    val quoteId: UUID,
    val reservationId: UUID,
    val methodId: String,
    val destinationReference: String,
    val grossAmountMinorUnits: Long,
    val feeMinorUnits: Long,
    val netPayoutAmountMinorUnits: Long,
    val currencyCode: String,
    val status: WithdrawalRequestStatus,
    val reviewState: WithdrawalReviewState,
    val immutableDigest: String,
    val requestVersion: Long,
    val serverTime: Instant,
)

data class AuthoritativeWithdrawalReviewResult(
    val requestId: UUID,
    val previousState: WithdrawalReviewState,
    val newState: WithdrawalReviewState,
    val dualControlReceiptId: UUID?,
    val serverTime: Instant,
    val serverVersion: Long,
)

// =============================================================================
// Commands
// =============================================================================

data class CreateAuthoritativeQuoteCommand(
    val principal: AuthenticatedPrincipal?,
    val sessionId: String,
    val tenantId: String,
    val ownerId: UUID,
    val currencyCode: String,
    val methodId: String,
    val destinationId: UUID,
    val grossAmountMinorUnits: Long,
    val idempotencyKey: String,
    val correlationId: String = "corr-quote",
    val causationId: String = "caus-quote",
)

data class IssueStepUpAssertionCommand(
    val principal: AuthenticatedPrincipal?,
    val sessionId: String,
    val tenantId: String,
    val ownerId: UUID,
    val quoteId: UUID,
)

data class CreateAuthoritativeWithdrawalRequestCommand(
    val principal: AuthenticatedPrincipal?,
    val sessionId: String,
    val tenantId: String,
    val ownerId: UUID,
    val quoteId: UUID,
    val destinationId: UUID,
    val stepUpToken: String?,
    val idempotencyKey: String,
    val correlationId: String = "corr-req",
    val causationId: String = "caus-req",
)

data class ReviewWithdrawalCommand(
    val principal: AuthenticatedPrincipal?,
    val sessionId: String,
    val tenantId: String,
    val requestId: UUID,
    val action: WithdrawalReviewAction,
    val dualControlReceipt: DualControlReceipt? = null,
    val reasonNotes: String? = null,
    val idempotencyKey: String,
)
