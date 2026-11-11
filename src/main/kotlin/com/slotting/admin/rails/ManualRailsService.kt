package com.slotting.admin.rails

import java.math.BigDecimal
import java.math.RoundingMode

enum class SubmissionStatus {
    SUBMITTED,
    APPROVED,
    REJECTED,
}

data class DepositSubmission(
    val id: String,
    val tenantId: String,
    val playerId: String,
    val amountPkr: BigDecimal,
    val status: SubmissionStatus,
    val rateApplied: BigDecimal? = null,
    val amountUsd: BigDecimal? = null,
    val rejectReason: String? = null,
)

interface DepositSubmissionRepository {
    fun find(id: String): DepositSubmission?

    fun markApproved(id: String, rate: BigDecimal, usd: BigDecimal, by: String): Boolean

    fun markRejected(id: String, reason: String, by: String): Boolean

    fun hasApprovedDeposit(playerId: String): Boolean

    fun insert(
        submission: DepositSubmission,
        fundingAccountId: String,
        transferReference: String,
        transferredUtc: java.time.Instant,
        receiptObject: String,
    )

    fun listByStatus(tenantId: String, status: SubmissionStatus): List<DepositSubmission>

    fun listMine(tenantId: String, playerId: String): List<DepositSubmission>
}

enum class ApprovalOutcome {
    APPROVED,
    ALREADY_DECIDED,
    NOT_FOUND,
}

data class ApprovalResult(
    val outcome: ApprovalOutcome,
    val amountUsd: BigDecimal? = null,
    val rateApplied: BigDecimal? = null,
)

class ManualRailsService(
    private val repository: DepositSubmissionRepository,
    private val depositRate: () -> BigDecimal,
    private val credit: (playerId: String, amountUsd: BigDecimal) -> Unit,
) {
    fun approve(id: String, adminId: String): ApprovalResult {
        val submission = repository.find(id) ?: return ApprovalResult(ApprovalOutcome.NOT_FOUND)
        if (submission.status != SubmissionStatus.SUBMITTED) {
            return ApprovalResult(ApprovalOutcome.ALREADY_DECIDED)
        }
        val rate = depositRate()
        val usd = submission.amountPkr.divide(rate, 2, RoundingMode.HALF_UP)
        if (!repository.markApproved(id, rate, usd, adminId)) {
            return ApprovalResult(ApprovalOutcome.ALREADY_DECIDED)
        }
        credit(submission.playerId, usd)
        return ApprovalResult(ApprovalOutcome.APPROVED, usd, rate)
    }

    fun reject(id: String, reason: String, adminId: String): ApprovalResult {
        val submission = repository.find(id) ?: return ApprovalResult(ApprovalOutcome.NOT_FOUND)
        if (submission.status != SubmissionStatus.SUBMITTED) {
            return ApprovalResult(ApprovalOutcome.ALREADY_DECIDED)
        }
        if (!repository.markRejected(id, reason, adminId)) {
            return ApprovalResult(ApprovalOutcome.ALREADY_DECIDED)
        }
        return ApprovalResult(ApprovalOutcome.APPROVED)
    }
}

enum class GateDecision {
    ALLOWED,
    DENIED,
}

data class GateResult(
    val decision: GateDecision,
    val code: String? = null,
    val message: String = "",
)

class DepositGate(
    private val repository: DepositSubmissionRepository,
) {
    fun check(playerId: String): GateResult =
        if (repository.hasApprovedDeposit(playerId)) {
            GateResult(GateDecision.ALLOWED, message = "verified deposit present")
        } else {
            GateResult(
                GateDecision.DENIED,
                code = "NO_VERIFIED_DEPOSIT",
                message = "a verified deposit is required before placing bets",
            )
        }
}
