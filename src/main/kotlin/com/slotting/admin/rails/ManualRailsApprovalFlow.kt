package com.slotting.admin.rails

import com.slotting.admin.auth.AdminRole
import com.slotting.admin.auth.AuthenticatedPrincipal
import com.slotting.admin.auth.PrincipalKind
import com.slotting.admin.ledger.JournalEntryDirection
import com.slotting.admin.ledger.JournalEntryDraft
import com.slotting.admin.ledger.LedgerPostingService
import com.slotting.admin.ledger.PostTransactionCommand
import java.math.BigDecimal

interface DepositCreditPoster {
    fun post(tenantId: String, playerId: String, amountUsd: BigDecimal, submissionId: String)
}

class LedgerDepositCreditPoster(
    private val send: (PostTransactionCommand) -> Unit,
) : DepositCreditPoster {
    constructor(ledgerPostingService: LedgerPostingService) : this({ ledgerPostingService.postTransaction(it) })

    override fun post(tenantId: String, playerId: String, amountUsd: BigDecimal, submissionId: String) {
        val minorUnits = amountUsd.movePointRight(2).longValueExact()
        send(
            PostTransactionCommand(
                principal = AuthenticatedPrincipal(
                    id = "sys-manual-rails",
                    tenantId = tenantId,
                    kind = PrincipalKind.ADMIN,
                    roles = setOf(AdminRole.SUPER_ADMIN),
                ),
                tenantId = tenantId,
                transactionReference = "TX-MANUAL-DEP-$submissionId",
                currencyCode = "USD",
                entries = listOf(
                    JournalEntryDraft(
                        accountReference = "house:funding:clearing",
                        direction = JournalEntryDirection.DEBIT,
                        amountMinorUnits = minorUnits,
                        currencyCode = "USD",
                    ),
                    JournalEntryDraft(
                        accountReference = "PLAYER:$playerId",
                        direction = JournalEntryDirection.CREDIT,
                        amountMinorUnits = minorUnits,
                        currencyCode = "USD",
                    ),
                ),
                idempotencyKey = "LEDGER-MANUAL-DEP-$submissionId",
                correlationId = "corr-$submissionId",
                causationId = "caus-$submissionId",
            ),
        )
    }
}

class ManualRailsApprovalFlow(
    private val repository: DepositSubmissionRepository,
    private val service: ManualRailsService,
    private val poster: DepositCreditPoster,
) {
    fun approve(id: String, adminId: String): ApprovalResult {
        val submission = repository.find(id) ?: return ApprovalResult(ApprovalOutcome.NOT_FOUND)
        if (submission.status == SubmissionStatus.REJECTED) {
            return ApprovalResult(ApprovalOutcome.ALREADY_DECIDED)
        }
        if (submission.status == SubmissionStatus.APPROVED) {
            val usd = submission.amountUsd ?: return ApprovalResult(ApprovalOutcome.ALREADY_DECIDED)
            poster.post(submission.tenantId, submission.playerId, usd, id)
            return ApprovalResult(ApprovalOutcome.APPROVED, usd, submission.rateApplied)
        }
        return try {
            service.approve(id, adminId)
        } catch (error: Exception) {
            repository.revertApproval(id)
            throw error
        }
    }
}
