package com.slotting.admin.rails

import com.slotting.admin.auth.AdminRole
import com.slotting.admin.auth.AuthenticatedPrincipal
import com.slotting.admin.auth.PrincipalKind
import com.slotting.admin.ledger.JournalEntryDirection
import com.slotting.admin.ledger.JournalEntryDraft
import com.slotting.admin.ledger.LedgerPostingService
import com.slotting.admin.ledger.PostTransactionCommand
import java.math.BigDecimal

open class PayoutLedgerDebitPoster(
    private val send: (PostTransactionCommand) -> Unit,
) {
    constructor(ledgerPostingService: LedgerPostingService) : this({ ledgerPostingService.postTransaction(it) })

    open fun post(tenantId: String, playerId: String, amountUsd: BigDecimal, feeUsd: BigDecimal, netUsd: BigDecimal, requestId: String) {
        val amount = amountUsd.movePointRight(2).longValueExact()
        val fee = feeUsd.movePointRight(2).longValueExact()
        val net = netUsd.movePointRight(2).longValueExact()
        send(
            PostTransactionCommand(
                principal = AuthenticatedPrincipal(
                    id = "sys-manual-rails",
                    tenantId = tenantId,
                    kind = PrincipalKind.ADMIN,
                    roles = setOf(AdminRole.SUPER_ADMIN),
                ),
                tenantId = tenantId,
                transactionReference = "TX-MANUAL-PAYOUT-$requestId",
                currencyCode = "USD",
                entries = listOf(
                    JournalEntryDraft("PLAYER:$playerId", JournalEntryDirection.DEBIT, amount, "USD"),
                    JournalEntryDraft("house:funding:clearing", JournalEntryDirection.CREDIT, net, "USD"),
                    JournalEntryDraft("revenue:processing-fee", JournalEntryDirection.CREDIT, fee, "USD"),
                ),
                idempotencyKey = "LEDGER-MANUAL-PAYOUT-$requestId",
                correlationId = "corr-$requestId",
                causationId = "caus-$requestId",
            ),
        )
    }
}

class ManualPayoutLedgerDebitFlow(
    private val repository: PayoutRequestRepository,
    private val poster: PayoutLedgerDebitPoster,
) {
    fun markPaid(id: String, by: String): PayoutResult {
        val row = repository.find(id) ?: return PayoutResult(PayoutOutcome.NOT_FOUND)
        if (row.status != PayoutStatus.APPROVED_FUNDS_LOCKED && row.status != PayoutStatus.PAID) {
            return PayoutResult(PayoutOutcome.INVALID_STATE)
        }
        if (row.receiptObject.isNullOrBlank()) {
            return PayoutResult(PayoutOutcome.RECEIPT_REQUIRED, "receipt required before marking paid")
        }
        poster.post(row.tenantId, row.playerId, row.amountUsd, row.feeUsd, row.netUsd, id)
        if (row.status == PayoutStatus.PAID) {
            return PayoutResult(PayoutOutcome.PAID)
        }
        return if (repository.markPaid(id, by)) PayoutResult(PayoutOutcome.PAID) else PayoutResult(PayoutOutcome.ALREADY_DECIDED)
    }
}
