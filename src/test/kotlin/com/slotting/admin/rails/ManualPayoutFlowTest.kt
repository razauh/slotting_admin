package com.slotting.admin.rails

import org.junit.jupiter.api.Test
import java.math.BigDecimal
import java.util.UUID
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue

class ManualPayoutFlowTest {
    private class FakeRepo : PayoutRequestRepository {
        val rows = mutableMapOf<String, PayoutRequest>()
        var locked = BigDecimal.ZERO
        var inserts = 0
        override fun insert(request: PayoutRequest): Boolean {
            inserts += 1
            rows[request.id] = request
            return true
        }
        override fun find(id: String) = rows[id]
        override fun lockedTotal(tenantId: String, playerId: String) = locked
        override fun markLocked(id: String, by: String): Boolean {
            val row = rows[id] ?: return false
            if (row.status != PayoutStatus.PENDING) return false
            rows[id] = row.copy(status = PayoutStatus.APPROVED_FUNDS_LOCKED)
            return true
        }
        override fun markPaid(id: String, by: String): Boolean {
            val row = rows[id] ?: return false
            if (row.status != PayoutStatus.APPROVED_FUNDS_LOCKED) return false
            rows[id] = row.copy(status = PayoutStatus.PAID)
            return true
        }
        override fun markRejected(id: String, reason: String, by: String): Boolean {
            val row = rows[id] ?: return false
            if (row.status != PayoutStatus.PENDING && row.status != PayoutStatus.APPROVED_FUNDS_LOCKED) return false
            rows[id] = row.copy(status = PayoutStatus.REJECTED)
            return true
        }
    }

    private class FakePoster : PayoutLedgerDebitPoster({}) {
        val posted = mutableMapOf<String, BigDecimal>()
        override fun post(tenantId: String, playerId: String, amountUsd: BigDecimal, feeUsd: BigDecimal, netUsd: BigDecimal, requestId: String) {
            posted.putIfAbsent(requestId, amountUsd)
        }
    }

    private fun flow(repo: FakeRepo, fee: String = "5", rate: String = "280") =
        ManualPayoutFlow(repo, PayoutSettings(BigDecimal(rate), BigDecimal(fee)))

    @Test
    fun `quote computes fee net and pkr with 2dp rounding`() {
        val repo = FakeRepo()
        val result = flow(repo).request("t1", "p1", BigDecimal("100.00"), BigDecimal("500.00"), "BANK", "T", "123")

        assertEquals(PayoutOutcome.CREATED, result.outcome)
        assertEquals(BigDecimal("5.00"), result.quote!!.feeUsd)
        assertEquals(BigDecimal("95.00"), result.quote!!.netUsd)
        assertEquals(BigDecimal("26600.00"), result.quote!!.payoutPkr)
        assertEquals(1, repo.inserts)
    }

    @Test
    fun `zero fee keeps the full amount`() {
        val result = flow(FakeRepo(), fee = "0").request("t1", "p1", BigDecimal("10.00"), BigDecimal("50.00"), "BANK", "T", "1")
        assertEquals(BigDecimal("0.00"), result.quote!!.feeUsd)
        assertEquals(BigDecimal("10.00"), result.quote!!.netUsd)
    }

    @Test
    fun `insufficient balance refuses with no insert`() {
        val repo = FakeRepo()
        val result = flow(repo).request("t1", "p1", BigDecimal("100.00"), BigDecimal("50.00"), "BANK", "T", "1")

        assertEquals(PayoutOutcome.INSUFFICIENT_AVAILABLE_BALANCE, result.outcome)
        assertEquals(0, repo.inserts)
    }

    @Test
    fun `pending locks are counted against the available balance`() {
        val repo = FakeRepo().apply { locked = BigDecimal("60.00") }
        val result = flow(repo).request("t1", "p1", BigDecimal("50.00"), BigDecimal("100.00"), "BANK", "T", "1")

        assertEquals(PayoutOutcome.INSUFFICIENT_AVAILABLE_BALANCE, result.outcome)
        assertEquals(0, repo.inserts)
    }

    @Test
    fun `lock is conditional and double lock has one winner`() {
        val repo = FakeRepo()
        val id = flow(repo).request("t1", "p1", BigDecimal("10.00"), BigDecimal("50.00"), "BANK", "T", "1")
            .let { repo.rows.keys.first() }

        assertEquals(PayoutOutcome.LOCKED, flow(repo).lock(id, "admin").outcome)
        assertEquals(PayoutOutcome.ALREADY_DECIDED, flow(repo).lock(id, "admin").outcome)
    }

    @Test
    fun `reject after lock unlocks the funds`() {
        val repo = FakeRepo()
        val id = flow(repo).request("t1", "p1", BigDecimal("10.00"), BigDecimal("50.00"), "BANK", "T", "1")
            .let { repo.rows.keys.first() }
        flow(repo).lock(id, "admin")

        assertEquals(PayoutOutcome.REJECTED, flow(repo).reject(id, "mismatch", "admin").outcome)
        assertEquals(PayoutStatus.REJECTED, repo.rows[id]!!.status)
    }

    @Test
    fun `mark paid requires a receipt and posts once`() {
        val repo = FakeRepo()
        val id = flow(repo).request("t1", "p1", BigDecimal("100.00"), BigDecimal("500.00"), "BANK", "T", "1")
            .let { repo.rows.keys.first() }
        flow(repo).lock(id, "admin")
        val poster = FakePoster()
        val debit = ManualPayoutLedgerDebitFlow(repo, poster)

        val refused = debit.markPaid(id, "admin")
        assertEquals(PayoutOutcome.RECEIPT_REQUIRED, refused.outcome)
        assertTrue(poster.posted.isEmpty())

        repo.rows[id] = repo.rows[id]!!.copy(receiptObject = "tenant/t/receipt.png")
        assertEquals(PayoutOutcome.PAID, debit.markPaid(id, "admin").outcome)
        assertEquals(1, poster.posted.size)

        assertEquals(PayoutOutcome.PAID, debit.markPaid(id, "admin").outcome)
        assertEquals(1, poster.posted.size)
        assertFalse(repo.rows[id]!!.status == PayoutStatus.APPROVED_FUNDS_LOCKED)
    }

    @Test
    fun `debit poster builds the three balanced legs`() {
        var captured: com.slotting.admin.ledger.PostTransactionCommand? = null
        PayoutLedgerDebitPoster { captured = it }.post("t1", "p1", BigDecimal("100.00"), BigDecimal("5.00"), BigDecimal("95.00"), "req-1")

        val command = captured!!
        assertEquals("USD", command.currencyCode)
        assertEquals("TX-MANUAL-PAYOUT-req-1", command.transactionReference)
        assertEquals("LEDGER-MANUAL-PAYOUT-req-1", command.idempotencyKey)
        assertEquals(3, command.entries.size)
        val debit = command.entries.single { it.direction == com.slotting.admin.ledger.JournalEntryDirection.DEBIT }
        assertEquals(10000L, debit.amountMinorUnits)
        assertEquals(9500L + 500L, command.entries.filter { it.direction == com.slotting.admin.ledger.JournalEntryDirection.CREDIT }.sumOf { it.amountMinorUnits })
    }
}
