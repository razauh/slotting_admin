package com.slotting.admin.rails

import org.junit.jupiter.api.Test
import java.math.BigDecimal
import java.sql.DriverManager
import java.util.UUID
import kotlin.test.assertEquals
import kotlin.test.assertTrue

class PayoutReplayIntegrationTest {
    private val url = System.getenv("PAYOUT_JDBC_URL") ?: "jdbc:postgresql://127.0.0.1:5432/slotting_admin_ci"
    private val user = System.getenv("PAYOUT_JDBC_USER") ?: "ci_runner"
    private fun connection() = DriverManager.getConnection(url, user, "")
    private val repository = JdbcPayoutRequestRepository { connection() }
    private val settings = PayoutSettings(BigDecimal("280"), BigDecimal("5"))
    private val flow = ManualPayoutFlow(repository, settings)
    private val tenant = "t-" + UUID.randomUUID()
    private val player = "p-" + UUID.randomUUID()

    private class IdempotentPoster : PayoutLedgerDebitPoster({}) {
        val posted = mutableMapOf<String, BigDecimal>()

        override fun post(tenantId: String, playerId: String, amountUsd: BigDecimal, feeUsd: BigDecimal, netUsd: BigDecimal, requestId: String) {
            posted.putIfAbsent(requestId, amountUsd)
        }
    }

    private fun cleanup() {
        connection().use { c ->
            c.prepareStatement("delete from public.payout_requests where tenant_id = ?").use { it.setString(1, tenant); it.executeUpdate() }
        }
    }

    private fun createRequest(): PayoutRequest {
        flow.request(tenant, player, BigDecimal("100.00"), BigDecimal("500.00"), "BANK", "T", "123")
        val rows = repository.listMine(tenant, player)
        val row = rows.first()
        repository.markLocked(row.id, "admin")
        repository.updateReceiptObject(row.id, "tenant/t/receipt.png")
        return repository.find(row.id)!!
    }

    @Test
    fun `mark paid posts exactly once and stamps paid`() {
        cleanup()
        try {
            val row = createRequest()
            val poster = IdempotentPoster()
            val debit = ManualPayoutLedgerDebitFlow(repository, poster)

            assertEquals(PayoutOutcome.PAID, debit.markPaid(row.id, "admin").outcome)
            assertEquals(1, poster.posted.size)
            assertEquals(PayoutStatus.PAID, repository.find(row.id)!!.status)
        } finally {
            cleanup()
        }
    }

    @Test
    fun `crash between post and stamp heals with one posting on replay`() {
        cleanup()
        try {
            val row = createRequest()
            val poster = IdempotentPoster()
            poster.post(row.tenantId, row.playerId, row.amountUsd, row.feeUsd, row.netUsd, row.id)
            val debit = ManualPayoutLedgerDebitFlow(repository, poster)

            assertEquals(PayoutOutcome.PAID, debit.markPaid(row.id, "admin").outcome)
            assertEquals(1, poster.posted.size)
            assertEquals(PayoutStatus.PAID, repository.find(row.id)!!.status)
        } finally {
            cleanup()
        }
    }

    @Test
    fun `double mark paid keeps a single posting`() {
        cleanup()
        try {
            val row = createRequest()
            val poster = IdempotentPoster()
            val debit = ManualPayoutLedgerDebitFlow(repository, poster)

            debit.markPaid(row.id, "admin")
            debit.markPaid(row.id, "admin")

            assertEquals(1, poster.posted.size)
        } finally {
            cleanup()
        }
    }

    @Test
    fun `insufficient request inserts nothing and a funded request does`() {
        cleanup()
        try {
            val refused = flow.request(tenant, player, BigDecimal("100.00"), BigDecimal("50.00"), "BANK", "T", "1")
            assertEquals(PayoutOutcome.INSUFFICIENT_AVAILABLE_BALANCE, refused.outcome)
            assertTrue(repository.listMine(tenant, player).isEmpty())

            val created = flow.request(tenant, player, BigDecimal("100.00"), BigDecimal("500.00"), "BANK", "T", "1")
            assertEquals(PayoutOutcome.CREATED, created.outcome)
            assertEquals(1, repository.listMine(tenant, player).size)
        } finally {
            cleanup()
        }
    }
}
