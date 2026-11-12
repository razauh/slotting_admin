package com.slotting.admin.rails

import org.junit.jupiter.api.Test
import java.math.BigDecimal
import java.sql.DriverManager
import java.util.UUID
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue

class JdbcPayoutRequestRepositoryTest {
    private val url = System.getenv("PAYOUT_JDBC_URL") ?: "jdbc:postgresql://127.0.0.1:5432/slotting_admin_ci"
    private val user = System.getenv("PAYOUT_JDBC_USER") ?: "ci_runner"
    private fun connection() = DriverManager.getConnection(url, user, "")
    private val repository = JdbcPayoutRequestRepository { connection() }
    private val tenant = "t-" + UUID.randomUUID()
    private val player = "p-" + UUID.randomUUID()

    private fun row(id: String = UUID.randomUUID().toString()) = PayoutRequest(
        id = id, tenantId = tenant, playerId = player,
        amountUsd = BigDecimal("100.00"), feeUsd = BigDecimal("5.00"), netUsd = BigDecimal("95.00"),
        payoutRate = BigDecimal("280"), payoutPkr = BigDecimal("26600.00"),
        destType = "BANK", destTitle = "T", destNumber = "123", status = PayoutStatus.PENDING,
    )

    private fun cleanup() {
        connection().use { c ->
            c.prepareStatement("delete from public.payout_requests where tenant_id = ?").use { it.setString(1, tenant); it.executeUpdate() }
        }
    }

    @Test
    fun `insert lock paid round-trip`() {
        cleanup()
        try {
            val r = row()
            assertTrue(repository.insert(r))
            assertEquals(PayoutStatus.PENDING, repository.find(r.id)!!.status)
            assertTrue(repository.markLocked(r.id, "admin"))
            assertEquals(PayoutStatus.APPROVED_FUNDS_LOCKED, repository.find(r.id)!!.status)
            assertTrue(repository.markPaid(r.id, "admin"))
            assertEquals(PayoutStatus.PAID, repository.find(r.id)!!.status)
        } finally {
            cleanup()
        }
    }

    @Test
    fun `conditional transitions win once`() {
        cleanup()
        try {
            val r = row()
            repository.insert(r)
            assertTrue(repository.markLocked(r.id, "admin"))
            assertFalse(repository.markLocked(r.id, "admin"))
            assertTrue(repository.markPaid(r.id, "admin"))
            assertFalse(repository.markPaid(r.id, "admin"))
        } finally {
            cleanup()
        }
    }

    @Test
    fun `locked total counts pending and locked and excludes paid and rejected`() {
        cleanup()
        try {
            val a = row(); val b = row(); val c = row(); val d = row()
            repository.insert(a); repository.insert(b); repository.insert(c); repository.insert(d)
            repository.markLocked(b.id, "admin")
            repository.markLocked(c.id, "admin")
            repository.markPaid(c.id, "admin")
            repository.markRejected(d.id, "no", "admin")
            val total = repository.lockedTotal(tenant, player)
            assertEquals(0, BigDecimal("200.00").compareTo(total))
        } finally {
            cleanup()
        }
    }
}
