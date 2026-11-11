package com.slotting.admin.rails

import org.junit.jupiter.api.Test
import java.math.BigDecimal
import java.sql.DriverManager
import java.time.Instant
import java.util.UUID
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNotNull
import kotlin.test.assertTrue

class JdbcDepositSubmissionRepositoryTest {
    private val url = System.getenv("RAILS_JDBC_URL") ?: "jdbc:postgresql://127.0.0.1:55433/slotting_restore"
    private val user = System.getenv("RAILS_JDBC_USER") ?: "ci_runner"
    private fun connection() = DriverManager.getConnection(url, user, "")
    private val repository = JdbcDepositSubmissionRepository { connection() }
    private val accounts = JdbcFundingAccountsRepository { connection() }
    private val tenant = "t-" + UUID.randomUUID()
    private val player = "p-" + UUID.randomUUID()

    private fun account(): String {
        val id = UUID.randomUUID()
        accounts.insert(FundingAccount(id.toString(), tenant, "BANK", "Title", "123", null, 0))
        return id.toString()
    }

    private fun submission(id: String = UUID.randomUUID().toString(), accountId: String = account()) =
        DepositSubmission(
            id = id,
            tenantId = tenant,
            playerId = player,
            amountPkr = BigDecimal("2800.00"),
            status = SubmissionStatus.SUBMITTED,
        )

    private fun cleanup() {
        connection().use { c ->
            c.prepareStatement("delete from public.deposit_submissions where tenant_id = ?").use { it.setString(1, tenant); it.executeUpdate() }
            c.prepareStatement("delete from public.funding_accounts where tenant_id = ?").use { it.setString(1, tenant); it.executeUpdate() }
        }
    }

    @Test
    fun `insert and find round-trip`() {
        cleanup()
        try {
            val row = submission()
            repository.insert(row, account(), "REF-1", Instant.parse("2026-11-11T06:00:00Z"), "tenant/x/receipt.png")
            val found = repository.find(row.id)
            assertNotNull(found)
            assertEquals(SubmissionStatus.SUBMITTED, found.status)
            assertEquals(0, BigDecimal("2800.00").compareTo(found.amountPkr))
        } finally {
            cleanup()
        }
    }

    @Test
    fun `conditional approve wins once`() {
        cleanup()
        try {
            val row = submission()
            repository.insert(row, account(), "REF-2", Instant.parse("2026-11-11T06:00:00Z"), "tenant/x/receipt.png")
            assertTrue(repository.markApproved(row.id, BigDecimal("280"), BigDecimal("10.00"), "admin"))
            assertFalse(repository.markApproved(row.id, BigDecimal("280"), BigDecimal("10.00"), "admin"))
        } finally {
            cleanup()
        }
    }

    @Test
    fun `has approved deposit reflects approved rows only`() {
        cleanup()
        try {
            val row = submission()
            repository.insert(row, account(), "REF-3", Instant.parse("2026-11-11T06:00:00Z"), "tenant/x/receipt.png")
            assertFalse(repository.hasApprovedDeposit(player))
            repository.markApproved(row.id, BigDecimal("280"), BigDecimal("10.00"), "admin")
            assertTrue(repository.hasApprovedDeposit(player))
        } finally {
            cleanup()
        }
    }

    @Test
    fun `list by status and mine return the row`() {
        cleanup()
        try {
            val row = submission()
            repository.insert(row, account(), "REF-4", Instant.parse("2026-11-11T06:00:00Z"), "tenant/x/receipt.png")
            assertEquals(1, repository.listByStatus(tenant, SubmissionStatus.SUBMITTED).size)
            assertEquals(1, repository.listMine(tenant, player).size)
        } finally {
            cleanup()
        }
    }

    @Test
    fun `reject only applies to submitted rows`() {
        cleanup()
        try {
            val row = submission()
            repository.insert(row, account(), "REF-5", Instant.parse("2026-11-11T06:00:00Z"), "tenant/x/receipt.png")
            assertTrue(repository.markRejected(row.id, "mismatch", "admin"))
            assertFalse(repository.markRejected(row.id, "again", "admin"))
        } finally {
            cleanup()
        }
    }
}
