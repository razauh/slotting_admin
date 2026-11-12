package com.slotting.admin.rails

import org.junit.jupiter.api.Test
import java.math.BigDecimal
import java.sql.DriverManager
import java.time.Instant
import java.util.UUID
import kotlin.test.assertEquals

class JdbcDepositGateTest {
    private val url = System.getenv("RAILS_JDBC_URL") ?: "jdbc:postgresql://127.0.0.1:55433/slotting_restore"
    private val user = System.getenv("RAILS_JDBC_USER") ?: "ci_runner"
    private fun connection() = DriverManager.getConnection(url, user, "")
    private val submissions = JdbcDepositSubmissionRepository { connection() }
    private val accounts = JdbcFundingAccountsRepository { connection() }
    private val gate = DepositGate(submissions)
    private val tenant = "t-" + UUID.randomUUID()
    private val player = "p-" + UUID.randomUUID()

    private fun seedSubmission(): String {
        val accountId = UUID.randomUUID().toString()
        accounts.insert(FundingAccount(accountId, tenant, "BANK", "Title", "123", null, 0))
        val id = UUID.randomUUID().toString()
        submissions.insert(
            DepositSubmission(id, tenant, player, BigDecimal("2800"), SubmissionStatus.SUBMITTED),
            accountId,
            "REF",
            Instant.now(),
            "tenant/x/receipt.png",
        )
        return id
    }

    private fun cleanup() {
        connection().use { c ->
            c.prepareStatement("delete from public.deposit_submissions where tenant_id = ?").use { it.setString(1, tenant); it.executeUpdate() }
            c.prepareStatement("delete from public.funding_accounts where tenant_id = ?").use { it.setString(1, tenant); it.executeUpdate() }
        }
    }

    @Test
    fun `gate denies without approval and allows after approval through jdbc`() {
        cleanup()
        try {
            val id = seedSubmission()

            assertEquals(GateDecision.DENIED, gate.check(player).decision)
            assertEquals("NO_VERIFIED_DEPOSIT", gate.check(player).code)

            submissions.markApproved(id, BigDecimal("280"), BigDecimal("10.00"), "admin")

            assertEquals(GateDecision.ALLOWED, gate.check(player).decision)
        } finally {
            cleanup()
        }
    }
}
