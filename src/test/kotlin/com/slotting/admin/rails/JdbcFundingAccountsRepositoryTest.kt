package com.slotting.admin.rails

import org.junit.jupiter.api.Test
import java.math.BigDecimal
import java.sql.DriverManager
import java.time.Instant
import java.util.UUID
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue

class JdbcFundingAccountsRepositoryTest {
    private val url = System.getenv("RAILS_JDBC_URL") ?: "jdbc:postgresql://127.0.0.1:55433/slotting_restore"
    private val user = System.getenv("RAILS_JDBC_USER") ?: "ci_runner"
    private fun connection() = DriverManager.getConnection(url, user, "")
    private val accounts = JdbcFundingAccountsRepository { connection() }
    private val submissions = JdbcDepositSubmissionRepository { connection() }
    private val tenant = "t-" + UUID.randomUUID()

    private fun cleanup() {
        connection().use { c ->
            c.prepareStatement("delete from public.deposit_submissions where tenant_id = ?").use { it.setString(1, tenant); it.executeUpdate() }
            c.prepareStatement("delete from public.funding_accounts where tenant_id = ?").use { it.setString(1, tenant); it.executeUpdate() }
        }
    }

    @Test
    fun `visible filter hides hidden accounts from players`() {
        cleanup()
        try {
            accounts.insert(FundingAccount(UUID.randomUUID().toString(), tenant, "BANK", "Visible", "111", null, 1))
            accounts.insert(FundingAccount(UUID.randomUUID().toString(), tenant, "RAAST", "Hidden", "222", null, 2).copy(visible = false))
            assertEquals(1, accounts.listVisible(tenant).size)
            assertEquals(2, accounts.listAll(tenant).size)
        } finally {
            cleanup()
        }
    }

    @Test
    fun `delete is refused while a submission references the account`() {
        cleanup()
        try {
            val accountId = UUID.randomUUID().toString()
            accounts.insert(FundingAccount(accountId, tenant, "BANK", "Referenced", "333", null, 0))
            submissions.insert(
                DepositSubmission(UUID.randomUUID().toString(), tenant, "p1", BigDecimal("100.00"), SubmissionStatus.SUBMITTED),
                accountId,
                "REF",
                Instant.now(),
                "tenant/x/receipt.png",
            )
            assertFalse(accounts.deleteIfUnreferenced(accountId))
        } finally {
            cleanup()
        }
    }

    @Test
    fun `unreferenced account can be deleted`() {
        cleanup()
        try {
            val accountId = UUID.randomUUID().toString()
            accounts.insert(FundingAccount(accountId, tenant, "JAZZCASH", "Free", "444", null, 0))
            assertTrue(accounts.deleteIfUnreferenced(accountId))
        } finally {
            cleanup()
        }
    }
}
