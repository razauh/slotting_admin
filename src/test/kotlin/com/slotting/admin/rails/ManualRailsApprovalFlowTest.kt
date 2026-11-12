package com.slotting.admin.rails

import com.slotting.admin.auth.AdminRole
import com.slotting.admin.auth.AuthenticatedPrincipal
import com.slotting.admin.auth.PrincipalKind
import com.slotting.admin.ledger.JournalEntryDirection
import com.slotting.admin.ledger.PostTransactionCommand
import org.junit.jupiter.api.Test
import java.math.BigDecimal
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertTrue

class ManualRailsApprovalFlowTest {
    private class FakeRepository : DepositSubmissionRepository {
        val submissions = mutableMapOf<String, DepositSubmission>()

        override fun find(id: String) = submissions[id]
        override fun markApproved(id: String, rate: BigDecimal, usd: BigDecimal, by: String): Boolean {
            val current = submissions[id] ?: return false
            if (current.status != SubmissionStatus.SUBMITTED) return false
            submissions[id] = current.copy(status = SubmissionStatus.APPROVED, rateApplied = rate, amountUsd = usd)
            return true
        }
        override fun markRejected(id: String, reason: String, by: String): Boolean = false
        override fun hasApprovedDeposit(playerId: String) = false
        override fun insert(submission: DepositSubmission, fundingAccountId: String, transferReference: String, transferredUtc: java.time.Instant, receiptObject: String) {
            submissions[submission.id] = submission
        }
        override fun listByStatus(tenantId: String, status: SubmissionStatus): List<DepositSubmission> = emptyList()
        override fun listMine(tenantId: String, playerId: String): List<DepositSubmission> = emptyList()
        override fun revertApproval(id: String): Boolean {
            val current = submissions[id] ?: return false
            submissions[id] = current.copy(status = SubmissionStatus.SUBMITTED, rateApplied = null, amountUsd = null)
            return true
        }
    }

    private fun submission(id: String = "s1") = DepositSubmission(
        id = id,
        tenantId = "t1",
        playerId = "p1",
        amountPkr = BigDecimal("2800"),
        status = SubmissionStatus.SUBMITTED,
    )

    @Test
    fun `approval posts one usd credit with the submission correlation`() {
        val repo = FakeRepository().apply { submissions["s1"] = submission() }
        val posted = mutableListOf<Triple<String, String, BigDecimal>>()
        val poster = object : DepositCreditPoster {
            override fun post(tenantId: String, playerId: String, amountUsd: BigDecimal, submissionId: String) {
                posted += Triple(tenantId, submissionId, amountUsd)
            }
        }
        val flow = ManualRailsApprovalFlow(
            repo,
            ManualRailsService(repo, { BigDecimal("280") }) { playerId, usd -> poster.post("t1", playerId, usd, "s1") },
            poster,
        )

        val result = flow.approve("s1", "admin")

        assertEquals(ApprovalOutcome.APPROVED, result.outcome)
        assertEquals(1, posted.size)
        assertEquals("t1", posted.single().first)
        assertEquals("s1", posted.single().second)
        assertEquals(BigDecimal("10.00"), posted.single().third)
        assertEquals(SubmissionStatus.APPROVED, repo.submissions["s1"]!!.status)
    }

    @Test
    fun `poster failure reverts the submission to submitted`() {
        val repo = FakeRepository().apply { submissions["s1"] = submission() }
        val poster = object : DepositCreditPoster {
            override fun post(tenantId: String, playerId: String, amountUsd: BigDecimal, submissionId: String) {
                throw IllegalStateException("ledger unavailable")
            }
        }
        val flow = ManualRailsApprovalFlow(
            repo,
            ManualRailsService(repo, { BigDecimal("280") }) { playerId, usd -> poster.post("t1", playerId, usd, "s1") },
            poster,
        )

        assertFailsWith<IllegalStateException> { flow.approve("s1", "admin") }
        assertEquals(SubmissionStatus.SUBMITTED, repo.submissions["s1"]!!.status)
    }

    @Test
    fun `double approval posts once`() {
        val repo = FakeRepository().apply { submissions["s1"] = submission() }
        val calls = linkedSetOf<String>()
        val poster = object : DepositCreditPoster {
            override fun post(tenantId: String, playerId: String, amountUsd: BigDecimal, submissionId: String) {
                calls += submissionId
            }
        }
        val flow = ManualRailsApprovalFlow(
            repo,
            ManualRailsService(repo, { BigDecimal("280") }) { playerId, usd -> poster.post("t1", playerId, usd, "s1") },
            poster,
        )

        flow.approve("s1", "admin")
        val second = flow.approve("s1", "admin")

        assertEquals(ApprovalOutcome.APPROVED, second.outcome)
        assertEquals(1, calls.size)
    }

    @Test
    fun `ledger poster builds balanced usd legs and the submission reference`() {
        var captured: PostTransactionCommand? = null
        val poster = LedgerDepositCreditPoster { captured = it }

        poster.post("t1", "p1", BigDecimal("10.00"), "sub-1")

        val command = captured!!
        assertEquals("USD", command.currencyCode)
        assertEquals("TX-MANUAL-DEP-sub-1", command.transactionReference)
        assertTrue(command.idempotencyKey.contains("sub-1"))
        val debit = command.entries.single { it.direction == JournalEntryDirection.DEBIT }
        val credit = command.entries.single { it.direction == JournalEntryDirection.CREDIT }
        assertEquals(1000L, debit.amountMinorUnits)
        assertEquals(1000L, credit.amountMinorUnits)
        assertTrue(credit.accountReference.contains("PLAYER:p1"))
        assertEquals(PrincipalKind.ADMIN, command.principal?.kind)
        assertEquals(setOf(AdminRole.SUPER_ADMIN), command.principal?.roles)
    }
}
