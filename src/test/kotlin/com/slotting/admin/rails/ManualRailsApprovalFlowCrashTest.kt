package com.slotting.admin.rails

import org.junit.jupiter.api.Test
import java.math.BigDecimal
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith

class ManualRailsApprovalFlowCrashTest {
    private class FakeRepository : DepositSubmissionRepository {
        val submissions = mutableMapOf<String, DepositSubmission>()
        override fun find(id: String) = submissions[id]
        override fun markApproved(id: String, rate: BigDecimal, usd: BigDecimal, by: String): Boolean {
            val current = submissions[id] ?: return false
            if (current.status != SubmissionStatus.SUBMITTED) return false
            submissions[id] = current.copy(status = SubmissionStatus.APPROVED, rateApplied = rate, amountUsd = usd)
            return true
        }
        override fun markRejected(id: String, reason: String, by: String) = false
        override fun hasApprovedDeposit(playerId: String) = false
        override fun insert(submission: DepositSubmission, fundingAccountId: String, transferReference: String, transferredUtc: java.time.Instant, receiptObject: String) {
            submissions[submission.id] = submission
        }
        override fun listByStatus(tenantId: String, status: SubmissionStatus): List<DepositSubmission> = emptyList()
        override fun listMine(tenantId: String, playerId: String): List<DepositSubmission> = emptyList()
        override fun revertApproval(id: String): Boolean {
            val current = submissions[id] ?: return false
            submissions[id] = current.copy(status = SubmissionStatus.SUBMITTED)
            return true
        }
    }

    private class IdempotentPoster : DepositCreditPoster {
        val posted = mutableMapOf<String, BigDecimal>()

        override fun post(tenantId: String, playerId: String, amountUsd: BigDecimal, submissionId: String) {
            val existing = posted[submissionId]
            if (existing != null) {
                if (existing.compareTo(amountUsd) == 0) return
                throw IllegalStateException("IDEMPOTENCY_CONFLICT")
            }
            posted[submissionId] = amountUsd
        }
    }

    private fun crashState(repo: FakeRepository, usd: String = "10.00") {
        repo.submissions["s1"] = DepositSubmission(
            id = "s1",
            tenantId = "t1",
            playerId = "p1",
            amountPkr = BigDecimal("2800"),
            status = SubmissionStatus.APPROVED,
            rateApplied = BigDecimal("280"),
            amountUsd = BigDecimal(usd),
        )
    }

    @Test
    fun `crash stranded approved row is healed with exactly one posting across two calls`() {
        val repo = FakeRepository().apply { crashState(this) }
        val poster = IdempotentPoster()
        val service = ManualRailsService(repo, { BigDecimal("280") }) { player, usd -> poster.post("t1", player, usd, "s1") }
        val flow = ManualRailsApprovalFlow(repo, service, poster)

        val first = flow.approve("s1", "admin")
        val second = flow.approve("s1", "admin")

        assertEquals(ApprovalOutcome.APPROVED, first.outcome)
        assertEquals(ApprovalOutcome.APPROVED, second.outcome)
        assertEquals(1, poster.posted.size)
        assertEquals(BigDecimal("10.00"), poster.posted["s1"])
    }

    @Test
    fun `changed payload on replay surfaces the idempotency conflict`() {
        val repo = FakeRepository().apply { crashState(this) }
        val poster = IdempotentPoster()
        poster.post("t1", "p1", BigDecimal("9.00"), "s1")
        val service = ManualRailsService(repo, { BigDecimal("280") }) { player, usd -> poster.post("t1", player, usd, "s1") }

        assertFailsWith<IllegalStateException> {
            ManualRailsApprovalFlow(repo, service, poster).approve("s1", "admin")
        }
    }

    @Test
    fun `rejected and missing rows never reach the poster`() {
        val repo = FakeRepository()
        repo.submissions["s1"] = DepositSubmission("s1", "t1", "p1", BigDecimal("2800"), SubmissionStatus.REJECTED)
        val poster = IdempotentPoster()
        val flow = ManualRailsApprovalFlow(repo, ManualRailsService(repo, { BigDecimal("280") }) { _, _ -> }, poster)

        assertEquals(ApprovalOutcome.ALREADY_DECIDED, flow.approve("s1", "admin").outcome)
        assertEquals(ApprovalOutcome.NOT_FOUND, flow.approve("missing", "admin").outcome)
        assertEquals(0, poster.posted.size)
    }
}
