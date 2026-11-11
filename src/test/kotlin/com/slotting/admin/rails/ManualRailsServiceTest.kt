package com.slotting.admin.rails

import org.junit.jupiter.api.Test
import java.math.BigDecimal
import kotlin.test.assertEquals
import kotlin.test.assertTrue

class ManualRailsServiceTest {
    private class FakeRepository : DepositSubmissionRepository {
        val submissions = mutableMapOf<String, DepositSubmission>()
        var approvedCount = 0

        override fun find(id: String) = submissions[id]
        override fun markApproved(id: String, rate: BigDecimal, usd: BigDecimal, by: String): Boolean {
            val current = submissions[id] ?: return false
            if (current.status != SubmissionStatus.SUBMITTED) return false
            submissions[id] = current.copy(status = SubmissionStatus.APPROVED, rateApplied = rate, amountUsd = usd)
            return true
        }
        override fun markRejected(id: String, reason: String, by: String): Boolean {
            val current = submissions[id] ?: return false
            if (current.status != SubmissionStatus.SUBMITTED) return false
            submissions[id] = current.copy(status = SubmissionStatus.REJECTED, rejectReason = reason)
            return true
        }
        override fun hasApprovedDeposit(playerId: String): Boolean =
            submissions.values.any { it.playerId == playerId && it.status == SubmissionStatus.APPROVED }
        override fun insert(
            submission: DepositSubmission,
            fundingAccountId: String,
            transferReference: String,
            transferredUtc: java.time.Instant,
            receiptObject: String,
        ) {
            submissions[submission.id] = submission
        }
        override fun listByStatus(tenantId: String, status: SubmissionStatus): List<DepositSubmission> =
            submissions.values.filter { it.tenantId == tenantId && it.status == status }
        override fun listMine(tenantId: String, playerId: String): List<DepositSubmission> =
            submissions.values.filter { it.tenantId == tenantId && it.playerId == playerId }
    }

    private fun submission(id: String, playerId: String, pkr: String) = DepositSubmission(
        id = id,
        tenantId = "t1",
        playerId = playerId,
        amountPkr = BigDecimal(pkr),
        status = SubmissionStatus.SUBMITTED,
    )

    @Test
    fun `approval applies the rate and rounds to two decimals`() {
        val repo = FakeRepository().apply { submissions["s1"] = submission("s1", "p1", "1000") }
        val credited = mutableListOf<BigDecimal>()
        val service = ManualRailsService(repo, { BigDecimal("280") }) { _, usd -> credited += usd }

        val result = service.approve("s1", "admin")

        assertEquals(ApprovalOutcome.APPROVED, result.outcome)
        assertEquals(BigDecimal("3.57"), result.amountUsd)
        assertEquals(listOf(BigDecimal("3.57")), credited)
    }

    @Test
    fun `rate is read at approval time so later changes give different credits`() {
        val repo = FakeRepository().apply {
            submissions["s1"] = submission("s1", "p1", "2800")
            submissions["s2"] = submission("s2", "p2", "2800")
        }
        val credited = mutableListOf<BigDecimal>()
        var rate = BigDecimal("280")
        val service = ManualRailsService(repo, { rate }) { _, usd -> credited += usd }

        service.approve("s1", "admin")
        rate = BigDecimal("300")
        service.approve("s2", "admin")

        assertEquals(BigDecimal("10.00"), credited[0])
        assertEquals(BigDecimal("9.33"), credited[1])
    }

    @Test
    fun `double approval credits once`() {
        val repo = FakeRepository().apply { submissions["s1"] = submission("s1", "p1", "1000") }
        val credits = mutableListOf<BigDecimal>()
        val service = ManualRailsService(repo, { BigDecimal("280") }) { _, usd -> credits += usd }

        val first = service.approve("s1", "admin")
        val second = service.approve("s1", "admin")

        assertEquals(ApprovalOutcome.APPROVED, first.outcome)
        assertEquals(ApprovalOutcome.ALREADY_DECIDED, second.outcome)
        assertEquals(1, credits.size)
    }

    @Test
    fun `reject after approve is refused and changes nothing`() {
        val repo = FakeRepository().apply { submissions["s1"] = submission("s1", "p1", "1000") }
        val service = ManualRailsService(repo, { BigDecimal("280") }) { _, _ -> }

        service.approve("s1", "admin")
        val rejected = service.reject("s1", "late", "admin")

        assertEquals(ApprovalOutcome.ALREADY_DECIDED, rejected.outcome)
        assertEquals(SubmissionStatus.APPROVED, repo.submissions["s1"]!!.status)
    }

    @Test
    fun `gate refuses a player without an approved deposit`() {
        val repo = FakeRepository()
        val gate = DepositGate(repo)

        val decision = gate.check("p1")

        assertEquals(GateDecision.DENIED, decision.decision)
        assertEquals("NO_VERIFIED_DEPOSIT", decision.code)
        assertTrue(decision.message.contains("verified deposit"))
    }

    @Test
    fun `gate allows a player with an approved deposit`() {
        val repo = FakeRepository().apply { submissions["s1"] = submission("s1", "p1", "1000") }
        val service = ManualRailsService(repo, { BigDecimal("280") }) { _, _ -> }
        service.approve("s1", "admin")

        assertEquals(GateDecision.ALLOWED, DepositGate(repo).check("p1").decision)
    }
}
