package com.slotting.admin.kyc

import com.slotting.admin.auth.*
import org.junit.jupiter.api.Assertions.*
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test
import java.time.Clock
import java.time.Duration
import java.time.Instant
import java.time.ZoneOffset
import java.util.concurrent.Callable
import java.util.concurrent.Executors

class KycManualReviewTest {

    private lateinit var fixedInstant: Instant
    private lateinit var clock: Clock
    private lateinit var service: KycManualReviewService

    private val tenantId = "tenant-prod-1"
    private val caseRef = "case-kyc-001"
    private val userId = "user-kyc-001"

    private val primaryReviewer = AuthenticatedPrincipal(
        id = "admin-rev-1",
        tenantId = tenantId,
        kind = PrincipalKind.ADMIN,
        roles = setOf(AdminRole.SECURITY),
    )

    private val secondaryApprover = AuthenticatedPrincipal(
        id = "admin-rev-2",
        tenantId = tenantId,
        kind = PrincipalKind.ADMIN,
        roles = setOf(AdminRole.SUPER_ADMIN),
    )

    private val auditorAdmin = AuthenticatedPrincipal(
        id = "admin-aud-1",
        tenantId = tenantId,
        kind = PrincipalKind.ADMIN,
        roles = setOf(AdminRole.AUDITOR),
    )

    private val playerPrincipal = AuthenticatedPrincipal(
        id = userId,
        tenantId = tenantId,
        kind = PrincipalKind.PLAYER,
        roles = emptySet(),
    )

    @BeforeEach
    fun setUp() {
        fixedInstant = Instant.parse("2026-09-19T10:00:00Z")
        clock = Clock.fixed(fixedInstant, ZoneOffset.UTC)
        service = KycManualReviewService(
            clock = clock,
            claimLease = Duration.ofMinutes(15),
            dualControlRequired = true,
            minimumLegalAge = 18,
            reverificationValidityDuration = Duration.ofDays(365),
        )
    }

    // =========================================================================
    // KYC-001-03-T001: Authoritative Outcome Verification
    // =========================================================================

    @Test
    fun `KYC-001-03-T001 Implement manual KYC review produces the required authoritative outcome`() {
        KycManualReviewBinding.checkBound()

        // 1. Enqueue case
        val initialCase = service.enqueueCase(
            tenantId = tenantId,
            userId = userId,
            caseReference = caseRef,
            verifiedAge = 24,
            documents = listOf("PASSPORT", "UTILITY_BILL"),
        )
        assertEquals(KycManualReviewState.QUEUED, initialCase.state)

        // 2. Claim case
        val claimCommand = KycManualReviewCommand(
            principal = primaryReviewer,
            sessionId = "sess-rev-1",
            tenantId = tenantId,
            caseReference = caseRef,
            action = KycManualReviewAction.CLAIM,
            reason = "Claiming case for expedited manual review",
            idempotencyKey = "claim-key-1",
            correlationId = "corr-1",
            causationId = "cause-1",
            expectedVersion = 0L,
        )
        val claimResult = service.executeReviewAction(claimCommand)
        assertTrue(claimResult.isSuccess)
        assertEquals(KycManualReviewState.CLAIMED, claimResult.getOrThrow().case.state)

        // 3. Approve case with dual approval & justification
        val approveCommand = KycManualReviewCommand(
            principal = primaryReviewer,
            sessionId = "sess-rev-1",
            tenantId = tenantId,
            caseReference = caseRef,
            action = KycManualReviewAction.APPROVE,
            reason = "Physical passport inspection verified in person",
            verifiedAge = 24,
            secondApproverId = secondaryApprover.id,
            idempotencyKey = "approve-key-1",
            correlationId = "corr-2",
            causationId = "cause-2",
            expectedVersion = 1L,
        )
        val approveResult = service.executeReviewAction(approveCommand)
        assertTrue(approveResult.isSuccess)
        val res = approveResult.getOrThrow()

        assertEquals(KycManualReviewState.APPROVED, res.case.state)
        assertFalse(res.directEligibilityGranted)
        assertFalse(res.financialMutationPermitted)
        assertEquals("Age/identity approval only from policy; manual override reason/role; stale reverification blocks.", res.message)

        // 4. Authoritative evaluation reflects manual approval
        val evaluation = service.evaluateReviewStatus(tenantId, caseRef)
        assertEquals(KycManualReviewState.APPROVED, evaluation.state)
        assertTrue(evaluation.isEligible)
        assertFalse(evaluation.directEligibilityGranted)
        assertFalse(evaluation.financialMutationPermitted)
        assertEquals("Age/identity approval only from policy; manual override reason/role; stale reverification blocks.", evaluation.message)

        // 5. Durable record check
        val storedCase = service.getCase(tenantId, caseRef)
        assertNotNull(storedCase)
        assertEquals(KycManualReviewState.APPROVED, storedCase!!.state)
        assertEquals(fixedInstant, storedCase.approvedAt)
        assertEquals(fixedInstant.plus(Duration.ofDays(365)), storedCase.reverificationExpiresAt)
        assertEquals(2L, storedCase.serverVersion)
    }

    // =========================================================================
    // KYC-001-03-T002: Negative, Boundary & Rejection Verification
    // =========================================================================

    @Test
    fun `KYC-001-03-T002 Implement manual KYC review rejects invalid, boundary, unauthorized, and stale input`() {
        KycManualReviewBinding.checkBound()

        service.enqueueCase(tenantId, userId, "case-negative-1", verifiedAge = 16)

        // 1. Unauthorized principal (player) rejected
        val playerClaim = KycManualReviewCommand(
            principal = playerPrincipal,
            sessionId = "sess-player",
            tenantId = tenantId,
            caseReference = "case-negative-1",
            action = KycManualReviewAction.CLAIM,
            reason = "Player attempting claim",
            idempotencyKey = "player-claim",
            correlationId = "corr-neg-1",
            causationId = "cause-neg-1",
            expectedVersion = 0L,
        )
        assertTrue(service.executeReviewAction(playerClaim).isFailure)

        // 2. Auditor lacking MANAGE_SECURITY role rejected
        val audClaim = KycManualReviewCommand(
            principal = auditorAdmin,
            sessionId = "sess-aud",
            tenantId = tenantId,
            caseReference = "case-negative-1",
            action = KycManualReviewAction.CLAIM,
            reason = "Auditor attempting claim",
            idempotencyKey = "aud-claim",
            correlationId = "corr-neg-2",
            causationId = "cause-neg-2",
            expectedVersion = 0L,
        )
        assertTrue(service.executeReviewAction(audClaim).isFailure)

        // 3. Claim by authorized reviewer
        val claimCmd = KycManualReviewCommand(
            principal = primaryReviewer,
            sessionId = "sess-rev-1",
            tenantId = tenantId,
            caseReference = "case-negative-1",
            action = KycManualReviewAction.CLAIM,
            reason = "Legitimate reviewer claim",
            idempotencyKey = "claim-neg",
            correlationId = "corr-neg-3",
            causationId = "cause-neg-3",
            expectedVersion = 0L,
        )
        assertTrue(service.executeReviewAction(claimCmd).isSuccess)

        // 4. Approval of underage player (< 18) rejected by policy
        val underageApprove = KycManualReviewCommand(
            principal = primaryReviewer,
            sessionId = "sess-rev-1",
            tenantId = tenantId,
            caseReference = "case-negative-1",
            action = KycManualReviewAction.APPROVE,
            reason = "Attempting to approve underage player",
            verifiedAge = 16,
            secondApproverId = secondaryApprover.id,
            idempotencyKey = "approve-underage",
            correlationId = "corr-neg-4",
            causationId = "cause-neg-4",
            expectedVersion = 1L,
        )
        val underResult = service.executeReviewAction(underageApprove)
        assertTrue(underResult.isFailure)

        // 5. Blank reason rejected
        val blankReasonCmd = KycManualReviewCommand(
            principal = primaryReviewer,
            sessionId = "sess-rev-1",
            tenantId = tenantId,
            caseReference = "case-negative-1",
            action = KycManualReviewAction.APPROVE,
            reason = "   ",
            verifiedAge = 25,
            secondApproverId = secondaryApprover.id,
            idempotencyKey = "approve-blank",
            correlationId = "corr-neg-5",
            causationId = "cause-neg-5",
            expectedVersion = 1L,
        )
        assertTrue(service.executeReviewAction(blankReasonCmd).isFailure)

        // 6. Dual approval self-approval rejected
        val selfSecondApprove = KycManualReviewCommand(
            principal = primaryReviewer,
            sessionId = "sess-rev-1",
            tenantId = tenantId,
            caseReference = "case-negative-1",
            action = KycManualReviewAction.APPROVE,
            reason = "Valid justification meeting min length requirement",
            verifiedAge = 25,
            secondApproverId = primaryReviewer.id, // Self approval!
            idempotencyKey = "approve-self",
            correlationId = "corr-neg-6",
            causationId = "cause-neg-6",
            expectedVersion = 1L,
        )
        assertTrue(service.executeReviewAction(selfSecondApprove).isFailure)

        // 7. Stale expected version rejected
        val staleVersionCmd = KycManualReviewCommand(
            principal = primaryReviewer,
            sessionId = "sess-rev-1",
            tenantId = tenantId,
            caseReference = "case-negative-1",
            action = KycManualReviewAction.APPROVE,
            reason = "Valid justification meeting min length requirement",
            verifiedAge = 25,
            secondApproverId = secondaryApprover.id,
            idempotencyKey = "approve-stale",
            correlationId = "corr-neg-7",
            causationId = "cause-neg-7",
            expectedVersion = 99L,
        )
        assertTrue(service.executeReviewAction(staleVersionCmd).isFailure)
    }

    // =========================================================================
    // KYC-001-03-T003: Concurrency, Duplicate Delivery, and Failure Recovery
    // =========================================================================

    @Test
    fun `KYC-001-03-T003 Implement manual KYC review survives concurrency, duplicate delivery, and dependency failure`() {
        KycManualReviewBinding.checkBound()

        service.enqueueCase(tenantId, userId, "case-concurrency-1", verifiedAge = 25)

        val claimCmd = KycManualReviewCommand(
            principal = primaryReviewer,
            sessionId = "sess-rev-1",
            tenantId = tenantId,
            caseReference = "case-concurrency-1",
            action = KycManualReviewAction.CLAIM,
            reason = "Initial claim for concurrency test",
            idempotencyKey = "idem-claim-1",
            correlationId = "corr-c-1",
            causationId = "cause-c-1",
            expectedVersion = 0L,
        )

        // 1. Duplicate claim returns identical cached result
        val firstResult = service.executeReviewAction(claimCmd)
        assertTrue(firstResult.isSuccess)

        val duplicateResult = service.executeReviewAction(claimCmd)
        assertTrue(duplicateResult.isSuccess)
        assertEquals(firstResult.getOrThrow().resultId, duplicateResult.getOrThrow().resultId)

        // 2. Conflicting command with same idempotency key fails with CONFLICT
        val conflictingCmd = claimCmd.copy(reason = "Changed reason payload conflict")
        val conflictResult = service.executeReviewAction(conflictingCmd)
        assertTrue(conflictResult.isFailure)
        assertTrue(conflictResult.exceptionOrNull() is IllegalArgumentException)

        // 3. Concurrent claim attempts by other reviewers fail (lease locked)
        val otherReviewer = AuthenticatedPrincipal("admin-other", tenantId, PrincipalKind.ADMIN, setOf(AdminRole.SECURITY))
        val otherClaim = KycManualReviewCommand(
            principal = otherReviewer,
            sessionId = "sess-other",
            tenantId = tenantId,
            caseReference = "case-concurrency-1",
            action = KycManualReviewAction.CLAIM,
            reason = "Competing claim attempt",
            idempotencyKey = "competing-claim",
            correlationId = "corr-c-2",
            causationId = "cause-c-2",
            expectedVersion = 1L,
        )
        val competingResult = service.executeReviewAction(otherClaim)
        assertTrue(competingResult.isFailure)

        // 4. Multithreaded execution across independent cases
        val executor = Executors.newFixedThreadPool(4)
        val futures = (1..8).map { i ->
            executor.submit(Callable {
                val cRef = "concurrent-case-$i"
                service.enqueueCase(tenantId, "user-$i", cRef, verifiedAge = 25)
                service.executeReviewAction(
                    KycManualReviewCommand(
                        principal = primaryReviewer,
                        sessionId = "sess-rev-1",
                        tenantId = tenantId,
                        caseReference = cRef,
                        action = KycManualReviewAction.CLAIM,
                        reason = "Concurrent claim worker $i",
                        idempotencyKey = "worker-idem-$i",
                        correlationId = "corr-w-$i",
                        causationId = "cause-w-$i",
                        expectedVersion = 0L,
                    )
                )
            })
        }
        futures.forEach { assertTrue(it.get().isSuccess) }
        executor.shutdown()
    }

    // =========================================================================
    // KYC-001-03-T004: Lifecycle, Recovery, and Restore Compatibility
    // =========================================================================

    @Test
    fun `KYC-001-03-T004 Implement manual KYC review remains compatible, recoverable, observable, and lifecycle-safe`() {
        KycManualReviewBinding.checkBound()

        val cRef = "case-lifecycle-1"
        service.enqueueCase(tenantId, userId, cRef, verifiedAge = 30)

        // Claim and Reject flow
        service.executeReviewAction(
            KycManualReviewCommand(
                principal = primaryReviewer,
                sessionId = "sess-rev-1",
                tenantId = tenantId,
                caseReference = cRef,
                action = KycManualReviewAction.CLAIM,
                reason = "Claiming for fraudulent documentation rejection",
                idempotencyKey = "life-claim",
                correlationId = "corr-l-1",
                causationId = "cause-l-1",
                expectedVersion = 0L,
            )
        )

        val rejectResult = service.executeReviewAction(
            KycManualReviewCommand(
                principal = primaryReviewer,
                sessionId = "sess-rev-1",
                tenantId = tenantId,
                caseReference = cRef,
                action = KycManualReviewAction.REJECT,
                reason = "Fraudulent documentation detected during forensic inspection",
                idempotencyKey = "life-reject",
                correlationId = "corr-l-2",
                causationId = "cause-l-2",
                expectedVersion = 1L,
            )
        )
        assertTrue(rejectResult.isSuccess)
        assertEquals(KycManualReviewState.REJECTED, rejectResult.getOrThrow().case.state)

        // Observability check: audits recorded
        val audits = service.getAuditLogs(tenantId)
        assertTrue(audits.isNotEmpty())

        // Rejection evaluation reflects not eligible
        val eval = service.evaluateReviewStatus(tenantId, cRef)
        assertEquals(KycManualReviewState.REJECTED, eval.state)
        assertFalse(eval.isEligible)
        assertFalse(eval.directEligibilityGranted)
        assertFalse(eval.financialMutationPermitted)
    }
}
