package com.slotting.admin.infra

import com.slotting.admin.adjustment.*
import com.slotting.admin.aml.*
import com.slotting.admin.auth.*
import com.slotting.admin.rg.*
import com.slotting.admin.withdrawal.*
import org.junit.jupiter.api.Test
import org.mockito.ArgumentMatchers.anyString
import org.mockito.Mockito.*
import org.springframework.jdbc.core.JdbcTemplate
import java.time.Clock
import java.time.Duration
import java.time.Instant
import java.time.ZoneOffset
import java.util.UUID
import java.util.concurrent.CountDownLatch
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit
import kotlin.test.*

/**
 * TC-007 Contract Test Suite:
 * Correct PostgreSQL admin transitions, CAS handling, and bounded fingerprints.
 *
 * Covers:
 * 1. BE-014: Zero-row CAS versioned updates must fail with typed conflict and not commit results.
 * 2. BE-015: Withdrawal terminal transitions (APPROVE, REJECT) must clear claimedBy and claimExpiresAt
 *    to satisfy V6 database check constraint.
 * 3. BE-016: Manual adjustment fingerprint must be bounded (<= 512 chars) even with max length inputs.
 */
class PostgresTransitionsAndBoundedFingerprintContractTest {

    private val now = Instant.parse("2026-09-24T12:00:00Z")
    private val clock = Clock.fixed(now, ZoneOffset.UTC)

    private val admin1 = AuthenticatedPrincipal("admin-1", "tenant-1", PrincipalKind.ADMIN, setOf(AdminRole.SUPER_ADMIN))
    private val admin2 = AuthenticatedPrincipal("admin-2", "tenant-1", PrincipalKind.ADMIN, setOf(AdminRole.SUPER_ADMIN))

    private val sessionDir = object : AdminSessionDirectory {
        override fun find(tenantId: String, principalId: String, sessionId: String): AdminSessionStatus =
            AdminSessionStatus(active = true, breakGlass = false, expiresAt = now.plus(Duration.ofHours(8)), mfaVerified = true)
    }

    private val policy = AdminRbacPolicy(dualControlRequired = true)

    // =========================================================================
    // 1. BE-015: V6 Check Constraint & Queue State Transition Alignment
    // =========================================================================

    @Test
    fun `test01 withdrawal transition approve and reject clears claimedBy ensuring V6 check constraint compliance`() {
        val memoryStore = InMemoryWithdrawalStore()
        val queue = WithdrawalReviewQueue(policy, sessionDir, memoryStore, clock)

        // 1. Claim withdrawal
        val claimCmd = WithdrawalReviewCommand(
            principal = admin1,
            sessionId = "sess-1",
            tenantId = "tenant-1",
            withdrawalReference = "w-101",
            action = WithdrawalReviewAction.CLAIM,
            reason = WithdrawalReviewReason.REVIEW_REQUIRED,
            idempotencyKey = "idemp-claim-1",
            correlationId = "corr-1",
            causationId = "cause-1",
            expectedVersion = 0L
        )
        val claimed = queue.operate(claimCmd)
        assertEquals(WithdrawalReviewState.CLAIMED, claimed.item.state)
        assertEquals("admin-1", claimed.item.claimedBy)
        assertNotNull(claimed.item.claimExpiresAt)

        // 2. Approve withdrawal with distinct second approver
        val approveCmd = WithdrawalReviewCommand(
            principal = admin1,
            sessionId = "sess-1",
            tenantId = "tenant-1",
            withdrawalReference = "w-101",
            action = WithdrawalReviewAction.APPROVE,
            reason = WithdrawalReviewReason.REVIEW_REQUIRED,
            idempotencyKey = "idemp-approve-1",
            correlationId = "corr-2",
            causationId = "cause-2",
            expectedVersion = 1L,
            secondApproverId = "admin-2"
        )
        val approved = queue.operate(approveCmd)
        assertEquals(WithdrawalReviewState.APPROVED, approved.item.state)

        // V6 database constraint:
        // check ((state = 'CLAIMED' and claimed_by is not null and claim_expires_at is not null) or
        //        (state <> 'CLAIMED' and claimed_by is null and claim_expires_at is null))
        assertNull(approved.item.claimedBy, "claimedBy must be null after APPROVE to satisfy V6 check constraint")
        assertNull(approved.item.claimExpiresAt, "claimExpiresAt must be null after APPROVE to satisfy V6 check constraint")
    }

    // =========================================================================
    // 2. BE-014: CAS Zero-Row Count Handling Across Stores
    // =========================================================================

    @Test
    fun `test02 withdrawal store zero-row CAS update throws typed conflict`() {
        val mockJdbc = mock(JdbcTemplate::class.java)
        // Simulate zero rows updated on concurrent CAS update
        `when`(mockJdbc.update(anyString(), any(), any(), any(), any(), any(), any(), any())).thenReturn(0)

        val store = JdbcWithdrawalQueueStore(mockJdbc)
        val result = WithdrawalReviewResult(
            resultId = UUID.randomUUID(),
            item = WithdrawalQueueItem("w-101", WithdrawalReviewState.APPROVED, null, null, 2L),
            serverTime = now,
            evidenceReference = "evidence-1"
        )

        val audit = AuditEvent(UUID.randomUUID(), result.resultId, "tenant-1", "WITHDRAWAL_REVIEW_APPROVE", now, "corr", "cause")
        val outbox = OutboxEvent(UUID.randomUUID(), result.resultId, "tenant-1", "WITHDRAWAL_REVIEW_APPROVE", now)

        val failure = assertFailsWith<AuthenticationFailure.Rejected> {
            store.save(result, "tenant-1", WithdrawalReviewReason.REVIEW_REQUIRED, "admin-2", "fp-1", "idemp-1", audit, outbox)
        }
        assertEquals(AuthErrorCode.CONFLICT, failure.code)
    }

    @Test
    fun `test03 aml store zero-row CAS update throws typed conflict`() {
        val mockJdbc = mock(JdbcTemplate::class.java)
        `when`(mockJdbc.update(anyString(), any(), any(), any(), any(), any(), any(), any())).thenReturn(0)

        val store = JdbcAmlReviewQueueStore(mockJdbc)
        val result = AmlReviewResult(
            resultId = UUID.randomUUID(),
            item = AmlQueueItem("case-101", AmlReviewState.APPROVED, null, null, 2L),
            serverTime = now,
            evidenceReference = "aml-evidence-1"
        )
        val audit = AuditEvent(UUID.randomUUID(), result.resultId, "tenant-1", "AML_REVIEW_APPROVE", now, "corr", "cause")
        val outbox = OutboxEvent(UUID.randomUUID(), result.resultId, "tenant-1", "AML_REVIEW_APPROVE", now)

        val failure = assertFailsWith<AuthenticationFailure.Rejected> {
            store.save(result, "tenant-1", AmlReviewReason.SANCTION_SCREENING, "admin-2", "fp-1", "idemp-1", audit, outbox)
        }
        assertEquals(AuthErrorCode.CONFLICT, failure.code)
    }

    @Test
    fun `test04 rg store zero-row CAS update throws typed conflict`() {
        val mockJdbc = mock(JdbcTemplate::class.java)
        `when`(mockJdbc.update(anyString(), any(), any(), any(), any(), any(), any(), any())).thenReturn(0)

        val store = JdbcRgReviewQueueStore(mockJdbc)
        val result = RgReviewResult(
            resultId = UUID.randomUUID(),
            item = RgQueueItem("rg-101", RgReviewState.APPROVED, null, null, 2L),
            serverTime = now,
            evidenceReference = "rg-evidence-1"
        )
        val audit = AuditEvent(UUID.randomUUID(), result.resultId, "tenant-1", "RG_REVIEW_APPROVE", now, "corr", "cause")
        val outbox = OutboxEvent(UUID.randomUUID(), result.resultId, "tenant-1", "RG_REVIEW_APPROVE", now)

        val failure = assertFailsWith<AuthenticationFailure.Rejected> {
            store.save(result, "tenant-1", RgReviewReason.REVIEW_REQUIRED, "admin-2", "fp-1", "idemp-1", audit, outbox)
        }
        assertEquals(AuthErrorCode.CONFLICT, failure.code)
    }

    @Test
    fun `test05 manual adjustment store zero-row CAS update throws typed conflict`() {
        val mockJdbc = mock(JdbcTemplate::class.java)
        // Existing item found, but update returns 0 rows due to version mismatch
        val batch = ManualAdjustmentBatch(
            adjustmentReference = "adj-101",
            state = ManualAdjustmentState.PENDING_APPROVAL,
            currencyCode = "EUR",
            legs = emptyList(),
            totalDebitsMinorUnits = 1000L,
            totalCreditsMinorUnits = 1000L,
            makerId = "admin-1",
            secondApproverId = null,
            serverVersion = 1L,
            postingReference = null
        )
        `when`(mockJdbc.query(anyString(), any<org.springframework.jdbc.core.RowMapper<ManualAdjustmentBatch>>(), any(), any()))
            .thenReturn(listOf(batch))
        `when`(mockJdbc.update(anyString(), any(), any(), any(), any(), any(), any(), any(), any())).thenReturn(0)

        val store = JdbcManualAdjustmentStore(mockJdbc)
        val result = ManualAdjustmentResult(
            resultId = UUID.randomUUID(),
            item = batch.copy(state = ManualAdjustmentState.APPROVED, serverVersion = 2L),
            isBalanced = true,
            totalDebits = 1000L,
            totalCredits = 1000L,
            receiptReference = "receipt-1",
            serverTime = now,
            evidenceReference = "ev-1"
        )
        val audit = AuditEvent(UUID.randomUUID(), result.resultId, "tenant-1", "ADJUSTMENT_APPROVE", now, "corr", "cause")
        val outbox = OutboxEvent(UUID.randomUUID(), result.resultId, "tenant-1", "ADJUSTMENT_APPROVE", now)

        val failure = assertFailsWith<AuthenticationFailure.Rejected> {
            store.save(result, "tenant-1", ManualAdjustmentReason.DISPUTE_RESOLUTION, "ev-1", "fp-1", "idemp-1", audit, outbox)
        }
        assertEquals(AuthErrorCode.CONFLICT, failure.code)
    }

    // =========================================================================
    // 3. BE-016: Bounded Fingerprint for Manual Adjustment (V10 Schema)
    // =========================================================================

    @Test
    fun `test06 adjustment fingerprint is strictly bounded under schema varchar 512 for max inputs`() {
        val memoryStore = InMemoryAdjustmentStore()
        val service = ManualAdjustmentService(policy, sessionDir, memoryStore, clock)

        // Build command with maximum permitted lengths
        val maxTenant = "T".repeat(128)
        val maxAdjRef = "A".repeat(128)
        val maxEvRef = "E".repeat(128)
        val maxApprover = "P".repeat(128)
        val maxSession = "S".repeat(128)

        val maxPrincipal = AuthenticatedPrincipal(
            id = "admin-maker-1",
            tenantId = maxTenant,
            kind = PrincipalKind.ADMIN,
            roles = setOf(AdminRole.SUPER_ADMIN)
        )

        val maxCommand = ManualAdjustmentCommand(
            principal = maxPrincipal,
            sessionId = maxSession,
            tenantId = maxTenant,
            adjustmentReference = maxAdjRef,
            action = ManualAdjustmentAction.PREVIEW,
            reason = ManualAdjustmentReason.DISPUTE_RESOLUTION,
            currencyCode = "USD",
            legs = listOf(
                AdjustmentLeg("ACC-DEBIT-MAX-LENGTH-IDENTIFIER-1", 100_000L, AdjustmentLegDirection.DEBIT),
                AdjustmentLeg("ACC-CREDIT-MAX-LENGTH-IDENTIFIER-2", 100_000L, AdjustmentLegDirection.CREDIT)
            ),
            expectedVersion = 0L,
            evidenceReference = maxEvRef,
            secondApproverId = maxApprover,
            idempotencyKey = "idemp-max-1",
            correlationId = "corr-max",
            causationId = "cause-max"
        )

        service.operate(maxCommand)

        // The stored fingerprint must fit within PostgreSQL column varchar(512)
        val storedFp = memoryStore.lastSavedFingerprint
        assertNotNull(storedFp, "Fingerprint must be recorded on save")
        assertTrue(
            storedFp.length <= 512,
            "Fingerprint length was ${storedFp.length}, which exceeds V10 schema column limit varchar(512)"
        )
    }

    // =========================================================================
    // 4. Concurrency & Race Condition Invariant
    // =========================================================================

    @Test
    fun `test07 two service instances racing on same withdrawal only one commits success`() {
        val mockStore = SynchronizedAtomicQueueStore()
        val serviceA = WithdrawalReviewQueue(policy, sessionDir, mockStore, clock)
        val serviceB = WithdrawalReviewQueue(policy, sessionDir, mockStore, clock)

        val pool = Executors.newFixedThreadPool(2)
        val gate = CountDownLatch(1)

        val cmdA = WithdrawalReviewCommand(
            principal = admin1,
            sessionId = "sess-1",
            tenantId = "tenant-1",
            withdrawalReference = "w-race-1",
            action = WithdrawalReviewAction.APPROVE,
            reason = WithdrawalReviewReason.REVIEW_REQUIRED,
            idempotencyKey = "idemp-race-a",
            correlationId = "corr-ra",
            causationId = "cause-ra",
            expectedVersion = 1L,
            secondApproverId = "admin-2"
        )

        val cmdB = WithdrawalReviewCommand(
            principal = admin1,
            sessionId = "sess-1",
            tenantId = "tenant-1",
            withdrawalReference = "w-race-1",
            action = WithdrawalReviewAction.REJECT,
            reason = WithdrawalReviewReason.REVIEW_REQUIRED,
            idempotencyKey = "idemp-race-b",
            correlationId = "corr-rb",
            causationId = "cause-rb",
            expectedVersion = 1L,
            secondApproverId = "admin-2"
        )

        val callA = pool.submit<Result<WithdrawalReviewResult>> {
            gate.await()
            runCatching { serviceA.operate(cmdA) }
        }
        val callB = pool.submit<Result<WithdrawalReviewResult>> {
            gate.await()
            runCatching { serviceB.operate(cmdB) }
        }

        gate.countDown()
        val resA = callA.get(5, TimeUnit.SECONDS)
        val resB = callB.get(5, TimeUnit.SECONDS)
        pool.shutdown()

        val successes = listOf(resA, resB).count { it.isSuccess }
        val failures = listOf(resA, resB).count { it.isFailure }

        assertEquals(1, successes, "Exactly one concurrent transition must succeed")
        assertEquals(1, failures, "Losing concurrent transition must receive conflict")
    }

    // =========================================================================
    // 5. Stale, Idempotency, Lease Expiry, Rollback & Restart Scenarios
    // =========================================================================

    @Test
    fun `test08 stale expected version throws STALE error without mutating store`() {
        val memoryStore = InMemoryWithdrawalStore()
        val queue = WithdrawalReviewQueue(policy, sessionDir, memoryStore, clock)

        val staleCmd = WithdrawalReviewCommand(
            principal = admin1,
            sessionId = "sess-1",
            tenantId = "tenant-1",
            withdrawalReference = "w-101",
            action = WithdrawalReviewAction.CLAIM,
            reason = WithdrawalReviewReason.REVIEW_REQUIRED,
            idempotencyKey = "idemp-stale",
            correlationId = "corr-stale",
            causationId = "cause-stale",
            expectedVersion = 99L // Outdated / stale version
        )

        val failure = assertFailsWith<AuthenticationFailure.Rejected> {
            queue.operate(staleCmd)
        }
        assertEquals(AuthErrorCode.STALE, failure.code)
    }

    @Test
    fun `test09 duplicate command returns exact idempotent replay without re-executing transition`() {
        val memoryStore = InMemoryWithdrawalStore()
        val queue = WithdrawalReviewQueue(policy, sessionDir, memoryStore, clock)

        val claimCmd = WithdrawalReviewCommand(
            principal = admin1,
            sessionId = "sess-1",
            tenantId = "tenant-1",
            withdrawalReference = "w-101",
            action = WithdrawalReviewAction.CLAIM,
            reason = WithdrawalReviewReason.REVIEW_REQUIRED,
            idempotencyKey = "idemp-dup",
            correlationId = "corr-dup",
            causationId = "cause-dup",
            expectedVersion = 0L
        )

        val first = queue.operate(claimCmd)
        val second = queue.operate(claimCmd)

        assertEquals(first.resultId, second.resultId)
        assertEquals(first.item.serverVersion, second.item.serverVersion)
        assertEquals(first.item.state, second.item.state)
    }

    @Test
    fun `test10 changed payload reusing idempotency key is rejected with CONFLICT`() {
        val memoryStore = InMemoryWithdrawalStore()
        val queue = WithdrawalReviewQueue(policy, sessionDir, memoryStore, clock)

        val claimCmd = WithdrawalReviewCommand(
            principal = admin1,
            sessionId = "sess-1",
            tenantId = "tenant-1",
            withdrawalReference = "w-101",
            action = WithdrawalReviewAction.CLAIM,
            reason = WithdrawalReviewReason.REVIEW_REQUIRED,
            idempotencyKey = "idemp-conflict-reuse",
            correlationId = "corr-1",
            causationId = "cause-1",
            expectedVersion = 0L
        )
        queue.operate(claimCmd)

        // Attempt to replay the same key with changed reason
        val tamperedCmd = claimCmd.copy(reason = WithdrawalReviewReason.FRAUD_REVIEW)
        val failure = assertFailsWith<AuthenticationFailure.Rejected> {
            queue.operate(tamperedCmd)
        }
        assertEquals(AuthErrorCode.CONFLICT, failure.code)
    }

    @Test
    fun `test11 expired claim lease allows another admin to claim and transition queue item`() {
        val memoryStore = InMemoryWithdrawalStore()
        val queue = WithdrawalReviewQueue(policy, sessionDir, memoryStore, clock, claimLease = Duration.ofMinutes(10))

        // Admin 1 claims
        val claim1 = queue.operate(
            WithdrawalReviewCommand(
                principal = admin1,
                sessionId = "sess-1",
                tenantId = "tenant-1",
                withdrawalReference = "w-101",
                action = WithdrawalReviewAction.CLAIM,
                reason = WithdrawalReviewReason.REVIEW_REQUIRED,
                idempotencyKey = "idemp-claim-1",
                correlationId = "c1",
                causationId = "ca1",
                expectedVersion = 0L
            )
        )
        assertEquals("admin-1", claim1.item.claimedBy)

        // Advance clock past 10 minutes lease
        val futureClock = Clock.fixed(now.plus(Duration.ofMinutes(15)), ZoneOffset.UTC)
        val futureQueue = WithdrawalReviewQueue(policy, sessionDir, memoryStore, futureClock, claimLease = Duration.ofMinutes(10))

        // Admin 2 claims expired lease
        val claim2 = futureQueue.operate(
            WithdrawalReviewCommand(
                principal = admin2,
                sessionId = "sess-2",
                tenantId = "tenant-1",
                withdrawalReference = "w-101",
                action = WithdrawalReviewAction.CLAIM,
                reason = WithdrawalReviewReason.REVIEW_REQUIRED,
                idempotencyKey = "idemp-claim-2",
                correlationId = "c2",
                causationId = "ca2",
                expectedVersion = 1L
            )
        )
        assertEquals("admin-2", claim2.item.claimedBy)
        assertEquals(2L, claim2.item.serverVersion)
    }

    @Test
    fun `test12 CAS failure prevents subsequent result audit and outbox writes ensuring complete rollback`() {
        val mockJdbc = mock(JdbcTemplate::class.java)
        // CAS update returns 0 rows updated
        `when`(mockJdbc.update(anyString(), any(), any(), any(), any(), any(), any(), any())).thenReturn(0)

        val store = JdbcWithdrawalQueueStore(mockJdbc)
        val result = WithdrawalReviewResult(
            resultId = UUID.randomUUID(),
            item = WithdrawalQueueItem("w-101", WithdrawalReviewState.APPROVED, null, null, 2L),
            serverTime = now,
            evidenceReference = "ev-1"
        )
        val audit = AuditEvent(UUID.randomUUID(), result.resultId, "tenant-1", "WITHDRAWAL_REVIEW_APPROVE", now, "c", "ca")
        val outbox = OutboxEvent(UUID.randomUUID(), result.resultId, "tenant-1", "WITHDRAWAL_REVIEW_APPROVE", now)

        assertFailsWith<AuthenticationFailure.Rejected> {
            store.save(result, "tenant-1", WithdrawalReviewReason.REVIEW_REQUIRED, "admin-2", "fp-1", "idemp-rollback", audit, outbox)
        }

        // Verify that subsequent insert into result, audit, or outbox was never executed
        verify(mockJdbc, times(1)).update(anyString(), any(), any(), any(), any(), any(), any(), any())
        verifyNoMoreInteractions(mockJdbc)
    }

    @Test
    fun `test13 service restart preserves committed transitions and returns exact replay`() {
        val persistentStore = InMemoryWithdrawalStore()
        var queue = WithdrawalReviewQueue(policy, sessionDir, persistentStore, clock)

        val claimCmd = WithdrawalReviewCommand(
            principal = admin1,
            sessionId = "sess-1",
            tenantId = "tenant-1",
            withdrawalReference = "w-101",
            action = WithdrawalReviewAction.CLAIM,
            reason = WithdrawalReviewReason.REVIEW_REQUIRED,
            idempotencyKey = "idemp-persist-1",
            correlationId = "c1",
            causationId = "ca1",
            expectedVersion = 0L
        )
        val preRestartResult = queue.operate(claimCmd)

        // Simulate service restart by instantiating new service with same persistent store
        val restartedQueue = WithdrawalReviewQueue(policy, sessionDir, persistentStore, clock)

        // Exact replay works on restarted instance
        val replayResult = restartedQueue.operate(claimCmd)
        assertEquals(preRestartResult.resultId, replayResult.resultId)
        assertEquals(preRestartResult.item.serverVersion, replayResult.item.serverVersion)
        assertEquals(preRestartResult.item.claimedBy, replayResult.item.claimedBy)
    }

    // =========================================================================
    // Helpers & Test Stores
    // =========================================================================

    private class InMemoryWithdrawalStore : WithdrawalQueueStore {
        private val items = mutableMapOf("tenant-1:w-101" to WithdrawalQueueItem("w-101", WithdrawalReviewState.QUEUED, null, null, 0L))
        private val results = mutableMapOf<String, Pair<String, WithdrawalReviewResult>>()

        override fun findByIdempotency(tenantId: String, key: String): Pair<String, WithdrawalReviewResult>? =
            results["$tenantId:$key"]

        override fun findItem(tenantId: String, withdrawalReference: String): WithdrawalQueueItem? =
            items["$tenantId:$withdrawalReference"]

        override fun save(
            result: WithdrawalReviewResult,
            tenantId: String,
            reason: WithdrawalReviewReason,
            secondApproverId: String?,
            queryFingerprint: String,
            idempotencyKey: String,
            audit: AuditEvent,
            outbox: OutboxEvent
        ) {
            items["$tenantId:${result.item.withdrawalReference}"] = result.item
            results["$tenantId:$idempotencyKey"] = queryFingerprint to result
        }
    }

    private class InMemoryAdjustmentStore : ManualAdjustmentStore {
        private val batches = mutableMapOf<String, ManualAdjustmentBatch>()
        private val results = mutableMapOf<String, Pair<String, ManualAdjustmentResult>>()
        var lastSavedFingerprint: String? = null

        override fun findByIdempotency(tenantId: String, key: String): Pair<String, ManualAdjustmentResult>? =
            results["$tenantId:$key"]

        override fun findItem(tenantId: String, adjustmentReference: String): ManualAdjustmentBatch? =
            batches["$tenantId:$adjustmentReference"]

        override fun save(
            result: ManualAdjustmentResult,
            tenantId: String,
            reason: ManualAdjustmentReason,
            evidenceReference: String,
            queryFingerprint: String,
            idempotencyKey: String,
            audit: AuditEvent,
            outbox: OutboxEvent
        ) {
            batches["$tenantId:${result.item.adjustmentReference}"] = result.item
            results["$tenantId:$idempotencyKey"] = queryFingerprint to result
            lastSavedFingerprint = queryFingerprint
        }
    }

    /**
     * Simulates an atomic database store with CAS semantics across independent service instances.
     */
    private class SynchronizedAtomicQueueStore : WithdrawalQueueStore {
        private var currentItem = WithdrawalQueueItem("w-race-1", WithdrawalReviewState.CLAIMED, "admin-1", Instant.now().plusSeconds(600), 1L)
        private val results = mutableMapOf<String, Pair<String, WithdrawalReviewResult>>()

        @Synchronized
        override fun findByIdempotency(tenantId: String, key: String): Pair<String, WithdrawalReviewResult>? =
            results["$tenantId:$key"]

        @Synchronized
        override fun findItem(tenantId: String, withdrawalReference: String): WithdrawalQueueItem? =
            currentItem

        @Synchronized
        override fun save(
            result: WithdrawalReviewResult,
            tenantId: String,
            reason: WithdrawalReviewReason,
            secondApproverId: String?,
            queryFingerprint: String,
            idempotencyKey: String,
            audit: AuditEvent,
            outbox: OutboxEvent
        ) {
            // Emulate SQL CAS: where server_version = result.item.serverVersion - 1
            if (currentItem.serverVersion != result.item.serverVersion - 1) {
                // Zero rows updated -> throws CONFLICT
                throw AuthenticationFailure.Rejected(AuthErrorCode.CONFLICT)
            }
            currentItem = result.item
            results["$tenantId:$idempotencyKey"] = queryFingerprint to result
        }
    }
}
