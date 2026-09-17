package com.slotting.admin.aml

import com.slotting.admin.auth.*
import java.io.File
import java.time.Clock
import java.time.Instant
import java.time.ZoneOffset
import java.util.UUID
import java.util.concurrent.CountDownLatch
import java.util.concurrent.Executors
import kotlin.test.*
import org.junit.jupiter.api.Test

class ImmutableAmlDecisionTest {
    private val now = Instant.parse("2026-09-17T20:00:00Z")
    private val clock = Clock.fixed(now, ZoneOffset.UTC)

    @Test
    fun `AML-003-02-T001 Record immutable AML decisions produces the required authoritative outcome`() {
        val store = MemoryImmutableAmlDecisionStore()
        val service = service(store)

        // Seed initial queued case in review store
        val caseRef = "AML-CASE-player-decision-001"
        store.queueItems[caseRef] = AmlQueueItem(
            caseReference = caseRef,
            state = AmlReviewState.QUEUED,
            claimedBy = null,
            claimExpiresAt = null,
            serverVersion = 1L,
        )

        // 1. Initial payout clearance must be blocked (prevent payout before required review)
        val initialClearance = service.verifyPayoutClearance(
            VerifyAmlPayoutClearanceCommand("tenant-1", "player-decision-001", 300_000L)
        )
        assertFalse(initialClearance.payoutPermitted)
        assertEquals(AmlDecisionPayoutStatus.BLOCKED_PENDING_REVIEW, initialClearance.status)
        assertNotNull(initialClearance.denialReason)

        // 2. Record immutable APPROVE decision
        val approveCmd = command(
            caseReference = caseRef,
            subjectReference = "player-decision-001",
            decisionType = AmlDecisionType.APPROVE,
            reason = AmlReviewReason.HIGH_RISK_ACTION,
            justification = "SOF verified and authenticated by compliance team",
            secondApproverId = "admin-second-approver",
            idempotencyKey = "key-decision-approve-001",
            correlationId = "corr-decide-1",
            causationId = "cause-decide-1",
        )
        val approveResult = service.recordDecision(approveCmd)

        // Assert: Decision immutable; superseding record only; minimal retention per approved policy
        assertEquals("player-decision-001", approveResult.subjectReference)
        assertEquals(AmlDecisionType.APPROVE, approveResult.decisionType)
        assertNull(approveResult.supersedesDecisionId)
        assertEquals(AmlReviewState.APPROVED, approveResult.updatedQueueItem.state)
        assertFalse(approveResult.financialAuthorityCreated) // Outcome cannot create financial authority
        assertFalse(approveResult.moneyMutated)             // Cannot mutate money
        assertEquals("EVID-AML-DECISION-player-decision-001", approveResult.evidenceReference)
        assertTrue(approveResult.retentionExpiresAt.isAfter(now))

        // Payout clearance is now permitted
        val approvedClearance = service.verifyPayoutClearance(
            VerifyAmlPayoutClearanceCommand("tenant-1", "player-decision-001", 300_000L)
        )
        assertTrue(approvedClearance.payoutPermitted)
        assertEquals(AmlDecisionPayoutStatus.PAYOUT_PERMITTED, approvedClearance.status)
        assertNull(approvedClearance.denialReason)

        // 3. Superseding record: Compliance discovers forged document, records superseding REJECT decision
        val rejectCmd = command(
            caseReference = caseRef,
            subjectReference = "player-decision-001",
            decisionType = AmlDecisionType.REJECT,
            reason = AmlReviewReason.SUSPICIOUS_ACTIVITY,
            justification = "Subsequent bank confirmation revealed fraudulent payslip",
            secondApproverId = "admin-second-approver",
            supersedesDecisionId = approveResult.decisionId,
            idempotencyKey = "key-decision-reject-001",
        )
        val rejectResult = service.recordDecision(rejectCmd)

        assertEquals(approveResult.decisionId, rejectResult.supersedesDecisionId)
        assertNotEquals(approveResult.decisionId, rejectResult.decisionId)
        assertEquals(AmlReviewState.REJECTED, rejectResult.updatedQueueItem.state)

        // Immutable decision verification: old approval record remains intact and immutable, marked superseded
        val priorDecision = store.findDecisionById("tenant-1", approveResult.decisionId)
        assertNotNull(priorDecision)
        assertTrue(priorDecision.isSuperseded)
        assertEquals(AmlDecisionType.APPROVE, priorDecision.decisionType)

        // Payout clearance is now blocked due to REJECTED decision
        val rejectedClearance = service.verifyPayoutClearance(
            VerifyAmlPayoutClearanceCommand("tenant-1", "player-decision-001", 300_000L)
        )
        assertFalse(rejectedClearance.payoutPermitted)
        assertEquals(AmlDecisionPayoutStatus.BLOCKED_REJECTED, rejectedClearance.status)
        assertNotNull(rejectedClearance.denialReason)

        // 4. Replay with identical idempotency key returns identical result
        val replay = service.recordDecision(approveCmd)
        assertEquals(approveResult.resultId, replay.resultId)
        assertEquals(approveResult.decisionId, replay.decisionId)
        assertEquals(approveResult.evidenceReference, replay.evidenceReference)

        // Observability check
        assertEquals(2, store.audit.size)
        assertEquals("AML_DECISION_RECORDED", store.audit[0].type)
        assertEquals("corr-decide-1", store.audit[0].correlationId)
        assertEquals("cause-decide-1", store.audit[0].causationId)
        assertFalse(store.audit[0].type.contains("secret"))
    }

    @Test
    fun `AML-003-02-T002 Record immutable AML decisions rejects invalid, boundary, unauthorized, and stale input`() {
        val store = MemoryImmutableAmlDecisionStore()
        val service = service(store)

        val caseRef = "AML-CASE-player-002"
        store.queueItems[caseRef] = AmlQueueItem(caseRef, AmlReviewState.QUEUED, null, null, 1L)

        // Unauthenticated
        assertFailsWith<AuthenticationFailure.Rejected> {
            service.recordDecision(command(principal = null, idempotencyKey = "key-unauth"))
        }.also { assertEquals(AuthErrorCode.UNAUTHENTICATED, it.code) }

        // Non-admin player
        assertFailsWith<AuthenticationFailure.Rejected> {
            service.recordDecision(command(principal = player(), idempotencyKey = "key-player"))
        }.also { assertEquals(AuthErrorCode.FORBIDDEN, it.code) }

        // Cross-tenant admin
        assertFailsWith<AuthenticationFailure.Rejected> {
            service.recordDecision(command(principal = admin(tenantId = "other-tenant"), idempotencyKey = "key-cross-tenant"))
        }.also { assertEquals(AuthErrorCode.FORBIDDEN, it.code) }

        // Unauthorized role lacking MANAGE_SECURITY
        val supportAdmin = AuthenticatedPrincipal("admin-support", "tenant-1", PrincipalKind.ADMIN, setOf(AdminRole.SUPPORT))
        assertFailsWith<AuthenticationFailure.Rejected> {
            service.recordDecision(command(principal = supportAdmin, idempotencyKey = "key-support-unauth"))
        }.also { assertEquals(AuthErrorCode.FORBIDDEN, it.code) }

        // Inactive / expired session
        val expiredSessionService = ImmutableAmlDecisionService(AdminRbacPolicy(true), TestDecisionExpiredSessionDirectory(), store, clock)
        assertFailsWith<AuthenticationFailure.Rejected> {
            expiredSessionService.recordDecision(command(idempotencyKey = "key-expired-sess"))
        }.also { assertEquals(AuthErrorCode.FORBIDDEN, it.code) }

        // Segregation of duties violation: second approver same as primary approver
        assertFailsWith<AuthenticationFailure.Rejected> {
            service.recordDecision(command(secondApproverId = "admin-decision-1", idempotencyKey = "key-same-approver"))
        }.also { assertEquals(AuthErrorCode.INVALID, it.code) }

        // Blank case reference
        assertFailsWith<AuthenticationFailure.Rejected> {
            service.recordDecision(command(caseReference = "   ", idempotencyKey = "key-blank-case"))
        }.also { assertEquals(AuthErrorCode.INVALID, it.code) }

        // Blank justification
        assertFailsWith<AuthenticationFailure.Rejected> {
            service.recordDecision(command(justification = "   ", idempotencyKey = "key-blank-just"))
        }.also { assertEquals(AuthErrorCode.INVALID, it.code) }

        // Non-existent supersedesDecisionId
        assertFailsWith<AuthenticationFailure.Rejected> {
            service.recordDecision(command(supersedesDecisionId = UUID.randomUUID(), idempotencyKey = "key-bad-supersede"))
        }.also { assertEquals(AuthErrorCode.INVALID, it.code) }

        // Stale expected version
        assertFailsWith<AuthenticationFailure.Rejected> {
            service.recordDecision(command(expectedVersion = 8L, idempotencyKey = "key-stale-ver"))
        }.also { assertEquals(AuthErrorCode.STALE, it.code) }

        // Conflicting replay with different payload
        service.recordDecision(command(idempotencyKey = "key-conflict-decision"))
        assertFailsWith<AuthenticationFailure.Rejected> {
            service.recordDecision(command(
                justification = "Altered justification for conflict test",
                idempotencyKey = "key-conflict-decision"
            ))
        }.also { assertEquals(AuthErrorCode.CONFLICT, it.code) }
    }

    @Test
    fun `AML-003-02-T003 Record immutable AML decisions survives concurrency, duplicate delivery, and dependency failure`() {
        val store = MemoryImmutableAmlDecisionStore()
        val service = service(store)

        val caseRef = "AML-CASE-concurrent-001"
        store.queueItems[caseRef] = AmlQueueItem(caseRef, AmlReviewState.QUEUED, null, null, 1L)

        // 1. Concurrency: duplicate submissions race with identical idempotency key
        val gate = CountDownLatch(1)
        val pool = Executors.newFixedThreadPool(4)
        val cmd = command(caseReference = caseRef, idempotencyKey = "key-concurrent-decide-001")
        val calls = (1..4).map {
            pool.submit<AmlDecisionResult> {
                gate.await()
                service.recordDecision(cmd)
            }
        }
        gate.countDown()
        val outcomes = calls.map { runCatching { it.get() } }

        assertEquals(4, outcomes.count { it.isSuccess })
        val distinctResultIds = outcomes.mapNotNull { it.getOrNull()?.resultId }.toSet()
        assertEquals(1, distinctResultIds.size)

        // 2. Dependency failure on session directory -> fails closed (DEPENDENCY_UNAVAILABLE)
        val failingService = ImmutableAmlDecisionService(AdminRbacPolicy(true), TestDecisionFailingSessionDirectory(), store, clock)
        assertFailsWith<AuthenticationFailure.Rejected> {
            failingService.recordDecision(command(idempotencyKey = "key-dep-fail"))
        }.also { assertEquals(AuthErrorCode.DEPENDENCY_UNAVAILABLE, it.code) }

        pool.shutdown()
    }

    @Test
    fun `AML-003-02-T004 Record immutable AML decisions remains compatible, recoverable, observable, and lifecycle-safe`() {
        // Assert: committed rows/constraints on admin_aml_review_queue in V8
        val migration = File("src/main/resources/db/migration/V8__aml_review_queue.sql").readText()
        assertTrue(migration.contains("admin_aml_review_queue"))
        assertTrue(migration.contains("admin_aml_review_result"))
        assertTrue(migration.contains("check (state in ('QUEUED','CLAIMED','APPROVED','REJECTED'))"))
        assertTrue(migration.contains("foreign key"))
        assertTrue(!migration.contains("balance"))

        // Assert: no unapproved persistence or migration introduced
        val migrationDir = File("src/main/resources/db/migration")
        val sqlFiles = migrationDir.listFiles { _, name -> name.endsWith(".sql") } ?: emptyArray()
        assertTrue(sqlFiles.isNotEmpty())
        val migrationVersions = sqlFiles.map { it.name.substringBefore("__") }
        assertTrue(!migrationVersions.contains("V17"))

        // Assert: restart/recreation preserves consistency and immutability
        val store = MemoryImmutableAmlDecisionStore()
        val service = service(store)

        val caseRef = "AML-CASE-reboot-001"
        store.queueItems[caseRef] = AmlQueueItem(caseRef, AmlReviewState.QUEUED, null, null, 1L)

        val cmd = command(
            caseReference = caseRef,
            subjectReference = "player-reboot-001",
            decisionType = AmlDecisionType.APPROVE,
            idempotencyKey = "key-reboot-decision",
            correlationId = "corr-reboot-decide-1",
            causationId = "cause-reboot-decide-1",
        )
        val first = service.recordDecision(cmd)

        // Recreate service (restart)
        val restartedService = service(store)

        // Payout clearance remains permitted after reboot
        val eligibility = restartedService.verifyPayoutClearance(
            VerifyAmlPayoutClearanceCommand("tenant-1", "player-reboot-001", 100_000L)
        )
        assertTrue(eligibility.payoutPermitted)
        assertEquals(AmlDecisionPayoutStatus.PAYOUT_PERMITTED, eligibility.status)

        // Replay produces identical result
        val second = restartedService.recordDecision(cmd)
        assertEquals(first.resultId, second.resultId)
        assertEquals(first.decisionId, second.decisionId)
        assertEquals(first.evidenceReference, second.evidenceReference)
        assertFalse(second.financialAuthorityCreated)
        assertFalse(second.moneyMutated)

        // Observability check
        assertEquals(1, store.audit.size)
        assertEquals("AML_DECISION_RECORDED", store.audit[0].type)
        assertEquals("corr-reboot-decide-1", store.audit[0].correlationId)
        assertEquals("cause-reboot-decide-1", store.audit[0].causationId)
        assertFalse(store.audit[0].type.contains("secret"))
    }

    private fun service(store: ImmutableAmlDecisionStore) =
        ImmutableAmlDecisionService(AdminRbacPolicy(true), TestDecisionActiveSessionDirectory(), store, clock)

    private fun command(
        principal: AuthenticatedPrincipal? = admin(),
        caseReference: String = "AML-CASE-player-default",
        subjectReference: String = "player-default",
        decisionType: AmlDecisionType = AmlDecisionType.APPROVE,
        reason: AmlReviewReason = AmlReviewReason.REVIEW_REQUIRED,
        justification: String = "Authoritative AML review verified and signed",
        evidenceReference: String = "EVID-SOF-REF-100",
        secondApproverId: String? = null,
        supersedesDecisionId: UUID? = null,
        idempotencyKey: String = "key-decide-cmd-001",
        correlationId: String = "corr-decide-default",
        causationId: String = "cause-decide-default",
        expectedVersion: Long = 1L,
    ) = RecordAmlDecisionCommand(
        principal = principal,
        sessionId = "session-decide-1",
        tenantId = "tenant-1",
        caseReference = caseReference,
        subjectReference = subjectReference,
        decisionType = decisionType,
        reason = reason,
        justification = justification,
        evidenceReference = evidenceReference,
        secondApproverId = secondApproverId,
        supersedesDecisionId = supersedesDecisionId,
        idempotencyKey = idempotencyKey,
        correlationId = correlationId,
        causationId = causationId,
        expectedVersion = expectedVersion,
    )

    private fun admin(tenantId: String = "tenant-1") =
        AuthenticatedPrincipal("admin-decision-1", tenantId, PrincipalKind.ADMIN, setOf(AdminRole.SECURITY))

    private fun player() =
        AuthenticatedPrincipal("player-decision-1", "tenant-1", PrincipalKind.PLAYER, emptySet())
}

private class TestDecisionActiveSessionDirectory : AdminSessionDirectory {
    override fun find(tenantId: String, principalId: String, sessionId: String) =
        if (tenantId == "tenant-1" && sessionId == "session-decide-1")
            AdminSessionStatus(true, false, Instant.parse("2026-09-17T21:00:00Z"))
        else null
}

private class TestDecisionExpiredSessionDirectory : AdminSessionDirectory {
    override fun find(tenantId: String, principalId: String, sessionId: String) =
        AdminSessionStatus(false, false, Instant.parse("2026-09-17T19:00:00Z"))
}

private class TestDecisionFailingSessionDirectory : AdminSessionDirectory {
    override fun find(tenantId: String, principalId: String, sessionId: String): AdminSessionStatus =
        error("session directory failure")
}

private class MemoryImmutableAmlDecisionStore : ImmutableAmlDecisionStore {
    val results = mutableMapOf<String, Pair<String, AmlDecisionResult>>()
    val decisions = mutableMapOf<UUID, ImmutableAmlDecisionRecord>()
    val latestBySubject = mutableMapOf<String, ImmutableAmlDecisionRecord>()
    val queueItems = mutableMapOf<String, AmlQueueItem>()
    val audit = mutableListOf<AuditEvent>()
    val outbox = mutableListOf<OutboxEvent>()

    override fun findByIdempotency(tenantId: String, idempotencyKey: String) =
        synchronized(this) { results["$tenantId:$idempotencyKey"] }

    override fun findLatestDecision(tenantId: String, subjectReference: String) =
        synchronized(this) { latestBySubject["$tenantId:$subjectReference"] }

    override fun findDecisionById(tenantId: String, decisionId: UUID) =
        synchronized(this) { decisions[decisionId] }

    override fun findQueueItem(tenantId: String, caseReference: String) =
        synchronized(this) { queueItems[caseReference] }

    override fun save(
        decision: ImmutableAmlDecisionRecord,
        result: AmlDecisionResult,
        tenantId: String,
        queryFingerprint: String,
        idempotencyKey: String,
        audit: AuditEvent,
        outbox: OutboxEvent,
        updatedQueueItem: AmlQueueItem,
        supersededDecision: ImmutableAmlDecisionRecord?,
    ) = synchronized(this) {
        results["$tenantId:$idempotencyKey"] = queryFingerprint to result
        decisions[decision.decisionId] = decision
        latestBySubject["$tenantId:${decision.subjectReference}"] = decision
        if (supersededDecision != null) {
            decisions[supersededDecision.decisionId] = supersededDecision
        }
        queueItems[updatedQueueItem.caseReference] = updatedQueueItem
        this.audit += audit
        this.outbox += outbox
    }
}
