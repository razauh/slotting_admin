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

class DurableAccountRestrictionEnforcementTest {
    private val now = Instant.parse("2026-09-17T19:00:00Z")
    private val clock = Clock.fixed(now, ZoneOffset.UTC)

    @Test
    fun `AML-002-03-T001 Enforce durable account restrictions produces the required authoritative outcome`() {
        val store = MemoryDurableAccountRestrictionStore()
        val cache = MemoryEphemeralRestrictionCache()
        val service = service(store, cache)

        // 1. Apply durable restriction: ACCOUNT_FROZEN with review case
        val cmd = command(
            subjectReference = "player-restrict-001",
            restrictionType = AccountRestrictionType.ACCOUNT_FROZEN,
            reason = AmlReviewReason.HIGH_RISK_ACTION,
            justification = "Severe fraud indicators detected; freezing account pending review",
            idempotencyKey = "key-restrict-cmd-001",
            correlationId = "corr-restrict-1",
            causationId = "cause-restrict-1",
        )
        val result = service.applyRestriction(cmd)

        // Assert: Ephemeral cache loss never erases restriction; case actions RBAC/audited
        assertEquals("player-restrict-001", result.subjectReference)
        assertEquals(AccountRestrictionType.ACCOUNT_FROZEN, result.restrictionType)
        assertNotNull(result.amlCaseReference)
        assertEquals(AmlReviewState.QUEUED, result.queuedAmlItem.state)
        assertFalse(result.financialAuthorityCreated) // Invariant: no financial authority created
        assertFalse(result.moneyMutated)             // Invariant: cannot mutate money
        assertEquals("EVID-RESTRICT-player-restrict-001", result.evidenceReference)

        // Verify atomic store persistence
        val storedRecord = store.restrictions["tenant-1:player-restrict-001"]
        assertNotNull(storedRecord)
        assertEquals(AccountRestrictionType.ACCOUNT_FROZEN, storedRecord.restrictionType)
        val queuedCase = store.queueItems[result.amlCaseReference]
        assertNotNull(queuedCase)
        assertEquals(AmlReviewState.QUEUED, queuedCase.state)

        // 2. Enforce restriction: WITHDRAWAL attempt must be BLOCKED
        val blockedWithdrawal = service.enforceAction(EnforceRestrictionCommand("tenant-1", "player-restrict-001", RestrictedActionType.WITHDRAWAL))
        assertEquals(RestrictionEnforcementOutcome.BLOCKED, blockedWithdrawal.outcome)
        assertEquals(AccountRestrictionType.ACCOUNT_FROZEN, blockedWithdrawal.currentRestriction)
        assertNotNull(blockedWithdrawal.denialReason)

        // 3. Ephemeral cache loss never erases restriction:
        // Simulate Redis loss / cache flush / eviction
        cache.flushAll()
        assertNull(cache.getRestriction("tenant-1", "player-restrict-001"))

        // Enforce DEPOSIT attempt after Redis loss: MUST STILL BE BLOCKED by durable store!
        val blockedDepositAfterLoss = service.enforceAction(EnforceRestrictionCommand("tenant-1", "player-restrict-001", RestrictedActionType.DEPOSIT))
        assertEquals(RestrictionEnforcementOutcome.BLOCKED, blockedDepositAfterLoss.outcome)
        assertEquals(AccountRestrictionType.ACCOUNT_FROZEN, blockedDepositAfterLoss.currentRestriction)
        assertNotNull(blockedDepositAfterLoss.denialReason)
        // Cache re-populated
        assertEquals(AccountRestrictionType.ACCOUNT_FROZEN, cache.getRestriction("tenant-1", "player-restrict-001"))

        // 4. Clean account enforcement: unrestricted account allows actions
        val allowedWithdrawal = service.enforceAction(EnforceRestrictionCommand("tenant-1", "player-clean-001", RestrictedActionType.WITHDRAWAL))
        assertEquals(RestrictionEnforcementOutcome.ALLOWED, allowedWithdrawal.outcome)
        assertEquals(AccountRestrictionType.NONE, allowedWithdrawal.currentRestriction)
        assertNull(allowedWithdrawal.denialReason)

        // 5. Replay with identical idempotency key returns identical authoritative result
        val replay = service.applyRestriction(cmd)
        assertEquals(result.resultId, replay.resultId)
        assertEquals(result.amlCaseReference, replay.amlCaseReference)

        // Observability check
        assertEquals(1, store.audit.size)
        assertEquals("AML_ACCOUNT_RESTRICTION_APPLIED", store.audit[0].type)
        assertEquals("corr-restrict-1", store.audit[0].correlationId)
        assertEquals("cause-restrict-1", store.audit[0].causationId)
        assertFalse(store.audit[0].type.contains("secret"))
    }

    @Test
    fun `AML-002-03-T002 Enforce durable account restrictions rejects invalid, boundary, unauthorized, and stale input`() {
        val store = MemoryDurableAccountRestrictionStore()
        val cache = MemoryEphemeralRestrictionCache()
        val service = service(store, cache)

        // Unauthenticated
        assertFailsWith<AuthenticationFailure.Rejected> {
            service.applyRestriction(command(principal = null, idempotencyKey = "key-unauth"))
        }.also { assertEquals(AuthErrorCode.UNAUTHENTICATED, it.code) }

        // Non-admin player
        assertFailsWith<AuthenticationFailure.Rejected> {
            service.applyRestriction(command(principal = player(), idempotencyKey = "key-player"))
        }.also { assertEquals(AuthErrorCode.FORBIDDEN, it.code) }

        // Cross-tenant admin
        assertFailsWith<AuthenticationFailure.Rejected> {
            service.applyRestriction(command(principal = admin(tenantId = "other-tenant"), idempotencyKey = "key-cross-tenant"))
        }.also { assertEquals(AuthErrorCode.FORBIDDEN, it.code) }

        // Unauthorized role lacking MANAGE_SECURITY
        val supportAdmin = AuthenticatedPrincipal("admin-support", "tenant-1", PrincipalKind.ADMIN, setOf(AdminRole.SUPPORT))
        assertFailsWith<AuthenticationFailure.Rejected> {
            service.applyRestriction(command(principal = supportAdmin, idempotencyKey = "key-support-unauth"))
        }.also { assertEquals(AuthErrorCode.FORBIDDEN, it.code) }

        // Inactive / expired session
        val expiredSessionService = DurableAccountRestrictionEnforcementService(AdminRbacPolicy(true), TestRestrictionExpiredSessionDirectory(), store, cache, clock)
        assertFailsWith<AuthenticationFailure.Rejected> {
            expiredSessionService.applyRestriction(command(idempotencyKey = "key-expired-sess"))
        }.also { assertEquals(AuthErrorCode.FORBIDDEN, it.code) }

        // Blank subject reference
        assertFailsWith<AuthenticationFailure.Rejected> {
            service.applyRestriction(command(subjectReference = "   ", idempotencyKey = "key-blank-subj"))
        }.also { assertEquals(AuthErrorCode.INVALID, it.code) }

        // Blank justification
        assertFailsWith<AuthenticationFailure.Rejected> {
            service.applyRestriction(command(justification = "   ", idempotencyKey = "key-blank-just"))
        }.also { assertEquals(AuthErrorCode.INVALID, it.code) }

        // Stale expected version
        assertFailsWith<AuthenticationFailure.Rejected> {
            service.applyRestriction(command(expectedVersion = 7L, idempotencyKey = "key-stale-ver"))
        }.also { assertEquals(AuthErrorCode.STALE, it.code) }

        // Conflicting replay with different payload
        service.applyRestriction(command(idempotencyKey = "key-conflict-restrict"))
        assertFailsWith<AuthenticationFailure.Rejected> {
            service.applyRestriction(command(
                restrictionType = AccountRestrictionType.SUSPENDED_DEPOSITS,
                idempotencyKey = "key-conflict-restrict"
            ))
        }.also { assertEquals(AuthErrorCode.CONFLICT, it.code) }
    }

    @Test
    fun `AML-002-03-T003 Enforce durable account restrictions survives concurrency, duplicate delivery, and dependency failure`() {
        val store = MemoryDurableAccountRestrictionStore()
        val cache = MemoryEphemeralRestrictionCache()
        val service = service(store, cache)

        // 1. Concurrency: duplicate submissions race with identical idempotency key
        val gate = CountDownLatch(1)
        val pool = Executors.newFixedThreadPool(4)
        val cmd = command(idempotencyKey = "key-concurrent-restrict-001")
        val calls = (1..4).map {
            pool.submit<AccountRestrictionResult> {
                gate.await()
                service.applyRestriction(cmd)
            }
        }
        gate.countDown()
        val outcomes = calls.map { runCatching { it.get() } }

        assertEquals(4, outcomes.count { it.isSuccess })
        val distinctResultIds = outcomes.mapNotNull { it.getOrNull()?.resultId }.toSet()
        assertEquals(1, distinctResultIds.size)

        // 2. Dependency failure on session directory -> fails closed (DEPENDENCY_UNAVAILABLE)
        val failingService = DurableAccountRestrictionEnforcementService(AdminRbacPolicy(true), TestRestrictionFailingSessionDirectory(), store, cache, clock)
        assertFailsWith<AuthenticationFailure.Rejected> {
            failingService.applyRestriction(command(idempotencyKey = "key-dep-fail"))
        }.also { assertEquals(AuthErrorCode.DEPENDENCY_UNAVAILABLE, it.code) }

        pool.shutdown()
    }

    @Test
    fun `AML-002-03-T004 Enforce durable account restrictions remains compatible, recoverable, observable, and lifecycle-safe`() {
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

        // Assert: restart/recreation preserves consistency
        val store = MemoryDurableAccountRestrictionStore()
        val cache = MemoryEphemeralRestrictionCache()
        val service = service(store, cache)

        val cmd = command(
            subjectReference = "player-reboot-restrict-001",
            restrictionType = AccountRestrictionType.SUSPENDED_WITHDRAWALS,
            reason = AmlReviewReason.SUSPICIOUS_ACTIVITY,
            justification = "Rapid high velocity withdrawals detected",
            idempotencyKey = "key-reboot-restrict",
            correlationId = "corr-reboot-restrict-1",
            causationId = "cause-reboot-restrict-1",
        )
        val first = service.applyRestriction(cmd)

        // Cold restart with fresh empty cache
        val coldCache = MemoryEphemeralRestrictionCache()
        val restartedService = service(store, coldCache)

        // Enforce restriction after reboot with cold cache: WITHDRAWAL is still BLOCKED
        val postRebootDecision = restartedService.enforceAction(EnforceRestrictionCommand("tenant-1", "player-reboot-restrict-001", RestrictedActionType.WITHDRAWAL))
        assertEquals(RestrictionEnforcementOutcome.BLOCKED, postRebootDecision.outcome)
        assertEquals(AccountRestrictionType.SUSPENDED_WITHDRAWALS, postRebootDecision.currentRestriction)

        // Replay produces identical result
        val second = restartedService.applyRestriction(cmd)
        assertEquals(first.resultId, second.resultId)
        assertEquals(first.amlCaseReference, second.amlCaseReference)
        assertFalse(second.financialAuthorityCreated)
        assertFalse(second.moneyMutated)

        // Observability check
        assertEquals(1, store.audit.size)
        assertEquals("AML_ACCOUNT_RESTRICTION_APPLIED", store.audit[0].type)
        assertEquals("corr-reboot-restrict-1", store.audit[0].correlationId)
        assertEquals("cause-reboot-restrict-1", store.audit[0].causationId)
        assertFalse(store.audit[0].type.contains("secret"))
    }

    private fun service(store: DurableAccountRestrictionStore, cache: EphemeralRestrictionCache) =
        DurableAccountRestrictionEnforcementService(AdminRbacPolicy(true), TestRestrictionActiveSessionDirectory(), store, cache, clock)

    private fun command(
        principal: AuthenticatedPrincipal? = admin(),
        subjectReference: String = "player-restrict-001",
        restrictionType: AccountRestrictionType = AccountRestrictionType.ACCOUNT_FROZEN,
        reason: AmlReviewReason = AmlReviewReason.HIGH_RISK_ACTION,
        justification: String = "High risk AML activity observed",
        idempotencyKey: String = "key-restrict-cmd-001",
        correlationId: String = "corr-restrict-default",
        causationId: String = "cause-restrict-default",
        expectedVersion: Long = 1L,
    ) = ApplyAccountRestrictionCommand(
        principal = principal,
        sessionId = "session-restrict-1",
        tenantId = "tenant-1",
        subjectReference = subjectReference,
        restrictionType = restrictionType,
        reason = reason,
        justification = justification,
        idempotencyKey = idempotencyKey,
        correlationId = correlationId,
        causationId = causationId,
        expectedVersion = expectedVersion,
    )

    private fun admin(tenantId: String = "tenant-1") =
        AuthenticatedPrincipal("admin-restrict-1", tenantId, PrincipalKind.ADMIN, setOf(AdminRole.SECURITY))

    private fun player() =
        AuthenticatedPrincipal("player-restrict-1", "tenant-1", PrincipalKind.PLAYER, emptySet())
}

private class TestRestrictionActiveSessionDirectory : AdminSessionDirectory {
    override fun find(tenantId: String, principalId: String, sessionId: String) =
        if (tenantId == "tenant-1" && sessionId == "session-restrict-1")
            AdminSessionStatus(true, false, Instant.parse("2026-09-17T20:00:00Z"))
        else null
}

private class TestRestrictionExpiredSessionDirectory : AdminSessionDirectory {
    override fun find(tenantId: String, principalId: String, sessionId: String) =
        AdminSessionStatus(false, false, Instant.parse("2026-09-17T18:00:00Z"))
}

private class TestRestrictionFailingSessionDirectory : AdminSessionDirectory {
    override fun find(tenantId: String, principalId: String, sessionId: String): AdminSessionStatus =
        error("session directory failure")
}

private class MemoryEphemeralRestrictionCache : EphemeralRestrictionCache {
    private val cache = mutableMapOf<String, AccountRestrictionType>()

    override fun getRestriction(tenantId: String, subjectReference: String): AccountRestrictionType? =
        synchronized(this) { cache["$tenantId:$subjectReference"] }

    override fun putRestriction(tenantId: String, subjectReference: String, restriction: AccountRestrictionType) =
        synchronized(this) { cache["$tenantId:$subjectReference"] = restriction }

    override fun evict(tenantId: String, subjectReference: String) =
        synchronized(this) { cache.remove("$tenantId:$subjectReference"); Unit }

    override fun flushAll() =
        synchronized(this) { cache.clear() }
}

private class MemoryDurableAccountRestrictionStore : DurableAccountRestrictionStore {
    val results = mutableMapOf<String, Pair<String, AccountRestrictionResult>>()
    val restrictions = mutableMapOf<String, AccountRestrictionRecord>()
    val queueItems = mutableMapOf<String, AmlQueueItem>()
    val audit = mutableListOf<AuditEvent>()
    val outbox = mutableListOf<OutboxEvent>()

    override fun findByIdempotency(tenantId: String, idempotencyKey: String) =
        synchronized(this) { results["$tenantId:$idempotencyKey"] }

    override fun findRestriction(tenantId: String, subjectReference: String) =
        synchronized(this) { restrictions["$tenantId:$subjectReference"] }

    override fun save(
        record: AccountRestrictionRecord,
        result: AccountRestrictionResult,
        tenantId: String,
        queryFingerprint: String,
        idempotencyKey: String,
        audit: AuditEvent,
        outbox: OutboxEvent,
        queueItem: AmlQueueItem,
    ) = synchronized(this) {
        results["$tenantId:$idempotencyKey"] = queryFingerprint to result
        restrictions["$tenantId:${record.subjectReference}"] = record
        queueItems[queueItem.caseReference] = queueItem
        this.audit += audit
        this.outbox += outbox
    }
}
