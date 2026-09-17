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

class AmlAlertCaseCreationTest {
    private val now = Instant.parse("2026-09-17T18:30:00Z")
    private val clock = Clock.fixed(now, ZoneOffset.UTC)

    @Test
    fun `AML-002-02-T001 Create AML alerts and review cases produces the required authoritative outcome`() {
        val store = MemoryAmlAlertCaseStore()
        val cache = MemoryEphemeralAmlRestrictionCache()
        val service = service(store, cache)

        // 1. Create alert with critical severity and account frozen restriction
        val cmd = command(
            subjectReference = "player-aml-case-001",
            alertType = AmlAlertType.SANCTIONS_HIT,
            severity = AmlAlertSeverity.CRITICAL,
            reason = AmlReviewReason.SANCTION_SCREENING,
            description = "High confidence OFAC match on sanctions list",
            restrictionApplied = AmlAccountRestriction.ACCOUNT_FROZEN,
            idempotencyKey = "key-aml-alert-001",
            correlationId = "corr-aml-alert-1",
            causationId = "cause-aml-alert-1",
        )
        val result = service.createAlertAndCase(cmd)

        // Assert: Ephemeral cache loss never erases restriction; case actions RBAC/audited
        assertEquals("player-aml-case-001", result.subjectReference)
        assertEquals(AmlAlertType.SANCTIONS_HIT, result.alertType)
        assertEquals(AmlAlertSeverity.CRITICAL, result.severity)
        assertEquals(AmlAccountRestriction.ACCOUNT_FROZEN, result.restrictionApplied)
        assertNotNull(result.caseReference)
        assertEquals(AmlReviewState.QUEUED, result.caseItem.state)
        assertFalse(result.financialAuthorityCreated) // Outcome cannot create financial authority
        assertFalse(result.moneyMutated)             // Cannot mutate money
        assertEquals("EVID-AML-ALERT-${cmd.subjectReference}", result.evidenceReference)

        // Assert: Committed rows/constraints and transactional atomicity in store
        val storedAlert = store.alerts[result.alertId]
        assertNotNull(storedAlert)
        assertEquals(result.caseReference, storedAlert.caseReference)

        // Alert no case prevented: review case item exists in queue store
        val storedCase = store.queueItems[result.caseReference]
        assertNotNull(storedCase)
        assertEquals(AmlReviewState.QUEUED, storedCase.state)

        // Ephemeral cache loss never erases restriction:
        // Currently cached
        assertEquals(AmlAccountRestriction.ACCOUNT_FROZEN, cache.getRestriction("tenant-1", "player-aml-case-001"))

        // Simulate Redis loss / cache flush / eviction
        cache.flushAll()
        assertNull(cache.getRestriction("tenant-1", "player-aml-case-001"))

        // Verify that checkRestriction still returns ACCOUNT_FROZEN from durable store!
        val preservedRestriction = service.checkRestriction("tenant-1", "player-aml-case-001")
        assertEquals(AmlAccountRestriction.ACCOUNT_FROZEN, preservedRestriction)
        assertEquals(AmlAccountRestriction.ACCOUNT_FROZEN, cache.getRestriction("tenant-1", "player-aml-case-001"))

        // 2. Replay with identical idempotency key returns identical authoritative result
        val replay = service.createAlertAndCase(cmd)
        assertEquals(result.resultId, replay.resultId)
        assertEquals(result.alertId, replay.alertId)
        assertEquals(result.caseReference, replay.caseReference)

        // Observability check
        assertEquals(1, store.audit.size)
        assertEquals("AML_ALERT_CASE_CREATED", store.audit[0].type)
        assertEquals("corr-aml-alert-1", store.audit[0].correlationId)
        assertEquals("cause-aml-alert-1", store.audit[0].causationId)
        assertFalse(store.audit[0].type.contains("secret"))
    }

    @Test
    fun `AML-002-02-T002 Create AML alerts and review cases rejects invalid, boundary, unauthorized, and stale input`() {
        val store = MemoryAmlAlertCaseStore()
        val cache = MemoryEphemeralAmlRestrictionCache()
        val service = service(store, cache)

        // Unauthenticated
        assertFailsWith<AuthenticationFailure.Rejected> {
            service.createAlertAndCase(command(principal = null, idempotencyKey = "key-unauth"))
        }.also { assertEquals(AuthErrorCode.UNAUTHENTICATED, it.code) }

        // Non-admin player
        assertFailsWith<AuthenticationFailure.Rejected> {
            service.createAlertAndCase(command(principal = player(), idempotencyKey = "key-player"))
        }.also { assertEquals(AuthErrorCode.FORBIDDEN, it.code) }

        // Cross-tenant admin
        assertFailsWith<AuthenticationFailure.Rejected> {
            service.createAlertAndCase(command(principal = admin(tenantId = "other-tenant"), idempotencyKey = "key-cross-tenant"))
        }.also { assertEquals(AuthErrorCode.FORBIDDEN, it.code) }

        // Unauthorized role lacking MANAGE_SECURITY
        val supportAdmin = AuthenticatedPrincipal("admin-support", "tenant-1", PrincipalKind.ADMIN, setOf(AdminRole.SUPPORT))
        assertFailsWith<AuthenticationFailure.Rejected> {
            service.createAlertAndCase(command(principal = supportAdmin, idempotencyKey = "key-support-unauth"))
        }.also { assertEquals(AuthErrorCode.FORBIDDEN, it.code) }

        // Inactive / expired session
        val expiredSessionService = AmlAlertCaseCreationService(AdminRbacPolicy(true), TestAmlCaseExpiredSessionDirectory(), store, cache, clock)
        assertFailsWith<AuthenticationFailure.Rejected> {
            expiredSessionService.createAlertAndCase(command(idempotencyKey = "key-expired-sess"))
        }.also { assertEquals(AuthErrorCode.FORBIDDEN, it.code) }

        // Blank subject reference
        assertFailsWith<AuthenticationFailure.Rejected> {
            service.createAlertAndCase(command(subjectReference = "   ", idempotencyKey = "key-blank-subj"))
        }.also { assertEquals(AuthErrorCode.INVALID, it.code) }

        // Blank description
        assertFailsWith<AuthenticationFailure.Rejected> {
            service.createAlertAndCase(command(description = "   ", idempotencyKey = "key-blank-desc"))
        }.also { assertEquals(AuthErrorCode.INVALID, it.code) }

        // Stale expected version
        assertFailsWith<AuthenticationFailure.Rejected> {
            service.createAlertAndCase(command(expectedVersion = 5L, idempotencyKey = "key-stale-ver"))
        }.also { assertEquals(AuthErrorCode.STALE, it.code) }

        // Conflicting replay with different payload
        service.createAlertAndCase(command(idempotencyKey = "key-conflict-aml"))
        assertFailsWith<AuthenticationFailure.Rejected> {
            service.createAlertAndCase(command(description = "Altered description for conflict", idempotencyKey = "key-conflict-aml"))
        }.also { assertEquals(AuthErrorCode.CONFLICT, it.code) }
    }

    @Test
    fun `AML-002-02-T003 Create AML alerts and review cases survives concurrency, duplicate delivery, and dependency failure`() {
        val store = MemoryAmlAlertCaseStore()
        val cache = MemoryEphemeralAmlRestrictionCache()
        val service = service(store, cache)

        // 1. Concurrency: duplicate submissions race with identical idempotency key
        val gate = CountDownLatch(1)
        val pool = Executors.newFixedThreadPool(4)
        val cmd = command(idempotencyKey = "key-concurrent-aml-001")
        val calls = (1..4).map {
            pool.submit<AmlAlertCaseResult> {
                gate.await()
                service.createAlertAndCase(cmd)
            }
        }
        gate.countDown()
        val outcomes = calls.map { runCatching { it.get() } }

        assertEquals(4, outcomes.count { it.isSuccess })
        val distinctResultIds = outcomes.mapNotNull { it.getOrNull()?.resultId }.toSet()
        assertEquals(1, distinctResultIds.size)

        // 2. Dependency failure on session directory -> fails closed (DEPENDENCY_UNAVAILABLE)
        val failingService = AmlAlertCaseCreationService(AdminRbacPolicy(true), TestAmlCaseFailingSessionDirectory(), store, cache, clock)
        assertFailsWith<AuthenticationFailure.Rejected> {
            failingService.createAlertAndCase(command(idempotencyKey = "key-dep-fail"))
        }.also { assertEquals(AuthErrorCode.DEPENDENCY_UNAVAILABLE, it.code) }

        pool.shutdown()
    }

    @Test
    fun `AML-002-02-T004 Create AML alerts and review cases remains compatible, recoverable, observable, and lifecycle-safe`() {
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
        val store = MemoryAmlAlertCaseStore()
        val cache = MemoryEphemeralAmlRestrictionCache()
        val service = service(store, cache)

        val cmd = command(
            subjectReference = "player-reboot-aml-001",
            alertType = AmlAlertType.STRUCTURING_DETECTED,
            severity = AmlAlertSeverity.HIGH,
            reason = AmlReviewReason.STRUCTURING_ALERT,
            description = "Multiple transactions just below 10k EUR",
            restrictionApplied = AmlAccountRestriction.SUSPENDED_WITHDRAWALS,
            idempotencyKey = "key-reboot-aml",
            correlationId = "corr-reboot-aml-1",
            causationId = "cause-reboot-aml-1",
        )
        val first = service.createAlertAndCase(cmd)

        // Cold restart with fresh empty cache
        val coldCache = MemoryEphemeralAmlRestrictionCache()
        val restartedService = service(store, coldCache)

        // Restriction survives restart and cold cache
        val restoredRestriction = restartedService.checkRestriction("tenant-1", "player-reboot-aml-001")
        assertEquals(AmlAccountRestriction.SUSPENDED_WITHDRAWALS, restoredRestriction)

        // Replay produces identical result
        val second = restartedService.createAlertAndCase(cmd)
        assertEquals(first.resultId, second.resultId)
        assertEquals(first.alertId, second.alertId)
        assertEquals(first.caseReference, second.caseReference)
        assertFalse(second.financialAuthorityCreated)
        assertFalse(second.moneyMutated)

        // Observability check
        assertEquals(1, store.audit.size)
        assertEquals("AML_ALERT_CASE_CREATED", store.audit[0].type)
        assertEquals("corr-reboot-aml-1", store.audit[0].correlationId)
        assertEquals("cause-reboot-aml-1", store.audit[0].causationId)
        assertFalse(store.audit[0].type.contains("secret"))
    }

    private fun service(store: AmlAlertCaseStore, cache: EphemeralAmlRestrictionCache) =
        AmlAlertCaseCreationService(AdminRbacPolicy(true), TestAmlCaseActiveSessionDirectory(), store, cache, clock)

    private fun command(
        principal: AuthenticatedPrincipal? = admin(),
        subjectReference: String = "player-aml-case-001",
        alertType: AmlAlertType = AmlAlertType.SUSPICIOUS_TRANSACTION,
        severity: AmlAlertSeverity = AmlAlertSeverity.HIGH,
        reason: AmlReviewReason = AmlReviewReason.SUSPICIOUS_ACTIVITY,
        description: String = "Unusual transaction velocity alert",
        restrictionApplied: AmlAccountRestriction = AmlAccountRestriction.NONE,
        idempotencyKey: String = "key-aml-case-cmd-001",
        correlationId: String = "corr-aml-default",
        causationId: String = "cause-aml-default",
        expectedVersion: Long = 1L,
    ) = CreateAmlAlertCommand(
        principal = principal,
        sessionId = "session-aml-case-1",
        tenantId = "tenant-1",
        subjectReference = subjectReference,
        alertType = alertType,
        severity = severity,
        reason = reason,
        description = description,
        restrictionApplied = restrictionApplied,
        idempotencyKey = idempotencyKey,
        correlationId = correlationId,
        causationId = causationId,
        expectedVersion = expectedVersion,
    )

    private fun admin(tenantId: String = "tenant-1") =
        AuthenticatedPrincipal("admin-aml-case-1", tenantId, PrincipalKind.ADMIN, setOf(AdminRole.SECURITY))

    private fun player() =
        AuthenticatedPrincipal("player-aml-case-1", "tenant-1", PrincipalKind.PLAYER, emptySet())
}

private class TestAmlCaseActiveSessionDirectory : AdminSessionDirectory {
    override fun find(tenantId: String, principalId: String, sessionId: String) =
        if (tenantId == "tenant-1" && sessionId == "session-aml-case-1")
            AdminSessionStatus(true, false, Instant.parse("2026-09-17T19:30:00Z"))
        else null
}

private class TestAmlCaseExpiredSessionDirectory : AdminSessionDirectory {
    override fun find(tenantId: String, principalId: String, sessionId: String) =
        AdminSessionStatus(false, false, Instant.parse("2026-09-17T17:30:00Z"))
}

private class TestAmlCaseFailingSessionDirectory : AdminSessionDirectory {
    override fun find(tenantId: String, principalId: String, sessionId: String): AdminSessionStatus =
        error("session directory failure")
}

private class MemoryEphemeralAmlRestrictionCache : EphemeralAmlRestrictionCache {
    private val cache = mutableMapOf<String, AmlAccountRestriction>()

    override fun getRestriction(tenantId: String, subjectReference: String): AmlAccountRestriction? =
        synchronized(this) { cache["$tenantId:$subjectReference"] }

    override fun putRestriction(tenantId: String, subjectReference: String, restriction: AmlAccountRestriction) =
        synchronized(this) { cache["$tenantId:$subjectReference"] = restriction }

    override fun evict(tenantId: String, subjectReference: String) =
        synchronized(this) { cache.remove("$tenantId:$subjectReference"); Unit }

    override fun flushAll() =
        synchronized(this) { cache.clear() }
}

private class MemoryAmlAlertCaseStore : AmlAlertCaseStore {
    val results = mutableMapOf<String, Pair<String, AmlAlertCaseResult>>()
    val alerts = mutableMapOf<UUID, AmlAlertRecord>()
    val restrictions = mutableMapOf<String, AmlAccountRestriction>()
    val queueItems = mutableMapOf<String, AmlQueueItem>()
    val audit = mutableListOf<AuditEvent>()
    val outbox = mutableListOf<OutboxEvent>()

    override fun findByIdempotency(tenantId: String, idempotencyKey: String) =
        synchronized(this) { results["$tenantId:$idempotencyKey"] }

    override fun findActiveRestriction(tenantId: String, subjectReference: String) =
        synchronized(this) { restrictions["$tenantId:$subjectReference"] }

    override fun findAlert(tenantId: String, alertId: UUID) =
        synchronized(this) { alerts[alertId] }

    override fun save(
        alert: AmlAlertRecord,
        result: AmlAlertCaseResult,
        tenantId: String,
        queryFingerprint: String,
        idempotencyKey: String,
        audit: AuditEvent,
        outbox: OutboxEvent,
        queueItem: AmlQueueItem,
    ) = synchronized(this) {
        results["$tenantId:$idempotencyKey"] = queryFingerprint to result
        alerts[alert.alertId] = alert
        if (alert.restriction != AmlAccountRestriction.NONE) {
            restrictions["$tenantId:${alert.subjectReference}"] = alert.restriction
        }
        queueItems[queueItem.caseReference] = queueItem
        this.audit += audit
        this.outbox += outbox
    }
}
