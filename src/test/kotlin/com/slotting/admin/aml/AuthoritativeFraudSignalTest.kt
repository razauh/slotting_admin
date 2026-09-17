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

class AuthoritativeFraudSignalTest {
    private val now = Instant.parse("2026-09-17T18:00:00Z")
    private val clock = Clock.fixed(now, ZoneOffset.UTC)

    @Test
    fun `AML-002-01-T001 Collect authoritative fraud signals produces the required authoritative outcome`() {
        val store = MemoryFraudSignalStore()
        val cache = MemoryEphemeralFraudSignalCache()
        val service = service(store, cache)

        // 1. High-risk signal (compromised device + velocity) -> must restrict/freeze account, queue review case (no alert without case)
        val highRiskCmd = command(
            subjectReference = "player-fraud-001",
            signals = FraudSignalPayload(
                subjectReference = "player-fraud-001",
                deviceFingerprint = "dev-fp-compromised-99",
                ipAddress = "192.168.1.100",
                isDeviceCompromised = true,
                velocityCountInWindow = 12,
                distinctIpCountInWindow = 4,
                isVpnOrProxy = true,
            ),
            idempotencyKey = "key-fraud-sig-001",
            correlationId = "corr-fraud-1",
            causationId = "cause-fraud-1",
        )
        val highRiskRes = service.collectSignals(highRiskCmd)

        // Assert: Ephemeral cache loss never erases restriction; case actions RBAC/audited
        assertEquals(FraudRestrictionLevel.FROZEN, highRiskRes.restrictionLevel)
        assertEquals(FraudAlertSeverity.CRITICAL, highRiskRes.alertSeverity)
        assertNotNull(highRiskRes.amlCaseReference)
        assertEquals(AmlReviewReason.HIGH_RISK_ACTION, highRiskRes.amlQueueReason)
        assertTrue(highRiskRes.detectedAnomalies.contains("COMPROMISED_DEVICE"))
        assertFalse(highRiskRes.financialAuthorityCreated) // Outcome cannot create financial authority
        assertFalse(highRiskRes.moneyMutated)             // Cannot mutate money
        assertEquals("EVID-FRAUD-player-fraud-001", highRiskRes.evidenceReference)

        // Provenance assertions
        assertEquals(12, highRiskRes.provenance.observedVelocity)
        assertTrue(highRiskRes.provenance.deviceCompromised)
        assertTrue(highRiskRes.provenance.vpnOrProxyDetected)

        // Assert: Atomic queue item created in store (alert always has a case)
        val queuedItem = store.queuedItems[highRiskRes.amlCaseReference]
        assertNotNull(queuedItem)
        assertEquals(AmlReviewState.QUEUED, queuedItem.state)

        // Assert: Ephemeral cache loss never erases restriction!
        // Verify cache currently has the restriction
        assertEquals(FraudRestrictionLevel.FROZEN, cache.getRestriction("tenant-1", "player-fraud-001"))

        // Simulate Redis loss / cache flush / eviction
        cache.flushAll()
        assertNull(cache.getRestriction("tenant-1", "player-fraud-001"))

        // Verify that checkRestriction still returns FROZEN from durable storage!
        val preservedRestriction = service.checkRestriction("tenant-1", "player-fraud-001")
        assertEquals(FraudRestrictionLevel.FROZEN, preservedRestriction)
        // And repopulates cache
        assertEquals(FraudRestrictionLevel.FROZEN, cache.getRestriction("tenant-1", "player-fraud-001"))

        // 2. Velocity spike only -> RESTRICTED with SUSPICIOUS_ACTIVITY
        val velocityCmd = command(
            subjectReference = "player-fraud-002",
            signals = FraudSignalPayload(
                subjectReference = "player-fraud-002",
                deviceFingerprint = "dev-fp-normal-1",
                ipAddress = "10.0.0.1",
                velocityCountInWindow = 15,
                distinctIpCountInWindow = 1,
            ),
            idempotencyKey = "key-fraud-sig-002",
        )
        val velRes = service.collectSignals(velocityCmd)
        assertEquals(FraudRestrictionLevel.RESTRICTED, velRes.restrictionLevel)
        assertEquals(FraudAlertSeverity.HIGH, velRes.alertSeverity)
        assertEquals(AmlReviewReason.SUSPICIOUS_ACTIVITY, velRes.amlQueueReason)
        assertNotNull(velRes.amlCaseReference)
        assertNotNull(store.queuedItems[velRes.amlCaseReference])

        // 3. Clean signals -> NONE with LOW alert severity and no case queued
        val cleanCmd = command(
            subjectReference = "player-fraud-003",
            signals = FraudSignalPayload(
                subjectReference = "player-fraud-003",
                deviceFingerprint = "dev-fp-clean-1",
                ipAddress = "10.0.0.2",
                velocityCountInWindow = 1,
                distinctIpCountInWindow = 1,
            ),
            idempotencyKey = "key-fraud-clean-001",
        )
        val cleanRes = service.collectSignals(cleanCmd)
        assertEquals(FraudRestrictionLevel.NONE, cleanRes.restrictionLevel)
        assertEquals(FraudAlertSeverity.LOW, cleanRes.alertSeverity)
        assertNull(cleanRes.amlCaseReference)
        assertNull(cleanRes.amlQueueReason)

        // 4. Replay with identical idempotency key returns identical result
        val replay = service.collectSignals(highRiskCmd)
        assertEquals(highRiskRes.resultId, replay.resultId)
        assertEquals(highRiskRes.evidenceReference, replay.evidenceReference)

        // Observability check
        assertEquals(3, store.audit.size)
        assertEquals("AML_FRAUD_SIGNAL_COLLECTION", store.audit[0].type)
        assertEquals("corr-fraud-1", store.audit[0].correlationId)
        assertEquals("cause-fraud-1", store.audit[0].causationId)
        assertFalse(store.audit[0].type.contains("secret"))
    }

    @Test
    fun `AML-002-01-T002 Collect authoritative fraud signals rejects invalid, boundary, unauthorized, and stale input`() {
        val store = MemoryFraudSignalStore()
        val cache = MemoryEphemeralFraudSignalCache()
        val service = service(store, cache)

        // Unauthenticated
        assertFailsWith<AuthenticationFailure.Rejected> {
            service.collectSignals(command(principal = null, idempotencyKey = "key-unauth"))
        }.also { assertEquals(AuthErrorCode.UNAUTHENTICATED, it.code) }

        // Non-admin player
        assertFailsWith<AuthenticationFailure.Rejected> {
            service.collectSignals(command(principal = player(), idempotencyKey = "key-player"))
        }.also { assertEquals(AuthErrorCode.FORBIDDEN, it.code) }

        // Cross-tenant admin
        assertFailsWith<AuthenticationFailure.Rejected> {
            service.collectSignals(command(principal = admin(tenantId = "other-tenant"), idempotencyKey = "key-cross-tenant"))
        }.also { assertEquals(AuthErrorCode.FORBIDDEN, it.code) }

        // Unauthorized role lacking MANAGE_SECURITY
        val supportAdmin = AuthenticatedPrincipal("admin-support", "tenant-1", PrincipalKind.ADMIN, setOf(AdminRole.SUPPORT))
        assertFailsWith<AuthenticationFailure.Rejected> {
            service.collectSignals(command(principal = supportAdmin, idempotencyKey = "key-support-unauth"))
        }.also { assertEquals(AuthErrorCode.FORBIDDEN, it.code) }

        // Inactive / expired session
        val expiredSessionService = AuthoritativeFraudSignalService(AdminRbacPolicy(true), TestFraudExpiredSessionDirectory(), store, cache, clock)
        assertFailsWith<AuthenticationFailure.Rejected> {
            expiredSessionService.collectSignals(command(idempotencyKey = "key-expired-sess"))
        }.also { assertEquals(AuthErrorCode.FORBIDDEN, it.code) }

        // Blank subject reference
        assertFailsWith<AuthenticationFailure.Rejected> {
            service.collectSignals(command(subjectReference = "   ", idempotencyKey = "key-blank-subj"))
        }.also { assertEquals(AuthErrorCode.INVALID, it.code) }

        // Blank device fingerprint
        assertFailsWith<AuthenticationFailure.Rejected> {
            service.collectSignals(command(
                signals = FraudSignalPayload(subjectReference = "player-1", deviceFingerprint = "   ", ipAddress = "127.0.0.1"),
                idempotencyKey = "key-blank-device"
            ))
        }.also { assertEquals(AuthErrorCode.INVALID, it.code) }

        // Blank IP address
        assertFailsWith<AuthenticationFailure.Rejected> {
            service.collectSignals(command(
                signals = FraudSignalPayload(subjectReference = "player-1", deviceFingerprint = "dev-1", ipAddress = "   "),
                idempotencyKey = "key-blank-ip"
            ))
        }.also { assertEquals(AuthErrorCode.INVALID, it.code) }

        // Stale expected version
        assertFailsWith<AuthenticationFailure.Rejected> {
            service.collectSignals(command(expectedVersion = 4L, idempotencyKey = "key-stale-ver"))
        }.also { assertEquals(AuthErrorCode.STALE, it.code) }

        // Conflicting replay with different payload
        service.collectSignals(command(idempotencyKey = "key-conflict-fraud"))
        assertFailsWith<AuthenticationFailure.Rejected> {
            service.collectSignals(command(
                signals = FraudSignalPayload(subjectReference = "player-fraud-001", deviceFingerprint = "dev-altered", ipAddress = "10.99.99.99"),
                idempotencyKey = "key-conflict-fraud"
            ))
        }.also { assertEquals(AuthErrorCode.CONFLICT, it.code) }
    }

    @Test
    fun `AML-002-01-T003 Collect authoritative fraud signals survives concurrency, duplicate delivery, and dependency failure`() {
        val store = MemoryFraudSignalStore()
        val cache = MemoryEphemeralFraudSignalCache()
        val service = service(store, cache)

        // 1. Concurrency: duplicate submissions race with identical idempotency key
        val gate = CountDownLatch(1)
        val pool = Executors.newFixedThreadPool(4)
        val cmd = command(idempotencyKey = "key-concurrent-fraud-001")
        val calls = (1..4).map {
            pool.submit<FraudSignalCollectionResult> {
                gate.await()
                service.collectSignals(cmd)
            }
        }
        gate.countDown()
        val outcomes = calls.map { runCatching { it.get() } }

        assertEquals(4, outcomes.count { it.isSuccess })
        val distinctResultIds = outcomes.mapNotNull { it.getOrNull()?.resultId }.toSet()
        assertEquals(1, distinctResultIds.size)

        // 2. Dependency failure on session directory -> fails closed (DEPENDENCY_UNAVAILABLE)
        val failingService = AuthoritativeFraudSignalService(AdminRbacPolicy(true), TestFraudFailingSessionDirectory(), store, cache, clock)
        assertFailsWith<AuthenticationFailure.Rejected> {
            failingService.collectSignals(command(idempotencyKey = "key-dep-fail"))
        }.also { assertEquals(AuthErrorCode.DEPENDENCY_UNAVAILABLE, it.code) }

        pool.shutdown()
    }

    @Test
    fun `AML-002-01-T004 Collect authoritative fraud signals remains compatible, recoverable, observable, and lifecycle-safe`() {
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
        val store = MemoryFraudSignalStore()
        val cache = MemoryEphemeralFraudSignalCache()
        val service = service(store, cache)

        val cmd = command(
            subjectReference = "player-reboot-001",
            signals = FraudSignalPayload(
                subjectReference = "player-reboot-001",
                deviceFingerprint = "dev-reboot-fp",
                ipAddress = "127.0.0.1",
                isDeviceCompromised = true,
            ),
            idempotencyKey = "key-reboot-fraud",
            correlationId = "corr-reboot-fraud-1",
            causationId = "cause-reboot-fraud-1",
        )
        val first = service.collectSignals(cmd)

        // Recreate service with wiped cache (cold restart)
        val coldCache = MemoryEphemeralFraudSignalCache()
        val restartedService = service(store, coldCache)

        // Ephemeral cache loss after reboot still retains restriction
        val restrictionAfterReboot = restartedService.checkRestriction("tenant-1", "player-reboot-001")
        assertEquals(FraudRestrictionLevel.FROZEN, restrictionAfterReboot)

        // Replay returns identical result
        val second = restartedService.collectSignals(cmd)
        assertEquals(first.resultId, second.resultId)
        assertEquals(first.evidenceReference, second.evidenceReference)
        assertFalse(second.financialAuthorityCreated)
        assertFalse(second.moneyMutated)

        // Observability check
        assertEquals(1, store.audit.size)
        assertEquals("AML_FRAUD_SIGNAL_COLLECTION", store.audit[0].type)
        assertEquals("corr-reboot-fraud-1", store.audit[0].correlationId)
        assertEquals("cause-reboot-fraud-1", store.audit[0].causationId)
        assertFalse(store.audit[0].type.contains("secret"))
    }

    private fun service(store: FraudSignalStore, cache: EphemeralFraudSignalCache) =
        AuthoritativeFraudSignalService(AdminRbacPolicy(true), TestFraudActiveSessionDirectory(), store, cache, clock)

    private fun command(
        principal: AuthenticatedPrincipal? = admin(),
        subjectReference: String = "player-fraud-001",
        signals: FraudSignalPayload = FraudSignalPayload(
            subjectReference = subjectReference,
            deviceFingerprint = "dev-fp-default",
            ipAddress = "127.0.0.1",
        ),
        idempotencyKey: String = "key-fraud-cmd-001",
        correlationId: String = "corr-fraud-default",
        causationId: String = "cause-fraud-default",
        expectedVersion: Long = 1L,
    ) = CollectFraudSignalsCommand(
        principal = principal,
        sessionId = "session-fraud-1",
        tenantId = "tenant-1",
        subjectReference = subjectReference,
        signals = signals,
        idempotencyKey = idempotencyKey,
        correlationId = correlationId,
        causationId = causationId,
        expectedVersion = expectedVersion,
    )

    private fun admin(tenantId: String = "tenant-1") =
        AuthenticatedPrincipal("admin-fraud-1", tenantId, PrincipalKind.ADMIN, setOf(AdminRole.SECURITY))

    private fun player() =
        AuthenticatedPrincipal("player-fraud-1", "tenant-1", PrincipalKind.PLAYER, emptySet())
}

private class TestFraudActiveSessionDirectory : AdminSessionDirectory {
    override fun find(tenantId: String, principalId: String, sessionId: String) =
        if (tenantId == "tenant-1" && sessionId == "session-fraud-1")
            AdminSessionStatus(true, false, Instant.parse("2026-09-17T19:00:00Z"))
        else null
}

private class TestFraudExpiredSessionDirectory : AdminSessionDirectory {
    override fun find(tenantId: String, principalId: String, sessionId: String) =
        AdminSessionStatus(false, false, Instant.parse("2026-09-17T17:00:00Z"))
}

private class TestFraudFailingSessionDirectory : AdminSessionDirectory {
    override fun find(tenantId: String, principalId: String, sessionId: String): AdminSessionStatus =
        error("session directory failure")
}

private class MemoryEphemeralFraudSignalCache : EphemeralFraudSignalCache {
    private val cache = mutableMapOf<String, FraudRestrictionLevel>()

    override fun getRestriction(tenantId: String, subjectReference: String): FraudRestrictionLevel? =
        synchronized(this) { cache["$tenantId:$subjectReference"] }

    override fun putRestriction(tenantId: String, subjectReference: String, level: FraudRestrictionLevel) =
        synchronized(this) { cache["$tenantId:$subjectReference"] = level }

    override fun evict(tenantId: String, subjectReference: String) =
        synchronized(this) { cache.remove("$tenantId:$subjectReference"); Unit }

    override fun flushAll() =
        synchronized(this) { cache.clear() }
}

private class MemoryFraudSignalStore : FraudSignalStore {
    val results = mutableMapOf<String, Pair<String, FraudSignalCollectionResult>>()
    val records = mutableMapOf<String, DurableFraudRecord>()
    val queuedItems = mutableMapOf<String, AmlQueueItem>()
    val audit = mutableListOf<AuditEvent>()
    val outbox = mutableListOf<OutboxEvent>()

    override fun findByIdempotency(tenantId: String, idempotencyKey: String) =
        synchronized(this) { results["$tenantId:$idempotencyKey"] }

    override fun findRecord(tenantId: String, subjectReference: String) =
        synchronized(this) { records["$tenantId:$subjectReference"] }

    override fun save(
        record: DurableFraudRecord,
        result: FraudSignalCollectionResult,
        tenantId: String,
        queryFingerprint: String,
        idempotencyKey: String,
        audit: AuditEvent,
        outbox: OutboxEvent,
        queuedAmlItem: AmlQueueItem?,
    ) = synchronized(this) {
        results["$tenantId:$idempotencyKey"] = queryFingerprint to result
        records["$tenantId:${record.subjectReference}"] = record
        queuedAmlItem?.let { queuedItems[it.caseReference] = it }
        this.audit += audit
        this.outbox += outbox
    }
}
