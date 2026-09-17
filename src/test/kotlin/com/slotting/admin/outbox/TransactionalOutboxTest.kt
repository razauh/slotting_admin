package com.slotting.admin.outbox

import com.slotting.admin.auth.*
import java.io.File
import java.time.Clock
import java.time.Instant
import java.time.ZoneOffset
import java.util.UUID
import java.util.concurrent.CountDownLatch
import java.util.concurrent.Executors
import java.util.concurrent.atomic.AtomicInteger
import kotlin.test.*
import org.junit.jupiter.api.Test

class TransactionalOutboxTest {
    private val now = Instant.parse("2026-09-17T12:00:00Z")
    private val clock = Clock.fixed(now, ZoneOffset.UTC)

    @Test
    fun `ADR-003-01-T001 Decide transactional outbox contract produces the required authoritative outcome`() {
        val store = OutboxMemoryStore()
        val broker = FakeOutboxBroker()
        val alerts = FakeOutboxAlertSink()
        val service = service(store, broker, alerts)

        // 1. Stage an outbox event alongside DB authority
        val stageCmd = stageCommand(
            eventType = "ACCOUNT_SUSPENDED",
            topic = "player-events",
            payload = "{\"playerId\":\"player-123\",\"reason\":\"terms_violation\"}",
            correlationId = "corr-100",
            causationId = "cause-100",
            idempotencyKey = "outbox-stage-001",
        )
        val stagedResult = service.stage(stageCmd)
        assertEquals(OutboxStatus.PENDING, stagedResult.status)
        assertEquals("corr-100", stagedResult.correlationId)
        assertEquals("cause-100", stagedResult.causationId)

        // Verify DB remains authority (stored in DB memory store)
        val eventInDb = store.findEvent("tenant-1", stagedResult.eventId)
        assertNotNull(eventInDb)
        assertEquals(OutboxStatus.PENDING, eventInDb.status)
        assertEquals("corr-100", eventInDb.correlationId)
        assertEquals("cause-100", eventInDb.causationId)

        // 2. Replay with same idempotency key preserves causation
        val replayResult = service.stage(stageCmd)
        assertEquals(stagedResult.resultId, replayResult.resultId)
        assertEquals(stagedResult.eventId, replayResult.eventId)
        assertEquals("cause-100", replayResult.causationId)
        assertEquals("corr-100", replayResult.correlationId)

        // 3. Publish outbox event to broker
        val pubCmd = PublishOutboxCommand(
            principal = admin(),
            sessionId = "session-outbox-1",
            tenantId = "tenant-1",
            eventId = stagedResult.eventId,
            expectedVersion = eventInDb.version,
        )
        val publishedResult = service.publish(pubCmd)
        assertEquals(OutboxStatus.PUBLISHED, publishedResult.status)
        assertEquals(1, broker.publishedEvents.size)
        assertEquals("cause-100", broker.publishedEvents[0].causationId)

        // 4. Poison event quarantine and alert
        val poisonCmd = stageCommand(
            eventType = "POISON_EVENT",
            topic = "poison-events",
            payload = "{\"corrupt\":\"POISON\"}",
            idempotencyKey = "outbox-poison-001",
        )
        val poisonStaged = service.stage(poisonCmd)
        val poisonInDb = store.findEvent("tenant-1", poisonStaged.eventId)!!

        val poisonPubCmd = PublishOutboxCommand(
            principal = admin(),
            sessionId = "session-outbox-1",
            tenantId = "tenant-1",
            eventId = poisonStaged.eventId,
            expectedVersion = poisonInDb.version,
        )
        val poisonResult = service.publish(poisonPubCmd)
        assertEquals(OutboxStatus.QUARANTINED, poisonResult.status)
        assertEquals(1, alerts.emittedAlerts.size)
        assertEquals(poisonStaged.eventId, alerts.emittedAlerts[0].eventId)

        // Assert: DB remains authority, no money mutated, no secrets disclosed
        assertEquals(3, store.audit.size)
        assertFalse(store.audit[0].type.contains("secret"))
        assertTrue(alerts.emittedAlerts[0].reason.contains("poison") || alerts.emittedAlerts[0].reason.contains("quarantine"))
    }

    @Test
    fun `ADR-003-01-T002 Decide transactional outbox contract rejects invalid, boundary, unauthorized, and stale input`() {
        val store = OutboxMemoryStore()
        val broker = FakeOutboxBroker()
        val alerts = FakeOutboxAlertSink()
        val service = service(store, broker, alerts)

        // Unauthenticated
        assertFailsWith<AuthenticationFailure.Rejected> {
            service.stage(stageCommand(principal = null, idempotencyKey = "unauth-key"))
        }.also { assertEquals(AuthErrorCode.UNAUTHENTICATED, it.code) }

        // Non-admin player
        assertFailsWith<AuthenticationFailure.Rejected> {
            service.stage(stageCommand(principal = player(), idempotencyKey = "player-key"))
        }.also { assertEquals(AuthErrorCode.FORBIDDEN, it.code) }

        // Cross-tenant
        assertFailsWith<AuthenticationFailure.Rejected> {
            service.stage(stageCommand(principal = admin(tenantId = "tenant-other"), idempotencyKey = "cross-tenant-key"))
        }.also { assertEquals(AuthErrorCode.FORBIDDEN, it.code) }

        // Invalid: blank eventType, topic, correlationId, causationId
        assertFailsWith<AuthenticationFailure.Rejected> {
            service.stage(stageCommand(eventType = "  ", idempotencyKey = "blank-type-key"))
        }.also { assertEquals(AuthErrorCode.INVALID, it.code) }

        assertFailsWith<AuthenticationFailure.Rejected> {
            service.stage(stageCommand(topic = "", idempotencyKey = "blank-topic-key"))
        }.also { assertEquals(AuthErrorCode.INVALID, it.code) }

        assertFailsWith<AuthenticationFailure.Rejected> {
            service.stage(stageCommand(correlationId = "", idempotencyKey = "blank-corr-key"))
        }.also { assertEquals(AuthErrorCode.INVALID, it.code) }

        assertFailsWith<AuthenticationFailure.Rejected> {
            service.stage(stageCommand(causationId = "", idempotencyKey = "blank-cause-key"))
        }.also { assertEquals(AuthErrorCode.INVALID, it.code) }

        // Conflict: reuse same idempotency key with different payload
        service.stage(stageCommand(payload = "{\"v\":1}", idempotencyKey = "conflict-key"))
        assertFailsWith<AuthenticationFailure.Rejected> {
            service.stage(stageCommand(payload = "{\"v\":2}", idempotencyKey = "conflict-key"))
        }.also { assertEquals(AuthErrorCode.CONFLICT, it.code) }

        // Publish unknown event -> FORBIDDEN
        assertFailsWith<AuthenticationFailure.Rejected> {
            service.publish(
                PublishOutboxCommand(
                    principal = admin(),
                    sessionId = "session-outbox-1",
                    tenantId = "tenant-1",
                    eventId = UUID.randomUUID(),
                    expectedVersion = 1L,
                )
            )
        }.also { assertEquals(AuthErrorCode.FORBIDDEN, it.code) }

        // Stale version on publish
        val validStage = service.stage(stageCommand(idempotencyKey = "valid-stage-stale"))
        assertFailsWith<AuthenticationFailure.Rejected> {
            service.publish(
                PublishOutboxCommand(
                    principal = admin(),
                    sessionId = "session-outbox-1",
                    tenantId = "tenant-1",
                    eventId = validStage.eventId,
                    expectedVersion = 999L,
                )
            )
        }.also { assertEquals(AuthErrorCode.STALE, it.code) }
    }

    @Test
    fun `ADR-003-01-T003 Decide transactional outbox contract survives concurrency, duplicate delivery, and dependency failure`() {
        val store = OutboxMemoryStore()
        val broker = FakeOutboxBroker()
        val alerts = FakeOutboxAlertSink()
        val service = service(store, broker, alerts)

        // 1. Benchmark concurrent duplicate staging with same idempotency key
        val gate = CountDownLatch(1)
        val pool = Executors.newFixedThreadPool(4)
        val calls = (1..4).map {
            pool.submit<OutboxResult> {
                gate.await()
                service.stage(
                    stageCommand(
                        eventType = "CONCURRENT_TEST",
                        topic = "concurrent-topic",
                        payload = "{\"item\":42}",
                        idempotencyKey = "key-concurrent-dup",
                    )
                )
            }
        }
        gate.countDown()
        val outcomes = calls.map { runCatching { it.get() } }

        assertEquals(4, outcomes.count { it.isSuccess })
        val distinctIds = outcomes.mapNotNull { it.getOrNull()?.resultId }.toSet()
        assertEquals(1, distinctIds.size)
        // Only 1 record in store
        assertEquals(1, store.events.size)

        // 2. Broker dependency failure during publishing
        val failingBroker = FailingOutboxBroker()
        val failingService = service(store, failingBroker, alerts)
        val stagedForFail = failingService.stage(stageCommand(idempotencyKey = "stage-for-fail"))
        val eventBeforeFail = store.findEvent("tenant-1", stagedForFail.eventId)!!

        assertFailsWith<AuthenticationFailure.Rejected> {
            failingService.publish(
                PublishOutboxCommand(
                    principal = admin(),
                    sessionId = "session-outbox-1",
                    tenantId = "tenant-1",
                    eventId = stagedForFail.eventId,
                    expectedVersion = eventBeforeFail.version,
                )
            )
        }.also { assertEquals(AuthErrorCode.DEPENDENCY_UNAVAILABLE, it.code) }

        // DB remains authority: event is still PENDING with retry recorded, not lost or marked published
        val eventAfterFail = store.findEvent("tenant-1", stagedForFail.eventId)!!
        assertEquals(OutboxStatus.PENDING, eventAfterFail.status)
        assertEquals(1, eventAfterFail.retryCount)

        // 3. Dependency failure on session directory
        assertFailsWith<AuthenticationFailure.Rejected> {
            serviceWithDependencyFailure(store, broker, alerts).stage(stageCommand(idempotencyKey = "dep-session-fail"))
        }.also { assertEquals(AuthErrorCode.DEPENDENCY_UNAVAILABLE, it.code) }

        pool.shutdown()
    }

    @Test
    fun `ADR-003-01-T004 Decide transactional outbox contract remains compatible, recoverable, observable, and lifecycle-safe`() {
        // Assert: no unapproved persistence or migration introduced
        val migrationDir = File("src/main/resources/db/migration")
        val sqlFiles = migrationDir.listFiles { _, name -> name.endsWith(".sql") } ?: emptyArray()
        assertTrue(sqlFiles.isNotEmpty())
        val migrationVersions = sqlFiles.map { it.name.substringBefore("__") }
        assertTrue(!migrationVersions.contains("V17"))

        // Assert: DB remains authority and replay preserves causation after restart/recreation
        val store = OutboxMemoryStore()
        val broker = FakeOutboxBroker()
        val alerts = FakeOutboxAlertSink()
        val service = service(store, broker, alerts)

        val first = service.stage(
            stageCommand(
                eventType = "AUDIT_RECOVERY",
                topic = "lifecycle-topic",
                payload = "{\"recovered\":true}",
                correlationId = "corr-lifecycle-1",
                causationId = "cause-lifecycle-1",
                idempotencyKey = "key-lifecycle-recovery",
            )
        )

        // Simulating restart/new service instance over existing store
        val restartedService = service(store, broker, alerts)
        val second = restartedService.stage(
            stageCommand(
                eventType = "AUDIT_RECOVERY",
                topic = "lifecycle-topic",
                payload = "{\"recovered\":true}",
                correlationId = "corr-lifecycle-1",
                causationId = "cause-lifecycle-1",
                idempotencyKey = "key-lifecycle-recovery",
            )
        )
        assertEquals(first.resultId, second.resultId)
        assertEquals(first.causationId, second.causationId)
        assertEquals("cause-lifecycle-1", second.causationId)

        // Telemetry contains required IDs and no secrets
        assertEquals(1, store.audit.size)
        assertEquals("OUTBOX_STAGED", store.audit[0].type)
        assertEquals("corr-lifecycle-1", store.audit[0].correlationId)
        assertEquals("cause-lifecycle-1", store.audit[0].causationId)
        assertFalse(store.audit[0].type.contains("secret"))
    }

    private fun service(store: TransactionalOutboxStore, broker: OutboxBrokerSink, alerts: OutboxAlertSink) =
        TransactionalOutboxService(AdminRbacPolicy(true), ActiveOutboxSessionDirectory(), store, broker, alerts, clock)

    private fun serviceWithDependencyFailure(store: TransactionalOutboxStore, broker: OutboxBrokerSink, alerts: OutboxAlertSink) =
        TransactionalOutboxService(AdminRbacPolicy(true), FailingOutboxSessionDirectory(), store, broker, alerts, clock)

    private fun stageCommand(
        principal: AuthenticatedPrincipal? = admin(),
        eventType: String = "ACCOUNT_EVENT",
        topic: String = "account-topic",
        payload: String = "{\"data\":\"test\"}",
        correlationId: String = "corr-default-1",
        causationId: String = "cause-default-1",
        idempotencyKey: String = "key-outbox-default",
    ) = StageOutboxCommand(
        principal = principal,
        sessionId = "session-outbox-1",
        tenantId = "tenant-1",
        eventType = eventType,
        topic = topic,
        payload = payload,
        correlationId = correlationId,
        causationId = causationId,
        idempotencyKey = idempotencyKey,
        expectedVersion = 0L,
    )

    private fun admin(tenantId: String = "tenant-1") =
        AuthenticatedPrincipal("admin-outbox-1", tenantId, PrincipalKind.ADMIN, setOf(AdminRole.SUPER_ADMIN))

    private fun player() =
        AuthenticatedPrincipal("player-1", "tenant-1", PrincipalKind.PLAYER, emptySet())
}

private class ActiveOutboxSessionDirectory : AdminSessionDirectory {
    override fun find(tenantId: String, principalId: String, sessionId: String) =
        if (tenantId == "tenant-1" && principalId == "admin-outbox-1" && sessionId == "session-outbox-1")
            AdminSessionStatus(true, false, Instant.parse("2026-09-17T18:00:00Z"))
        else null
}

private class FailingOutboxSessionDirectory : AdminSessionDirectory {
    override fun find(tenantId: String, principalId: String, sessionId: String): AdminSessionStatus =
        error("session dependency unavailable")
}

private class FakeOutboxBroker : OutboxBrokerSink {
    val publishedEvents = mutableListOf<OutboxEventRecord>()

    override fun publish(event: OutboxEventRecord) {
        publishedEvents += event
    }
}

private class FailingOutboxBroker : OutboxBrokerSink {
    override fun publish(event: OutboxEventRecord) {
        error("broker unavailable")
    }
}

private class FakeOutboxAlertSink : OutboxAlertSink {
    val emittedAlerts = mutableListOf<OutboxAlert>()

    override fun emitAlert(alert: OutboxAlert) {
        emittedAlerts += alert
    }
}

private class OutboxMemoryStore : TransactionalOutboxStore {
    val events = mutableMapOf<String, OutboxEventRecord>()
    val results = mutableMapOf<String, Pair<String, OutboxResult>>()
    val audit = mutableListOf<AuditEvent>()
    val outbox = mutableListOf<OutboxEvent>()

    override fun findByIdempotency(tenantId: String, idempotencyKey: String) =
        synchronized(this) { results["$tenantId:$idempotencyKey"] }

    override fun findEvent(tenantId: String, eventId: UUID) =
        synchronized(this) { events["$tenantId:$eventId"] }

    override fun saveStaged(
        result: OutboxResult,
        record: OutboxEventRecord,
        tenantId: String,
        queryFingerprint: String,
        idempotencyKey: String,
        audit: AuditEvent,
        outbox: OutboxEvent,
    ) = synchronized(this) {
        events["$tenantId:${record.eventId}"] = record
        results["$tenantId:$idempotencyKey"] = queryFingerprint to result
        this.audit += audit
        this.outbox += outbox
    }

    override fun updateStatus(record: OutboxEventRecord, audit: AuditEvent?) = synchronized(this) {
        events["${record.tenantId}:${record.eventId}"] = record
        if (audit != null) {
            this.audit += audit
        }
    }
}
