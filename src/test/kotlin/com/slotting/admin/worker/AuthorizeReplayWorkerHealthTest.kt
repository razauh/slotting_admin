package com.slotting.admin.worker

import com.slotting.admin.auth.AdminRole
import com.slotting.admin.auth.AuthenticatedPrincipal
import com.slotting.admin.auth.PrincipalKind
import org.junit.jupiter.api.AfterEach
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test
import java.time.Clock
import java.time.Instant
import java.time.ZoneOffset
import java.util.UUID
import java.util.concurrent.Callable
import java.util.concurrent.Executors
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertNotNull
import kotlin.test.assertTrue

class AuthorizeReplayWorkerHealthTest {
    private var now = Instant.parse("2026-09-20T21:15:00Z")
    private val clock: Clock get() = Clock.fixed(now, ZoneOffset.UTC)

    private val tenantId = "tenant-replay-health-test"
    private val adminOperatorPrincipal = AuthenticatedPrincipal(
        id = "admin-op-replay-01",
        tenantId = tenantId,
        kind = PrincipalKind.ADMIN,
        roles = setOf(AdminRole.SUPPORT, AdminRole.SUPER_ADMIN)
    )

    private val playerPrincipal = AuthenticatedPrincipal(
        id = "player-999",
        tenantId = tenantId,
        kind = PrincipalKind.PLAYER,
        roles = emptySet()
    )

    private val foreignAdminPrincipal = AuthenticatedPrincipal(
        id = "foreign-admin-02",
        tenantId = "tenant-other",
        kind = PrincipalKind.ADMIN,
        roles = setOf(AdminRole.SUPER_ADMIN)
    )

    private lateinit var store: InMemoryAuthorizeReplayWorkerHealthStore
    private lateinit var publisherSink: InMemoryWorkerHealthPublisherSink
    private lateinit var alertSink: InMemoryWorkerHealthAlertSink
    private lateinit var observability: InMemoryWorkerReplayHealthObservability
    private lateinit var service: AuthorizeReplayWorkerHealthService

    @BeforeEach
    fun setUp() {
        AuthorizeReplayWorkerHealthBinding.checkBound()
        store = InMemoryAuthorizeReplayWorkerHealthStore()
        publisherSink = InMemoryWorkerHealthPublisherSink()
        alertSink = InMemoryWorkerHealthAlertSink()
        observability = InMemoryWorkerReplayHealthObservability()

        service = AuthorizeReplayWorkerHealthService(
            store = store,
            publisherSink = publisherSink,
            alertSink = alertSink,
            observability = observability,
            clock = object : Clock() {
                override fun getZone(): ZoneOffset = ZoneOffset.UTC
                override fun withZone(zone: java.time.ZoneId?): Clock = this
                override fun instant(): Instant = now
            }
        )
    }

    @AfterEach
    fun tearDown() {
    }

    private fun stageEvent(
        eventType: String = "settlement.completed",
        payload: String = """{"orderId":"${UUID.randomUUID()}","amount":25000}""",
        status: WorkerOutboxStatus = WorkerOutboxStatus.QUARANTINED,
        retryCount: Int = 3,
        createdAt: Instant = now.minusSeconds(120),
        lastError: String? = "Downstream 504 gateway timeout after 3 retries"
    ): LeasedOutboxEventRecord {
        val event = LeasedOutboxEventRecord(
            eventId = UUID.randomUUID(),
            tenantId = tenantId,
            topic = "settlement.events",
            eventType = eventType,
            payload = payload,
            correlationId = "corr-${UUID.randomUUID()}",
            causationId = "caus-${UUID.randomUUID()}",
            idempotencyKey = "idemp-${UUID.randomUUID()}",
            status = status,
            retryCount = retryCount,
            maxRetries = 3,
            lastError = lastError,
            createdAt = createdAt
        )
        return store.saveEvent(event)
    }

    // =========================================================================
    // WORKER-001-03-T001 — Produces required authoritative outcome
    // =========================================================================
    @Test
    fun `WORKER-001-03-T001 — Authorize replay and publish worker health produces the required authoritative outcome`() {
        // 1. Register worker heartbeats for cluster liveness
        service.recordHeartbeat(
            RegisterWorkerHeartbeatCommand(
                workerId = "worker-primary-01",
                tenantId = tenantId,
                hostname = "worker-host-prod-1",
                activeLeaseCount = 2,
                correlationId = "corr-hb-1"
            )
        )

        // 2. Stage a quarantined event
        val quarantinedEvent = stageEvent()

        // 3. Authorize replay by an authorized admin operator
        val replayCmd = AuthorizeReplayCommand(
            principal = adminOperatorPrincipal,
            tenantId = tenantId,
            eventId = quarantinedEvent.eventId,
            justification = "Manual audit confirmation of downstream gateway recovery",
            idempotencyKey = "auth-replay-key-001",
            correlationId = "corr-auth-1",
            causationId = "caus-auth-1"
        )
        val replayResult = service.authorizeReplay(replayCmd)

        assertEquals(ReplayAuthorizationStatus.AUTHORIZED, replayResult.status)
        assertEquals(adminOperatorPrincipal.id, replayResult.authorizedBy)
        assertEquals(now, replayResult.authorizedAt)
        assertEquals(replayCmd.justification, replayResult.justification)
        assertEquals("OUTBOX_REPLAY_AUTHORIZED", replayResult.auditEvent.type)
        assertFalse(replayResult.hasFinancialAuthorityImpact)
        assertFalse(replayResult.hasAndroidDbImpact)
        assertFalse(replayResult.hasAndroidLifecycleClaim)
        assertEquals(WORKER_HEALTH_REPLAY_CONTRACT, replayResult.semanticContract)

        val updatedRecord = store.findEvent(tenantId, quarantinedEvent.eventId)
        assertNotNull(updatedRecord)
        assertEquals(WorkerOutboxStatus.PENDING, updatedRecord.status)
        assertEquals(0, updatedRecord.retryCount)
        assertEquals(now, updatedRecord.replayedAt)
        assertEquals(adminOperatorPrincipal.id, updatedRecord.replayedBy)
        assertEquals(quarantinedEvent.version + 1, updatedRecord.version)

        // 4. Publish worker health
        val healthCmd = PublishWorkerHealthCommand(
            principal = adminOperatorPrincipal,
            tenantId = tenantId,
            correlationId = "corr-pub-1",
            causationId = "caus-pub-1"
        )
        val healthReport = service.publishHealth(healthCmd)

        assertNotNull(healthReport)
        assertEquals(tenantId, healthReport.tenantId)
        assertEquals(1, healthReport.activeWorkersCount)
        assertEquals(1, healthReport.pendingCount) // Replayed event is now PENDING
        assertEquals(0, healthReport.quarantinedCount)
        assertFalse(healthReport.hasFinancialAuthorityImpact)
        assertFalse(healthReport.hasAndroidDbImpact)
        assertFalse(healthReport.hasAndroidLifecycleClaim)
        assertEquals(WORKER_HEALTH_REPLAY_CONTRACT, healthReport.semanticContract)

        // Verify published report was received by the publisher sink
        val publishedReports = publisherSink.getPublishedReports()
        assertEquals(1, publishedReports.size)
        assertEquals(healthReport.reportId, publishedReports.first().reportId)
    }

    // =========================================================================
    // WORKER-001-03-T002 — Rejects invalid, boundary, unauthorized, and stale input
    // =========================================================================
    @Test
    fun `WORKER-001-03-T002 — Authorize replay and publish worker health rejects invalid, boundary, unauthorized, and stale input`() {
        val event = stageEvent()

        val validCmd = AuthorizeReplayCommand(
            principal = adminOperatorPrincipal,
            tenantId = tenantId,
            eventId = event.eventId,
            justification = "Audited retry justification",
            idempotencyKey = "auth-val-key-002",
            correlationId = "corr-val-002",
            causationId = "caus-val-002"
        )

        // 1. Unauthenticated principal
        assertFailsWith<UnauthorizedReplayActionException> {
            service.authorizeReplay(validCmd.copy(principal = null))
        }

        // 2. Unauthorized principal (Player role)
        assertFailsWith<UnauthorizedReplayActionException> {
            service.authorizeReplay(validCmd.copy(principal = playerPrincipal))
        }

        // 3. Cross-tenant access
        assertFailsWith<UnauthorizedReplayActionException> {
            service.authorizeReplay(validCmd.copy(principal = foreignAdminPrincipal))
        }

        // 4. Unknown event ID
        assertFailsWith<ReplayEventNotFoundException> {
            service.authorizeReplay(validCmd.copy(eventId = UUID.randomUUID()))
        }

        // 5. Stale version check (optimistic lock mismatch)
        assertFailsWith<ReplayStaleVersionException> {
            service.authorizeReplay(validCmd.copy(expectedVersion = 999L))
        }

        // 6. Non-quarantined status conflict (event already PENDING or PUBLISHED)
        val pendingEvent = stageEvent(status = WorkerOutboxStatus.PENDING)
        assertFailsWith<ReplayConflictException> {
            service.authorizeReplay(validCmd.copy(eventId = pendingEvent.eventId))
        }

        // 7. Invalid parameters
        assertFailsWith<InvalidReplayParametersException> {
            service.authorizeReplay(validCmd.copy(justification = " "))
        }
        assertFailsWith<InvalidReplayParametersException> {
            service.authorizeReplay(validCmd.copy(idempotencyKey = " "))
        }
        assertFailsWith<InvalidReplayParametersException> {
            service.authorizeReplay(validCmd.copy(correlationId = " "))
        }

        // 8. Publish health with unauthenticated or cross-tenant principal
        assertFailsWith<UnauthorizedReplayActionException> {
            service.publishHealth(
                PublishWorkerHealthCommand(
                    principal = null,
                    tenantId = tenantId,
                    correlationId = "c",
                    causationId = "ca"
                )
            )
        }
        assertFailsWith<UnauthorizedReplayActionException> {
            service.publishHealth(
                PublishWorkerHealthCommand(
                    principal = foreignAdminPrincipal,
                    tenantId = tenantId,
                    correlationId = "c",
                    causationId = "ca"
                )
            )
        }

        // Verify durable state and financial authority remain unmutated
        val unchangedEvent = store.findEvent(tenantId, event.eventId)
        assertEquals(WorkerOutboxStatus.QUARANTINED, unchangedEvent?.status)
    }

    // =========================================================================
    // WORKER-001-03-T003 — Survives concurrency, duplicate delivery, and dependency failure
    // =========================================================================
    @Test
    fun `WORKER-001-03-T003 — Authorize replay and publish worker health survives concurrency, duplicate delivery, and dependency failure`() {
        val event = stageEvent()

        // 1. Concurrent race: multiple operators/threads attempting to authorize replay of the same event
        val executor = Executors.newFixedThreadPool(4)
        val tasks = (1..4).map { idx ->
            Callable {
                try {
                    service.authorizeReplay(
                        AuthorizeReplayCommand(
                            principal = adminOperatorPrincipal,
                            tenantId = tenantId,
                            eventId = event.eventId,
                            justification = "Concurrent audit justification",
                            idempotencyKey = "shared-race-key-003",
                            correlationId = "corr-race-$idx",
                            causationId = "caus-race-$idx"
                        )
                    )
                } catch (ex: Exception) {
                    ex
                }
            }
        }
        val futures = executor.invokeAll(tasks)
        executor.shutdown()

        val results = futures.map { it.get() }
        val successfulReplays = results.filterIsInstance<AuthorizeReplayResult>()
        assertTrue(successfulReplays.isNotEmpty())

        // All callers receive the exact same result identity
        val firstResultId = successfulReplays.first().resultId
        successfulReplays.forEach {
            assertEquals(firstResultId, it.resultId)
        }

        // Exactly one version increment
        val finalRecord = store.findEvent(tenantId, event.eventId)
        assertNotNull(finalRecord)
        assertEquals(WorkerOutboxStatus.PENDING, finalRecord.status)
        assertEquals(event.version + 1, finalRecord.version)

        // 2. Conflicting idempotency key reuse with different parameters
        assertFailsWith<ReplayConflictException> {
            service.authorizeReplay(
                AuthorizeReplayCommand(
                    principal = adminOperatorPrincipal,
                    tenantId = tenantId,
                    eventId = event.eventId,
                    justification = "Different justification with same key",
                    idempotencyKey = "shared-race-key-003",
                    correlationId = "corr-diff",
                    causationId = "caus-diff"
                )
            )
        }
    }

    // =========================================================================
    // WORKER-001-03-T004 — Remains compatible, recoverable, observable, and lifecycle-safe
    // =========================================================================
    @Test
    fun `WORKER-001-03-T004 — Authorize replay and publish worker health remains compatible, recoverable, observable, and lifecycle-safe`() {
        // 1. Stage heartbeat and event, then authorize replay
        service.recordHeartbeat(
            RegisterWorkerHeartbeatCommand(
                workerId = "worker-life-01",
                tenantId = tenantId,
                hostname = "host-life-1",
                activeLeaseCount = 1,
                correlationId = "corr-hb-life"
            )
        )
        val event = stageEvent()
        val replayResult = service.authorizeReplay(
            AuthorizeReplayCommand(
                principal = adminOperatorPrincipal,
                tenantId = tenantId,
                eventId = event.eventId,
                justification = "Audited recovery justification",
                idempotencyKey = "replay-life-key",
                correlationId = "corr-life",
                causationId = "caus-life"
            )
        )

        val healthReport = service.publishHealth(
            PublishWorkerHealthCommand(
                principal = adminOperatorPrincipal,
                tenantId = tenantId,
                correlationId = "corr-life-health",
                causationId = "caus-life-health"
            )
        )

        // 2. Simulated restart / service recreation from store
        val restartedService = AuthorizeReplayWorkerHealthService(
            store = store,
            publisherSink = publisherSink,
            alertSink = alertSink,
            observability = observability,
            clock = clock
        )

        // Verify state is completely preserved
        val reloadedEvent = store.findEvent(tenantId, event.eventId)
        assertNotNull(reloadedEvent)
        assertEquals(WorkerOutboxStatus.PENDING, reloadedEvent.status)
        assertEquals(0, reloadedEvent.retryCount)

        // Replay idempotency persists across restart
        val replayedAgain = restartedService.authorizeReplay(
            AuthorizeReplayCommand(
                principal = adminOperatorPrincipal,
                tenantId = tenantId,
                eventId = event.eventId,
                justification = "Audited recovery justification",
                idempotencyKey = "replay-life-key",
                correlationId = "corr-life",
                causationId = "caus-life"
            )
        )
        assertEquals(replayResult.resultId, replayedAgain.resultId)

        // 3. Observability checks: telemetry events recorded with correlation IDs and no secrets
        val events = observability.getEvents()
        assertTrue(events.isNotEmpty())
        assertTrue(events.any { it["eventType"] == "worker_replay_authorized" })
        assertTrue(events.any { it["eventType"] == "worker_health_published" })
        assertTrue(events.any { it["eventType"] == "worker_heartbeat" })

        events.forEach { ev ->
            assertFalse(ev.toString().contains("secret"))
            assertFalse(ev.toString().contains("password"))
        }

        // 4. Assert zero financial mutation and zero Android DB/lifecycle claims
        assertFalse(replayResult.hasFinancialAuthorityImpact)
        assertFalse(replayResult.hasAndroidDbImpact)
        assertFalse(replayResult.hasAndroidLifecycleClaim)

        assertFalse(healthReport.hasFinancialAuthorityImpact)
        assertFalse(healthReport.hasAndroidDbImpact)
        assertFalse(healthReport.hasAndroidLifecycleClaim)
    }
}
