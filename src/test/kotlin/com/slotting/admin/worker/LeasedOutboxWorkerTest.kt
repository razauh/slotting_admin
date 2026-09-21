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

class LeasedOutboxWorkerTest {
    private var now = Instant.parse("2026-09-20T20:45:00Z")
    private val clock: Clock get() = Clock.fixed(now, ZoneOffset.UTC)

    private val tenantId = "tenant-worker-test"
    private val adminOperatorPrincipal = AuthenticatedPrincipal(
        id = "admin-worker-op-01",
        tenantId = tenantId,
        kind = PrincipalKind.ADMIN,
        roles = setOf(AdminRole.SUPPORT, AdminRole.SUPER_ADMIN)
    )

    private val playerPrincipal = AuthenticatedPrincipal(
        id = "player-001",
        tenantId = tenantId,
        kind = PrincipalKind.PLAYER,
        roles = emptySet()
    )

    private val foreignAdminPrincipal = AuthenticatedPrincipal(
        id = "foreign-admin-01",
        tenantId = "tenant-foreign",
        kind = PrincipalKind.ADMIN,
        roles = setOf(AdminRole.SUPER_ADMIN)
    )

    private lateinit var store: InMemoryLeasedOutboxStore
    private lateinit var broker: FakeWorkerOutboxBrokerSink
    private lateinit var alertSink: InMemoryWorkerOutboxAlertSink
    private lateinit var observability: InMemoryOutboxWorkerObservability
    private lateinit var service: LeasedOutboxWorkerService

    @BeforeEach
    fun setUp() {
        LeasedOutboxWorkerBinding.isBound = true
        store = InMemoryLeasedOutboxStore()
        broker = FakeWorkerOutboxBrokerSink()
        alertSink = InMemoryWorkerOutboxAlertSink()
        observability = InMemoryOutboxWorkerObservability()

        service = LeasedOutboxWorkerService(
            store = store,
            broker = broker,
            alertSink = alertSink,
            observability = observability,
            clock = object : Clock() {
                override fun getZone(): ZoneOffset = ZoneOffset.UTC
                override fun withZone(zone: java.time.ZoneId?): Clock = this
                override fun instant(): Instant = now
            },
            baseDelaySeconds = 1L,
            maxDelaySeconds = 60L
        )
    }

    @AfterEach
    fun tearDown() {
        LeasedOutboxWorkerBinding.isBound = true
    }

    private fun stageEvent(
        eventType: String = "payment.completed",
        payload: String = """{"paymentId":"${UUID.randomUUID()}","amount":1000}""",
        status: WorkerOutboxStatus = WorkerOutboxStatus.PENDING,
        createdAt: Instant = now.minusSeconds(60),
        retryCount: Int = 0,
        maxRetries: Int = 3
    ): LeasedOutboxEventRecord {
        val event = LeasedOutboxEventRecord(
            eventId = UUID.randomUUID(),
            tenantId = tenantId,
            topic = "payments.events",
            eventType = eventType,
            payload = payload,
            correlationId = "corr-${UUID.randomUUID()}",
            causationId = "caus-${UUID.randomUUID()}",
            idempotencyKey = "idemp-${UUID.randomUUID()}",
            status = status,
            retryCount = retryCount,
            maxRetries = maxRetries,
            createdAt = createdAt
        )
        return store.stageEvent(event)
    }

    // =========================================================================
    // WORKER-001-01-T001 — Produces required authoritative outcome
    // =========================================================================
    @Test
    fun `WORKER-001-01-T001 — Run leased transactional-outbox workers produces the required authoritative outcome`() {
        // 1. Normal Poll and Publish with exclusive lease
        val event1 = stageEvent(eventType = "wallet.credited")
        val cmdPoll = PollAndProcessOutboxCommand(
            tenantId = tenantId,
            workerId = "worker-node-1",
            batchSize = 10,
            leaseDurationSeconds = 30L,
            correlationId = "corr-poll-1",
            causationId = "caus-poll-1"
        )
        val pollResult = service.pollAndProcess(cmdPoll)

        assertEquals(1, pollResult.polledCount)
        assertEquals(1, pollResult.publishedCount)
        assertEquals(0, pollResult.retryCount)
        assertEquals(0, pollResult.quarantinedCount)
        assertFalse(pollResult.hasFinancialAuthorityImpact)
        assertFalse(pollResult.hasAndroidDbImpact)
        assertFalse(pollResult.hasAndroidLifecycleClaim)

        val publishedRecord = store.findById(tenantId, event1.eventId)
        assertNotNull(publishedRecord)
        assertEquals(WorkerOutboxStatus.PUBLISHED, publishedRecord.status)
        assertNotNull(publishedRecord.publishedAt)

        // 2. Bounded Exponential Retry: broker fails for event2
        val event2 = stageEvent(eventType = "withdrawal.initiated")
        broker.failurePredicate = { it.eventId == event2.eventId }

        val retryResult = service.pollAndProcess(cmdPoll)
        assertEquals(1, retryResult.retryCount)
        assertEquals(0, retryResult.publishedCount)

        val retriedRecord = store.findById(tenantId, event2.eventId)
        assertNotNull(retriedRecord)
        assertEquals(WorkerOutboxStatus.PENDING, retriedRecord.status)
        assertEquals(1, retriedRecord.retryCount)
        // Bounded backoff: baseDelay * 2^(1-1) = 1s
        assertEquals(now.plusSeconds(1), retriedRecord.nextRetryAt)

        // 3. Poison Payload Immediate Quarantine
        broker.failurePredicate = null
        val poisonEvent = stageEvent(
            eventType = "fraud.alert",
            payload = """{"status":"POISON_DATA_MALFORMED"}""",
            createdAt = now.minusSeconds(120)
        )
        val poisonResult = service.pollAndProcess(cmdPoll)

        assertEquals(1, poisonResult.quarantinedCount)
        val quarantinedRecord = store.findById(tenantId, poisonEvent.eventId)
        assertNotNull(quarantinedRecord)
        assertEquals(WorkerOutboxStatus.QUARANTINED, quarantinedRecord.status)
        assertTrue(quarantinedRecord.lastError!!.contains("poison"))

        val dlqAlerts = alertSink.getAlerts()
        assertTrue(dlqAlerts.any { it.eventId == poisonEvent.eventId && it.reason.contains("poison") })

        // 4. Authorized and Audited Replay of Quarantined Event
        val replayCmd = ReplayQuarantinedOutboxCommand(
            principal = adminOperatorPrincipal,
            tenantId = tenantId,
            eventId = poisonEvent.eventId,
            idempotencyKey = "replay-cmd-001",
            correlationId = "corr-replay-1",
            causationId = "caus-replay-1"
        )
        val replayResult = service.replayDeadLetter(replayCmd)
        assertEquals(WorkerOutboxStatus.PENDING, replayResult.status)
        assertEquals(adminOperatorPrincipal.id, replayResult.replayedBy)
        assertFalse(replayResult.hasFinancialAuthorityImpact)
        assertEquals("OUTBOX_WORKER_EVENT_REPLAYED", replayResult.auditEvent.type)

        val replayedRecord = store.findById(tenantId, poisonEvent.eventId)
        assertNotNull(replayedRecord)
        assertEquals(WorkerOutboxStatus.PENDING, replayedRecord.status)
        assertEquals(0, replayedRecord.retryCount)

        // 5. Lag and Oldest-Age Health Monitoring
        val healthReport = service.getHealth(GetOutboxWorkerHealthQuery(tenantId = tenantId))
        assertNotNull(healthReport)
        assertTrue(healthReport.pendingCount >= 1)
        assertFalse(healthReport.alerts.isEmpty()) // poison event was replayed into pending with age > 60s
    }

    // =========================================================================
    // WORKER-001-01-T002 — Rejects invalid, boundary, unauthorized, and stale input
    // =========================================================================
    @Test
    fun `WORKER-001-01-T002 — Run leased transactional-outbox workers rejects invalid, boundary, unauthorized, and stale input`() {
        val event = stageEvent(status = WorkerOutboxStatus.QUARANTINED)

        val validReplayCmd = ReplayQuarantinedOutboxCommand(
            principal = adminOperatorPrincipal,
            tenantId = tenantId,
            eventId = event.eventId,
            idempotencyKey = "replay-key-002",
            correlationId = "corr-002",
            causationId = "caus-002"
        )

        // 1. Unauthenticated principal
        assertFailsWith<UnauthorizedWorkerActionException> {
            service.replayDeadLetter(validReplayCmd.copy(principal = null))
        }

        // 2. Unauthorized principal (Player role)
        assertFailsWith<UnauthorizedWorkerActionException> {
            service.replayDeadLetter(validReplayCmd.copy(principal = playerPrincipal))
        }

        // 3. Cross-tenant access
        assertFailsWith<UnauthorizedWorkerActionException> {
            service.replayDeadLetter(validReplayCmd.copy(principal = foreignAdminPrincipal))
        }

        // 4. Non-quarantined event replay conflict
        val pendingEvent = stageEvent(status = WorkerOutboxStatus.PENDING)
        assertFailsWith<OutboxWorkerConflictException> {
            service.replayDeadLetter(validReplayCmd.copy(eventId = pendingEvent.eventId))
        }

        // 5. Unknown event ID
        assertFailsWith<OutboxEventNotFoundException> {
            service.replayDeadLetter(validReplayCmd.copy(eventId = UUID.randomUUID()))
        }

        // 6. Invalid boundary poll parameters
        val cmdPoll = PollAndProcessOutboxCommand(
            tenantId = tenantId,
            workerId = "worker-1",
            batchSize = 10,
            leaseDurationSeconds = 30L,
            correlationId = "corr-p",
            causationId = "caus-p"
        )
        assertFailsWith<InvalidWorkerParametersException> {
            service.pollAndProcess(cmdPoll.copy(workerId = " "))
        }
        assertFailsWith<InvalidWorkerParametersException> {
            service.pollAndProcess(cmdPoll.copy(batchSize = 0))
        }
        assertFailsWith<InvalidWorkerParametersException> {
            service.pollAndProcess(cmdPoll.copy(leaseDurationSeconds = -5L))
        }

        // State remains intact; money is never mutated
        val unchangedRecord = store.findById(tenantId, event.eventId)
        assertEquals(WorkerOutboxStatus.QUARANTINED, unchangedRecord?.status)
    }

    // =========================================================================
    // WORKER-001-01-T003 — Survives concurrency, duplicate delivery, and dependency failure
    // =========================================================================
    @Test
    fun `WORKER-001-01-T003 — Run leased transactional-outbox workers survives concurrency, duplicate delivery, and dependency failure`() {
        // 1. Concurrent worker leasing race: 4 workers compete for 12 pending events
        val stagedEvents = (1..12).map { stageEvent(eventType = "event-$it") }

        val executor = Executors.newFixedThreadPool(4)
        val tasks = (1..4).map { workerIdx ->
            Callable {
                service.pollAndProcess(
                    PollAndProcessOutboxCommand(
                        tenantId = tenantId,
                        workerId = "worker-concurrent-$workerIdx",
                        batchSize = 5,
                        leaseDurationSeconds = 30L,
                        correlationId = "corr-race-$workerIdx",
                        causationId = "caus-race-$workerIdx"
                    )
                )
            }
        }
        val futures = executor.invokeAll(tasks)
        executor.shutdown()

        val results = futures.map { it.get() }
        val totalPublished = results.sumOf { it.publishedCount }
        assertEquals(12, totalPublished)

        // Verify zero duplicate deliveries: broker received exactly 12 events
        val deliveredEventIds = broker.publishedEvents.map { it.eventId }
        assertEquals(12, deliveredEventIds.size)
        assertEquals(12, deliveredEventIds.toSet().size)

        // 2. Crash & Lease Expiration Recovery
        // Worker 1 leases an event, then "crashes"
        val crashEvent = stageEvent(eventType = "crash.recovery.test")
        val leasedBatch = store.acquireLeases(
            tenantId = tenantId,
            workerId = "crashed-worker-99",
            limit = 1,
            leaseDurationSeconds = 10L,
            now = now
        )
        assertEquals(1, leasedBatch.size)

        // Advance time past lease expiration (15 seconds)
        now = now.plusSeconds(15)

        // Worker 2 polls and safely recovers the expired lease
        val recoverResult = service.pollAndProcess(
            PollAndProcessOutboxCommand(
                tenantId = tenantId,
                workerId = "healthy-worker-02",
                batchSize = 10,
                leaseDurationSeconds = 30L,
                correlationId = "corr-recov",
                causationId = "caus-recov"
            )
        )
        assertEquals(1, recoverResult.publishedCount)
        val recoveredRecord = store.findById(tenantId, crashEvent.eventId)
        assertEquals(WorkerOutboxStatus.PUBLISHED, recoveredRecord?.status)

        // 3. Dependency failure: broker outage moves to DLQ on max retries exhaustion
        val failEvent = stageEvent(eventType = "fail.test", maxRetries = 2)
        broker.shouldFail = true

        // Retry 1: schedules retry backoff
        service.pollAndProcess(
            PollAndProcessOutboxCommand(
                tenantId = tenantId,
                workerId = "worker-fail",
                batchSize = 10,
                leaseDurationSeconds = 30L,
                correlationId = "corr-f1",
                causationId = "caus-f1"
            )
        )
        val recordAfterRetry1 = store.findById(tenantId, failEvent.eventId)
        assertEquals(WorkerOutboxStatus.PENDING, recordAfterRetry1?.status)
        assertEquals(1, recordAfterRetry1?.retryCount)

        // Advance past retry backoff and poll again -> retry 2 exhausts maxRetries (2) -> QUARANTINED
        now = now.plusSeconds(5)
        service.pollAndProcess(
            PollAndProcessOutboxCommand(
                tenantId = tenantId,
                workerId = "worker-fail",
                batchSize = 10,
                leaseDurationSeconds = 30L,
                correlationId = "corr-f2",
                causationId = "caus-f2"
            )
        )
        val recordAfterRetry2 = store.findById(tenantId, failEvent.eventId)
        assertEquals(WorkerOutboxStatus.QUARANTINED, recordAfterRetry2?.status)
        assertEquals(2, recordAfterRetry2?.retryCount)

        // 4. Idempotent replay
        broker.shouldFail = false
        val replayCmd = ReplayQuarantinedOutboxCommand(
            principal = adminOperatorPrincipal,
            tenantId = tenantId,
            eventId = failEvent.eventId,
            idempotencyKey = "shared-replay-key-003",
            correlationId = "corr-rep-1",
            causationId = "caus-rep-1"
        )
        val replay1 = service.replayDeadLetter(replayCmd)
        val replay2 = service.replayDeadLetter(replayCmd)
        assertEquals(replay1.resultId, replay2.resultId)

        // Conflicting idempotency key
        val conflictCmd = replayCmd.copy(eventId = crashEvent.eventId)
        assertFailsWith<OutboxWorkerConflictException> {
            service.replayDeadLetter(conflictCmd)
        }
    }

    // =========================================================================
    // WORKER-001-01-T004 — Remains compatible, recoverable, observable, and lifecycle-safe
    // =========================================================================
    @Test
    fun `WORKER-001-01-T004 — Run leased transactional-outbox workers remains compatible, recoverable, observable, and lifecycle-safe`() {
        val event = stageEvent(eventType = "audit.lifecycle")

        // 1. Process event through worker
        val pollResult = service.pollAndProcess(
            PollAndProcessOutboxCommand(
                tenantId = tenantId,
                workerId = "worker-life-1",
                batchSize = 10,
                leaseDurationSeconds = 30L,
                correlationId = "corr-life",
                causationId = "caus-life"
            )
        )
        assertEquals(1, pollResult.publishedCount)

        // 2. Simulated restart / service recreation from store
        val restartedService = LeasedOutboxWorkerService(
            store = store,
            broker = broker,
            alertSink = alertSink,
            observability = observability,
            clock = clock
        )

        // Historical state is preserved without edits
        val recoveredRecord = store.findById(tenantId, event.eventId)
        assertNotNull(recoveredRecord)
        assertEquals(WorkerOutboxStatus.PUBLISHED, recoveredRecord.status)

        // 3. Observability checks: metrics recorded with correlation/causation and no secret leakage
        val metrics = observability.getMetrics()
        assertTrue(metrics.isNotEmpty())
        assertTrue(metrics.any { it.eventType == "worker_poll" })
        assertTrue(metrics.any { it.eventType == "published" })

        metrics.forEach { m ->
            assertFalse(m.details.toString().contains("secret"))
            assertFalse(m.details.toString().contains("password"))
        }

        // 4. Android lifecycle & DB checks
        assertFalse(pollResult.hasFinancialAuthorityImpact)
        assertFalse(pollResult.hasAndroidDbImpact)
        assertFalse(pollResult.hasAndroidLifecycleClaim)
    }
}
