package com.slotting.admin.worker

import com.slotting.admin.auth.AdminRole
import com.slotting.admin.auth.AuthenticatedPrincipal
import com.slotting.admin.auth.PrincipalKind
import org.junit.jupiter.api.AfterEach
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test
import java.time.Clock
import java.time.Duration
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

class BoundedRetryDlqTest {
    private var now = Instant.parse("2026-09-20T21:00:00Z")
    private val clock: Clock get() = Clock.fixed(now, ZoneOffset.UTC)

    private val tenantId = "tenant-dlq-test"
    private val adminOperatorPrincipal = AuthenticatedPrincipal(
        id = "admin-dlq-op-01",
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

    private lateinit var store: InMemoryBoundedRetryDlqStore
    private lateinit var alertSink: InMemoryDlqAlertSink
    private lateinit var observability: InMemoryDlqObservability
    private lateinit var service: BoundedRetryDlqService

    @BeforeEach
    fun setUp() {
        BoundedRetryDlqBinding.checkBound()
        store = InMemoryBoundedRetryDlqStore()
        alertSink = InMemoryDlqAlertSink()
        observability = InMemoryDlqObservability()

        service = BoundedRetryDlqService(
            store = store,
            retryPolicy = BoundedRetryPolicy(
                baseDelaySeconds = 1L,
                maxDelaySeconds = 60L,
                multiplier = 2.0,
                maxRetries = 3
            ),
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

    private fun stageDlqItem(
        eventType: String = "payment.failed",
        payload: String = """{"paymentId":"${UUID.randomUUID()}","amount":5000}""",
        status: DlqItemStatus = DlqItemStatus.QUARANTINED,
        retryCount: Int = 3,
        maxRetries: Int = 3,
        quarantinedAt: Instant = now.minusSeconds(120),
        lastError: String? = "Downstream 503 gateway timeout"
    ): DlqItemRecord {
        val record = DlqItemRecord(
            eventId = UUID.randomUUID(),
            tenantId = tenantId,
            topic = "payments.dlq",
            eventType = eventType,
            payload = payload,
            correlationId = "corr-${UUID.randomUUID()}",
            causationId = "caus-${UUID.randomUUID()}",
            status = status,
            retryCount = retryCount,
            maxRetries = maxRetries,
            lastError = lastError,
            quarantinedAt = quarantinedAt
        )
        return store.save(record)
    }

    // =========================================================================
    // WORKER-001-02-T001 — Produces required authoritative outcome
    // =========================================================================
    @Test
    fun `WORKER-001-02-T001 — Operate bounded retry and dead-letter queues produces the required authoritative outcome`() {
        // 1. Verify Bounded Exponential Retry Policy
        val policy = service.retryPolicy
        assertEquals(Duration.ofSeconds(1), policy.calculateBackoff(0))
        assertEquals(Duration.ofSeconds(1), policy.calculateBackoff(1))
        assertEquals(Duration.ofSeconds(2), policy.calculateBackoff(2))
        assertEquals(Duration.ofSeconds(4), policy.calculateBackoff(3))
        assertEquals(Duration.ofSeconds(8), policy.calculateBackoff(4))
        assertEquals(Duration.ofSeconds(16), policy.calculateBackoff(5))
        assertEquals(Duration.ofSeconds(32), policy.calculateBackoff(6))
        assertEquals(Duration.ofSeconds(60), policy.calculateBackoff(7)) // Capped at maxDelaySeconds (60)
        assertEquals(Duration.ofSeconds(60), policy.calculateBackoff(10))

        assertTrue(policy.isRetryable(0))
        assertTrue(policy.isRetryable(2))
        assertFalse(policy.isRetryable(3)) // maxRetries = 3
        assertFalse(policy.isRetryable(1, isPoison = true)) // Poison is never retryable

        // 2. Query and inspect DLQ queue
        val item1 = stageDlqItem(eventType = "transfer.rejected")
        val item2 = stageDlqItem(eventType = "account.locked")

        val queryCmd = QueryDlqQueueCommand(
            principal = adminOperatorPrincipal,
            tenantId = tenantId,
            statusFilter = DlqItemStatus.QUARANTINED,
            limit = 10,
            offset = 0
        )
        val queryResult = service.queryDlq(queryCmd)
        assertEquals(2, queryResult.totalCount)
        assertEquals(2, queryResult.items.size)
        assertEquals(BOUNDED_RETRY_DLQ_CONTRACT, queryResult.semanticContract)

        val itemDetails = service.getDlqItemDetails(
            GetDlqItemDetailsQuery(
                principal = adminOperatorPrincipal,
                tenantId = tenantId,
                eventId = item1.eventId
            )
        )
        assertEquals(item1.eventId, itemDetails.eventId)
        assertEquals(item1.eventType, itemDetails.eventType)
        assertEquals(DlqItemStatus.QUARANTINED, itemDetails.status)

        // 3. Authorized Redelivery (Quarantine -> Redelivered)
        val redeliverCmd = RedeliverDlqEventCommand(
            principal = adminOperatorPrincipal,
            tenantId = tenantId,
            eventId = item1.eventId,
            idempotencyKey = "redeliver-key-001",
            correlationId = "corr-redeliver-1",
            causationId = "caus-redeliver-1"
        )
        val redeliverResult = service.redeliver(redeliverCmd)
        assertEquals(DlqItemStatus.REDELIVERED, redeliverResult.status)
        assertEquals(adminOperatorPrincipal.id, redeliverResult.replayedBy)
        assertEquals(now, redeliverResult.replayedAt)
        assertEquals("OUTBOX_DLQ_EVENT_REDELIVERED", redeliverResult.auditEvent.type)
        assertFalse(redeliverResult.hasFinancialAuthorityImpact)
        assertFalse(redeliverResult.hasAndroidDbImpact)
        assertFalse(redeliverResult.hasAndroidLifecycleClaim)
        assertEquals(BOUNDED_RETRY_DLQ_CONTRACT, redeliverResult.semanticContract)

        val updatedRecord1 = store.findById(tenantId, item1.eventId)
        assertNotNull(updatedRecord1)
        assertEquals(DlqItemStatus.REDELIVERED, updatedRecord1.status)
        assertEquals(0, updatedRecord1.retryCount)

        // 4. Authorized Discard / Purge (Quarantine -> Discarded)
        val discardCmd = DiscardDlqEventCommand(
            principal = adminOperatorPrincipal,
            tenantId = tenantId,
            eventId = item2.eventId,
            reasonCode = DlqDiscardReason.CORRUPTED_PAYLOAD.name,
            operatorNotes = "Unparseable payload confirmed corrupted by upstream source",
            idempotencyKey = "discard-key-001",
            correlationId = "corr-discard-1",
            causationId = "caus-discard-1"
        )
        val discardResult = service.discard(discardCmd)
        assertEquals(DlqItemStatus.DISCARDED, discardResult.status)
        assertEquals(adminOperatorPrincipal.id, discardResult.discardedBy)
        assertEquals(DlqDiscardReason.CORRUPTED_PAYLOAD.name, discardResult.reasonCode)
        assertEquals("OUTBOX_DLQ_EVENT_DISCARDED", discardResult.auditEvent.type)
        assertFalse(discardResult.hasFinancialAuthorityImpact)
        assertFalse(discardResult.hasAndroidDbImpact)
        assertFalse(discardResult.hasAndroidLifecycleClaim)
        assertEquals(BOUNDED_RETRY_DLQ_CONTRACT, discardResult.semanticContract)

        val updatedRecord2 = store.findById(tenantId, item2.eventId)
        assertNotNull(updatedRecord2)
        assertEquals(DlqItemStatus.DISCARDED, updatedRecord2.status)
        assertEquals(DlqDiscardReason.CORRUPTED_PAYLOAD.name, updatedRecord2.discardReason)

        // 5. Lag and Health Monitoring
        // Add a fresh quarantined item with age > 60s to trigger degraded health
        stageDlqItem(eventType = "critical.alert", quarantinedAt = now.minusSeconds(70))
        val healthReport = service.getHealth(GetDlqHealthCommand(principal = adminOperatorPrincipal, tenantId = tenantId))
        assertNotNull(healthReport)
        assertEquals(1, healthReport.quarantinedCount)
        assertEquals(1, healthReport.discardedCount)
        assertEquals(DlqHealthStatus.DEGRADED, healthReport.status)
        assertTrue(healthReport.alerts.any { it.contains("DEGRADED_DLQ_LAG_AGE") })
        assertFalse(healthReport.hasFinancialAuthorityImpact)
    }

    // =========================================================================
    // WORKER-001-02-T002 — Rejects invalid, boundary, unauthorized, and stale input
    // =========================================================================
    @Test
    fun `WORKER-001-02-T002 — Operate bounded retry and dead-letter queues rejects invalid, boundary, unauthorized, and stale input`() {
        val item = stageDlqItem()

        val validRedeliverCmd = RedeliverDlqEventCommand(
            principal = adminOperatorPrincipal,
            tenantId = tenantId,
            eventId = item.eventId,
            idempotencyKey = "redeliver-val-002",
            correlationId = "corr-002",
            causationId = "caus-002"
        )

        // 1. Unauthenticated principal
        assertFailsWith<UnauthorizedDlqOperationException> {
            service.redeliver(validRedeliverCmd.copy(principal = null))
        }

        // 2. Unauthorized principal (Player role)
        assertFailsWith<UnauthorizedDlqOperationException> {
            service.redeliver(validRedeliverCmd.copy(principal = playerPrincipal))
        }

        // 3. Cross-tenant access
        assertFailsWith<UnauthorizedDlqOperationException> {
            service.redeliver(validRedeliverCmd.copy(principal = foreignAdminPrincipal))
        }

        // 4. Unknown event ID
        assertFailsWith<DlqEventNotFoundException> {
            service.redeliver(validRedeliverCmd.copy(eventId = UUID.randomUUID()))
        }

        // 5. Stale version check (optimistic lock mismatch)
        assertFailsWith<DlqStaleVersionException> {
            service.redeliver(validRedeliverCmd.copy(expectedVersion = 999L))
        }

        // 6. Non-quarantined status conflict (cannot redeliver already discarded item)
        val discardCmd = DiscardDlqEventCommand(
            principal = adminOperatorPrincipal,
            tenantId = tenantId,
            eventId = item.eventId,
            reasonCode = "TEST_DISCARD",
            operatorNotes = "testing non-quarantined status",
            idempotencyKey = "discard-002",
            correlationId = "corr-disc",
            causationId = "caus-disc"
        )
        service.discard(discardCmd)

        assertFailsWith<DlqOperationConflictException> {
            service.redeliver(validRedeliverCmd)
        }
        assertFailsWith<DlqOperationConflictException> {
            service.discard(discardCmd.copy(idempotencyKey = "different-key"))
        }

        // 7. Invalid parameters
        assertFailsWith<InvalidDlqParametersException> {
            service.queryDlq(
                QueryDlqQueueCommand(
                    principal = adminOperatorPrincipal,
                    tenantId = tenantId,
                    limit = 0
                )
            )
        }
        assertFailsWith<InvalidDlqParametersException> {
            service.queryDlq(
                QueryDlqQueueCommand(
                    principal = adminOperatorPrincipal,
                    tenantId = tenantId,
                    offset = -1
                )
            )
        }
        assertFailsWith<InvalidDlqParametersException> {
            service.discard(
                discardCmd.copy(
                    reasonCode = " "
                )
            )
        }
    }

    // =========================================================================
    // WORKER-001-02-T003 — Survives concurrency, duplicate delivery, and dependency failure
    // =========================================================================
    @Test
    fun `WORKER-001-02-T003 — Operate bounded retry and dead-letter queues survives concurrency, duplicate delivery, and dependency failure`() {
        // 1. Concurrent redelivery race: multiple threads race to redeliver the same quarantined event
        val item = stageDlqItem()

        val executor = Executors.newFixedThreadPool(4)
        val tasks = (1..4).map { idx ->
            Callable {
                try {
                    service.redeliver(
                        RedeliverDlqEventCommand(
                            principal = adminOperatorPrincipal,
                            tenantId = tenantId,
                            eventId = item.eventId,
                            idempotencyKey = "shared-redeliver-race",
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

        val outcomes = futures.map { it.get() }
        val successfulResults = outcomes.filterIsInstance<DlqRedeliverResult>()
        // All callers receive the exact same result due to synchronized idempotency
        assertTrue(successfulResults.isNotEmpty())
        val firstResultId = successfulResults.first().resultId
        successfulResults.forEach {
            assertEquals(firstResultId, it.resultId)
        }

        val finalRecord = store.findById(tenantId, item.eventId)
        assertNotNull(finalRecord)
        assertEquals(DlqItemStatus.REDELIVERED, finalRecord.status)
        assertEquals(2L, finalRecord.version) // Exactly one version increment

        // 2. Conflicting idempotency key reuse
        assertFailsWith<DlqOperationConflictException> {
            service.redeliver(
                RedeliverDlqEventCommand(
                    principal = adminOperatorPrincipal,
                    tenantId = tenantId,
                    eventId = UUID.randomUUID(), // different event with same idempotency key
                    idempotencyKey = "shared-redeliver-race",
                    correlationId = "corr-conflict",
                    causationId = "caus-conflict"
                )
            )
        }

        // 3. Idempotent discard
        val itemToDiscard = stageDlqItem()
        val discardCmd = DiscardDlqEventCommand(
            principal = adminOperatorPrincipal,
            tenantId = tenantId,
            eventId = itemToDiscard.eventId,
            reasonCode = "OBSOLETE",
            operatorNotes = "Event superseded",
            idempotencyKey = "idemp-discard-003",
            correlationId = "corr-d3",
            causationId = "caus-d3"
        )
        val discardResult1 = service.discard(discardCmd)
        val discardResult2 = service.discard(discardCmd)
        assertEquals(discardResult1.resultId, discardResult2.resultId)

        // Conflicting discard key with different reason
        assertFailsWith<DlqOperationConflictException> {
            service.discard(discardCmd.copy(reasonCode = "DIFFERENT_REASON"))
        }
    }

    // =========================================================================
    // WORKER-001-02-T004 — Remains compatible, recoverable, observable, and lifecycle-safe
    // =========================================================================
    @Test
    fun `WORKER-001-02-T004 — Operate bounded retry and dead-letter queues remains compatible, recoverable, observable, and lifecycle-safe`() {
        val item1 = stageDlqItem()
        val item2 = stageDlqItem()

        // 1. Perform redeliver and discard operations
        val redeliverResult = service.redeliver(
            RedeliverDlqEventCommand(
                principal = adminOperatorPrincipal,
                tenantId = tenantId,
                eventId = item1.eventId,
                idempotencyKey = "life-redeliver-key",
                correlationId = "corr-life-1",
                causationId = "caus-life-1"
            )
        )
        val discardResult = service.discard(
            DiscardDlqEventCommand(
                principal = adminOperatorPrincipal,
                tenantId = tenantId,
                eventId = item2.eventId,
                reasonCode = "PERMANENT_POISON",
                operatorNotes = "Poison payload confirmed",
                idempotencyKey = "life-discard-key",
                correlationId = "corr-life-2",
                causationId = "caus-life-2"
            )
        )

        // 2. Simulated service recreation / restart
        val restartedService = BoundedRetryDlqService(
            store = store,
            retryPolicy = service.retryPolicy,
            alertSink = alertSink,
            observability = observability,
            clock = clock
        )

        // Verify state is completely preserved across restart
        val rec1 = store.findById(tenantId, item1.eventId)
        assertEquals(DlqItemStatus.REDELIVERED, rec1?.status)

        val rec2 = store.findById(tenantId, item2.eventId)
        assertEquals(DlqItemStatus.DISCARDED, rec2?.status)

        // Idempotency survives restart
        val replayedRedeliver = restartedService.redeliver(
            RedeliverDlqEventCommand(
                principal = adminOperatorPrincipal,
                tenantId = tenantId,
                eventId = item1.eventId,
                idempotencyKey = "life-redeliver-key",
                correlationId = "corr-life-1",
                causationId = "caus-life-1"
            )
        )
        assertEquals(redeliverResult.resultId, replayedRedeliver.resultId)

        // 3. Observability checks
        val metrics = observability.getMetrics()
        assertTrue(metrics.isNotEmpty())
        assertTrue(metrics.any { it.eventType == "dlq_redelivered" })
        assertTrue(metrics.any { it.eventType == "dlq_discarded" })

        // Check metrics do not leak secrets or credentials
        metrics.forEach { m ->
            assertFalse(m.details.toString().contains("secret"))
            assertFalse(m.details.toString().contains("password"))
        }

        // 4. Assert zero financial mutation and zero Android DB/lifecycle claims
        assertFalse(redeliverResult.hasFinancialAuthorityImpact)
        assertFalse(redeliverResult.hasAndroidDbImpact)
        assertFalse(redeliverResult.hasAndroidLifecycleClaim)

        assertFalse(discardResult.hasFinancialAuthorityImpact)
        assertFalse(discardResult.hasAndroidDbImpact)
        assertFalse(discardResult.hasAndroidLifecycleClaim)
    }
}
