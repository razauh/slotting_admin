package com.slotting.admin.notification

import com.slotting.admin.auth.AdminRole
import com.slotting.admin.auth.AuthenticatedPrincipal
import com.slotting.admin.auth.PrincipalKind
import org.junit.jupiter.api.Assertions.*
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.DisplayName
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.assertThrows
import java.time.Clock
import java.time.Duration
import java.time.Instant
import java.time.ZoneOffset
import java.util.UUID
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit

class NotificationDeliveryRetryTest {

    private val tenantId = "tenant-notify-retry-01"
    private val clock = Clock.fixed(Instant.parse("2026-09-19T22:00:00Z"), ZoneOffset.UTC)
    private lateinit var service: NotificationDeliveryRetryService

    private val validPrincipal = AuthenticatedPrincipal(
        id = "service-actor-01",
        tenantId = tenantId,
        roles = setOf(AdminRole.SUPPORT),
        kind = PrincipalKind.ADMIN,
    )

    private val otherTenantPrincipal = AuthenticatedPrincipal(
        id = "service-actor-other",
        tenantId = "tenant-other",
        roles = setOf(AdminRole.SUPPORT),
        kind = PrincipalKind.ADMIN,
    )

    @BeforeEach
    fun setup() {
        service = NotificationDeliveryRetryService(clock = clock)
    }

    private fun createScheduleCommand(
        trackingId: UUID = UUID.randomUUID(),
        notificationId: UUID = UUID.randomUUID(),
        channel: NotificationDeliveryChannel = NotificationDeliveryChannel.EMAIL,
        attemptNumber: Int = 1,
        lastErrorReason: String = "CARRIER_TIMEOUT",
        idempotencyKey: String = "idem-sched-${UUID.randomUUID()}",
        tenant: String = tenantId,
        principal: AuthenticatedPrincipal? = validPrincipal,
        customPolicy: RetryPolicy? = null,
    ) = ScheduleRetryCommand(
        principal = principal,
        tenantId = tenant,
        trackingId = trackingId,
        notificationId = notificationId,
        channel = channel,
        attemptNumber = attemptNumber,
        lastErrorReason = lastErrorReason,
        idempotencyKey = idempotencyKey,
        correlationId = "corr-${UUID.randomUUID()}",
        causationId = "caus-${UUID.randomUUID()}",
        customPolicy = customPolicy,
    )

    private fun createExecuteCommand(
        retryId: UUID,
        success: Boolean = true,
        errorReason: String? = null,
        idempotencyKey: String = "idem-exec-${UUID.randomUUID()}",
        expectedVersion: Long = 1L,
        tenant: String = tenantId,
        principal: AuthenticatedPrincipal? = validPrincipal,
    ) = ExecuteRetryCommand(
        principal = principal,
        tenantId = tenant,
        retryId = retryId,
        success = success,
        errorReason = errorReason,
        idempotencyKey = idempotencyKey,
        correlationId = "corr-${UUID.randomUUID()}",
        causationId = "caus-${UUID.randomUUID()}",
        expectedVersion = expectedVersion,
    )

    @Test
    @DisplayName("NOTIFY-003-02-T001 — Retry notification delivery with bounds produces the required authoritative outcome")
    fun testNOTIFY_003_02_T001_AuthoritativeOutcome() {
        val trackingId = UUID.randomUUID()
        val notifId = UUID.randomUUID()

        // 1. Schedule bounded retry
        val scheduleCmd = createScheduleCommand(
            trackingId = trackingId,
            notificationId = notifId,
            attemptNumber = 1,
            lastErrorReason = "503_SERVICE_UNAVAILABLE"
        )
        val scheduleResult = service.scheduleRetry(scheduleCmd)

        assertEquals(
            "Delivery status not proof user read; health/latency/failure dashboards.",
            scheduleResult.semanticContract
        )
        assertFalse(scheduleResult.directEligibilityGranted)
        assertFalse(scheduleResult.financialMutationPermitted)
        assertFalse(scheduleResult.isUserRead, "Retry status is never proof user read")
        assertEquals(RetryStatus.SCHEDULED, scheduleResult.retryStatus)
        assertEquals(1, scheduleResult.attemptNumber)
        assertEquals(3, scheduleResult.maxAttempts)
        assertFalse(scheduleResult.isExhausted)
        assertTrue(scheduleResult.scheduledAt.isAfter(Instant.parse("2026-09-19T22:00:00Z")))

        // 2. Execute retry successfully
        val executeCmd = createExecuteCommand(
            retryId = scheduleResult.retryId,
            success = true
        )
        val executeResult = service.executeRetry(executeCmd)

        assertEquals(RetryStatus.SUCCEEDED, executeResult.retryStatus)
        assertNotNull(executeResult.executedAt)
        assertFalse(executeResult.isUserRead, "Success in retry delivery is distinct from read proof")
        assertFalse(executeResult.directEligibilityGranted)
        assertFalse(executeResult.financialMutationPermitted)

        // Verify audit log
        val auditEntries = service.getAuditEntries(scheduleResult.retryId)
        assertEquals(2, auditEntries.size)
        assertEquals("RETRY_SCHEDULED", auditEntries[0].eventType)
        assertEquals("RETRY_EXECUTION_SUCCEEDED", auditEntries[1].eventType)
    }

    @Test
    @DisplayName("NOTIFY-003-02-T002 — Retry notification delivery with bounds rejects invalid, boundary, unauthorized, and stale input")
    fun testNOTIFY_003_02_T002_RejectInvalidBoundaryUnauthorizedStale() {
        val trackingId = UUID.randomUUID()

        // 1. Unauthenticated schedule
        val unauthEx = assertThrows<NotificationDeliveryRetryException> {
            service.scheduleRetry(createScheduleCommand(trackingId = trackingId, principal = null))
        }
        assertEquals("UNAUTHENTICATED", unauthEx.errorCode)

        // 2. Cross-tenant access forbidden
        val forbiddenEx = assertThrows<NotificationDeliveryRetryException> {
            service.scheduleRetry(createScheduleCommand(trackingId = trackingId, principal = otherTenantPrincipal))
        }
        assertEquals("FORBIDDEN", forbiddenEx.errorCode)

        // 3. Boundary check: attemptNumber <= 0 or > 20
        val boundaryEx = assertThrows<NotificationDeliveryRetryException> {
            service.scheduleRetry(createScheduleCommand(trackingId = trackingId, attemptNumber = 0))
        }
        assertEquals("BOUNDARY", boundaryEx.errorCode)

        // Successfully schedule attempt 1
        val scheduled = service.scheduleRetry(createScheduleCommand(trackingId = trackingId, attemptNumber = 1))

        // 4. Stale expectedVersion on execution
        val staleEx = assertThrows<NotificationDeliveryRetryException> {
            service.executeRetry(
                createExecuteCommand(
                    retryId = scheduled.retryId,
                    expectedVersion = 999L
                )
            )
        }
        assertEquals("STALE", staleEx.errorCode)

        // 5. Conflict: cannot re-schedule identical attemptNumber for the same trackingId
        val conflictEx = assertThrows<NotificationDeliveryRetryException> {
            service.scheduleRetry(
                createScheduleCommand(
                    trackingId = trackingId,
                    attemptNumber = 1,
                    idempotencyKey = "diff-key"
                )
            )
        }
        assertEquals("CONFLICT", conflictEx.errorCode)
    }

    @Test
    @DisplayName("NOTIFY-003-02-T003 — Retry notification delivery with bounds survives concurrency, duplicate delivery, and dependency failure")
    fun testNOTIFY_003_02_T003_ConcurrencyDuplicateDeliveryAndDependencyFailure() {
        val trackingId = UUID.randomUUID()
        val scheduleCmd = createScheduleCommand(trackingId = trackingId, idempotencyKey = "sched-idem-c1")
        val res1 = service.scheduleRetry(scheduleCmd)

        // Idempotent duplicate replay
        val res2 = service.scheduleRetry(scheduleCmd)
        assertEquals(res1.retryId, res2.retryId)
        assertEquals(res1.serverTime, res2.serverTime)

        // Conflicting payload reuse produces CONFLICT
        val conflictEx = assertThrows<NotificationDeliveryRetryException> {
            service.scheduleRetry(scheduleCmd.copy(lastErrorReason = "DIFFERENT_ERROR_REASON"))
        }
        assertEquals("CONFLICT", conflictEx.errorCode)

        // Concurrent execution attempts on the same scheduled retry
        val executor = Executors.newFixedThreadPool(4)
        val successfulExecutions = ConcurrentHashMap<String, DeliveryRetryResult>()
        val failureExceptions = ConcurrentHashMap<String, Exception>()

        for (i in 1..4) {
            val key = "exec-concurrent-$i"
            executor.submit {
                try {
                    val res = service.executeRetry(
                        createExecuteCommand(
                            retryId = res1.retryId,
                            idempotencyKey = key,
                            expectedVersion = 1L
                        )
                    )
                    successfulExecutions[key] = res
                } catch (e: Exception) {
                    failureExceptions[key] = e
                }
            }
        }

        executor.shutdown()
        assertTrue(executor.awaitTermination(5, TimeUnit.SECONDS))

        // Exactly one concurrent execution succeeds, remaining are rejected
        assertEquals(1, successfulExecutions.size)
        assertEquals(3, failureExceptions.size)

        // Bounded retry exhaustion check: attempting retry beyond maxRetries (e.g. attempt 4 when max is 3)
        val exhaustTrackingId = UUID.randomUUID()
        val exhaustedResult = service.scheduleRetry(
            createScheduleCommand(
                trackingId = exhaustTrackingId,
                attemptNumber = 4,
                customPolicy = RetryPolicy(maxRetries = 3)
            )
        )
        assertEquals(RetryStatus.EXHAUSTED, exhaustedResult.retryStatus)
        assertTrue(exhaustedResult.isExhausted)
    }

    @Test
    @DisplayName("NOTIFY-003-02-T004 — Retry notification delivery with bounds remains compatible, recoverable, observable, and lifecycle-safe")
    fun testNOTIFY_003_02_T004_CompatibilityRecoverableObservableAndLifecycleSafe() {
        // Test exponential backoff calculation
        val policy = RetryPolicy(
            maxRetries = 3,
            initialIntervalSeconds = 60,
            backoffMultiplier = 2.0,
            maxIntervalSeconds = 600
        )
        val backoff1 = service.calculateNextBackoff(1, policy)
        val backoff2 = service.calculateNextBackoff(2, policy)
        val backoff3 = service.calculateNextBackoff(3, policy)
        val backoff4 = service.calculateNextBackoff(10, policy)

        assertEquals(Duration.ofSeconds(60), backoff1)
        assertEquals(Duration.ofSeconds(120), backoff2)
        assertEquals(Duration.ofSeconds(240), backoff3)
        assertEquals(Duration.ofSeconds(600), backoff4) // capped at maxIntervalSeconds

        // Dashboard metrics and state tracking
        val t1 = UUID.randomUUID()
        val t2 = UUID.randomUUID()
        val t3 = UUID.randomUUID()

        val r1 = service.scheduleRetry(createScheduleCommand(trackingId = t1, attemptNumber = 1))
        service.executeRetry(createExecuteCommand(retryId = r1.retryId, success = true))

        val r2 = service.scheduleRetry(createScheduleCommand(trackingId = t2, attemptNumber = 1))
        service.executeRetry(createExecuteCommand(retryId = r2.retryId, success = false, errorReason = "REJECTED"))

        service.scheduleRetry(createScheduleCommand(trackingId = t3, attemptNumber = 4, customPolicy = RetryPolicy(maxRetries = 3)))

        val metrics = service.getDashboardMetrics(tenantId)
        assertEquals(3, metrics.totalRetriesScheduled)
        assertEquals(1, metrics.retriesSucceeded)
        assertEquals(1, metrics.retriesFailed)
        assertEquals(1, metrics.retriesExhausted)
        assertEquals(0, metrics.activeScheduledRetries)

        val record1 = service.getRetryRecord(r1.retryId)
        assertNotNull(record1)
        assertFalse(record1!!.isUserRead)
        assertFalse(record1.directEligibilityGranted)
        assertFalse(record1.financialMutationPermitted)
    }
}
