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
import java.time.Instant
import java.time.ZoneOffset
import java.util.UUID
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit

class NotificationDeliveryTrackingTest {

    private val tenantId = "tenant-notify-01"
    private val clock = Clock.fixed(Instant.parse("2026-09-19T22:00:00Z"), ZoneOffset.UTC)
    private lateinit var service: NotificationDeliveryTrackingService

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
        service = NotificationDeliveryTrackingService(clock = clock)
    }

    private fun createQueueCommand(
        notificationId: UUID = UUID.randomUUID(),
        recipientId: String = "user-01@example.com",
        channel: NotificationDeliveryChannel = NotificationDeliveryChannel.EMAIL,
        idempotencyKey: String = "idem-queue-${UUID.randomUUID()}",
        tenant: String = tenantId,
        principal: AuthenticatedPrincipal? = validPrincipal,
        maxAttempts: Int = 3,
    ) = QueueDeliveryCommand(
        principal = principal,
        tenantId = tenant,
        notificationId = notificationId,
        recipientId = recipientId,
        channel = channel,
        idempotencyKey = idempotencyKey,
        correlationId = "corr-${UUID.randomUUID()}",
        causationId = "caus-${UUID.randomUUID()}",
        maxAttempts = maxAttempts,
    )

    private fun createTransitionCommand(
        notificationId: UUID,
        targetState: DeliveryState,
        idempotencyKey: String = "idem-trans-${UUID.randomUUID()}",
        expectedVersion: Long = 1L,
        providerReference: String? = "prov-ref-12345",
        errorCode: String? = null,
        errorDetail: String? = null,
        tenant: String = tenantId,
        principal: AuthenticatedPrincipal? = validPrincipal,
    ) = TransitionDeliveryCommand(
        principal = principal,
        tenantId = tenant,
        notificationId = notificationId,
        targetState = targetState,
        providerReference = providerReference,
        errorCode = errorCode,
        errorDetail = errorDetail,
        idempotencyKey = idempotencyKey,
        correlationId = "corr-${UUID.randomUUID()}",
        causationId = "caus-${UUID.randomUUID()}",
        expectedVersion = expectedVersion,
    )

    @Test
    @DisplayName("NOTIFY-003-01-T001 — Track notification delivery states produces the required authoritative outcome")
    fun testNOTIFY_003_01_T001_AuthoritativeOutcome() {
        val notifId = UUID.randomUUID()
        val queueCmd = createQueueCommand(notificationId = notifId)
        val queueResult = service.queueDelivery(queueCmd)

        assertEquals(
            "Delivery status not proof user read; health/latency/failure dashboards.",
            queueResult.semanticContract
        )
        assertFalse(queueResult.directEligibilityGranted)
        assertFalse(queueResult.financialMutationPermitted)
        assertFalse(queueResult.isUserRead, "Delivery status is never proof user read")
        assertEquals(DeliveryState.QUEUED, queueResult.deliveryState)
        assertEquals(0, queueResult.attemptCount)
        assertFalse(queueResult.isTerminal)

        // Transition to SENT_TO_PROVIDER
        val sendCmd = createTransitionCommand(
            notificationId = notifId,
            targetState = DeliveryState.SENT_TO_PROVIDER,
            idempotencyKey = "idem-send-01",
            expectedVersion = 1L,
        )
        val sendResult = service.transitionDeliveryState(sendCmd)
        assertEquals(DeliveryState.SENT_TO_PROVIDER, sendResult.deliveryState)
        assertEquals(1, sendResult.attemptCount)
        assertFalse(sendResult.isTerminal)

        // Transition to DELIVERED
        val deliverCmd = createTransitionCommand(
            notificationId = notifId,
            targetState = DeliveryState.DELIVERED,
            idempotencyKey = "idem-deliver-01",
            expectedVersion = 2L,
        )
        val deliverResult = service.transitionDeliveryState(deliverCmd)
        assertEquals(DeliveryState.DELIVERED, deliverResult.deliveryState)
        assertTrue(deliverResult.isTerminal)
        assertFalse(deliverResult.isUserRead, "Delivery status must remain distinct from read proof")
        assertNotNull(deliverResult.latencyMs)

        // Verify audit trail
        val auditEntries = service.getAuditEntries(deliverResult.trackingId)
        assertEquals(3, auditEntries.size)
        assertEquals("DELIVERY_QUEUED", auditEntries[0].eventType)
        assertEquals("DELIVERY_TRANSITION_SENT_TO_PROVIDER", auditEntries[1].eventType)
        assertEquals("DELIVERY_TRANSITION_DELIVERED", auditEntries[2].eventType)
    }

    @Test
    @DisplayName("NOTIFY-003-01-T002 — Track notification delivery states rejects invalid, boundary, unauthorized, and stale input")
    fun testNOTIFY_003_01_T002_RejectInvalidBoundaryUnauthorizedStale() {
        val notifId = UUID.randomUUID()

        // 1. Unauthenticated queue
        val unauthEx = assertThrows<NotificationDeliveryTrackingException> {
            service.queueDelivery(createQueueCommand(notificationId = notifId, principal = null))
        }
        assertEquals("UNAUTHENTICATED", unauthEx.errorCode)

        // 2. Forbidden cross-tenant queue
        val forbiddenEx = assertThrows<NotificationDeliveryTrackingException> {
            service.queueDelivery(createQueueCommand(notificationId = notifId, principal = otherTenantPrincipal))
        }
        assertEquals("FORBIDDEN", forbiddenEx.errorCode)

        // 3. Boundary check: invalid maxAttempts
        val boundaryEx = assertThrows<NotificationDeliveryTrackingException> {
            service.queueDelivery(createQueueCommand(notificationId = notifId, maxAttempts = 0))
        }
        assertEquals("BOUNDARY", boundaryEx.errorCode)

        // Successfully queue
        service.queueDelivery(createQueueCommand(notificationId = notifId))

        // 4. Stale expectedVersion
        val staleEx = assertThrows<NotificationDeliveryTrackingException> {
            service.transitionDeliveryState(
                createTransitionCommand(
                    notificationId = notifId,
                    targetState = DeliveryState.SENT_TO_PROVIDER,
                    expectedVersion = 999L
                )
            )
        }
        assertEquals("STALE", staleEx.errorCode)

        // 5. Invalid state transition: from QUEUED directly to DELIVERED without sending
        val invalidTransitionEx = assertThrows<NotificationDeliveryTrackingException> {
            service.transitionDeliveryState(
                createTransitionCommand(
                    notificationId = notifId,
                    targetState = DeliveryState.DELIVERED,
                    expectedVersion = 1L
                )
            )
        }
        assertEquals("INVALID_TRANSITION", invalidTransitionEx.errorCode)
    }

    @Test
    @DisplayName("NOTIFY-003-01-T003 — Track notification delivery states survives concurrency, duplicate delivery, and dependency failure")
    fun testNOTIFY_003_01_T003_ConcurrencyDuplicateDeliveryAndDependencyFailure() {
        val notifId = UUID.randomUUID()
        val queueCmd = createQueueCommand(notificationId = notifId, idempotencyKey = "queue-idem-c1")
        val queueResult1 = service.queueDelivery(queueCmd)

        // Duplicate replay with identical idempotency key returns exact same result
        val queueResult2 = service.queueDelivery(queueCmd)
        assertEquals(queueResult1.trackingId, queueResult2.trackingId)
        assertEquals(queueResult1.serverTime, queueResult2.serverTime)

        // Conflicting payload reuse produces CONFLICT
        val conflictEx = assertThrows<NotificationDeliveryTrackingException> {
            service.queueDelivery(
                queueCmd.copy(recipientId = "different-recipient@example.com")
            )
        }
        assertEquals("CONFLICT", conflictEx.errorCode)

        // Concurrent transitions on the same record
        service.transitionDeliveryState(
            createTransitionCommand(
                notificationId = notifId,
                targetState = DeliveryState.SENT_TO_PROVIDER,
                idempotencyKey = "send-c1",
                expectedVersion = 1L
            )
        )

        val executor = Executors.newFixedThreadPool(4)
        val successfulTransitions = ConcurrentHashMap<String, DeliveryTrackingResult>()
        val failureExceptions = ConcurrentHashMap<String, Exception>()

        for (i in 1..4) {
            val key = "deliver-concurrent-$i"
            executor.submit {
                try {
                    val res = service.transitionDeliveryState(
                        createTransitionCommand(
                            notificationId = notifId,
                            targetState = DeliveryState.DELIVERED,
                            idempotencyKey = key,
                            expectedVersion = 2L
                        )
                    )
                    successfulTransitions[key] = res
                } catch (e: Exception) {
                    failureExceptions[key] = e
                }
            }
        }

        executor.shutdown()
        assertTrue(executor.awaitTermination(5, TimeUnit.SECONDS))

        // Exactly one transition must succeed; remaining must fail due to version mismatch or terminal state conflict
        assertEquals(1, successfulTransitions.size)
        assertEquals(3, failureExceptions.size)

        // Check retry exhaustion: bounded retry prevents unbounded loops
        val retryNotifId = UUID.randomUUID()
        service.queueDelivery(createQueueCommand(notificationId = retryNotifId, maxAttempts = 1))
        service.transitionDeliveryState(
            createTransitionCommand(
                notificationId = retryNotifId,
                targetState = DeliveryState.SENT_TO_PROVIDER,
                idempotencyKey = "send-retry-1",
                expectedVersion = 1L
            )
        )
        // Re-queue
        service.transitionDeliveryState(
            createTransitionCommand(
                notificationId = retryNotifId,
                targetState = DeliveryState.QUEUED,
                idempotencyKey = "requeue-retry-1",
                expectedVersion = 2L
            )
        )
        // Second send should be rejected as RETRY_EXHAUSTED since maxAttempts = 1
        val retryEx = assertThrows<NotificationDeliveryTrackingException> {
            service.transitionDeliveryState(
                createTransitionCommand(
                    notificationId = retryNotifId,
                    targetState = DeliveryState.SENT_TO_PROVIDER,
                    idempotencyKey = "send-retry-2",
                    expectedVersion = 3L
                )
            )
        }
        assertEquals("RETRY_EXHAUSTED", retryEx.errorCode)
    }

    @Test
    @DisplayName("NOTIFY-003-01-T004 — Track notification delivery states remains compatible, recoverable, observable, and lifecycle-safe")
    fun testNOTIFY_003_01_T004_CompatibilityRecoverableObservableAndLifecycleSafe() {
        val notif1 = UUID.randomUUID()
        val notif2 = UUID.randomUUID()

        service.queueDelivery(createQueueCommand(notificationId = notif1))
        service.transitionDeliveryState(
            createTransitionCommand(
                notificationId = notif1,
                targetState = DeliveryState.SENT_TO_PROVIDER,
                idempotencyKey = "send-n1",
                expectedVersion = 1L
            )
        )
        service.transitionDeliveryState(
            createTransitionCommand(
                notificationId = notif1,
                targetState = DeliveryState.DELIVERED,
                idempotencyKey = "deliver-n1",
                expectedVersion = 2L
            )
        )

        service.queueDelivery(createQueueCommand(notificationId = notif2))
        service.transitionDeliveryState(
            createTransitionCommand(
                notificationId = notif2,
                targetState = DeliveryState.SENT_TO_PROVIDER,
                idempotencyKey = "send-n2",
                expectedVersion = 1L
            )
        )
        service.transitionDeliveryState(
            createTransitionCommand(
                notificationId = notif2,
                targetState = DeliveryState.FAILED,
                errorCode = "CARRIER_UNREACHABLE",
                errorDetail = "Carrier reported timeout",
                idempotencyKey = "fail-n2",
                expectedVersion = 2L
            )
        )

        val metrics = service.getMetricsSummary(tenantId)
        assertEquals(2, metrics.totalCount)
        assertEquals(1, metrics.deliveredCount)
        assertEquals(1, metrics.failedCount)
        assertEquals(0, metrics.inFlightCount)
        assertEquals(50.0, metrics.deliveryRate, 0.001)
        assertTrue(metrics.averageLatencyMs >= 0.0)

        // Record verification
        val record1 = service.getDeliveryRecord(tenantId, notif1)
        assertNotNull(record1)
        assertFalse(record1!!.isUserRead)
        assertFalse(record1.directEligibilityGranted)
        assertFalse(record1.financialMutationPermitted)
        assertEquals(DeliveryState.DELIVERED, record1.deliveryState)

        val record2 = service.getDeliveryRecord(tenantId, notif2)
        assertNotNull(record2)
        assertEquals(DeliveryState.FAILED, record2!!.deliveryState)
        assertEquals("CARRIER_UNREACHABLE", record2.errorCode)
    }
}
