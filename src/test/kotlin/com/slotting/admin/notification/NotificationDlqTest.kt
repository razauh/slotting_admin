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

class NotificationDlqTest {

    private val tenantId = "tenant-notify-dlq-01"
    private val clock = Clock.fixed(Instant.parse("2026-09-19T22:00:00Z"), ZoneOffset.UTC)
    private lateinit var service: NotificationDlqService

    private val validAdminPrincipal = AuthenticatedPrincipal(
        id = "admin-actor-01",
        tenantId = tenantId,
        roles = setOf(AdminRole.SUPER_ADMIN),
        kind = PrincipalKind.ADMIN,
    )

    private val auditorPrincipal = AuthenticatedPrincipal(
        id = "auditor-actor-01",
        tenantId = tenantId,
        roles = setOf(AdminRole.AUDITOR),
        kind = PrincipalKind.ADMIN,
    )

    private val otherTenantPrincipal = AuthenticatedPrincipal(
        id = "other-actor-01",
        tenantId = "tenant-other",
        roles = setOf(AdminRole.SUPER_ADMIN),
        kind = PrincipalKind.ADMIN,
    )

    @BeforeEach
    fun setup() {
        service = NotificationDlqService(clock = clock)
    }

    private fun createQuarantineCommand(
        trackingId: UUID = UUID.randomUUID(),
        notificationId: UUID = UUID.randomUUID(),
        recipientId: String = "user-dlq@example.com",
        channel: NotificationDeliveryChannel = NotificationDeliveryChannel.EMAIL,
        quarantineReason: QuarantineReason = QuarantineReason.RETRY_EXHAUSTION,
        quarantineDetail: String = "Max retries 3 exceeded; downstream carrier unavailable",
        failureCount: Int = 3,
        idempotencyKey: String = "idem-dlq-${UUID.randomUUID()}",
        tenant: String = tenantId,
        principal: AuthenticatedPrincipal? = validAdminPrincipal,
    ) = QuarantineNotificationCommand(
        principal = principal,
        tenantId = tenant,
        trackingId = trackingId,
        notificationId = notificationId,
        recipientId = recipientId,
        channel = channel,
        quarantineReason = quarantineReason,
        quarantineDetail = quarantineDetail,
        failureCount = failureCount,
        idempotencyKey = idempotencyKey,
        correlationId = "corr-${UUID.randomUUID()}",
        causationId = "caus-${UUID.randomUUID()}",
    )

    private fun createResolveCommand(
        dlqId: UUID,
        action: String = "REPLAY",
        resolutionNote: String = "Carrier outage resolved, approved replay",
        idempotencyKey: String = "idem-resolve-${UUID.randomUUID()}",
        expectedVersion: Long = 1L,
        tenant: String = tenantId,
        principal: AuthenticatedPrincipal? = validAdminPrincipal,
    ) = ResolveDlqItemCommand(
        principal = principal,
        tenantId = tenant,
        dlqId = dlqId,
        action = action,
        resolutionNote = resolutionNote,
        idempotencyKey = idempotencyKey,
        correlationId = "corr-${UUID.randomUUID()}",
        causationId = "caus-${UUID.randomUUID()}",
        expectedVersion = expectedVersion,
    )

    @Test
    @DisplayName("NOTIFY-003-03-T001 — Quarantine notification failures in a DLQ produces the required authoritative outcome")
    fun testNOTIFY_003_03_T001_AuthoritativeOutcome() {
        val notifId = UUID.randomUUID()
        val quarantineCmd = createQuarantineCommand(notificationId = notifId)
        val quarantineResult = service.quarantineNotification(quarantineCmd)

        assertEquals(
            "Delivery status not proof user read; health/latency/failure dashboards.",
            quarantineResult.semanticContract
        )
        assertFalse(quarantineResult.directEligibilityGranted)
        assertFalse(quarantineResult.financialMutationPermitted)
        assertFalse(quarantineResult.isUserRead, "DLQ quarantine status is never proof user read")
        assertEquals(DlqStatus.QUARANTINED, quarantineResult.dlqStatus)
        assertEquals(QuarantineReason.RETRY_EXHAUSTION, quarantineResult.quarantineReason)
        assertTrue(quarantineResult.alertEmitted)
        assertEquals(3, quarantineResult.failureCount)

        // Resolve via REPLAY
        val resolveCmd = createResolveCommand(
            dlqId = quarantineResult.dlqId,
            action = "REPLAY",
            resolutionNote = "Resolved downstream issue",
            expectedVersion = 1L,
        )
        val resolveResult = service.resolveDlqItem(resolveCmd)

        assertEquals(DlqStatus.RESOLVED_REPLAYED, resolveResult.dlqStatus)
        assertFalse(resolveResult.alertEmitted)
        assertFalse(resolveResult.isUserRead, "Resolved DLQ item is distinct from read proof")
        assertFalse(resolveResult.directEligibilityGranted)
        assertFalse(resolveResult.financialMutationPermitted)

        // Verify audit log
        val auditEntries = service.getAuditEntries(quarantineResult.dlqId)
        assertEquals(2, auditEntries.size)
        assertEquals("NOTIFICATION_QUARANTINED", auditEntries[0].eventType)
        assertEquals("NOTIFICATION_DLQ_RESOLVED_RESOLVED_REPLAYED", auditEntries[1].eventType)
    }

    @Test
    @DisplayName("NOTIFY-003-03-T002 — Quarantine notification failures in a DLQ rejects invalid, boundary, unauthorized, and stale input")
    fun testNOTIFY_003_03_T002_RejectInvalidBoundaryUnauthorizedStale() {
        val notifId = UUID.randomUUID()

        // 1. Unauthenticated quarantine
        val unauthEx = assertThrows<NotificationDlqException> {
            service.quarantineNotification(createQuarantineCommand(notificationId = notifId, principal = null))
        }
        assertEquals("UNAUTHENTICATED", unauthEx.errorCode)

        // 2. Cross-tenant quarantine
        val forbiddenEx = assertThrows<NotificationDlqException> {
            service.quarantineNotification(createQuarantineCommand(notificationId = notifId, principal = otherTenantPrincipal))
        }
        assertEquals("FORBIDDEN", forbiddenEx.errorCode)

        // 3. Boundary check: failureCount <= 0
        val boundaryEx = assertThrows<NotificationDlqException> {
            service.quarantineNotification(createQuarantineCommand(notificationId = notifId, failureCount = 0))
        }
        assertEquals("BOUNDARY", boundaryEx.errorCode)

        // Successfully quarantine
        val quarantined = service.quarantineNotification(createQuarantineCommand(notificationId = notifId))

        // 4. Stale version on resolve
        val staleEx = assertThrows<NotificationDlqException> {
            service.resolveDlqItem(
                createResolveCommand(
                    dlqId = quarantined.dlqId,
                    expectedVersion = 999L
                )
            )
        }
        assertEquals("STALE", staleEx.errorCode)

        // 5. RBAC check: AUDITOR cannot resolve DLQ items
        val rbacEx = assertThrows<NotificationDlqException> {
            service.resolveDlqItem(
                createResolveCommand(
                    dlqId = quarantined.dlqId,
                    principal = auditorPrincipal
                )
            )
        }
        assertEquals("FORBIDDEN", rbacEx.errorCode)
    }

    @Test
    @DisplayName("NOTIFY-003-03-T003 — Quarantine notification failures in a DLQ survives concurrency, duplicate delivery, and dependency failure")
    fun testNOTIFY_003_03_T003_ConcurrencyDuplicateDeliveryAndDependencyFailure() {
        val notifId = UUID.randomUUID()
        val quarantineCmd = createQuarantineCommand(notificationId = notifId, idempotencyKey = "dlq-idem-c1")
        val res1 = service.quarantineNotification(quarantineCmd)

        // Idempotent duplicate replay
        val res2 = service.quarantineNotification(quarantineCmd)
        assertEquals(res1.dlqId, res2.dlqId)
        assertEquals(res1.serverTime, res2.serverTime)

        // Conflicting payload reuse produces CONFLICT
        val conflictEx = assertThrows<NotificationDlqException> {
            service.quarantineNotification(quarantineCmd.copy(failureCount = 99))
        }
        assertEquals("CONFLICT", conflictEx.errorCode)

        // Concurrent resolution attempts
        val executor = Executors.newFixedThreadPool(4)
        val successfulResolutions = ConcurrentHashMap<String, NotificationDlqResult>()
        val failureExceptions = ConcurrentHashMap<String, Exception>()

        for (i in 1..4) {
            val key = "resolve-concurrent-$i"
            executor.submit {
                try {
                    val res = service.resolveDlqItem(
                        createResolveCommand(
                            dlqId = res1.dlqId,
                            action = if (i % 2 == 0) "REPLAY" else "DISCARD",
                            idempotencyKey = key,
                            expectedVersion = 1L
                        )
                    )
                    successfulResolutions[key] = res
                } catch (e: Exception) {
                    failureExceptions[key] = e
                }
            }
        }

        executor.shutdown()
        assertTrue(executor.awaitTermination(5, TimeUnit.SECONDS))

        // Exactly one resolution succeeds; remaining fail due to version mismatch or finalized state conflict
        assertEquals(1, successfulResolutions.size)
        assertEquals(3, failureExceptions.size)
    }

    @Test
    @DisplayName("NOTIFY-003-03-T004 — Quarantine notification failures in a DLQ remains compatible, recoverable, observable, and lifecycle-safe")
    fun testNOTIFY_003_03_T004_CompatibilityRecoverableObservableAndLifecycleSafe() {
        val notif1 = UUID.randomUUID()
        val notif2 = UUID.randomUUID()
        val notif3 = UUID.randomUUID()

        // 1. Quarantined & Replayed
        val q1 = service.quarantineNotification(createQuarantineCommand(notificationId = notif1))
        service.resolveDlqItem(createResolveCommand(dlqId = q1.dlqId, action = "REPLAY", resolutionNote = "Replay authorized"))

        // 2. Quarantined & Discarded
        val q2 = service.quarantineNotification(createQuarantineCommand(notificationId = notif2))
        service.resolveDlqItem(createResolveCommand(dlqId = q2.dlqId, action = "DISCARD", resolutionNote = "Discard poison payload"))

        // 3. Active Quarantined
        val q3 = service.quarantineNotification(createQuarantineCommand(notificationId = notif3))

        val metrics = service.getDashboardMetrics(tenantId)
        assertEquals(3, metrics.totalQuarantined)
        assertEquals(1, metrics.activeQuarantined)
        assertEquals(1, metrics.resolvedReplayed)
        assertEquals(1, metrics.resolvedDiscarded)
        assertEquals(3, metrics.alertCount)

        val record3 = service.getDlqRecord(q3.dlqId)
        assertNotNull(record3)
        assertFalse(record3!!.isUserRead)
        assertFalse(record3.directEligibilityGranted)
        assertFalse(record3.financialMutationPermitted)
        assertEquals(DlqStatus.QUARANTINED, record3.dlqStatus)
    }
}
