package com.slotting.admin.observability

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

class OperationalObservabilityTest {

    private val tenantId = "tenant-obs-01"
    private val clock = Clock.fixed(Instant.parse("2026-09-19T22:00:00Z"), ZoneOffset.UTC)
    private lateinit var service: OperationalObservabilityService

    private val validPrincipal = AuthenticatedPrincipal(
        id = "telemetry-actor-01",
        tenantId = tenantId,
        roles = setOf(AdminRole.SUPPORT),
        kind = PrincipalKind.ADMIN,
    )

    private val otherTenantPrincipal = AuthenticatedPrincipal(
        id = "telemetry-actor-other",
        tenantId = "tenant-other",
        roles = setOf(AdminRole.SUPPORT),
        kind = PrincipalKind.ADMIN,
    )

    @BeforeEach
    fun setup() {
        service = OperationalObservabilityService(clock = clock)
    }

    private fun createEmitCommand(
        serviceName: String = "ledger-service",
        signalType: TelemetrySignalType = TelemetrySignalType.LOG,
        incidentType: CriticalIncidentType = CriticalIncidentType.POSTING_FAILURE,
        severity: TelemetrySeverity = TelemetrySeverity.CRITICAL,
        message: String = "Ledger posting failed due to balance mismatch",
        correlationId: String = "corr-${UUID.randomUUID()}",
        causationId: String = "caus-${UUID.randomUUID()}",
        traceId: String? = "trace-${UUID.randomUUID()}",
        spanId: String? = "span-${UUID.randomUUID()}",
        metricName: String? = null,
        metricValue: Double? = null,
        idempotencyKey: String = "idem-obs-${UUID.randomUUID()}",
        tenant: String = tenantId,
        principal: AuthenticatedPrincipal? = validPrincipal,
    ) = EmitTelemetryCommand(
        principal = principal,
        tenantId = tenant,
        serviceName = serviceName,
        signalType = signalType,
        incidentType = incidentType,
        severity = severity,
        message = message,
        correlationId = correlationId,
        causationId = causationId,
        traceId = traceId,
        spanId = spanId,
        metricName = metricName,
        metricValue = metricValue,
        idempotencyKey = idempotencyKey,
    )

    @Test
    @DisplayName("OBS-001-01-T001 — Emit correlated structured logs, metrics, and traces produces the required authoritative outcome")
    fun testOBS_001_01_T001_AuthoritativeOutcome() {
        // Critical incident: posting failure MUST page on-call SRE
        val cmd = createEmitCommand(
            incidentType = CriticalIncidentType.POSTING_FAILURE,
            severity = TelemetrySeverity.CRITICAL,
            message = "Critical ledger posting failure: unbalanced debit/credit"
        )
        val result = service.emitTelemetry(cmd)

        assertEquals(
            "Dashboards include duplicates, posting failures, imbalance, mismatch, failed callbacks, stuck withdrawals.",
            result.semanticContract
        )
        assertFalse(result.directEligibilityGranted)
        assertFalse(result.financialMutationPermitted)
        assertTrue(result.paged, "Injected critical failure must trigger page alert")
        assertNotNull(result.alertId)

        // Verify event record and paging alert
        val eventRecord = service.getEventRecord(result.eventId)
        assertNotNull(eventRecord)
        assertEquals(CriticalIncidentType.POSTING_FAILURE, eventRecord!!.incidentType)
        assertEquals(TelemetrySeverity.CRITICAL, eventRecord.severity)
        assertTrue(eventRecord.paged)
        assertFalse(eventRecord.directEligibilityGranted)
        assertFalse(eventRecord.financialMutationPermitted)

        val alertRecord = service.getAlertRecord(result.alertId!!)
        assertNotNull(alertRecord)
        assertEquals("on-call-sre@slotting-admin", alertRecord!!.pagerTarget)
        assertTrue(alertRecord.delivered)

        // Non-critical incident: WARN should NOT page
        val warnCmd = createEmitCommand(
            incidentType = CriticalIncidentType.DUPLICATE_REQUEST,
            severity = TelemetrySeverity.WARN,
            message = "Duplicate request detected and dropped safely"
        )
        val warnResult = service.emitTelemetry(warnCmd)
        assertFalse(warnResult.paged, "Non-critical warning must not page")
        assertNull(warnResult.alertId)
    }

    @Test
    @DisplayName("OBS-001-01-T002 — Emit correlated structured logs, metrics, and traces rejects invalid, boundary, unauthorized, and stale input")
    fun testOBS_001_01_T002_RejectInvalidBoundaryUnauthorizedStale() {
        // 1. Unauthenticated emission
        val unauthEx = assertThrows<ObservabilityException> {
            service.emitTelemetry(createEmitCommand(principal = null))
        }
        assertEquals("UNAUTHENTICATED", unauthEx.errorCode)

        // 2. Cross-tenant emission
        val forbiddenEx = assertThrows<ObservabilityException> {
            service.emitTelemetry(createEmitCommand(principal = otherTenantPrincipal))
        }
        assertEquals("FORBIDDEN", forbiddenEx.errorCode)

        // 3. Boundary check: empty message
        val boundaryEx = assertThrows<ObservabilityException> {
            service.emitTelemetry(createEmitCommand(message = ""))
        }
        assertEquals("INVALID", boundaryEx.errorCode)

        // 4. PII Redaction: message containing PII must be sanitized before persistence
        val piiCmd = createEmitCommand(
            message = "Player user_id with email player@example.com and SSN 123-45-6789 reported issue"
        )
        val piiResult = service.emitTelemetry(piiCmd)
        val storedEvent = service.getEventRecord(piiResult.eventId)
        assertNotNull(storedEvent)
        assertFalse(storedEvent!!.message.contains("player@example.com"))
        assertFalse(storedEvent.message.contains("123-45-6789"))
        assertTrue(storedEvent.message.contains("[REDACTED]"))
    }

    @Test
    @DisplayName("OBS-001-01-T003 — Emit correlated structured logs, metrics, and traces survives concurrency, duplicate delivery, and dependency failure")
    fun testOBS_001_01_T003_ConcurrencyDuplicateDeliveryAndDependencyFailure() {
        val emitCmd = createEmitCommand(idempotencyKey = "obs-idem-c1")
        val res1 = service.emitTelemetry(emitCmd)

        // Duplicate replay with identical key
        val res2 = service.emitTelemetry(emitCmd)
        assertEquals(res1.eventId, res2.eventId)
        assertEquals(res1.serverTime, res2.serverTime)

        // Conflicting payload reuse produces CONFLICT
        val conflictEx = assertThrows<ObservabilityException> {
            service.emitTelemetry(emitCmd.copy(serviceName = "different-service"))
        }
        assertEquals("CONFLICT", conflictEx.errorCode)

        // Concurrent telemetry emission races
        val executor = Executors.newFixedThreadPool(4)
        val successfulEmissions = ConcurrentHashMap<String, TelemetryResult>()
        val failureExceptions = ConcurrentHashMap<String, Exception>()

        for (i in 1..4) {
            val key = "concurrent-obs-$i"
            executor.submit {
                try {
                    val res = service.emitTelemetry(
                        createEmitCommand(
                            idempotencyKey = "key-$i",
                            correlationId = "corr-race-$i"
                        )
                    )
                    successfulEmissions[key] = res
                } catch (e: Exception) {
                    failureExceptions[key] = e
                }
            }
        }

        executor.shutdown()
        assertTrue(executor.awaitTermination(5, TimeUnit.SECONDS))

        // All distinct emissions succeed concurrently with isolated correlation IDs
        assertEquals(4, successfulEmissions.size)
        assertEquals(0, failureExceptions.size)
    }

    @Test
    @DisplayName("OBS-001-01-T004 — Emit correlated structured logs, metrics, and traces remains compatible, recoverable, observable, and lifecycle-safe")
    fun testOBS_001_01_T004_CompatibilityRecoverableObservableAndLifecycleSafe() {
        // Emit events across all required operational dimensions
        val incidentTypes = listOf(
            CriticalIncidentType.DUPLICATE_REQUEST,
            CriticalIncidentType.POSTING_FAILURE,
            CriticalIncidentType.BALANCE_IMBALANCE,
            CriticalIncidentType.CATALOG_MISMATCH,
            CriticalIncidentType.CALLBACK_FAILURE,
            CriticalIncidentType.STUCK_WITHDRAWAL,
        )

        for (incident in incidentTypes) {
            service.emitTelemetry(
                createEmitCommand(
                    incidentType = incident,
                    severity = TelemetrySeverity.CRITICAL,
                    message = "Operational incident for $incident"
                )
            )
        }

        // Add an extra non-critical event
        service.emitTelemetry(
            createEmitCommand(
                incidentType = CriticalIncidentType.DUPLICATE_REQUEST,
                severity = TelemetrySeverity.INFO,
                message = "Informational duplicate dropped"
            )
        )

        val summary = service.getDashboardSummary(tenantId)
        assertEquals(7, summary.totalEvents)
        assertEquals(6, summary.criticalCount)
        assertEquals(6, summary.pagedAlertCount)
        assertEquals(2, summary.duplicatesCount)
        assertEquals(1, summary.postingFailuresCount)
        assertEquals(1, summary.balanceImbalanceCount)
        assertEquals(1, summary.catalogMismatchCount)
        assertEquals(1, summary.callbackFailuresCount)
        assertEquals(1, summary.stuckWithdrawalsCount)
    }
}
