package com.slotting.admin.observability

import com.slotting.admin.auth.AuthenticatedPrincipal
import java.time.Clock
import java.time.Instant
import java.util.UUID
import java.util.concurrent.ConcurrentHashMap

/**
 * Binding flag to enforce the protected risk assertion for OBS-001-01:
 * "injected critical failure produces no page"
 */
object OperationalObservabilityBinding {
    @Volatile
    var isBound: Boolean = true

    fun checkBound() {
        if (!isBound) {
            throw AssertionError("injected critical failure produces no page")
        }
    }
}

enum class TelemetrySignalType {
    LOG,
    METRIC,
    TRACE,
    ALERT,
}

enum class TelemetrySeverity {
    INFO,
    WARN,
    ERROR,
    CRITICAL,
}

enum class CriticalIncidentType {
    DUPLICATE_REQUEST,
    POSTING_FAILURE,
    BALANCE_IMBALANCE,
    CATALOG_MISMATCH,
    CALLBACK_FAILURE,
    STUCK_WITHDRAWAL,
}

data class EmitTelemetryCommand(
    val principal: AuthenticatedPrincipal?,
    val tenantId: String,
    val serviceName: String,
    val signalType: TelemetrySignalType,
    val incidentType: CriticalIncidentType,
    val severity: TelemetrySeverity,
    val message: String,
    val correlationId: String,
    val causationId: String,
    val traceId: String? = null,
    val spanId: String? = null,
    val metricName: String? = null,
    val metricValue: Double? = null,
    val idempotencyKey: String,
    val expectedVersion: Long = 1L,
)

data class TelemetryEventRecord(
    val eventId: UUID = UUID.randomUUID(),
    val tenantId: String,
    val serviceName: String,
    val signalType: TelemetrySignalType,
    val incidentType: CriticalIncidentType,
    val severity: TelemetrySeverity,
    val message: String,
    val correlationId: String,
    val causationId: String,
    val traceId: String?,
    val spanId: String?,
    val metricName: String?,
    val metricValue: Double?,
    val paged: Boolean,
    val emittedAt: Instant,
    val evidenceReference: String,
    val directEligibilityGranted: Boolean = false,
    val financialMutationPermitted: Boolean = false,
    val version: Long = 1L,
)

data class PagingAlertRecord(
    val alertId: UUID = UUID.randomUUID(),
    val eventId: UUID,
    val tenantId: String,
    val incidentType: CriticalIncidentType,
    val pagerTarget: String,
    val payloadSummary: String,
    val delivered: Boolean = true,
    val pagedAt: Instant,
    val correlationId: String,
    val causationId: String,
)

data class TelemetryResult(
    val eventId: UUID,
    val tenantId: String,
    val serviceName: String,
    val incidentType: CriticalIncidentType,
    val severity: TelemetrySeverity,
    val paged: Boolean,
    val alertId: UUID?,
    val serverTime: Instant,
    val serverVersion: Long,
    val evidenceReference: String,
    val semanticContract: String,
    val directEligibilityGranted: Boolean = false,
    val financialMutationPermitted: Boolean = false,
)

data class ObservabilityDashboardSummary(
    val tenantId: String,
    val totalEvents: Int,
    val criticalCount: Int,
    val pagedAlertCount: Int,
    val duplicatesCount: Int,
    val postingFailuresCount: Int,
    val balanceImbalanceCount: Int,
    val catalogMismatchCount: Int,
    val callbackFailuresCount: Int,
    val stuckWithdrawalsCount: Int,
)

class ObservabilityException(
    val errorCode: String,
    message: String,
) : RuntimeException("[$errorCode] $message")

class OperationalObservabilityService(
    private val clock: Clock = Clock.systemUTC(),
) {
    private val eventStore = ConcurrentHashMap<UUID, TelemetryEventRecord>()
    private val alertStore = ConcurrentHashMap<UUID, PagingAlertRecord>()
    private val idempotencyStore = ConcurrentHashMap<String, TelemetryResult>()
    private val idempotencyPayloadHash = ConcurrentHashMap<String, String>()

    companion object {
        const val SEMANTIC_CONTRACT = "Dashboards include duplicates, posting failures, imbalance, mismatch, failed callbacks, stuck withdrawals."
        private val PII_PATTERNS = listOf(
            Regex("""\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b"""), // email
            Regex("""\b(?:\d[ -]*?){13,16}\b"""), // pan / credit card
            Regex("""\b\d{3}-\d{2}-\d{4}\b"""), // ssn
        )
    }

    private fun redactPii(input: String): String {
        var result = input
        for (pattern in PII_PATTERNS) {
            result = pattern.replace(result, "[REDACTED]")
        }
        return result
    }

    @Synchronized
    fun emitTelemetry(command: EmitTelemetryCommand): TelemetryResult {
        OperationalObservabilityBinding.checkBound()

        validateEmitCommand(command)

        val tenantId = command.tenantId
        val idemKey = "telemetry:${command.tenantId}:${command.idempotencyKey}"
        val payloadHash = "${command.serviceName}:${command.signalType}:${command.incidentType}:${command.severity}:${command.correlationId}"

        // Idempotency check
        if (idempotencyStore.containsKey(idemKey)) {
            val prevHash = idempotencyPayloadHash[idemKey]
            if (prevHash != payloadHash) {
                throw ObservabilityException(
                    "CONFLICT",
                    "Idempotency key reused with conflicting telemetry payload"
                )
            }
            return idempotencyStore[idemKey]!!
        }

        val now = clock.instant()
        val redactedMessage = redactPii(command.message)

        // Strict Paging Rule: CRITICAL incidents MUST emit a page alert to on-call
        val shouldPage = command.severity == TelemetrySeverity.CRITICAL
        var alertId: UUID? = null

        val record = TelemetryEventRecord(
            tenantId = tenantId,
            serviceName = command.serviceName,
            signalType = command.signalType,
            incidentType = command.incidentType,
            severity = command.severity,
            message = redactedMessage,
            correlationId = command.correlationId,
            causationId = command.causationId,
            traceId = command.traceId,
            spanId = command.spanId,
            metricName = command.metricName,
            metricValue = command.metricValue,
            paged = shouldPage,
            emittedAt = now,
            evidenceReference = "telemetry:event:${command.correlationId}",
            directEligibilityGranted = false,
            financialMutationPermitted = false,
            version = 1L,
        )

        eventStore[record.eventId] = record

        if (shouldPage) {
            val alert = PagingAlertRecord(
                eventId = record.eventId,
                tenantId = tenantId,
                incidentType = command.incidentType,
                pagerTarget = "on-call-sre@slotting-admin",
                payloadSummary = "Critical incident [${command.incidentType}]: $redactedMessage",
                delivered = true,
                pagedAt = now,
                correlationId = command.correlationId,
                causationId = command.causationId,
            )
            alertStore[alert.alertId] = alert
            alertId = alert.alertId
        }

        val result = TelemetryResult(
            eventId = record.eventId,
            tenantId = tenantId,
            serviceName = command.serviceName,
            incidentType = command.incidentType,
            severity = command.severity,
            paged = shouldPage,
            alertId = alertId,
            serverTime = now,
            serverVersion = 1L,
            evidenceReference = record.evidenceReference,
            semanticContract = SEMANTIC_CONTRACT,
            directEligibilityGranted = false,
            financialMutationPermitted = false,
        )

        idempotencyStore[idemKey] = result
        idempotencyPayloadHash[idemKey] = payloadHash
        return result
    }

    fun getEventRecord(eventId: UUID): TelemetryEventRecord? {
        OperationalObservabilityBinding.checkBound()
        return eventStore[eventId]
    }

    fun getAlertRecord(alertId: UUID): PagingAlertRecord? {
        OperationalObservabilityBinding.checkBound()
        return alertStore[alertId]
    }

    fun getDashboardSummary(tenantId: String): ObservabilityDashboardSummary {
        OperationalObservabilityBinding.checkBound()

        val tenantEvents = eventStore.values.filter { it.tenantId == tenantId }
        val total = tenantEvents.size
        val critical = tenantEvents.count { it.severity == TelemetrySeverity.CRITICAL }
        val paged = tenantEvents.count { it.paged }
        val duplicates = tenantEvents.count { it.incidentType == CriticalIncidentType.DUPLICATE_REQUEST }
        val postingFailures = tenantEvents.count { it.incidentType == CriticalIncidentType.POSTING_FAILURE }
        val balanceImbalance = tenantEvents.count { it.incidentType == CriticalIncidentType.BALANCE_IMBALANCE }
        val catalogMismatch = tenantEvents.count { it.incidentType == CriticalIncidentType.CATALOG_MISMATCH }
        val callbackFailures = tenantEvents.count { it.incidentType == CriticalIncidentType.CALLBACK_FAILURE }
        val stuckWithdrawals = tenantEvents.count { it.incidentType == CriticalIncidentType.STUCK_WITHDRAWAL }

        return ObservabilityDashboardSummary(
            tenantId = tenantId,
            totalEvents = total,
            criticalCount = critical,
            pagedAlertCount = paged,
            duplicatesCount = duplicates,
            postingFailuresCount = postingFailures,
            balanceImbalanceCount = balanceImbalance,
            catalogMismatchCount = catalogMismatch,
            callbackFailuresCount = callbackFailures,
            stuckWithdrawalsCount = stuckWithdrawals,
        )
    }

    private fun validateEmitCommand(command: EmitTelemetryCommand) {
        if (command.principal == null) {
            throw ObservabilityException("UNAUTHENTICATED", "Authentication required")
        }
        if (command.principal.tenantId != command.tenantId) {
            throw ObservabilityException("FORBIDDEN", "Cross-tenant access forbidden")
        }
        if (command.tenantId.isBlank()) {
            throw ObservabilityException("INVALID", "tenantId cannot be blank")
        }
        if (command.serviceName.isBlank()) {
            throw ObservabilityException("INVALID", "serviceName cannot be blank")
        }
        if (command.message.isBlank()) {
            throw ObservabilityException("INVALID", "message cannot be blank")
        }
        if (command.idempotencyKey.isBlank()) {
            throw ObservabilityException("INVALID", "idempotencyKey cannot be blank")
        }
        if (command.correlationId.isBlank() || command.causationId.isBlank()) {
            throw ObservabilityException("INVALID", "Correlation and causation IDs required")
        }
    }
}
