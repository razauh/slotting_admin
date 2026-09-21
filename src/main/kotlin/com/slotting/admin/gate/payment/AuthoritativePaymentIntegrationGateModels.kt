package com.slotting.admin.gate.payment

import com.slotting.admin.auth.AuditEvent
import com.slotting.admin.auth.AuthenticatedPrincipal
import java.time.Instant
import java.util.UUID
import java.util.concurrent.ConcurrentHashMap

// =============================================================================
// Semantic Contract & Enums
// =============================================================================

const val PAYMENT_INTEGRATION_GATE_CONTRACT =
    "Canonical deposit initiation, authenticated callbacks, server-only credit, compensation, disputes, and provider-to-ledger reconciliation pass end to end without trusting Android or a return URL."

enum class PaymentGateDecision {
    GO,
    NO_GO
}

enum class PaymentScenarioId {
    T001_CERTIFIED_SANDBOX_DEPOSIT_E2E,
    T002_BAD_SIGNATURE_REPLAY_MUTATION_PROTECTION,
    T003_DUPLICATE_REORDERED_TIMEOUT_IDEMPOTENCY,
    T004_REFUND_REVERSAL_CHARGEBACK_COMPENSATION,
    T005_UNTRUSTED_CLIENT_RETURN_FLOW_SAFETY,
    T006_RECONCILIATION_ACROSS_LEDGER_STATEMENTS_QUEUE
}

enum class PaymentScenarioStatus {
    PASS,
    FAIL,
    SKIPPED
}

// =============================================================================
// Artifact Evidence Manifest
// =============================================================================

data class PaymentArtifactManifest(
    val commitHash: String,
    val artifactDigest: String,
    val configurationVersion: String,
    val environment: String,
    val owner: String,
    val reviewer: String,
    val signedAt: Instant,
    val expiry: Instant
) {
    fun isValid(now: Instant): Boolean {
        return commitHash.isNotBlank() &&
                artifactDigest.isNotBlank() &&
                configurationVersion.isNotBlank() &&
                environment.isNotBlank() &&
                owner.isNotBlank() &&
                reviewer.isNotBlank() &&
                now.isBefore(expiry)
    }
}

// =============================================================================
// Scenario Results & Execution Commands
// =============================================================================

data class PaymentScenarioResult(
    val scenarioId: PaymentScenarioId,
    val status: PaymentScenarioStatus,
    val details: String,
    val evidenceReference: String,
    val executedAt: Instant,
    val failureReason: String? = null
)

data class EvaluatePaymentGateCommand(
    val principal: AuthenticatedPrincipal?,
    val tenantId: String,
    val manifest: PaymentArtifactManifest,
    val selectedScenarios: Set<PaymentScenarioId> = PaymentScenarioId.values().toSet(),
    val correlationId: String,
    val causationId: String
)

data class EvaluateSinglePaymentScenarioCommand(
    val principal: AuthenticatedPrincipal?,
    val tenantId: String,
    val scenarioId: PaymentScenarioId,
    val manifest: PaymentArtifactManifest,
    val correlationId: String,
    val causationId: String
)

data class PaymentGateReport(
    val reportId: UUID,
    val tenantId: String,
    val decision: PaymentGateDecision,
    val scenarioResults: Map<PaymentScenarioId, PaymentScenarioResult>,
    val manifest: PaymentArtifactManifest,
    val summary: String,
    val evaluatedAt: Instant,
    val evidenceReference: String,
    val auditEvent: AuditEvent,
    val financialConservationEnforced: Boolean = true,
    val hasAndroidDbImpact: Boolean = false,
    val hasAndroidLifecycleClaim: Boolean = false,
    val semanticContract: String = PAYMENT_INTEGRATION_GATE_CONTRACT
)

// =============================================================================
// Evidence Store Interface & In-Memory Implementation
// =============================================================================

interface PaymentGateEvidenceStore {
    fun saveReport(report: PaymentGateReport): PaymentGateReport
    fun findLatestReport(tenantId: String): PaymentGateReport?
    fun findAllReports(tenantId: String): List<PaymentGateReport>
}

class InMemoryPaymentGateEvidenceStore : PaymentGateEvidenceStore {
    private val reports = ConcurrentHashMap<UUID, PaymentGateReport>()

    override fun saveReport(report: PaymentGateReport): PaymentGateReport {
        reports[report.reportId] = report
        return report
    }

    override fun findLatestReport(tenantId: String): PaymentGateReport? {
        return reports.values
            .filter { it.tenantId == tenantId }
            .maxByOrNull { it.evaluatedAt }
    }

    override fun findAllReports(tenantId: String): List<PaymentGateReport> {
        return reports.values
            .filter { it.tenantId == tenantId }
            .sortedByDescending { it.evaluatedAt }
    }
}

// =============================================================================
// Alert Sink & Observability
// =============================================================================

data class PaymentGateAlert(
    val alertId: UUID,
    val tenantId: String,
    val reportId: UUID?,
    val scenarioId: PaymentScenarioId?,
    val message: String,
    val occurredAt: Instant
)

interface PaymentGateAlertSink {
    fun emitAlert(alert: PaymentGateAlert)
    fun getAlerts(): List<PaymentGateAlert>
}

class InMemoryPaymentGateAlertSink : PaymentGateAlertSink {
    private val alerts = mutableListOf<PaymentGateAlert>()

    @Synchronized
    override fun emitAlert(alert: PaymentGateAlert) {
        alerts.add(alert)
    }

    @Synchronized
    override fun getAlerts(): List<PaymentGateAlert> = alerts.toList()
}

data class PaymentGateMetricEvent(
    val eventType: String,
    val tenantId: String,
    val scenarioId: PaymentScenarioId?,
    val outcome: String,
    val correlationId: String?,
    val causationId: String?,
    val timestamp: Instant,
    val details: Map<String, Any?> = emptyMap()
)

interface PaymentGateObservability {
    fun recordMetric(event: PaymentGateMetricEvent)
    fun getMetrics(): List<PaymentGateMetricEvent>
}

class InMemoryPaymentGateObservability : PaymentGateObservability {
    private val metrics = mutableListOf<PaymentGateMetricEvent>()

    @Synchronized
    override fun recordMetric(event: PaymentGateMetricEvent) {
        metrics.add(event)
    }

    @Synchronized
    override fun getMetrics(): List<PaymentGateMetricEvent> = metrics.toList()
}

// =============================================================================
// Exceptions
// =============================================================================

class InvalidPaymentGateManifestException(message: String) : RuntimeException(message)
class UnauthorizedPaymentGateException(message: String) : RuntimeException(message)
class PaymentGateExecutionException(message: String) : RuntimeException(message)
class PaymentInvariantViolationException(message: String) : RuntimeException(message)
