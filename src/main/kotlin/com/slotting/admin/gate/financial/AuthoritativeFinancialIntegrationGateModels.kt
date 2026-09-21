package com.slotting.admin.gate.financial

import com.slotting.admin.auth.AuditEvent
import com.slotting.admin.auth.AuthenticatedPrincipal
import java.time.Instant
import java.util.UUID
import java.util.concurrent.ConcurrentHashMap

// =============================================================================
// Semantic Contract & Enums
// =============================================================================

const val FINANCIAL_INTEGRATION_GATE_CONTRACT =
    "All twelve TEST-FIN assertions pass together against one production-like PostgreSQL artifact with zero imbalance, duplicate effect, illegal bucket transfer, projection drift, or replay mismatch."

enum class FinancialGateDecision {
    GO,
    NO_GO
}

enum class FinancialScenarioId {
    T001_DEBITS_EQUAL_CREDITS,
    T002_ATOMIC_COMMIT_UNDER_FAULTS,
    T003_IDEMPOTENT_REPLAY_AND_KEY_REUSE,
    T004_CONCURRENT_POSTINGS_NO_OVERSPEND,
    T005_BUCKET_INTEGRITY_NO_CROSS,
    T006_UNTRUSTED_CLIENT_CANNOT_MUTATE,
    T007_DUPLICATE_REORDERED_PROVIDER_EVENTS,
    T008_IMMUTABLE_COMPENSATING_ENTRIES,
    T009_JOURNAL_REBUILD_EQUALS_PROJECTION,
    T010_MISMATCH_AND_STUCK_ITEMS_SURFACED,
    T011_RESTORE_REPLAY_LINEAGE_PRESERVED,
    T012_CURRENCY_AND_VALUE_CONSTRAINTS
}

enum class FinancialScenarioStatus {
    PASS,
    FAIL,
    SKIPPED
}

// =============================================================================
// Artifact Evidence Manifest
// =============================================================================

data class FinancialArtifactManifest(
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

data class FinancialScenarioResult(
    val scenarioId: FinancialScenarioId,
    val status: FinancialScenarioStatus,
    val details: String,
    val evidenceReference: String,
    val executedAt: Instant,
    val failureReason: String? = null
)

data class EvaluateFinancialGateCommand(
    val principal: AuthenticatedPrincipal?,
    val tenantId: String,
    val manifest: FinancialArtifactManifest,
    val selectedScenarios: Set<FinancialScenarioId> = FinancialScenarioId.values().toSet(),
    val correlationId: String,
    val causationId: String
)

data class EvaluateSingleFinancialScenarioCommand(
    val principal: AuthenticatedPrincipal?,
    val tenantId: String,
    val scenarioId: FinancialScenarioId,
    val manifest: FinancialArtifactManifest,
    val correlationId: String,
    val causationId: String
)

data class FinancialGateReport(
    val reportId: UUID,
    val tenantId: String,
    val decision: FinancialGateDecision,
    val scenarioResults: Map<FinancialScenarioId, FinancialScenarioResult>,
    val manifest: FinancialArtifactManifest,
    val summary: String,
    val evaluatedAt: Instant,
    val evidenceReference: String,
    val auditEvent: AuditEvent,
    val financialConservationEnforced: Boolean = true,
    val hasAndroidDbImpact: Boolean = false,
    val hasAndroidLifecycleClaim: Boolean = false,
    val semanticContract: String = FINANCIAL_INTEGRATION_GATE_CONTRACT
)

// =============================================================================
// Evidence Store Interface & In-Memory Implementation
// =============================================================================

interface FinancialGateEvidenceStore {
    fun saveReport(report: FinancialGateReport): FinancialGateReport
    fun findLatestReport(tenantId: String): FinancialGateReport?
    fun findAllReports(tenantId: String): List<FinancialGateReport>
}

class InMemoryFinancialGateEvidenceStore : FinancialGateEvidenceStore {
    private val reports = ConcurrentHashMap<UUID, FinancialGateReport>()

    override fun saveReport(report: FinancialGateReport): FinancialGateReport {
        reports[report.reportId] = report
        return report
    }

    override fun findLatestReport(tenantId: String): FinancialGateReport? {
        return reports.values
            .filter { it.tenantId == tenantId }
            .maxByOrNull { it.evaluatedAt }
    }

    override fun findAllReports(tenantId: String): List<FinancialGateReport> {
        return reports.values
            .filter { it.tenantId == tenantId }
            .sortedByDescending { it.evaluatedAt }
    }
}

// =============================================================================
// Alert Sink & Observability
// =============================================================================

data class FinancialGateAlert(
    val alertId: UUID,
    val tenantId: String,
    val reportId: UUID?,
    val scenarioId: FinancialScenarioId?,
    val message: String,
    val occurredAt: Instant
)

interface FinancialGateAlertSink {
    fun emitAlert(alert: FinancialGateAlert)
    fun getAlerts(): List<FinancialGateAlert>
}

class InMemoryFinancialGateAlertSink : FinancialGateAlertSink {
    private val alerts = mutableListOf<FinancialGateAlert>()

    @Synchronized
    override fun emitAlert(alert: FinancialGateAlert) {
        alerts.add(alert)
    }

    @Synchronized
    override fun getAlerts(): List<FinancialGateAlert> = alerts.toList()
}

data class FinancialGateMetricEvent(
    val eventType: String,
    val tenantId: String,
    val scenarioId: FinancialScenarioId?,
    val outcome: String,
    val correlationId: String?,
    val causationId: String?,
    val timestamp: Instant,
    val details: Map<String, Any?> = emptyMap()
)

interface FinancialGateObservability {
    fun recordMetric(event: FinancialGateMetricEvent)
    fun getMetrics(): List<FinancialGateMetricEvent>
}

class InMemoryFinancialGateObservability : FinancialGateObservability {
    private val metrics = mutableListOf<FinancialGateMetricEvent>()

    @Synchronized
    override fun recordMetric(event: FinancialGateMetricEvent) {
        metrics.add(event)
    }

    @Synchronized
    override fun getMetrics(): List<FinancialGateMetricEvent> = metrics.toList()
}

// =============================================================================
// Exceptions
// =============================================================================

class InvalidFinancialGateManifestException(message: String) : RuntimeException(message)
class UnauthorizedFinancialGateException(message: String) : RuntimeException(message)
class FinancialGateExecutionException(message: String) : RuntimeException(message)
class FinancialInvariantViolationException(message: String) : RuntimeException(message)
