package com.slotting.admin.gate.resilience

import com.slotting.admin.auth.AuditEvent
import com.slotting.admin.auth.AuthenticatedPrincipal
import java.time.Instant
import java.util.UUID
import java.util.concurrent.ConcurrentHashMap

// =============================================================================
// Semantic Contract & Enums
// =============================================================================

const val RESILIENCE_INTEGRATION_GATE_CONTRACT =
    "All ten TEST-FAIL scenarios recover to one authoritative state with no partial financial effect, lost restriction, silent corruption, unsafe availability, or missing alert."

enum class ResilienceGateDecision {
    GO,
    NO_GO
}

enum class ResilienceScenarioId {
    T001_DB_ABORT_AND_RESTART_CONVERGENCE,
    T002_OUTBOX_WORKER_CRASH_LEASE_EXPIRY,
    T003_REDIS_LOSS_SAFE_DEGRADATION,
    T004_PROVIDER_TIMEOUT_STATUS_QUERY,
    T005_DUPLICATE_REORDERED_NO_REGRESSION,
    T006_ANDROID_NETWORK_LOSS_REQUERY,
    T007_SOCKET_DROP_JOURNAL_SNAPSHOT_CONVERGENCE,
    T008_DEPENDENCY_OUTAGES_FAIL_CLOSED,
    T009_MIGRATION_FAILURE_WRITERS_COMPATIBLE,
    T010_REGION_PROVIDER_DISABLE_COMPLETION_CONTINUES
}

enum class ResilienceScenarioStatus {
    PASS,
    FAIL,
    SKIPPED
}

// =============================================================================
// Artifact Evidence Manifest
// =============================================================================

data class ResilienceArtifactManifest(
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

data class ResilienceScenarioResult(
    val scenarioId: ResilienceScenarioId,
    val status: ResilienceScenarioStatus,
    val details: String,
    val evidenceReference: String,
    val executedAt: Instant,
    val failureReason: String? = null
)

data class EvaluateResilienceGateCommand(
    val principal: AuthenticatedPrincipal?,
    val tenantId: String,
    val manifest: ResilienceArtifactManifest,
    val selectedScenarios: Set<ResilienceScenarioId> = ResilienceScenarioId.values().toSet(),
    val correlationId: String,
    val causationId: String
)

data class EvaluateSingleResilienceScenarioCommand(
    val principal: AuthenticatedPrincipal?,
    val tenantId: String,
    val scenarioId: ResilienceScenarioId,
    val manifest: ResilienceArtifactManifest,
    val correlationId: String,
    val causationId: String
)

data class ResilienceGateReport(
    val reportId: UUID,
    val tenantId: String,
    val decision: ResilienceGateDecision,
    val scenarioResults: Map<ResilienceScenarioId, ResilienceScenarioResult>,
    val manifest: ResilienceArtifactManifest,
    val summary: String,
    val evaluatedAt: Instant,
    val evidenceReference: String,
    val auditEvent: AuditEvent,
    val hasFinancialAuthorityImpact: Boolean = false,
    val hasAndroidDbImpact: Boolean = false,
    val hasAndroidLifecycleClaim: Boolean = false,
    val semanticContract: String = RESILIENCE_INTEGRATION_GATE_CONTRACT
)

// =============================================================================
// Evidence Store Interface & In-Memory Implementation
// =============================================================================

interface ResilienceGateEvidenceStore {
    fun saveReport(report: ResilienceGateReport): ResilienceGateReport
    fun findLatestReport(tenantId: String): ResilienceGateReport?
    fun findAllReports(tenantId: String): List<ResilienceGateReport>
}

class InMemoryResilienceGateEvidenceStore : ResilienceGateEvidenceStore {
    private val reports = ConcurrentHashMap<UUID, ResilienceGateReport>()

    override fun saveReport(report: ResilienceGateReport): ResilienceGateReport {
        reports[report.reportId] = report
        return report
    }

    override fun findLatestReport(tenantId: String): ResilienceGateReport? {
        return reports.values
            .filter { it.tenantId == tenantId }
            .maxByOrNull { it.evaluatedAt }
    }

    override fun findAllReports(tenantId: String): List<ResilienceGateReport> {
        return reports.values
            .filter { it.tenantId == tenantId }
            .sortedByDescending { it.evaluatedAt }
    }
}

// =============================================================================
// Alert Sink & Observability
// =============================================================================

data class ResilienceGateAlert(
    val alertId: UUID,
    val tenantId: String,
    val reportId: UUID?,
    val scenarioId: ResilienceScenarioId?,
    val message: String,
    val occurredAt: Instant
)

interface ResilienceGateAlertSink {
    fun emitAlert(alert: ResilienceGateAlert)
    fun getAlerts(): List<ResilienceGateAlert>
}

class InMemoryResilienceGateAlertSink : ResilienceGateAlertSink {
    private val alerts = mutableListOf<ResilienceGateAlert>()

    @Synchronized
    override fun emitAlert(alert: ResilienceGateAlert) {
        alerts.add(alert)
    }

    @Synchronized
    override fun getAlerts(): List<ResilienceGateAlert> = alerts.toList()
}

data class ResilienceGateMetricEvent(
    val eventType: String,
    val tenantId: String,
    val scenarioId: ResilienceScenarioId?,
    val outcome: String,
    val correlationId: String?,
    val causationId: String?,
    val timestamp: Instant,
    val details: Map<String, Any?> = emptyMap()
)

interface ResilienceGateObservability {
    fun recordMetric(event: ResilienceGateMetricEvent)
    fun getMetrics(): List<ResilienceGateMetricEvent>
}

class InMemoryResilienceGateObservability : ResilienceGateObservability {
    private val metrics = mutableListOf<ResilienceGateMetricEvent>()

    @Synchronized
    override fun recordMetric(event: ResilienceGateMetricEvent) {
        metrics.add(event)
    }

    @Synchronized
    override fun getMetrics(): List<ResilienceGateMetricEvent> = metrics.toList()
}

// =============================================================================
// Exceptions
// =============================================================================

class InvalidResilienceGateManifestException(message: String) : RuntimeException(message)
class UnauthorizedResilienceGateException(message: String) : RuntimeException(message)
class ResilienceGateExecutionException(message: String) : RuntimeException(message)
class ResilienceInvariantViolationException(message: String) : RuntimeException(message)
