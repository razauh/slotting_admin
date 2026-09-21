package com.slotting.admin.gate.casino

import com.slotting.admin.auth.AuditEvent
import com.slotting.admin.auth.AuthenticatedPrincipal
import java.time.Instant
import java.util.UUID
import java.util.concurrent.ConcurrentHashMap

// =============================================================================
// Semantic Contract & Enums
// =============================================================================

const val CASINO_INTEGRATION_GATE_CONTRACT =
    "Catalog, eligibility, launch, wager reservation, signed provider callback, settlement, rollback, round reconciliation, degraded mode, and Android compatibility pass against certified contracts."

enum class CasinoGateDecision {
    GO,
    NO_GO
}

enum class CasinoScenarioId {
    T001_ELIGIBLE_PLAY_E2E,
    T002_RESTRICTIONS_DENIAL,
    T003_IDEMPOTENT_REORDERED_EVENTS,
    T004_TIMEOUT_SNAPSHOT_RECONCILIATION,
    T005_DEGRADED_PROVIDER_CONTROL,
    T006_AVIATOR_COMPATIBILITY_AGREEMENT
}

enum class CasinoScenarioStatus {
    PASS,
    FAIL,
    SKIPPED
}

// =============================================================================
// Domain Manifest & Records
// =============================================================================

data class ArtifactEvidenceManifest(
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

data class CasinoScenarioResult(
    val scenarioId: CasinoScenarioId,
    val status: CasinoScenarioStatus,
    val details: String,
    val evidenceReference: String,
    val executedAt: Instant,
    val failureReason: String? = null
)

data class EvaluateCasinoGateCommand(
    val principal: AuthenticatedPrincipal?,
    val tenantId: String,
    val manifest: ArtifactEvidenceManifest,
    val selectedScenarios: Set<CasinoScenarioId> = CasinoScenarioId.values().toSet(),
    val correlationId: String,
    val causationId: String
)

data class EvaluateSingleScenarioCommand(
    val principal: AuthenticatedPrincipal?,
    val tenantId: String,
    val scenarioId: CasinoScenarioId,
    val manifest: ArtifactEvidenceManifest,
    val correlationId: String,
    val causationId: String
)

data class CasinoGateReport(
    val reportId: UUID,
    val tenantId: String,
    val decision: CasinoGateDecision,
    val scenarioResults: Map<CasinoScenarioId, CasinoScenarioResult>,
    val manifest: ArtifactEvidenceManifest,
    val summary: String,
    val evaluatedAt: Instant,
    val evidenceReference: String,
    val auditEvent: AuditEvent,
    val hasFinancialAuthorityImpact: Boolean = false,
    val hasAndroidDbImpact: Boolean = false,
    val hasAndroidLifecycleClaim: Boolean = false,
    val semanticContract: String = CASINO_INTEGRATION_GATE_CONTRACT
)

// =============================================================================
// Evidence Store Interface & In-Memory Implementation
// =============================================================================

interface CasinoGateEvidenceStore {
    fun saveReport(report: CasinoGateReport): CasinoGateReport
    fun findLatestReport(tenantId: String): CasinoGateReport?
    fun findAllReports(tenantId: String): List<CasinoGateReport>
}

class InMemoryCasinoGateEvidenceStore : CasinoGateEvidenceStore {
    private val reports = ConcurrentHashMap<UUID, CasinoGateReport>()

    override fun saveReport(report: CasinoGateReport): CasinoGateReport {
        reports[report.reportId] = report
        return report
    }

    override fun findLatestReport(tenantId: String): CasinoGateReport? {
        return reports.values
            .filter { it.tenantId == tenantId }
            .maxByOrNull { it.evaluatedAt }
    }

    override fun findAllReports(tenantId: String): List<CasinoGateReport> {
        return reports.values
            .filter { it.tenantId == tenantId }
            .sortedByDescending { it.evaluatedAt }
    }
}

// =============================================================================
// Alert Sink & Observability
// =============================================================================

data class CasinoGateAlert(
    val alertId: UUID,
    val tenantId: String,
    val reportId: UUID?,
    val scenarioId: CasinoScenarioId?,
    val message: String,
    val occurredAt: Instant
)

interface CasinoGateAlertSink {
    fun emitAlert(alert: CasinoGateAlert)
    fun getAlerts(): List<CasinoGateAlert>
}

class InMemoryCasinoGateAlertSink : CasinoGateAlertSink {
    private val alerts = mutableListOf<CasinoGateAlert>()

    @Synchronized
    override fun emitAlert(alert: CasinoGateAlert) {
        alerts.add(alert)
    }

    @Synchronized
    override fun getAlerts(): List<CasinoGateAlert> = alerts.toList()
}

data class CasinoGateMetricEvent(
    val eventType: String,
    val tenantId: String,
    val scenarioId: CasinoScenarioId?,
    val outcome: String,
    val correlationId: String?,
    val causationId: String?,
    val timestamp: Instant,
    val details: Map<String, Any?> = emptyMap()
)

interface CasinoGateObservability {
    fun recordMetric(event: CasinoGateMetricEvent)
    fun getMetrics(): List<CasinoGateMetricEvent>
}

class InMemoryCasinoGateObservability : CasinoGateObservability {
    private val metrics = mutableListOf<CasinoGateMetricEvent>()

    @Synchronized
    override fun recordMetric(event: CasinoGateMetricEvent) {
        metrics.add(event)
    }

    @Synchronized
    override fun getMetrics(): List<CasinoGateMetricEvent> = metrics.toList()
}

// =============================================================================
// Exceptions
// =============================================================================

class UnauthorizedCasinoGateException(message: String) : RuntimeException(message)
class InvalidCasinoGateManifestException(message: String) : RuntimeException(message)
class CasinoGateExecutionException(message: String) : RuntimeException(message)
