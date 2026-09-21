package com.slotting.admin.gate.compliance

import com.slotting.admin.auth.AuditEvent
import com.slotting.admin.auth.AuthenticatedPrincipal
import java.time.Instant
import java.util.UUID
import java.util.concurrent.ConcurrentHashMap

// =============================================================================
// Semantic Contract & Enums
// =============================================================================

const val COMPLIANCE_INTEGRATION_GATE_CONTRACT =
    "KYC, AML, geolocation, responsible-gaming, account state, and game/payment eligibility compose into one versioned server decision that fails closed on stale, ambiguous, or unavailable evidence."

enum class ComplianceGateDecision {
    GO,
    NO_GO
}

enum class ComplianceScenarioId {
    T001_ELIGIBLE_PLAYER_E2E,
    T002_RESTRICTIONS_DENIAL,
    T003_STALE_SPOOFED_UNAVAILABLE_EVIDENCE,
    T004_IMMEDIATE_CROSS_PRODUCT_STOP,
    T005_DELAYED_LIMITS_CONTROLLED_REOPENING,
    T006_AUDIT_RETENTION_REDACTION
}

enum class ComplianceScenarioStatus {
    PASS,
    FAIL,
    SKIPPED
}

// =============================================================================
// Domain Manifest & Records
// =============================================================================

data class ComplianceArtifactManifest(
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

data class ComplianceScenarioResult(
    val scenarioId: ComplianceScenarioId,
    val status: ComplianceScenarioStatus,
    val details: String,
    val evidenceReference: String,
    val executedAt: Instant,
    val failureReason: String? = null
)

data class EvaluateComplianceGateCommand(
    val principal: AuthenticatedPrincipal?,
    val tenantId: String,
    val manifest: ComplianceArtifactManifest,
    val selectedScenarios: Set<ComplianceScenarioId> = ComplianceScenarioId.values().toSet(),
    val correlationId: String,
    val causationId: String
)

data class ComplianceGateReport(
    val reportId: UUID,
    val tenantId: String,
    val decision: ComplianceGateDecision,
    val scenarioResults: Map<ComplianceScenarioId, ComplianceScenarioResult>,
    val manifest: ComplianceArtifactManifest,
    val summary: String,
    val evaluatedAt: Instant,
    val evidenceReference: String,
    val auditEvent: AuditEvent,
    val hasFinancialAuthorityImpact: Boolean = false,
    val hasAndroidDbImpact: Boolean = false,
    val hasAndroidLifecycleClaim: Boolean = false,
    val semanticContract: String = COMPLIANCE_INTEGRATION_GATE_CONTRACT
)

// =============================================================================
// Evidence Store Interface & In-Memory Implementation
// =============================================================================

interface ComplianceGateEvidenceStore {
    fun saveReport(report: ComplianceGateReport): ComplianceGateReport
    fun findLatestReport(tenantId: String): ComplianceGateReport?
    fun findAllReports(tenantId: String): List<ComplianceGateReport>
}

class InMemoryComplianceGateEvidenceStore : ComplianceGateEvidenceStore {
    private val reports = ConcurrentHashMap<UUID, ComplianceGateReport>()

    override fun saveReport(report: ComplianceGateReport): ComplianceGateReport {
        reports[report.reportId] = report
        return report
    }

    override fun findLatestReport(tenantId: String): ComplianceGateReport? {
        return reports.values
            .filter { it.tenantId == tenantId }
            .maxByOrNull { it.evaluatedAt }
    }

    override fun findAllReports(tenantId: String): List<ComplianceGateReport> {
        return reports.values
            .filter { it.tenantId == tenantId }
            .sortedByDescending { it.evaluatedAt }
    }
}

// =============================================================================
// Alert Sink & Observability
// =============================================================================

data class ComplianceGateAlert(
    val alertId: UUID,
    val tenantId: String,
    val reportId: UUID?,
    val scenarioId: ComplianceScenarioId?,
    val message: String,
    val occurredAt: Instant
)

interface ComplianceGateAlertSink {
    fun emitAlert(alert: ComplianceGateAlert)
    fun getAlerts(): List<ComplianceGateAlert>
}

class InMemoryComplianceGateAlertSink : ComplianceGateAlertSink {
    private val alerts = mutableListOf<ComplianceGateAlert>()

    @Synchronized
    override fun emitAlert(alert: ComplianceGateAlert) {
        alerts.add(alert)
    }

    @Synchronized
    override fun getAlerts(): List<ComplianceGateAlert> = alerts.toList()
}

data class ComplianceGateMetricEvent(
    val eventType: String,
    val tenantId: String,
    val scenarioId: ComplianceScenarioId?,
    val outcome: String,
    val correlationId: String?,
    val causationId: String?,
    val timestamp: Instant,
    val details: Map<String, Any?> = emptyMap()
)

interface ComplianceGateObservability {
    fun recordMetric(event: ComplianceGateMetricEvent)
    fun getMetrics(): List<ComplianceGateMetricEvent>
}

class InMemoryComplianceGateObservability : ComplianceGateObservability {
    private val metrics = mutableListOf<ComplianceGateMetricEvent>()

    @Synchronized
    override fun recordMetric(event: ComplianceGateMetricEvent) {
        metrics.add(event)
    }

    @Synchronized
    override fun getMetrics(): List<ComplianceGateMetricEvent> = metrics.toList()
}

// =============================================================================
// Exceptions
// =============================================================================

class UnauthorizedComplianceGateException(message: String) : RuntimeException(message)
class InvalidComplianceGateManifestException(message: String) : RuntimeException(message)
class ComplianceGateExecutionException(message: String) : RuntimeException(message)
