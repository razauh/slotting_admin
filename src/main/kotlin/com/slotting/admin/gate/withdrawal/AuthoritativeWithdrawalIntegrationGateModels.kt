package com.slotting.admin.gate.withdrawal

import com.slotting.admin.auth.AuditEvent
import com.slotting.admin.auth.AuthenticatedPrincipal
import java.time.Instant
import java.util.UUID
import java.util.concurrent.ConcurrentHashMap

// =============================================================================
// Semantic Contract & Enums
// =============================================================================

const val WITHDRAWAL_INTEGRATION_GATE_CONTRACT =
    "A withdrawal passes quote, ownership, step-up, reservation, AML hold, maker-checker, idempotent payout, authenticated callback, ambiguity handling, and ledger reconciliation without premature release."

enum class WithdrawalGateDecision {
    GO,
    NO_GO
}

enum class WithdrawalScenarioId {
    T001_ELIGIBLE_OWNER_APPROVED_PAYOUT_BALANCED_POSTING,
    T002_EXPIRED_QUOTE_UNOWNED_DEST_FAILED_STEPUP_DENIED,
    T003_CONCURRENT_REQUESTS_NO_OVER_RESERVE_DUPLICATE_PAYOUT,
    T004_TIMEOUT_UNKNOWN_STAYS_PENDING_UNTIL_RECONCILIATION,
    T005_FAILURE_RELEASES_OR_COMPENSATES_EXACTLY_ONCE,
    T006_PROVIDER_STATE_LEDGER_STATEMENT_ADMIN_RECONCILE
}

enum class WithdrawalScenarioStatus {
    PASS,
    FAIL,
    SKIPPED
}

// =============================================================================
// Artifact Evidence Manifest
// =============================================================================

data class WithdrawalArtifactManifest(
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

data class WithdrawalScenarioResult(
    val scenarioId: WithdrawalScenarioId,
    val status: WithdrawalScenarioStatus,
    val details: String,
    val evidenceReference: String,
    val executedAt: Instant,
    val failureReason: String? = null
)

data class EvaluateWithdrawalGateCommand(
    val principal: AuthenticatedPrincipal?,
    val tenantId: String,
    val manifest: WithdrawalArtifactManifest,
    val selectedScenarios: Set<WithdrawalScenarioId> = WithdrawalScenarioId.values().toSet(),
    val correlationId: String,
    val causationId: String
)

data class EvaluateSingleWithdrawalScenarioCommand(
    val principal: AuthenticatedPrincipal?,
    val tenantId: String,
    val scenarioId: WithdrawalScenarioId,
    val manifest: WithdrawalArtifactManifest,
    val correlationId: String,
    val causationId: String
)

data class WithdrawalGateReport(
    val reportId: UUID,
    val tenantId: String,
    val decision: WithdrawalGateDecision,
    val scenarioResults: Map<WithdrawalScenarioId, WithdrawalScenarioResult>,
    val manifest: WithdrawalArtifactManifest,
    val summary: String,
    val evaluatedAt: Instant,
    val evidenceReference: String,
    val auditEvent: AuditEvent,
    val financialConservationEnforced: Boolean = true,
    val hasAndroidDbImpact: Boolean = false,
    val hasAndroidLifecycleClaim: Boolean = false,
    val semanticContract: String = WITHDRAWAL_INTEGRATION_GATE_CONTRACT
)

// =============================================================================
// Evidence Store Interface & In-Memory Implementation
// =============================================================================

interface WithdrawalGateEvidenceStore {
    fun saveReport(report: WithdrawalGateReport): WithdrawalGateReport
    fun findLatestReport(tenantId: String): WithdrawalGateReport?
    fun findAllReports(tenantId: String): List<WithdrawalGateReport>
}

class InMemoryWithdrawalGateEvidenceStore : WithdrawalGateEvidenceStore {
    private val reports = ConcurrentHashMap<UUID, WithdrawalGateReport>()

    override fun saveReport(report: WithdrawalGateReport): WithdrawalGateReport {
        reports[report.reportId] = report
        return report
    }

    override fun findLatestReport(tenantId: String): WithdrawalGateReport? {
        return reports.values
            .filter { it.tenantId == tenantId }
            .maxByOrNull { it.evaluatedAt }
    }

    override fun findAllReports(tenantId: String): List<WithdrawalGateReport> {
        return reports.values
            .filter { it.tenantId == tenantId }
            .sortedByDescending { it.evaluatedAt }
    }
}

// =============================================================================
// Alert Sink & Observability
// =============================================================================

data class WithdrawalGateAlert(
    val alertId: UUID,
    val tenantId: String,
    val reportId: UUID?,
    val scenarioId: WithdrawalScenarioId?,
    val message: String,
    val occurredAt: Instant
)

interface WithdrawalGateAlertSink {
    fun emitAlert(alert: WithdrawalGateAlert)
    fun getAlerts(): List<WithdrawalGateAlert>
}

class InMemoryWithdrawalGateAlertSink : WithdrawalGateAlertSink {
    private val alerts = mutableListOf<WithdrawalGateAlert>()

    @Synchronized
    override fun emitAlert(alert: WithdrawalGateAlert) {
        alerts.add(alert)
    }

    @Synchronized
    override fun getAlerts(): List<WithdrawalGateAlert> = alerts.toList()
}

data class WithdrawalGateMetricEvent(
    val eventType: String,
    val tenantId: String,
    val scenarioId: WithdrawalScenarioId?,
    val outcome: String,
    val correlationId: String?,
    val causationId: String?,
    val timestamp: Instant,
    val details: Map<String, Any?> = emptyMap()
)

interface WithdrawalGateObservability {
    fun recordMetric(event: WithdrawalGateMetricEvent)
    fun getMetrics(): List<WithdrawalGateMetricEvent>
}

class InMemoryWithdrawalGateObservability : WithdrawalGateObservability {
    private val metrics = mutableListOf<WithdrawalGateMetricEvent>()

    @Synchronized
    override fun recordMetric(event: WithdrawalGateMetricEvent) {
        metrics.add(event)
    }

    @Synchronized
    override fun getMetrics(): List<WithdrawalGateMetricEvent> = metrics.toList()
}

// =============================================================================
// Exceptions
// =============================================================================

class InvalidWithdrawalGateManifestException(message: String) : RuntimeException(message)
class UnauthorizedWithdrawalGateException(message: String) : RuntimeException(message)
class WithdrawalGateExecutionException(message: String) : RuntimeException(message)
class WithdrawalInvariantViolationException(message: String) : RuntimeException(message)
