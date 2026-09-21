package com.slotting.admin.validation.rollout

import com.slotting.admin.auth.AdminRole
import com.slotting.admin.auth.AuthenticatedPrincipal
import com.slotting.admin.auth.PrincipalKind
import java.time.Instant
import java.util.UUID
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.atomic.AtomicLong

// =============================================================================
// Semantic Contract & Enums
// =============================================================================

const val STAGING_ROLLOUT_ROLLBACK_CONTRACT =
    "Automatic/manual stop criteria objective; rollback preserves financial processing/reconciliation."

enum class RolloutCohortStage {
    CANARY_5_PERCENT,
    STAGE_25_PERCENT,
    STAGE_50_PERCENT,
    GENERAL_AVAILABILITY_100
}

enum class StopCriteriaType {
    ERROR_RATE_SPIKE,
    LATENCY_P99_SPIKE,
    LEDGER_IMBALANCE,
    MANUAL_INCIDENT_COMMANDER,
    SMOKE_TEST_FAILURE,
    PAGE_DRILL_UNACKNOWLEDGED
}

enum class RolloutState {
    STAGING_SMOKE_PASSED,
    COHORT_IN_PROGRESS,
    PROMOTED_TO_GA,
    ROLLBACK_TRIGGERED,
    ROLLBACK_COMPLETED_RECONCILED
}

// =============================================================================
// Evidence Models: Smoke, Stop Criteria, On-Call Drill, Financial Reconciliation
// =============================================================================

data class SmokeTestResult(
    val smokeId: String,
    val suitesExecuted: List<String>,
    val isPassed: Boolean,
    val latencyP99Ms: Long,
    val errorCount: Int
)

data class StopCriteriaEvaluation(
    val evaluatedAt: Instant,
    val errorRatePercent: Double,
    val latencyP99Ms: Long,
    val ledgerImbalanceMinor: Long,
    val isStopTriggered: Boolean,
    val triggeredCriteria: List<StopCriteriaType>
)

data class OnCallPageDrillRecord(
    val drillId: String,
    val pagerService: String,
    val primaryResponder: String,
    val secondaryResponder: String,
    val pagedAt: Instant,
    val acknowledgedAt: Instant,
    val responseSlaSeconds: Long,
    val isSlaMet: Boolean,
    val runbookRef: String
)

data class RollbackFinancialEvidence(
    val totalPreRollbackDebitsMinor: Long,
    val totalPreRollbackCreditsMinor: Long,
    val totalPostRollbackDebitsMinor: Long,
    val totalPostRollbackCreditsMinor: Long,
    val netImbalanceMinor: Long,
    val postedHistoryModified: Boolean,
    val reconciliationStatus: String
)

// =============================================================================
// Artifact Evidence Manifest
// =============================================================================

data class RolloutArtifactManifest(
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
// Command & Report
// =============================================================================

data class RunRolloutValidationCommand(
    val principal: AuthenticatedPrincipal?,
    val tenantId: String,
    val manifest: RolloutArtifactManifest,
    val targetCohort: RolloutCohortStage = RolloutCohortStage.GENERAL_AVAILABILITY_100,
    val smokeTest: SmokeTestResult,
    val onCallDrill: OnCallPageDrillRecord,
    val triggerRollbackScenario: Boolean = false,
    val injectedFaults: Set<StopCriteriaType> = emptySet(),
    val idempotencyKey: String,
    val correlationId: String,
    val causationId: String
)

data class RolloutValidationReport(
    val rolloutId: UUID,
    val tenantId: String,
    val semanticContract: String = STAGING_ROLLOUT_ROLLBACK_CONTRACT,
    val currentState: RolloutState,
    val manifest: RolloutArtifactManifest,
    val smokeTest: SmokeTestResult,
    val onCallDrill: OnCallPageDrillRecord,
    val stopCriteria: StopCriteriaEvaluation,
    val financialEvidence: RollbackFinancialEvidence,
    val isContractSatisfied: Boolean,
    val hasAndroidLifecycleClaim: Boolean = false,
    val hasAndroidDbImpact: Boolean = false,
    val correlationId: String,
    val causationId: String,
    val evidenceReference: String,
    val evaluatedAt: Instant,
    val failureReason: String? = null
)

// =============================================================================
// Domain Exceptions
// =============================================================================

open class StagingRolloutValidationException(message: String) : RuntimeException(message)
class UnauthorizedRolloutException(message: String) : StagingRolloutValidationException(message)
class InvalidRolloutManifestException(message: String) : StagingRolloutValidationException(message)
class InvalidRolloutInputException(message: String) : StagingRolloutValidationException(message)
class IdempotencyConflictException(message: String) : StagingRolloutValidationException(message)
class StopCriteriaBreachedException(message: String) : StagingRolloutValidationException(message)

// =============================================================================
// Observability, Alerts & Evidence Store
// =============================================================================

data class RolloutAlert(
    val alertId: UUID,
    val tenantId: String,
    val rolloutId: UUID?,
    val state: RolloutState?,
    val message: String,
    val occurredAt: Instant
)

interface RolloutAlertSink {
    fun emitAlert(alert: RolloutAlert)
    fun getAlerts(): List<RolloutAlert>
}

class InMemoryRolloutAlertSink : RolloutAlertSink {
    private val alerts = mutableListOf<RolloutAlert>()
    @Synchronized override fun emitAlert(alert: RolloutAlert) { alerts.add(alert) }
    @Synchronized override fun getAlerts(): List<RolloutAlert> = alerts.toList()
}

interface RolloutObservability {
    fun recordEvaluation(tenantId: String, state: RolloutState, durationMs: Long)
    fun recordStageTransition(tenantId: String, stage: RolloutCohortStage)
    fun getEvaluationsCount(): Long
    fun getTransitionsCount(): Long
}

class InMemoryRolloutObservability : RolloutObservability {
    private val evaluations = AtomicLong(0)
    private val transitions = AtomicLong(0)

    override fun recordEvaluation(tenantId: String, state: RolloutState, durationMs: Long) {
        evaluations.incrementAndGet()
    }
    override fun recordStageTransition(tenantId: String, stage: RolloutCohortStage) {
        transitions.incrementAndGet()
    }
    override fun getEvaluationsCount(): Long = evaluations.get()
    override fun getTransitionsCount(): Long = transitions.get()
}

interface RolloutEvidenceStore {
    fun saveReport(report: RolloutValidationReport)
    fun getReport(rolloutId: UUID): RolloutValidationReport?
    fun getAllReports(): List<RolloutValidationReport>
}

class InMemoryRolloutEvidenceStore : RolloutEvidenceStore {
    private val reports = ConcurrentHashMap<UUID, RolloutValidationReport>()
    override fun saveReport(report: RolloutValidationReport) {
        reports[report.rolloutId] = report
    }
    override fun getReport(rolloutId: UUID): RolloutValidationReport? = reports[rolloutId]
    override fun getAllReports(): List<RolloutValidationReport> = reports.values.toList()
}
