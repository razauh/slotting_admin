package com.slotting.admin.validation.chaos

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

const val LOAD_SOAK_CHAOS_FAILOVER_CONTRACT =
    "Includes hot wallet, callback burst, socket soak, DB failover, Redis loss, worker restart."

enum class ChaosScenarioType {
    HOT_WALLET,
    CALLBACK_BURST,
    SOCKET_SOAK,
    DB_FAILOVER,
    REDIS_LOSS,
    WORKER_RESTART
}

enum class ChaosScenarioStatus {
    PASSED,
    FAILED_THRESHOLD_BREACH,
    FAILED_DEPENDENCY,
    FAILED_INTEGRITY
}

enum class ChaosExecutionStatus {
    COMPLETED_HEALTHY,
    FAILED_BREACH,
    DEGRADED
}

enum class ChaosFaultType {
    LATENCY_SPIKE,
    LEDGER_CORRUPTION,
    FAILOVER_TIMEOUT,
    WORKER_HANG,
    SOCKET_DROP_CASCADE,
    REDIS_FALLBACK_FAILURE
}

// =============================================================================
// Thresholds & Scenario Results
// =============================================================================

data class ChaosThresholdConfig(
    val maxAllowedLatencyMs: Long = 200L,
    val maxAllowedErrorRatePercent: Double = 0.01,
    val maxFailoverRecoveryTimeMs: Long = 5_000L,
    val maxWorkerRestartRecoveryMs: Long = 2_000L,
    val minSocketStabilityPercent: Double = 99.9,
    val maxAllowedLedgerImbalanceMinor: Long = 0L
)

data class ChaosScenarioResult(
    val scenarioType: ChaosScenarioType,
    val status: ChaosScenarioStatus,
    val totalOperations: Long,
    val successfulOperations: Long,
    val failedOperations: Long,
    val p99LatencyMs: Long,
    val recoveryTimeMs: Long? = null,
    val deduplicationRatePercent: Double? = null,
    val socketStabilityPercent: Double? = null,
    val fallbackSuccessRatePercent: Double? = null,
    val duplicateExecutions: Long = 0,
    val ledgerDebitsMinor: Long = 0,
    val ledgerCreditsMinor: Long = 0,
    val ledgerImbalanceMinor: Long = 0,
    val details: String
)

// =============================================================================
// Artifact Evidence Manifest
// =============================================================================

data class ChaosArtifactManifest(
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

data class RunChaosValidationCommand(
    val principal: AuthenticatedPrincipal?,
    val tenantId: String,
    val scenarios: Set<ChaosScenarioType> = ChaosScenarioType.values().toSet(),
    val thresholdConfig: ChaosThresholdConfig = ChaosThresholdConfig(),
    val manifest: ChaosArtifactManifest,
    val idempotencyKey: String,
    val correlationId: String,
    val causationId: String,
    val injectedFaults: Set<ChaosFaultType> = emptySet()
)

data class ChaosValidationReport(
    val executionId: UUID,
    val tenantId: String,
    val semanticContract: String = LOAD_SOAK_CHAOS_FAILOVER_CONTRACT,
    val status: ChaosExecutionStatus,
    val manifest: ChaosArtifactManifest,
    val scenarioResults: Map<ChaosScenarioType, ChaosScenarioResult>,
    val totalLedgerDebitsMinor: Long,
    val totalLedgerCreditsMinor: Long,
    val netLedgerImbalanceMinor: Long,
    val isZeroLedgerImbalance: Boolean,
    val hasAndroidLifecycleClaim: Boolean = false,
    val hasAndroidDbImpact: Boolean = false,
    val correlationId: String,
    val causationId: String,
    val evidenceReference: String,
    val executedAt: Instant,
    val failureReason: String? = null
)

// =============================================================================
// Domain Exceptions
// =============================================================================

open class ChaosValidationException(message: String) : RuntimeException(message)
class UnauthorizedChaosException(message: String) : ChaosValidationException(message)
class InvalidChaosManifestException(message: String) : ChaosValidationException(message)
class InvalidChaosInputException(message: String) : ChaosValidationException(message)
class IdempotencyConflictException(message: String) : ChaosValidationException(message)
class ChaosThresholdBreachedException(message: String) : ChaosValidationException(message)

// =============================================================================
// Observability, Alerts & Evidence Store
// =============================================================================

data class ChaosAlert(
    val alertId: UUID,
    val tenantId: String,
    val executionId: UUID?,
    val scenario: ChaosScenarioType?,
    val message: String,
    val occurredAt: Instant
)

interface ChaosAlertSink {
    fun emitAlert(alert: ChaosAlert)
    fun getAlerts(): List<ChaosAlert>
}

class InMemoryChaosAlertSink : ChaosAlertSink {
    private val alerts = mutableListOf<ChaosAlert>()
    @Synchronized override fun emitAlert(alert: ChaosAlert) { alerts.add(alert) }
    @Synchronized override fun getAlerts(): List<ChaosAlert> = alerts.toList()
}

interface ChaosObservability {
    fun recordExecution(tenantId: String, status: ChaosExecutionStatus, durationMs: Long)
    fun recordScenarioCompleted(tenantId: String, scenario: ChaosScenarioType)
    fun getExecutionsCount(): Long
    fun getScenariosCompletedCount(): Long
}

class InMemoryChaosObservability : ChaosObservability {
    private val executions = AtomicLong(0)
    private val scenariosCompleted = AtomicLong(0)

    override fun recordExecution(tenantId: String, status: ChaosExecutionStatus, durationMs: Long) {
        executions.incrementAndGet()
    }
    override fun recordScenarioCompleted(tenantId: String, scenario: ChaosScenarioType) {
        scenariosCompleted.incrementAndGet()
    }
    override fun getExecutionsCount(): Long = executions.get()
    override fun getScenariosCompletedCount(): Long = scenariosCompleted.get()
}

interface ChaosEvidenceStore {
    fun saveReport(report: ChaosValidationReport)
    fun getReport(executionId: UUID): ChaosValidationReport?
    fun getAllReports(): List<ChaosValidationReport>
}

class InMemoryChaosEvidenceStore : ChaosEvidenceStore {
    private val reports = ConcurrentHashMap<UUID, ChaosValidationReport>()
    override fun saveReport(report: ChaosValidationReport) {
        reports[report.executionId] = report
    }
    override fun getReport(executionId: UUID): ChaosValidationReport? = reports[executionId]
    override fun getAllReports(): List<ChaosValidationReport> = reports.values.toList()
}
