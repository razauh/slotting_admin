package com.slotting.admin.validation.journey

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

const val CRITICAL_JOURNEY_E2E_CONTRACT =
    "Assert ledger/provider/admin/Android views reconcile at every step."

enum class JourneyStep {
    INITIATED,
    DEPOSIT_INITIATED,
    DEPOSIT_CREDITED,
    WAGER_RESERVED,
    GAME_SETTLED,
    WITHDRAWAL_REQUESTED,
    WITHDRAWAL_APPROVED,
    PAYOUT_COMPLETED,
    COMPENSATED
}

enum class JourneyStatus {
    PENDING,
    IN_PROGRESS,
    COMPLETED,
    FAILED,
    COMPENSATED
}

// =============================================================================
// Reconciled Views at Each Step
// =============================================================================

data class LedgerView(
    val balanceMinor: Long,
    val availableMinor: Long,
    val reservedMinor: Long,
    val lockedMinor: Long,
    val postedDebitsMinor: Long,
    val postedCreditsMinor: Long,
    val isBalanced: Boolean,
    val currency: String
)

data class ProviderView(
    val depositProviderStatus: String,
    val depositReference: String?,
    val gameProviderStatus: String,
    val gameRoundReference: String?,
    val payoutProviderStatus: String,
    val payoutReference: String?,
    val isReconciled: Boolean
)

data class AdminView(
    val journeyStatus: JourneyStatus,
    val makerCheckerApproved: Boolean,
    val makerPrincipalId: String?,
    val checkerPrincipalId: String?,
    val amlRiskClear: Boolean,
    val kycVerified: Boolean,
    val auditEventsCount: Int,
    val reconciliationState: String
)

data class AndroidView(
    val presentedAvailableBalanceMinor: Long,
    val presentedLockedBalanceMinor: Long,
    val displayStatus: String,
    val isUntrustedPresentation: Boolean = true,
    val requiresServerRequery: Boolean = false,
    val hasAndroidLifecycleClaim: Boolean = false,
    val hasAndroidDbImpact: Boolean = false
)

data class StepReconciliationRecord(
    val step: JourneyStep,
    val stepSequence: Int,
    val ledgerView: LedgerView,
    val providerView: ProviderView,
    val adminView: AdminView,
    val androidView: AndroidView,
    val isReconciled: Boolean,
    val reconciliationNotes: String,
    val timestamp: Instant
)

// =============================================================================
// Launch Validation Artifact Manifest
// =============================================================================

data class LaunchValidationArtifactManifest(
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
// Journey Execution Command & Report
// =============================================================================

data class ExecuteCriticalJourneyCommand(
    val principal: AuthenticatedPrincipal?,
    val tenantId: String,
    val playerId: String,
    val currency: String,
    val depositAmountMinor: Long,
    val wagerAmountMinor: Long,
    val gameWinMultiplier: Double,
    val withdrawalAmountMinor: Long,
    val manifest: LaunchValidationArtifactManifest,
    val idempotencyKey: String,
    val correlationId: String,
    val causationId: String,
    val approverPrincipal: AuthenticatedPrincipal? = null
)

data class CriticalJourneyReport(
    val journeyId: UUID,
    val tenantId: String,
    val playerId: String,
    val currency: String,
    val status: JourneyStatus,
    val manifest: LaunchValidationArtifactManifest,
    val stepRecords: List<StepReconciliationRecord>,
    val isFullyReconciled: Boolean,
    val initialBalanceMinor: Long,
    val depositAmountMinor: Long,
    val wagerAmountMinor: Long,
    val gameWinMultiplier: Double,
    val settledWinningsMinor: Long,
    val withdrawalAmountMinor: Long,
    val finalBalanceMinor: Long,
    val correlationId: String,
    val causationId: String,
    val evidenceReference: String,
    val executedAt: Instant,
    val failureReason: String? = null
)

// =============================================================================
// Domain Exceptions
// =============================================================================

open class CriticalJourneyException(message: String) : RuntimeException(message)
class UnauthorizedJourneyException(message: String) : CriticalJourneyException(message)
class InvalidJourneyManifestException(message: String) : CriticalJourneyException(message)
class InvalidJourneyInputException(message: String) : CriticalJourneyException(message)
class InsufficientFundsJourneyException(message: String) : CriticalJourneyException(message)
class MakerCheckerViolationException(message: String) : CriticalJourneyException(message)
class IdempotencyConflictException(message: String) : CriticalJourneyException(message)
class ViewReconciliationMismatchException(message: String) : CriticalJourneyException(message)
class JourneyExecutionException(message: String) : CriticalJourneyException(message)

// =============================================================================
// Observability, Alerts & Evidence Store
// =============================================================================

data class CriticalJourneyAlert(
    val alertId: UUID,
    val tenantId: String,
    val journeyId: UUID?,
    val step: JourneyStep?,
    val message: String,
    val occurredAt: Instant
)

interface CriticalJourneyAlertSink {
    fun emitAlert(alert: CriticalJourneyAlert)
    fun getAlerts(): List<CriticalJourneyAlert>
}

class InMemoryCriticalJourneyAlertSink : CriticalJourneyAlertSink {
    private val alerts = mutableListOf<CriticalJourneyAlert>()
    @Synchronized override fun emitAlert(alert: CriticalJourneyAlert) { alerts.add(alert) }
    @Synchronized override fun getAlerts(): List<CriticalJourneyAlert> = alerts.toList()
}

interface CriticalJourneyObservability {
    fun recordExecution(tenantId: String, status: JourneyStatus, durationMs: Long)
    fun recordStepReconciled(tenantId: String, step: JourneyStep)
    fun getExecutionsCount(): Long
    fun getReconciliationsCount(): Long
}

class InMemoryCriticalJourneyObservability : CriticalJourneyObservability {
    private val executions = AtomicLong(0)
    private val reconciliations = AtomicLong(0)

    override fun recordExecution(tenantId: String, status: JourneyStatus, durationMs: Long) {
        executions.incrementAndGet()
    }
    override fun recordStepReconciled(tenantId: String, step: JourneyStep) {
        reconciliations.incrementAndGet()
    }
    override fun getExecutionsCount(): Long = executions.get()
    override fun getReconciliationsCount(): Long = reconciliations.get()
}

interface CriticalJourneyEvidenceStore {
    fun saveReport(report: CriticalJourneyReport)
    fun getReport(journeyId: UUID): CriticalJourneyReport?
    fun getAllReports(): List<CriticalJourneyReport>
}

class InMemoryCriticalJourneyEvidenceStore : CriticalJourneyEvidenceStore {
    private val reports = ConcurrentHashMap<UUID, CriticalJourneyReport>()
    override fun saveReport(report: CriticalJourneyReport) {
        reports[report.journeyId] = report
    }
    override fun getReport(journeyId: UUID): CriticalJourneyReport? = reports[journeyId]
    override fun getAllReports(): List<CriticalJourneyReport> = reports.values.toList()
}
