package com.slotting.admin.validation.rehearsal

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

const val RESTORE_REPLAY_MIGRATION_REHEARSAL_CONTRACT =
    "Zero ledger imbalance; approved RPO/RTO; forward-fix/rollback decision recorded."

enum class RehearsalType {
    RESTORE,
    REPLAY,
    MIGRATION,
    FULL_COMBINED
}

enum class RehearsalDecisionType {
    FORWARD_FIX,
    ROLLBACK
}

enum class RehearsalPhase {
    PRE_CHECK,
    RESTORE_EXECUTION,
    REPLAY_EXECUTION,
    MIGRATION_EXECUTION,
    POST_VERIFICATION,
    DECISION_RECORDED,
    COMPLETED
}

enum class RehearsalStatus {
    IN_PROGRESS,
    PASSED,
    FAILED
}

// =============================================================================
// Metrics, Evidence & Decision Records
// =============================================================================

data class RehearsalRpoRtoMetrics(
    val targetRpoMs: Long,
    val actualRpoMs: Long,
    val isRpoApproved: Boolean,
    val targetRtoMs: Long,
    val actualRtoMs: Long,
    val isRtoApproved: Boolean
)

data class RehearsalIntegrityEvidence(
    val preExecutionRecordCount: Long,
    val postExecutionRecordCount: Long,
    val preExecutionChecksum: String,
    val postExecutionChecksum: String,
    val checksumMatches: Boolean,
    val eventLineageGapsDetected: Int,
    val ledgerTotalDebitsMinor: Long,
    val ledgerTotalCreditsMinor: Long,
    val ledgerImbalanceMinor: Long,
    val isZeroLedgerImbalance: Boolean
)

data class RehearsalDecisionRecord(
    val decisionType: RehearsalDecisionType,
    val decidedBy: String,
    val justification: String,
    val rollbackPreservesPostedHistory: Boolean,
    val recordedAt: Instant
)

// =============================================================================
// Artifact Evidence Manifest
// =============================================================================

data class RehearsalArtifactManifest(
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

data class RunRehearsalCommand(
    val principal: AuthenticatedPrincipal?,
    val tenantId: String,
    val rehearsalType: RehearsalType = RehearsalType.FULL_COMBINED,
    val manifest: RehearsalArtifactManifest,
    val maxAllowedRpoMs: Long = 60_000L,
    val maxAllowedRtoMs: Long = 900_000L,
    val decisionType: RehearsalDecisionType = RehearsalDecisionType.FORWARD_FIX,
    val decisionJustification: String = "Automated rehearsed forward-fix validated with zero imbalance",
    val idempotencyKey: String,
    val correlationId: String,
    val causationId: String
)

data class RehearsalReport(
    val rehearsalId: UUID,
    val tenantId: String,
    val rehearsalType: RehearsalType,
    val manifest: RehearsalArtifactManifest,
    val status: RehearsalStatus,
    val rpoRtoMetrics: RehearsalRpoRtoMetrics,
    val integrityEvidence: RehearsalIntegrityEvidence,
    val decisionRecord: RehearsalDecisionRecord,
    val isContractSatisfied: Boolean,
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

open class RehearsalException(message: String) : RuntimeException(message)
class UnauthorizedRehearsalException(message: String) : RehearsalException(message)
class InvalidRehearsalManifestException(message: String) : RehearsalException(message)
class InvalidRehearsalInputException(message: String) : RehearsalException(message)
class RehearsalValidationException(message: String) : RehearsalException(message)
class IdempotencyConflictException(message: String) : RehearsalException(message)
class RehearsalExecutionException(message: String) : RehearsalException(message)

// =============================================================================
// Observability, Alerts & Evidence Store
// =============================================================================

data class RehearsalAlert(
    val alertId: UUID,
    val tenantId: String,
    val rehearsalId: UUID?,
    val phase: RehearsalPhase?,
    val message: String,
    val occurredAt: Instant
)

interface RehearsalAlertSink {
    fun emitAlert(alert: RehearsalAlert)
    fun getAlerts(): List<RehearsalAlert>
}

class InMemoryRehearsalAlertSink : RehearsalAlertSink {
    private val alerts = mutableListOf<RehearsalAlert>()
    @Synchronized override fun emitAlert(alert: RehearsalAlert) { alerts.add(alert) }
    @Synchronized override fun getAlerts(): List<RehearsalAlert> = alerts.toList()
}

interface RehearsalObservability {
    fun recordExecution(tenantId: String, status: RehearsalStatus, durationMs: Long)
    fun recordPhaseCompleted(tenantId: String, phase: RehearsalPhase)
    fun getExecutionsCount(): Long
    fun getPhasesCompletedCount(): Long
}

class InMemoryRehearsalObservability : RehearsalObservability {
    private val executions = AtomicLong(0)
    private val phasesCompleted = AtomicLong(0)

    override fun recordExecution(tenantId: String, status: RehearsalStatus, durationMs: Long) {
        executions.incrementAndGet()
    }
    override fun recordPhaseCompleted(tenantId: String, phase: RehearsalPhase) {
        phasesCompleted.incrementAndGet()
    }
    override fun getExecutionsCount(): Long = executions.get()
    override fun getPhasesCompletedCount(): Long = phasesCompleted.get()
}

interface RehearsalEvidenceStore {
    fun saveReport(report: RehearsalReport)
    fun getReport(rehearsalId: UUID): RehearsalReport?
    fun getAllReports(): List<RehearsalReport>
}

class InMemoryRehearsalEvidenceStore : RehearsalEvidenceStore {
    private val reports = ConcurrentHashMap<UUID, RehearsalReport>()
    override fun saveReport(report: RehearsalReport) {
        reports[report.rehearsalId] = report
    }
    override fun getReport(rehearsalId: UUID): RehearsalReport? = reports[rehearsalId]
    override fun getAllReports(): List<RehearsalReport> = reports.values.toList()
}
