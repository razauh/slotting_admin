package com.slotting.admin.validation.pack

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

const val TECHNICAL_LAUNCH_EVIDENCE_PACK_CONTRACT =
    "Technical pack cannot substitute legal/store/provider approvals; CI-004 computes decision."

enum class EvidenceItemType {
    GATE_FINANCIAL_001,
    GATE_PAYMENT_001,
    GATE_WITHDRAWAL_001,
    GATE_CASINO_001,
    GATE_COMPLIANCE_001,
    GATE_SECURITY_001,
    GATE_RESILIENCE_001,
    SYS_001_JOURNEY,
    SYS_002_PROVIDER,
    SYS_003_REHEARSAL,
    SYS_004_CHAOS,
    SYS_005_PENTEST,
    SYS_006_DEVICE,
    SYS_007_RELEASE_CI,
    SYS_008_ROLLOUT
}

enum class EvidenceItemStatus {
    PASSED,
    FAILED,
    STALE,
    PENDING
}

enum class ExternalApprovalType {
    LEGAL_COMPLIANCE,
    APP_STORE,
    PROVIDER_REGULATORY
}

enum class ExternalApprovalStatus {
    APPROVED,
    REJECTED,
    PENDING
}

enum class Ci004GateDecision {
    READY_FOR_FINAL_SIGN_OFF,
    BLOCKED
}

// =============================================================================
// Evidence Records
// =============================================================================

data class EvidenceItemRecord(
    val type: EvidenceItemType,
    val evidenceId: String,
    val status: EvidenceItemStatus,
    val artifactDigest: String,
    val evaluatedAt: Instant,
    val expiry: Instant,
    val summary: String
)

data class ExternalApprovalRecord(
    val approvalType: ExternalApprovalType,
    val approvalId: String,
    val authorityName: String,
    val status: ExternalApprovalStatus,
    val approvedAt: Instant,
    val expiry: Instant,
    val referenceDoc: String
)

data class EvidencePackArtifactManifest(
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

data class PackFinancialEvidence(
    val totalDebitsMinor: Long,
    val totalCreditsMinor: Long,
    val netImbalanceMinor: Long,
    val postedHistoryModified: Boolean,
    val reconciliationStatus: String
)

// =============================================================================
// Command & Report
// =============================================================================

data class RunEvidencePackCommand(
    val principal: AuthenticatedPrincipal?,
    val tenantId: String,
    val manifest: EvidencePackArtifactManifest,
    val technicalEvidenceItems: List<EvidenceItemRecord>,
    val externalApprovals: List<ExternalApprovalRecord>,
    val attemptExternalApprovalSubstitution: Boolean = false,
    val idempotencyKey: String,
    val correlationId: String,
    val causationId: String
)

data class TechnicalEvidencePackReport(
    val packId: UUID,
    val tenantId: String,
    val semanticContract: String = TECHNICAL_LAUNCH_EVIDENCE_PACK_CONTRACT,
    val decision: Ci004GateDecision,
    val manifest: EvidencePackArtifactManifest,
    val evaluatedItems: List<EvidenceItemRecord>,
    val externalApprovals: List<ExternalApprovalRecord>,
    val financialEvidence: PackFinancialEvidence,
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

open class TechnicalEvidencePackException(message: String) : RuntimeException(message)
class MissingStaleEvidencePackException(message: String) : TechnicalEvidencePackException(message)
class UnauthorizedEvidencePackException(message: String) : TechnicalEvidencePackException(message)
class InvalidEvidencePackManifestException(message: String) : TechnicalEvidencePackException(message)
class InvalidEvidencePackInputException(message: String) : TechnicalEvidencePackException(message)
class IdempotencyConflictException(message: String) : TechnicalEvidencePackException(message)

// =============================================================================
// Observability, Alerts & Evidence Store
// =============================================================================

data class EvidencePackAlert(
    val alertId: UUID,
    val tenantId: String,
    val packId: UUID?,
    val decision: Ci004GateDecision?,
    val message: String,
    val occurredAt: Instant
)

interface EvidencePackAlertSink {
    fun emitAlert(alert: EvidencePackAlert)
    fun getAlerts(): List<EvidencePackAlert>
}

class InMemoryEvidencePackAlertSink : EvidencePackAlertSink {
    private val alerts = mutableListOf<EvidencePackAlert>()
    @Synchronized override fun emitAlert(alert: EvidencePackAlert) { alerts.add(alert) }
    @Synchronized override fun getAlerts(): List<EvidencePackAlert> = alerts.toList()
}

interface EvidencePackObservability {
    fun recordEvaluation(tenantId: String, decision: Ci004GateDecision, durationMs: Long)
    fun getEvaluationsCount(): Long
}

class InMemoryEvidencePackObservability : EvidencePackObservability {
    private val evaluations = AtomicLong(0)

    override fun recordEvaluation(tenantId: String, decision: Ci004GateDecision, durationMs: Long) {
        evaluations.incrementAndGet()
    }
    override fun getEvaluationsCount(): Long = evaluations.get()
}

interface TechnicalEvidencePackStore {
    fun saveReport(report: TechnicalEvidencePackReport)
    fun getReport(packId: UUID): TechnicalEvidencePackReport?
    fun getAllReports(): List<TechnicalEvidencePackReport>
}

class InMemoryTechnicalEvidencePackStore : TechnicalEvidencePackStore {
    private val reports = ConcurrentHashMap<UUID, TechnicalEvidencePackReport>()
    override fun saveReport(report: TechnicalEvidencePackReport) {
        reports[report.packId] = report
    }
    override fun getReport(packId: UUID): TechnicalEvidencePackReport? = reports[packId]
    override fun getAllReports(): List<TechnicalEvidencePackReport> = reports.values.toList()
}
