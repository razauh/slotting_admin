package com.slotting.admin.validation.pack

import com.slotting.admin.auth.AuthenticatedPrincipal
import com.slotting.admin.recovery.RestoreDrillStatus
import java.time.Clock
import java.time.Instant
import java.util.UUID
import java.util.concurrent.ConcurrentHashMap

// =============================================================================
// External Prerequisites Governance Enums & Models
// =============================================================================

enum class ExternalPrerequisiteType {
    GAMING_LICENSE,
    PAYMENT_PROVIDER_APPROVAL,
    KYC_PROVIDER_APPROVAL,
    GAME_STUDIO_APPROVAL,
    RNG_CERTIFICATION,
    GAME_MATH_CERTIFICATION,
    SECURITY_ASSESSMENT,
    INFRASTRUCTURE_HA_ATTESTATION,
    OTHER_REGULATORY_APPROVAL
}

enum class ExternalPrerequisiteCategory {
    LEGAL_LICENSING,
    PAYMENT_APPROVAL,
    IDENTITY_KYC_APPROVAL,
    GAME_CERTIFICATION,
    SECURITY_ASSESSMENT,
    INFRASTRUCTURE_COMPLIANCE
}

enum class ExternalPrerequisiteStatus {
    UNRESOLVED,
    SUBMITTED,
    VERIFIED,
    EXPIRED,
    REJECTED,
    REVOKED,
    NOT_APPLICABLE
}

data class ExternalPrerequisiteItem(
    val prerequisiteId: UUID = UUID.randomUUID(),
    val prerequisiteType: ExternalPrerequisiteType,
    val category: ExternalPrerequisiteCategory,
    val name: String,
    val applicableEnvironment: String,
    val applicableProduct: String,
    val owner: String,
    val issuer: String,
    val referenceId: String,
    val status: ExternalPrerequisiteStatus = ExternalPrerequisiteStatus.UNRESOLVED,
    val submittedBy: String? = null,
    val submittedAt: Instant? = null,
    val verifiedBy: String? = null,
    val verifiedAt: Instant? = null,
    val expiresAt: Instant? = null,
    val evidenceReference: String? = null,
    val notes: String? = null,
    val createdAt: Instant = Instant.now(),
    val updatedAt: Instant = Instant.now()
)

data class PrerequisiteAuditRecord(
    val auditId: UUID = UUID.randomUUID(),
    val prerequisiteId: UUID,
    val action: String,
    val actorId: String,
    val previousStatus: ExternalPrerequisiteStatus?,
    val newStatus: ExternalPrerequisiteStatus,
    val timestamp: Instant,
    val details: String
)

class MakerCheckerViolationException(message: String) : RuntimeException(message)

interface ExternalPrerequisiteRegister {
    fun registerPrerequisite(item: ExternalPrerequisiteItem)
    fun getPrerequisite(id: UUID): ExternalPrerequisiteItem?
    fun getAllPrerequisites(): List<ExternalPrerequisiteItem>
    fun submitEvidence(
        prerequisiteId: UUID,
        evidenceReference: String,
        expiresAt: Instant?,
        notes: String?,
        principal: AuthenticatedPrincipal
    )
    fun verifyEvidence(
        prerequisiteId: UUID,
        verificationNotes: String?,
        principal: AuthenticatedPrincipal
    )
    fun rejectEvidence(
        prerequisiteId: UUID,
        rejectionReason: String,
        principal: AuthenticatedPrincipal
    )
    fun revokeEvidence(
        prerequisiteId: UUID,
        revokeReason: String,
        principal: AuthenticatedPrincipal
    )
    fun getAuditHistory(prerequisiteId: UUID): List<PrerequisiteAuditRecord>
}

class InMemoryExternalPrerequisiteRegister(
    private val clock: Clock = Clock.systemUTC()
) : ExternalPrerequisiteRegister {

    private val prerequisites = ConcurrentHashMap<UUID, ExternalPrerequisiteItem>()
    private val auditLog = ConcurrentHashMap<UUID, MutableList<PrerequisiteAuditRecord>>()

    override fun registerPrerequisite(item: ExternalPrerequisiteItem) {
        prerequisites[item.prerequisiteId] = item
        recordAudit(item.prerequisiteId, "REGISTER", item.owner, null, item.status, "Registered initial prerequisite")
    }

    override fun getPrerequisite(id: UUID): ExternalPrerequisiteItem? {
        val item = prerequisites[id] ?: return null
        return resolveCurrentStatus(item)
    }

    override fun getAllPrerequisites(): List<ExternalPrerequisiteItem> {
        return prerequisites.values.map { resolveCurrentStatus(it) }
    }

    private fun resolveCurrentStatus(item: ExternalPrerequisiteItem): ExternalPrerequisiteItem {
        val now = clock.instant()
        if (item.status == ExternalPrerequisiteStatus.VERIFIED && item.expiresAt != null && now.isAfter(item.expiresAt)) {
            return item.copy(status = ExternalPrerequisiteStatus.EXPIRED)
        }
        return item
    }

    override fun submitEvidence(
        prerequisiteId: UUID,
        evidenceReference: String,
        expiresAt: Instant?,
        notes: String?,
        principal: AuthenticatedPrincipal
    ) {
        val existing = prerequisites[prerequisiteId]
            ?: throw IllegalArgumentException("Prerequisite not found: $prerequisiteId")
        val now = clock.instant()
        val updated = existing.copy(
            status = ExternalPrerequisiteStatus.SUBMITTED,
            submittedBy = principal.id,
            submittedAt = now,
            evidenceReference = evidenceReference,
            expiresAt = expiresAt,
            notes = notes,
            updatedAt = now
        )
        prerequisites[prerequisiteId] = updated
        recordAudit(prerequisiteId, "SUBMIT_EVIDENCE", principal.id, existing.status, ExternalPrerequisiteStatus.SUBMITTED, notes ?: "")
    }

    override fun verifyEvidence(
        prerequisiteId: UUID,
        verificationNotes: String?,
        principal: AuthenticatedPrincipal
    ) {
        val existing = prerequisites[prerequisiteId]
            ?: throw IllegalArgumentException("Prerequisite not found: $prerequisiteId")

        // Maker-Checker enforcement: the submitter cannot verify their own submission
        if (existing.submittedBy == principal.id) {
            throw MakerCheckerViolationException("Maker-checker violation: Verifier (${principal.id}) cannot verify their own submission")
        }

        val now = clock.instant()
        val updated = existing.copy(
            status = ExternalPrerequisiteStatus.VERIFIED,
            verifiedBy = principal.id,
            verifiedAt = now,
            notes = verificationNotes ?: existing.notes,
            updatedAt = now
        )
        prerequisites[prerequisiteId] = updated
        recordAudit(prerequisiteId, "VERIFY_EVIDENCE", principal.id, existing.status, ExternalPrerequisiteStatus.VERIFIED, verificationNotes ?: "")
    }

    override fun rejectEvidence(
        prerequisiteId: UUID,
        rejectionReason: String,
        principal: AuthenticatedPrincipal
    ) {
        val existing = prerequisites[prerequisiteId]
            ?: throw IllegalArgumentException("Prerequisite not found: $prerequisiteId")
        val now = clock.instant()
        val updated = existing.copy(
            status = ExternalPrerequisiteStatus.REJECTED,
            notes = rejectionReason,
            updatedAt = now
        )
        prerequisites[prerequisiteId] = updated
        recordAudit(prerequisiteId, "REJECT_EVIDENCE", principal.id, existing.status, ExternalPrerequisiteStatus.REJECTED, rejectionReason)
    }

    override fun revokeEvidence(
        prerequisiteId: UUID,
        revokeReason: String,
        principal: AuthenticatedPrincipal
    ) {
        val existing = prerequisites[prerequisiteId]
            ?: throw IllegalArgumentException("Prerequisite not found: $prerequisiteId")
        val now = clock.instant()
        val updated = existing.copy(
            status = ExternalPrerequisiteStatus.REVOKED,
            notes = revokeReason,
            updatedAt = now
        )
        prerequisites[prerequisiteId] = updated
        recordAudit(prerequisiteId, "REVOKE_EVIDENCE", principal.id, existing.status, ExternalPrerequisiteStatus.REVOKED, revokeReason)
    }

    override fun getAuditHistory(prerequisiteId: UUID): List<PrerequisiteAuditRecord> {
        return auditLog[prerequisiteId]?.toList() ?: emptyList()
    }

    private fun recordAudit(
        prerequisiteId: UUID,
        action: String,
        actorId: String,
        prev: ExternalPrerequisiteStatus?,
        newStat: ExternalPrerequisiteStatus,
        details: String
    ) {
        val record = PrerequisiteAuditRecord(
            prerequisiteId = prerequisiteId,
            action = action,
            actorId = actorId,
            previousStatus = prev,
            newStatus = newStat,
            timestamp = clock.instant(),
            details = details
        )
        auditLog.computeIfAbsent(prerequisiteId) { mutableListOf() }.add(record)
    }
}

// =============================================================================
// Authoritative Subsystem Receipts & Candidate Descriptor
// =============================================================================

data class CandidateArtifactDescriptor(
    val backendCommitSha: String,
    val backendArtifactDigest: String,
    val androidConnectedAabSha256: String,
    val androidGitCommitSha: String,
    val androidSignerFingerprint: String,
    val androidVariant: String,
    val androidApplicationId: String
)

data class CurrencyBalanceSummary(
    val totalDebitsMinor: Long,
    val totalCreditsMinor: Long,
    val netImbalanceMinor: Long
)

data class LedgerReconciliationReceipt(
    val reconciledCurrencies: Map<String, CurrencyBalanceSummary>,
    val postedEntriesImmutable: Boolean,
    val hasAmbiguousPayouts: Boolean,
    val unconfirmedWagersCount: Int,
    val evaluatedAt: Instant
)

data class AuthoritativeRecoveryReceipt(
    val drillId: UUID,
    val issuerSubsystem: String,
    val targetEnvironment: String,
    val artifactDigestVerified: Boolean,
    val decryptionVerified: Boolean,
    val postgresStartupVerified: Boolean,
    val flywayMigrationVerified: Boolean,
    val ledgerReconciled: Boolean,
    val rpoBreached: Boolean,
    val rtoBreached: Boolean,
    val status: RestoreDrillStatus,
    val completedAt: Instant
)

enum class ProviderHealthState {
    CONFIGURED,
    READY,
    DEGRADED,
    INVALID,
    TIMEOUT,
    STALE_KYC_DETECTED
}

data class AuthoritativeProviderReadinessReceipt(
    val providerStatuses: Map<String, ProviderHealthState>,
    val evaluatedAt: Instant
)

data class AuthoritativeSecurityTelemetryReceipt(
    val siemDeliveryVerified: Boolean,
    val auditLogDispatchVerified: Boolean,
    val rateLimiterReady: Boolean,
    val tokenRevocationVerified: Boolean,
    val syntheticAcksDetected: Boolean,
    val evaluatedAt: Instant
)

data class AuthoritativeMobileEvidenceReceipt(
    val artifactSha256: String,
    val gitCommitSha: String,
    val buildVariant: String,
    val minSdkVerified: Int,
    val targetSdkVerified: Int,
    val securityScenariosVerified: Set<String>,
    val accessibilityScenariosVerified: Set<String>,
    val isVerified: Boolean,
    val evaluatedAt: Instant
)

data class AuthoritativeRestrictionSessionReceipt(
    val banBypassAttemptBlocked: Boolean,
    val selfExclusionBypassBlocked: Boolean,
    val staleSocketGenerationFenced: Boolean,
    val reconnectActiveGenerationAuthorized: Boolean,
    val evaluatedAt: Instant
)

data class FullStackTechnicalEvidencePack(
    val candidate: CandidateArtifactDescriptor,
    val ledgerReceipt: LedgerReconciliationReceipt,
    val recoveryReceipt: AuthoritativeRecoveryReceipt,
    val providerReadiness: AuthoritativeProviderReadinessReceipt,
    val securityTelemetry: AuthoritativeSecurityTelemetryReceipt,
    val mobileEvidence: AuthoritativeMobileEvidenceReceipt,
    val restrictionSession: AuthoritativeRestrictionSessionReceipt
)

// =============================================================================
// Gate Statuses & Decision Dimensions
// =============================================================================

enum class TechnicalReadinessStatus {
    TECHNICAL_READY,
    TECHNICAL_BLOCKED,
    TECHNICAL_INCOMPLETE
}

enum class ExternalPrerequisiteReadinessStatus {
    ALL_EXTERNAL_PREREQUISITES_VERIFIED,
    EXTERNAL_PREREQUISITES_PENDING,
    EXTERNAL_PREREQUISITES_EXPIRED,
    EXTERNAL_PREREQUISITES_REJECTED
}

enum class PilotGateDecision {
    TECHNICAL_BLOCKED,
    TECHNICAL_READY_EXTERNALS_PENDING,
    PILOT_PREREQUISITES_VERIFIED,
    PILOT_AUTHORIZED
}

data class PilotReadinessPolicy(
    val policyId: String = "policy-pilot-v1",
    val policyVersion: String = "1.0.0",
    val requiredExternalTypes: Set<ExternalPrerequisiteType> = setOf(
        ExternalPrerequisiteType.GAMING_LICENSE,
        ExternalPrerequisiteType.PAYMENT_PROVIDER_APPROVAL
    ),
    val requireSiemReady: Boolean = true,
    val requireMobileEvidence: Boolean = true,
    val maxRestoreAgeDays: Long = 7L
)

data class AuthoritativePilotReadinessReport(
    val reportId: UUID,
    val tenantId: String,
    val technicalReadiness: TechnicalReadinessStatus,
    val externalReadiness: ExternalPrerequisiteReadinessStatus,
    val decision: PilotGateDecision,
    val isLegallyApproved: Boolean = false,
    val summary: String,
    val blockerReasons: List<String>,
    val unresolvedExternalTypes: List<ExternalPrerequisiteType>,
    val expiredExternalTypes: List<ExternalPrerequisiteType>,
    val technicalPack: FullStackTechnicalEvidencePack,
    val policyVersion: String,
    val evaluatedAt: Instant,
    val correlationId: String
)

interface AuthoritativePilotEvidenceStore {
    fun saveReport(report: AuthoritativePilotReadinessReport)
    fun getReport(id: UUID): AuthoritativePilotReadinessReport?
    fun getAllReports(): List<AuthoritativePilotReadinessReport>
}

class InMemoryAuthoritativePilotEvidenceStore : AuthoritativePilotEvidenceStore {
    private val reports = ConcurrentHashMap<UUID, AuthoritativePilotReadinessReport>()
    override fun saveReport(report: AuthoritativePilotReadinessReport) {
        reports[report.reportId] = report
    }
    override fun getReport(id: UUID): AuthoritativePilotReadinessReport? = reports[id]
    override fun getAllReports(): List<AuthoritativePilotReadinessReport> = reports.values.toList()
}
