package com.slotting.admin.validation.release

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

const val CONNECTED_RELEASE_CI_ARTIFACT_CONTRACT =
    "P0/P1 suites unskippable; signer/KMS audit; reproducible artifact comparison."

enum class ReleaseTestSuite {
    GATE_FINANCIAL,
    GATE_PAYMENT,
    GATE_WITHDRAWAL,
    GATE_CASINO,
    GATE_COMPLIANCE,
    GATE_SECURITY,
    GATE_RESILIENCE,
    SYS_CRITICAL_JOURNEY,
    SYS_PROVIDER_CERTIFICATION,
    SYS_RESTORE_REHEARSAL,
    SYS_LOAD_CHAOS_FAILOVER,
    SYS_PENTEST_VERIFICATION,
    SYS_DEVICE_MATRIX
}

enum class SuiteExecutionStatus {
    PASSED,
    FAILED,
    SKIPPED
}

enum class ReleasePipelineStatus {
    CERTIFIED_APPROVED,
    BLOCKED_REJECTED
}

// =============================================================================
// Evidence Models: Suites, KMS Signer, Reproducibility
// =============================================================================

data class SuiteExecutionRecord(
    val suite: ReleaseTestSuite,
    val priority: String, // "P0", "P1"
    val status: SuiteExecutionStatus,
    val testCount: Int,
    val executedAt: Instant,
    val evidenceDigest: String
)

data class KmsSignerAuditRecord(
    val kmsKeyArn: String,
    val signingAlgorithm: String,
    val custodianSignatures: List<String>,
    val cloudTrailAuditId: String,
    val isHsmBacked: Boolean,
    val signedAt: Instant
) {
    fun isValid(): Boolean {
        return kmsKeyArn.isNotBlank() &&
                signingAlgorithm.isNotBlank() &&
                custodianSignatures.size >= 2 &&
                cloudTrailAuditId.isNotBlank() &&
                isHsmBacked
    }
}

data class ReproducibleArtifactRecord(
    val artifactName: String,
    val candidateDigest: String,
    val referenceDigest: String,
    val isReproducible: Boolean,
    val sbomFormat: String,
    val sbomDigest: String,
    val criticalVulnerabilitiesCount: Int,
    val slsaLevel: Int
) {
    fun isValid(): Boolean {
        return artifactName.isNotBlank() &&
                candidateDigest.isNotBlank() &&
                referenceDigest.isNotBlank() &&
                candidateDigest == referenceDigest &&
                isReproducible &&
                sbomFormat.isNotBlank() &&
                sbomDigest.isNotBlank() &&
                criticalVulnerabilitiesCount == 0 &&
                slsaLevel >= 3
    }
}

// =============================================================================
// Artifact Evidence Manifest
// =============================================================================

data class ReleaseArtifactManifest(
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

data class RunReleasePipelineCommand(
    val principal: AuthenticatedPrincipal?,
    val tenantId: String,
    val manifest: ReleaseArtifactManifest,
    val suiteRecords: Map<ReleaseTestSuite, SuiteExecutionRecord>,
    val kmsSignerRecord: KmsSignerAuditRecord,
    val reproducibleRecord: ReproducibleArtifactRecord,
    val idempotencyKey: String,
    val correlationId: String,
    val causationId: String
)

data class ReleasePipelineReport(
    val releaseId: UUID,
    val tenantId: String,
    val semanticContract: String = CONNECTED_RELEASE_CI_ARTIFACT_CONTRACT,
    val status: ReleasePipelineStatus,
    val manifest: ReleaseArtifactManifest,
    val suiteExecutions: Map<ReleaseTestSuite, SuiteExecutionRecord>,
    val kmsAudit: KmsSignerAuditRecord,
    val reproducibility: ReproducibleArtifactRecord,
    val isAllMandatorySuitesPassed: Boolean,
    val isKmsAuditValid: Boolean,
    val isArtifactReproducible: Boolean,
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

open class ReleasePipelineValidationException(message: String) : RuntimeException(message)
class UnauthorizedReleasePipelineException(message: String) : ReleasePipelineValidationException(message)
class InvalidReleaseManifestException(message: String) : ReleasePipelineValidationException(message)
class InvalidReleasePipelineInputException(message: String) : ReleasePipelineValidationException(message)
class IdempotencyConflictException(message: String) : ReleasePipelineValidationException(message)
class ReleasePipelineMissingEvidenceException(message: String) : ReleasePipelineValidationException(message)

// =============================================================================
// Observability, Alerts & Evidence Store
// =============================================================================

data class ReleasePipelineAlert(
    val alertId: UUID,
    val tenantId: String,
    val releaseId: UUID?,
    val suite: ReleaseTestSuite?,
    val message: String,
    val occurredAt: Instant
)

interface ReleasePipelineAlertSink {
    fun emitAlert(alert: ReleasePipelineAlert)
    fun getAlerts(): List<ReleasePipelineAlert>
}

class InMemoryReleasePipelineAlertSink : ReleasePipelineAlertSink {
    private val alerts = mutableListOf<ReleasePipelineAlert>()
    @Synchronized override fun emitAlert(alert: ReleasePipelineAlert) { alerts.add(alert) }
    @Synchronized override fun getAlerts(): List<ReleasePipelineAlert> = alerts.toList()
}

interface ReleasePipelineObservability {
    fun recordEvaluation(tenantId: String, status: ReleasePipelineStatus, durationMs: Long)
    fun recordSuiteVerified(tenantId: String, suite: ReleaseTestSuite)
    fun getEvaluationsCount(): Long
    fun getSuitesVerifiedCount(): Long
}

class InMemoryReleasePipelineObservability : ReleasePipelineObservability {
    private val evaluations = AtomicLong(0)
    private val suitesVerified = AtomicLong(0)

    override fun recordEvaluation(tenantId: String, status: ReleasePipelineStatus, durationMs: Long) {
        evaluations.incrementAndGet()
    }
    override fun recordSuiteVerified(tenantId: String, suite: ReleaseTestSuite) {
        suitesVerified.incrementAndGet()
    }
    override fun getEvaluationsCount(): Long = evaluations.get()
    override fun getSuitesVerifiedCount(): Long = suitesVerified.get()
}

interface ReleasePipelineEvidenceStore {
    fun saveReport(report: ReleasePipelineReport)
    fun getReport(releaseId: UUID): ReleasePipelineReport?
    fun getAllReports(): List<ReleasePipelineReport>
}

class InMemoryReleasePipelineEvidenceStore : ReleasePipelineEvidenceStore {
    private val reports = ConcurrentHashMap<UUID, ReleasePipelineReport>()
    override fun saveReport(report: ReleasePipelineReport) {
        reports[report.releaseId] = report
    }
    override fun getReport(releaseId: UUID): ReleasePipelineReport? = reports[releaseId]
    override fun getAllReports(): List<ReleasePipelineReport> = reports.values.toList()
}
