package com.slotting.admin.validation.provider

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

const val PROVIDER_CERTIFICATION_RECONCILIATION_CONTRACT =
    "Duplicate/late/out-of-order/timeout/refund/rollback/chargeback evidence included."

enum class ProviderCertificationCase {
    DUPLICATE,
    LATE,
    OUT_OF_ORDER,
    TIMEOUT,
    REFUND,
    ROLLBACK,
    CHARGEBACK
}

enum class CaseVerificationStatus {
    PASSED,
    FAILED,
    SKIPPED
}

// =============================================================================
// Case Evidence & Results
// =============================================================================

data class ProviderCaseEvidence(
    val caseType: ProviderCertificationCase,
    val status: CaseVerificationStatus,
    val providerReference: String,
    val eventId: String,
    val debitsEqualCredits: Boolean,
    val doubleEffectPrevented: Boolean,
    val immutableCompensationVerified: Boolean,
    val details: String,
    val evidenceDigest: String,
    val timestamp: Instant
)

data class ProviderCaseResult(
    val caseType: ProviderCertificationCase,
    val status: CaseVerificationStatus,
    val evidence: ProviderCaseEvidence,
    val notes: String
)

// =============================================================================
// Artifact Evidence Manifest
// =============================================================================

data class ProviderCertificationArtifactManifest(
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
// Commands & Certification Report
// =============================================================================

data class RunProviderCertificationCommand(
    val principal: AuthenticatedPrincipal?,
    val tenantId: String,
    val providerId: String,
    val manifest: ProviderCertificationArtifactManifest,
    val targetCases: Set<ProviderCertificationCase> = ProviderCertificationCase.values().toSet(),
    val idempotencyKey: String,
    val correlationId: String,
    val causationId: String
)

data class ProviderCertificationReport(
    val reportId: UUID,
    val tenantId: String,
    val providerId: String,
    val manifest: ProviderCertificationArtifactManifest,
    val caseResults: Map<ProviderCertificationCase, ProviderCaseResult>,
    val isFullyCertified: Boolean,
    val evidenceIncluded: Set<ProviderCertificationCase>,
    val debitsEqualCreditsPreserved: Boolean,
    val hasAndroidLifecycleClaim: Boolean = false,
    val hasAndroidDbImpact: Boolean = false,
    val summary: String,
    val correlationId: String,
    val causationId: String,
    val evidenceReference: String,
    val executedAt: Instant,
    val failureReason: String? = null
)

// =============================================================================
// Domain Exceptions
// =============================================================================

open class ProviderCertificationException(message: String) : RuntimeException(message)
class UnauthorizedProviderCertificationException(message: String) : ProviderCertificationException(message)
class InvalidProviderCertificationManifestException(message: String) : ProviderCertificationException(message)
class InvalidProviderCertificationInputException(message: String) : ProviderCertificationException(message)
class ProviderCertificationFailedException(message: String) : ProviderCertificationException(message)
class IdempotencyConflictException(message: String) : ProviderCertificationException(message)
class ProviderCertificationExecutionException(message: String) : ProviderCertificationException(message)

// =============================================================================
// Observability, Alerts & Evidence Store
// =============================================================================

data class ProviderCertificationAlert(
    val alertId: UUID,
    val tenantId: String,
    val reportId: UUID?,
    val caseType: ProviderCertificationCase?,
    val message: String,
    val occurredAt: Instant
)

interface ProviderCertificationAlertSink {
    fun emitAlert(alert: ProviderCertificationAlert)
    fun getAlerts(): List<ProviderCertificationAlert>
}

class InMemoryProviderCertificationAlertSink : ProviderCertificationAlertSink {
    private val alerts = mutableListOf<ProviderCertificationAlert>()
    @Synchronized override fun emitAlert(alert: ProviderCertificationAlert) { alerts.add(alert) }
    @Synchronized override fun getAlerts(): List<ProviderCertificationAlert> = alerts.toList()
}

interface ProviderCertificationObservability {
    fun recordExecution(tenantId: String, certified: Boolean, durationMs: Long)
    fun recordCaseVerified(tenantId: String, caseType: ProviderCertificationCase)
    fun getExecutionsCount(): Long
    fun getCasesVerifiedCount(): Long
}

class InMemoryProviderCertificationObservability : ProviderCertificationObservability {
    private val executions = AtomicLong(0)
    private val casesVerified = AtomicLong(0)

    override fun recordExecution(tenantId: String, certified: Boolean, durationMs: Long) {
        executions.incrementAndGet()
    }
    override fun recordCaseVerified(tenantId: String, caseType: ProviderCertificationCase) {
        casesVerified.incrementAndGet()
    }
    override fun getExecutionsCount(): Long = executions.get()
    override fun getCasesVerifiedCount(): Long = casesVerified.get()
}

interface ProviderCertificationEvidenceStore {
    fun saveReport(report: ProviderCertificationReport)
    fun getReport(reportId: UUID): ProviderCertificationReport?
    fun getAllReports(): List<ProviderCertificationReport>
}

class InMemoryProviderCertificationEvidenceStore : ProviderCertificationEvidenceStore {
    private val reports = ConcurrentHashMap<UUID, ProviderCertificationReport>()
    override fun saveReport(report: ProviderCertificationReport) {
        reports[report.reportId] = report
    }
    override fun getReport(reportId: UUID): ProviderCertificationReport? = reports[reportId]
    override fun getAllReports(): List<ProviderCertificationReport> = reports.values.toList()
}
