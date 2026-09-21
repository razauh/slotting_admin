package com.slotting.admin.validation.device

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

const val PHYSICAL_DEVICE_MATRIX_CONTRACT =
    "TalkBack/switch/font/foldable/rotation/battery/startup/network/socket and process death."

enum class MatrixDimension {
    TALKBACK,
    SWITCH_ACCESS,
    FONT_SCALING,
    FOLDABLE_POSTURE,
    CONFIGURATION_ROTATION,
    BATTERY_OPTIMIZATION,
    COLD_HOT_STARTUP,
    NETWORK_ADAPTABILITY,
    SOCKET_RESILIENCE,
    PROCESS_DEATH
}

enum class DeviceTier {
    TIER_1_FLAGSHIP,
    TIER_2_MIDRANGE,
    TIER_3_BUDGET,
    FOLDABLE_LARGE_SCREEN
}

enum class MatrixDimensionStatus {
    PASSED_CERTIFIED,
    FAILED_MATRIX_DEFECT
}

enum class DeviceMatrixStatus {
    CERTIFIED_PASSED,
    FAILED_MATRIX_DEFECTS
}

// =============================================================================
// Dimension Result Models
// =============================================================================

data class MatrixDimensionResult(
    val dimension: MatrixDimension,
    val status: MatrixDimensionStatus,
    val testedTiers: Set<DeviceTier>,
    val testsExecuted: Int,
    val passedTests: Int,
    val failedTests: Int,
    val metrics: Map<String, String>,
    val details: String
)

// =============================================================================
// Artifact Evidence Manifest
// =============================================================================

data class DeviceArtifactManifest(
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

data class RunDeviceMatrixValidationCommand(
    val principal: AuthenticatedPrincipal?,
    val tenantId: String,
    val dimensions: Set<MatrixDimension> = MatrixDimension.values().toSet(),
    val targetTiers: Set<DeviceTier> = DeviceTier.values().toSet(),
    val manifest: DeviceArtifactManifest,
    val idempotencyKey: String,
    val correlationId: String,
    val causationId: String,
    val injectedFailures: Set<MatrixDimension> = emptySet()
)

data class DeviceMatrixReport(
    val reportId: UUID,
    val tenantId: String,
    val semanticContract: String = PHYSICAL_DEVICE_MATRIX_CONTRACT,
    val status: DeviceMatrixStatus,
    val manifest: DeviceArtifactManifest,
    val dimensionResults: Map<MatrixDimension, MatrixDimensionResult>,
    val totalTestsExecuted: Int,
    val totalPassedTests: Int,
    val totalFailedTests: Int,
    val isMatrixCertified: Boolean,
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

open class DeviceMatrixValidationException(message: String) : RuntimeException(message)
class UnauthorizedDeviceMatrixException(message: String) : DeviceMatrixValidationException(message)
class InvalidDeviceManifestException(message: String) : DeviceMatrixValidationException(message)
class InvalidDeviceMatrixInputException(message: String) : DeviceMatrixValidationException(message)
class IdempotencyConflictException(message: String) : DeviceMatrixValidationException(message)
class MatrixValidationBreachedException(message: String) : DeviceMatrixValidationException(message)

// =============================================================================
// Observability, Alerts & Evidence Store
// =============================================================================

data class DeviceMatrixAlert(
    val alertId: UUID,
    val tenantId: String,
    val reportId: UUID?,
    val dimension: MatrixDimension?,
    val message: String,
    val occurredAt: Instant
)

interface DeviceMatrixAlertSink {
    fun emitAlert(alert: DeviceMatrixAlert)
    fun getAlerts(): List<DeviceMatrixAlert>
}

class InMemoryDeviceMatrixAlertSink : DeviceMatrixAlertSink {
    private val alerts = mutableListOf<DeviceMatrixAlert>()
    @Synchronized override fun emitAlert(alert: DeviceMatrixAlert) { alerts.add(alert) }
    @Synchronized override fun getAlerts(): List<DeviceMatrixAlert> = alerts.toList()
}

interface DeviceMatrixObservability {
    fun recordEvaluation(tenantId: String, status: DeviceMatrixStatus, durationMs: Long)
    fun recordDimensionEvaluated(tenantId: String, dimension: MatrixDimension)
    fun getEvaluationsCount(): Long
    fun getDimensionsEvaluatedCount(): Long
}

class InMemoryDeviceMatrixObservability : DeviceMatrixObservability {
    private val evaluations = AtomicLong(0)
    private val dimensionsEvaluated = AtomicLong(0)

    override fun recordEvaluation(tenantId: String, status: DeviceMatrixStatus, durationMs: Long) {
        evaluations.incrementAndGet()
    }
    override fun recordDimensionEvaluated(tenantId: String, dimension: MatrixDimension) {
        dimensionsEvaluated.incrementAndGet()
    }
    override fun getEvaluationsCount(): Long = evaluations.get()
    override fun getDimensionsEvaluatedCount(): Long = dimensionsEvaluated.get()
}

interface DeviceMatrixEvidenceStore {
    fun saveReport(report: DeviceMatrixReport)
    fun getReport(reportId: UUID): DeviceMatrixReport?
    fun getAllReports(): List<DeviceMatrixReport>
}

class InMemoryDeviceMatrixEvidenceStore : DeviceMatrixEvidenceStore {
    private val reports = ConcurrentHashMap<UUID, DeviceMatrixReport>()
    override fun saveReport(report: DeviceMatrixReport) {
        reports[report.reportId] = report
    }
    override fun getReport(reportId: UUID): DeviceMatrixReport? = reports[reportId]
    override fun getAllReports(): List<DeviceMatrixReport> = reports.values.toList()
}
