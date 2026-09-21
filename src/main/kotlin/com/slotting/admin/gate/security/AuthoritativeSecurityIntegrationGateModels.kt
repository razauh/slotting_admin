package com.slotting.admin.gate.security

import com.slotting.admin.auth.AuditEvent
import com.slotting.admin.auth.AuthenticatedPrincipal
import java.time.Instant
import java.util.UUID
import java.util.concurrent.ConcurrentHashMap

// =============================================================================
// Semantic Contract & Enums
// =============================================================================

const val SECURITY_INTEGRATION_GATE_CONTRACT =
    "All ten TEST-SEC assertions pass for one candidate with zero authorization bypass, replay mutation, secret or PII leak, unsafe rotation, or unalerted privileged failure."

enum class SecurityGateDecision {
    GO,
    NO_GO
}

enum class SecurityScenarioId {
    T001_TOKEN_EXPIRY_MALFORMED_CONCURRENT_REFRESH,
    T002_REFRESH_TOKEN_LOGOUT_REUSE_REVOCATION,
    T003_ACCOUNT_STATE_RESTRICTION_DENIAL,
    T004_IDOR_ROLE_BYPASS_MAKER_CHECKER_COLLISION,
    T005_CALLBACK_SPOOF_REPLAY_NO_MUTATION,
    T006_MANIPULATED_CLIENT_INPUT_GRANTS_NOTHING,
    T007_HTTPS_APP_LINKS_PKCE_NONCE_REPLAY,
    T008_CLIENT_HARDENING_POLICY_ENFORCEMENT,
    T009_SECRETS_PII_LEAK_PREVENTION,
    T010_ROTATION_INFRA_FAILURES_SAFE_ALERT
}

enum class SecurityScenarioStatus {
    PASS,
    FAIL,
    SKIPPED
}

// =============================================================================
// Artifact Evidence Manifest
// =============================================================================

data class SecurityArtifactManifest(
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

data class SecurityScenarioResult(
    val scenarioId: SecurityScenarioId,
    val status: SecurityScenarioStatus,
    val details: String,
    val evidenceReference: String,
    val executedAt: Instant,
    val failureReason: String? = null
)

data class EvaluateSecurityGateCommand(
    val principal: AuthenticatedPrincipal?,
    val tenantId: String,
    val manifest: SecurityArtifactManifest,
    val selectedScenarios: Set<SecurityScenarioId> = SecurityScenarioId.values().toSet(),
    val correlationId: String,
    val causationId: String
)

data class EvaluateSingleSecurityScenarioCommand(
    val principal: AuthenticatedPrincipal?,
    val tenantId: String,
    val scenarioId: SecurityScenarioId,
    val manifest: SecurityArtifactManifest,
    val correlationId: String,
    val causationId: String
)

data class SecurityGateReport(
    val reportId: UUID,
    val tenantId: String,
    val decision: SecurityGateDecision,
    val scenarioResults: Map<SecurityScenarioId, SecurityScenarioResult>,
    val manifest: SecurityArtifactManifest,
    val summary: String,
    val evaluatedAt: Instant,
    val evidenceReference: String,
    val auditEvent: AuditEvent,
    val hasFinancialAuthorityImpact: Boolean = false,
    val hasAndroidDbImpact: Boolean = false,
    val hasAndroidLifecycleClaim: Boolean = false,
    val semanticContract: String = SECURITY_INTEGRATION_GATE_CONTRACT
)

// =============================================================================
// Evidence Store Interface & In-Memory Implementation
// =============================================================================

interface SecurityGateEvidenceStore {
    fun saveReport(report: SecurityGateReport): SecurityGateReport
    fun findLatestReport(tenantId: String): SecurityGateReport?
    fun findAllReports(tenantId: String): List<SecurityGateReport>
}

class InMemorySecurityGateEvidenceStore : SecurityGateEvidenceStore {
    private val reports = ConcurrentHashMap<UUID, SecurityGateReport>()

    override fun saveReport(report: SecurityGateReport): SecurityGateReport {
        reports[report.reportId] = report
        return report
    }

    override fun findLatestReport(tenantId: String): SecurityGateReport? {
        return reports.values
            .filter { it.tenantId == tenantId }
            .maxByOrNull { it.evaluatedAt }
    }

    override fun findAllReports(tenantId: String): List<SecurityGateReport> {
        return reports.values
            .filter { it.tenantId == tenantId }
            .sortedByDescending { it.evaluatedAt }
    }
}

// =============================================================================
// Alert Sink & Observability
// =============================================================================

data class SecurityGateAlert(
    val alertId: UUID,
    val tenantId: String,
    val reportId: UUID?,
    val scenarioId: SecurityScenarioId?,
    val message: String,
    val occurredAt: Instant
)

interface SecurityGateAlertSink {
    fun emitAlert(alert: SecurityGateAlert)
    fun getAlerts(): List<SecurityGateAlert>
}

class InMemorySecurityGateAlertSink : SecurityGateAlertSink {
    private val alerts = mutableListOf<SecurityGateAlert>()

    @Synchronized
    override fun emitAlert(alert: SecurityGateAlert) {
        alerts.add(alert)
    }

    @Synchronized
    override fun getAlerts(): List<SecurityGateAlert> = alerts.toList()
}

data class SecurityGateMetricEvent(
    val eventType: String,
    val tenantId: String,
    val scenarioId: SecurityScenarioId?,
    val outcome: String,
    val correlationId: String?,
    val causationId: String?,
    val timestamp: Instant,
    val details: Map<String, Any?> = emptyMap()
)

interface SecurityGateObservability {
    fun recordMetric(event: SecurityGateMetricEvent)
    fun getMetrics(): List<SecurityGateMetricEvent>
}

class InMemorySecurityGateObservability : SecurityGateObservability {
    private val metrics = mutableListOf<SecurityGateMetricEvent>()

    @Synchronized
    override fun recordMetric(event: SecurityGateMetricEvent) {
        metrics.add(event)
    }

    @Synchronized
    override fun getMetrics(): List<SecurityGateMetricEvent> = metrics.toList()
}

// =============================================================================
// Exceptions
// =============================================================================

class InvalidSecurityGateManifestException(message: String) : RuntimeException(message)
class UnauthorizedSecurityGateException(message: String) : RuntimeException(message)
class SecurityGateExecutionException(message: String) : RuntimeException(message)
class SecurityInvariantViolationException(message: String) : RuntimeException(message)
