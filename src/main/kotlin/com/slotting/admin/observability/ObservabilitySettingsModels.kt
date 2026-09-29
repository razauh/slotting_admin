package com.slotting.admin.observability

import com.slotting.admin.secret.EncryptedSecretPayload
import java.time.Instant
import java.util.UUID
import java.util.concurrent.ConcurrentHashMap

enum class SiemProviderType {
    OPENSEARCH,
    SPLUNK,
    ELASTICSEARCH,
    DATADOG,
    GENERIC_HTTPS,
}

enum class SiemAuthType {
    API_TOKEN,
    BASIC_AUTH,
    BEARER_TOKEN,
    NONE,
}

enum class PagingProviderType {
    GOALERT,
    ALERTMANAGER,
    PAGERDUTY,
    GENERIC_WEBHOOK,
}

enum class MetricsProviderType {
    OTEL_COLLECTOR,
    PROMETHEUS_REMOTE_WRITE,
    DATADOG,
    GENERIC_OTLP,
}

enum class TracingProviderType {
    TEMPO,
    OTEL_COLLECTOR,
    JAEGER,
    GENERIC_OTLP,
}

enum class ObservabilityReadinessState {
    NOT_CONFIGURED,
    CONFIGURED,
    VALIDATING,
    READY,
    DEGRADED,
    INVALID,
    DISABLED,
}

enum class IncidentSeverity {
    INFO,
    WARNING,
    HIGH,
    CRITICAL,
}

enum class OperationalIncidentType {
    LEDGER_IMBALANCE,
    AMBIGUOUS_PAYOUT,
    STUCK_OUTBOX,
    STUCK_WORKER,
    AUTH_ATTACK,
    PIN_FAILURE,
    MFA_FAILURE,
    SOCKET_PROTOCOL_FAILURE,
    PROVIDER_OUTAGE,
    PROVIDER_TIMEOUT,
    EXPORTER_OUTAGE,
    DLQ_GROWTH,
    MONITORING_PIPELINE_FAILURE,
}

enum class SiemDispatchStatus {
    PENDING_FORWARD,
    DISPATCHING,
    ACCEPTED,
    FAILED_RETRYABLE,
    FAILED_PERMANENT,
    DEAD_LETTER,
}

enum class PagingDispatchStatus {
    DISPATCHING,
    ACCEPTED,
    FAILED_RETRYABLE,
    FAILED_PERMANENT,
    DEAD_LETTER,
}

enum class HumanIncidentStatus {
    TRIGGERED,
    ACKNOWLEDGED_BY_HUMAN,
    RESOLVED,
}

data class SecretStatusInfo(
    val configured: Boolean,
    val keyVersion: Int? = null,
    val lastRotatedAt: Instant? = null,
)

// Internal persisted configs
data class SiemConfigRecord(
    val tenantId: String,
    val providerType: SiemProviderType,
    val enabled: Boolean = true,
    val endpointUrl: String? = null,
    val authType: SiemAuthType = SiemAuthType.API_TOKEN,
    val username: String? = null,
    val indexOrDataStream: String? = "security-events",
    val encryptedAuthSecret: EncryptedSecretPayload? = null,
    val timeoutMs: Long = 5000L,
    val retryLimit: Int = 3,
    val verifyTls: Boolean = true,
    val readiness: ObservabilityReadinessState = ObservabilityReadinessState.NOT_CONFIGURED,
    val configVersion: Long = 1L,
    val updatedAt: Instant,
)

data class PagingConfigRecord(
    val tenantId: String,
    val providerType: PagingProviderType,
    val enabled: Boolean = true,
    val endpointUrl: String? = null,
    val serviceKeyOrId: String? = null,
    val encryptedRoutingSecret: EncryptedSecretPayload? = null,
    val timeoutMs: Long = 5000L,
    val retryLimit: Int = 3,
    val verifyTls: Boolean = true,
    val readiness: ObservabilityReadinessState = ObservabilityReadinessState.NOT_CONFIGURED,
    val configVersion: Long = 1L,
    val updatedAt: Instant,
)

data class MetricsConfigRecord(
    val tenantId: String,
    val providerType: MetricsProviderType,
    val enabled: Boolean = true,
    val endpointUrl: String? = null,
    val encryptedAuthSecret: EncryptedSecretPayload? = null,
    val pushIntervalSeconds: Int = 15,
    val verifyTls: Boolean = true,
    val readiness: ObservabilityReadinessState = ObservabilityReadinessState.NOT_CONFIGURED,
    val configVersion: Long = 1L,
    val updatedAt: Instant,
)

data class TracingConfigRecord(
    val tenantId: String,
    val providerType: TracingProviderType,
    val enabled: Boolean = true,
    val endpointUrl: String? = null,
    val encryptedAuthSecret: EncryptedSecretPayload? = null,
    val samplingRatio: Double = 1.0,
    val verifyTls: Boolean = true,
    val readiness: ObservabilityReadinessState = ObservabilityReadinessState.NOT_CONFIGURED,
    val configVersion: Long = 1L,
    val updatedAt: Instant,
)

data class AlertRoutingRule(
    val incidentType: OperationalIncidentType,
    val severity: IncidentSeverity,
    val ownerTeam: String,
    val targetServiceOrTier: String,
    val runbookUrl: String,
    val requiresPaging: Boolean = true,
)

data class AlertRoutingPolicyConfig(
    val tenantId: String,
    val rules: Map<OperationalIncidentType, AlertRoutingRule> = defaultRoutingRules(),
    val configVersion: Long = 1L,
    val updatedAt: Instant,
) {
    companion object {
        fun defaultRoutingRules(): Map<OperationalIncidentType, AlertRoutingRule> = mapOf(
            OperationalIncidentType.LEDGER_IMBALANCE to AlertRoutingRule(
                OperationalIncidentType.LEDGER_IMBALANCE,
                IncidentSeverity.CRITICAL,
                "Financial Ledger Operations",
                "finance-critical",
                "/runbooks/ledger-imbalance.md",
                requiresPaging = true
            ),
            OperationalIncidentType.AMBIGUOUS_PAYOUT to AlertRoutingRule(
                OperationalIncidentType.AMBIGUOUS_PAYOUT,
                IncidentSeverity.CRITICAL,
                "Payout Operations",
                "payouts-critical",
                "/runbooks/ambiguous-payout.md",
                requiresPaging = true
            ),
            OperationalIncidentType.STUCK_WORKER to AlertRoutingRule(
                OperationalIncidentType.STUCK_WORKER,
                IncidentSeverity.HIGH,
                "Infrastructure Platform",
                "infra-high",
                "/runbooks/stuck-worker.md",
                requiresPaging = true
            ),
            OperationalIncidentType.STUCK_OUTBOX to AlertRoutingRule(
                OperationalIncidentType.STUCK_OUTBOX,
                IncidentSeverity.HIGH,
                "Infrastructure Platform",
                "infra-high",
                "/runbooks/stuck-outbox.md",
                requiresPaging = true
            ),
            OperationalIncidentType.AUTH_ATTACK to AlertRoutingRule(
                OperationalIncidentType.AUTH_ATTACK,
                IncidentSeverity.CRITICAL,
                "Security Operations Center",
                "security-critical",
                "/runbooks/auth-attack.md",
                requiresPaging = true
            ),
            OperationalIncidentType.PIN_FAILURE to AlertRoutingRule(
                OperationalIncidentType.PIN_FAILURE,
                IncidentSeverity.HIGH,
                "Security Operations Center",
                "security-high",
                "/runbooks/pin-failure.md",
                requiresPaging = false
            ),
            OperationalIncidentType.MFA_FAILURE to AlertRoutingRule(
                OperationalIncidentType.MFA_FAILURE,
                IncidentSeverity.HIGH,
                "Security Operations Center",
                "security-high",
                "/runbooks/mfa-failure.md",
                requiresPaging = false
            ),
            OperationalIncidentType.SOCKET_PROTOCOL_FAILURE to AlertRoutingRule(
                OperationalIncidentType.SOCKET_PROTOCOL_FAILURE,
                IncidentSeverity.HIGH,
                "Gaming Platform",
                "games-high",
                "/runbooks/socket-failure.md",
                requiresPaging = true
            ),
            OperationalIncidentType.PROVIDER_OUTAGE to AlertRoutingRule(
                OperationalIncidentType.PROVIDER_OUTAGE,
                IncidentSeverity.CRITICAL,
                "Payment Integrations",
                "payments-critical",
                "/runbooks/provider-outage.md",
                requiresPaging = true
            ),
            OperationalIncidentType.PROVIDER_TIMEOUT to AlertRoutingRule(
                OperationalIncidentType.PROVIDER_TIMEOUT,
                IncidentSeverity.HIGH,
                "Payment Integrations",
                "payments-high",
                "/runbooks/provider-timeout.md",
                requiresPaging = false
            ),
            OperationalIncidentType.EXPORTER_OUTAGE to AlertRoutingRule(
                OperationalIncidentType.EXPORTER_OUTAGE,
                IncidentSeverity.HIGH,
                "Observability Team",
                "observability-high",
                "/runbooks/exporter-outage.md",
                requiresPaging = true
            ),
            OperationalIncidentType.DLQ_GROWTH to AlertRoutingRule(
                OperationalIncidentType.DLQ_GROWTH,
                IncidentSeverity.HIGH,
                "Observability Team",
                "observability-high",
                "/runbooks/dlq-growth.md",
                requiresPaging = true
            ),
            OperationalIncidentType.MONITORING_PIPELINE_FAILURE to AlertRoutingRule(
                OperationalIncidentType.MONITORING_PIPELINE_FAILURE,
                IncidentSeverity.CRITICAL,
                "Observability Team",
                "observability-critical",
                "/runbooks/monitoring-failure.md",
                requiresPaging = true
            )
        )
    }
}

// Write-only presentation views
data class SiemIntegrationView(
    val tenantId: String,
    val providerType: SiemProviderType,
    val enabled: Boolean,
    val endpointUrl: String?,
    val authType: SiemAuthType,
    val username: String?,
    val indexOrDataStream: String?,
    val secretStatus: SecretStatusInfo,
    val timeoutMs: Long,
    val retryLimit: Int,
    val verifyTls: Boolean,
    val readiness: ObservabilityReadinessState,
    val configVersion: Long,
    val updatedAt: Instant,
)

data class PagingIntegrationView(
    val tenantId: String,
    val providerType: PagingProviderType,
    val enabled: Boolean,
    val endpointUrl: String?,
    val serviceKeyOrId: String?,
    val secretStatus: SecretStatusInfo,
    val timeoutMs: Long,
    val retryLimit: Int,
    val verifyTls: Boolean,
    val readiness: ObservabilityReadinessState,
    val configVersion: Long,
    val updatedAt: Instant,
)

data class MetricsIntegrationView(
    val tenantId: String,
    val providerType: MetricsProviderType,
    val enabled: Boolean,
    val endpointUrl: String?,
    val secretStatus: SecretStatusInfo,
    val pushIntervalSeconds: Int,
    val verifyTls: Boolean,
    val readiness: ObservabilityReadinessState,
    val configVersion: Long,
    val updatedAt: Instant,
)

data class TracingIntegrationView(
    val tenantId: String,
    val providerType: TracingProviderType,
    val enabled: Boolean,
    val endpointUrl: String?,
    val secretStatus: SecretStatusInfo,
    val samplingRatio: Double,
    val verifyTls: Boolean,
    val readiness: ObservabilityReadinessState,
    val configVersion: Long,
    val updatedAt: Instant,
)

data class AlertRoutingPolicyView(
    val tenantId: String,
    val rules: List<AlertRoutingRule>,
    val configVersion: Long,
    val updatedAt: Instant,
)

// Update commands
data class UpdateSiemConfigCommand(
    val tenantId: String,
    val sessionId: String,
    val providerType: SiemProviderType,
    val enabled: Boolean = true,
    val endpointUrl: String?,
    val authType: SiemAuthType = SiemAuthType.API_TOKEN,
    val username: String? = null,
    val indexOrDataStream: String? = "security-events",
    val replaceAuthSecret: String? = null,
    val clearAuthSecret: Boolean = false,
    val timeoutMs: Long = 5000L,
    val retryLimit: Int = 3,
    val verifyTls: Boolean = true,
    val expectedVersion: Long,
    val correlationId: String,
    val causationId: String,
)

data class UpdatePagingConfigCommand(
    val tenantId: String,
    val sessionId: String,
    val providerType: PagingProviderType,
    val enabled: Boolean = true,
    val endpointUrl: String?,
    val serviceKeyOrId: String? = null,
    val replaceRoutingSecret: String? = null,
    val clearRoutingSecret: Boolean = false,
    val timeoutMs: Long = 5000L,
    val retryLimit: Int = 3,
    val verifyTls: Boolean = true,
    val expectedVersion: Long,
    val correlationId: String,
    val causationId: String,
)

data class UpdateMetricsConfigCommand(
    val tenantId: String,
    val sessionId: String,
    val providerType: MetricsProviderType,
    val enabled: Boolean = true,
    val endpointUrl: String?,
    val replaceAuthSecret: String? = null,
    val clearAuthSecret: Boolean = false,
    val pushIntervalSeconds: Int = 15,
    val verifyTls: Boolean = true,
    val expectedVersion: Long,
    val correlationId: String,
    val causationId: String,
)

data class UpdateTracingConfigCommand(
    val tenantId: String,
    val sessionId: String,
    val providerType: TracingProviderType,
    val enabled: Boolean = true,
    val endpointUrl: String?,
    val replaceAuthSecret: String? = null,
    val clearAuthSecret: Boolean = false,
    val samplingRatio: Double = 1.0,
    val verifyTls: Boolean = true,
    val expectedVersion: Long,
    val correlationId: String,
    val causationId: String,
)

data class UpdateAlertRoutingCommand(
    val tenantId: String,
    val sessionId: String,
    val rules: List<AlertRoutingRule>,
    val expectedVersion: Long,
    val correlationId: String,
    val causationId: String,
)

// In-Memory store
class ObservabilitySettingsStore {
    private val siemConfigs = ConcurrentHashMap<String, SiemConfigRecord>()
    private val pagingConfigs = ConcurrentHashMap<String, PagingConfigRecord>()
    private val metricsConfigs = ConcurrentHashMap<String, MetricsConfigRecord>()
    private val tracingConfigs = ConcurrentHashMap<String, TracingConfigRecord>()
    private val alertRoutingConfigs = ConcurrentHashMap<String, AlertRoutingPolicyConfig>()

    fun getSiemConfig(tenantId: String): SiemConfigRecord? = siemConfigs[tenantId]
    fun saveSiemConfig(config: SiemConfigRecord) { siemConfigs[config.tenantId] = config }

    fun getPagingConfig(tenantId: String): PagingConfigRecord? = pagingConfigs[tenantId]
    fun savePagingConfig(config: PagingConfigRecord) { pagingConfigs[config.tenantId] = config }

    fun getMetricsConfig(tenantId: String): MetricsConfigRecord? = metricsConfigs[tenantId]
    fun saveMetricsConfig(config: MetricsConfigRecord) { metricsConfigs[config.tenantId] = config }

    fun getTracingConfig(tenantId: String): TracingConfigRecord? = tracingConfigs[tenantId]
    fun saveTracingConfig(config: TracingConfigRecord) { tracingConfigs[config.tenantId] = config }

    fun getAlertRouting(tenantId: String): AlertRoutingPolicyConfig? = alertRoutingConfigs[tenantId]
    fun saveAlertRouting(config: AlertRoutingPolicyConfig) { alertRoutingConfigs[config.tenantId] = config }
}
