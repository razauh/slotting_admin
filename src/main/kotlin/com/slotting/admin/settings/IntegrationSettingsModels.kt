package com.slotting.admin.settings

import com.slotting.admin.auth.AuthenticatedPrincipal
import com.slotting.admin.secret.EncryptedSecretPayload
import java.time.Instant
import java.util.concurrent.ConcurrentHashMap

enum class IntegrationChannel {
    SMS,
    EMAIL,
    PUSH,
    KMS,
    WEBHOOK,
}

enum class IntegrationReadinessState {
    NOT_CONFIGURED,
    CONFIGURED,
    VALIDATING,
    READY,
    DEGRADED,
    INVALID,
    DISABLED,
}

enum class SmsProviderType {
    TWILIO,
    AWS_SNS,
    CUSTOM_HTTP,
}

enum class EmailProviderType {
    AWS_SES,
    SENDGRID,
    SMTP,
    CUSTOM_HTTP,
}

enum class PushProviderType {
    FCM,
    APNS,
    CUSTOM_HTTP,
}

enum class KmsProviderType {
    AWS_KMS,
    GCP_KMS,
    HASHICORP_VAULT,
    LOCAL_DEV,
}

data class SecretStatusInfo(
    val configured: Boolean,
    val keyVersion: Int? = null,
    val lastRotatedAt: Instant? = null,
)

// --- Internal Persisted Configurations (with encrypted secrets) ---

data class SmsIntegrationConfig(
    val tenantId: String,
    val providerType: SmsProviderType,
    val enabled: Boolean = true,
    val endpointUrl: String? = null,
    val accountId: String? = null,
    val senderId: String? = null,
    val encryptedAuthToken: EncryptedSecretPayload? = null,
    val encryptedWebhookSecret: EncryptedSecretPayload? = null,
    val timeoutMs: Long = 5000L,
    val retryLimit: Int = 3,
    val readiness: IntegrationReadinessState = IntegrationReadinessState.NOT_CONFIGURED,
    val configVersion: Long = 1L,
    val updatedAt: Instant,
)

data class EmailIntegrationConfig(
    val tenantId: String,
    val providerType: EmailProviderType,
    val enabled: Boolean = true,
    val region: String? = null,
    val endpointUrl: String? = null,
    val senderAddress: String? = null,
    val fromDisplayName: String? = null,
    val replyTo: String? = null,
    val encryptedApiKey: EncryptedSecretPayload? = null,
    val encryptedWebhookSecret: EncryptedSecretPayload? = null,
    val timeoutMs: Long = 5000L,
    val retryLimit: Int = 3,
    val readiness: IntegrationReadinessState = IntegrationReadinessState.NOT_CONFIGURED,
    val configVersion: Long = 1L,
    val updatedAt: Instant,
)

data class PushIntegrationConfig(
    val tenantId: String,
    val providerType: PushProviderType,
    val enabled: Boolean = true,
    val projectId: String? = null,
    val endpointUrl: String? = null,
    val encryptedCredentialsJson: EncryptedSecretPayload? = null,
    val encryptedWebhookSecret: EncryptedSecretPayload? = null,
    val timeoutMs: Long = 5000L,
    val retryLimit: Int = 3,
    val readiness: IntegrationReadinessState = IntegrationReadinessState.NOT_CONFIGURED,
    val configVersion: Long = 1L,
    val updatedAt: Instant,
)

data class KmsIntegrationConfig(
    val tenantId: String,
    val providerType: KmsProviderType,
    val enabled: Boolean = true,
    val keyIdentifier: String? = null, // e.g. KMS ARN / URI
    val endpointOrRegion: String? = null,
    val activeKeyVersion: Int = 1,
    val readiness: IntegrationReadinessState = IntegrationReadinessState.NOT_CONFIGURED,
    val configVersion: Long = 1L,
    val updatedAt: Instant,
)

// --- Admin Presentation Views (Write-Only Secrets Masked) ---

data class SmsIntegrationView(
    val tenantId: String,
    val providerType: SmsProviderType,
    val enabled: Boolean,
    val endpointUrl: String?,
    val accountId: String?,
    val senderId: String?,
    val tokenStatus: SecretStatusInfo,
    val webhookSecretStatus: SecretStatusInfo,
    val timeoutMs: Long,
    val retryLimit: Int,
    val readiness: IntegrationReadinessState,
    val configVersion: Long,
    val updatedAt: Instant,
)

data class EmailIntegrationView(
    val tenantId: String,
    val providerType: EmailProviderType,
    val enabled: Boolean,
    val region: String?,
    val endpointUrl: String?,
    val senderAddress: String?,
    val fromDisplayName: String?,
    val replyTo: String?,
    val apiKeyStatus: SecretStatusInfo,
    val webhookSecretStatus: SecretStatusInfo,
    val timeoutMs: Long,
    val retryLimit: Int,
    val readiness: IntegrationReadinessState,
    val configVersion: Long,
    val updatedAt: Instant,
)

data class PushIntegrationView(
    val tenantId: String,
    val providerType: PushProviderType,
    val enabled: Boolean,
    val projectId: String?,
    val endpointUrl: String?,
    val credentialsStatus: SecretStatusInfo,
    val webhookSecretStatus: SecretStatusInfo,
    val timeoutMs: Long,
    val retryLimit: Int,
    val readiness: IntegrationReadinessState,
    val configVersion: Long,
    val updatedAt: Instant,
)

data class KmsIntegrationView(
    val tenantId: String,
    val providerType: KmsProviderType,
    val enabled: Boolean,
    val keyIdentifier: String?,
    val endpointOrRegion: String?,
    val activeKeyVersion: Int,
    val readiness: IntegrationReadinessState,
    val configVersion: Long,
    val updatedAt: Instant,
)

// --- Update Commands ---

data class UpdateSmsIntegrationCommand(
    val principal: AuthenticatedPrincipal?,
    val sessionId: String,
    val tenantId: String,
    val providerType: SmsProviderType,
    val enabled: Boolean = true,
    val endpointUrl: String? = null,
    val accountId: String? = null,
    val senderId: String? = null,
    val replaceAuthToken: String? = null,
    val clearAuthToken: Boolean = false,
    val replaceWebhookSecret: String? = null,
    val clearWebhookSecret: Boolean = false,
    val timeoutMs: Long = 5000L,
    val retryLimit: Int = 3,
    val expectedVersion: Long,
)

data class UpdateEmailIntegrationCommand(
    val principal: AuthenticatedPrincipal?,
    val sessionId: String,
    val tenantId: String,
    val providerType: EmailProviderType,
    val enabled: Boolean = true,
    val region: String? = null,
    val endpointUrl: String? = null,
    val senderAddress: String? = null,
    val fromDisplayName: String? = null,
    val replyTo: String? = null,
    val replaceApiKey: String? = null,
    val clearApiKey: Boolean = false,
    val replaceWebhookSecret: String? = null,
    val clearWebhookSecret: Boolean = false,
    val timeoutMs: Long = 5000L,
    val retryLimit: Int = 3,
    val expectedVersion: Long,
)

data class UpdatePushIntegrationCommand(
    val principal: AuthenticatedPrincipal?,
    val sessionId: String,
    val tenantId: String,
    val providerType: PushProviderType,
    val enabled: Boolean = true,
    val projectId: String? = null,
    val endpointUrl: String? = null,
    val replaceCredentialsJson: String? = null,
    val clearCredentialsJson: Boolean = false,
    val replaceWebhookSecret: String? = null,
    val clearWebhookSecret: Boolean = false,
    val timeoutMs: Long = 5000L,
    val retryLimit: Int = 3,
    val expectedVersion: Long,
)

data class UpdateKmsIntegrationCommand(
    val principal: AuthenticatedPrincipal?,
    val sessionId: String,
    val tenantId: String,
    val providerType: KmsProviderType,
    val enabled: Boolean = true,
    val keyIdentifier: String? = null,
    val endpointOrRegion: String? = null,
    val activeKeyVersion: Int = 1,
    val expectedVersion: Long,
)

data class IntegrationTestResult(
    val tenantId: String,
    val channel: IntegrationChannel,
    val success: Boolean,
    val message: String,
    val validatedAt: Instant,
)

interface IntegrationSettingsStore {
    fun saveSmsConfig(config: SmsIntegrationConfig)
    fun getSmsConfig(tenantId: String): SmsIntegrationConfig?
    fun saveEmailConfig(config: EmailIntegrationConfig)
    fun getEmailConfig(tenantId: String): EmailIntegrationConfig?
    fun savePushConfig(config: PushIntegrationConfig)
    fun getPushConfig(tenantId: String): PushIntegrationConfig?
    fun saveKmsConfig(config: KmsIntegrationConfig)
    fun getKmsConfig(tenantId: String): KmsIntegrationConfig?
}

class InMemoryIntegrationSettingsStore : IntegrationSettingsStore {
    private val smsConfigs = ConcurrentHashMap<String, SmsIntegrationConfig>()
    private val emailConfigs = ConcurrentHashMap<String, EmailIntegrationConfig>()
    private val pushConfigs = ConcurrentHashMap<String, PushIntegrationConfig>()
    private val kmsConfigs = ConcurrentHashMap<String, KmsIntegrationConfig>()

    override fun saveSmsConfig(config: SmsIntegrationConfig) { smsConfigs[config.tenantId] = config }
    override fun getSmsConfig(tenantId: String): SmsIntegrationConfig? = smsConfigs[tenantId]

    override fun saveEmailConfig(config: EmailIntegrationConfig) { emailConfigs[config.tenantId] = config }
    override fun getEmailConfig(tenantId: String): EmailIntegrationConfig? = emailConfigs[tenantId]

    override fun savePushConfig(config: PushIntegrationConfig) { pushConfigs[config.tenantId] = config }
    override fun getPushConfig(tenantId: String): PushIntegrationConfig? = pushConfigs[tenantId]

    override fun saveKmsConfig(config: KmsIntegrationConfig) { kmsConfigs[config.tenantId] = config }
    override fun getKmsConfig(tenantId: String): KmsIntegrationConfig? = kmsConfigs[tenantId]
}
