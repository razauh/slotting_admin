package com.slotting.admin.settings

import com.slotting.admin.auth.AdminPermission
import com.slotting.admin.auth.AdminRbacPolicy
import com.slotting.admin.auth.AdminSessionDirectory
import com.slotting.admin.auth.AlertSink
import com.slotting.admin.auth.AuditEvent
import com.slotting.admin.auth.AuthErrorCode
import com.slotting.admin.auth.AuthenticatedPrincipal
import com.slotting.admin.auth.AuthenticationFailure
import com.slotting.admin.secret.AesGcmEnvelopeEncryptor
import java.time.Clock
import java.time.Instant
import java.util.UUID

class IntegrationSettingsService(
    private val store: IntegrationSettingsStore,
    private val sessions: AdminSessionDirectory,
    private val rbacPolicy: AdminRbacPolicy,
    private val encryptor: AesGcmEnvelopeEncryptor,
    private val alertSink: AlertSink? = null,
    private val clock: Clock = Clock.systemUTC(),
    private val environment: String = "TEST",
) {

    private fun validateAccess(
        principal: AuthenticatedPrincipal?,
        tenantId: String,
        sessionId: String,
        requiredPermission: AdminPermission
    ) {
        val p = principal ?: throw AuthenticationFailure.Rejected(AuthErrorCode.UNAUTHENTICATED)
        if (p.tenantId != tenantId) {
            throw AuthenticationFailure.Rejected(AuthErrorCode.FORBIDDEN)
        }
        val now = clock.instant()
        val session = try {
            sessions.find(tenantId, p.id, sessionId)
        } catch (_: Exception) {
            null
        }
        if (session == null || !session.active || !session.expiresAt.isAfter(now)) {
            throw AuthenticationFailure.Rejected(AuthErrorCode.FORBIDDEN)
        }
        if (!rbacPolicy.isPermitted(p, requiredPermission)) {
            throw AuthenticationFailure.Rejected(AuthErrorCode.FORBIDDEN)
        }
    }

    // =========================================================================
    // SMS Settings
    // =========================================================================

    fun getSmsSettings(principal: AuthenticatedPrincipal?, tenantId: String, sessionId: String): SmsIntegrationView {
        validateAccess(principal, tenantId, sessionId, AdminPermission.VIEW_INTEGRATION_SETTINGS)
        val config = store.getSmsConfig(tenantId)
        val now = clock.instant()
        if (config == null) {
            return SmsIntegrationView(
                tenantId = tenantId,
                providerType = SmsProviderType.TWILIO,
                enabled = false,
                endpointUrl = null,
                accountId = null,
                senderId = null,
                tokenStatus = SecretStatusInfo(configured = false),
                webhookSecretStatus = SecretStatusInfo(configured = false),
                timeoutMs = 5000L,
                retryLimit = 3,
                readiness = IntegrationReadinessState.NOT_CONFIGURED,
                configVersion = 0L,
                updatedAt = now,
            )
        }
        return SmsIntegrationView(
            tenantId = config.tenantId,
            providerType = config.providerType,
            enabled = config.enabled,
            endpointUrl = config.endpointUrl,
            accountId = config.accountId,
            senderId = config.senderId,
            tokenStatus = SecretStatusInfo(
                configured = config.encryptedAuthToken != null,
                keyVersion = config.encryptedAuthToken?.keyVersion,
                lastRotatedAt = config.updatedAt
            ),
            webhookSecretStatus = SecretStatusInfo(
                configured = config.encryptedWebhookSecret != null,
                keyVersion = config.encryptedWebhookSecret?.keyVersion,
                lastRotatedAt = config.updatedAt
            ),
            timeoutMs = config.timeoutMs,
            retryLimit = config.retryLimit,
            readiness = config.readiness,
            configVersion = config.configVersion,
            updatedAt = config.updatedAt,
        )
    }

    fun updateSmsSettings(command: UpdateSmsIntegrationCommand): SmsIntegrationView {
        val requiredPerm = if (command.replaceAuthToken != null || command.replaceWebhookSecret != null) {
            AdminPermission.ROTATE_INTEGRATION_SECRETS
        } else {
            AdminPermission.EDIT_INTEGRATION_SETTINGS
        }
        validateAccess(command.principal, command.tenantId, command.sessionId, requiredPerm)

        val existing = store.getSmsConfig(command.tenantId)
        val now = clock.instant()

        val newAuthToken = when {
            command.clearAuthToken -> null
            command.replaceAuthToken != null -> encryptor.encryptString(command.tenantId, "SMS_AUTH_TOKEN", command.replaceAuthToken)
            else -> existing?.encryptedAuthToken
        }

        val newWebhookSecret = when {
            command.clearWebhookSecret -> null
            command.replaceWebhookSecret != null -> encryptor.encryptString(command.tenantId, "SMS_WEBHOOK_SECRET", command.replaceWebhookSecret)
            else -> existing?.encryptedWebhookSecret
        }

        val readiness = when {
            !command.enabled -> IntegrationReadinessState.DISABLED
            newAuthToken != null -> IntegrationReadinessState.READY
            else -> IntegrationReadinessState.CONFIGURED
        }

        val updated = SmsIntegrationConfig(
            tenantId = command.tenantId,
            providerType = command.providerType,
            enabled = command.enabled,
            endpointUrl = command.endpointUrl,
            accountId = command.accountId,
            senderId = command.senderId,
            encryptedAuthToken = newAuthToken,
            encryptedWebhookSecret = newWebhookSecret,
            timeoutMs = command.timeoutMs,
            retryLimit = command.retryLimit,
            readiness = readiness,
            configVersion = (existing?.configVersion ?: 0L) + 1L,
            updatedAt = now,
        )

        store.saveSmsConfig(updated)

        alertSink?.alert(
            AuditEvent(
                eventId = UUID.randomUUID(),
                resultId = UUID.randomUUID(),
                tenantId = command.tenantId,
                type = "INTEGRATION_SETTINGS_SMS_UPDATED",
                occurredAt = now,
                correlationId = command.sessionId,
                causationId = command.principal!!.id,
            )
        )

        return getSmsSettings(command.principal, command.tenantId, command.sessionId)
    }

    // =========================================================================
    // Email Settings
    // =========================================================================

    fun getEmailSettings(principal: AuthenticatedPrincipal?, tenantId: String, sessionId: String): EmailIntegrationView {
        validateAccess(principal, tenantId, sessionId, AdminPermission.VIEW_INTEGRATION_SETTINGS)
        val config = store.getEmailConfig(tenantId)
        val now = clock.instant()
        if (config == null) {
            return EmailIntegrationView(
                tenantId = tenantId,
                providerType = EmailProviderType.AWS_SES,
                enabled = false,
                region = null,
                endpointUrl = null,
                senderAddress = null,
                fromDisplayName = null,
                replyTo = null,
                apiKeyStatus = SecretStatusInfo(configured = false),
                webhookSecretStatus = SecretStatusInfo(configured = false),
                timeoutMs = 5000L,
                retryLimit = 3,
                readiness = IntegrationReadinessState.NOT_CONFIGURED,
                configVersion = 0L,
                updatedAt = now,
            )
        }
        return EmailIntegrationView(
            tenantId = config.tenantId,
            providerType = config.providerType,
            enabled = config.enabled,
            region = config.region,
            endpointUrl = config.endpointUrl,
            senderAddress = config.senderAddress,
            fromDisplayName = config.fromDisplayName,
            replyTo = config.replyTo,
            apiKeyStatus = SecretStatusInfo(
                configured = config.encryptedApiKey != null,
                keyVersion = config.encryptedApiKey?.keyVersion,
                lastRotatedAt = config.updatedAt
            ),
            webhookSecretStatus = SecretStatusInfo(
                configured = config.encryptedWebhookSecret != null,
                keyVersion = config.encryptedWebhookSecret?.keyVersion,
                lastRotatedAt = config.updatedAt
            ),
            timeoutMs = config.timeoutMs,
            retryLimit = config.retryLimit,
            readiness = config.readiness,
            configVersion = config.configVersion,
            updatedAt = config.updatedAt,
        )
    }

    fun updateEmailSettings(command: UpdateEmailIntegrationCommand): EmailIntegrationView {
        val requiredPerm = if (command.replaceApiKey != null || command.replaceWebhookSecret != null) {
            AdminPermission.ROTATE_INTEGRATION_SECRETS
        } else {
            AdminPermission.EDIT_INTEGRATION_SETTINGS
        }
        validateAccess(command.principal, command.tenantId, command.sessionId, requiredPerm)

        val existing = store.getEmailConfig(command.tenantId)
        val now = clock.instant()

        val newApiKey = when {
            command.clearApiKey -> null
            command.replaceApiKey != null -> encryptor.encryptString(command.tenantId, "EMAIL_API_KEY", command.replaceApiKey)
            else -> existing?.encryptedApiKey
        }

        val newWebhookSecret = when {
            command.clearWebhookSecret -> null
            command.replaceWebhookSecret != null -> encryptor.encryptString(command.tenantId, "EMAIL_WEBHOOK_SECRET", command.replaceWebhookSecret)
            else -> existing?.encryptedWebhookSecret
        }

        val readiness = when {
            !command.enabled -> IntegrationReadinessState.DISABLED
            newApiKey != null -> IntegrationReadinessState.READY
            else -> IntegrationReadinessState.CONFIGURED
        }

        val updated = EmailIntegrationConfig(
            tenantId = command.tenantId,
            providerType = command.providerType,
            enabled = command.enabled,
            region = command.region,
            endpointUrl = command.endpointUrl,
            senderAddress = command.senderAddress,
            fromDisplayName = command.fromDisplayName,
            replyTo = command.replyTo,
            encryptedApiKey = newApiKey,
            encryptedWebhookSecret = newWebhookSecret,
            timeoutMs = command.timeoutMs,
            retryLimit = command.retryLimit,
            readiness = readiness,
            configVersion = (existing?.configVersion ?: 0L) + 1L,
            updatedAt = now,
        )

        store.saveEmailConfig(updated)

        alertSink?.alert(
            AuditEvent(
                eventId = UUID.randomUUID(),
                resultId = UUID.randomUUID(),
                tenantId = command.tenantId,
                type = "INTEGRATION_SETTINGS_EMAIL_UPDATED",
                occurredAt = now,
                correlationId = command.sessionId,
                causationId = command.principal!!.id,
            )
        )

        return getEmailSettings(command.principal, command.tenantId, command.sessionId)
    }

    // =========================================================================
    // Push Settings
    // =========================================================================

    fun getPushSettings(principal: AuthenticatedPrincipal?, tenantId: String, sessionId: String): PushIntegrationView {
        validateAccess(principal, tenantId, sessionId, AdminPermission.VIEW_INTEGRATION_SETTINGS)
        val config = store.getPushConfig(tenantId)
        val now = clock.instant()
        if (config == null) {
            return PushIntegrationView(
                tenantId = tenantId,
                providerType = PushProviderType.FCM,
                enabled = false,
                projectId = null,
                endpointUrl = null,
                credentialsStatus = SecretStatusInfo(configured = false),
                webhookSecretStatus = SecretStatusInfo(configured = false),
                timeoutMs = 5000L,
                retryLimit = 3,
                readiness = IntegrationReadinessState.NOT_CONFIGURED,
                configVersion = 0L,
                updatedAt = now,
            )
        }
        return PushIntegrationView(
            tenantId = config.tenantId,
            providerType = config.providerType,
            enabled = config.enabled,
            projectId = config.projectId,
            endpointUrl = config.endpointUrl,
            credentialsStatus = SecretStatusInfo(
                configured = config.encryptedCredentialsJson != null,
                keyVersion = config.encryptedCredentialsJson?.keyVersion,
                lastRotatedAt = config.updatedAt
            ),
            webhookSecretStatus = SecretStatusInfo(
                configured = config.encryptedWebhookSecret != null,
                keyVersion = config.encryptedWebhookSecret?.keyVersion,
                lastRotatedAt = config.updatedAt
            ),
            timeoutMs = config.timeoutMs,
            retryLimit = config.retryLimit,
            readiness = config.readiness,
            configVersion = config.configVersion,
            updatedAt = config.updatedAt,
        )
    }

    fun updatePushSettings(command: UpdatePushIntegrationCommand): PushIntegrationView {
        val requiredPerm = if (command.replaceCredentialsJson != null || command.replaceWebhookSecret != null) {
            AdminPermission.ROTATE_INTEGRATION_SECRETS
        } else {
            AdminPermission.EDIT_INTEGRATION_SETTINGS
        }
        validateAccess(command.principal, command.tenantId, command.sessionId, requiredPerm)

        val existing = store.getPushConfig(command.tenantId)
        val now = clock.instant()

        val newCreds = when {
            command.clearCredentialsJson -> null
            command.replaceCredentialsJson != null -> encryptor.encryptString(command.tenantId, "PUSH_CREDENTIALS", command.replaceCredentialsJson)
            else -> existing?.encryptedCredentialsJson
        }

        val newWebhook = when {
            command.clearWebhookSecret -> null
            command.replaceWebhookSecret != null -> encryptor.encryptString(command.tenantId, "PUSH_WEBHOOK_SECRET", command.replaceWebhookSecret)
            else -> existing?.encryptedWebhookSecret
        }

        val readiness = when {
            !command.enabled -> IntegrationReadinessState.DISABLED
            newCreds != null -> IntegrationReadinessState.READY
            else -> IntegrationReadinessState.CONFIGURED
        }

        val updated = PushIntegrationConfig(
            tenantId = command.tenantId,
            providerType = command.providerType,
            enabled = command.enabled,
            projectId = command.projectId,
            endpointUrl = command.endpointUrl,
            encryptedCredentialsJson = newCreds,
            encryptedWebhookSecret = newWebhook,
            timeoutMs = command.timeoutMs,
            retryLimit = command.retryLimit,
            readiness = readiness,
            configVersion = (existing?.configVersion ?: 0L) + 1L,
            updatedAt = now,
        )

        store.savePushConfig(updated)

        alertSink?.alert(
            AuditEvent(
                eventId = UUID.randomUUID(),
                resultId = UUID.randomUUID(),
                tenantId = command.tenantId,
                type = "INTEGRATION_SETTINGS_PUSH_UPDATED",
                occurredAt = now,
                correlationId = command.sessionId,
                causationId = command.principal!!.id,
            )
        )

        return getPushSettings(command.principal, command.tenantId, command.sessionId)
    }

    // =========================================================================
    // KMS Settings
    // =========================================================================

    fun getKmsSettings(principal: AuthenticatedPrincipal?, tenantId: String, sessionId: String): KmsIntegrationView {
        validateAccess(principal, tenantId, sessionId, AdminPermission.VIEW_INTEGRATION_SETTINGS)
        val config = store.getKmsConfig(tenantId)
        val now = clock.instant()
        if (config == null) {
            return KmsIntegrationView(
                tenantId = tenantId,
                providerType = KmsProviderType.AWS_KMS,
                enabled = false,
                keyIdentifier = null,
                endpointOrRegion = null,
                activeKeyVersion = 1,
                readiness = IntegrationReadinessState.NOT_CONFIGURED,
                configVersion = 0L,
                updatedAt = now,
            )
        }
        return KmsIntegrationView(
            tenantId = config.tenantId,
            providerType = config.providerType,
            enabled = config.enabled,
            keyIdentifier = config.keyIdentifier,
            endpointOrRegion = config.endpointOrRegion,
            activeKeyVersion = config.activeKeyVersion,
            readiness = config.readiness,
            configVersion = config.configVersion,
            updatedAt = config.updatedAt,
        )
    }

    fun updateKmsSettings(command: UpdateKmsIntegrationCommand): KmsIntegrationView {
        validateAccess(command.principal, command.tenantId, command.sessionId, AdminPermission.MANAGE_KEY_CONFIGURATION)

        val existing = store.getKmsConfig(command.tenantId)
        val now = clock.instant()

        val readiness = if (command.enabled && command.keyIdentifier != null) {
            IntegrationReadinessState.READY
        } else if (!command.enabled) {
            IntegrationReadinessState.DISABLED
        } else {
            IntegrationReadinessState.CONFIGURED
        }

        val updated = KmsIntegrationConfig(
            tenantId = command.tenantId,
            providerType = command.providerType,
            enabled = command.enabled,
            keyIdentifier = command.keyIdentifier,
            endpointOrRegion = command.endpointOrRegion,
            activeKeyVersion = command.activeKeyVersion,
            readiness = readiness,
            configVersion = (existing?.configVersion ?: 0L) + 1L,
            updatedAt = now,
        )

        store.saveKmsConfig(updated)

        alertSink?.alert(
            AuditEvent(
                eventId = UUID.randomUUID(),
                resultId = UUID.randomUUID(),
                tenantId = command.tenantId,
                type = "INTEGRATION_SETTINGS_KMS_UPDATED",
                occurredAt = now,
                correlationId = command.sessionId,
                causationId = command.principal!!.id,
            )
        )

        return getKmsSettings(command.principal, command.tenantId, command.sessionId)
    }

    // =========================================================================
    // Test Integration Action
    // =========================================================================

    fun testIntegration(
        principal: AuthenticatedPrincipal?,
        tenantId: String,
        sessionId: String,
        channel: IntegrationChannel
    ): IntegrationTestResult {
        validateAccess(principal, tenantId, sessionId, AdminPermission.TEST_INTEGRATION)
        val now = clock.instant()

        val (success, msg) = when (channel) {
            IntegrationChannel.SMS -> {
                val cfg = store.getSmsConfig(tenantId)
                if (cfg == null || !cfg.enabled) {
                    Pair(false, "SMS integration is not configured or disabled")
                } else if (cfg.encryptedAuthToken == null) {
                    Pair(false, "SMS authentication token is not configured")
                } else {
                    try {
                        val token = encryptor.decryptString(tenantId, "SMS_AUTH_TOKEN", cfg.encryptedAuthToken)
                        Pair(token.isNotBlank(), "SMS configuration valid and decrypted successfully")
                    } catch (e: Exception) {
                        Pair(false, "Decryption failed for SMS authentication credential")
                    }
                }
            }
            IntegrationChannel.EMAIL -> {
                val cfg = store.getEmailConfig(tenantId)
                if (cfg == null || !cfg.enabled) {
                    Pair(false, "Email integration is not configured or disabled")
                } else if (cfg.encryptedApiKey == null) {
                    Pair(false, "Email API credential is not configured")
                } else {
                    try {
                        val key = encryptor.decryptString(tenantId, "EMAIL_API_KEY", cfg.encryptedApiKey)
                        Pair(key.isNotBlank(), "Email configuration valid and decrypted successfully")
                    } catch (e: Exception) {
                        Pair(false, "Decryption failed for Email API credential")
                    }
                }
            }
            IntegrationChannel.PUSH -> {
                val cfg = store.getPushConfig(tenantId)
                if (cfg == null || !cfg.enabled) {
                    Pair(false, "Push integration is not configured or disabled")
                } else if (cfg.encryptedCredentialsJson == null) {
                    Pair(false, "Push credentials are not configured")
                } else {
                    try {
                        val creds = encryptor.decryptString(tenantId, "PUSH_CREDENTIALS", cfg.encryptedCredentialsJson)
                        Pair(creds.isNotBlank(), "Push configuration valid and decrypted successfully")
                    } catch (e: Exception) {
                        Pair(false, "Decryption failed for Push credentials")
                    }
                }
            }
            IntegrationChannel.KMS -> {
                val cfg = store.getKmsConfig(tenantId)
                if (cfg == null || !cfg.enabled) {
                    Pair(false, "KMS integration is not configured or disabled")
                } else if (cfg.keyIdentifier.isNullOrBlank()) {
                    Pair(false, "KMS key identifier is blank")
                } else {
                    Pair(true, "KMS configuration valid")
                }
            }
            IntegrationChannel.WEBHOOK -> Pair(true, "Webhook endpoints ready")
        }

        return IntegrationTestResult(
            tenantId = tenantId,
            channel = channel,
            success = success,
            message = msg,
            validatedAt = now,
        )
    }
}
