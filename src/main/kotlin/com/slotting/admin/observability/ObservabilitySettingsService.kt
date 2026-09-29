package com.slotting.admin.observability

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

class VersionConflictException(message: String) : RuntimeException(message)

class ObservabilitySettingsService(
    private val store: ObservabilitySettingsStore,
    private val sessions: AdminSessionDirectory,
    private val rbacPolicy: AdminRbacPolicy,
    private val encryptor: AesGcmEnvelopeEncryptor,
    private val alertSink: AlertSink? = null,
    private val clock: Clock = Clock.systemUTC(),
    private val environment: String = "TEST",
    private val allowLocalDevEndpoints: Boolean = false,
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
    // SIEM Settings
    // =========================================================================

    fun getSiemSettings(principal: AuthenticatedPrincipal?, tenantId: String, sessionId: String): SiemIntegrationView {
        validateAccess(principal, tenantId, sessionId, AdminPermission.VIEW_OBSERVABILITY_SETTINGS)
        val config = store.getSiemConfig(tenantId)
        val now = clock.instant()
        if (config == null) {
            return SiemIntegrationView(
                tenantId = tenantId,
                providerType = SiemProviderType.OPENSEARCH,
                enabled = false,
                endpointUrl = null,
                authType = SiemAuthType.API_TOKEN,
                username = null,
                indexOrDataStream = "security-events",
                secretStatus = SecretStatusInfo(configured = false),
                timeoutMs = 5000L,
                retryLimit = 3,
                verifyTls = true,
                readiness = ObservabilityReadinessState.NOT_CONFIGURED,
                configVersion = 0L,
                updatedAt = now,
            )
        }
        return SiemIntegrationView(
            tenantId = config.tenantId,
            providerType = config.providerType,
            enabled = config.enabled,
            endpointUrl = config.endpointUrl,
            authType = config.authType,
            username = config.username,
            indexOrDataStream = config.indexOrDataStream,
            secretStatus = SecretStatusInfo(
                configured = config.encryptedAuthSecret != null,
                keyVersion = config.encryptedAuthSecret?.keyVersion,
                lastRotatedAt = config.updatedAt,
            ),
            timeoutMs = config.timeoutMs,
            retryLimit = config.retryLimit,
            verifyTls = config.verifyTls,
            readiness = config.readiness,
            configVersion = config.configVersion,
            updatedAt = config.updatedAt,
        )
    }

    fun updateSiemSettings(
        principal: AuthenticatedPrincipal?,
        command: UpdateSiemConfigCommand
    ): SiemIntegrationView {
        validateAccess(principal, command.tenantId, command.sessionId, AdminPermission.EDIT_OBSERVABILITY_SETTINGS)
        if (command.replaceAuthSecret != null) {
            validateAccess(principal, command.tenantId, command.sessionId, AdminPermission.ROTATE_OBSERVABILITY_SECRETS)
        }

        // Validate endpoint against SSRF
        OutboundEndpointValidator.validateEndpoint(
            command.endpointUrl,
            environment = environment,
            allowLocalDev = allowLocalDevEndpoints
        )

        val existing = store.getSiemConfig(command.tenantId)
        val currentVersion = existing?.configVersion ?: 0L
        if (command.expectedVersion != currentVersion) {
            throw VersionConflictException("Expected version ${command.expectedVersion} does not match current version $currentVersion")
        }

        val encryptedAuth = when {
            command.clearAuthSecret -> null
            command.replaceAuthSecret != null -> {
                encryptor.encrypt(
                    tenantId = command.tenantId,
                    context = "observability/siem/auth",
                    plaintext = command.replaceAuthSecret.toByteArray(Charsets.UTF_8)
                )
            }
            else -> existing?.encryptedAuthSecret
        }

        val readiness = when {
            !command.enabled -> ObservabilityReadinessState.DISABLED
            command.endpointUrl.isNullOrBlank() -> ObservabilityReadinessState.NOT_CONFIGURED
            else -> ObservabilityReadinessState.CONFIGURED
        }

        val updated = SiemConfigRecord(
            tenantId = command.tenantId,
            providerType = command.providerType,
            enabled = command.enabled,
            endpointUrl = command.endpointUrl,
            authType = command.authType,
            username = command.username,
            indexOrDataStream = command.indexOrDataStream,
            encryptedAuthSecret = encryptedAuth,
            timeoutMs = command.timeoutMs,
            retryLimit = command.retryLimit,
            verifyTls = command.verifyTls,
            readiness = readiness,
            configVersion = currentVersion + 1,
            updatedAt = clock.instant(),
        )

        store.saveSiemConfig(updated)
        recordAudit(principal!!.id, command.tenantId, "SIEM_INTEGRATION_CONFIGURED", command.correlationId, command.causationId)

        return getSiemSettings(principal, command.tenantId, command.sessionId)
    }

    // =========================================================================
    // Paging / Alerting Settings
    // =========================================================================

    fun getPagingSettings(principal: AuthenticatedPrincipal?, tenantId: String, sessionId: String): PagingIntegrationView {
        validateAccess(principal, tenantId, sessionId, AdminPermission.VIEW_OBSERVABILITY_SETTINGS)
        val config = store.getPagingConfig(tenantId)
        val now = clock.instant()
        if (config == null) {
            return PagingIntegrationView(
                tenantId = tenantId,
                providerType = PagingProviderType.GOALERT,
                enabled = false,
                endpointUrl = null,
                serviceKeyOrId = null,
                secretStatus = SecretStatusInfo(configured = false),
                timeoutMs = 5000L,
                retryLimit = 3,
                verifyTls = true,
                readiness = ObservabilityReadinessState.NOT_CONFIGURED,
                configVersion = 0L,
                updatedAt = now,
            )
        }
        return PagingIntegrationView(
            tenantId = config.tenantId,
            providerType = config.providerType,
            enabled = config.enabled,
            endpointUrl = config.endpointUrl,
            serviceKeyOrId = config.serviceKeyOrId,
            secretStatus = SecretStatusInfo(
                configured = config.encryptedRoutingSecret != null,
                keyVersion = config.encryptedRoutingSecret?.keyVersion,
                lastRotatedAt = config.updatedAt,
            ),
            timeoutMs = config.timeoutMs,
            retryLimit = config.retryLimit,
            verifyTls = config.verifyTls,
            readiness = config.readiness,
            configVersion = config.configVersion,
            updatedAt = config.updatedAt,
        )
    }

    fun updatePagingSettings(
        principal: AuthenticatedPrincipal?,
        command: UpdatePagingConfigCommand
    ): PagingIntegrationView {
        validateAccess(principal, command.tenantId, command.sessionId, AdminPermission.EDIT_OBSERVABILITY_SETTINGS)
        if (command.replaceRoutingSecret != null) {
            validateAccess(principal, command.tenantId, command.sessionId, AdminPermission.ROTATE_OBSERVABILITY_SECRETS)
        }

        OutboundEndpointValidator.validateEndpoint(
            command.endpointUrl,
            environment = environment,
            allowLocalDev = allowLocalDevEndpoints
        )

        val existing = store.getPagingConfig(command.tenantId)
        val currentVersion = existing?.configVersion ?: 0L
        if (command.expectedVersion != currentVersion) {
            throw VersionConflictException("Expected version ${command.expectedVersion} does not match current version $currentVersion")
        }

        val encryptedRouting = when {
            command.clearRoutingSecret -> null
            command.replaceRoutingSecret != null -> {
                encryptor.encrypt(
                    tenantId = command.tenantId,
                    context = "observability/paging/routing",
                    plaintext = command.replaceRoutingSecret.toByteArray(Charsets.UTF_8)
                )
            }
            else -> existing?.encryptedRoutingSecret
        }

        val readiness = when {
            !command.enabled -> ObservabilityReadinessState.DISABLED
            command.endpointUrl.isNullOrBlank() -> ObservabilityReadinessState.NOT_CONFIGURED
            else -> ObservabilityReadinessState.CONFIGURED
        }

        val updated = PagingConfigRecord(
            tenantId = command.tenantId,
            providerType = command.providerType,
            enabled = command.enabled,
            endpointUrl = command.endpointUrl,
            serviceKeyOrId = command.serviceKeyOrId,
            encryptedRoutingSecret = encryptedRouting,
            timeoutMs = command.timeoutMs,
            retryLimit = command.retryLimit,
            verifyTls = command.verifyTls,
            readiness = readiness,
            configVersion = currentVersion + 1,
            updatedAt = clock.instant(),
        )

        store.savePagingConfig(updated)
        recordAudit(principal!!.id, command.tenantId, "PAGING_INTEGRATION_CONFIGURED", command.correlationId, command.causationId)

        return getPagingSettings(principal, command.tenantId, command.sessionId)
    }

    // =========================================================================
    // Alert Routing Policy
    // =========================================================================

    fun getAlertRoutingPolicy(principal: AuthenticatedPrincipal?, tenantId: String, sessionId: String): AlertRoutingPolicyView {
        validateAccess(principal, tenantId, sessionId, AdminPermission.VIEW_OBSERVABILITY_SETTINGS)
        val config = store.getAlertRouting(tenantId)
        val now = clock.instant()
        if (config == null) {
            val defaultPolicy = AlertRoutingPolicyConfig(tenantId = tenantId, updatedAt = now)
            return AlertRoutingPolicyView(
                tenantId = tenantId,
                rules = defaultPolicy.rules.values.toList(),
                configVersion = defaultPolicy.configVersion,
                updatedAt = now,
            )
        }
        return AlertRoutingPolicyView(
            tenantId = config.tenantId,
            rules = config.rules.values.toList(),
            configVersion = config.configVersion,
            updatedAt = config.updatedAt,
        )
    }

    fun updateAlertRoutingPolicy(
        principal: AuthenticatedPrincipal?,
        command: UpdateAlertRoutingCommand
    ): AlertRoutingPolicyView {
        validateAccess(principal, command.tenantId, command.sessionId, AdminPermission.MANAGE_ALERT_ROUTING)

        val existing = store.getAlertRouting(command.tenantId)
        val currentVersion = existing?.configVersion ?: 0L
        if (command.expectedVersion != currentVersion) {
            throw VersionConflictException("Expected version ${command.expectedVersion} does not match current version $currentVersion")
        }

        val ruleMap = command.rules.associateBy { it.incidentType }
        val updated = AlertRoutingPolicyConfig(
            tenantId = command.tenantId,
            rules = ruleMap,
            configVersion = currentVersion + 1,
            updatedAt = clock.instant(),
        )

        store.saveAlertRouting(updated)
        recordAudit(principal!!.id, command.tenantId, "ALERT_ROUTING_CONFIGURED", command.correlationId, command.causationId)

        return getAlertRoutingPolicy(principal, command.tenantId, command.sessionId)
    }

    // Helper to decrypt auth secret internally for transport
    fun decryptSiemSecret(tenantId: String, payload: com.slotting.admin.secret.EncryptedSecretPayload): String {
        val bytes = encryptor.decrypt(tenantId, "observability/siem/auth", payload)
        return String(bytes, Charsets.UTF_8)
    }

    fun decryptPagingSecret(tenantId: String, payload: com.slotting.admin.secret.EncryptedSecretPayload): String {
        val bytes = encryptor.decrypt(tenantId, "observability/paging/routing", payload)
        return String(bytes, Charsets.UTF_8)
    }

    private fun recordAudit(
        actorId: String,
        tenantId: String,
        action: String,
        correlationId: String,
        causationId: String
    ) {
        alertSink?.alert(
            AuditEvent(
                eventId = UUID.randomUUID(),
                resultId = UUID.randomUUID(),
                tenantId = tenantId,
                type = action,
                occurredAt = clock.instant(),
                correlationId = correlationId,
                causationId = causationId
            )
        )
    }
}
