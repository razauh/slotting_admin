package com.slotting.admin.provider

import com.slotting.admin.auth.*
import java.security.MessageDigest
import java.time.Clock
import java.time.Instant
import java.util.UUID

enum class PaymentProviderStatus { ENABLED, DISABLED, SUSPENDED }
enum class PaymentProviderConfigAction { REGISTER, UPDATE_CONFIG, ENABLE, DISABLE }

data class PaymentProviderConfigCommand(
    val principal: AuthenticatedPrincipal?,
    val sessionId: String,
    val tenantId: String,
    val providerId: String,
    val action: PaymentProviderConfigAction,
    val displayName: String,
    val endpointUrl: String,
    val apiKeySecret: String? = null,
    val incidentReference: String? = null,
    val idempotencyKey: String,
    val correlationId: String,
    val causationId: String,
    val expectedVersion: Long,
)

data class PaymentProviderConfig(
    val providerId: String,
    val displayName: String,
    val status: PaymentProviderStatus,
    val endpointUrl: String,
    val maskedSecretPreview: String,
    val incidentReference: String?,
    val serverVersion: Long,
)

data class PaymentProviderConfigResult(
    val resultId: UUID,
    val provider: PaymentProviderConfig,
    val serverTime: Instant,
    val evidenceReference: String,
)

interface PaymentProviderConfigStore {
    fun findByIdempotency(tenantId: String, key: String): Pair<String, PaymentProviderConfigResult>?
    fun findProvider(tenantId: String, providerId: String): PaymentProviderConfig?
    fun save(
        result: PaymentProviderConfigResult,
        tenantId: String,
        secretHash: String,
        queryFingerprint: String,
        idempotencyKey: String,
        audit: AuditEvent,
        outbox: OutboxEvent,
    )
}

class PaymentProviderConfigService(
    private val policy: AdminRbacPolicy,
    private val sessions: AdminSessionDirectory,
    private val store: PaymentProviderConfigStore,
    private val clock: Clock = Clock.systemUTC(),
) {
    @Synchronized
    fun operate(command: PaymentProviderConfigCommand): PaymentProviderConfigResult {
        val principal = command.principal ?: throw AuthenticationFailure.Rejected(AuthErrorCode.UNAUTHENTICATED)
        val fingerprint = fingerprint(command)
        store.findByIdempotency(command.tenantId, command.idempotencyKey)?.let { replay ->
            if (replay.first != fingerprint) throw AuthenticationFailure.Rejected(AuthErrorCode.CONFLICT)
            return replay.second
        }

        if (principal.kind != PrincipalKind.ADMIN || principal.tenantId != command.tenantId) {
            throw AuthenticationFailure.Rejected(AuthErrorCode.FORBIDDEN)
        }

        if (command.providerId.isBlank() || command.providerId.length > 128 ||
            command.displayName.isBlank() || command.displayName.length > 128 ||
            command.sessionId.isBlank() || command.correlationId.isBlank() || command.causationId.isBlank()) {
            throw AuthenticationFailure.Rejected(AuthErrorCode.INVALID)
        }

        if (!command.endpointUrl.startsWith("https://") && !command.endpointUrl.startsWith("http://")) {
            throw AuthenticationFailure.Rejected(AuthErrorCode.INVALID)
        }

        val now = Instant.now(clock)
        val session = try {
            sessions.find(command.tenantId, principal.id, command.sessionId)
        } catch (_: Exception) {
            throw AuthenticationFailure.Rejected(AuthErrorCode.DEPENDENCY_UNAVAILABLE)
        }
        if (session == null || !session.active || !session.expiresAt.isAfter(now) ||
            (!policy.isPermitted(principal, AdminPermission.MANAGE_SECURITY) &&
             !policy.isPermitted(principal, AdminPermission.MANAGE_SUPPORT))) {
            throw AuthenticationFailure.Rejected(AuthErrorCode.FORBIDDEN)
        }

        val (nextProvider, secretHash) = when (command.action) {
            PaymentProviderConfigAction.REGISTER -> {
                val existing = store.findProvider(command.tenantId, command.providerId)
                if (existing != null) throw AuthenticationFailure.Rejected(AuthErrorCode.CONFLICT)
                val secret = command.apiKeySecret ?: ""
                val masked = if (secret.length > 4) "****" + secret.takeLast(4) else "****"
                val hash = sha256(secret)
                val provider = PaymentProviderConfig(
                    providerId = command.providerId,
                    displayName = command.displayName,
                    status = PaymentProviderStatus.ENABLED,
                    endpointUrl = command.endpointUrl,
                    maskedSecretPreview = masked,
                    incidentReference = command.incidentReference,
                    serverVersion = 1L,
                )
                provider to hash
            }
            PaymentProviderConfigAction.ENABLE -> {
                val existing = store.findProvider(command.tenantId, command.providerId)
                    ?: throw AuthenticationFailure.Rejected(AuthErrorCode.FORBIDDEN)
                if (existing.serverVersion != command.expectedVersion) throw AuthenticationFailure.Rejected(AuthErrorCode.STALE)
                if (existing.status == PaymentProviderStatus.ENABLED) throw AuthenticationFailure.Rejected(AuthErrorCode.CONFLICT)
                if (command.incidentReference.isNullOrBlank()) {
                    throw AuthenticationFailure.Rejected(AuthErrorCode.INVALID)
                }
                val provider = existing.copy(
                    status = PaymentProviderStatus.ENABLED,
                    incidentReference = command.incidentReference,
                    serverVersion = existing.serverVersion + 1,
                )
                provider to ""
            }
            PaymentProviderConfigAction.DISABLE -> {
                val existing = store.findProvider(command.tenantId, command.providerId)
                    ?: throw AuthenticationFailure.Rejected(AuthErrorCode.FORBIDDEN)
                if (existing.serverVersion != command.expectedVersion) throw AuthenticationFailure.Rejected(AuthErrorCode.STALE)
                if (existing.status == PaymentProviderStatus.DISABLED) throw AuthenticationFailure.Rejected(AuthErrorCode.CONFLICT)
                if (command.incidentReference.isNullOrBlank()) {
                    throw AuthenticationFailure.Rejected(AuthErrorCode.INVALID)
                }
                val provider = existing.copy(
                    status = PaymentProviderStatus.DISABLED,
                    incidentReference = command.incidentReference,
                    serverVersion = existing.serverVersion + 1,
                )
                provider to ""
            }
            PaymentProviderConfigAction.UPDATE_CONFIG -> {
                val existing = store.findProvider(command.tenantId, command.providerId)
                    ?: throw AuthenticationFailure.Rejected(AuthErrorCode.FORBIDDEN)
                if (existing.serverVersion != command.expectedVersion) throw AuthenticationFailure.Rejected(AuthErrorCode.STALE)
                val (masked, hash) = if (!command.apiKeySecret.isNullOrBlank()) {
                    val m = if (command.apiKeySecret.length > 4) "****" + command.apiKeySecret.takeLast(4) else "****"
                    m to sha256(command.apiKeySecret)
                } else {
                    existing.maskedSecretPreview to ""
                }
                val provider = existing.copy(
                    displayName = command.displayName,
                    endpointUrl = command.endpointUrl,
                    maskedSecretPreview = masked,
                    incidentReference = command.incidentReference ?: existing.incidentReference,
                    serverVersion = existing.serverVersion + 1,
                )
                provider to hash
            }
        }

        val resultId = UUID.randomUUID()
        val result = PaymentProviderConfigResult(
            resultId = resultId,
            provider = nextProvider,
            serverTime = now,
            evidenceReference = "provider-config:$resultId",
        )

        val type = "PROVIDER_CONFIG_${command.action.name}"
        val audit = AuditEvent(UUID.randomUUID(), resultId, command.tenantId, type, now, command.correlationId, command.causationId)
        val outbox = OutboxEvent(UUID.randomUUID(), resultId, command.tenantId, type, now)
        store.save(result, command.tenantId, secretHash, fingerprint, command.idempotencyKey, audit, outbox)
        return result
    }

    private fun fingerprint(command: PaymentProviderConfigCommand): String = listOf(
        command.tenantId,
        command.providerId,
        command.action,
        command.displayName,
        command.endpointUrl,
        command.incidentReference,
        command.expectedVersion,
    ).joinToString("|") { sha256(it.toString()) }

    private fun sha256(value: String): String = MessageDigest.getInstance("SHA-256")
        .digest(value.toByteArray(Charsets.UTF_8))
        .joinToString("") { "%02x".format(it) }
}
