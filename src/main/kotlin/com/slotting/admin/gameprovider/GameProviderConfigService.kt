package com.slotting.admin.gameprovider

import com.slotting.admin.auth.*
import java.security.MessageDigest
import java.time.Clock
import java.time.Instant
import java.util.UUID

enum class GameProviderStatus { ENABLED, DISABLED, SUSPENDED }
enum class GameProviderConfigAction { REGISTER, UPDATE_CONFIG, ENABLE, DISABLE }

data class GameProviderConfigCommand(
    val principal: AuthenticatedPrincipal?,
    val sessionId: String,
    val tenantId: String,
    val providerId: String,
    val action: GameProviderConfigAction,
    val displayName: String,
    val endpointUrl: String,
    val apiKeySecret: String? = null,
    val incidentReference: String? = null,
    val idempotencyKey: String,
    val correlationId: String,
    val causationId: String,
    val expectedVersion: Long,
)

data class GameProviderConfig(
    val providerId: String,
    val displayName: String,
    val status: GameProviderStatus,
    val endpointUrl: String,
    val maskedSecretPreview: String,
    val incidentReference: String?,
    val serverVersion: Long,
)

data class GameProviderConfigResult(
    val resultId: UUID,
    val provider: GameProviderConfig,
    val serverTime: Instant,
    val evidenceReference: String,
)

interface GameProviderConfigStore {
    fun findByIdempotency(tenantId: String, key: String): Pair<String, GameProviderConfigResult>?
    fun findProvider(tenantId: String, providerId: String): GameProviderConfig?
    fun save(
        result: GameProviderConfigResult,
        tenantId: String,
        secretHash: String,
        queryFingerprint: String,
        idempotencyKey: String,
        audit: AuditEvent,
        outbox: OutboxEvent,
    )
}

class GameProviderConfigService(
    private val policy: AdminRbacPolicy,
    private val sessions: AdminSessionDirectory,
    private val store: GameProviderConfigStore,
    private val clock: Clock = Clock.systemUTC(),
) {
    @Synchronized
    fun operate(command: GameProviderConfigCommand): GameProviderConfigResult {
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
            GameProviderConfigAction.REGISTER -> {
                val existing = store.findProvider(command.tenantId, command.providerId)
                if (existing != null) throw AuthenticationFailure.Rejected(AuthErrorCode.CONFLICT)
                val secret = command.apiKeySecret ?: ""
                val masked = if (secret.length > 4) "****" + secret.takeLast(4) else "****"
                val hash = sha256(secret)
                val provider = GameProviderConfig(
                    providerId = command.providerId,
                    displayName = command.displayName,
                    status = GameProviderStatus.ENABLED,
                    endpointUrl = command.endpointUrl,
                    maskedSecretPreview = masked,
                    incidentReference = command.incidentReference,
                    serverVersion = 1L,
                )
                provider to hash
            }
            GameProviderConfigAction.ENABLE -> {
                val existing = store.findProvider(command.tenantId, command.providerId)
                    ?: throw AuthenticationFailure.Rejected(AuthErrorCode.FORBIDDEN)
                if (existing.serverVersion != command.expectedVersion) throw AuthenticationFailure.Rejected(AuthErrorCode.STALE)
                if (existing.status == GameProviderStatus.ENABLED) throw AuthenticationFailure.Rejected(AuthErrorCode.CONFLICT)
                if (command.incidentReference.isNullOrBlank()) {
                    throw AuthenticationFailure.Rejected(AuthErrorCode.INVALID)
                }
                val provider = existing.copy(
                    status = GameProviderStatus.ENABLED,
                    incidentReference = command.incidentReference,
                    serverVersion = existing.serverVersion + 1,
                )
                provider to ""
            }
            GameProviderConfigAction.DISABLE -> {
                val existing = store.findProvider(command.tenantId, command.providerId)
                    ?: throw AuthenticationFailure.Rejected(AuthErrorCode.FORBIDDEN)
                if (existing.serverVersion != command.expectedVersion) throw AuthenticationFailure.Rejected(AuthErrorCode.STALE)
                if (existing.status == GameProviderStatus.DISABLED) throw AuthenticationFailure.Rejected(AuthErrorCode.CONFLICT)
                if (command.incidentReference.isNullOrBlank()) {
                    throw AuthenticationFailure.Rejected(AuthErrorCode.INVALID)
                }
                val provider = existing.copy(
                    status = GameProviderStatus.DISABLED,
                    incidentReference = command.incidentReference,
                    serverVersion = existing.serverVersion + 1,
                )
                provider to ""
            }
            GameProviderConfigAction.UPDATE_CONFIG -> {
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
        val result = GameProviderConfigResult(
            resultId = resultId,
            provider = nextProvider,
            serverTime = now,
            evidenceReference = "game-provider-config:$resultId",
        )

        val type = "GAME_PROVIDER_CONFIG_${command.action.name}"
        val audit = AuditEvent(UUID.randomUUID(), resultId, command.tenantId, type, now, command.correlationId, command.causationId)
        val outbox = OutboxEvent(UUID.randomUUID(), resultId, command.tenantId, type, now)
        store.save(result, command.tenantId, secretHash, fingerprint, command.idempotencyKey, audit, outbox)
        return result
    }

    private fun fingerprint(command: GameProviderConfigCommand): String = listOf(
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
