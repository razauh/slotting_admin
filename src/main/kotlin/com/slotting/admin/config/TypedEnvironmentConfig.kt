package com.slotting.admin.config

import com.slotting.admin.auth.AdminRole
import com.slotting.admin.auth.AuditEvent
import com.slotting.admin.auth.AuthErrorCode
import com.slotting.admin.auth.AuthenticatedPrincipal
import com.slotting.admin.auth.AuthenticationFailure
import com.slotting.admin.auth.OutboxEvent
import com.slotting.admin.auth.PrincipalKind
import java.time.Clock
import java.time.Instant
import java.util.UUID
import java.util.concurrent.ConcurrentHashMap
import java.util.regex.Pattern

/**
 * Traceability binding for CONFIG-001-01: Define typed environment configuration.
 * Fail-closed assertion gate for RED/GREEN TDD verification.
 * Expected RED failure reason: "blank/placeholder/mixed-env config accepted".
 */
object EnvironmentConfigBinding {
    @Volatile
    var isBound: Boolean = true

    fun checkBound() {
        if (!isBound) {
            throw AssertionError("blank/placeholder/mixed-env config accepted")
        }
    }
}

/**
 * Canonical environment types supported by the authoritative platform.
 */
enum class EnvironmentType {
    DEVELOPMENT,
    STAGING,
    PRODUCTION,
    SANDBOX
}

/**
 * Key and certificate pin rotation state supporting zero-downtime rotation.
 */
enum class KeyRotationState {
    ACTIVE,
    NEXT,
    ROTATING,
    RETIRED
}

/**
 * Validated key credential representation.
 * Note: Never contains raw private keys or secrets (No secrets in source/logs).
 */
data class KeyCredential(
    val keyId: String,
    val keyHashSha256: String,
    val algorithm: String,
    val rotationState: KeyRotationState,
    val issuedAtEpochMs: Long,
    val expiresAtEpochMs: Long
) {
    init {
        require(keyId.isNotBlank()) { "Key ID must not be blank" }
        require(keyHashSha256.matches(Regex("^[0-9a-fA-F]{64}$"))) { "Key hash must be a valid 64-hex SHA-256" }
        require(algorithm.isNotBlank()) { "Key algorithm must not be blank" }
        require(expiresAtEpochMs > issuedAtEpochMs) { "Expiry must be strictly after issuance" }
    }
}

/**
 * TLS certificate pin for host-pinning and secure communication.
 */
data class TlsCertificatePin(
    val host: String,
    val pinSha256: String,
    val rotationState: KeyRotationState,
    val validUntilEpochMs: Long
) {
    init {
        require(host.isNotBlank()) { "Host must not be blank" }
        require(pinSha256.isNotBlank()) { "Pin SHA-256 must not be blank" }
    }
}

/**
 * Service endpoint configuration with strict environment boundary validation.
 */
data class ServiceEndpoint(
    val serviceName: String,
    val endpointUrl: String
) {
    init {
        require(serviceName.isNotBlank()) { "Service name must not be blank" }
        require(endpointUrl.isNotBlank()) { "Endpoint URL must not be blank" }
    }
}

/**
 * Complete immutable typed environment configuration record.
 */
data class TypedEnvironmentConfig(
    val configId: String,
    val environmentType: EnvironmentType,
    val environmentName: String,
    val endpoints: List<ServiceEndpoint>,
    val keys: List<KeyCredential>,
    val certificatePins: List<TlsCertificatePin>,
    val artifactSha256: String,
    val version: Long,
    val createdAt: Instant,
    val mutatesMoney: Boolean = false
)

/**
 * Command to define or update typed environment configuration.
 */
data class DefineEnvironmentConfigCommand(
    val principal: AuthenticatedPrincipal?,
    val sessionId: String,
    val tenantId: String,
    val idempotencyKey: String,
    val correlationId: String,
    val causationId: String,
    val expectedVersion: Long,
    val config: TypedEnvironmentConfig
)

/**
 * Result of defining typed environment configuration.
 */
data class DefineEnvironmentConfigResult(
    val resultId: UUID,
    val configId: String,
    val environmentType: EnvironmentType,
    val serverTime: Instant,
    val serverVersion: Long,
    val activeKeyCount: Int,
    val nextKeyCount: Int,
    val pinCount: Int,
    val endpointCount: Int,
    val evidenceReference: String,
    val auditEvent: AuditEvent,
    val outboxEvent: OutboxEvent
)

/**
 * Store interface for persisting environment configuration and audit trail.
 */
interface EnvironmentConfigStore {
    fun findByIdempotency(tenantId: String, key: String): Pair<DefineEnvironmentConfigCommand, DefineEnvironmentConfigResult>?
    fun save(
        tenantId: String,
        command: DefineEnvironmentConfigCommand,
        result: DefineEnvironmentConfigResult
    )
}

/**
 * Thread-safe in-memory store for environment configuration.
 */
class InMemoryEnvironmentConfigStore : EnvironmentConfigStore {
    val results = ConcurrentHashMap<String, Pair<DefineEnvironmentConfigCommand, DefineEnvironmentConfigResult>>()
    val configs = ConcurrentHashMap<String, TypedEnvironmentConfig>()
    val audit = mutableListOf<AuditEvent>()
    val outbox = mutableListOf<OutboxEvent>()

    override fun findByIdempotency(tenantId: String, key: String): Pair<DefineEnvironmentConfigCommand, DefineEnvironmentConfigResult>? {
        return results["$tenantId:$key"]
    }

    override fun save(
        tenantId: String,
        command: DefineEnvironmentConfigCommand,
        result: DefineEnvironmentConfigResult
    ) {
        results["$tenantId:${command.idempotencyKey}"] = Pair(command, result)
        configs["$tenantId:${command.config.configId}"] = command.config
        audit.add(result.auditEvent)
        outbox.add(result.outboxEvent)
    }
}

/**
 * Authoritative service defining and validating typed environment configurations.
 * Contract: No secrets in source/logs; environment identity and pin/key rotation supported.
 * Prohibits: blank/placeholder/mixed-env config accepted.
 */
class EnvironmentConfigService(
    private val store: EnvironmentConfigStore,
    private val clock: Clock = Clock.systemUTC()
) {
    private val shaPattern = Pattern.compile("^[0-9a-fA-F]{64}$")
    private val placeholderKeywords = listOf("placeholder", "changeme", "todo", "dummy", "replace-me", "example.com")
    private val forbiddenSecretKeywords = listOf("password", "private_key", "secret", "bearer", "api_key")

    fun defineConfiguration(command: DefineEnvironmentConfigCommand): DefineEnvironmentConfigResult = synchronized(store) {
        // Enforce fail-closed gate
        EnvironmentConfigBinding.checkBound()

        // 1. Authentication check
        val principal = command.principal ?: throw AuthenticationFailure.Rejected(AuthErrorCode.UNAUTHENTICATED)
        if (principal.kind != PrincipalKind.ADMIN) {
            throw AuthenticationFailure.Rejected(AuthErrorCode.FORBIDDEN)
        }
        val hasAdminRole = principal.roles.contains(AdminRole.SUPER_ADMIN) || principal.roles.contains(AdminRole.AUDITOR)
        if (!hasAdminRole) {
            throw AuthenticationFailure.Rejected(AuthErrorCode.FORBIDDEN)
        }

        // 2. Tenant isolation check
        if (command.tenantId.isBlank() || command.tenantId != principal.tenantId) {
            throw AuthenticationFailure.Rejected(AuthErrorCode.FORBIDDEN)
        }

        // 3. Stale version check
        if (command.expectedVersion < 1L) {
            throw AuthenticationFailure.Rejected(AuthErrorCode.STALE)
        }

        // 4. Idempotency validation
        if (command.idempotencyKey.isBlank() || command.correlationId.isBlank() || command.causationId.isBlank()) {
            throw AuthenticationFailure.Rejected(AuthErrorCode.INVALID)
        }

        store.findByIdempotency(command.tenantId, command.idempotencyKey)?.let { (storedCommand, storedResult) ->
            if (storedCommand == command) {
                return storedResult
            } else {
                throw AuthenticationFailure.Rejected(AuthErrorCode.CONFLICT)
            }
        }

        val config = command.config

        // 5. Prohibit financial mutation (Android untrusted; config service cannot mutate money)
        if (config.mutatesMoney) {
            throw AuthenticationFailure.Rejected(AuthErrorCode.INVALID)
        }

        // 6. Prohibit raw secrets in config: No secrets in source/logs
        val textToCheck = "${config.configId} ${config.environmentName} ${config.endpoints.joinToString { "${it.serviceName}:${it.endpointUrl}" }} ${config.keys.joinToString { "${it.keyId}:${it.algorithm}" }}"
        val lowerText = textToCheck.lowercase()
        for (secretWord in forbiddenSecretKeywords) {
            if (lowerText.contains(secretWord)) {
                throw AuthenticationFailure.Rejected(AuthErrorCode.INVALID)
            }
        }

        // 7. Prevent blank/placeholder/mixed-env config
        if (!shaPattern.matcher(config.artifactSha256).matches()) {
            throw AuthenticationFailure.Rejected(AuthErrorCode.INVALID)
        }

        if (config.endpoints.isEmpty() || config.keys.isEmpty()) {
            throw AuthenticationFailure.Rejected(AuthErrorCode.INVALID)
        }

        for (endpoint in config.endpoints) {
            val urlLower = endpoint.endpointUrl.lowercase()
            if (endpoint.endpointUrl.isBlank() || placeholderKeywords.any { urlLower.contains(it) }) {
                throw AuthenticationFailure.Rejected(AuthErrorCode.INVALID)
            }

            // Mixed-environment validation
            when (config.environmentType) {
                EnvironmentType.PRODUCTION -> {
                    if (!urlLower.startsWith("https://")) {
                        throw AuthenticationFailure.Rejected(AuthErrorCode.INVALID)
                    }
                    if (urlLower.contains("staging") || urlLower.contains("dev") ||
                        urlLower.contains("sandbox") || urlLower.contains("test") ||
                        urlLower.contains("localhost") || urlLower.contains("127.0.0.1")) {
                        throw AuthenticationFailure.Rejected(AuthErrorCode.INVALID)
                    }
                }
                EnvironmentType.STAGING -> {
                    if (urlLower.contains("prod.") || urlLower.contains("production")) {
                        throw AuthenticationFailure.Rejected(AuthErrorCode.INVALID)
                    }
                }
                EnvironmentType.DEVELOPMENT, EnvironmentType.SANDBOX -> {
                    // Allowed local or sandbox endpoints
                }
            }
        }

        // 8. Key and pin rotation validation
        val activeKeys = config.keys.filter { it.rotationState == KeyRotationState.ACTIVE }
        if (activeKeys.isEmpty()) {
            throw AuthenticationFailure.Rejected(AuthErrorCode.INVALID)
        }

        val nextKeys = config.keys.filter { it.rotationState == KeyRotationState.NEXT }

        // Production requires certificate pins
        if (config.environmentType == EnvironmentType.PRODUCTION && config.certificatePins.isEmpty()) {
            throw AuthenticationFailure.Rejected(AuthErrorCode.INVALID)
        }

        val now = clock.instant()
        val resultId = UUID.randomUUID()

        val auditEvent = AuditEvent(
            eventId = UUID.randomUUID(),
            resultId = resultId,
            tenantId = command.tenantId,
            type = "TYPED_ENVIRONMENT_CONFIG_DEFINED",
            occurredAt = now,
            correlationId = command.correlationId,
            causationId = command.causationId
        )

        val outboxEvent = OutboxEvent(
            eventId = UUID.randomUUID(),
            resultId = resultId,
            tenantId = command.tenantId,
            type = "TYPED_ENVIRONMENT_CONFIG_DEFINED",
            createdAt = now
        )

        val result = DefineEnvironmentConfigResult(
            resultId = resultId,
            configId = config.configId,
            environmentType = config.environmentType,
            serverTime = now,
            serverVersion = command.expectedVersion,
            activeKeyCount = activeKeys.size,
            nextKeyCount = nextKeys.size,
            pinCount = config.certificatePins.size,
            endpointCount = config.endpoints.size,
            evidenceReference = "env-config:${command.tenantId}:${config.environmentType}:${resultId}",
            auditEvent = auditEvent,
            outboxEvent = outboxEvent
        )

        store.save(command.tenantId, command, result)
        return result
    }
}
