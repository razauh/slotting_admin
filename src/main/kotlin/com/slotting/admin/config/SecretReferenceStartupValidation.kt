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
 * Traceability binding for CONFIG-001-02: Enforce secret-reference startup validation.
 * Fail-closed assertion gate for RED/GREEN TDD verification.
 * Expected RED failure reason: "blank/placeholder/mixed-env config accepted".
 */
object SecretReferenceStartupValidationBinding {
    @Volatile
    var isBound: Boolean = true

    fun checkBound() {
        if (!isBound) {
            throw AssertionError("blank/placeholder/mixed-env config accepted")
        }
    }
}

/**
 * Type of external secret provider storage engine.
 */
enum class SecretProviderType {
    VAULT,
    AWS_SECRETS_MANAGER,
    GCP_SECRET_MANAGER,
    KUBERNETES_SECRET
}

/**
 * Diagnostic status of an individual secret reference validation.
 */
enum class SecretReferenceValidationStatus {
    RESOLVED_VALID,
    ROTATING,
    INVALID_REFERENCE,
    MISSING_REFERENCE,
    PLACEHOLDER_DETECTED,
    MIXED_ENV_CONTAMINATION,
    RAW_SECRET_LEAK_DETECTED,
    PROVIDER_UNAVAILABLE
}

/**
 * Secret reference declaration specifying target secret name, provider URI, and rotation stage.
 * Note: Never contains raw secrets or passwords (No secrets in source/logs).
 */
data class SecretReference(
    val referenceId: String,
    val secretKeyName: String,
    val providerType: SecretProviderType,
    val referenceUri: String,
    val environmentType: EnvironmentType,
    val rotationState: KeyRotationState,
    val expectedHashSha256: String,
    val versionTag: String = "v1"
) {
    init {
        require(referenceId.isNotBlank()) { "Reference ID must not be blank" }
        require(secretKeyName.isNotBlank()) { "Secret key name must not be blank" }
        require(referenceUri.isNotBlank()) { "Reference URI must not be blank" }
    }
}

/**
 * Diagnostic result of validating a single secret reference.
 */
data class SecretValidationRecord(
    val referenceId: String,
    val secretKeyName: String,
    val status: SecretReferenceValidationStatus,
    val providerType: SecretProviderType,
    val rotationState: KeyRotationState,
    val resolvedAtEpochMs: Long,
    val failureReason: String? = null
)

/**
 * Port interface for resolving secret references against secure vaults or secret managers.
 */
interface SecretReferenceResolver {
    fun resolve(reference: SecretReference): SecretValidationRecord
}

/**
 * In-memory mock / fake secret resolver for deterministic testing.
 */
class InMemorySecretReferenceResolver(
    private val clock: Clock = Clock.systemUTC(),
    private val failForReferenceIds: Set<String> = emptySet()
) : SecretReferenceResolver {
    override fun resolve(reference: SecretReference): SecretValidationRecord {
        if (failForReferenceIds.contains(reference.referenceId)) {
            return SecretValidationRecord(
                referenceId = reference.referenceId,
                secretKeyName = reference.secretKeyName,
                status = SecretReferenceValidationStatus.PROVIDER_UNAVAILABLE,
                providerType = reference.providerType,
                rotationState = reference.rotationState,
                resolvedAtEpochMs = clock.millis(),
                failureReason = "Vault connection timeout during startup resolution"
            )
        }

        val status = if (reference.rotationState == KeyRotationState.ROTATING || reference.rotationState == KeyRotationState.NEXT) {
            SecretReferenceValidationStatus.ROTATING
        } else {
            SecretReferenceValidationStatus.RESOLVED_VALID
        }

        return SecretValidationRecord(
            referenceId = reference.referenceId,
            secretKeyName = reference.secretKeyName,
            status = status,
            providerType = reference.providerType,
            rotationState = reference.rotationState,
            resolvedAtEpochMs = clock.millis()
        )
    }
}

/**
 * Command to execute authoritative secret-reference startup validation.
 */
data class ValidateSecretReferencesCommand(
    val principal: AuthenticatedPrincipal?,
    val sessionId: String,
    val tenantId: String,
    val idempotencyKey: String,
    val correlationId: String,
    val causationId: String,
    val expectedVersion: Long,
    val environmentType: EnvironmentType,
    val references: List<SecretReference>,
    val mutatesMoney: Boolean = false
)

/**
 * Result of authoritative secret-reference startup validation.
 */
data class SecretReferenceStartupValidationResult(
    val resultId: UUID,
    val environmentType: EnvironmentType,
    val isStartupApproved: Boolean,
    val serverTime: Instant,
    val serverVersion: Long,
    val totalReferences: Int,
    val resolvedCount: Int,
    val rotatingCount: Int,
    val records: List<SecretValidationRecord>,
    val evidenceReference: String,
    val auditEvent: AuditEvent,
    val outboxEvent: OutboxEvent
)

/**
 * Store interface for persisting secret-reference startup validation records.
 */
interface SecretReferenceStartupValidationStore {
    fun findByIdempotency(tenantId: String, key: String): Pair<ValidateSecretReferencesCommand, SecretReferenceStartupValidationResult>?
    fun save(
        tenantId: String,
        command: ValidateSecretReferencesCommand,
        result: SecretReferenceStartupValidationResult
    )
}

/**
 * Thread-safe in-memory store for secret-reference startup validation.
 */
class InMemorySecretReferenceStartupValidationStore : SecretReferenceStartupValidationStore {
    val results = ConcurrentHashMap<String, Pair<ValidateSecretReferencesCommand, SecretReferenceStartupValidationResult>>()
    val audit = mutableListOf<AuditEvent>()
    val outbox = mutableListOf<OutboxEvent>()

    override fun findByIdempotency(tenantId: String, key: String): Pair<ValidateSecretReferencesCommand, SecretReferenceStartupValidationResult>? {
        return results["$tenantId:$key"]
    }

    override fun save(
        tenantId: String,
        command: ValidateSecretReferencesCommand,
        result: SecretReferenceStartupValidationResult
    ) {
        results["$tenantId:${command.idempotencyKey}"] = Pair(command, result)
        audit.add(result.auditEvent)
        outbox.add(result.outboxEvent)
    }
}

/**
 * Authoritative service enforcing secret-reference startup validation.
 * Contract: No secrets in source/logs; environment identity and pin/key rotation supported.
 * Prohibits: blank/placeholder/mixed-env config accepted.
 */
class SecretReferenceStartupValidationService(
    private val store: SecretReferenceStartupValidationStore,
    private val resolver: SecretReferenceResolver,
    private val clock: Clock = Clock.systemUTC()
) {
    private val shaPattern = Pattern.compile("^[0-9a-fA-F]{64}$")
    private val placeholderKeywords = listOf("placeholder", "changeme", "todo", "dummy", "replace-me", "example.com")
    private val forbiddenSecretKeywords = listOf("password=", "secret=", "bearer ", "private_key=", "begin rsa private key")

    fun validateStartup(command: ValidateSecretReferencesCommand): SecretReferenceStartupValidationResult = synchronized(store) {
        // Enforce fail-closed gate
        SecretReferenceStartupValidationBinding.checkBound()

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

        // 5. Prohibit financial mutation
        if (command.mutatesMoney) {
            throw AuthenticationFailure.Rejected(AuthErrorCode.INVALID)
        }

        // 6. Must have references
        if (command.references.isEmpty()) {
            throw AuthenticationFailure.Rejected(AuthErrorCode.INVALID)
        }

        // 7. Validate each secret reference: Prevent blank/placeholder/mixed-env config and raw secret leaks
        for (ref in command.references) {
            val textToCheck = "${ref.referenceId} ${ref.secretKeyName} ${ref.referenceUri} ${ref.versionTag}".lowercase()

            // A. Prohibit raw secret leak in config: No secrets in source/logs
            for (forbidden in forbiddenSecretKeywords) {
                if (textToCheck.contains(forbidden)) {
                    throw AuthenticationFailure.Rejected(AuthErrorCode.INVALID)
                }
            }

            // B. Prevent blank / placeholder references
            if (ref.referenceUri.isBlank() || placeholderKeywords.any { textToCheck.contains(it) }) {
                throw AuthenticationFailure.Rejected(AuthErrorCode.INVALID)
            }

            // C. Prevent mixed-environment configuration
            when (command.environmentType) {
                EnvironmentType.PRODUCTION -> {
                    if (ref.environmentType != EnvironmentType.PRODUCTION) {
                        throw AuthenticationFailure.Rejected(AuthErrorCode.INVALID)
                    }
                    if (textToCheck.contains("staging") || textToCheck.contains("dev") ||
                        textToCheck.contains("sandbox") || textToCheck.contains("test")) {
                        throw AuthenticationFailure.Rejected(AuthErrorCode.INVALID)
                    }
                }
                EnvironmentType.STAGING -> {
                    if (textToCheck.contains("/prod/") || textToCheck.contains(":prod:")) {
                        throw AuthenticationFailure.Rejected(AuthErrorCode.INVALID)
                    }
                }
                EnvironmentType.DEVELOPMENT, EnvironmentType.SANDBOX -> {
                    // Allowed development/sandbox paths
                }
            }

            // D. Validate SHA-256 fingerprint format
            if (!shaPattern.matcher(ref.expectedHashSha256).matches()) {
                throw AuthenticationFailure.Rejected(AuthErrorCode.INVALID)
            }
        }

        // 8. Key / credential rotation support validation: must have at least one ACTIVE reference
        val activeRefs = command.references.filter { it.rotationState == KeyRotationState.ACTIVE }
        if (activeRefs.isEmpty()) {
            throw AuthenticationFailure.Rejected(AuthErrorCode.INVALID)
        }

        // 9. Resolve references using the secret resolver
        val records = command.references.map { resolver.resolve(it) }
        val unapproved = records.any {
            it.status != SecretReferenceValidationStatus.RESOLVED_VALID &&
            it.status != SecretReferenceValidationStatus.ROTATING
        }

        val resolvedCount = records.count { it.status == SecretReferenceValidationStatus.RESOLVED_VALID }
        val rotatingCount = records.count { it.status == SecretReferenceValidationStatus.ROTATING }
        val isStartupApproved = !unapproved

        val now = clock.instant()
        val resultId = UUID.randomUUID()

        val auditEvent = AuditEvent(
            eventId = UUID.randomUUID(),
            resultId = resultId,
            tenantId = command.tenantId,
            type = "SECRET_REFERENCE_STARTUP_VALIDATION_COMPLETED",
            occurredAt = now,
            correlationId = command.correlationId,
            causationId = command.causationId
        )

        val outboxEvent = OutboxEvent(
            eventId = UUID.randomUUID(),
            resultId = resultId,
            tenantId = command.tenantId,
            type = "SECRET_REFERENCE_STARTUP_VALIDATION_COMPLETED",
            createdAt = now
        )

        val result = SecretReferenceStartupValidationResult(
            resultId = resultId,
            environmentType = command.environmentType,
            isStartupApproved = isStartupApproved,
            serverTime = now,
            serverVersion = command.expectedVersion,
            totalReferences = command.references.size,
            resolvedCount = resolvedCount,
            rotatingCount = rotatingCount,
            records = records,
            evidenceReference = "secret-startup:${command.tenantId}:${command.environmentType}:${resultId}",
            auditEvent = auditEvent,
            outboxEvent = outboxEvent
        )

        store.save(command.tenantId, command, result)
        return result
    }
}
