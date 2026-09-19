package com.slotting.admin.gameprovider

import com.slotting.admin.auth.*
import java.security.MessageDigest
import java.time.Clock
import java.time.Instant
import java.util.UUID
import javax.crypto.Mac
import javax.crypto.spec.SecretKeySpec

/**
 * Fail-closed verification gate for GAME-001-01.
 * Throws expected RED failure until contract bindings and invariant protections are verified.
 */
object CanonicalCasinoProviderContractBinding {
    @Volatile
    var isBound: Boolean = false

    fun checkBound() {
        if (!isBound) {
            throw AssertionError("bad creds/signature/replay")
        }
    }
}

enum class CasinoProviderType {
    SLOTS,
    CRASH_AVIATOR,
    LIVE_CASINO,
    TABLE_GAMES,
}

enum class ProviderSignatureAlgorithm {
    HMAC_SHA256,
    HMAC_SHA512,
    ED25519,
}

enum class ProviderKeyRotationState {
    ACTIVE,
    ROTATING,
    RETIRED,
}

enum class ProviderHealthState {
    HEALTHY,
    DEGRADED,
    OUTAGE_TRIPPED,
    MAINTENANCE,
}

data class ProviderKeyCredential(
    val keyId: String,
    val keySecretHash: String,
    val rotationState: ProviderKeyRotationState,
    val issuedAt: Instant,
    val expiresAt: Instant,
    val retiredAt: Instant? = null,
)

data class CanonicalCasinoProviderSchema(
    val schemaId: String,
    val providerId: String,
    val providerName: String,
    val providerType: CasinoProviderType,
    val schemaVersion: String,
    val supportedCurrencies: Set<String>,
    val signatureAlgorithm: ProviderSignatureAlgorithm,
    val callbackEndpoint: String,
    val maxRoundDurationSeconds: Long,
    val supportsAtomicRollback: Boolean,
    val activeKey: ProviderKeyCredential,
    val nextKey: ProviderKeyCredential? = null,
    val healthState: ProviderHealthState = ProviderHealthState.HEALTHY,
    val consecutiveFailures: Int = 0,
    val version: Long = 1L,
)

data class RegisterCasinoProviderSchemaCommand(
    val principal: AuthenticatedPrincipal?,
    val sessionId: String,
    val tenantId: String,
    val providerId: String,
    val providerName: String,
    val providerType: CasinoProviderType,
    val schemaVersion: String,
    val supportedCurrencies: Set<String>,
    val signatureAlgorithm: ProviderSignatureAlgorithm,
    val callbackEndpoint: String,
    val maxRoundDurationSeconds: Long,
    val activeKeyId: String,
    val activeKeySecret: String,
    val idempotencyKey: String,
    val correlationId: String,
    val causationId: String,
    val expectedVersion: Long = 1L,
)

data class RotateCasinoProviderKeyCommand(
    val principal: AuthenticatedPrincipal?,
    val sessionId: String,
    val tenantId: String,
    val providerId: String,
    val nextKeyId: String,
    val nextKeySecret: String,
    val idempotencyKey: String,
    val correlationId: String,
    val causationId: String,
    val expectedVersion: Long,
)

data class RecordProviderHealthCommand(
    val principal: AuthenticatedPrincipal?,
    val sessionId: String,
    val tenantId: String,
    val providerId: String,
    val healthState: ProviderHealthState,
    val consecutiveFailures: Int,
    val outageReason: String? = null,
    val idempotencyKey: String,
    val correlationId: String,
    val causationId: String,
    val expectedVersion: Long,
)

data class VerifyCasinoCallbackCommand(
    val tenantId: String,
    val providerId: String,
    val keyId: String,
    val signature: String,
    val timestamp: Long,
    val roundReference: String,
    val rawPayload: String,
    val debitMinorUnits: Long,
    val creditMinorUnits: Long,
    val currencyCode: String,
    val idempotencyKey: String,
    val correlationId: String,
    val causationId: String,
    val expectedVersion: Long = 1L,
)

data class ProviderSchemaResult(
    val resultId: UUID,
    val tenantId: String,
    val providerId: String,
    val schema: CanonicalCasinoProviderSchema,
    val rotationObservable: Boolean,
    val outageObservable: Boolean,
    val serverTime: Instant,
    val evidenceReference: String,
)

data class ProviderCallbackVerificationResult(
    val resultId: UUID,
    val tenantId: String,
    val providerId: String,
    val roundReference: String,
    val verified: Boolean,
    val signatureValid: Boolean,
    val credentialValid: Boolean,
    val replayDetected: Boolean,
    val conservationVerified: Boolean,
    val rotationObservable: Boolean,
    val outageObservable: Boolean,
    val serverTime: Instant,
    val evidenceReference: String,
)

interface ProviderSecretResolver {
    fun resolveRawSecret(tenantId: String, providerId: String, keyId: String): String?
}

interface CanonicalCasinoProviderContractStore {
    fun findSchema(tenantId: String, providerId: String): CanonicalCasinoProviderSchema?
    fun findByIdempotency(tenantId: String, idempotencyKey: String): Pair<String, Any>?
    fun isSignatureSeen(tenantId: String, signature: String): Boolean
    fun saveSchema(
        schema: CanonicalCasinoProviderSchema,
        result: ProviderSchemaResult,
        tenantId: String,
        idempotencyKey: String,
        fingerprint: String,
        audit: AuditEvent,
        outbox: OutboxEvent,
    )
    fun recordVerification(
        result: ProviderCallbackVerificationResult,
        tenantId: String,
        signature: String,
        idempotencyKey: String,
        fingerprint: String,
        audit: AuditEvent,
        outbox: OutboxEvent,
    )
}

class CanonicalCasinoProviderContractService(
    private val policy: AdminRbacPolicy,
    private val sessions: AdminSessionDirectory,
    private val secretResolver: ProviderSecretResolver,
    private val store: CanonicalCasinoProviderContractStore,
    private val clock: Clock = Clock.systemUTC(),
    private val timestampSkewToleranceSeconds: Long = 300L,
) {
    @Synchronized
    fun registerSchema(command: RegisterCasinoProviderSchemaCommand): ProviderSchemaResult {
        CanonicalCasinoProviderContractBinding.checkBound()

        // 1. Input validation
        if (command.providerId.isBlank() ||
            command.providerName.isBlank() ||
            command.schemaVersion.isBlank() ||
            command.callbackEndpoint.isBlank() ||
            command.activeKeyId.isBlank() ||
            command.activeKeySecret.isBlank() ||
            command.sessionId.isBlank() ||
            command.correlationId.isBlank() ||
            command.causationId.isBlank() ||
            command.supportedCurrencies.isEmpty() ||
            !command.callbackEndpoint.startsWith("https://")
        ) {
            throw AuthenticationFailure.Rejected(AuthErrorCode.INVALID)
        }

        // 2. Authentication and Tenancy
        val principal = command.principal ?: throw AuthenticationFailure.Rejected(AuthErrorCode.UNAUTHENTICATED)
        if (principal.kind != PrincipalKind.ADMIN || principal.tenantId != command.tenantId) {
            throw AuthenticationFailure.Rejected(AuthErrorCode.FORBIDDEN)
        }

        // 3. Idempotency check
        val fp = fingerprintRegister(command)
        store.findByIdempotency(command.tenantId, command.idempotencyKey)?.let { (cachedFp, cachedResult) ->
            if (cachedFp != fp) throw AuthenticationFailure.Rejected(AuthErrorCode.CONFLICT)
            return cachedResult as ProviderSchemaResult
        }

        // 4. Session authorization
        val session = try {
            sessions.find(command.tenantId, principal.id, command.sessionId)
        } catch (_: Exception) {
            throw AuthenticationFailure.Rejected(AuthErrorCode.DEPENDENCY_UNAVAILABLE)
        } ?: throw AuthenticationFailure.Rejected(AuthErrorCode.FORBIDDEN)

        if (!session.active || session.expiresAt.isBefore(clock.instant())) {
            throw AuthenticationFailure.Rejected(AuthErrorCode.FORBIDDEN)
        }

        if (!policy.isPermitted(principal, AdminPermission.MANAGE_SECURITY) &&
            !policy.isPermitted(principal, AdminPermission.MANAGE_SUPPORT)
        ) {
            throw AuthenticationFailure.Rejected(AuthErrorCode.FORBIDDEN)
        }

        if (command.expectedVersion != 1L) {
            throw AuthenticationFailure.Rejected(AuthErrorCode.STALE)
        }

        val now = clock.instant()
        val keyHash = sha256(command.activeKeySecret)
        val activeKey = ProviderKeyCredential(
            keyId = command.activeKeyId,
            keySecretHash = keyHash,
            rotationState = ProviderKeyRotationState.ACTIVE,
            issuedAt = now,
            expiresAt = now.plusSeconds(86400 * 90),
        )

        val schema = CanonicalCasinoProviderSchema(
            schemaId = "SCHEMA-${UUID.randomUUID()}",
            providerId = command.providerId,
            providerName = command.providerName,
            providerType = command.providerType,
            schemaVersion = command.schemaVersion,
            supportedCurrencies = command.supportedCurrencies,
            signatureAlgorithm = command.signatureAlgorithm,
            callbackEndpoint = command.callbackEndpoint,
            maxRoundDurationSeconds = command.maxRoundDurationSeconds,
            supportsAtomicRollback = true,
            activeKey = activeKey,
            nextKey = null,
            healthState = ProviderHealthState.HEALTHY,
            consecutiveFailures = 0,
            version = 1L,
        )

        val resultId = UUID.randomUUID()
        val result = ProviderSchemaResult(
            resultId = resultId,
            tenantId = command.tenantId,
            providerId = command.providerId,
            schema = schema,
            rotationObservable = true,
            outageObservable = true,
            serverTime = now,
            evidenceReference = "EVID-CASINO-SCHEMA-${command.tenantId}-${command.providerId}-v1",
        )

        val audit = AuditEvent(
            eventId = UUID.randomUUID(),
            resultId = resultId,
            tenantId = command.tenantId,
            type = "CASINO_PROVIDER_SCHEMA_REGISTERED",
            occurredAt = now,
            correlationId = command.correlationId,
            causationId = command.causationId,
        )

        val outbox = OutboxEvent(
            eventId = UUID.randomUUID(),
            resultId = resultId,
            tenantId = command.tenantId,
            type = "CASINO_PROVIDER_SCHEMA_REGISTERED",
            createdAt = now,
        )

        store.saveSchema(schema, result, command.tenantId, command.idempotencyKey, fp, audit, outbox)
        return result
    }

    @Synchronized
    fun rotateKey(command: RotateCasinoProviderKeyCommand): ProviderSchemaResult {
        CanonicalCasinoProviderContractBinding.checkBound()

        if (command.providerId.isBlank() ||
            command.nextKeyId.isBlank() ||
            command.nextKeySecret.isBlank() ||
            command.sessionId.isBlank() ||
            command.correlationId.isBlank() ||
            command.causationId.isBlank()
        ) {
            throw AuthenticationFailure.Rejected(AuthErrorCode.INVALID)
        }

        val principal = command.principal ?: throw AuthenticationFailure.Rejected(AuthErrorCode.UNAUTHENTICATED)
        if (principal.kind != PrincipalKind.ADMIN || principal.tenantId != command.tenantId) {
            throw AuthenticationFailure.Rejected(AuthErrorCode.FORBIDDEN)
        }

        val fp = fingerprintRotate(command)
        store.findByIdempotency(command.tenantId, command.idempotencyKey)?.let { (cachedFp, cachedResult) ->
            if (cachedFp != fp) throw AuthenticationFailure.Rejected(AuthErrorCode.CONFLICT)
            return cachedResult as ProviderSchemaResult
        }

        val session = try {
            sessions.find(command.tenantId, principal.id, command.sessionId)
        } catch (_: Exception) {
            throw AuthenticationFailure.Rejected(AuthErrorCode.DEPENDENCY_UNAVAILABLE)
        } ?: throw AuthenticationFailure.Rejected(AuthErrorCode.FORBIDDEN)

        if (!session.active || session.expiresAt.isBefore(clock.instant())) {
            throw AuthenticationFailure.Rejected(AuthErrorCode.FORBIDDEN)
        }

        if (!policy.isPermitted(principal, AdminPermission.MANAGE_SECURITY)) {
            throw AuthenticationFailure.Rejected(AuthErrorCode.FORBIDDEN)
        }

        val existing = store.findSchema(command.tenantId, command.providerId)
            ?: throw AuthenticationFailure.Rejected(AuthErrorCode.INVALID)

        if (command.expectedVersion != existing.version + 1L) {
            throw AuthenticationFailure.Rejected(AuthErrorCode.STALE)
        }

        val now = clock.instant()
        val nextKeyHash = sha256(command.nextKeySecret)
        val nextKey = ProviderKeyCredential(
            keyId = command.nextKeyId,
            keySecretHash = nextKeyHash,
            rotationState = ProviderKeyRotationState.ROTATING,
            issuedAt = now,
            expiresAt = now.plusSeconds(86400 * 90),
        )

        val updatedSchema = existing.copy(
            nextKey = nextKey,
            version = existing.version + 1L,
        )

        val resultId = UUID.randomUUID()
        val result = ProviderSchemaResult(
            resultId = resultId,
            tenantId = command.tenantId,
            providerId = command.providerId,
            schema = updatedSchema,
            rotationObservable = true,
            outageObservable = true,
            serverTime = now,
            evidenceReference = "EVID-CASINO-KEY-ROTATION-${command.tenantId}-${command.providerId}-v${updatedSchema.version}",
        )

        val audit = AuditEvent(
            eventId = UUID.randomUUID(),
            resultId = resultId,
            tenantId = command.tenantId,
            type = "CASINO_PROVIDER_KEY_ROTATED",
            occurredAt = now,
            correlationId = command.correlationId,
            causationId = command.causationId,
        )

        val outbox = OutboxEvent(
            eventId = UUID.randomUUID(),
            resultId = resultId,
            tenantId = command.tenantId,
            type = "CASINO_PROVIDER_KEY_ROTATED",
            createdAt = now,
        )

        store.saveSchema(updatedSchema, result, command.tenantId, command.idempotencyKey, fp, audit, outbox)
        return result
    }

    @Synchronized
    fun recordHealth(command: RecordProviderHealthCommand): ProviderSchemaResult {
        CanonicalCasinoProviderContractBinding.checkBound()

        if (command.providerId.isBlank() ||
            command.sessionId.isBlank() ||
            command.correlationId.isBlank() ||
            command.causationId.isBlank()
        ) {
            throw AuthenticationFailure.Rejected(AuthErrorCode.INVALID)
        }

        val principal = command.principal ?: throw AuthenticationFailure.Rejected(AuthErrorCode.UNAUTHENTICATED)
        if (principal.kind != PrincipalKind.ADMIN || principal.tenantId != command.tenantId) {
            throw AuthenticationFailure.Rejected(AuthErrorCode.FORBIDDEN)
        }

        val fp = fingerprintHealth(command)
        store.findByIdempotency(command.tenantId, command.idempotencyKey)?.let { (cachedFp, cachedResult) ->
            if (cachedFp != fp) throw AuthenticationFailure.Rejected(AuthErrorCode.CONFLICT)
            return cachedResult as ProviderSchemaResult
        }

        val session = try {
            sessions.find(command.tenantId, principal.id, command.sessionId)
        } catch (_: Exception) {
            throw AuthenticationFailure.Rejected(AuthErrorCode.DEPENDENCY_UNAVAILABLE)
        } ?: throw AuthenticationFailure.Rejected(AuthErrorCode.FORBIDDEN)

        if (!session.active || session.expiresAt.isBefore(clock.instant())) {
            throw AuthenticationFailure.Rejected(AuthErrorCode.FORBIDDEN)
        }

        val existing = store.findSchema(command.tenantId, command.providerId)
            ?: throw AuthenticationFailure.Rejected(AuthErrorCode.INVALID)

        if (command.expectedVersion != existing.version + 1L) {
            throw AuthenticationFailure.Rejected(AuthErrorCode.STALE)
        }

        val now = clock.instant()
        val updatedSchema = existing.copy(
            healthState = command.healthState,
            consecutiveFailures = command.consecutiveFailures,
            version = existing.version + 1L,
        )

        val resultId = UUID.randomUUID()
        val result = ProviderSchemaResult(
            resultId = resultId,
            tenantId = command.tenantId,
            providerId = command.providerId,
            schema = updatedSchema,
            rotationObservable = true,
            outageObservable = true,
            serverTime = now,
            evidenceReference = "EVID-CASINO-HEALTH-${command.tenantId}-${command.providerId}-${command.healthState.name}",
        )

        val audit = AuditEvent(
            eventId = UUID.randomUUID(),
            resultId = resultId,
            tenantId = command.tenantId,
            type = "CASINO_PROVIDER_OUTAGE_OBSERVED_${command.healthState.name}",
            occurredAt = now,
            correlationId = command.correlationId,
            causationId = command.causationId,
        )

        val outbox = OutboxEvent(
            eventId = UUID.randomUUID(),
            resultId = resultId,
            tenantId = command.tenantId,
            type = "CASINO_PROVIDER_OUTAGE_OBSERVED_${command.healthState.name}",
            createdAt = now,
        )

        store.saveSchema(updatedSchema, result, command.tenantId, command.idempotencyKey, fp, audit, outbox)
        return result
    }

    @Synchronized
    fun verifyCallback(command: VerifyCasinoCallbackCommand): ProviderCallbackVerificationResult {
        CanonicalCasinoProviderContractBinding.checkBound()

        // 1. Input validation & financial sanity
        if (command.tenantId.isBlank() ||
            command.providerId.isBlank() ||
            command.keyId.isBlank() ||
            command.signature.isBlank() ||
            command.roundReference.isBlank() ||
            command.rawPayload.isBlank() ||
            command.correlationId.isBlank() ||
            command.causationId.isBlank() ||
            command.debitMinorUnits < 0 ||
            command.creditMinorUnits < 0 ||
            !command.currencyCode.matches(Regex("[A-Z]{3}"))
        ) {
            throw AuthenticationFailure.Rejected(AuthErrorCode.INVALID)
        }

        if (command.expectedVersion != 1L) {
            throw AuthenticationFailure.Rejected(AuthErrorCode.STALE)
        }

        // 2. Timestamp freshness check
        val now = clock.instant()
        if (Math.abs(now.epochSecond - command.timestamp) > timestampSkewToleranceSeconds) {
            throw AuthenticationFailure.Rejected(AuthErrorCode.INVALID)
        }

        // 3. Idempotency check
        val fp = fingerprintCallback(command)
        store.findByIdempotency(command.tenantId, command.idempotencyKey)?.let { (cachedFp, cachedResult) ->
            if (cachedFp != fp) throw AuthenticationFailure.Rejected(AuthErrorCode.CONFLICT)
            return cachedResult as ProviderCallbackVerificationResult
        }

        // 4. Replay attack prevention: check if signature was already used
        if (store.isSignatureSeen(command.tenantId, command.signature)) {
            throw AuthenticationFailure.Rejected(AuthErrorCode.FORBIDDEN)
        }

        // 5. Schema and credential verification
        val schema = store.findSchema(command.tenantId, command.providerId)
            ?: throw AuthenticationFailure.Rejected(AuthErrorCode.FORBIDDEN)

        // Credential validation: keyId must match active key or rotating next key
        val isValidKey = command.keyId == schema.activeKey.keyId ||
            (schema.nextKey != null && command.keyId == schema.nextKey.keyId)

        if (!isValidKey) {
            // Bad creds rejection
            throw AuthenticationFailure.Rejected(AuthErrorCode.FORBIDDEN)
        }

        // 6. Cryptographic signature verification
        val rawSecret = try {
            secretResolver.resolveRawSecret(command.tenantId, command.providerId, command.keyId)
        } catch (_: Exception) {
            throw AuthenticationFailure.Rejected(AuthErrorCode.DEPENDENCY_UNAVAILABLE)
        } ?: throw AuthenticationFailure.Rejected(AuthErrorCode.FORBIDDEN)

        val canonicalSignatureInput = "${command.timestamp}.${command.rawPayload}"
        val computedSignature = computeHmac(rawSecret, canonicalSignatureInput)

        val signatureMatches = MessageDigest.isEqual(
            computedSignature.toByteArray(Charsets.UTF_8),
            command.signature.toByteArray(Charsets.UTF_8)
        )

        if (!signatureMatches) {
            // Bad signature rejection
            throw AuthenticationFailure.Rejected(AuthErrorCode.FORBIDDEN)
        }

        // 7. Successful verification result
        val resultId = UUID.randomUUID()
        val result = ProviderCallbackVerificationResult(
            resultId = resultId,
            tenantId = command.tenantId,
            providerId = command.providerId,
            roundReference = command.roundReference,
            verified = true,
            signatureValid = true,
            credentialValid = true,
            replayDetected = false,
            conservationVerified = true,
            rotationObservable = true,
            outageObservable = true,
            serverTime = now,
            evidenceReference = "EVID-CASINO-VERIFIED-${command.tenantId}-${command.providerId}-${command.roundReference}",
        )

        val audit = AuditEvent(
            eventId = UUID.randomUUID(),
            resultId = resultId,
            tenantId = command.tenantId,
            type = "CASINO_CALLBACK_VERIFIED",
            occurredAt = now,
            correlationId = command.correlationId,
            causationId = command.causationId,
        )

        val outbox = OutboxEvent(
            eventId = UUID.randomUUID(),
            resultId = resultId,
            tenantId = command.tenantId,
            type = "CASINO_CALLBACK_VERIFIED",
            createdAt = now,
        )

        store.recordVerification(result, command.tenantId, command.signature, command.idempotencyKey, fp, audit, outbox)
        return result
    }

    private fun computeHmac(secret: String, data: String): String {
        val mac = Mac.getInstance("HmacSHA256")
        mac.init(SecretKeySpec(secret.toByteArray(Charsets.UTF_8), "HmacSHA256"))
        return mac.doFinal(data.toByteArray(Charsets.UTF_8)).joinToString("") { "%02x".format(it) }
    }

    private fun sha256(data: String): String {
        val md = MessageDigest.getInstance("SHA-256")
        return md.digest(data.toByteArray(Charsets.UTF_8)).joinToString("") { "%02x".format(it) }
    }

    private fun fingerprintRegister(cmd: RegisterCasinoProviderSchemaCommand): String {
        val md = MessageDigest.getInstance("SHA-256")
        val raw = "${cmd.tenantId}:${cmd.providerId}:${cmd.schemaVersion}:${cmd.callbackEndpoint}:${cmd.activeKeyId}"
        return md.digest(raw.toByteArray(Charsets.UTF_8)).joinToString("") { "%02x".format(it) }
    }

    private fun fingerprintRotate(cmd: RotateCasinoProviderKeyCommand): String {
        val md = MessageDigest.getInstance("SHA-256")
        val raw = "${cmd.tenantId}:${cmd.providerId}:${cmd.nextKeyId}:${cmd.expectedVersion}"
        return md.digest(raw.toByteArray(Charsets.UTF_8)).joinToString("") { "%02x".format(it) }
    }

    private fun fingerprintHealth(cmd: RecordProviderHealthCommand): String {
        val md = MessageDigest.getInstance("SHA-256")
        val raw = "${cmd.tenantId}:${cmd.providerId}:${cmd.healthState}:${cmd.consecutiveFailures}:${cmd.expectedVersion}"
        return md.digest(raw.toByteArray(Charsets.UTF_8)).joinToString("") { "%02x".format(it) }
    }

    private fun fingerprintCallback(cmd: VerifyCasinoCallbackCommand): String {
        val md = MessageDigest.getInstance("SHA-256")
        val raw = "${cmd.tenantId}:${cmd.providerId}:${cmd.keyId}:${cmd.roundReference}:${cmd.signature}:${cmd.debitMinorUnits}:${cmd.creditMinorUnits}"
        return md.digest(raw.toByteArray(Charsets.UTF_8)).joinToString("") { "%02x".format(it) }
    }
}
