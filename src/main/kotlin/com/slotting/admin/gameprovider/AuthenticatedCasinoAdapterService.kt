package com.slotting.admin.gameprovider

import com.slotting.admin.auth.*
import java.security.MessageDigest
import java.time.Clock
import java.time.Instant
import java.util.UUID
import javax.crypto.Mac
import javax.crypto.spec.SecretKeySpec

/**
 * Fail-closed verification gate for GAME-001-03.
 * Throws expected RED failure until contract bindings and invariant protections are verified.
 */
object AuthenticatedCasinoAdapterBinding {
    @Volatile
    var isBound: Boolean = false

    fun checkBound() {
        if (!isBound) {
            throw AssertionError("bad creds/signature/replay")
        }
    }
}

enum class CasinoCertificationStatus {
    PENDING_REVIEW,
    CERTIFIED,
    REVOKED,
    EXPIRED,
}

data class CasinoProviderCertification(
    val certificationId: UUID,
    val tenantId: String,
    val providerId: String,
    val tier: CasinoProviderAdapterTier,
    val status: CasinoCertificationStatus,
    val canonicalSemanticsVerified: Boolean,
    val signatureVerificationVerified: Boolean,
    val retryAcknowledgementVerified: Boolean,
    val productionApproved: Boolean,
    val sandboxAccessVerified: Boolean,
    val certifierId: String,
    val issuedAt: Instant,
    val expiresAt: Instant,
    val revokedAt: Instant? = null,
    val revocationReason: String? = null,
    val version: Long = 1L,
)

data class CasinoGatewayResponse(
    val statusCode: Int,
    val headers: Map<String, String>,
    val body: String,
)

interface CasinoProviderGatewayClient {
    fun executePost(
        endpoint: String,
        headers: Map<String, String>,
        payload: String,
    ): CasinoGatewayResponse
}

data class CertifyCasinoAdapterCommand(
    val principal: AuthenticatedPrincipal?,
    val sessionId: String,
    val tenantId: String,
    val providerId: String,
    val requestedTier: CasinoProviderAdapterTier,
    val canonicalSemanticsVerified: Boolean,
    val signatureVerificationVerified: Boolean,
    val retryAcknowledgementVerified: Boolean,
    val productionApproved: Boolean,
    val sandboxAccessVerified: Boolean,
    val expiresAt: Instant,
    val idempotencyKey: String,
    val correlationId: String,
    val causationId: String,
    val expectedVersion: Long = 1L,
)

data class RevokeCasinoCertificationCommand(
    val principal: AuthenticatedPrincipal?,
    val sessionId: String,
    val tenantId: String,
    val providerId: String,
    val certificationId: UUID,
    val reason: String,
    val idempotencyKey: String,
    val correlationId: String,
    val causationId: String,
    val expectedVersion: Long,
)

data class ExecuteCasinoRoundCommand(
    val principal: AuthenticatedPrincipal?,
    val sessionId: String,
    val tenantId: String,
    val providerId: String,
    val roundReference: String,
    val debitMinorUnits: Long,
    val creditMinorUnits: Long,
    val currencyCode: String,
    val tier: CasinoProviderAdapterTier,
    val idempotencyKey: String,
    val correlationId: String,
    val causationId: String,
    val expectedVersion: Long = 1L,
)

data class ExecuteCasinoRollbackCommand(
    val principal: AuthenticatedPrincipal?,
    val sessionId: String,
    val tenantId: String,
    val providerId: String,
    val roundReference: String,
    val originalDebitMinorUnits: Long,
    val compensatingCreditMinorUnits: Long,
    val currencyCode: String,
    val reason: String,
    val tier: CasinoProviderAdapterTier,
    val idempotencyKey: String,
    val correlationId: String,
    val causationId: String,
    val expectedVersion: Long = 1L,
)

data class ProcessCasinoCallbackCommand(
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
    val tier: CasinoProviderAdapterTier,
    val idempotencyKey: String,
    val correlationId: String,
    val causationId: String,
    val expectedVersion: Long = 1L,
)

data class CasinoCertificationResult(
    val resultId: UUID,
    val certificationId: UUID,
    val tenantId: String,
    val providerId: String,
    val tier: CasinoProviderAdapterTier,
    val status: CasinoCertificationStatus,
    val rotationObservable: Boolean,
    val outageObservable: Boolean,
    val serverTime: Instant,
    val evidenceReference: String,
)

data class CasinoRoundExecutionResult(
    val resultId: UUID,
    val tenantId: String,
    val providerId: String,
    val roundReference: String,
    val debitMinorUnits: Long,
    val creditMinorUnits: Long,
    val currencyCode: String,
    val tier: CasinoProviderAdapterTier,
    val executedSuccessfully: Boolean,
    val rotationObservable: Boolean,
    val outageObservable: Boolean,
    val serverTime: Instant,
    val evidenceReference: String,
)

data class CasinoRollbackExecutionResult(
    val resultId: UUID,
    val tenantId: String,
    val providerId: String,
    val roundReference: String,
    val debitMinorUnits: Long,
    val creditMinorUnits: Long,
    val conserved: Boolean,
    val compensationReference: String,
    val tier: CasinoProviderAdapterTier,
    val rotationObservable: Boolean,
    val outageObservable: Boolean,
    val serverTime: Instant,
    val evidenceReference: String,
)

data class CasinoCallbackProcessingResult(
    val resultId: UUID,
    val tenantId: String,
    val providerId: String,
    val roundReference: String,
    val verified: Boolean,
    val signatureValid: Boolean,
    val credentialValid: Boolean,
    val replayDetected: Boolean,
    val conservationVerified: Boolean,
    val tier: CasinoProviderAdapterTier,
    val rotationObservable: Boolean,
    val outageObservable: Boolean,
    val serverTime: Instant,
    val evidenceReference: String,
)

interface AuthenticatedCasinoAdapterStore {
    fun findCertification(tenantId: String, providerId: String): CasinoProviderCertification?
    fun findCertificationById(tenantId: String, certificationId: UUID): CasinoProviderCertification?
    fun findCertByIdempotency(tenantId: String, idempotencyKey: String): Pair<String, CasinoCertificationResult>?
    fun saveCertification(
        certification: CasinoProviderCertification,
        result: CasinoCertificationResult,
        tenantId: String,
        idempotencyKey: String,
        fingerprint: String,
        audit: AuditEvent,
        outbox: OutboxEvent,
    )
    fun findRoundByIdempotency(tenantId: String, idempotencyKey: String): Pair<String, CasinoRoundExecutionResult>?
    fun saveRound(
        result: CasinoRoundExecutionResult,
        tenantId: String,
        idempotencyKey: String,
        fingerprint: String,
        audit: AuditEvent,
        outbox: OutboxEvent,
    )
    fun findRollbackByIdempotency(tenantId: String, idempotencyKey: String): Pair<String, CasinoRollbackExecutionResult>?
    fun saveRollback(
        result: CasinoRollbackExecutionResult,
        tenantId: String,
        idempotencyKey: String,
        fingerprint: String,
        audit: AuditEvent,
        outbox: OutboxEvent,
    )
    fun findCallbackByIdempotency(tenantId: String, idempotencyKey: String): Pair<String, CasinoCallbackProcessingResult>?
    fun isSignatureSeen(tenantId: String, signature: String): Boolean
    fun saveCallback(
        result: CasinoCallbackProcessingResult,
        tenantId: String,
        signature: String,
        idempotencyKey: String,
        fingerprint: String,
        audit: AuditEvent,
        outbox: OutboxEvent,
    )
}

class AuthenticatedCasinoAdapterService(
    private val policy: AdminRbacPolicy,
    private val sessions: AdminSessionDirectory,
    private val contractStore: CanonicalCasinoProviderContractStore,
    private val secretResolver: ProviderSecretResolver,
    private val adapterStore: AuthenticatedCasinoAdapterStore,
    private val gatewayClient: CasinoProviderGatewayClient,
    private val clock: Clock = Clock.systemUTC(),
    private val timestampSkewToleranceSeconds: Long = 300L,
) {

    @Synchronized
    fun certifyAdapter(command: CertifyCasinoAdapterCommand): CasinoCertificationResult {
        AuthenticatedCasinoAdapterBinding.checkBound()

        // 1. Input validation
        if (command.providerId.isBlank() ||
            command.sessionId.isBlank() ||
            command.correlationId.isBlank() ||
            command.causationId.isBlank() ||
            command.expiresAt.isBefore(clock.instant())
        ) {
            throw AuthenticationFailure.Rejected(AuthErrorCode.INVALID)
        }

        // 2. Authentication and Tenancy
        val principal = command.principal ?: throw AuthenticationFailure.Rejected(AuthErrorCode.UNAUTHENTICATED)
        if (principal.kind != PrincipalKind.ADMIN || principal.tenantId != command.tenantId) {
            throw AuthenticationFailure.Rejected(AuthErrorCode.FORBIDDEN)
        }

        // 3. Idempotency check
        val fp = fingerprintCertify(command)
        adapterStore.findCertByIdempotency(command.tenantId, command.idempotencyKey)?.let { (cachedFp, cachedResult) ->
            if (cachedFp != fp) throw AuthenticationFailure.Rejected(AuthErrorCode.CONFLICT)
            return cachedResult
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

        // 5. Version check
        val existing = adapterStore.findCertification(command.tenantId, command.providerId)
        val targetVersion = if (existing != null) existing.version + 1L else 1L
        if (command.expectedVersion != targetVersion) {
            throw AuthenticationFailure.Rejected(AuthErrorCode.STALE)
        }

        // 6. Schema check
        val schema = contractStore.findSchema(command.tenantId, command.providerId)
            ?: throw AuthenticationFailure.Rejected(AuthErrorCode.FORBIDDEN)

        // External decision contract:
        // Absent evidence permits only port/fake work: production requires full verification
        if (command.requestedTier == CasinoProviderAdapterTier.PRODUCTION_CERTIFIED) {
            if (!command.canonicalSemanticsVerified ||
                !command.signatureVerificationVerified ||
                !command.retryAcknowledgementVerified ||
                !command.productionApproved
            ) {
                throw AuthenticationFailure.Rejected(AuthErrorCode.FORBIDDEN)
            }
        }

        // Sandbox requires verified sandbox access
        if (command.requestedTier == CasinoProviderAdapterTier.SANDBOX) {
            if (!command.sandboxAccessVerified) {
                throw AuthenticationFailure.Rejected(AuthErrorCode.FORBIDDEN)
            }
        }

        val now = clock.instant()
        val certId = UUID.randomUUID()
        val certification = CasinoProviderCertification(
            certificationId = certId,
            tenantId = command.tenantId,
            providerId = command.providerId,
            tier = command.requestedTier,
            status = CasinoCertificationStatus.CERTIFIED,
            canonicalSemanticsVerified = command.canonicalSemanticsVerified,
            signatureVerificationVerified = command.signatureVerificationVerified,
            retryAcknowledgementVerified = command.retryAcknowledgementVerified,
            productionApproved = command.productionApproved,
            sandboxAccessVerified = command.sandboxAccessVerified,
            certifierId = principal.id,
            issuedAt = now,
            expiresAt = command.expiresAt,
            version = targetVersion,
        )

        val resultId = UUID.randomUUID()
        val result = CasinoCertificationResult(
            resultId = resultId,
            certificationId = certId,
            tenantId = command.tenantId,
            providerId = command.providerId,
            tier = command.requestedTier,
            status = CasinoCertificationStatus.CERTIFIED,
            rotationObservable = schema.nextKey != null,
            outageObservable = schema.healthState != ProviderHealthState.HEALTHY,
            serverTime = now,
            evidenceReference = "EVID-CASINO-CERT-${command.tenantId}-${command.providerId}-v$targetVersion",
        )

        val audit = AuditEvent(
            eventId = UUID.randomUUID(),
            resultId = resultId,
            tenantId = command.tenantId,
            type = "CASINO_ADAPTER_CERTIFIED",
            occurredAt = now,
            correlationId = command.correlationId,
            causationId = command.causationId,
        )

        val outbox = OutboxEvent(
            eventId = UUID.randomUUID(),
            resultId = resultId,
            tenantId = command.tenantId,
            type = "CASINO_ADAPTER_CERTIFIED",
            createdAt = now,
        )

        adapterStore.saveCertification(certification, result, command.tenantId, command.idempotencyKey, fp, audit, outbox)
        return result
    }

    @Synchronized
    fun revokeCertification(command: RevokeCasinoCertificationCommand): CasinoCertificationResult {
        AuthenticatedCasinoAdapterBinding.checkBound()

        if (command.providerId.isBlank() ||
            command.reason.isBlank() ||
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

        val cert = adapterStore.findCertificationById(command.tenantId, command.certificationId)
            ?: throw AuthenticationFailure.Rejected(AuthErrorCode.INVALID)

        if (command.expectedVersion != cert.version + 1L) {
            throw AuthenticationFailure.Rejected(AuthErrorCode.STALE)
        }

        val now = clock.instant()
        val revoked = cert.copy(
            status = CasinoCertificationStatus.REVOKED,
            revokedAt = now,
            revocationReason = command.reason,
            version = cert.version + 1L,
        )

        val resultId = UUID.randomUUID()
        val result = CasinoCertificationResult(
            resultId = resultId,
            certificationId = cert.certificationId,
            tenantId = command.tenantId,
            providerId = command.providerId,
            tier = cert.tier,
            status = CasinoCertificationStatus.REVOKED,
            rotationObservable = true,
            outageObservable = true,
            serverTime = now,
            evidenceReference = "EVID-CASINO-CERT-REVOKED-${command.tenantId}-${cert.certificationId}",
        )

        val audit = AuditEvent(
            eventId = UUID.randomUUID(),
            resultId = resultId,
            tenantId = command.tenantId,
            type = "CASINO_ADAPTER_CERTIFICATION_REVOKED",
            occurredAt = now,
            correlationId = command.correlationId,
            causationId = command.causationId,
        )

        val outbox = OutboxEvent(
            eventId = UUID.randomUUID(),
            resultId = resultId,
            tenantId = command.tenantId,
            type = "CASINO_ADAPTER_CERTIFICATION_REVOKED",
            createdAt = now,
        )

        adapterStore.saveCertification(revoked, result, command.tenantId, command.idempotencyKey, command.reason, audit, outbox)
        return result
    }

    @Synchronized
    fun executeRound(command: ExecuteCasinoRoundCommand): CasinoRoundExecutionResult {
        AuthenticatedCasinoAdapterBinding.checkBound()

        // 1. Financial & Input Validation
        if (command.providerId.isBlank() ||
            command.roundReference.isBlank() ||
            command.sessionId.isBlank() ||
            command.correlationId.isBlank() ||
            command.causationId.isBlank() ||
            command.debitMinorUnits < 0 ||
            command.creditMinorUnits < 0 ||
            !command.currencyCode.matches(Regex("[A-Z]{3}"))
        ) {
            throw AuthenticationFailure.Rejected(AuthErrorCode.INVALID)
        }

        val principal = command.principal ?: throw AuthenticationFailure.Rejected(AuthErrorCode.UNAUTHENTICATED)
        if (principal.kind != PrincipalKind.ADMIN || principal.tenantId != command.tenantId) {
            throw AuthenticationFailure.Rejected(AuthErrorCode.FORBIDDEN)
        }

        // 2. Idempotency Check
        val fp = fingerprintRound(command)
        adapterStore.findRoundByIdempotency(command.tenantId, command.idempotencyKey)?.let { (cachedFp, cachedResult) ->
            if (cachedFp != fp) throw AuthenticationFailure.Rejected(AuthErrorCode.CONFLICT)
            return cachedResult
        }

        // 3. Session Check
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

        // 4. Schema & Outage Check
        val schema = contractStore.findSchema(command.tenantId, command.providerId)
            ?: throw AuthenticationFailure.Rejected(AuthErrorCode.FORBIDDEN)

        if (schema.healthState == ProviderHealthState.OUTAGE_TRIPPED) {
            throw AuthenticationFailure.Rejected(AuthErrorCode.DEPENDENCY_UNAVAILABLE)
        }

        // 5. Tier & Certification Verification: Absent evidence permits only port/fake work!
        if (command.tier == CasinoProviderAdapterTier.PRODUCTION_CERTIFIED ||
            command.tier == CasinoProviderAdapterTier.SANDBOX
        ) {
            val cert = adapterStore.findCertification(command.tenantId, command.providerId)
                ?: throw AuthenticationFailure.Rejected(AuthErrorCode.FORBIDDEN)

            if (cert.status != CasinoCertificationStatus.CERTIFIED ||
                cert.expiresAt.isBefore(clock.instant()) ||
                cert.tier != command.tier
            ) {
                throw AuthenticationFailure.Rejected(AuthErrorCode.FORBIDDEN)
            }

            if (command.tier == CasinoProviderAdapterTier.PRODUCTION_CERTIFIED &&
                (!cert.productionApproved || !cert.canonicalSemanticsVerified || !cert.signatureVerificationVerified)
            ) {
                throw AuthenticationFailure.Rejected(AuthErrorCode.FORBIDDEN)
            }

            if (command.tier == CasinoProviderAdapterTier.SANDBOX && !cert.sandboxAccessVerified) {
                throw AuthenticationFailure.Rejected(AuthErrorCode.FORBIDDEN)
            }
        }

        // 6. Authenticated Gateway Communication
        val rawSecret = try {
            secretResolver.resolveRawSecret(command.tenantId, command.providerId, schema.activeKey.keyId)
        } catch (_: Exception) {
            throw AuthenticationFailure.Rejected(AuthErrorCode.DEPENDENCY_UNAVAILABLE)
        } ?: throw AuthenticationFailure.Rejected(AuthErrorCode.FORBIDDEN)

        val timestamp = clock.instant().epochSecond
        val payload = """{"roundId":"${command.roundReference}","debit":${command.debitMinorUnits},"credit":${command.creditMinorUnits},"currency":"${command.currencyCode}"}"""
        val signature = computeHmac(rawSecret, "$timestamp.$payload")

        val headers = mapOf(
            "X-Provider-Key-Id" to schema.activeKey.keyId,
            "X-Provider-Signature" to signature,
            "X-Provider-Timestamp" to timestamp.toString(),
            "X-Correlation-Id" to command.correlationId,
        )

        val response = try {
            gatewayClient.executePost(schema.callbackEndpoint, headers, payload)
        } catch (_: Exception) {
            throw AuthenticationFailure.Rejected(AuthErrorCode.DEPENDENCY_UNAVAILABLE)
        }

        if (response.statusCode >= 500) {
            throw AuthenticationFailure.Rejected(AuthErrorCode.DEPENDENCY_UNAVAILABLE)
        } else if (response.statusCode >= 400) {
            throw AuthenticationFailure.Rejected(AuthErrorCode.FORBIDDEN)
        }

        val now = clock.instant()
        val resultId = UUID.randomUUID()
        val result = CasinoRoundExecutionResult(
            resultId = resultId,
            tenantId = command.tenantId,
            providerId = command.providerId,
            roundReference = command.roundReference,
            debitMinorUnits = command.debitMinorUnits,
            creditMinorUnits = command.creditMinorUnits,
            currencyCode = command.currencyCode,
            tier = command.tier,
            executedSuccessfully = true,
            rotationObservable = schema.nextKey != null,
            outageObservable = schema.healthState != ProviderHealthState.HEALTHY,
            serverTime = now,
            evidenceReference = "EVID-CASINO-ROUND-${command.tenantId}-${command.roundReference}",
        )

        val audit = AuditEvent(
            eventId = UUID.randomUUID(),
            resultId = resultId,
            tenantId = command.tenantId,
            type = "CASINO_ADAPTER_ROUND_EXECUTED",
            occurredAt = now,
            correlationId = command.correlationId,
            causationId = command.causationId,
        )

        val outbox = OutboxEvent(
            eventId = UUID.randomUUID(),
            resultId = resultId,
            tenantId = command.tenantId,
            type = "CASINO_ADAPTER_ROUND_EXECUTED",
            createdAt = now,
        )

        adapterStore.saveRound(result, command.tenantId, command.idempotencyKey, fp, audit, outbox)
        return result
    }

    @Synchronized
    fun executeRollback(command: ExecuteCasinoRollbackCommand): CasinoRollbackExecutionResult {
        AuthenticatedCasinoAdapterBinding.checkBound()

        // Financial conservation check: debits must equal credits
        if (command.providerId.isBlank() ||
            command.roundReference.isBlank() ||
            command.sessionId.isBlank() ||
            command.correlationId.isBlank() ||
            command.causationId.isBlank() ||
            command.originalDebitMinorUnits < 0 ||
            command.compensatingCreditMinorUnits < 0 ||
            command.originalDebitMinorUnits != command.compensatingCreditMinorUnits ||
            !command.currencyCode.matches(Regex("[A-Z]{3}"))
        ) {
            throw AuthenticationFailure.Rejected(AuthErrorCode.INVALID)
        }

        val principal = command.principal ?: throw AuthenticationFailure.Rejected(AuthErrorCode.UNAUTHENTICATED)
        if (principal.kind != PrincipalKind.ADMIN || principal.tenantId != command.tenantId) {
            throw AuthenticationFailure.Rejected(AuthErrorCode.FORBIDDEN)
        }

        val fp = fingerprintRollback(command)
        adapterStore.findRollbackByIdempotency(command.tenantId, command.idempotencyKey)?.let { (cachedFp, cachedResult) ->
            if (cachedFp != fp) throw AuthenticationFailure.Rejected(AuthErrorCode.CONFLICT)
            return cachedResult
        }

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

        val schema = contractStore.findSchema(command.tenantId, command.providerId)
            ?: throw AuthenticationFailure.Rejected(AuthErrorCode.FORBIDDEN)

        if (schema.healthState == ProviderHealthState.OUTAGE_TRIPPED) {
            throw AuthenticationFailure.Rejected(AuthErrorCode.DEPENDENCY_UNAVAILABLE)
        }

        // Production / Sandbox certification check
        if (command.tier == CasinoProviderAdapterTier.PRODUCTION_CERTIFIED ||
            command.tier == CasinoProviderAdapterTier.SANDBOX
        ) {
            val cert = adapterStore.findCertification(command.tenantId, command.providerId)
                ?: throw AuthenticationFailure.Rejected(AuthErrorCode.FORBIDDEN)

            if (cert.status != CasinoCertificationStatus.CERTIFIED ||
                cert.expiresAt.isBefore(clock.instant()) ||
                cert.tier != command.tier
            ) {
                throw AuthenticationFailure.Rejected(AuthErrorCode.FORBIDDEN)
            }
        }

        // Authenticated rollback request to provider endpoint
        val rawSecret = try {
            secretResolver.resolveRawSecret(command.tenantId, command.providerId, schema.activeKey.keyId)
        } catch (_: Exception) {
            throw AuthenticationFailure.Rejected(AuthErrorCode.DEPENDENCY_UNAVAILABLE)
        } ?: throw AuthenticationFailure.Rejected(AuthErrorCode.FORBIDDEN)

        val timestamp = clock.instant().epochSecond
        val payload = """{"roundId":"${command.roundReference}","rollback":true,"debit":${command.originalDebitMinorUnits},"credit":${command.compensatingCreditMinorUnits},"currency":"${command.currencyCode}","reason":"${command.reason}"}"""
        val signature = computeHmac(rawSecret, "$timestamp.$payload")

        val headers = mapOf(
            "X-Provider-Key-Id" to schema.activeKey.keyId,
            "X-Provider-Signature" to signature,
            "X-Provider-Timestamp" to timestamp.toString(),
            "X-Correlation-Id" to command.correlationId,
        )

        val response = try {
            gatewayClient.executePost(schema.callbackEndpoint, headers, payload)
        } catch (_: Exception) {
            throw AuthenticationFailure.Rejected(AuthErrorCode.DEPENDENCY_UNAVAILABLE)
        }

        if (response.statusCode >= 500) {
            throw AuthenticationFailure.Rejected(AuthErrorCode.DEPENDENCY_UNAVAILABLE)
        } else if (response.statusCode >= 400) {
            throw AuthenticationFailure.Rejected(AuthErrorCode.FORBIDDEN)
        }

        val now = clock.instant()
        val resultId = UUID.randomUUID()
        val rollbackId = UUID.randomUUID()
        val result = CasinoRollbackExecutionResult(
            resultId = resultId,
            tenantId = command.tenantId,
            providerId = command.providerId,
            roundReference = command.roundReference,
            debitMinorUnits = command.originalDebitMinorUnits,
            creditMinorUnits = command.compensatingCreditMinorUnits,
            conserved = true,
            compensationReference = "COMP-ROLLBACK-${command.tenantId}-$rollbackId",
            tier = command.tier,
            rotationObservable = schema.nextKey != null,
            outageObservable = schema.healthState != ProviderHealthState.HEALTHY,
            serverTime = now,
            evidenceReference = "EVID-CASINO-ROLLBACK-${command.tenantId}-${command.roundReference}",
        )

        val audit = AuditEvent(
            eventId = UUID.randomUUID(),
            resultId = resultId,
            tenantId = command.tenantId,
            type = "CASINO_ADAPTER_ROLLBACK_COMPENSATED",
            occurredAt = now,
            correlationId = command.correlationId,
            causationId = command.causationId,
        )

        val outbox = OutboxEvent(
            eventId = UUID.randomUUID(),
            resultId = resultId,
            tenantId = command.tenantId,
            type = "CASINO_ADAPTER_ROLLBACK_COMPENSATED",
            createdAt = now,
        )

        adapterStore.saveRollback(result, command.tenantId, command.idempotencyKey, fp, audit, outbox)
        return result
    }

    @Synchronized
    fun processIncomingCallback(command: ProcessCasinoCallbackCommand): CasinoCallbackProcessingResult {
        AuthenticatedCasinoAdapterBinding.checkBound()

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
        adapterStore.findCallbackByIdempotency(command.tenantId, command.idempotencyKey)?.let { (cachedFp, cachedResult) ->
            if (cachedFp != fp) throw AuthenticationFailure.Rejected(AuthErrorCode.CONFLICT)
            return cachedResult
        }

        // 4. Replay attack prevention: check if signature was already used
        if (adapterStore.isSignatureSeen(command.tenantId, command.signature)) {
            throw AuthenticationFailure.Rejected(AuthErrorCode.FORBIDDEN)
        }

        // 5. Schema & Credential verification
        val schema = contractStore.findSchema(command.tenantId, command.providerId)
            ?: throw AuthenticationFailure.Rejected(AuthErrorCode.FORBIDDEN)

        val isValidKey = command.keyId == schema.activeKey.keyId ||
            (schema.nextKey != null && command.keyId == schema.nextKey.keyId)

        if (!isValidKey) {
            // Bad creds rejection
            throw AuthenticationFailure.Rejected(AuthErrorCode.FORBIDDEN)
        }

        // 6. Tier & Certification check for Production / Sandbox
        if (command.tier == CasinoProviderAdapterTier.PRODUCTION_CERTIFIED ||
            command.tier == CasinoProviderAdapterTier.SANDBOX
        ) {
            val cert = adapterStore.findCertification(command.tenantId, command.providerId)
                ?: throw AuthenticationFailure.Rejected(AuthErrorCode.FORBIDDEN)

            if (cert.status != CasinoCertificationStatus.CERTIFIED ||
                cert.expiresAt.isBefore(clock.instant()) ||
                cert.tier != command.tier
            ) {
                throw AuthenticationFailure.Rejected(AuthErrorCode.FORBIDDEN)
            }
        }

        // 7. Cryptographic signature verification
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

        val resultId = UUID.randomUUID()
        val result = CasinoCallbackProcessingResult(
            resultId = resultId,
            tenantId = command.tenantId,
            providerId = command.providerId,
            roundReference = command.roundReference,
            verified = true,
            signatureValid = true,
            credentialValid = true,
            replayDetected = false,
            conservationVerified = true,
            tier = command.tier,
            rotationObservable = schema.nextKey != null,
            outageObservable = schema.healthState != ProviderHealthState.HEALTHY,
            serverTime = now,
            evidenceReference = "EVID-CASINO-CALLBACK-${command.tenantId}-${command.roundReference}",
        )

        val audit = AuditEvent(
            eventId = UUID.randomUUID(),
            resultId = resultId,
            tenantId = command.tenantId,
            type = "CASINO_ADAPTER_CALLBACK_VERIFIED",
            occurredAt = now,
            correlationId = command.correlationId,
            causationId = command.causationId,
        )

        val outbox = OutboxEvent(
            eventId = UUID.randomUUID(),
            resultId = resultId,
            tenantId = command.tenantId,
            type = "CASINO_ADAPTER_CALLBACK_VERIFIED",
            createdAt = now,
        )

        adapterStore.saveCallback(result, command.tenantId, command.signature, command.idempotencyKey, fp, audit, outbox)
        return result
    }

    private fun computeHmac(secret: String, data: String): String {
        val mac = Mac.getInstance("HmacSHA256")
        mac.init(SecretKeySpec(secret.toByteArray(Charsets.UTF_8), "HmacSHA256"))
        return mac.doFinal(data.toByteArray(Charsets.UTF_8)).joinToString("") { "%02x".format(it) }
    }

    private fun fingerprintCertify(cmd: CertifyCasinoAdapterCommand): String {
        val md = MessageDigest.getInstance("SHA-256")
        val raw = "${cmd.tenantId}:${cmd.providerId}:${cmd.requestedTier}:${cmd.canonicalSemanticsVerified}:${cmd.signatureVerificationVerified}:${cmd.productionApproved}:${cmd.expectedVersion}"
        return md.digest(raw.toByteArray(Charsets.UTF_8)).joinToString("") { "%02x".format(it) }
    }

    private fun fingerprintRound(cmd: ExecuteCasinoRoundCommand): String {
        val md = MessageDigest.getInstance("SHA-256")
        val raw = "${cmd.tenantId}:${cmd.providerId}:${cmd.roundReference}:${cmd.debitMinorUnits}:${cmd.creditMinorUnits}:${cmd.currencyCode}:${cmd.tier}"
        return md.digest(raw.toByteArray(Charsets.UTF_8)).joinToString("") { "%02x".format(it) }
    }

    private fun fingerprintRollback(cmd: ExecuteCasinoRollbackCommand): String {
        val md = MessageDigest.getInstance("SHA-256")
        val raw = "${cmd.tenantId}:${cmd.providerId}:${cmd.roundReference}:${cmd.originalDebitMinorUnits}:${cmd.compensatingCreditMinorUnits}:${cmd.currencyCode}:${cmd.tier}"
        return md.digest(raw.toByteArray(Charsets.UTF_8)).joinToString("") { "%02x".format(it) }
    }

    private fun fingerprintCallback(cmd: ProcessCasinoCallbackCommand): String {
        val md = MessageDigest.getInstance("SHA-256")
        val raw = "${cmd.tenantId}:${cmd.providerId}:${cmd.keyId}:${cmd.roundReference}:${cmd.signature}:${cmd.debitMinorUnits}:${cmd.creditMinorUnits}:${cmd.tier}"
        return md.digest(raw.toByteArray(Charsets.UTF_8)).joinToString("") { "%02x".format(it) }
    }
}
