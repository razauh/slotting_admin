package com.slotting.admin.payment

import com.slotting.admin.auth.*
import java.security.MessageDigest
import java.time.Clock
import java.time.Instant
import java.util.UUID

enum class AdapterTier {
    PORT_ONLY,
    ADVERSARIAL_FAKE,
    SANDBOX,
    PRODUCTION_CERTIFIED,
}

enum class CertificationStatus {
    PENDING_REVIEW,
    CERTIFIED,
    REVOKED,
    EXPIRED,
}

data class PaymentAdapterCertification(
    val certificationId: UUID,
    val tenantId: String,
    val providerId: String,
    val tier: AdapterTier,
    val status: CertificationStatus,
    val canonicalSemanticsVerified: Boolean,
    val signatureVerificationVerified: Boolean,
    val retryAcknowledgementVerified: Boolean,
    val productionApproved: Boolean,
    val certifierId: String,
    val issuedAt: Instant,
    val expiresAt: Instant,
    val revokedAt: Instant? = null,
    val revocationReason: String? = null,
    val version: Long = 1L,
)

data class CertifyAdapterCommand(
    val principal: AuthenticatedPrincipal?,
    val sessionId: String,
    val tenantId: String,
    val providerId: String,
    val requestedTier: AdapterTier,
    val canonicalSemanticsVerified: Boolean,
    val signatureVerificationVerified: Boolean,
    val retryAcknowledgementVerified: Boolean,
    val productionApproved: Boolean,
    val expiresAt: Instant,
    val idempotencyKey: String,
    val correlationId: String,
    val causationId: String,
    val expectedVersion: Long = 1L,
)

data class RevokeCertificationCommand(
    val principal: AuthenticatedPrincipal?,
    val sessionId: String,
    val tenantId: String,
    val certificationId: UUID,
    val reason: String,
    val idempotencyKey: String,
    val correlationId: String,
    val causationId: String,
    val expectedVersion: Long,
)

data class CertificationVerificationResult(
    val resultId: UUID,
    val certificationId: UUID,
    val tenantId: String,
    val providerId: String,
    val tier: AdapterTier,
    val status: CertificationStatus,
    val serverTime: Instant,
    val evidenceReference: String,
)

interface PaymentAdapterCertificationStore {
    fun findByIdempotency(tenantId: String, idempotencyKey: String): Pair<String, CertificationVerificationResult>?
    fun findCertification(tenantId: String, certificationId: UUID): PaymentAdapterCertification?
    fun findByProvider(tenantId: String, providerId: String): PaymentAdapterCertification?
    fun saveCertification(
        certification: PaymentAdapterCertification,
        result: CertificationVerificationResult,
        queryFingerprint: String,
        idempotencyKey: String,
        audit: AuditEvent,
        outbox: OutboxEvent,
    )
}

class PaymentAdapterCertificationService(
    private val policy: AdminRbacPolicy,
    private val sessions: AdminSessionDirectory,
    private val store: PaymentAdapterCertificationStore,
    private val clock: Clock = Clock.systemUTC(),
) {
    @Synchronized
    fun certifyAdapter(command: CertifyAdapterCommand): CertificationVerificationResult {
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

        if (command.providerId.isBlank() || command.correlationId.isBlank() || command.causationId.isBlank()) {
            throw AuthenticationFailure.Rejected(AuthErrorCode.INVALID)
        }

        if (command.expiresAt.isBefore(clock.instant())) {
            throw AuthenticationFailure.Rejected(AuthErrorCode.INVALID)
        }

        val fp = fingerprintCertify(command)
        store.findByIdempotency(command.tenantId, command.idempotencyKey)?.let { (cachedFp, cachedResult) ->
            if (cachedFp != fp) throw AuthenticationFailure.Rejected(AuthErrorCode.CONFLICT)
            return cachedResult
        }

        // Absent evidence permits only port/fake work: production requires full verification
        if (command.requestedTier == AdapterTier.PRODUCTION_CERTIFIED) {
            if (!command.canonicalSemanticsVerified || !command.signatureVerificationVerified ||
                !command.retryAcknowledgementVerified || !command.productionApproved) {
                throw AuthenticationFailure.Rejected(AuthErrorCode.FORBIDDEN)
            }
        }

        val now = clock.instant()
        val certId = UUID.randomUUID()
        val resultId = UUID.randomUUID()
        val evidenceRef = "CERT-EVID-$resultId"

        val certification = PaymentAdapterCertification(
            certificationId = certId,
            tenantId = command.tenantId,
            providerId = command.providerId.trim(),
            tier = command.requestedTier,
            status = CertificationStatus.CERTIFIED,
            canonicalSemanticsVerified = command.canonicalSemanticsVerified,
            signatureVerificationVerified = command.signatureVerificationVerified,
            retryAcknowledgementVerified = command.retryAcknowledgementVerified,
            productionApproved = command.productionApproved,
            certifierId = principal.id,
            issuedAt = now,
            expiresAt = command.expiresAt,
            version = 1L,
        )

        val result = CertificationVerificationResult(
            resultId = resultId,
            certificationId = certId,
            tenantId = command.tenantId,
            providerId = command.providerId.trim(),
            tier = command.requestedTier,
            status = CertificationStatus.CERTIFIED,
            serverTime = now,
            evidenceReference = evidenceRef,
        )

        val audit = AuditEvent(
            eventId = UUID.randomUUID(),
            resultId = resultId,
            tenantId = command.tenantId,
            type = "PAYMENT_ADAPTER_CERTIFIED",
            occurredAt = now,
            correlationId = command.correlationId,
            causationId = command.causationId,
        )
        val outbox = OutboxEvent(
            eventId = UUID.randomUUID(),
            resultId = resultId,
            tenantId = command.tenantId,
            type = "PAYMENT_ADAPTER_CERTIFIED",
            createdAt = now,
        )

        store.saveCertification(certification, result, fp, command.idempotencyKey, audit, outbox)
        return result
    }

    @Synchronized
    fun revokeCertification(command: RevokeCertificationCommand): CertificationVerificationResult {
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

        if (command.reason.isBlank() || command.correlationId.isBlank() || command.causationId.isBlank()) {
            throw AuthenticationFailure.Rejected(AuthErrorCode.INVALID)
        }

        val fp = fingerprintRevoke(command)
        store.findByIdempotency(command.tenantId, command.idempotencyKey)?.let { (cachedFp, cachedResult) ->
            if (cachedFp != fp) throw AuthenticationFailure.Rejected(AuthErrorCode.CONFLICT)
            return cachedResult
        }

        val cert = store.findCertification(command.tenantId, command.certificationId)
            ?: throw AuthenticationFailure.Rejected(AuthErrorCode.FORBIDDEN)

        if (cert.version != command.expectedVersion) {
            throw AuthenticationFailure.Rejected(AuthErrorCode.STALE)
        }

        val now = clock.instant()
        val resultId = UUID.randomUUID()
        val evidenceRef = "REVOKE-EVID-$resultId"

        val revokedCert = cert.copy(
            status = CertificationStatus.REVOKED,
            revokedAt = now,
            revocationReason = command.reason.trim(),
            version = cert.version + 1L,
        )

        val result = CertificationVerificationResult(
            resultId = resultId,
            certificationId = cert.certificationId,
            tenantId = command.tenantId,
            providerId = cert.providerId,
            tier = cert.tier,
            status = CertificationStatus.REVOKED,
            serverTime = now,
            evidenceReference = evidenceRef,
        )

        val audit = AuditEvent(
            eventId = UUID.randomUUID(),
            resultId = resultId,
            tenantId = command.tenantId,
            type = "PAYMENT_ADAPTER_REVOKED",
            occurredAt = now,
            correlationId = command.correlationId,
            causationId = command.causationId,
        )
        val outbox = OutboxEvent(
            eventId = UUID.randomUUID(),
            resultId = resultId,
            tenantId = command.tenantId,
            type = "PAYMENT_ADAPTER_REVOKED",
            createdAt = now,
        )

        store.saveCertification(revokedCert, result, fp, command.idempotencyKey, audit, outbox)
        return result
    }

    @Synchronized
    fun assertProductionAllowed(tenantId: String, providerId: String) {
        val cert = store.findByProvider(tenantId, providerId)
            ?: throw AuthenticationFailure.Rejected(AuthErrorCode.FORBIDDEN)

        if (cert.tier != AdapterTier.PRODUCTION_CERTIFIED ||
            cert.status != CertificationStatus.CERTIFIED ||
            cert.expiresAt.isBefore(clock.instant())) {
            throw AuthenticationFailure.Rejected(AuthErrorCode.FORBIDDEN)
        }
    }

    private fun fingerprintCertify(cmd: CertifyAdapterCommand): String {
        val digest = MessageDigest.getInstance("SHA-256")
        val raw = "${cmd.tenantId}:${cmd.providerId}:${cmd.requestedTier}:${cmd.canonicalSemanticsVerified}:${cmd.signatureVerificationVerified}:${cmd.retryAcknowledgementVerified}:${cmd.productionApproved}:${cmd.expiresAt}:${cmd.expectedVersion}"
        return digest.digest(raw.toByteArray(Charsets.UTF_8)).joinToString("") { "%02x".format(it) }
    }

    private fun fingerprintRevoke(cmd: RevokeCertificationCommand): String {
        val digest = MessageDigest.getInstance("SHA-256")
        val raw = "${cmd.tenantId}:${cmd.certificationId}:${cmd.reason}:${cmd.expectedVersion}"
        return digest.digest(raw.toByteArray(Charsets.UTF_8)).joinToString("") { "%02x".format(it) }
    }
}
