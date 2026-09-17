package com.slotting.admin.kyc

import com.slotting.admin.auth.*
import java.security.MessageDigest
import java.time.Clock
import java.time.Instant
import java.util.UUID

enum class KycEvidencePortOperation {
    SUBMIT_VERIFICATION,
    CHECK_STATUS,
    PROCESS_WEBHOOK,
}

enum class KycCheckType {
    DOCUMENT_IDENTITY,
    BIOMETRIC_LIVENESS,
    SANCTIONS_PEP,
    PROOF_OF_ADDRESS,
}

enum class KycVendorOutcome {
    PASSED,
    FAILED,
    SUSPICIOUS,
    INDETERMINATE,
    OUTAGE,
}

enum class KycCanonicalStatus {
    PENDING,
    EVIDENCE_COLLECTED,
    SUSPENDED,
    FAILED_CLOSED,
}

data class KycVendorEvidenceCommand(
    val principal: AuthenticatedPrincipal?,
    val sessionId: String,
    val tenantId: String,
    val subjectReference: String,
    val operation: KycEvidencePortOperation,
    val checkType: KycCheckType,
    val providerId: String,
    val vendorCheckReference: String? = null,
    val idempotencyKey: String,
    val correlationId: String,
    val causationId: String,
    val expectedVersion: Long = 1L,
)

data class KycWebhookEvidenceCommand(
    val tenantId: String,
    val providerId: String,
    val signatureHeader: String,
    val rawPayload: String,
    val idempotencyKey: String,
    val correlationId: String,
    val causationId: String,
)

data class KycVendorExecutionResponse(
    val vendorCheckReference: String,
    val outcome: KycVendorOutcome,
    val confidenceScore: Double?,
    val minimalEvidenceReference: String,
)

data class KycCanonicalWebhookEvidence(
    val subjectReference: String,
    val checkType: KycCheckType,
    val outcome: KycVendorOutcome,
    val confidenceScore: Double?,
    val vendorCheckReference: String,
)

data class KycVendorEvidenceResult(
    val resultId: UUID,
    val tenantId: String,
    val subjectReference: String,
    val providerId: String,
    val operation: KycEvidencePortOperation,
    val canonicalStatus: KycCanonicalStatus,
    val vendorOutcome: KycVendorOutcome,
    val directEligibilityGranted: Boolean, // Invariant: client/vendor cannot grant eligibility
    val confidenceScore: Double?,
    val evidenceReference: String,
    val serverTime: Instant,
)

interface KycVendorAdapter {
    val providerId: String
    fun executeCheck(command: KycVendorEvidenceCommand): KycVendorExecutionResponse
    fun verifyWebhook(signature: String, rawPayload: String): KycCanonicalWebhookEvidence?
}

interface KycVendorEvidenceStore {
    fun findByIdempotency(tenantId: String, idempotencyKey: String): Pair<String, KycVendorEvidenceResult>?
    fun save(
        result: KycVendorEvidenceResult,
        tenantId: String,
        queryFingerprint: String,
        idempotencyKey: String,
        audit: AuditEvent,
        outbox: OutboxEvent,
    )
}

class KycVendorEvidencePortService(
    private val policy: AdminRbacPolicy,
    private val sessions: AdminSessionDirectory,
    private val store: KycVendorEvidenceStore,
    private val adapters: Map<String, KycVendorAdapter>,
    private val clock: Clock = Clock.systemUTC(),
) {
    @Synchronized
    fun executeOperation(command: KycVendorEvidenceCommand): KycVendorEvidenceResult {
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

        if (command.subjectReference.isBlank() ||
            command.sessionId.isBlank() ||
            command.correlationId.isBlank() ||
            command.causationId.isBlank()) {
            throw AuthenticationFailure.Rejected(AuthErrorCode.INVALID)
        }

        if (command.expectedVersion != 1L) {
            throw AuthenticationFailure.Rejected(AuthErrorCode.STALE)
        }

        val fp = fingerprintCommand(command)
        store.findByIdempotency(command.tenantId, command.idempotencyKey)?.let { (cachedFp, cachedResult) ->
            if (cachedFp != fp) throw AuthenticationFailure.Rejected(AuthErrorCode.CONFLICT)
            return cachedResult
        }

        val adapter = adapters[command.providerId]
            ?: throw AuthenticationFailure.Rejected(AuthErrorCode.FORBIDDEN)

        val response = try {
            adapter.executeCheck(command)
        } catch (_: Exception) {
            throw AuthenticationFailure.Rejected(AuthErrorCode.DEPENDENCY_UNAVAILABLE)
        }

        val canonicalStatus = when (response.outcome) {
            KycVendorOutcome.PASSED -> KycCanonicalStatus.EVIDENCE_COLLECTED
            KycVendorOutcome.FAILED -> KycCanonicalStatus.FAILED_CLOSED
            KycVendorOutcome.SUSPICIOUS -> KycCanonicalStatus.SUSPENDED
            KycVendorOutcome.INDETERMINATE -> KycCanonicalStatus.SUSPENDED
            KycVendorOutcome.OUTAGE -> KycCanonicalStatus.SUSPENDED
        }

        val resultId = UUID.randomUUID()
        val now = clock.instant()
        val result = KycVendorEvidenceResult(
            resultId = resultId,
            tenantId = command.tenantId,
            subjectReference = command.subjectReference,
            providerId = command.providerId,
            operation = command.operation,
            canonicalStatus = canonicalStatus,
            vendorOutcome = response.outcome,
            directEligibilityGranted = false,
            confidenceScore = response.confidenceScore,
            evidenceReference = response.minimalEvidenceReference,
            serverTime = now,
        )

        val audit = AuditEvent(
            eventId = UUID.randomUUID(),
            resultId = resultId,
            tenantId = command.tenantId,
            type = "KYC_VENDOR_CHECK_${command.operation.name}",
            occurredAt = now,
            correlationId = command.correlationId,
            causationId = command.causationId,
        )

        val outbox = OutboxEvent(
            eventId = UUID.randomUUID(),
            resultId = resultId,
            tenantId = command.tenantId,
            type = "KYC_VENDOR_CHECK_${command.operation.name}",
            createdAt = now,
        )

        store.save(result, command.tenantId, fp, command.idempotencyKey, audit, outbox)
        return result
    }

    @Synchronized
    fun processWebhook(command: KycWebhookEvidenceCommand): KycVendorEvidenceResult {
        if (command.tenantId.isBlank() ||
            command.providerId.isBlank() ||
            command.signatureHeader.isBlank() ||
            command.rawPayload.isBlank() ||
            command.idempotencyKey.isBlank() ||
            command.correlationId.isBlank() ||
            command.causationId.isBlank()) {
            throw AuthenticationFailure.Rejected(AuthErrorCode.INVALID)
        }

        val fp = fingerprintWebhook(command)
        store.findByIdempotency(command.tenantId, command.idempotencyKey)?.let { (cachedFp, cachedResult) ->
            if (cachedFp != fp) throw AuthenticationFailure.Rejected(AuthErrorCode.CONFLICT)
            return cachedResult
        }

        val adapter = adapters[command.providerId]
            ?: throw AuthenticationFailure.Rejected(AuthErrorCode.FORBIDDEN)

        val webhookEvidence = try {
            adapter.verifyWebhook(command.signatureHeader, command.rawPayload)
        } catch (_: Exception) {
            throw AuthenticationFailure.Rejected(AuthErrorCode.DEPENDENCY_UNAVAILABLE)
        } ?: throw AuthenticationFailure.Rejected(AuthErrorCode.FORBIDDEN)

        val canonicalStatus = when (webhookEvidence.outcome) {
            KycVendorOutcome.PASSED -> KycCanonicalStatus.EVIDENCE_COLLECTED
            KycVendorOutcome.FAILED -> KycCanonicalStatus.FAILED_CLOSED
            KycVendorOutcome.SUSPICIOUS -> KycCanonicalStatus.SUSPENDED
            KycVendorOutcome.INDETERMINATE -> KycCanonicalStatus.SUSPENDED
            KycVendorOutcome.OUTAGE -> KycCanonicalStatus.SUSPENDED
        }

        val resultId = UUID.randomUUID()
        val now = clock.instant()
        val result = KycVendorEvidenceResult(
            resultId = resultId,
            tenantId = command.tenantId,
            subjectReference = webhookEvidence.subjectReference,
            providerId = command.providerId,
            operation = KycEvidencePortOperation.PROCESS_WEBHOOK,
            canonicalStatus = canonicalStatus,
            vendorOutcome = webhookEvidence.outcome,
            directEligibilityGranted = false,
            confidenceScore = webhookEvidence.confidenceScore,
            evidenceReference = "EVID-WEBHOOK-${webhookEvidence.vendorCheckReference}",
            serverTime = now,
        )

        val audit = AuditEvent(
            eventId = UUID.randomUUID(),
            resultId = resultId,
            tenantId = command.tenantId,
            type = "KYC_VENDOR_WEBHOOK_PROCESSED",
            occurredAt = now,
            correlationId = command.correlationId,
            causationId = command.causationId,
        )

        val outbox = OutboxEvent(
            eventId = UUID.randomUUID(),
            resultId = resultId,
            tenantId = command.tenantId,
            type = "KYC_VENDOR_WEBHOOK_PROCESSED",
            createdAt = now,
        )

        store.save(result, command.tenantId, fp, command.idempotencyKey, audit, outbox)
        return result
    }

    private fun fingerprintCommand(cmd: KycVendorEvidenceCommand): String {
        val md = MessageDigest.getInstance("SHA-256")
        val raw = "${cmd.tenantId}:${cmd.providerId}:${cmd.subjectReference}:${cmd.operation}:${cmd.checkType}:${cmd.expectedVersion}"
        return md.digest(raw.toByteArray(Charsets.UTF_8)).joinToString("") { "%02x".format(it) }
    }

    private fun fingerprintWebhook(cmd: KycWebhookEvidenceCommand): String {
        val md = MessageDigest.getInstance("SHA-256")
        val raw = "${cmd.tenantId}:${cmd.providerId}:${cmd.rawPayload}"
        return md.digest(raw.toByteArray(Charsets.UTF_8)).joinToString("") { "%02x".format(it) }
    }
}
