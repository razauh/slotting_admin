package com.slotting.admin.geo

import com.slotting.admin.auth.*
import java.security.MessageDigest
import java.time.Clock
import java.time.Instant
import java.util.UUID

enum class GeoEvidencePortOperation {
    VERIFY_LOCATION,
    POLL_LOCATION,
    PROCESS_WEBHOOK,
}

enum class GeoCheckType {
    LOGIN_LOCATION,
    WAGER_LOCATION,
    WITHDRAWAL_LOCATION,
}

enum class GeoVendorOutcome {
    PERMITTED_JURISDICTION,
    PROHIBITED_JURISDICTION,
    SUSPECTED_PROXY_OR_VPN,
    INDETERMINATE,
    OUTAGE,
}

enum class GeoCanonicalStatus {
    PENDING,
    EVIDENCE_COLLECTED,
    SUSPENDED,
    FAILED_CLOSED,
}

data class GeoVendorEvidenceCommand(
    val principal: AuthenticatedPrincipal?,
    val sessionId: String,
    val tenantId: String,
    val subjectReference: String,
    val operation: GeoEvidencePortOperation,
    val checkType: GeoCheckType,
    val providerId: String,
    val ipAddress: String,
    val locationToken: String? = null,
    val idempotencyKey: String,
    val correlationId: String,
    val causationId: String,
    val expectedVersion: Long = 1L,
)

data class GeoWebhookEvidenceCommand(
    val tenantId: String,
    val providerId: String,
    val signatureHeader: String,
    val rawPayload: String,
    val idempotencyKey: String,
    val correlationId: String,
    val causationId: String,
)

data class GeoVendorExecutionResponse(
    val vendorCheckReference: String,
    val outcome: GeoVendorOutcome,
    val detectedJurisdiction: String?,
    val minimalEvidenceReference: String,
)

data class GeoCanonicalWebhookEvidence(
    val subjectReference: String,
    val checkType: GeoCheckType,
    val outcome: GeoVendorOutcome,
    val detectedJurisdiction: String?,
    val vendorCheckReference: String,
)

data class GeoVendorEvidenceResult(
    val resultId: UUID,
    val tenantId: String,
    val subjectReference: String,
    val providerId: String,
    val operation: GeoEvidencePortOperation,
    val canonicalStatus: GeoCanonicalStatus,
    val vendorOutcome: GeoVendorOutcome,
    val detectedJurisdiction: String?,
    val directEligibilityGranted: Boolean, // Invariant: client/vendor cannot grant eligibility
    val evidenceReference: String,
    val serverTime: Instant,
)

interface GeoVendorAdapter {
    val providerId: String
    fun executeCheck(command: GeoVendorEvidenceCommand): GeoVendorExecutionResponse
    fun verifyWebhook(signature: String, rawPayload: String): GeoCanonicalWebhookEvidence?
}

interface GeoVendorEvidenceStore {
    fun findByIdempotency(tenantId: String, idempotencyKey: String): Pair<String, GeoVendorEvidenceResult>?
    fun save(
        result: GeoVendorEvidenceResult,
        tenantId: String,
        queryFingerprint: String,
        idempotencyKey: String,
        audit: AuditEvent,
        outbox: OutboxEvent,
    )
}

class GeolocationVendorEvidencePortService(
    private val policy: AdminRbacPolicy,
    private val sessions: AdminSessionDirectory,
    private val store: GeoVendorEvidenceStore,
    private val adapters: Map<String, GeoVendorAdapter>,
    private val clock: Clock = Clock.systemUTC(),
) {
    @Synchronized
    fun executeOperation(command: GeoVendorEvidenceCommand): GeoVendorEvidenceResult {
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
            command.ipAddress.isBlank() ||
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
            GeoVendorOutcome.PERMITTED_JURISDICTION -> GeoCanonicalStatus.EVIDENCE_COLLECTED
            GeoVendorOutcome.PROHIBITED_JURISDICTION -> GeoCanonicalStatus.FAILED_CLOSED
            GeoVendorOutcome.SUSPECTED_PROXY_OR_VPN -> GeoCanonicalStatus.FAILED_CLOSED
            GeoVendorOutcome.INDETERMINATE -> GeoCanonicalStatus.SUSPENDED
            GeoVendorOutcome.OUTAGE -> GeoCanonicalStatus.SUSPENDED
        }

        val resultId = UUID.randomUUID()
        val now = clock.instant()
        val result = GeoVendorEvidenceResult(
            resultId = resultId,
            tenantId = command.tenantId,
            subjectReference = command.subjectReference,
            providerId = command.providerId,
            operation = command.operation,
            canonicalStatus = canonicalStatus,
            vendorOutcome = response.outcome,
            detectedJurisdiction = response.detectedJurisdiction,
            directEligibilityGranted = false,
            evidenceReference = response.minimalEvidenceReference,
            serverTime = now,
        )

        val audit = AuditEvent(
            eventId = UUID.randomUUID(),
            resultId = resultId,
            tenantId = command.tenantId,
            type = "GEO_VENDOR_CHECK_${command.operation.name}",
            occurredAt = now,
            correlationId = command.correlationId,
            causationId = command.causationId,
        )

        val outbox = OutboxEvent(
            eventId = UUID.randomUUID(),
            resultId = resultId,
            tenantId = command.tenantId,
            type = "GEO_VENDOR_CHECK_${command.operation.name}",
            createdAt = now,
        )

        store.save(result, command.tenantId, fp, command.idempotencyKey, audit, outbox)
        return result
    }

    @Synchronized
    fun processWebhook(command: GeoWebhookEvidenceCommand): GeoVendorEvidenceResult {
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
            GeoVendorOutcome.PERMITTED_JURISDICTION -> GeoCanonicalStatus.EVIDENCE_COLLECTED
            GeoVendorOutcome.PROHIBITED_JURISDICTION -> GeoCanonicalStatus.FAILED_CLOSED
            GeoVendorOutcome.SUSPECTED_PROXY_OR_VPN -> GeoCanonicalStatus.FAILED_CLOSED
            GeoVendorOutcome.INDETERMINATE -> GeoCanonicalStatus.SUSPENDED
            GeoVendorOutcome.OUTAGE -> GeoCanonicalStatus.SUSPENDED
        }

        val resultId = UUID.randomUUID()
        val now = clock.instant()
        val result = GeoVendorEvidenceResult(
            resultId = resultId,
            tenantId = command.tenantId,
            subjectReference = webhookEvidence.subjectReference,
            providerId = command.providerId,
            operation = GeoEvidencePortOperation.PROCESS_WEBHOOK,
            canonicalStatus = canonicalStatus,
            vendorOutcome = webhookEvidence.outcome,
            detectedJurisdiction = webhookEvidence.detectedJurisdiction,
            directEligibilityGranted = false,
            evidenceReference = "EVID-GEO-WEBHOOK-${webhookEvidence.vendorCheckReference}",
            serverTime = now,
        )

        val audit = AuditEvent(
            eventId = UUID.randomUUID(),
            resultId = resultId,
            tenantId = command.tenantId,
            type = "GEO_VENDOR_WEBHOOK_PROCESSED",
            occurredAt = now,
            correlationId = command.correlationId,
            causationId = command.causationId,
        )

        val outbox = OutboxEvent(
            eventId = UUID.randomUUID(),
            resultId = resultId,
            tenantId = command.tenantId,
            type = "GEO_VENDOR_WEBHOOK_PROCESSED",
            createdAt = now,
        )

        store.save(result, command.tenantId, fp, command.idempotencyKey, audit, outbox)
        return result
    }

    private fun fingerprintCommand(cmd: GeoVendorEvidenceCommand): String {
        val md = MessageDigest.getInstance("SHA-256")
        val raw = "${cmd.tenantId}:${cmd.providerId}:${cmd.subjectReference}:${cmd.operation}:${cmd.checkType}:${cmd.ipAddress}:${cmd.expectedVersion}"
        return md.digest(raw.toByteArray(Charsets.UTF_8)).joinToString("") { "%02x".format(it) }
    }

    private fun fingerprintWebhook(cmd: GeoWebhookEvidenceCommand): String {
        val md = MessageDigest.getInstance("SHA-256")
        val raw = "${cmd.tenantId}:${cmd.providerId}:${cmd.rawPayload}"
        return md.digest(raw.toByteArray(Charsets.UTF_8)).joinToString("") { "%02x".format(it) }
    }
}
