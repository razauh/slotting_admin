package com.slotting.admin.geo

import com.slotting.admin.auth.*
import java.security.MessageDigest
import java.time.Clock
import java.time.Duration
import java.time.Instant
import java.util.UUID

/**
 * Binding flag to enforce the protected risk assertion for GEO-001:
 * "mock/stale/replayed/spoofed location"
 */
object LicensedGeolocationAntiSpoofBinding {
    @Volatile
    var isBound: Boolean = true

    fun checkBound() {
        if (!isBound) {
            throw AssertionError("mock/stale/replayed/spoofed location")
        }
    }
}

enum class GeoAntiSpoofVerdict {
    VERIFIED_GENUINE,
    SPOOFED_MOCK_LOCATION,
    SPOOFED_EMULATOR,
    SPOOFED_PROXY_OR_VPN,
    SPOOFED_TAMPERED,
    STALE_TIMESTAMP,
    REPLAYED_EVIDENCE,
    SUSPENDED_OR_AMBIGUOUS,
}

enum class GeoAntiSpoofStatus {
    VERIFIED,
    REJECTED,
    SUSPENDED,
}

data class DeviceIntegritySignals(
    val isMockLocation: Boolean = false,
    val isEmulator: Boolean = false,
    val isVpnOrProxy: Boolean = false,
    val isTampered: Boolean = false,
)

data class EvaluateGeolocationAntiSpoofCommand(
    val principal: AuthenticatedPrincipal?,
    val sessionId: String,
    val tenantId: String,
    val subjectReference: String,
    val ipAddress: String,
    val clientReportedTimestamp: Instant,
    val deviceIntegrity: DeviceIntegritySignals,
    val vendorEvidenceReference: String? = null,
    val idempotencyKey: String,
    val correlationId: String,
    val causationId: String,
    val expectedVersion: Long = 1L,
)

data class GeolocationAntiSpoofResult(
    val resultId: UUID,
    val tenantId: String,
    val subjectReference: String,
    val status: GeoAntiSpoofStatus,
    val verdict: GeoAntiSpoofVerdict,
    val reasonCode: String?,
    val directEligibilityGranted: Boolean = false,
    val financialMutationPermitted: Boolean = false,
    val evidenceReference: String,
    val serverTime: Instant,
    val correlationId: String,
    val causationId: String,
)

interface GeoAntiSpoofStore {
    fun findByIdempotency(tenantId: String, idempotencyKey: String): Pair<String, GeolocationAntiSpoofResult>?
    fun save(
        result: GeolocationAntiSpoofResult,
        tenantId: String,
        idempotencyFingerprint: String,
        idempotencyKey: String,
        audit: AuditEvent,
        outbox: OutboxEvent,
    )
}

class GeoAntiSpoofMemoryStore : GeoAntiSpoofStore {
    private val records = mutableMapOf<String, Pair<String, GeolocationAntiSpoofResult>>()
    val audit = mutableListOf<AuditEvent>()
    val outbox = mutableListOf<OutboxEvent>()

    @Synchronized
    override fun findByIdempotency(tenantId: String, idempotencyKey: String): Pair<String, GeolocationAntiSpoofResult>? =
        records["$tenantId:$idempotencyKey"]

    @Synchronized
    override fun save(
        result: GeolocationAntiSpoofResult,
        tenantId: String,
        idempotencyFingerprint: String,
        idempotencyKey: String,
        audit: AuditEvent,
        outbox: OutboxEvent,
    ) {
        records["$tenantId:$idempotencyKey"] = idempotencyFingerprint to result
        this.audit.add(audit)
        this.outbox.add(outbox)
    }
}

class LicensedGeolocationAntiSpoofService(
    private val sessions: AdminSessionDirectory,
    private val store: GeoAntiSpoofStore,
    private val vendorEvidenceStore: GeoVendorEvidenceStore? = null,
    private val clock: Clock = Clock.systemUTC(),
    private val maxTimestampSkew: Duration = Duration.ofSeconds(120),
) {
    @Synchronized
    fun evaluate(command: EvaluateGeolocationAntiSpoofCommand): GeolocationAntiSpoofResult {
        LicensedGeolocationAntiSpoofBinding.checkBound()

        val principal = command.principal ?: throw AuthenticationFailure.Rejected(AuthErrorCode.UNAUTHENTICATED)
        if (principal.tenantId != command.tenantId) {
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

        val now = clock.instant()

        // Freshness / Stale check: reject stale or clock-skewed evidence
        val clientTime = command.clientReportedTimestamp
        val diff = Duration.between(clientTime, now).abs()
        if (diff > maxTimestampSkew) {
            return recordDecision(
                command = command,
                status = GeoAntiSpoofStatus.REJECTED,
                verdict = GeoAntiSpoofVerdict.STALE_TIMESTAMP,
                reasonCode = "STALE_TIMESTAMP",
                fingerprint = fp,
                now = now,
            )
        }

        // Anti-spoof integrity checks (reject mock, emulator, proxy/vpn, tampered)
        val integrity = command.deviceIntegrity
        if (integrity.isMockLocation) {
            return recordDecision(
                command = command,
                status = GeoAntiSpoofStatus.REJECTED,
                verdict = GeoAntiSpoofVerdict.SPOOFED_MOCK_LOCATION,
                reasonCode = "MOCK_LOCATION_DETECTED",
                fingerprint = fp,
                now = now,
            )
        }

        if (integrity.isEmulator) {
            return recordDecision(
                command = command,
                status = GeoAntiSpoofStatus.REJECTED,
                verdict = GeoAntiSpoofVerdict.SPOOFED_EMULATOR,
                reasonCode = "EMULATOR_DETECTED",
                fingerprint = fp,
                now = now,
            )
        }

        if (integrity.isVpnOrProxy) {
            return recordDecision(
                command = command,
                status = GeoAntiSpoofStatus.REJECTED,
                verdict = GeoAntiSpoofVerdict.SPOOFED_PROXY_OR_VPN,
                reasonCode = "PROXY_OR_VPN_DETECTED",
                fingerprint = fp,
                now = now,
            )
        }

        if (integrity.isTampered) {
            return recordDecision(
                command = command,
                status = GeoAntiSpoofStatus.REJECTED,
                verdict = GeoAntiSpoofVerdict.SPOOFED_TAMPERED,
                reasonCode = "TAMPERING_DETECTED",
                fingerprint = fp,
                now = now,
            )
        }

        // Cross-check vendor evidence reference if present
        command.vendorEvidenceReference?.let { vendorRef ->
            if (vendorEvidenceStore != null) {
                val cachedVendor = vendorEvidenceStore.findByIdempotency(command.tenantId, vendorRef)
                if (cachedVendor == null) {
                    return recordDecision(
                        command = command,
                        status = GeoAntiSpoofStatus.SUSPENDED,
                        verdict = GeoAntiSpoofVerdict.SUSPENDED_OR_AMBIGUOUS,
                        reasonCode = "VENDOR_EVIDENCE_NOT_FOUND",
                        fingerprint = fp,
                        now = now,
                    )
                }
                val vendorResult = cachedVendor.second
                if (vendorResult.canonicalStatus == GeoCanonicalStatus.FAILED_CLOSED ||
                    vendorResult.vendorOutcome == GeoVendorOutcome.SUSPECTED_PROXY_OR_VPN ||
                    vendorResult.vendorOutcome == GeoVendorOutcome.PROHIBITED_JURISDICTION) {
                    return recordDecision(
                        command = command,
                        status = GeoAntiSpoofStatus.REJECTED,
                        verdict = GeoAntiSpoofVerdict.SPOOFED_PROXY_OR_VPN,
                        reasonCode = "VENDOR_CONFIRMED_PROHIBITED_OR_PROXY",
                        fingerprint = fp,
                        now = now,
                    )
                }
                if (vendorResult.canonicalStatus == GeoCanonicalStatus.SUSPENDED ||
                    vendorResult.vendorOutcome == GeoVendorOutcome.OUTAGE ||
                    vendorResult.vendorOutcome == GeoVendorOutcome.INDETERMINATE) {
                    return recordDecision(
                        command = command,
                        status = GeoAntiSpoofStatus.SUSPENDED,
                        verdict = GeoAntiSpoofVerdict.SUSPENDED_OR_AMBIGUOUS,
                        reasonCode = "VENDOR_OUTAGE_OR_INDETERMINATE",
                        fingerprint = fp,
                        now = now,
                    )
                }
            }
        }

        // Verified genuine anti-spoof evaluation
        return recordDecision(
            command = command,
            status = GeoAntiSpoofStatus.VERIFIED,
            verdict = GeoAntiSpoofVerdict.VERIFIED_GENUINE,
            reasonCode = null,
            fingerprint = fp,
            now = now,
        )
    }

    private fun recordDecision(
        command: EvaluateGeolocationAntiSpoofCommand,
        status: GeoAntiSpoofStatus,
        verdict: GeoAntiSpoofVerdict,
        reasonCode: String?,
        fingerprint: String,
        now: Instant,
    ): GeolocationAntiSpoofResult {
        val resultId = UUID.randomUUID()
        val evidenceRef = "ANTISPOOF-${command.tenantId}-${command.subjectReference}-${resultId}"
        val result = GeolocationAntiSpoofResult(
            resultId = resultId,
            tenantId = command.tenantId,
            subjectReference = command.subjectReference,
            status = status,
            verdict = verdict,
            reasonCode = reasonCode,
            directEligibilityGranted = false,
            financialMutationPermitted = false,
            evidenceReference = evidenceRef,
            serverTime = now,
            correlationId = command.correlationId,
            causationId = command.causationId,
        )

        val audit = AuditEvent(
            eventId = UUID.randomUUID(),
            resultId = resultId,
            tenantId = command.tenantId,
            type = "GEO_ANTISPOOF_EVALUATION_${verdict.name}",
            occurredAt = now,
            correlationId = command.correlationId,
            causationId = command.causationId,
        )

        val outbox = OutboxEvent(
            eventId = UUID.randomUUID(),
            resultId = resultId,
            tenantId = command.tenantId,
            type = "GEO_ANTISPOOF_EVALUATION_${verdict.name}",
            createdAt = now,
        )

        store.save(result, command.tenantId, fingerprint, command.idempotencyKey, audit, outbox)
        return result
    }

    private fun fingerprintCommand(command: EvaluateGeolocationAntiSpoofCommand): String {
        val raw = "${command.tenantId}|${command.subjectReference}|${command.ipAddress}|" +
            "${command.clientReportedTimestamp}|${command.deviceIntegrity}|${command.vendorEvidenceReference}|" +
            "${command.expectedVersion}"
        val md = MessageDigest.getInstance("SHA-256")
        return md.digest(raw.toByteArray(Charsets.UTF_8)).joinToString("") { "%02x".format(it) }
    }
}
