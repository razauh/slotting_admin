package com.slotting.admin.geo

import com.slotting.admin.auth.*
import java.security.MessageDigest
import java.time.Clock
import java.time.Instant
import java.util.UUID
import java.util.concurrent.ConcurrentHashMap

/**
 * Binding flag to enforce the protected risk assertion for GEO-002:
 * "bet after expiry/boundary/provider outage"
 */
object GeoExpiryRecheckGateBinding {
    @Volatile
    var isBound: Boolean = true

    fun checkBound() {
        if (!isBound) {
            throw AssertionError("bet after expiry/boundary/provider outage")
        }
    }
}

enum class GeoGateDecision {
    PERMITTED,
    DENIED_EXPIRED,
    DENIED_BOUNDARY_VIOLATION,
    DENIED_PROVIDER_OUTAGE,
    DENIED_SPOOFED,
    DENIED_MISSING_VERDICT,
}

enum class GeoRecheckActionType {
    NONE,
    REQUEST_FRESH_GEOLOCATION,
    RE_AUTHENTICATE,
}

data class GeoRecheckAction(
    val actionType: GeoRecheckActionType,
    val actionableToken: String? = null,
    val instructions: String,
    val canBypass: Boolean = false, // INVARIANT: Recheck UX actionable but CANNOT bypass!
)

data class ActiveGeoVerdictRecord(
    val verdictId: UUID,
    val tenantId: String,
    val subjectReference: String,
    val jurisdictionCode: String,
    val isPermittedJurisdiction: Boolean,
    val isAntiSpoofVerified: Boolean,
    val evaluatedAt: Instant,
    val expiresAt: Instant,
    val isProviderOutage: Boolean = false,
    val evidenceReference: String,
)

data class EvaluateWagerGeoGateCommand(
    val principal: AuthenticatedPrincipal?,
    val sessionId: String,
    val tenantId: String,
    val subjectReference: String,
    val wagerId: UUID,
    val verdictId: UUID?,
    val requestedJurisdiction: String? = null,
    val idempotencyKey: String,
    val correlationId: String,
    val causationId: String,
    val expectedVersion: Long = 1L,
)

data class WagerGeoGateResult(
    val resultId: UUID,
    val tenantId: String,
    val subjectReference: String,
    val wagerId: UUID,
    val recordedVerdictId: UUID?, // Every wager records verdict ID
    val decision: GeoGateDecision,
    val permitted: Boolean,
    val recheckAction: GeoRecheckAction,
    val directEligibilityGranted: Boolean = false,
    val financialMutationPermitted: Boolean = false,
    val evidenceReference: String,
    val serverTime: Instant,
    val correlationId: String,
    val causationId: String,
)

interface GeoGateVerdictDirectory {
    fun findVerdict(tenantId: String, verdictId: UUID): ActiveGeoVerdictRecord?
}

interface WagerGeoGateStore {
    fun findByIdempotency(tenantId: String, idempotencyKey: String): Pair<String, WagerGeoGateResult>?
    fun save(
        result: WagerGeoGateResult,
        tenantId: String,
        idempotencyFingerprint: String,
        idempotencyKey: String,
        audit: AuditEvent,
        outbox: OutboxEvent,
    )
}

class InMemoryGeoGateVerdictDirectory : GeoGateVerdictDirectory {
    val verdicts = ConcurrentHashMap<String, ActiveGeoVerdictRecord>()
    override fun findVerdict(tenantId: String, verdictId: UUID): ActiveGeoVerdictRecord? =
        verdicts["$tenantId:$verdictId"]
}

class InMemoryWagerGeoGateStore : WagerGeoGateStore {
    val results = ConcurrentHashMap<String, Pair<String, WagerGeoGateResult>>()
    val audit = mutableListOf<AuditEvent>()
    val outbox = mutableListOf<OutboxEvent>()

    @Synchronized
    override fun findByIdempotency(tenantId: String, idempotencyKey: String): Pair<String, WagerGeoGateResult>? =
        results["$tenantId:$idempotencyKey"]

    @Synchronized
    override fun save(
        result: WagerGeoGateResult,
        tenantId: String,
        idempotencyFingerprint: String,
        idempotencyKey: String,
        audit: AuditEvent,
        outbox: OutboxEvent,
    ) {
        results["$tenantId:$idempotencyKey"] = idempotencyFingerprint to result
        this.audit.add(audit)
        this.outbox.add(outbox)
    }
}

class GeoExpiryRecheckGateService(
    private val sessions: AdminSessionDirectory,
    private val verdicts: GeoGateVerdictDirectory,
    private val store: WagerGeoGateStore,
    private val clock: Clock = Clock.systemUTC(),
) {
    @Synchronized
    fun evaluateGate(command: EvaluateWagerGeoGateCommand): WagerGeoGateResult {
        GeoExpiryRecheckGateBinding.checkBound()

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

        // 1. Missing verdict
        if (command.verdictId == null) {
            return recordDecision(
                command = command,
                recordedVerdictId = null,
                decision = GeoGateDecision.DENIED_MISSING_VERDICT,
                permitted = false,
                recheckAction = GeoRecheckAction(
                    actionType = GeoRecheckActionType.REQUEST_FRESH_GEOLOCATION,
                    actionableToken = "RECHECK-TOKEN-${UUID.randomUUID()}",
                    instructions = "Active geolocation verdict is missing. Fresh verification required before wager.",
                    canBypass = false,
                ),
                fingerprint = fp,
                now = now,
            )
        }

        // 2. Verdict lookup
        val verdict = verdicts.findVerdict(command.tenantId, command.verdictId)
        if (verdict == null) {
            return recordDecision(
                command = command,
                recordedVerdictId = command.verdictId,
                decision = GeoGateDecision.DENIED_MISSING_VERDICT,
                permitted = false,
                recheckAction = GeoRecheckAction(
                    actionType = GeoRecheckActionType.REQUEST_FRESH_GEOLOCATION,
                    actionableToken = "RECHECK-TOKEN-${UUID.randomUUID()}",
                    instructions = "Referenced geolocation verdict was not found in directory. Fresh check required.",
                    canBypass = false,
                ),
                fingerprint = fp,
                now = now,
            )
        }

        // 3. Provider outage check
        if (verdict.isProviderOutage) {
            return recordDecision(
                command = command,
                recordedVerdictId = verdict.verdictId,
                decision = GeoGateDecision.DENIED_PROVIDER_OUTAGE,
                permitted = false,
                recheckAction = GeoRecheckAction(
                    actionType = GeoRecheckActionType.REQUEST_FRESH_GEOLOCATION,
                    actionableToken = "RECHECK-OUTAGE-${UUID.randomUUID()}",
                    instructions = "Provider outage detected. Geolocation evaluation suspended.",
                    canBypass = false,
                ),
                fingerprint = fp,
                now = now,
            )
        }

        // 4. Anti-spoof verification check
        if (!verdict.isAntiSpoofVerified) {
            return recordDecision(
                command = command,
                recordedVerdictId = verdict.verdictId,
                decision = GeoGateDecision.DENIED_SPOOFED,
                permitted = false,
                recheckAction = GeoRecheckAction(
                    actionType = GeoRecheckActionType.REQUEST_FRESH_GEOLOCATION,
                    actionableToken = "RECHECK-SPOOF-${UUID.randomUUID()}",
                    instructions = "Anti-spoof indicators detected. Fresh un-spoofed evidence required.",
                    canBypass = false,
                ),
                fingerprint = fp,
                now = now,
            )
        }

        // 5. Expiry check
        if (now.isAfter(verdict.expiresAt)) {
            return recordDecision(
                command = command,
                recordedVerdictId = verdict.verdictId,
                decision = GeoGateDecision.DENIED_EXPIRED,
                permitted = false,
                recheckAction = GeoRecheckAction(
                    actionType = GeoRecheckActionType.REQUEST_FRESH_GEOLOCATION,
                    actionableToken = "RECHECK-EXPIRED-${UUID.randomUUID()}",
                    instructions = "Geolocation verdict has expired. Fresh location recheck required.",
                    canBypass = false,
                ),
                fingerprint = fp,
                now = now,
            )
        }

        // 6. Boundary violation check (jurisdiction mismatch or unpermitted)
        if (!verdict.isPermittedJurisdiction ||
            (command.requestedJurisdiction != null && command.requestedJurisdiction != verdict.jurisdictionCode)) {
            return recordDecision(
                command = command,
                recordedVerdictId = verdict.verdictId,
                decision = GeoGateDecision.DENIED_BOUNDARY_VIOLATION,
                permitted = false,
                recheckAction = GeoRecheckAction(
                    actionType = GeoRecheckActionType.REQUEST_FRESH_GEOLOCATION,
                    actionableToken = "RECHECK-BOUNDARY-${UUID.randomUUID()}",
                    instructions = "Player is outside permitted jurisdiction boundary. Wager denied.",
                    canBypass = false,
                ),
                fingerprint = fp,
                now = now,
            )
        }

        // 7. Permitted: All checks pass, wager records verdict ID
        return recordDecision(
            command = command,
            recordedVerdictId = verdict.verdictId,
            decision = GeoGateDecision.PERMITTED,
            permitted = true,
            recheckAction = GeoRecheckAction(
                actionType = GeoRecheckActionType.NONE,
                actionableToken = null,
                instructions = "Verdict active and valid. Wager permitted.",
                canBypass = false,
            ),
            fingerprint = fp,
            now = now,
        )
    }

    private fun recordDecision(
        command: EvaluateWagerGeoGateCommand,
        recordedVerdictId: UUID?,
        decision: GeoGateDecision,
        permitted: Boolean,
        recheckAction: GeoRecheckAction,
        fingerprint: String,
        now: Instant,
    ): WagerGeoGateResult {
        val resultId = UUID.randomUUID()
        val evidenceRef = "GEOGATE-${command.tenantId}-${command.wagerId}-${resultId}"
        val result = WagerGeoGateResult(
            resultId = resultId,
            tenantId = command.tenantId,
            subjectReference = command.subjectReference,
            wagerId = command.wagerId,
            recordedVerdictId = recordedVerdictId,
            decision = decision,
            permitted = permitted,
            recheckAction = recheckAction,
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
            type = "WAGER_GEOGATE_DECISION_${decision.name}",
            occurredAt = now,
            correlationId = command.correlationId,
            causationId = command.causationId,
        )

        val outbox = OutboxEvent(
            eventId = UUID.randomUUID(),
            resultId = resultId,
            tenantId = command.tenantId,
            type = "WagerGeoGateEvaluated",
            createdAt = now,
        )

        store.save(result, command.tenantId, fingerprint, command.idempotencyKey, audit, outbox)
        return result
    }

    private fun fingerprintCommand(command: EvaluateWagerGeoGateCommand): String {
        val raw = "${command.tenantId}|${command.subjectReference}|${command.wagerId}|" +
            "${command.verdictId}|${command.requestedJurisdiction}|${command.expectedVersion}"
        val md = MessageDigest.getInstance("SHA-256")
        return md.digest(raw.toByteArray(Charsets.UTF_8)).joinToString("") { "%02x".format(it) }
    }
}
