package com.slotting.admin.gameprovider

import com.slotting.admin.auth.AuditEvent
import com.slotting.admin.auth.AuthErrorCode
import com.slotting.admin.auth.AuthenticationFailure
import com.slotting.admin.auth.OutboxEvent
import com.slotting.admin.geo.GeoVendorOutcome
import java.nio.charset.StandardCharsets
import java.security.MessageDigest
import java.time.Clock
import java.time.Instant
import java.util.UUID
import java.util.concurrent.ConcurrentHashMap

/**
 * Gate to enforce GAME-004: Jurisdiction restrictions.
 * Protected risk: "location expiry/bypass"
 * Semantic contract: "Fail closed, reason safe for player, full reason restricted to ops."
 */
object JurisdictionRestrictionBinding {
    var isBound: Boolean = false

    fun checkBound() {
        if (!isBound) {
            throw AssertionError("location expiry/bypass")
        }
    }
}

enum class JurisdictionRestrictionDecision {
    PERMITTED,
    RESTRICTED_LOCATION_EXPIRED,
    RESTRICTED_BYPASS_DETECTED,
    RESTRICTED_UNLICENSED_JURISDICTION,
    RESTRICTED_GAME_TYPE_PROHIBITED,
    RESTRICTED_BET_LIMIT_EXCEEDED,
    RESTRICTED_INDETERMINATE_LOCATION,
    RESTRICTED_DEPENDENCY_FAILURE,
}

data class LocationEvidence(
    val evidenceId: UUID = UUID.randomUUID(),
    val tenantId: String,
    val playerId: UUID,
    val ipAddress: String,
    val countryCode: String,
    val jurisdictionCode: String,
    val latitude: Double? = null,
    val longitude: Double? = null,
    val accuracyMeters: Double? = null,
    val isProxyOrVpn: Boolean = false,
    val isMockLocation: Boolean = false,
    val confidenceScore: Double = 1.0,
    val vendorOutcome: GeoVendorOutcome = GeoVendorOutcome.PERMITTED_JURISDICTION,
    val verifiedAt: Instant,
    val expiresAt: Instant,
)

data class EvaluateJurisdictionRestrictionCommand(
    val tenantId: String,
    val playerId: UUID,
    val providerId: String,
    val gameId: String,
    val gameType: CasinoProviderType,
    val locationEvidence: LocationEvidence?,
    val clientReportedJurisdiction: String? = null,
    val requestedBetMinorUnits: Long? = null,
    val currencyCode: String = "USD",
    val idempotencyKey: String,
    val correlationId: String,
    val causationId: String,
    val expectedVersion: Long = 1L,
)

data class JurisdictionRestrictionResult(
    val resultId: UUID,
    val decision: JurisdictionRestrictionDecision,
    val permitted: Boolean,
    val tenantId: String,
    val playerId: UUID,
    val gameId: String,
    val evaluatedJurisdiction: String?,
    val playerSafeReason: String?,
    val opsDetailedReason: String?,
    val evidenceReference: String,
    val serverTime: Instant,
    val expectedNextCheckSeconds: Long,
)

interface JurisdictionRestrictionStore {
    fun findByIdempotency(tenantId: String, idempotencyKey: String): Pair<String, JurisdictionRestrictionResult>?
    fun saveDecision(
        result: JurisdictionRestrictionResult,
        idempotencyKey: String,
        fingerprint: String,
        audit: AuditEvent,
        outbox: OutboxEvent,
    )
    fun findLatestDecision(tenantId: String, playerId: UUID, gameId: String): JurisdictionRestrictionResult?
}

class InMemoryJurisdictionRestrictionStore : JurisdictionRestrictionStore {
    private val idempotency = ConcurrentHashMap<String, Pair<String, JurisdictionRestrictionResult>>()
    private val latestDecisions = ConcurrentHashMap<String, JurisdictionRestrictionResult>()
    val auditEvents = mutableListOf<AuditEvent>()
    val outboxEvents = mutableListOf<OutboxEvent>()

    @Synchronized
    override fun findByIdempotency(tenantId: String, idempotencyKey: String): Pair<String, JurisdictionRestrictionResult>? {
        return idempotency["$tenantId:$idempotencyKey"]
    }

    @Synchronized
    override fun saveDecision(
        result: JurisdictionRestrictionResult,
        idempotencyKey: String,
        fingerprint: String,
        audit: AuditEvent,
        outbox: OutboxEvent,
    ) {
        idempotency["${result.tenantId}:$idempotencyKey"] = fingerprint to result
        latestDecisions["${result.tenantId}:${result.playerId}:${result.gameId}"] = result
        auditEvents.add(audit)
        outboxEvents.add(outbox)
    }

    @Synchronized
    override fun findLatestDecision(tenantId: String, playerId: UUID, gameId: String): JurisdictionRestrictionResult? {
        return latestDecisions["$tenantId:$playerId:$gameId"]
    }
}

interface JurisdictionAlertSink {
    fun sendAlert(tenantId: String, severity: String, alertType: String, detail: String)
}

class InMemoryJurisdictionAlertSink : JurisdictionAlertSink {
    val alerts = mutableListOf<String>()
    override fun sendAlert(tenantId: String, severity: String, alertType: String, detail: String) {
        alerts.add("$tenantId:$severity:$alertType:$detail")
    }
}

class JurisdictionRestrictionService(
    private val operatorJurisdictionService: OperatorJurisdictionEnablementService,
    private val catalogStore: AuthoritativeCatalogStore,
    private val store: JurisdictionRestrictionStore,
    private val alertSink: JurisdictionAlertSink = InMemoryJurisdictionAlertSink(),
    private val clock: Clock = Clock.systemUTC(),
    private val maxLocationAgeSeconds: Long = 900L, // 15-minute max location freshness
    private val minimumConfidenceThreshold: Double = 0.70,
) {

    private fun sha256(input: String): String {
        val digest = MessageDigest.getInstance("SHA-256")
        val hash = digest.digest(input.toByteArray(StandardCharsets.UTF_8))
        return hash.joinToString("") { "%02x".format(it) }
    }

    private fun fingerprintCommand(cmd: EvaluateJurisdictionRestrictionCommand): String {
        val locHash = cmd.locationEvidence?.let {
            "${it.ipAddress}:${it.jurisdictionCode}:${it.verifiedAt.toEpochMilli()}:${it.isProxyOrVpn}"
        } ?: "NO_LOCATION"
        return sha256("${cmd.tenantId}:${cmd.playerId}:${cmd.providerId}:${cmd.gameId}:${cmd.gameType}:${cmd.requestedBetMinorUnits}:$locHash:${cmd.expectedVersion}")
    }

    @Synchronized
    fun evaluateRestrictions(command: EvaluateJurisdictionRestrictionCommand): JurisdictionRestrictionResult {
        JurisdictionRestrictionBinding.checkBound()

        // 1. Validation of essential fields
        if (command.tenantId.isBlank() ||
            command.providerId.isBlank() ||
            command.gameId.isBlank() ||
            command.idempotencyKey.isBlank() ||
            command.correlationId.isBlank() ||
            command.causationId.isBlank() ||
            (command.requestedBetMinorUnits != null && command.requestedBetMinorUnits < 0) ||
            !command.currencyCode.matches(Regex("[A-Z]{3}"))
        ) {
            throw AuthenticationFailure.Rejected(AuthErrorCode.INVALID)
        }

        if (command.expectedVersion != 1L) {
            throw AuthenticationFailure.Rejected(AuthErrorCode.STALE)
        }

        // 2. Idempotency Check
        val fp = fingerprintCommand(command)
        store.findByIdempotency(command.tenantId, command.idempotencyKey)?.let { (cachedFp, cachedResult) ->
            if (cachedFp != fp) throw AuthenticationFailure.Rejected(AuthErrorCode.CONFLICT)
            return cachedResult
        }

        val now = clock.instant()
        val resultId = UUID.randomUUID()

        // 3. Location Evidence & Freshness Evaluation (Protected Risk: Location Expiry / Bypass)
        val evidence = command.locationEvidence
        if (evidence == null) {
            return recordDecision(
                decision = JurisdictionRestrictionDecision.RESTRICTED_INDETERMINATE_LOCATION,
                permitted = false,
                command = command,
                resultId = resultId,
                evaluatedJurisdiction = null,
                playerSafeReason = "Unable to verify your location. Please check your device location settings.",
                opsDetailedReason = "Fail closed: Location evidence is missing or null for player ${command.playerId}",
                fingerprint = fp,
                now = now,
                nextCheckSeconds = 60L,
            )
        }

        // Check if evidence belongs to this tenant and player
        if (evidence.tenantId != command.tenantId || evidence.playerId != command.playerId) {
            alertSink.sendAlert(
                tenantId = command.tenantId,
                severity = "HIGH",
                alertType = "LOCATION_EVIDENCE_MISMATCH",
                detail = "Location evidence mismatch for player ${command.playerId}",
            )
            return recordDecision(
                decision = JurisdictionRestrictionDecision.RESTRICTED_BYPASS_DETECTED,
                permitted = false,
                command = command,
                resultId = resultId,
                evaluatedJurisdiction = evidence.jurisdictionCode,
                playerSafeReason = "Location verification error. Please reconnect.",
                opsDetailedReason = "Fail closed: Location evidence ownership mismatch: evidence.playerId=${evidence.playerId} vs cmd.playerId=${command.playerId}",
                fingerprint = fp,
                now = now,
                nextCheckSeconds = 60L,
            )
        }

        // Check location expiry (Protected Risk: Location Expiry)
        val locationAgeSeconds = now.epochSecond - evidence.verifiedAt.epochSecond
        val isExpired = now.isAfter(evidence.expiresAt) || locationAgeSeconds > maxLocationAgeSeconds
        if (isExpired) {
            return recordDecision(
                decision = JurisdictionRestrictionDecision.RESTRICTED_LOCATION_EXPIRED,
                permitted = false,
                command = command,
                resultId = resultId,
                evaluatedJurisdiction = evidence.jurisdictionCode,
                playerSafeReason = "Location verification expired. Please re-verify your location to continue.",
                opsDetailedReason = "Fail closed: Location evidence expired (age=${locationAgeSeconds}s > maxTTL=${maxLocationAgeSeconds}s, expiresAt=${evidence.expiresAt})",
                fingerprint = fp,
                now = now,
                nextCheckSeconds = 30L,
            )
        }

        // Check location bypass / spoofing (Protected Risk: Location Bypass)
        if (evidence.isProxyOrVpn || evidence.isMockLocation || evidence.vendorOutcome == GeoVendorOutcome.SUSPECTED_PROXY_OR_VPN) {
            alertSink.sendAlert(
                tenantId = command.tenantId,
                severity = "HIGH",
                alertType = "GEO_LOCATION_BYPASS_ATTEMPT",
                detail = "Proxy/VPN or mock location detected: IP=${evidence.ipAddress}, mock=${evidence.isMockLocation}, proxy=${evidence.isProxyOrVpn}",
            )
            return recordDecision(
                decision = JurisdictionRestrictionDecision.RESTRICTED_BYPASS_DETECTED,
                permitted = false,
                command = command,
                resultId = resultId,
                evaluatedJurisdiction = evidence.jurisdictionCode,
                playerSafeReason = "Game is unavailable from your current network or location.",
                opsDetailedReason = "Fail closed: Proxy/VPN or mock location bypass detected: IP=${evidence.ipAddress}, isProxyOrVpn=${evidence.isProxyOrVpn}, isMockLocation=${evidence.isMockLocation}, vendorOutcome=${evidence.vendorOutcome}",
                fingerprint = fp,
                now = now,
                nextCheckSeconds = 120L,
            )
        }

        // Check confidence and vendor indeterminate outcome
        if (evidence.confidenceScore < minimumConfidenceThreshold ||
            evidence.vendorOutcome == GeoVendorOutcome.INDETERMINATE ||
            evidence.vendorOutcome == GeoVendorOutcome.OUTAGE
        ) {
            return recordDecision(
                decision = JurisdictionRestrictionDecision.RESTRICTED_INDETERMINATE_LOCATION,
                permitted = false,
                command = command,
                resultId = resultId,
                evaluatedJurisdiction = evidence.jurisdictionCode,
                playerSafeReason = "Unable to reliably verify your location. Please try again.",
                opsDetailedReason = "Fail closed: Location confidence (${evidence.confidenceScore} < $minimumConfidenceThreshold) or vendor status (${evidence.vendorOutcome}) indeterminate",
                fingerprint = fp,
                now = now,
                nextCheckSeconds = 60L,
            )
        }

        // Check if vendor outcome is explicitly prohibited
        if (evidence.vendorOutcome == GeoVendorOutcome.PROHIBITED_JURISDICTION) {
            return recordDecision(
                decision = JurisdictionRestrictionDecision.RESTRICTED_UNLICENSED_JURISDICTION,
                permitted = false,
                command = command,
                resultId = resultId,
                evaluatedJurisdiction = evidence.jurisdictionCode,
                playerSafeReason = "This game is not available in your region.",
                opsDetailedReason = "Fail closed: Geo vendor flagged jurisdiction ${evidence.jurisdictionCode} as PROHIBITED_JURISDICTION",
                fingerprint = fp,
                now = now,
                nextCheckSeconds = 300L,
            )
        }

        val evaluatedJurisdiction = evidence.jurisdictionCode

        // 4. Authoritative Catalog & Game Jurisdiction Support Check
        val game = try {
            catalogStore.findGame(command.tenantId, command.providerId, command.gameId)
        } catch (e: Exception) {
            return recordDecision(
                decision = JurisdictionRestrictionDecision.RESTRICTED_DEPENDENCY_FAILURE,
                permitted = false,
                command = command,
                resultId = resultId,
                evaluatedJurisdiction = evaluatedJurisdiction,
                playerSafeReason = "Game service is temporarily unavailable. Please try again later.",
                opsDetailedReason = "Fail closed: Catalog lookup dependency failed: ${e.message}",
                fingerprint = fp,
                now = now,
                nextCheckSeconds = 60L,
            )
        }

        if (game == null) {
            return recordDecision(
                decision = JurisdictionRestrictionDecision.RESTRICTED_UNLICENSED_JURISDICTION,
                permitted = false,
                command = command,
                resultId = resultId,
                evaluatedJurisdiction = evaluatedJurisdiction,
                playerSafeReason = "Game not found or unavailable in your region.",
                opsDetailedReason = "Fail closed: Game ${command.gameId} not present in catalog for provider ${command.providerId}",
                fingerprint = fp,
                now = now,
                nextCheckSeconds = 300L,
            )
        }

        if (!game.supportedJurisdictions.contains(evaluatedJurisdiction)) {
            return recordDecision(
                decision = JurisdictionRestrictionDecision.RESTRICTED_UNLICENSED_JURISDICTION,
                permitted = false,
                command = command,
                resultId = resultId,
                evaluatedJurisdiction = evaluatedJurisdiction,
                playerSafeReason = "This game is not available in your region.",
                opsDetailedReason = "Fail closed: Evaluated jurisdiction $evaluatedJurisdiction not in game supportedJurisdictions: ${game.supportedJurisdictions}",
                fingerprint = fp,
                now = now,
                nextCheckSeconds = 300L,
            )
        }

        // 5. Operator & Jurisdiction Regulatory Policy Check (GAME-002-02)
        val eligibility = try {
            operatorJurisdictionService.evaluateEligibility(
                EvaluateGameLaunchEligibilityCommand(
                    tenantId = command.tenantId,
                    providerId = command.providerId,
                    gameId = command.gameId,
                    playerId = command.playerId.toString(),
                    jurisdictionCode = evaluatedJurisdiction,
                    requestedBetMinorUnits = command.requestedBetMinorUnits ?: game.minBetMinorUnits,
                    currencyCode = command.currencyCode,
                )
            )
        } catch (e: Exception) {
            return recordDecision(
                decision = JurisdictionRestrictionDecision.RESTRICTED_DEPENDENCY_FAILURE,
                permitted = false,
                command = command,
                resultId = resultId,
                evaluatedJurisdiction = evaluatedJurisdiction,
                playerSafeReason = "Compliance verification is temporarily unavailable. Please try again later.",
                opsDetailedReason = "Fail closed: Operator jurisdiction service evaluation failed: ${e.message}",
                fingerprint = fp,
                now = now,
                nextCheckSeconds = 60L,
            )
        }

        if (!eligibility.eligible) {
            val (decision, playerSafe, opsDetail) = when {
                eligibility.unlicensedDetected -> Triple(
                    JurisdictionRestrictionDecision.RESTRICTED_UNLICENSED_JURISDICTION,
                    "This game is not available in your region.",
                    "Fail closed: Unlicensed jurisdiction or restricted game in jurisdiction $evaluatedJurisdiction: ${eligibility.rejectionDetail}",
                )
                eligibility.disabledDetected -> Triple(
                    JurisdictionRestrictionDecision.RESTRICTED_GAME_TYPE_PROHIBITED,
                    "This game is currently disabled.",
                    "Fail closed: Game disabled by operator or regulatory policy: ${eligibility.rejectionDetail}",
                )
                eligibility.staleSyncDetected -> Triple(
                    JurisdictionRestrictionDecision.RESTRICTED_DEPENDENCY_FAILURE,
                    "Game is undergoing routine maintenance. Please try again shortly.",
                    "Fail closed: Stale catalog sync detected for game ${command.gameId}: ${eligibility.rejectionDetail}",
                )
                else -> Triple(
                    JurisdictionRestrictionDecision.RESTRICTED_BET_LIMIT_EXCEEDED,
                    "Requested bet exceeds regulatory limit for your region.",
                    "Fail closed: Bet limit or RTP compliance check failed: ${eligibility.rejectionDetail}",
                )
            }

            return recordDecision(
                decision = decision,
                permitted = false,
                command = command,
                resultId = resultId,
                evaluatedJurisdiction = evaluatedJurisdiction,
                playerSafeReason = playerSafe,
                opsDetailedReason = opsDetail,
                fingerprint = fp,
                now = now,
                nextCheckSeconds = 120L,
            )
        }

        // 6. PERMITTED outcome: Location verified, jurisdiction licensed, game allowed
        return recordDecision(
            decision = JurisdictionRestrictionDecision.PERMITTED,
            permitted = true,
            command = command,
            resultId = resultId,
            evaluatedJurisdiction = evaluatedJurisdiction,
            playerSafeReason = null,
            opsDetailedReason = "Permitted: Verified location in jurisdiction $evaluatedJurisdiction with confidence ${evidence.confidenceScore}; game ${command.gameId} (${command.gameType}) compliant.",
            fingerprint = fp,
            now = now,
            nextCheckSeconds = 900L,
        )
    }

    private fun recordDecision(
        decision: JurisdictionRestrictionDecision,
        permitted: Boolean,
        command: EvaluateJurisdictionRestrictionCommand,
        resultId: UUID,
        evaluatedJurisdiction: String?,
        playerSafeReason: String?,
        opsDetailedReason: String?,
        fingerprint: String,
        now: Instant,
        nextCheckSeconds: Long,
    ): JurisdictionRestrictionResult {
        val evidenceRef = sha256("${command.tenantId}:${command.playerId}:${command.gameId}:$decision:${now.toEpochMilli()}")

        val result = JurisdictionRestrictionResult(
            resultId = resultId,
            decision = decision,
            permitted = permitted,
            tenantId = command.tenantId,
            playerId = command.playerId,
            gameId = command.gameId,
            evaluatedJurisdiction = evaluatedJurisdiction,
            playerSafeReason = playerSafeReason,
            opsDetailedReason = opsDetailedReason,
            evidenceReference = evidenceRef,
            serverTime = now,
            expectedNextCheckSeconds = nextCheckSeconds,
        )

        val eventType = if (permitted) "JURISDICTION_RESTRICTION_PERMITTED" else "JURISDICTION_RESTRICTION_ENFORCED"

        // Redacted structured audit and outbox:
        // Audit contains full ops detail for compliance/investigations
        // Outbox contains player-safe metadata (no secrets/PII)
        val audit = AuditEvent(
            eventId = UUID.randomUUID(),
            resultId = resultId,
            tenantId = command.tenantId,
            type = eventType,
            occurredAt = now,
            correlationId = command.correlationId,
            causationId = command.causationId,
        )

        val outbox = OutboxEvent(
            eventId = UUID.randomUUID(),
            resultId = resultId,
            tenantId = command.tenantId,
            type = eventType,
            createdAt = now,
        )

        store.saveDecision(
            result = result,
            idempotencyKey = command.idempotencyKey,
            fingerprint = fingerprint,
            audit = audit,
            outbox = outbox,
        )

        return result
    }
}
