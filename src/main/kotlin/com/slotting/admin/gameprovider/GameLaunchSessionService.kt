package com.slotting.admin.gameprovider

import com.slotting.admin.auth.AuditEvent
import com.slotting.admin.auth.AuthErrorCode
import com.slotting.admin.auth.AuthenticationFailure
import com.slotting.admin.auth.OutboxEvent
import com.slotting.admin.identity.AmlComplianceStatus
import com.slotting.admin.identity.KycComplianceStatus
import com.slotting.admin.identity.PlayerAccountStatus
import com.slotting.admin.identity.PlayerComplianceProfile
import com.slotting.admin.identity.PlayerRegistrationRecord
import com.slotting.admin.identity.PlayerRegistrationStore
import com.slotting.admin.identity.ResponsiblePlayProfile
import com.slotting.admin.identity.ServerEligibilityStore
import com.slotting.admin.identity.ServerEligibilityVerdict
import java.nio.charset.StandardCharsets
import java.security.MessageDigest
import java.security.SecureRandom
import java.time.Clock
import java.time.Instant
import java.time.LocalDate
import java.time.Period
import java.time.ZoneOffset
import java.util.UUID
import java.util.concurrent.ConcurrentHashMap

/**
 * Gate to enforce GAME-003: Launch sessions/tokens.
 * Protected risk: "replay/expired/wrong-player token"
 * Semantic contract: "Launch rechecks jurisdiction/account/game and emits session correlation."
 */
object GameLaunchTokenBinding {
    var isBound: Boolean = false

    fun checkBound() {
        if (!isBound) {
            throw AssertionError("replay/expired/wrong-player token")
        }
    }
}

enum class GameLaunchSessionStatus {
    ISSUED,
    ACTIVE,
    CONSUMED,
    EXPIRED,
    TERMINATED,
    REJECTED
}

enum class LaunchTokenStatus {
    ACTIVE,
    CONSUMED,
    EXPIRED,
    REVOKED
}

data class GameLaunchSessionRecord(
    val sessionId: UUID,
    val tenantId: String,
    val playerId: UUID,
    val providerId: String,
    val gameId: String,
    val jurisdictionCode: String,
    val currencyCode: String,
    val sessionCorrelationId: String,
    val tokenHash: String,
    var tokenStatus: LaunchTokenStatus,
    var status: GameLaunchSessionStatus,
    val issuedAt: Instant,
    val tokenExpiresAt: Instant,
    val sessionExpiresAt: Instant,
    var consumedAt: Instant? = null,
    var terminatedAt: Instant? = null,
    var terminationReason: String? = null,
    val eligibilityDecisionId: UUID,
    val eligibilityVersion: Long,
    val launchUrl: String,
    var version: Long = 1L,
)

data class RequestGameLaunchSessionCommand(
    val tenantId: String,
    val playerId: UUID,
    val providerId: String,
    val gameId: String,
    val jurisdictionCode: String,
    val currencyCode: String,
    val requestedBetMinorUnits: Long = 100L,
    val clientIp: String? = null,
    val deviceId: String? = null,
    val idempotencyKey: String,
    val correlationId: String,
    val causationId: String,
    val expectedVersion: Long = 1L,
)

data class ValidateLaunchTokenCommand(
    val tenantId: String,
    val sessionId: UUID,
    val launchToken: String,
    val playerId: UUID,
    val providerId: String,
    val gameId: String,
    val correlationId: String,
    val causationId: String,
)

data class TerminateLaunchSessionCommand(
    val tenantId: String,
    val sessionId: UUID,
    val playerId: UUID,
    val reason: String,
    val idempotencyKey: String,
    val correlationId: String,
    val causationId: String,
    val expectedVersion: Long = 1L,
)

data class GameLaunchSessionResult(
    val resultId: UUID,
    val sessionId: UUID,
    val tenantId: String,
    val playerId: UUID,
    val providerId: String,
    val gameId: String,
    val jurisdictionCode: String,
    val currencyCode: String,
    val sessionCorrelationId: String,
    val launchToken: String,
    val launchUrl: String,
    val tokenExpiresAt: Instant,
    val sessionExpiresAt: Instant,
    val status: GameLaunchSessionStatus,
    val serverTime: Instant,
    val evidenceReference: String,
)

data class ValidateLaunchTokenResult(
    val resultId: UUID,
    val sessionId: UUID,
    val sessionCorrelationId: String,
    val tenantId: String,
    val playerId: UUID,
    val providerId: String,
    val gameId: String,
    val currencyCode: String,
    val authorized: Boolean,
    val sessionStatus: GameLaunchSessionStatus,
    val serverTime: Instant,
    val evidenceReference: String,
)

data class TerminateLaunchSessionResult(
    val resultId: UUID,
    val sessionId: UUID,
    val status: GameLaunchSessionStatus,
    val terminatedAt: Instant,
    val serverTime: Instant,
    val evidenceReference: String,
)

interface GameLaunchSessionStore {
    fun findSession(tenantId: String, sessionId: UUID): GameLaunchSessionRecord?
    fun saveSession(
        session: GameLaunchSessionRecord,
        result: GameLaunchSessionResult,
        idempotencyKey: String,
        fingerprint: String,
        audit: AuditEvent,
        outbox: OutboxEvent,
    )
    fun updateSession(
        session: GameLaunchSessionRecord,
        audit: AuditEvent,
        outbox: OutboxEvent,
    )
    fun findLaunchByIdempotency(tenantId: String, idempotencyKey: String): Pair<String, GameLaunchSessionResult>?
    fun findTerminationByIdempotency(tenantId: String, idempotencyKey: String): Pair<String, TerminateLaunchSessionResult>?
    fun saveTerminationIdempotency(
        tenantId: String,
        idempotencyKey: String,
        fingerprint: String,
        result: TerminateLaunchSessionResult,
    )
    fun findActiveSessionsForPlayer(tenantId: String, playerId: UUID): List<GameLaunchSessionRecord>
}

class InMemoryGameLaunchSessionStore : GameLaunchSessionStore {
    private val sessions = ConcurrentHashMap<String, GameLaunchSessionRecord>()
    private val launchIdempotency = ConcurrentHashMap<String, Pair<String, GameLaunchSessionResult>>()
    private val terminationIdempotency = ConcurrentHashMap<String, Pair<String, TerminateLaunchSessionResult>>()
    val auditEvents = mutableListOf<AuditEvent>()
    val outboxEvents = mutableListOf<OutboxEvent>()

    private fun key(tenantId: String, sessionId: UUID) = "$tenantId:$sessionId"

    @Synchronized
    override fun findSession(tenantId: String, sessionId: UUID): GameLaunchSessionRecord? {
        return sessions[key(tenantId, sessionId)]?.copy()
    }

    @Synchronized
    override fun saveSession(
        session: GameLaunchSessionRecord,
        result: GameLaunchSessionResult,
        idempotencyKey: String,
        fingerprint: String,
        audit: AuditEvent,
        outbox: OutboxEvent,
    ) {
        sessions[key(session.tenantId, session.sessionId)] = session.copy()
        launchIdempotency["${session.tenantId}:$idempotencyKey"] = fingerprint to result
        auditEvents.add(audit)
        outboxEvents.add(outbox)
    }

    @Synchronized
    override fun updateSession(
        session: GameLaunchSessionRecord,
        audit: AuditEvent,
        outbox: OutboxEvent,
    ) {
        sessions[key(session.tenantId, session.sessionId)] = session.copy()
        auditEvents.add(audit)
        outboxEvents.add(outbox)
    }

    @Synchronized
    override fun findLaunchByIdempotency(tenantId: String, idempotencyKey: String): Pair<String, GameLaunchSessionResult>? {
        return launchIdempotency["$tenantId:$idempotencyKey"]
    }

    @Synchronized
    override fun findTerminationByIdempotency(tenantId: String, idempotencyKey: String): Pair<String, TerminateLaunchSessionResult>? {
        return terminationIdempotency["$tenantId:$idempotencyKey"]
    }

    @Synchronized
    override fun saveTerminationIdempotency(
        tenantId: String,
        idempotencyKey: String,
        fingerprint: String,
        result: TerminateLaunchSessionResult,
    ) {
        terminationIdempotency["$tenantId:$idempotencyKey"] = fingerprint to result
    }

    @Synchronized
    override fun findActiveSessionsForPlayer(tenantId: String, playerId: UUID): List<GameLaunchSessionRecord> {
        return sessions.values
            .filter { it.tenantId == tenantId && it.playerId == playerId && it.status == GameLaunchSessionStatus.ACTIVE }
            .map { it.copy() }
    }
}

interface GameLaunchAlertSink {
    fun sendAlert(tenantId: String, severity: String, alertType: String, detail: String)
}

class InMemoryGameLaunchAlertSink : GameLaunchAlertSink {
    val alerts = mutableListOf<String>()
    override fun sendAlert(tenantId: String, severity: String, alertType: String, detail: String) {
        alerts.add("$tenantId:$severity:$alertType:$detail")
    }
}

class GameLaunchSessionService(
    private val operatorEnablementService: OperatorJurisdictionEnablementService,
    private val registrationStore: PlayerRegistrationStore,
    private val eligibilityStore: ServerEligibilityStore,
    private val launchStore: GameLaunchSessionStore,
    private val alertSink: GameLaunchAlertSink = InMemoryGameLaunchAlertSink(),
    private val clock: Clock = Clock.systemUTC(),
    private val tokenTtlSeconds: Long = 120L,
    private val sessionTtlSeconds: Long = 7200L,
) {
    private val secureRandom = SecureRandom()

    private fun sha256(input: String): String {
        val digest = MessageDigest.getInstance("SHA-256")
        val hash = digest.digest(input.toByteArray(StandardCharsets.UTF_8))
        return hash.joinToString("") { "%02x".format(it) }
    }

    private fun generateRandomToken(): String {
        val bytes = ByteArray(32)
        secureRandom.nextBytes(bytes)
        return "launch_tok_" + bytes.joinToString("") { "%02x".format(it) }
    }

    private fun fingerprintRequest(cmd: RequestGameLaunchSessionCommand): String {
        return sha256("${cmd.tenantId}:${cmd.playerId}:${cmd.providerId}:${cmd.gameId}:${cmd.jurisdictionCode}:${cmd.currencyCode}:${cmd.requestedBetMinorUnits}:${cmd.expectedVersion}")
    }

    private fun fingerprintTerminate(cmd: TerminateLaunchSessionCommand): String {
        return sha256("${cmd.tenantId}:${cmd.sessionId}:${cmd.playerId}:${cmd.reason}:${cmd.expectedVersion}")
    }

    @Synchronized
    fun requestLaunchSession(command: RequestGameLaunchSessionCommand): GameLaunchSessionResult {
        GameLaunchTokenBinding.checkBound()

        // 1. Structural Validation
        if (command.tenantId.isBlank() ||
            command.providerId.isBlank() ||
            command.gameId.isBlank() ||
            command.jurisdictionCode.isBlank() ||
            command.idempotencyKey.isBlank() ||
            command.correlationId.isBlank() ||
            command.causationId.isBlank() ||
            command.requestedBetMinorUnits < 0 ||
            !command.currencyCode.matches(Regex("[A-Z]{3}"))
        ) {
            throw AuthenticationFailure.Rejected(AuthErrorCode.INVALID)
        }

        if (command.expectedVersion != 1L) {
            throw AuthenticationFailure.Rejected(AuthErrorCode.STALE)
        }

        // 2. Idempotency Check
        val fp = fingerprintRequest(command)
        launchStore.findLaunchByIdempotency(command.tenantId, command.idempotencyKey)?.let { (cachedFp, cachedResult) ->
            if (cachedFp != fp) throw AuthenticationFailure.Rejected(AuthErrorCode.CONFLICT)
            return cachedResult
        }

        val now = clock.instant()

        // 3. Recheck Game & Jurisdiction Enablement (GAME-002-02)
        val gameEligibility = try {
            operatorEnablementService.evaluateEligibility(
                EvaluateGameLaunchEligibilityCommand(
                    tenantId = command.tenantId,
                    providerId = command.providerId,
                    gameId = command.gameId,
                    playerId = command.playerId.toString(),
                    jurisdictionCode = command.jurisdictionCode,
                    requestedBetMinorUnits = command.requestedBetMinorUnits,
                    currencyCode = command.currencyCode,
                )
            )
        } catch (e: AuthenticationFailure) {
            throw e
        } catch (e: Exception) {
            throw AuthenticationFailure.Rejected(AuthErrorCode.DEPENDENCY_UNAVAILABLE)
        }

        if (!gameEligibility.eligible) {
            val reason = gameEligibility.rejectionReasonCode ?: AuthErrorCode.FORBIDDEN
            val eventType = when {
                gameEligibility.staleSyncDetected -> "LAUNCH_SESSION_REJECTED_STALE_SYNC"
                gameEligibility.unlicensedDetected -> "LAUNCH_SESSION_REJECTED_UNLICENSED"
                gameEligibility.disabledDetected -> "LAUNCH_SESSION_REJECTED_GAME_DISABLED"
                else -> "LAUNCH_SESSION_REJECTED_INVALID_BET"
            }

            val audit = AuditEvent(
                eventId = UUID.randomUUID(),
                resultId = UUID.randomUUID(),
                tenantId = command.tenantId,
                type = eventType,
                occurredAt = now,
                correlationId = command.correlationId,
                causationId = command.causationId,
            )
            val outbox = OutboxEvent(
                eventId = UUID.randomUUID(),
                resultId = audit.resultId,
                tenantId = command.tenantId,
                type = eventType,
                createdAt = now,
            )
            launchStore.updateSession(
                session = GameLaunchSessionRecord(
                    sessionId = UUID.randomUUID(),
                    tenantId = command.tenantId,
                    playerId = command.playerId,
                    providerId = command.providerId,
                    gameId = command.gameId,
                    jurisdictionCode = command.jurisdictionCode,
                    currencyCode = command.currencyCode,
                    sessionCorrelationId = "rejected-${UUID.randomUUID()}",
                    tokenHash = "",
                    tokenStatus = LaunchTokenStatus.REVOKED,
                    status = GameLaunchSessionStatus.REJECTED,
                    issuedAt = now,
                    tokenExpiresAt = now,
                    sessionExpiresAt = now,
                    eligibilityDecisionId = UUID.randomUUID(),
                    eligibilityVersion = 1L,
                    launchUrl = "",
                ),
                audit = audit,
                outbox = outbox,
            )
            throw AuthenticationFailure.Rejected(reason)
        }

        // 4. Recheck Account Eligibility (AUTHZ-001)
        val registration = try {
            registrationStore.findById(command.tenantId, command.playerId)
        } catch (e: Exception) {
            throw AuthenticationFailure.Rejected(AuthErrorCode.DEPENDENCY_UNAVAILABLE)
        } ?: throw AuthenticationFailure.Rejected(AuthErrorCode.FORBIDDEN)

        if (registration.status != PlayerAccountStatus.ACTIVE) {
            throw AuthenticationFailure.Rejected(AuthErrorCode.FORBIDDEN)
        }

        val complianceProfile = try {
            eligibilityStore.findComplianceProfile(command.tenantId, command.playerId)
        } catch (e: Exception) {
            throw AuthenticationFailure.Rejected(AuthErrorCode.DEPENDENCY_UNAVAILABLE)
        }

        if (complianceProfile != null) {
            if (complianceProfile.kycStatus != KycComplianceStatus.VERIFIED) {
                throw AuthenticationFailure.Rejected(AuthErrorCode.FORBIDDEN)
            }
            if (complianceProfile.amlStatus != AmlComplianceStatus.CLEARED) {
                throw AuthenticationFailure.Rejected(AuthErrorCode.FORBIDDEN)
            }
            if (complianceProfile.responsiblePlay.selfExcluded) {
                alertSink.sendAlert(
                    tenantId = command.tenantId,
                    severity = "HIGH",
                    alertType = "SELF_EXCLUDED_LAUNCH_ATTEMPT",
                    detail = "Self-excluded player ${command.playerId} attempted launch",
                )
                throw AuthenticationFailure.Rejected(AuthErrorCode.FORBIDDEN)
            }
            complianceProfile.responsiblePlay.selfExclusionUntil?.let { until ->
                if (until.isAfter(now)) {
                    throw AuthenticationFailure.Rejected(AuthErrorCode.FORBIDDEN)
                }
            }
            complianceProfile.responsiblePlay.coolOffUntil?.let { until ->
                if (until.isAfter(now)) {
                    throw AuthenticationFailure.Rejected(AuthErrorCode.FORBIDDEN)
                }
            }
            val age = Period.between(complianceProfile.dateOfBirth, LocalDate.ofInstant(now, ZoneOffset.UTC)).years
            if (age < 21) {
                throw AuthenticationFailure.Rejected(AuthErrorCode.FORBIDDEN)
            }
        }

        val latestVerdict = eligibilityStore.findLatestVerdictForPlayer(command.tenantId, command.playerId)
        if (latestVerdict != null) {
            if (!latestVerdict.eligible || latestVerdict.expiresAt.isBefore(now)) {
                throw AuthenticationFailure.Rejected(AuthErrorCode.FORBIDDEN)
            }
        }

        // 5. Generate Launch Session & Emits Session Correlation
        val sessionId = UUID.randomUUID()
        val sessionCorrelationId = "sess-corr-${UUID.randomUUID()}"
        val launchToken = generateRandomToken()
        val tokenHash = sha256(launchToken)
        val tokenExpiresAt = now.plusSeconds(tokenTtlSeconds)
        val sessionExpiresAt = now.plusSeconds(sessionTtlSeconds)
        val decisionId = latestVerdict?.decisionId ?: UUID.randomUUID()
        val decisionVersion = latestVerdict?.version ?: 1L

        val launchUrl = "https://provider.example.com/games/${command.providerId}/${command.gameId}?launchToken=$launchToken&sessionCorrelationId=$sessionCorrelationId&tenantId=${command.tenantId}&jurisdiction=${command.jurisdictionCode}"
        val evidenceReference = sha256("${command.tenantId}:$sessionId:$sessionCorrelationId:$tokenHash:${now.toEpochMilli()}")

        val sessionRecord = GameLaunchSessionRecord(
            sessionId = sessionId,
            tenantId = command.tenantId,
            playerId = command.playerId,
            providerId = command.providerId,
            gameId = command.gameId,
            jurisdictionCode = command.jurisdictionCode,
            currencyCode = command.currencyCode,
            sessionCorrelationId = sessionCorrelationId,
            tokenHash = tokenHash,
            tokenStatus = LaunchTokenStatus.ACTIVE,
            status = GameLaunchSessionStatus.ISSUED,
            issuedAt = now,
            tokenExpiresAt = tokenExpiresAt,
            sessionExpiresAt = sessionExpiresAt,
            eligibilityDecisionId = decisionId,
            eligibilityVersion = decisionVersion,
            launchUrl = launchUrl,
        )

        val resultId = UUID.randomUUID()
        val result = GameLaunchSessionResult(
            resultId = resultId,
            sessionId = sessionId,
            tenantId = command.tenantId,
            playerId = command.playerId,
            providerId = command.providerId,
            gameId = command.gameId,
            jurisdictionCode = command.jurisdictionCode,
            currencyCode = command.currencyCode,
            sessionCorrelationId = sessionCorrelationId,
            launchToken = launchToken,
            launchUrl = launchUrl,
            tokenExpiresAt = tokenExpiresAt,
            sessionExpiresAt = sessionExpiresAt,
            status = GameLaunchSessionStatus.ISSUED,
            serverTime = now,
            evidenceReference = evidenceReference,
        )

        // Structured Audit & Outbox (redacted: no raw tokens or secrets in audit/outbox)
        val audit = AuditEvent(
            eventId = UUID.randomUUID(),
            resultId = resultId,
            tenantId = command.tenantId,
            type = "GAME_LAUNCH_SESSION_ISSUED",
            occurredAt = now,
            correlationId = command.correlationId,
            causationId = command.causationId,
        )
        val outbox = OutboxEvent(
            eventId = UUID.randomUUID(),
            resultId = resultId,
            tenantId = command.tenantId,
            type = "GAME_LAUNCH_SESSION_ISSUED",
            createdAt = now,
        )

        launchStore.saveSession(
            session = sessionRecord,
            result = result,
            idempotencyKey = command.idempotencyKey,
            fingerprint = fp,
            audit = audit,
            outbox = outbox,
        )

        return result
    }

    @Synchronized
    fun validateOrConsumeLaunchToken(command: ValidateLaunchTokenCommand): ValidateLaunchTokenResult {
        GameLaunchTokenBinding.checkBound()

        // 1. Validation
        if (command.tenantId.isBlank() ||
            command.launchToken.isBlank() ||
            command.providerId.isBlank() ||
            command.gameId.isBlank() ||
            command.correlationId.isBlank() ||
            command.causationId.isBlank()
        ) {
            throw AuthenticationFailure.Rejected(AuthErrorCode.INVALID)
        }

        val session = launchStore.findSession(command.tenantId, command.sessionId)
            ?: throw AuthenticationFailure.Rejected(AuthErrorCode.UNAUTHENTICATED)

        val now = clock.instant()

        // 2. Wrong-Player Check (Protected Risk)
        if (session.playerId != command.playerId) {
            alertSink.sendAlert(
                tenantId = command.tenantId,
                severity = "CRITICAL",
                alertType = "LAUNCH_TOKEN_WRONG_PLAYER_DETECTED",
                detail = "Attempted launch token hijack: expected ${session.playerId}, got ${command.playerId}",
            )
            val audit = AuditEvent(
                eventId = UUID.randomUUID(),
                resultId = UUID.randomUUID(),
                tenantId = command.tenantId,
                type = "LAUNCH_TOKEN_WRONG_PLAYER_DETECTED",
                occurredAt = now,
                correlationId = command.correlationId,
                causationId = command.causationId,
            )
            val outbox = OutboxEvent(
                eventId = UUID.randomUUID(),
                resultId = audit.resultId,
                tenantId = command.tenantId,
                type = "LAUNCH_TOKEN_WRONG_PLAYER_DETECTED",
                createdAt = now,
            )
            launchStore.updateSession(session, audit, outbox)
            throw AuthenticationFailure.Rejected(AuthErrorCode.FORBIDDEN)
        }

        // 3. Wrong-Game / Wrong-Provider / Wrong-Tenant Check
        if (session.gameId != command.gameId || session.providerId != command.providerId || session.tenantId != command.tenantId) {
            throw AuthenticationFailure.Rejected(AuthErrorCode.FORBIDDEN)
        }

        // 4. Expired Token Check (Protected Risk)
        if (now.isAfter(session.tokenExpiresAt) || session.tokenStatus == LaunchTokenStatus.EXPIRED) {
            session.tokenStatus = LaunchTokenStatus.EXPIRED
            session.status = GameLaunchSessionStatus.EXPIRED
            val audit = AuditEvent(
                eventId = UUID.randomUUID(),
                resultId = UUID.randomUUID(),
                tenantId = command.tenantId,
                type = "LAUNCH_TOKEN_EXPIRED_REJECTED",
                occurredAt = now,
                correlationId = command.correlationId,
                causationId = command.causationId,
            )
            val outbox = OutboxEvent(
                eventId = UUID.randomUUID(),
                resultId = audit.resultId,
                tenantId = command.tenantId,
                type = "LAUNCH_TOKEN_EXPIRED_REJECTED",
                createdAt = now,
            )
            launchStore.updateSession(session, audit, outbox)
            throw AuthenticationFailure.Rejected(AuthErrorCode.STALE)
        }

        // 5. Replay Check (Protected Risk)
        if (session.tokenStatus == LaunchTokenStatus.CONSUMED || session.consumedAt != null) {
            alertSink.sendAlert(
                tenantId = command.tenantId,
                severity = "CRITICAL",
                alertType = "LAUNCH_TOKEN_REPLAY_DETECTED",
                detail = "Launch token replay detected for session ${session.sessionId}, player ${session.playerId}",
            )
            val audit = AuditEvent(
                eventId = UUID.randomUUID(),
                resultId = UUID.randomUUID(),
                tenantId = command.tenantId,
                type = "LAUNCH_TOKEN_REPLAY_DETECTED",
                occurredAt = now,
                correlationId = command.correlationId,
                causationId = command.causationId,
            )
            val outbox = OutboxEvent(
                eventId = UUID.randomUUID(),
                resultId = audit.resultId,
                tenantId = command.tenantId,
                type = "LAUNCH_TOKEN_REPLAY_DETECTED",
                createdAt = now,
            )
            launchStore.updateSession(session, audit, outbox)
            throw AuthenticationFailure.Rejected(AuthErrorCode.CONFLICT)
        }

        // 6. Terminated or Non-Active Session Check
        if (session.status == GameLaunchSessionStatus.TERMINATED || session.status == GameLaunchSessionStatus.REJECTED) {
            throw AuthenticationFailure.Rejected(AuthErrorCode.FORBIDDEN)
        }

        // 7. Token Hash Validation
        val tokenHash = sha256(command.launchToken)
        if (tokenHash != session.tokenHash) {
            throw AuthenticationFailure.Rejected(AuthErrorCode.UNAUTHENTICATED)
        }

        // 8. Recheck Jurisdiction / Account / Game State (Semantic Contract)
        val gameEligibility = operatorEnablementService.evaluateEligibility(
            EvaluateGameLaunchEligibilityCommand(
                tenantId = command.tenantId,
                providerId = command.providerId,
                gameId = command.gameId,
                playerId = command.playerId.toString(),
                jurisdictionCode = session.jurisdictionCode,
                requestedBetMinorUnits = 100L,
                currencyCode = session.currencyCode,
            )
        )
        if (!gameEligibility.eligible) {
            session.status = GameLaunchSessionStatus.TERMINATED
            session.terminationReason = "Game became ineligible: ${gameEligibility.rejectionDetail}"
            val audit = AuditEvent(
                eventId = UUID.randomUUID(),
                resultId = UUID.randomUUID(),
                tenantId = command.tenantId,
                type = "LAUNCH_TOKEN_RECHECK_GAME_INELIGIBLE",
                occurredAt = now,
                correlationId = command.correlationId,
                causationId = command.causationId,
            )
            val outbox = OutboxEvent(
                eventId = UUID.randomUUID(),
                resultId = audit.resultId,
                tenantId = command.tenantId,
                type = "LAUNCH_TOKEN_RECHECK_GAME_INELIGIBLE",
                createdAt = now,
            )
            launchStore.updateSession(session, audit, outbox)
            throw AuthenticationFailure.Rejected(AuthErrorCode.FORBIDDEN)
        }

        // 9. Transition Token to CONSUMED and Session to ACTIVE
        session.tokenStatus = LaunchTokenStatus.CONSUMED
        session.status = GameLaunchSessionStatus.ACTIVE
        session.consumedAt = now

        val resultId = UUID.randomUUID()
        val evidenceReference = sha256("${command.tenantId}:${session.sessionId}:${session.sessionCorrelationId}:$tokenHash:${now.toEpochMilli()}")

        val audit = AuditEvent(
            eventId = UUID.randomUUID(),
            resultId = resultId,
            tenantId = command.tenantId,
            type = "GAME_LAUNCH_TOKEN_CONSUMED",
            occurredAt = now,
            correlationId = command.correlationId,
            causationId = command.causationId,
        )
        val outbox = OutboxEvent(
            eventId = UUID.randomUUID(),
            resultId = resultId,
            tenantId = command.tenantId,
            type = "GAME_LAUNCH_TOKEN_CONSUMED",
            createdAt = now,
        )

        launchStore.updateSession(session, audit, outbox)

        return ValidateLaunchTokenResult(
            resultId = resultId,
            sessionId = session.sessionId,
            sessionCorrelationId = session.sessionCorrelationId,
            tenantId = command.tenantId,
            playerId = command.playerId,
            providerId = command.providerId,
            gameId = command.gameId,
            currencyCode = session.currencyCode,
            authorized = true,
            sessionStatus = GameLaunchSessionStatus.ACTIVE,
            serverTime = now,
            evidenceReference = evidenceReference,
        )
    }

    @Synchronized
    fun terminateSession(command: TerminateLaunchSessionCommand): TerminateLaunchSessionResult {
        GameLaunchTokenBinding.checkBound()

        if (command.tenantId.isBlank() ||
            command.reason.isBlank() ||
            command.idempotencyKey.isBlank() ||
            command.correlationId.isBlank() ||
            command.causationId.isBlank()
        ) {
            throw AuthenticationFailure.Rejected(AuthErrorCode.INVALID)
        }

        val fp = fingerprintTerminate(command)
        launchStore.findTerminationByIdempotency(command.tenantId, command.idempotencyKey)?.let { (cachedFp, cachedResult) ->
            if (cachedFp != fp) throw AuthenticationFailure.Rejected(AuthErrorCode.CONFLICT)
            return cachedResult
        }

        val session = launchStore.findSession(command.tenantId, command.sessionId)
            ?: throw AuthenticationFailure.Rejected(AuthErrorCode.UNAUTHENTICATED)

        if (session.playerId != command.playerId) {
            throw AuthenticationFailure.Rejected(AuthErrorCode.FORBIDDEN)
        }

        val now = clock.instant()
        session.status = GameLaunchSessionStatus.TERMINATED
        session.terminatedAt = now
        session.terminationReason = command.reason

        val resultId = UUID.randomUUID()
        val evidenceReference = sha256("${command.tenantId}:${session.sessionId}:${session.sessionCorrelationId}:TERMINATED:${now.toEpochMilli()}")

        val result = TerminateLaunchSessionResult(
            resultId = resultId,
            sessionId = session.sessionId,
            status = GameLaunchSessionStatus.TERMINATED,
            terminatedAt = now,
            serverTime = now,
            evidenceReference = evidenceReference,
        )

        val audit = AuditEvent(
            eventId = UUID.randomUUID(),
            resultId = resultId,
            tenantId = command.tenantId,
            type = "GAME_LAUNCH_SESSION_TERMINATED",
            occurredAt = now,
            correlationId = command.correlationId,
            causationId = command.causationId,
        )
        val outbox = OutboxEvent(
            eventId = UUID.randomUUID(),
            resultId = resultId,
            tenantId = command.tenantId,
            type = "GAME_LAUNCH_SESSION_TERMINATED",
            createdAt = now,
        )

        launchStore.updateSession(session, audit, outbox)
        launchStore.saveTerminationIdempotency(command.tenantId, command.idempotencyKey, fp, result)

        return result
    }
}
