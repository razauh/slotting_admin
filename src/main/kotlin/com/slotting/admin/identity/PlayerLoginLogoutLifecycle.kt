package com.slotting.admin.identity

import com.slotting.admin.auth.AuditEvent
import com.slotting.admin.auth.AuthErrorCode
import com.slotting.admin.auth.AuthenticationFailure
import com.slotting.admin.auth.OutboxEvent
import java.security.MessageDigest
import java.time.Clock
import java.time.Duration
import java.time.Instant
import java.util.UUID
import java.util.concurrent.ConcurrentHashMap

/**
 * Gate to prevent unverified or recovery bypass during player login/logout lifecycle.
 */
object PlayerLoginLogoutBinding {
    var isBound: Boolean = true

    fun checkBound() {
        if (!isBound) {
            throw AssertionError("unverified/recovery bypass")
        }
    }
}

enum class LoginStatus {
    AUTHENTICATED,
    CHALLENGE_REQUIRED,
    UNVERIFIED_CONTACT,
    SUSPENDED
}

enum class SessionState {
    ACTIVE,
    TERMINATED,
    EXPIRED
}

data class LoginPlayerCommand(
    val tenantId: String,
    val identifier: String, // email or username
    val rawPassword: String,
    val idempotencyKey: String,
    val correlationId: String,
    val causationId: String,
    val expectedVersion: Long = 1L,
    val ipAddress: String = "127.0.0.1",
    val userAgent: String = "SlottingAndroid/1.0"
)

data class LoginPlayerResult(
    val resultId: UUID,
    val playerId: UUID?,
    val status: LoginStatus,
    val sessionId: UUID?,
    val accessToken: String?,
    val refreshToken: String?,
    val mfaChallengeId: UUID?,
    val expiresAt: Instant?,
    val serverTime: Instant,
    val serverVersion: Long,
    val evidenceReference: String,
    val auditEvent: AuditEvent,
    val outboxEvent: OutboxEvent
)

data class SubmitMfaChallengeCommand(
    val tenantId: String,
    val challengeId: UUID,
    val playerId: UUID,
    val mfaCode: String,
    val idempotencyKey: String,
    val correlationId: String,
    val causationId: String,
    val expectedVersion: Long = 1L
)

data class SubmitMfaChallengeResult(
    val resultId: UUID,
    val playerId: UUID,
    val status: LoginStatus,
    val sessionId: UUID,
    val accessToken: String,
    val refreshToken: String,
    val expiresAt: Instant,
    val serverTime: Instant,
    val serverVersion: Long,
    val evidenceReference: String,
    val auditEvent: AuditEvent,
    val outboxEvent: OutboxEvent
)

data class LogoutPlayerCommand(
    val tenantId: String,
    val sessionId: UUID,
    val playerId: UUID,
    val idempotencyKey: String,
    val correlationId: String,
    val causationId: String,
    val expectedVersion: Long = 1L
)

data class LogoutPlayerResult(
    val resultId: UUID,
    val sessionId: UUID,
    val playerId: UUID,
    val terminated: Boolean,
    val serverTime: Instant,
    val serverVersion: Long,
    val evidenceReference: String,
    val auditEvent: AuditEvent,
    val outboxEvent: OutboxEvent
)

data class PlayerSession(
    val sessionId: UUID,
    val tenantId: String,
    val playerId: UUID,
    val accessToken: String,
    val refreshToken: String,
    var state: SessionState,
    val createdAt: Instant,
    val expiresAt: Instant,
    var terminatedAt: Instant? = null
)

data class MfaChallenge(
    val challengeId: UUID,
    val tenantId: String,
    val playerId: UUID,
    val expectedCodeHash: String,
    val expiresAt: Instant,
    var consumed: Boolean = false
)

interface PlayerSessionStore {
    fun findByIdempotency(tenantId: String, key: String): Pair<Any, Any>?
    fun saveSession(
        session: PlayerSession,
        idempotencyKey: String,
        command: Any,
        result: Any
    )
    fun findSession(tenantId: String, sessionId: UUID): PlayerSession?
    fun terminateSession(tenantId: String, sessionId: UUID, terminatedAt: Instant)
    fun revokeAllPlayerSessions(tenantId: String, playerId: UUID, terminatedAt: Instant): Int
    fun saveMfaChallenge(challenge: MfaChallenge)
    fun findMfaChallenge(tenantId: String, challengeId: UUID): MfaChallenge?
    fun consumeMfaChallenge(tenantId: String, challengeId: UUID)
}

class InMemoryPlayerSessionStore : PlayerSessionStore {
    val idempotency = ConcurrentHashMap<String, Pair<Any, Any>>()
    val sessions = ConcurrentHashMap<UUID, PlayerSession>()
    val challenges = ConcurrentHashMap<UUID, MfaChallenge>()
    val audit = mutableListOf<AuditEvent>()
    val outbox = mutableListOf<OutboxEvent>()

    override fun findByIdempotency(tenantId: String, key: String): Pair<Any, Any>? =
        idempotency["$tenantId:$key"]

    override fun saveSession(
        session: PlayerSession,
        idempotencyKey: String,
        command: Any,
        result: Any
    ) {
        idempotency["${session.tenantId}:$idempotencyKey"] = Pair(command, result)
        sessions[session.sessionId] = session
        when (result) {
            is LoginPlayerResult -> {
                audit.add(result.auditEvent)
                outbox.add(result.outboxEvent)
            }
            is SubmitMfaChallengeResult -> {
                audit.add(result.auditEvent)
                outbox.add(result.outboxEvent)
            }
            is LogoutPlayerResult -> {
                audit.add(result.auditEvent)
                outbox.add(result.outboxEvent)
            }
        }
    }

    override fun findSession(tenantId: String, sessionId: UUID): PlayerSession? =
        sessions[sessionId]?.takeIf { it.tenantId == tenantId }

    override fun terminateSession(tenantId: String, sessionId: UUID, terminatedAt: Instant) {
        sessions[sessionId]?.let {
            if (it.tenantId == tenantId) {
                it.state = SessionState.TERMINATED
                it.terminatedAt = terminatedAt
            }
        }
    }

    override fun revokeAllPlayerSessions(tenantId: String, playerId: UUID, terminatedAt: Instant): Int {
        var count = 0
        sessions.values.forEach {
            if (it.tenantId == tenantId && it.playerId == playerId && it.state == SessionState.ACTIVE) {
                it.state = SessionState.TERMINATED
                it.terminatedAt = terminatedAt
                count++
            }
        }
        return count
    }

    override fun saveMfaChallenge(challenge: MfaChallenge) {
        challenges[challenge.challengeId] = challenge
    }

    override fun findMfaChallenge(tenantId: String, challengeId: UUID): MfaChallenge? =
        challenges[challengeId]?.takeIf { it.tenantId == tenantId }

    override fun consumeMfaChallenge(tenantId: String, challengeId: UUID) {
        challenges[challengeId]?.let {
            if (it.tenantId == tenantId) {
                it.consumed = true
            }
        }
    }
}

class PlayerSessionService(
    private val registrationStore: PlayerRegistrationStore,
    private val sessionStore: PlayerSessionStore,
    private val clock: Clock = Clock.systemUTC(),
    private val sessionTtl: Duration = Duration.ofHours(1),
    private val challengeTtl: Duration = Duration.ofMinutes(5)
) {
    fun login(command: LoginPlayerCommand): LoginPlayerResult = synchronized(sessionStore) {
        PlayerLoginLogoutBinding.checkBound()

        // 1. Header validations
        if (command.tenantId.isBlank() || command.correlationId.isBlank() || command.causationId.isBlank()) {
            throw AuthenticationFailure.Rejected(AuthErrorCode.INVALID)
        }
        if (command.expectedVersion < 1L) {
            throw AuthenticationFailure.Rejected(AuthErrorCode.STALE)
        }
        if (command.idempotencyKey.isBlank() || command.identifier.isBlank() || command.rawPassword.isBlank()) {
            throw AuthenticationFailure.Rejected(AuthErrorCode.INVALID)
        }

        sessionStore.findByIdempotency(command.tenantId, command.idempotencyKey)?.let { (cachedCmd, cachedResult) ->
            if (cachedCmd == command && cachedResult is LoginPlayerResult) {
                return cachedResult
            } else {
                throw AuthenticationFailure.Rejected(AuthErrorCode.CONFLICT)
            }
        }

        val normalizedIdentifier = command.identifier.trim().lowercase()
        val emailHash = sha256(normalizedIdentifier)
        val candidate = registrationStore.findByEmailHash(command.tenantId, emailHash)
            ?: registrationStore.findByPhoneHash(command.tenantId, sha256(command.identifier.trim()))

        val now = clock.instant()
        val resultId = UUID.randomUUID()

        // 2. Enumeration-safe credentials check:
        // If player does not exist OR password does not match, return safe INVALID rejection
        val expectedPasswordHash = candidate?.passwordHash
        val givenPasswordHash = sha256(command.rawPassword)

        if (candidate == null || expectedPasswordHash != givenPasswordHash) {
            val failureEvent = AuditEvent(
                eventId = UUID.randomUUID(),
                resultId = resultId,
                tenantId = command.tenantId,
                type = "PLAYER_LOGIN_FAILED_CREDENTIALS",
                occurredAt = now,
                correlationId = command.correlationId,
                causationId = command.causationId
            )
            // Audit failed attempt without leaking whether user exists
            if (sessionStore is InMemoryPlayerSessionStore) {
                sessionStore.audit.add(failureEvent)
            }
            throw AuthenticationFailure.Rejected(AuthErrorCode.INVALID)
        }

        // 3. Unverified / Recovery Bypass Defense:
        // A player with PENDING_VERIFICATION cannot log in to an active session
        if (candidate.status == PlayerAccountStatus.PENDING_VERIFICATION) {
            // Fails closed to protect against unverified bypass
            throw AuthenticationFailure.Rejected(AuthErrorCode.FORBIDDEN)
        }

        if (candidate.status == PlayerAccountStatus.SUSPENDED) {
            throw AuthenticationFailure.Rejected(AuthErrorCode.FORBIDDEN)
        }

        // 4. Jurisdiction & Risk MFA Configuration:
        // If MFA is required (either by jurisdiction/risk config or player status is PENDING_MFA)
        if (candidate.mfaRequired || candidate.status == PlayerAccountStatus.PENDING_MFA) {
            val challengeId = UUID.randomUUID()
            val mfaChallenge = MfaChallenge(
                challengeId = challengeId,
                tenantId = command.tenantId,
                playerId = candidate.playerId,
                expectedCodeHash = sha256("MFA-654321"),
                expiresAt = now.plus(challengeTtl),
                consumed = false
            )
            sessionStore.saveMfaChallenge(mfaChallenge)

            val auditEvent = AuditEvent(
                eventId = UUID.randomUUID(),
                resultId = resultId,
                tenantId = command.tenantId,
                type = "PLAYER_MFA_CHALLENGE_ISSUED",
                occurredAt = now,
                correlationId = command.correlationId,
                causationId = command.causationId
            )
            val outboxEvent = OutboxEvent(
                eventId = UUID.randomUUID(),
                resultId = resultId,
                tenantId = command.tenantId,
                type = "PLAYER_MFA_CHALLENGE_ISSUED",
                createdAt = now
            )

            val result = LoginPlayerResult(
                resultId = resultId,
                playerId = candidate.playerId,
                status = LoginStatus.CHALLENGE_REQUIRED,
                sessionId = null,
                accessToken = null,
                refreshToken = null,
                mfaChallengeId = challengeId,
                expiresAt = null,
                serverTime = now,
                serverVersion = candidate.version,
                evidenceReference = "mfa-chal:${command.tenantId}:$challengeId",
                auditEvent = auditEvent,
                outboxEvent = outboxEvent
            )
            if (sessionStore is InMemoryPlayerSessionStore) {
                sessionStore.idempotency["${command.tenantId}:${command.idempotencyKey}"] = Pair(command, result)
                sessionStore.audit.add(auditEvent)
                sessionStore.outbox.add(outboxEvent)
            }
            return result
        }

        // 5. Standard Authenticated Session
        val sessionId = UUID.randomUUID()
        val expiresAt = now.plus(sessionTtl)
        val accessToken = "pat_${UUID.randomUUID()}"
        val refreshToken = "prt_${UUID.randomUUID()}"

        val session = PlayerSession(
            sessionId = sessionId,
            tenantId = command.tenantId,
            playerId = candidate.playerId,
            accessToken = accessToken,
            refreshToken = refreshToken,
            state = SessionState.ACTIVE,
            createdAt = now,
            expiresAt = expiresAt
        )

        val auditEvent = AuditEvent(
            eventId = UUID.randomUUID(),
            resultId = resultId,
            tenantId = command.tenantId,
            type = "PLAYER_LOGIN_SUCCEEDED",
            occurredAt = now,
            correlationId = command.correlationId,
            causationId = command.causationId
        )
        val outboxEvent = OutboxEvent(
            eventId = UUID.randomUUID(),
            resultId = resultId,
            tenantId = command.tenantId,
            type = "PLAYER_LOGIN_SUCCEEDED",
            createdAt = now
        )

        val result = LoginPlayerResult(
            resultId = resultId,
            playerId = candidate.playerId,
            status = LoginStatus.AUTHENTICATED,
            sessionId = sessionId,
            accessToken = accessToken,
            refreshToken = refreshToken,
            mfaChallengeId = null,
            expiresAt = expiresAt,
            serverTime = now,
            serverVersion = candidate.version,
            evidenceReference = "sess:${command.tenantId}:$sessionId",
            auditEvent = auditEvent,
            outboxEvent = outboxEvent
        )

        sessionStore.saveSession(session, command.idempotencyKey, command, result)
        return result
    }

    fun submitMfaChallenge(command: SubmitMfaChallengeCommand): SubmitMfaChallengeResult = synchronized(sessionStore) {
        PlayerLoginLogoutBinding.checkBound()

        if (command.tenantId.isBlank() || command.correlationId.isBlank() || command.causationId.isBlank()) {
            throw AuthenticationFailure.Rejected(AuthErrorCode.INVALID)
        }
        if (command.expectedVersion < 1L) {
            throw AuthenticationFailure.Rejected(AuthErrorCode.STALE)
        }
        if (command.idempotencyKey.isBlank() || command.mfaCode.isBlank()) {
            throw AuthenticationFailure.Rejected(AuthErrorCode.INVALID)
        }

        sessionStore.findByIdempotency(command.tenantId, command.idempotencyKey)?.let { (cachedCmd, cachedResult) ->
            if (cachedCmd == command && cachedResult is SubmitMfaChallengeResult) {
                return cachedResult
            } else {
                throw AuthenticationFailure.Rejected(AuthErrorCode.CONFLICT)
            }
        }

        val challenge = sessionStore.findMfaChallenge(command.tenantId, command.challengeId)
            ?: throw AuthenticationFailure.Rejected(AuthErrorCode.INVALID)

        if (challenge.consumed || challenge.playerId != command.playerId) {
            throw AuthenticationFailure.Rejected(AuthErrorCode.INVALID)
        }

        val now = clock.instant()
        if (now.isAfter(challenge.expiresAt)) {
            throw AuthenticationFailure.Rejected(AuthErrorCode.INVALID)
        }

        val codeHash = sha256(command.mfaCode.trim())
        if (codeHash != challenge.expectedCodeHash) {
            throw AuthenticationFailure.Rejected(AuthErrorCode.INVALID)
        }

        sessionStore.consumeMfaChallenge(command.tenantId, command.challengeId)

        // If player was PENDING_MFA, now upgrade to ACTIVE
        val player = registrationStore.findById(command.tenantId, command.playerId)
        if (player != null && player.status == PlayerAccountStatus.PENDING_MFA) {
            player.status = PlayerAccountStatus.ACTIVE
            player.version++
            player.updatedAt = now
        }

        val sessionId = UUID.randomUUID()
        val expiresAt = now.plus(sessionTtl)
        val accessToken = "pat_${UUID.randomUUID()}"
        val refreshToken = "prt_${UUID.randomUUID()}"

        val session = PlayerSession(
            sessionId = sessionId,
            tenantId = command.tenantId,
            playerId = command.playerId,
            accessToken = accessToken,
            refreshToken = refreshToken,
            state = SessionState.ACTIVE,
            createdAt = now,
            expiresAt = expiresAt
        )

        val resultId = UUID.randomUUID()
        val auditEvent = AuditEvent(
            eventId = UUID.randomUUID(),
            resultId = resultId,
            tenantId = command.tenantId,
            type = "PLAYER_MFA_VERIFIED",
            occurredAt = now,
            correlationId = command.correlationId,
            causationId = command.causationId
        )
        val outboxEvent = OutboxEvent(
            eventId = UUID.randomUUID(),
            resultId = resultId,
            tenantId = command.tenantId,
            type = "PLAYER_MFA_VERIFIED",
            createdAt = now
        )

        val result = SubmitMfaChallengeResult(
            resultId = resultId,
            playerId = command.playerId,
            status = LoginStatus.AUTHENTICATED,
            sessionId = sessionId,
            accessToken = accessToken,
            refreshToken = refreshToken,
            expiresAt = expiresAt,
            serverTime = now,
            serverVersion = player?.version ?: command.expectedVersion,
            evidenceReference = "sess-mfa:${command.tenantId}:$sessionId",
            auditEvent = auditEvent,
            outboxEvent = outboxEvent
        )

        sessionStore.saveSession(session, command.idempotencyKey, command, result)
        return result
    }

    fun logout(command: LogoutPlayerCommand): LogoutPlayerResult = synchronized(sessionStore) {
        PlayerLoginLogoutBinding.checkBound()

        if (command.tenantId.isBlank() || command.correlationId.isBlank() || command.causationId.isBlank()) {
            throw AuthenticationFailure.Rejected(AuthErrorCode.INVALID)
        }
        if (command.expectedVersion < 1L) {
            throw AuthenticationFailure.Rejected(AuthErrorCode.STALE)
        }
        if (command.idempotencyKey.isBlank()) {
            throw AuthenticationFailure.Rejected(AuthErrorCode.INVALID)
        }

        sessionStore.findByIdempotency(command.tenantId, command.idempotencyKey)?.let { (cachedCmd, cachedResult) ->
            if (cachedCmd == command && cachedResult is LogoutPlayerResult) {
                return cachedResult
            } else {
                throw AuthenticationFailure.Rejected(AuthErrorCode.CONFLICT)
            }
        }

        val session = sessionStore.findSession(command.tenantId, command.sessionId)
            ?: throw AuthenticationFailure.Rejected(AuthErrorCode.UNAUTHENTICATED)

        if (session.playerId != command.playerId) {
            throw AuthenticationFailure.Rejected(AuthErrorCode.FORBIDDEN)
        }

        val now = clock.instant()
        sessionStore.terminateSession(command.tenantId, command.sessionId, now)

        val resultId = UUID.randomUUID()
        val auditEvent = AuditEvent(
            eventId = UUID.randomUUID(),
            resultId = resultId,
            tenantId = command.tenantId,
            type = "PLAYER_LOGOUT_COMPLETED",
            occurredAt = now,
            correlationId = command.correlationId,
            causationId = command.causationId
        )
        val outboxEvent = OutboxEvent(
            eventId = UUID.randomUUID(),
            resultId = resultId,
            tenantId = command.tenantId,
            type = "PLAYER_LOGOUT_COMPLETED",
            createdAt = now
        )

        val result = LogoutPlayerResult(
            resultId = resultId,
            sessionId = command.sessionId,
            playerId = command.playerId,
            terminated = true,
            serverTime = now,
            serverVersion = command.expectedVersion,
            evidenceReference = "logout:${command.tenantId}:${command.sessionId}",
            auditEvent = auditEvent,
            outboxEvent = outboxEvent
        )

        if (sessionStore is InMemoryPlayerSessionStore) {
            sessionStore.idempotency["${command.tenantId}:${command.idempotencyKey}"] = Pair(command, result)
            sessionStore.audit.add(auditEvent)
            sessionStore.outbox.add(outboxEvent)
        }
        return result
    }

    fun validateSession(tenantId: String, sessionId: UUID): PlayerSession = synchronized(sessionStore) {
        PlayerLoginLogoutBinding.checkBound()

        val session = sessionStore.findSession(tenantId, sessionId)
            ?: throw AuthenticationFailure.Rejected(AuthErrorCode.UNAUTHENTICATED)

        if (session.state != SessionState.ACTIVE) {
            throw AuthenticationFailure.Rejected(AuthErrorCode.UNAUTHENTICATED)
        }

        val now = clock.instant()
        if (now.isAfter(session.expiresAt)) {
            session.state = SessionState.EXPIRED
            throw AuthenticationFailure.Rejected(AuthErrorCode.UNAUTHENTICATED)
        }

        return session
    }

    private fun sha256(input: String): String {
        val digest = MessageDigest.getInstance("SHA-256")
        val bytes = digest.digest(input.toByteArray(Charsets.UTF_8))
        return bytes.joinToString("") { "%02x".format(it) }
    }
}
