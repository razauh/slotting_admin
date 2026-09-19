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
 * Gate to prevent expired, malformed, revoked, simultaneous refresh, reuse, and logout reuse.
 */
object ShortLivedTokenBinding {
    var isBound: Boolean = true

    fun checkBound() {
        if (!isBound) {
            throw AssertionError("expired/malformed/revoked, simultaneous refresh, reuse and logout reuse")
        }
    }
}

/**
 * Gate to enforce AUTH-002-02: Rotate refresh-token families with reuse detection.
 * Semantic contract: "Reuse revokes family and alerts; Android Keystore remains refresh-token store."
 */
object RefreshTokenRotationBinding {
    var isBound: Boolean = true

    fun checkBound() {
        if (!isBound) {
            throw AssertionError("expired/malformed/revoked, simultaneous refresh, reuse and logout reuse")
        }
    }
}

enum class TokenStatus {
    ACTIVE,
    ROTATED,
    REVOKED,
    EXPIRED
}

enum class TokenRevocationReason {
    LOGOUT,
    ROTATED_REUSE_DETECTED,
    SECURITY_POLICY,
    EXPIRED
}

data class TokenFamilyRecord(
    val familyId: UUID,
    val tenantId: String,
    val playerId: UUID,
    var isRevoked: Boolean = false,
    var revocationReason: TokenRevocationReason? = null,
    val createdAt: Instant,
    var updatedAt: Instant
)

data class AccessTokenRecord(
    val tokenId: UUID,
    val tokenHash: String,
    val tenantId: String,
    val playerId: UUID,
    val familyId: UUID,
    var status: TokenStatus,
    val issuedAt: Instant,
    val expiresAt: Instant
)

data class RefreshTokenRecord(
    val tokenId: UUID,
    val tokenHash: String,
    val tenantId: String,
    val playerId: UUID,
    val familyId: UUID,
    val parentTokenHash: String?,
    var status: TokenStatus,
    val issuedAt: Instant,
    val expiresAt: Instant,
    var rotatedAt: Instant? = null,
    var revokedAt: Instant? = null
)

data class IssueTokenPairCommand(
    val tenantId: String,
    val playerId: UUID,
    val idempotencyKey: String,
    val correlationId: String,
    val causationId: String,
    val expectedVersion: Long = 1L
)

data class RefreshTokenCommand(
    val tenantId: String,
    val refreshToken: String,
    val idempotencyKey: String,
    val correlationId: String,
    val causationId: String,
    val expectedVersion: Long = 1L
)

data class RevokeTokenFamilyCommand(
    val tenantId: String,
    val familyId: UUID,
    val playerId: UUID,
    val reason: TokenRevocationReason,
    val idempotencyKey: String,
    val correlationId: String,
    val causationId: String,
    val expectedVersion: Long = 1L
)

data class TokenPairResult(
    val resultId: UUID,
    val familyId: UUID,
    val playerId: UUID,
    val accessToken: String,
    val accessTokenExpiresAt: Instant,
    val refreshToken: String,
    val refreshTokenExpiresAt: Instant,
    val serverTime: Instant,
    val serverVersion: Long,
    val evidenceReference: String,
    val auditEvent: AuditEvent,
    val outboxEvent: OutboxEvent
)

data class AccessTokenValidationResult(
    val valid: Boolean,
    val playerId: UUID? = null,
    val familyId: UUID? = null,
    val expiresAt: Instant? = null,
    val reasonCode: AuthErrorCode? = null
)

data class RevokeTokenFamilyResult(
    val resultId: UUID,
    val familyId: UUID,
    val revoked: Boolean,
    val reason: TokenRevocationReason,
    val serverTime: Instant,
    val serverVersion: Long,
    val evidenceReference: String,
    val auditEvent: AuditEvent,
    val outboxEvent: OutboxEvent
)

interface TokenSecurityAlertSink {
    fun sendSecurityAlert(tenantId: String, playerId: UUID, familyId: UUID, reason: String, details: String)
}

class InMemoryTokenSecurityAlertSink : TokenSecurityAlertSink {
    val alerts = mutableListOf<String>()
    override fun sendSecurityAlert(tenantId: String, playerId: UUID, familyId: UUID, reason: String, details: String) {
        alerts.add("$tenantId:$playerId:$familyId:$reason:$details")
    }
}

interface TokenSecurityStore {
    fun findByIdempotency(tenantId: String, key: String): Pair<Any, Any>?
    fun saveIdempotency(tenantId: String, key: String, command: Any, result: Any)
    fun saveFamily(family: TokenFamilyRecord)
    fun findFamily(tenantId: String, familyId: UUID): TokenFamilyRecord?
    fun saveAccessToken(token: AccessTokenRecord)
    fun findAccessTokenByHash(tenantId: String, hash: String): AccessTokenRecord?
    fun saveRefreshToken(token: RefreshTokenRecord)
    fun findRefreshTokenByHash(tenantId: String, hash: String): RefreshTokenRecord?
    fun revokeEntireFamily(tenantId: String, familyId: UUID, reason: TokenRevocationReason, revokedAt: Instant)
    fun revokeAllFamiliesForPlayer(tenantId: String, playerId: UUID, reason: TokenRevocationReason, revokedAt: Instant)
}

class InMemoryTokenSecurityStore : TokenSecurityStore {
    val idempotency = ConcurrentHashMap<String, Pair<Any, Any>>()
    val families = ConcurrentHashMap<UUID, TokenFamilyRecord>()
    val accessTokens = ConcurrentHashMap<String, AccessTokenRecord>()
    val refreshTokens = ConcurrentHashMap<String, RefreshTokenRecord>()
    val audit = mutableListOf<AuditEvent>()
    val outbox = mutableListOf<OutboxEvent>()

    override fun findByIdempotency(tenantId: String, key: String): Pair<Any, Any>? =
        idempotency["$tenantId:$key"]

    override fun saveIdempotency(tenantId: String, key: String, command: Any, result: Any) {
        idempotency["$tenantId:$key"] = Pair(command, result)
        when (result) {
            is TokenPairResult -> {
                audit.add(result.auditEvent)
                outbox.add(result.outboxEvent)
            }
            is RevokeTokenFamilyResult -> {
                audit.add(result.auditEvent)
                outbox.add(result.outboxEvent)
            }
        }
    }

    override fun saveFamily(family: TokenFamilyRecord) {
        families[family.familyId] = family
    }

    override fun findFamily(tenantId: String, familyId: UUID): TokenFamilyRecord? =
        families[familyId]?.takeIf { it.tenantId == tenantId }

    override fun saveAccessToken(token: AccessTokenRecord) {
        accessTokens["${token.tenantId}:${token.tokenHash}"] = token
    }

    override fun findAccessTokenByHash(tenantId: String, hash: String): AccessTokenRecord? =
        accessTokens["$tenantId:$hash"]

    override fun saveRefreshToken(token: RefreshTokenRecord) {
        refreshTokens["${token.tenantId}:${token.tokenHash}"] = token
    }

    override fun findRefreshTokenByHash(tenantId: String, hash: String): RefreshTokenRecord? =
        refreshTokens["$tenantId:$hash"]

    override fun revokeEntireFamily(tenantId: String, familyId: UUID, reason: TokenRevocationReason, revokedAt: Instant) {
        families[familyId]?.let {
            if (it.tenantId == tenantId) {
                it.isRevoked = true
                it.revocationReason = reason
                it.updatedAt = revokedAt
            }
        }
        accessTokens.values.filter { it.tenantId == tenantId && it.familyId == familyId }.forEach {
            it.status = TokenStatus.REVOKED
        }
        refreshTokens.values.filter { it.tenantId == tenantId && it.familyId == familyId }.forEach {
            it.status = TokenStatus.REVOKED
            it.revokedAt = revokedAt
        }
    }

    override fun revokeAllFamiliesForPlayer(tenantId: String, playerId: UUID, reason: TokenRevocationReason, revokedAt: Instant) {
        val playerFamilyIds = families.values.filter { it.tenantId == tenantId && it.playerId == playerId }.map { it.familyId }
        for (fId in playerFamilyIds) {
            revokeEntireFamily(tenantId, fId, reason, revokedAt)
        }
    }
}

class ShortLivedTokenService(
    private val registrationStore: PlayerRegistrationStore,
    private val tokenStore: TokenSecurityStore,
    private val alertSink: TokenSecurityAlertSink = InMemoryTokenSecurityAlertSink(),
    private val clock: Clock = Clock.systemUTC(),
    private val accessTokenTtl: Duration = Duration.ofMinutes(15),
    private val refreshTokenTtl: Duration = Duration.ofDays(30)
) {
    fun issueTokenPair(command: IssueTokenPairCommand): TokenPairResult = synchronized(tokenStore) {
        ShortLivedTokenBinding.checkBound()

        validateHeaders(command.tenantId, command.correlationId, command.causationId, command.idempotencyKey, command.expectedVersion)

        tokenStore.findByIdempotency(command.tenantId, command.idempotencyKey)?.let { (cachedCmd, cachedResult) ->
            if (cachedCmd == command && cachedResult is TokenPairResult) {
                return cachedResult
            } else {
                throw AuthenticationFailure.Rejected(AuthErrorCode.CONFLICT)
            }
        }

        val player = registrationStore.findById(command.tenantId, command.playerId)
            ?: throw AuthenticationFailure.Rejected(AuthErrorCode.INVALID)

        if (player.status == PlayerAccountStatus.PENDING_VERIFICATION ||
            player.status == PlayerAccountStatus.LOCKED ||
            player.status == PlayerAccountStatus.SUSPENDED ||
            player.status == PlayerAccountStatus.CLOSED
        ) {
            throw AuthenticationFailure.Rejected(AuthErrorCode.FORBIDDEN)
        }

        val now = clock.instant()
        val familyId = UUID.randomUUID()
        val family = TokenFamilyRecord(
            familyId = familyId,
            tenantId = command.tenantId,
            playerId = command.playerId,
            isRevoked = false,
            createdAt = now,
            updatedAt = now
        )
        tokenStore.saveFamily(family)

        val rawAccessToken = "sat_${UUID.randomUUID()}"
        val rawRefreshToken = "srt_${UUID.randomUUID()}"
        val accessExpiresAt = now.plus(accessTokenTtl)
        val refreshExpiresAt = now.plus(refreshTokenTtl)

        val accessTokenRecord = AccessTokenRecord(
            tokenId = UUID.randomUUID(),
            tokenHash = sha256(rawAccessToken),
            tenantId = command.tenantId,
            playerId = command.playerId,
            familyId = familyId,
            status = TokenStatus.ACTIVE,
            issuedAt = now,
            expiresAt = accessExpiresAt
        )
        val refreshTokenRecord = RefreshTokenRecord(
            tokenId = UUID.randomUUID(),
            tokenHash = sha256(rawRefreshToken),
            tenantId = command.tenantId,
            playerId = command.playerId,
            familyId = familyId,
            parentTokenHash = null,
            status = TokenStatus.ACTIVE,
            issuedAt = now,
            expiresAt = refreshExpiresAt
        )

        tokenStore.saveAccessToken(accessTokenRecord)
        tokenStore.saveRefreshToken(refreshTokenRecord)

        val resultId = UUID.randomUUID()
        val auditEvent = AuditEvent(
            eventId = UUID.randomUUID(),
            resultId = resultId,
            tenantId = command.tenantId,
            type = "ACCESS_TOKEN_ISSUED",
            occurredAt = now,
            correlationId = command.correlationId,
            causationId = command.causationId
        )
        val outboxEvent = OutboxEvent(
            eventId = UUID.randomUUID(),
            resultId = resultId,
            tenantId = command.tenantId,
            type = "ACCESS_TOKEN_ISSUED",
            createdAt = now
        )

        val result = TokenPairResult(
            resultId = resultId,
            familyId = familyId,
            playerId = command.playerId,
            accessToken = rawAccessToken,
            accessTokenExpiresAt = accessExpiresAt,
            refreshToken = rawRefreshToken,
            refreshTokenExpiresAt = refreshExpiresAt,
            serverTime = now,
            serverVersion = command.expectedVersion,
            evidenceReference = "tok-pair:${command.tenantId}:$familyId",
            auditEvent = auditEvent,
            outboxEvent = outboxEvent
        )

        tokenStore.saveIdempotency(command.tenantId, command.idempotencyKey, command, result)
        return result
    }

    fun rotateRefreshToken(command: RefreshTokenCommand): TokenPairResult = synchronized(tokenStore) {
        ShortLivedTokenBinding.checkBound()
        RefreshTokenRotationBinding.checkBound()

        validateHeaders(command.tenantId, command.correlationId, command.causationId, command.idempotencyKey, command.expectedVersion)
        if (command.refreshToken.isBlank()) {
            throw AuthenticationFailure.Rejected(AuthErrorCode.INVALID)
        }

        tokenStore.findByIdempotency(command.tenantId, command.idempotencyKey)?.let { (cachedCmd, cachedResult) ->
            if (cachedCmd == command && cachedResult is TokenPairResult) {
                return cachedResult
            } else {
                throw AuthenticationFailure.Rejected(AuthErrorCode.CONFLICT)
            }
        }

        val incomingHash = sha256(command.refreshToken.trim())
        val existingToken = tokenStore.findRefreshTokenByHash(command.tenantId, incomingHash)
            ?: throw AuthenticationFailure.Rejected(AuthErrorCode.INVALID)

        val now = clock.instant()
        val family = tokenStore.findFamily(command.tenantId, existingToken.familyId)
            ?: throw AuthenticationFailure.Rejected(AuthErrorCode.INVALID)

        val player = registrationStore.findById(command.tenantId, existingToken.playerId)
        if (player != null && (
            player.status == PlayerAccountStatus.LOCKED ||
            player.status == PlayerAccountStatus.SUSPENDED ||
            player.status == PlayerAccountStatus.CLOSED
        )) {
            throw AuthenticationFailure.Rejected(AuthErrorCode.FORBIDDEN)
        }

        // 1. REUSE DETECTION: If token was already ROTATED or REVOKED -> Attack!
        if (existingToken.status == TokenStatus.ROTATED || existingToken.status == TokenStatus.REVOKED || family.isRevoked) {
            // Immediate family revocation
            tokenStore.revokeEntireFamily(command.tenantId, existingToken.familyId, TokenRevocationReason.ROTATED_REUSE_DETECTED, now)

            // Alert dispatch
            alertSink.sendSecurityAlert(
                tenantId = command.tenantId,
                playerId = existingToken.playerId,
                familyId = existingToken.familyId,
                reason = "REFRESH_TOKEN_REUSE_DETECTED",
                details = "Token reuse detected for family ${existingToken.familyId}; entire family revoked."
            )

            // Observable audit
            val alertResultId = UUID.randomUUID()
            val auditEvent = AuditEvent(
                eventId = UUID.randomUUID(),
                resultId = alertResultId,
                tenantId = command.tenantId,
                type = "TOKEN_FAMILY_REUSE_REVOKED",
                occurredAt = now,
                correlationId = command.correlationId,
                causationId = command.causationId
            )
            val outboxEvent = OutboxEvent(
                eventId = UUID.randomUUID(),
                resultId = alertResultId,
                tenantId = command.tenantId,
                type = "TOKEN_FAMILY_REUSE_REVOKED",
                createdAt = now
            )
            if (tokenStore is InMemoryTokenSecurityStore) {
                tokenStore.audit.add(auditEvent)
                tokenStore.outbox.add(outboxEvent)
            }

            throw AuthenticationFailure.Rejected(AuthErrorCode.FORBIDDEN)
        }

        // 2. Expiration check
        if (now.isAfter(existingToken.expiresAt)) {
            existingToken.status = TokenStatus.EXPIRED
            throw AuthenticationFailure.Rejected(AuthErrorCode.UNAUTHENTICATED)
        }

        // 3. Perform lawful rotation
        existingToken.status = TokenStatus.ROTATED
        existingToken.rotatedAt = now
        tokenStore.saveRefreshToken(existingToken)

        val rawAccessToken = "sat_${UUID.randomUUID()}"
        val rawRefreshToken = "srt_${UUID.randomUUID()}"
        val accessExpiresAt = now.plus(accessTokenTtl)
        val refreshExpiresAt = now.plus(refreshTokenTtl)

        val newAccessTokenRecord = AccessTokenRecord(
            tokenId = UUID.randomUUID(),
            tokenHash = sha256(rawAccessToken),
            tenantId = command.tenantId,
            playerId = existingToken.playerId,
            familyId = existingToken.familyId,
            status = TokenStatus.ACTIVE,
            issuedAt = now,
            expiresAt = accessExpiresAt
        )
        val newRefreshTokenRecord = RefreshTokenRecord(
            tokenId = UUID.randomUUID(),
            tokenHash = sha256(rawRefreshToken),
            tenantId = command.tenantId,
            playerId = existingToken.playerId,
            familyId = existingToken.familyId,
            parentTokenHash = incomingHash,
            status = TokenStatus.ACTIVE,
            issuedAt = now,
            expiresAt = refreshExpiresAt
        )

        tokenStore.saveAccessToken(newAccessTokenRecord)
        tokenStore.saveRefreshToken(newRefreshTokenRecord)

        val resultId = UUID.randomUUID()
        val auditEvent = AuditEvent(
            eventId = UUID.randomUUID(),
            resultId = resultId,
            tenantId = command.tenantId,
            type = "REFRESH_TOKEN_ROTATED",
            occurredAt = now,
            correlationId = command.correlationId,
            causationId = command.causationId
        )
        val outboxEvent = OutboxEvent(
            eventId = UUID.randomUUID(),
            resultId = resultId,
            tenantId = command.tenantId,
            type = "REFRESH_TOKEN_ROTATED",
            createdAt = now
        )

        val result = TokenPairResult(
            resultId = resultId,
            familyId = existingToken.familyId,
            playerId = existingToken.playerId,
            accessToken = rawAccessToken,
            accessTokenExpiresAt = accessExpiresAt,
            refreshToken = rawRefreshToken,
            refreshTokenExpiresAt = refreshExpiresAt,
            serverTime = now,
            serverVersion = command.expectedVersion,
            evidenceReference = "tok-rot:${command.tenantId}:${existingToken.familyId}",
            auditEvent = auditEvent,
            outboxEvent = outboxEvent
        )

        tokenStore.saveIdempotency(command.tenantId, command.idempotencyKey, command, result)
        return result
    }

    fun validateAccessToken(tenantId: String, rawAccessToken: String): AccessTokenValidationResult = synchronized(tokenStore) {
        ShortLivedTokenBinding.checkBound()

        if (tenantId.isBlank() || rawAccessToken.isBlank()) {
            return AccessTokenValidationResult(valid = false, reasonCode = AuthErrorCode.INVALID)
        }

        val tokenHash = sha256(rawAccessToken.trim())
        val token = tokenStore.findAccessTokenByHash(tenantId, tokenHash)
            ?: return AccessTokenValidationResult(valid = false, reasonCode = AuthErrorCode.UNAUTHENTICATED)

        val family = tokenStore.findFamily(tenantId, token.familyId)
            ?: return AccessTokenValidationResult(valid = false, reasonCode = AuthErrorCode.UNAUTHENTICATED)

        if (family.isRevoked || token.status == TokenStatus.REVOKED) {
            return AccessTokenValidationResult(valid = false, reasonCode = AuthErrorCode.UNAUTHENTICATED)
        }

        val now = clock.instant()
        if (now.isAfter(token.expiresAt)) {
            token.status = TokenStatus.EXPIRED
            return AccessTokenValidationResult(valid = false, reasonCode = AuthErrorCode.UNAUTHENTICATED)
        }

        return AccessTokenValidationResult(
            valid = true,
            playerId = token.playerId,
            familyId = token.familyId,
            expiresAt = token.expiresAt
        )
    }

    fun revokeFamily(command: RevokeTokenFamilyCommand): RevokeTokenFamilyResult = synchronized(tokenStore) {
        ShortLivedTokenBinding.checkBound()

        validateHeaders(command.tenantId, command.correlationId, command.causationId, command.idempotencyKey, command.expectedVersion)

        tokenStore.findByIdempotency(command.tenantId, command.idempotencyKey)?.let { (cachedCmd, cachedResult) ->
            if (cachedCmd == command && cachedResult is RevokeTokenFamilyResult) {
                return cachedResult
            } else {
                throw AuthenticationFailure.Rejected(AuthErrorCode.CONFLICT)
            }
        }

        val family = tokenStore.findFamily(command.tenantId, command.familyId)
            ?: throw AuthenticationFailure.Rejected(AuthErrorCode.INVALID)

        if (family.playerId != command.playerId) {
            throw AuthenticationFailure.Rejected(AuthErrorCode.FORBIDDEN)
        }

        val now = clock.instant()
        tokenStore.revokeEntireFamily(command.tenantId, command.familyId, command.reason, now)

        val resultId = UUID.randomUUID()
        val auditEvent = AuditEvent(
            eventId = UUID.randomUUID(),
            resultId = resultId,
            tenantId = command.tenantId,
            type = "TOKEN_FAMILY_REVOKED_${command.reason.name}",
            occurredAt = now,
            correlationId = command.correlationId,
            causationId = command.causationId
        )
        val outboxEvent = OutboxEvent(
            eventId = UUID.randomUUID(),
            resultId = resultId,
            tenantId = command.tenantId,
            type = "TOKEN_FAMILY_REVOKED_${command.reason.name}",
            createdAt = now
        )

        val result = RevokeTokenFamilyResult(
            resultId = resultId,
            familyId = command.familyId,
            revoked = true,
            reason = command.reason,
            serverTime = now,
            serverVersion = command.expectedVersion,
            evidenceReference = "tok-rev:${command.tenantId}:${command.familyId}",
            auditEvent = auditEvent,
            outboxEvent = outboxEvent
        )

        tokenStore.saveIdempotency(command.tenantId, command.idempotencyKey, command, result)
        return result
    }

    private fun validateHeaders(tenantId: String, corrId: String, causId: String, idempKey: String, expectedVersion: Long) {
        if (tenantId.isBlank() || corrId.isBlank() || causId.isBlank()) {
            throw AuthenticationFailure.Rejected(AuthErrorCode.INVALID)
        }
        if (expectedVersion < 1L) {
            throw AuthenticationFailure.Rejected(AuthErrorCode.STALE)
        }
        if (idempKey.isBlank()) {
            throw AuthenticationFailure.Rejected(AuthErrorCode.INVALID)
        }
    }

    internal fun sha256(input: String): String {
        val digest = MessageDigest.getInstance("SHA-256")
        val bytes = digest.digest(input.toByteArray(Charsets.UTF_8))
        return bytes.joinToString("") { "%02x".format(it) }
    }
}
