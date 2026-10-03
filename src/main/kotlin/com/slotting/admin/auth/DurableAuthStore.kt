package com.slotting.admin.auth

import org.springframework.dao.DuplicateKeyException
import org.springframework.jdbc.core.JdbcTemplate
import org.springframework.jdbc.core.RowMapper
import org.springframework.stereotype.Repository
import org.springframework.transaction.annotation.Transactional
import java.sql.ResultSet
import java.sql.Timestamp
import java.time.Instant
import java.util.UUID
import java.util.concurrent.ConcurrentHashMap

/**
 * Port and adapters for durable auth persistence (TC-004).
 */
interface DurableAuthStore {
    fun saveCredential(cred: PlayerCredentialRecord)
    fun findCredential(tenantId: String, identifier: String): PlayerCredentialRecord?
    fun findCredentialByPlayerId(tenantId: String, playerId: UUID): PlayerCredentialRecord?
    fun updatePassword(playerId: UUID, newHash: String, newSalt: String, iterations: Int, algo: String)

    fun saveChallenge(challenge: AuthChallengeRecord)
    fun findChallenge(challengeId: UUID): AuthChallengeRecord?
    fun decrementChallengeAttempts(challengeId: UUID): Int
    fun consumeChallenge(challengeId: UUID, consumedAt: Instant): Boolean

    fun saveAuthorizationCode(codeSession: AuthorizationCodeSessionRecord)
    fun findAuthorizationCode(code: String): AuthorizationCodeSessionRecord?
    fun consumeAuthorizationCode(code: String, consumedAt: Instant): Boolean

    fun createSession(session: PlayerSessionRecord)
    fun findSession(sessionId: UUID): PlayerSessionRecord?
    fun terminateSession(sessionId: UUID, terminatedAt: Instant)

    fun createTokenFamily(family: TokenFamilyRecord)
    fun findTokenFamily(familyId: UUID): TokenFamilyRecord?
    fun revokeTokenFamily(familyId: UUID, reason: String)

    fun saveRefreshToken(token: RefreshTokenRecord)
    fun findRefreshTokenByHash(tokenHash: String): RefreshTokenRecord?
    fun rotateRefreshToken(oldTokenHash: String, newToken: RefreshTokenRecord, rotatedAt: Instant): Boolean
    fun revokeRefreshToken(tokenHash: String, revokedAt: Instant)

    fun revokeAllSessionsForPlayer(tenantId: String, playerId: UUID, terminatedAt: Instant): Int
    fun revokeAllTokenFamiliesForPlayer(tenantId: String, playerId: UUID, reason: String): Int
    fun revokeAllAuthorizationCodesForPlayer(tenantId: String, playerId: UUID, consumedAt: Instant): Int
}

/**
 * In-memory thread-safe implementation of DurableAuthStore for unit tests and local isolation.
 */
class InMemoryDurableAuthStore : DurableAuthStore {
    val credentials = ConcurrentHashMap<String, PlayerCredentialRecord>()
    val challenges = ConcurrentHashMap<UUID, AuthChallengeRecord>()
    val authCodes = ConcurrentHashMap<String, AuthorizationCodeSessionRecord>()
    val sessions = ConcurrentHashMap<UUID, PlayerSessionRecord>()
    val families = ConcurrentHashMap<UUID, TokenFamilyRecord>()
    val refreshTokens = ConcurrentHashMap<String, RefreshTokenRecord>()

    override fun saveCredential(cred: PlayerCredentialRecord) {
        val key = "${cred.tenantId}:${cred.identifier}"
        credentials[key] = cred
    }

    override fun findCredential(tenantId: String, identifier: String): PlayerCredentialRecord? =
        credentials["$tenantId:$identifier"]

    override fun findCredentialByPlayerId(tenantId: String, playerId: UUID): PlayerCredentialRecord? =
        credentials.values.firstOrNull { it.tenantId == tenantId && it.playerId == playerId }

    override fun updatePassword(playerId: UUID, newHash: String, newSalt: String, iterations: Int, algo: String) {
        credentials.values.firstOrNull { it.playerId == playerId }?.let { existing ->
            val updated = existing.copy(
                passwordHash = newHash,
                passwordSalt = newSalt,
                iterations = iterations,
                passwordAlgo = algo,
                updatedAt = Instant.now(),
                version = existing.version + 1
            )
            credentials["${updated.tenantId}:${updated.identifier}"] = updated
        }
    }

    override fun saveChallenge(challenge: AuthChallengeRecord) {
        challenges[challenge.challengeId] = challenge
    }

    override fun findChallenge(challengeId: UUID): AuthChallengeRecord? =
        challenges[challengeId]

    @Synchronized
    override fun decrementChallengeAttempts(challengeId: UUID): Int {
        val challenge = challenges[challengeId] ?: return 0
        if (challenge.attemptsRemaining > 0) {
            challenge.attemptsRemaining--
        }
        return challenge.attemptsRemaining
    }

    @Synchronized
    override fun consumeChallenge(challengeId: UUID, consumedAt: Instant): Boolean {
        val challenge = challenges[challengeId] ?: return false
        if (challenge.consumedAt != null) return false
        challenge.consumedAt = consumedAt
        return true
    }

    override fun saveAuthorizationCode(codeSession: AuthorizationCodeSessionRecord) {
        authCodes[codeSession.code] = codeSession
    }

    override fun findAuthorizationCode(code: String): AuthorizationCodeSessionRecord? =
        authCodes[code]

    @Synchronized
    override fun consumeAuthorizationCode(code: String, consumedAt: Instant): Boolean {
        val record = authCodes[code] ?: return false
        if (record.consumed) return false
        record.consumed = true
        record.consumedAt = consumedAt
        return true
    }

    override fun createSession(session: PlayerSessionRecord) {
        sessions[session.sessionId] = session
    }

    override fun findSession(sessionId: UUID): PlayerSessionRecord? =
        sessions[sessionId]

    @Synchronized
    override fun terminateSession(sessionId: UUID, terminatedAt: Instant) {
        sessions[sessionId]?.let {
            it.state = SessionState.TERMINATED
            it.terminatedAt = terminatedAt
            it.version++
        }
    }

    override fun createTokenFamily(family: TokenFamilyRecord) {
        families[family.familyId] = family
    }

    override fun findTokenFamily(familyId: UUID): TokenFamilyRecord? =
        families[familyId]

    @Synchronized
    override fun revokeTokenFamily(familyId: UUID, reason: String) {
        families[familyId]?.let {
            it.isRevoked = true
            it.revocationReason = reason
            it.updatedAt = Instant.now()
            it.version++
        }
        // Mark tokens in family revoked
        refreshTokens.values.filter { it.familyId == familyId }.forEach {
            it.status = RefreshTokenStatus.REVOKED
            it.revokedAt = Instant.now()
        }
    }

    override fun saveRefreshToken(token: RefreshTokenRecord) {
        refreshTokens[token.tokenHash] = token
    }

    override fun findRefreshTokenByHash(tokenHash: String): RefreshTokenRecord? =
        refreshTokens[tokenHash]

    @Synchronized
    override fun rotateRefreshToken(oldTokenHash: String, newToken: RefreshTokenRecord, rotatedAt: Instant): Boolean {
        val oldToken = refreshTokens[oldTokenHash] ?: return false
        if (oldToken.status != RefreshTokenStatus.ACTIVE) return false

        oldToken.status = RefreshTokenStatus.ROTATED
        oldToken.rotatedAt = rotatedAt
        refreshTokens[newToken.tokenHash] = newToken
        return true
    }

    @Synchronized
    override fun revokeRefreshToken(tokenHash: String, revokedAt: Instant) {
        refreshTokens[tokenHash]?.let {
            it.status = RefreshTokenStatus.REVOKED
            it.revokedAt = revokedAt
        }
    }

    @Synchronized
    override fun revokeAllSessionsForPlayer(tenantId: String, playerId: UUID, terminatedAt: Instant): Int {
        var count = 0
        sessions.values.filter { it.tenantId == tenantId && it.playerId == playerId && it.state == SessionState.ACTIVE }.forEach {
            it.state = SessionState.TERMINATED
            it.terminatedAt = terminatedAt
            it.version++
            count++
        }
        return count
    }

    @Synchronized
    override fun revokeAllTokenFamiliesForPlayer(tenantId: String, playerId: UUID, reason: String): Int {
        var count = 0
        families.values.filter { it.tenantId == tenantId && it.playerId == playerId && !it.isRevoked }.forEach {
            revokeTokenFamily(it.familyId, reason)
            count++
        }
        return count
    }

    @Synchronized
    override fun revokeAllAuthorizationCodesForPlayer(tenantId: String, playerId: UUID, consumedAt: Instant): Int {
        var count = 0
        authCodes.values.filter { it.tenantId == tenantId && it.playerId == playerId && !it.consumed }.forEach {
            it.consumed = true
            it.consumedAt = consumedAt
            count++
        }
        return count
    }
}

/**
 * JDBC PostgreSQL backed implementation of DurableAuthStore.
 */
@Repository
class JdbcDurableAuthStore(private val jdbc: JdbcTemplate) : DurableAuthStore {

    override fun saveCredential(cred: PlayerCredentialRecord) {
        jdbc.update(
            """
            insert into player_credential(player_id, tenant_id, identifier, password_hash, password_algo, password_salt, iterations, status, version, created_at, updated_at)
            values (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """.trimIndent(),
            cred.playerId, cred.tenantId, cred.identifier, cred.passwordHash, cred.passwordAlgo, cred.passwordSalt,
            cred.iterations, cred.status, cred.version, Timestamp.from(cred.createdAt), Timestamp.from(cred.updatedAt)
        )
    }

    override fun findCredential(tenantId: String, identifier: String): PlayerCredentialRecord? =
        jdbc.query(
            "select * from player_credential where tenant_id = ? and identifier = ?",
            credentialMapper, tenantId, identifier
        ).firstOrNull()

    override fun findCredentialByPlayerId(tenantId: String, playerId: UUID): PlayerCredentialRecord? =
        jdbc.query(
            "select * from player_credential where tenant_id = ? and player_id = ?",
            credentialMapper, tenantId, playerId
        ).firstOrNull()

    override fun updatePassword(playerId: UUID, newHash: String, newSalt: String, iterations: Int, algo: String) {
        jdbc.update(
            """
            update player_credential 
            set password_hash = ?, password_salt = ?, iterations = ?, password_algo = ?, updated_at = now(), version = version + 1
            where player_id = ?
            """.trimIndent(),
            newHash, newSalt, iterations, algo, playerId
        )
    }

    override fun saveChallenge(challenge: AuthChallengeRecord) {
        jdbc.update(
            """
            insert into auth_challenge(challenge_id, tenant_id, player_id, purpose, code_hash, salt, attempts_remaining, max_attempts, expires_at, consumed_at, created_at)
            values (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """.trimIndent(),
            challenge.challengeId, challenge.tenantId, challenge.playerId, challenge.purpose, challenge.codeHash,
            challenge.salt, challenge.attemptsRemaining, challenge.maxAttempts, Timestamp.from(challenge.expiresAt),
            challenge.consumedAt?.let { Timestamp.from(it) }, Timestamp.from(challenge.createdAt)
        )
    }

    override fun findChallenge(challengeId: UUID): AuthChallengeRecord? =
        jdbc.query("select * from auth_challenge where challenge_id = ?", challengeMapper, challengeId).firstOrNull()

    override fun decrementChallengeAttempts(challengeId: UUID): Int {
        jdbc.update(
            "update auth_challenge set attempts_remaining = greatest(0, attempts_remaining - 1) where challenge_id = ?",
            challengeId
        )
        return jdbc.queryForObject(
            "select attempts_remaining from auth_challenge where challenge_id = ?",
            Int::class.java, challengeId
        ) ?: 0
    }

    override fun consumeChallenge(challengeId: UUID, consumedAt: Instant): Boolean {
        val rows = jdbc.update(
            "update auth_challenge set consumed_at = ? where challenge_id = ? and consumed_at is null",
            Timestamp.from(consumedAt), challengeId
        )
        return rows > 0
    }

    override fun saveAuthorizationCode(codeSession: AuthorizationCodeSessionRecord) {
        jdbc.update(
            """
            insert into authorization_code_session(code, code_challenge, code_challenge_method, state, nonce, redirect_uri, tenant_id, player_id, expires_at, consumed, consumed_at, created_at)
            values (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """.trimIndent(),
            codeSession.code, codeSession.codeChallenge, codeSession.codeChallengeMethod, codeSession.state,
            codeSession.nonce, codeSession.redirectUri, codeSession.tenantId, codeSession.playerId,
            Timestamp.from(codeSession.expiresAt), codeSession.consumed, codeSession.consumedAt?.let { Timestamp.from(it) },
            Timestamp.from(codeSession.createdAt)
        )
    }

    override fun findAuthorizationCode(code: String): AuthorizationCodeSessionRecord? =
        jdbc.query("select * from authorization_code_session where code = ?", authCodeMapper, code).firstOrNull()

    override fun consumeAuthorizationCode(code: String, consumedAt: Instant): Boolean {
        val rows = jdbc.update(
            "update authorization_code_session set consumed = true, consumed_at = ? where code = ? and consumed = false",
            Timestamp.from(consumedAt), code
        )
        return rows > 0
    }

    override fun createSession(session: PlayerSessionRecord) {
        jdbc.update(
            """
            insert into player_session(session_id, tenant_id, player_id, state, device_fingerprint, ip_address, user_agent, created_at, expires_at, terminated_at, version)
            values (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """.trimIndent(),
            session.sessionId, session.tenantId, session.playerId, session.state.name, session.deviceFingerprint,
            session.ipAddress, session.userAgent, Timestamp.from(session.createdAt), Timestamp.from(session.expiresAt),
            session.terminatedAt?.let { Timestamp.from(it) }, session.version
        )
    }

    override fun findSession(sessionId: UUID): PlayerSessionRecord? =
        jdbc.query("select * from player_session where session_id = ?", sessionMapper, sessionId).firstOrNull()

    override fun terminateSession(sessionId: UUID, terminatedAt: Instant) {
        jdbc.update(
            "update player_session set state = 'TERMINATED', terminated_at = ?, version = version + 1 where session_id = ?",
            Timestamp.from(terminatedAt), sessionId
        )
    }

    override fun createTokenFamily(family: TokenFamilyRecord) {
        jdbc.update(
            """
            insert into token_family(family_id, tenant_id, player_id, session_id, is_revoked, revocation_reason, created_at, updated_at, version)
            values (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """.trimIndent(),
            family.familyId, family.tenantId, family.playerId, family.sessionId, family.isRevoked, family.revocationReason,
            Timestamp.from(family.createdAt), Timestamp.from(family.updatedAt), family.version
        )
    }

    override fun findTokenFamily(familyId: UUID): TokenFamilyRecord? =
        jdbc.query("select * from token_family where family_id = ?", familyMapper, familyId).firstOrNull()

    @Transactional
    override fun revokeTokenFamily(familyId: UUID, reason: String) {
        jdbc.update(
            "update token_family set is_revoked = true, revocation_reason = ?, updated_at = now(), version = version + 1 where family_id = ?",
            reason, familyId
        )
        jdbc.update(
            "update refresh_token_record set status = 'REVOKED', revoked_at = now() where family_id = ? and status != 'REVOKED'",
            familyId
        )
    }

    override fun saveRefreshToken(token: RefreshTokenRecord) {
        jdbc.update(
            """
            insert into refresh_token_record(token_id, family_id, token_hash, tenant_id, player_id, parent_token_hash, status, issued_at, expires_at, rotated_at, revoked_at)
            values (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """.trimIndent(),
            token.tokenId, token.familyId, token.tokenHash, token.tenantId, token.playerId, token.parentTokenHash,
            token.status.name, Timestamp.from(token.issuedAt), Timestamp.from(token.expiresAt),
            token.rotatedAt?.let { Timestamp.from(it) }, token.revokedAt?.let { Timestamp.from(it) }
        )
    }

    override fun findRefreshTokenByHash(tokenHash: String): RefreshTokenRecord? =
        jdbc.query("select * from refresh_token_record where token_hash = ?", refreshTokenMapper, tokenHash).firstOrNull()

    @Transactional
    override fun rotateRefreshToken(oldTokenHash: String, newToken: RefreshTokenRecord, rotatedAt: Instant): Boolean {
        // Atomic Compare-And-Set: Only update if current status is ACTIVE
        val rowsUpdated = jdbc.update(
            "update refresh_token_record set status = 'ROTATED', rotated_at = ? where token_hash = ? and status = 'ACTIVE'",
            Timestamp.from(rotatedAt), oldTokenHash
        )
        if (rowsUpdated == 0) {
            return false
        }
        saveRefreshToken(newToken)
        return true
    }

    override fun revokeRefreshToken(tokenHash: String, revokedAt: Instant) {
        jdbc.update(
            "update refresh_token_record set status = 'REVOKED', revoked_at = ? where token_hash = ?",
            Timestamp.from(revokedAt), tokenHash
        )
    }

    @Transactional
    override fun revokeAllSessionsForPlayer(tenantId: String, playerId: UUID, terminatedAt: Instant): Int {
        return jdbc.update(
            "update player_session set state = 'TERMINATED', terminated_at = ?, version = version + 1 where tenant_id = ? and player_id = ? and state = 'ACTIVE'",
            Timestamp.from(terminatedAt), tenantId, playerId
        )
    }

    @Transactional
    override fun revokeAllTokenFamiliesForPlayer(tenantId: String, playerId: UUID, reason: String): Int {
        val families = jdbc.queryForList(
            "select family_id from token_family where tenant_id = ? and player_id = ? and is_revoked = false",
            UUID::class.java, tenantId, playerId
        )
        for (fId in families) {
            revokeTokenFamily(fId, reason)
        }
        return families.size
    }

    @Transactional
    override fun revokeAllAuthorizationCodesForPlayer(tenantId: String, playerId: UUID, consumedAt: Instant): Int {
        return jdbc.update(
            "update authorization_code_session set consumed = true, consumed_at = ? where tenant_id = ? and player_id = ? and consumed = false",
            Timestamp.from(consumedAt), tenantId, playerId
        )
    }

    private val credentialMapper = RowMapper { rs: ResultSet, _ ->
        PlayerCredentialRecord(
            playerId = rs.getObject("player_id", UUID::class.java),
            tenantId = rs.getString("tenant_id"),
            identifier = rs.getString("identifier"),
            passwordHash = rs.getString("password_hash"),
            passwordAlgo = rs.getString("password_algo"),
            passwordSalt = rs.getString("password_salt"),
            iterations = rs.getInt("iterations"),
            status = rs.getString("status"),
            version = rs.getLong("version"),
            createdAt = rs.getTimestamp("created_at").toInstant(),
            updatedAt = rs.getTimestamp("updated_at").toInstant()
        )
    }

    private val challengeMapper = RowMapper { rs: ResultSet, _ ->
        AuthChallengeRecord(
            challengeId = rs.getObject("challenge_id", UUID::class.java),
            tenantId = rs.getString("tenant_id"),
            playerId = rs.getObject("player_id", UUID::class.java),
            purpose = rs.getString("purpose"),
            codeHash = rs.getString("code_hash"),
            salt = rs.getString("salt"),
            attemptsRemaining = rs.getInt("attempts_remaining"),
            maxAttempts = rs.getInt("max_attempts"),
            expiresAt = rs.getTimestamp("expires_at").toInstant(),
            consumedAt = rs.getTimestamp("consumed_at")?.toInstant(),
            createdAt = rs.getTimestamp("created_at").toInstant()
        )
    }

    private val authCodeMapper = RowMapper { rs: ResultSet, _ ->
        AuthorizationCodeSessionRecord(
            code = rs.getString("code"),
            codeChallenge = rs.getString("code_challenge"),
            codeChallengeMethod = rs.getString("code_challenge_method"),
            state = rs.getString("state"),
            nonce = rs.getString("nonce"),
            redirectUri = rs.getString("redirect_uri"),
            tenantId = rs.getString("tenant_id"),
            playerId = rs.getObject("player_id", UUID::class.java),
            expiresAt = rs.getTimestamp("expires_at").toInstant(),
            consumed = rs.getBoolean("consumed"),
            consumedAt = rs.getTimestamp("consumed_at")?.toInstant(),
            createdAt = rs.getTimestamp("created_at").toInstant()
        )
    }

    private val sessionMapper = RowMapper { rs: ResultSet, _ ->
        PlayerSessionRecord(
            sessionId = rs.getObject("session_id", UUID::class.java),
            tenantId = rs.getString("tenant_id"),
            playerId = rs.getObject("player_id", UUID::class.java),
            state = SessionState.valueOf(rs.getString("state")),
            deviceFingerprint = rs.getString("device_fingerprint"),
            ipAddress = rs.getString("ip_address"),
            userAgent = rs.getString("user_agent"),
            createdAt = rs.getTimestamp("created_at").toInstant(),
            expiresAt = rs.getTimestamp("expires_at").toInstant(),
            terminatedAt = rs.getTimestamp("terminated_at")?.toInstant(),
            version = rs.getLong("version")
        )
    }

    private val familyMapper = RowMapper { rs: ResultSet, _ ->
        TokenFamilyRecord(
            familyId = rs.getObject("family_id", UUID::class.java),
            tenantId = rs.getString("tenant_id"),
            playerId = rs.getObject("player_id", UUID::class.java),
            sessionId = rs.getObject("session_id", UUID::class.java),
            isRevoked = rs.getBoolean("is_revoked"),
            revocationReason = rs.getString("revocation_reason"),
            createdAt = rs.getTimestamp("created_at").toInstant(),
            updatedAt = rs.getTimestamp("updated_at").toInstant(),
            version = rs.getLong("version")
        )
    }

    private val refreshTokenMapper = RowMapper { rs: ResultSet, _ ->
        RefreshTokenRecord(
            tokenId = rs.getObject("token_id", UUID::class.java),
            familyId = rs.getObject("family_id", UUID::class.java),
            tokenHash = rs.getString("token_hash"),
            tenantId = rs.getString("tenant_id"),
            playerId = rs.getObject("player_id", UUID::class.java),
            parentTokenHash = rs.getString("parent_token_hash"),
            status = RefreshTokenStatus.valueOf(rs.getString("status")),
            issuedAt = rs.getTimestamp("issued_at").toInstant(),
            expiresAt = rs.getTimestamp("expires_at").toInstant(),
            rotatedAt = rs.getTimestamp("rotated_at")?.toInstant(),
            revokedAt = rs.getTimestamp("revoked_at")?.toInstant()
        )
    }
}
