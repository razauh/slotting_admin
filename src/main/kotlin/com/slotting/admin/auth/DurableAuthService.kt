package com.slotting.admin.auth

import com.slotting.admin.contract.auth.*
import org.slf4j.LoggerFactory
import org.springframework.stereotype.Service
import java.security.MessageDigest
import java.security.SecureRandom
import java.time.Clock
import java.time.Duration
import java.time.Instant
import java.util.Base64
import java.util.UUID
import java.util.concurrent.ConcurrentHashMap

class AuthenticationException(
    val errorCode: String,
    override val message: String,
    val retryable: Boolean = false
) : RuntimeException(message)

/**
 * Production service providing durable authentication, session lifecycle,
 * refresh token rotation with reuse detection, and route-level authority (TC-004).
 */
@Service
class DurableAuthService(
    private val store: DurableAuthStore,
    private val clock: Clock = Clock.systemUTC(),
    val oidcKeyService: OidcKeyService = OidcKeyService(clock)
) {
    private val logger = LoggerFactory.getLogger(javaClass)
    private val secureRandom = SecureRandom()

    // In-memory token cache mapping accessToken -> PrincipalTokenData for fast lookup
    data class PrincipalTokenData(
        val playerId: UUID,
        val tenantId: String,
        val sessionId: UUID,
        val familyId: UUID,
        val expiresAt: Instant
    )

    private val tokenCache = ConcurrentHashMap<String, PrincipalTokenData>()

    companion object {
        val ACCESS_TOKEN_TTL: Duration = Duration.ofMinutes(15)
        val REFRESH_TOKEN_TTL: Duration = Duration.ofDays(30)
        val SESSION_TTL: Duration = Duration.ofDays(30)
    }

    fun createAuthorizationCode(
        clientId: String,
        redirectUri: String,
        scope: String,
        state: String,
        nonce: String?,
        codeChallenge: String,
        codeChallengeMethod: String,
        tenantId: String,
        playerId: UUID,
        authTime: Instant = Instant.now(clock)
    ): AuthorizationCodeSessionRecord {
        val client = OAuthClientRegistry.findClient(clientId)
            ?: throw AuthenticationException("UNAUTHORIZED_CLIENT", "Unknown or inactive client: $clientId")

        if (!OAuthClientRegistry.validateRedirectUri(clientId, redirectUri)) {
            throw AuthenticationException("INVALID_REQUEST", "Unregistered redirect URI: $redirectUri")
        }

        if (!OAuthClientRegistry.validateScope(clientId, scope)) {
            throw AuthenticationException("INVALID_SCOPE", "Requested scope not allowed for client: $scope")
        }

        if (codeChallengeMethod != "S256") {
            throw AuthenticationException("PROTOCOL_DOWNGRADE_REJECTED", "PKCE code_challenge_method must be S256")
        }

        if (codeChallenge.isBlank() || codeChallenge.length < 43 || codeChallenge.length > 128) {
            throw AuthenticationException("INVALID_REQUEST", "Invalid PKCE code_challenge")
        }

        if (state.isBlank()) {
            throw AuthenticationException("INVALID_REQUEST", "state parameter is required")
        }

        val code = generateSecureToken("code")
        val now = Instant.now(clock)
        val expiresAt = now.plus(Duration.ofMinutes(5))

        val record = AuthorizationCodeSessionRecord(
            code = code,
            codeChallenge = codeChallenge,
            codeChallengeMethod = codeChallengeMethod,
            state = state,
            nonce = nonce,
            redirectUri = redirectUri,
            tenantId = tenantId,
            playerId = playerId,
            expiresAt = expiresAt,
            consumed = false,
            consumedAt = null,
            createdAt = now,
            clientId = clientId,
            scope = scope,
            authTime = authTime
        )

        store.saveAuthorizationCode(record)
        return record
    }

    fun authenticatePlayer(tenantId: String, identifier: String, password: String): PlayerCredentialRecord? {
        val cred = store.findCredential(tenantId, identifier) ?: return null
        if (cred.status != "ACTIVE") return null
        val result = PasswordKdfService.verifyPassword(
            password = password,
            storedHash = cred.passwordHash,
            salt = cred.passwordSalt,
            iterations = cred.iterations,
            algo = cred.passwordAlgo
        )
        if (!result.valid) return null
        if (result.needsRehash) {
            val newHash = PasswordKdfService.hashPassword(password)
            store.updatePassword(
                playerId = cred.playerId,
                newHash = newHash.hash,
                newSalt = newHash.salt,
                iterations = newHash.iterations,
                algo = newHash.algo
            )
        }
        return cred
    }

    fun registerPlayer(
        tenantId: String,
        identifier: String,
        password: String
    ): PlayerCredentialRecord {
        val existing = store.findCredential(tenantId, identifier)
        if (existing != null) {
            throw AuthenticationException("IDENTIFIER_EXISTS", "Identifier already registered")
        }
        val hashed = PasswordKdfService.hashPassword(password)
        val now = Instant.now(clock)
        val cred = PlayerCredentialRecord(
            playerId = UUID.randomUUID(),
            tenantId = tenantId,
            identifier = identifier,
            passwordHash = hashed.hash,
            passwordSalt = hashed.salt,
            iterations = hashed.iterations,
            passwordAlgo = hashed.algo,
            status = "ACTIVE",
            createdAt = now,
            updatedAt = now
        )
        store.saveCredential(cred)
        return cred
    }

    fun findCredential(tenantId: String, identifier: String): PlayerCredentialRecord? =
        store.findCredential(tenantId, identifier)

    fun exchangeAuthorizationCode(
        grantType: String,
        code: String,
        codeVerifier: String,
        codeChallengeMethod: String,
        state: String,
        redirectUri: String,
        clientId: String
    ): TokenResponseDto {
        val now = Instant.now(clock)
        if (grantType != "authorization_code") {
            throw AuthenticationException("INVALID_REQUEST", "grant_type must be authorization_code")
        }
        if (codeChallengeMethod != "S256") {
            throw AuthenticationException("PROTOCOL_DOWNGRADE_REJECTED", "PKCE code_challenge_method must be S256")
        }

        val authSession = store.findAuthorizationCode(code)
            ?: throw AuthenticationException("INVALID_GRANT", "Authorization code not found or invalid")

        if (authSession.consumed) {
            throw AuthenticationException("INVALID_GRANT", "Authorization code already consumed")
        }
        if (now.isAfter(authSession.expiresAt)) {
            throw AuthenticationException("INVALID_GRANT", "Authorization code expired")
        }
        if (authSession.state != state) {
            throw AuthenticationException("INVALID_STATE_OR_NONCE", "State parameter mismatch")
        }
        if (authSession.redirectUri != redirectUri) {
            throw AuthenticationException("UNAUTHORIZED_CLIENT", "Redirect URI mismatch")
        }
        if (authSession.clientId.isNotBlank() && clientId.isNotBlank() && authSession.clientId != clientId) {
            throw AuthenticationException("UNAUTHORIZED_CLIENT", "Client ID mismatch: expected ${authSession.clientId}")
        }

        // Validate PKCE S256
        val pkceValid = AuthContractCodec.validatePkce(codeVerifier, authSession.codeChallenge, "S256")
        if (!pkceValid) {
            throw AuthenticationException("INVALID_VERIFIER", "PKCE code verifier does not match challenge")
        }

        // Consume authorization code atomically
        val consumed = store.consumeAuthorizationCode(code, now)
        if (!consumed) {
            throw AuthenticationException("INVALID_GRANT", "Authorization code already consumed")
        }

        // Create session
        val sessionId = UUID.randomUUID()
        val session = PlayerSessionRecord(
            sessionId = sessionId,
            tenantId = authSession.tenantId,
            playerId = authSession.playerId,
            state = SessionState.ACTIVE,
            createdAt = now,
            expiresAt = now.plus(SESSION_TTL)
        )
        store.createSession(session)

        // Create token family
        val familyId = UUID.randomUUID()
        val family = TokenFamilyRecord(
            familyId = familyId,
            tenantId = authSession.tenantId,
            playerId = authSession.playerId,
            sessionId = sessionId,
            createdAt = now,
            updatedAt = now
        )
        store.createTokenFamily(family)

        // Issue tokens
        val accessToken = generateSecureToken("atk")
        val refreshToken = generateSecureToken("rtk")
        val refreshHash = hashToken(refreshToken)

        val refreshRecord = RefreshTokenRecord(
            tokenId = UUID.randomUUID(),
            familyId = familyId,
            tokenHash = refreshHash,
            tenantId = authSession.tenantId,
            playerId = authSession.playerId,
            status = RefreshTokenStatus.ACTIVE,
            issuedAt = now,
            expiresAt = now.plus(REFRESH_TOKEN_TTL)
        )
        store.saveRefreshToken(refreshRecord)

        // Generate OIDC ID Token if openid scope is present
        val effectiveScope = authSession.scope.ifBlank { "openid profile" }
        val idToken = if (effectiveScope.split(" ").contains("openid")) {
            oidcKeyService.issueIdToken(
                playerId = authSession.playerId,
                clientId = if (clientId.isNotBlank()) clientId else authSession.clientId,
                tenantId = authSession.tenantId,
                nonce = authSession.nonce,
                authTime = authSession.authTime
            )
        } else null

        // Cache access token
        tokenCache[accessToken] = PrincipalTokenData(
            playerId = authSession.playerId,
            tenantId = authSession.tenantId,
            sessionId = sessionId,
            familyId = familyId,
            expiresAt = now.plus(ACCESS_TOKEN_TTL)
        )

        return TokenResponseDto(
            accessToken = accessToken,
            tokenType = "Bearer",
            expiresInSeconds = ACCESS_TOKEN_TTL.seconds,
            refreshToken = refreshToken,
            scope = effectiveScope,
            playerId = authSession.playerId.toString(),
            tenantId = authSession.tenantId,
            tokenFamilyId = familyId.toString(),
            sessionId = sessionId.toString(),
            issuedAtEpochMs = now.toEpochMilli(),
            idToken = idToken
        )
    }

    fun rotateRefreshToken(refreshToken: String, clientId: String? = null): TokenResponseDto {
        val now = Instant.now(clock)
        val tokenHash = hashToken(refreshToken)
        val record = store.findRefreshTokenByHash(tokenHash)
            ?: throw AuthenticationException("INVALID_GRANT", "Invalid refresh token")

        // 1. REUSE DETECTION: If token is already ROTATED, an attacker or compromised client replayed it!
        if (record.status == RefreshTokenStatus.ROTATED) {
            logger.error("SECURITY_ALERT: Refresh token reuse detected! Revoking token family {}", record.familyId)
            store.revokeTokenFamily(record.familyId, "ROTATED_REUSE_DETECTED")
            throw AuthenticationException("TOKEN_REUSE_REVOKED", "Refresh token reuse detected; family revoked")
        }

        // 2. Check if family is revoked
        val family = store.findTokenFamily(record.familyId)
        if (family == null || family.isRevoked) {
            throw AuthenticationException("TOKEN_REVOKED", "Token family is revoked")
        }

        // 3. Check token status
        if (record.status != RefreshTokenStatus.ACTIVE) {
            throw AuthenticationException("TOKEN_REVOKED", "Refresh token is not active")
        }
        if (now.isAfter(record.expiresAt)) {
            throw AuthenticationException("TOKEN_EXPIRED", "Refresh token has expired")
        }

        // 4. Check session status
        val session = store.findSession(family.sessionId)
        if (session == null || session.state != SessionState.ACTIVE || now.isAfter(session.expiresAt)) {
            throw AuthenticationException("TOKEN_REVOKED", "Session is terminated or expired")
        }

        // 5. Issue new tokens and rotate old token atomically
        val newAccessToken = generateSecureToken("atk")
        val newRefreshToken = generateSecureToken("rtk")
        val newRefreshHash = hashToken(newRefreshToken)

        val newRecord = RefreshTokenRecord(
            tokenId = UUID.randomUUID(),
            familyId = record.familyId,
            tokenHash = newRefreshHash,
            tenantId = record.tenantId,
            playerId = record.playerId,
            parentTokenHash = tokenHash,
            status = RefreshTokenStatus.ACTIVE,
            issuedAt = now,
            expiresAt = now.plus(REFRESH_TOKEN_TTL)
        )

        val rotated = store.rotateRefreshToken(tokenHash, newRecord, now)
        if (!rotated) {
            // Concurrent refresh race detected
            throw AuthenticationException("INVALID_GRANT", "Concurrent refresh conflict detected; retry")
        }

        // Cache new access token
        tokenCache[newAccessToken] = PrincipalTokenData(
            playerId = record.playerId,
            tenantId = record.tenantId,
            sessionId = family.sessionId,
            familyId = record.familyId,
            expiresAt = now.plus(ACCESS_TOKEN_TTL)
        )

        val idToken = oidcKeyService.issueIdToken(
            playerId = record.playerId,
            clientId = if (!clientId.isNullOrBlank()) clientId else "slotting-android",
            tenantId = record.tenantId,
            nonce = null
        )

        return TokenResponseDto(
            accessToken = newAccessToken,
            tokenType = "Bearer",
            expiresInSeconds = ACCESS_TOKEN_TTL.seconds,
            refreshToken = newRefreshToken,
            scope = "openid profile wallet.read cashier.write gameplay",
            playerId = record.playerId.toString(),
            tenantId = record.tenantId,
            tokenFamilyId = record.familyId.toString(),
            sessionId = family.sessionId.toString(),
            issuedAtEpochMs = now.toEpochMilli(),
            idToken = idToken
        )
    }

    fun revokeToken(token: String, hint: String? = null): TokenRevocationResponseDto {
        val now = Instant.now(clock)
        val tokenHash = hashToken(token)
        val record = store.findRefreshTokenByHash(tokenHash)
        if (record != null) {
            store.revokeTokenFamily(record.familyId, "REVOKED_BY_CLIENT")
        }
        tokenCache.remove(token)
        return TokenRevocationResponseDto(
            revoked = true,
            tokenType = hint ?: "refresh_token",
            serverTimeEpochMs = now.toEpochMilli()
        )
    }

    fun logoutSession(sessionId: UUID, idempotencyKey: String, correlationId: String): SessionLogoutResponseDto {
        val now = Instant.now(clock)
        val session = store.findSession(sessionId)
            ?: throw AuthenticationException("INVALID_REQUEST", "Session not found")

        store.terminateSession(sessionId, now)

        // Invalidate cached tokens belonging to this session
        tokenCache.entries.removeIf { it.value.sessionId == sessionId }

        return SessionLogoutResponseDto(
            terminated = true,
            sessionId = sessionId.toString(),
            playerId = session.playerId.toString(),
            serverTimeEpochMs = now.toEpochMilli(),
            evidenceReference = "ev-logout-${UUID.randomUUID()}"
        )
    }

    fun validateAccessToken(token: String): AuthenticatedPrincipal? {
        val now = Instant.now(clock)
        val data = tokenCache[token] ?: return null
        if (now.isAfter(data.expiresAt)) {
            tokenCache.remove(token)
            return null
        }

        // Verify session and family are active in store
        val session = store.findSession(data.sessionId)
        if (session == null || session.state != SessionState.ACTIVE) {
            tokenCache.remove(token)
            return null
        }

        val family = store.findTokenFamily(data.familyId)
        if (family == null || family.isRevoked) {
            tokenCache.remove(token)
            return null
        }

        return AuthenticatedPrincipal(
            id = data.playerId.toString(),
            tenantId = data.tenantId,
            kind = PrincipalKind.PLAYER,
            roles = emptySet()
        )
    }

    private fun generateSecureToken(prefix: String): String {
        val bytes = ByteArray(32).also { secureRandom.nextBytes(it) }
        return "$prefix." + Base64.getUrlEncoder().withoutPadding().encodeToString(bytes)
    }

    fun hashToken(token: String): String {
        val digest = MessageDigest.getInstance("SHA-256").digest(token.toByteArray(Charsets.UTF_8))
        return PasswordKdfService.bytesToHex(digest)
    }
}
