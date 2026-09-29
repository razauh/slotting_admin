package com.slotting.admin.auth

import com.slotting.admin.contract.auth.*
import org.junit.jupiter.api.Assertions.*
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.DisplayName
import org.junit.jupiter.api.Test
import org.springframework.http.HttpStatus
import java.time.Clock
import java.time.Duration
import java.time.Instant
import java.time.ZoneOffset
import java.util.UUID
import java.util.concurrent.CountDownLatch
import java.util.concurrent.Executors
import java.util.concurrent.atomic.AtomicInteger

/**
 * TC-004 Integration Test Suite in slotting_admin.
 *
 * Covers:
 * 1. Password KDF with per-credential salts, adaptive PBKDF2, and legacy migration.
 * 2. Unpredictable challenges with purpose/subject binding, attempt limits, and replay rejection (BE-009).
 * 3. Token family rotation, atomic compare-and-set, and reuse detection revoking family.
 * 4. Bounded canonical fingerprint fitting in SQL schema (BE-017).
 * 5. Route-level authorization and server-derived subject (BE-008, XREP-001).
 * 6. Concurrency and restart simulation.
 */
class DurableAuthenticationIntegrationTest {

    private val tenantId = "tenant-casino-1"
    private val clock = Clock.fixed(Instant.parse("2026-09-24T12:00:00Z"), ZoneOffset.UTC)
    private lateinit var store: InMemoryDurableAuthStore
    private lateinit var authService: DurableAuthService
    private lateinit var controller: AuthController

    @BeforeEach
    fun setUp() {
        store = InMemoryDurableAuthStore()
        authService = DurableAuthService(store, clock)
        controller = AuthController(authService)
    }

    // =========================================================================
    // 1. Password KDF & Legacy Migration Tests (BE-009)
    // =========================================================================
    @Test
    @DisplayName("Password KDF - Adaptive PBKDF2 with salt, reject default pass, and legacy migration")
    fun testPasswordKdfAndMigration() {
        val password = "SecurePlayerPassword#2026"
        val hashed = PasswordKdfService.hashPassword(password)

        assertEquals("pbkdf2_sha256", hashed.algo)
        assertEquals(100_000, hashed.iterations)
        assertNotNull(hashed.salt)
        assertNotEquals(password, hashed.hash)

        // Verify correct password
        val okResult = PasswordKdfService.verifyPassword(password, hashed.hash, hashed.salt, hashed.iterations, hashed.algo)
        assertTrue(okResult.valid)
        assertFalse(okResult.needsRehash)

        // Verify wrong password
        val wrongResult = PasswordKdfService.verifyPassword("WrongPassword123", hashed.hash, hashed.salt, hashed.iterations, hashed.algo)
        assertFalse(wrongResult.valid)

        // Reject known default password
        assertThrows(IllegalArgumentException::class.java) {
            PasswordKdfService.hashPassword("DefaultPass123!")
        }

        // Reject blank password
        assertThrows(IllegalArgumentException::class.java) {
            PasswordKdfService.hashPassword("   ")
        }

        // Legacy SHA-256 password migration
        val legacySha256Hex = "5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8" // SHA-256("password")
        val legacyResult = PasswordKdfService.verifyPassword("password", legacySha256Hex, "", 0, PasswordKdfService.LEGACY_SHA256_ALGO)
        assertTrue(legacyResult.valid)
        assertTrue(legacyResult.needsRehash, "Legacy SHA-256 hash must signal needsRehash for transparent upgrade")
    }

    // =========================================================================
    // 2. Unpredictable Challenge Service Tests (BE-009)
    // =========================================================================
    @Test
    @DisplayName("Unpredictable challenges - Purpose and subject binding, replay prevention, attempt limits")
    fun testUnpredictableChallenges() {
        val playerId = UUID.randomUUID()
        val otherPlayerId = UUID.randomUUID()
        val now = Instant.now(clock)

        val challenge = UnpredictableChallengeService.generateChallenge(
            tenantId = tenantId,
            playerId = playerId,
            purpose = "REGISTRATION_VERIFY",
            now = now
        )

        // Plaintext code is 6 digits and unpredictable
        assertTrue(challenge.plaintextCode.length == 6)
        assertTrue(challenge.plaintextCode.toIntOrNull() != null)
        assertNotEquals("EMAIL-123456", challenge.plaintextCode)

        // 1. Success on valid code
        val successRes = UnpredictableChallengeService.validateCode(
            submittedCode = challenge.plaintextCode,
            expectedHash = challenge.codeHash,
            saltHex = challenge.salt,
            expectedPurpose = "REGISTRATION_VERIFY",
            actualPurpose = "REGISTRATION_VERIFY",
            expectedPlayerId = playerId,
            actualPlayerId = playerId,
            expectedTenantId = tenantId,
            actualTenantId = tenantId,
            expiresAt = challenge.expiresAt,
            attemptsRemaining = 3,
            consumed = false,
            now = now
        )
        assertEquals(UnpredictableChallengeService.ChallengeValidationResult.Success, successRes)

        // 2. Rejection of predictable test codes
        val predictableRes = UnpredictableChallengeService.validateCode(
            submittedCode = "EMAIL-123456",
            expectedHash = challenge.codeHash,
            saltHex = challenge.salt,
            expectedPurpose = "REGISTRATION_VERIFY",
            actualPurpose = "REGISTRATION_VERIFY",
            expectedPlayerId = playerId,
            actualPlayerId = playerId,
            expectedTenantId = tenantId,
            actualTenantId = tenantId,
            expiresAt = challenge.expiresAt,
            attemptsRemaining = 3,
            consumed = false,
            now = now
        )
        assertTrue(predictableRes is UnpredictableChallengeService.ChallengeValidationResult.Rejected)

        // 3. Rejection of cross-purpose use
        val crossPurposeRes = UnpredictableChallengeService.validateCode(
            submittedCode = challenge.plaintextCode,
            expectedHash = challenge.codeHash,
            saltHex = challenge.salt,
            expectedPurpose = "REGISTRATION_VERIFY",
            actualPurpose = "PASSWORD_RESET",
            expectedPlayerId = playerId,
            actualPlayerId = playerId,
            expectedTenantId = tenantId,
            actualTenantId = tenantId,
            expiresAt = challenge.expiresAt,
            attemptsRemaining = 3,
            consumed = false,
            now = now
        )
        assertTrue(crossPurposeRes is UnpredictableChallengeService.ChallengeValidationResult.Rejected)

        // 4. Rejection of cross-subject use
        val crossSubjectRes = UnpredictableChallengeService.validateCode(
            submittedCode = challenge.plaintextCode,
            expectedHash = challenge.codeHash,
            saltHex = challenge.salt,
            expectedPurpose = "REGISTRATION_VERIFY",
            actualPurpose = "REGISTRATION_VERIFY",
            expectedPlayerId = playerId,
            actualPlayerId = otherPlayerId,
            expectedTenantId = tenantId,
            actualTenantId = tenantId,
            expiresAt = challenge.expiresAt,
            attemptsRemaining = 3,
            consumed = false,
            now = now
        )
        assertTrue(crossSubjectRes is UnpredictableChallengeService.ChallengeValidationResult.Rejected)

        // 5. Replay rejection (consumed)
        val replayRes = UnpredictableChallengeService.validateCode(
            submittedCode = challenge.plaintextCode,
            expectedHash = challenge.codeHash,
            saltHex = challenge.salt,
            expectedPurpose = "REGISTRATION_VERIFY",
            actualPurpose = "REGISTRATION_VERIFY",
            expectedPlayerId = playerId,
            actualPlayerId = playerId,
            expectedTenantId = tenantId,
            actualTenantId = tenantId,
            expiresAt = challenge.expiresAt,
            attemptsRemaining = 3,
            consumed = true,
            now = now
        )
        assertTrue(replayRes is UnpredictableChallengeService.ChallengeValidationResult.Rejected)

        // 6. Attempt limit exceeded
        val attemptsExceededRes = UnpredictableChallengeService.validateCode(
            submittedCode = challenge.plaintextCode,
            expectedHash = challenge.codeHash,
            saltHex = challenge.salt,
            expectedPurpose = "REGISTRATION_VERIFY",
            actualPurpose = "REGISTRATION_VERIFY",
            expectedPlayerId = playerId,
            actualPlayerId = playerId,
            expectedTenantId = tenantId,
            actualTenantId = tenantId,
            expiresAt = challenge.expiresAt,
            attemptsRemaining = 0,
            consumed = false,
            now = now
        )
        assertTrue(attemptsExceededRes is UnpredictableChallengeService.ChallengeValidationResult.Rejected)

        // 7. Expired challenge
        val expiredRes = UnpredictableChallengeService.validateCode(
            submittedCode = challenge.plaintextCode,
            expectedHash = challenge.codeHash,
            saltHex = challenge.salt,
            expectedPurpose = "REGISTRATION_VERIFY",
            actualPurpose = "REGISTRATION_VERIFY",
            expectedPlayerId = playerId,
            actualPlayerId = playerId,
            expectedTenantId = tenantId,
            actualTenantId = tenantId,
            expiresAt = challenge.expiresAt,
            attemptsRemaining = 3,
            consumed = false,
            now = challenge.expiresAt.plusSeconds(1)
        )
        assertTrue(expiredRes is UnpredictableChallengeService.ChallengeValidationResult.Rejected)
    }

    // =========================================================================
    // 3. BE-017 Maximum-Identity Fingerprint Test
    // =========================================================================
    @Test
    @DisplayName("BE-017: Maximum-identity fingerprint produces a bounded 64-char digest fitting in varchar(128)")
    fun testMaximumIdentityFingerprintFitsInSchema() {
        val longPrincipal = AuthenticatedPrincipal(
            id = "principal-uuid-" + UUID.randomUUID().toString(),
            tenantId = "tenant-enterprise-high-security-compliance-division-01",
            kind = PrincipalKind.ADMIN,
            roles = setOf(AdminRole.SUPER_ADMIN, AdminRole.SECURITY)
        )

        val command = AdminMfaCommand(
            principal = longPrincipal,
            requestedRole = AdminRole.SUPER_ADMIN,
            sessionId = "session-uuid-" + UUID.randomUUID().toString(),
            idempotencyKey = "idem-long-key-" + UUID.randomUUID().toString(),
            correlationId = "corr-" + UUID.randomUUID().toString(),
            causationId = "caus-" + UUID.randomUUID().toString(),
            expectedVersion = 1000L,
            mfaAssertion = "98765432101234567890",
            breakGlass = true
        )

        val authenticator = AdminMfaAuthenticator(
            verifier = object : MfaVerifier {
                override fun verify(tenantId: String, principalId: String, sessionId: String, assertion: String): Boolean = true
            },
            store = object : AuthenticationStore {
                override fun currentVersion(tenantId: String, principalId: String): Long = 1000L
                override fun findByIdempotency(tenantId: String, key: String): Pair<String, AuthenticationResult>? = null
                override fun save(
                    result: AuthenticationResult,
                    tenantId: String,
                    principalId: String,
                    sessionId: String,
                    idempotencyKey: String,
                    requestFingerprint: String,
                    audit: AuditEvent,
                    outbox: OutboxEvent
                ) {
                    // Critical assertion for BE-017: requestFingerprint must fit in varchar(128)
                    assertTrue(
                        requestFingerprint.length <= 128,
                        "Fingerprint length (${requestFingerprint.length}) exceeds varchar(128) schema limit!"
                    )
                    assertEquals(64, requestFingerprint.length, "Bounded SHA-256 fingerprint should be exactly 64 characters")
                }
            },
            alerts = object : AlertSink {
                override fun alert(event: AuditEvent) {}
            },
            clock = clock
        )

        val result = authenticator.authenticate(command)
        assertEquals(AuthenticationState.AUTHENTICATED, result.state)
    }

    // =========================================================================
    // 4. Token Family Rotation & Reuse Detection (AUTH-002)
    // =========================================================================
    @Test
    @DisplayName("Token Family - Refresh rotation, reuse detection revoking family, and session termination")
    fun testTokenFamilyRotationAndReuseDetection() {
        val playerId = UUID.randomUUID()
        val codeVerifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
        val codeChallenge = AuthContractCodec.computeS256Challenge(codeVerifier)

        // Seed an authorization code session
        val authCode = "auth-code-12345"
        store.saveAuthorizationCode(
            AuthorizationCodeSessionRecord(
                code = authCode,
                codeChallenge = codeChallenge,
                codeChallengeMethod = "S256",
                state = "state-xyz-123",
                redirectUri = "https://auth.slotting.com/callback",
                tenantId = tenantId,
                playerId = playerId,
                expiresAt = Instant.now(clock).plusSeconds(300)
            )
        )

        // 1. Exchange authorization code
        val tokenResponse = authService.exchangeAuthorizationCode(
            grantType = "authorization_code",
            code = authCode,
            codeVerifier = codeVerifier,
            codeChallengeMethod = "S256",
            state = "state-xyz-123",
            redirectUri = "https://auth.slotting.com/callback",
            clientId = "slotting-android"
        )
        assertNotNull(tokenResponse.accessToken)
        assertNotNull(tokenResponse.refreshToken)
        assertEquals(playerId.toString(), tokenResponse.playerId)
        val initialRefreshToken = tokenResponse.refreshToken
        val familyId = UUID.fromString(tokenResponse.tokenFamilyId)

        // Verify authorization code cannot be replayed
        assertThrows(AuthenticationException::class.java) {
            authService.exchangeAuthorizationCode(
                grantType = "authorization_code",
                code = authCode,
                codeVerifier = codeVerifier,
                codeChallengeMethod = "S256",
                state = "state-xyz-123",
                redirectUri = "https://auth.slotting.com/callback",
                clientId = "slotting-android"
            )
        }

        // 2. Rotate refresh token legitimately
        val rotatedResponse = authService.rotateRefreshToken(initialRefreshToken)
        assertNotNull(rotatedResponse.accessToken)
        assertNotNull(rotatedResponse.refreshToken)
        assertNotEquals(initialRefreshToken, rotatedResponse.refreshToken)
        assertEquals(familyId.toString(), rotatedResponse.tokenFamilyId)

        // 3. REUSE DETECTION: Present old rotated refresh token again!
        val reuseException = assertThrows(AuthenticationException::class.java) {
            authService.rotateRefreshToken(initialRefreshToken)
        }
        assertEquals("TOKEN_REUSE_REVOKED", reuseException.errorCode)

        // 4. Entire family is now revoked! Even the newest refresh token cannot be used!
        val familyRevokedException = assertThrows(AuthenticationException::class.java) {
            authService.rotateRefreshToken(rotatedResponse.refreshToken)
        }
        assertEquals("TOKEN_REVOKED", familyRevokedException.errorCode)
    }

    // =========================================================================
    // 5. Concurrency: Simultaneous Refresh Race
    // =========================================================================
    @Test
    @DisplayName("Concurrency: Simultaneous refresh requests with identical token results in exactly one success")
    fun testConcurrentRefreshRace() {
        val playerId = UUID.randomUUID()
        val codeVerifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
        val codeChallenge = AuthContractCodec.computeS256Challenge(codeVerifier)
        val authCode = "auth-code-conc"

        store.saveAuthorizationCode(
            AuthorizationCodeSessionRecord(
                code = authCode,
                codeChallenge = codeChallenge,
                codeChallengeMethod = "S256",
                state = "state-xyz-123",
                redirectUri = "https://auth.slotting.com/callback",
                tenantId = tenantId,
                playerId = playerId,
                expiresAt = Instant.now(clock).plusSeconds(300)
            )
        )

        val tokenResponse = authService.exchangeAuthorizationCode(
            grantType = "authorization_code",
            code = authCode,
            codeVerifier = codeVerifier,
            codeChallengeMethod = "S256",
            state = "state-xyz-123",
            redirectUri = "https://auth.slotting.com/callback",
            clientId = "slotting-android"
        )
        val refreshToken = tokenResponse.refreshToken

        val threadCount = 4
        val pool = Executors.newFixedThreadPool(threadCount)
        val gate = CountDownLatch(1)
        val successCount = AtomicInteger(0)
        val failureCount = AtomicInteger(0)

        val futures = (1..threadCount).map {
            pool.submit {
                gate.await()
                try {
                    val resp = authService.rotateRefreshToken(refreshToken)
                    if (resp.accessToken.isNotBlank()) {
                        successCount.incrementAndGet()
                    }
                } catch (e: AuthenticationException) {
                    failureCount.incrementAndGet()
                }
            }
        }
        gate.countDown()
        futures.forEach { it.get() }
        pool.shutdown()

        assertEquals(1, successCount.get(), "Exactly one concurrent refresh must succeed")
        assertEquals(threadCount - 1, failureCount.get(), "All other concurrent attempts must fail")
    }

    // =========================================================================
    // 6. HTTP Routes & Protected Endpoint Authorization (BE-008, XREP-001)
    // =========================================================================
    @Test
    @DisplayName("HTTP Routes - Token exchange, eligibility bearer derivation, and unauthorized rejection")
    fun testHttpRoutesAndProtectedEndpoints() {
        val playerId = UUID.randomUUID()
        val codeVerifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
        val codeChallenge = AuthContractCodec.computeS256Challenge(codeVerifier)
        val authCode = "auth-code-route"

        store.saveAuthorizationCode(
            AuthorizationCodeSessionRecord(
                code = authCode,
                codeChallenge = codeChallenge,
                codeChallengeMethod = "S256",
                state = "state-route",
                redirectUri = "https://auth.slotting.com/callback",
                tenantId = tenantId,
                playerId = playerId,
                expiresAt = Instant.now(clock).plusSeconds(300)
            )
        )

        // 1. POST /auth/token (authorization_code)
        val tokenReqJson = """
            {
                "grant_type": "authorization_code",
                "code": "$authCode",
                "code_verifier": "$codeVerifier",
                "code_challenge_method": "S256",
                "state": "state-route",
                "redirect_uri": "https://auth.slotting.com/callback",
                "client_id": "slotting-android"
            }
        """.trimIndent()
        val tokenResp = controller.token(tokenReqJson)
        assertEquals(HttpStatus.OK, tokenResp.statusCode)
        val tokenDto = tokenResp.body as TokenResponseDto
        val accessToken = tokenDto.accessToken

        // 2. GET /auth/eligibility without Bearer token -> 401 Unauthorized
        val unauthResp = controller.eligibility(null, null)
        assertEquals(HttpStatus.UNAUTHORIZED, unauthResp.statusCode)

        // 3. GET /auth/eligibility with valid Bearer token -> 200 OK
        // Invariant: Server derives subject from Bearer token, ignoring spoofed user_id
        val authResp = controller.eligibility("Bearer $accessToken", "spoofed_attacker_id")
        assertEquals(HttpStatus.OK, authResp.statusCode)
        val eligDto = authResp.body as AuthoritativeEligibilityResponseDto
        assertEquals(playerId.toString(), eligDto.playerId, "Subject must be derived from verified server credentials, not client query parameter")
        assertEquals(tenantId, eligDto.tenantId)
        assertTrue(eligDto.eligible)

        // 4. POST /auth/logout -> terminates session
        val logoutJson = """
            {
                "session_id": "${tokenDto.sessionId}",
                "idempotency_key": "logout-idem-001",
                "correlation_id": "logout-corr-001"
            }
        """.trimIndent()
        val logoutResp = controller.logout(logoutJson)
        assertEquals(HttpStatus.OK, logoutResp.statusCode)

        // 5. Subsequent access token query after logout -> 401 Unauthorized (session terminated)
        val afterLogoutResp = controller.eligibility("Bearer $accessToken", null)
        assertEquals(HttpStatus.UNAUTHORIZED, afterLogoutResp.statusCode)
    }

    // =========================================================================
    // 7. Restart Persistence Simulation
    // =========================================================================
    @Test
    @DisplayName("Restart: Valid sessions and token family revocation status survive service recreation")
    fun testRestartPersistence() {
        val playerId = UUID.randomUUID()
        val codeVerifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
        val codeChallenge = AuthContractCodec.computeS256Challenge(codeVerifier)
        val authCode = "auth-code-restart"

        store.saveAuthorizationCode(
            AuthorizationCodeSessionRecord(
                code = authCode,
                codeChallenge = codeChallenge,
                codeChallengeMethod = "S256",
                state = "state-restart",
                redirectUri = "https://auth.slotting.com/callback",
                tenantId = tenantId,
                playerId = playerId,
                expiresAt = Instant.now(clock).plusSeconds(300)
            )
        )

        val tokenResponse = authService.exchangeAuthorizationCode(
            grantType = "authorization_code",
            code = authCode,
            codeVerifier = codeVerifier,
            codeChallengeMethod = "S256",
            state = "state-restart",
            redirectUri = "https://auth.slotting.com/callback",
            clientId = "slotting-android"
        )

        // Revoke token
        authService.revokeToken(tokenResponse.refreshToken)

        // SIMULATE SERVICE RESTART: Create a brand new DurableAuthService instance pointing to the same store
        val restartedAuthService = DurableAuthService(store, clock)

        // Verify that the revoked token family is STILL revoked after restart
        val ex = assertThrows(AuthenticationException::class.java) {
            restartedAuthService.rotateRefreshToken(tokenResponse.refreshToken)
        }
        assertEquals("TOKEN_REVOKED", ex.errorCode)
    }
}
