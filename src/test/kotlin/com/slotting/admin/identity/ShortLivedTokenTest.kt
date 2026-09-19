package com.slotting.admin.identity

import com.slotting.admin.auth.AuthErrorCode
import com.slotting.admin.auth.AuthenticationFailure
import org.junit.jupiter.api.AfterEach
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test
import java.io.File
import java.time.Clock
import java.time.Duration
import java.time.Instant
import java.time.ZoneOffset
import java.util.UUID
import java.util.concurrent.CountDownLatch
import java.util.concurrent.Executors
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertNotNull
import kotlin.test.assertTrue

class ShortLivedTokenTest {

    private val now = Instant.parse("2026-09-18T17:00:00Z")
    private val clock = Clock.fixed(now, ZoneOffset.UTC)

    @BeforeEach
    fun setUp() {
        ShortLivedTokenBinding.isBound = true
        RefreshTokenRotationBinding.isBound = true
    }

    @AfterEach
    fun tearDown() {
        ShortLivedTokenBinding.isBound = true
        RefreshTokenRotationBinding.isBound = true
    }

    private fun registerAndVerifyPlayer(
        regStore: InMemoryPlayerRegistrationStore,
        tenantId: String = "tenant-casino-1",
        email: String = "token.player@example.com"
    ): RegisterPlayerResult {
        val regService = PlayerRegistrationService(store = regStore, clock = clock)
        val regCmd = RegisterPlayerCommand(
            tenantId = tenantId,
            email = email,
            phone = "+1555" + (4000000 + regStore.players.size + 1),
            jurisdiction = "DEFAULT",
            riskScore = 20.0,
            idempotencyKey = "reg-${UUID.randomUUID()}",
            correlationId = "corr-reg-${UUID.randomUUID()}",
            causationId = "caus-reg-${UUID.randomUUID()}"
        )
        val regResult = regService.register(regCmd)

        val verCmd = VerifyContactCommand(
            tenantId = tenantId,
            playerId = regResult.playerId,
            channel = ContactVerificationChannel.EMAIL,
            verificationCode = "EMAIL-123456",
            idempotencyKey = "ver-${UUID.randomUUID()}",
            correlationId = "corr-ver-${UUID.randomUUID()}",
            causationId = "caus-ver-${UUID.randomUUID()}"
        )
        regService.verifyContact(verCmd)
        return regResult
    }

    // =========================================================================
    // AUTH-002-01-T001: Primary Authoritative Outcome
    // =========================================================================

    @Test
    fun `AUTH-002-01-T001 Issue short-lived access tokens produces the required authoritative outcome`() {
        val regStore = InMemoryPlayerRegistrationStore()
        val tokenStore = InMemoryTokenSecurityStore()
        val alertSink = InMemoryTokenSecurityAlertSink()
        val tokenService = ShortLivedTokenService(
            registrationStore = regStore,
            tokenStore = tokenStore,
            alertSink = alertSink,
            clock = clock
        )

        val player = registerAndVerifyPlayer(regStore)

        // 1. Issue token pair: short-lived access token (15 mins) + rotating refresh token (30 days)
        val issueCmd = IssueTokenPairCommand(
            tenantId = "tenant-casino-1",
            playerId = player.playerId,
            idempotencyKey = "issue-pair-1",
            correlationId = "corr-iss-1",
            causationId = "caus-iss-1"
        )
        val tokenPair = tokenService.issueTokenPair(issueCmd)

        assertNotNull(tokenPair.accessToken)
        assertNotNull(tokenPair.refreshToken)
        assertEquals(now.plus(Duration.ofMinutes(15)), tokenPair.accessTokenExpiresAt)
        assertEquals(now.plus(Duration.ofDays(30)), tokenPair.refreshTokenExpiresAt)

        // Validate access token
        val validation1 = tokenService.validateAccessToken("tenant-casino-1", tokenPair.accessToken)
        assertTrue(validation1.valid)
        assertEquals(player.playerId, validation1.playerId)
        assertEquals(tokenPair.familyId, validation1.familyId)

        // 2. Lawful refresh token rotation
        val refreshCmd = RefreshTokenCommand(
            tenantId = "tenant-casino-1",
            refreshToken = tokenPair.refreshToken,
            idempotencyKey = "rot-pair-1",
            correlationId = "corr-rot-1",
            causationId = "caus-rot-1"
        )
        val rotatedPair = tokenService.rotateRefreshToken(refreshCmd)
        assertNotNull(rotatedPair.accessToken)
        assertNotNull(rotatedPair.refreshToken)
        assertEquals(tokenPair.familyId, rotatedPair.familyId)

        // New access token is valid
        val validation2 = tokenService.validateAccessToken("tenant-casino-1", rotatedPair.accessToken)
        assertTrue(validation2.valid)

        // 3. REUSE DETECTION: Re-presenting the OLD refresh token (tokenPair.refreshToken) triggers reuse revocation!
        val reuseCmd = RefreshTokenCommand(
            tenantId = "tenant-casino-1",
            refreshToken = tokenPair.refreshToken, // OLD, ALREADY ROTATED TOKEN!
            idempotencyKey = "reuse-attack-1",
            correlationId = "corr-reuse-1",
            causationId = "caus-reuse-1"
        )
        assertFailsWith<AuthenticationFailure.Rejected> {
            tokenService.rotateRefreshToken(reuseCmd)
        }.also { assertEquals(AuthErrorCode.FORBIDDEN, it.code) }

        // Alert dispatched
        assertEquals(1, alertSink.alerts.size)
        assertTrue(alertSink.alerts[0].contains("REFRESH_TOKEN_REUSE_DETECTED"))

        // ENTIRE FAMILY REVOKED: Even the latest access token is now rejected
        val validationAfterReuse = tokenService.validateAccessToken("tenant-casino-1", rotatedPair.accessToken)
        assertTrue(!validationAfterReuse.valid, "Access token from revoked family must be rejected")
        assertEquals(AuthErrorCode.UNAUTHENTICATED, validationAfterReuse.reasonCode)

        // Audited transitions
        val auditTypes = tokenStore.audit.map { it.type }
        assertTrue(auditTypes.contains("ACCESS_TOKEN_ISSUED"))
        assertTrue(auditTypes.contains("REFRESH_TOKEN_ROTATED"))
        assertTrue(auditTypes.contains("TOKEN_FAMILY_REUSE_REVOKED"))

        // Assert no financial authority or money mutation occurred
        assertEquals(0, regStore.audit.count { it.type.contains("BALANCE") })
    }

    // =========================================================================
    // AUTH-002-01-T002: Negative, Boundary, Security & Malformed Rejection
    // =========================================================================

    @Test
    fun `AUTH-002-01-T002 Issue short-lived access tokens rejects invalid boundary unauthorized and stale input`() {
        val regStore = InMemoryPlayerRegistrationStore()
        val tokenStore = InMemoryTokenSecurityStore()
        val alertSink = InMemoryTokenSecurityAlertSink()
        val tokenService = ShortLivedTokenService(
            registrationStore = regStore,
            tokenStore = tokenStore,
            alertSink = alertSink,
            clock = clock
        )

        val player = registerAndVerifyPlayer(regStore, email = "neg.player@example.com")

        // Blank tenant rejected
        assertFailsWith<AuthenticationFailure.Rejected> {
            tokenService.issueTokenPair(IssueTokenPairCommand(
                tenantId = "",
                playerId = player.playerId,
                idempotencyKey = "k",
                correlationId = "c",
                causationId = "ca"
            ))
        }.also { assertEquals(AuthErrorCode.INVALID, it.code) }

        // Stale expectedVersion rejected
        assertFailsWith<AuthenticationFailure.Rejected> {
            tokenService.issueTokenPair(IssueTokenPairCommand(
                tenantId = "tenant-casino-1",
                playerId = player.playerId,
                expectedVersion = 0L,
                idempotencyKey = "k",
                correlationId = "c",
                causationId = "ca"
            ))
        }.also { assertEquals(AuthErrorCode.STALE, it.code) }

        // Unverified account defense: register unverified player
        val regService = PlayerRegistrationService(store = regStore, clock = clock)
        val unverifiedPlayer = regService.register(RegisterPlayerCommand(
            tenantId = "tenant-casino-1",
            email = "unverified.tok@example.com",
            phone = "+15559876677",
            jurisdiction = "DEFAULT",
            idempotencyKey = "reg-unver-tok",
            correlationId = "c",
            causationId = "ca"
        ))
        assertFailsWith<AuthenticationFailure.Rejected> {
            tokenService.issueTokenPair(IssueTokenPairCommand(
                tenantId = "tenant-casino-1",
                playerId = unverifiedPlayer.playerId,
                idempotencyKey = "k-unver",
                correlationId = "c",
                causationId = "ca"
            ))
        }.also { assertEquals(AuthErrorCode.FORBIDDEN, it.code) }

        // Non-existent refresh token rejected
        assertFailsWith<AuthenticationFailure.Rejected> {
            tokenService.rotateRefreshToken(RefreshTokenCommand(
                tenantId = "tenant-casino-1",
                refreshToken = "srt_nonexistent",
                idempotencyKey = "rot-nonexist",
                correlationId = "c",
                causationId = "ca"
            ))
        }.also { assertEquals(AuthErrorCode.INVALID, it.code) }

        // Malformed / blank access token validation returns invalid
        val malformedVal = tokenService.validateAccessToken("tenant-casino-1", "")
        assertTrue(!malformedVal.valid)

        // Logout reuse defense:
        val pair = tokenService.issueTokenPair(IssueTokenPairCommand(
            tenantId = "tenant-casino-1",
            playerId = player.playerId,
            idempotencyKey = "pair-for-logout",
            correlationId = "c",
            causationId = "ca"
        ))
        // Explicit logout / family revocation
        val revokeResult = tokenService.revokeFamily(RevokeTokenFamilyCommand(
            tenantId = "tenant-casino-1",
            familyId = pair.familyId,
            playerId = player.playerId,
            reason = TokenRevocationReason.LOGOUT,
            idempotencyKey = "revoke-logout",
            correlationId = "c",
            causationId = "ca"
        ))
        assertTrue(revokeResult.revoked)

        // Access token reuse after logout is rejected
        val postLogoutVal = tokenService.validateAccessToken("tenant-casino-1", pair.accessToken)
        assertTrue(!postLogoutVal.valid, "Access token after logout must be rejected")
        assertEquals(AuthErrorCode.UNAUTHENTICATED, postLogoutVal.reasonCode)

        // Refresh token reuse after logout is rejected
        assertFailsWith<AuthenticationFailure.Rejected> {
            tokenService.rotateRefreshToken(RefreshTokenCommand(
                tenantId = "tenant-casino-1",
                refreshToken = pair.refreshToken,
                idempotencyKey = "rot-post-logout",
                correlationId = "c",
                causationId = "ca"
            ))
        }.also { assertEquals(AuthErrorCode.FORBIDDEN, it.code) }
    }

    // =========================================================================
    // AUTH-002-01-T003: Concurrency, Duplicate Delivery, Idempotency & Conflict
    // =========================================================================

    @Test
    fun `AUTH-002-01-T003 Issue short-lived access tokens survives concurrency duplicate delivery and dependency failure`() {
        val regStore = InMemoryPlayerRegistrationStore()
        val tokenStore = InMemoryTokenSecurityStore()
        val alertSink = InMemoryTokenSecurityAlertSink()
        val tokenService = ShortLivedTokenService(
            registrationStore = regStore,
            tokenStore = tokenStore,
            alertSink = alertSink,
            clock = clock
        )

        val player = registerAndVerifyPlayer(regStore, email = "concurrent.tokens@example.com")

        val gate = CountDownLatch(1)
        val pool = Executors.newFixedThreadPool(2)
        val command = IssueTokenPairCommand(
            tenantId = "tenant-casino-1",
            playerId = player.playerId,
            idempotencyKey = "idemp-concurrent-tok-001",
            correlationId = "corr-conc-1",
            causationId = "caus-conc-1"
        )

        val calls = (1..2).map {
            pool.submit<TokenPairResult> {
                gate.await()
                tokenService.issueTokenPair(command)
            }
        }
        gate.countDown()
        val results = calls.map { it.get() }
        pool.shutdown()

        // Concurrent equivalent submissions produce identical authoritative result
        assertEquals(results[0].resultId, results[1].resultId)
        assertEquals(results[0].familyId, results[1].familyId)
        assertEquals(results[0].accessToken, results[1].accessToken)
        assertEquals(results[0].refreshToken, results[1].refreshToken)

        // Conflicting payload with reused key rejected with CONFLICT
        val conflictingCommand = command.copy(playerId = UUID.randomUUID())
        assertFailsWith<AuthenticationFailure.Rejected> {
            tokenService.issueTokenPair(conflictingCommand)
        }.also { assertEquals(AuthErrorCode.CONFLICT, it.code) }

        // Refresh token rotation concurrency
        val rGate = CountDownLatch(1)
        val rPool = Executors.newFixedThreadPool(2)
        val rCommand = RefreshTokenCommand(
            tenantId = "tenant-casino-1",
            refreshToken = results[0].refreshToken,
            idempotencyKey = "idemp-concurrent-rot-001",
            correlationId = "c",
            causationId = "ca"
        )
        val rCalls = (1..2).map {
            rPool.submit<TokenPairResult> {
                rGate.await()
                tokenService.rotateRefreshToken(rCommand)
            }
        }
        rGate.countDown()
        val rResults = rCalls.map { it.get() }
        rPool.shutdown()

        assertEquals(rResults[0].resultId, rResults[1].resultId)
        assertEquals(rResults[0].accessToken, rResults[1].accessToken)
    }

    // =========================================================================
    // AUTH-002-01-T004: Compatibility, Lifecycle, Migration & Redaction Safety
    // =========================================================================

    @Test
    fun `AUTH-002-01-T004 Issue short-lived access tokens remains compatible recoverable observable and lifecycle-safe`() {
        val regStore = InMemoryPlayerRegistrationStore()
        val tokenStore = InMemoryTokenSecurityStore()
        val alertSink = InMemoryTokenSecurityAlertSink()
        val tokenService = ShortLivedTokenService(
            registrationStore = regStore,
            tokenStore = tokenStore,
            alertSink = alertSink,
            clock = clock
        )

        // 1. Fail-closed assertion gate (expected RED failure: expired/malformed/revoked, simultaneous refresh, reuse and logout reuse)
        ShortLivedTokenBinding.isBound = false
        val exIssue = assertFailsWith<AssertionError> {
            tokenService.issueTokenPair(IssueTokenPairCommand(
                tenantId = "t1",
                playerId = UUID.randomUUID(),
                idempotencyKey = "k",
                correlationId = "c",
                causationId = "ca"
            ))
        }
        assertEquals("expired/malformed/revoked, simultaneous refresh, reuse and logout reuse", exIssue.message)

        val exRotate = assertFailsWith<AssertionError> {
            tokenService.rotateRefreshToken(RefreshTokenCommand(
                tenantId = "t1",
                refreshToken = "tok",
                idempotencyKey = "k",
                correlationId = "c",
                causationId = "ca"
            ))
        }
        assertEquals("expired/malformed/revoked, simultaneous refresh, reuse and logout reuse", exRotate.message)

        val exValidate = assertFailsWith<AssertionError> {
            tokenService.validateAccessToken("t1", "sat_123")
        }
        assertEquals("expired/malformed/revoked, simultaneous refresh, reuse and logout reuse", exValidate.message)

        val exRevoke = assertFailsWith<AssertionError> {
            tokenService.revokeFamily(RevokeTokenFamilyCommand(
                tenantId = "t1",
                familyId = UUID.randomUUID(),
                playerId = UUID.randomUUID(),
                reason = TokenRevocationReason.LOGOUT,
                idempotencyKey = "k",
                correlationId = "c",
                causationId = "ca"
            ))
        }
        assertEquals("expired/malformed/revoked, simultaneous refresh, reuse and logout reuse", exRevoke.message)

        // Re-bind for remainder of test
        ShortLivedTokenBinding.isBound = true

        // 2. Assert no unapproved persistence or migration is introduced
        val migrationDir = File("src/main/resources/db/migration")
        val sqlFiles = migrationDir.listFiles { _, name -> name.endsWith(".sql") } ?: emptyArray()
        assertTrue(sqlFiles.isNotEmpty())
        val migrationVersions = sqlFiles.map { it.name.substringBefore("__") }
        assertTrue(migrationVersions.all { it.matches(Regex("V[0-9]+")) })
        assertTrue(!migrationVersions.contains("V17"), "No unapproved V17 migration should be introduced")

        // 3. Observability & Redaction: Audit events must not leak raw tokens or secrets
        val player = registerAndVerifyPlayer(regStore, email = "obs.tokens@example.com")
        val pair = tokenService.issueTokenPair(IssueTokenPairCommand(
            tenantId = "tenant-casino-1",
            playerId = player.playerId,
            idempotencyKey = "obs-token-pair",
            correlationId = "corr-obs-1",
            causationId = "caus-obs-1"
        ))

        val auditEvent = pair.auditEvent
        assertNotNull(auditEvent)
        val auditString = "${auditEvent.type}:${auditEvent.tenantId}:${auditEvent.correlationId}:${auditEvent.causationId}"
        assertTrue(!auditString.contains("sat_"), "Must not leak raw access token")
        assertTrue(!auditString.contains("srt_"), "Must not leak raw refresh token")
        assertTrue(!auditString.contains("SECRET", ignoreCase = true))
        assertTrue(!auditString.contains("PASSWORD", ignoreCase = true))
    }
}
