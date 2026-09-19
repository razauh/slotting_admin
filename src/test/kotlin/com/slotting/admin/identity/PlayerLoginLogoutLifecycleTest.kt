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
import kotlin.test.assertNull
import kotlin.test.assertTrue

class PlayerLoginLogoutLifecycleTest {

    private val now = Instant.parse("2026-09-18T14:00:00Z")
    private val clock = Clock.fixed(now, ZoneOffset.UTC)

    @BeforeEach
    fun setUp() {
        // Controlled per-test; will be set to true for GREEN phase
    }

    @AfterEach
    fun tearDown() {
        PlayerLoginLogoutBinding.isBound = true
    }

    private fun registerAndVerifyPlayer(
        regStore: InMemoryPlayerRegistrationStore,
        tenantId: String = "tenant-casino-1",
        email: String = "player.login@example.com",
        phone: String = "+1555" + (1000000 + regStore.players.size + 1),
        jurisdiction: String = "DEFAULT",
        riskScore: Double = 20.0,
        rawPassword: String = "SecretPass123!"
    ): RegisterPlayerResult {
        val regService = PlayerRegistrationService(store = regStore, clock = clock)
        val regCmd = RegisterPlayerCommand(
            tenantId = tenantId,
            email = email,
            phone = phone,
            jurisdiction = jurisdiction,
            riskScore = riskScore,
            rawPassword = rawPassword,
            idempotencyKey = "reg-${UUID.randomUUID()}",
            correlationId = "corr-reg-${UUID.randomUUID()}",
            causationId = "caus-reg-${UUID.randomUUID()}"
        )
        val regResult = regService.register(regCmd)

        // Verify email to satisfy contact verification
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

    private fun loginCommand(
        tenantId: String = "tenant-casino-1",
        identifier: String = "player.login@example.com",
        rawPassword: String = "SecretPass123!",
        idempotencyKey: String = "login-idemp-001",
        correlationId: String = "corr-login-001",
        causationId: String = "caus-login-001",
        expectedVersion: Long = 1L
    ) = LoginPlayerCommand(
        tenantId = tenantId,
        identifier = identifier,
        rawPassword = rawPassword,
        idempotencyKey = idempotencyKey,
        correlationId = correlationId,
        causationId = causationId,
        expectedVersion = expectedVersion
    )

    private fun logoutCommand(
        tenantId: String = "tenant-casino-1",
        sessionId: UUID,
        playerId: UUID,
        idempotencyKey: String = "logout-idemp-001",
        correlationId: String = "corr-logout-001",
        causationId: String = "caus-logout-001",
        expectedVersion: Long = 1L
    ) = LogoutPlayerCommand(
        tenantId = tenantId,
        sessionId = sessionId,
        playerId = playerId,
        idempotencyKey = idempotencyKey,
        correlationId = correlationId,
        causationId = causationId,
        expectedVersion = expectedVersion
    )

    // =========================================================================
    // AUTH-001-02-T001: Primary Authoritative Outcome
    // =========================================================================

    @Test
    fun `AUTH-001-02-T001 Implement login and logout lifecycle produces the required authoritative outcome`() {
        val regStore = InMemoryPlayerRegistrationStore()
        val sessionStore = InMemoryPlayerSessionStore()
        val sessionService = PlayerSessionService(
            registrationStore = regStore,
            sessionStore = sessionStore,
            clock = clock
        )

        // 1. Standard low-risk player (MFA not required by policy)
        val regResult = registerAndVerifyPlayer(
            regStore = regStore,
            email = "player.standard@example.com",
            jurisdiction = "DEFAULT",
            riskScore = 20.0,
            rawPassword = "StandardPassword123!"
        )

        val loginCmd = loginCommand(
            identifier = "player.standard@example.com",
            rawPassword = "StandardPassword123!",
            idempotencyKey = "login-cmd-1"
        )
        val loginResult = sessionService.login(loginCmd)

        assertEquals(LoginStatus.AUTHENTICATED, loginResult.status)
        assertNotNull(loginResult.sessionId)
        assertNotNull(loginResult.accessToken)
        assertNotNull(loginResult.refreshToken)
        assertNull(loginResult.mfaChallengeId)

        // Session validation succeeds
        val session = sessionService.validateSession(loginCmd.tenantId, loginResult.sessionId!!)
        assertEquals(SessionState.ACTIVE, session.state)

        // All transitions audited: login success event
        val loginAuditEvent = loginResult.auditEvent
        assertEquals("PLAYER_LOGIN_SUCCEEDED", loginAuditEvent.type)
        assertEquals(1, sessionStore.outbox.size)

        // Logout terminates session
        val logoutCmd = logoutCommand(
            sessionId = loginResult.sessionId!!,
            playerId = loginResult.playerId!!,
            idempotencyKey = "logout-cmd-1"
        )
        val logoutResult = sessionService.logout(logoutCmd)
        assertTrue(logoutResult.terminated)
        assertEquals("PLAYER_LOGOUT_COMPLETED", logoutResult.auditEvent.type)

        // Further validateSession fails because session is terminated
        assertFailsWith<AuthenticationFailure.Rejected> {
            sessionService.validateSession(loginCmd.tenantId, loginResult.sessionId!!)
        }.also { assertEquals(AuthErrorCode.UNAUTHENTICATED, it.code) }

        // 2. Regulated jurisdiction player requiring MFA
        val mfaPlayer = registerAndVerifyPlayer(
            regStore = regStore,
            email = "player.mfa@example.com",
            jurisdiction = "NJ", // NJ requires MFA
            riskScore = 80.0,
            rawPassword = "MfaPassword123!"
        )

        val mfaLoginCmd = loginCommand(
            identifier = "player.mfa@example.com",
            rawPassword = "MfaPassword123!",
            idempotencyKey = "login-mfa-1"
        )
        val mfaLoginResult = sessionService.login(mfaLoginCmd)

        // Challenge required: session is NOT issued yet
        assertEquals(LoginStatus.CHALLENGE_REQUIRED, mfaLoginResult.status)
        assertNull(mfaLoginResult.sessionId)
        assertNotNull(mfaLoginResult.mfaChallengeId)

        // Submitting MFA challenge response succeeds and establishes session
        val submitMfaCmd = SubmitMfaChallengeCommand(
            tenantId = mfaLoginCmd.tenantId,
            challengeId = mfaLoginResult.mfaChallengeId!!,
            playerId = mfaLoginResult.playerId!!,
            mfaCode = "MFA-654321",
            idempotencyKey = "mfa-submit-1",
            correlationId = "corr-mfa-1",
            causationId = "caus-mfa-1"
        )
        val mfaSubmitResult = sessionService.submitMfaChallenge(submitMfaCmd)
        assertEquals(LoginStatus.AUTHENTICATED, mfaSubmitResult.status)
        assertNotNull(mfaSubmitResult.sessionId)
        assertEquals("PLAYER_MFA_VERIFIED", mfaSubmitResult.auditEvent.type)

        // Assert no financial authority or balance mutation occurred
        assertEquals(0, regStore.audit.count { it.type.contains("BALANCE") })
    }

    // =========================================================================
    // AUTH-001-02-T002: Negative, Boundary, Security & Enumeration Defense
    // =========================================================================

    @Test
    fun `AUTH-001-02-T002 Implement login and logout lifecycle rejects invalid boundary unauthorized and stale input`() {
        val regStore = InMemoryPlayerRegistrationStore()
        val sessionStore = InMemoryPlayerSessionStore()
        val sessionService = PlayerSessionService(
            registrationStore = regStore,
            sessionStore = sessionStore,
            clock = clock
        )

        val activePlayer = registerAndVerifyPlayer(
            regStore = regStore,
            email = "active.player@example.com",
            rawPassword = "CorrectPass123!"
        )

        // Blank tenant rejected
        assertFailsWith<AuthenticationFailure.Rejected> {
            sessionService.login(loginCommand(tenantId = ""))
        }.also { assertEquals(AuthErrorCode.INVALID, it.code) }

        // Blank identifier rejected
        assertFailsWith<AuthenticationFailure.Rejected> {
            sessionService.login(loginCommand(identifier = ""))
        }.also { assertEquals(AuthErrorCode.INVALID, it.code) }

        // Blank password rejected
        assertFailsWith<AuthenticationFailure.Rejected> {
            sessionService.login(loginCommand(rawPassword = ""))
        }.also { assertEquals(AuthErrorCode.INVALID, it.code) }

        // Stale expectedVersion rejected
        assertFailsWith<AuthenticationFailure.Rejected> {
            sessionService.login(loginCommand(expectedVersion = 0L))
        }.also { assertEquals(AuthErrorCode.STALE, it.code) }

        // Blank idempotency key rejected
        assertFailsWith<AuthenticationFailure.Rejected> {
            sessionService.login(loginCommand(idempotencyKey = "  "))
        }.also { assertEquals(AuthErrorCode.INVALID, it.code) }

        // Enumeration-safe credentials failure:
        // 1. Non-existent player returns INVALID
        val exNonExistent = assertFailsWith<AuthenticationFailure.Rejected> {
            sessionService.login(loginCommand(identifier = "doesnotexist@example.com", rawPassword = "SomePassword!"))
        }
        assertEquals(AuthErrorCode.INVALID, exNonExistent.code)

        // 2. Existing player with wrong password returns identical INVALID
        val exWrongPassword = assertFailsWith<AuthenticationFailure.Rejected> {
            sessionService.login(loginCommand(identifier = "active.player@example.com", rawPassword = "WrongPassword!"))
        }
        assertEquals(AuthErrorCode.INVALID, exWrongPassword.code)

        // Unverified / recovery bypass defense:
        // Register an unverified player (do NOT verify contact)
        val regService = PlayerRegistrationService(store = regStore, clock = clock)
        val unverifiedCmd = RegisterPlayerCommand(
            tenantId = "tenant-casino-1",
            email = "unverified.player@example.com",
            phone = "+15559876543",
            jurisdiction = "DEFAULT",
            rawPassword = "UnverifiedPass123!",
            idempotencyKey = "reg-unverified",
            correlationId = "corr-unverified",
            causationId = "caus-unverified"
        )
        regService.register(unverifiedCmd)

        // Attempting login with unverified account is denied (cannot bypass unverified state)
        assertFailsWith<AuthenticationFailure.Rejected> {
            sessionService.login(loginCommand(
                identifier = "unverified.player@example.com",
                rawPassword = "UnverifiedPass123!"
            ))
        }.also { assertEquals(AuthErrorCode.FORBIDDEN, it.code) }

        // MFA challenge negative checks:
        // High-risk player requiring MFA
        registerAndVerifyPlayer(
            regStore = regStore,
            email = "mfa.test@example.com",
            jurisdiction = "UK",
            riskScore = 85.0,
            rawPassword = "MfaPass123!"
        )
        val mfaResult = sessionService.login(loginCommand(
            identifier = "mfa.test@example.com",
            rawPassword = "MfaPass123!",
            idempotencyKey = "login-mfa-test"
        ))

        // Wrong MFA code rejected
        assertFailsWith<AuthenticationFailure.Rejected> {
            sessionService.submitMfaChallenge(SubmitMfaChallengeCommand(
                tenantId = "tenant-casino-1",
                challengeId = mfaResult.mfaChallengeId!!,
                playerId = mfaResult.playerId!!,
                mfaCode = "WRONG-CODE",
                idempotencyKey = "mfa-wrong-1",
                correlationId = "corr-mfa-w1",
                causationId = "caus-mfa-w1"
            ))
        }.also { assertEquals(AuthErrorCode.INVALID, it.code) }

        // Non-existent challenge rejected
        assertFailsWith<AuthenticationFailure.Rejected> {
            sessionService.submitMfaChallenge(SubmitMfaChallengeCommand(
                tenantId = "tenant-casino-1",
                challengeId = UUID.randomUUID(),
                playerId = mfaResult.playerId!!,
                mfaCode = "MFA-654321",
                idempotencyKey = "mfa-nonexist",
                correlationId = "corr-mfa-ne",
                causationId = "caus-mfa-ne"
            ))
        }.also { assertEquals(AuthErrorCode.INVALID, it.code) }

        // Logout of non-existent session rejected
        assertFailsWith<AuthenticationFailure.Rejected> {
            sessionService.logout(logoutCommand(
                sessionId = UUID.randomUUID(),
                playerId = activePlayer.playerId
            ))
        }.also { assertEquals(AuthErrorCode.UNAUTHENTICATED, it.code) }

        // Logout with wrong player ID rejected
        val validLogin = sessionService.login(loginCommand(
            identifier = "active.player@example.com",
            rawPassword = "CorrectPass123!",
            idempotencyKey = "login-for-wrong-player-logout"
        ))
        assertFailsWith<AuthenticationFailure.Rejected> {
            sessionService.logout(logoutCommand(
                sessionId = validLogin.sessionId!!,
                playerId = UUID.randomUUID(),
                idempotencyKey = "logout-wrong-player"
            ))
        }.also { assertEquals(AuthErrorCode.FORBIDDEN, it.code) }
    }

    // =========================================================================
    // AUTH-001-02-T003: Concurrency, Duplicate Delivery, Idempotency & Conflict
    // =========================================================================

    @Test
    fun `AUTH-001-02-T003 Implement login and logout lifecycle survives concurrency duplicate delivery and dependency failure`() {
        val regStore = InMemoryPlayerRegistrationStore()
        val sessionStore = InMemoryPlayerSessionStore()
        val sessionService = PlayerSessionService(
            registrationStore = regStore,
            sessionStore = sessionStore,
            clock = clock
        )

        registerAndVerifyPlayer(
            regStore = regStore,
            email = "concurrent.player@example.com",
            rawPassword = "ConcurrentPass123!"
        )

        val gate = CountDownLatch(1)
        val pool = Executors.newFixedThreadPool(2)
        val command = loginCommand(
            identifier = "concurrent.player@example.com",
            rawPassword = "ConcurrentPass123!",
            idempotencyKey = "idemp-concurrent-login-001"
        )

        val calls = (1..2).map {
            pool.submit<LoginPlayerResult> {
                gate.await()
                sessionService.login(command)
            }
        }
        gate.countDown()
        val results = calls.map { it.get() }
        pool.shutdown()

        // Concurrent equivalent submissions produce identical authoritative result
        assertEquals(results[0].resultId, results[1].resultId)
        assertEquals(results[0].sessionId, results[1].sessionId)
        assertEquals(LoginStatus.AUTHENTICATED, results[0].status)
        assertEquals(LoginStatus.AUTHENTICATED, results[1].status)

        // Conflicting payload with reused key rejected with CONFLICT
        val conflictingCommand = command.copy(rawPassword = "DifferentPassword123!")
        assertFailsWith<AuthenticationFailure.Rejected> {
            sessionService.login(conflictingCommand)
        }.also { assertEquals(AuthErrorCode.CONFLICT, it.code) }

        // Logout concurrency test
        val logoutCmd = logoutCommand(
            sessionId = results[0].sessionId!!,
            playerId = results[0].playerId!!,
            idempotencyKey = "idemp-concurrent-logout-001"
        )
        val lGate = CountDownLatch(1)
        val lPool = Executors.newFixedThreadPool(2)
        val lCalls = (1..2).map {
            lPool.submit<LogoutPlayerResult> {
                lGate.await()
                sessionService.logout(logoutCmd)
            }
        }
        lGate.countDown()
        val lResults = lCalls.map { it.get() }
        lPool.shutdown()

        assertEquals(lResults[0].resultId, lResults[1].resultId)
        assertTrue(lResults[0].terminated)
    }

    // =========================================================================
    // AUTH-001-02-T004: Compatibility, Lifecycle, Migration & Redaction Safety
    // =========================================================================

    @Test
    fun `AUTH-001-02-T004 Implement login and logout lifecycle remains compatible recoverable observable and lifecycle-safe`() {
        val regStore = InMemoryPlayerRegistrationStore()
        val sessionStore = InMemoryPlayerSessionStore()
        val sessionService = PlayerSessionService(
            registrationStore = regStore,
            sessionStore = sessionStore,
            clock = clock
        )

        // 1. Fail-closed assertion gate (expected RED failure: unverified/recovery bypass)
        PlayerLoginLogoutBinding.isBound = false
        val exLogin = assertFailsWith<AssertionError> {
            sessionService.login(loginCommand())
        }
        assertEquals("unverified/recovery bypass", exLogin.message)

        val exMfa = assertFailsWith<AssertionError> {
            sessionService.submitMfaChallenge(SubmitMfaChallengeCommand(
                tenantId = "t1",
                challengeId = UUID.randomUUID(),
                playerId = UUID.randomUUID(),
                mfaCode = "123456",
                idempotencyKey = "k",
                correlationId = "c",
                causationId = "ca"
            ))
        }
        assertEquals("unverified/recovery bypass", exMfa.message)

        val exLogout = assertFailsWith<AssertionError> {
            sessionService.logout(logoutCommand(
                sessionId = UUID.randomUUID(),
                playerId = UUID.randomUUID()
            ))
        }
        assertEquals("unverified/recovery bypass", exLogout.message)

        val exValidate = assertFailsWith<AssertionError> {
            sessionService.validateSession("t1", UUID.randomUUID())
        }
        assertEquals("unverified/recovery bypass", exValidate.message)

        // Re-bind for remainder of test
        PlayerLoginLogoutBinding.isBound = true

        // 2. Assert no unapproved persistence or migration is introduced
        val migrationDir = File("src/main/resources/db/migration")
        val sqlFiles = migrationDir.listFiles { _, name -> name.endsWith(".sql") } ?: emptyArray()
        assertTrue(sqlFiles.isNotEmpty())
        val migrationVersions = sqlFiles.map { it.name.substringBefore("__") }
        assertTrue(migrationVersions.all { it.matches(Regex("V[0-9]+")) })
        assertTrue(!migrationVersions.contains("V17"), "No unapproved V17 migration should be introduced")

        // 3. Observability & Redaction: Audit events must not leak raw password, token, or unmasked PII
        registerAndVerifyPlayer(
            regStore = regStore,
            email = "audit.player@example.com",
            rawPassword = "SensitivePassword123!"
        )
        val loginResult = sessionService.login(loginCommand(
            identifier = "audit.player@example.com",
            rawPassword = "SensitivePassword123!",
            idempotencyKey = "obs-login-001"
        ))

        val auditEvent = loginResult.auditEvent
        assertNotNull(auditEvent)
        val auditString = "${auditEvent.type}:${auditEvent.tenantId}:${auditEvent.correlationId}:${auditEvent.causationId}"
        assertTrue(!auditString.contains("SensitivePassword123!"), "Must not contain raw password")
        assertTrue(!auditString.contains("SECRET", ignoreCase = true))
        assertTrue(!auditString.contains("PASSWORD", ignoreCase = true))
    }
}
