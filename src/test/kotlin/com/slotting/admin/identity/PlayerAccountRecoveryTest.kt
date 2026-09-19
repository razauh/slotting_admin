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

class PlayerAccountRecoveryTest {

    private val now = Instant.parse("2026-09-18T15:00:00Z")
    private val clock = Clock.fixed(now, ZoneOffset.UTC)

    @BeforeEach
    fun setUp() {
        // Controlled per-test; set to true for GREEN phase
    }

    @AfterEach
    fun tearDown() {
        PlayerAccountRecoveryBinding.isBound = true
    }

    private fun registerAndVerifyPlayer(
        regStore: InMemoryPlayerRegistrationStore,
        tenantId: String = "tenant-casino-1",
        email: String = "player.rec@example.com",
        jurisdiction: String = "DEFAULT",
        riskScore: Double = 20.0,
        rawPassword: String = "OldSecretPass123!"
    ): RegisterPlayerResult {
        val regService = PlayerRegistrationService(store = regStore, clock = clock)
        val regCmd = RegisterPlayerCommand(
            tenantId = tenantId,
            email = email,
            phone = "+1555" + (2000000 + regStore.players.size + 1),
            jurisdiction = jurisdiction,
            riskScore = riskScore,
            rawPassword = rawPassword,
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
    // AUTH-001-03-T001: Primary Authoritative Outcome
    // =========================================================================

    @Test
    fun `AUTH-001-03-T001 Implement account recovery produces the required authoritative outcome`() {
        val regStore = InMemoryPlayerRegistrationStore()
        val sessionStore = InMemoryPlayerSessionStore()
        val recoveryStore = InMemoryPlayerRecoveryStore()

        val sessionService = PlayerSessionService(
            registrationStore = regStore,
            sessionStore = sessionStore,
            clock = clock
        )
        val recoveryService = PlayerAccountRecoveryService(
            registrationStore = regStore,
            sessionStore = sessionStore,
            recoveryStore = recoveryStore,
            clock = clock
        )

        // 1. Standard player recovery (MFA not required by policy)
        val player = registerAndVerifyPlayer(
            regStore = regStore,
            email = "standard.recovery@example.com",
            rawPassword = "OldPassword123!"
        )

        // Active session established before recovery
        val loginBefore = sessionService.login(LoginPlayerCommand(
            tenantId = "tenant-casino-1",
            identifier = "standard.recovery@example.com",
            rawPassword = "OldPassword123!",
            idempotencyKey = "login-before-rec",
            correlationId = "corr-1",
            causationId = "caus-1"
        ))
        val activeSessionId = loginBefore.sessionId!!
        sessionService.validateSession("tenant-casino-1", activeSessionId)

        // Initiate recovery
        val initCmd = InitiateRecoveryCommand(
            tenantId = "tenant-casino-1",
            identifier = "standard.recovery@example.com",
            idempotencyKey = "init-rec-1",
            correlationId = "corr-init-1",
            causationId = "caus-init-1"
        )
        val initResult = recoveryService.initiateRecovery(initCmd)
        assertEquals(RecoveryStatus.DISPATCHED, initResult.status)
        assertNotNull(initResult.recoveryToken)
        assertEquals(false, initResult.mfaRequired)

        // Complete recovery with new password
        val compCmd = CompleteRecoveryCommand(
            tenantId = "tenant-casino-1",
            recoveryToken = initResult.recoveryToken!!,
            newPassword = "NewPassword123!",
            idempotencyKey = "comp-rec-1",
            correlationId = "corr-comp-1",
            causationId = "caus-comp-1"
        )
        val compResult = recoveryService.completeRecovery(compCmd)
        assertEquals(RecoveryStatus.COMPLETED, compResult.status)
        assertTrue(compResult.sessionsRevokedCount >= 1, "Must revoke active sessions upon recovery")

        // Assert old session is revoked and cannot be used
        assertFailsWith<AuthenticationFailure.Rejected> {
            sessionService.validateSession("tenant-casino-1", activeSessionId)
        }.also { assertEquals(AuthErrorCode.UNAUTHENTICATED, it.code) }

        // Assert old password fails to log in
        assertFailsWith<AuthenticationFailure.Rejected> {
            sessionService.login(LoginPlayerCommand(
                tenantId = "tenant-casino-1",
                identifier = "standard.recovery@example.com",
                rawPassword = "OldPassword123!",
                idempotencyKey = "login-old-fail",
                correlationId = "c",
                causationId = "ca"
            ))
        }.also { assertEquals(AuthErrorCode.INVALID, it.code) }

        // Assert new password successfully logs in
        val loginAfter = sessionService.login(LoginPlayerCommand(
            tenantId = "tenant-casino-1",
            identifier = "standard.recovery@example.com",
            rawPassword = "NewPassword123!",
            idempotencyKey = "login-new-success",
            correlationId = "c",
            causationId = "ca"
        ))
        assertEquals(LoginStatus.AUTHENTICATED, loginAfter.status)

        // 2. High-risk / MFA-required player recovery
        val mfaPlayer = registerAndVerifyPlayer(
            regStore = regStore,
            email = "mfa.recovery@example.com",
            jurisdiction = "NJ", // NJ requires MFA
            riskScore = 80.0,
            rawPassword = "OldMfaPassword123!"
        )

        val mfaInitResult = recoveryService.initiateRecovery(InitiateRecoveryCommand(
            tenantId = "tenant-casino-1",
            identifier = "mfa.recovery@example.com",
            idempotencyKey = "init-mfa-rec",
            correlationId = "c",
            causationId = "ca"
        ))
        assertEquals(true, mfaInitResult.mfaRequired)

        // Attempting complete recovery without MFA code fails (cannot bypass MFA during recovery!)
        assertFailsWith<AuthenticationFailure.Rejected> {
            recoveryService.completeRecovery(CompleteRecoveryCommand(
                tenantId = "tenant-casino-1",
                recoveryToken = mfaInitResult.recoveryToken!!,
                newPassword = "NewMfaPassword123!",
                mfaCode = null,
                idempotencyKey = "comp-no-mfa",
                correlationId = "c",
                causationId = "ca"
            ))
        }.also { assertEquals(AuthErrorCode.FORBIDDEN, it.code) }

        // Complete recovery with valid MFA code succeeds
        val mfaCompResult = recoveryService.completeRecovery(CompleteRecoveryCommand(
            tenantId = "tenant-casino-1",
            recoveryToken = mfaInitResult.recoveryToken!!,
            newPassword = "NewMfaPassword123!",
            mfaCode = "MFA-654321",
            idempotencyKey = "comp-valid-mfa",
            correlationId = "c",
            causationId = "ca"
        ))
        assertEquals(RecoveryStatus.COMPLETED, mfaCompResult.status)

        // Assert all transitions audited
        val auditTypes = recoveryStore.audit.map { it.type }
        assertTrue(auditTypes.contains("ACCOUNT_RECOVERY_INITIATED"))
        assertTrue(auditTypes.contains("ACCOUNT_RECOVERY_COMPLETED"))
        assertTrue(recoveryStore.outbox.any { it.type == "ACCOUNT_RECOVERY_COMPLETED" })
    }

    // =========================================================================
    // AUTH-001-03-T002: Negative, Boundary, Security & Enumeration Defense
    // =========================================================================

    @Test
    fun `AUTH-001-03-T002 Implement account recovery rejects invalid boundary unauthorized and stale input`() {
        val regStore = InMemoryPlayerRegistrationStore()
        val sessionStore = InMemoryPlayerSessionStore()
        val recoveryStore = InMemoryPlayerRecoveryStore()

        val recoveryService = PlayerAccountRecoveryService(
            registrationStore = regStore,
            sessionStore = sessionStore,
            recoveryStore = recoveryStore,
            clock = clock
        )

        val player = registerAndVerifyPlayer(
            regStore = regStore,
            email = "existing.player@example.com"
        )

        // Blank tenant rejected
        assertFailsWith<AuthenticationFailure.Rejected> {
            recoveryService.initiateRecovery(InitiateRecoveryCommand(
                tenantId = "",
                identifier = "existing.player@example.com",
                idempotencyKey = "k",
                correlationId = "c",
                causationId = "ca"
            ))
        }.also { assertEquals(AuthErrorCode.INVALID, it.code) }

        // Stale version rejected
        assertFailsWith<AuthenticationFailure.Rejected> {
            recoveryService.initiateRecovery(InitiateRecoveryCommand(
                tenantId = "tenant-casino-1",
                identifier = "existing.player@example.com",
                expectedVersion = 0L,
                idempotencyKey = "k",
                correlationId = "c",
                causationId = "ca"
            ))
        }.also { assertEquals(AuthErrorCode.STALE, it.code) }

        // Enumeration defense on non-existent player: returns safe DISPATCHED response without leaking presence
        val nonExistentResult = recoveryService.initiateRecovery(InitiateRecoveryCommand(
            tenantId = "tenant-casino-1",
            identifier = "doesnotexist@example.com",
            idempotencyKey = "init-nonexist",
            correlationId = "c",
            causationId = "ca"
        ))
        assertEquals(RecoveryStatus.DISPATCHED, nonExistentResult.status)
        assertNull(nonExistentResult.recoveryToken, "Non-existent account must not receive a recovery token")

        // Unverified account defense: register an unverified player
        val regService = PlayerRegistrationService(store = regStore, clock = clock)
        regService.register(RegisterPlayerCommand(
            tenantId = "tenant-casino-1",
            email = "unverified.rec@example.com",
            phone = "+15559871122",
            jurisdiction = "DEFAULT",
            idempotencyKey = "reg-unver",
            correlationId = "c",
            causationId = "ca"
        ))
        // Attempting recovery for unverified account does NOT issue recovery token
        val unverifiedRecResult = recoveryService.initiateRecovery(InitiateRecoveryCommand(
            tenantId = "tenant-casino-1",
            identifier = "unverified.rec@example.com",
            idempotencyKey = "init-unver-rec",
            correlationId = "c",
            causationId = "ca"
        ))
        assertEquals(RecoveryStatus.DISPATCHED, unverifiedRecResult.status)
        assertNull(unverifiedRecResult.recoveryToken, "Unverified account cannot bypass verification via recovery")

        // Complete recovery negative checks:
        // Invalid token rejected
        assertFailsWith<AuthenticationFailure.Rejected> {
            recoveryService.completeRecovery(CompleteRecoveryCommand(
                tenantId = "tenant-casino-1",
                recoveryToken = "INVALID-TOKEN",
                newPassword = "Pass123!New",
                idempotencyKey = "comp-invalid-tok",
                correlationId = "c",
                causationId = "ca"
            ))
        }.also { assertEquals(AuthErrorCode.INVALID, it.code) }

        // Initiate valid token
        val validInit = recoveryService.initiateRecovery(InitiateRecoveryCommand(
            tenantId = "tenant-casino-1",
            identifier = "existing.player@example.com",
            idempotencyKey = "init-valid-neg",
            correlationId = "c",
            causationId = "ca"
        ))
        val token = validInit.recoveryToken!!

        // Consuming token once succeeds
        recoveryService.completeRecovery(CompleteRecoveryCommand(
            tenantId = "tenant-casino-1",
            recoveryToken = token,
            newPassword = "BrandNewPass123!",
            idempotencyKey = "comp-success-once",
            correlationId = "c",
            causationId = "ca"
        ))

        // Reusing consumed token rejected
        assertFailsWith<AuthenticationFailure.Rejected> {
            recoveryService.completeRecovery(CompleteRecoveryCommand(
                tenantId = "tenant-casino-1",
                recoveryToken = token,
                newPassword = "AnotherNewPass123!",
                idempotencyKey = "comp-reuse-tok",
                correlationId = "c",
                causationId = "ca"
            ))
        }.also { assertEquals(AuthErrorCode.INVALID, it.code) }
    }

    // =========================================================================
    // AUTH-001-03-T003: Concurrency, Duplicate Delivery, Idempotency & Conflict
    // =========================================================================

    @Test
    fun `AUTH-001-03-T003 Implement account recovery survives concurrency duplicate delivery and dependency failure`() {
        val regStore = InMemoryPlayerRegistrationStore()
        val sessionStore = InMemoryPlayerSessionStore()
        val recoveryStore = InMemoryPlayerRecoveryStore()

        val recoveryService = PlayerAccountRecoveryService(
            registrationStore = regStore,
            sessionStore = sessionStore,
            recoveryStore = recoveryStore,
            clock = clock
        )

        registerAndVerifyPlayer(
            regStore = regStore,
            email = "concurrent.recovery@example.com"
        )

        val gate = CountDownLatch(1)
        val pool = Executors.newFixedThreadPool(2)
        val command = InitiateRecoveryCommand(
            tenantId = "tenant-casino-1",
            identifier = "concurrent.recovery@example.com",
            idempotencyKey = "idemp-concurrent-rec-001",
            correlationId = "corr-conc-1",
            causationId = "caus-conc-1"
        )

        val calls = (1..2).map {
            pool.submit<InitiateRecoveryResult> {
                gate.await()
                recoveryService.initiateRecovery(command)
            }
        }
        gate.countDown()
        val results = calls.map { it.get() }
        pool.shutdown()

        // Concurrent equivalent submissions produce identical authoritative result
        assertEquals(results[0].resultId, results[1].resultId)
        assertEquals(results[0].recoveryToken, results[1].recoveryToken)

        // Conflicting payload with reused key rejected with CONFLICT
        val conflictingCommand = command.copy(identifier = "different.player@example.com")
        assertFailsWith<AuthenticationFailure.Rejected> {
            recoveryService.initiateRecovery(conflictingCommand)
        }.also { assertEquals(AuthErrorCode.CONFLICT, it.code) }

        // Concurrency on complete recovery
        val compCmd = CompleteRecoveryCommand(
            tenantId = "tenant-casino-1",
            recoveryToken = results[0].recoveryToken!!,
            newPassword = "ConcurrentResetPass123!",
            idempotencyKey = "idemp-concurrent-comp-001",
            correlationId = "c",
            causationId = "ca"
        )
        val cGate = CountDownLatch(1)
        val cPool = Executors.newFixedThreadPool(2)
        val cCalls = (1..2).map {
            cPool.submit<CompleteRecoveryResult> {
                cGate.await()
                recoveryService.completeRecovery(compCmd)
            }
        }
        cGate.countDown()
        val cResults = cCalls.map { it.get() }
        cPool.shutdown()

        assertEquals(cResults[0].resultId, cResults[1].resultId)
        assertEquals(RecoveryStatus.COMPLETED, cResults[0].status)
    }

    // =========================================================================
    // AUTH-001-03-T004: Compatibility, Lifecycle, Migration & Redaction Safety
    // =========================================================================

    @Test
    fun `AUTH-001-03-T004 Implement account recovery remains compatible recoverable observable and lifecycle-safe`() {
        val regStore = InMemoryPlayerRegistrationStore()
        val sessionStore = InMemoryPlayerSessionStore()
        val recoveryStore = InMemoryPlayerRecoveryStore()

        val recoveryService = PlayerAccountRecoveryService(
            registrationStore = regStore,
            sessionStore = sessionStore,
            recoveryStore = recoveryStore,
            clock = clock
        )

        // 1. Fail-closed assertion gate (expected RED failure: unverified/recovery bypass)
        PlayerAccountRecoveryBinding.isBound = false
        val exInit = assertFailsWith<AssertionError> {
            recoveryService.initiateRecovery(InitiateRecoveryCommand(
                tenantId = "t1",
                identifier = "user@example.com",
                idempotencyKey = "k",
                correlationId = "c",
                causationId = "ca"
            ))
        }
        assertEquals("unverified/recovery bypass", exInit.message)

        val exComp = assertFailsWith<AssertionError> {
            recoveryService.completeRecovery(CompleteRecoveryCommand(
                tenantId = "t1",
                recoveryToken = "tok",
                newPassword = "pass",
                idempotencyKey = "k",
                correlationId = "c",
                causationId = "ca"
            ))
        }
        assertEquals("unverified/recovery bypass", exComp.message)

        // Re-bind for remainder of test
        PlayerAccountRecoveryBinding.isBound = true

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
            email = "audit.recovery@example.com"
        )
        val initResult = recoveryService.initiateRecovery(InitiateRecoveryCommand(
            tenantId = "tenant-casino-1",
            identifier = "audit.recovery@example.com",
            idempotencyKey = "obs-rec-init",
            correlationId = "corr-obs-1",
            causationId = "caus-obs-1"
        ))

        val auditEvent = initResult.auditEvent
        assertNotNull(auditEvent)
        val auditString = "${auditEvent.type}:${auditEvent.tenantId}:${auditEvent.correlationId}:${auditEvent.causationId}"
        assertTrue(!auditString.contains("SECRET", ignoreCase = true))
        assertTrue(!auditString.contains("PASSWORD", ignoreCase = true))
        assertTrue(!auditString.contains("REC-", ignoreCase = false), "Must not leak raw recovery token")
    }
}
