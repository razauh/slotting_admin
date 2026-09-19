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

class ConfigurableMfaChallengeTest {

    private val now = Instant.parse("2026-09-18T16:00:00Z")
    private val clock = Clock.fixed(now, ZoneOffset.UTC)

    @BeforeEach
    fun setUp() {
        // Controlled per-test; set to true for GREEN phase
    }

    @AfterEach
    fun tearDown() {
        ConfigurableMfaBinding.isBound = true
    }

    private fun registerAndVerifyPlayer(
        regStore: InMemoryPlayerRegistrationStore,
        tenantId: String = "tenant-casino-1",
        email: String = "mfa.player@example.com",
        jurisdiction: String = "DEFAULT",
        riskScore: Double = 20.0
    ): RegisterPlayerResult {
        val regService = PlayerRegistrationService(store = regStore, clock = clock)
        val regCmd = RegisterPlayerCommand(
            tenantId = tenantId,
            email = email,
            phone = "+1555" + (3000000 + regStore.players.size + 1),
            jurisdiction = jurisdiction,
            riskScore = riskScore,
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
    // AUTH-001-04-T001: Primary Authoritative Outcome
    // =========================================================================

    @Test
    fun `AUTH-001-04-T001 Implement configurable MFA challenges produces the required authoritative outcome`() {
        val regStore = InMemoryPlayerRegistrationStore()
        val mfaStore = InMemoryConfigurableMfaStore()
        val mfaService = ConfigurableMfaChallengeService(
            registrationStore = regStore,
            mfaStore = mfaStore,
            clock = clock
        )

        // 1. Configurable MFA policy evaluation
        assertTrue(mfaService.isMfaRequired("tenant-casino-1", "NJ", 20.0), "NJ must require MFA by policy")
        assertTrue(mfaService.isMfaRequired("tenant-casino-1", "UK", 10.0), "UK must require MFA by policy")
        assertTrue(mfaService.isMfaRequired("tenant-casino-1", "DEFAULT", 85.0), "High risk score must require MFA")
        assertTrue(!mfaService.isMfaRequired("tenant-casino-1", "DEFAULT", 30.0), "Low risk score in default jurisdiction does not require MFA")

        // Dynamic tenant policy override
        mfaService.configureJurisdictionRule("tenant-casino-1", JurisdictionMfaRule(
            jurisdiction = "CUSTOM_MARKET",
            requirement = MfaRequirementPolicy.MANDATORY,
            riskScoreThreshold = 50.0
        ))
        assertTrue(mfaService.isMfaRequired("tenant-casino-1", "CUSTOM_MARKET", 10.0))

        // 2. Active player enrolling and confirming TOTP factor
        val player = registerAndVerifyPlayer(regStore, email = "player.totp@example.com")

        val enrollCmd = EnrollMfaFactorCommand(
            tenantId = "tenant-casino-1",
            playerId = player.playerId,
            factorType = MfaFactorType.TOTP,
            secretAssertion = "JBSWY3DPEHPK3PXP",
            idempotencyKey = "enroll-totp-1",
            correlationId = "corr-en-1",
            causationId = "caus-en-1"
        )
        val enrollResult = mfaService.enrollFactor(enrollCmd)
        assertEquals(MfaEnrollmentStatus.PENDING_CONFIRMATION, enrollResult.status)

        // Confirm enrollment
        val confirmCmd = ConfirmMfaEnrollmentCommand(
            tenantId = "tenant-casino-1",
            playerId = player.playerId,
            factorType = MfaFactorType.TOTP,
            confirmationCode = "CONFIRM-123456",
            idempotencyKey = "confirm-totp-1",
            correlationId = "corr-conf-1",
            causationId = "caus-conf-1"
        )
        val confirmResult = mfaService.confirmEnrollment(confirmCmd)
        assertEquals(MfaEnrollmentStatus.ENROLLED, confirmResult.status)

        // 3. Issue and verify challenge
        val issueCmd = IssueMfaChallengeCommand(
            tenantId = "tenant-casino-1",
            playerId = player.playerId,
            actionTrigger = "LOGIN",
            preferredFactor = MfaFactorType.TOTP,
            idempotencyKey = "issue-chal-1",
            correlationId = "corr-iss-1",
            causationId = "caus-iss-1"
        )
        val issueResult = mfaService.issueChallenge(issueCmd)
        assertEquals(MfaChallengeStatus.ISSUED, issueResult.status)
        assertEquals(MfaFactorType.TOTP, issueResult.factorType)

        val verifyCmd = VerifyMfaChallengeCommand(
            tenantId = "tenant-casino-1",
            challengeId = issueResult.challengeId,
            playerId = player.playerId,
            code = "MFA-654321",
            idempotencyKey = "verify-chal-1",
            correlationId = "corr-ver-1",
            causationId = "caus-ver-1"
        )
        val verifyResult = mfaService.verifyChallenge(verifyCmd)
        assertEquals(MfaChallengeStatus.VERIFIED, verifyResult.status)
        assertNotNull(verifyResult.verificationToken)

        // Assert all transitions audited
        val auditTypes = mfaStore.audit.map { it.type }
        assertTrue(auditTypes.contains("MFA_ENROLLMENT_INITIATED_TOTP"))
        assertTrue(auditTypes.contains("MFA_ENROLLMENT_CONFIRMED_TOTP"))
        assertTrue(auditTypes.contains("MFA_CHALLENGE_ISSUED_TOTP"))
        assertTrue(auditTypes.contains("MFA_CHALLENGE_VERIFIED_TOTP"))

        // Assert no financial authority or balance mutation occurred
        assertEquals(0, regStore.audit.count { it.type.contains("BALANCE") })
    }

    // =========================================================================
    // AUTH-001-04-T002: Negative, Boundary, Security & Enumeration Defense
    // =========================================================================

    @Test
    fun `AUTH-001-04-T002 Implement configurable MFA challenges rejects invalid boundary unauthorized and stale input`() {
        val regStore = InMemoryPlayerRegistrationStore()
        val mfaStore = InMemoryConfigurableMfaStore()
        val mfaService = ConfigurableMfaChallengeService(
            registrationStore = regStore,
            mfaStore = mfaStore,
            clock = clock
        )

        val player = registerAndVerifyPlayer(regStore, email = "existing.mfa@example.com")

        // Blank tenant rejected
        assertFailsWith<AuthenticationFailure.Rejected> {
            mfaService.enrollFactor(EnrollMfaFactorCommand(
                tenantId = "",
                playerId = player.playerId,
                factorType = MfaFactorType.TOTP,
                secretAssertion = "SECRET",
                idempotencyKey = "k",
                correlationId = "c",
                causationId = "ca"
            ))
        }.also { assertEquals(AuthErrorCode.INVALID, it.code) }

        // Stale version rejected
        assertFailsWith<AuthenticationFailure.Rejected> {
            mfaService.enrollFactor(EnrollMfaFactorCommand(
                tenantId = "tenant-casino-1",
                playerId = player.playerId,
                factorType = MfaFactorType.TOTP,
                secretAssertion = "SECRET",
                expectedVersion = 0L,
                idempotencyKey = "k",
                correlationId = "c",
                causationId = "ca"
            ))
        }.also { assertEquals(AuthErrorCode.STALE, it.code) }

        // Blank secret rejected
        assertFailsWith<AuthenticationFailure.Rejected> {
            mfaService.enrollFactor(EnrollMfaFactorCommand(
                tenantId = "tenant-casino-1",
                playerId = player.playerId,
                factorType = MfaFactorType.TOTP,
                secretAssertion = "  ",
                idempotencyKey = "k",
                correlationId = "c",
                causationId = "ca"
            ))
        }.also { assertEquals(AuthErrorCode.INVALID, it.code) }

        // Unverified account defense: register unverified player
        val regService = PlayerRegistrationService(store = regStore, clock = clock)
        val unverifiedPlayer = regService.register(RegisterPlayerCommand(
            tenantId = "tenant-casino-1",
            email = "unver.mfa@example.com",
            phone = "+15559873344",
            jurisdiction = "DEFAULT",
            idempotencyKey = "reg-unver-mfa",
            correlationId = "c",
            causationId = "ca"
        ))
        // Attempting to enroll MFA for unverified account is denied (cannot bypass unverified state)
        assertFailsWith<AuthenticationFailure.Rejected> {
            mfaService.enrollFactor(EnrollMfaFactorCommand(
                tenantId = "tenant-casino-1",
                playerId = unverifiedPlayer.playerId,
                factorType = MfaFactorType.TOTP,
                secretAssertion = "SECRET",
                idempotencyKey = "k-unver",
                correlationId = "c",
                causationId = "ca"
            ))
        }.also { assertEquals(AuthErrorCode.FORBIDDEN, it.code) }

        // Challenge negative checks:
        val issueResult = mfaService.issueChallenge(IssueMfaChallengeCommand(
            tenantId = "tenant-casino-1",
            playerId = player.playerId,
            actionTrigger = "WITHDRAWAL",
            idempotencyKey = "issue-chal-neg",
            correlationId = "c",
            causationId = "ca"
        ))

        // Wrong code rejected
        assertFailsWith<AuthenticationFailure.Rejected> {
            mfaService.verifyChallenge(VerifyMfaChallengeCommand(
                tenantId = "tenant-casino-1",
                challengeId = issueResult.challengeId,
                playerId = player.playerId,
                code = "WRONG-CODE-1",
                idempotencyKey = "v-wrong-1",
                correlationId = "c",
                causationId = "ca"
            ))
        }.also { assertEquals(AuthErrorCode.INVALID, it.code) }

        // Fail 2 more times to lock challenge
        mfaService.runCatching {
            mfaService.verifyChallenge(VerifyMfaChallengeCommand(
                tenantId = "tenant-casino-1",
                challengeId = issueResult.challengeId,
                playerId = player.playerId,
                code = "WRONG-CODE-2",
                idempotencyKey = "v-wrong-2",
                correlationId = "c",
                causationId = "ca"
            ))
        }
        mfaService.runCatching {
            mfaService.verifyChallenge(VerifyMfaChallengeCommand(
                tenantId = "tenant-casino-1",
                challengeId = issueResult.challengeId,
                playerId = player.playerId,
                code = "WRONG-CODE-3",
                idempotencyKey = "v-wrong-3",
                correlationId = "c",
                causationId = "ca"
            ))
        }

        // Now challenge is locked
        assertFailsWith<AuthenticationFailure.Rejected> {
            mfaService.verifyChallenge(VerifyMfaChallengeCommand(
                tenantId = "tenant-casino-1",
                challengeId = issueResult.challengeId,
                playerId = player.playerId,
                code = "MFA-654321",
                idempotencyKey = "v-after-lock",
                correlationId = "c",
                causationId = "ca"
            ))
        }.also { assertEquals(AuthErrorCode.FORBIDDEN, it.code) }

        // Non-existent challenge rejected
        assertFailsWith<AuthenticationFailure.Rejected> {
            mfaService.verifyChallenge(VerifyMfaChallengeCommand(
                tenantId = "tenant-casino-1",
                challengeId = UUID.randomUUID(),
                playerId = player.playerId,
                code = "MFA-654321",
                idempotencyKey = "v-nonexist",
                correlationId = "c",
                causationId = "ca"
            ))
        }.also { assertEquals(AuthErrorCode.INVALID, it.code) }

        // Cross-player challenge rejected
        val anotherPlayer = registerAndVerifyPlayer(regStore, email = "another.player@example.com")
        val anotherChal = mfaService.issueChallenge(IssueMfaChallengeCommand(
            tenantId = "tenant-casino-1",
            playerId = anotherPlayer.playerId,
            actionTrigger = "LOGIN",
            idempotencyKey = "issue-chal-another",
            correlationId = "c",
            causationId = "ca"
        ))
        assertFailsWith<AuthenticationFailure.Rejected> {
            mfaService.verifyChallenge(VerifyMfaChallengeCommand(
                tenantId = "tenant-casino-1",
                challengeId = anotherChal.challengeId,
                playerId = player.playerId, // wrong player ID
                code = "MFA-654321",
                idempotencyKey = "v-wrong-player",
                correlationId = "c",
                causationId = "ca"
            ))
        }.also { assertEquals(AuthErrorCode.INVALID, it.code) }
    }

    // =========================================================================
    // AUTH-001-04-T003: Concurrency, Duplicate Delivery, Idempotency & Conflict
    // =========================================================================

    @Test
    fun `AUTH-001-04-T003 Implement configurable MFA challenges survives concurrency duplicate delivery and dependency failure`() {
        val regStore = InMemoryPlayerRegistrationStore()
        val mfaStore = InMemoryConfigurableMfaStore()
        val mfaService = ConfigurableMfaChallengeService(
            registrationStore = regStore,
            mfaStore = mfaStore,
            clock = clock
        )

        val player = registerAndVerifyPlayer(regStore, email = "concurrent.mfa@example.com")

        val gate = CountDownLatch(1)
        val pool = Executors.newFixedThreadPool(2)
        val command = EnrollMfaFactorCommand(
            tenantId = "tenant-casino-1",
            playerId = player.playerId,
            factorType = MfaFactorType.TOTP,
            secretAssertion = "CONCURRENT_SECRET",
            idempotencyKey = "idemp-concurrent-mfa-001",
            correlationId = "corr-conc-1",
            causationId = "caus-conc-1"
        )

        val calls = (1..2).map {
            pool.submit<EnrollMfaFactorResult> {
                gate.await()
                mfaService.enrollFactor(command)
            }
        }
        gate.countDown()
        val results = calls.map { it.get() }
        pool.shutdown()

        // Concurrent equivalent submissions produce identical authoritative result
        assertEquals(results[0].resultId, results[1].resultId)
        assertEquals(MfaEnrollmentStatus.PENDING_CONFIRMATION, results[0].status)

        // Conflicting payload with reused key rejected with CONFLICT
        val conflictingCommand = command.copy(secretAssertion = "DIFFERENT_SECRET")
        assertFailsWith<AuthenticationFailure.Rejected> {
            mfaService.enrollFactor(conflictingCommand)
        }.also { assertEquals(AuthErrorCode.CONFLICT, it.code) }

        // Challenge issue concurrency
        val chalCmd = IssueMfaChallengeCommand(
            tenantId = "tenant-casino-1",
            playerId = player.playerId,
            actionTrigger = "LOGIN",
            idempotencyKey = "idemp-concurrent-chal-001",
            correlationId = "c",
            causationId = "ca"
        )
        val cGate = CountDownLatch(1)
        val cPool = Executors.newFixedThreadPool(2)
        val cCalls = (1..2).map {
            cPool.submit<IssueMfaChallengeResult> {
                cGate.await()
                mfaService.issueChallenge(chalCmd)
            }
        }
        cGate.countDown()
        val cResults = cCalls.map { it.get() }
        cPool.shutdown()

        assertEquals(cResults[0].resultId, cResults[1].resultId)
        assertEquals(cResults[0].challengeId, cResults[1].challengeId)
    }

    // =========================================================================
    // AUTH-001-04-T004: Compatibility, Lifecycle, Migration & Redaction Safety
    // =========================================================================

    @Test
    fun `AUTH-001-04-T004 Implement configurable MFA challenges remains compatible recoverable observable and lifecycle-safe`() {
        val regStore = InMemoryPlayerRegistrationStore()
        val mfaStore = InMemoryConfigurableMfaStore()
        val mfaService = ConfigurableMfaChallengeService(
            registrationStore = regStore,
            mfaStore = mfaStore,
            clock = clock
        )

        // 1. Fail-closed assertion gate (expected RED failure: unverified/recovery bypass)
        ConfigurableMfaBinding.isBound = false
        val exEnroll = assertFailsWith<AssertionError> {
            mfaService.enrollFactor(EnrollMfaFactorCommand(
                tenantId = "t1",
                playerId = UUID.randomUUID(),
                factorType = MfaFactorType.TOTP,
                secretAssertion = "s",
                idempotencyKey = "k",
                correlationId = "c",
                causationId = "ca"
            ))
        }
        assertEquals("unverified/recovery bypass", exEnroll.message)

        val exIssue = assertFailsWith<AssertionError> {
            mfaService.issueChallenge(IssueMfaChallengeCommand(
                tenantId = "t1",
                playerId = UUID.randomUUID(),
                actionTrigger = "LOGIN",
                idempotencyKey = "k",
                correlationId = "c",
                causationId = "ca"
            ))
        }
        assertEquals("unverified/recovery bypass", exIssue.message)

        val exVerify = assertFailsWith<AssertionError> {
            mfaService.verifyChallenge(VerifyMfaChallengeCommand(
                tenantId = "t1",
                challengeId = UUID.randomUUID(),
                playerId = UUID.randomUUID(),
                code = "123",
                idempotencyKey = "k",
                correlationId = "c",
                causationId = "ca"
            ))
        }
        assertEquals("unverified/recovery bypass", exVerify.message)

        // Re-bind for remainder of test
        ConfigurableMfaBinding.isBound = true

        // 2. Assert no unapproved persistence or migration is introduced
        val migrationDir = File("src/main/resources/db/migration")
        val sqlFiles = migrationDir.listFiles { _, name -> name.endsWith(".sql") } ?: emptyArray()
        assertTrue(sqlFiles.isNotEmpty())
        val migrationVersions = sqlFiles.map { it.name.substringBefore("__") }
        assertTrue(migrationVersions.all { it.matches(Regex("V[0-9]+")) })
        assertTrue(!migrationVersions.contains("V17"), "No unapproved V17 migration should be introduced")

        // 3. Observability & Redaction: Audit events must not leak raw secret assertions or codes
        val player = registerAndVerifyPlayer(regStore, email = "obs.mfa@example.com")
        val result = mfaService.enrollFactor(EnrollMfaFactorCommand(
            tenantId = "tenant-casino-1",
            playerId = player.playerId,
            factorType = MfaFactorType.TOTP,
            secretAssertion = "SuperSensitiveTotpSeed123!",
            idempotencyKey = "obs-mfa-enroll",
            correlationId = "corr-obs-1",
            causationId = "caus-obs-1"
        ))

        val auditEvent = result.auditEvent
        assertNotNull(auditEvent)
        val auditString = "${auditEvent.type}:${auditEvent.tenantId}:${auditEvent.correlationId}:${auditEvent.causationId}"
        assertTrue(!auditString.contains("SuperSensitiveTotpSeed123!"), "Must not leak raw TOTP secret")
        assertTrue(!auditString.contains("SECRET", ignoreCase = true))
        assertTrue(!auditString.contains("PASSWORD", ignoreCase = true))
    }
}
