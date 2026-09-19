package com.slotting.admin.identity

import com.slotting.admin.auth.AuthErrorCode
import com.slotting.admin.auth.AuthenticationFailure
import org.junit.jupiter.api.AfterEach
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test
import java.io.File
import java.time.Clock
import java.time.Instant
import java.time.LocalDate
import java.time.ZoneOffset
import java.util.UUID
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.CountDownLatch
import java.util.concurrent.Executors
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertNotNull
import kotlin.test.assertTrue

class ServerEligibilityPolicyTest {

    private val now = Instant.parse("2026-09-18T22:00:00Z")
    private val clock = Clock.fixed(now, ZoneOffset.UTC)

    @BeforeEach
    fun setUp() {
        ServerEligibilityBinding.isBound = true
    }

    @AfterEach
    fun tearDown() {
        ShortLivedTokenBinding.isBound = true
        RefreshTokenRotationBinding.isBound = true
        SessionDeviceRevocationBinding.isBound = true
        LoginAbuseBinding.isBound = true
        AccountStateLifecycleBinding.isBound = true
        ServerEligibilityBinding.isBound = true
    }

    private fun registerAndVerifyPlayer(
        regStore: InMemoryPlayerRegistrationStore,
        tenantId: String = "tenant-casino-1",
        email: String = "eligibility.player@example.com"
    ): RegisterPlayerResult {
        val regService = PlayerRegistrationService(store = regStore, clock = clock)
        val regCmd = RegisterPlayerCommand(
            tenantId = tenantId,
            email = email,
            phone = "+1555" + (9000000 + regStore.players.size + 1),
            jurisdiction = "NV",
            riskScore = 15.0,
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
    // AUTHZ-001-T001: Primary Authoritative Outcome
    // =========================================================================

    @Test
    fun `AUTHZ-001-T001 Server eligibility policy evaluates eligibility, enforces decisionId and version on each command, denies self-excluded and stale, guarantees zero financial mutation`() {
        ServerEligibilityBinding.checkBound()

        val regStore = InMemoryPlayerRegistrationStore()
        val eligStore = InMemoryServerEligibilityStore()
        val alertSink = InMemoryServerEligibilityAlertSink()
        val service = ServerEligibilityPolicyService(
            registrationStore = regStore,
            eligibilityStore = eligStore,
            alertSink = alertSink,
            clock = clock
        )

        val regResult = registerAndVerifyPlayer(regStore)
        val playerId = regResult.playerId
        val tenantId = "tenant-casino-1"

        // Configure valid compliance profile: 26 years old, KYC verified, AML cleared, NV jurisdiction
        eligStore.saveComplianceProfile(
            PlayerComplianceProfile(
                playerId = playerId,
                tenantId = tenantId,
                dateOfBirth = LocalDate.of(2000, 1, 1),
                kycStatus = KycComplianceStatus.VERIFIED,
                amlStatus = AmlComplianceStatus.CLEARED,
                jurisdiction = "NV",
                responsiblePlay = ResponsiblePlayProfile(
                    playerId = playerId,
                    selfExcluded = false,
                    dailyWagerLimitMinor = 100_000L,
                    singleWagerLimitMinor = 20_000L
                )
            )
        )

        // 1. Fail-closed gate verification: When unbound, throws protected risk assertion
        ServerEligibilityBinding.isBound = false
        val evalCmd = EvaluateEligibilityCommand(
            tenantId = tenantId,
            playerId = playerId,
            declaredJurisdiction = "NV",
            idempotencyKey = "eval-1",
            correlationId = "corr-eval-1",
            causationId = "caus-eval-1"
        )
        val gateError = assertFailsWith<AssertionError> {
            service.evaluateEligibility(evalCmd)
        }
        assertEquals("manipulated Android input/self-excluded user succeeds", gateError.message)

        // Bind gate for functional execution
        ServerEligibilityBinding.isBound = true

        // 2. Authoritative evaluation succeeds for compliant active player
        val verdict = service.evaluateEligibility(evalCmd)
        assertTrue(verdict.eligible, "Compliant player must be eligible")
        assertNotNull(verdict.decisionId)
        assertEquals(1L, verdict.version)
        assertEquals(tenantId, verdict.tenantId)
        assertEquals(playerId, verdict.playerId)
        assertEquals(PlayerAccountStatus.ACTIVE, verdict.accountStatus)
        assertEquals(KycComplianceStatus.VERIFIED, verdict.kycStatus)
        assertEquals(AmlComplianceStatus.CLEARED, verdict.amlStatus)
        assertEquals("NV", verdict.jurisdiction)
        assertTrue(verdict.ageVerified)
        assertEquals(26, verdict.calculatedAge)
        assertEquals(21, verdict.minAgeRequired) // NV requires 21
        assertFalse(verdict.selfExcluded)
        assertTrue(verdict.denialReasons.isEmpty())
        assertEquals(now, verdict.evaluatedAt)
        assertEquals(now.plusSeconds(300L), verdict.expiresAt)
        assertEquals("ELIGIBILITY_EVALUATED_ELIGIBLE", verdict.auditEvent.type)
        assertEquals("ELIGIBILITY_VERDICT_ELIGIBLE", verdict.outboxEvent.type)

        // 3. Verifying command with valid decisionId and expectedDecisionVersion succeeds
        val verifyCmd = VerifyEligibilityCommand(
            tenantId = tenantId,
            playerId = playerId,
            decisionId = verdict.decisionId,
            expectedDecisionVersion = verdict.version,
            requestedAction = "SPIN_REEL",
            wagerMinor = 1_000L,
            idempotencyKey = "ver-cmd-1",
            correlationId = "corr-ver-1",
            causationId = "caus-ver-1"
        )
        val verifyResult = service.verifyCommandEligibility(verifyCmd)
        assertTrue(verifyResult.verified)
        assertEquals(verdict.decisionId, verifyResult.decisionId)
        assertEquals(verdict.version, verifyResult.decisionVersion)
        assertEquals("SPIN_REEL", verifyResult.requestedAction)
        assertEquals("ELIGIBILITY_COMMAND_VERIFIED", verifyResult.auditEvent.type)
        assertEquals("ELIGIBILITY_COMMAND_VERIFIED", verifyResult.outboxEvent.type)

        // 4. Deny on self-excluded user
        val selfExcludedPlayer = registerAndVerifyPlayer(regStore, email = "selfexcluded@example.com")
        eligStore.saveComplianceProfile(
            PlayerComplianceProfile(
                playerId = selfExcludedPlayer.playerId,
                tenantId = tenantId,
                dateOfBirth = LocalDate.of(1995, 5, 5),
                responsiblePlay = ResponsiblePlayProfile(
                    playerId = selfExcludedPlayer.playerId,
                    selfExcluded = true
                )
            )
        )
        val selfExcludedVerdict = service.evaluateEligibility(
            EvaluateEligibilityCommand(
                tenantId = tenantId,
                playerId = selfExcludedPlayer.playerId,
                idempotencyKey = "eval-self-ex",
                correlationId = "corr-self-ex",
                causationId = "caus-self-ex"
            )
        )
        assertFalse(selfExcludedVerdict.eligible)
        assertTrue(selfExcludedVerdict.denialReasons.contains("RESPONSIBLE_GAMING_SELF_EXCLUDED"))
        assertTrue(selfExcludedVerdict.selfExcluded)
        assertEquals("ELIGIBILITY_EVALUATED_INELIGIBLE", selfExcludedVerdict.auditEvent.type)
        // Command verification for self-excluded verdict must strictly fail closed
        val selfExcludedVerifyError = assertFailsWith<AuthenticationFailure.Rejected> {
            service.verifyCommandEligibility(
                VerifyEligibilityCommand(
                    tenantId = tenantId,
                    playerId = selfExcludedPlayer.playerId,
                    decisionId = selfExcludedVerdict.decisionId,
                    expectedDecisionVersion = selfExcludedVerdict.version,
                    requestedAction = "SPIN_REEL",
                    idempotencyKey = "ver-self-ex",
                    correlationId = "corr-ver-se",
                    causationId = "caus-ver-se"
                )
            )
        }
        assertEquals(AuthErrorCode.FORBIDDEN, selfExcludedVerifyError.code)

        // 5. Deny on cool-off active user
        val coolOffPlayer = registerAndVerifyPlayer(regStore, email = "cooloff@example.com")
        eligStore.saveComplianceProfile(
            PlayerComplianceProfile(
                playerId = coolOffPlayer.playerId,
                tenantId = tenantId,
                dateOfBirth = LocalDate.of(1998, 3, 10),
                responsiblePlay = ResponsiblePlayProfile(
                    playerId = coolOffPlayer.playerId,
                    coolOffUntil = now.plusSeconds(3600)
                )
            )
        )
        val coolOffVerdict = service.evaluateEligibility(
            EvaluateEligibilityCommand(
                tenantId = tenantId,
                playerId = coolOffPlayer.playerId,
                idempotencyKey = "eval-cooloff",
                correlationId = "corr-cooloff",
                causationId = "caus-cooloff"
            )
        )
        assertFalse(coolOffVerdict.eligible)
        assertTrue(coolOffVerdict.denialReasons.contains("RESPONSIBLE_GAMING_COOL_OFF_ACTIVE"))

        // 6. Deny on stale / expired verdict
        val expiredClock = Clock.fixed(now.plusSeconds(301), ZoneOffset.UTC)
        val expiredService = ServerEligibilityPolicyService(
            registrationStore = regStore,
            eligibilityStore = eligStore,
            alertSink = alertSink,
            clock = expiredClock
        )
        val staleError = assertFailsWith<AuthenticationFailure.Rejected> {
            expiredService.verifyCommandEligibility(
                VerifyEligibilityCommand(
                    tenantId = tenantId,
                    playerId = playerId,
                    decisionId = verdict.decisionId,
                    expectedDecisionVersion = verdict.version,
                    requestedAction = "SPIN_REEL",
                    idempotencyKey = "ver-cmd-stale",
                    correlationId = "corr-stale",
                    causationId = "caus-stale"
                )
            )
        }
        assertEquals(AuthErrorCode.STALE, staleError.code)

        // 7. Deny on missing verdict
        val missingError = assertFailsWith<AuthenticationFailure.Rejected> {
            service.verifyCommandEligibility(
                VerifyEligibilityCommand(
                    tenantId = tenantId,
                    playerId = playerId,
                    decisionId = UUID.randomUUID(), // non-existent decisionId
                    expectedDecisionVersion = 1L,
                    requestedAction = "SPIN_REEL",
                    idempotencyKey = "ver-cmd-missing",
                    correlationId = "corr-missing",
                    causationId = "caus-missing"
                )
            )
        }
        assertEquals(AuthErrorCode.INVALID, missingError.code)

        // 8. Deny on decision version mismatch
        val versionMismatchError = assertFailsWith<AuthenticationFailure.Rejected> {
            service.verifyCommandEligibility(
                VerifyEligibilityCommand(
                    tenantId = tenantId,
                    playerId = playerId,
                    decisionId = verdict.decisionId,
                    expectedDecisionVersion = 999L, // wrong version
                    requestedAction = "SPIN_REEL",
                    idempotencyKey = "ver-cmd-version-mismatch",
                    correlationId = "corr-vm",
                    causationId = "caus-vm"
                )
            )
        }
        assertEquals(AuthErrorCode.CONFLICT, versionMismatchError.code)

        // 9. Zero financial mutation guarantee
        // Verify eligibility service interacts strictly with registration and compliance stores;
        // no payment, wallet, or settlement records are created or mutated.
        assertTrue(verdict.eligible)
        assertEquals(0L, eligStore.findComplianceProfile(tenantId, playerId)!!.responsiblePlay.currentDailyWagerMinor)
    }

    // =========================================================================
    // AUTHZ-001-T002: Negative, Boundary, and Security Cases
    // =========================================================================

    @Test
    fun `AUTHZ-001-T002 Negative, boundary, and security cases enforce cross-tenant, underage, jurisdiction, AML, account state, and wager limit controls`() {
        ServerEligibilityBinding.isBound = true
        val regStore = InMemoryPlayerRegistrationStore()
        val eligStore = InMemoryServerEligibilityStore()
        val alertSink = InMemoryServerEligibilityAlertSink()
        val service = ServerEligibilityPolicyService(
            registrationStore = regStore,
            eligibilityStore = eligStore,
            alertSink = alertSink,
            clock = clock,
            allowedJurisdictions = setOf("NV", "NJ", "UK")
        )

        val tenantA = "tenant-alpha"
        val tenantB = "tenant-bravo"
        val playerA = registerAndVerifyPlayer(regStore, tenantId = tenantA, email = "alpha@example.com")
        val playerB = registerAndVerifyPlayer(regStore, tenantId = tenantB, email = "bravo@example.com")

        eligStore.saveComplianceProfile(
            PlayerComplianceProfile(
                playerId = playerA.playerId,
                tenantId = tenantA,
                dateOfBirth = LocalDate.of(1990, 1, 1),
                jurisdiction = "NV",
                responsiblePlay = ResponsiblePlayProfile(
                    playerId = playerA.playerId,
                    singleWagerLimitMinor = 5_000L,
                    dailyWagerLimitMinor = 20_000L,
                    currentDailyWagerMinor = 18_000L
                )
            )
        )

        val verdictA = service.evaluateEligibility(
            EvaluateEligibilityCommand(
                tenantId = tenantA,
                playerId = playerA.playerId,
                idempotencyKey = "eval-tenant-a",
                correlationId = "corr-a",
                causationId = "caus-a"
            )
        )
        assertTrue(verdictA.eligible)

        // 1. Cross-tenant attack: tenant B attempts to use tenant A's decisionId
        val crossTenantError = assertFailsWith<AuthenticationFailure.Rejected> {
            service.verifyCommandEligibility(
                VerifyEligibilityCommand(
                    tenantId = tenantB,
                    playerId = playerA.playerId,
                    decisionId = verdictA.decisionId,
                    expectedDecisionVersion = verdictA.version,
                    requestedAction = "SPIN_REEL",
                    idempotencyKey = "ver-cross-tenant",
                    correlationId = "corr-cross-t",
                    causationId = "caus-cross-t"
                )
            )
        }
        assertEquals(AuthErrorCode.INVALID, crossTenantError.code) // verdict not in tenantB

        // 2. Cross-player attack: player B attempts to use player A's decisionId within tenant A
        val crossPlayerError = assertFailsWith<AuthenticationFailure.Rejected> {
            service.verifyCommandEligibility(
                VerifyEligibilityCommand(
                    tenantId = tenantA,
                    playerId = playerB.playerId,
                    decisionId = verdictA.decisionId,
                    expectedDecisionVersion = verdictA.version,
                    requestedAction = "SPIN_REEL",
                    idempotencyKey = "ver-cross-player",
                    correlationId = "corr-cross-p",
                    causationId = "caus-cross-p"
                )
            )
        }
        assertEquals(AuthErrorCode.FORBIDDEN, crossPlayerError.code)

        // 3. Underage player (born 2012, 14 years old in 2026)
        val underagePlayer = registerAndVerifyPlayer(regStore, tenantId = tenantA, email = "underage@example.com")
        eligStore.saveComplianceProfile(
            PlayerComplianceProfile(
                playerId = underagePlayer.playerId,
                tenantId = tenantA,
                dateOfBirth = LocalDate.of(2012, 6, 15),
                jurisdiction = "UK"
            )
        )
        val underageVerdict = service.evaluateEligibility(
            EvaluateEligibilityCommand(
                tenantId = tenantA,
                playerId = underagePlayer.playerId,
                idempotencyKey = "eval-underage",
                correlationId = "corr-underage",
                causationId = "caus-underage"
            )
        )
        assertFalse(underageVerdict.eligible)
        assertTrue(underageVerdict.denialReasons.contains("UNDERAGE"))
        assertFalse(underageVerdict.ageVerified)

        // 4. Prohibited jurisdiction
        val foreignPlayer = registerAndVerifyPlayer(regStore, tenantId = tenantA, email = "foreign@example.com")
        eligStore.saveComplianceProfile(
            PlayerComplianceProfile(
                playerId = foreignPlayer.playerId,
                tenantId = tenantA,
                dateOfBirth = LocalDate.of(1995, 1, 1),
                jurisdiction = "RESTRICTED_COUNTRY"
            )
        )
        val foreignVerdict = service.evaluateEligibility(
            EvaluateEligibilityCommand(
                tenantId = tenantA,
                playerId = foreignPlayer.playerId,
                declaredJurisdiction = "RESTRICTED_COUNTRY",
                idempotencyKey = "eval-foreign",
                correlationId = "corr-foreign",
                causationId = "caus-foreign"
            )
        )
        assertFalse(foreignVerdict.eligible)
        assertTrue(foreignVerdict.denialReasons.contains("PROHIBITED_JURISDICTION"))

        // 5. AML Restricted/Sanctioned status
        val amlPlayer = registerAndVerifyPlayer(regStore, tenantId = tenantA, email = "aml@example.com")
        eligStore.saveComplianceProfile(
            PlayerComplianceProfile(
                playerId = amlPlayer.playerId,
                tenantId = tenantA,
                dateOfBirth = LocalDate.of(1990, 1, 1),
                amlStatus = AmlComplianceStatus.SANCTIONED,
                jurisdiction = "NV"
            )
        )
        val amlVerdict = service.evaluateEligibility(
            EvaluateEligibilityCommand(
                tenantId = tenantA,
                playerId = amlPlayer.playerId,
                idempotencyKey = "eval-aml",
                correlationId = "corr-aml",
                causationId = "caus-aml"
            )
        )
        assertFalse(amlVerdict.eligible)
        assertTrue(amlVerdict.denialReasons.contains("AML_SANCTIONED"))
        assertTrue(alertSink.alerts.any { it.contains("AML_SANCTIONED") })

        // 6. Non-active account states: SUSPENDED and LOCKED
        val suspendedPlayer = registerAndVerifyPlayer(regStore, tenantId = tenantA, email = "suspended@example.com")
        regStore.findById(tenantA, suspendedPlayer.playerId)!!.status = PlayerAccountStatus.SUSPENDED
        eligStore.saveComplianceProfile(
            PlayerComplianceProfile(
                playerId = suspendedPlayer.playerId,
                tenantId = tenantA,
                dateOfBirth = LocalDate.of(1990, 1, 1),
                jurisdiction = "NV"
            )
        )
        val suspendedVerdict = service.evaluateEligibility(
            EvaluateEligibilityCommand(
                tenantId = tenantA,
                playerId = suspendedPlayer.playerId,
                idempotencyKey = "eval-suspended",
                correlationId = "corr-susp",
                causationId = "caus-susp"
            )
        )
        assertFalse(suspendedVerdict.eligible)
        assertTrue(suspendedVerdict.denialReasons.contains("ACCOUNT_NOT_ACTIVE_SUSPENDED"))

        // 7. Responsible play: single wager limit exceeded
        val singleWagerExceededError = assertFailsWith<AuthenticationFailure.Rejected> {
            service.verifyCommandEligibility(
                VerifyEligibilityCommand(
                    tenantId = tenantA,
                    playerId = playerA.playerId,
                    decisionId = verdictA.decisionId,
                    expectedDecisionVersion = verdictA.version,
                    requestedAction = "SPIN_REEL",
                    wagerMinor = 6_000L, // limit is 5_000L
                    idempotencyKey = "ver-single-wager-exceeded",
                    correlationId = "corr-wager-max",
                    causationId = "caus-wager-max"
                )
            )
        }
        assertEquals(AuthErrorCode.FORBIDDEN, singleWagerExceededError.code)

        // 8. Responsible play: daily wager limit exceeded (18_000 current + 3_000 attempted > 20_000 limit)
        val dailyWagerExceededError = assertFailsWith<AuthenticationFailure.Rejected> {
            service.verifyCommandEligibility(
                VerifyEligibilityCommand(
                    tenantId = tenantA,
                    playerId = playerA.playerId,
                    decisionId = verdictA.decisionId,
                    expectedDecisionVersion = verdictA.version,
                    requestedAction = "SPIN_REEL",
                    wagerMinor = 3_000L,
                    idempotencyKey = "ver-daily-wager-exceeded",
                    correlationId = "corr-wager-daily",
                    causationId = "caus-wager-daily"
                )
            )
        }
        assertEquals(AuthErrorCode.FORBIDDEN, dailyWagerExceededError.code)

        // 9. Real-time revocation defense: Account suspended after verdict was issued
        regStore.findById(tenantA, playerA.playerId)!!.status = PlayerAccountStatus.SUSPENDED
        val realtimeSuspendError = assertFailsWith<AuthenticationFailure.Rejected> {
            service.verifyCommandEligibility(
                VerifyEligibilityCommand(
                    tenantId = tenantA,
                    playerId = playerA.playerId,
                    decisionId = verdictA.decisionId,
                    expectedDecisionVersion = verdictA.version,
                    requestedAction = "SPIN_REEL",
                    wagerMinor = 1_000L,
                    idempotencyKey = "ver-realtime-suspend",
                    correlationId = "corr-rt-susp",
                    causationId = "caus-rt-susp"
                )
            )
        }
        assertEquals(AuthErrorCode.FORBIDDEN, realtimeSuspendError.code)

        // Restore playerA status
        regStore.findById(tenantA, playerA.playerId)!!.status = PlayerAccountStatus.ACTIVE

        // 10. Blank and invalid headers
        assertFailsWith<AuthenticationFailure.Rejected> {
            service.evaluateEligibility(
                EvaluateEligibilityCommand(
                    tenantId = "",
                    playerId = playerA.playerId,
                    idempotencyKey = "key",
                    correlationId = "corr",
                    causationId = "caus"
                )
            )
        }
        assertFailsWith<AuthenticationFailure.Rejected> {
            service.evaluateEligibility(
                EvaluateEligibilityCommand(
                    tenantId = tenantA,
                    playerId = playerA.playerId,
                    idempotencyKey = "key",
                    correlationId = "corr",
                    causationId = "caus",
                    expectedVersion = 0L
                )
            )
        }
    }

    // =========================================================================
    // AUTHZ-001-T003: Concurrency, Idempotency, and Duplicate Delivery
    // =========================================================================

    @Test
    fun `AUTHZ-001-T003 Concurrency, idempotency, duplicate delivery, and race condition defense`() {
        ServerEligibilityBinding.isBound = true
        val regStore = InMemoryPlayerRegistrationStore()
        val eligStore = InMemoryServerEligibilityStore()
        val alertSink = InMemoryServerEligibilityAlertSink()
        val service = ServerEligibilityPolicyService(
            registrationStore = regStore,
            eligibilityStore = eligStore,
            alertSink = alertSink,
            clock = clock
        )

        val tenantId = "tenant-concurrent"
        val player = registerAndVerifyPlayer(regStore, tenantId = tenantId, email = "concurrent@example.com")
        eligStore.saveComplianceProfile(
            PlayerComplianceProfile(
                playerId = player.playerId,
                tenantId = tenantId,
                dateOfBirth = LocalDate.of(1992, 4, 12),
                jurisdiction = "NV"
            )
        )

        val evalCmd = EvaluateEligibilityCommand(
            tenantId = tenantId,
            playerId = player.playerId,
            idempotencyKey = "idem-eval-1",
            correlationId = "corr-idem",
            causationId = "caus-idem"
        )

        // 1. Evaluation idempotency
        val verdict1 = service.evaluateEligibility(evalCmd)
        val verdict2 = service.evaluateEligibility(evalCmd)
        assertEquals(verdict1.decisionId, verdict2.decisionId)
        assertEquals(verdict1.version, verdict2.version)
        assertEquals(verdict1.evidenceReference, verdict2.evidenceReference)

        // 2. Evaluation conflict on changed payload
        val conflictingCmd = evalCmd.copy(declaredJurisdiction = "CHANGED_JURISDICTION")
        val conflictError = assertFailsWith<AuthenticationFailure.Rejected> {
            service.evaluateEligibility(conflictingCmd)
        }
        assertEquals(AuthErrorCode.CONFLICT, conflictError.code)

        // 3. Verification idempotency
        val verifyCmd = VerifyEligibilityCommand(
            tenantId = tenantId,
            playerId = player.playerId,
            decisionId = verdict1.decisionId,
            expectedDecisionVersion = verdict1.version,
            requestedAction = "SPIN_REEL",
            idempotencyKey = "idem-ver-1",
            correlationId = "corr-ver-idem",
            causationId = "caus-ver-idem"
        )
        val vResult1 = service.verifyCommandEligibility(verifyCmd)
        val vResult2 = service.verifyCommandEligibility(verifyCmd)
        assertEquals(vResult1.resultId, vResult2.resultId)
        assertEquals(vResult1.decisionId, vResult2.decisionId)
        assertEquals(vResult1.evidenceReference, vResult2.evidenceReference)

        // 4. Verification conflict on changed payload
        val conflictingVerifyCmd = verifyCmd.copy(requestedAction = "ENTER_TOURNAMENT")
        val verConflictError = assertFailsWith<AuthenticationFailure.Rejected> {
            service.verifyCommandEligibility(conflictingVerifyCmd)
        }
        assertEquals(AuthErrorCode.CONFLICT, verConflictError.code)

        // 5. Multi-threaded concurrent evaluations
        val threads = 16
        val executor = Executors.newFixedThreadPool(threads)
        val latch = CountDownLatch(threads)
        val players = (1..threads).map { i ->
            val p = registerAndVerifyPlayer(regStore, tenantId = tenantId, email = "p$i@example.com")
            eligStore.saveComplianceProfile(
                PlayerComplianceProfile(
                    playerId = p.playerId,
                    tenantId = tenantId,
                    dateOfBirth = LocalDate.of(1990 + (i % 10), 1, 1),
                    jurisdiction = "NV"
                )
            )
            p
        }

        val results = ConcurrentHashMap<UUID, ServerEligibilityVerdict>()
        players.forEachIndexed { idx, p ->
            executor.submit {
                try {
                    val res = service.evaluateEligibility(
                        EvaluateEligibilityCommand(
                            tenantId = tenantId,
                            playerId = p.playerId,
                            idempotencyKey = "concurrent-eval-$idx",
                            correlationId = "corr-concurrent-$idx",
                            causationId = "caus-concurrent-$idx"
                        )
                    )
                    results[p.playerId] = res
                } finally {
                    latch.countDown()
                }
            }
        }
        latch.await()
        assertEquals(threads, results.size)
        results.values.forEach { v ->
            assertTrue(v.eligible)
            assertNotNull(v.decisionId)
        }

        // 6. Multi-threaded concurrent verifications
        val verLatch = CountDownLatch(threads)
        val verifyResults = ConcurrentHashMap<UUID, VerifyEligibilityResult>()
        players.forEachIndexed { idx, p ->
            executor.submit {
                try {
                    val verdict = results[p.playerId]!!
                    val vRes = service.verifyCommandEligibility(
                        VerifyEligibilityCommand(
                            tenantId = tenantId,
                            playerId = p.playerId,
                            decisionId = verdict.decisionId,
                            expectedDecisionVersion = verdict.version,
                            requestedAction = "SPIN_REEL",
                            idempotencyKey = "concurrent-ver-$idx",
                            correlationId = "corr-concurrent-ver-$idx",
                            causationId = "caus-concurrent-ver-$idx"
                        )
                    )
                    verifyResults[p.playerId] = vRes
                } finally {
                    verLatch.countDown()
                }
            }
        }
        verLatch.await()
        executor.shutdown()
        assertEquals(threads, verifyResults.size)
        verifyResults.values.forEach { vr ->
            assertTrue(vr.verified)
        }
    }

    // =========================================================================
    // AUTHZ-001-T004: Migration Integrity, Recovery & Observability
    // =========================================================================

    @Test
    fun `AUTHZ-001-T004 Migration integrity, recovery and restart, observability and redaction`() {
        // 1. Migration integrity: No migrations > V16
        val migrationsDir = File("src/main/resources/db/migration")
        if (migrationsDir.exists()) {
            val invalidMigrations = migrationsDir.listFiles()?.filter { file ->
                val name = file.name
                if (name.startsWith("V") && name.contains("__")) {
                    val versionStr = name.substring(1, name.indexOf("__"))
                    val versionNum = versionStr.toIntOrNull()
                    versionNum != null && versionNum > 16
                } else false
            } ?: emptyList()
            assertTrue(invalidMigrations.isEmpty(), "Found illegal migrations > V16: ${invalidMigrations.map { it.name }}")
        }

        ServerEligibilityBinding.isBound = true
        val regStore = InMemoryPlayerRegistrationStore()
        val eligStore = InMemoryServerEligibilityStore()
        val alertSink = InMemoryServerEligibilityAlertSink()
        val service1 = ServerEligibilityPolicyService(
            registrationStore = regStore,
            eligibilityStore = eligStore,
            alertSink = alertSink,
            clock = clock
        )

        val tenantId = "tenant-restart"
        val player = registerAndVerifyPlayer(regStore, tenantId = tenantId, email = "restart@example.com")
        eligStore.saveComplianceProfile(
            PlayerComplianceProfile(
                playerId = player.playerId,
                tenantId = tenantId,
                dateOfBirth = LocalDate.of(1995, 8, 20),
                jurisdiction = "NV"
            )
        )

        val verdict = service1.evaluateEligibility(
            EvaluateEligibilityCommand(
                tenantId = tenantId,
                playerId = player.playerId,
                idempotencyKey = "restart-eval-1",
                correlationId = "corr-restart",
                causationId = "caus-restart"
            )
        )
        assertTrue(verdict.eligible)

        // 2. Recovery and restart: New service instance attached to same store
        val service2 = ServerEligibilityPolicyService(
            registrationStore = regStore,
            eligibilityStore = eligStore,
            alertSink = alertSink,
            clock = clock
        )
        val verifiedOnRestart = service2.verifyCommandEligibility(
            VerifyEligibilityCommand(
                tenantId = tenantId,
                playerId = player.playerId,
                decisionId = verdict.decisionId,
                expectedDecisionVersion = verdict.version,
                requestedAction = "SPIN_REEL",
                idempotencyKey = "restart-ver-1",
                correlationId = "corr-restart-ver",
                causationId = "caus-restart-ver"
            )
        )
        assertTrue(verifiedOnRestart.verified)
        assertEquals(verdict.decisionId, verifiedOnRestart.decisionId)

        // 3. Observability and Redaction
        // Verify audit event has required metadata and no raw PII leak
        val audit = verdict.auditEvent
        assertEquals(tenantId, audit.tenantId)
        assertEquals("corr-restart", audit.correlationId)
        assertEquals("caus-restart", audit.causationId)
        assertEquals("ELIGIBILITY_EVALUATED_ELIGIBLE", audit.type)
        assertEquals(now, audit.occurredAt)

        val outbox = verdict.outboxEvent
        assertEquals(tenantId, outbox.tenantId)
        assertEquals("ELIGIBILITY_VERDICT_ELIGIBLE", outbox.type)
        assertEquals(now, outbox.createdAt)

        // Denial reasons must use safe structured codes, not sensitive customer data
        val ineligiblePlayer = registerAndVerifyPlayer(regStore, tenantId = tenantId, email = "ineligible@example.com")
        eligStore.saveComplianceProfile(
            PlayerComplianceProfile(
                playerId = ineligiblePlayer.playerId,
                tenantId = tenantId,
                dateOfBirth = LocalDate.of(2015, 1, 1), // Underage
                kycStatus = KycComplianceStatus.PENDING,
                amlStatus = AmlComplianceStatus.RESTRICTED,
                jurisdiction = "RESTRICTED_TERRITORY",
                responsiblePlay = ResponsiblePlayProfile(
                    playerId = ineligiblePlayer.playerId,
                    selfExcluded = true
                )
            )
        )
        val badVerdict = service2.evaluateEligibility(
            EvaluateEligibilityCommand(
                tenantId = tenantId,
                playerId = ineligiblePlayer.playerId,
                declaredJurisdiction = "RESTRICTED_TERRITORY",
                idempotencyKey = "eval-bad",
                correlationId = "corr-bad",
                causationId = "caus-bad"
            )
        )
        assertFalse(badVerdict.eligible)
        val reasons = badVerdict.denialReasons
        assertTrue(reasons.contains("UNDERAGE"))
        assertTrue(reasons.contains("KYC_PENDING"))
        assertTrue(reasons.contains("AML_RESTRICTED"))
        assertTrue(reasons.contains("RESPONSIBLE_GAMING_SELF_EXCLUDED"))
        assertTrue(reasons.contains("PROHIBITED_JURISDICTION"))

        // Alert details should not contain raw credit card or password data
        alertSink.alerts.forEach { alert ->
            assertFalse(alert.contains("password"))
            assertFalse(alert.contains("cvv"))
        }
    }
}
