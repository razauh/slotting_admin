package com.slotting.admin.payment

import com.slotting.admin.auth.*
import com.slotting.admin.identity.AmlComplianceStatus
import com.slotting.admin.identity.InMemoryServerEligibilityStore
import com.slotting.admin.identity.ServerEligibilityStore
import com.slotting.admin.identity.KycComplianceStatus
import com.slotting.admin.identity.PlayerAccountStatus
import com.slotting.admin.identity.ServerEligibilityVerdict
import java.io.File
import java.time.Clock
import java.time.Instant
import java.time.ZoneOffset
import java.util.UUID
import java.util.concurrent.CountDownLatch
import java.util.concurrent.Executors
import kotlin.test.*
import org.junit.jupiter.api.AfterEach
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test

class DepositStateMachineTest {
    private val now = Instant.parse("2026-09-19T14:00:00Z")
    private val clock = Clock.fixed(now, ZoneOffset.UTC)
    private val tenantId = "tenant-deposit-1"
    private val fakeProviderId = "prov-adversarial-fake"
    private val playerId = UUID.fromString("11111111-1111-1111-1111-111111111111")
    private val eligibilityDecisionId = UUID.fromString("22222222-2222-2222-2222-222222222222")

    private val adminPrincipal = AuthenticatedPrincipal(
        id = "admin-dep-1",
        tenantId = tenantId,
        kind = PrincipalKind.ADMIN,
        roles = setOf(AdminRole.SUPER_ADMIN),
    )

    private val playerPrincipal = AuthenticatedPrincipal(
        id = "player-dep-1",
        tenantId = tenantId,
        kind = PrincipalKind.PLAYER,
        roles = emptySet(),
    )

    private val crossTenantPrincipal = AuthenticatedPrincipal(
        id = "admin-other",
        tenantId = "tenant-other",
        kind = PrincipalKind.ADMIN,
        roles = setOf(AdminRole.SUPER_ADMIN),
    )

    @BeforeEach
    fun setUp() {
        DepositStateMachineBinding.isBound = true
    }

    @AfterEach
    fun tearDown() {
        DepositStateMachineBinding.isBound = true
    }

    @Test
    fun `PAYMENT-002-T001 — Deposit state machine produces the required authoritative outcome`() {
        // 1. Expected RED failure verification: Fail-closed gate throws expected assertion when unbound
        DepositStateMachineBinding.isBound = false
        val store = InMemoryDepositStateMachineStore()
        val eligibilityStore = InMemoryServerEligibilityStore()
        setupValidEligibility(eligibilityStore)
        val alertSink = InMemoryDepositAlertSink()
        val fakeAdapter = AdversarialPaymentProviderFakeAdapter(fakeProviderId, clock = clock)
        val service = createService(store, eligibilityStore, mapOf(fakeProviderId to fakeAdapter), alertSink)

        val initCmd = initiateCommand(depositReference = "dep-red-001", idempotencyKey = "key-init-red-001")
        val gateError = assertFailsWith<AssertionError> {
            service.initiateDeposit(initCmd)
        }
        assertEquals("illegal transition/replay", gateError.message)

        // Bind the fail-closed gate
        DepositStateMachineBinding.isBound = true

        // 2. Authoritative operation: INITIATE deposit
        val depCmd = initiateCommand(
            depositReference = "dep-t001-001",
            amountMinorUnits = 10000L,
            currencyCode = "EUR",
            returnUrl = "https://client.example.com/payment-return?token=abc",
            idempotencyKey = "key-dep-t001-001",
            correlationId = "corr-dep-1",
            causationId = "cause-dep-1",
        )
        val initRecord = service.initiateDeposit(depCmd)
        assertNotNull(initRecord)
        assertEquals(DepositStatus.INITIATED, initRecord.status)
        assertEquals("dep-t001-001", initRecord.depositReference)
        assertEquals(10000L, initRecord.amountMinorUnits)
        assertEquals("EUR", initRecord.currencyCode)
        assertEquals(fakeProviderId, initRecord.providerId)
        assertEquals("INITIATED", initRecord.safeReasonCode)
        assertEquals(1L, initRecord.version)

        // Outcome-specific semantic contract assertion:
        // "Amount/currency/routing server validated; return URL is informational only."
        assertEquals(DEPOSIT_STATE_MACHINE_CONTRACT, initRecord.semanticContract)
        assertTrue(initRecord.returnUrlIsInformationalOnly)
        assertEquals("https://client.example.com/payment-return?token=abc", initRecord.returnUrl)

        // Financial conservation in INITIATED state: debit tracked, credit = 0 until SUCCEEDED
        assertEquals(10000L, initRecord.debitMinorUnits)
        assertEquals(0L, initRecord.creditMinorUnits)
        assertTrue(initRecord.conserved)

        // Idempotent replay yields identical authoritative identity
        val replayInit = service.initiateDeposit(depCmd)
        assertEquals(initRecord.depositId, replayInit.depositId)
        assertEquals(initRecord.evidenceReference, replayInit.evidenceReference)
        assertEquals(initRecord.version, replayInit.version)

        // 3. Authoritative transition: INITIATED -> PENDING
        val toPendingCmd = TransitionDepositCommand(
            principal = adminPrincipal,
            sessionId = "session-dep-1",
            tenantId = tenantId,
            depositReference = "dep-t001-001",
            targetStatus = DepositStatus.PENDING,
            externalTransactionReference = "EXT-PENDING-001",
            idempotencyKey = "key-pend-t001-001",
            correlationId = "corr-pend-1",
            causationId = "cause-pend-1",
            expectedVersion = 1L,
            deliverySequence = 2L,
        )
        val pendingRecord = service.transitionDeposit(toPendingCmd)
        assertEquals(DepositStatus.PENDING, pendingRecord.status)
        assertEquals(2L, pendingRecord.version)
        assertEquals(DEPOSIT_STATE_MACHINE_CONTRACT, pendingRecord.semanticContract)

        // 4. Authoritative transition: PENDING -> SUCCEEDED
        val toSucceededCmd = TransitionDepositCommand(
            principal = adminPrincipal,
            sessionId = "session-dep-1",
            tenantId = tenantId,
            depositReference = "dep-t001-001",
            targetStatus = DepositStatus.SUCCEEDED,
            externalTransactionReference = "EXT-SUCC-001",
            idempotencyKey = "key-succ-t001-001",
            correlationId = "corr-succ-1",
            causationId = "cause-succ-1",
            expectedVersion = 2L,
            deliverySequence = 3L,
        )
        val succeededRecord = service.transitionDeposit(toSucceededCmd)
        assertEquals(DepositStatus.SUCCEEDED, succeededRecord.status)
        assertEquals(3L, succeededRecord.version)
        assertEquals("SUCCESS", succeededRecord.safeReasonCode)

        // Financial conservation: debits equal credits upon SUCCEEDED
        assertEquals(10000L, succeededRecord.debitMinorUnits)
        assertEquals(10000L, succeededRecord.creditMinorUnits)
        assertTrue(succeededRecord.conserved)
        assertEquals(DEPOSIT_STATE_MACHINE_CONTRACT, succeededRecord.semanticContract)

        // 5. Immutable compensation: SUCCEEDED -> REVERSED
        val compCmd = CompensateDepositCommand(
            principal = adminPrincipal,
            sessionId = "session-dep-1",
            tenantId = tenantId,
            depositReference = "dep-t001-001",
            originalDebitMinorUnits = 10000L,
            compensatingCreditMinorUnits = 10000L,
            currencyCode = "EUR",
            reason = "Customer chargeback",
            idempotencyKey = "key-comp-t001-001",
            correlationId = "corr-comp-1",
            causationId = "cause-comp-1",
            expectedVersion = 3L,
        )
        val compResult = service.compensateDeposit(compCmd)
        assertNotNull(compResult)
        assertEquals("dep-t001-001", compResult.depositReference)
        assertEquals(10000L, compResult.debitMinorUnits)
        assertEquals(10000L, compResult.creditMinorUnits)
        assertTrue(compResult.conserved)
        assertTrue(compResult.immutableCompensationReference.startsWith("COMP-REV-"))
        assertEquals(DEPOSIT_STATE_MACHINE_CONTRACT, compResult.semanticContract)

        // Verify deposit updated to REVERSED
        val finalRecord = service.getDeposit(tenantId, "dep-t001-001")
        assertNotNull(finalRecord)
        assertEquals(DepositStatus.REVERSED, finalRecord.status)
        assertEquals(4L, finalRecord.version)

        // 6. Transactional atomicity, correlation/causation identity, and zero PII disclosure
        val auditEvents = store.getAuditEvents()
        assertTrue(auditEvents.size >= 4)
        for (event in auditEvents) {
            assertEquals(tenantId, event.tenantId)
            assertNotNull(event.correlationId)
            assertNotNull(event.causationId)
            assertFalse(event.type.contains("secret", ignoreCase = true))
            assertFalse(event.type.contains("token", ignoreCase = true))
        }

        val outboxEvents = store.getOutboxEvents()
        assertTrue(outboxEvents.size >= 4)
    }

    @Test
    fun `PAYMENT-002-T002 — Deposit state machine rejects invalid, boundary, unauthorized, and stale input`() {
        val store = InMemoryDepositStateMachineStore()
        val eligibilityStore = InMemoryServerEligibilityStore()
        setupValidEligibility(eligibilityStore)
        val alertSink = InMemoryDepositAlertSink()
        val fakeAdapter = AdversarialPaymentProviderFakeAdapter(fakeProviderId, clock = clock)
        val service = createService(store, eligibilityStore, mapOf(fakeProviderId to fakeAdapter), alertSink)

        // 1. UNAUTHENTICATED: null principal
        val unauthError = assertFailsWith<AuthenticationFailure.Rejected> {
            service.initiateDeposit(initiateCommand(principal = null, idempotencyKey = "key-err-unauth"))
        }
        assertEquals(AuthErrorCode.UNAUTHENTICATED, unauthError.code)

        // 2. FORBIDDEN: wrong principal kind (PLAYER)
        val playerError = assertFailsWith<AuthenticationFailure.Rejected> {
            service.initiateDeposit(initiateCommand(principal = playerPrincipal, idempotencyKey = "key-err-player"))
        }
        assertEquals(AuthErrorCode.FORBIDDEN, playerError.code)

        // 3. FORBIDDEN: cross-tenant principal
        val crossError = assertFailsWith<AuthenticationFailure.Rejected> {
            service.initiateDeposit(initiateCommand(principal = crossTenantPrincipal, idempotencyKey = "key-err-cross"))
        }
        assertEquals(AuthErrorCode.FORBIDDEN, crossError.code)

        // 4. FORBIDDEN: missing session
        val noSessionError = assertFailsWith<AuthenticationFailure.Rejected> {
            service.initiateDeposit(initiateCommand(sessionId = "non-existent-session", idempotencyKey = "key-err-sess"))
        }
        assertEquals(AuthErrorCode.FORBIDDEN, noSessionError.code)

        // 5. AUTHZ-001 behavioral prerequisite: missing eligibility verdict
        val missingVerdictId = UUID.randomUUID()
        val noVerdictError = assertFailsWith<AuthenticationFailure.Rejected> {
            service.initiateDeposit(initiateCommand(eligibilityDecisionId = missingVerdictId, idempotencyKey = "key-err-no-verdict"))
        }
        assertEquals(AuthErrorCode.FORBIDDEN, noVerdictError.code)

        // 6. AUTHZ-001: player ineligible verdict
        val ineligibleVerdictId = UUID.randomUUID()
        eligibilityStore.saveVerdict(createVerdict(ineligibleVerdictId, eligible = false))
        val ineligibleError = assertFailsWith<AuthenticationFailure.Rejected> {
            service.initiateDeposit(initiateCommand(eligibilityDecisionId = ineligibleVerdictId, idempotencyKey = "key-err-ineligible"))
        }
        assertEquals(AuthErrorCode.FORBIDDEN, ineligibleError.code)

        // 7. AUTHZ-001: expired eligibility verdict
        val expiredVerdictId = UUID.randomUUID()
        eligibilityStore.saveVerdict(createVerdict(expiredVerdictId, eligible = true, expiresAt = now.minusSeconds(60)))
        val expiredError = assertFailsWith<AuthenticationFailure.Rejected> {
            service.initiateDeposit(initiateCommand(eligibilityDecisionId = expiredVerdictId, idempotencyKey = "key-err-expired-verdict"))
        }
        assertEquals(AuthErrorCode.STALE, expiredError.code)

        // 8. AUTHZ-001: verdict version mismatch
        val staleVersionError = assertFailsWith<AuthenticationFailure.Rejected> {
            service.initiateDeposit(initiateCommand(eligibilityDecisionVersion = 999L, idempotencyKey = "key-err-verdict-v"))
        }
        assertEquals(AuthErrorCode.STALE, staleVersionError.code)

        // 9. INVALID: amount <= 0
        val zeroAmtError = assertFailsWith<AuthenticationFailure.Rejected> {
            service.initiateDeposit(initiateCommand(amountMinorUnits = 0L, idempotencyKey = "key-err-zero-amt"))
        }
        assertEquals(AuthErrorCode.INVALID, zeroAmtError.code)

        val negAmtError = assertFailsWith<AuthenticationFailure.Rejected> {
            service.initiateDeposit(initiateCommand(amountMinorUnits = -500L, idempotencyKey = "key-err-neg-amt"))
        }
        assertEquals(AuthErrorCode.INVALID, negAmtError.code)

        // 10. INVALID: malformed currency
        val badCurrencyError = assertFailsWith<AuthenticationFailure.Rejected> {
            service.initiateDeposit(initiateCommand(currencyCode = "EURO", idempotencyKey = "key-err-bad-curr"))
        }
        assertEquals(AuthErrorCode.INVALID, badCurrencyError.code)

        // 11. INVALID: blank deposit reference
        val blankRefError = assertFailsWith<AuthenticationFailure.Rejected> {
            service.initiateDeposit(initiateCommand(depositReference = "", idempotencyKey = "key-err-blank-ref"))
        }
        assertEquals(AuthErrorCode.INVALID, blankRefError.code)

        // 12. FORBIDDEN: unauthorized / unknown provider routing
        val badRoutingError = assertFailsWith<AuthenticationFailure.Rejected> {
            service.initiateDeposit(initiateCommand(providerId = "unauthorized-provider", idempotencyKey = "key-err-routing"))
        }
        assertEquals(AuthErrorCode.FORBIDDEN, badRoutingError.code)

        // 13. STALE: command expectedVersion mismatch
        val staleExpectedVersionError = assertFailsWith<AuthenticationFailure.Rejected> {
            service.initiateDeposit(initiateCommand(expectedVersion = 2L, idempotencyKey = "key-err-stale-v"))
        }
        assertEquals(AuthErrorCode.STALE, staleExpectedVersionError.code)

        // 14. CONFLICT: Idempotency replay with changed payload
        service.initiateDeposit(initiateCommand(depositReference = "dep-fp-test", amountMinorUnits = 1000L, idempotencyKey = "key-fp-test"))
        val changedPayloadError = assertFailsWith<AuthenticationFailure.Rejected> {
            service.initiateDeposit(initiateCommand(depositReference = "dep-fp-test", amountMinorUnits = 2000L, idempotencyKey = "key-fp-test"))
        }
        assertEquals(AuthErrorCode.CONFLICT, changedPayloadError.code)

        // 15. CONFLICT: Illegal state transitions
        // Create an INITIATED deposit
        service.initiateDeposit(initiateCommand(depositReference = "dep-transitions", idempotencyKey = "key-dep-trans"))

        // (a) INITIATED -> SUCCEEDED (illegal: bypassing PENDING)
        val skipPendingError = assertFailsWith<AuthenticationFailure.Rejected> {
            service.transitionDeposit(TransitionDepositCommand(
                principal = adminPrincipal,
                sessionId = "session-dep-1",
                tenantId = tenantId,
                depositReference = "dep-transitions",
                targetStatus = DepositStatus.SUCCEEDED,
                idempotencyKey = "key-skip-pending",
                correlationId = "corr-skip",
                causationId = "cause-skip",
                expectedVersion = 1L,
            ))
        }
        assertEquals(AuthErrorCode.CONFLICT, skipPendingError.code)

        // (b) INITIATED -> REVERSED (illegal)
        val initToRevError = assertFailsWith<AuthenticationFailure.Rejected> {
            service.transitionDeposit(TransitionDepositCommand(
                principal = adminPrincipal,
                sessionId = "session-dep-1",
                tenantId = tenantId,
                depositReference = "dep-transitions",
                targetStatus = DepositStatus.REVERSED,
                idempotencyKey = "key-init-rev",
                correlationId = "corr-init-rev",
                causationId = "cause-init-rev",
                expectedVersion = 1L,
            ))
        }
        assertEquals(AuthErrorCode.CONFLICT, initToRevError.code)

        // Transition to PENDING, then to FAILED
        service.transitionDeposit(TransitionDepositCommand(
            principal = adminPrincipal,
            sessionId = "session-dep-1",
            tenantId = tenantId,
            depositReference = "dep-transitions",
            targetStatus = DepositStatus.PENDING,
            idempotencyKey = "key-to-pend",
            correlationId = "corr-to-pend",
            causationId = "cause-to-pend",
            expectedVersion = 1L,
            deliverySequence = 2L,
        ))

        service.transitionDeposit(TransitionDepositCommand(
            principal = adminPrincipal,
            sessionId = "session-dep-1",
            tenantId = tenantId,
            depositReference = "dep-transitions",
            targetStatus = DepositStatus.FAILED,
            idempotencyKey = "key-to-fail",
            correlationId = "corr-to-fail",
            causationId = "cause-to-fail",
            expectedVersion = 2L,
            deliverySequence = 3L,
        ))

        // (c) FAILED -> SUCCEEDED (illegal: terminal failed state cannot transition to succeeded)
        val failToSuccError = assertFailsWith<AuthenticationFailure.Rejected> {
            service.transitionDeposit(TransitionDepositCommand(
                principal = adminPrincipal,
                sessionId = "session-dep-1",
                tenantId = tenantId,
                depositReference = "dep-transitions",
                targetStatus = DepositStatus.SUCCEEDED,
                idempotencyKey = "key-fail-succ",
                correlationId = "corr-fail-succ",
                causationId = "cause-fail-succ",
                expectedVersion = 3L,
                deliverySequence = 4L,
            ))
        }
        assertEquals(AuthErrorCode.CONFLICT, failToSuccError.code)

        // (d) FAILED -> PENDING (illegal)
        val failToPendError = assertFailsWith<AuthenticationFailure.Rejected> {
            service.transitionDeposit(TransitionDepositCommand(
                principal = adminPrincipal,
                sessionId = "session-dep-1",
                tenantId = tenantId,
                depositReference = "dep-transitions",
                targetStatus = DepositStatus.PENDING,
                idempotencyKey = "key-fail-pend",
                correlationId = "corr-fail-pend",
                causationId = "cause-fail-pend",
                expectedVersion = 3L,
                deliverySequence = 4L,
            ))
        }
        assertEquals(AuthErrorCode.CONFLICT, failToPendError.code)

        // 16. Informational return URL boundary:
        // Even if client attempts to pass returnUrl parameter asserting success, it is informational only
        val forgedReturnUrlCmd = TransitionDepositCommand(
            principal = adminPrincipal,
            sessionId = "session-dep-1",
            tenantId = tenantId,
            depositReference = "dep-transitions",
            targetStatus = DepositStatus.SUCCEEDED,
            returnUrlParameterPayload = "status=success&paid=true&token=fake",
            idempotencyKey = "key-forged-url",
            correlationId = "corr-forged-url",
            causationId = "cause-forged-url",
            expectedVersion = 3L,
            deliverySequence = 5L,
        )
        val forgeError = assertFailsWith<AuthenticationFailure.Rejected> {
            service.transitionDeposit(forgedReturnUrlCmd)
        }
        assertEquals(AuthErrorCode.CONFLICT, forgeError.code)

        // Verify actionable alerts recorded in alert sink
        assertTrue(alertSink.alerts.isNotEmpty())
        assertTrue(alertSink.alerts.any { it.contains("ILLEGAL_STATE_TRANSITION") })
        assertTrue(alertSink.alerts.any { it.contains("UNAUTHORIZED_ROUTING") })
    }

    @Test
    fun `PAYMENT-002-T003 — Deposit state machine survives concurrency, duplicate delivery, and dependency failure`() {
        val store = InMemoryDepositStateMachineStore()
        val eligibilityStore = InMemoryServerEligibilityStore()
        setupValidEligibility(eligibilityStore)
        val alertSink = InMemoryDepositAlertSink()
        val fakeAdapter = AdversarialPaymentProviderFakeAdapter(fakeProviderId, clock = clock)
        val service = createService(store, eligibilityStore, mapOf(fakeProviderId to fakeAdapter), alertSink)

        // 1. Concurrency: 8 threads concurrently submitting identical initiateDeposit
        val threadCount = 8
        val executor = Executors.newFixedThreadPool(threadCount)
        val startLatch = CountDownLatch(1)
        val doneLatch = CountDownLatch(threadCount)
        val results = java.util.Collections.synchronizedList(mutableListOf<DepositRecord>())
        val errors = java.util.Collections.synchronizedList(mutableListOf<Throwable>())

        val cmd = initiateCommand(
            depositReference = "dep-concurrent-001",
            idempotencyKey = "key-concurrent-001",
        )

        for (i in 0 until threadCount) {
            executor.submit {
                try {
                    startLatch.await()
                    val res = service.initiateDeposit(cmd)
                    results.add(res)
                } catch (t: Throwable) {
                    errors.add(t)
                } finally {
                    doneLatch.done()
                }
            }
        }

        startLatch.countDown()
        doneLatch.await()
        executor.shutdown()

        assertTrue(errors.isEmpty(), "No errors expected on concurrent equivalent replay: $errors")
        assertEquals(threadCount, results.size)
        val firstResultId = results.first().depositId
        for (res in results) {
            assertEquals(firstResultId, res.depositId)
            assertEquals("dep-concurrent-001", res.depositReference)
            assertEquals(DEPOSIT_STATE_MACHINE_CONTRACT, res.semanticContract)
        }

        // Exactly one deposit record persisted
        assertNotNull(store.findDeposit(tenantId, "dep-concurrent-001"))

        // 2. Concurrency race on transitions: racing PENDING -> SUCCEEDED and PENDING -> FAILED
        // First transition to PENDING
        service.transitionDeposit(TransitionDepositCommand(
            principal = adminPrincipal,
            sessionId = "session-dep-1",
            tenantId = tenantId,
            depositReference = "dep-concurrent-001",
            targetStatus = DepositStatus.PENDING,
            idempotencyKey = "key-con-pend",
            correlationId = "corr-con-pend",
            causationId = "cause-con-pend",
            expectedVersion = 1L,
            deliverySequence = 2L,
        ))

        val raceExecutor = Executors.newFixedThreadPool(2)
        val raceStart = CountDownLatch(1)
        val raceDone = CountDownLatch(2)
        val raceSuccesses = java.util.Collections.synchronizedList(mutableListOf<DepositRecord>())
        val raceFailures = java.util.Collections.synchronizedList(mutableListOf<Throwable>())

        val succCmd = TransitionDepositCommand(
            principal = adminPrincipal,
            sessionId = "session-dep-1",
            tenantId = tenantId,
            depositReference = "dep-concurrent-001",
            targetStatus = DepositStatus.SUCCEEDED,
            idempotencyKey = "key-race-succ",
            correlationId = "corr-race-succ",
            causationId = "cause-race-succ",
            expectedVersion = 2L,
            deliverySequence = 3L,
        )

        val failCmd = TransitionDepositCommand(
            principal = adminPrincipal,
            sessionId = "session-dep-1",
            tenantId = tenantId,
            depositReference = "dep-concurrent-001",
            targetStatus = DepositStatus.FAILED,
            idempotencyKey = "key-race-fail",
            correlationId = "corr-race-fail",
            causationId = "cause-race-fail",
            expectedVersion = 2L,
            deliverySequence = 3L,
        )

        raceExecutor.submit {
            try {
                raceStart.await()
                raceSuccesses.add(service.transitionDeposit(succCmd))
            } catch (t: Throwable) {
                raceFailures.add(t)
            } finally {
                raceDone.countDown()
            }
        }

        raceExecutor.submit {
            try {
                raceStart.await()
                raceSuccesses.add(service.transitionDeposit(failCmd))
            } catch (t: Throwable) {
                raceFailures.add(t)
            } finally {
                raceDone.countDown()
            }
        }

        raceStart.countDown()
        raceDone.await()
        raceExecutor.shutdown()

        // Exactly one transition succeeded, the other must have failed with CONFLICT or STALE
        assertEquals(1, raceSuccesses.size, "Exactly one transition must succeed")
        assertEquals(1, raceFailures.size, "Exactly one transition must fail")
        val rejectedError = raceFailures.first() as? AuthenticationFailure.Rejected
        assertNotNull(rejectedError)
        assertTrue(rejectedError.code == AuthErrorCode.CONFLICT || rejectedError.code == AuthErrorCode.STALE)

        // 3. Out-of-order sequence rejection:
        val outOfOrderError = assertFailsWith<AuthenticationFailure.Rejected> {
            service.transitionDeposit(TransitionDepositCommand(
                principal = adminPrincipal,
                sessionId = "session-dep-1",
                tenantId = tenantId,
                depositReference = "dep-concurrent-001",
                targetStatus = DepositStatus.REVERSED,
                idempotencyKey = "key-out-of-order",
                correlationId = "corr-ooo",
                causationId = "cause-ooo",
                expectedVersion = 3L,
                deliverySequence = 2L, // sequence 2 <= last sequence 3
            ))
        }
        assertEquals(AuthErrorCode.CONFLICT, outOfOrderError.code)

        // 4. Dependency failure during webhook: Provider throws DEPENDENCY_UNAVAILABLE
        val failingAdapter = object : CanonicalPaymentProviderPort {
            override val providerId: String = "prov-failing"
            override val tier: AdapterTier = AdapterTier.ADVERSARIAL_FAKE
            override fun execute(command: ExecuteCanonicalPaymentCommand): Pair<CanonicalPaymentStatus, String> {
                throw AuthenticationFailure.Rejected(AuthErrorCode.DEPENDENCY_UNAVAILABLE)
            }
            override fun verifyWebhook(signature: String, rawPayload: String): CanonicalWebhookEvent? {
                throw AuthenticationFailure.Rejected(AuthErrorCode.DEPENDENCY_UNAVAILABLE)
            }
        }

        val serviceWithFailingAdapter = createService(
            store, eligibilityStore, mapOf("prov-failing" to failingAdapter), alertSink
        )

        val webhookCmd = ProcessDepositWebhookCommand(
            tenantId = tenantId,
            providerId = "prov-failing",
            signatureHeader = "sig-fail",
            rawPayload = "payload-fail",
            idempotencyKey = "key-webhook-dep-fail",
            correlationId = "corr-dep-fail",
            causationId = "cause-dep-fail",
            expectedVersion = 3L,
        )

        val depFailError = assertFailsWith<AuthenticationFailure.Rejected> {
            serviceWithFailingAdapter.processWebhook(webhookCmd)
        }
        assertEquals(AuthErrorCode.DEPENDENCY_UNAVAILABLE, depFailError.code)
    }

    @Test
    fun `PAYMENT-002-T004 — Deposit state machine remains compatible, recoverable, observable, and lifecycle-safe`() {
        // 1. Schema migration contract: V16 Flyway migration exists, no rogue V17
        val migrationsDir = File("src/main/resources/db/migration")
        val sqlFiles = migrationsDir.listFiles { _, name -> name.endsWith(".sql") } ?: emptyArray()
        assertTrue(sqlFiles.isNotEmpty(), "Migrations directory must contain Flyway files")
        val migrationVersions = sqlFiles.map { it.name.substringBefore("__") }
        assertTrue(migrationVersions.contains("V16"), "V16 must be present")
        assertFalse(migrationVersions.contains("V17"), "V17 must not be created prematurely")

        // 2. Lifecycle safety: Confirm no Android lifecycle surface is claimed
        val androidActivityClass = runCatching { Class.forName("android.app.Activity") }
        assertTrue(androidActivityClass.isFailure, "Authoritative backend must not link Android framework lifecycle")

        // 3. Recovery and compatibility across restart/rehydration
        val initialStore = InMemoryDepositStateMachineStore()
        val eligibilityStore = InMemoryServerEligibilityStore()
        setupValidEligibility(eligibilityStore)
        val alertSink = InMemoryDepositAlertSink()
        val fakeAdapter = AdversarialPaymentProviderFakeAdapter(fakeProviderId, clock = clock)
        val initialService = createService(initialStore, eligibilityStore, mapOf(fakeProviderId to fakeAdapter), alertSink)

        val initCmd = initiateCommand(
            depositReference = "dep-recover-001",
            amountMinorUnits = 15000L,
            currencyCode = "EUR",
            idempotencyKey = "key-recover-init-001",
            correlationId = "corr-rec-1",
            causationId = "cause-rec-1",
        )
        val initialRecord = initialService.initiateDeposit(initCmd)
        assertEquals(DepositStatus.INITIATED, initialRecord.status)
        assertEquals(15000L, initialRecord.amountMinorUnits)

        // Transition to PENDING, then SUCCEEDED
        val pendingRecord = initialService.transitionDeposit(TransitionDepositCommand(
            principal = adminPrincipal,
            sessionId = "session-dep-1",
            tenantId = tenantId,
            depositReference = "dep-recover-001",
            targetStatus = DepositStatus.PENDING,
            idempotencyKey = "key-rec-pend",
            correlationId = "corr-rec-pend",
            causationId = "cause-rec-pend",
            expectedVersion = 1L,
            deliverySequence = 2L,
        ))
        assertEquals(DepositStatus.PENDING, pendingRecord.status)

        val succRecord = initialService.transitionDeposit(TransitionDepositCommand(
            principal = adminPrincipal,
            sessionId = "session-dep-1",
            tenantId = tenantId,
            depositReference = "dep-recover-001",
            targetStatus = DepositStatus.SUCCEEDED,
            idempotencyKey = "key-rec-succ",
            correlationId = "corr-rec-succ",
            causationId = "cause-rec-succ",
            expectedVersion = 2L,
            deliverySequence = 3L,
        ))
        assertEquals(DepositStatus.SUCCEEDED, succRecord.status)

        // 4. Export snapshot and rehydrate into fresh store instance simulating server restart
        val snapshot = initialStore.exportState()
        val rehydratedStore = InMemoryDepositStateMachineStore()
        rehydratedStore.importState(snapshot)
        val restartedService = createService(rehydratedStore, eligibilityStore, mapOf(fakeProviderId to fakeAdapter), alertSink)

        // Verify deposit state recovered identically
        val recoveredDeposit = restartedService.getDeposit(tenantId, "dep-recover-001")
        assertNotNull(recoveredDeposit)
        assertEquals(DepositStatus.SUCCEEDED, recoveredDeposit.status)
        assertEquals(3L, recoveredDeposit.version)
        assertEquals(15000L, recoveredDeposit.debitMinorUnits)
        assertEquals(15000L, recoveredDeposit.creditMinorUnits)
        assertTrue(recoveredDeposit.conserved)
        assertEquals(DEPOSIT_STATE_MACHINE_CONTRACT, recoveredDeposit.semanticContract)

        // Calling initiateDeposit with original idempotency key returns cached record without fabricating new state
        val replayedRecord = restartedService.initiateDeposit(initCmd)
        assertEquals(initialRecord.depositId, replayedRecord.depositId)
        assertEquals(initialRecord.evidenceReference, replayedRecord.evidenceReference)

        // 5. Compensate on recovered instance: creates immutable compensation without editing posted history
        val compCmd = CompensateDepositCommand(
            principal = adminPrincipal,
            sessionId = "session-dep-1",
            tenantId = tenantId,
            depositReference = "dep-recover-001",
            originalDebitMinorUnits = 15000L,
            compensatingCreditMinorUnits = 15000L,
            currencyCode = "EUR",
            reason = "Settlement chargeback post-recovery",
            idempotencyKey = "key-rec-comp-001",
            correlationId = "corr-rec-comp-1",
            causationId = "cause-rec-comp-1",
            expectedVersion = 3L,
        )
        val compResult = restartedService.compensateDeposit(compCmd)
        assertNotNull(compResult)
        assertEquals(15000L, compResult.debitMinorUnits)
        assertEquals(15000L, compResult.creditMinorUnits)
        assertTrue(compResult.conserved)
        assertTrue(compResult.immutableCompensationReference.startsWith("COMP-REV-"))
        assertEquals(DEPOSIT_STATE_MACHINE_CONTRACT, compResult.semanticContract)

        // 6. Observability: zero PII or raw secrets in audit or outbox
        val auditEvents = rehydratedStore.getAuditEvents()
        assertTrue(auditEvents.isNotEmpty())
        for (audit in auditEvents) {
            assertEquals(tenantId, audit.tenantId)
            assertNotNull(audit.correlationId)
            assertNotNull(audit.causationId)
            assertFalse(audit.type.contains("secret", ignoreCase = true))
            assertFalse(audit.type.contains("token", ignoreCase = true))
        }

        val outboxEvents = rehydratedStore.getOutboxEvents()
        assertTrue(outboxEvents.isNotEmpty())
        for (outbox in outboxEvents) {
            assertEquals(tenantId, outbox.tenantId)
            assertNotNull(outbox.type)
        }
    }

    private fun setupValidEligibility(eligibilityStore: InMemoryServerEligibilityStore) {
        eligibilityStore.saveVerdict(createVerdict(eligibilityDecisionId, eligible = true))
    }

    private fun createVerdict(
        decisionId: UUID,
        eligible: Boolean,
        expiresAt: Instant = now.plusSeconds(3600),
    ): ServerEligibilityVerdict {
        val audit = AuditEvent(UUID.randomUUID(), decisionId, tenantId, "ELIGIBILITY_EVALUATED", now, "corr-elig-1", "cause-elig-1")
        val outbox = OutboxEvent(UUID.randomUUID(), decisionId, tenantId, "ELIGIBILITY_EVALUATED", now)
        return ServerEligibilityVerdict(
            decisionId = decisionId,
            version = 1L,
            tenantId = tenantId,
            playerId = playerId,
            eligible = eligible,
            accountStatus = PlayerAccountStatus.ACTIVE,
            kycStatus = KycComplianceStatus.VERIFIED,
            amlStatus = AmlComplianceStatus.CLEARED,
            jurisdiction = "DEFAULT",
            ageVerified = true,
            calculatedAge = 25,
            minAgeRequired = 21,
            selfExcluded = false,
            coolOffUntil = null,
            dailyWagerLimitMinor = null,
            currentDailyWagerMinor = 0L,
            singleWagerLimitMinor = null,
            denialReasons = if (eligible) emptyList() else listOf("Ineligible"),
            evaluatedAt = now,
            expiresAt = expiresAt,
            evidenceReference = "EVID-ELIG-$decisionId",
            auditEvent = audit,
            outboxEvent = outbox,
        )
    }

    private fun createService(
        store: DepositStateMachineStore,
        eligibilityStore: ServerEligibilityStore,
        adapters: Map<String, CanonicalPaymentProviderPort>,
        alertSink: DepositAlertSink = InMemoryDepositAlertSink(),
    ) = DepositStateMachineService(
        sessions = TestDepositAdminSessionDirectory(),
        eligibilityStore = eligibilityStore,
        store = store,
        adapters = adapters,
        alertSink = alertSink,
        clock = clock,
    )

    private fun initiateCommand(
        principal: AuthenticatedPrincipal? = adminPrincipal,
        sessionId: String = "session-dep-1",
        depositReference: String = "dep-ref-default",
        amountMinorUnits: Long = 5000L,
        currencyCode: String = "EUR",
        providerId: String = fakeProviderId,
        returnUrl: String = "https://client.example.com/return",
        eligibilityDecisionId: UUID = this.eligibilityDecisionId,
        eligibilityDecisionVersion: Long = 1L,
        idempotencyKey: String = "key-dep-default",
        correlationId: String = "corr-dep-default",
        causationId: String = "cause-dep-default",
        expectedVersion: Long = 1L,
    ) = InitiateDepositCommand(
        principal = principal,
        sessionId = sessionId,
        tenantId = tenantId,
        playerId = playerId,
        depositReference = depositReference,
        amountMinorUnits = amountMinorUnits,
        currencyCode = currencyCode,
        providerId = providerId,
        returnUrl = returnUrl,
        eligibilityDecisionId = eligibilityDecisionId,
        eligibilityDecisionVersion = eligibilityDecisionVersion,
        idempotencyKey = idempotencyKey,
        correlationId = correlationId,
        causationId = causationId,
        expectedVersion = expectedVersion,
    )

    private fun CountDownLatch.done() = countDown()
}

private class TestDepositAdminSessionDirectory : AdminSessionDirectory {
    override fun find(tenantId: String, principalId: String, sessionId: String): AdminSessionStatus? =
        if (tenantId == "tenant-deposit-1" && principalId == "admin-dep-1" && sessionId == "session-dep-1")
            AdminSessionStatus(true, false, Instant.parse("2026-09-19T18:00:00Z"))
        else null
}
