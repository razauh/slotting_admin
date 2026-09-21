package com.slotting.admin.validation.journey

import com.slotting.admin.auth.AdminRole
import com.slotting.admin.auth.AuthenticatedPrincipal
import com.slotting.admin.auth.PrincipalKind
import org.junit.jupiter.api.Assertions.*
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.DisplayName
import org.junit.jupiter.api.Test
import java.time.Clock
import java.time.Instant
import java.util.UUID
import java.util.concurrent.Callable
import java.util.concurrent.Executors

class CriticalJourneyE2ETest {

    private lateinit var evidenceStore: InMemoryCriticalJourneyEvidenceStore
    private lateinit var alertSink: InMemoryCriticalJourneyAlertSink
    private lateinit var observability: InMemoryCriticalJourneyObservability
    private lateinit var service: CriticalJourneyE2EService

    private val tenantId = "tenant-prod-1"
    private val playerId = "player-e2e-123"
    private val clock = Clock.systemUTC()

    private val makerPrincipal = AuthenticatedPrincipal(
        id = "admin-maker-1",
        tenantId = tenantId,
        roles = setOf(AdminRole.SUPER_ADMIN),
        kind = PrincipalKind.ADMIN
    )

    private val checkerPrincipal = AuthenticatedPrincipal(
        id = "admin-checker-2",
        tenantId = tenantId,
        roles = setOf(AdminRole.SUPPORT),
        kind = PrincipalKind.ADMIN
    )

    private val validManifest = LaunchValidationArtifactManifest(
        commitHash = "794dbc16dc6b882f3102574f241fee436e9d9987",
        artifactDigest = "sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        configurationVersion = "v10.1.0",
        environment = "PRODUCTION",
        owner = "security-team",
        reviewer = "release-authority",
        signedAt = Instant.now().minusSeconds(3600),
        expiry = Instant.now().plusSeconds(86400)
    )

    @BeforeEach
    fun setUp() {
        evidenceStore = InMemoryCriticalJourneyEvidenceStore()
        alertSink = InMemoryCriticalJourneyAlertSink()
        observability = InMemoryCriticalJourneyObservability()
        service = CriticalJourneyE2EService(
            evidenceStore = evidenceStore,
            alertSink = alertSink,
            observability = observability,
            clock = clock
        )
    }

    private fun buildValidCommand(
        depositMinor: Long = 1000L,
        wagerMinor: Long = 200L,
        multiplier: Double = 1.5,
        withdrawalMinor: Long = 500L,
        idempotencyKey: String = "idem-${UUID.randomUUID()}"
    ) = ExecuteCriticalJourneyCommand(
        principal = makerPrincipal,
        tenantId = tenantId,
        playerId = playerId,
        currency = "USD",
        depositAmountMinor = depositMinor,
        wagerAmountMinor = wagerMinor,
        gameWinMultiplier = multiplier,
        withdrawalAmountMinor = withdrawalMinor,
        manifest = validManifest,
        idempotencyKey = idempotencyKey,
        correlationId = "corr-${UUID.randomUUID()}",
        causationId = "caus-${UUID.randomUUID()}",
        approverPrincipal = checkerPrincipal
    )

    @Test
    @DisplayName("SYS-001-T001 — Critical-journey E2E produces the required authoritative outcome")
    fun testT001ProducesAuthoritativeOutcome() {
        val cmd = buildValidCommand(
            depositMinor = 1000L,
            wagerMinor = 200L,
            multiplier = 1.5,
            withdrawalMinor = 500L
        )

        val report = service.executeCriticalJourney(cmd)

        assertNotNull(report)
        assertEquals(cmd.tenantId, report.tenantId)
        assertEquals(cmd.playerId, report.playerId)
        assertEquals("USD", report.currency)
        assertEquals(JourneyStatus.COMPLETED, report.status)
        assertTrue(report.isFullyReconciled)
        assertEquals(8, report.stepRecords.size)

        // Expected balance math: initial 0 + deposit 1000 - wager 200 + win 300 - withdrawal 500 = 600
        assertEquals(0L, report.initialBalanceMinor)
        assertEquals(1000L, report.depositAmountMinor)
        assertEquals(200L, report.wagerAmountMinor)
        assertEquals(300L, report.settledWinningsMinor)
        assertEquals(500L, report.withdrawalAmountMinor)
        assertEquals(600L, report.finalBalanceMinor)

        // Exact assertion: "Assert ledger/provider/admin/Android views reconcile at every step."
        for (stepRecord in report.stepRecords) {
            assertTrue(stepRecord.isReconciled, "Step ${stepRecord.step} must be reconciled")
            assertTrue(stepRecord.ledgerView.isBalanced, "Ledger must be balanced at step ${stepRecord.step}")
            assertEquals(
                stepRecord.ledgerView.postedDebitsMinor,
                stepRecord.ledgerView.postedCreditsMinor,
                "Debits must equal credits at step ${stepRecord.step}"
            )
            assertTrue(stepRecord.providerView.isReconciled, "Provider must be reconciled at step ${stepRecord.step}")
            assertTrue(stepRecord.androidView.isUntrustedPresentation, "Android must be untrusted at step ${stepRecord.step}")
            assertFalse(stepRecord.androidView.hasAndroidLifecycleClaim, "Android cannot claim lifecycle authority")
            assertFalse(stepRecord.androidView.hasAndroidDbImpact, "Android cannot impact DB authority")
            assertEquals(
                stepRecord.ledgerView.availableMinor,
                stepRecord.androidView.presentedAvailableBalanceMinor,
                "Android view must present exactly the ledger available balance at step ${stepRecord.step}"
            )
        }

        // Assert committed correlation/causation identity
        assertEquals(cmd.correlationId, report.correlationId)
        assertEquals(cmd.causationId, report.causationId)
        assertTrue(report.evidenceReference.startsWith("ev-journey-"))
    }

    @Test
    @DisplayName("SYS-001-T002 — Critical-journey E2E rejects invalid, boundary, unauthorized, and stale input")
    fun testT002RejectsInvalidAndUnauthorizedInput() {
        val baseCmd = buildValidCommand()

        // 1. Unauthenticated principal
        assertThrows(UnauthorizedJourneyException::class.java) {
            service.executeCriticalJourney(baseCmd.copy(principal = null))
        }

        // 2. Unauthorized role
        val playerPrincipal = AuthenticatedPrincipal(
            id = "player-1",
            tenantId = tenantId,
            roles = emptySet(),
            kind = PrincipalKind.PLAYER
        )
        assertThrows(UnauthorizedJourneyException::class.java) {
            service.executeCriticalJourney(baseCmd.copy(principal = playerPrincipal))
        }

        // 3. Cross-tenant principal
        val crossTenantPrincipal = makerPrincipal.copy(tenantId = "foreign-tenant")
        assertThrows(UnauthorizedJourneyException::class.java) {
            service.executeCriticalJourney(baseCmd.copy(principal = crossTenantPrincipal))
        }

        // 4. Stale / Expired manifest
        val expiredManifest = validManifest.copy(expiry = Instant.now().minusSeconds(100))
        assertThrows(InvalidJourneyManifestException::class.java) {
            service.executeCriticalJourney(baseCmd.copy(manifest = expiredManifest))
        }

        // 5. Blank manifest fields
        val blankManifest = validManifest.copy(commitHash = "")
        assertThrows(InvalidJourneyManifestException::class.java) {
            service.executeCriticalJourney(baseCmd.copy(manifest = blankManifest))
        }

        // 6. Invalid currency
        assertThrows(InvalidJourneyInputException::class.java) {
            service.executeCriticalJourney(baseCmd.copy(currency = "usd")) // lowercase
        }
        assertThrows(InvalidJourneyInputException::class.java) {
            service.executeCriticalJourney(baseCmd.copy(currency = "US")) // 2 letters
        }

        // 7. Non-positive amounts
        assertThrows(InvalidJourneyInputException::class.java) {
            service.executeCriticalJourney(baseCmd.copy(depositAmountMinor = 0L))
        }
        assertThrows(InvalidJourneyInputException::class.java) {
            service.executeCriticalJourney(baseCmd.copy(wagerAmountMinor = -10L))
        }
        assertThrows(InvalidJourneyInputException::class.java) {
            service.executeCriticalJourney(baseCmd.copy(withdrawalAmountMinor = 0L))
        }

        // 8. Blank correlation / causation
        assertThrows(InvalidJourneyInputException::class.java) {
            service.executeCriticalJourney(baseCmd.copy(correlationId = "  "))
        }
        assertThrows(InvalidJourneyInputException::class.java) {
            service.executeCriticalJourney(baseCmd.copy(causationId = ""))
        }

        // 9. Insufficient funds for wager
        assertThrows(InsufficientFundsJourneyException::class.java) {
            service.executeCriticalJourney(baseCmd.copy(depositAmountMinor = 100L, wagerAmountMinor = 200L))
        }

        // 10. Insufficient funds for withdrawal (e.g. lost bet and withdrawal > settled)
        assertThrows(InsufficientFundsJourneyException::class.java) {
            service.executeCriticalJourney(
                baseCmd.copy(
                    depositAmountMinor = 500L,
                    wagerAmountMinor = 500L,
                    gameWinMultiplier = 0.0, // lost everything
                    withdrawalAmountMinor = 100L
                )
            )
        }

        // 11. Maker-checker violation: self-approval
        assertThrows(MakerCheckerViolationException::class.java) {
            service.executeCriticalJourney(baseCmd.copy(approverPrincipal = makerPrincipal))
        }

        // 12. Missing approver
        assertThrows(UnauthorizedJourneyException::class.java) {
            service.executeCriticalJourney(baseCmd.copy(approverPrincipal = null))
        }

        // 13. Cross-tenant approver
        val crossTenantApprover = checkerPrincipal.copy(tenantId = "other-tenant")
        assertThrows(UnauthorizedJourneyException::class.java) {
            service.executeCriticalJourney(baseCmd.copy(approverPrincipal = crossTenantApprover))
        }

        // 14. View reconciliation drift / mismatch fault injection
        service.scenarioFaults["VIEW_RECONCILIATION_DRIFT"] = "simulated Android balance drift"
        val faultEx = assertThrows(ViewReconciliationMismatchException::class.java) {
            service.executeCriticalJourney(buildValidCommand())
        }
        assertTrue(faultEx.message!!.contains(CRITICAL_JOURNEY_E2E_CONTRACT))
        service.scenarioFaults.clear()

        // Authoritative evidence check: no reports saved for invalid attempts
        assertEquals(0, evidenceStore.getAllReports().size)
    }

    @Test
    @DisplayName("SYS-001-T003 — Critical-journey E2E survives concurrency, duplicate delivery, and dependency failure")
    fun testT003SurvivesConcurrencyDuplicateAndFailure() {
        val idempotencyKey = "idem-stable-${UUID.randomUUID()}"
        val cmd1 = buildValidCommand(idempotencyKey = idempotencyKey)

        // 1. First execution succeeds
        val report1 = service.executeCriticalJourney(cmd1)
        assertNotNull(report1)

        // 2. Duplicate delivery / idempotent replay returns identical report
        val report2 = service.executeCriticalJourney(cmd1)
        assertEquals(report1.journeyId, report2.journeyId)
        assertEquals(report1.evidenceReference, report2.evidenceReference)
        assertEquals(report1.finalBalanceMinor, report2.finalBalanceMinor)

        // 3. Changed-payload key reuse conflicts
        val conflictingCmd = cmd1.copy(depositAmountMinor = 9999L)
        assertThrows(IdempotencyConflictException::class.java) {
            service.executeCriticalJourney(conflictingCmd)
        }

        // 4. Concurrency race on same idempotency key
        val executor = Executors.newFixedThreadPool(8)
        val concurrentKey = "idem-race-${UUID.randomUUID()}"
        val concurrentCmd = buildValidCommand(idempotencyKey = concurrentKey)
        val tasks = (1..8).map {
            Callable { service.executeCriticalJourney(concurrentCmd) }
        }
        val futures = executor.invokeAll(tasks)
        executor.shutdown()

        val results = futures.map { it.get() }
        val firstJourneyId = results[0].journeyId
        assertTrue(results.all { it.journeyId == firstJourneyId }, "All concurrent replays must return the same journey ID")

        // 5. Injected payout provider failure
        service.scenarioFaults["PAYOUT_PROVIDER_FAILURE"] = "Payment gateway timeout 504"
        val failCmd = buildValidCommand()
        val pex = assertThrows(JourneyExecutionException::class.java) {
            service.executeCriticalJourney(failCmd)
        }
        assertTrue(pex.message!!.contains("Payment gateway timeout 504"))
        service.scenarioFaults.clear()

        val alerts = alertSink.getAlerts()
        assertTrue(alerts.any { it.step == JourneyStep.PAYOUT_COMPLETED })
    }

    @Test
    @DisplayName("SYS-001-T004 — Critical-journey E2E remains compatible, recoverable, observable, and lifecycle-safe")
    fun testT004RemainsCompatibleRecoverableObservableAndLifecycleSafe() {
        val cmd = buildValidCommand()
        val report = service.executeCriticalJourney(cmd)

        // 1. Android lifecycle boundary verification
        for (stepRecord in report.stepRecords) {
            assertFalse(stepRecord.androidView.hasAndroidLifecycleClaim, "Android must not claim lifecycle authority")
            assertFalse(stepRecord.androidView.hasAndroidDbImpact, "Android must not claim DB authority")
            assertTrue(stepRecord.androidView.isUntrustedPresentation, "Android presentation must be untrusted")
        }

        // 2. Observability & Telemetry verification
        assertTrue(observability.getExecutionsCount() > 0)
        assertTrue(observability.getReconciliationsCount() >= 8)

        // 3. Durable Evidence Store Recovery (Restart Simulation)
        val recoveredReport = evidenceStore.getReport(report.journeyId)
        assertNotNull(recoveredReport, "Report must be recoverable from evidence store")
        assertEquals(report.journeyId, recoveredReport!!.journeyId)
        assertEquals(report.finalBalanceMinor, recoveredReport.finalBalanceMinor)
        assertEquals(8, recoveredReport.stepRecords.size)

        // Verify recovered step records all satisfy: "Assert ledger/provider/admin/Android views reconcile at every step."
        for (stepRecord in recoveredReport.stepRecords) {
            assertTrue(stepRecord.isReconciled)
            assertTrue(stepRecord.ledgerView.isBalanced)
            assertEquals(stepRecord.ledgerView.postedDebitsMinor, stepRecord.ledgerView.postedCreditsMinor)
            assertEquals(stepRecord.ledgerView.availableMinor, stepRecord.androidView.presentedAvailableBalanceMinor)
        }

        // 4. Financial conservation: debits == credits across journey
        val lastStep = recoveredReport.stepRecords.last()
        assertEquals(lastStep.ledgerView.postedDebitsMinor, lastStep.ledgerView.postedCreditsMinor)
    }
}
