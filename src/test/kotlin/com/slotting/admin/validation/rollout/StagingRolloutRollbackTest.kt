package com.slotting.admin.validation.rollout

import com.slotting.admin.auth.AdminRole
import com.slotting.admin.auth.AuthenticatedPrincipal
import com.slotting.admin.auth.PrincipalKind
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertNotNull
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.DisplayName
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.assertThrows
import java.time.Instant
import java.time.temporal.ChronoUnit
import java.util.UUID
import java.util.concurrent.Callable
import java.util.concurrent.Executors

class StagingRolloutRollbackTest {

    private lateinit var service: StagingRolloutRollbackService
    private lateinit var evidenceStore: InMemoryRolloutEvidenceStore
    private lateinit var alertSink: InMemoryRolloutAlertSink
    private lateinit var observability: InMemoryRolloutObservability

    private val tenantId = "tenant-rollout-ops"
    private val securityPrincipal = AuthenticatedPrincipal(
        id = "security-officer-rollout-1",
        kind = PrincipalKind.ADMIN,
        roles = setOf(AdminRole.SECURITY),
        tenantId = tenantId
    )
    private val superAdminPrincipal = AuthenticatedPrincipal(
        id = "superadmin-rollout-1",
        kind = PrincipalKind.ADMIN,
        roles = setOf(AdminRole.SUPER_ADMIN),
        tenantId = tenantId
    )
    private val supportPrincipal = AuthenticatedPrincipal(
        id = "support-rollout-1",
        kind = PrincipalKind.ADMIN,
        roles = setOf(AdminRole.SUPPORT),
        tenantId = tenantId
    )

    private val now = Instant.now()
    private val validManifest = RolloutArtifactManifest(
        commitHash = "794dbc16dc6b882f3102574f241fee436e9d9987",
        artifactDigest = "sha256:rollout-candidate-v1",
        configurationVersion = "1.0.0",
        environment = "production-launch-rollout",
        owner = "site-reliability-engineering-director",
        reviewer = "principal-security-auditor",
        signedAt = now.minus(2, ChronoUnit.HOURS),
        expiry = now.plus(48, ChronoUnit.HOURS)
    )

    private val validSmokeTest = SmokeTestResult(
        smokeId = "smoke-suite-run-101",
        suitesExecuted = listOf("AUTH_SMOKE", "DEPOSIT_SMOKE", "WAGER_SMOKE", "WITHDRAWAL_SMOKE"),
        isPassed = true,
        latencyP99Ms = 120L,
        errorCount = 0
    )

    private val validOnCallDrill = OnCallPageDrillRecord(
        drillId = "page-drill-run-501",
        pagerService = "PagerDuty High-Urgency Service",
        primaryResponder = "primary-oncall-sre@slotting.internal",
        secondaryResponder = "secondary-oncall-dev@slotting.internal",
        pagedAt = now.minus(15, ChronoUnit.MINUTES),
        acknowledgedAt = now.minus(12, ChronoUnit.MINUTES),
        responseSlaSeconds = 180L, // 180s <= 300s SLA
        isSlaMet = true,
        runbookRef = "RUNBOOK-INC-ROLLOUT-001"
    )

    @BeforeEach
    fun setUp() {
        evidenceStore = InMemoryRolloutEvidenceStore()
        alertSink = InMemoryRolloutAlertSink()
        observability = InMemoryRolloutObservability()
        service = StagingRolloutRollbackService(
            evidenceStore = evidenceStore,
            alertSink = alertSink,
            observability = observability
        )
    }

    private fun createValidCommand(
        idempotencyKey: String = UUID.randomUUID().toString(),
        targetCohort: RolloutCohortStage = RolloutCohortStage.GENERAL_AVAILABILITY_100,
        smokeTest: SmokeTestResult = validSmokeTest,
        onCallDrill: OnCallPageDrillRecord = validOnCallDrill,
        triggerRollbackScenario: Boolean = false,
        injectedFaults: Set<StopCriteriaType> = emptySet()
    ): RunRolloutValidationCommand {
        return RunRolloutValidationCommand(
            principal = superAdminPrincipal,
            tenantId = tenantId,
            manifest = validManifest,
            targetCohort = targetCohort,
            smokeTest = smokeTest,
            onCallDrill = onCallDrill,
            triggerRollbackScenario = triggerRollbackScenario,
            injectedFaults = injectedFaults,
            idempotencyKey = idempotencyKey,
            correlationId = "corr-${UUID.randomUUID()}",
            causationId = "caus-${UUID.randomUUID()}"
        )
    }

    @Test
    @DisplayName("SYS-008-T001 — Staging/rollout/rollback/on-call produces the required authoritative outcome")
    fun testSYS008T001PrimaryAuthoritativeOutcome() {
        // 1. Normal Rollout Promotion to GA
        val rolloutCmd = createValidCommand(targetCohort = RolloutCohortStage.GENERAL_AVAILABILITY_100)
        val rolloutReport = service.runRolloutValidation(rolloutCmd)

        assertEquals(
            "Automatic/manual stop criteria objective; rollback preserves financial processing/reconciliation.",
            rolloutReport.semanticContract
        )
        assertEquals(RolloutState.PROMOTED_TO_GA, rolloutReport.currentState)
        assertTrue(rolloutReport.isContractSatisfied)
        assertTrue(rolloutReport.smokeTest.isPassed)
        assertTrue(rolloutReport.onCallDrill.isSlaMet)
        assertFalse(rolloutReport.stopCriteria.isStopTriggered)
        assertEquals(0L, rolloutReport.financialEvidence.netImbalanceMinor)
        assertFalse(rolloutReport.financialEvidence.postedHistoryModified)
        assertEquals("RECONCILED_MATCH", rolloutReport.financialEvidence.reconciliationStatus)

        // 2. Clean Rollback Scenario preserving posted financial history
        val rollbackCmd = createValidCommand(
            idempotencyKey = "rollback-test-${UUID.randomUUID()}",
            triggerRollbackScenario = true
        )
        val rollbackReport = service.runRolloutValidation(rollbackCmd)

        assertEquals(RolloutState.ROLLBACK_COMPLETED_RECONCILED, rollbackReport.currentState)
        assertTrue(rollbackReport.isContractSatisfied)
        assertEquals(0L, rollbackReport.financialEvidence.netImbalanceMinor)
        assertFalse(rollbackReport.financialEvidence.postedHistoryModified)
        assertEquals("RECONCILED_MATCH", rollbackReport.financialEvidence.reconciliationStatus)

        // Strict Android boundary: presentation layer untrusted
        assertFalse(rolloutReport.hasAndroidLifecycleClaim)
        assertFalse(rolloutReport.hasAndroidDbImpact)
        assertFalse(rollbackReport.hasAndroidLifecycleClaim)
        assertFalse(rollbackReport.hasAndroidDbImpact)

        // Correlated evidence reference
        assertNotNull(rolloutReport.evidenceReference)
        assertEquals(rolloutCmd.correlationId, rolloutReport.correlationId)
        assertEquals(rolloutCmd.causationId, rolloutReport.causationId)

        // Saved in evidence store
        val stored = evidenceStore.getReport(rolloutReport.rolloutId)
        assertNotNull(stored)
        assertEquals(rolloutReport.rolloutId, stored!!.rolloutId)
    }

    @Test
    @DisplayName("SYS-008-T002 — Staging/rollout/rollback/on-call rejects invalid, boundary, unauthorized, and stale input")
    fun testSYS008T002RejectsInvalidBoundaryUnauthorizedInput() {
        val validCmd = createValidCommand()

        // 1. Unauthenticated principal
        val unauthCmd = validCmd.copy(principal = null)
        assertThrows<UnauthorizedRolloutException> {
            service.runRolloutValidation(unauthCmd)
        }

        // 2. Insufficient permissions (SUPPORT cannot run staging rollout validation)
        val supportCmd = validCmd.copy(principal = supportPrincipal)
        assertThrows<UnauthorizedRolloutException> {
            service.runRolloutValidation(supportCmd)
        }

        // 3. Cross-tenant execution
        val crossTenantCmd = validCmd.copy(tenantId = "cross-tenant-rollout")
        assertThrows<UnauthorizedRolloutException> {
            service.runRolloutValidation(crossTenantCmd)
        }

        // 4. Blank input fields
        assertThrows<InvalidRolloutInputException> {
            service.runRolloutValidation(validCmd.copy(idempotencyKey = "   "))
        }
        assertThrows<InvalidRolloutInputException> {
            service.runRolloutValidation(validCmd.copy(correlationId = "   "))
        }
        assertThrows<InvalidRolloutInputException> {
            service.runRolloutValidation(validCmd.copy(causationId = "   "))
        }

        // 5. Expired manifest
        val expiredManifest = validManifest.copy(expiry = now.minus(1, ChronoUnit.HOURS))
        assertThrows<InvalidRolloutManifestException> {
            service.runRolloutValidation(validCmd.copy(manifest = expiredManifest))
        }

        // 6. Smoke test failure must throw StopCriteriaBreachedException with exact text
        val failedSmoke = validSmokeTest.copy(isPassed = false, errorCount = 4)
        val smokeFailCmd = createValidCommand(smokeTest = failedSmoke)
        val exSmoke = assertThrows<StopCriteriaBreachedException> {
            service.runRolloutValidation(smokeFailCmd)
        }
        assertTrue(exSmoke.message!!.contains("smoke/rollback/page drill fails"))

        // 7. On-call page drill SLA breach (>300s) must throw
        val failedPageDrill = validOnCallDrill.copy(responseSlaSeconds = 420L, isSlaMet = false)
        val pageDrillFailCmd = createValidCommand(onCallDrill = failedPageDrill)
        val exPage = assertThrows<StopCriteriaBreachedException> {
            service.runRolloutValidation(pageDrillFailCmd)
        }
        assertTrue(exPage.message!!.contains("smoke/rollback/page drill fails"))

        // 8. Financial ledger imbalance / corrupted rollback must throw
        val imbalanceFaultCmd = createValidCommand(injectedFaults = setOf(StopCriteriaType.LEDGER_IMBALANCE))
        val exImbalance = assertThrows<StopCriteriaBreachedException> {
            service.runRolloutValidation(imbalanceFaultCmd)
        }
        assertTrue(exImbalance.message!!.contains("smoke/rollback/page drill fails"))

        // Verify alert emitted
        assertTrue(alertSink.getAlerts().any { it.message.contains("smoke/rollback/page drill fails") })
    }

    @Test
    @DisplayName("SYS-008-T003 — Staging/rollout/rollback/on-call survives concurrency, duplicate delivery, and dependency failure")
    fun testSYS008T003ConcurrencyIdempotencyDependencyFailure() {
        val idempotencyKey = "rollout-idem-${UUID.randomUUID()}"
        val cmd1 = createValidCommand(idempotencyKey = idempotencyKey)

        // 1. First execution succeeds
        val report1 = service.runRolloutValidation(cmd1)
        assertEquals(RolloutState.PROMOTED_TO_GA, report1.currentState)

        // 2. Duplicate delivery with identical payload returns exact same report
        val report2 = service.runRolloutValidation(cmd1)
        assertEquals(report1.rolloutId, report2.rolloutId)
        assertEquals(report1.evaluatedAt, report2.evaluatedAt)

        // 3. Changed-payload key reuse throws IdempotencyConflictException
        val conflictingCmd = cmd1.copy(
            targetCohort = RolloutCohortStage.CANARY_5_PERCENT
        )
        assertThrows<IdempotencyConflictException> {
            service.runRolloutValidation(conflictingCmd)
        }

        // 4. Dependency failure handling
        service.scenarioFaults["DEPENDENCY_FAILURE"] = "Simulated synthetic monitoring telemetry timeout"
        val depFailCmd = createValidCommand()
        val depEx = assertThrows<StagingRolloutValidationException> {
            service.runRolloutValidation(depFailCmd)
        }
        assertTrue(depEx.message!!.contains("Dependency failure"))
        assertTrue(alertSink.getAlerts().any { it.message.contains("Dependency failure") })
        service.scenarioFaults.remove("DEPENDENCY_FAILURE")

        // 5. Concurrency: multiple parallel requests handle cleanly
        val executor = Executors.newFixedThreadPool(4)
        val callables = (1..8).map { i ->
            Callable {
                val threadCmd = createValidCommand(idempotencyKey = "thread-idem-rollout-$i")
                service.runRolloutValidation(threadCmd)
            }
        }
        val futures = executor.invokeAll(callables)
        for (f in futures) {
            val r = f.get()
            assertEquals(RolloutState.PROMOTED_TO_GA, r.currentState)
            assertTrue(r.isContractSatisfied)
        }
        executor.shutdown()
    }

    @Test
    @DisplayName("SYS-008-T004 — Staging/rollout/rollback/on-call remains compatible, recoverable, observable, and lifecycle-safe")
    fun testSYS008T004LifecycleRecoveryObservability() {
        val cmd = createValidCommand()
        val report = service.runRolloutValidation(cmd)

        // Zero Android lifecycle surface
        assertFalse(report.hasAndroidLifecycleClaim)
        assertFalse(report.hasAndroidDbImpact)

        // Observability metrics recorded
        assertTrue(observability.getEvaluationsCount() > 0)
        assertTrue(observability.getTransitionsCount() > 0)

        // Immutable evidence binding
        assertEquals(validManifest.commitHash, report.manifest.commitHash)
        assertEquals(validManifest.artifactDigest, report.manifest.artifactDigest)
        assertEquals(validManifest.environment, report.manifest.environment)
        assertEquals(validManifest.owner, report.manifest.owner)
        assertEquals(validManifest.reviewer, report.manifest.reviewer)
        assertTrue(report.evidenceReference.startsWith("ev-rollout-"))
    }
}
