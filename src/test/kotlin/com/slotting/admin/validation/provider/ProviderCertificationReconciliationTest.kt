package com.slotting.admin.validation.provider

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

class ProviderCertificationReconciliationTest {

    private lateinit var evidenceStore: InMemoryProviderCertificationEvidenceStore
    private lateinit var alertSink: InMemoryProviderCertificationAlertSink
    private lateinit var observability: InMemoryProviderCertificationObservability
    private lateinit var service: ProviderCertificationReconciliationService

    private val tenantId = "tenant-prod-1"
    private val providerId = "provider-gateway-alpha"
    private val clock = Clock.systemUTC()

    private val adminPrincipal = AuthenticatedPrincipal(
        id = "admin-cert-1",
        tenantId = tenantId,
        roles = setOf(AdminRole.SUPER_ADMIN),
        kind = PrincipalKind.ADMIN
    )

    private val validManifest = ProviderCertificationArtifactManifest(
        commitHash = "794dbc16dc6b882f3102574f241fee436e9d9987",
        artifactDigest = "sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        configurationVersion = "v10.2.0",
        environment = "PRODUCTION",
        owner = "provider-integration-authority",
        reviewer = "compliance-lead",
        signedAt = Instant.now().minusSeconds(3600),
        expiry = Instant.now().plusSeconds(86400)
    )

    @BeforeEach
    fun setUp() {
        evidenceStore = InMemoryProviderCertificationEvidenceStore()
        alertSink = InMemoryProviderCertificationAlertSink()
        observability = InMemoryProviderCertificationObservability()
        service = ProviderCertificationReconciliationService(
            evidenceStore = evidenceStore,
            alertSink = alertSink,
            observability = observability,
            clock = clock
        )
    }

    private fun buildValidCommand(
        targetCases: Set<ProviderCertificationCase> = ProviderCertificationCase.values().toSet(),
        idempotencyKey: String = "idem-${UUID.randomUUID()}"
    ) = RunProviderCertificationCommand(
        principal = adminPrincipal,
        tenantId = tenantId,
        providerId = providerId,
        manifest = validManifest,
        targetCases = targetCases,
        idempotencyKey = idempotencyKey,
        correlationId = "corr-${UUID.randomUUID()}",
        causationId = "caus-${UUID.randomUUID()}"
    )

    @Test
    @DisplayName("SYS-002-T001 — Provider certification/reconciliation produces the required authoritative outcome")
    fun testT001ProducesAuthoritativeOutcome() {
        val cmd = buildValidCommand()
        val report = service.runCertification(cmd)

        assertNotNull(report)
        assertEquals(cmd.tenantId, report.tenantId)
        assertEquals(cmd.providerId, report.providerId)
        assertTrue(report.isFullyCertified)
        assertTrue(report.debitsEqualCreditsPreserved)
        assertFalse(report.hasAndroidLifecycleClaim)
        assertFalse(report.hasAndroidDbImpact)

        // Exact semantic contract assertion:
        // "Duplicate/late/out-of-order/timeout/refund/rollback/chargeback evidence included."
        val expectedCases = setOf(
            ProviderCertificationCase.DUPLICATE,
            ProviderCertificationCase.LATE,
            ProviderCertificationCase.OUT_OF_ORDER,
            ProviderCertificationCase.TIMEOUT,
            ProviderCertificationCase.REFUND,
            ProviderCertificationCase.ROLLBACK,
            ProviderCertificationCase.CHARGEBACK
        )
        assertEquals(expectedCases, report.evidenceIncluded)
        assertEquals(7, report.caseResults.size)

        for (expectedCase in expectedCases) {
            val caseResult = report.caseResults[expectedCase]
            assertNotNull(caseResult, "Result for case $expectedCase must not be null")
            assertEquals(CaseVerificationStatus.PASSED, caseResult!!.status)
            assertTrue(caseResult.evidence.debitsEqualCredits, "Debits must equal credits for case $expectedCase")
            assertTrue(caseResult.evidence.doubleEffectPrevented, "Double effect must be prevented for case $expectedCase")
            assertTrue(caseResult.evidence.immutableCompensationVerified, "Immutable compensation verified for case $expectedCase")
            assertTrue(caseResult.evidence.evidenceDigest.startsWith("sha256:"))
        }

        // Assert committed correlation/causation identity
        assertEquals(cmd.correlationId, report.correlationId)
        assertEquals(cmd.causationId, report.causationId)
        assertTrue(report.evidenceReference.startsWith("ev-prov-cert-"))
    }

    @Test
    @DisplayName("SYS-002-T002 — Provider certification/reconciliation rejects invalid, boundary, unauthorized, and stale input")
    fun testT002RejectsInvalidAndUnauthorizedInput() {
        val baseCmd = buildValidCommand()

        // 1. Unauthenticated caller
        assertThrows(UnauthorizedProviderCertificationException::class.java) {
            service.runCertification(baseCmd.copy(principal = null))
        }

        // 2. Unauthorized role
        val playerPrincipal = AuthenticatedPrincipal(
            id = "player-99",
            tenantId = tenantId,
            roles = emptySet(),
            kind = PrincipalKind.PLAYER
        )
        assertThrows(UnauthorizedProviderCertificationException::class.java) {
            service.runCertification(baseCmd.copy(principal = playerPrincipal))
        }

        // 3. Cross-tenant caller
        val crossTenantPrincipal = adminPrincipal.copy(tenantId = "other-tenant")
        assertThrows(UnauthorizedProviderCertificationException::class.java) {
            service.runCertification(baseCmd.copy(principal = crossTenantPrincipal))
        }

        // 4. Expired manifest
        val expiredManifest = validManifest.copy(expiry = Instant.now().minusSeconds(120))
        assertThrows(InvalidProviderCertificationManifestException::class.java) {
            service.runCertification(baseCmd.copy(manifest = expiredManifest))
        }

        // 5. Blank manifest fields
        val blankManifest = validManifest.copy(commitHash = "  ")
        assertThrows(InvalidProviderCertificationManifestException::class.java) {
            service.runCertification(baseCmd.copy(manifest = blankManifest))
        }

        // 6. Blank providerId
        assertThrows(InvalidProviderCertificationInputException::class.java) {
            service.runCertification(baseCmd.copy(providerId = ""))
        }

        // 7. Blank correlation or causation
        assertThrows(InvalidProviderCertificationInputException::class.java) {
            service.runCertification(baseCmd.copy(correlationId = " "))
        }
        assertThrows(InvalidProviderCertificationInputException::class.java) {
            service.runCertification(baseCmd.copy(causationId = ""))
        }

        // 8. Empty targetCases
        assertThrows(InvalidProviderCertificationInputException::class.java) {
            service.runCertification(baseCmd.copy(targetCases = emptySet()))
        }

        // 9. Injected case failure: must fail with "certification cases fail"
        service.scenarioFaults[ProviderCertificationCase.DUPLICATE.name] = "Duplicate re-execution detected in provider"
        val ex = assertThrows(ProviderCertificationFailedException::class.java) {
            service.runCertification(buildValidCommand())
        }
        assertTrue(ex.message!!.startsWith("certification cases fail"))
        service.scenarioFaults.clear()

        // Verify zero unauthorized durable mutation
        assertEquals(0, evidenceStore.getAllReports().size)
    }

    @Test
    @DisplayName("SYS-002-T003 — Provider certification/reconciliation survives concurrency, duplicate delivery, and dependency failure")
    fun testT003SurvivesConcurrencyDuplicateAndFailure() {
        val idempotencyKey = "idem-prov-cert-${UUID.randomUUID()}"
        val cmd1 = buildValidCommand(idempotencyKey = idempotencyKey)

        // 1. First execution
        val report1 = service.runCertification(cmd1)
        assertNotNull(report1)

        // 2. Duplicate delivery / idempotent replay
        val report2 = service.runCertification(cmd1)
        assertEquals(report1.reportId, report2.reportId)
        assertEquals(report1.evidenceReference, report2.evidenceReference)

        // 3. Conflicting key reuse
        val conflictingCmd = cmd1.copy(targetCases = setOf(ProviderCertificationCase.DUPLICATE))
        assertThrows(IdempotencyConflictException::class.java) {
            service.runCertification(conflictingCmd)
        }

        // 4. Concurrency race on same idempotency key
        val executor = Executors.newFixedThreadPool(8)
        val concurrentKey = "idem-race-${UUID.randomUUID()}"
        val concurrentCmd = buildValidCommand(idempotencyKey = concurrentKey)
        val tasks = (1..8).map {
            Callable { service.runCertification(concurrentCmd) }
        }
        val futures = executor.invokeAll(tasks)
        executor.shutdown()

        val results = futures.map { it.get() }
        val firstReportId = results[0].reportId
        assertTrue(results.all { it.reportId == firstReportId }, "All concurrent executions must share the same report ID")

        // 5. Injected provider dependency failure
        service.scenarioFaults["PROVIDER_DEPENDENCY_FAILURE"] = "Connection refused: 504 gateway timeout"
        val failCmd = buildValidCommand()
        val dex = assertThrows(ProviderCertificationExecutionException::class.java) {
            service.runCertification(failCmd)
        }
        assertTrue(dex.message!!.contains("Connection refused: 504 gateway timeout"))
        service.scenarioFaults.clear()

        val alerts = alertSink.getAlerts()
        assertTrue(alerts.any { it.message.contains("Provider dependency failure") })
    }

    @Test
    @DisplayName("SYS-002-T004 — Provider certification/reconciliation remains compatible, recoverable, observable, and lifecycle-safe")
    fun testT004RemainsCompatibleRecoverableObservableAndLifecycleSafe() {
        val cmd = buildValidCommand()
        val report = service.runCertification(cmd)

        // 1. Android lifecycle boundary verification
        assertFalse(report.hasAndroidLifecycleClaim, "Must not claim Android lifecycle authority")
        assertFalse(report.hasAndroidDbImpact, "Must not have Android DB impact")

        // 2. Observability verification
        assertTrue(observability.getExecutionsCount() > 0)
        assertTrue(observability.getCasesVerifiedCount() >= 7)

        // 3. Recovery from durable evidence store (Restart Simulation)
        val recoveredReport = evidenceStore.getReport(report.reportId)
        assertNotNull(recoveredReport, "Report must be recoverable from evidence store")
        assertEquals(report.reportId, recoveredReport!!.reportId)
        assertTrue(recoveredReport.isFullyCertified)

        // Exact semantic contract assertion on recovered state:
        // "Duplicate/late/out-of-order/timeout/refund/rollback/chargeback evidence included."
        val expectedCases = setOf(
            ProviderCertificationCase.DUPLICATE,
            ProviderCertificationCase.LATE,
            ProviderCertificationCase.OUT_OF_ORDER,
            ProviderCertificationCase.TIMEOUT,
            ProviderCertificationCase.REFUND,
            ProviderCertificationCase.ROLLBACK,
            ProviderCertificationCase.CHARGEBACK
        )
        assertEquals(expectedCases, recoveredReport.evidenceIncluded)
        assertTrue(recoveredReport.debitsEqualCreditsPreserved)
        assertTrue(recoveredReport.caseResults.values.all { it.evidence.doubleEffectPrevented })
    }
}
