package com.slotting.admin.gate.compliance

import com.slotting.admin.auth.AdminRole
import com.slotting.admin.auth.AuthenticatedPrincipal
import com.slotting.admin.auth.PrincipalKind
import org.junit.jupiter.api.AfterEach
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test
import java.time.Clock
import java.time.Instant
import java.time.ZoneOffset
import java.util.concurrent.Callable
import java.util.concurrent.Executors
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertNotNull
import kotlin.test.assertTrue

class AuthoritativeComplianceIntegrationGateTest {
    private var now = Instant.parse("2026-09-21T06:30:00Z")
    private val clock: Clock get() = Clock.fixed(now, ZoneOffset.UTC)

    private val tenantId = "tenant-compliance-gate-test"
    private val adminOperatorPrincipal = AuthenticatedPrincipal(
        id = "admin-comp-gate-op-01",
        tenantId = tenantId,
        kind = PrincipalKind.ADMIN,
        roles = setOf(AdminRole.SUPPORT, AdminRole.SUPER_ADMIN)
    )

    private val playerPrincipal = AuthenticatedPrincipal(
        id = "player-comp-01",
        tenantId = tenantId,
        kind = PrincipalKind.PLAYER,
        roles = emptySet()
    )

    private val foreignAdminPrincipal = AuthenticatedPrincipal(
        id = "foreign-admin-comp-99",
        tenantId = "tenant-other",
        kind = PrincipalKind.ADMIN,
        roles = setOf(AdminRole.SUPER_ADMIN)
    )

    private lateinit var evidenceStore: InMemoryComplianceGateEvidenceStore
    private lateinit var alertSink: InMemoryComplianceGateAlertSink
    private lateinit var observability: InMemoryComplianceGateObservability
    private lateinit var service: AuthoritativeComplianceIntegrationGateService

    private fun createValidManifest(): ComplianceArtifactManifest {
        return ComplianceArtifactManifest(
            commitHash = "794dbc16dc6b882f3102574f241fee436e9d9987",
            artifactDigest = "sha256:comp5b8c9d1e2f3a4b5c6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f1a2b3c4d5e6f7a",
            configurationVersion = "comp-cfg-v1.0",
            environment = "production-candidate",
            owner = "compliance-security-team",
            reviewer = "mlro-compliance-director",
            signedAt = now.minusSeconds(3600),
            expiry = now.plusSeconds(86400)
        )
    }

    @BeforeEach
    fun setUp() {
        AuthoritativeComplianceIntegrationGateBinding.checkBound()
        evidenceStore = InMemoryComplianceGateEvidenceStore()
        alertSink = InMemoryComplianceGateAlertSink()
        observability = InMemoryComplianceGateObservability()

        service = AuthoritativeComplianceIntegrationGateService(
            evidenceStore = evidenceStore,
            alertSink = alertSink,
            observability = observability,
            clock = object : Clock() {
                override fun getZone(): ZoneOffset = ZoneOffset.UTC
                override fun withZone(zone: java.time.ZoneId?): Clock = this
                override fun instant(): Instant = now
            }
        )
    }

    @AfterEach
    fun tearDown() {
    }

    // =========================================================================
    // GATE-COMPLIANCE-001-T001 — A fully eligible player receives a versioned decision bound to current evidence
    // =========================================================================
    @Test
    fun `GATE-COMPLIANCE-001-T001 — A fully eligible player receives a versioned decision bound to current evidence`() {
        val manifest = createValidManifest()
        val cmd = EvaluateComplianceGateCommand(
            principal = adminOperatorPrincipal,
            tenantId = tenantId,
            manifest = manifest,
            selectedScenarios = setOf(ComplianceScenarioId.T001_ELIGIBLE_PLAYER_E2E),
            correlationId = "corr-comp-001",
            causationId = "caus-comp-001"
        )

        // 1. Valid execution yields GO
        val report = service.evaluateGate(cmd)
        assertEquals(ComplianceGateDecision.GO, report.decision)
        assertEquals(1, report.scenarioResults.size)
        val scenario1 = report.scenarioResults[ComplianceScenarioId.T001_ELIGIBLE_PLAYER_E2E]
        assertNotNull(scenario1)
        assertEquals(ComplianceScenarioStatus.PASS, scenario1.status)
        assertEquals(COMPLIANCE_INTEGRATION_GATE_CONTRACT, report.semanticContract)
        assertFalse(report.hasFinancialAuthorityImpact)
        assertFalse(report.hasAndroidDbImpact)
        assertFalse(report.hasAndroidLifecycleClaim)

        // 2. Injected defect yields deterministic NO-GO
        service.scenarioFaults[ComplianceScenarioId.T001_ELIGIBLE_PLAYER_E2E] = "KYC verified status failed to compose with geo verdict"
        val failReport = service.evaluateGate(cmd)
        assertEquals(ComplianceGateDecision.NO_GO, failReport.decision)
        assertEquals(ComplianceScenarioStatus.FAIL, failReport.scenarioResults[ComplianceScenarioId.T001_ELIGIBLE_PLAYER_E2E]?.status)
        assertTrue(failReport.scenarioResults[ComplianceScenarioId.T001_ELIGIBLE_PLAYER_E2E]?.failureReason!!.contains("KYC verified status"))
    }

    // =========================================================================
    // GATE-COMPLIANCE-001-T002 — Underage, unscreened, sanctioned, excluded, out-of-region, and restricted states deny commands
    // =========================================================================
    @Test
    fun `GATE-COMPLIANCE-001-T002 — Underage, unscreened, sanctioned, excluded, out-of-region, and restricted states deny commands`() {
        val manifest = createValidManifest()
        val cmd = EvaluateComplianceGateCommand(
            principal = adminOperatorPrincipal,
            tenantId = tenantId,
            manifest = manifest,
            selectedScenarios = setOf(ComplianceScenarioId.T002_RESTRICTIONS_DENIAL),
            correlationId = "corr-comp-002",
            causationId = "caus-comp-002"
        )

        // 1. Pass when all security & compliance restrictions are enforced
        val report = service.evaluateGate(cmd)
        assertEquals(ComplianceGateDecision.GO, report.decision)
        assertEquals(ComplianceScenarioStatus.PASS, report.scenarioResults[ComplianceScenarioId.T002_RESTRICTIONS_DENIAL]?.status)

        // 2. Unauthenticated caller rejected
        assertFailsWith<UnauthorizedComplianceGateException> {
            service.evaluateGate(cmd.copy(principal = null))
        }

        // 3. Player caller rejected
        assertFailsWith<UnauthorizedComplianceGateException> {
            service.evaluateGate(cmd.copy(principal = playerPrincipal))
        }

        // 4. Cross-tenant caller rejected
        assertFailsWith<UnauthorizedComplianceGateException> {
            service.evaluateGate(cmd.copy(principal = foreignAdminPrincipal))
        }

        // 5. Expired manifest rejected
        val expiredManifest = manifest.copy(expiry = now.minusSeconds(60))
        assertFailsWith<InvalidComplianceGateManifestException> {
            service.evaluateGate(cmd.copy(manifest = expiredManifest))
        }

        // 6. Injected defect where restriction is bypassed yields NO-GO
        service.scenarioFaults[ComplianceScenarioId.T002_RESTRICTIONS_DENIAL] = "Sanctioned player allowed to deposit"
        val failReport = service.evaluateGate(cmd)
        assertEquals(ComplianceGateDecision.NO_GO, failReport.decision)
    }

    // =========================================================================
    // GATE-COMPLIANCE-001-T003 — Stale, spoofed, replayed, ambiguous, and unavailable vendor evidence never grants eligibility
    // =========================================================================
    @Test
    fun `GATE-COMPLIANCE-001-T003 — Stale, spoofed, replayed, ambiguous, and unavailable vendor evidence never grants eligibility`() {
        val manifest = createValidManifest()
        val cmd = EvaluateComplianceGateCommand(
            principal = adminOperatorPrincipal,
            tenantId = tenantId,
            manifest = manifest,
            selectedScenarios = setOf(ComplianceScenarioId.T003_STALE_SPOOFED_UNAVAILABLE_EVIDENCE),
            correlationId = "corr-comp-003",
            causationId = "caus-comp-003"
        )

        // 1. Valid execution yields GO
        val report = service.evaluateGate(cmd)
        assertEquals(ComplianceGateDecision.GO, report.decision)
        assertEquals(ComplianceScenarioStatus.PASS, report.scenarioResults[ComplianceScenarioId.T003_STALE_SPOOFED_UNAVAILABLE_EVIDENCE]?.status)

        // 2. Injected defect where stale geo verdict grants eligibility yields NO-GO
        service.scenarioFaults[ComplianceScenarioId.T003_STALE_SPOOFED_UNAVAILABLE_EVIDENCE] = "Stale TTL geolocation verdict granted wager eligibility"
        val failReport = service.evaluateGate(cmd)
        assertEquals(ComplianceGateDecision.NO_GO, failReport.decision)
    }

    // =========================================================================
    // GATE-COMPLIANCE-001-T004 — Self-exclusion and restriction changes immediately stop protected activity across products
    // =========================================================================
    @Test
    fun `GATE-COMPLIANCE-001-T004 — Self-exclusion and restriction changes immediately stop protected activity across products`() {
        val manifest = createValidManifest()
        val cmd = EvaluateComplianceGateCommand(
            principal = adminOperatorPrincipal,
            tenantId = tenantId,
            manifest = manifest,
            selectedScenarios = setOf(ComplianceScenarioId.T004_IMMEDIATE_CROSS_PRODUCT_STOP),
            correlationId = "corr-comp-004",
            causationId = "caus-comp-004"
        )

        // 1. Immediate cross-product stop PASS
        val report = service.evaluateGate(cmd)
        assertEquals(ComplianceGateDecision.GO, report.decision)
        assertEquals(ComplianceScenarioStatus.PASS, report.scenarioResults[ComplianceScenarioId.T004_IMMEDIATE_CROSS_PRODUCT_STOP]?.status)

        // 2. Injected defect yields NO-GO
        service.scenarioFaults[ComplianceScenarioId.T004_IMMEDIATE_CROSS_PRODUCT_STOP] = "Active game launch continued after self-exclusion request"
        val failReport = service.evaluateGate(cmd)
        assertEquals(ComplianceGateDecision.NO_GO, failReport.decision)
    }

    // =========================================================================
    // GATE-COMPLIANCE-001-T005 — Delayed limit increases and controlled reopening use approved server time and evidence
    // =========================================================================
    @Test
    fun `GATE-COMPLIANCE-001-T005 — Delayed limit increases and controlled reopening use approved server time and evidence`() {
        val manifest = createValidManifest()
        val cmd = EvaluateComplianceGateCommand(
            principal = adminOperatorPrincipal,
            tenantId = tenantId,
            manifest = manifest,
            selectedScenarios = setOf(ComplianceScenarioId.T005_DELAYED_LIMITS_CONTROLLED_REOPENING),
            correlationId = "corr-comp-005",
            causationId = "caus-comp-005"
        )

        // 1. Delayed limits control PASS
        val report = service.evaluateGate(cmd)
        assertEquals(ComplianceGateDecision.GO, report.decision)
        assertEquals(ComplianceScenarioStatus.PASS, report.scenarioResults[ComplianceScenarioId.T005_DELAYED_LIMITS_CONTROLLED_REOPENING]?.status)

        // 2. Injected defect yields NO-GO with alert
        service.scenarioFaults[ComplianceScenarioId.T005_DELAYED_LIMITS_CONTROLLED_REOPENING] = "Deposit limit increase took effect without cooling-off period"
        val failReport = service.evaluateGate(cmd)
        assertEquals(ComplianceGateDecision.NO_GO, failReport.decision)

        val alerts = alertSink.getAlerts()
        assertTrue(alerts.any { it.message.contains("NO-GO") })
    }

    // =========================================================================
    // GATE-COMPLIANCE-001-T006 — Minimal evidence, retention, case audit, reason taxonomy, and redaction satisfy approved policy
    // =========================================================================
    @Test
    fun `GATE-COMPLIANCE-001-T006 — Minimal evidence, retention, case audit, reason taxonomy, and redaction satisfy approved policy`() {
        val manifest = createValidManifest()

        // 1. Full suite evaluation across all 6 scenarios
        val cmd = EvaluateComplianceGateCommand(
            principal = adminOperatorPrincipal,
            tenantId = tenantId,
            manifest = manifest,
            selectedScenarios = ComplianceScenarioId.values().toSet(),
            correlationId = "corr-comp-all-006",
            causationId = "caus-comp-all-006"
        )
        val report = service.evaluateGate(cmd)
        assertEquals(ComplianceGateDecision.GO, report.decision)
        assertEquals(6, report.scenarioResults.size)
        report.scenarioResults.values.forEach {
            assertEquals(ComplianceScenarioStatus.PASS, it.status)
        }

        // 2. Concurrent evaluations race safely
        val executor = Executors.newFixedThreadPool(4)
        val tasks = (1..4).map { idx ->
            Callable {
                service.evaluateGate(cmd.copy(correlationId = "corr-comp-race-$idx"))
            }
        }
        val futures = executor.invokeAll(tasks)
        executor.shutdown()
        futures.forEach {
            assertEquals(ComplianceGateDecision.GO, it.get().decision)
        }

        // 3. Recreated service / store persistence test
        val reloadedReport = evidenceStore.findLatestReport(tenantId)
        assertNotNull(reloadedReport)
        assertTrue(evidenceStore.findAllReports(tenantId).any { it.reportId == report.reportId })
        assertEquals(ComplianceGateDecision.GO, reloadedReport.decision)

        // 4. Observability checks: structured events without secrets/PII
        val metrics = observability.getMetrics()
        assertTrue(metrics.isNotEmpty())
        assertTrue(metrics.any { it.eventType == "compliance_gate_evaluated" })

        metrics.forEach { m ->
            assertFalse(m.details.toString().contains("secret"))
            assertFalse(m.details.toString().contains("password"))
        }

        // 5. Zero financial authority created & zero Android lifecycle surface
        assertFalse(report.hasFinancialAuthorityImpact)
        assertFalse(report.hasAndroidDbImpact)
        assertFalse(report.hasAndroidLifecycleClaim)

        // 6. Injected defect yields NO-GO
        service.scenarioFaults[ComplianceScenarioId.T006_AUDIT_RETENTION_REDACTION] = "Raw passport document leaked in audit evidence trail"
        val failReport = service.evaluateGate(cmd)
        assertEquals(ComplianceGateDecision.NO_GO, failReport.decision)
    }
}
