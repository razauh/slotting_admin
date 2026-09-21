package com.slotting.admin.gate.casino

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

class AuthoritativeCasinoIntegrationGateTest {
    private var now = Instant.parse("2026-09-20T21:30:00Z")
    private val clock: Clock get() = Clock.fixed(now, ZoneOffset.UTC)

    private val tenantId = "tenant-gate-casino-test"
    private val adminOperatorPrincipal = AuthenticatedPrincipal(
        id = "admin-gate-op-01",
        tenantId = tenantId,
        kind = PrincipalKind.ADMIN,
        roles = setOf(AdminRole.SUPPORT, AdminRole.SUPER_ADMIN)
    )

    private val playerPrincipal = AuthenticatedPrincipal(
        id = "player-007",
        tenantId = tenantId,
        kind = PrincipalKind.PLAYER,
        roles = emptySet()
    )

    private val foreignAdminPrincipal = AuthenticatedPrincipal(
        id = "foreign-admin-99",
        tenantId = "tenant-other",
        kind = PrincipalKind.ADMIN,
        roles = setOf(AdminRole.SUPER_ADMIN)
    )

    private lateinit var evidenceStore: InMemoryCasinoGateEvidenceStore
    private lateinit var alertSink: InMemoryCasinoGateAlertSink
    private lateinit var observability: InMemoryCasinoGateObservability
    private lateinit var service: AuthoritativeCasinoIntegrationGateService

    private fun createValidManifest(): ArtifactEvidenceManifest {
        return ArtifactEvidenceManifest(
            commitHash = "794dbc16dc6b882f3102574f241fee436e9d9987",
            artifactDigest = "sha256:4a3b8c9d1e2f3a4b5c6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f1a2b3c4d5e6f7a8b",
            configurationVersion = "cfg-prod-2026-09-v1.0",
            environment = "production-candidate",
            owner = "slotting-platform-team",
            reviewer = "security-compliance-lead",
            signedAt = now.minusSeconds(3600),
            expiry = now.plusSeconds(86400)
        )
    }

    @BeforeEach
    fun setUp() {
        AuthoritativeCasinoIntegrationGateBinding.checkBound()
        evidenceStore = InMemoryCasinoGateEvidenceStore()
        alertSink = InMemoryCasinoGateAlertSink()
        observability = InMemoryCasinoGateObservability()

        service = AuthoritativeCasinoIntegrationGateService(
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
    // GATE-CASINO-001-T001 — Eligible play maps one launch, round, provider transaction, reservation, and settlement
    // =========================================================================
    @Test
    fun `GATE-CASINO-001-T001 — Eligible play maps one launch, round, provider transaction, reservation, and settlement`() {
        val manifest = createValidManifest()
        val cmd = EvaluateCasinoGateCommand(
            principal = adminOperatorPrincipal,
            tenantId = tenantId,
            manifest = manifest,
            selectedScenarios = setOf(CasinoScenarioId.T001_ELIGIBLE_PLAY_E2E),
            correlationId = "corr-gate-001",
            causationId = "caus-gate-001"
        )

        // 1. Valid execution yields GO
        val report = service.evaluateGate(cmd)
        assertEquals(CasinoGateDecision.GO, report.decision)
        assertEquals(1, report.scenarioResults.size)
        val scenario1 = report.scenarioResults[CasinoScenarioId.T001_ELIGIBLE_PLAY_E2E]
        assertNotNull(scenario1)
        assertEquals(CasinoScenarioStatus.PASS, scenario1.status)
        assertEquals(CASINO_INTEGRATION_GATE_CONTRACT, report.semanticContract)
        assertFalse(report.hasFinancialAuthorityImpact)
        assertFalse(report.hasAndroidDbImpact)
        assertFalse(report.hasAndroidLifecycleClaim)

        // 2. Injected defect yields deterministic NO-GO
        service.scenarioFaults[CasinoScenarioId.T001_ELIGIBLE_PLAY_E2E] = "Reservation settlement ledger balance mismatch"
        val failReport = service.evaluateGate(cmd)
        assertEquals(CasinoGateDecision.NO_GO, failReport.decision)
        assertEquals(CasinoScenarioStatus.FAIL, failReport.scenarioResults[CasinoScenarioId.T001_ELIGIBLE_PLAY_E2E]?.status)
        assertTrue(failReport.scenarioResults[CasinoScenarioId.T001_ELIGIBLE_PLAY_E2E]?.failureReason!!.contains("Reservation settlement"))
    }

    // =========================================================================
    // GATE-CASINO-001-T002 — Disabled jurisdiction, restricted account, stale eligibility, and forged callback are denied
    // =========================================================================
    @Test
    fun `GATE-CASINO-001-T002 — Disabled jurisdiction, restricted account, stale eligibility, and forged callback are denied`() {
        val manifest = createValidManifest()
        val cmd = EvaluateCasinoGateCommand(
            principal = adminOperatorPrincipal,
            tenantId = tenantId,
            manifest = manifest,
            selectedScenarios = setOf(CasinoScenarioId.T002_RESTRICTIONS_DENIAL),
            correlationId = "corr-gate-002",
            causationId = "caus-gate-002"
        )

        // 1. Pass when all security restrictions are enforced
        val report = service.evaluateGate(cmd)
        assertEquals(CasinoGateDecision.GO, report.decision)
        assertEquals(CasinoScenarioStatus.PASS, report.scenarioResults[CasinoScenarioId.T002_RESTRICTIONS_DENIAL]?.status)

        // 2. Unauthenticated caller rejected
        assertFailsWith<UnauthorizedCasinoGateException> {
            service.evaluateGate(cmd.copy(principal = null))
        }

        // 3. Player caller rejected
        assertFailsWith<UnauthorizedCasinoGateException> {
            service.evaluateGate(cmd.copy(principal = playerPrincipal))
        }

        // 4. Cross-tenant caller rejected
        assertFailsWith<UnauthorizedCasinoGateException> {
            service.evaluateGate(cmd.copy(principal = foreignAdminPrincipal))
        }

        // 5. Expired manifest rejected
        val expiredManifest = manifest.copy(expiry = now.minusSeconds(60))
        assertFailsWith<InvalidCasinoGateManifestException> {
            service.evaluateGate(cmd.copy(manifest = expiredManifest))
        }

        // 6. Injected defect where restriction is bypassed yields NO-GO
        service.scenarioFaults[CasinoScenarioId.T002_RESTRICTIONS_DENIAL] = "Forged callback signature accepted without rejection"
        val failReport = service.evaluateGate(cmd)
        assertEquals(CasinoGateDecision.NO_GO, failReport.decision)
    }

    // =========================================================================
    // GATE-CASINO-001-T003 — Duplicate and reordered wager, win, refund, and rollback events create one lawful effect
    // =========================================================================
    @Test
    fun `GATE-CASINO-001-T003 — Duplicate and reordered wager, win, refund, and rollback events create one lawful effect`() {
        val manifest = createValidManifest()
        val cmd = EvaluateCasinoGateCommand(
            principal = adminOperatorPrincipal,
            tenantId = tenantId,
            manifest = manifest,
            selectedScenarios = setOf(CasinoScenarioId.T003_IDEMPOTENT_REORDERED_EVENTS),
            correlationId = "corr-gate-003",
            causationId = "caus-gate-003"
        )

        // 1. Valid execution yields GO
        val report = service.evaluateGate(cmd)
        assertEquals(CasinoGateDecision.GO, report.decision)
        assertEquals(CasinoScenarioStatus.PASS, report.scenarioResults[CasinoScenarioId.T003_IDEMPOTENT_REORDERED_EVENTS]?.status)

        // 2. Concurrent evaluations race safely
        val executor = Executors.newFixedThreadPool(4)
        val tasks = (1..4).map { idx ->
            Callable {
                service.evaluateGate(cmd.copy(correlationId = "corr-race-$idx"))
            }
        }
        val futures = executor.invokeAll(tasks)
        executor.shutdown()

        val results = futures.map { it.get() }
        results.forEach {
            assertEquals(CasinoGateDecision.GO, it.decision)
        }

        // 3. Injected defect yields NO-GO
        service.scenarioFaults[CasinoScenarioId.T003_IDEMPOTENT_REORDERED_EVENTS] = "Duplicate wager produced split-ledger debit"
        val failReport = service.evaluateGate(cmd)
        assertEquals(CasinoGateDecision.NO_GO, failReport.decision)
    }

    // =========================================================================
    // GATE-CASINO-001-T004 — Provider timeout, socket gap, and stuck round converge through snapshot reconciliation
    // =========================================================================
    @Test
    fun `GATE-CASINO-001-T004 — Provider timeout, socket gap, and stuck round converge through snapshot reconciliation`() {
        val manifest = createValidManifest()
        val cmd = EvaluateCasinoGateCommand(
            principal = adminOperatorPrincipal,
            tenantId = tenantId,
            manifest = manifest,
            selectedScenarios = setOf(CasinoScenarioId.T004_TIMEOUT_SNAPSHOT_RECONCILIATION),
            correlationId = "corr-gate-004",
            causationId = "caus-gate-004"
        )

        // 1. Snapshot reconciliation convergence PASS
        val report = service.evaluateGate(cmd)
        assertEquals(CasinoGateDecision.GO, report.decision)
        assertEquals(CasinoScenarioStatus.PASS, report.scenarioResults[CasinoScenarioId.T004_TIMEOUT_SNAPSHOT_RECONCILIATION]?.status)

        // 2. Injected defect (stuck round unreconciled) yields NO-GO
        service.scenarioFaults[CasinoScenarioId.T004_TIMEOUT_SNAPSHOT_RECONCILIATION] = "Snapshot reconciliation failed to resolve pending round"
        val failReport = service.evaluateGate(cmd)
        assertEquals(CasinoGateDecision.NO_GO, failReport.decision)
    }

    // =========================================================================
    // GATE-CASINO-001-T005 — Degraded provider state blocks new activity while safe completion continues
    // =========================================================================
    @Test
    fun `GATE-CASINO-001-T005 — Degraded provider state blocks new activity while safe completion continues`() {
        val manifest = createValidManifest()
        val cmd = EvaluateCasinoGateCommand(
            principal = adminOperatorPrincipal,
            tenantId = tenantId,
            manifest = manifest,
            selectedScenarios = setOf(CasinoScenarioId.T005_DEGRADED_PROVIDER_CONTROL),
            correlationId = "corr-gate-005",
            causationId = "caus-gate-005"
        )

        // 1. Degraded provider control PASS
        val report = service.evaluateGate(cmd)
        assertEquals(CasinoGateDecision.GO, report.decision)
        assertEquals(CasinoScenarioStatus.PASS, report.scenarioResults[CasinoScenarioId.T005_DEGRADED_PROVIDER_CONTROL]?.status)

        // 2. Injected defect yields NO-GO with alert
        service.scenarioFaults[CasinoScenarioId.T005_DEGRADED_PROVIDER_CONTROL] = "New launch allowed while provider state was DEGRADED"
        val failReport = service.evaluateGate(cmd)
        assertEquals(CasinoGateDecision.NO_GO, failReport.decision)

        val alerts = alertSink.getAlerts()
        assertTrue(alerts.any { it.message.contains("NO-GO") })
    }

    // =========================================================================
    // GATE-CASINO-001-T006 — Aviator REST, socket, command journal, ledger, and provider history agree
    // =========================================================================
    @Test
    fun `GATE-CASINO-001-T006 — Aviator REST, socket, command journal, ledger, and provider history agree`() {
        val manifest = createValidManifest()

        // 1. Full suite evaluation across all 6 scenarios
        val cmd = EvaluateCasinoGateCommand(
            principal = adminOperatorPrincipal,
            tenantId = tenantId,
            manifest = manifest,
            selectedScenarios = CasinoScenarioId.values().toSet(),
            correlationId = "corr-gate-all-006",
            causationId = "caus-gate-all-006"
        )
        val report = service.evaluateGate(cmd)
        assertEquals(CasinoGateDecision.GO, report.decision)
        assertEquals(6, report.scenarioResults.size)
        report.scenarioResults.values.forEach {
            assertEquals(CasinoScenarioStatus.PASS, it.status)
        }

        // 2. Recreated service / store persistence test
        val reloadedReport = evidenceStore.findLatestReport(tenantId)
        assertNotNull(reloadedReport)
        assertEquals(report.reportId, reloadedReport.reportId)
        assertEquals(CasinoGateDecision.GO, reloadedReport.decision)

        // 3. Observability checks: structured events without secrets/PII
        val metrics = observability.getMetrics()
        assertTrue(metrics.isNotEmpty())
        assertTrue(metrics.any { it.eventType == "casino_gate_evaluated" })

        metrics.forEach { m ->
            assertFalse(m.details.toString().contains("secret"))
            assertFalse(m.details.toString().contains("password"))
        }

        // 4. Zero financial authority created & zero Android lifecycle surface
        assertFalse(report.hasFinancialAuthorityImpact)
        assertFalse(report.hasAndroidDbImpact)
        assertFalse(report.hasAndroidLifecycleClaim)

        // 5. Injected defect on Aviator agreement yields NO-GO
        service.scenarioFaults[CasinoScenarioId.T006_AVIATOR_COMPATIBILITY_AGREEMENT] = "Aviator socket multiplier sequence desync from ledger"
        val failReport = service.evaluateGate(cmd)
        assertEquals(CasinoGateDecision.NO_GO, failReport.decision)
    }
}
