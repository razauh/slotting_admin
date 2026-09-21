package com.slotting.admin.gate.withdrawal

import com.slotting.admin.auth.AdminRole
import com.slotting.admin.auth.AuthenticatedPrincipal
import com.slotting.admin.auth.PrincipalKind
import org.junit.jupiter.api.AfterEach
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test
import java.time.Clock
import java.time.Instant
import java.time.ZoneOffset
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertNotNull
import kotlin.test.assertTrue

class AuthoritativeWithdrawalIntegrationGateTest {
    private var now = Instant.parse("2026-09-21T08:00:00Z")
    private val clock: Clock get() = Clock.fixed(now, ZoneOffset.UTC)

    private val tenantId = "tenant-wdr-gate-test"
    private val adminOperatorPrincipal = AuthenticatedPrincipal(
        id = "admin-wdr-gate-op-01",
        tenantId = tenantId,
        kind = PrincipalKind.ADMIN,
        roles = setOf(AdminRole.SUPPORT, AdminRole.SUPER_ADMIN)
    )

    private val playerPrincipal = AuthenticatedPrincipal(
        id = "player-wdr-01",
        tenantId = tenantId,
        kind = PrincipalKind.PLAYER,
        roles = emptySet()
    )

    private val foreignAdminPrincipal = AuthenticatedPrincipal(
        id = "foreign-admin-wdr-99",
        tenantId = "tenant-other",
        kind = PrincipalKind.ADMIN,
        roles = setOf(AdminRole.SUPER_ADMIN)
    )

    private lateinit var evidenceStore: InMemoryWithdrawalGateEvidenceStore
    private lateinit var alertSink: InMemoryWithdrawalGateAlertSink
    private lateinit var observability: InMemoryWithdrawalGateObservability
    private lateinit var service: AuthoritativeWithdrawalIntegrationGateService

    private fun createValidManifest(): WithdrawalArtifactManifest {
        return WithdrawalArtifactManifest(
            commitHash = "794dbc16dc6b882f3102574f241fee436e9d9987",
            artifactDigest = "sha256:wdr4b8c9d1e2f3a4b5c6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f1a2b3c4d5e6f7a",
            configurationVersion = "wdr-cfg-v1.0",
            environment = "production-candidate",
            owner = "payments-withdrawal-team",
            reviewer = "head-of-treasury",
            signedAt = now.minusSeconds(3600),
            expiry = now.plusSeconds(86400)
        )
    }

    @BeforeEach
    fun setUp() {
        AuthoritativeWithdrawalIntegrationGateBinding.checkBound()
        evidenceStore = InMemoryWithdrawalGateEvidenceStore()
        alertSink = InMemoryWithdrawalGateAlertSink()
        observability = InMemoryWithdrawalGateObservability()

        service = AuthoritativeWithdrawalIntegrationGateService(
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
    // GATE-WITHDRAWAL-001-T001 — An eligible owner completes one approved payout and one balanced terminal posting
    // =========================================================================
    @Test
    fun `GATE-WITHDRAWAL-001-T001 — An eligible owner completes one approved payout and one balanced terminal posting`() {
        val manifest = createValidManifest()
        val cmd = EvaluateWithdrawalGateCommand(
            principal = adminOperatorPrincipal,
            tenantId = tenantId,
            manifest = manifest,
            selectedScenarios = setOf(WithdrawalScenarioId.T001_ELIGIBLE_OWNER_APPROVED_PAYOUT_BALANCED_POSTING),
            correlationId = "corr-wdr-001",
            causationId = "caus-wdr-001"
        )

        val report = service.evaluateGate(cmd)

        assertEquals(WithdrawalGateDecision.GO, report.decision)
        val scenarioResult = report.scenarioResults[WithdrawalScenarioId.T001_ELIGIBLE_OWNER_APPROVED_PAYOUT_BALANCED_POSTING]
        assertNotNull(scenarioResult)
        assertEquals(WithdrawalScenarioStatus.PASS, scenarioResult.status)
        assertTrue(scenarioResult.details.contains("Complete withdrawal lifecycle succeeded"))
        assertTrue(report.financialConservationEnforced)
        assertFalse(report.hasAndroidDbImpact)
        assertFalse(report.hasAndroidLifecycleClaim)
    }

    // =========================================================================
    // GATE-WITHDRAWAL-001-T002 — Expired quote, unowned destination, failed step-up, restriction, and self-approval are denied
    // =========================================================================
    @Test
    fun `GATE-WITHDRAWAL-001-T002 — Expired quote, unowned destination, failed step-up, restriction, and self-approval are denied`() {
        val manifest = createValidManifest()
        val cmd = EvaluateWithdrawalGateCommand(
            principal = adminOperatorPrincipal,
            tenantId = tenantId,
            manifest = manifest,
            selectedScenarios = setOf(WithdrawalScenarioId.T002_EXPIRED_QUOTE_UNOWNED_DEST_FAILED_STEPUP_DENIED),
            correlationId = "corr-wdr-002",
            causationId = "caus-wdr-002"
        )

        val report = service.evaluateGate(cmd)

        assertEquals(WithdrawalGateDecision.GO, report.decision)
        val scenarioResult = report.scenarioResults[WithdrawalScenarioId.T002_EXPIRED_QUOTE_UNOWNED_DEST_FAILED_STEPUP_DENIED]
        assertNotNull(scenarioResult)
        assertEquals(WithdrawalScenarioStatus.PASS, scenarioResult.status)
        assertTrue(scenarioResult.details.contains("deterministically denied with zero reservation"))
    }

    // =========================================================================
    // GATE-WITHDRAWAL-001-T003 — Concurrent requests cannot reserve beyond withdrawable funds or duplicate payout
    // =========================================================================
    @Test
    fun `GATE-WITHDRAWAL-001-T003 — Concurrent requests cannot reserve beyond withdrawable funds or duplicate payout`() {
        val manifest = createValidManifest()
        val cmd = EvaluateWithdrawalGateCommand(
            principal = adminOperatorPrincipal,
            tenantId = tenantId,
            manifest = manifest,
            selectedScenarios = setOf(WithdrawalScenarioId.T003_CONCURRENT_REQUESTS_NO_OVER_RESERVE_DUPLICATE_PAYOUT),
            correlationId = "corr-wdr-003",
            causationId = "caus-wdr-003"
        )

        val report = service.evaluateGate(cmd)

        assertEquals(WithdrawalGateDecision.GO, report.decision)
        val scenarioResult = report.scenarioResults[WithdrawalScenarioId.T003_CONCURRENT_REQUESTS_NO_OVER_RESERVE_DUPLICATE_PAYOUT]
        assertNotNull(scenarioResult)
        assertEquals(WithdrawalScenarioStatus.PASS, scenarioResult.status)
        assertTrue(scenarioResult.details.contains("Concurrent reservations strictly bounded by withdrawable funds"))
    }

    // =========================================================================
    // GATE-WITHDRAWAL-001-T004 — Timeout and unknown provider outcomes stay pending until authoritative reconciliation
    // =========================================================================
    @Test
    fun `GATE-WITHDRAWAL-001-T004 — Timeout and unknown provider outcomes stay pending until authoritative reconciliation`() {
        val manifest = createValidManifest()
        val cmd = EvaluateWithdrawalGateCommand(
            principal = adminOperatorPrincipal,
            tenantId = tenantId,
            manifest = manifest,
            selectedScenarios = setOf(WithdrawalScenarioId.T004_TIMEOUT_UNKNOWN_STAYS_PENDING_UNTIL_RECONCILIATION),
            correlationId = "corr-wdr-004",
            causationId = "caus-wdr-004"
        )

        val report = service.evaluateGate(cmd)

        assertEquals(WithdrawalGateDecision.GO, report.decision)
        val scenarioResult = report.scenarioResults[WithdrawalScenarioId.T004_TIMEOUT_UNKNOWN_STAYS_PENDING_UNTIL_RECONCILIATION]
        assertNotNull(scenarioResult)
        assertEquals(WithdrawalScenarioStatus.PASS, scenarioResult.status)
        assertTrue(scenarioResult.details.contains("Timeout held withdrawal safely in PENDING_RECONCILIATION without premature release"))
    }

    // =========================================================================
    // GATE-WITHDRAWAL-001-T005 — Failure releases or compensates reservations exactly once and preserves audit lineage
    // =========================================================================
    @Test
    fun `GATE-WITHDRAWAL-001-T005 — Failure releases or compensates reservations exactly once and preserves audit lineage`() {
        val manifest = createValidManifest()
        val cmd = EvaluateWithdrawalGateCommand(
            principal = adminOperatorPrincipal,
            tenantId = tenantId,
            manifest = manifest,
            selectedScenarios = setOf(WithdrawalScenarioId.T005_FAILURE_RELEASES_OR_COMPENSATES_EXACTLY_ONCE),
            correlationId = "corr-wdr-005",
            causationId = "caus-wdr-005"
        )

        val report = service.evaluateGate(cmd)

        assertEquals(WithdrawalGateDecision.GO, report.decision)
        val scenarioResult = report.scenarioResults[WithdrawalScenarioId.T005_FAILURE_RELEASES_OR_COMPENSATES_EXACTLY_ONCE]
        assertNotNull(scenarioResult)
        assertEquals(WithdrawalScenarioStatus.PASS, scenarioResult.status)
        assertTrue(scenarioResult.details.contains("Rejection compensated reservation exactly once"))
        assertTrue(report.financialConservationEnforced)
    }

    // =========================================================================
    // GATE-WITHDRAWAL-001-T006 — Payout provider, withdrawal state, ledger, statement, and admin evidence reconcile
    // =========================================================================
    @Test
    fun `GATE-WITHDRAWAL-001-T006 — Payout provider, withdrawal state, ledger, statement, and admin evidence reconcile`() {
        val manifest = createValidManifest()
        val cmd = EvaluateWithdrawalGateCommand(
            principal = adminOperatorPrincipal,
            tenantId = tenantId,
            manifest = manifest,
            selectedScenarios = setOf(WithdrawalScenarioId.T006_PROVIDER_STATE_LEDGER_STATEMENT_ADMIN_RECONCILE),
            correlationId = "corr-wdr-006",
            causationId = "caus-wdr-006"
        )

        val report = service.evaluateGate(cmd)

        assertEquals(WithdrawalGateDecision.GO, report.decision)
        val scenarioResult = report.scenarioResults[WithdrawalScenarioId.T006_PROVIDER_STATE_LEDGER_STATEMENT_ADMIN_RECONCILE]
        assertNotNull(scenarioResult)
        assertEquals(WithdrawalScenarioStatus.PASS, scenarioResult.status)
        assertTrue(scenarioResult.details.contains("Full multi-system reconciliation verified"))
    }

    // =========================================================================
    // Comprehensive Multi-Scenario Evaluation & Withdrawal Gate Boundaries
    // =========================================================================
    @Test
    fun `Comprehensive Withdrawal Gate Evaluation with all 6 scenarios produces authoritative GO`() {
        val manifest = createValidManifest()
        val cmd = EvaluateWithdrawalGateCommand(
            principal = adminOperatorPrincipal,
            tenantId = tenantId,
            manifest = manifest,
            selectedScenarios = WithdrawalScenarioId.values().toSet(),
            correlationId = "corr-wdr-all",
            causationId = "caus-wdr-all"
        )

        val report = service.evaluateGate(cmd)

        assertEquals(WithdrawalGateDecision.GO, report.decision)
        assertEquals(6, report.scenarioResults.size)
        assertTrue(report.scenarioResults.values.all { it.status == WithdrawalScenarioStatus.PASS })
        assertEquals(WITHDRAWAL_INTEGRATION_GATE_CONTRACT, report.semanticContract)
        assertTrue(report.financialConservationEnforced)
        assertFalse(report.hasAndroidDbImpact)
        assertFalse(report.hasAndroidLifecycleClaim)

        // Verify report persisted in evidence store
        val stored = evidenceStore.findLatestReport(tenantId)
        assertNotNull(stored)
        assertEquals(report.reportId, stored.reportId)
    }

    @Test
    fun `Injected failure in withdrawal scenario produces deterministic NO-GO and emits alert`() {
        val manifest = createValidManifest()
        service.scenarioFaults[WithdrawalScenarioId.T001_ELIGIBLE_OWNER_APPROVED_PAYOUT_BALANCED_POSTING] = "Injected financial posting imbalance defect"

        val cmd = EvaluateWithdrawalGateCommand(
            principal = adminOperatorPrincipal,
            tenantId = tenantId,
            manifest = manifest,
            selectedScenarios = WithdrawalScenarioId.values().toSet(),
            correlationId = "corr-wdr-fault",
            causationId = "caus-wdr-fault"
        )

        val report = service.evaluateGate(cmd)

        assertEquals(WithdrawalGateDecision.NO_GO, report.decision)
        val failedScenario = report.scenarioResults[WithdrawalScenarioId.T001_ELIGIBLE_OWNER_APPROVED_PAYOUT_BALANCED_POSTING]
        assertNotNull(failedScenario)
        assertEquals(WithdrawalScenarioStatus.FAIL, failedScenario.status)

        // Verify alert emitted for NO-GO
        val alerts = alertSink.getAlerts()
        assertTrue(alerts.any { it.message.contains("GATE-WITHDRAWAL-001 evaluation resulted in NO-GO") })
    }

    @Test
    fun `Unauthenticated or player principal is rejected with UnauthorizedWithdrawalGateException`() {
        val manifest = createValidManifest()

        // Null principal
        assertFailsWith<UnauthorizedWithdrawalGateException> {
            service.evaluateGate(
                EvaluateWithdrawalGateCommand(
                    principal = null,
                    tenantId = tenantId,
                    manifest = manifest,
                    correlationId = "corr-wdr-null",
                    causationId = "caus-wdr-null"
                )
            )
        }

        // Player principal
        assertFailsWith<UnauthorizedWithdrawalGateException> {
            service.evaluateGate(
                EvaluateWithdrawalGateCommand(
                    principal = playerPrincipal,
                    tenantId = tenantId,
                    manifest = manifest,
                    correlationId = "corr-wdr-player",
                    causationId = "caus-wdr-player"
                )
            )
        }

        // Foreign admin principal
        assertFailsWith<UnauthorizedWithdrawalGateException> {
            service.evaluateGate(
                EvaluateWithdrawalGateCommand(
                    principal = foreignAdminPrincipal,
                    tenantId = tenantId,
                    manifest = manifest,
                    correlationId = "corr-wdr-foreign",
                    causationId = "caus-wdr-foreign"
                )
            )
        }
    }

    @Test
    fun `Expired manifest throws InvalidWithdrawalGateManifestException and emits alert`() {
        val expiredManifest = createValidManifest().copy(
            expiry = now.minusSeconds(10)
        )

        assertFailsWith<InvalidWithdrawalGateManifestException> {
            service.evaluateGate(
                EvaluateWithdrawalGateCommand(
                    principal = adminOperatorPrincipal,
                    tenantId = tenantId,
                    manifest = expiredManifest,
                    correlationId = "corr-wdr-expired",
                    causationId = "caus-wdr-expired"
                )
            )
        }

        val alerts = alertSink.getAlerts()
        assertTrue(alerts.any { it.message.contains("manifest is invalid or expired") })
    }
}
