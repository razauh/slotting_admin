package com.slotting.admin.gate.payment

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

class AuthoritativePaymentIntegrationGateTest {
    private var now = Instant.parse("2026-09-21T07:30:00Z")
    private val clock: Clock get() = Clock.fixed(now, ZoneOffset.UTC)

    private val tenantId = "tenant-pay-gate-test"
    private val adminOperatorPrincipal = AuthenticatedPrincipal(
        id = "admin-pay-gate-op-01",
        tenantId = tenantId,
        kind = PrincipalKind.ADMIN,
        roles = setOf(AdminRole.SUPPORT, AdminRole.SUPER_ADMIN)
    )

    private val playerPrincipal = AuthenticatedPrincipal(
        id = "player-pay-01",
        tenantId = tenantId,
        kind = PrincipalKind.PLAYER,
        roles = emptySet()
    )

    private val foreignAdminPrincipal = AuthenticatedPrincipal(
        id = "foreign-admin-pay-99",
        tenantId = "tenant-other",
        kind = PrincipalKind.ADMIN,
        roles = setOf(AdminRole.SUPER_ADMIN)
    )

    private lateinit var evidenceStore: InMemoryPaymentGateEvidenceStore
    private lateinit var alertSink: InMemoryPaymentGateAlertSink
    private lateinit var observability: InMemoryPaymentGateObservability
    private lateinit var service: AuthoritativePaymentIntegrationGateService

    private fun createValidManifest(): PaymentArtifactManifest {
        return PaymentArtifactManifest(
            commitHash = "794dbc16dc6b882f3102574f241fee436e9d9987",
            artifactDigest = "sha256:pay5b8c9d1e2f3a4b5c6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f1a2b3c4d5e6f7a",
            configurationVersion = "pay-cfg-v1.0",
            environment = "production-candidate",
            owner = "payments-core-team",
            reviewer = "head-of-financial-risk",
            signedAt = now.minusSeconds(3600),
            expiry = now.plusSeconds(86400)
        )
    }

    @BeforeEach
    fun setUp() {
        AuthoritativePaymentIntegrationGateBinding.checkBound()
        evidenceStore = InMemoryPaymentGateEvidenceStore()
        alertSink = InMemoryPaymentGateAlertSink()
        observability = InMemoryPaymentGateObservability()

        service = AuthoritativePaymentIntegrationGateService(
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
    // GATE-PAYMENT-001-T001 — A certified sandbox deposit reaches one canonical terminal state and one ledger credit
    // =========================================================================
    @Test
    fun `GATE-PAYMENT-001-T001 — A certified sandbox deposit reaches one canonical terminal state and one ledger credit`() {
        val manifest = createValidManifest()
        val cmd = EvaluatePaymentGateCommand(
            principal = adminOperatorPrincipal,
            tenantId = tenantId,
            manifest = manifest,
            selectedScenarios = setOf(PaymentScenarioId.T001_CERTIFIED_SANDBOX_DEPOSIT_E2E),
            correlationId = "corr-pay-001",
            causationId = "caus-pay-001"
        )

        // 1. Valid execution yields GO
        val report = service.evaluateGate(cmd)
        assertEquals(PaymentGateDecision.GO, report.decision)
        assertEquals(1, report.scenarioResults.size)
        val scenario1 = report.scenarioResults[PaymentScenarioId.T001_CERTIFIED_SANDBOX_DEPOSIT_E2E]
        assertNotNull(scenario1)
        assertEquals(PaymentScenarioStatus.PASS, scenario1.status)
        assertEquals(PAYMENT_INTEGRATION_GATE_CONTRACT, report.semanticContract)
        assertTrue(report.financialConservationEnforced)
        assertFalse(report.hasAndroidDbImpact)
        assertFalse(report.hasAndroidLifecycleClaim)

        // 2. Direct primitive assertion
        assertTrue(service.validateCanonicalDepositFlow("ptx-123", 5000L, "USD", "SETTLED"))
        assertFalse(service.validateCanonicalDepositFlow("ptx-123", 0L, "USD", "SETTLED"))
        assertFalse(service.validateCanonicalDepositFlow("ptx-123", 5000L, "USD", "PENDING"))

        // 3. Injected defect yields deterministic NO-GO
        service.scenarioFaults[PaymentScenarioId.T001_CERTIFIED_SANDBOX_DEPOSIT_E2E] = "Sandbox deposit did not create ledger credit batch"
        val failReport = service.evaluateGate(cmd)
        assertEquals(PaymentGateDecision.NO_GO, failReport.decision)
        assertEquals(PaymentScenarioStatus.FAIL, failReport.scenarioResults[PaymentScenarioId.T001_CERTIFIED_SANDBOX_DEPOSIT_E2E]?.status)
    }

    // =========================================================================
    // GATE-PAYMENT-001-T002 — Bad-signature, replayed, malformed, and cross-tenant callbacks cause no mutation
    // =========================================================================
    @Test
    fun `GATE-PAYMENT-001-T002 — Bad-signature, replayed, malformed, and cross-tenant callbacks cause no mutation`() {
        val manifest = createValidManifest()
        val cmd = EvaluatePaymentGateCommand(
            principal = adminOperatorPrincipal,
            tenantId = tenantId,
            manifest = manifest,
            selectedScenarios = setOf(PaymentScenarioId.T002_BAD_SIGNATURE_REPLAY_MUTATION_PROTECTION),
            correlationId = "corr-pay-002",
            causationId = "caus-pay-002"
        )

        val report = service.evaluateGate(cmd)
        assertEquals(PaymentGateDecision.GO, report.decision)
        val result = report.scenarioResults[PaymentScenarioId.T002_BAD_SIGNATURE_REPLAY_MUTATION_PROTECTION]
        assertNotNull(result)
        assertEquals(PaymentScenarioStatus.PASS, result.status)

        // Direct primitive assertions
        assertFalse(service.validateWebhookSecurity(signatureValid = false, isReplayed = false, isMalformed = false, isCrossTenant = false))
        assertFalse(service.validateWebhookSecurity(signatureValid = true, isReplayed = true, isMalformed = false, isCrossTenant = false))
        assertFalse(service.validateWebhookSecurity(signatureValid = true, isReplayed = false, isMalformed = true, isCrossTenant = false))
        assertFalse(service.validateWebhookSecurity(signatureValid = true, isReplayed = false, isMalformed = false, isCrossTenant = true))
        assertTrue(service.validateWebhookSecurity(signatureValid = true, isReplayed = false, isMalformed = false, isCrossTenant = false))

        // Injected fault
        service.scenarioFaults[PaymentScenarioId.T002_BAD_SIGNATURE_REPLAY_MUTATION_PROTECTION] = "Callback with bad HMAC credited account balance"
        val failReport = service.evaluateGate(cmd)
        assertEquals(PaymentGateDecision.NO_GO, failReport.decision)
    }

    // =========================================================================
    // GATE-PAYMENT-001-T003 — Duplicate, late, reordered, timeout, and provider-5xx paths remain idempotent and reconcile
    // =========================================================================
    @Test
    fun `GATE-PAYMENT-001-T003 — Duplicate, late, reordered, timeout, and provider-5xx paths remain idempotent and reconcile`() {
        val manifest = createValidManifest()
        val cmd = EvaluatePaymentGateCommand(
            principal = adminOperatorPrincipal,
            tenantId = tenantId,
            manifest = manifest,
            selectedScenarios = setOf(PaymentScenarioId.T003_DUPLICATE_REORDERED_TIMEOUT_IDEMPOTENCY),
            correlationId = "corr-pay-003",
            causationId = "caus-pay-003"
        )

        val report = service.evaluateGate(cmd)
        assertEquals(PaymentGateDecision.GO, report.decision)
        val result = report.scenarioResults[PaymentScenarioId.T003_DUPLICATE_REORDERED_TIMEOUT_IDEMPOTENCY]
        assertNotNull(result)
        assertEquals(PaymentScenarioStatus.PASS, result.status)

        // Direct primitive assertions
        val ptx = "ptx-test-reorder-99"
        assertEquals("PROCESSED", service.handleDuplicateOrReorderedCallbacks(ptx, "SETTLED"))
        assertEquals("DEDUPLICATED", service.handleDuplicateOrReorderedCallbacks(ptx, "SETTLED"))
        assertEquals("IGNORED_REORDERED", service.handleDuplicateOrReorderedCallbacks(ptx, "PENDING"))
        assertTrue(service.handleProviderTimeoutOr5xx(ptx))

        // Injected fault
        service.scenarioFaults[PaymentScenarioId.T003_DUPLICATE_REORDERED_TIMEOUT_IDEMPOTENCY] = "Late callback overwrote terminal SETTLED status"
        val failReport = service.evaluateGate(cmd)
        assertEquals(PaymentGateDecision.NO_GO, failReport.decision)
    }

    // =========================================================================
    // GATE-PAYMENT-001-T004 — Refund, reversal, and chargeback post compensation without editing history
    // =========================================================================
    @Test
    fun `GATE-PAYMENT-001-T004 — Refund, reversal, and chargeback post compensation without editing history`() {
        val manifest = createValidManifest()
        val cmd = EvaluatePaymentGateCommand(
            principal = adminOperatorPrincipal,
            tenantId = tenantId,
            manifest = manifest,
            selectedScenarios = setOf(PaymentScenarioId.T004_REFUND_REVERSAL_CHARGEBACK_COMPENSATION),
            correlationId = "corr-pay-004",
            causationId = "caus-pay-004"
        )

        val report = service.evaluateGate(cmd)
        assertEquals(PaymentGateDecision.GO, report.decision)
        val result = report.scenarioResults[PaymentScenarioId.T004_REFUND_REVERSAL_CHARGEBACK_COMPENSATION]
        assertNotNull(result)
        assertEquals(PaymentScenarioStatus.PASS, result.status)

        // Direct primitive assertions
        val comp = service.processCompensatingEntry("batch-orig-100", 2500L, "REFUND")
        assertEquals("batch-orig-100", comp.compensationForBatchReference)
        assertEquals(2500L, comp.reversedAmount)
        assertTrue(comp.originalEntryImmutable)

        // Injected fault
        service.scenarioFaults[PaymentScenarioId.T004_REFUND_REVERSAL_CHARGEBACK_COMPENSATION] = "Chargeback mutated original journal batch record directly"
        val failReport = service.evaluateGate(cmd)
        assertEquals(PaymentGateDecision.NO_GO, failReport.decision)
    }

    // =========================================================================
    // GATE-PAYMENT-001-T005 — Android return and deep-link flows only request authoritative status refresh
    // =========================================================================
    @Test
    fun `GATE-PAYMENT-001-T005 — Android return and deep-link flows only request authoritative status refresh`() {
        val manifest = createValidManifest()
        val cmd = EvaluatePaymentGateCommand(
            principal = adminOperatorPrincipal,
            tenantId = tenantId,
            manifest = manifest,
            selectedScenarios = setOf(PaymentScenarioId.T005_UNTRUSTED_CLIENT_RETURN_FLOW_SAFETY),
            correlationId = "corr-pay-005",
            causationId = "caus-pay-005"
        )

        val report = service.evaluateGate(cmd)
        assertEquals(PaymentGateDecision.GO, report.decision)
        val result = report.scenarioResults[PaymentScenarioId.T005_UNTRUSTED_CLIENT_RETURN_FLOW_SAFETY]
        assertNotNull(result)
        assertEquals(PaymentScenarioStatus.PASS, result.status)

        // Direct primitive assertions
        assertFalse(service.validateClientReturnFlow(isAndroidDirectCreditClaim = true))
        assertTrue(service.validateClientReturnFlow(isAndroidDirectCreditClaim = false))

        // Injected fault
        service.scenarioFaults[PaymentScenarioId.T005_UNTRUSTED_CLIENT_RETURN_FLOW_SAFETY] = "Client return URL credited balance before server webhook verification"
        val failReport = service.evaluateGate(cmd)
        assertEquals(PaymentGateDecision.NO_GO, failReport.decision)
    }

    // =========================================================================
    // GATE-PAYMENT-001-T006 — Provider report, payment state, ledger, statement, and exception queue reconcile
    // =========================================================================
    @Test
    fun `GATE-PAYMENT-001-T006 — Provider report, payment state, ledger, statement, and exception queue reconcile`() {
        val manifest = createValidManifest()
        val cmd = EvaluatePaymentGateCommand(
            principal = adminOperatorPrincipal,
            tenantId = tenantId,
            manifest = manifest,
            selectedScenarios = PaymentScenarioId.values().toSet(),
            correlationId = "corr-pay-006",
            causationId = "caus-pay-006"
        )

        // 1. All 6 scenarios evaluated together yield GO
        val report = service.evaluateGate(cmd)
        assertEquals(PaymentGateDecision.GO, report.decision)
        assertEquals(6, report.scenarioResults.size)
        assertTrue(report.scenarioResults.values.all { it.status == PaymentScenarioStatus.PASS })

        // 2. Direct primitive assertion for reconciliation
        assertTrue(service.reconcileProviderAndLedger(listOf(1000L, 2000L), listOf(1000L, 2000L)))
        assertFalse(service.reconcileProviderAndLedger(listOf(1000L, 2000L), listOf(1000L, 1900L)))
        assertFalse(service.reconcileProviderAndLedger(listOf(1000L, 2000L), listOf(3000L)))

        // 3. Concurrent gate evaluations race safely
        val executor = Executors.newFixedThreadPool(4)
        val tasks = (1..4).map { idx ->
            Callable {
                service.evaluateGate(cmd.copy(correlationId = "corr-pay-race-$idx"))
            }
        }
        val futures = executor.invokeAll(tasks)
        executor.shutdown()
        futures.forEach {
            assertEquals(PaymentGateDecision.GO, it.get().decision)
        }

        // 4. Persistence in evidence store verified
        val reloadedReport = evidenceStore.findLatestReport(tenantId)
        assertNotNull(reloadedReport)
        assertTrue(evidenceStore.findAllReports(tenantId).any { it.reportId == report.reportId })
        assertEquals(PaymentGateDecision.GO, reloadedReport.decision)

        // 5. Telemetry & alertSink verified
        val metrics = observability.getMetrics()
        assertTrue(metrics.isNotEmpty())
        assertTrue(metrics.any { it.eventType == "payment_gate_evaluated" })
        metrics.forEach { m ->
            assertFalse(m.details.toString().contains("secret"))
            assertFalse(m.details.toString().contains("password"))
        }

        // 6. Manifest expiration & authorization security checks
        val expiredManifest = manifest.copy(expiry = now.minusSeconds(10))
        assertFailsWith<InvalidPaymentGateManifestException> {
            service.evaluateGate(cmd.copy(manifest = expiredManifest))
        }

        assertFailsWith<UnauthorizedPaymentGateException> {
            service.evaluateGate(cmd.copy(principal = playerPrincipal))
        }

        assertFailsWith<UnauthorizedPaymentGateException> {
            service.evaluateGate(cmd.copy(principal = foreignAdminPrincipal))
        }

        assertFailsWith<UnauthorizedPaymentGateException> {
            service.evaluateGate(cmd.copy(principal = null))
        }
    }
}
