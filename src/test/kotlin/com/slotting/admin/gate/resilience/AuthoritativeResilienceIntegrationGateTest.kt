package com.slotting.admin.gate.resilience

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

class AuthoritativeResilienceIntegrationGateTest {
    private var now = Instant.parse("2026-09-21T08:00:00Z")
    private val clock: Clock get() = Clock.fixed(now, ZoneOffset.UTC)

    private val tenantId = "tenant-res-gate-test"
    private val adminOperatorPrincipal = AuthenticatedPrincipal(
        id = "admin-res-gate-op-01",
        tenantId = tenantId,
        kind = PrincipalKind.ADMIN,
        roles = setOf(AdminRole.SUPPORT, AdminRole.SUPER_ADMIN)
    )

    private val playerPrincipal = AuthenticatedPrincipal(
        id = "player-res-01",
        tenantId = tenantId,
        kind = PrincipalKind.PLAYER,
        roles = emptySet()
    )

    private val foreignAdminPrincipal = AuthenticatedPrincipal(
        id = "foreign-admin-res-99",
        tenantId = "tenant-other",
        kind = PrincipalKind.ADMIN,
        roles = setOf(AdminRole.SUPER_ADMIN)
    )

    private lateinit var evidenceStore: InMemoryResilienceGateEvidenceStore
    private lateinit var alertSink: InMemoryResilienceGateAlertSink
    private lateinit var observability: InMemoryResilienceGateObservability
    private lateinit var service: AuthoritativeResilienceIntegrationGateService

    private fun createValidManifest(): ResilienceArtifactManifest {
        return ResilienceArtifactManifest(
            commitHash = "794dbc16dc6b882f3102574f241fee436e9d9987",
            artifactDigest = "sha256:res5b8c9d1e2f3a4b5c6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f1a2b3c4d5e6f7a",
            configurationVersion = "res-cfg-v1.0",
            environment = "production-candidate",
            owner = "infra-resilience-team",
            reviewer = "head-of-sre-reliability",
            signedAt = now.minusSeconds(3600),
            expiry = now.plusSeconds(86400)
        )
    }

    @BeforeEach
    fun setUp() {
        AuthoritativeResilienceIntegrationGateBinding.checkBound()
        evidenceStore = InMemoryResilienceGateEvidenceStore()
        alertSink = InMemoryResilienceGateAlertSink()
        observability = InMemoryResilienceGateObservability()

        service = AuthoritativeResilienceIntegrationGateService(
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
    // GATE-RESILIENCE-001-T001 — Database abort and restart leave no partial posting and idempotent retry converges
    // =========================================================================
    @Test
    fun `GATE-RESILIENCE-001-T001 — Database abort and restart leave no partial posting and idempotent retry converges`() {
        val manifest = createValidManifest()
        val cmd = EvaluateResilienceGateCommand(
            principal = adminOperatorPrincipal,
            tenantId = tenantId,
            manifest = manifest,
            selectedScenarios = setOf(ResilienceScenarioId.T001_DB_ABORT_AND_RESTART_CONVERGENCE),
            correlationId = "corr-res-001",
            causationId = "caus-res-001"
        )

        // 1. Valid execution yields GO
        val report = service.evaluateGate(cmd)
        assertEquals(ResilienceGateDecision.GO, report.decision)
        assertEquals(1, report.scenarioResults.size)
        val scenario1 = report.scenarioResults[ResilienceScenarioId.T001_DB_ABORT_AND_RESTART_CONVERGENCE]
        assertNotNull(scenario1)
        assertEquals(ResilienceScenarioStatus.PASS, scenario1.status)
        assertEquals(RESILIENCE_INTEGRATION_GATE_CONTRACT, report.semanticContract)
        assertFalse(report.hasFinancialAuthorityImpact)
        assertFalse(report.hasAndroidDbImpact)
        assertFalse(report.hasAndroidLifecycleClaim)

        // 2. Direct primitive assertion
        assertTrue(service.validateDatabaseAbortRecovery(aborted = true))
        assertTrue(service.validateDatabaseAbortRecovery(aborted = false))

        // 3. Injected defect yields deterministic NO-GO
        service.scenarioFaults[ResilienceScenarioId.T001_DB_ABORT_AND_RESTART_CONVERGENCE] = "Partial journal row committed before DB crash"
        val failReport = service.evaluateGate(cmd)
        assertEquals(ResilienceGateDecision.NO_GO, failReport.decision)
        assertEquals(ResilienceScenarioStatus.FAIL, failReport.scenarioResults[ResilienceScenarioId.T001_DB_ABORT_AND_RESTART_CONVERGENCE]?.status)
    }

    // =========================================================================
    // GATE-RESILIENCE-001-T002 — Outbox worker crash expires its lease, creates one effect, and bounds retry or dead-letter
    // =========================================================================
    @Test
    fun `GATE-RESILIENCE-001-T002 — Outbox worker crash expires its lease, creates one effect, and bounds retry or dead-letter`() {
        val manifest = createValidManifest()
        val cmd = EvaluateResilienceGateCommand(
            principal = adminOperatorPrincipal,
            tenantId = tenantId,
            manifest = manifest,
            selectedScenarios = setOf(ResilienceScenarioId.T002_OUTBOX_WORKER_CRASH_LEASE_EXPIRY),
            correlationId = "corr-res-002",
            causationId = "caus-res-002"
        )

        val report = service.evaluateGate(cmd)
        assertEquals(ResilienceGateDecision.GO, report.decision)
        val result = report.scenarioResults[ResilienceScenarioId.T002_OUTBOX_WORKER_CRASH_LEASE_EXPIRY]
        assertNotNull(result)
        assertEquals(ResilienceScenarioStatus.PASS, result.status)

        // Direct primitive assertion
        assertTrue(service.validateOutboxCrashAndLease(workerCrashed = true))
        assertTrue(service.validateOutboxCrashAndLease(workerCrashed = false))

        // Injected fault
        service.scenarioFaults[ResilienceScenarioId.T002_OUTBOX_WORKER_CRASH_LEASE_EXPIRY] = "Outbox message re-dispatched duplicate webhook"
        val failReport = service.evaluateGate(cmd)
        assertEquals(ResilienceGateDecision.NO_GO, failReport.decision)
    }

    // =========================================================================
    // GATE-RESILIENCE-001-T003 — Redis loss cannot remove authority or restrictions and degradation is safe
    // =========================================================================
    @Test
    fun `GATE-RESILIENCE-001-T003 — Redis loss cannot remove authority or restrictions and degradation is safe`() {
        val manifest = createValidManifest()
        val cmd = EvaluateResilienceGateCommand(
            principal = adminOperatorPrincipal,
            tenantId = tenantId,
            manifest = manifest,
            selectedScenarios = setOf(ResilienceScenarioId.T003_REDIS_LOSS_SAFE_DEGRADATION),
            correlationId = "corr-res-003",
            causationId = "caus-res-003"
        )

        val report = service.evaluateGate(cmd)
        assertEquals(ResilienceGateDecision.GO, report.decision)
        val result = report.scenarioResults[ResilienceScenarioId.T003_REDIS_LOSS_SAFE_DEGRADATION]
        assertNotNull(result)
        assertEquals(ResilienceScenarioStatus.PASS, result.status)

        // Direct primitive assertion
        assertTrue(service.validateRedisLossGracefulDegradation(redisDown = true))

        // Injected fault
        service.scenarioFaults[ResilienceScenarioId.T003_REDIS_LOSS_SAFE_DEGRADATION] = "Redis eviction lifted player cooling-off restriction"
        val failReport = service.evaluateGate(cmd)
        assertEquals(ResilienceGateDecision.NO_GO, failReport.decision)
    }

    // =========================================================================
    // GATE-RESILIENCE-001-T004 — Provider timeout and 5xx remain pending or unknown until authoritative status query
    // =========================================================================
    @Test
    fun `GATE-RESILIENCE-001-T004 — Provider timeout and 5xx remain pending or unknown until authoritative status query`() {
        val manifest = createValidManifest()
        val cmd = EvaluateResilienceGateCommand(
            principal = adminOperatorPrincipal,
            tenantId = tenantId,
            manifest = manifest,
            selectedScenarios = setOf(ResilienceScenarioId.T004_PROVIDER_TIMEOUT_STATUS_QUERY),
            correlationId = "corr-res-004",
            causationId = "caus-res-004"
        )

        val report = service.evaluateGate(cmd)
        assertEquals(ResilienceGateDecision.GO, report.decision)
        val result = report.scenarioResults[ResilienceScenarioId.T004_PROVIDER_TIMEOUT_STATUS_QUERY]
        assertNotNull(result)
        assertEquals(ResilienceScenarioStatus.PASS, result.status)

        // Direct primitive assertion
        assertTrue(service.validateProviderTimeoutUnknownState(timedOut = true))

        // Injected fault
        service.scenarioFaults[ResilienceScenarioId.T004_PROVIDER_TIMEOUT_STATUS_QUERY] = "Provider gateway timeout marked deposit as failed prematurely"
        val failReport = service.evaluateGate(cmd)
        assertEquals(ResilienceGateDecision.NO_GO, failReport.decision)
    }

    // =========================================================================
    // GATE-RESILIENCE-001-T005 — Duplicate, late, and reordered events never regress canonical state
    // =========================================================================
    @Test
    fun `GATE-RESILIENCE-001-T005 — Duplicate, late, and reordered events never regress canonical state`() {
        val manifest = createValidManifest()
        val cmd = EvaluateResilienceGateCommand(
            principal = adminOperatorPrincipal,
            tenantId = tenantId,
            manifest = manifest,
            selectedScenarios = setOf(ResilienceScenarioId.T005_DUPLICATE_REORDERED_NO_REGRESSION),
            correlationId = "corr-res-005",
            causationId = "caus-res-005"
        )

        val report = service.evaluateGate(cmd)
        assertEquals(ResilienceGateDecision.GO, report.decision)
        val result = report.scenarioResults[ResilienceScenarioId.T005_DUPLICATE_REORDERED_NO_REGRESSION]
        assertNotNull(result)
        assertEquals(ResilienceScenarioStatus.PASS, result.status)

        // Direct primitive assertion
        assertTrue(service.validateStateNonRegression("SETTLED", "PENDING"))
        assertTrue(service.validateStateNonRegression("SETTLED", "INITIATED"))
        assertTrue(service.validateStateNonRegression("SETTLED", "SETTLED"))

        // Injected fault
        service.scenarioFaults[ResilienceScenarioId.T005_DUPLICATE_REORDERED_NO_REGRESSION] = "Out-of-order event regressed SETTLED round back to OPEN"
        val failReport = service.evaluateGate(cmd)
        assertEquals(ResilienceGateDecision.NO_GO, failReport.decision)
    }

    // =========================================================================
    // GATE-RESILIENCE-001-T006 — Android network loss, termination, and recreation requery authority without duplicate mutation
    // =========================================================================
    @Test
    fun `GATE-RESILIENCE-001-T006 — Android network loss, termination, and recreation requery authority without duplicate mutation`() {
        val manifest = createValidManifest()
        val cmd = EvaluateResilienceGateCommand(
            principal = adminOperatorPrincipal,
            tenantId = tenantId,
            manifest = manifest,
            selectedScenarios = setOf(ResilienceScenarioId.T006_ANDROID_NETWORK_LOSS_REQUERY),
            correlationId = "corr-res-006",
            causationId = "caus-res-006"
        )

        val report = service.evaluateGate(cmd)
        assertEquals(ResilienceGateDecision.GO, report.decision)
        val result = report.scenarioResults[ResilienceScenarioId.T006_ANDROID_NETWORK_LOSS_REQUERY]
        assertNotNull(result)
        assertEquals(ResilienceScenarioStatus.PASS, result.status)

        // Direct primitive assertion
        assertTrue(service.validateAndroidReconnectionIdempotency(clientReconnected = true))

        // Injected fault
        service.scenarioFaults[ResilienceScenarioId.T006_ANDROID_NETWORK_LOSS_REQUERY] = "App restart triggered duplicate bet submission"
        val failReport = service.evaluateGate(cmd)
        assertEquals(ResilienceGateDecision.NO_GO, failReport.decision)
    }

    // =========================================================================
    // GATE-RESILIENCE-001-T007 — Socket drop, reorder, and gap converge through command journal and snapshot
    // =========================================================================
    @Test
    fun `GATE-RESILIENCE-001-T007 — Socket drop, reorder, and gap converge through command journal and snapshot`() {
        val manifest = createValidManifest()
        val cmd = EvaluateResilienceGateCommand(
            principal = adminOperatorPrincipal,
            tenantId = tenantId,
            manifest = manifest,
            selectedScenarios = setOf(ResilienceScenarioId.T007_SOCKET_DROP_JOURNAL_SNAPSHOT_CONVERGENCE),
            correlationId = "corr-res-007",
            causationId = "caus-res-007"
        )

        val report = service.evaluateGate(cmd)
        assertEquals(ResilienceGateDecision.GO, report.decision)
        val result = report.scenarioResults[ResilienceScenarioId.T007_SOCKET_DROP_JOURNAL_SNAPSHOT_CONVERGENCE]
        assertNotNull(result)
        assertEquals(ResilienceScenarioStatus.PASS, result.status)

        // Direct primitive assertion
        assertTrue(service.validateSocketConvergence(packetsDropped = true))

        // Injected fault
        service.scenarioFaults[ResilienceScenarioId.T007_SOCKET_DROP_JOURNAL_SNAPSHOT_CONVERGENCE] = "Websocket gap caused missing crash multiplier update"
        val failReport = service.evaluateGate(cmd)
        assertEquals(ResilienceGateDecision.NO_GO, failReport.decision)
    }

    // =========================================================================
    // GATE-RESILIENCE-001-T008 — KYC, GEO, Integrity, and AML outages apply approved fail-closed or hold policy
    // =========================================================================
    @Test
    fun `GATE-RESILIENCE-001-T008 — KYC, GEO, Integrity, and AML outages apply approved fail-closed or hold policy`() {
        val manifest = createValidManifest()
        val cmd = EvaluateResilienceGateCommand(
            principal = adminOperatorPrincipal,
            tenantId = tenantId,
            manifest = manifest,
            selectedScenarios = setOf(ResilienceScenarioId.T008_DEPENDENCY_OUTAGES_FAIL_CLOSED),
            correlationId = "corr-res-008",
            causationId = "caus-res-008"
        )

        val report = service.evaluateGate(cmd)
        assertEquals(ResilienceGateDecision.GO, report.decision)
        val result = report.scenarioResults[ResilienceScenarioId.T008_DEPENDENCY_OUTAGES_FAIL_CLOSED]
        assertNotNull(result)
        assertEquals(ResilienceScenarioStatus.PASS, result.status)

        // Direct primitive assertion
        assertTrue(service.validateDependencyOutagePolicy("KYC", isOutage = true))
        assertTrue(service.validateDependencyOutagePolicy("GEO", isOutage = true))
        assertTrue(service.validateDependencyOutagePolicy("AML", isOutage = true))

        // Injected fault
        service.scenarioFaults[ResilienceScenarioId.T008_DEPENDENCY_OUTAGES_FAIL_CLOSED] = "Geolocation outage permitted out-of-jurisdiction wagers"
        val failReport = service.evaluateGate(cmd)
        assertEquals(ResilienceGateDecision.NO_GO, failReport.decision)
    }

    // =========================================================================
    // GATE-RESILIENCE-001-T009 — Migration failure leaves writers unavailable or compatible and exposes integrity evidence
    // =========================================================================
    @Test
    fun `GATE-RESILIENCE-001-T009 — Migration failure leaves writers unavailable or compatible and exposes integrity evidence`() {
        val manifest = createValidManifest()
        val cmd = EvaluateResilienceGateCommand(
            principal = adminOperatorPrincipal,
            tenantId = tenantId,
            manifest = manifest,
            selectedScenarios = setOf(ResilienceScenarioId.T009_MIGRATION_FAILURE_WRITERS_COMPATIBLE),
            correlationId = "corr-res-009",
            causationId = "caus-res-009"
        )

        val report = service.evaluateGate(cmd)
        assertEquals(ResilienceGateDecision.GO, report.decision)
        val result = report.scenarioResults[ResilienceScenarioId.T009_MIGRATION_FAILURE_WRITERS_COMPATIBLE]
        assertNotNull(result)
        assertEquals(ResilienceScenarioStatus.PASS, result.status)

        // Direct primitive assertion
        assertTrue(service.validateMigrationFailureBehavior(migrationFailed = true))

        // Injected fault
        service.scenarioFaults[ResilienceScenarioId.T009_MIGRATION_FAILURE_WRITERS_COMPATIBLE] = "Partial schema migration corrupted ledger constraints"
        val failReport = service.evaluateGate(cmd)
        assertEquals(ResilienceGateDecision.NO_GO, failReport.decision)
    }

    // =========================================================================
    // GATE-RESILIENCE-001-T010 — Region or provider disable stops new activity while completion and reconciliation continue
    // =========================================================================
    @Test
    fun `GATE-RESILIENCE-001-T010 — Region or provider disable stops new activity while completion and reconciliation continue`() {
        val manifest = createValidManifest()
        val cmd = EvaluateResilienceGateCommand(
            principal = adminOperatorPrincipal,
            tenantId = tenantId,
            manifest = manifest,
            selectedScenarios = ResilienceScenarioId.values().toSet(),
            correlationId = "corr-res-010",
            causationId = "caus-res-010"
        )

        // 1. All 10 scenarios evaluated together yield GO
        val report = service.evaluateGate(cmd)
        assertEquals(ResilienceGateDecision.GO, report.decision)
        assertEquals(10, report.scenarioResults.size)
        assertTrue(report.scenarioResults.values.all { it.status == ResilienceScenarioStatus.PASS })

        // 2. Direct primitive assertion
        assertTrue(service.validateDisableRegionOrProvider(regionDisabled = true))

        // 3. Concurrent gate evaluations race safely
        val executor = Executors.newFixedThreadPool(4)
        val tasks = (1..4).map { idx ->
            Callable {
                service.evaluateGate(cmd.copy(correlationId = "corr-res-race-$idx"))
            }
        }
        val futures = executor.invokeAll(tasks)
        executor.shutdown()
        futures.forEach {
            assertEquals(ResilienceGateDecision.GO, it.get().decision)
        }

        // 4. Persistence in evidence store verified
        val reloadedReport = evidenceStore.findLatestReport(tenantId)
        assertNotNull(reloadedReport)
        assertTrue(evidenceStore.findAllReports(tenantId).any { it.reportId == report.reportId })
        assertEquals(ResilienceGateDecision.GO, reloadedReport.decision)

        // 5. Telemetry & alertSink verified
        val metrics = observability.getMetrics()
        assertTrue(metrics.isNotEmpty())
        assertTrue(metrics.any { it.eventType == "resilience_gate_evaluated" })
        metrics.forEach { m ->
            assertFalse(m.details.toString().contains("secret"))
            assertFalse(m.details.toString().contains("password"))
        }

        // 6. Manifest expiration & authorization security checks
        val expiredManifest = manifest.copy(expiry = now.minusSeconds(10))
        assertFailsWith<InvalidResilienceGateManifestException> {
            service.evaluateGate(cmd.copy(manifest = expiredManifest))
        }

        assertFailsWith<UnauthorizedResilienceGateException> {
            service.evaluateGate(cmd.copy(principal = playerPrincipal))
        }

        assertFailsWith<UnauthorizedResilienceGateException> {
            service.evaluateGate(cmd.copy(principal = foreignAdminPrincipal))
        }

        assertFailsWith<UnauthorizedResilienceGateException> {
            service.evaluateGate(cmd.copy(principal = null))
        }
    }
}
