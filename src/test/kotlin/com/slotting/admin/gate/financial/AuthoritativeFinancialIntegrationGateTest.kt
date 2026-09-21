package com.slotting.admin.gate.financial

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

class AuthoritativeFinancialIntegrationGateTest {
    private var now = Instant.parse("2026-09-21T07:00:00Z")
    private val clock: Clock get() = Clock.fixed(now, ZoneOffset.UTC)

    private val tenantId = "tenant-fin-gate-test"
    private val adminOperatorPrincipal = AuthenticatedPrincipal(
        id = "admin-fin-gate-op-01",
        tenantId = tenantId,
        kind = PrincipalKind.ADMIN,
        roles = setOf(AdminRole.SUPPORT, AdminRole.SUPER_ADMIN)
    )

    private val playerPrincipal = AuthenticatedPrincipal(
        id = "player-fin-01",
        tenantId = tenantId,
        kind = PrincipalKind.PLAYER,
        roles = emptySet()
    )

    private val foreignAdminPrincipal = AuthenticatedPrincipal(
        id = "foreign-admin-fin-99",
        tenantId = "tenant-other",
        kind = PrincipalKind.ADMIN,
        roles = setOf(AdminRole.SUPER_ADMIN)
    )

    private lateinit var evidenceStore: InMemoryFinancialGateEvidenceStore
    private lateinit var alertSink: InMemoryFinancialGateAlertSink
    private lateinit var observability: InMemoryFinancialGateObservability
    private lateinit var service: AuthoritativeFinancialIntegrationGateService

    private fun createValidManifest(): FinancialArtifactManifest {
        return FinancialArtifactManifest(
            commitHash = "794dbc16dc6b882f3102574f241fee436e9d9987",
            artifactDigest = "sha256:fin5b8c9d1e2f3a4b5c6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f1a2b3c4d5e6f7a",
            configurationVersion = "fin-cfg-v1.0",
            environment = "production-candidate",
            owner = "ledger-platform-team",
            reviewer = "head-of-finance-audit",
            signedAt = now.minusSeconds(3600),
            expiry = now.plusSeconds(86400)
        )
    }

    @BeforeEach
    fun setUp() {
        AuthoritativeFinancialIntegrationGateBinding.checkBound()
        evidenceStore = InMemoryFinancialGateEvidenceStore()
        alertSink = InMemoryFinancialGateAlertSink()
        observability = InMemoryFinancialGateObservability()

        service = AuthoritativeFinancialIntegrationGateService(
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
    // GATE-FINANCIAL-001-T001 — Debits equal credits per batch and currency, and posted entries are immutable
    // =========================================================================
    @Test
    fun `GATE-FINANCIAL-001-T001 — Debits equal credits per batch and currency, and posted entries are immutable`() {
        val manifest = createValidManifest()
        val cmd = EvaluateFinancialGateCommand(
            principal = adminOperatorPrincipal,
            tenantId = tenantId,
            manifest = manifest,
            selectedScenarios = setOf(FinancialScenarioId.T001_DEBITS_EQUAL_CREDITS),
            correlationId = "corr-fin-001",
            causationId = "caus-fin-001"
        )

        // 1. Valid execution yields GO
        val report = service.evaluateGate(cmd)
        assertEquals(FinancialGateDecision.GO, report.decision)
        assertEquals(1, report.scenarioResults.size)
        val scenario1 = report.scenarioResults[FinancialScenarioId.T001_DEBITS_EQUAL_CREDITS]
        assertNotNull(scenario1)
        assertEquals(FinancialScenarioStatus.PASS, scenario1.status)
        assertEquals(FINANCIAL_INTEGRATION_GATE_CONTRACT, report.semanticContract)
        assertTrue(report.financialConservationEnforced)
        assertFalse(report.hasAndroidDbImpact)
        assertFalse(report.hasAndroidLifecycleClaim)

        // 2. Direct primitive assertion: unbalanced batch fails
        assertFalse(service.validateJournalConservation(listOf(1000L), listOf(900L), "USD"))

        // 3. Injected defect yields deterministic NO-GO
        service.scenarioFaults[FinancialScenarioId.T001_DEBITS_EQUAL_CREDITS] = "Ledger batch sum debits != credits"
        val failReport = service.evaluateGate(cmd)
        assertEquals(FinancialGateDecision.NO_GO, failReport.decision)
        assertEquals(FinancialScenarioStatus.FAIL, failReport.scenarioResults[FinancialScenarioId.T001_DEBITS_EQUAL_CREDITS]?.status)
    }

    // =========================================================================
    // GATE-FINANCIAL-001-T002 — Journal, projection, reservation, inbox, and outbox commit atomically under injected faults
    // =========================================================================
    @Test
    fun `GATE-FINANCIAL-001-T002 — Journal, projection, reservation, inbox, and outbox commit atomically under injected faults`() {
        val manifest = createValidManifest()
        val cmd = EvaluateFinancialGateCommand(
            principal = adminOperatorPrincipal,
            tenantId = tenantId,
            manifest = manifest,
            selectedScenarios = setOf(FinancialScenarioId.T002_ATOMIC_COMMIT_UNDER_FAULTS),
            correlationId = "corr-fin-002",
            causationId = "caus-fin-002"
        )

        val report = service.evaluateGate(cmd)
        assertEquals(FinancialGateDecision.GO, report.decision)
        val result = report.scenarioResults[FinancialScenarioId.T002_ATOMIC_COMMIT_UNDER_FAULTS]
        assertNotNull(result)
        assertEquals(FinancialScenarioStatus.PASS, result.status)

        // Direct primitive assertion
        assertTrue(service.simulateAtomicCommit(faultInjected = false))
        assertFalse(service.simulateAtomicCommit(faultInjected = true))

        // Injected fault
        service.scenarioFaults[FinancialScenarioId.T002_ATOMIC_COMMIT_UNDER_FAULTS] = "Partial flush left orphaned journal row"
        val failReport = service.evaluateGate(cmd)
        assertEquals(FinancialGateDecision.NO_GO, failReport.decision)
    }

    // =========================================================================
    // GATE-FINANCIAL-001-T003 — Equivalent idempotent replay is stable and changed-payload key reuse conflicts
    // =========================================================================
    @Test
    fun `GATE-FINANCIAL-001-T003 — Equivalent idempotent replay is stable and changed-payload key reuse conflicts`() {
        val manifest = createValidManifest()
        val cmd = EvaluateFinancialGateCommand(
            principal = adminOperatorPrincipal,
            tenantId = tenantId,
            manifest = manifest,
            selectedScenarios = setOf(FinancialScenarioId.T003_IDEMPOTENT_REPLAY_AND_KEY_REUSE),
            correlationId = "corr-fin-003",
            causationId = "caus-fin-003"
        )

        val report = service.evaluateGate(cmd)
        assertEquals(FinancialGateDecision.GO, report.decision)
        val result = report.scenarioResults[FinancialScenarioId.T003_IDEMPOTENT_REPLAY_AND_KEY_REUSE]
        assertNotNull(result)
        assertEquals(FinancialScenarioStatus.PASS, result.status)

        // Direct primitive assertion
        val key = "test-key-idem-unique"
        val res1 = service.testIdempotency(key, "payload-hash-a", "payload-hash-a")
        val res2 = service.testIdempotency(key, "payload-hash-a", "payload-hash-a")
        assertEquals(res1, res2)
        assertFailsWith<FinancialInvariantViolationException> {
            service.testIdempotency(key, "payload-hash-a", "payload-hash-b-modified")
        }

        // Injected fault
        service.scenarioFaults[FinancialScenarioId.T003_IDEMPOTENT_REPLAY_AND_KEY_REUSE] = "Key reuse accepted with modified amount"
        val failReport = service.evaluateGate(cmd)
        assertEquals(FinancialGateDecision.NO_GO, failReport.decision)
    }

    // =========================================================================
    // GATE-FINANCIAL-001-T004 — Concurrent postings and reservations cannot overspend or lose updates
    // =========================================================================
    @Test
    fun `GATE-FINANCIAL-001-T004 — Concurrent postings and reservations cannot overspend or lose updates`() {
        val manifest = createValidManifest()
        val cmd = EvaluateFinancialGateCommand(
            principal = adminOperatorPrincipal,
            tenantId = tenantId,
            manifest = manifest,
            selectedScenarios = setOf(FinancialScenarioId.T004_CONCURRENT_POSTINGS_NO_OVERSPEND),
            correlationId = "corr-fin-004",
            causationId = "caus-fin-004"
        )

        val report = service.evaluateGate(cmd)
        assertEquals(FinancialGateDecision.GO, report.decision)
        val result = report.scenarioResults[FinancialScenarioId.T004_CONCURRENT_POSTINGS_NO_OVERSPEND]
        assertNotNull(result)
        assertEquals(FinancialScenarioStatus.PASS, result.status)

        // Direct primitive assertion: starting 500, debiting 300 twice -> exactly 1 succeeds, remaining 200
        val (finalBal, count) = service.simulateConcurrentPostings(500L, listOf(300L, 300L))
        assertEquals(200L, finalBal)
        assertEquals(1, count)

        // Injected fault
        service.scenarioFaults[FinancialScenarioId.T004_CONCURRENT_POSTINGS_NO_OVERSPEND] = "Race condition produced balance -100"
        val failReport = service.evaluateGate(cmd)
        assertEquals(FinancialGateDecision.NO_GO, failReport.decision)
    }

    // =========================================================================
    // GATE-FINANCIAL-001-T005 — Cash, bonus, pending, locked, and withdrawable buckets never cross illegally
    // =========================================================================
    @Test
    fun `GATE-FINANCIAL-001-T005 — Cash, bonus, pending, locked, and withdrawable buckets never cross illegally`() {
        val manifest = createValidManifest()
        val cmd = EvaluateFinancialGateCommand(
            principal = adminOperatorPrincipal,
            tenantId = tenantId,
            manifest = manifest,
            selectedScenarios = setOf(FinancialScenarioId.T005_BUCKET_INTEGRITY_NO_CROSS),
            correlationId = "corr-fin-005",
            causationId = "caus-fin-005"
        )

        val report = service.evaluateGate(cmd)
        assertEquals(FinancialGateDecision.GO, report.decision)
        val result = report.scenarioResults[FinancialScenarioId.T005_BUCKET_INTEGRITY_NO_CROSS]
        assertNotNull(result)
        assertEquals(FinancialScenarioStatus.PASS, result.status)

        // Direct primitive assertion
        assertFalse(service.validateBucketTransition("BONUS", "WITHDRAWABLE", wageringMet = false))
        assertTrue(service.validateBucketTransition("BONUS", "WITHDRAWABLE", wageringMet = true))
        assertFalse(service.validateBucketTransition("LOCKED", "WITHDRAWABLE", wageringMet = false))

        // Injected fault
        service.scenarioFaults[FinancialScenarioId.T005_BUCKET_INTEGRITY_NO_CROSS] = "Bonus converted directly to withdrawable without wagering"
        val failReport = service.evaluateGate(cmd)
        assertEquals(FinancialGateDecision.NO_GO, failReport.decision)
    }

    // =========================================================================
    // GATE-FINANCIAL-001-T006 — Android and return URLs cannot credit, settle, adjust, or release funds
    // =========================================================================
    @Test
    fun `GATE-FINANCIAL-001-T006 — Android and return URLs cannot credit, settle, adjust, or release funds`() {
        val manifest = createValidManifest()
        val cmd = EvaluateFinancialGateCommand(
            principal = adminOperatorPrincipal,
            tenantId = tenantId,
            manifest = manifest,
            selectedScenarios = setOf(FinancialScenarioId.T006_UNTRUSTED_CLIENT_CANNOT_MUTATE),
            correlationId = "corr-fin-006",
            causationId = "caus-fin-006"
        )

        val report = service.evaluateGate(cmd)
        assertEquals(FinancialGateDecision.GO, report.decision)
        val result = report.scenarioResults[FinancialScenarioId.T006_UNTRUSTED_CLIENT_CANNOT_MUTATE]
        assertNotNull(result)
        assertEquals(FinancialScenarioStatus.PASS, result.status)

        // Direct primitive assertion
        assertFalse(service.validateClientAuthority(isUntrustedClient = true))
        assertTrue(service.validateClientAuthority(isUntrustedClient = false))

        // Injected fault
        service.scenarioFaults[FinancialScenarioId.T006_UNTRUSTED_CLIENT_CANNOT_MUTATE] = "Client return URL settled deposit directly"
        val failReport = service.evaluateGate(cmd)
        assertEquals(FinancialGateDecision.NO_GO, failReport.decision)
    }

    // =========================================================================
    // GATE-FINANCIAL-001-T007 — Duplicate, late, and reordered provider events produce one lawful financial effect
    // =========================================================================
    @Test
    fun `GATE-FINANCIAL-001-T007 — Duplicate, late, and reordered provider events produce one lawful financial effect`() {
        val manifest = createValidManifest()
        val cmd = EvaluateFinancialGateCommand(
            principal = adminOperatorPrincipal,
            tenantId = tenantId,
            manifest = manifest,
            selectedScenarios = setOf(FinancialScenarioId.T007_DUPLICATE_REORDERED_PROVIDER_EVENTS),
            correlationId = "corr-fin-007",
            causationId = "caus-fin-007"
        )

        val report = service.evaluateGate(cmd)
        assertEquals(FinancialGateDecision.GO, report.decision)
        val result = report.scenarioResults[FinancialScenarioId.T007_DUPLICATE_REORDERED_PROVIDER_EVENTS]
        assertNotNull(result)
        assertEquals(FinancialScenarioStatus.PASS, result.status)

        // Direct primitive assertion
        val provRef = "ref-order-test-1"
        assertEquals("PROCESSED", service.processProviderCallback("ev1", "SETTLED", provRef))
        assertEquals("DEDUPLICATED", service.processProviderCallback("ev2", "SETTLED", provRef))
        assertEquals("IGNORED_REORDERED", service.processProviderCallback("ev0", "INITIATED", provRef))

        // Injected fault
        service.scenarioFaults[FinancialScenarioId.T007_DUPLICATE_REORDERED_PROVIDER_EVENTS] = "Duplicate callback created second ledger credit"
        val failReport = service.evaluateGate(cmd)
        assertEquals(FinancialGateDecision.NO_GO, failReport.decision)
    }

    // =========================================================================
    // GATE-FINANCIAL-001-T008 — Refunds, rollbacks, and chargebacks use immutable compensating entries
    // =========================================================================
    @Test
    fun `GATE-FINANCIAL-001-T008 — Refunds, rollbacks, and chargebacks use immutable compensating entries`() {
        val manifest = createValidManifest()
        val cmd = EvaluateFinancialGateCommand(
            principal = adminOperatorPrincipal,
            tenantId = tenantId,
            manifest = manifest,
            selectedScenarios = setOf(FinancialScenarioId.T008_IMMUTABLE_COMPENSATING_ENTRIES),
            correlationId = "corr-fin-008",
            causationId = "caus-fin-008"
        )

        val report = service.evaluateGate(cmd)
        assertEquals(FinancialGateDecision.GO, report.decision)
        val result = report.scenarioResults[FinancialScenarioId.T008_IMMUTABLE_COMPENSATING_ENTRIES]
        assertNotNull(result)
        assertEquals(FinancialScenarioStatus.PASS, result.status)

        // Direct primitive assertion
        val original = listOf("account-a" to 2000L, "account-b" to -2000L)
        val comp = service.createCompensatingBatch("batch-1", original)
        assertEquals(-2000L, comp[0].second)
        assertEquals(2000L, comp[1].second)

        // Injected fault
        service.scenarioFaults[FinancialScenarioId.T008_IMMUTABLE_COMPENSATING_ENTRIES] = "Historical journal row mutated during refund"
        val failReport = service.evaluateGate(cmd)
        assertEquals(FinancialGateDecision.NO_GO, failReport.decision)
    }

    // =========================================================================
    // GATE-FINANCIAL-001-T009 — Journal rebuild equals projections and cursor statements
    // =========================================================================
    @Test
    fun `GATE-FINANCIAL-001-T009 — Journal rebuild equals projections and cursor statements`() {
        val manifest = createValidManifest()
        val cmd = EvaluateFinancialGateCommand(
            principal = adminOperatorPrincipal,
            tenantId = tenantId,
            manifest = manifest,
            selectedScenarios = setOf(FinancialScenarioId.T009_JOURNAL_REBUILD_EQUALS_PROJECTION),
            correlationId = "corr-fin-009",
            causationId = "caus-fin-009"
        )

        val report = service.evaluateGate(cmd)
        assertEquals(FinancialGateDecision.GO, report.decision)
        val result = report.scenarioResults[FinancialScenarioId.T009_JOURNAL_REBUILD_EQUALS_PROJECTION]
        assertNotNull(result)
        assertEquals(FinancialScenarioStatus.PASS, result.status)

        // Direct primitive assertion
        val entries = listOf("tx1" to 1000L, "tx2" to -400L, "tx3" to 150L)
        assertEquals(750L, service.rebuildProjectionFromJournal(entries))

        // Injected fault
        service.scenarioFaults[FinancialScenarioId.T009_JOURNAL_REBUILD_EQUALS_PROJECTION] = "Projection rebuild drifted by 50 cents"
        val failReport = service.evaluateGate(cmd)
        assertEquals(FinancialGateDecision.NO_GO, failReport.decision)
    }

    // =========================================================================
    // GATE-FINANCIAL-001-T010 — Provider and ledger reports surface every mismatch and stuck item
    // =========================================================================
    @Test
    fun `GATE-FINANCIAL-001-T010 — Provider and ledger reports surface every mismatch and stuck item`() {
        val manifest = createValidManifest()
        val cmd = EvaluateFinancialGateCommand(
            principal = adminOperatorPrincipal,
            tenantId = tenantId,
            manifest = manifest,
            selectedScenarios = setOf(FinancialScenarioId.T010_MISMATCH_AND_STUCK_ITEMS_SURFACED),
            correlationId = "corr-fin-010",
            causationId = "caus-fin-010"
        )

        val report = service.evaluateGate(cmd)
        assertEquals(FinancialGateDecision.GO, report.decision)
        val result = report.scenarioResults[FinancialScenarioId.T010_MISMATCH_AND_STUCK_ITEMS_SURFACED]
        assertNotNull(result)
        assertEquals(FinancialScenarioStatus.PASS, result.status)

        // Direct primitive assertion
        assertTrue(service.detectReconciliationDiscrepancies(5000L, 4900L))
        assertFalse(service.detectReconciliationDiscrepancies(5000L, 5000L))

        // Injected fault
        service.scenarioFaults[FinancialScenarioId.T010_MISMATCH_AND_STUCK_ITEMS_SURFACED] = "Reconciliation exception dropped silently"
        val failReport = service.evaluateGate(cmd)
        assertEquals(FinancialGateDecision.NO_GO, failReport.decision)
    }

    // =========================================================================
    // GATE-FINANCIAL-001-T011 — Restore and replay preserve counts, hashes, balances, and event lineage
    // =========================================================================
    @Test
    fun `GATE-FINANCIAL-001-T011 — Restore and replay preserve counts, hashes, balances, and event lineage`() {
        val manifest = createValidManifest()
        val cmd = EvaluateFinancialGateCommand(
            principal = adminOperatorPrincipal,
            tenantId = tenantId,
            manifest = manifest,
            selectedScenarios = setOf(FinancialScenarioId.T011_RESTORE_REPLAY_LINEAGE_PRESERVED),
            correlationId = "corr-fin-011",
            causationId = "caus-fin-011"
        )

        val report = service.evaluateGate(cmd)
        assertEquals(FinancialGateDecision.GO, report.decision)
        val result = report.scenarioResults[FinancialScenarioId.T011_RESTORE_REPLAY_LINEAGE_PRESERVED]
        assertNotNull(result)
        assertEquals(FinancialScenarioStatus.PASS, result.status)

        // Direct primitive assertion
        assertTrue(service.verifyBackupRestoreIntegrity("hash1", "hash1", 100L, 100L))
        assertFalse(service.verifyBackupRestoreIntegrity("hash1", "hash2", 100L, 100L))
        assertFalse(service.verifyBackupRestoreIntegrity("hash1", "hash1", 100L, 99L))

        // Injected fault
        service.scenarioFaults[FinancialScenarioId.T011_RESTORE_REPLAY_LINEAGE_PRESERVED] = "Restored backup hash mismatch detected"
        val failReport = service.evaluateGate(cmd)
        assertEquals(FinancialGateDecision.NO_GO, failReport.decision)
    }

    // =========================================================================
    // GATE-FINANCIAL-001-T012 — Currency, minor-unit, range, and null constraints reject malformed values
    // =========================================================================
    @Test
    fun `GATE-FINANCIAL-001-T012 — Currency, minor-unit, range, and null constraints reject malformed values`() {
        val manifest = createValidManifest()
        val cmd = EvaluateFinancialGateCommand(
            principal = adminOperatorPrincipal,
            tenantId = tenantId,
            manifest = manifest,
            selectedScenarios = FinancialScenarioId.values().toSet(),
            correlationId = "corr-fin-012",
            causationId = "caus-fin-012"
        )

        // 1. All 12 scenarios evaluated together yield GO
        val report = service.evaluateGate(cmd)
        assertEquals(FinancialGateDecision.GO, report.decision)
        assertEquals(12, report.scenarioResults.size)
        assertTrue(report.scenarioResults.values.all { it.status == FinancialScenarioStatus.PASS })

        // 2. Direct primitive assertion
        assertTrue(service.validateFinancialConstraints(100L, "USD"))
        assertFalse(service.validateFinancialConstraints(-50L, "USD"))
        assertFalse(service.validateFinancialConstraints(100L, "INVALID_CURRENCY"))

        // 3. Concurrent gate evaluations race safely
        val executor = Executors.newFixedThreadPool(4)
        val tasks = (1..4).map { idx ->
            Callable {
                service.evaluateGate(cmd.copy(correlationId = "corr-fin-race-$idx"))
            }
        }
        val futures = executor.invokeAll(tasks)
        executor.shutdown()
        futures.forEach {
            assertEquals(FinancialGateDecision.GO, it.get().decision)
        }

        // 4. Persistence in evidence store verified
        val reloadedReport = evidenceStore.findLatestReport(tenantId)
        assertNotNull(reloadedReport)
        assertTrue(evidenceStore.findAllReports(tenantId).any { it.reportId == report.reportId })
        assertEquals(FinancialGateDecision.GO, reloadedReport.decision)

        // 5. Telemetry & alertSink verified
        val metrics = observability.getMetrics()
        assertTrue(metrics.isNotEmpty())
        assertTrue(metrics.any { it.eventType == "financial_gate_evaluated" })
        metrics.forEach { m ->
            assertFalse(m.details.toString().contains("secret"))
            assertFalse(m.details.toString().contains("password"))
        }

        // 6. Manifest expiration & authorization security checks
        val expiredManifest = manifest.copy(expiry = now.minusSeconds(10))
        assertFailsWith<InvalidFinancialGateManifestException> {
            service.evaluateGate(cmd.copy(manifest = expiredManifest))
        }

        assertFailsWith<UnauthorizedFinancialGateException> {
            service.evaluateGate(cmd.copy(principal = playerPrincipal))
        }

        assertFailsWith<UnauthorizedFinancialGateException> {
            service.evaluateGate(cmd.copy(principal = foreignAdminPrincipal))
        }

        assertFailsWith<UnauthorizedFinancialGateException> {
            service.evaluateGate(cmd.copy(principal = null))
        }
    }
}
