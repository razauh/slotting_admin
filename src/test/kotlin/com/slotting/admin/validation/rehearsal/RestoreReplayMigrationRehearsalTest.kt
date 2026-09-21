package com.slotting.admin.validation.rehearsal

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

class RestoreReplayMigrationRehearsalTest {

    private lateinit var evidenceStore: InMemoryRehearsalEvidenceStore
    private lateinit var alertSink: InMemoryRehearsalAlertSink
    private lateinit var observability: InMemoryRehearsalObservability
    private lateinit var service: RestoreReplayMigrationRehearsalService

    private val tenantId = "tenant-prod-1"
    private val clock = Clock.systemUTC()

    private val adminPrincipal = AuthenticatedPrincipal(
        id = "admin-rehearsal-1",
        tenantId = tenantId,
        roles = setOf(AdminRole.SUPER_ADMIN),
        kind = PrincipalKind.ADMIN
    )

    private val validManifest = RehearsalArtifactManifest(
        commitHash = "794dbc16dc6b882f3102574f241fee436e9d9987",
        artifactDigest = "sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        configurationVersion = "v10.3.0",
        environment = "PRODUCTION",
        owner = "infrastructure-lead",
        reviewer = "security-auditor",
        signedAt = Instant.now().minusSeconds(3600),
        expiry = Instant.now().plusSeconds(86400)
    )

    @BeforeEach
    fun setUp() {
        evidenceStore = InMemoryRehearsalEvidenceStore()
        alertSink = InMemoryRehearsalAlertSink()
        observability = InMemoryRehearsalObservability()
        service = RestoreReplayMigrationRehearsalService(
            evidenceStore = evidenceStore,
            alertSink = alertSink,
            observability = observability,
            clock = clock
        )
    }

    private fun buildValidCommand(
        rehearsalType: RehearsalType = RehearsalType.FULL_COMBINED,
        decisionType: RehearsalDecisionType = RehearsalDecisionType.FORWARD_FIX,
        idempotencyKey: String = "idem-${UUID.randomUUID()}"
    ) = RunRehearsalCommand(
        principal = adminPrincipal,
        tenantId = tenantId,
        rehearsalType = rehearsalType,
        manifest = validManifest,
        maxAllowedRpoMs = 60_000L,
        maxAllowedRtoMs = 900_000L,
        decisionType = decisionType,
        decisionJustification = "Validated automated rehearsal forward-fix with zero ledger imbalance",
        idempotencyKey = idempotencyKey,
        correlationId = "corr-${UUID.randomUUID()}",
        causationId = "caus-${UUID.randomUUID()}"
    )

    @Test
    @DisplayName("SYS-003-T001 — Restore/replay/migration rehearsal produces the required authoritative outcome")
    fun testT001ProducesAuthoritativeOutcome() {
        val cmd = buildValidCommand()
        val report = service.runRehearsal(cmd)

        assertNotNull(report)
        assertEquals(cmd.tenantId, report.tenantId)
        assertEquals(RehearsalStatus.PASSED, report.status)
        assertTrue(report.isContractSatisfied)
        assertFalse(report.hasAndroidLifecycleClaim)
        assertFalse(report.hasAndroidDbImpact)

        // Exact semantic contract assertions:
        // "Zero ledger imbalance; approved RPO/RTO; forward-fix/rollback decision recorded."
        assertTrue(report.integrityEvidence.isZeroLedgerImbalance, "Zero ledger imbalance required")
        assertEquals(0L, report.integrityEvidence.ledgerImbalanceMinor, "Imbalance minor units must be zero")
        assertEquals(
            report.integrityEvidence.ledgerTotalDebitsMinor,
            report.integrityEvidence.ledgerTotalCreditsMinor,
            "Debits must equal credits"
        )
        assertTrue(report.integrityEvidence.checksumMatches, "Checksums must match pre- and post-rehearsal")
        assertEquals(0, report.integrityEvidence.eventLineageGapsDetected, "Zero event lineage gaps required")

        // Approved RPO/RTO
        assertTrue(report.rpoRtoMetrics.isRpoApproved, "RPO must be approved")
        assertTrue(report.rpoRtoMetrics.isRtoApproved, "RTO must be approved")
        assertTrue(report.rpoRtoMetrics.actualRpoMs <= report.rpoRtoMetrics.targetRpoMs)
        assertTrue(report.rpoRtoMetrics.actualRtoMs <= report.rpoRtoMetrics.targetRtoMs)

        // Forward-fix/rollback decision recorded
        assertEquals(RehearsalDecisionType.FORWARD_FIX, report.decisionRecord.decisionType)
        assertEquals(adminPrincipal.id, report.decisionRecord.decidedBy)
        assertTrue(report.decisionRecord.rollbackPreservesPostedHistory)
        assertTrue(report.decisionRecord.justification.isNotBlank())

        // Correlation / causation and evidence reference
        assertEquals(cmd.correlationId, report.correlationId)
        assertEquals(cmd.causationId, report.causationId)
        assertTrue(report.evidenceReference.startsWith("ev-rehearsal-"))
    }

    @Test
    @DisplayName("SYS-003-T002 — Restore/replay/migration rehearsal rejects invalid, boundary, unauthorized, and stale input")
    fun testT002RejectsInvalidAndUnauthorizedInput() {
        val baseCmd = buildValidCommand()

        // 1. Unauthenticated principal
        assertThrows(UnauthorizedRehearsalException::class.java) {
            service.runRehearsal(baseCmd.copy(principal = null))
        }

        // 2. Unauthorized role
        val playerPrincipal = AuthenticatedPrincipal(
            id = "player-99",
            tenantId = tenantId,
            roles = emptySet(),
            kind = PrincipalKind.PLAYER
        )
        assertThrows(UnauthorizedRehearsalException::class.java) {
            service.runRehearsal(baseCmd.copy(principal = playerPrincipal))
        }

        // 3. Cross-tenant principal
        val crossTenantPrincipal = adminPrincipal.copy(tenantId = "foreign-tenant")
        assertThrows(UnauthorizedRehearsalException::class.java) {
            service.runRehearsal(baseCmd.copy(principal = crossTenantPrincipal))
        }

        // 4. Stale / Expired manifest
        val expiredManifest = validManifest.copy(expiry = Instant.now().minusSeconds(180))
        assertThrows(InvalidRehearsalManifestException::class.java) {
            service.runRehearsal(baseCmd.copy(manifest = expiredManifest))
        }

        // 5. Blank manifest fields
        val blankManifest = validManifest.copy(commitHash = "")
        assertThrows(InvalidRehearsalManifestException::class.java) {
            service.runRehearsal(baseCmd.copy(manifest = blankManifest))
        }

        // 6. Invalid RPO/RTO bounds
        assertThrows(InvalidRehearsalInputException::class.java) {
            service.runRehearsal(baseCmd.copy(maxAllowedRpoMs = 0L))
        }
        assertThrows(InvalidRehearsalInputException::class.java) {
            service.runRehearsal(baseCmd.copy(maxAllowedRtoMs = -500L))
        }

        // 7. Blank justification
        assertThrows(InvalidRehearsalInputException::class.java) {
            service.runRehearsal(baseCmd.copy(decisionJustification = "  "))
        }

        // 8. Blank correlation / causation
        assertThrows(InvalidRehearsalInputException::class.java) {
            service.runRehearsal(baseCmd.copy(correlationId = " "))
        }
        assertThrows(InvalidRehearsalInputException::class.java) {
            service.runRehearsal(baseCmd.copy(causationId = ""))
        }

        // 9. Injected fault: Ledger Imbalance -> throws RehearsalValidationException with "checksum/balance/event gaps"
        service.scenarioFaults["LEDGER_IMBALANCE"] = "Injected 100 minor imbalance"
        val ex1 = assertThrows(RehearsalValidationException::class.java) {
            service.runRehearsal(buildValidCommand())
        }
        assertTrue(ex1.message!!.startsWith("checksum/balance/event gaps"))
        service.scenarioFaults.clear()

        // 10. Injected fault: Checksum Mismatch -> throws RehearsalValidationException with "checksum/balance/event gaps"
        service.scenarioFaults["CHECKSUM_MISMATCH"] = "Injected bit flip"
        val ex2 = assertThrows(RehearsalValidationException::class.java) {
            service.runRehearsal(buildValidCommand())
        }
        assertTrue(ex2.message!!.startsWith("checksum/balance/event gaps"))
        service.scenarioFaults.clear()

        // 11. Injected fault: Event Gap -> throws RehearsalValidationException with "checksum/balance/event gaps"
        service.scenarioFaults["EVENT_GAP"] = "Injected missing events"
        val ex3 = assertThrows(RehearsalValidationException::class.java) {
            service.runRehearsal(buildValidCommand())
        }
        assertTrue(ex3.message!!.startsWith("checksum/balance/event gaps"))
        service.scenarioFaults.clear()

        // Zero unauthorized durable mutation
        assertEquals(0, evidenceStore.getAllReports().size)
    }

    @Test
    @DisplayName("SYS-003-T003 — Restore/replay/migration rehearsal survives concurrency, duplicate delivery, and dependency failure")
    fun testT003SurvivesConcurrencyDuplicateAndFailure() {
        val idempotencyKey = "idem-rehearsal-${UUID.randomUUID()}"
        val cmd1 = buildValidCommand(idempotencyKey = idempotencyKey)

        // 1. First execution
        val report1 = service.runRehearsal(cmd1)
        assertNotNull(report1)

        // 2. Duplicate delivery / idempotent replay
        val report2 = service.runRehearsal(cmd1)
        assertEquals(report1.rehearsalId, report2.rehearsalId)
        assertEquals(report1.evidenceReference, report2.evidenceReference)

        // 3. Conflicting key reuse
        val conflictingCmd = cmd1.copy(rehearsalType = RehearsalType.RESTORE)
        assertThrows(IdempotencyConflictException::class.java) {
            service.runRehearsal(conflictingCmd)
        }

        // 4. Concurrency race on same idempotency key
        val executor = Executors.newFixedThreadPool(8)
        val concurrentKey = "idem-race-${UUID.randomUUID()}"
        val concurrentCmd = buildValidCommand(idempotencyKey = concurrentKey)
        val tasks = (1..8).map {
            Callable { service.runRehearsal(concurrentCmd) }
        }
        val futures = executor.invokeAll(tasks)
        executor.shutdown()

        val results = futures.map { it.get() }
        val firstId = results[0].rehearsalId
        assertTrue(results.all { it.rehearsalId == firstId }, "All concurrent replays must share the same rehearsal ID")

        // 5. Injected dependency failure
        service.scenarioFaults["DEPENDENCY_FAILURE"] = "S3 backup bucket connection timeout"
        val failCmd = buildValidCommand()
        val dex = assertThrows(RehearsalExecutionException::class.java) {
            service.runRehearsal(failCmd)
        }
        assertTrue(dex.message!!.contains("S3 backup bucket connection timeout"))
        service.scenarioFaults.clear()

        val alerts = alertSink.getAlerts()
        assertTrue(alerts.any { it.message.contains("Dependency failure") })
    }

    @Test
    @DisplayName("SYS-003-T004 — Restore/replay/migration rehearsal remains compatible, recoverable, observable, and lifecycle-safe")
    fun testT004RemainsCompatibleRecoverableObservableAndLifecycleSafe() {
        val cmd = buildValidCommand(decisionType = RehearsalDecisionType.ROLLBACK)
        val report = service.runRehearsal(cmd)

        // 1. Android lifecycle boundary verification
        assertFalse(report.hasAndroidLifecycleClaim, "Must not claim Android lifecycle authority")
        assertFalse(report.hasAndroidDbImpact, "Must not claim Android DB authority")

        // 2. Observability verification
        assertTrue(observability.getExecutionsCount() > 0)
        assertTrue(observability.getPhasesCompletedCount() >= 7)

        // 3. Recovery from durable evidence store (Restart Simulation)
        val recoveredReport = evidenceStore.getReport(report.rehearsalId)
        assertNotNull(recoveredReport, "Report must be recoverable from evidence store")
        assertEquals(report.rehearsalId, recoveredReport!!.rehearsalId)
        assertTrue(recoveredReport.isContractSatisfied)

        // Exact semantic contract assertion on recovered state:
        // "Zero ledger imbalance; approved RPO/RTO; forward-fix/rollback decision recorded."
        assertTrue(recoveredReport.integrityEvidence.isZeroLedgerImbalance)
        assertEquals(0L, recoveredReport.integrityEvidence.ledgerImbalanceMinor)
        assertEquals(
            recoveredReport.integrityEvidence.ledgerTotalDebitsMinor,
            recoveredReport.integrityEvidence.ledgerTotalCreditsMinor
        )
        assertTrue(recoveredReport.rpoRtoMetrics.isRpoApproved)
        assertTrue(recoveredReport.rpoRtoMetrics.isRtoApproved)
        assertEquals(RehearsalDecisionType.ROLLBACK, recoveredReport.decisionRecord.decisionType)
        assertTrue(recoveredReport.decisionRecord.rollbackPreservesPostedHistory)
    }
}
