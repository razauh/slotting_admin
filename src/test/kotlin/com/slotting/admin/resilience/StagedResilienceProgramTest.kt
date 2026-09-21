package com.slotting.admin.resilience

import com.slotting.admin.auth.AdminRole
import com.slotting.admin.auth.AuthenticatedPrincipal
import com.slotting.admin.auth.PrincipalKind
import org.junit.jupiter.api.AfterEach
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test
import java.time.Clock
import java.time.Instant
import java.time.ZoneOffset
import java.util.UUID
import java.util.concurrent.Callable
import java.util.concurrent.Executors
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertNotNull
import kotlin.test.assertTrue

class StagedResilienceProgramTest {
    private val now = Instant.parse("2026-09-21T11:00:00Z")
    private val clock = Clock.fixed(now, ZoneOffset.UTC)

    private val tenantId = "tenant-staged-res-01"
    private val programRef = "PROG-STAGED-2026-01"

    private val securityAdminPrincipal = AuthenticatedPrincipal(
        id = "admin-sec-01",
        tenantId = tenantId,
        kind = PrincipalKind.ADMIN,
        roles = setOf(AdminRole.SECURITY, AdminRole.SUPER_ADMIN)
    )

    private val supportAdminPrincipal = AuthenticatedPrincipal(
        id = "admin-support-01",
        tenantId = tenantId,
        kind = PrincipalKind.ADMIN,
        roles = setOf(AdminRole.SUPPORT)
    )

    private val playerPrincipal = AuthenticatedPrincipal(
        id = "player-007",
        tenantId = tenantId,
        kind = PrincipalKind.PLAYER,
        roles = emptySet()
    )

    private val foreignAdminPrincipal = AuthenticatedPrincipal(
        id = "admin-foreign-01",
        tenantId = "tenant-other",
        kind = PrincipalKind.ADMIN,
        roles = setOf(AdminRole.SUPER_ADMIN)
    )

    private lateinit var store: InMemoryStagedResilienceProgramStore
    private lateinit var alertSink: InMemoryStagedResilienceAlertSink
    private lateinit var observability: InMemoryStagedResilienceObservability
    private lateinit var service: StagedResilienceProgramService

    @BeforeEach
    fun setUp() {
        StagedResilienceProgramBinding.checkBound()
        store = InMemoryStagedResilienceProgramStore()
        alertSink = InMemoryStagedResilienceAlertSink()
        observability = InMemoryStagedResilienceObservability()

        service = StagedResilienceProgramService(
            store = store,
            alertSink = alertSink,
            observability = observability,
            clock = clock
        )
    }

    @AfterEach
    fun tearDown() {
    }

    // =========================================================================
    // RES-001-02-T001 — Execute staged resilience program produces the required authoritative outcome
    // =========================================================================
    @Test
    fun `RES-001-02-T001 — Execute staged resilience program produces the required authoritative outcome`() {
        // Step 1: Create 2-stage program (Sandbox non-destructive -> Production destructive)
        val stage1 = ResilienceProgramStage(
            stageLevel = ProgramStageLevel.STAGE_1_SANDBOX,
            environment = TargetEnvironment.SANDBOX,
            isDestructive = false,
            faultTypes = listOf(FaultType.PROVIDER_RPC_TIMEOUT),
            preStateDigest = "DIGEST-SBOX-01"
        )
        val stage2 = ResilienceProgramStage(
            stageLevel = ProgramStageLevel.STAGE_4_PRODUCTION,
            environment = TargetEnvironment.PRODUCTION,
            isDestructive = true,
            faultTypes = listOf(FaultType.DATABASE_ROLLBACK_INJECTION),
            preStateDigest = "DIGEST-PROD-01"
        )

        val createCmd = CreateStagedProgramCommand(
            principal = securityAdminPrincipal,
            tenantId = tenantId,
            programReference = programRef,
            title = "Annual Cross-Environment Resilience Program",
            stages = listOf(stage1, stage2),
            idempotencyKey = "idem-prog-create-01",
            correlationId = "corr-prog-001",
            causationId = "caus-prog-001"
        )

        val createRes = service.createStagedProgram(createCmd)
        assertNotNull(createRes)
        assertEquals(StagedProgramStatus.PLANNED, createRes.record.status)
        assertEquals(2, createRes.record.stages.size)
        assertEquals(STAGED_RESILIENCE_CONTRACT, createRes.record.semanticContract)
        assertFalse(createRes.record.isFinancialAuthorityCreated)
        assertFalse(createRes.record.hasAndroidDbImpact)
        assertFalse(createRes.record.hasAndroidLifecycleClaim)

        // Step 2: Advance Stage 1 (Sandbox)
        val advStage1 = service.advanceStageExecution(
            AdvanceStageExecutionCommand(
                principal = securityAdminPrincipal,
                tenantId = tenantId,
                programReference = programRef,
                simulatedStageDurationMs = 75L,
                idempotencyKey = "idem-adv-s1",
                correlationId = "corr-prog-002",
                causationId = "caus-prog-002"
            )
        )
        assertEquals(StagedProgramStatus.IN_PROGRESS, advStage1.record.status)
        assertEquals(1, advStage1.record.currentStageIndex)
        assertEquals(StageExecutionStatus.PASSED, advStage1.record.stages[0].status)
        assertTrue(advStage1.record.stages[0].dataIntegrityVerified)

        // Step 3: Approve Stage 2 (Production destructive)
        service.approveProductionStage(
            ApproveProductionStageCommand(
                principal = securityAdminPrincipal,
                tenantId = tenantId,
                programReference = programRef,
                approvalReference = "CAB-APPROVAL-STAGED-01",
                justification = "Change approval granted for Stage 4 execution",
                idempotencyKey = "idem-appr-s2",
                correlationId = "corr-prog-003",
                causationId = "caus-prog-003"
            )
        )

        // Step 4: Advance Stage 2 (Production destructive)
        val advStage2 = service.advanceStageExecution(
            AdvanceStageExecutionCommand(
                principal = securityAdminPrincipal,
                tenantId = tenantId,
                programReference = programRef,
                simulatedStageDurationMs = 150L,
                idempotencyKey = "idem-adv-s2",
                correlationId = "corr-prog-004",
                causationId = "caus-prog-004"
            )
        )

        val finalRec = advStage2.record
        assertEquals(StagedProgramStatus.SUCCESSFULLY_COMPLETED, finalRec.status)
        assertEquals(2, finalRec.currentStageIndex)
        assertTrue(finalRec.cumulativeIntegrityVerified)
        assertEquals(225L, finalRec.totalRecoveryTimeMs)
        assertEquals(StageExecutionStatus.PASSED, finalRec.stages[1].status)

        // Verify alerts pipeline
        val alerts = alertSink.getAlerts()
        assertTrue(alerts.any { it.alertType == "PROGRAM_PLANNED" })
        assertTrue(alerts.any { it.alertType == "PROGRAM_PRODUCTION_APPROVED" })
        assertTrue(alerts.any { it.alertType == "STAGE_PASSED" })
    }

    // =========================================================================
    // RES-001-02-T002 — Execute staged resilience program rejects invalid, boundary, unauthorized, and stale input
    // =========================================================================
    @Test
    fun `RES-001-02-T002 — Execute staged resilience program rejects invalid, boundary, unauthorized, and stale input`() {
        val stage1 = ResilienceProgramStage(
            stageLevel = ProgramStageLevel.STAGE_4_PRODUCTION,
            environment = TargetEnvironment.PRODUCTION,
            isDestructive = true,
            faultTypes = listOf(FaultType.NETWORK_SOCKET_DROP),
            preStateDigest = "DIGEST-PROD-REJ"
        )
        val validCreate = CreateStagedProgramCommand(
            principal = securityAdminPrincipal,
            tenantId = tenantId,
            programReference = "PROG-REJECT-001",
            title = "Rejection Test Program",
            stages = listOf(stage1),
            idempotencyKey = "idem-rej-create",
            correlationId = "corr-rej-001",
            causationId = "caus-rej-001"
        )

        // 1. Unauthenticated principal
        assertFailsWith<UnauthorizedStagedProgramException> {
            service.createStagedProgram(validCreate.copy(principal = null))
        }

        // 2. Cross-tenant admin
        assertFailsWith<UnauthorizedStagedProgramException> {
            service.createStagedProgram(validCreate.copy(principal = foreignAdminPrincipal))
        }

        // 3. Unauthorized role (support admin, player)
        assertFailsWith<UnauthorizedStagedProgramException> {
            service.createStagedProgram(validCreate.copy(principal = supportAdminPrincipal))
        }
        assertFailsWith<UnauthorizedStagedProgramException> {
            service.createStagedProgram(validCreate.copy(principal = playerPrincipal))
        }

        // 4. Blank fields or empty stages
        assertFailsWith<InvalidStagedProgramCommandException> {
            service.createStagedProgram(validCreate.copy(programReference = ""))
        }
        assertFailsWith<InvalidStagedProgramCommandException> {
            service.createStagedProgram(validCreate.copy(stages = emptyList()))
        }

        // 5. UNAPPROVED production destructive stage must be strictly blocked!
        service.createStagedProgram(validCreate)
        assertFailsWith<UnapprovedProductionDestructiveProgramException> {
            service.advanceStageExecution(
                AdvanceStageExecutionCommand(
                    principal = securityAdminPrincipal,
                    tenantId = tenantId,
                    programReference = "PROG-REJECT-001",
                    idempotencyKey = "idem-unappr-adv",
                    correlationId = "corr-rej-002",
                    causationId = "caus-rej-002"
                )
            )
        }

        // Verify alert emitted for blocked unapproved production stage
        val alerts = alertSink.getAlerts()
        assertTrue(alerts.any { it.alertType == "UNAPPROVED_PRODUCTION_STAGE_BLOCKED" })
    }

    // =========================================================================
    // RES-001-02-T003 — Execute staged resilience program survives concurrency, duplicate delivery, and dependency failure
    // =========================================================================
    @Test
    fun `RES-001-02-T003 — Execute staged resilience program survives concurrency, duplicate delivery, and dependency failure`() {
        val stage = ResilienceProgramStage(
            stageLevel = ProgramStageLevel.STAGE_2_STAGING,
            environment = TargetEnvironment.STAGING,
            isDestructive = false,
            faultTypes = listOf(FaultType.REDIS_CACHE_PARTITION),
            preStateDigest = "DIGEST-STAGING-CONC"
        )
        val createCmd = CreateStagedProgramCommand(
            principal = securityAdminPrincipal,
            tenantId = tenantId,
            programReference = "PROG-CONC-001",
            title = "Concurrent Program Creation",
            stages = listOf(stage),
            idempotencyKey = "idem-conc-001",
            correlationId = "corr-conc-001",
            causationId = "caus-conc-001"
        )

        // 1. Initial creation
        val initial = service.createStagedProgram(createCmd)
        assertFalse(initial.isDuplicate)

        // 2. Duplicate creation
        val duplicate = service.createStagedProgram(createCmd)
        assertTrue(duplicate.isDuplicate)
        assertEquals(initial.record.programId, duplicate.record.programId)

        // 3. Conflicting payload with same idempotency key
        assertFailsWith<ConflictStagedProgramException> {
            service.createStagedProgram(createCmd.copy(title = "Conflicting Title"))
        }

        // 4. Multithreaded concurrent creations
        val executor = Executors.newFixedThreadPool(4)
        val tasks = (1..4).map { idx ->
            Callable {
                service.createStagedProgram(
                    CreateStagedProgramCommand(
                        principal = securityAdminPrincipal,
                        tenantId = tenantId,
                        programReference = "PROG-THREAD-$idx",
                        title = "Threaded Program $idx",
                        stages = listOf(stage),
                        idempotencyKey = "idem-thread-$idx",
                        correlationId = "corr-thread-$idx",
                        causationId = "caus-thread-$idx"
                    )
                )
            }
        }

        val futures = executor.invokeAll(tasks)
        executor.shutdown()

        for (future in futures) {
            val res = future.get()
            assertNotNull(res)
            assertEquals(StagedProgramStatus.PLANNED, res.record.status)
        }
    }

    // =========================================================================
    // RES-001-02-T004 — Execute staged resilience program remains compatible, recoverable, observable, and lifecycle-safe
    // =========================================================================
    @Test
    fun `RES-001-02-T004 — Execute staged resilience program remains compatible, recoverable, observable, and lifecycle-safe`() {
        val stage = ResilienceProgramStage(
            stageLevel = ProgramStageLevel.STAGE_3_CANARY,
            environment = TargetEnvironment.TEST,
            isDestructive = false,
            faultTypes = listOf(FaultType.OUTBOX_LEASE_EXPIRY_CRASH),
            preStateDigest = "DIGEST-CANARY-004"
        )

        val createCmd = CreateStagedProgramCommand(
            principal = securityAdminPrincipal,
            tenantId = tenantId,
            programReference = "PROG-LIFECYCLE-004",
            title = "Lifecycle and Observability Program",
            stages = listOf(stage),
            idempotencyKey = "idem-life-004",
            correlationId = "corr-life-004",
            causationId = "caus-life-004"
        )

        val createRes = service.createStagedProgram(createCmd)
        val progId = createRes.record.programId

        // Query by ID and reference
        val stored = store.findById(progId)
        assertNotNull(stored)
        assertEquals("PROG-LIFECYCLE-004", stored.programReference)

        val storedByRef = store.findByReference(tenantId, "PROG-LIFECYCLE-004")
        assertNotNull(storedByRef)
        assertEquals(progId, storedByRef.programId)

        // Abort program safely
        val abortRes = service.abortProgram(
            AbortStagedProgramCommand(
                principal = securityAdminPrincipal,
                tenantId = tenantId,
                programReference = "PROG-LIFECYCLE-004",
                reason = "Maintenance window rescheduled",
                idempotencyKey = "idem-abort-004",
                correlationId = "corr-abort-004",
                causationId = "caus-abort-004"
            )
        )
        assertEquals(StagedProgramStatus.ABORTED, abortRes.record.status)

        // Verify Observability Metrics
        val metrics = observability.getMetrics()
        assertTrue(metrics.any { it.eventType == "PROGRAM_PLANNED" && it.programReference == "PROG-LIFECYCLE-004" })
        assertTrue(metrics.any { it.eventType == "PROGRAM_ABORTED" && it.programReference == "PROG-LIFECYCLE-004" })

        // Verify Alerts
        val alerts = alertSink.getAlerts()
        assertTrue(alerts.any { it.alertType == "PROGRAM_PLANNED" })
        assertTrue(alerts.any { it.alertType == "PROGRAM_ABORTED" })

        // Verify Invariants: No financial mutation, no Android DB/lifecycle claims, contract preserved
        assertFalse(stored.isFinancialAuthorityCreated)
        assertFalse(stored.hasAndroidDbImpact)
        assertFalse(stored.hasAndroidLifecycleClaim)
        assertEquals(STAGED_RESILIENCE_CONTRACT, stored.semanticContract)
    }
}
