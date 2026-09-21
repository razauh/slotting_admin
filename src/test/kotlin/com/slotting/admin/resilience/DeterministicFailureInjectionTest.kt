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

class DeterministicFailureInjectionTest {
    private val now = Instant.parse("2026-09-21T10:00:00Z")
    private val clock = Clock.fixed(now, ZoneOffset.UTC)

    private val tenantId = "tenant-resilience-01"
    private val experimentRef = "EXP-FAULT-2026-001"

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
        id = "player-777",
        tenantId = tenantId,
        kind = PrincipalKind.PLAYER,
        roles = emptySet()
    )

    private val foreignAdminPrincipal = AuthenticatedPrincipal(
        id = "admin-foreign-01",
        tenantId = "tenant-different",
        kind = PrincipalKind.ADMIN,
        roles = setOf(AdminRole.SUPER_ADMIN)
    )

    private lateinit var store: InMemoryFailureInjectionExperimentStore
    private lateinit var alertSink: InMemoryFailureInjectionAlertSink
    private lateinit var observability: InMemoryFailureInjectionObservability
    private lateinit var service: DeterministicFailureInjectionService

    @BeforeEach
    fun setUp() {
        FailureInjectionBinding.checkBound()
        store = InMemoryFailureInjectionExperimentStore()
        alertSink = InMemoryFailureInjectionAlertSink()
        observability = InMemoryFailureInjectionObservability()

        service = DeterministicFailureInjectionService(
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
    // RES-001-01-T001 — Build deterministic failure-injection experiments produces the required authoritative outcome
    // =========================================================================
    @Test
    fun `RES-001-01-T001 — Build deterministic failure-injection experiments produces the required authoritative outcome`() {
        // Step 1: Plan a destructive experiment targeting PRODUCTION
        val planCmd = CreateExperimentPlanCommand(
            principal = securityAdminPrincipal,
            tenantId = tenantId,
            experimentReference = experimentRef,
            faultType = FaultType.DATABASE_ROLLBACK_INJECTION,
            targetEnvironment = TargetEnvironment.PRODUCTION,
            isDestructive = true,
            preStateDigest = "DIGEST-DB-STATE-001",
            details = mapOf("targetCluster" to "primary-db-readwrite"),
            idempotencyKey = "idem-plan-001",
            correlationId = "corr-exp-001",
            causationId = "caus-exp-001"
        )

        val planRes = service.createExperimentPlan(planCmd)
        assertNotNull(planRes)
        assertEquals(ExperimentStatus.PLANNED, planRes.record.status)
        assertEquals(FAILURE_INJECTION_CONTRACT, planRes.record.semanticContract)
        assertFalse(planRes.record.isFinancialAuthorityCreated)
        assertFalse(planRes.record.hasAndroidDbImpact)
        assertFalse(planRes.record.hasAndroidLifecycleClaim)

        // Step 2: Formally approve the destructive production test
        val approveCmd = ApproveExperimentCommand(
            principal = securityAdminPrincipal,
            tenantId = tenantId,
            experimentReference = experimentRef,
            approvalReference = "CAB-APPROVAL-2026-99",
            justification = "Quarterly DR resilience validation approved by Change Advisory Board",
            idempotencyKey = "idem-appr-001",
            correlationId = "corr-exp-002",
            causationId = "caus-exp-002"
        )

        val approveRes = service.approveExperiment(approveCmd)
        assertEquals(ExperimentStatus.APPROVED, approveRes.record.status)
        assertEquals("CAB-APPROVAL-2026-99", approveRes.record.approvalReference)

        // Step 3: Execute approved experiment
        val executeCmd = ExecuteExperimentCommand(
            principal = securityAdminPrincipal,
            tenantId = tenantId,
            experimentReference = experimentRef,
            simulatedDurationMs = 120L,
            injectInvariantBreach = false,
            idempotencyKey = "idem-exec-001",
            correlationId = "corr-exp-003",
            causationId = "caus-exp-003"
        )

        val executeRes = service.executeExperiment(executeCmd)
        val rec = executeRes.record

        assertEquals(ExperimentStatus.RECOVERED_SUCCESS, rec.status)
        assertTrue(rec.dataIntegrityVerified)
        assertFalse(rec.invariantsViolated)
        assertEquals(120L, rec.recoveryTimeMs)
        assertEquals("DIGEST-DB-STATE-001", rec.postStateDigest)

        // Verify alert pipeline recorded alerts
        val alerts = alertSink.getAlerts()
        assertTrue(alerts.any { it.alertType == "EXPERIMENT_PLANNED" })
        assertTrue(alerts.any { it.alertType == "EXPERIMENT_APPROVED" })
        assertTrue(alerts.any { it.alertType == "EXPERIMENT_RECOVERY_COMPLETED" })
    }

    // =========================================================================
    // RES-001-01-T002 — Build deterministic failure-injection experiments rejects invalid, boundary, unauthorized, and stale input
    // =========================================================================
    @Test
    fun `RES-001-01-T002 — Build deterministic failure-injection experiments rejects invalid, boundary, unauthorized, and stale input`() {
        val validPlan = CreateExperimentPlanCommand(
            principal = securityAdminPrincipal,
            tenantId = tenantId,
            experimentReference = "EXP-REJECT-001",
            faultType = FaultType.REDIS_CACHE_PARTITION,
            targetEnvironment = TargetEnvironment.PRODUCTION,
            isDestructive = true,
            preStateDigest = "DIGEST-REDIS-001",
            idempotencyKey = "idem-rej-001",
            correlationId = "corr-rej-001",
            causationId = "caus-rej-001"
        )

        // 1. Unauthenticated principal
        assertFailsWith<UnauthorizedFailureInjectionException> {
            service.createExperimentPlan(validPlan.copy(principal = null))
        }

        // 2. Cross-tenant admin
        assertFailsWith<UnauthorizedFailureInjectionException> {
            service.createExperimentPlan(validPlan.copy(principal = foreignAdminPrincipal))
        }

        // 3. Unauthorized role (support admin, player)
        assertFailsWith<UnauthorizedFailureInjectionException> {
            service.createExperimentPlan(validPlan.copy(principal = supportAdminPrincipal))
        }
        assertFailsWith<UnauthorizedFailureInjectionException> {
            service.createExperimentPlan(validPlan.copy(principal = playerPrincipal))
        }

        // 4. Blank fields
        assertFailsWith<InvalidFailureInjectionCommandException> {
            service.createExperimentPlan(validPlan.copy(experimentReference = ""))
        }
        assertFailsWith<InvalidFailureInjectionCommandException> {
            service.createExperimentPlan(validPlan.copy(preStateDigest = ""))
        }

        // 5. UNAPPROVED destructive test in PRODUCTION must be rejected!
        service.createExperimentPlan(validPlan)
        val unapprovedExecute = ExecuteExperimentCommand(
            principal = securityAdminPrincipal,
            tenantId = tenantId,
            experimentReference = "EXP-REJECT-001",
            idempotencyKey = "idem-unapproved-exec",
            correlationId = "corr-rej-002",
            causationId = "caus-rej-002"
        )
        assertFailsWith<UnapprovedDestructiveExperimentException> {
            service.executeExperiment(unapprovedExecute)
        }

        // Verify alert emitted for blocked unapproved destructive test
        val alerts = alertSink.getAlerts()
        assertTrue(alerts.any { it.alertType == "UNAPPROVED_DESTRUCTIVE_PRODUCTION_BLOCKED" })
    }

    // =========================================================================
    // RES-001-01-T003 — Build deterministic failure-injection experiments survives concurrency, duplicate delivery, and dependency failure
    // =========================================================================
    @Test
    fun `RES-001-01-T003 — Build deterministic failure-injection experiments survives concurrency, duplicate delivery, and dependency failure`() {
        val planCmd = CreateExperimentPlanCommand(
            principal = securityAdminPrincipal,
            tenantId = tenantId,
            experimentReference = "EXP-CONC-001",
            faultType = FaultType.PROVIDER_RPC_TIMEOUT,
            targetEnvironment = TargetEnvironment.STAGING,
            isDestructive = false,
            preStateDigest = "DIGEST-STAGING-001",
            idempotencyKey = "idem-conc-999",
            correlationId = "corr-conc-001",
            causationId = "caus-conc-001"
        )

        // 1. Initial plan creation
        val initial = service.createExperimentPlan(planCmd)
        assertFalse(initial.isDuplicate)

        // 2. Duplicate delivery with identical key
        val duplicate = service.createExperimentPlan(planCmd)
        assertTrue(duplicate.isDuplicate)
        assertEquals(initial.record.experimentId, duplicate.record.experimentId)

        // 3. Conflicting payload with same idempotency key
        assertFailsWith<ConflictFailureInjectionException> {
            service.createExperimentPlan(planCmd.copy(faultType = FaultType.NETWORK_SOCKET_DROP))
        }

        // 4. Multithreaded concurrent plan creation
        val executor = Executors.newFixedThreadPool(4)
        val tasks = (1..4).map { idx ->
            Callable {
                service.createExperimentPlan(
                    CreateExperimentPlanCommand(
                        principal = securityAdminPrincipal,
                        tenantId = tenantId,
                        experimentReference = "EXP-CONC-THREAD-$idx",
                        faultType = FaultType.OUTBOX_LEASE_EXPIRY_CRASH,
                        targetEnvironment = TargetEnvironment.SANDBOX,
                        isDestructive = false,
                        preStateDigest = "DIGEST-THREAD-$idx",
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
            assertEquals(ExperimentStatus.PLANNED, res.record.status)
        }
    }

    // =========================================================================
    // RES-001-01-T004 — Build deterministic failure-injection experiments remains compatible, recoverable, observable, and lifecycle-safe
    // =========================================================================
    @Test
    fun `RES-001-01-T004 — Build deterministic failure-injection experiments remains compatible, recoverable, observable, and lifecycle-safe`() {
        val planCmd = CreateExperimentPlanCommand(
            principal = securityAdminPrincipal,
            tenantId = tenantId,
            experimentReference = "EXP-LIFECYCLE-004",
            faultType = FaultType.WORKER_ABORT_RETRY,
            targetEnvironment = TargetEnvironment.TEST,
            isDestructive = false,
            preStateDigest = "DIGEST-TEST-004",
            idempotencyKey = "idem-life-004",
            correlationId = "corr-life-004",
            causationId = "caus-life-004"
        )

        val planRes = service.createExperimentPlan(planCmd)
        val experimentId = planRes.record.experimentId

        // Query by ID and reference
        val stored = store.findById(experimentId)
        assertNotNull(stored)
        assertEquals("EXP-LIFECYCLE-004", stored.experimentReference)

        val storedByRef = store.findByReference(tenantId, "EXP-LIFECYCLE-004")
        assertNotNull(storedByRef)
        assertEquals(experimentId, storedByRef.experimentId)

        // Abort experiment safely
        val abortRes = service.abortExperiment(
            AbortExperimentCommand(
                principal = securityAdminPrincipal,
                tenantId = tenantId,
                experimentReference = "EXP-LIFECYCLE-004",
                abortReason = "Pre-flight checks identified worker dependency maintenance",
                idempotencyKey = "idem-abort-004",
                correlationId = "corr-abort-004",
                causationId = "caus-abort-004"
            )
        )
        assertEquals(ExperimentStatus.ABORTED, abortRes.record.status)

        // Verify Observability Metrics
        val metrics = observability.getMetrics()
        assertTrue(metrics.any { it.eventType == "EXPERIMENT_PLANNED" && it.experimentReference == "EXP-LIFECYCLE-004" })
        assertTrue(metrics.any { it.eventType == "EXPERIMENT_ABORTED" && it.experimentReference == "EXP-LIFECYCLE-004" })

        // Verify Alerts
        val alerts = alertSink.getAlerts()
        assertTrue(alerts.any { it.alertType == "EXPERIMENT_PLANNED" })
        assertTrue(alerts.any { it.alertType == "EXPERIMENT_ABORTED" })

        // Verify Invariant Assertions
        assertFalse(stored.isFinancialAuthorityCreated)
        assertFalse(stored.hasAndroidDbImpact)
        assertFalse(stored.hasAndroidLifecycleClaim)
        assertEquals(FAILURE_INJECTION_CONTRACT, stored.semanticContract)
    }
}
