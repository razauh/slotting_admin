package com.slotting.admin.infra

import com.slotting.admin.auth.AdminRole
import com.slotting.admin.auth.AuthenticatedPrincipal
import com.slotting.admin.auth.PrincipalKind
import org.junit.jupiter.api.Assertions.*
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test
import java.time.Clock
import java.time.Instant
import java.time.ZoneOffset
import java.util.concurrent.Callable
import java.util.concurrent.Executors

class ExerciseDdosEdgeControlsTest {

    private lateinit var fixedInstant: Instant
    private lateinit var clock: Clock
    private lateinit var fakeProvider: FakeEdgeDdosProviderAdapter
    private lateinit var service: ExerciseDdosEdgeControlsService

    private val tenantId = "tenant-prod-1"

    private val securityAdmin = AuthenticatedPrincipal(
        id = "admin-sec-1",
        tenantId = tenantId,
        kind = PrincipalKind.ADMIN,
        roles = setOf(AdminRole.SECURITY),
    )

    private val superAdmin = AuthenticatedPrincipal(
        id = "admin-super-1",
        tenantId = tenantId,
        kind = PrincipalKind.ADMIN,
        roles = setOf(AdminRole.SUPER_ADMIN),
    )

    private val auditor = AuthenticatedPrincipal(
        id = "admin-audit-1",
        tenantId = tenantId,
        kind = PrincipalKind.ADMIN,
        roles = setOf(AdminRole.AUDITOR),
    )

    @BeforeEach
    fun setUp() {
        fixedInstant = Instant.parse("2026-09-19T10:00:00Z")
        clock = Clock.fixed(fixedInstant, ZoneOffset.UTC)
        fakeProvider = FakeEdgeDdosProviderAdapter()
        service = ExerciseDdosEdgeControlsService(clock = clock, provider = fakeProvider)
    }

    // =========================================================================
    // INFRA-003-04-T001: Authoritative Outcome Verification
    // =========================================================================

    @Test
    fun `INFRA-003-04-T001 Exercise DDoS and edge emergency controls produces the required authoritative outcome`() {
        // Must fail with AssertionError("rotation/abuse/bypass scenarios") in RED phase
        ExerciseDdosEdgeControlsBinding.checkBound()

        // 1. Configure Edge Controls
        val configResult = service.configureEdgeControls(
            tenantId = tenantId,
            mode = EdgeProtectionMode.NORMAL,
            rateLimitChallengeEnabled = true,
            botChallengeEnabled = true,
            geoFencingEnabled = true,
            nonCriticalSheddingEnabled = false,
            principal = securityAdmin,
            idempotencyKey = "edge-cfg-1",
        )
        assertTrue(configResult.isSuccess)
        val config = configResult.getOrThrow()
        assertEquals(1L, config.version)
        assertEquals(EdgeProtectionMode.NORMAL, config.mode)

        // 2. Exercise DDoS Drill and Rollback
        val drillResult = service.exerciseDdosDrill(
            tenantId = tenantId,
            scenario = DdosDrillScenario.HTTP_LAYER_7_GET_FLOOD,
            principal = superAdmin,
            idempotencyKey = "drill-1",
            verificationEvidence = "Simulated 100k rps GET flood mitigated; rollback to normal verified under 30s",
        )
        assertTrue(drillResult.isSuccess)
        val drill = drillResult.getOrThrow()
        assertTrue(drill.drillSuccess)
        assertTrue(drill.rollbackSuccess)
        assertEquals(80L, drill.mitigationLatencyMs)

        // 3. Authoritative Readiness Evaluation
        val evaluation = service.evaluateDdosEdgeReadiness(tenantId, securityAdmin)
        assertEquals(EdgeReadinessDecision.GO, evaluation.status)
        assertEquals(EdgeReadinessReason.DDOS_CONTROLS_ACTIVE_AND_EMERGENCY_TESTED, evaluation.reason)
        assertEquals(EdgeProtectionMode.NORMAL, evaluation.currentMode)
        assertEquals(1, evaluation.drillsExecutedCount)
        assertTrue(evaluation.emergencyProceduresTested)

        // Semantic & Financial Contracts
        assertFalse(evaluation.directEligibilityGranted)
        assertFalse(evaluation.financialMutationPermitted)
        assertEquals("Rate limits never become financial authority; emergency procedures tested.", evaluation.message)
        assertTrue(evaluation.evidenceReference.isNotBlank())
    }

    // =========================================================================
    // INFRA-003-04-T002: Negative, Boundary & Rejection Verification
    // =========================================================================

    @Test
    fun `INFRA-003-04-T002 Exercise DDoS and edge emergency controls rejects invalid, boundary, unauthorized, and stale input`() {
        ExerciseDdosEdgeControlsBinding.checkBound()

        // Unauthorized principal cannot configure edge controls
        val unauthResult = service.configureEdgeControls(
            tenantId = tenantId,
            mode = EdgeProtectionMode.NORMAL,
            rateLimitChallengeEnabled = true,
            botChallengeEnabled = true,
            geoFencingEnabled = false,
            nonCriticalSheddingEnabled = false,
            principal = auditor,
            idempotencyKey = "unauth-cfg-1",
        )
        assertTrue(unauthResult.isFailure)
        assertTrue(unauthResult.exceptionOrNull() is SecurityException)

        // Cross-tenant configuration forbidden
        val crossTenantPrincipal = AuthenticatedPrincipal(
            id = "cross-admin",
            tenantId = "other-tenant",
            kind = PrincipalKind.ADMIN,
            roles = setOf(AdminRole.SECURITY),
        )
        val crossTenantResult = service.configureEdgeControls(
            tenantId = tenantId,
            mode = EdgeProtectionMode.NORMAL,
            rateLimitChallengeEnabled = true,
            botChallengeEnabled = true,
            geoFencingEnabled = false,
            nonCriticalSheddingEnabled = false,
            principal = crossTenantPrincipal,
            idempotencyKey = "cross-cfg-1",
        )
        assertTrue(crossTenantResult.isFailure)
        assertTrue(crossTenantResult.exceptionOrNull() is SecurityException)

        // Stale expected version conflict
        service.configureEdgeControls(
            tenantId = tenantId,
            mode = EdgeProtectionMode.NORMAL,
            rateLimitChallengeEnabled = true,
            botChallengeEnabled = true,
            geoFencingEnabled = true,
            nonCriticalSheddingEnabled = false,
            principal = securityAdmin,
            idempotencyKey = "cfg-v1",
            expectedVersion = 1L,
        ).getOrThrow()

        val staleResult = service.configureEdgeControls(
            tenantId = tenantId,
            mode = EdgeProtectionMode.UNDER_DDOS_ATTACK,
            rateLimitChallengeEnabled = true,
            botChallengeEnabled = true,
            geoFencingEnabled = true,
            nonCriticalSheddingEnabled = true,
            principal = securityAdmin,
            idempotencyKey = "cfg-stale",
            expectedVersion = 999L,
        )
        assertTrue(staleResult.isFailure)
        assertTrue(staleResult.exceptionOrNull() is IllegalStateException)

        // Untested emergency procedures yields NO_GO
        val evalUntested = service.evaluateDdosEdgeReadiness(tenantId, securityAdmin)
        assertEquals(EdgeReadinessDecision.NO_GO, evalUntested.status)
        assertEquals(EdgeReadinessReason.EMERGENCY_PROCEDURES_UNTESTED, evalUntested.reason)

        // Missing configuration yields NO_GO
        val evalMissing = service.evaluateDdosEdgeReadiness("unconfigured-tenant", securityAdmin)
        assertEquals(EdgeReadinessDecision.NO_GO, evalMissing.status)
        assertEquals(EdgeReadinessReason.ROTATION_ABUSE_BYPASS_SCENARIOS, evalMissing.reason)

        // Audit log captures failures
        val audits = service.getAuditLog(tenantId)
        assertTrue(audits.any { !it.success })
    }

    // =========================================================================
    // INFRA-003-04-T003: Concurrency, Duplicate Delivery, and Failure Recovery
    // =========================================================================

    @Test
    fun `INFRA-003-04-T003 Exercise DDoS and edge emergency controls survives concurrency, duplicate delivery, and dependency failure`() {
        ExerciseDdosEdgeControlsBinding.checkBound()

        // Idempotent duplicate update
        val cfg1 = service.configureEdgeControls(
            tenantId = tenantId,
            mode = EdgeProtectionMode.NORMAL,
            rateLimitChallengeEnabled = true,
            botChallengeEnabled = true,
            geoFencingEnabled = true,
            nonCriticalSheddingEnabled = false,
            principal = securityAdmin,
            idempotencyKey = "idem-cfg-1",
        ).getOrThrow()

        val cfg2 = service.configureEdgeControls(
            tenantId = tenantId,
            mode = EdgeProtectionMode.NORMAL,
            rateLimitChallengeEnabled = true,
            botChallengeEnabled = true,
            geoFencingEnabled = true,
            nonCriticalSheddingEnabled = false,
            principal = securityAdmin,
            idempotencyKey = "idem-cfg-1",
        ).getOrThrow()

        assertEquals(cfg1.configId, cfg2.configId)
        assertEquals(cfg1.version, cfg2.version)

        // Conflict on payload reuse
        val conflictResult = service.configureEdgeControls(
            tenantId = tenantId,
            mode = EdgeProtectionMode.EMERGENCY_SHEDDING,
            rateLimitChallengeEnabled = true,
            botChallengeEnabled = true,
            geoFencingEnabled = true,
            nonCriticalSheddingEnabled = true,
            principal = securityAdmin,
            idempotencyKey = "idem-cfg-1",
        )
        assertTrue(conflictResult.isFailure)
        assertTrue(conflictResult.exceptionOrNull() is IllegalArgumentException)

        // Provider failure handling
        fakeProvider.shouldFail = true
        val failedResult = service.configureEdgeControls(
            tenantId = tenantId,
            mode = EdgeProtectionMode.UNDER_DDOS_ATTACK,
            rateLimitChallengeEnabled = true,
            botChallengeEnabled = true,
            geoFencingEnabled = true,
            nonCriticalSheddingEnabled = true,
            principal = securityAdmin,
            idempotencyKey = "fail-cfg-1",
        )
        assertTrue(failedResult.isFailure)

        // Recover provider
        fakeProvider.shouldFail = false
        val recoveredResult = service.configureEdgeControls(
            tenantId = tenantId,
            mode = EdgeProtectionMode.UNDER_DDOS_ATTACK,
            rateLimitChallengeEnabled = true,
            botChallengeEnabled = true,
            geoFencingEnabled = true,
            nonCriticalSheddingEnabled = true,
            principal = securityAdmin,
            idempotencyKey = "recover-cfg-1",
        )
        assertTrue(recoveredResult.isSuccess)

        // Concurrent drills execution
        val pool = Executors.newFixedThreadPool(4)
        val futures = (1..5).map { i ->
            pool.submit(Callable {
                service.exerciseDdosDrill(
                    tenantId = tenantId,
                    scenario = DdosDrillScenario.VOLUMETRIC_L3_L4_SYN_FLOOD,
                    principal = superAdmin,
                    idempotencyKey = "concurrent-drill-$i",
                    verificationEvidence = "Concurrent drill test $i",
                )
            })
        }
        val results = futures.map { it.get() }
        pool.shutdown()

        assertTrue(results.all { it.isSuccess })
    }

    // =========================================================================
    // INFRA-003-04-T004: Lifecycle, Recovery, and Restore Compatibility
    // =========================================================================

    @Test
    fun `INFRA-003-04-T004 Exercise DDoS and edge emergency controls remains compatible, recoverable, observable, and lifecycle-safe`() {
        ExerciseDdosEdgeControlsBinding.checkBound()

        // Sandbox adapter compatibility
        val sandboxAdapter = SandboxEdgeDdosProviderAdapter()
        val sandboxService = ExerciseDdosEdgeControlsService(clock = clock, provider = sandboxAdapter)

        val sandboxResult = sandboxService.configureEdgeControls(
            tenantId = tenantId,
            mode = EdgeProtectionMode.NORMAL,
            rateLimitChallengeEnabled = true,
            botChallengeEnabled = true,
            geoFencingEnabled = true,
            nonCriticalSheddingEnabled = false,
            principal = securityAdmin,
            idempotencyKey = "sandbox-cfg-1",
        )
        assertTrue(sandboxResult.isSuccess)

        // Exercise full drill scenarios
        service.configureEdgeControls(
            tenantId = tenantId,
            mode = EdgeProtectionMode.NORMAL,
            rateLimitChallengeEnabled = true,
            botChallengeEnabled = true,
            geoFencingEnabled = true,
            nonCriticalSheddingEnabled = false,
            principal = securityAdmin,
            idempotencyKey = "setup-cfg",
        )

        val scenarios = listOf(
            DdosDrillScenario.VOLUMETRIC_L3_L4_SYN_FLOOD,
            DdosDrillScenario.SLOWLORIS_CONNECTION_EXHAUSTION,
            DdosDrillScenario.CREDENTIAL_STUFFING_DISTRIBUTED_BOTNET,
            DdosDrillScenario.EDGE_ORIGIN_FAILOVER_DRILL,
        )

        scenarios.forEachIndexed { idx, scenario ->
            val drill = service.exerciseDdosDrill(
                tenantId = tenantId,
                scenario = scenario,
                principal = superAdmin,
                idempotencyKey = "scenario-drill-$idx",
                verificationEvidence = "Executed $scenario with successful recovery",
            ).getOrThrow()
            assertTrue(drill.drillSuccess)
            assertTrue(drill.rollbackSuccess)
        }

        val evaluation = service.evaluateDdosEdgeReadiness(tenantId, securityAdmin)
        assertEquals(EdgeReadinessDecision.GO, evaluation.status)
        assertEquals("Rate limits never become financial authority; emergency procedures tested.", evaluation.message)
        assertFalse(evaluation.directEligibilityGranted)
        assertFalse(evaluation.financialMutationPermitted)
        assertEquals(4, evaluation.drillsExecutedCount)

        // Observability
        val audits = service.getAuditLog(tenantId)
        assertTrue(audits.isNotEmpty())
        assertTrue(audits.all { it.detailsRedacted.isNotBlank() })
    }
}
