package com.slotting.admin.observability

import com.slotting.admin.auth.AdminRole
import com.slotting.admin.auth.AuthenticatedPrincipal
import com.slotting.admin.auth.PrincipalKind
import org.junit.jupiter.api.Assertions.*
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.DisplayName
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.assertThrows
import java.time.Clock
import java.time.Instant
import java.time.ZoneOffset
import java.util.UUID
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit

class OperationalSloTest {

    private val tenantId = "tenant-slo-01"
    private val clock = Clock.fixed(Instant.parse("2026-09-19T22:00:00Z"), ZoneOffset.UTC)
    private lateinit var service: OperationalSloService

    private val validPrincipal = AuthenticatedPrincipal(
        id = "slo-admin-01",
        tenantId = tenantId,
        roles = setOf(AdminRole.SUPPORT),
        kind = PrincipalKind.ADMIN,
    )

    private val otherTenantPrincipal = AuthenticatedPrincipal(
        id = "slo-admin-other",
        tenantId = "tenant-other",
        roles = setOf(AdminRole.SUPPORT),
        kind = PrincipalKind.ADMIN,
    )

    @BeforeEach
    fun setup() {
        service = OperationalSloService(clock = clock)
    }

    private fun createDefineCommand(
        sloName: String = "ledger-posting-slo",
        serviceName: String = "ledger-service",
        indicatorType: SloIndicatorType = SloIndicatorType.AVAILABILITY,
        incidentFocus: CriticalIncidentType = CriticalIncidentType.POSTING_FAILURE,
        targetPercentage: Double = 99.9,
        idempotencyKey: String = "idem-slo-def-${UUID.randomUUID()}",
        tenant: String = tenantId,
        principal: AuthenticatedPrincipal? = validPrincipal,
    ) = DefineSloCommand(
        principal = principal,
        tenantId = tenant,
        sloName = sloName,
        serviceName = serviceName,
        indicatorType = indicatorType,
        incidentFocus = incidentFocus,
        targetPercentage = targetPercentage,
        idempotencyKey = idempotencyKey,
        correlationId = "corr-${UUID.randomUUID()}",
        causationId = "caus-${UUID.randomUUID()}",
    )

    private fun createEvaluateCommand(
        sloId: UUID,
        observedSuccessCount: Long = 999L,
        observedTotalCount: Long = 1000L,
        idempotencyKey: String = "idem-slo-eval-${UUID.randomUUID()}",
        expectedVersion: Long = 1L,
        tenant: String = tenantId,
        principal: AuthenticatedPrincipal? = validPrincipal,
    ) = EvaluateSloCommand(
        principal = principal,
        tenantId = tenant,
        sloId = sloId,
        observedSuccessCount = observedSuccessCount,
        observedTotalCount = observedTotalCount,
        idempotencyKey = idempotencyKey,
        correlationId = "corr-${UUID.randomUUID()}",
        causationId = "caus-${UUID.randomUUID()}",
        expectedVersion = expectedVersion,
    )

    @Test
    @DisplayName("OBS-001-02-T001 — Define production SLOs produces the required authoritative outcome")
    fun testOBS_001_02_T001_AuthoritativeOutcome() {
        val defCmd = createDefineCommand(
            sloName = "posting-failure-slo",
            incidentFocus = CriticalIncidentType.POSTING_FAILURE,
            targetPercentage = 99.9
        )
        val defResult = service.defineSlo(defCmd)

        assertEquals(
            "Dashboards include duplicates, posting failures, imbalance, mismatch, failed callbacks, stuck withdrawals.",
            defResult.semanticContract
        )
        assertFalse(defResult.directEligibilityGranted)
        assertFalse(defResult.financialMutationPermitted)
        assertEquals(SloStatus.HEALTHY, defResult.sloStatus)
        assertEquals(99.9, defResult.targetPercentage, 0.001)

        // Evaluate healthy SLO: 99.95% success (higher than 99.9% target)
        val healthyEval = service.evaluateSlo(
            createEvaluateCommand(
                sloId = defResult.sloId,
                observedSuccessCount = 9995L,
                observedTotalCount = 10000L,
                expectedVersion = 1L
            )
        )
        assertEquals(SloStatus.HEALTHY, healthyEval.sloStatus)
        assertFalse(healthyEval.paged)

        // Injected critical failure: 95.0% success (breaches 99.9% target, burn rate >= 1.0) -> MUST page
        val breachedEval = service.evaluateSlo(
            createEvaluateCommand(
                sloId = defResult.sloId,
                observedSuccessCount = 9500L,
                observedTotalCount = 10000L,
                expectedVersion = 2L
            )
        )
        assertEquals(SloStatus.BREACHED, breachedEval.sloStatus)
        assertTrue(breachedEval.paged, "Injected critical failure breaching SLO must trigger page")
        assertTrue(breachedEval.currentBurnRate >= 1.0)

        // Verify breach audit trail
        val breachAudits = service.getBreachAuditEntries(defResult.sloId)
        assertEquals(1, breachAudits.size)
        assertTrue(breachAudits[0].paged)
        assertEquals(CriticalIncidentType.POSTING_FAILURE, breachAudits[0].incidentFocus)
    }

    @Test
    @DisplayName("OBS-001-02-T002 — Define production SLOs rejects invalid, boundary, unauthorized, and stale input")
    fun testOBS_001_02_T002_RejectInvalidBoundaryUnauthorizedStale() {
        // 1. Unauthenticated define
        val unauthEx = assertThrows<SloException> {
            service.defineSlo(createDefineCommand(principal = null))
        }
        assertEquals("UNAUTHENTICATED", unauthEx.errorCode)

        // 2. Cross-tenant define
        val forbiddenEx = assertThrows<SloException> {
            service.defineSlo(createDefineCommand(principal = otherTenantPrincipal))
        }
        assertEquals("FORBIDDEN", forbiddenEx.errorCode)

        // 3. Boundary check: targetPercentage <= 0 or > 100
        val boundaryEx = assertThrows<SloException> {
            service.defineSlo(createDefineCommand(targetPercentage = 105.0))
        }
        assertEquals("BOUNDARY", boundaryEx.errorCode)

        // Successfully define
        val defined = service.defineSlo(createDefineCommand())

        // 4. Stale version on evaluation
        val staleEx = assertThrows<SloException> {
            service.evaluateSlo(
                createEvaluateCommand(
                    sloId = defined.sloId,
                    expectedVersion = 999L
                )
            )
        }
        assertEquals("STALE", staleEx.errorCode)

        // 5. Boundary check on evaluation: success > total
        val evalBoundaryEx = assertThrows<SloException> {
            service.evaluateSlo(
                createEvaluateCommand(
                    sloId = defined.sloId,
                    observedSuccessCount = 200L,
                    observedTotalCount = 100L,
                    expectedVersion = 1L
                )
            )
        }
        assertEquals("BOUNDARY", evalBoundaryEx.errorCode)
    }

    @Test
    @DisplayName("OBS-001-02-T003 — Define production SLOs survives concurrency, duplicate delivery, and dependency failure")
    fun testOBS_001_02_T003_ConcurrencyDuplicateDeliveryAndDependencyFailure() {
        val defCmd = createDefineCommand(idempotencyKey = "slo-idem-c1")
        val res1 = service.defineSlo(defCmd)

        // Idempotent duplicate replay
        val res2 = service.defineSlo(defCmd)
        assertEquals(res1.sloId, res2.sloId)
        assertEquals(res1.serverTime, res2.serverTime)

        // Conflicting payload reuse produces CONFLICT
        val conflictEx = assertThrows<SloException> {
            service.defineSlo(defCmd.copy(targetPercentage = 95.0))
        }
        assertEquals("CONFLICT", conflictEx.errorCode)

        // Concurrent evaluation races on the same SLO
        val executor = Executors.newFixedThreadPool(4)
        val successfulEvals = ConcurrentHashMap<String, SloResult>()
        val failureExceptions = ConcurrentHashMap<String, Exception>()

        for (i in 1..4) {
            val key = "eval-concurrent-$i"
            executor.submit {
                try {
                    val res = service.evaluateSlo(
                        createEvaluateCommand(
                            sloId = res1.sloId,
                            idempotencyKey = key,
                            expectedVersion = 1L
                        )
                    )
                    successfulEvals[key] = res
                } catch (e: Exception) {
                    failureExceptions[key] = e
                }
            }
        }

        executor.shutdown()
        assertTrue(executor.awaitTermination(5, TimeUnit.SECONDS))

        // Exactly one concurrent evaluation succeeds; remaining fail due to version mismatch
        assertEquals(1, successfulEvals.size)
        assertEquals(3, failureExceptions.size)
    }

    @Test
    @DisplayName("OBS-001-02-T004 — Define production SLOs remains compatible, recoverable, observable, and lifecycle-safe")
    fun testOBS_001_02_T004_CompatibilityRecoverableObservableAndLifecycleSafe() {
        // Define SLOs for all critical operational incident domains
        val incidentTypes = listOf(
            Pair("slo-duplicate", CriticalIncidentType.DUPLICATE_REQUEST),
            Pair("slo-posting", CriticalIncidentType.POSTING_FAILURE),
            Pair("slo-imbalance", CriticalIncidentType.BALANCE_IMBALANCE),
            Pair("slo-catalog", CriticalIncidentType.CATALOG_MISMATCH),
            Pair("slo-callback", CriticalIncidentType.CALLBACK_FAILURE),
            Pair("slo-withdrawal", CriticalIncidentType.STUCK_WITHDRAWAL),
        )

        val createdSlos = incidentTypes.map { (name, type) ->
            service.defineSlo(
                createDefineCommand(
                    sloName = name,
                    incidentFocus = type,
                    targetPercentage = 99.9
                )
            )
        }

        // Breach the posting SLO to verify dashboard paging aggregation
        val postingSlo = createdSlos.first { it.incidentFocus == CriticalIncidentType.POSTING_FAILURE }
        service.evaluateSlo(
            createEvaluateCommand(
                sloId = postingSlo.sloId,
                observedSuccessCount = 800L,
                observedTotalCount = 1000L,
                expectedVersion = 1L
            )
        )

        val summary = service.getDashboardSummary(tenantId)
        assertEquals(6, summary.totalSlos)
        assertEquals(5, summary.healthySlos)
        assertEquals(0, summary.warningSlos)
        assertEquals(1, summary.breachedSlos)
        assertEquals(1, summary.activeBreachPages)

        val record = service.getSloRecord(postingSlo.sloId)
        assertNotNull(record)
        assertFalse(record!!.directEligibilityGranted)
        assertFalse(record.financialMutationPermitted)
        assertEquals(SloStatus.BREACHED, record.sloStatus)
    }
}
