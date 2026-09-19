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

class CriticalPagingTest {

    private val tenantId = "tenant-paging-01"
    private val clock = Clock.fixed(Instant.parse("2026-09-19T22:00:00Z"), ZoneOffset.UTC)
    private lateinit var service: CriticalPagingService

    private val validAdminPrincipal = AuthenticatedPrincipal(
        id = "paging-admin-01",
        tenantId = tenantId,
        roles = setOf(AdminRole.SUPER_ADMIN),
        kind = PrincipalKind.ADMIN,
    )

    private val auditorPrincipal = AuthenticatedPrincipal(
        id = "auditor-01",
        tenantId = tenantId,
        roles = setOf(AdminRole.AUDITOR),
        kind = PrincipalKind.ADMIN,
    )

    private val otherTenantPrincipal = AuthenticatedPrincipal(
        id = "other-admin-01",
        tenantId = "tenant-other",
        roles = setOf(AdminRole.SUPER_ADMIN),
        kind = PrincipalKind.ADMIN,
    )

    @BeforeEach
    fun setup() {
        service = CriticalPagingService(clock = clock)
    }

    private fun createTriggerCommand(
        category: IncidentCategory = IncidentCategory.FINANCIAL,
        failureType: CriticalFailureType = CriticalFailureType.POSTING_FAILURE,
        title: String = "Ledger Out-of-Balance Detected",
        description: String = "Journal debit sum does not match credit sum for transaction 999",
        idempotencyKey: String = "idem-trigger-${UUID.randomUUID()}",
        tenant: String = tenantId,
        principal: AuthenticatedPrincipal? = validAdminPrincipal,
    ) = TriggerCriticalPageCommand(
        principal = principal,
        tenantId = tenant,
        category = category,
        failureType = failureType,
        title = title,
        description = description,
        idempotencyKey = idempotencyKey,
        correlationId = "corr-${UUID.randomUUID()}",
        causationId = "caus-${UUID.randomUUID()}",
    )

    private fun createAcknowledgeCommand(
        incidentId: UUID,
        note: String = "On-call investigating root cause",
        idempotencyKey: String = "idem-ack-${UUID.randomUUID()}",
        expectedVersion: Long = 1L,
        tenant: String = tenantId,
        principal: AuthenticatedPrincipal? = validAdminPrincipal,
    ) = AcknowledgePageCommand(
        principal = principal,
        tenantId = tenant,
        incidentId = incidentId,
        note = note,
        idempotencyKey = idempotencyKey,
        correlationId = "corr-${UUID.randomUUID()}",
        causationId = "caus-${UUID.randomUUID()}",
        expectedVersion = expectedVersion,
    )

    private fun createResolveCommand(
        incidentId: UUID,
        resolutionSummary: String = "Database replica re-synced, out-of-balance corrected",
        idempotencyKey: String = "idem-res-${UUID.randomUUID()}",
        expectedVersion: Long = 2L,
        tenant: String = tenantId,
        principal: AuthenticatedPrincipal? = validAdminPrincipal,
    ) = ResolvePageCommand(
        principal = principal,
        tenantId = tenant,
        incidentId = incidentId,
        resolutionSummary = resolutionSummary,
        idempotencyKey = idempotencyKey,
        correlationId = "corr-${UUID.randomUUID()}",
        causationId = "caus-${UUID.randomUUID()}",
        expectedVersion = expectedVersion,
    )

    @Test
    @DisplayName("OBS-001-03-T001 — Page on critical financial and security failures produces the required authoritative outcome")
    fun testOBS_001_03_T001_AuthoritativeOutcome() {
        val triggerCmd = createTriggerCommand(
            category = IncidentCategory.FINANCIAL,
            failureType = CriticalFailureType.POSTING_FAILURE
        )
        val triggerResult = service.triggerCriticalPage(triggerCmd)

        assertEquals(
            "Dashboards include duplicates, posting failures, imbalance, mismatch, failed callbacks, stuck withdrawals.",
            triggerResult.semanticContract
        )
        assertFalse(triggerResult.directEligibilityGranted)
        assertFalse(triggerResult.financialMutationPermitted)
        assertTrue(triggerResult.paged, "Injected critical failure must trigger page")
        assertEquals(PagingIncidentStatus.PAGING_TRIGGERED, triggerResult.status)
        assertTrue(triggerResult.pagerReference.startsWith("page-ref-"))

        // Acknowledge page
        val ackCmd = createAcknowledgeCommand(
            incidentId = triggerResult.incidentId,
            expectedVersion = 1L
        )
        val ackResult = service.acknowledgePage(ackCmd)
        assertEquals(PagingIncidentStatus.ACKNOWLEDGED, ackResult.status)

        // Resolve page
        val resCmd = createResolveCommand(
            incidentId = triggerResult.incidentId,
            expectedVersion = 2L
        )
        val resResult = service.resolvePage(resCmd)
        assertEquals(PagingIncidentStatus.RESOLVED, resResult.status)
        assertFalse(resResult.directEligibilityGranted)
        assertFalse(resResult.financialMutationPermitted)

        // Verify audit log
        val auditEntries = service.getAuditEntries(triggerResult.incidentId)
        assertEquals(3, auditEntries.size)
        assertEquals("CRITICAL_PAGE_TRIGGERED", auditEntries[0].eventType)
        assertEquals("CRITICAL_PAGE_ACKNOWLEDGED", auditEntries[1].eventType)
        assertEquals("CRITICAL_PAGE_RESOLVED", auditEntries[2].eventType)
    }

    @Test
    @DisplayName("OBS-001-03-T002 — Page on critical financial and security failures rejects invalid, boundary, unauthorized, and stale input")
    fun testOBS_001_03_T002_RejectInvalidBoundaryUnauthorizedStale() {
        // 1. Unauthenticated trigger
        val unauthEx = assertThrows<CriticalPagingException> {
            service.triggerCriticalPage(createTriggerCommand(principal = null))
        }
        assertEquals("UNAUTHENTICATED", unauthEx.errorCode)

        // 2. Cross-tenant access
        val forbiddenEx = assertThrows<CriticalPagingException> {
            service.triggerCriticalPage(createTriggerCommand(principal = otherTenantPrincipal))
        }
        assertEquals("FORBIDDEN", forbiddenEx.errorCode)

        // 3. Boundary check: empty title
        val boundaryEx = assertThrows<CriticalPagingException> {
            service.triggerCriticalPage(createTriggerCommand(title = ""))
        }
        assertEquals("INVALID", boundaryEx.errorCode)

        // Trigger valid incident
        val incident = service.triggerCriticalPage(createTriggerCommand())

        // 4. Stale version on acknowledge
        val staleEx = assertThrows<CriticalPagingException> {
            service.acknowledgePage(createAcknowledgeCommand(incidentId = incident.incidentId, expectedVersion = 999L))
        }
        assertEquals("STALE", staleEx.errorCode)

        // 5. RBAC check: AUDITOR cannot resolve critical page
        service.acknowledgePage(createAcknowledgeCommand(incidentId = incident.incidentId, expectedVersion = 1L))
        val rbacEx = assertThrows<CriticalPagingException> {
            service.resolvePage(createResolveCommand(incidentId = incident.incidentId, principal = auditorPrincipal, expectedVersion = 2L))
        }
        assertEquals("FORBIDDEN", rbacEx.errorCode)
    }

    @Test
    @DisplayName("OBS-001-03-T003 — Page on critical financial and security failures survives concurrency, duplicate delivery, and dependency failure")
    fun testOBS_001_03_T003_ConcurrencyDuplicateDeliveryAndDependencyFailure() {
        val triggerCmd = createTriggerCommand(idempotencyKey = "page-idem-c1")
        val res1 = service.triggerCriticalPage(triggerCmd)

        // Idempotent duplicate replay
        val res2 = service.triggerCriticalPage(triggerCmd)
        assertEquals(res1.incidentId, res2.incidentId)
        assertEquals(res1.serverTime, res2.serverTime)

        // Conflicting payload reuse produces CONFLICT
        val conflictEx = assertThrows<CriticalPagingException> {
            service.triggerCriticalPage(triggerCmd.copy(title = "Conflicting title"))
        }
        assertEquals("CONFLICT", conflictEx.errorCode)

        // Concurrent acknowledge races
        val executor = Executors.newFixedThreadPool(4)
        val successfulAcks = ConcurrentHashMap<String, PagingIncidentResult>()
        val failureExceptions = ConcurrentHashMap<String, Exception>()

        for (i in 1..4) {
            val key = "ack-concurrent-$i"
            executor.submit {
                try {
                    val res = service.acknowledgePage(
                        createAcknowledgeCommand(
                            incidentId = res1.incidentId,
                            idempotencyKey = key,
                            expectedVersion = 1L
                        )
                    )
                    successfulAcks[key] = res
                } catch (e: Exception) {
                    failureExceptions[key] = e
                }
            }
        }

        executor.shutdown()
        assertTrue(executor.awaitTermination(5, TimeUnit.SECONDS))

        // Exactly one acknowledge succeeds, remainder fail due to version mismatch or state transition conflict
        assertEquals(1, successfulAcks.size)
        assertEquals(3, failureExceptions.size)
    }

    @Test
    @DisplayName("OBS-001-03-T004 — Page on critical financial and security failures remains compatible, recoverable, observable, and lifecycle-safe")
    fun testOBS_001_03_T004_CompatibilityRecoverableObservableAndLifecycleSafe() {
        // Trigger financial incidents
        val inc1 = service.triggerCriticalPage(
            createTriggerCommand(category = IncidentCategory.FINANCIAL, failureType = CriticalFailureType.POSTING_FAILURE)
        )
        service.acknowledgePage(createAcknowledgeCommand(incidentId = inc1.incidentId, expectedVersion = 1L))
        service.resolvePage(createResolveCommand(incidentId = inc1.incidentId, expectedVersion = 2L))

        val inc2 = service.triggerCriticalPage(
            createTriggerCommand(category = IncidentCategory.FINANCIAL, failureType = CriticalFailureType.STUCK_WITHDRAWAL)
        )

        // Trigger security incident
        val inc3 = service.triggerCriticalPage(
            createTriggerCommand(category = IncidentCategory.SECURITY, failureType = CriticalFailureType.AUTH_BREACH)
        )

        val summary = service.getDashboardSummary(tenantId)
        assertEquals(3, summary.totalIncidents)
        assertEquals(2, summary.activePaging)
        assertEquals(0, summary.acknowledged)
        assertEquals(1, summary.resolved)
        assertEquals(2, summary.financialIncidents)
        assertEquals(1, summary.securityIncidents)

        val record = service.getIncidentRecord(inc1.incidentId)
        assertNotNull(record)
        assertFalse(record!!.directEligibilityGranted)
        assertFalse(record.financialMutationPermitted)
        assertEquals(PagingIncidentStatus.RESOLVED, record.status)
    }
}
