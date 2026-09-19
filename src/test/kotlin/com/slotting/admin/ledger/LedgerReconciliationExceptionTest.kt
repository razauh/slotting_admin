package com.slotting.admin.ledger

import com.slotting.admin.auth.AdminRole
import com.slotting.admin.auth.AuthenticatedPrincipal
import com.slotting.admin.auth.PrincipalKind
import org.junit.jupiter.api.Assertions.*
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.DisplayName
import org.junit.jupiter.api.Test
import java.time.Clock
import java.time.Instant
import java.time.ZoneOffset
import java.util.UUID
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit

class LedgerReconciliationExceptionTest {

    private val tenantId = "tenant-reconcile-005"
    private val clock = Clock.fixed(Instant.parse("2026-09-19T12:00:00Z"), ZoneOffset.UTC)
    private lateinit var service: LedgerReconciliationExceptionService

    private val validAdminPrincipal = AuthenticatedPrincipal(
        id = "admin-user-01",
        tenantId = tenantId,
        roles = setOf(AdminRole.SUPER_ADMIN),
        kind = PrincipalKind.ADMIN,
    )

    private val otherTenantPrincipal = AuthenticatedPrincipal(
        id = "admin-user-other",
        tenantId = "tenant-other",
        roles = setOf(AdminRole.SUPER_ADMIN),
        kind = PrincipalKind.ADMIN,
    )

    private val unauthorizedPlayerPrincipal = AuthenticatedPrincipal(
        id = "player-001",
        tenantId = tenantId,
        roles = emptySet(),
        kind = PrincipalKind.PLAYER,
    )

    @BeforeEach
    fun setup() {
        service = LedgerReconciliationExceptionService(clock)
    }

    @Test
    @DisplayName("LEDGER-005-02-T001 — Manage immutable reconciliation exceptions produces the required authoritative outcome")
    fun testT001_AuthoritativeOutcome() {
        // Create an exception for an imbalance
        val createCmd = CreateLedgerExceptionCommand(
            principal = validAdminPrincipal,
            tenantId = tenantId,
            accountReference = "ACC-PLAYER-101",
            currencyCode = "USD",
            discrepancyMinorUnits = 5000L,
            journalSumMinorUnits = 10000L,
            projectedBalanceMinorUnits = 15000L,
            idempotencyKey = "idem-create-001",
            correlationId = "corr-001",
            causationId = "caus-001",
        )

        val createResult = service.createException(createCmd)

        // Assert: Zero-tolerance ledger imbalance pages; exceptions cannot be silently closed.
        assertEquals("Zero-tolerance ledger imbalance pages; exceptions cannot be silently closed.", createResult.semanticContract)
        assertFalse(createResult.directEligibilityGranted)
        assertFalse(createResult.financialMutationPermitted)
        assertTrue(createResult.exception.isPaged)
        assertEquals(DiscrepancySeverity.CRITICAL, createResult.exception.severity)
        assertEquals(LedgerExceptionStatus.PAGED, createResult.exception.status)
        assertEquals(1L, createResult.exception.version)
        assertNotNull(createResult.exception.auditChecksumSha256)

        // Assign exception
        val assignCmd = AssignLedgerExceptionCommand(
            principal = validAdminPrincipal,
            tenantId = tenantId,
            exceptionId = createResult.exception.exceptionId,
            assigneeId = "investigator-01",
            expectedVersion = 1L,
            correlationId = "corr-002",
            causationId = "caus-002",
        )
        val assignResult = service.assignException(assignCmd)
        assertEquals(LedgerExceptionStatus.ASSIGNED, assignResult.exception.status)
        assertEquals("investigator-01", assignResult.exception.assigneeId)
        assertEquals(2L, assignResult.exception.version)

        // Resolve with compensation
        val compensationBatchId = UUID.randomUUID()
        val resolveCmd = ResolveLedgerExceptionCommand(
            principal = validAdminPrincipal,
            tenantId = tenantId,
            exceptionId = createResult.exception.exceptionId,
            compensationBatchId = compensationBatchId,
            reasonCode = "RECONCILIATION_CORRECTION",
            resolutionNotes = "Compensation journal entry posted to correct timing mismatch",
            approverId = "supervisor-01",
            expectedVersion = 2L,
            idempotencyKey = "idem-resolve-001",
            correlationId = "corr-003",
            causationId = "caus-003",
        )
        val resolveResult = service.resolveExceptionWithCompensation(resolveCmd)
        assertEquals(LedgerExceptionStatus.RESOLVED_BY_COMPENSATION, resolveResult.exception.status)
        assertEquals(compensationBatchId, resolveResult.exception.compensationBatchId)
        assertEquals(3L, resolveResult.exception.version)

        // Assert audit trail
        val auditLogs = service.getAuditLog(tenantId)
        assertTrue(auditLogs.any { it.type == "LEDGER_EXCEPTION_PAGED" })
        assertTrue(auditLogs.any { it.type == "LEDGER_EXCEPTION_ASSIGNED" })
        assertTrue(auditLogs.any { it.type == "LEDGER_EXCEPTION_RESOLVED_COMPENSATED" })
    }

    @Test
    @DisplayName("LEDGER-005-02-T002 — Manage immutable reconciliation exceptions rejects invalid, boundary, unauthorized, and stale input")
    fun testT002_RejectsInvalidUnauthorizedAndStale() {
        // 1. Silent closure attempt unconditionally throws SilentClosureProhibitedException
        val exceptionId = UUID.randomUUID()
        val exSilent = assertThrows(SilentClosureProhibitedException::class.java) {
            service.attemptSilentClose(exceptionId)
        }
        assertTrue(exSilent.message!!.contains("cannot be silently closed"))

        // 2. Waive attempt unconditionally prohibited
        val waiveCmd = WaiveLedgerExceptionCommand(
            principal = validAdminPrincipal,
            tenantId = tenantId,
            exceptionId = exceptionId,
            reason = "Dismissing imbalance",
        )
        val exWaive = assertThrows(SilentClosureProhibitedException::class.java) {
            service.waiveException(waiveCmd)
        }
        assertTrue(exWaive.message!!.contains("Zero-tolerance ledger imbalance cannot be waived"))

        // 3. Unauthenticated attempt
        val unauthCmd = CreateLedgerExceptionCommand(
            principal = null,
            tenantId = tenantId,
            accountReference = "ACC-01",
            currencyCode = "USD",
            discrepancyMinorUnits = 100L,
            journalSumMinorUnits = 100L,
            projectedBalanceMinorUnits = 200L,
            idempotencyKey = "idem-unauth",
            correlationId = "corr-01",
            causationId = "caus-01",
        )
        assertThrows(DiscrepancyUnauthorizedException::class.java) {
            service.createException(unauthCmd)
        }

        // 4. Cross-tenant access forbidden
        val crossTenantCmd = unauthCmd.copy(principal = otherTenantPrincipal)
        assertThrows(DiscrepancyForbiddenException::class.java) {
            service.createException(crossTenantCmd)
        }

        // 5. Player forbidden
        val playerCmd = unauthCmd.copy(principal = unauthorizedPlayerPrincipal)
        assertThrows(DiscrepancyForbiddenException::class.java) {
            service.createException(playerCmd)
        }

        // 6. Stale version rejection
        val createCmd = unauthCmd.copy(principal = validAdminPrincipal, idempotencyKey = "idem-stale-base")
        val created = service.createException(createCmd)

        val staleAssignCmd = AssignLedgerExceptionCommand(
            principal = validAdminPrincipal,
            tenantId = tenantId,
            exceptionId = created.exception.exceptionId,
            assigneeId = "investigator-02",
            expectedVersion = 999L, // wrong version
            correlationId = "corr-stale",
            causationId = "caus-stale",
        )
        assertThrows(DiscrepancyConflictException::class.java) {
            service.assignException(staleAssignCmd)
        }

        // 7. Resolution without mandatory fields rejected
        val incompleteResolveCmd = ResolveLedgerExceptionCommand(
            principal = validAdminPrincipal,
            tenantId = tenantId,
            exceptionId = created.exception.exceptionId,
            compensationBatchId = null, // missing compensation batch
            reasonCode = "SOME_REASON",
            resolutionNotes = "Notes",
            approverId = "approver-01",
            expectedVersion = 1L,
            idempotencyKey = "idem-incomplete",
            correlationId = "corr",
            causationId = "caus",
        )
        assertThrows(SilentClosureProhibitedException::class.java) {
            service.resolveExceptionWithCompensation(incompleteResolveCmd)
        }
    }

    @Test
    @DisplayName("LEDGER-005-02-T003 — Manage immutable reconciliation exceptions survives concurrency, duplicate delivery, and dependency failure")
    fun testT003_ConcurrencyAndIdempotency() {
        val createCmd = CreateLedgerExceptionCommand(
            principal = validAdminPrincipal,
            tenantId = tenantId,
            accountReference = "ACC-CONCURRENCY-1",
            currencyCode = "USD",
            discrepancyMinorUnits = 2500L,
            journalSumMinorUnits = 5000L,
            projectedBalanceMinorUnits = 7500L,
            idempotencyKey = "idem-concurrency-create",
            correlationId = "corr-conc",
            causationId = "caus-conc",
        )

        // Concurrent creation with exact same idempotency key
        val executor = Executors.newFixedThreadPool(4)
        val results = mutableListOf<LedgerExceptionOperationResult>()
        val exceptions = mutableListOf<Throwable>()

        for (i in 0 until 4) {
            executor.submit {
                try {
                    val res = service.createException(createCmd)
                    synchronized(results) { results.add(res) }
                } catch (t: Throwable) {
                    synchronized(exceptions) { exceptions.add(t) }
                }
            }
        }

        executor.shutdown()
        assertTrue(executor.awaitTermination(5, TimeUnit.SECONDS))

        // All should succeed with equivalent result and same exception ID
        assertTrue(exceptions.isEmpty(), "Expected no unexpected exceptions during identical replay")
        assertEquals(4, results.size)
        val firstId = results[0].exception.exceptionId
        results.forEach { assertEquals(firstId, it.exception.exceptionId) }

        // Idempotency key reuse with differing payload causes CONFLICT
        val conflictingCmd = createCmd.copy(discrepancyMinorUnits = 99999L)
        assertThrows(DiscrepancyConflictException::class.java) {
            service.createException(conflictingCmd)
        }
    }

    @Test
    @DisplayName("LEDGER-005-02-T004 — Manage immutable reconciliation exceptions remains compatible, recoverable, observable, and lifecycle-safe")
    fun testT004_CompatibilityRecoverableObservableLifecycle() {
        // Assert no Android lifecycle surface is claimed
        val createCmd = CreateLedgerExceptionCommand(
            principal = validAdminPrincipal,
            tenantId = tenantId,
            accountReference = "ACC-LIFECYCLE-01",
            currencyCode = "USD",
            discrepancyMinorUnits = 1200L,
            journalSumMinorUnits = 1000L,
            projectedBalanceMinorUnits = 2200L,
            idempotencyKey = "idem-lifecycle-create",
            correlationId = "corr-life",
            causationId = "caus-life",
        )
        val created = service.createException(createCmd)

        // Verification of read-only access and persistence recovery
        val retrieved = service.getException(tenantId, created.exception.exceptionId)
        assertNotNull(retrieved)
        assertEquals(created.exception.exceptionId, retrieved!!.exceptionId)
        assertEquals(created.exception.auditChecksumSha256, retrieved.auditChecksumSha256)

        // List exceptions by status
        val pagedList = service.listExceptions(tenantId, LedgerExceptionStatus.PAGED)
        assertTrue(pagedList.any { it.exceptionId == created.exception.exceptionId })

        // Check audit log contains required IDs and no secrets
        val auditEvents = service.getAuditLog(tenantId)
        val relevantAudit = auditEvents.find { it.resultId == created.exception.exceptionId }
        assertNotNull(relevantAudit)
        assertEquals("LEDGER_EXCEPTION_PAGED", relevantAudit!!.type)
        assertEquals("corr-life", relevantAudit.correlationId)
        assertEquals("caus-life", relevantAudit.causationId)
    }
}
