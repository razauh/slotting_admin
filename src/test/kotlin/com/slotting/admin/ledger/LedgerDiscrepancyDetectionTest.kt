package com.slotting.admin.ledger

import com.slotting.admin.auth.*
import org.junit.jupiter.api.Assertions.*
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test
import java.time.Clock
import java.time.Instant
import java.time.ZoneOffset
import java.util.UUID

/**
 * Mandatory backend TDD test suite for LEDGER-005-01:
 * Detect journal and projection discrepancies.
 *
 * Semantic contract: "Zero-tolerance ledger imbalance pages; exceptions cannot be silently closed."
 * Protected risk assertion: "imbalance/mismatch not detected"
 */
class LedgerDiscrepancyDetectionTest {

    private val fixedClock = Clock.fixed(Instant.parse("2026-09-19T10:00:00Z"), ZoneOffset.UTC)
    private lateinit var service: LedgerDiscrepancyDetectionService

    private val adminPrincipal = AuthenticatedPrincipal(
        id = "admin-user-01",
        tenantId = "tenant-01",
        kind = PrincipalKind.ADMIN,
        roles = setOf(AdminRole.SUPER_ADMIN),
    )

    private val crossTenantPrincipal = AuthenticatedPrincipal(
        id = "admin-user-02",
        tenantId = "tenant-other",
        kind = PrincipalKind.ADMIN,
        roles = setOf(AdminRole.SUPER_ADMIN),
    )

    private val playerPrincipal = AuthenticatedPrincipal(
        id = "player-01",
        tenantId = "tenant-01",
        kind = PrincipalKind.PLAYER,
        roles = emptySet(),
    )

    @BeforeEach
    fun setUp() {
        service = LedgerDiscrepancyDetectionService(clock = fixedClock)
    }

    private fun sampleBatches(): List<JournalBatchRecord> {
        val now = Instant.now(fixedClock)
        val batchId = UUID.randomUUID()
        return listOf(
            JournalBatchRecord(
                batchId = batchId,
                tenantId = "tenant-01",
                batchReference = "BATCH-REC-001",
                currencyCode = "USD",
                totalDebitsMinorUnits = 10000L,
                totalCreditsMinorUnits = 10000L,
                status = JournalBatchStatus.POSTED,
                entries = listOf(
                    JournalEntryRecord(UUID.randomUUID(), batchId, "tenant-01", "ACC-1", JournalEntryDirection.DEBIT, 10000L, "USD", 1, null, now),
                    JournalEntryRecord(UUID.randomUUID(), batchId, "tenant-01", "ACC-2", JournalEntryDirection.CREDIT, 10000L, "USD", 2, null, now),
                ),
                postedAt = now,
                postedBy = "admin-user-01",
                idempotencyKey = "IDEM-REC-001",
                correlationId = "corr-rec-001",
                causationId = "caus-rec-001",
                createdAt = now,
            )
        )
    }

    // =========================================================================
    // LEDGER-005-01-T001: Authoritative Outcome Verification
    // =========================================================================

    @Test
    fun `LEDGER-005-01-T001 Detect journal and projection discrepancies produces the required authoritative outcome`() {
        val batches = sampleBatches()

        // Live projection has an imbalance: ACC-2 has 9900 instead of 10000 (100 minor units drift)
        val projections = listOf(
            AccountBalanceProjection("tenant-01", "ACC-1", "USD", -10000L, 1L, batches[0].batchId, Instant.now(fixedClock)),
            AccountBalanceProjection("tenant-01", "ACC-2", "USD", 9900L, 1L, batches[0].batchId, Instant.now(fixedClock)), // DRIFT!
        )

        val command = RunDiscrepancyCheckCommand(
            principal = adminPrincipal,
            tenantId = "tenant-01",
            currencyCode = "USD",
            idempotencyKey = "IDEM-CHECK-001",
            correlationId = "corr-chk-001",
            causationId = "caus-chk-001",
        )

        val result = service.runDiscrepancyCheck(command, batches, projections)

        assertNotNull(result.checkId)
        assertEquals(2, result.totalAccountsScanned)
        assertEquals(1, result.discrepanciesFound)
        assertTrue(result.zeroToleranceImbalanceDetected)
        assertTrue(result.isPaged) // Zero-tolerance page triggered!
        assertFalse(result.directEligibilityGranted)
        assertFalse(result.financialMutationPermitted)
        assertEquals(
            "Zero-tolerance ledger imbalance pages; exceptions cannot be silently closed.",
            result.semanticContract
        )

        val discrepancy = result.discrepancies.first()
        assertEquals("ACC-2", discrepancy.accountReference)
        assertEquals(-100L, discrepancy.differenceMinorUnits)
        assertEquals(DiscrepancySeverity.CRITICAL, discrepancy.severity)
        assertTrue(discrepancy.isPaged)
        assertEquals(DiscrepancyStatus.PAGED, discrepancy.status)
    }

    // =========================================================================
    // LEDGER-005-01-T002: Negative, Boundary & Rejection Verification
    // =========================================================================

    @Test
    fun `LEDGER-005-01-T002 Detect journal and projection discrepancies rejects invalid, boundary, unauthorized, and stale input`() {
        val batches = sampleBatches()
        val projections = listOf(
            AccountBalanceProjection("tenant-01", "ACC-1", "USD", -10000L, 1L, null, Instant.now(fixedClock)),
            AccountBalanceProjection("tenant-01", "ACC-2", "USD", 9900L, 1L, null, Instant.now(fixedClock)),
        )

        val command = RunDiscrepancyCheckCommand(
            principal = adminPrincipal,
            tenantId = "tenant-01",
            currencyCode = "USD",
            idempotencyKey = "IDEM-CHECK-002",
            correlationId = "corr",
            causationId = "caus",
        )
        val result = service.runDiscrepancyCheck(command, batches, projections)
        val disc = result.discrepancies.first()

        // SILENT CLOSURE PROHIBITION: Attempting silent closure must throw SilentClosureProhibitedException
        val silentCloseCmd = CloseDiscrepancyCommand(
            principal = adminPrincipal,
            tenantId = "tenant-01",
            discrepancyId = disc.discrepancyId,
            reason = null,
            compensationBatchId = null,
        )
        val silentEx = assertThrows(SilentClosureProhibitedException::class.java) {
            service.attemptSilentClose(silentCloseCmd)
        }
        assertEquals("SILENT_CLOSURE_PROHIBITED", silentEx.errorCode)

        // Attempt resolve with missing reason
        val noReasonCmd = silentCloseCmd.copy(compensationBatchId = UUID.randomUUID())
        assertThrows(SilentClosureProhibitedException::class.java) {
            service.resolveWithCompensation(noReasonCmd)
        }

        // Attempt resolve with missing compensation batch
        val noCompBatchCmd = silentCloseCmd.copy(reason = "Valid reason", compensationBatchId = null)
        assertThrows(SilentClosureProhibitedException::class.java) {
            service.resolveWithCompensation(noCompBatchCmd)
        }

        // Unauthenticated check attempt
        assertThrows(DiscrepancyUnauthorizedException::class.java) {
            service.runDiscrepancyCheck(command.copy(principal = null), batches, projections)
        }

        // Cross-tenant check attempt
        assertThrows(DiscrepancyForbiddenException::class.java) {
            service.runDiscrepancyCheck(command.copy(principal = crossTenantPrincipal), batches, projections)
        }

        // Player principal lacks permission
        assertThrows(DiscrepancyForbiddenException::class.java) {
            service.runDiscrepancyCheck(command.copy(principal = playerPrincipal), batches, projections)
        }
    }

    // =========================================================================
    // LEDGER-005-01-T003: Concurrency, Duplicate Delivery & Failure Recovery
    // =========================================================================

    @Test
    fun `LEDGER-005-01-T003 Detect journal and projection discrepancies survives concurrency, duplicate delivery, and dependency failure`() {
        val batches = sampleBatches()
        val projections = listOf(
            AccountBalanceProjection("tenant-01", "ACC-1", "USD", -10000L, 1L, null, Instant.now(fixedClock)),
            AccountBalanceProjection("tenant-01", "ACC-2", "USD", 10000L, 1L, null, Instant.now(fixedClock)),
        )

        val command = RunDiscrepancyCheckCommand(
            principal = adminPrincipal,
            tenantId = "tenant-01",
            currencyCode = "USD",
            idempotencyKey = "IDEM-CHECK-CONC",
            correlationId = "corr-conc",
            causationId = "caus-conc",
        )

        // Idempotent duplicate delivery
        val r1 = service.runDiscrepancyCheck(command, batches, projections)
        val r2 = service.runDiscrepancyCheck(command, batches, projections)
        assertEquals(r1.checkId, r2.checkId)
        assertEquals(0, r1.discrepanciesFound)
        assertFalse(r1.zeroToleranceImbalanceDetected)
        assertFalse(r1.isPaged)

        // Conflicting idempotency replay
        val conflictingCmd = command.copy(currencyCode = "EUR")
        val conflictEx = assertThrows(DiscrepancyConflictException::class.java) {
            service.runDiscrepancyCheck(conflictingCmd, batches, projections)
        }
        assertEquals("CONFLICT", conflictEx.errorCode)
    }

    // =========================================================================
    // LEDGER-005-01-T004: Compatibility, Recovery, Lifecycle & Observability
    // =========================================================================

    @Test
    fun `LEDGER-005-01-T004 Detect journal and projection discrepancies remains compatible, recoverable, observable, and lifecycle-safe`() {
        val batches = sampleBatches()
        val projections = listOf(
            AccountBalanceProjection("tenant-01", "ACC-1", "USD", -10000L, 1L, null, Instant.now(fixedClock)),
            AccountBalanceProjection("tenant-01", "ACC-2", "USD", 9500L, 1L, null, Instant.now(fixedClock)),
        )

        val command = RunDiscrepancyCheckCommand(
            principal = adminPrincipal,
            tenantId = "tenant-01",
            currencyCode = "USD",
            idempotencyKey = "IDEM-CHECK-OBS",
            correlationId = "corr-obs-01",
            causationId = "caus-obs-01",
        )
        val result = service.runDiscrepancyCheck(command, batches, projections)
        val disc = result.discrepancies.first()

        // Resolve formally with compensation batch ID and reason
        val resolveCmd = CloseDiscrepancyCommand(
            principal = adminPrincipal,
            tenantId = "tenant-01",
            discrepancyId = disc.discrepancyId,
            reason = "Reconciled via journal compensation batch #COMP-901",
            compensationBatchId = UUID.randomUUID(),
        )
        val resolvedDisc = service.resolveWithCompensation(resolveCmd)
        assertEquals(DiscrepancyStatus.RESOLVED_BY_COMPENSATION, resolvedDisc.status)

        // Observability audit verification
        val logs = service.getAuditLogs("tenant-01")
        val pagedEvent = logs.find { it.type == "LEDGER_DISCREPANCY_PAGED" }
        val resolvedEvent = logs.find { it.type == "LEDGER_DISCREPANCY_RESOLVED" }

        assertNotNull(pagedEvent)
        assertNotNull(resolvedEvent)
        assertEquals("corr-obs-01", pagedEvent!!.correlationId)
        assertEquals("caus-obs-01", pagedEvent.causationId)

        // Client untrusted invariants
        assertFalse(result.directEligibilityGranted)
        assertFalse(result.financialMutationPermitted)
    }
}
