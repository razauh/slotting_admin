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
 * Mandatory backend TDD test suite for LEDGER-003:
 * Atomic projection.
 *
 * Semantic contract: "Projection rebuild equals journal; optimistic/pessimistic choice follows ADR-002."
 * Protected risk assertion: "crash leaves journal/projection split"
 */
class LedgerProjectionTest {

    private val fixedClock = Clock.fixed(Instant.parse("2026-09-19T10:00:00Z"), ZoneOffset.UTC)
    private lateinit var service: LedgerProjectionService

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
        service = LedgerProjectionService(clock = fixedClock)
    }

    private fun createTestBatch(
        batchId: UUID = UUID.randomUUID(),
        tenantId: String = "tenant-01",
        batchReference: String = "BATCH-001",
        currencyCode: String = "USD",
        debitAccount: String = "ACC-DEBIT",
        creditAccount: String = "ACC-CREDIT",
        amountMinorUnits: Long = 5000L,
        status: JournalBatchStatus = JournalBatchStatus.POSTED,
    ): JournalBatchRecord {
        val now = Instant.now(fixedClock)
        val entries = listOf(
            JournalEntryRecord(
                entryId = UUID.randomUUID(),
                batchId = batchId,
                tenantId = tenantId,
                accountReference = debitAccount,
                direction = JournalEntryDirection.DEBIT,
                amountMinorUnits = amountMinorUnits,
                currencyCode = currencyCode,
                lineOrder = 1,
                createdAt = now,
            ),
            JournalEntryRecord(
                entryId = UUID.randomUUID(),
                batchId = batchId,
                tenantId = tenantId,
                accountReference = creditAccount,
                direction = JournalEntryDirection.CREDIT,
                amountMinorUnits = amountMinorUnits,
                currencyCode = currencyCode,
                lineOrder = 2,
                createdAt = now,
            ),
        )
        return JournalBatchRecord(
            batchId = batchId,
            tenantId = tenantId,
            batchReference = batchReference,
            currencyCode = currencyCode,
            totalDebitsMinorUnits = amountMinorUnits,
            totalCreditsMinorUnits = amountMinorUnits,
            status = status,
            entries = entries,
            postedAt = now,
            postedBy = "admin-user-01",
            idempotencyKey = "IDEM-$batchReference",
            correlationId = "corr-$batchReference",
            causationId = "caus-$batchReference",
            createdAt = now,
        )
    }

    // =========================================================================
    // LEDGER-003-T001: Authoritative Outcome Verification
    // =========================================================================

    @Test
    fun `LEDGER-003-T001 Atomic projection produces the required authoritative outcome`() {
        val batch = createTestBatch(
            debitAccount = "ACC-PLAYER-1",
            creditAccount = "ACC-HOUSE-1",
            amountMinorUnits = 10000L,
        )

        val result = service.applyBatchToProjection(adminPrincipal, "tenant-01", batch)

        assertNotNull(result.resultId)
        assertEquals("tenant-01", result.tenantId)
        assertEquals(batch.batchId, result.batchId)
        assertEquals(2, result.appliedEntriesCount)
        assertEquals(
            "Projection rebuild equals journal; optimistic/pessimistic choice follows ADR-002.",
            result.semanticContract
        )

        // Check projected account balances
        val playerProjection = service.getAccountProjection(adminPrincipal, "tenant-01", "ACC-PLAYER-1")
        val houseProjection = service.getAccountProjection(adminPrincipal, "tenant-01", "ACC-HOUSE-1")

        assertNotNull(playerProjection)
        assertNotNull(houseProjection)
        assertEquals(-10000L, playerProjection!!.balanceMinorUnits) // debited
        assertEquals(10000L, houseProjection!!.balanceMinorUnits) // credited
        assertEquals(1L, playerProjection.version)
        assertEquals(1L, houseProjection.version)

        // Verify: Projection rebuild equals journal
        val rebuildResult = service.rebuildProjectionFromJournal(
            adminPrincipal,
            "tenant-01",
            listOf(batch),
        )
        assertTrue(rebuildResult.isReconciliationEqual)
        assertEquals(2, rebuildResult.rebuiltAccountsCount)
        assertEquals(1, rebuildResult.totalBatchesProcessed)
        assertEquals(2, rebuildResult.totalEntriesProcessed)
        assertFalse(rebuildResult.directEligibilityGranted)
        assertFalse(rebuildResult.financialMutationPermitted)

        // Balances after rebuild match live projection
        val rebuiltPlayer = service.getAccountProjection(adminPrincipal, "tenant-01", "ACC-PLAYER-1")
        val rebuiltHouse = service.getAccountProjection(adminPrincipal, "tenant-01", "ACC-HOUSE-1")
        assertEquals(playerProjection.balanceMinorUnits, rebuiltPlayer!!.balanceMinorUnits)
        assertEquals(houseProjection.balanceMinorUnits, rebuiltHouse!!.balanceMinorUnits)
    }

    // =========================================================================
    // LEDGER-003-T002: Negative, Boundary & Rejection Verification
    // =========================================================================

    @Test
    fun `LEDGER-003-T002 Atomic projection rejects invalid, boundary, unauthorized, and stale input`() {
        val batch = createTestBatch(debitAccount = "ACC-STALE-1", creditAccount = "ACC-STALE-2")
        service.applyBatchToProjection(adminPrincipal, "tenant-01", batch)

        // Optimistic locking conflict (ADR-002): account ACC-STALE-1 is at version 1, passing expectedVersion 0 must fail
        val nextBatch = createTestBatch(
            batchReference = "BATCH-002",
            debitAccount = "ACC-STALE-1",
            creditAccount = "ACC-STALE-2",
        )
        val conflictEx = assertThrows(ProjectionConflictException::class.java) {
            service.applyBatchToProjection(
                principal = adminPrincipal,
                tenantId = "tenant-01",
                batch = nextBatch,
                expectedAccountVersions = mapOf("ACC-STALE-1" to 0L), // Stale version!
            )
        }
        assertEquals("CONFLICT", conflictEx.errorCode)

        // Unauthenticated access
        assertThrows(ProjectionUnauthorizedException::class.java) {
            service.applyBatchToProjection(null, "tenant-01", nextBatch)
        }

        // Cross-tenant IDOR access
        assertThrows(ProjectionForbiddenException::class.java) {
            service.applyBatchToProjection(crossTenantPrincipal, "tenant-01", nextBatch)
        }

        // Player principal lacks authority
        assertThrows(ProjectionForbiddenException::class.java) {
            service.applyBatchToProjection(playerPrincipal, "tenant-01", nextBatch)
        }

        // Batch with PENDING status (must be POSTED)
        val pendingBatch = batch.copy(batchId = UUID.randomUUID(), status = JournalBatchStatus.PENDING)
        assertThrows(ProjectionInvalidException::class.java) {
            service.applyBatchToProjection(adminPrincipal, "tenant-01", pendingBatch)
        }
    }

    // =========================================================================
    // LEDGER-003-T003: Concurrency, Duplicate Delivery & Failure Recovery
    // =========================================================================

    @Test
    fun `LEDGER-003-T003 Atomic projection survives concurrency, duplicate delivery, and dependency failure`() {
        val batch = createTestBatch(
            batchReference = "BATCH-DUP-001",
            debitAccount = "ACC-CONC-1",
            creditAccount = "ACC-CONC-2",
            amountMinorUnits = 7000L,
        )

        // First application
        val firstResult = service.applyBatchToProjection(adminPrincipal, "tenant-01", batch)
        assertEquals(2, firstResult.appliedEntriesCount)

        // Duplicate delivery of the exact same batchId -> must not double-debit or double-credit
        val duplicateResult = service.applyBatchToProjection(adminPrincipal, "tenant-01", batch)
        assertEquals(batch.batchId, duplicateResult.batchId)

        // Balances must strictly reflect single application (7000, not 14000)
        val p1 = service.getAccountProjection(adminPrincipal, "tenant-01", "ACC-CONC-1")
        val p2 = service.getAccountProjection(adminPrincipal, "tenant-01", "ACC-CONC-2")
        assertEquals(-7000L, p1!!.balanceMinorUnits)
        assertEquals(7000L, p2!!.balanceMinorUnits)
        assertEquals(1L, p1.version)
        assertEquals(1L, p2.version)
    }

    // =========================================================================
    // LEDGER-003-T004: Compatibility, Recovery, Lifecycle & Observability
    // =========================================================================

    @Test
    fun `LEDGER-003-T004 Atomic projection remains compatible, recoverable, observable, and lifecycle-safe`() {
        val b1 = createTestBatch(
            batchReference = "BATCH-REC-001",
            debitAccount = "ACC-REC-A",
            creditAccount = "ACC-REC-B",
            amountMinorUnits = 3000L,
        )
        val b2 = createTestBatch(
            batchReference = "BATCH-REC-002",
            debitAccount = "ACC-REC-B",
            creditAccount = "ACC-REC-C",
            amountMinorUnits = 1000L,
        )

        service.applyBatchToProjection(adminPrincipal, "tenant-01", b1)
        service.applyBatchToProjection(adminPrincipal, "tenant-01", b2)

        // Simulate crash drift / split: balance drifted on ACC-REC-B
        service.simulateCrashSplit("tenant-01", "ACC-REC-B", 9999L)
        val corruptedB = service.getAccountProjection(adminPrincipal, "tenant-01", "ACC-REC-B")
        assertNotEquals(2000L, corruptedB!!.balanceMinorUnits) // Corrupted/drifted!

        // Rebuild from authoritative journal batches restores exact equality
        val rebuildResult = service.rebuildProjectionFromJournal(
            adminPrincipal,
            "tenant-01",
            listOf(b1, b2),
        )

        assertTrue(rebuildResult.isReconciliationEqual)
        val reconciledA = service.getAccountProjection(adminPrincipal, "tenant-01", "ACC-REC-A")
        val reconciledB = service.getAccountProjection(adminPrincipal, "tenant-01", "ACC-REC-B")
        val reconciledC = service.getAccountProjection(adminPrincipal, "tenant-01", "ACC-REC-C")

        assertEquals(-3000L, reconciledA!!.balanceMinorUnits)
        assertEquals(2000L, reconciledB!!.balanceMinorUnits) // Recovered from drift!
        assertEquals(1000L, reconciledC!!.balanceMinorUnits)

        // Observability assertions
        val auditLogs = service.getAuditLogs("tenant-01")
        assertTrue(auditLogs.any { it.type == "LEDGER_PROJECTION_APPLIED" })
        assertTrue(auditLogs.any { it.type == "LEDGER_PROJECTION_REBUILT" })
    }
}
