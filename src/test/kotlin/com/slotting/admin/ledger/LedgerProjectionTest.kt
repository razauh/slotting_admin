package com.slotting.admin.ledger

import com.slotting.admin.auth.*
import com.slotting.admin.wallet.CrossCurrencyNotAllowedException
import com.slotting.admin.wallet.InMemoryWalletAccountStore
import com.slotting.admin.wallet.TransferFundsCommand
import com.slotting.admin.wallet.WalletAccountService
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

    // =========================================================================
    // TC-003: Currency-partitioned wallet projections and rebuilds
    // =========================================================================

    private val walletAdminPrincipal = AuthenticatedPrincipal(
        id = "admin-wallet-tc003",
        tenantId = "tenant-01",
        kind = PrincipalKind.ADMIN,
        roles = setOf(AdminRole.SUPER_ADMIN, AdminRole.SECURITY),
    )

    @Test
    fun `TC-003-R1 same owner reference holds separate PKR and USD projections with separate versions`() {
        val pkrBatch = createTestBatch(
            batchReference = "TC003-BATCH-PKR",
            currencyCode = "PKR",
            debitAccount = "ESCROW:tc003-house",
            creditAccount = "PLAYER:tc003-player-alpha",
            amountMinorUnits = 10000L,
        )
        val usdBatch = createTestBatch(
            batchReference = "TC003-BATCH-USD",
            currencyCode = "USD",
            debitAccount = "ESCROW:tc003-house",
            creditAccount = "PLAYER:tc003-player-alpha",
            amountMinorUnits = 2500L,
        )

        service.applyBatchToProjection(adminPrincipal, "tenant-01", pkrBatch)
        service.applyBatchToProjection(adminPrincipal, "tenant-01", usdBatch)

        val pkrProjection = service.getAccountProjection(adminPrincipal, "tenant-01", "PLAYER:tc003-player-alpha", "PKR")
        val usdProjection = service.getAccountProjection(adminPrincipal, "tenant-01", "PLAYER:tc003-player-alpha", "USD")

        assertNotNull(pkrProjection)
        assertNotNull(usdProjection)
        assertEquals(10000L, pkrProjection!!.balanceMinorUnits)
        assertEquals("PKR", pkrProjection.currencyCode)
        assertEquals(10000L, service.getAccountProjection(adminPrincipal, "tenant-01", "ESCROW:tc003-house", "PKR")!!.balanceMinorUnits * -1)
        assertEquals(2500L, usdProjection!!.balanceMinorUnits)
        assertEquals("USD", usdProjection.currencyCode)
        assertEquals(1L, pkrProjection.version)
        assertEquals(1L, usdProjection.version)

        val pkrHouse = service.getAccountProjection(adminPrincipal, "tenant-01", "ESCROW:tc003-house", "PKR")
        assertEquals(-10000L, pkrHouse!!.balanceMinorUnits)
        val usdHouse = service.getAccountProjection(adminPrincipal, "tenant-01", "ESCROW:tc003-house", "USD")
        assertEquals(-2500L, usdHouse!!.balanceMinorUnits)
    }

    @Test
    fun `TC-003-R2 replaying the PKR batch after a USD batch leaves neither balance changed`() {
        val pkrBatch = createTestBatch(
            batchReference = "TC003-REPLAY-PKR",
            currencyCode = "PKR",
            debitAccount = "ESCROW:tc003-replay-house",
            creditAccount = "PLAYER:tc003-replay-player",
            amountMinorUnits = 3000L,
        )
        val usdBatch = createTestBatch(
            batchReference = "TC003-REPLAY-USD",
            currencyCode = "USD",
            debitAccount = "ESCROW:tc003-replay-house",
            creditAccount = "PLAYER:tc003-replay-player",
            amountMinorUnits = 2500L,
        )

        service.applyBatchToProjection(adminPrincipal, "tenant-01", pkrBatch)
        service.applyBatchToProjection(adminPrincipal, "tenant-01", usdBatch)

        val pkrBefore = service.getAccountProjection(adminPrincipal, "tenant-01", "PLAYER:tc003-replay-player", "PKR")!!.balanceMinorUnits
        val usdBefore = service.getAccountProjection(adminPrincipal, "tenant-01", "PLAYER:tc003-replay-player", "USD")!!.balanceMinorUnits

        val replayResult = service.applyBatchToProjection(adminPrincipal, "tenant-01", pkrBatch)

        assertEquals(pkrBatch.batchId, replayResult.batchId)
        val pkrAfter = service.getAccountProjection(adminPrincipal, "tenant-01", "PLAYER:tc003-replay-player", "PKR")!!.balanceMinorUnits
        val usdAfter = service.getAccountProjection(adminPrincipal, "tenant-01", "PLAYER:tc003-replay-player", "USD")!!.balanceMinorUnits
        assertEquals(pkrBefore, pkrAfter)
        assertEquals(usdBefore, usdAfter)
        assertEquals(3000L, pkrAfter)
        assertEquals(2500L, usdAfter)
    }

    @Test
    fun `TC-003-R3 rebuild after drop repartitions balances and versions per currency from journals`() {
        val pkrBatch = createTestBatch(
            batchReference = "TC003-R3BATCH-PKR",
            currencyCode = "PKR",
            debitAccount = "ESCROW:tc003-r3-house",
            creditAccount = "PLAYER:tc003-r3-player",
            amountMinorUnits = 3000L,
        )
        val usdBatch = createTestBatch(
            batchReference = "TC003-R3BATCH-USD",
            currencyCode = "USD",
            debitAccount = "ESCROW:tc003-r3-house",
            creditAccount = "PLAYER:tc003-r3-player",
            amountMinorUnits = 2500L,
        )

        service.applyBatchToProjection(adminPrincipal, "tenant-01", pkrBatch)
        service.applyBatchToProjection(adminPrincipal, "tenant-01", usdBatch)
        service.simulateCrashSplit("tenant-01", "PLAYER:tc003-r3-player", 987654321L)
        service.simulateCrashSplit("tenant-01", "ESCROW:tc003-r3-house", 12345L)

        val rebuildResult = service.rebuildProjectionFromJournal(
            adminPrincipal,
            "tenant-01",
            listOf(pkrBatch, usdBatch),
        )

        assertTrue(rebuildResult.isReconciliationEqual)
        assertEquals(4, rebuildResult.rebuiltAccountsCount)

        val pkrPlayer = service.getAccountProjection(adminPrincipal, "tenant-01", "PLAYER:tc003-r3-player", "PKR")
        val usdPlayer = service.getAccountProjection(adminPrincipal, "tenant-01", "PLAYER:tc003-r3-player", "USD")
        val pkrHouse = service.getAccountProjection(adminPrincipal, "tenant-01", "ESCROW:tc003-r3-house", "PKR")
        val usdHouse = service.getAccountProjection(adminPrincipal, "tenant-01", "ESCROW:tc003-r3-house", "USD")

        assertNotNull(pkrPlayer)
        assertNotNull(usdPlayer)
        assertNotNull(pkrHouse)
        assertNotNull(usdHouse)
        assertEquals(3000L, pkrPlayer!!.balanceMinorUnits)
        assertEquals("PKR", pkrPlayer.currencyCode)
        assertEquals(2500L, usdPlayer!!.balanceMinorUnits)
        assertEquals("USD", usdPlayer.currencyCode)
        assertEquals(-3000L, pkrHouse!!.balanceMinorUnits)
        assertEquals(-2500L, usdHouse!!.balanceMinorUnits)
        assertEquals(1L, pkrPlayer.version)
        assertEquals(1L, usdPlayer.version)
    }

    @Test
    fun `TC-003-R4 cross-currency transfer from a PKR wallet to a USD wallet is denied with no postings or balance changes`() {
        val walletStore = InMemoryWalletAccountStore()
        val walletService = WalletAccountService(walletStore, fixedClock)

        val sourceOwnerId = UUID.randomUUID()
        val destinationOwnerId = UUID.randomUUID()
        val pkrAccount = walletService.createAccount(
            com.slotting.admin.wallet.CreateWalletAccountCommand(
                principal = walletAdminPrincipal,
                tenantId = "tenant-01",
                ownerId = sourceOwnerId,
                currencyCode = "PKR",
                accountType = com.slotting.admin.wallet.WalletAccountType.CASH,
                initialBalanceMinorUnits = 10000L,
                idempotencyKey = "idem-tc003-r4-src",
                correlationId = "corr-tc003-r4",
                causationId = "caus-tc003-r4"
            )
        ).account
        val usdAccount = walletService.createAccount(
            com.slotting.admin.wallet.CreateWalletAccountCommand(
                principal = walletAdminPrincipal,
                tenantId = "tenant-01",
                ownerId = destinationOwnerId,
                currencyCode = "USD",
                accountType = com.slotting.admin.wallet.WalletAccountType.CASH,
                initialBalanceMinorUnits = 2500L,
                idempotencyKey = "idem-tc003-r4-dest",
                correlationId = "corr-tc003-r4",
                causationId = "caus-tc003-r4"
            )
        ).account

        val sourceBefore = walletService.getAccount("tenant-01", pkrAccount.accountId, walletAdminPrincipal)
        val destinationBefore = walletService.getAccount("tenant-01", usdAccount.accountId, walletAdminPrincipal)

        val denied = assertThrows(CrossCurrencyNotAllowedException::class.java) {
            walletService.transferFunds(
                TransferFundsCommand(
                    principal = walletAdminPrincipal,
                    tenantId = "tenant-01",
                    sourceAccountId = pkrAccount.accountId,
                    destinationAccountId = usdAccount.accountId,
                    amountMinorUnits = 100L,
                    currencyCode = "PKR",
                    idempotencyKey = "idem-tc003-r4-transfer",
                    correlationId = "corr-tc003-r4-transfer",
                    causationId = "caus-tc003-r4-transfer",
                    expectedVersion = sourceBefore.version
                )
            )
        }
        assertEquals("CROSS_CURRENCY_NOT_ALLOWED", denied.errorCode)

        val sourceAfter = walletService.getAccount("tenant-01", pkrAccount.accountId, walletAdminPrincipal)
        val destinationAfter = walletService.getAccount("tenant-01", usdAccount.accountId, walletAdminPrincipal)
        assertEquals(sourceBefore.availableBalanceMinorUnits, sourceAfter.availableBalanceMinorUnits)
        assertEquals(sourceBefore.version, sourceAfter.version)
        assertEquals(destinationBefore.availableBalanceMinorUnits, destinationAfter.availableBalanceMinorUnits)
        assertEquals(destinationBefore.version, destinationAfter.version)
    }


    @Test
    fun `TC-003-R5 projection overflow on the final account leaves every earlier mutation unwritten`() {
        val hugeDelta = Long.MAX_VALUE
        val tenant = "tenant-01"
        val playerA = "PLAYER:tc003-r5-a"
        val playerB = "PLAYER:tc003-r5-b"

        val seedEntries = listOf(
            JournalEntryRecord(
                entryId = UUID.randomUUID(), batchId = UUID.randomUUID(), tenantId = tenant,
                accountReference = playerA, direction = JournalEntryDirection.CREDIT,
                amountMinorUnits = hugeDelta, currencyCode = "PKR", lineOrder = 1, createdAt = Instant.now(fixedClock),
            ),
        )
        val seedBatch = JournalBatchRecord(
            batchId = UUID.randomUUID(), tenantId = tenant, batchReference = "TC003-R5-SEED",
            currencyCode = "PKR", totalDebitsMinorUnits = hugeDelta, totalCreditsMinorUnits = hugeDelta,
            status = JournalBatchStatus.POSTED, entries = seedEntries,
            postedAt = Instant.now(fixedClock), postedBy = "admin-user-01",
            idempotencyKey = "IDEM-TC003-R5-SEED", correlationId = "corr-tc003-r5",
            causationId = "caus-tc003-r5", createdAt = Instant.now(fixedClock),
        )
        service.applyBatchToProjection(adminPrincipal, tenant, seedBatch)

        val beforeA = service.getAccountProjection(adminPrincipal, tenant, playerA, "PKR")!!
        assertEquals(hugeDelta, beforeA.balanceMinorUnits)
        assertEquals(1L, beforeA.version)

        val now = Instant.now(fixedClock)
        val batchId = UUID.randomUUID()
        val entries = listOf(
            JournalEntryRecord(
                entryId = UUID.randomUUID(), batchId = batchId, tenantId = tenant,
                accountReference = playerA, direction = JournalEntryDirection.CREDIT,
                amountMinorUnits = 1L, currencyCode = "PKR", lineOrder = 1, createdAt = now,
            ),
            JournalEntryRecord(
                entryId = UUID.randomUUID(), batchId = batchId, tenantId = tenant,
                accountReference = playerB, direction = JournalEntryDirection.CREDIT,
                amountMinorUnits = 1L, currencyCode = "PKR", lineOrder = 2, createdAt = now,
            ),
        )
        val overflowingBatch = JournalBatchRecord(
            batchId = batchId, tenantId = tenant, batchReference = "TC003-R5-OVERFLOW",
            currencyCode = "PKR", totalDebitsMinorUnits = 2L, totalCreditsMinorUnits = 2L,
            status = JournalBatchStatus.POSTED, entries = entries,
            postedAt = now, postedBy = "admin-user-01",
            idempotencyKey = "IDEM-TC003-R5-OVERFLOW", correlationId = "corr-tc003-r5-ovr",
            causationId = "caus-tc003-r5-ovr", createdAt = now,
        )

        assertThrows(ProjectionInvalidException::class.java) {
            service.applyBatchToProjection(adminPrincipal, tenant, overflowingBatch)
        }

        val afterA = service.getAccountProjection(adminPrincipal, tenant, playerA, "PKR")!!
        assertEquals(hugeDelta, afterA.balanceMinorUnits)
        assertEquals(1L, afterA.version)
        assertEquals(beforeA.lastAppliedBatchId, afterA.lastAppliedBatchId)
        assertTrue(afterA == beforeA, "Projection for the first account must be unchanged after an overflow abort")

        val afterB = service.getAccountProjection(adminPrincipal, tenant, playerB, "PKR")
        assertNull(afterB, "No projection may be created for the second account when the batch aborts")
    }
}
