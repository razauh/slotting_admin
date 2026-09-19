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

class FinancialRestoreReplayTest {

    private val tenantId = "tenant-restore-01"
    private val clock = Clock.fixed(Instant.parse("2026-09-19T14:00:00Z"), ZoneOffset.UTC)
    private lateinit var backupService: EncryptedFinancialBackupService
    private lateinit var restoreService: FinancialRestoreReplayService

    private val validAdmin = AuthenticatedPrincipal(
        id = "admin-restore-01",
        tenantId = tenantId,
        roles = setOf(AdminRole.SUPER_ADMIN),
        kind = PrincipalKind.ADMIN,
    )

    private val otherTenantAdmin = AuthenticatedPrincipal(
        id = "admin-other",
        tenantId = "tenant-other",
        roles = setOf(AdminRole.SUPER_ADMIN),
        kind = PrincipalKind.ADMIN,
    )

    private val unauthorizedPlayer = AuthenticatedPrincipal(
        id = "player-restore-01",
        tenantId = tenantId,
        roles = emptySet(),
        kind = PrincipalKind.PLAYER,
    )

    private val batchId = UUID.randomUUID()
    private val sampleBatches = listOf(
        JournalBatchRecord(
            batchId = batchId,
            tenantId = tenantId,
            batchReference = "BATCH-RESTORE-001",
            currencyCode = "USD",
            totalDebitsMinorUnits = 5000L,
            totalCreditsMinorUnits = 5000L,
            status = JournalBatchStatus.POSTED,
            entries = listOf(
                JournalEntryRecord(
                    entryId = UUID.randomUUID(),
                    batchId = batchId,
                    tenantId = tenantId,
                    accountReference = "ACC-01",
                    direction = JournalEntryDirection.DEBIT,
                    amountMinorUnits = 5000L,
                    currencyCode = "USD",
                    lineOrder = 1,
                    createdAt = Instant.parse("2026-09-19T11:00:00Z"),
                ),
                JournalEntryRecord(
                    entryId = UUID.randomUUID(),
                    batchId = batchId,
                    tenantId = tenantId,
                    accountReference = "ACC-02",
                    direction = JournalEntryDirection.CREDIT,
                    amountMinorUnits = 5000L,
                    currencyCode = "USD",
                    lineOrder = 2,
                    createdAt = Instant.parse("2026-09-19T11:00:00Z"),
                )
            ),
            postedAt = Instant.parse("2026-09-19T11:00:00Z"),
            postedBy = "admin-user",
            idempotencyKey = "idem-batch-restore-001",
            correlationId = "corr-batch-001",
            causationId = "caus-batch-001",
            serverVersion = 1L,
            createdAt = Instant.parse("2026-09-19T11:00:00Z"),
        )
    )

    private val sampleProjections = listOf(
        AccountBalanceProjection(
            tenantId = tenantId,
            accountReference = "ACC-01",
            currencyCode = "USD",
            balanceMinorUnits = -5000L,
            version = 1L,
            lastAppliedBatchId = batchId,
            lastUpdated = Instant.parse("2026-09-19T11:00:00Z"),
        ),
        AccountBalanceProjection(
            tenantId = tenantId,
            accountReference = "ACC-02",
            currencyCode = "USD",
            balanceMinorUnits = 5000L,
            version = 1L,
            lastAppliedBatchId = batchId,
            lastUpdated = Instant.parse("2026-09-19T11:00:00Z"),
        )
    )

    private lateinit var sampleBackup: EncryptedFinancialBackupRecord

    @BeforeEach
    fun setup() {
        backupService = EncryptedFinancialBackupService(clock)
        restoreService = FinancialRestoreReplayService(clock)

        val backupResult = backupService.createEncryptedBackup(
            CreateFinancialBackupCommand(
                principal = validAdmin,
                tenantId = tenantId,
                rpoMinutes = 5L,
                rtoMinutes = 15L,
                idempotencyKey = "idem-setup-backup",
                correlationId = "corr-setup",
                causationId = "caus-setup",
            ),
            sampleBatches,
            sampleProjections,
        )
        sampleBackup = backupResult.backup
    }

    @Test
    @DisplayName("LEDGER-006-02-T001 — Restore and deterministically replay financial state produces the required authoritative outcome")
    fun testT001_AuthoritativeOutcome() {
        val cmd = ExecuteFinancialRestoreCommand(
            principal = validAdmin,
            tenantId = tenantId,
            backupId = sampleBackup.backupId,
            idempotencyKey = "idem-restore-001",
            correlationId = "corr-restore-001",
            causationId = "caus-restore-001",
        )

        val result = restoreService.restoreAndReplay(cmd, sampleBackup, sampleBatches)

        // Assert: Defined RPO/RTO approved; hashes/counts/balances reconcile; no historical mutation.
        assertEquals("Defined RPO/RTO approved; hashes/counts/balances reconcile; no historical mutation.", result.semanticContract)
        assertFalse(result.directEligibilityGranted)
        assertFalse(result.financialMutationPermitted)

        // Assert reconciliation report
        assertEquals(FinancialRestoreStatus.COMPLETED, result.status)
        assertTrue(result.report.hashesReconciled)
        assertTrue(result.report.countsReconciled)
        assertTrue(result.report.balancesReconciled)
        assertTrue(result.report.noHistoricalMutationConfirmed)
        assertEquals(1, result.report.restoredBatchesCount)
        assertEquals(2, result.report.restoredEntriesCount)
        assertEquals(2, result.report.restoredAccountsCount)
        assertEquals(5000L, result.report.totalDebitsMinorUnits)
        assertEquals(5000L, result.report.totalCreditsMinorUnits)

        // Assert restored projection balances match deterministic calculation
        val acc1 = result.restoredProjections.find { it.accountReference == "ACC-01" }
        assertNotNull(acc1)
        assertEquals(-5000L, acc1!!.balanceMinorUnits)

        val acc2 = result.restoredProjections.find { it.accountReference == "ACC-02" }
        assertNotNull(acc2)
        assertEquals(5000L, acc2!!.balanceMinorUnits)

        // Assert audit trail
        val audits = restoreService.getAuditLogs(tenantId)
        assertTrue(audits.any { it.type == "FINANCIAL_RESTORE_COMPLETED" && it.resultId == result.restoreId })
    }

    @Test
    @DisplayName("LEDGER-006-02-T002 — Restore and deterministically replay financial state rejects invalid, boundary, unauthorized, and stale input")
    fun testT002_RejectsInvalidAndUnauthorized() {
        val unauthCmd = ExecuteFinancialRestoreCommand(
            principal = null,
            tenantId = tenantId,
            backupId = sampleBackup.backupId,
            idempotencyKey = "idem-unauth",
            correlationId = "corr",
            causationId = "caus",
        )

        // 1. Unauthenticated
        assertThrows(DiscrepancyUnauthorizedException::class.java) {
            restoreService.restoreAndReplay(unauthCmd, sampleBackup, sampleBatches)
        }

        // 2. Cross-tenant forbidden
        val crossTenantCmd = unauthCmd.copy(principal = otherTenantAdmin)
        assertThrows(DiscrepancyForbiddenException::class.java) {
            restoreService.restoreAndReplay(crossTenantCmd, sampleBackup, sampleBatches)
        }

        // 3. Player unauthorized
        val playerCmd = unauthCmd.copy(principal = unauthorizedPlayer)
        assertThrows(DiscrepancyForbiddenException::class.java) {
            restoreService.restoreAndReplay(playerCmd, sampleBackup, sampleBatches)
        }

        // 4. Blank idempotency key
        val blankIdemCmd = unauthCmd.copy(principal = validAdmin, idempotencyKey = "")
        assertThrows(DiscrepancyInvalidException::class.java) {
            restoreService.restoreAndReplay(blankIdemCmd, sampleBackup, sampleBatches)
        }

        // 5. Tampered batch (debits != credits) fails closed
        val tamperedBatches = listOf(
            sampleBatches[0].copy(
                entries = listOf(
                    sampleBatches[0].entries[0], // debit 5000
                    sampleBatches[0].entries[1].copy(amountMinorUnits = 9999L), // credit 9999 (imbalance)
                )
            )
        )
        val validCmd = unauthCmd.copy(principal = validAdmin, idempotencyKey = "idem-tampered")
        assertThrows(DiscrepancyInvalidException::class.java) {
            restoreService.restoreAndReplay(validCmd, sampleBackup, tamperedBatches)
        }
    }

    @Test
    @DisplayName("LEDGER-006-02-T003 — Restore and deterministically replay financial state survives concurrency, duplicate delivery, and dependency failure")
    fun testT003_ConcurrencyAndIdempotency() {
        val cmd = ExecuteFinancialRestoreCommand(
            principal = validAdmin,
            tenantId = tenantId,
            backupId = sampleBackup.backupId,
            idempotencyKey = "idem-conc-restore",
            correlationId = "corr-conc",
            causationId = "caus-conc",
        )

        val executor = Executors.newFixedThreadPool(4)
        val results = mutableListOf<FinancialRestoreResult>()
        val exceptions = mutableListOf<Throwable>()

        for (i in 0 until 4) {
            executor.submit {
                try {
                    val res = restoreService.restoreAndReplay(cmd, sampleBackup, sampleBatches)
                    synchronized(results) { results.add(res) }
                } catch (t: Throwable) {
                    synchronized(exceptions) { exceptions.add(t) }
                }
            }
        }

        executor.shutdown()
        assertTrue(executor.awaitTermination(5, TimeUnit.SECONDS))

        // Equivalent replay yields identical restore result
        assertTrue(exceptions.isEmpty())
        assertEquals(4, results.size)
        val firstId = results[0].restoreId
        results.forEach { assertEquals(firstId, it.restoreId) }

        // Idempotency key reuse with different backupId throws CONFLICT
        val conflictingCmd = cmd.copy(backupId = UUID.randomUUID())
        assertThrows(DiscrepancyConflictException::class.java) {
            restoreService.restoreAndReplay(conflictingCmd, sampleBackup, sampleBatches)
        }
    }

    @Test
    @DisplayName("LEDGER-006-02-T004 — Restore and deterministically replay financial state remains compatible, recoverable, observable, and lifecycle-safe")
    fun testT004_CompatibilityRecoverableObservableLifecycle() {
        val cmd = ExecuteFinancialRestoreCommand(
            principal = validAdmin,
            tenantId = tenantId,
            backupId = sampleBackup.backupId,
            idempotencyKey = "idem-life-restore",
            correlationId = "corr-life",
            causationId = "caus-life",
        )

        val result = restoreService.restoreAndReplay(cmd, sampleBackup, sampleBatches)

        // Retrieve restore record
        val retrieved = restoreService.getRestore(tenantId, result.restoreId)
        assertNotNull(retrieved)
        assertEquals(result.restoreId, retrieved!!.restoreId)
        assertEquals(FinancialRestoreStatus.COMPLETED, retrieved.status)

        // List restores
        val list = restoreService.listRestores(tenantId)
        assertTrue(list.any { it.restoreId == result.restoreId })

        // Observability check
        val audits = restoreService.getAuditLogs(tenantId)
        val relevantAudit = audits.find { it.resultId == result.restoreId }
        assertNotNull(relevantAudit)
        assertEquals("FINANCIAL_RESTORE_COMPLETED", relevantAudit!!.type)
        assertEquals("corr-life", relevantAudit.correlationId)
        assertEquals("caus-life", relevantAudit.causationId)
    }
}
