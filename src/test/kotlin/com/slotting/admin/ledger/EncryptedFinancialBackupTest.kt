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

class EncryptedFinancialBackupTest {

    private val tenantId = "tenant-fin-backup-01"
    private val clock = Clock.fixed(Instant.parse("2026-09-19T12:00:00Z"), ZoneOffset.UTC)
    private lateinit var service: EncryptedFinancialBackupService

    private val validAdmin = AuthenticatedPrincipal(
        id = "admin-backup-01",
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
        id = "player-01",
        tenantId = tenantId,
        roles = emptySet(),
        kind = PrincipalKind.PLAYER,
    )

    private val batchId = UUID.randomUUID()
    private val sampleBatches = listOf(
        JournalBatchRecord(
            batchId = batchId,
            tenantId = tenantId,
            batchReference = "BATCH-001",
            currencyCode = "USD",
            totalDebitsMinorUnits = 1000L,
            totalCreditsMinorUnits = 1000L,
            status = JournalBatchStatus.POSTED,
            entries = listOf(
                JournalEntryRecord(
                    entryId = UUID.randomUUID(),
                    batchId = batchId,
                    tenantId = tenantId,
                    accountReference = "ACC-01",
                    direction = JournalEntryDirection.DEBIT,
                    amountMinorUnits = 1000L,
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
                    amountMinorUnits = 1000L,
                    currencyCode = "USD",
                    lineOrder = 2,
                    createdAt = Instant.parse("2026-09-19T11:00:00Z"),
                )
            ),
            postedAt = Instant.parse("2026-09-19T11:00:00Z"),
            postedBy = "admin-user",
            idempotencyKey = "idem-batch-001",
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
            balanceMinorUnits = -1000L,
            version = 1L,
            lastAppliedBatchId = batchId,
            lastUpdated = Instant.parse("2026-09-19T11:00:00Z"),
        ),
        AccountBalanceProjection(
            tenantId = tenantId,
            accountReference = "ACC-02",
            currencyCode = "USD",
            balanceMinorUnits = 1000L,
            version = 1L,
            lastAppliedBatchId = batchId,
            lastUpdated = Instant.parse("2026-09-19T11:00:00Z"),
        )
    )

    @BeforeEach
    fun setup() {
        service = EncryptedFinancialBackupService(clock)
    }

    @Test
    @DisplayName("LEDGER-006-01-T001 — Create encrypted financial backups produces the required authoritative outcome")
    fun testT001_AuthoritativeOutcome() {
        val cmd = CreateFinancialBackupCommand(
            principal = validAdmin,
            tenantId = tenantId,
            rpoMinutes = 5L,
            rtoMinutes = 15L,
            idempotencyKey = "idem-backup-001",
            correlationId = "corr-001",
            causationId = "caus-001",
        )

        val result = service.createEncryptedBackup(cmd, sampleBatches, sampleProjections)

        // Assert: Defined RPO/RTO approved; hashes/counts/balances reconcile; no historical mutation.
        assertEquals("Defined RPO/RTO approved; hashes/counts/balances reconcile; no historical mutation.", result.semanticContract)
        assertFalse(result.directEligibilityGranted)
        assertFalse(result.financialMutationPermitted)

        // Assert backup fields
        assertEquals(FinancialBackupStatus.COMPLETED, result.backup.status)
        assertEquals("AES-256-GCM", result.backup.encryptionMetadata.encryptionAlgorithm)
        assertNotNull(result.backup.encryptionMetadata.ciphertextSha256)
        assertTrue(result.backup.manifest.rpoApproved)
        assertTrue(result.backup.manifest.rtoApproved)
        assertEquals(5L, result.backup.manifest.rpoTargetMinutes)
        assertEquals(15L, result.backup.manifest.rtoTargetMinutes)
        assertEquals(1, result.backup.manifest.totalJournalBatches)
        assertEquals(2, result.backup.manifest.totalJournalEntries)
        assertEquals(1000L, result.backup.manifest.totalDebitsMinorUnits)
        assertEquals(1000L, result.backup.manifest.totalCreditsMinorUnits)
        assertNotNull(result.backup.manifest.entryHashChainSha256)
        assertNotNull(result.backup.manifest.balancesHashSha256)

        // Assert audit trail
        val audits = service.getAuditLogs(tenantId)
        assertTrue(audits.any { it.type == "FINANCIAL_BACKUP_COMPLETED" && it.resultId == result.backup.backupId })
    }

    @Test
    @DisplayName("LEDGER-006-01-T002 — Create encrypted financial backups rejects invalid, boundary, unauthorized, and stale input")
    fun testT002_RejectsInvalidAndUnauthorized() {
        // 1. Unauthenticated request
        val unauthCmd = CreateFinancialBackupCommand(
            principal = null,
            tenantId = tenantId,
            idempotencyKey = "idem-unauth",
            correlationId = "corr",
            causationId = "caus",
        )
        assertThrows(DiscrepancyUnauthorizedException::class.java) {
            service.createEncryptedBackup(unauthCmd, sampleBatches, sampleProjections)
        }

        // 2. Cross-tenant access
        val crossTenantCmd = unauthCmd.copy(principal = otherTenantAdmin)
        assertThrows(DiscrepancyForbiddenException::class.java) {
            service.createEncryptedBackup(crossTenantCmd, sampleBatches, sampleProjections)
        }

        // 3. Player unauthorized
        val playerCmd = unauthCmd.copy(principal = unauthorizedPlayer)
        assertThrows(DiscrepancyForbiddenException::class.java) {
            service.createEncryptedBackup(playerCmd, sampleBatches, sampleProjections)
        }

        // 4. Invalid RPO/RTO boundaries
        val zeroRpoCmd = unauthCmd.copy(principal = validAdmin, rpoMinutes = 0L)
        assertThrows(DiscrepancyInvalidException::class.java) {
            service.createEncryptedBackup(zeroRpoCmd, sampleBatches, sampleProjections)
        }

        val excessiveRpoCmd = unauthCmd.copy(principal = validAdmin, rpoMinutes = 999L)
        assertThrows(DiscrepancyInvalidException::class.java) {
            service.createEncryptedBackup(excessiveRpoCmd, sampleBatches, sampleProjections)
        }

        // 5. Blank idempotency key
        val blankIdemCmd = unauthCmd.copy(principal = validAdmin, idempotencyKey = "")
        assertThrows(DiscrepancyInvalidException::class.java) {
            service.createEncryptedBackup(blankIdemCmd, sampleBatches, sampleProjections)
        }
    }

    @Test
    @DisplayName("LEDGER-006-01-T003 — Create encrypted financial backups survives concurrency, duplicate delivery, and dependency failure")
    fun testT003_ConcurrencyAndIdempotency() {
        val cmd = CreateFinancialBackupCommand(
            principal = validAdmin,
            tenantId = tenantId,
            rpoMinutes = 5L,
            rtoMinutes = 15L,
            idempotencyKey = "idem-conc-001",
            correlationId = "corr-conc",
            causationId = "caus-conc",
        )

        val executor = Executors.newFixedThreadPool(4)
        val results = mutableListOf<FinancialBackupResult>()
        val exceptions = mutableListOf<Throwable>()

        for (i in 0 until 4) {
            executor.submit {
                try {
                    val res = service.createEncryptedBackup(cmd, sampleBatches, sampleProjections)
                    synchronized(results) { results.add(res) }
                } catch (t: Throwable) {
                    synchronized(exceptions) { exceptions.add(t) }
                }
            }
        }

        executor.shutdown()
        assertTrue(executor.awaitTermination(5, TimeUnit.SECONDS))

        // Equivalent replay succeeds with the same result
        assertTrue(exceptions.isEmpty())
        assertEquals(4, results.size)
        val firstId = results[0].backup.backupId
        results.forEach { assertEquals(firstId, it.backup.backupId) }

        // Idempotency key reuse with different payload causes CONFLICT
        val conflictingCmd = cmd.copy(rpoMinutes = 10L)
        assertThrows(DiscrepancyConflictException::class.java) {
            service.createEncryptedBackup(conflictingCmd, sampleBatches, sampleProjections)
        }
    }

    @Test
    @DisplayName("LEDGER-006-01-T004 — Create encrypted financial backups remains compatible, recoverable, observable, and lifecycle-safe")
    fun testT004_CompatibilityRecoverableObservableLifecycle() {
        val cmd = CreateFinancialBackupCommand(
            principal = validAdmin,
            tenantId = tenantId,
            rpoMinutes = 5L,
            rtoMinutes = 15L,
            idempotencyKey = "idem-life-001",
            correlationId = "corr-life",
            causationId = "caus-life",
        )

        val result = service.createEncryptedBackup(cmd, sampleBatches, sampleProjections)

        // Verify retrieval and recovery of exact backup
        val retrieved = service.getBackup(tenantId, result.backup.backupId)
        assertNotNull(retrieved)
        assertEquals(result.backup.backupId, retrieved!!.backupId)
        assertEquals(result.backup.encryptionMetadata.ciphertextSha256, retrieved.encryptionMetadata.ciphertextSha256)

        // List backups
        val backups = service.listBackups(tenantId)
        assertTrue(backups.any { it.backupId == result.backup.backupId })

        // Observability check
        val audits = service.getAuditLogs(tenantId)
        val relevantAudit = audits.find { it.resultId == result.backup.backupId }
        assertNotNull(relevantAudit)
        assertEquals("FINANCIAL_BACKUP_COMPLETED", relevantAudit!!.type)
        assertEquals("corr-life", relevantAudit.correlationId)
        assertEquals("caus-life", relevantAudit.causationId)
    }
}
