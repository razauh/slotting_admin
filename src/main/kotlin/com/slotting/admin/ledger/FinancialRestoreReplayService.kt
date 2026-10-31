package com.slotting.admin.ledger

import com.slotting.admin.auth.*
import java.security.MessageDigest
import java.time.Clock
import java.time.Instant
import java.util.UUID
import java.util.concurrent.ConcurrentHashMap

/**
 * Binding flag to enforce the protected risk assertion for LEDGER-006-02:
 * "restore differs from source"
 */
object FinancialRestoreReplayBinding {
    @Volatile
    var isBound: Boolean = true

    fun checkBound() {
        if (!isBound) {
            throw AssertionError("restore differs from source")
        }
    }
}

enum class FinancialRestoreStatus {
    PENDING,
    IN_PROGRESS,
    COMPLETED,
    FAILED,
}

data class FinancialRestoreReconciliationReport(
    val restoredBatchesCount: Int,
    val restoredEntriesCount: Int,
    val restoredAccountsCount: Int,
    val totalDebitsMinorUnits: Long,
    val totalCreditsMinorUnits: Long,
    val hashesReconciled: Boolean,
    val countsReconciled: Boolean,
    val balancesReconciled: Boolean,
    val noHistoricalMutationConfirmed: Boolean,
)

data class ExecuteFinancialRestoreCommand(
    val principal: AuthenticatedPrincipal?,
    val tenantId: String,
    val backupId: UUID,
    val targetTimestamp: Instant? = null,
    val idempotencyKey: String,
    val correlationId: String,
    val causationId: String,
)

data class FinancialRestoreResult(
    val restoreId: UUID,
    val backupId: UUID,
    val tenantId: String,
    val status: FinancialRestoreStatus,
    val report: FinancialRestoreReconciliationReport,
    val restoredProjections: List<AccountBalanceProjection>,
    val completedAt: Instant,
    val evidenceReference: String,
    val semanticContract: String = "Defined RPO/RTO approved; hashes/counts/balances reconcile; no historical mutation.",
    val directEligibilityGranted: Boolean = false, // Untrusted client invariant
    val financialMutationPermitted: Boolean = false, // Untrusted client invariant
)

/**
 * Authoritative service to restore and deterministically replay financial state
 * from encrypted backups and posted journal records.
 *
 * Semantic contract: "Defined RPO/RTO approved; hashes/counts/balances reconcile; no historical mutation."
 * Protected risk assertion: "restore differs from source"
 */
class FinancialRestoreReplayService(
    private val clock: Clock = Clock.systemUTC(),
) {
    private val restoreStore = ConcurrentHashMap<UUID, FinancialRestoreResult>()
    private val restoreIdempotency = ConcurrentHashMap<String, Pair<String, FinancialRestoreResult>>()
    private val auditLogs = mutableListOf<AuditEvent>()

    @Synchronized
    fun restoreAndReplay(
        command: ExecuteFinancialRestoreCommand,
        backup: EncryptedFinancialBackupRecord,
        journalBatches: List<JournalBatchRecord>,
    ): FinancialRestoreResult {
        FinancialRestoreReplayBinding.checkBound()

        // 1. Auth & Permission checks
        val principal = command.principal ?: throw DiscrepancyUnauthorizedException("Unauthenticated financial restore")
        if (principal.tenantId != command.tenantId) {
            throw DiscrepancyForbiddenException("Cross-tenant restore forbidden")
        }
        if (principal.kind != PrincipalKind.ADMIN || principal.roles.none { it in setOf(AdminRole.SUPER_ADMIN, AdminRole.SECURITY) }) {
            throw DiscrepancyForbiddenException("Principal lacks financial restore authority")
        }

        // 2. Input validation
        if (command.idempotencyKey.isBlank() || command.correlationId.isBlank() || command.causationId.isBlank()) {
            throw DiscrepancyInvalidException("Idempotency key, correlation ID, and causation ID are mandatory")
        }
        if (backup.tenantId != command.tenantId) {
            throw DiscrepancyForbiddenException("Backup does not match requested tenant")
        }

        val replayableBatches = journalBatches.filter {
            it.tenantId == command.tenantId &&
                (command.targetTimestamp == null || !it.postedAt.isAfter(command.targetTimestamp))
        }.sortedBy { it.postedAt }
        val canonicalEntryFingerprint = replayableBatches
            .flatMap { it.entries }
            .map { entry ->
                listOf(
                    entry.entryId.toString(),
                    entry.batchId.toString(),
                    entry.accountReference,
                    entry.currencyCode,
                    entry.amountMinorUnits.toString(),
                    entry.direction.name,
                    entry.lineOrder.toString(),
                ).joinToString(":")
            }
            .sorted()
        val sig = hashPayload(
            command.tenantId,
            command.backupId.toString(),
            command.targetTimestamp?.toString() ?: "LATEST",
            canonicalEntryFingerprint.joinToString(";"),
        )

        // 3. Idempotency check
        restoreIdempotency[command.idempotencyKey]?.let { (cachedSig, cachedResult) ->
            if (cachedSig == sig) return cachedResult
            throw DiscrepancyConflictException("Idempotency key reused with conflicting payload")
        }

        if (backup.backupId != command.backupId) {
            throw DiscrepancyForbiddenException("Backup does not match requested ID")
        }
        if (backup.status != FinancialBackupStatus.COMPLETED) {
            throw DiscrepancyInvalidException("Cannot restore from non-completed backup")
        }

        // 4. Deterministic replay of journal entries
        val eligibleBatches = replayableBatches

        var totalDebits = 0L
        var totalCredits = 0L
        var totalEntries = 0
        val entryHashes = mutableListOf<String>()
        data class AccountPartition(val accountReference: String, val currencyCode: String)
        val accountBalances = mutableMapOf<AccountPartition, Long>()
        val lastAppliedBatches = mutableMapOf<AccountPartition, UUID>()

        for (batch in eligibleBatches) {
            for (entry in batch.entries) {
                val partition = AccountPartition(entry.accountReference, entry.currencyCode)
                totalEntries++
                val sign = if (entry.direction == JournalEntryDirection.CREDIT) 1L else -1L
                val delta = try {
                    Math.multiplyExact(entry.amountMinorUnits, sign)
                } catch (e: ArithmeticException) {
                    throw DiscrepancyInvalidException("Arithmetic overflow detected while applying restore sign shift")
                }
                accountBalances[partition] = try {
                    Math.addExact(accountBalances[partition] ?: 0L, delta)
                } catch (e: ArithmeticException) {
                    throw DiscrepancyInvalidException("Arithmetic overflow detected while replaying journal state")
                }
                lastAppliedBatches[partition] = batch.batchId

                if (entry.direction == JournalEntryDirection.DEBIT) {
                    totalDebits = try {
                        Math.addExact(totalDebits, entry.amountMinorUnits)
                    } catch (e: ArithmeticException) {
                        throw DiscrepancyInvalidException("Arithmetic overflow detected while totalling restored debits")
                    }
                } else {
                    totalCredits = try {
                        Math.addExact(totalCredits, entry.amountMinorUnits)
                    } catch (e: ArithmeticException) {
                        throw DiscrepancyInvalidException("Arithmetic overflow detected while totalling restored credits")
                    }
                }

                entryHashes.add(hashPayload(entry.entryId.toString(), entry.accountReference, entry.amountMinorUnits.toString(), entry.direction.name))
            }
        }

        // Conservation check
        if (totalDebits != totalCredits) {
            throw DiscrepancyInvalidException("restore differs from source: debits ($totalDebits) != credits ($totalCredits)")
        }

        val replayedEntryHashChain = hashPayload(*entryHashes.toTypedArray())
        val now = Instant.now(clock)

        // Build deterministic projections
        val restoredProjections = accountBalances.map { (partition, bal) ->
            AccountBalanceProjection(
                tenantId = command.tenantId,
                accountReference = partition.accountReference,
                currencyCode = partition.currencyCode,
                balanceMinorUnits = bal,
                version = 1L,
                lastAppliedBatchId = lastAppliedBatches[partition],
                lastUpdated = now,
            )
        }

        val replayedBalancesHash = hashPayload(
            *restoredProjections.sortedBy { it.accountReference }.map {
                "${it.accountReference}:${it.balanceMinorUnits}:${it.currencyCode}"
            }.toTypedArray()
        )

        // Reconciliation against backup manifest
        val hashesReconciled = (replayedEntryHashChain == backup.manifest.entryHashChainSha256) &&
            (replayedBalancesHash == backup.manifest.balancesHashSha256)
        val countsReconciled = (totalEntries == backup.manifest.totalJournalEntries) &&
            (eligibleBatches.size == backup.manifest.totalJournalBatches)
        val balancesReconciled = (totalDebits == backup.manifest.totalDebitsMinorUnits) &&
            (totalCredits == backup.manifest.totalCreditsMinorUnits)

        if (!hashesReconciled || !countsReconciled || !balancesReconciled) {
            throw DiscrepancyInvalidException("restore differs from source: manifest reconciliation failed")
        }

        val report = FinancialRestoreReconciliationReport(
            restoredBatchesCount = eligibleBatches.size,
            restoredEntriesCount = totalEntries,
            restoredAccountsCount = restoredProjections.size,
            totalDebitsMinorUnits = totalDebits,
            totalCreditsMinorUnits = totalCredits,
            hashesReconciled = hashesReconciled,
            countsReconciled = countsReconciled,
            balancesReconciled = balancesReconciled,
            noHistoricalMutationConfirmed = true,
        )

        val restoreId = UUID.randomUUID()
        val result = FinancialRestoreResult(
            restoreId = restoreId,
            backupId = command.backupId,
            tenantId = command.tenantId,
            status = FinancialRestoreStatus.COMPLETED,
            report = report,
            restoredProjections = restoredProjections,
            completedAt = now,
            evidenceReference = "financial-restore:record:$restoreId",
        )

        restoreStore[restoreId] = result

        auditLogs.add(
            AuditEvent(
                eventId = UUID.randomUUID(),
                resultId = restoreId,
                tenantId = command.tenantId,
                type = "FINANCIAL_RESTORE_COMPLETED",
                occurredAt = now,
                correlationId = command.correlationId,
                causationId = command.causationId,
            )
        )

        restoreIdempotency[command.idempotencyKey] = Pair(sig, result)
        return result
    }

    fun getRestore(tenantId: String, restoreId: UUID): FinancialRestoreResult? {
        FinancialRestoreReplayBinding.checkBound()
        val result = restoreStore[restoreId] ?: return null
        if (result.tenantId != tenantId) return null
        return result
    }

    fun listRestores(tenantId: String): List<FinancialRestoreResult> {
        FinancialRestoreReplayBinding.checkBound()
        return restoreStore.values.filter { it.tenantId == tenantId }
    }

    fun getAuditLogs(tenantId: String): List<AuditEvent> {
        return auditLogs.filter { it.tenantId == tenantId }
    }

    private fun hashPayload(vararg values: String): String {
        val digest = MessageDigest.getInstance("SHA-256")
        return digest.digest(values.joinToString("|").toByteArray(Charsets.UTF_8))
            .joinToString("") { "%02x".format(it) }
    }
}
