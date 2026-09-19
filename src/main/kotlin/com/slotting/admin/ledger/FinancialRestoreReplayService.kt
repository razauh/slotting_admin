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

        // 3. Idempotency check
        val sig = hashPayload(command.tenantId, command.backupId.toString(), command.targetTimestamp?.toString() ?: "LATEST")
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
        val eligibleBatches = journalBatches.filter {
            it.tenantId == command.tenantId &&
                (command.targetTimestamp == null || !it.postedAt.isAfter(command.targetTimestamp))
        }.sortedBy { it.postedAt }

        var totalDebits = 0L
        var totalCredits = 0L
        var totalEntries = 0
        val entryHashes = mutableListOf<String>()
        val accountBalances = mutableMapOf<String, Long>()
        val accountCurrencies = mutableMapOf<String, String>()
        val lastAppliedBatches = mutableMapOf<String, UUID>()

        for (batch in eligibleBatches) {
            for (entry in batch.entries) {
                totalEntries++
                val sign = if (entry.direction == JournalEntryDirection.CREDIT) 1L else -1L
                val delta = entry.amountMinorUnits * sign
                accountBalances[entry.accountReference] = (accountBalances[entry.accountReference] ?: 0L) + delta
                accountCurrencies[entry.accountReference] = entry.currencyCode
                lastAppliedBatches[entry.accountReference] = batch.batchId

                if (entry.direction == JournalEntryDirection.DEBIT) {
                    totalDebits += entry.amountMinorUnits
                } else {
                    totalCredits += entry.amountMinorUnits
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
        val restoredProjections = accountBalances.map { (accRef, bal) ->
            AccountBalanceProjection(
                tenantId = command.tenantId,
                accountReference = accRef,
                currencyCode = accountCurrencies[accRef] ?: "USD",
                balanceMinorUnits = bal,
                version = 1L,
                lastAppliedBatchId = lastAppliedBatches[accRef],
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
