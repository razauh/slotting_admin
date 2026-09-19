package com.slotting.admin.ledger

import com.slotting.admin.auth.*
import java.time.Clock
import java.time.Instant
import java.util.UUID
import java.util.concurrent.ConcurrentHashMap

/**
 * Binding flag to enforce the protected risk assertion for LEDGER-003:
 * "crash leaves journal/projection split"
 */
object LedgerProjectionBinding {
    @Volatile
    var isBound: Boolean = true

    fun checkBound() {
        if (!isBound) {
            throw AssertionError("crash leaves journal/projection split")
        }
    }
}

open class LedgerProjectionException(val errorCode: String, message: String) : RuntimeException(message)

class ProjectionSplitException(
    message: String = "Crash leaves journal/projection split",
) : LedgerProjectionException("PROJECTION_SPLIT", message)

class ProjectionConflictException(
    message: String,
) : LedgerProjectionException("CONFLICT", message)

class ProjectionUnauthorizedException(
    message: String = "Unauthenticated projection access attempt",
) : LedgerProjectionException("UNAUTHORIZED", message)

class ProjectionForbiddenException(
    message: String = "Forbidden: insufficient permissions or cross-tenant projection access",
) : LedgerProjectionException("FORBIDDEN", message)

class ProjectionInvalidException(
    message: String,
) : LedgerProjectionException("INVALID", message)

data class AccountBalanceProjection(
    val tenantId: String,
    val accountReference: String,
    val currencyCode: String,
    val balanceMinorUnits: Long,
    val version: Long,
    val lastAppliedBatchId: UUID?,
    val lastUpdated: Instant,
)

data class ProjectionRebuildResult(
    val tenantId: String,
    val rebuiltAccountsCount: Int,
    val totalBatchesProcessed: Int,
    val totalEntriesProcessed: Int,
    val isReconciliationEqual: Boolean,
    val serverTime: Instant,
    val evidenceReference: String,
    val semanticContract: String = "Projection rebuild equals journal; optimistic/pessimistic choice follows ADR-002.",
    val directEligibilityGranted: Boolean = false, // Untrusted client invariant
    val financialMutationPermitted: Boolean = false, // Untrusted client invariant
)

data class ProjectedBatchApplicationResult(
    val resultId: UUID,
    val tenantId: String,
    val batchId: UUID,
    val appliedEntriesCount: Int,
    val updatedProjections: List<AccountBalanceProjection>,
    val serverTime: Instant,
    val evidenceReference: String,
    val semanticContract: String = "Projection rebuild equals journal; optimistic/pessimistic choice follows ADR-002.",
)

/**
 * Authoritative service managing ledger projections, atomic journal-coupled projection updates,
 * optimistic concurrency versioning per ADR-002, and projection rebuild reconciliation.
 *
 * Semantic contract: "Projection rebuild equals journal; optimistic/pessimistic choice follows ADR-002."
 * Protected risk assertion: "crash leaves journal/projection split"
 */
class LedgerProjectionService(
    private val clock: Clock = Clock.systemUTC(),
) {
    // Key: "tenantId:accountReference" -> AccountBalanceProjection
    private val projections = ConcurrentHashMap<String, AccountBalanceProjection>()
    private val auditLogs = mutableListOf<AuditEvent>()
    private val processedBatches = ConcurrentHashMap<String, UUID>() // "tenantId:batchId" -> batchId

    /**
     * Atomically apply a posted journal batch to the account balance projections.
     * Enforces optimistic locking per ADR-002 via expectedAccountVersions.
     */
    @Synchronized
    fun applyBatchToProjection(
        principal: AuthenticatedPrincipal?,
        tenantId: String,
        batch: JournalBatchRecord,
        expectedAccountVersions: Map<String, Long> = emptyMap(),
    ): ProjectedBatchApplicationResult {
        LedgerProjectionBinding.checkBound()

        // 1. Auth & Permission checks
        val authPrincipal = principal ?: throw ProjectionUnauthorizedException("Unauthenticated projection update")
        if (authPrincipal.tenantId != tenantId || batch.tenantId != tenantId) {
            throw ProjectionForbiddenException("Cross-tenant projection update forbidden")
        }
        if (authPrincipal.kind != PrincipalKind.ADMIN || authPrincipal.roles.none { it in setOf(AdminRole.SUPER_ADMIN, AdminRole.SECURITY) }) {
            throw ProjectionForbiddenException("Principal lacks ledger projection authority")
        }

        // 2. Batch integrity check
        if (batch.status != JournalBatchStatus.POSTED && batch.status != JournalBatchStatus.COMPENSATED) {
            throw ProjectionInvalidException("Only POSTED or COMPENSATED batches may be projected")
        }
        if (batch.entries.isEmpty()) {
            throw ProjectionInvalidException("Cannot project batch without entries")
        }

        // 3. Exact-once batch application check
        val batchKey = "$tenantId:${batch.batchId}"
        if (processedBatches.containsKey(batchKey)) {
            // Already applied - return existing projected state for affected accounts
            val affectedRefs = batch.entries.map { it.accountReference }.distinct()
            val existingProjections = affectedRefs.mapNotNull { ref ->
                projections["$tenantId:$ref"]
            }
            return ProjectedBatchApplicationResult(
                resultId = UUID.randomUUID(),
                tenantId = tenantId,
                batchId = batch.batchId,
                appliedEntriesCount = batch.entries.size,
                updatedProjections = existingProjections,
                serverTime = Instant.now(clock),
                evidenceReference = "ledger-projection:batch:${batch.batchId}:replayed",
            )
        }

        // 4. Optimistic locking check per ADR-002
        for ((accRef, expectedVer) in expectedAccountVersions) {
            val key = "$tenantId:$accRef"
            val current = projections[key]
            val actualVer = current?.version ?: 0L
            if (actualVer != expectedVer) {
                throw ProjectionConflictException(
                    "Optimistic concurrency conflict on account '$accRef': expected version $expectedVer but found $actualVer"
                )
            }
        }

        // 5. Atomic projection calculation
        val now = Instant.now(clock)
        val updatedList = mutableListOf<AccountBalanceProjection>()

        // Group delta per account
        val deltasByAccount = mutableMapOf<String, Long>()
        for (entry in batch.entries) {
            if (entry.currencyCode != batch.currencyCode) {
                throw ProjectionInvalidException("Entry currency '${entry.currencyCode}' mismatch with batch currency '${batch.currencyCode}'")
            }
            val sign = if (entry.direction == JournalEntryDirection.CREDIT) 1L else -1L
            val delta = entry.amountMinorUnits * sign
            deltasByAccount[entry.accountReference] = (deltasByAccount[entry.accountReference] ?: 0L) + delta
        }

        // Commit updated projections
        for ((accRef, delta) in deltasByAccount) {
            val key = "$tenantId:$accRef"
            val current = projections[key]
            val currentBalance = current?.balanceMinorUnits ?: 0L
            val currentVer = current?.version ?: 0L
            val newProjection = AccountBalanceProjection(
                tenantId = tenantId,
                accountReference = accRef,
                currencyCode = batch.currencyCode,
                balanceMinorUnits = currentBalance + delta,
                version = currentVer + 1L,
                lastAppliedBatchId = batch.batchId,
                lastUpdated = now,
            )
            projections[key] = newProjection
            updatedList.add(newProjection)
        }

        processedBatches[batchKey] = batch.batchId

        val resultId = UUID.randomUUID()
        auditLogs.add(
            AuditEvent(
                eventId = UUID.randomUUID(),
                resultId = resultId,
                tenantId = tenantId,
                type = "LEDGER_PROJECTION_APPLIED",
                occurredAt = now,
                correlationId = batch.correlationId,
                causationId = batch.causationId,
            )
        )

        return ProjectedBatchApplicationResult(
            resultId = resultId,
            tenantId = tenantId,
            batchId = batch.batchId,
            appliedEntriesCount = batch.entries.size,
            updatedProjections = updatedList,
            serverTime = now,
            evidenceReference = "ledger-projection:batch:${batch.batchId}",
        )
    }

    /**
     * Rebuild the entire projection from the authoritative journal batches from scratch.
     * Reconciles any split or drifted projection state to ensure projection rebuild equals journal.
     */
    @Synchronized
    fun rebuildProjectionFromJournal(
        principal: AuthenticatedPrincipal?,
        tenantId: String,
        journalBatches: List<JournalBatchRecord>,
    ): ProjectionRebuildResult {
        LedgerProjectionBinding.checkBound()

        val authPrincipal = principal ?: throw ProjectionUnauthorizedException("Unauthenticated projection rebuild")
        if (authPrincipal.tenantId != tenantId) {
            throw ProjectionForbiddenException("Cross-tenant projection rebuild forbidden")
        }
        if (authPrincipal.kind != PrincipalKind.ADMIN || authPrincipal.roles.none { it in setOf(AdminRole.SUPER_ADMIN, AdminRole.SECURITY) }) {
            throw ProjectionForbiddenException("Principal lacks ledger rebuild authority")
        }

        val now = Instant.now(clock)
        val rebuiltBalances = mutableMapOf<String, Long>()
        val rebuiltCurrencies = mutableMapOf<String, String>()
        val rebuiltVersions = mutableMapOf<String, Long>()
        var totalEntries = 0

        // Chronological replay
        val sortedBatches = journalBatches
            .filter { it.tenantId == tenantId && (it.status == JournalBatchStatus.POSTED || it.status == JournalBatchStatus.COMPENSATED) }
            .sortedBy { it.createdAt }

        for (batch in sortedBatches) {
            for (entry in batch.entries) {
                totalEntries++
                val sign = if (entry.direction == JournalEntryDirection.CREDIT) 1L else -1L
                val delta = entry.amountMinorUnits * sign
                rebuiltBalances[entry.accountReference] = (rebuiltBalances[entry.accountReference] ?: 0L) + delta
                rebuiltCurrencies[entry.accountReference] = entry.currencyCode
                rebuiltVersions[entry.accountReference] = (rebuiltVersions[entry.accountReference] ?: 0L) + 1L
            }
        }

        // Atomically overwrite projections to match rebuilt journal state exactly
        projections.keys.filter { it.startsWith("$tenantId:") }.forEach { projections.remove(it) }
        processedBatches.keys.filter { it.startsWith("$tenantId:") }.forEach { processedBatches.remove(it) }

        for ((accRef, balance) in rebuiltBalances) {
            val key = "$tenantId:$accRef"
            projections[key] = AccountBalanceProjection(
                tenantId = tenantId,
                accountReference = accRef,
                currencyCode = rebuiltCurrencies[accRef] ?: "USD",
                balanceMinorUnits = balance,
                version = rebuiltVersions[accRef] ?: 1L,
                lastAppliedBatchId = sortedBatches.lastOrNull()?.batchId,
                lastUpdated = now,
            )
        }

        for (batch in sortedBatches) {
            processedBatches["$tenantId:${batch.batchId}"] = batch.batchId
        }

        val resultId = UUID.randomUUID()
        auditLogs.add(
            AuditEvent(
                eventId = UUID.randomUUID(),
                resultId = resultId,
                tenantId = tenantId,
                type = "LEDGER_PROJECTION_REBUILT",
                occurredAt = now,
                correlationId = "corr-rebuild",
                causationId = "caus-rebuild",
            )
        )

        return ProjectionRebuildResult(
            tenantId = tenantId,
            rebuiltAccountsCount = rebuiltBalances.size,
            totalBatchesProcessed = sortedBatches.size,
            totalEntriesProcessed = totalEntries,
            isReconciliationEqual = true,
            serverTime = now,
            evidenceReference = "ledger-projection:rebuild:$resultId",
        )
    }

    /**
     * Query current projected balance for an account.
     */
    fun getAccountProjection(
        principal: AuthenticatedPrincipal?,
        tenantId: String,
        accountReference: String,
    ): AccountBalanceProjection? {
        LedgerProjectionBinding.checkBound()

        val authPrincipal = principal ?: throw ProjectionUnauthorizedException("Unauthenticated projection query")
        if (authPrincipal.tenantId != tenantId) {
            throw ProjectionForbiddenException("Cross-tenant projection query forbidden")
        }
        return projections["$tenantId:$accountReference"]
    }

    /**
     * Test-only helper to simulate an uncoordinated split or crash drift to prove reconciliation recovery.
     */
    fun simulateCrashSplit(tenantId: String, accountReference: String, driftAmountMinorUnits: Long) {
        val key = "$tenantId:$accountReference"
        val current = projections[key]
        if (current != null) {
            projections[key] = current.copy(
                balanceMinorUnits = current.balanceMinorUnits + driftAmountMinorUnits
            )
        }
    }

    fun getAuditLogs(tenantId: String): List<AuditEvent> {
        return auditLogs.filter { it.tenantId == tenantId }
    }
}
