package com.slotting.admin.wallet

import com.slotting.admin.auth.AuditEvent
import com.slotting.admin.auth.AuthenticatedPrincipal
import com.slotting.admin.auth.OutboxEvent
import java.time.Instant
import java.util.UUID

// =============================================================================
// Statement Enums & Records
// =============================================================================

enum class StatementEntryType {
    DEPOSIT,
    WITHDRAWAL,
    WAGER,
    WIN_PAYOUT,
    REFUND,
    MANUAL_ADJUSTMENT,
    BONUS_GRANT,
    BONUS_CONVERSION
}

enum class StatementDirection {
    CREDIT,
    DEBIT
}

/**
 * Authoritative statement line mapping a double-entry ledger posting.
 * Explicitly bound to "SERVER_LEDGER", never untrusted Android local activity.
 */
data class StatementEntryRecord(
    val entryId: UUID,
    val tenantId: String,
    val walletId: UUID,
    val ownerId: UUID,
    val currencyCode: String,
    val entryType: StatementEntryType,
    val direction: StatementDirection,
    val amountMinorUnits: Long,
    val balanceAfterMinorUnits: Long,
    val cashAvailableAfterMinorUnits: Long,
    val bonusActiveAfterMinorUnits: Long,
    val reference: String,
    val sourceAuthority: String = "SERVER_LEDGER",
    val postedAt: Instant,
    val sequenceNumber: Long
) {
    init {
        require(amountMinorUnits > 0L) { "Amount must be strictly positive ($amountMinorUnits)" }
        require(balanceAfterMinorUnits >= 0L) { "Running balance cannot be negative ($balanceAfterMinorUnits)" }
        require(sourceAuthority == "SERVER_LEDGER") { "Statement entry must map server ledger postings, never local activity" }
    }
}

// =============================================================================
// Query & Result Models
// =============================================================================

data class BalanceSnapshotQuery(
    val principal: AuthenticatedPrincipal?,
    val tenantId: String,
    val ownerId: UUID,
    val currencyCode: String,
    val walletId: UUID? = null,
    val correlationId: String,
    val causationId: String
)

data class BalanceSnapshotResult(
    val walletId: UUID,
    val tenantId: String,
    val ownerId: UUID,
    val currencyCode: String,
    val asOfTime: Instant,
    val version: Long,
    val totalBalanceMinorUnits: Long,
    val availableBalanceMinorUnits: Long,
    val lockedBalanceMinorUnits: Long,
    val pendingBalanceMinorUnits: Long,
    val withdrawableCashMinorUnits: Long,
    val cash: CashBuckets,
    val bonus: BonusBuckets,
    val evidenceReference: String,
    val auditEvent: AuditEvent,
    val outboxEvent: OutboxEvent,
    val hasAndroidDbImpact: Boolean = false,
    val hasAndroidLifecycleClaim: Boolean = false
)

data class GetStatementQuery(
    val principal: AuthenticatedPrincipal?,
    val tenantId: String,
    val ownerId: UUID,
    val currencyCode: String,
    val cursor: String? = null,
    val limit: Int = 20,
    val fromTime: Instant? = null,
    val toTime: Instant? = null,
    val correlationId: String,
    val causationId: String
)

data class StatementPageResult(
    val entries: List<StatementEntryRecord>,
    val nextCursor: String?,
    val hasMore: Boolean,
    val pageSize: Int,
    val asOfTime: Instant,
    val version: Long,
    val evidenceReference: String,
    val auditEvent: AuditEvent,
    val outboxEvent: OutboxEvent,
    val hasAndroidDbImpact: Boolean = false,
    val hasAndroidLifecycleClaim: Boolean = false
)

// =============================================================================
// Observability Models
// =============================================================================

data class StatementMetricEvent(
    val eventType: String, // "attempt", "accept", "reject", "query"
    val tenantId: String,
    val ownerId: UUID?,
    val correlationId: String,
    val causationId: String,
    val timestamp: Instant,
    val details: Map<String, Any?> = emptyMap()
)

interface WalletStatementObservability {
    fun recordMetric(event: StatementMetricEvent)
    fun getMetrics(): List<StatementMetricEvent>
}

class InMemoryWalletStatementObservability : WalletStatementObservability {
    private val metrics = mutableListOf<StatementMetricEvent>()

    @Synchronized
    override fun recordMetric(event: StatementMetricEvent) {
        metrics.add(event)
    }

    @Synchronized
    override fun getMetrics(): List<StatementMetricEvent> = metrics.toList()
}

// =============================================================================
// Store Interfaces & In-Memory Implementations
// =============================================================================

interface WalletStatementStore {
    fun recordPosting(entry: StatementEntryRecord)
    fun queryEntries(
        tenantId: String,
        ownerId: UUID,
        currencyCode: String,
        afterSeq: Long?,
        limit: Int,
        fromTime: Instant? = null,
        toTime: Instant? = null
    ): List<StatementEntryRecord>
    fun countEntries(tenantId: String, ownerId: UUID, currencyCode: String): Long
}

class InMemoryWalletStatementStore : WalletStatementStore {
    // Key: "tenantId:ownerId:currencyCode" -> synchronized list of entries sorted by sequenceNumber ASC
    private val store = java.util.concurrent.ConcurrentHashMap<String, MutableList<StatementEntryRecord>>()
    private val sequenceGenerators = java.util.concurrent.ConcurrentHashMap<String, java.util.concurrent.atomic.AtomicLong>()

    private fun key(tenantId: String, ownerId: UUID, currencyCode: String): String =
        "$tenantId:$ownerId:$currencyCode"

    fun nextSequence(tenantId: String, ownerId: UUID, currencyCode: String): Long {
        return sequenceGenerators.computeIfAbsent(key(tenantId, ownerId, currencyCode)) {
            java.util.concurrent.atomic.AtomicLong(0L)
        }.incrementAndGet()
    }

    @Synchronized
    override fun recordPosting(entry: StatementEntryRecord) {
        val list = store.computeIfAbsent(key(entry.tenantId, entry.ownerId, entry.currencyCode)) {
            mutableListOf()
        }
        list.add(entry)
    }

    @Synchronized
    override fun queryEntries(
        tenantId: String,
        ownerId: UUID,
        currencyCode: String,
        afterSeq: Long?,
        limit: Int,
        fromTime: Instant?,
        toTime: Instant?
    ): List<StatementEntryRecord> {
        val list = store[key(tenantId, ownerId, currencyCode)] ?: return emptyList()

        return list.asSequence()
            .filter { entry ->
                (afterSeq == null || entry.sequenceNumber > afterSeq) &&
                    (fromTime == null || !entry.postedAt.isBefore(fromTime)) &&
                    (toTime == null || !entry.postedAt.isAfter(toTime))
            }
            .take(limit)
            .toList()
    }

    @Synchronized
    override fun countEntries(tenantId: String, ownerId: UUID, currencyCode: String): Long {
        return store[key(tenantId, ownerId, currencyCode)]?.size?.toLong() ?: 0L
    }
}

// =============================================================================
// Domain Exceptions
// =============================================================================

class InvalidStatementRequestException(
    message: String,
    details: Map<String, Any?> = emptyMap()
) : WalletException(message, "INVALID_STATEMENT_REQUEST", details)

class InvalidCursorException(
    message: String,
    details: Map<String, Any?> = emptyMap()
) : WalletException(message, "INVALID_CURSOR", details)
