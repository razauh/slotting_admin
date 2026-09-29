package com.slotting.admin.wallet

import com.slotting.admin.auth.AuthenticatedPrincipal
import java.time.Instant
import java.util.UUID

enum class WalletSyncStatus {
    FRESH,
    STALE,
    UNAVAILABLE,
}

data class CurrencyBalance(
    val currencyCode: String,
    val balanceMinorUnits: Long,
) {
    init {
        require(currencyCode.matches(Regex("^[A-Z]{3}$"))) { "Invalid currency code: $currencyCode" }
    }
}

data class AuthoritativeWalletSnapshot(
    val ownerReference: String,
    val tenantId: String,
    val currencyBalances: List<CurrencyBalance>,
    val ledgerVersion: Long,
    val serverVersion: Long,
    val generatedAt: Instant,
    val expiresAt: Instant,
    val syncStatus: WalletSyncStatus,
    val evidenceReference: String,
)

data class AuthoritativeStatementEntry(
    val entryId: UUID,
    val tenantId: String,
    val ownerReference: String,
    val currencyCode: String,
    val direction: String, // "CREDIT", "DEBIT"
    val entryType: String,
    val amountMinorUnits: Long,
    val runningBalanceMinorUnits: Long?,
    val transactionReference: String,
    val ledgerVersion: Long,
    val postedAt: Instant,
    val sequenceNumber: Long,
)

data class AuthoritativeStatementPage(
    val entries: List<AuthoritativeStatementEntry>,
    val nextCursor: String?,
    val hasMore: Boolean,
    val pageSize: Int,
    val ledgerVersion: Long,
    val asOfTime: Instant,
    val evidenceReference: String,
)

data class WalletSnapshotQuery(
    val principal: AuthenticatedPrincipal?,
    val tenantId: String,
    val ownerReference: String,
    val expectedLedgerVersion: Long? = null,
    val allowStale: Boolean = true,
)

data class StatementPageQuery(
    val principal: AuthenticatedPrincipal?,
    val tenantId: String,
    val ownerReference: String,
    val currencyCode: String,
    val cursor: String? = null,
    val limit: Int = 20,
    val fromTime: Instant? = null,
    val toTime: Instant? = null,
    val idempotencyKey: String? = null,
)

data class ProjectionRebuildReport(
    val tenantId: String,
    val accountsRebuilt: Int,
    val totalBalancesMinorUnits: Long,
    val ledgerVersion: Long,
    val verified: Boolean,
    val durationMs: Long,
)
