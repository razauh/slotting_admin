package com.slotting.admin.analytics

import java.time.Instant
import java.time.LocalDate
import java.util.UUID

enum class AnalyticsFactType {
    GAME_ROUND_SETTLED,
    GAME_WAGER_PLACED,
    DEPOSIT_INITIATED,
    DEPOSIT_COMPLETED,
    DEPOSIT_FAILED,
    WITHDRAWAL_REQUESTED,
    WITHDRAWAL_COMPLETED,
    WITHDRAWAL_REJECTED,
    USER_REGISTRATION,
    USER_AUTHENTICATION,
    AUTH_FAILURE,
    KYC_STATUS_CHANGED,
    RESTRICTION_PLACED,
    FRAUD_CASE_DISPOSED,
    RECONCILIATION_EXCEPTION,
}

enum class FactStatus {
    SUCCEEDED,
    FAILED,
    PENDING,
    REJECTED,
}

data class AnalyticsFact(
    val factId: UUID = UUID.randomUUID(),
    val tenantId: String,
    val factType: AnalyticsFactType,
    val sourceEventId: String,
    val sourceEventType: String,
    val userId: String? = null,
    val sessionId: String? = null,
    val gameId: String? = null,
    val providerId: String? = null,
    val currency: String? = null,
    val amountMinor: Long? = null,
    val payoutMinor: Long? = null,
    val status: FactStatus,
    val occurredAt: Instant,
    val recordedAt: Instant,
    val correlationId: String,
    val causationId: String,
    val metadataJson: String? = null,
) {
    init {
        require(tenantId.isNotBlank()) { "tenantId must not be blank" }
        require(sourceEventId.isNotBlank()) { "sourceEventId must not be blank" }
        require(sourceEventType.isNotBlank()) { "sourceEventType must not be blank" }
    }
}

data class DailyProjectionRecord(
    val projectionId: UUID = UUID.randomUUID(),
    val tenantId: String,
    val dateBucket: LocalDate,
    val currency: String,
    val dimensionType: String = "OVERALL",
    val dimensionValue: String = "ALL",
    val totalWagersMinor: Long = 0L,
    val wagerCount: Long = 0L,
    val totalPayoutsMinor: Long = 0L,
    val payoutCount: Long = 0L,
    val ggrMinor: Long = 0L,
    val totalDepositsMinor: Long = 0L,
    val depositCount: Long = 0L,
    val totalWithdrawalsCompletedMinor: Long = 0L,
    val withdrawalCompletedCount: Long = 0L,
    val withdrawalRejectedCount: Long = 0L,
    val activePlayersCount: Long = 0L,
    val newRegistrationsCount: Long = 0L,
    val authFailuresCount: Long = 0L,
    val restrictionsPlacedCount: Long = 0L,
    val reconciliationExceptionsCount: Long = 0L,
    val chargebacksUnsupportedMarker: Boolean = true,
    val version: Long = 1L,
    val lastProcessedFactTime: Instant,
    val updatedAt: Instant,
)

data class ProjectionRebuildResult(
    val tenantId: String,
    val factsReplayedCount: Long,
    val projectionsGeneratedCount: Int,
    val rebuildTimestamp: Instant,
    val success: Boolean,
)

data class LedgerReconciliationReport(
    val tenantId: String,
    val dateBucket: LocalDate,
    val isBalanced: Boolean,
    val imbalances: List<LedgerCurrencyImbalance>,
)

data class LedgerCurrencyImbalance(
    val currency: String,
    val analyticsTotalMinor: Long,
    val ledgerTotalMinor: Long,
    val divergenceMinor: Long,
)
