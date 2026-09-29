package com.slotting.admin.analytics

import java.time.Clock
import java.time.Instant
import java.time.LocalDate
import java.time.ZoneOffset
import java.util.UUID

/**
 * Authoritative Server Engine for Analytics Facts and Incremental Projections.
 *
 * Implements:
 * - Deterministic, replayable facts derived exclusively from server events
 * - UTC calendar day bucket partitioning (DST-safe)
 * - Multi-currency strict separation (never combines different currencies)
 * - Exact unique player metrics (DAU, WAU, MAU)
 * - GGR calculation: settled wagers minus game payouts for same currency/time basis
 * - Replay/rebuild equivalence and ledger reconciliation
 */
class AnalyticsProjectionService(
    private val store: AnalyticsStore,
    private val clock: Clock = Clock.systemUTC(),
) {

    /**
     * Ingests an authoritative analytics fact and updates the appropriate projections incrementally.
     * Enforces idempotent deduplication by sourceEventId.
     */
    @Synchronized
    fun recordFactAndProject(fact: AnalyticsFact): Boolean {
        // 1. Deduplicate by tenantId + sourceEventId
        val saved = store.saveFact(fact)
        if (!saved) {
            return false // Duplicate event, skip projection to avoid double-counting
        }

        // 2. Determine UTC date bucket
        val dateBucket = fact.occurredAt.atZone(ZoneOffset.UTC).toLocalDate()

        // 3. Track unique players if userId is present and status is not REJECTED/FAILED
        if (fact.userId != null && fact.status == FactStatus.SUCCEEDED) {
            store.recordUniquePlayer(fact.tenantId, dateBucket, fact.userId, fact.occurredAt)
        }

        // 4. Update currency-specific financial projections if currency is present
        val currency = fact.currency
        if (currency != null) {
            updateProjectionForCurrency(fact, dateBucket, currency, "OVERALL", "ALL")
            if (fact.providerId != null) {
                updateProjectionForCurrency(fact, dateBucket, currency, "PROVIDER", fact.providerId)
            }
            if (fact.gameId != null) {
                updateProjectionForCurrency(fact, dateBucket, currency, "GAME", fact.gameId)
            }
        }

        return true
    }

    private fun updateProjectionForCurrency(
        fact: AnalyticsFact,
        dateBucket: LocalDate,
        currency: String,
        dimensionType: String = "OVERALL",
        dimensionValue: String = "ALL",
    ) {
        val existing = store.findProjection(fact.tenantId, dateBucket, currency, dimensionType, dimensionValue)
        val now = clock.instant()

        var totalWagers = existing?.totalWagersMinor ?: 0L
        var wagerCount = existing?.wagerCount ?: 0L
        var totalPayouts = existing?.totalPayoutsMinor ?: 0L
        var payoutCount = existing?.payoutCount ?: 0L
        var totalDeposits = existing?.totalDepositsMinor ?: 0L
        var depositCount = existing?.depositCount ?: 0L
        var totalWithdrawalsCompleted = existing?.totalWithdrawalsCompletedMinor ?: 0L
        var withdrawalCompletedCount = existing?.withdrawalCompletedCount ?: 0L
        var withdrawalRejectedCount = existing?.withdrawalRejectedCount ?: 0L
        var newRegistrations = existing?.newRegistrationsCount ?: 0L
        var authFailures = existing?.authFailuresCount ?: 0L
        var restrictionsPlaced = existing?.restrictionsPlacedCount ?: 0L
        var reconciliationExceptions = existing?.reconciliationExceptionsCount ?: 0L

        when (fact.factType) {
            AnalyticsFactType.GAME_ROUND_SETTLED -> {
                if (fact.status == FactStatus.SUCCEEDED) {
                    val wager = fact.amountMinor ?: 0L
                    val payout = fact.payoutMinor ?: 0L
                    totalWagers += wager
                    if (wager > 0L) wagerCount++
                    totalPayouts += payout
                    if (payout > 0L) payoutCount++
                }
            }
            AnalyticsFactType.GAME_WAGER_PLACED -> {
                if (fact.status == FactStatus.SUCCEEDED) {
                    val wager = fact.amountMinor ?: 0L
                    totalWagers += wager
                    if (wager > 0L) wagerCount++
                }
            }
            AnalyticsFactType.DEPOSIT_COMPLETED -> {
                if (fact.status == FactStatus.SUCCEEDED) {
                    val dep = fact.amountMinor ?: 0L
                    totalDeposits += dep
                    if (dep > 0L) depositCount++
                }
            }
            AnalyticsFactType.WITHDRAWAL_COMPLETED -> {
                if (fact.status == FactStatus.SUCCEEDED) {
                    val with = fact.amountMinor ?: 0L
                    totalWithdrawalsCompleted += with
                    if (with > 0L) withdrawalCompletedCount++
                }
            }
            AnalyticsFactType.WITHDRAWAL_REJECTED -> {
                if (fact.status == FactStatus.REJECTED) {
                    withdrawalRejectedCount++
                }
            }
            AnalyticsFactType.USER_REGISTRATION -> {
                if (fact.status == FactStatus.SUCCEEDED) {
                    newRegistrations++
                }
            }
            AnalyticsFactType.AUTH_FAILURE -> {
                authFailures++
            }
            AnalyticsFactType.RESTRICTION_PLACED -> {
                restrictionsPlaced++
            }
            AnalyticsFactType.RECONCILIATION_EXCEPTION -> {
                reconciliationExceptions++
            }
            else -> {
                // Pending, initiated, or informational facts do not alter settled volume
            }
        }

        val ggr = totalWagers - totalPayouts

        val projection = DailyProjectionRecord(
            projectionId = existing?.projectionId ?: UUID.randomUUID(),
            tenantId = fact.tenantId,
            dateBucket = dateBucket,
            currency = currency,
            dimensionType = dimensionType,
            dimensionValue = dimensionValue,
            totalWagersMinor = totalWagers,
            wagerCount = wagerCount,
            totalPayoutsMinor = totalPayouts,
            payoutCount = payoutCount,
            ggrMinor = ggr,
            totalDepositsMinor = totalDeposits,
            depositCount = depositCount,
            totalWithdrawalsCompletedMinor = totalWithdrawalsCompleted,
            withdrawalCompletedCount = withdrawalCompletedCount,
            withdrawalRejectedCount = withdrawalRejectedCount,
            activePlayersCount = store.countUniquePlayers(fact.tenantId, dateBucket, dateBucket),
            newRegistrationsCount = newRegistrations,
            authFailuresCount = authFailures,
            restrictionsPlacedCount = restrictionsPlaced,
            reconciliationExceptionsCount = reconciliationExceptions,
            chargebacksUnsupportedMarker = true,
            version = (existing?.version ?: 0L) + 1L,
            lastProcessedFactTime = fact.occurredAt,
            updatedAt = now,
        )

        store.saveOrUpdateProjection(projection)
    }

    fun getDailyProjection(
        tenantId: String,
        dateBucket: LocalDate,
        currency: String,
        dimensionType: String = "OVERALL",
        dimensionValue: String = "ALL",
    ): DailyProjectionRecord? {
        return store.findProjection(tenantId, dateBucket, currency, dimensionType, dimensionValue)
    }

    fun calculateDau(tenantId: String, date: LocalDate): Long {
        return store.countUniquePlayers(tenantId, date, date)
    }

    fun calculateWau(tenantId: String, endDate: LocalDate): Long {
        return store.countUniquePlayers(tenantId, endDate.minusDays(6), endDate)
    }

    fun calculateMau(tenantId: String, endDate: LocalDate): Long {
        return store.countUniquePlayers(tenantId, endDate.minusDays(29), endDate)
    }

    /**
     * Rebuilds all projections for a tenant from the historical canonical facts.
     */
    @Synchronized
    fun rebuildProjectionsFromFacts(tenantId: String): ProjectionRebuildResult {
        store.clearProjectionsForTenant(tenantId)
        val allFacts = store.listFactsForTenant(tenantId)

        var replayedCount = 0L
        for (fact in allFacts) {
            val dateBucket = fact.occurredAt.atZone(ZoneOffset.UTC).toLocalDate()
            if (fact.userId != null && fact.status == FactStatus.SUCCEEDED) {
                store.recordUniquePlayer(fact.tenantId, dateBucket, fact.userId, fact.occurredAt)
            }
            if (fact.currency != null) {
                updateProjectionForCurrency(fact, dateBucket, fact.currency, "OVERALL", "ALL")
                if (fact.providerId != null) {
                    updateProjectionForCurrency(fact, dateBucket, fact.currency, "PROVIDER", fact.providerId)
                }
                if (fact.gameId != null) {
                    updateProjectionForCurrency(fact, dateBucket, fact.currency, "GAME", fact.gameId)
                }
            }
            replayedCount++
        }

        return ProjectionRebuildResult(
            tenantId = tenantId,
            factsReplayedCount = replayedCount,
            projectionsGeneratedCount = 1,
            rebuildTimestamp = clock.instant(),
            success = true,
        )
    }

    /**
     * Reconciles daily analytics totals against double-entry ledger balances.
     */
    fun reconcileAgainstLedger(
        tenantId: String,
        dateBucket: LocalDate,
        ledgerTotalsByCurrency: Map<String, Long>,
    ): LedgerReconciliationReport {
        val imbalances = mutableListOf<LedgerCurrencyImbalance>()

        for ((currency, ledgerTotal) in ledgerTotalsByCurrency) {
            val proj = getDailyProjection(tenantId, dateBucket, currency)
            val analyticsTotal = proj?.totalDepositsMinor ?: 0L // or relevant financial movement
            if (analyticsTotal != ledgerTotal) {
                imbalances.add(
                    LedgerCurrencyImbalance(
                        currency = currency,
                        analyticsTotalMinor = analyticsTotal,
                        ledgerTotalMinor = ledgerTotal,
                        divergenceMinor = Math.abs(analyticsTotal - ledgerTotal)
                    )
                )
            }
        }

        return LedgerReconciliationReport(
            tenantId = tenantId,
            dateBucket = dateBucket,
            isBalanced = imbalances.isEmpty(),
            imbalances = imbalances,
        )
    }
}
