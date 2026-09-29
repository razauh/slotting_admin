package com.slotting.admin.analytics

import com.slotting.admin.auth.AdminPermission
import com.slotting.admin.auth.AdminRbacPolicy
import com.slotting.admin.auth.AdminSessionDirectory
import com.slotting.admin.auth.AlertSink
import com.slotting.admin.auth.AuditEvent
import com.slotting.admin.auth.AuthErrorCode
import com.slotting.admin.auth.AuthenticationFailure
import com.slotting.admin.fraud.FraudCaseStore
import com.slotting.admin.observability.OperationalObservabilityService
import com.slotting.admin.restriction.DurableServerRestrictionStore
import com.slotting.admin.withdrawal.WithdrawalQueueStore
import java.time.Clock
import java.time.Duration
import java.time.Instant
import java.time.LocalDate
import java.time.temporal.ChronoUnit
import java.util.UUID

class AdminAnalyticsDashboardService(
    private val analyticsStore: AnalyticsStore,
    private val sessions: AdminSessionDirectory,
    private val rbacPolicy: AdminRbacPolicy,
    private val withdrawalQueueStore: WithdrawalQueueStore? = null,
    private val fraudCaseStore: FraudCaseStore? = null,
    private val restrictionStore: DurableServerRestrictionStore? = null,
    private val observabilityService: OperationalObservabilityService? = null,
    private val alertSink: AlertSink? = null,
    private val clock: Clock = Clock.systemUTC(),
    private val staleLagThreshold: Duration = Duration.ofMinutes(15),
) {

    companion object {
        const val MAX_ALLOWED_RANGE_DAYS = 366L
    }

    fun queryDashboard(query: AdminAnalyticsQuery): AdminAnalyticsDashboardResponse {
        // 1. Authorize principal and active session BEFORE reading any cached or projected state
        val principal = query.principal ?: throw AuthenticationFailure.Rejected(AuthErrorCode.UNAUTHENTICATED)
        val tenantId = principal.tenantId

        // Mismatched tenant request is rejected with FORBIDDEN; tenant scope is strictly server-derived
        if (query.requestedTenantId != null && query.requestedTenantId != tenantId) {
            throw AuthenticationFailure.Rejected(AuthErrorCode.FORBIDDEN)
        }

        val now = Instant.now(clock)
        val session = try {
            sessions.find(tenantId, principal.id, query.sessionId)
        } catch (_: Exception) {
            null
        }

        if (session == null || !session.active || !session.expiresAt.isAfter(now)) {
            throw AuthenticationFailure.Rejected(AuthErrorCode.FORBIDDEN)
        }
        if (!session.mfaVerified || (session.mfaExpiresAt != null && !session.mfaExpiresAt.isAfter(now))) {
            throw AuthenticationFailure.Rejected(AuthErrorCode.FORBIDDEN)
        }

        // Dedicated read permission check
        if (!rbacPolicy.isPermitted(principal, AdminPermission.ANALYTICS_READ)) {
            throw AuthenticationFailure.Rejected(AuthErrorCode.FORBIDDEN)
        }

        // 2. Resolve date range with timezone conversion and bounds validation
        val today = LocalDate.now(clock.withZone(query.timezone))
        val (resolvedStart, resolvedEnd) = when (query.rangePreset) {
            TimeRangePreset.DAILY -> Pair(today, today)
            TimeRangePreset.WEEKLY -> Pair(today.minusDays(6), today)
            TimeRangePreset.MONTHLY -> Pair(today.minusDays(29), today)
            TimeRangePreset.CUSTOM -> {
                val s = query.startDate ?: today
                val e = query.endDate ?: today
                require(!e.isBefore(s)) { "endDate cannot be before startDate" }
                val days = ChronoUnit.DAYS.between(s, e)
                require(days <= MAX_ALLOWED_RANGE_DAYS) {
                    "Requested date range of $days days exceeds maximum allowed limit of $MAX_ALLOWED_RANGE_DAYS days"
                }
                Pair(s, e)
            }
        }

        // 3. Resolve dimension filter
        val (dimType, dimVal) = when {
            query.providerId != null -> Pair("PROVIDER", query.providerId)
            query.gameId != null -> Pair("GAME", query.gameId)
            else -> Pair("OVERALL", "ALL")
        }

        // 4. Query authoritative incremental projections
        val projections = analyticsStore.queryProjections(
            tenantId = tenantId,
            startDate = resolvedStart,
            endDate = resolvedEnd,
            currency = query.currency,
            dimensionType = dimType,
            dimensionValue = dimVal,
        )

        // 5. Compute source freshness and projection lag
        val latestFactFromProj = projections.maxOfOrNull { it.lastProcessedFactTime }
        val latestFactTime = latestFactFromProj ?: analyticsStore.listFactsForTenant(tenantId).maxOfOrNull { it.occurredAt }
        val lagSeconds = if (latestFactTime != null) {
            Math.max(0L, Duration.between(latestFactTime, now).seconds)
        } else {
            0L
        }
        val isStale = if (latestFactTime != null) lagSeconds > staleLagThreshold.seconds else false
        val freshness = DashboardFreshness(
            queryTimestamp = now,
            lastProcessedFactTime = latestFactTime,
            lagDurationSeconds = lagSeconds,
            isStale = isStale,
        )

        // 6. User metrics (DAU, WAU, MAU)
        val dauDef = MetricDictionary.getMetricDefinition("METRIC-DAU")!!
        val wauDef = MetricDictionary.getMetricDefinition("METRIC-WAU")!!
        val mauDef = MetricDictionary.getMetricDefinition("METRIC-MAU")!!

        val dauCount = analyticsStore.countUniquePlayers(tenantId, resolvedEnd, resolvedEnd)
        val wauCount = analyticsStore.countUniquePlayers(tenantId, resolvedEnd.minusDays(6), resolvedEnd)
        val mauCount = analyticsStore.countUniquePlayers(tenantId, resolvedEnd.minusDays(29), resolvedEnd)

        val userMetrics = listOf(
            DashboardMetricCard(
                metricId = dauDef.metricId,
                name = dauDef.name,
                formula = dauDef.formula,
                version = dauDef.version,
                currency = null,
                unit = MetricUnit.USERS,
                count = dauCount,
                dateRange = resolvedEnd.toString(),
            ),
            DashboardMetricCard(
                metricId = wauDef.metricId,
                name = wauDef.name,
                formula = wauDef.formula,
                version = wauDef.version,
                currency = null,
                unit = MetricUnit.USERS,
                count = wauCount,
                dateRange = "${resolvedEnd.minusDays(6)} to $resolvedEnd",
            ),
            DashboardMetricCard(
                metricId = mauDef.metricId,
                name = mauDef.name,
                formula = mauDef.formula,
                version = mauDef.version,
                currency = null,
                unit = MetricUnit.USERS,
                count = mauCount,
                dateRange = "${resolvedEnd.minusDays(29)} to $resolvedEnd",
            ),
        )

        // 7. Financial metrics strictly partitioned by currency (no cross-currency summation)
        val ggrDef = MetricDictionary.getMetricDefinition("METRIC-GGR")!!
        val wagerDef = MetricDictionary.getMetricDefinition("METRIC-WAGER-VOL")!!
        val payoutDef = MetricDictionary.getMetricDefinition("METRIC-PAYOUT-VOL")!!
        val depositDef = MetricDictionary.getMetricDefinition("METRIC-DEPOSIT-VOL")!!
        val withdrawalDef = MetricDictionary.getMetricDefinition("METRIC-WITHDRAWAL-VOL")!!

        val projectionsByCurrency = projections.groupBy { it.currency }.toMutableMap()
        if (query.currency != null && !projectionsByCurrency.containsKey(query.currency)) {
            projectionsByCurrency[query.currency] = emptyList()
        }

        val dateRangeStr = "$resolvedStart to $resolvedEnd"
        val financialMetricsByCurrency = mutableMapOf<String, List<DashboardMetricCard>>()

        for ((curr, currProjs) in projectionsByCurrency) {
            val totalWagers = currProjs.sumOf { it.totalWagersMinor }
            val wagerCount = currProjs.sumOf { it.wagerCount }
            val totalPayouts = currProjs.sumOf { it.totalPayoutsMinor }
            val payoutCount = currProjs.sumOf { it.payoutCount }
            val ggr = totalWagers - totalPayouts
            val totalDeposits = currProjs.sumOf { it.totalDepositsMinor }
            val depositCount = currProjs.sumOf { it.depositCount }
            val totalWithdrawals = currProjs.sumOf { it.totalWithdrawalsCompletedMinor }
            val withdrawalCount = currProjs.sumOf { it.withdrawalCompletedCount }

            financialMetricsByCurrency[curr] = listOf(
                DashboardMetricCard(
                    metricId = ggrDef.metricId,
                    name = ggrDef.name,
                    formula = ggrDef.formula,
                    version = ggrDef.version,
                    currency = curr,
                    unit = MetricUnit.MINOR_CURRENCY,
                    amountMinor = ggr,
                    dateRange = dateRangeStr,
                ),
                DashboardMetricCard(
                    metricId = wagerDef.metricId,
                    name = wagerDef.name,
                    formula = wagerDef.formula,
                    version = wagerDef.version,
                    currency = curr,
                    unit = MetricUnit.MINOR_CURRENCY,
                    amountMinor = totalWagers,
                    count = wagerCount,
                    dateRange = dateRangeStr,
                ),
                DashboardMetricCard(
                    metricId = payoutDef.metricId,
                    name = payoutDef.name,
                    formula = payoutDef.formula,
                    version = payoutDef.version,
                    currency = curr,
                    unit = MetricUnit.MINOR_CURRENCY,
                    amountMinor = totalPayouts,
                    count = payoutCount,
                    dateRange = dateRangeStr,
                ),
                DashboardMetricCard(
                    metricId = depositDef.metricId,
                    name = depositDef.name,
                    formula = depositDef.formula,
                    version = depositDef.version,
                    currency = curr,
                    unit = MetricUnit.MINOR_CURRENCY,
                    amountMinor = totalDeposits,
                    count = depositCount,
                    dateRange = dateRangeStr,
                ),
                DashboardMetricCard(
                    metricId = withdrawalDef.metricId,
                    name = withdrawalDef.name,
                    formula = withdrawalDef.formula,
                    version = withdrawalDef.version,
                    currency = curr,
                    unit = MetricUnit.MINOR_CURRENCY,
                    amountMinor = totalWithdrawals,
                    count = withdrawalCount,
                    dateRange = dateRangeStr,
                ),
            )
        }

        // 8. Unsupported metrics explicitly marked
        val chargebacksDef = MetricDictionary.getMetricDefinition("METRIC-CHARGEBACKS")!!
        val unsupportedMetrics = listOf(
            DashboardMetricCard(
                metricId = chargebacksDef.metricId,
                name = chargebacksDef.name,
                formula = chargebacksDef.formula,
                version = chargebacksDef.version,
                currency = query.currency,
                unit = MetricUnit.COUNT,
                availability = chargebacksDef.availability,
                unavailableReason = "Chargeback processing is not supported in this release",
                dateRange = dateRangeStr,
            )
        )

        // 9. Operational health and case queues
        val allTenantFacts = analyticsStore.listFactsForTenant(tenantId)
        val unresolvedFactsCount = allTenantFacts.count {
            it.status == FactStatus.FAILED || it.status == FactStatus.PENDING
        }.toLong()

        val reconExceptionsCount = projections.sumOf { it.reconciliationExceptionsCount }.takeIf { it > 0 }
            ?: allTenantFacts.count { it.factType == AnalyticsFactType.RECONCILIATION_EXCEPTION }.toLong()

        val authFailuresCount = projections.sumOf { it.authFailuresCount }.takeIf { it > 0 }
            ?: allTenantFacts.count { it.factType == AnalyticsFactType.AUTH_FAILURE }.toLong()

        val pendingWithdrawals = withdrawalQueueStore?.countPending(tenantId) ?: 0L
        val openFraudCases = fraudCaseStore?.countActiveCases(tenantId) ?: 0L
        val activeRestrictions = restrictionStore?.countActiveRestrictions(tenantId, now)
            ?: projections.sumOf { it.restrictionsPlacedCount }

        val obsSummary = observabilityService?.getDashboardSummary(tenantId)
        val criticalIncidents = obsSummary?.criticalCount?.toLong() ?: 0L
        val pagedAlerts = obsSummary?.pagedAlertCount?.toLong() ?: 0L
        val ledgerAlerts = obsSummary?.balanceImbalanceCount?.toLong() ?: 0L

        val operationalHealth = OperationalHealthSummary(
            tenantId = tenantId,
            unresolvedProviderEventsCount = unresolvedFactsCount,
            reconciliationExceptionsCount = reconExceptionsCount,
            ledgerAlertsCount = ledgerAlerts,
            pendingWithdrawalReviewsCount = pendingWithdrawals,
            openFraudCasesCount = openFraudCases,
            activeRestrictionsCount = activeRestrictions,
            authFailuresCount = authFailuresCount,
            criticalIncidentsCount = criticalIncidents,
            pagedAlertsCount = pagedAlerts,
        )

        // 10. Audit event logging
        alertSink?.alert(
            AuditEvent(
                eventId = UUID.randomUUID(),
                resultId = UUID.randomUUID(),
                tenantId = tenantId,
                type = "ADMIN_ANALYTICS_DASHBOARD_QUERY",
                occurredAt = now,
                correlationId = query.sessionId,
                causationId = principal.id,
            )
        )

        return AdminAnalyticsDashboardResponse(
            tenantId = tenantId,
            timeRange = query.rangePreset,
            startDate = resolvedStart,
            endDate = resolvedEnd,
            timezone = query.timezone.id,
            freshness = freshness,
            userMetrics = userMetrics,
            financialMetricsByCurrency = financialMetricsByCurrency,
            operationalHealth = operationalHealth,
            dimensionFilter = DimensionFilterInfo(
                providerId = query.providerId,
                gameId = query.gameId,
                dimensionType = dimType,
                dimensionValue = dimVal,
            ),
            unsupportedMetrics = unsupportedMetrics,
        )
    }
}
