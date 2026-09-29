package com.slotting.admin.analytics

import com.slotting.admin.auth.AuthenticatedPrincipal
import java.time.Instant
import java.time.LocalDate
import java.time.ZoneId
import java.time.ZoneOffset

enum class TimeRangePreset {
    DAILY,
    WEEKLY,
    MONTHLY,
    CUSTOM,
}

enum class MetricUnit {
    MINOR_CURRENCY,
    COUNT,
    USERS,
}

data class AdminAnalyticsQuery(
    val principal: AuthenticatedPrincipal?,
    val sessionId: String,
    val requestedTenantId: String? = null,
    val rangePreset: TimeRangePreset = TimeRangePreset.DAILY,
    val startDate: LocalDate? = null,
    val endDate: LocalDate? = null,
    val timezone: ZoneId = ZoneOffset.UTC,
    val currency: String? = null,
    val providerId: String? = null,
    val gameId: String? = null,
    val includeOperationalHealth: Boolean = true,
)

data class DashboardMetricCard(
    val metricId: String,
    val name: String,
    val formula: String,
    val version: String,
    val currency: String? = null,
    val unit: MetricUnit,
    val amountMinor: Long? = null,
    val count: Long? = null,
    val availability: MetricAvailability = MetricAvailability.AVAILABLE,
    val unavailableReason: String? = null,
    val dateRange: String,
)

data class DashboardFreshness(
    val queryTimestamp: Instant,
    val lastProcessedFactTime: Instant?,
    val lagDurationSeconds: Long,
    val isStale: Boolean,
)

data class DimensionFilterInfo(
    val providerId: String? = null,
    val gameId: String? = null,
    val dimensionType: String = "OVERALL",
    val dimensionValue: String = "ALL",
)

data class OperationalHealthSummary(
    val tenantId: String,
    val unresolvedProviderEventsCount: Long = 0L,
    val reconciliationExceptionsCount: Long = 0L,
    val ledgerAlertsCount: Long = 0L,
    val pendingWithdrawalReviewsCount: Long = 0L,
    val openFraudCasesCount: Long = 0L,
    val activeRestrictionsCount: Long = 0L,
    val authFailuresCount: Long = 0L,
    val criticalIncidentsCount: Long = 0L,
    val pagedAlertsCount: Long = 0L,
)

data class AdminAnalyticsDashboardResponse(
    val tenantId: String,
    val timeRange: TimeRangePreset,
    val startDate: LocalDate,
    val endDate: LocalDate,
    val timezone: String,
    val freshness: DashboardFreshness,
    val userMetrics: List<DashboardMetricCard>,
    val financialMetricsByCurrency: Map<String, List<DashboardMetricCard>>,
    val operationalHealth: OperationalHealthSummary,
    val dimensionFilter: DimensionFilterInfo? = null,
    val unsupportedMetrics: List<DashboardMetricCard>,
)
