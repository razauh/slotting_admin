package com.slotting.admin.analytics

enum class CurrencyBehavior {
    PER_CURRENCY,
    CURRENCY_INDEPENDENT,
}

enum class MetricAvailability {
    AVAILABLE,
    UNSUPPORTED,
}

data class MetricDefinition(
    val metricId: String,
    val name: String,
    val formula: String,
    val version: String,
    val currencyBehavior: CurrencyBehavior,
    val availability: MetricAvailability = MetricAvailability.AVAILABLE,
    val statusInclusion: Set<FactStatus> = setOf(FactStatus.SUCCEEDED),
    val exclusions: List<String> = emptyList(),
)

object MetricDictionary {
    private val metrics = listOf(
        MetricDefinition(
            metricId = "METRIC-GGR",
            name = "Gross Gaming Revenue (GGR)",
            formula = "sum(settled_wagers_minor) - sum(settled_payouts_minor) [by currency, strictly excluding canceled or pending rounds]",
            version = "1.0.0",
            currencyBehavior = CurrencyBehavior.PER_CURRENCY,
            statusInclusion = setOf(FactStatus.SUCCEEDED),
            exclusions = listOf("Canceled rounds", "Pending wagers", "Unsettled bets"),
        ),
        MetricDefinition(
            metricId = "METRIC-WAGER-VOL",
            name = "Total Wager Volume",
            formula = "sum(wager_amount_minor) [by currency]",
            version = "1.0.0",
            currencyBehavior = CurrencyBehavior.PER_CURRENCY,
            statusInclusion = setOf(FactStatus.SUCCEEDED),
        ),
        MetricDefinition(
            metricId = "METRIC-PAYOUT-VOL",
            name = "Total Payout Volume",
            formula = "sum(payout_amount_minor) [by currency]",
            version = "1.0.0",
            currencyBehavior = CurrencyBehavior.PER_CURRENCY,
            statusInclusion = setOf(FactStatus.SUCCEEDED),
        ),
        MetricDefinition(
            metricId = "METRIC-DEPOSIT-VOL",
            name = "Total Deposit Volume",
            formula = "sum(deposit_amount_minor) [by currency, only completed deposits]",
            version = "1.0.0",
            currencyBehavior = CurrencyBehavior.PER_CURRENCY,
            statusInclusion = setOf(FactStatus.SUCCEEDED),
            exclusions = listOf("Initiated/pending deposits", "Failed deposits"),
        ),
        MetricDefinition(
            metricId = "METRIC-WITHDRAWAL-VOL",
            name = "Total Withdrawal Volume",
            formula = "sum(withdrawal_amount_minor) [by currency, only completed payouts]",
            version = "1.0.0",
            currencyBehavior = CurrencyBehavior.PER_CURRENCY,
            statusInclusion = setOf(FactStatus.SUCCEEDED),
            exclusions = listOf("Requested/pending withdrawals", "Rejected withdrawals"),
        ),
        MetricDefinition(
            metricId = "METRIC-DAU",
            name = "Daily Active Users (DAU)",
            formula = "count(distinct user_id) where occurred_at in UTC date bucket",
            version = "1.0.0",
            currencyBehavior = CurrencyBehavior.CURRENCY_INDEPENDENT,
            statusInclusion = setOf(FactStatus.SUCCEEDED),
        ),
        MetricDefinition(
            metricId = "METRIC-WAU",
            name = "Weekly Active Users (WAU)",
            formula = "count(distinct user_id) where occurred_at in 7-day rolling UTC window",
            version = "1.0.0",
            currencyBehavior = CurrencyBehavior.CURRENCY_INDEPENDENT,
            statusInclusion = setOf(FactStatus.SUCCEEDED),
        ),
        MetricDefinition(
            metricId = "METRIC-MAU",
            name = "Monthly Active Users (MAU)",
            formula = "count(distinct user_id) where occurred_at in 30-day rolling UTC window",
            version = "1.0.0",
            currencyBehavior = CurrencyBehavior.CURRENCY_INDEPENDENT,
            statusInclusion = setOf(FactStatus.SUCCEEDED),
        ),
        MetricDefinition(
            metricId = "METRIC-CHARGEBACKS",
            name = "Chargebacks & Disputes",
            formula = "UNAVAILABLE (Chargeback processing is not supported in this release)",
            version = "1.0.0",
            currencyBehavior = CurrencyBehavior.PER_CURRENCY,
            availability = MetricAvailability.UNSUPPORTED,
            exclusions = listOf("Chargeback/dispute metrics are unavailable and must not be fabricated"),
        ),
    ).associateBy { it.metricId }

    fun getMetricDefinition(metricId: String): MetricDefinition? = metrics[metricId]

    fun listAllMetrics(): List<MetricDefinition> = metrics.values.toList()
}
