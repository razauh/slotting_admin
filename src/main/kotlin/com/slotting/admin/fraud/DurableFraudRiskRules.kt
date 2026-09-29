package com.slotting.admin.fraud

import java.time.Duration
import java.time.Instant

/**
 * TC-031: Configurable versioned risk rules.
 */

class FailedDepositsBurstRule(
    val burstCountThreshold: Int = 3,
    val windowDuration: Duration = Duration.ofMinutes(15),
) : RiskRule {
    override val ruleId: String = "RULE_FAILED_DEPOSITS_BURST"
    override val ruleName: String = "Failed Deposits Burst Detection"

    override fun evaluate(context: RuleEvaluationContext): RiskRuleMatch? {
        val windowStart = context.evalTime.minus(windowDuration)
        val failedDeposits = context.eventsInWindow.filter {
            it.eventType == RiskEventType.DEPOSIT_FAILED && !it.eventTimestamp.isBefore(windowStart)
        }
        if (failedDeposits.size >= burstCountThreshold) {
            return RiskRuleMatch(
                ruleId = ruleId,
                ruleName = ruleName,
                action = RiskActionRecommendation.HOLD,
                reason = "FAILED_DEPOSITS_BURST",
                matchedValues = mapOf(
                    "observedFailedDeposits" to failedDeposits.size.toString(),
                    "threshold" to burstCountThreshold.toString(),
                    "windowMinutes" to windowDuration.toMinutes().toString(),
                )
            )
        }
        return null
    }
}

class FailedWithdrawalsRule(
    val burstCountThreshold: Int = 3,
    val windowDuration: Duration = Duration.ofHours(1),
) : RiskRule {
    override val ruleId: String = "RULE_FAILED_WITHDRAWALS_BURST"
    override val ruleName: String = "Failed Withdrawals Burst Detection"

    override fun evaluate(context: RuleEvaluationContext): RiskRuleMatch? {
        val windowStart = context.evalTime.minus(windowDuration)
        val failedWithdrawals = context.eventsInWindow.filter {
            it.eventType == RiskEventType.WITHDRAWAL_FAILED && !it.eventTimestamp.isBefore(windowStart)
        }
        if (failedWithdrawals.size >= burstCountThreshold) {
            return RiskRuleMatch(
                ruleId = ruleId,
                ruleName = ruleName,
                action = RiskActionRecommendation.HOLD,
                reason = "FAILED_WITHDRAWALS_BURST",
                matchedValues = mapOf(
                    "observedFailedWithdrawals" to failedWithdrawals.size.toString(),
                    "threshold" to burstCountThreshold.toString(),
                )
            )
        }
        return null
    }
}

class DepositWithdrawCyclingRule(
    val windowDuration: Duration = Duration.ofMinutes(30),
) : RiskRule {
    override val ruleId: String = "RULE_DEPOSIT_WITHDRAW_CYCLING"
    override val ruleName: String = "Rapid Deposit-Withdrawal Cycling Detection"

    override fun evaluate(context: RuleEvaluationContext): RiskRuleMatch? {
        val windowStart = context.evalTime.minus(windowDuration)
        val relevantEvents = context.eventsInWindow.filter { !it.eventTimestamp.isBefore(windowStart) }

        val depositSucceeded = relevantEvents.any { it.eventType == RiskEventType.DEPOSIT_SUCCEEDED }
        val withdrawalRequested = relevantEvents.any { it.eventType == RiskEventType.WITHDRAWAL_REQUESTED }
        val wagers = relevantEvents.filter { it.eventType == RiskEventType.WAGER_PLACED }

        // If deposit succeeded and withdrawal requested with 0 wagers in short window
        if (depositSucceeded && withdrawalRequested && wagers.isEmpty()) {
            return RiskRuleMatch(
                ruleId = ruleId,
                ruleName = ruleName,
                action = RiskActionRecommendation.HOLD,
                reason = "DEPOSIT_WITHDRAWAL_CYCLING",
                matchedValues = mapOf(
                    "depositDetected" to "true",
                    "withdrawalDetected" to "true",
                    "wagerCount" to "0",
                )
            )
        }
        return null
    }
}

class UnusualWithdrawalRule(
    val thresholdMinorUnits: Long = 1_000_000L, // e.g. 10,000 in minor units
    val targetCurrency: String = "EUR",
) : RiskRule {
    override val ruleId: String = "RULE_UNUSUAL_WITHDRAWAL"
    override val ruleName: String = "Unusual High-Value Withdrawal Detection"

    override fun evaluate(context: RuleEvaluationContext): RiskRuleMatch? {
        val trigger = context.triggerEvent ?: context.eventsInWindow.lastOrNull { it.eventType == RiskEventType.WITHDRAWAL_REQUESTED }
        if (trigger != null && trigger.eventType == RiskEventType.WITHDRAWAL_REQUESTED) {
            val money = trigger.money
            if (money != null && money.currencyCode == targetCurrency && money.amountMinorUnits >= thresholdMinorUnits) {
                return RiskRuleMatch(
                    ruleId = ruleId,
                    ruleName = ruleName,
                    action = RiskActionRecommendation.HOLD,
                    reason = "UNUSUAL_WITHDRAWAL_AMOUNT",
                    matchedValues = mapOf(
                        "amountMinorUnits" to money.amountMinorUnits.toString(),
                        "currency" to money.currencyCode,
                        "threshold" to thresholdMinorUnits.toString(),
                    )
                )
            }
        }
        return null
    }
}

class AuthAnomaliesRule(
    val failedAuthThreshold: Int = 3,
    val distinctIpThreshold: Int = 3,
    val windowDuration: Duration = Duration.ofMinutes(15),
) : RiskRule {
    override val ruleId: String = "RULE_AUTH_ANOMALIES"
    override val ruleName: String = "Authentication Anomalies Detection"

    override fun evaluate(context: RuleEvaluationContext): RiskRuleMatch? {
        val windowStart = context.evalTime.minus(windowDuration)
        val relevantEvents = context.eventsInWindow.filter { !it.eventTimestamp.isBefore(windowStart) }

        val failedAuths = relevantEvents.filter { it.eventType == RiskEventType.AUTH_FAILED }
        val distinctIps = relevantEvents.mapNotNull { it.ipAddress }.distinct()
        val authAnomalyEvents = relevantEvents.filter { it.eventType == RiskEventType.AUTH_ANOMALY }

        if (authAnomalyEvents.isNotEmpty() || failedAuths.size >= failedAuthThreshold || distinctIps.size >= distinctIpThreshold) {
            val action = if (failedAuths.size >= failedAuthThreshold * 2) RiskActionRecommendation.DENY else RiskActionRecommendation.STEP_UP
            return RiskRuleMatch(
                ruleId = ruleId,
                ruleName = ruleName,
                action = action,
                reason = "AUTH_ANOMALY_DETECTED",
                matchedValues = mapOf(
                    "failedAuthCount" to failedAuths.size.toString(),
                    "distinctIps" to distinctIps.size.toString(),
                    "hasExplicitAnomalyEvent" to authAnomalyEvents.isNotEmpty().toString(),
                )
            )
        }
        return null
    }
}

class PaymentReuseRule : RiskRule {
    override val ruleId: String = "RULE_PAYMENT_INSTRUMENT_REUSE"
    override val ruleName: String = "Cross-Subject Payment Instrument Reuse Detection"

    override fun evaluate(context: RuleEvaluationContext): RiskRuleMatch? {
        val distinctSubjects = context.crossSubjectPaymentEvents.map { it.subjectReference }.distinct()
        if (distinctSubjects.size > 1) {
            return RiskRuleMatch(
                ruleId = ruleId,
                ruleName = ruleName,
                action = RiskActionRecommendation.HOLD,
                reason = "PAYMENT_INSTRUMENT_REUSE_DETECTED",
                matchedValues = mapOf(
                    "correlatedSubjectCount" to distinctSubjects.size.toString(),
                    "otherSubjects" to distinctSubjects.filter { it != context.subjectReference }.joinToString(","),
                )
            )
        }
        return null
    }
}

class ProviderAnomalyRule : RiskRule {
    override val ruleId: String = "RULE_PROVIDER_ANOMALY"
    override val ruleName: String = "Provider Dispute or Provider Alert Detection"

    override fun evaluate(context: RuleEvaluationContext): RiskRuleMatch? {
        val dispute = context.eventsInWindow.lastOrNull { it.eventType == RiskEventType.CHARGEBACK_DISPUTE }
        if (dispute != null) {
            return RiskRuleMatch(
                ruleId = ruleId,
                ruleName = ruleName,
                action = RiskActionRecommendation.DENY,
                reason = "PROVIDER_CHARGEBACK_DISPUTE",
                matchedValues = mapOf("disputeEventId" to dispute.eventId.toString())
            )
        }
        val providerAlert = context.eventsInWindow.lastOrNull { it.eventType == RiskEventType.PROVIDER_ALERT }
        if (providerAlert != null) {
            return RiskRuleMatch(
                ruleId = ruleId,
                ruleName = ruleName,
                action = RiskActionRecommendation.HOLD,
                reason = "PROVIDER_ALERT_DETECTED",
                matchedValues = mapOf("alertEventId" to providerAlert.eventId.toString())
            )
        }
        return null
    }
}

class ManualFlagRule : RiskRule {
    override val ruleId: String = "RULE_MANUAL_FRAUD_FLAG"
    override val ruleName: String = "Manual Fraud Flag Detection"

    override fun evaluate(context: RuleEvaluationContext): RiskRuleMatch? {
        val flag = context.eventsInWindow.lastOrNull {
            it.eventType == RiskEventType.MANUAL_FLAG && it.source == EventSource.ADMIN_ACTION
        }
        if (flag != null) {
            return RiskRuleMatch(
                ruleId = ruleId,
                ruleName = ruleName,
                action = RiskActionRecommendation.DENY,
                reason = "MANUAL_FRAUD_FLAG_ACTIVE",
                matchedValues = mapOf(
                    "flaggedBy" to (flag.metadata["adminId"] ?: "ADMIN"),
                    "flagReason" to (flag.metadata["reason"] ?: "UNSPECIFIED"),
                )
            )
        }
        return null
    }
}
