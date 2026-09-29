package com.slotting.admin.fraud

import com.slotting.admin.restriction.RestrictionScope
import com.slotting.admin.restriction.RestrictionSource
import com.slotting.admin.restriction.ServerRestrictionRecord
import java.time.Instant
import java.util.UUID

/**
 * TC-031: Immutable risk-event taxonomy and source confidence.
 */
enum class RiskEventType {
    AUTH_SUCCESS,
    AUTH_FAILED,
    AUTH_ANOMALY,
    DEPOSIT_INITIATED,
    DEPOSIT_SUCCEEDED,
    DEPOSIT_FAILED,
    WITHDRAWAL_REQUESTED,
    WITHDRAWAL_SUCCEEDED,
    WITHDRAWAL_FAILED,
    WAGER_PLACED,
    WAGER_SETTLED,
    CHARGEBACK_DISPUTE,
    PROVIDER_ALERT,
    PAYMENT_INSTRUMENT_REUSE,
    MANUAL_FLAG,
}

enum class EventSource {
    SERVER_OBSERVED,
    PROVIDER_VERIFIED,
    ADMIN_ACTION,
    CLIENT_TELEMETRY,
}

enum class SourceConfidence {
    HIGH,
    MEDIUM,
    LOW,
}

data class RiskMoney(
    val amountMinorUnits: Long,
    val currencyCode: String,
) {
    init {
        require(amountMinorUnits >= 0) { "Amount cannot be negative" }
        require(currencyCode.length == 3) { "Currency code must be 3 ISO characters" }
    }

    operator fun plus(other: RiskMoney): RiskMoney {
        require(currencyCode == other.currencyCode) {
            "Currency mismatch: cannot sum $currencyCode and ${other.currencyCode}"
        }
        val sum = Math.addExact(amountMinorUnits, other.amountMinorUnits)
        return RiskMoney(sum, currencyCode)
    }
}

data class DurableRiskEvent(
    val eventId: UUID = UUID.randomUUID(),
    val tenantId: String,
    val subjectReference: String,
    val eventType: RiskEventType,
    val source: EventSource,
    val confidence: SourceConfidence,
    val accountReference: String? = null,
    val deviceFingerprint: String? = null,
    val ipAddress: String? = null,
    val paymentInstrumentHash: String? = null,
    val money: RiskMoney? = null,
    val eventTimestamp: Instant,
    val ingestTimestamp: Instant = Instant.now(),
    val idempotencyKey: String,
    val correlationId: String,
    val causationId: String,
    val metadata: Map<String, String> = emptyMap(),
) {
    init {
        require(tenantId.isNotBlank()) { "tenantId must not be blank" }
        require(subjectReference.isNotBlank()) { "subjectReference must not be blank" }
        require(idempotencyKey.isNotBlank()) { "idempotencyKey must not be blank" }
        require(correlationId.isNotBlank()) { "correlationId must not be blank" }
        require(causationId.isNotBlank()) { "causationId must not be blank" }
    }
}

enum class RiskActionRecommendation {
    ALLOW,
    STEP_UP,
    REVIEW,
    HOLD,
    DENY,
}

data class RiskRuleMatch(
    val ruleId: String,
    val ruleName: String,
    val action: RiskActionRecommendation,
    val reason: String,
    val matchedValues: Map<String, String> = emptyMap(),
)

data class RiskEvaluationDecision(
    val decisionId: UUID = UUID.randomUUID(),
    val tenantId: String,
    val subjectReference: String,
    val ruleSetVersion: Long,
    val action: RiskActionRecommendation,
    val matchedRules: List<RiskRuleMatch>,
    val evidenceReference: String,
    val expiresAt: Instant? = null,
    val requiresCase: Boolean = false,
    val caseReference: String? = null,
    val evaluatedAt: Instant,
    val idempotencyKey: String,
    val serverRestriction: ServerRestrictionRecord? = null,
)

data class RuleEvaluationContext(
    val tenantId: String,
    val subjectReference: String,
    val triggerEvent: DurableRiskEvent?,
    val eventsInWindow: List<DurableRiskEvent>,
    val crossSubjectPaymentEvents: List<DurableRiskEvent> = emptyList(),
    val evalTime: Instant,
)

interface RiskRule {
    val ruleId: String
    val ruleName: String
    fun evaluate(context: RuleEvaluationContext): RiskRuleMatch?
}

data class RiskRuleSet(
    val version: Long,
    val active: Boolean = true,
    val rules: List<RiskRule>,
    val createdAt: Instant,
    val activatedAt: Instant? = null,
)

data class IngestRiskEventCommand(
    val tenantId: String,
    val subjectReference: String,
    val eventType: RiskEventType,
    val source: EventSource,
    val confidence: SourceConfidence,
    val accountReference: String? = null,
    val deviceFingerprint: String? = null,
    val ipAddress: String? = null,
    val paymentInstrumentHash: String? = null,
    val money: RiskMoney? = null,
    val eventTimestamp: Instant,
    val idempotencyKey: String,
    val correlationId: String,
    val causationId: String,
    val metadata: Map<String, String> = emptyMap(),
)

data class EvaluateSubjectRiskCommand(
    val tenantId: String,
    val subjectReference: String,
    val triggerEvent: DurableRiskEvent? = null,
    val idempotencyKey: String,
    val correlationId: String,
    val causationId: String,
    val specificRuleVersion: Long? = null,
)
