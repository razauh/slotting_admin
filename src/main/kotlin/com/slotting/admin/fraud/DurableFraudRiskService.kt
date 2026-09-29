package com.slotting.admin.fraud

import com.slotting.admin.restriction.DurableServerRestrictionStore
import com.slotting.admin.restriction.RestrictionScope
import com.slotting.admin.restriction.RestrictionSource
import com.slotting.admin.restriction.ServerRestrictionRecord
import java.time.Clock
import java.time.Duration
import java.time.Instant
import java.util.UUID

data class IngestRiskEventResult(
    val eventId: UUID,
    val tenantId: String,
    val subjectReference: String,
    val isNewEvent: Boolean,
    val eventTimestamp: Instant,
    val ingestTimestamp: Instant,
)

class DurableFraudRiskService(
    private val store: DurableFraudRiskStore,
    private val restrictionStore: DurableServerRestrictionStore? = null,
    private val clock: Clock = Clock.systemUTC(),
    private val defaultEvaluationWindow: Duration = Duration.ofDays(7),
) {

    init {
        // Ensure default seed rule set v1 is present if not already initialized
        if (store.findRuleSet(1L) == null) {
            val defaultSeedRules = listOf(
                FailedDepositsBurstRule(),
                FailedWithdrawalsRule(),
                DepositWithdrawCyclingRule(),
                UnusualWithdrawalRule(),
                AuthAnomaliesRule(),
                PaymentReuseRule(),
                ProviderAnomalyRule(),
                ManualFlagRule(),
            )
            store.saveRuleSet(
                RiskRuleSet(
                    version = 1L,
                    active = true,
                    rules = defaultSeedRules,
                    createdAt = clock.instant(),
                    activatedAt = clock.instant(),
                )
            )
        }
    }

    @Synchronized
    fun ingestEvent(command: IngestRiskEventCommand): IngestRiskEventResult {
        val now = clock.instant()

        store.findEventByIdempotency(command.tenantId, command.idempotencyKey)?.let { existing ->
            return IngestRiskEventResult(
                eventId = existing.eventId,
                tenantId = existing.tenantId,
                subjectReference = existing.subjectReference,
                isNewEvent = false,
                eventTimestamp = existing.eventTimestamp,
                ingestTimestamp = existing.ingestTimestamp,
            )
        }

        val event = DurableRiskEvent(
            eventId = UUID.randomUUID(),
            tenantId = command.tenantId,
            subjectReference = command.subjectReference,
            eventType = command.eventType,
            source = command.source,
            confidence = command.confidence,
            accountReference = command.accountReference,
            deviceFingerprint = command.deviceFingerprint,
            ipAddress = command.ipAddress,
            paymentInstrumentHash = command.paymentInstrumentHash,
            money = command.money,
            eventTimestamp = command.eventTimestamp,
            ingestTimestamp = now,
            idempotencyKey = command.idempotencyKey,
            correlationId = command.correlationId,
            causationId = command.causationId,
            metadata = command.metadata,
        )

        val inserted = store.saveEvent(event)
        return IngestRiskEventResult(
            eventId = event.eventId,
            tenantId = event.tenantId,
            subjectReference = event.subjectReference,
            isNewEvent = inserted,
            eventTimestamp = event.eventTimestamp,
            ingestTimestamp = event.ingestTimestamp,
        )
    }

    @Synchronized
    fun evaluateSubject(command: EvaluateSubjectRiskCommand): RiskEvaluationDecision {
        val now = clock.instant()

        store.findDecisionByIdempotency(command.tenantId, command.idempotencyKey)?.let { cached ->
            return cached
        }

        val ruleSet = if (command.specificRuleVersion != null) {
            store.findRuleSet(command.specificRuleVersion)
                ?: throw IllegalArgumentException("Rule set version ${command.specificRuleVersion} not found")
        } else {
            store.findActiveRuleSet()
                ?: throw IllegalStateException("No active risk rule set available")
        }

        val windowStart = now.minus(defaultEvaluationWindow)
        val subjectEvents = store.findEventsForSubject(
            tenantId = command.tenantId,
            subjectReference = command.subjectReference,
            fromTime = windowStart,
            toTime = now,
        )

        val paymentInstrumentHash = command.triggerEvent?.paymentInstrumentHash
            ?: subjectEvents.lastOrNull { it.paymentInstrumentHash != null }?.paymentInstrumentHash

        val crossSubjectPaymentEvents = if (paymentInstrumentHash != null) {
            store.findEventsByPaymentInstrument(command.tenantId, paymentInstrumentHash, windowStart)
        } else {
            emptyList()
        }

        val evalContext = RuleEvaluationContext(
            tenantId = command.tenantId,
            subjectReference = command.subjectReference,
            triggerEvent = command.triggerEvent,
            eventsInWindow = subjectEvents,
            crossSubjectPaymentEvents = crossSubjectPaymentEvents,
            evalTime = now,
        )

        val matchedRules = ruleSet.rules.mapNotNull { it.evaluate(evalContext) }

        val compositeAction = resolveCompositeAction(matchedRules)
        val requiresCase = compositeAction in setOf(
            RiskActionRecommendation.HOLD,
            RiskActionRecommendation.REVIEW,
            RiskActionRecommendation.DENY,
        )

        val decisionId = UUID.randomUUID()
        val caseRef = if (requiresCase) {
            "FRAUD-CASE-${command.tenantId}-${command.subjectReference}-${decisionId.toString().take(8)}"
        } else {
            null
        }

        val primaryReason = matchedRules.firstOrNull()?.reason ?: "NORMAL_ACTIVITY"
        val evidenceRef = "RISK-EVID-${command.tenantId}-${command.subjectReference}-$decisionId"

        val serverRestriction = if (compositeAction in setOf(RiskActionRecommendation.DENY, RiskActionRecommendation.HOLD)) {
            ServerRestrictionRecord(
                restrictionId = UUID.randomUUID(),
                tenantId = command.tenantId,
                subjectReference = command.subjectReference,
                source = RestrictionSource.FRAUD_SECURITY,
                reasonCode = primaryReason,
                safeUserMessage = "Security review pending for account activity.",
                scope = RestrictionScope.WholeAccount,
                effectiveFrom = now,
                evidenceReference = evidenceRef,
                ruleVersion = ruleSet.version,
                issuer = "FRAUD_RISK_SUBSYSTEM",
                active = true,
            )
        } else {
            null
        }

        if (serverRestriction != null && restrictionStore != null) {
            restrictionStore.saveRestriction(serverRestriction)
        }

        val decision = RiskEvaluationDecision(
            decisionId = decisionId,
            tenantId = command.tenantId,
            subjectReference = command.subjectReference,
            ruleSetVersion = ruleSet.version,
            action = compositeAction,
            matchedRules = matchedRules,
            evidenceReference = evidenceRef,
            expiresAt = if (compositeAction == RiskActionRecommendation.ALLOW) null else now.plus(Duration.ofDays(30)),
            requiresCase = requiresCase,
            caseReference = caseRef,
            evaluatedAt = now,
            idempotencyKey = command.idempotencyKey,
            serverRestriction = serverRestriction,
        )

        store.saveDecision(decision)
        return decision
    }

    private fun resolveCompositeAction(matchedRules: List<RiskRuleMatch>): RiskActionRecommendation {
        if (matchedRules.isEmpty()) return RiskActionRecommendation.ALLOW
        val actions = matchedRules.map { it.action }.toSet()
        return when {
            RiskActionRecommendation.DENY in actions -> RiskActionRecommendation.DENY
            RiskActionRecommendation.HOLD in actions -> RiskActionRecommendation.HOLD
            RiskActionRecommendation.STEP_UP in actions -> RiskActionRecommendation.STEP_UP
            RiskActionRecommendation.REVIEW in actions -> RiskActionRecommendation.REVIEW
            else -> RiskActionRecommendation.ALLOW
        }
    }

    @Synchronized
    fun activateRuleSet(version: Long): Boolean {
        return store.activateRuleSet(version, clock.instant())
    }

    @Synchronized
    fun rollbackToRuleSet(version: Long): Boolean {
        return store.activateRuleSet(version, clock.instant())
    }
}
