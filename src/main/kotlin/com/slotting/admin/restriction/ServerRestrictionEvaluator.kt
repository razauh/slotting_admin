package com.slotting.admin.restriction

import java.time.Clock
import java.time.Instant
import java.util.UUID

/**
 * TC-026 Authoritative Restriction Policy Matrix and Evaluator.
 * Full production implementation fulfilling the approved baseline:
 * - Access decision aggregation: DENY > STEP_UP > ALLOW
 * - Financial disposition aggregation: safest disposition (HOLD > CANCEL > REFUND > PAYOUT > COMPLETE / NONE)
 * - Cache loss cannot unlock: cache miss queries durable store
 * - Retains individual restriction provenance on every decision
 */

interface ServerRestrictionEvaluator {
    fun evaluate(context: OperationEvaluationContext): ServerRestrictionEvaluationResult
}

class DefaultServerRestrictionEvaluator(
    private val durableStore: DurableServerRestrictionStore,
    private val cache: EphemeralRestrictionCache? = null,
    private val clock: Clock = Clock.systemUTC()
) : ServerRestrictionEvaluator {

    override fun evaluate(context: OperationEvaluationContext): ServerRestrictionEvaluationResult {
        val now = context.now

        // 1. Check cache first, fallback to durable store on cache miss
        val cached = cache?.get(context.tenantId, context.subjectReference)
        val activeRestrictions = if (cached != null) {
            // Filter cached records to ensure freshness with current evaluation time
            cached.filter { it.isEffectiveAt(now) }
        } else {
            // Durable store is authoritative source of truth.
            val durableRecords = durableStore.findActiveRestrictions(context.tenantId, context.subjectReference, now)
            cache?.put(context.tenantId, context.subjectReference, durableRecords)
            durableRecords
        }

        // 2. If no restrictions are active, default to ALLOW and COMPLETE/NONE
        if (activeRestrictions.isEmpty()) {
            val defaultResult = ServerRestrictionEvaluationResult(
                tenantId = context.tenantId,
                subjectReference = context.subjectReference,
                operation = context.operation,
                compositeAccess = AccessDecision.ALLOW,
                financialDisposition = if (context.operation == ServerOperation.PENDING_FINANCIAL_OPERATIONS) {
                    FinancialDisposition.COMPLETE
                } else {
                    FinancialDisposition.NONE
                },
                contributingRestrictions = emptyList(),
                evaluatedAt = now
            )
            durableStore.recordEvaluation(defaultResult)
            return defaultResult
        }

        // 3. Evaluate each active restriction against the policy matrix
        val contributing = mutableListOf<ContributingRestrictionRecord>()
        val accessDecisions = mutableListOf<AccessDecision>()
        val financialDispositions = mutableListOf<FinancialDisposition>()

        for (restriction in activeRestrictions) {
            val (access, disposition) = ServerRestrictionPolicyMatrix.evaluateSingle(restriction, context)
            contributing.add(
                ContributingRestrictionRecord(
                    restrictionId = restriction.restrictionId,
                    source = restriction.source,
                    reasonCode = restriction.reasonCode,
                    evidenceReference = restriction.evidenceReference,
                    scope = restriction.scope,
                    individualAccess = access,
                    individualDisposition = disposition,
                    ruleVersion = restriction.ruleVersion,
                    expiresAt = restriction.expiresAt
                )
            )
            accessDecisions.add(access)
            financialDispositions.add(disposition)
        }

        // 4. Composite Access Decision: DENY > STEP_UP > ALLOW
        val compositeAccess = when {
            accessDecisions.any { it == AccessDecision.DENY } -> AccessDecision.DENY
            accessDecisions.any { it == AccessDecision.STEP_UP } -> AccessDecision.STEP_UP
            else -> AccessDecision.ALLOW
        }

        // 5. Composite Financial Disposition: HOLD > CANCEL > REFUND > PAYOUT > COMPLETE > NONE
        val compositeDisposition = when {
            financialDispositions.any { it == FinancialDisposition.HOLD } -> FinancialDisposition.HOLD
            financialDispositions.any { it == FinancialDisposition.CANCEL } -> FinancialDisposition.CANCEL
            financialDispositions.any { it == FinancialDisposition.REFUND } -> FinancialDisposition.REFUND
            financialDispositions.any { it == FinancialDisposition.PAYOUT } -> FinancialDisposition.PAYOUT
            financialDispositions.any { it == FinancialDisposition.COMPLETE } -> FinancialDisposition.COMPLETE
            else -> FinancialDisposition.NONE
        }

        val result = ServerRestrictionEvaluationResult(
            tenantId = context.tenantId,
            subjectReference = context.subjectReference,
            operation = context.operation,
            compositeAccess = compositeAccess,
            financialDisposition = compositeDisposition,
            contributingRestrictions = contributing,
            evaluatedAt = now
        )

        // 6. Record evaluation for durable audit trail
        durableStore.recordEvaluation(result)

        return result
    }
}

class ServerRestrictionEnforcementGate(
    private val evaluator: ServerRestrictionEvaluator
) {
    fun evaluate(context: OperationEvaluationContext): ServerRestrictionEvaluationResult =
        evaluator.evaluate(context)

    fun enforce(context: OperationEvaluationContext): ServerRestrictionEvaluationResult {
        val result = evaluator.evaluate(context)
        when (result.compositeAccess) {
            AccessDecision.DENY -> throw ServerRestrictionDeniedException(result)
            AccessDecision.STEP_UP -> throw ServerRestrictionStepUpRequiredException(result)
            AccessDecision.ALLOW -> return result
        }
    }
}
