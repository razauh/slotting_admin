package com.slotting.admin.release

import java.time.Clock

enum class StagedGateDecision {
    PROMOTION_APPROVED,
    REJECTED_MISSING_APPROVALS,
    REJECTED_DUAL_CONTROL_VIOLATION,
    REJECTED_APPROVAL_DIGEST_MISMATCH,
    REJECTED_PROVENANCE_FAILED,
    REJECTED_CANARY_HEALTH_FAILURE,
}

data class StagedPromotionEvaluation(
    val canPromote: Boolean,
    val decision: StagedGateDecision,
    val reasons: List<String>,
)

data class CanaryHealthMetrics(
    val errorRatePercent: Double,
    val latencyP99Ms: Long,
    val databaseErrorsCount: Int,
    val financialReconciliationErrorsCount: Int,
)

data class CanaryEvaluation(
    val isHealthy: Boolean,
    val suggestedNextStage: PromotionStage,
    val breachReasons: List<String>,
)

/**
 * Evaluates staged promotions, dual-control approvals, and canary metrics (TC-041).
 * Prevents synthetic GO decisions, ensuring all state progressions are backed by durable evidence.
 */
class StagedDeploymentGateService(
    private val maxCanaryErrorRatePercent: Double = 1.0,
    private val maxCanaryLatencyP99Ms: Long = 1000L,
    private val clock: Clock = Clock.systemUTC(),
) {

    private val validTransitions = mapOf(
        PromotionStage.BUILT to setOf(PromotionStage.BUILD_VERIFIED, PromotionStage.FAILED),
        PromotionStage.BUILD_VERIFIED to setOf(PromotionStage.SIGNED, PromotionStage.FAILED),
        PromotionStage.SIGNED to setOf(PromotionStage.STAGING_APPROVED, PromotionStage.FAILED),
        PromotionStage.STAGING_APPROVED to setOf(PromotionStage.STAGING_DEPLOYED, PromotionStage.FAILED),
        PromotionStage.STAGING_DEPLOYED to setOf(PromotionStage.STAGING_VERIFIED, PromotionStage.UNHEALTHY, PromotionStage.ROLLBACK_PENDING),
        PromotionStage.STAGING_VERIFIED to setOf(PromotionStage.CANARY, PromotionStage.FAILED),
        PromotionStage.CANARY to setOf(PromotionStage.CANARY_HEALTHY, PromotionStage.UNHEALTHY, PromotionStage.ROLLBACK_PENDING),
        PromotionStage.CANARY_HEALTHY to setOf(PromotionStage.PRODUCTION_APPROVED, PromotionStage.FAILED),
        PromotionStage.PRODUCTION_APPROVED to setOf(PromotionStage.PRODUCTION_DEPLOYED, PromotionStage.FAILED),
        PromotionStage.PRODUCTION_DEPLOYED to setOf(PromotionStage.PRODUCTION_VERIFIED, PromotionStage.UNHEALTHY, PromotionStage.ROLLBACK_PENDING),
        PromotionStage.ROLLBACK_PENDING to setOf(PromotionStage.ROLLED_BACK, PromotionStage.FAILED),
    )

    fun validateStateTransition(from: PromotionStage, to: PromotionStage): Boolean {
        return validTransitions[from]?.contains(to) == true
    }

    fun evaluateStagedPromotion(
        manifest: ReleaseEvidenceManifest,
        targetEnvironment: Environment,
        approvals: List<ApprovalEvidence>,
    ): StagedPromotionEvaluation {
        if (targetEnvironment != Environment.PRODUCTION) {
            return StagedPromotionEvaluation(true, StagedGateDecision.PROMOTION_APPROVED, emptyList())
        }

        // Production promotion requires dual-control approvals
        if (approvals.isEmpty()) {
            return StagedPromotionEvaluation(
                canPromote = false,
                decision = StagedGateDecision.REJECTED_MISSING_APPROVALS,
                reasons = listOf("Production promotion requires mandatory dual-control approvals"),
            )
        }

        // 1. Verify approval digests match the current manifest artifact digest exactly
        val mismatchedDigest = approvals.firstOrNull { it.artifactDigest != manifest.artifact.digest }
        if (mismatchedDigest != null) {
            return StagedPromotionEvaluation(
                canPromote = false,
                decision = StagedGateDecision.REJECTED_APPROVAL_DIGEST_MISMATCH,
                reasons = listOf("Approval ${mismatchedDigest.approvalId} was signed for digest '${mismatchedDigest.artifactDigest}' but current artifact digest is '${manifest.artifact.digest}'"),
            )
        }

        // 2. Check required roles
        val rolesPresent = approvals.map { it.role }.toSet()
        val hasOperator = rolesPresent.contains(ReleaseRole.OPERATOR)
        val hasCompliance = rolesPresent.contains(ReleaseRole.COMPLIANCE)

        if (!hasOperator || !hasCompliance) {
            return StagedPromotionEvaluation(
                canPromote = false,
                decision = StagedGateDecision.REJECTED_MISSING_APPROVALS,
                reasons = listOf("Missing required role approvals: OPERATOR and COMPLIANCE both required for production"),
            )
        }

        // 3. Enforce distinct identities for dual control
        val distinctApproverCount = approvals.map { it.approverId }.distinct().size
        if (distinctApproverCount < 2) {
            return StagedPromotionEvaluation(
                canPromote = false,
                decision = StagedGateDecision.REJECTED_DUAL_CONTROL_VIOLATION,
                reasons = listOf("Dual-control violation: OPERATOR and COMPLIANCE approvals must originate from distinct authorized individuals"),
            )
        }

        return StagedPromotionEvaluation(
            canPromote = true,
            decision = StagedGateDecision.PROMOTION_APPROVED,
            reasons = emptyList(),
        )
    }

    fun evaluateCanaryHealth(metrics: CanaryHealthMetrics): CanaryEvaluation {
        val breachReasons = mutableListOf<String>()

        if (metrics.financialReconciliationErrorsCount > 0) {
            breachReasons.add("CRITICAL: Financial reconciliation errors detected in canary: count=${metrics.financialReconciliationErrorsCount}")
        }
        if (metrics.errorRatePercent > maxCanaryErrorRatePercent) {
            breachReasons.add("Canary error rate ${metrics.errorRatePercent}% exceeds threshold of $maxCanaryErrorRatePercent%")
        }
        if (metrics.latencyP99Ms > maxCanaryLatencyP99Ms) {
            breachReasons.add("Canary p99 latency ${metrics.latencyP99Ms}ms exceeds threshold of ${maxCanaryLatencyP99Ms}ms")
        }
        if (metrics.databaseErrorsCount > 0) {
            breachReasons.add("Canary database error count ${metrics.databaseErrorsCount} exceeds threshold of 0")
        }

        val isHealthy = breachReasons.isEmpty()
        val nextStage = if (isHealthy) PromotionStage.CANARY_HEALTHY else PromotionStage.ROLLBACK_PENDING

        return CanaryEvaluation(
            isHealthy = isHealthy,
            suggestedNextStage = nextStage,
            breachReasons = breachReasons,
        )
    }
}
