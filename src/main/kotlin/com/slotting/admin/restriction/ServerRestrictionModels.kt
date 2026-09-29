package com.slotting.admin.restriction

import java.time.Instant
import java.util.UUID

/**
 * TC-026: Distinct Server Restriction Sources and Operation Policy Matrix.
 * Authoritative backend restriction models preserving provenance, scopes, and dual-axis decisions.
 */

enum class ServerOperation {
    AUTHENTICATION_OR_SESSION_CONTINUATION,
    NEW_GAME_SESSION,
    WAGER,
    DEPOSIT,
    WITHDRAWAL,
    SUPPORT_ACCESS,
    KYC_COMPLIANCE_SUBMISSION,
    ACCOUNT_DATA_ACCESS,
    PENDING_FINANCIAL_OPERATIONS
}

enum class RestrictionSource {
    ADMINISTRATIVE_BAN,
    FRAUD_SECURITY,
    RESPONSIBLE_GAMING,
    KYC_AML,
    PROVIDER_RESTRICTION,
    ACCOUNT_CLOSURE
}

enum class AccessDecision {
    ALLOW,
    STEP_UP,
    DENY
}

enum class FinancialDisposition {
    NONE,
    HOLD,
    CANCEL,
    REFUND,
    COMPLETE,
    PAYOUT
}

enum class PendingOperationType {
    PAYOUT,
    ACTIVE_BET,
    DEPOSIT_CONFIRMATION,
    GENERAL_FINANCIAL
}

enum class ProviderCategory {
    GAME,
    PAYMENT,
    ALL
}

sealed interface RestrictionScope {
    object WholeAccount : RestrictionScope {
        override fun toString(): String = "WHOLE_ACCOUNT"
    }

    data class ProviderScoped(
        val providerId: String,
        val category: ProviderCategory = ProviderCategory.ALL
    ) : RestrictionScope

    data class SurfaceScoped(
        val surface: String
    ) : RestrictionScope
}

data class ServerRestrictionRecord(
    val restrictionId: UUID = UUID.randomUUID(),
    val tenantId: String,
    val subjectReference: String,
    val source: RestrictionSource,
    val reasonCode: String,
    val safeUserMessage: String,
    val scope: RestrictionScope = RestrictionScope.WholeAccount,
    val effectiveFrom: Instant,
    val expiresAt: Instant? = null,
    val evidenceReference: String,
    val ruleVersion: Long = 1L,
    val issuer: String = "SYSTEM",
    val active: Boolean = true
) {
    init {
        require(tenantId.isNotBlank()) { "tenantId must not be blank" }
        require(subjectReference.isNotBlank()) { "subjectReference must not be blank" }
        require(reasonCode.isNotBlank()) { "reasonCode must not be blank" }
        require(evidenceReference.isNotBlank()) { "evidenceReference must not be blank" }
        require(safeUserMessage.isNotBlank()) { "safeUserMessage must not be blank" }
        if (expiresAt != null) {
            require(expiresAt.isAfter(effectiveFrom)) { "expiresAt must be after effectiveFrom" }
        }
    }

    fun isEffectiveAt(now: Instant): Boolean {
        if (!active) return false
        if (now.isBefore(effectiveFrom)) return false
        if (expiresAt != null && !now.isBefore(expiresAt)) return false
        return true
    }
}

data class OperationEvaluationContext(
    val operation: ServerOperation,
    val tenantId: String,
    val subjectReference: String,
    val providerId: String? = null,
    val gameId: String? = null,
    val paymentRail: String? = null,
    val isSensitiveDataExport: Boolean = false,
    val isRemediationFlow: Boolean = false,
    val isDedicatedLegalAccessPath: Boolean = false,
    val pendingOperationType: PendingOperationType? = null,
    val unwageredBalanceOnly: Boolean = false,
    val now: Instant = Instant.now()
) {
    init {
        require(tenantId.isNotBlank()) { "tenantId must not be blank" }
        require(subjectReference.isNotBlank()) { "subjectReference must not be blank" }
    }
}

data class ContributingRestrictionRecord(
    val restrictionId: UUID,
    val source: RestrictionSource,
    val reasonCode: String,
    val evidenceReference: String,
    val scope: RestrictionScope,
    val individualAccess: AccessDecision,
    val individualDisposition: FinancialDisposition,
    val ruleVersion: Long,
    val expiresAt: Instant?
)

data class ServerRestrictionEvaluationResult(
    val decisionId: UUID = UUID.randomUUID(),
    val tenantId: String,
    val subjectReference: String,
    val operation: ServerOperation,
    val compositeAccess: AccessDecision,
    val financialDisposition: FinancialDisposition,
    val contributingRestrictions: List<ContributingRestrictionRecord>,
    val evaluatedAt: Instant,
    val policyVersion: Long = 1L
) {
    val isAllowed: Boolean get() = compositeAccess == AccessDecision.ALLOW
    val isDenied: Boolean get() = compositeAccess == AccessDecision.DENY
    val isStepUpRequired: Boolean get() = compositeAccess == AccessDecision.STEP_UP
}

class ServerRestrictionDeniedException(
    val result: ServerRestrictionEvaluationResult,
    message: String = "Operation ${result.operation} denied for subject ${result.subjectReference} on tenant ${result.tenantId}"
) : RuntimeException(message)

class ServerRestrictionStepUpRequiredException(
    val result: ServerRestrictionEvaluationResult,
    message: String = "Step-up authentication required for operation ${result.operation} on tenant ${result.tenantId}"
) : RuntimeException(message)
