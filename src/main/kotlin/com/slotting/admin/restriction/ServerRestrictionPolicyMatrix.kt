package com.slotting.admin.restriction

/**
 * TC-026 Authoritative Restriction Source × Operation Policy Matrix.
 * Encodes the approved deterministic baseline rules:
 * - Dual-axis decision: AccessDecision (DENY > STEP_UP > ALLOW) & FinancialDisposition
 * - Scope checking: ProviderScoped restrictions apply ONLY when provider matches
 * - Contextual conditions: isRemediationFlow, isSensitiveDataExport, isDedicatedLegalAccessPath, unwageredBalanceOnly, pendingOperationType
 */
object ServerRestrictionPolicyMatrix {

    fun evaluateSingle(
        restriction: ServerRestrictionRecord,
        context: OperationEvaluationContext
    ): Pair<AccessDecision, FinancialDisposition> {
        // First check scope applicability:
        when (val scope = restriction.scope) {
            is RestrictionScope.WholeAccount -> Unit // Applies to entire account
            is RestrictionScope.ProviderScoped -> {
                // If operation does not involve this provider, it is NOT restricted by this provider-scoped rule
                val matchesProvider = context.providerId != null && context.providerId.equals(scope.providerId, ignoreCase = true)
                if (!matchesProvider) {
                    return AccessDecision.ALLOW to FinancialDisposition.COMPLETE
                }
            }
            is RestrictionScope.SurfaceScoped -> Unit
        }

        return when (restriction.source) {
            RestrictionSource.ADMINISTRATIVE_BAN -> evaluateAdministrativeBan(context)
            RestrictionSource.FRAUD_SECURITY -> evaluateFraudSecurity(context)
            RestrictionSource.RESPONSIBLE_GAMING -> evaluateResponsibleGaming(context)
            RestrictionSource.KYC_AML -> evaluateKycAml(context)
            RestrictionSource.PROVIDER_RESTRICTION -> evaluateProviderRestriction(restriction, context)
            RestrictionSource.ACCOUNT_CLOSURE -> evaluateAccountClosure(context)
        }
    }

    private fun evaluateAdministrativeBan(ctx: OperationEvaluationContext): Pair<AccessDecision, FinancialDisposition> =
        when (ctx.operation) {
            ServerOperation.AUTHENTICATION_OR_SESSION_CONTINUATION -> AccessDecision.DENY to FinancialDisposition.NONE
            ServerOperation.NEW_GAME_SESSION -> AccessDecision.DENY to FinancialDisposition.NONE
            ServerOperation.WAGER -> AccessDecision.DENY to FinancialDisposition.NONE
            ServerOperation.DEPOSIT -> AccessDecision.DENY to FinancialDisposition.NONE
            ServerOperation.WITHDRAWAL -> AccessDecision.DENY to FinancialDisposition.HOLD
            ServerOperation.SUPPORT_ACCESS -> AccessDecision.ALLOW to FinancialDisposition.NONE
            ServerOperation.KYC_COMPLIANCE_SUBMISSION -> AccessDecision.ALLOW to FinancialDisposition.NONE
            ServerOperation.ACCOUNT_DATA_ACCESS -> {
                if (ctx.isDedicatedLegalAccessPath) AccessDecision.ALLOW to FinancialDisposition.NONE
                else AccessDecision.DENY to FinancialDisposition.NONE
            }
            ServerOperation.PENDING_FINANCIAL_OPERATIONS -> AccessDecision.DENY to FinancialDisposition.HOLD
        }

    private fun evaluateFraudSecurity(ctx: OperationEvaluationContext): Pair<AccessDecision, FinancialDisposition> =
        when (ctx.operation) {
            ServerOperation.AUTHENTICATION_OR_SESSION_CONTINUATION -> {
                if (ctx.isRemediationFlow) AccessDecision.STEP_UP to FinancialDisposition.NONE
                else AccessDecision.DENY to FinancialDisposition.NONE
            }
            ServerOperation.NEW_GAME_SESSION -> AccessDecision.DENY to FinancialDisposition.NONE
            ServerOperation.WAGER -> AccessDecision.DENY to FinancialDisposition.NONE
            ServerOperation.DEPOSIT -> AccessDecision.DENY to FinancialDisposition.NONE
            ServerOperation.WITHDRAWAL -> AccessDecision.DENY to FinancialDisposition.HOLD
            ServerOperation.SUPPORT_ACCESS -> AccessDecision.ALLOW to FinancialDisposition.NONE
            ServerOperation.KYC_COMPLIANCE_SUBMISSION -> AccessDecision.ALLOW to FinancialDisposition.NONE
            ServerOperation.ACCOUNT_DATA_ACCESS -> {
                if (ctx.isSensitiveDataExport) AccessDecision.STEP_UP to FinancialDisposition.NONE
                else AccessDecision.ALLOW to FinancialDisposition.NONE
            }
            ServerOperation.PENDING_FINANCIAL_OPERATIONS -> AccessDecision.DENY to FinancialDisposition.HOLD
        }

    private fun evaluateResponsibleGaming(ctx: OperationEvaluationContext): Pair<AccessDecision, FinancialDisposition> =
        when (ctx.operation) {
            ServerOperation.AUTHENTICATION_OR_SESSION_CONTINUATION -> AccessDecision.ALLOW to FinancialDisposition.NONE
            ServerOperation.NEW_GAME_SESSION -> AccessDecision.DENY to FinancialDisposition.NONE
            ServerOperation.WAGER -> AccessDecision.DENY to FinancialDisposition.NONE
            ServerOperation.DEPOSIT -> AccessDecision.DENY to FinancialDisposition.NONE
            ServerOperation.WITHDRAWAL -> {
                // RG permits withdrawal of unwagered funds / balance return without new wagering
                AccessDecision.ALLOW to FinancialDisposition.PAYOUT
            }
            ServerOperation.SUPPORT_ACCESS -> AccessDecision.ALLOW to FinancialDisposition.NONE
            ServerOperation.KYC_COMPLIANCE_SUBMISSION -> AccessDecision.ALLOW to FinancialDisposition.NONE
            ServerOperation.ACCOUNT_DATA_ACCESS -> AccessDecision.ALLOW to FinancialDisposition.NONE
            ServerOperation.PENDING_FINANCIAL_OPERATIONS -> {
                when (ctx.pendingOperationType) {
                    PendingOperationType.PAYOUT -> AccessDecision.ALLOW to FinancialDisposition.PAYOUT
                    PendingOperationType.ACTIVE_BET -> AccessDecision.DENY to FinancialDisposition.CANCEL
                    PendingOperationType.DEPOSIT_CONFIRMATION, PendingOperationType.GENERAL_FINANCIAL, null ->
                        AccessDecision.DENY to FinancialDisposition.HOLD
                }
            }
        }

    private fun evaluateKycAml(ctx: OperationEvaluationContext): Pair<AccessDecision, FinancialDisposition> =
        when (ctx.operation) {
            ServerOperation.AUTHENTICATION_OR_SESSION_CONTINUATION -> AccessDecision.ALLOW to FinancialDisposition.NONE
            ServerOperation.NEW_GAME_SESSION -> AccessDecision.DENY to FinancialDisposition.NONE
            ServerOperation.WAGER -> AccessDecision.DENY to FinancialDisposition.NONE
            ServerOperation.DEPOSIT -> AccessDecision.DENY to FinancialDisposition.NONE
            ServerOperation.WITHDRAWAL -> AccessDecision.DENY to FinancialDisposition.HOLD
            ServerOperation.SUPPORT_ACCESS -> AccessDecision.ALLOW to FinancialDisposition.NONE
            ServerOperation.KYC_COMPLIANCE_SUBMISSION -> AccessDecision.ALLOW to FinancialDisposition.NONE
            ServerOperation.ACCOUNT_DATA_ACCESS -> AccessDecision.ALLOW to FinancialDisposition.NONE
            ServerOperation.PENDING_FINANCIAL_OPERATIONS -> AccessDecision.DENY to FinancialDisposition.HOLD
        }

    private fun evaluateProviderRestriction(
        restriction: ServerRestrictionRecord,
        ctx: OperationEvaluationContext
    ): Pair<AccessDecision, FinancialDisposition> {
        val scope = restriction.scope as? RestrictionScope.ProviderScoped
        val providerMatches = scope != null && ctx.providerId != null && ctx.providerId.equals(scope.providerId, ignoreCase = true)

        if (!providerMatches) {
            return AccessDecision.ALLOW to FinancialDisposition.COMPLETE
        }

        return when (ctx.operation) {
            ServerOperation.AUTHENTICATION_OR_SESSION_CONTINUATION -> AccessDecision.ALLOW to FinancialDisposition.NONE
            ServerOperation.NEW_GAME_SESSION -> AccessDecision.DENY to FinancialDisposition.NONE
            ServerOperation.WAGER -> AccessDecision.DENY to FinancialDisposition.NONE
            ServerOperation.DEPOSIT -> {
                // Deny only if affected provider is the deposit/payment provider
                if (scope.category == ProviderCategory.PAYMENT || scope.category == ProviderCategory.ALL) {
                    AccessDecision.DENY to FinancialDisposition.NONE
                } else {
                    AccessDecision.ALLOW to FinancialDisposition.NONE
                }
            }
            ServerOperation.WITHDRAWAL -> {
                // Deny/hold only if affected provider is required for that withdrawal route
                if (scope.category == ProviderCategory.PAYMENT || scope.category == ProviderCategory.ALL) {
                    AccessDecision.DENY to FinancialDisposition.HOLD
                } else {
                    AccessDecision.ALLOW to FinancialDisposition.NONE
                }
            }
            ServerOperation.SUPPORT_ACCESS -> AccessDecision.ALLOW to FinancialDisposition.NONE
            ServerOperation.KYC_COMPLIANCE_SUBMISSION -> AccessDecision.ALLOW to FinancialDisposition.NONE
            ServerOperation.ACCOUNT_DATA_ACCESS -> AccessDecision.ALLOW to FinancialDisposition.NONE
            ServerOperation.PENDING_FINANCIAL_OPERATIONS -> {
                AccessDecision.DENY to FinancialDisposition.HOLD
            }
        }
    }

    private fun evaluateAccountClosure(ctx: OperationEvaluationContext): Pair<AccessDecision, FinancialDisposition> =
        when (ctx.operation) {
            ServerOperation.AUTHENTICATION_OR_SESSION_CONTINUATION -> {
                if (ctx.isDedicatedLegalAccessPath) AccessDecision.ALLOW to FinancialDisposition.NONE
                else AccessDecision.DENY to FinancialDisposition.NONE
            }
            ServerOperation.NEW_GAME_SESSION -> AccessDecision.DENY to FinancialDisposition.NONE
            ServerOperation.WAGER -> AccessDecision.DENY to FinancialDisposition.NONE
            ServerOperation.DEPOSIT -> AccessDecision.DENY to FinancialDisposition.NONE
            ServerOperation.WITHDRAWAL -> AccessDecision.DENY to FinancialDisposition.HOLD
            ServerOperation.SUPPORT_ACCESS -> AccessDecision.ALLOW to FinancialDisposition.NONE
            ServerOperation.KYC_COMPLIANCE_SUBMISSION -> {
                if (ctx.isRemediationFlow || ctx.isDedicatedLegalAccessPath) AccessDecision.ALLOW to FinancialDisposition.NONE
                else AccessDecision.DENY to FinancialDisposition.NONE
            }
            ServerOperation.ACCOUNT_DATA_ACCESS -> {
                if (ctx.isDedicatedLegalAccessPath) AccessDecision.ALLOW to FinancialDisposition.NONE
                else AccessDecision.DENY to FinancialDisposition.NONE
            }
            ServerOperation.PENDING_FINANCIAL_OPERATIONS -> AccessDecision.DENY to FinancialDisposition.HOLD
        }
}
