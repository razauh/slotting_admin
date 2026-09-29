package com.slotting.admin.provider

import java.time.Clock

data class MethodAvailabilityEvaluation(
    val code: MethodAvailabilityCode,
    val isSelectable: Boolean,
    val reason: String? = null,
) {
    companion object {
        val AVAILABLE = MethodAvailabilityEvaluation(MethodAvailabilityCode.AVAILABLE, isSelectable = true)
        fun unavailable(code: MethodAvailabilityCode, reason: String? = null) =
            MethodAvailabilityEvaluation(code, isSelectable = false, reason = reason)
    }
}

class PaymentMethodAvailabilityEvaluator(
    private val paymentMethodStore: PaymentMethodStore,
    private val providerStatusResolver: ProviderStatusResolver = DefaultProviderStatusResolver(),
    private val restrictionPolicy: PaymentMethodRestrictionPolicy = AllowAllRestrictionPolicy(),
    private val clock: Clock = Clock.systemUTC(),
) {

    fun evaluate(
        tenantId: String,
        subjectId: String,
        method: PaymentMethodConfig,
        transactionType: TransactionType,
        currency: String? = null,
        amountMinorUnits: Long? = null,
    ): MethodAvailabilityEvaluation {
        // 1. Method lifecycle status
        if (method.status == PaymentMethodStatus.INACTIVE) {
            return MethodAvailabilityEvaluation.unavailable(
                MethodAvailabilityCode.INACTIVE,
                "Payment method is currently inactive"
            )
        }
        if (method.status == PaymentMethodStatus.MAINTENANCE) {
            return MethodAvailabilityEvaluation.unavailable(
                MethodAvailabilityCode.MAINTENANCE,
                method.maintenanceReason ?: "Payment method is undergoing scheduled maintenance"
            )
        }

        // 2. Transaction capability
        when (transactionType) {
            TransactionType.DEPOSIT -> {
                if (!method.allowsDeposit) {
                    return MethodAvailabilityEvaluation.unavailable(
                        MethodAvailabilityCode.CAPABILITY_DISABLED,
                        "Deposits are not supported for this payment method"
                    )
                }
            }
            TransactionType.WITHDRAWAL -> {
                if (!method.allowsWithdrawal) {
                    return MethodAvailabilityEvaluation.unavailable(
                        MethodAvailabilityCode.CAPABILITY_DISABLED,
                        "Withdrawals are not supported for this payment method"
                    )
                }
            }
        }

        // 3. Provider outage / circuit breaker status
        if (!providerStatusResolver.isProviderAvailable(tenantId, method.providerId)) {
            return MethodAvailabilityEvaluation.unavailable(
                MethodAvailabilityCode.PROVIDER_OUTAGE,
                "Payment provider is temporarily unavailable"
            )
        }

        // 4. Currency support
        if (currency != null && !method.supportedCurrencies.contains(currency)) {
            return MethodAvailabilityEvaluation.unavailable(
                MethodAvailabilityCode.UNSUPPORTED_CURRENCY,
                "Currency '$currency' is not supported by this payment method"
            )
        }

        // 5. Account / player restriction policy hook
        val restriction = restrictionPolicy.evaluateRestriction(tenantId, subjectId, transactionType, method)
        if (!restriction.isAllowed) {
            return MethodAvailabilityEvaluation.unavailable(
                MethodAvailabilityCode.RESTRICTED_ACCOUNT,
                restriction.message ?: "Account restriction prevents using this payment method"
            )
        }

        // 6. Amount bounds
        if (amountMinorUnits != null) {
            val (minAmount, maxAmount) = when (transactionType) {
                TransactionType.DEPOSIT -> method.minDepositMinorUnits to method.maxDepositMinorUnits
                TransactionType.WITHDRAWAL -> method.minWithdrawalMinorUnits to method.maxWithdrawalMinorUnits
            }
            if (amountMinorUnits < minAmount) {
                return MethodAvailabilityEvaluation.unavailable(
                    MethodAvailabilityCode.AMOUNT_BELOW_MINIMUM,
                    "Amount is below minimum limit ($minAmount minor units)"
                )
            }
            if (amountMinorUnits > maxAmount) {
                return MethodAvailabilityEvaluation.unavailable(
                    MethodAvailabilityCode.AMOUNT_ABOVE_MAXIMUM,
                    "Amount exceeds maximum limit ($maxAmount minor units)"
                )
            }
        }

        return MethodAvailabilityEvaluation.AVAILABLE
    }

    /**
     * Authoritatively revalidates that the method is selectable, active, matches expected version,
     * and meets all constraints at the exact moment of transaction initiation (TC-013 / TC-014).
     * Throws PaymentMethodUnavailableException if invalid or unavailable.
     */
    fun requireAvailable(
        tenantId: String,
        subjectId: String,
        methodId: String,
        expectedVersion: Long,
        transactionType: TransactionType,
        currency: String,
        amountMinorUnits: Long,
    ): PaymentMethodConfig {
        val method = paymentMethodStore.findMethod(tenantId, methodId)
            ?: throw PaymentMethodUnavailableException(
                code = MethodAvailabilityCode.INACTIVE,
                methodId = methodId,
                serverVersion = null,
                message = "Payment method '$methodId' does not exist"
            )

        val evaluation = evaluate(
            tenantId = tenantId,
            subjectId = subjectId,
            method = method,
            transactionType = transactionType,
            currency = currency,
            amountMinorUnits = amountMinorUnits,
        )

        if (!evaluation.isSelectable) {
            throw PaymentMethodUnavailableException(
                code = evaluation.code,
                methodId = methodId,
                serverVersion = method.serverVersion,
                message = evaluation.reason ?: "Payment method '$methodId' is unavailable (${evaluation.code})"
            )
        }

        if (method.serverVersion != expectedVersion) {
            throw PaymentMethodUnavailableException(
                code = MethodAvailabilityCode.INACTIVE,
                methodId = methodId,
                serverVersion = method.serverVersion,
                message = "Payment method '$methodId' configuration version changed (client=$expectedVersion, server=${method.serverVersion})"
            )
        }

        return method
    }
}
