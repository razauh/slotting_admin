package com.slotting.admin.provider

import com.slotting.admin.auth.AuthenticatedPrincipal
import com.slotting.admin.circuitbreaker.CircuitBreakerState
import com.slotting.admin.circuitbreaker.ProviderCircuitBreakerStore
import java.time.Instant

enum class TransactionType { DEPOSIT, WITHDRAWAL }

enum class MethodAvailabilityCode {
    AVAILABLE,
    INACTIVE,
    MAINTENANCE,
    PROVIDER_OUTAGE,
    UNSUPPORTED_CURRENCY,
    AMOUNT_BELOW_MINIMUM,
    AMOUNT_ABOVE_MAXIMUM,
    RESTRICTED_ACCOUNT,
    CAPABILITY_DISABLED,
}

data class PaymentMethodFeeSchedule(
    val flatMinorUnits: Long,
    val percentageBps: Int,
    val estimatedFeeMinorUnits: Long? = null,
)

data class PaymentMethodOption(
    val methodId: String,
    val methodType: PaymentMethodType,
    val displayName: String,
    val instructions: String?,
    val safeAccountTitle: String?,
    val safeAccountNumber: String?,
    val iconUrl: String?,
    val supportedCurrencies: List<String>,
    val allowsDeposit: Boolean,
    val allowsWithdrawal: Boolean,
    val minMinorUnits: Long,
    val maxMinorUnits: Long,
    val feeSchedule: PaymentMethodFeeSchedule,
    val displayOrder: Int,
    val isSelectable: Boolean,
    val availabilityCode: MethodAvailabilityCode,
    val availabilityReason: String? = null,
    val serverVersion: Long,
)

data class PaymentMethodQuery(
    val principal: AuthenticatedPrincipal?,
    val sessionId: String,
    val tenantId: String,
    val transactionType: TransactionType,
    val currency: String? = null,
    val amountMinorUnits: Long? = null,
    val clientKnownVersion: Long? = null,
    val includeUnavailable: Boolean = false,
)

data class PaymentMethodQueryResponse(
    val tenantId: String,
    val transactionType: TransactionType,
    val generatedAt: Instant,
    val expiresAt: Instant,
    val configurationVersion: Long,
    val isStale: Boolean,
    val options: List<PaymentMethodOption>,
    val filteredCount: Int,
    val eligibleCount: Int,
)

data class RestrictionEvaluation(
    val isAllowed: Boolean,
    val reasonCode: String? = null,
    val message: String? = null,
) {
    companion object {
        val ALLOWED = RestrictionEvaluation(true)
        fun denied(reasonCode: String, message: String) = RestrictionEvaluation(false, reasonCode, message)
    }
}

fun interface PaymentMethodRestrictionPolicy {
    fun evaluateRestriction(
        tenantId: String,
        subjectId: String,
        transactionType: TransactionType,
        method: PaymentMethodConfig,
    ): RestrictionEvaluation
}

class AllowAllRestrictionPolicy : PaymentMethodRestrictionPolicy {
    override fun evaluateRestriction(
        tenantId: String,
        subjectId: String,
        transactionType: TransactionType,
        method: PaymentMethodConfig,
    ): RestrictionEvaluation = RestrictionEvaluation.ALLOWED
}

fun interface ProviderStatusResolver {
    fun isProviderAvailable(tenantId: String, providerId: String): Boolean
}

class CircuitBreakerProviderStatusResolver(
    private val breakerStore: ProviderCircuitBreakerStore
) : ProviderStatusResolver {
    override fun isProviderAvailable(tenantId: String, providerId: String): Boolean {
        val breaker = breakerStore.findBreaker(tenantId, providerId) ?: return true
        return breaker.state != CircuitBreakerState.OPEN
    }
}

class DefaultProviderStatusResolver : ProviderStatusResolver {
    override fun isProviderAvailable(tenantId: String, providerId: String): Boolean = true
}

fun interface PaymentMethodQueryMetrics {
    fun recordQuery(
        tenantId: String,
        transactionType: TransactionType,
        eligibleCount: Int,
        filteredCount: Int,
        filteredReasons: Map<MethodAvailabilityCode, Int>,
    )
}

class NoOpPaymentMethodQueryMetrics : PaymentMethodQueryMetrics {
    override fun recordQuery(
        tenantId: String,
        transactionType: TransactionType,
        eligibleCount: Int,
        filteredCount: Int,
        filteredReasons: Map<MethodAvailabilityCode, Int>,
    ) {}
}

open class PaymentMethodUnavailableException(
    val code: MethodAvailabilityCode,
    val methodId: String,
    val serverVersion: Long?,
    message: String,
) : RuntimeException(message)
