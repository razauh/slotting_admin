package com.slotting.admin.provider

import com.slotting.admin.auth.*
import java.time.Clock
import java.time.Instant

class PaymentMethodQueryService(
    private val paymentMethodStore: PaymentMethodStore,
    private val sessions: AdminSessionDirectory,
    private val providerStatusResolver: ProviderStatusResolver = DefaultProviderStatusResolver(),
    private val restrictionPolicy: PaymentMethodRestrictionPolicy = AllowAllRestrictionPolicy(),
    availabilityEvaluator: PaymentMethodAvailabilityEvaluator? = null,
    private val metrics: PaymentMethodQueryMetrics = NoOpPaymentMethodQueryMetrics(),
    private val clock: Clock = Clock.systemUTC(),
    private val advisoryTtlSeconds: Long = 300L,
) {
    private val evaluator = availabilityEvaluator ?: PaymentMethodAvailabilityEvaluator(
        paymentMethodStore = paymentMethodStore,
        providerStatusResolver = providerStatusResolver,
        restrictionPolicy = restrictionPolicy,
        clock = clock,
    )

    private val currencyRegex = Regex("^[A-Z]{3}$")
    private val maxSafeAmount = 1_000_000_000_000L // 10 billion minor units safety bound

    fun query(query: PaymentMethodQuery): PaymentMethodQueryResponse {
        // 1. Session and Principal Authentication
        val principal = query.principal ?: throw AuthenticationFailure.Rejected(AuthErrorCode.UNAUTHENTICATED)

        if (principal.tenantId != query.tenantId) {
            throw AuthenticationFailure.Rejected(AuthErrorCode.FORBIDDEN)
        }

        val now = Instant.now(clock)
        val session = try {
            sessions.find(query.tenantId, principal.id, query.sessionId)
        } catch (_: Exception) {
            throw AuthenticationFailure.Rejected(AuthErrorCode.DEPENDENCY_UNAVAILABLE)
        }

        if (session == null || !session.active || !session.expiresAt.isAfter(now)) {
            throw AuthenticationFailure.Rejected(AuthErrorCode.FORBIDDEN)
        }

        // 2. Validate Query Parameters
        if (query.amountMinorUnits != null) {
            if (query.amountMinorUnits < 0 || query.amountMinorUnits > maxSafeAmount) {
                throw AuthenticationFailure.Rejected(AuthErrorCode.INVALID)
            }
        }
        if (query.currency != null && !currencyRegex.matches(query.currency)) {
            throw AuthenticationFailure.Rejected(AuthErrorCode.INVALID)
        }

        // 3. Query methods from authoritative store
        val allMethods = paymentMethodStore.listMethods(query.tenantId)
        val configurationVersion = allMethods.maxOfOrNull { it.serverVersion } ?: 0L
        val isStale = query.clientKnownVersion != null && query.clientKnownVersion < configurationVersion

        var eligibleCount = 0
        var filteredCount = 0
        val filteredReasons = mutableMapOf<MethodAvailabilityCode, Int>()
        val options = mutableListOf<PaymentMethodOption>()

        for (method in allMethods) {
            val eval = evaluator.evaluate(
                tenantId = query.tenantId,
                subjectId = principal.id,
                method = method,
                transactionType = query.transactionType,
                currency = query.currency,
                amountMinorUnits = query.amountMinorUnits,
            )

            val estimatedFee = if (query.amountMinorUnits != null) {
                method.feeFlatMinorUnits + (query.amountMinorUnits * method.feePercentageBps / 10000)
            } else null

            val (minUnits, maxUnits) = when (query.transactionType) {
                TransactionType.DEPOSIT -> method.minDepositMinorUnits to method.maxDepositMinorUnits
                TransactionType.WITHDRAWAL -> method.minWithdrawalMinorUnits to method.maxWithdrawalMinorUnits
            }

            val option = PaymentMethodOption(
                methodId = method.methodId,
                methodType = method.methodType,
                displayName = method.displayName,
                instructions = method.instructions,
                safeAccountTitle = method.safeAccountTitle,
                safeAccountNumber = method.safeAccountNumber,
                iconUrl = method.iconUrl,
                supportedCurrencies = method.supportedCurrencies,
                allowsDeposit = method.allowsDeposit,
                allowsWithdrawal = method.allowsWithdrawal,
                minMinorUnits = minUnits,
                maxMinorUnits = maxUnits,
                feeSchedule = PaymentMethodFeeSchedule(
                    flatMinorUnits = method.feeFlatMinorUnits,
                    percentageBps = method.feePercentageBps,
                    estimatedFeeMinorUnits = estimatedFee,
                ),
                displayOrder = method.displayOrder,
                isSelectable = eval.isSelectable,
                availabilityCode = eval.code,
                availabilityReason = eval.reason,
                serverVersion = method.serverVersion,
            )

            if (eval.isSelectable) {
                eligibleCount++
                options.add(option)
            } else {
                filteredCount++
                filteredReasons[eval.code] = (filteredReasons[eval.code] ?: 0) + 1
                if (query.includeUnavailable) {
                    options.add(option)
                }
            }
        }

        metrics.recordQuery(
            tenantId = query.tenantId,
            transactionType = query.transactionType,
            eligibleCount = eligibleCount,
            filteredCount = filteredCount,
            filteredReasons = filteredReasons,
        )

        return PaymentMethodQueryResponse(
            tenantId = query.tenantId,
            transactionType = query.transactionType,
            generatedAt = now,
            expiresAt = now.plusSeconds(advisoryTtlSeconds),
            configurationVersion = configurationVersion,
            isStale = isStale,
            options = options.sortedBy { it.displayOrder },
            filteredCount = filteredCount,
            eligibleCount = eligibleCount,
        )
    }
}
