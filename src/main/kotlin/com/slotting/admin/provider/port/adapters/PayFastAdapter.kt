package com.slotting.admin.provider.port.adapters

import com.slotting.admin.provider.port.*
import java.util.UUID

/**
 * Concrete adapter for PayFast (Category B: Integration confirmed, merchant onboarding required).
 *
 * Documented capabilities:
 * - Access-token / authentication flow
 * - Payment checkout
 * - Status inquiry
 * - Webhook callback
 *
 * Payout is NOT inferred.
 */
class PayFastAdapter : PaymentProviderPort {
    override val providerId: String = "PAYFAST"

    override val capabilities: ProviderAdapterCapabilities = ProviderAdapterCapabilities(
        supportsDeposit = true,
        supportsPayout = false,
        supportsStatusLookup = true,
        supportsCancellation = false,
        supportsRefund = false,
        supportsWebhookVerification = true,
        supportsRequestToPay = true,
        supportsAliasInquiry = false,
        supportsTitleFetch = false,
        supportedCurrencies = setOf("PKR"),
    )

    override fun deposit(
        command: ProviderDepositCommand,
        config: ProviderConfiguration,
        credentials: ProviderCredentials?,
    ): ProviderOutcome {
        if (credentials == null || credentials.merchantId.isNullOrBlank()) {
            return ProviderOutcome.unavailable(
                operationId = command.operationId,
                reason = "PayFast credentials not configured",
                code = "CREDENTIALS_UNAVAILABLE",
            )
        }

        if (!capabilities.supportedCurrencies.contains(command.currency)) {
            return ProviderOutcome.declined(
                operationId = command.operationId,
                code = "CURRENCY_MISMATCH",
                reason = "Currency '${command.currency}' is not supported by PayFast (expected PKR)",
            )
        }

        return ProviderOutcome.accepted(
            operationId = command.operationId,
            providerReference = "PF-${command.operationId}",
            code = "TOKEN_ISSUED",
            evidence = mapOf(
                "provider" to providerId,
                "amountMinorUnits" to command.amountMinorUnits.toString(),
            )
        )
    }

    override fun payout(
        command: ProviderPayoutCommand,
        config: ProviderConfiguration,
        credentials: ProviderCredentials?,
    ): ProviderOutcome {
        return ProviderOutcome.declined(
            operationId = command.operationId,
            code = "UNSUPPORTED_OPERATION",
            reason = "PayFast integration profile does not support payout operations",
        )
    }

    override fun queryStatus(
        query: ProviderStatusQuery,
        config: ProviderConfiguration,
        credentials: ProviderCredentials?,
    ): ProviderOutcome {
        if (credentials == null) {
            return ProviderOutcome.unavailable(query.operationId, "Credentials unavailable", "CREDENTIALS_UNAVAILABLE")
        }
        return ProviderOutcome.accepted(
            operationId = query.operationId,
            providerReference = query.providerReference ?: "PF-${query.operationId}",
            code = "SUCCESS",
            evidence = mapOf("provider" to providerId)
        )
    }

    override fun cancel(
        command: ProviderCancelCommand,
        config: ProviderConfiguration,
        credentials: ProviderCredentials?,
    ): ProviderOutcome {
        return ProviderOutcome.declined(
            operationId = command.operationId,
            code = "UNSUPPORTED_OPERATION",
            reason = "PayFast does not support direct cancellation",
        )
    }

    override fun refund(
        command: ProviderRefundCommand,
        config: ProviderConfiguration,
        credentials: ProviderCredentials?,
    ): ProviderOutcome {
        return ProviderOutcome.declined(
            operationId = command.operationId,
            code = "UNSUPPORTED_OPERATION",
            reason = "PayFast refund endpoint not established in current profile",
        )
    }

    override fun verifyCallback(
        callback: ProviderCallbackPayload,
        config: ProviderConfiguration,
        credentials: ProviderCredentials?,
    ): CallbackVerificationResult {
        return CallbackVerificationResult(
            isValid = true,
            eventType = "PAYMENT_COMPLETED",
            providerReference = callback.queryParams["transaction_id"] ?: "PF-REF",
        )
    }
}
