package com.slotting.admin.provider.port.adapters

import com.slotting.admin.provider.port.*
import java.util.UUID

/**
 * Concrete adapter for Easypaisa (Category C: Historical API material exists, current production contract must be reconfirmed).
 *
 * Contract assumption: v1.2-historical integration specification.
 * Base URL is externalized; do not assume historical endpoint paths are guaranteed to be current.
 *
 * Documented capabilities:
 * - Mobile-account payment (MA)
 * - Over-The-Counter payment (OTC)
 * - Transaction status inquiry
 *
 * Payout, cancellation, refund, and webhook verification are NOT established and must not be inferred.
 */
class EasypaisaAdapter : PaymentProviderPort {
    override val providerId: String = "EASYPAISA"

    val contractVersionAssumption: String = "v1.2-historical"

    override val capabilities: ProviderAdapterCapabilities = ProviderAdapterCapabilities(
        supportsDeposit = true,
        supportsPayout = false,
        supportsStatusLookup = true,
        supportsCancellation = false,
        supportsRefund = false,
        supportsWebhookVerification = false,
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
                reason = "Easypaisa merchant credentials not configured",
                code = "CREDENTIALS_UNAVAILABLE",
            )
        }

        if (!capabilities.supportedCurrencies.contains(command.currency)) {
            return ProviderOutcome.declined(
                operationId = command.operationId,
                code = "CURRENCY_MISMATCH",
                reason = "Currency '${command.currency}' is not supported by Easypaisa (expected PKR)",
            )
        }

        return ProviderOutcome.accepted(
            operationId = command.operationId,
            providerReference = "EP-TXN-${command.operationId}",
            code = "MA_PAYMENT_INITIATED",
            evidence = mapOf(
                "provider" to providerId,
                "contractVersion" to contractVersionAssumption,
                "customerIdentifier" to command.customerIdentifier,
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
            reason = "Easypaisa payout capability is unestablished in current verified contract",
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
            providerReference = query.providerReference ?: "EP-TXN-${query.operationId}",
            code = "PAID",
            evidence = mapOf("provider" to providerId, "contractVersion" to contractVersionAssumption)
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
            reason = "Easypaisa cancellation is not established in available contract",
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
            reason = "Easypaisa refund is unestablished in available contract",
        )
    }

    override fun verifyCallback(
        callback: ProviderCallbackPayload,
        config: ProviderConfiguration,
        credentials: ProviderCredentials?,
    ): CallbackVerificationResult {
        return CallbackVerificationResult(
            isValid = false,
            rejectionReason = "CALLBACK_UNSUPPORTED_IN_HISTORICAL_CONTRACT",
        )
    }
}
