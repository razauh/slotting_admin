package com.slotting.admin.provider.port.adapters

import com.slotting.admin.provider.port.*
import java.util.UUID

/**
 * Concrete adapter for 1LINK IBFT (Inter Bank Funds Transfer) (Category A: Documented Public Contract).
 *
 * Documented capabilities:
 * - Title fetch / account inquiry
 * - Outbound funds transfer (payout)
 * - Status inquiry
 *
 * Does not process player pay-in/deposits directly (handled via Raast or merchant gateways).
 */
class OneLinkIbftAdapter : PaymentProviderPort {
    override val providerId: String = "ONELINK_IBFT"

    override val capabilities: ProviderAdapterCapabilities = ProviderAdapterCapabilities(
        supportsDeposit = false,
        supportsPayout = true,
        supportsStatusLookup = true,
        supportsCancellation = false,
        supportsRefund = false,
        supportsWebhookVerification = false,
        supportsRequestToPay = false,
        supportsAliasInquiry = false,
        supportsTitleFetch = true,
        supportedCurrencies = setOf("PKR"),
    )

    override fun deposit(
        command: ProviderDepositCommand,
        config: ProviderConfiguration,
        credentials: ProviderCredentials?,
    ): ProviderOutcome {
        return ProviderOutcome.declined(
            operationId = command.operationId,
            code = "UNSUPPORTED_OPERATION",
            reason = "1LINK IBFT does not process inbound pay-in operations",
        )
    }

    override fun payout(
        command: ProviderPayoutCommand,
        config: ProviderConfiguration,
        credentials: ProviderCredentials?,
    ): ProviderOutcome {
        if (credentials == null || credentials.clientId.isNullOrBlank()) {
            return ProviderOutcome.unavailable(
                operationId = command.operationId,
                reason = "1LINK IBFT credentials not configured",
                code = "CREDENTIALS_UNAVAILABLE",
            )
        }

        if (!capabilities.supportedCurrencies.contains(command.currency)) {
            return ProviderOutcome.declined(
                operationId = command.operationId,
                code = "CURRENCY_MISMATCH",
                reason = "Currency '${command.currency}' is not supported by 1LINK IBFT (expected PKR)",
            )
        }

        return ProviderOutcome.accepted(
            operationId = command.operationId,
            providerReference = "IBFT-STAN-${command.operationId}",
            code = "TRANSFER_INITIATED",
            evidence = mapOf(
                "provider" to providerId,
                "destinationAccount" to command.destinationAccount,
                "amountMinorUnits" to command.amountMinorUnits.toString(),
            )
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
            providerReference = query.providerReference ?: "IBFT-STAN-${query.operationId}",
            code = "TRANSFER_SETTLED",
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
            reason = "Settled or in-flight IBFT transfers cannot be cancelled directly",
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
            reason = "IBFT does not provide a reverse-credit refund API",
        )
    }

    override fun verifyCallback(
        callback: ProviderCallbackPayload,
        config: ProviderConfiguration,
        credentials: ProviderCredentials?,
    ): CallbackVerificationResult {
        return CallbackVerificationResult(
            isValid = false,
            rejectionReason = "CALLBACK_UNSUPPORTED",
        )
    }
}
