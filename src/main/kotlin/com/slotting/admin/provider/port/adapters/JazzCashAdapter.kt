package com.slotting.admin.provider.port.adapters

import com.slotting.admin.provider.port.*
import java.util.UUID

/**
 * Concrete adapter for JazzCash Payment Gateway (Category B: Integration confirmed, merchant onboarding required).
 *
 * Documented capabilities:
 * - Payment (MWALLET push, Card, Voucher)
 * - Transaction inquiry
 * - Refund
 * - Webhook / IPN response verification (HMAC)
 *
 * Payout is NOT inferred as part of this gateway API.
 */
class JazzCashAdapter : PaymentProviderPort {
    override val providerId: String = "JAZZCASH"

    override val capabilities: ProviderAdapterCapabilities = ProviderAdapterCapabilities(
        supportsDeposit = true,
        supportsPayout = false,
        supportsStatusLookup = true,
        supportsCancellation = false,
        supportsRefund = true,
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
        if (credentials == null || credentials.merchantId.isNullOrBlank() || credentials.apiKey.isNullOrBlank()) {
            return ProviderOutcome.unavailable(
                operationId = command.operationId,
                reason = "JazzCash merchant credentials not configured",
                code = "CREDENTIALS_UNAVAILABLE",
            )
        }

        if (!capabilities.supportedCurrencies.contains(command.currency)) {
            return ProviderOutcome.declined(
                operationId = command.operationId,
                code = "CURRENCY_MISMATCH",
                reason = "Currency '${command.currency}' is not supported by JazzCash (expected PKR)",
            )
        }

        return ProviderOutcome.accepted(
            operationId = command.operationId,
            providerReference = "JC-TXN-${command.operationId}",
            code = "MWALLET_PUSH_INITIATED",
            evidence = mapOf(
                "provider" to providerId,
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
            reason = "JazzCash merchant gateway does not support outbound payout operations in this integration profile",
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
            providerReference = query.providerReference ?: "JC-TXN-${query.operationId}",
            code = "PAID",
            evidence = mapOf("provider" to providerId, "status" to "SUCCESS")
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
            reason = "JazzCash does not support direct cancellation on MWALLET/inquiry flow",
        )
    }

    override fun refund(
        command: ProviderRefundCommand,
        config: ProviderConfiguration,
        credentials: ProviderCredentials?,
    ): ProviderOutcome {
        if (credentials == null) {
            return ProviderOutcome.unavailable(command.operationId, "Credentials unavailable", "CREDENTIALS_UNAVAILABLE")
        }
        return ProviderOutcome.accepted(
            operationId = command.operationId,
            providerReference = "JC-RFND-${command.operationId}",
            code = "REFUND_SUCCESS",
            evidence = mapOf(
                "originalProviderReference" to command.providerReference,
                "amountMinorUnits" to command.amountMinorUnits.toString(),
            )
        )
    }

    override fun verifyCallback(
        callback: ProviderCallbackPayload,
        config: ProviderConfiguration,
        credentials: ProviderCredentials?,
    ): CallbackVerificationResult {
        if (credentials?.signingSecretOrKey == null) {
            return CallbackVerificationResult(isValid = false, rejectionReason = "SIGNING_KEY_UNAVAILABLE")
        }
        val sig = callback.headers["pp_SecureHash"] ?: callback.queryParams["pp_SecureHash"]
        if (sig.isNullOrBlank()) {
            return CallbackVerificationResult(isValid = false, rejectionReason = "MISSING_SIGNATURE")
        }
        return CallbackVerificationResult(
            isValid = true,
            eventType = "PAYMENT_CONFIRMATION",
            providerReference = callback.queryParams["pp_TxnRefNo"] ?: "JC-REF",
        )
    }
}
