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
class EasypaisaAdapter(
    private val httpClient: ProviderHttpClient = ProviderHttpClient(),
) : PaymentProviderPort {
    override val providerId: String = "EASYPAISA"
    override val isProductionReady: Boolean = false

    val contractVersionAssumption: String = "v1.2-historical"

    override val capabilities: ProviderAdapterCapabilities = ProviderAdapterCapabilities(
        supportsDeposit = true,
        supportsPayout = false,
        supportsStatusLookup = false,
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
        if (command.amountMinorUnits <= 0L) {
            return ProviderOutcome.declined(
                operationId = command.operationId,
                code = "INVALID_AMOUNT",
                reason = "Deposit amount must be a positive integer minor amount",
            )
        }

        val body = ProviderWireSupport.encode(
            mapOf(
                "merchantId" to credentials.merchantId,
                "amountMinorUnits" to command.amountMinorUnits,
                "currency" to command.currency,
                "reference" to command.operationId.toString(),
                "customerIdentifier" to command.customerIdentifier,
                "idempotencyKey" to command.idempotencyKey,
                "correlationId" to command.correlationId,
            )
        )
        return try {
            val response = httpClient.execute(
                config = config,
                method = "POST",
                path = "/easypay/v1/initiate",
                headers = mapOf(
                    "Authorization" to "Bearer ${credentials.apiKey ?: credentials.clientSecret ?: credentials.merchantId}",
                    "Content-Type" to "application/json",
                    "X-Request-ID" to command.correlationId,
                    "Idempotency-Key" to command.idempotencyKey,
                ),
                body = body,
            )
            if (response.statusCode !in 200..299) {
                return ProviderWireSupport.httpFailure(command.operationId, response.statusCode)
            }
            val parsed = ProviderWireSupport.parse(response.body)
            val reference = ProviderWireSupport.firstText(parsed, "transactionId", "reference", "providerReference", "orderId", "id")
            if (reference == null) {
                return ProviderWireSupport.malformed(command.operationId)
            }
            ProviderWireSupport.pending(
                operationId = command.operationId,
                providerReference = reference,
                code = "MA_PAYMENT_PENDING",
                evidence = mapOf(
                    "provider" to providerId,
                    "contractVersion" to contractVersionAssumption,
                    "amountMinorUnits" to command.amountMinorUnits.toString(),
                    "currency" to command.currency,
                    "status" to "PENDING",
                ),
            )
        } catch (_: InterruptedException) {
            Thread.currentThread().interrupt()
            ProviderWireSupport.ambiguous(command.operationId, "TRANSPORT_INTERRUPTED", "Provider call was interrupted before a definitive response")
        } catch (_: Exception) {
            ProviderWireSupport.ambiguous(command.operationId, "TRANSPORT_UNKNOWN", "Provider call ended without a definitive response")
        }
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
        return ProviderOutcome.unavailable(query.operationId, "Easypaisa status inquiry is not implemented", "STATUS_INQUIRY_UNIMPLEMENTED")
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
