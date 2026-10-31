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
class OneLinkIbftAdapter(
    private val httpClient: ProviderHttpClient = ProviderHttpClient(),
) : PaymentProviderPort {
    override val providerId: String = "ONELINK_IBFT"
    override val isProductionReady: Boolean = false

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
        if (command.amountMinorUnits <= 0L) {
            return ProviderOutcome.declined(
                operationId = command.operationId,
                code = "INVALID_AMOUNT",
                reason = "Payout amount must be a positive integer minor amount",
            )
        }

        val body = ProviderWireSupport.encode(
            mapOf(
                "clientId" to credentials.clientId,
                "amountMinorUnits" to command.amountMinorUnits,
                "currency" to command.currency,
                "reference" to command.operationId.toString(),
                "destinationAccount" to command.destinationAccount,
                "destinationTitle" to command.destinationTitle,
                "destinationBankCode" to command.destinationBankCode,
                "idempotencyKey" to command.idempotencyKey,
                "correlationId" to command.correlationId,
            )
        )
        return try {
            val response = httpClient.execute(
                config = config,
                method = "POST",
                path = "/ibft/v1/transfers",
                headers = mapOf(
                    "Authorization" to "Bearer ${credentials.apiKey ?: credentials.clientId}",
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
            val reference = ProviderWireSupport.firstText(parsed, "transferId", "reference", "providerReference", "transactionId", "id")
            if (reference == null) {
                return ProviderWireSupport.malformed(command.operationId)
            }
            ProviderOutcome.accepted(
                operationId = command.operationId,
                providerReference = reference,
                code = "TRANSFER_PENDING",
                evidence = mapOf(
                    "provider" to providerId,
                    "amountMinorUnits" to command.amountMinorUnits.toString(),
                    "currency" to command.currency,
                    "status" to "PENDING",
                )
            )
        } catch (_: InterruptedException) {
            Thread.currentThread().interrupt()
            ProviderWireSupport.ambiguous(command.operationId, "TRANSPORT_INTERRUPTED", "Provider call was interrupted before a definitive response")
        } catch (_: Exception) {
            ProviderWireSupport.ambiguous(command.operationId, "TRANSPORT_UNKNOWN", "Provider call ended without a definitive response")
        }
    }

    override fun queryStatus(
        query: ProviderStatusQuery,
        config: ProviderConfiguration,
        credentials: ProviderCredentials?,
    ): ProviderOutcome {
        if (credentials == null || credentials.clientId.isNullOrBlank()) {
            return ProviderOutcome.unavailable(query.operationId, "1LINK IBFT credentials not configured", "CREDENTIALS_UNAVAILABLE")
        }
        val reference = query.providerReference
            ?: return ProviderOutcome.unavailable(query.operationId, "Provider reference is required for authenticated inquiry", "REFERENCE_UNAVAILABLE")
        return try {
            val response = httpClient.execute(
                config = config,
                method = "GET",
                path = "/ibft/v1/transfers/$reference",
                headers = mapOf(
                    "Authorization" to "Bearer ${credentials.apiKey ?: credentials.clientId}",
                    "X-Request-ID" to query.idempotencyKey,
                ),
            )
            if (response.statusCode !in 200..299) {
                return ProviderWireSupport.httpFailure(query.operationId, response.statusCode)
            }
            val parsed = ProviderWireSupport.parse(response.body) ?: return ProviderWireSupport.malformed(query.operationId)
            val returnedReference = ProviderWireSupport.firstText(parsed, "transferId", "reference", "providerReference", "transactionId", "id")
                ?: return ProviderWireSupport.malformed(query.operationId)
            if (returnedReference != reference) {
                return ProviderOutcome.declined(query.operationId, "REFERENCE_MISMATCH", "Authenticated inquiry returned a different provider reference")
            }
            val amount = ProviderWireSupport.firstLong(parsed, "amountMinorUnits", "amount")
            val currency = ProviderWireSupport.firstText(parsed, "currency")
            val status = ProviderWireSupport.status(parsed, "status", "eventType")
            when (status) {
                "PAID", "SUCCESS", "SUCCEEDED", "SETTLED", "COMPLETED" -> {
                    if (amount == null || currency == null ||
                        amount != query.expectedAmountMinorUnits ||
                        !currency.equals(query.expectedCurrency, ignoreCase = true)
                    ) {
                        return ProviderOutcome.declined(query.operationId, "INQUIRY_MISMATCH", "Authenticated inquiry amount or currency does not match the operation")
                    }
                    ProviderOutcome.verifiedSettlement(
                        operationId = query.operationId,
                        providerReference = returnedReference,
                        amountMinorUnits = amount,
                        currency = currency,
                        evidence = mapOf(
                            "provider" to providerId,
                            "status" to status,
                            "amountMinorUnits" to amount.toString(),
                            "currency" to currency,
                        ),
                    )
                }
                "FAILED", "DECLINED", "REJECTED", "CANCELLED" -> ProviderOutcome.failed(
                    operationId = query.operationId,
                    code = status,
                    reason = "Provider inquiry reported a definitive failure",
                )
                else -> ProviderOutcome.pending(
                    operationId = query.operationId,
                    providerReference = returnedReference,
                    code = status ?: "PENDING",
                    reason = "Provider inquiry is not yet terminal",
                )
            }
        } catch (_: InterruptedException) {
            Thread.currentThread().interrupt()
            ProviderWireSupport.ambiguous(query.operationId, "INQUIRY_INTERRUPTED", "Provider inquiry was interrupted")
        } catch (_: Exception) {
            ProviderWireSupport.ambiguous(query.operationId, "INQUIRY_UNKNOWN", "Provider inquiry did not return a definitive result")
        }
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
