package com.slotting.admin.provider.port.adapters

import com.slotting.admin.provider.port.*
import com.fasterxml.jackson.databind.JsonNode
import com.fasterxml.jackson.databind.ObjectMapper
import java.util.UUID
import javax.crypto.Mac
import javax.crypto.spec.SecretKeySpec

/**
 * Concrete adapter for Safepay Raast Integration (Category A: Documented Public API Contract).
 *
 * Documented capabilities:
 * - Pay-in / Checkout token generation
 * - Tracker / Status inquiry
 * - Payout dispatch
 * - Refund
 * - Webhook HMAC-SHA256 signature verification (`x-sfpy-signature`)
 */
class SafepayRaastAdapter(
    private val httpClient: ProviderHttpClient = ProviderHttpClient(),
) : PaymentProviderPort {
    private val objectMapper = ObjectMapper()
    override val providerId: String = "SAFEPAY_RAAST"
    override val isProductionReady: Boolean = false

    override val capabilities: ProviderAdapterCapabilities = ProviderAdapterCapabilities(
        supportsDeposit = true,
        supportsPayout = true,
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
        if (credentials == null || credentials.apiKey.isNullOrBlank()) {
            return ProviderOutcome.unavailable(
                operationId = command.operationId,
                reason = "Safepay credentials not configured",
                code = "CREDENTIALS_UNAVAILABLE",
            )
        }

        if (!capabilities.supportedCurrencies.contains(command.currency)) {
            return ProviderOutcome.declined(
                operationId = command.operationId,
                code = "CURRENCY_MISMATCH",
                reason = "Currency '${command.currency}' is not supported by Safepay (expected PKR)",
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
                "amountMinorUnits" to command.amountMinorUnits,
                "currency" to command.currency,
                "reference" to command.operationId.toString(),
                "idempotencyKey" to command.idempotencyKey,
                "callbackUrl" to command.callbackUrl,
                "customerIdentifier" to command.customerIdentifier,
                "correlationId" to command.correlationId,
            )
        )
        return try {
            val response = httpClient.execute(
                config = config,
                method = "POST",
                path = "/api/v1/checkout/order",
                headers = mapOf(
                    "Authorization" to "Bearer ${credentials.apiKey}",
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
            val reference = ProviderWireSupport.firstText(parsed, "tracker", "reference", "providerReference", "token", "id")
            if (reference == null) {
                return ProviderWireSupport.malformed(command.operationId)
            }
            ProviderWireSupport.pending(
                operationId = command.operationId,
                providerReference = reference,
                code = "CHECKOUT_PENDING",
                evidence = mapOf(
                    "provider" to providerId,
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
        if (credentials == null || credentials.apiKey.isNullOrBlank()) {
            return ProviderOutcome.unavailable(
                operationId = command.operationId,
                reason = "Safepay credentials not configured",
                code = "CREDENTIALS_UNAVAILABLE",
            )
        }

        if (!capabilities.supportedCurrencies.contains(command.currency)) {
            return ProviderOutcome.declined(
                operationId = command.operationId,
                code = "CURRENCY_MISMATCH",
                reason = "Currency '${command.currency}' is not supported by Safepay",
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
                "amountMinorUnits" to command.amountMinorUnits,
                "currency" to command.currency,
                "reference" to command.operationId.toString(),
                "destinationAccount" to command.destinationAccount,
                "destinationTitle" to command.destinationTitle,
                "idempotencyKey" to command.idempotencyKey,
                "correlationId" to command.correlationId,
            )
        )
        return try {
            val response = httpClient.execute(
                config = config,
                method = "POST",
                path = "/api/v1/payouts",
                headers = mapOf(
                    "Authorization" to "Bearer ${credentials.apiKey}",
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
            val reference = ProviderWireSupport.firstText(parsed, "tracker", "reference", "providerReference", "payoutId", "id")
            if (reference == null) {
                return ProviderWireSupport.malformed(command.operationId)
            }
            ProviderOutcome.accepted(
                operationId = command.operationId,
                providerReference = reference,
                code = "PAYOUT_QUEUED",
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
        if (credentials == null || credentials.apiKey.isNullOrBlank()) {
            return ProviderOutcome.unavailable(query.operationId, "Safepay credentials not configured", "CREDENTIALS_UNAVAILABLE")
        }
        val reference = query.providerReference
            ?: return ProviderOutcome.unavailable(query.operationId, "Provider reference is required for authenticated inquiry", "REFERENCE_UNAVAILABLE")
        return try {
            val response = httpClient.execute(
                config = config,
                method = "GET",
                path = "/api/v1/payouts/$reference",
                headers = mapOf(
                    "Authorization" to "Bearer ${credentials.apiKey}",
                    "X-Request-ID" to query.idempotencyKey,
                ),
            )
            if (response.statusCode !in 200..299) {
                return ProviderWireSupport.httpFailure(query.operationId, response.statusCode)
            }
            val parsed = ProviderWireSupport.parse(response.body) ?: return ProviderWireSupport.malformed(query.operationId)
            val returnedReference = ProviderWireSupport.firstText(parsed, "tracker", "reference", "providerReference", "payoutId", "id")
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
            reason = "Safepay does not expose direct cancellation endpoint for pay-in tokens",
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
            reason = "Safepay refund execution is not implemented or approved; no settlement is produced",
        )
    }

    override fun verifyCallback(
        callback: ProviderCallbackPayload,
        config: ProviderConfiguration,
        credentials: ProviderCredentials?,
    ): CallbackVerificationResult {
        val secret = credentials?.signingSecretOrKey
            ?: return CallbackVerificationResult(isValid = false, rejectionReason = "SIGNING_KEY_UNAVAILABLE")

        val incomingSig = callback.headers["x-sfpy-signature"]
            ?: return CallbackVerificationResult(isValid = false, rejectionReason = "MISSING_SIGNATURE")

        val expectedSig = calculateHmacSha256(callback.rawBody, secret)
        if (!incomingSig.equals(expectedSig, ignoreCase = true)) {
            return CallbackVerificationResult(isValid = false, rejectionReason = "INVALID_SIGNATURE")
        }

        val payload = try {
            objectMapper.readTree(callback.rawBody)
        } catch (_: Exception) {
            return CallbackVerificationResult(isValid = false, rejectionReason = "INVALID_PAYLOAD")
        } ?: return CallbackVerificationResult(isValid = false, rejectionReason = "INVALID_PAYLOAD")
        val data = payload.path("data").takeIf(JsonNode::isObject) ?: payload
        val tracker = data.firstNonBlankText("tracker", "reference", "providerReference")
            ?: return CallbackVerificationResult(isValid = false, rejectionReason = "MISSING_REFERENCE")
        val evidence = buildMap {
            data.firstNonBlankText("amountMinorUnits", "amount")?.let { put("amountMinorUnits", it) }
            data.firstNonBlankText("currency")?.let { put("currency", it) }
            data.firstNonBlankText("status", "eventType")?.let { put("status", it) }
        }
        val status = evidence["status"]
        val outcome = if (status?.uppercase()?.let { it in setOf("PAID", "SUCCESS", "SUCCEEDED", "SETTLED") } == true) {
            ProviderOutcome.accepted(
                operationId = UUID.nameUUIDFromBytes(tracker.toByteArray(Charsets.UTF_8)),
                providerReference = tracker,
                code = status,
                evidence = evidence,
            )
        } else {
            ProviderOutcome.failed(
                operationId = UUID.nameUUIDFromBytes(tracker.toByteArray(Charsets.UTF_8)),
                code = status ?: "MISSING_STATUS",
                reason = "Provider callback does not confirm successful settlement",
                evidence = evidence,
            )
        }

        return CallbackVerificationResult(
            isValid = true,
            eventType = status,
            providerReference = tracker,
            outcome = outcome,
        )
    }

    private fun JsonNode.firstNonBlankText(vararg names: String): String? = names
        .asSequence()
        .mapNotNull { name -> get(name)?.takeIf { !it.isNull }?.asText()?.takeIf(String::isNotBlank) }
        .firstOrNull()

    fun calculateHmacSha256(data: String, key: String): String {
        val mac = Mac.getInstance("HmacSHA256")
        mac.init(SecretKeySpec(key.toByteArray(Charsets.UTF_8), "HmacSHA256"))
        val hash = mac.doFinal(data.toByteArray(Charsets.UTF_8))
        return hash.joinToString("") { "%02x".format(it) }
    }
}
