package com.slotting.admin.provider.port.adapters

import com.slotting.admin.provider.port.*
import java.nio.charset.StandardCharsets
import java.security.MessageDigest
import java.util.UUID
import javax.crypto.Mac
import javax.crypto.spec.SecretKeySpec

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
class JazzCashAdapter(
    private val httpClient: ProviderHttpClient = ProviderHttpClient(),
) : PaymentProviderPort {
    override val providerId: String = "JAZZCASH"
    override val isProductionReady: Boolean = false

    override val capabilities: ProviderAdapterCapabilities = ProviderAdapterCapabilities(
        supportsDeposit = true,
        supportsPayout = false,
        supportsStatusLookup = false,
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
        if (command.amountMinorUnits <= 0L) {
            return ProviderOutcome.declined(
                operationId = command.operationId,
                code = "INVALID_AMOUNT",
                reason = "Deposit amount must be a positive integer minor amount",
            )
        }

        val body = ProviderWireSupport.encode(
            mapOf(
                "pp_MerchantID" to credentials.merchantId,
                "pp_Amount" to command.amountMinorUnits,
                "pp_TxnCurrency" to command.currency,
                "pp_TxnRefNo" to command.operationId.toString(),
                "pp_Customer" to command.customerIdentifier,
                "pp_IdempotencyKey" to command.idempotencyKey,
                "pp_CorrelationId" to command.correlationId,
            )
        )
        return try {
            val response = httpClient.execute(
                config = config,
                method = "POST",
                path = "/payment/v1/initiate",
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
            val reference = ProviderWireSupport.firstText(parsed, "pp_TxnRefNo", "transactionId", "reference", "providerReference", "id")
            if (reference == null) {
                return ProviderWireSupport.malformed(command.operationId)
            }
            ProviderWireSupport.pending(
                operationId = command.operationId,
                providerReference = reference,
                code = "MWALLET_PUSH_PENDING",
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
        return ProviderOutcome.unavailable(query.operationId, "JazzCash status inquiry is not implemented", "STATUS_INQUIRY_UNIMPLEMENTED")
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
        return ProviderOutcome.declined(
            operationId = command.operationId,
            code = "UNSUPPORTED_OPERATION",
            reason = "JazzCash refund execution is not implemented or approved; no settlement is produced",
        )
    }

    override fun verifyCallback(
        callback: ProviderCallbackPayload,
        config: ProviderConfiguration,
        credentials: ProviderCredentials?,
    ): CallbackVerificationResult {
        val secret = credentials?.signingSecretOrKey?.takeIf(String::isNotBlank)
        if (secret == null) {
            return CallbackVerificationResult(isValid = false, rejectionReason = "SIGNING_KEY_UNAVAILABLE")
        }
        val presented = callback.headers.entries.firstOrNull { it.key.equals("pp_SecureHash", true) }?.value
            ?: callback.queryParams["pp_SecureHash"]
        if (presented.isNullOrBlank()) {
            return CallbackVerificationResult(isValid = false, rejectionReason = "MISSING_SIGNATURE")
        }
        val fields = callback.queryParams.filterKeys { it.startsWith("pp", ignoreCase = true) }
        if (!presented.matches(Regex("[0-9a-fA-F]{64}")) ||
            !MessageDigest.isEqual(
                calculateSecureHash(fields, secret).lowercase().toByteArray(StandardCharsets.US_ASCII),
                presented.lowercase().toByteArray(StandardCharsets.US_ASCII),
            )
        ) {
            return CallbackVerificationResult(isValid = false, rejectionReason = "SIGNATURE_MISMATCH")
        }

        val expectedMerchant = credentials.merchantId?.takeIf(String::isNotBlank)
        if (expectedMerchant != null && fields["pp_MerchantID"] != expectedMerchant) {
            return CallbackVerificationResult(isValid = false, rejectionReason = "MERCHANT_MISMATCH")
        }
        val providerReference = fields["pp_TxnRefNo"]?.takeIf(String::isNotBlank)
            ?: return CallbackVerificationResult(isValid = false, rejectionReason = "MISSING_TRANSACTION_REFERENCE")
        val amountMinorUnits = fields["pp_Amount"]?.toLongOrNull()
        val currency = fields["pp_TxnCurrency"]?.takeIf(String::isNotBlank)
        val responseCode = fields["pp_ResponseCode"]?.takeIf(String::isNotBlank)
        val evidence = buildMap {
            amountMinorUnits?.let { put("amountMinorUnits", it.toString()) }
            currency?.let { put("currency", it) }
            responseCode?.let { put("responseCode", it) }
        }
        val operationId = UUID.nameUUIDFromBytes(providerReference.toByteArray(StandardCharsets.UTF_8))
        val outcome = if (responseCode == "000") {
            ProviderOutcome.accepted(operationId, providerReference, responseCode, evidence)
        } else {
            ProviderOutcome.failed(
                operationId = operationId,
                code = responseCode ?: "MISSING_RESPONSE_CODE",
                reason = "Provider callback does not confirm successful settlement",
                evidence = evidence,
            )
        }
        return CallbackVerificationResult(
            isValid = true,
            eventType = "PAYMENT_CONFIRMATION",
            operationId = operationId,
            providerReference = providerReference,
            outcome = outcome,
        )
    }

    fun calculateSecureHash(fields: Map<String, String>, secret: String): String {
        val canonicalFields = fields.entries
            .filter { (name, _) -> name.startsWith("pp", ignoreCase = true) && !name.equals("pp_SecureHash", true) }
            .sortedBy { it.key }
            .joinToString("&") { it.value }
        val message = "$secret&$canonicalFields"
        val utf8Bytes = message.toByteArray(StandardCharsets.UTF_8)
        val latin1RoundTrip = String(utf8Bytes, StandardCharsets.ISO_8859_1)
            .toByteArray(StandardCharsets.ISO_8859_1)
        val mac = Mac.getInstance("HmacSHA256")
        mac.init(SecretKeySpec(secret.toByteArray(StandardCharsets.UTF_8), "HmacSHA256"))
        return mac.doFinal(latin1RoundTrip).joinToString("") { "%02x".format(it) }
    }
}
