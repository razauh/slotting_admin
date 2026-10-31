package com.slotting.admin.provider.port.adapters

import com.slotting.admin.provider.port.*
import com.fasterxml.jackson.databind.JsonNode
import com.fasterxml.jackson.databind.ObjectMapper
import java.nio.charset.StandardCharsets
import java.security.MessageDigest
import java.util.UUID
import javax.crypto.Mac
import javax.crypto.spec.SecretKeySpec

/**
 * Concrete adapter for 1LINK Raast P2M Rail (Category A: Documented Public API Contract).
 *
 * Documented capabilities:
 * - RTP now (Request to Pay push)
 * - RTP later
 * - Status inquiry
 * - RTP cancellation
 * - Alias inquiry
 * - Title fetch
 * - OAuth 2.0 / Client-ID based security
 *
 * Payouts and refunds are not part of the Raast P2M contract and must not be inferred.
 */
class OneLinkRaastAdapter : PaymentProviderPort {
    private val objectMapper = ObjectMapper()

    override val providerId: String = "ONELINK_RAAST"
    override val isProductionReady: Boolean = false

    override val capabilities: ProviderAdapterCapabilities = ProviderAdapterCapabilities(
        supportsDeposit = false,
        supportsPayout = false,
        supportsStatusLookup = false,
        supportsCancellation = false,
        supportsRefund = false,
        supportsWebhookVerification = false,
        supportsRequestToPay = false,
        supportsAliasInquiry = false,
        supportsTitleFetch = false,
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
            reason = "The 1LINK Raast pay-in rail is not selected or authorized in this deployment",
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
            reason = "1LINK Raast P2M rail does not execute outbound payouts (use 1LINK IBFT)",
        )
    }

    override fun queryStatus(
        query: ProviderStatusQuery,
        config: ProviderConfiguration,
        credentials: ProviderCredentials?,
    ): ProviderOutcome {
        return ProviderOutcome.unavailable(query.operationId, "OneLink Raast status inquiry is not implemented", "STATUS_INQUIRY_UNIMPLEMENTED")
    }

    override fun cancel(
        command: ProviderCancelCommand,
        config: ProviderConfiguration,
        credentials: ProviderCredentials?,
    ): ProviderOutcome {
        return ProviderOutcome.declined(
            operationId = command.operationId,
            code = "UNSUPPORTED_OPERATION",
            reason = "The 1LINK Raast rail is not selected or authorized in this deployment",
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
            reason = "Refund is not supported directly on 1LINK Raast P2M rail",
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
        val signatures = callback.headers.entries
            .filter { it.key.equals("x-raast-signature", true) || it.key.equals("signature", true) }
            .map { it.value }
        if (signatures.isEmpty() || signatures.any(String::isBlank)) {
            return CallbackVerificationResult(isValid = false, rejectionReason = "MISSING_SIGNATURE")
        }
        if (signatures.distinct().size > 1) {
            return CallbackVerificationResult(isValid = false, rejectionReason = "SIGNATURE_CONFLICT")
        }
        val presented = signatures.first()
        if (!presented.matches(Regex("[0-9a-fA-F]{64}"))) {
            return CallbackVerificationResult(isValid = false, rejectionReason = "SIGNATURE_MISMATCH")
        }
        val expected = calculateHmacSha256(callback.rawBody, secret)
        if (!MessageDigest.isEqual(
                expected.toByteArray(StandardCharsets.US_ASCII),
                presented.lowercase().toByteArray(StandardCharsets.US_ASCII),
            )
        ) {
            return CallbackVerificationResult(isValid = false, rejectionReason = "SIGNATURE_MISMATCH")
        }
        val payload = try {
            objectMapper.readTree(callback.rawBody)
        } catch (_: Exception) {
            return CallbackVerificationResult(isValid = false, rejectionReason = "INVALID_PAYLOAD")
        } ?: return CallbackVerificationResult(isValid = false, rejectionReason = "INVALID_PAYLOAD")
        val data = payload.path("data").takeIf(JsonNode::isObject) ?: payload
        val reference = data.firstNonBlankText("reference", "providerReference", "merchantReference")
            ?: return CallbackVerificationResult(isValid = false, rejectionReason = "MISSING_REFERENCE")
        val amount = data.firstNonBlankText("amountMinorUnits", "amount")?.toLongOrNull()
        val currency = data.firstNonBlankText("currency")
        val status = data.firstNonBlankText("status", "eventType")
        val evidence = buildMap {
            amount?.let { put("amountMinorUnits", it.toString()) }
            currency?.let { put("currency", it) }
            status?.let { put("status", it) }
        }
        val operationId = UUID.nameUUIDFromBytes(reference.toByteArray(StandardCharsets.UTF_8))
        val outcome = if (status == "RTP_SETTLED") {
            ProviderOutcome.accepted(operationId, reference, status, evidence)
        } else {
            ProviderOutcome.failed(
                operationId = operationId,
                code = status ?: "MISSING_STATUS",
                reason = "Provider callback does not confirm successful settlement",
                evidence = evidence,
            )
        }
        return CallbackVerificationResult(
            isValid = true,
            eventType = status,
            operationId = operationId,
            providerReference = reference,
            outcome = outcome,
        )
    }

    fun calculateHmacSha256(data: String, key: String): String {
        val mac = Mac.getInstance("HmacSHA256")
        mac.init(SecretKeySpec(key.toByteArray(StandardCharsets.UTF_8), "HmacSHA256"))
        return mac.doFinal(data.toByteArray(StandardCharsets.UTF_8))
            .joinToString("") { "%02x".format(it) }
    }

    private fun JsonNode.firstNonBlankText(vararg names: String): String? = names
        .asSequence()
        .mapNotNull { name -> get(name)?.takeIf { !it.isNull }?.asText()?.takeIf(String::isNotBlank) }
        .firstOrNull()
}
