package com.slotting.admin.provider.port

import java.net.URI
import java.time.Instant
import java.util.UUID

enum class ProviderOutcomeStatus {
    ACCEPTED,
    PENDING,
    DECLINED,
    FAILED,
    UNKNOWN_AMBIGUOUS,
    UNAVAILABLE,
}

data class ProviderOutcome(
    val status: ProviderOutcomeStatus,
    val operationId: UUID,
    val providerReference: String? = null,
    val rawResponseCode: String? = null,
    val safeReason: String? = null,
    val evidence: Map<String, String> = emptyMap(),
    val isAmbiguous: Boolean = (status == ProviderOutcomeStatus.UNKNOWN_AMBIGUOUS),
    val retryable: Boolean = (status == ProviderOutcomeStatus.UNKNOWN_AMBIGUOUS || status == ProviderOutcomeStatus.UNAVAILABLE),
    val occurredAt: Instant = Instant.now(),
) {
    companion object {
        fun accepted(
            operationId: UUID,
            providerReference: String,
            code: String? = "ACCEPTED",
            evidence: Map<String, String> = emptyMap(),
        ) = ProviderOutcome(
            status = ProviderOutcomeStatus.ACCEPTED,
            operationId = operationId,
            providerReference = providerReference,
            rawResponseCode = code,
            safeReason = "Transaction accepted by provider",
            evidence = evidence,
            isAmbiguous = false,
            retryable = false,
        )

        fun pending(
            operationId: UUID,
            providerReference: String? = null,
            code: String? = "PENDING",
            reason: String? = "Transaction pending confirmation",
            evidence: Map<String, String> = emptyMap(),
        ) = ProviderOutcome(
            status = ProviderOutcomeStatus.PENDING,
            operationId = operationId,
            providerReference = providerReference,
            rawResponseCode = code,
            safeReason = reason,
            evidence = evidence,
            isAmbiguous = false,
            retryable = true,
        )

        fun declined(
            operationId: UUID,
            code: String,
            reason: String,
            evidence: Map<String, String> = emptyMap(),
        ) = ProviderOutcome(
            status = ProviderOutcomeStatus.DECLINED,
            operationId = operationId,
            providerReference = null,
            rawResponseCode = code,
            safeReason = reason,
            evidence = evidence,
            isAmbiguous = false,
            retryable = false,
        )

        fun failed(
            operationId: UUID,
            code: String,
            reason: String,
            evidence: Map<String, String> = emptyMap(),
        ) = ProviderOutcome(
            status = ProviderOutcomeStatus.FAILED,
            operationId = operationId,
            providerReference = null,
            rawResponseCode = code,
            safeReason = reason,
            evidence = evidence,
            isAmbiguous = false,
            retryable = false,
        )

        fun ambiguous(
            operationId: UUID,
            code: String,
            reason: String,
            evidence: Map<String, String> = emptyMap(),
        ) = ProviderOutcome(
            status = ProviderOutcomeStatus.UNKNOWN_AMBIGUOUS,
            operationId = operationId,
            providerReference = null,
            rawResponseCode = code,
            safeReason = reason,
            evidence = evidence,
            isAmbiguous = true,
            retryable = true,
        )

        fun unavailable(
            operationId: UUID,
            reason: String,
            code: String = "PROVIDER_UNAVAILABLE",
        ) = ProviderOutcome(
            status = ProviderOutcomeStatus.UNAVAILABLE,
            operationId = operationId,
            providerReference = null,
            rawResponseCode = code,
            safeReason = reason,
            isAmbiguous = false,
            retryable = true,
        )
    }
}

data class ProviderDepositCommand(
    val tenantId: String,
    val operationId: UUID,
    val idempotencyKey: String,
    val providerId: String,
    val methodId: String,
    val amountMinorUnits: Long,
    val currency: String,
    val customerIdentifier: String,
    val callbackUrl: String? = null,
    val correlationId: String,
    val metadata: Map<String, String> = emptyMap(),
)

data class ProviderPayoutCommand(
    val tenantId: String,
    val operationId: UUID,
    val idempotencyKey: String,
    val providerId: String,
    val methodId: String,
    val amountMinorUnits: Long,
    val currency: String,
    val destinationAccount: String,
    val destinationTitle: String? = null,
    val destinationBankCode: String? = null,
    val correlationId: String,
    val metadata: Map<String, String> = emptyMap(),
)

data class ProviderStatusQuery(
    val tenantId: String,
    val operationId: UUID,
    val providerId: String,
    val providerReference: String? = null,
    val idempotencyKey: String,
)

data class ProviderCancelCommand(
    val tenantId: String,
    val operationId: UUID,
    val providerId: String,
    val providerReference: String? = null,
    val idempotencyKey: String,
    val reason: String,
)

data class ProviderRefundCommand(
    val tenantId: String,
    val operationId: UUID,
    val originalOperationId: UUID,
    val providerReference: String,
    val amountMinorUnits: Long,
    val currency: String,
    val idempotencyKey: String,
    val reason: String,
)

data class ProviderCallbackPayload(
    val providerId: String,
    val rawBody: String,
    val headers: Map<String, String>,
    val queryParams: Map<String, String> = emptyMap(),
)

data class CallbackVerificationResult(
    val isValid: Boolean,
    val eventType: String? = null,
    val operationId: UUID? = null,
    val providerReference: String? = null,
    val outcome: ProviderOutcome? = null,
    val rejectionReason: String? = null,
)

data class ProviderAdapterCapabilities(
    val supportsDeposit: Boolean = false,
    val supportsPayout: Boolean = false,
    val supportsStatusLookup: Boolean = false,
    val supportsCancellation: Boolean = false,
    val supportsRefund: Boolean = false,
    val supportsWebhookVerification: Boolean = false,
    val supportsRequestToPay: Boolean = false,
    val supportsAliasInquiry: Boolean = false,
    val supportsTitleFetch: Boolean = false,
    val supportedCurrencies: Set<String> = setOf("PKR"),
)

enum class ProviderEnvironment {
    PRODUCTION,
    SANDBOX,
    LOCAL_MOCK,
}

data class ProviderConfiguration(
    val providerId: String,
    val environment: ProviderEnvironment,
    val baseUrl: String,
    val timeoutMs: Long = 5000L,
    val maxRetries: Int = 3,
) {
    fun validateNetworkSafety() {
        val uri = try {
            URI.create(baseUrl)
        } catch (e: Exception) {
            throw IllegalArgumentException("Invalid baseUrl URI: $baseUrl", e)
        }

        if (environment == ProviderEnvironment.PRODUCTION) {
            require(uri.scheme.equals("https", ignoreCase = true)) {
                "Production environment requires HTTPS baseUrl, but got: ${uri.scheme}"
            }
            val host = uri.host?.lowercase() ?: throw IllegalArgumentException("baseUrl missing host: $baseUrl")
            val isLoopbackOrPrivate = host == "localhost" ||
                    host == "127.0.0.1" ||
                    host == "::1" ||
                    host.startsWith("10.") ||
                    host.startsWith("192.168.") ||
                    (host.startsWith("172.") && host.split(".").getOrNull(1)?.toIntOrNull() in 16..31)
            require(!isLoopbackOrPrivate) {
                "Production environment prohibits loopback and private IP base URLs: $host"
            }
        } else if (environment == ProviderEnvironment.SANDBOX) {
            require(uri.scheme.equals("https", ignoreCase = true) || uri.scheme.equals("http", ignoreCase = true)) {
                "Sandbox environment requires HTTP or HTTPS baseUrl"
            }
        }
    }
}

data class ProviderCredentials(
    val merchantId: String? = null,
    val clientId: String? = null,
    val clientSecret: String? = null,
    val apiKey: String? = null,
    val signingSecretOrKey: String? = null,
    val additionalProperties: Map<String, String> = emptyMap(),
)

fun interface ProviderCredentialsResolver {
    fun resolveCredentials(tenantId: String, providerId: String): ProviderCredentials?
}
