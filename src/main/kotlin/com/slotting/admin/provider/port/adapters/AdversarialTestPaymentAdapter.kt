package com.slotting.admin.provider.port.adapters

import com.slotting.admin.provider.port.*
import java.util.UUID
import java.util.concurrent.ConcurrentHashMap

enum class AdversarialSimulationMode {
    NORMAL_SUCCESS,
    EXPLICIT_DECLINE,
    TIMEOUT_AFTER_DISPATCH,
    HTTP_500_INTERNAL_ERROR,
    MALFORMED_RESPONSE_PAYLOAD,
    CONNECTION_RESET,
    RATE_LIMITED,
}

/**
 * Adversarial contract fake for testing timeouts, dropped connections, response loss,
 * malformed payloads, duplicate retries, and race conditions.
 *
 * Explicitly marked `isProductionReady = false` so ProductionProviderGuard prevents
 * accidental usage in production profiles.
 */
class AdversarialTestPaymentAdapter(
    override val providerId: String = "ADVERSARIAL_TEST",
    var simulationMode: AdversarialSimulationMode = AdversarialSimulationMode.NORMAL_SUCCESS,
) : PaymentProviderPort {

    override val isProductionReady: Boolean = false

    override val capabilities: ProviderAdapterCapabilities = ProviderAdapterCapabilities(
        supportsDeposit = true,
        supportsPayout = true,
        supportsStatusLookup = true,
        supportsCancellation = true,
        supportsRefund = true,
        supportsWebhookVerification = true,
        supportsRequestToPay = true,
        supportsAliasInquiry = true,
        supportsTitleFetch = true,
        supportedCurrencies = setOf("PKR", "USD"),
    )

    private val dispatchesByKey = ConcurrentHashMap<String, Int>()
    private val outcomesByKey = ConcurrentHashMap<String, ProviderOutcome>()

    fun recordedDispatches(idempotencyKey: String): Int = dispatchesByKey[idempotencyKey] ?: 0

    override fun deposit(
        command: ProviderDepositCommand,
        config: ProviderConfiguration,
        credentials: ProviderCredentials?,
    ): ProviderOutcome {
        val existing = outcomesByKey[command.idempotencyKey]
        if (existing != null) {
            return existing
        }

        dispatchesByKey.compute(command.idempotencyKey) { _, c -> (c ?: 0) + 1 }

        val outcome = when (simulationMode) {
            AdversarialSimulationMode.NORMAL_SUCCESS -> ProviderOutcome.accepted(
                operationId = command.operationId,
                providerReference = "prov-ref-${command.operationId}",
                code = "SUCCESS",
                evidence = mapOf("dispatched" to "true")
            )
            AdversarialSimulationMode.EXPLICIT_DECLINE -> ProviderOutcome.declined(
                operationId = command.operationId,
                code = "ISSUER_DECLINED",
                reason = "Transaction declined by issuing institution",
            )
            AdversarialSimulationMode.TIMEOUT_AFTER_DISPATCH -> ProviderOutcome.ambiguous(
                operationId = command.operationId,
                code = "TIMEOUT_AFTER_DISPATCH",
                reason = "Socket timeout waiting for provider response after request was transmitted",
                evidence = mapOf("requestSent" to "true")
            )
            AdversarialSimulationMode.HTTP_500_INTERNAL_ERROR -> ProviderOutcome.ambiguous(
                operationId = command.operationId,
                code = "HTTP_500",
                reason = "Provider gateway returned 500 Internal Server Error",
            )
            AdversarialSimulationMode.MALFORMED_RESPONSE_PAYLOAD -> ProviderOutcome.ambiguous(
                operationId = command.operationId,
                code = "MALFORMED_PAYLOAD",
                reason = "Unparseable non-JSON response received from provider",
            )
            AdversarialSimulationMode.CONNECTION_RESET -> ProviderOutcome.ambiguous(
                operationId = command.operationId,
                code = "CONNECTION_RESET",
                reason = "TCP connection reset by peer during response transfer",
            )
            AdversarialSimulationMode.RATE_LIMITED -> ProviderOutcome.unavailable(
                operationId = command.operationId,
                reason = "HTTP 429 Too Many Requests: upstream provider rate limit exceeded",
                code = "RATE_LIMITED",
            )
        }

        if (outcome.status == ProviderOutcomeStatus.ACCEPTED) {
            outcomesByKey[command.idempotencyKey] = outcome
        }

        return outcome
    }

    override fun payout(
        command: ProviderPayoutCommand,
        config: ProviderConfiguration,
        credentials: ProviderCredentials?,
    ): ProviderOutcome {
        val existing = outcomesByKey[command.idempotencyKey]
        if (existing != null) {
            return existing
        }

        dispatchesByKey.compute(command.idempotencyKey) { _, c -> (c ?: 0) + 1 }

        val outcome = when (simulationMode) {
            AdversarialSimulationMode.NORMAL_SUCCESS -> ProviderOutcome.accepted(
                operationId = command.operationId,
                providerReference = "prov-payout-${command.operationId}",
                code = "TRANSFER_SETTLED"
            )
            AdversarialSimulationMode.TIMEOUT_AFTER_DISPATCH -> ProviderOutcome.ambiguous(
                operationId = command.operationId,
                code = "TIMEOUT_AFTER_DISPATCH",
                reason = "Timeout on payout dispatch",
            )
            else -> ProviderOutcome.failed(command.operationId, "ERROR", "Simulation error")
        }

        if (outcome.status == ProviderOutcomeStatus.ACCEPTED) {
            outcomesByKey[command.idempotencyKey] = outcome
        }
        return outcome
    }

    override fun queryStatus(
        query: ProviderStatusQuery,
        config: ProviderConfiguration,
        credentials: ProviderCredentials?,
    ): ProviderOutcome {
        if (query.providerReference == "prov-ref-non-existent") {
            return ProviderOutcome.ambiguous(
                operationId = query.operationId,
                code = "UNKNOWN_REFERENCE",
                reason = "Provider has no record of the supplied reference",
            )
        }
        return when (simulationMode) {
            AdversarialSimulationMode.NORMAL_SUCCESS -> ProviderOutcome.accepted(
                operationId = query.operationId,
                providerReference = query.providerReference ?: "prov-ref-${query.operationId}",
                code = "SUCCESS",
                evidence = mapOf("inquiry" to "true")
            )
            AdversarialSimulationMode.EXPLICIT_DECLINE -> ProviderOutcome.declined(
                operationId = query.operationId,
                code = "ISSUER_DECLINED",
                reason = "Transaction declined by issuing institution",
            )
            AdversarialSimulationMode.TIMEOUT_AFTER_DISPATCH,
            AdversarialSimulationMode.HTTP_500_INTERNAL_ERROR,
            AdversarialSimulationMode.MALFORMED_RESPONSE_PAYLOAD,
            AdversarialSimulationMode.CONNECTION_RESET -> ProviderOutcome.ambiguous(
                operationId = query.operationId,
                code = "TIMEOUT_AFTER_DISPATCH",
                reason = "Inquiry timeout or connection reset",
            )
            AdversarialSimulationMode.RATE_LIMITED -> ProviderOutcome.unavailable(
                operationId = query.operationId,
                reason = "Rate limited on status query",
            )
        }
    }

    override fun cancel(
        command: ProviderCancelCommand,
        config: ProviderConfiguration,
        credentials: ProviderCredentials?,
    ): ProviderOutcome {
        return ProviderOutcome.accepted(
            operationId = command.operationId,
            providerReference = command.providerReference ?: "cancel-${command.operationId}",
            code = "CANCELLED",
        )
    }

    override fun refund(
        command: ProviderRefundCommand,
        config: ProviderConfiguration,
        credentials: ProviderCredentials?,
    ): ProviderOutcome {
        return ProviderOutcome.accepted(
            operationId = command.operationId,
            providerReference = "rfnd-${command.operationId}",
            code = "REFUND_SUCCESS",
        )
    }

    override fun verifyCallback(
        callback: ProviderCallbackPayload,
        config: ProviderConfiguration,
        credentials: ProviderCredentials?,
    ): CallbackVerificationResult {
        return CallbackVerificationResult(
            isValid = true,
            eventType = "CALLBACK_TEST",
            providerReference = "ref-callback",
        )
    }
}
