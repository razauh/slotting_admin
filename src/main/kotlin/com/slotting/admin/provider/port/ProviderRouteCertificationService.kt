package com.slotting.admin.provider.port

import com.slotting.admin.provider.port.adapters.EasypaisaAdapter
import com.slotting.admin.provider.port.adapters.JazzCashAdapter
import com.slotting.admin.provider.port.adapters.OneLinkIbftAdapter
import com.slotting.admin.provider.port.adapters.OneLinkRaastAdapter
import com.slotting.admin.provider.port.adapters.SafepayRaastAdapter

enum class ProviderRouteCertificationStatus {
    SIMULATED_PASS,
    DISABLED_UNSUPPORTED,
    EXTERNALLY_BLOCKED,
}

data class ProviderRouteCertification(
    val providerId: String,
    val environment: ProviderEnvironment,
    val operations: Set<String>,
    val currencies: Set<String>,
    val supportsAuthenticatedCallback: Boolean,
    val supportsInquiry: Boolean,
    val specificationRevision: String,
    val status: ProviderRouteCertificationStatus,
    val reason: String,
)

data class ExternalProviderEvidence(
    val status: ProviderRouteCertificationStatus,
    val reason: String,
)

class ProviderRouteCertificationService(
    private val adapters: List<PaymentProviderPort> = listOf(
        SafepayRaastAdapter(),
        OneLinkRaastAdapter(),
        JazzCashAdapter(),
        EasypaisaAdapter(),
        OneLinkIbftAdapter(),
    ),
) {
    fun routeMatrix(environment: ProviderEnvironment = ProviderEnvironment.LOCAL_MOCK): List<ProviderRouteCertification> =
        adapters.map { adapter ->
            val capabilities = adapter.capabilities
            val operations = buildSet {
                if (capabilities.supportsDeposit) add("DEPOSIT")
                if (capabilities.supportsPayout) add("PAYOUT")
                if (capabilities.supportsStatusLookup) add("STATUS_INQUIRY")
                if (capabilities.supportsCancellation) add("CANCELLATION")
                if (capabilities.supportsRefund) add("REFUND")
            }
            val disabled = operations.isEmpty() || (!capabilities.supportsDeposit && !capabilities.supportsPayout)
            ProviderRouteCertification(
                providerId = adapter.providerId,
                environment = environment,
                operations = operations,
                currencies = capabilities.supportedCurrencies,
                supportsAuthenticatedCallback = capabilities.supportsWebhookVerification,
                supportsInquiry = capabilities.supportsStatusLookup,
                specificationRevision = specificationRevision(adapter.providerId),
                status = if (disabled) ProviderRouteCertificationStatus.DISABLED_UNSUPPORTED else ProviderRouteCertificationStatus.SIMULATED_PASS,
                reason = if (disabled) {
                    "Route is not selected or authorized; deterministic tests assert an actionable unsupported result"
                } else {
                    "Deterministic local fake transport and isolated database evidence only"
                },
            )
        }

    fun externalEvidence(sandboxCredentialsPresent: Boolean, sandboxRouteAuthorized: Boolean): ExternalProviderEvidence =
        if (!sandboxCredentialsPresent || !sandboxRouteAuthorized) {
            ExternalProviderEvidence(
                status = ProviderRouteCertificationStatus.EXTERNALLY_BLOCKED,
                reason = "Sandbox credentials or provider authorization are unavailable; external conformance is not PASS",
            )
        } else {
            ExternalProviderEvidence(
                status = ProviderRouteCertificationStatus.EXTERNALLY_BLOCKED,
                reason = "Provider specification and allowed nonfinancial sandbox execution are required before external PASS",
            )
        }

    fun requireNonProductionEndpoint(config: ProviderConfiguration) {
        if (config.environment == ProviderEnvironment.PRODUCTION) {
            throw IllegalStateException("Certification tests must never target a production provider endpoint")
        }
        config.validateNetworkSafety()
    }

    private fun specificationRevision(providerId: String): String = when (providerId) {
        "SAFEPAY_RAAST" -> "customer-supplied-pending"
        "ONELINK_RAAST" -> "disabled-unselected"
        "JAZZCASH" -> "customer-supplied-pending"
        "EASYPAISA" -> "v1.2-historical-unverified"
        "ONELINK_IBFT" -> "customer-supplied-pending"
        else -> "unknown"
    }
}
