package com.slotting.admin.provider.port

interface PaymentProviderPort {
    val providerId: String
    val capabilities: ProviderAdapterCapabilities
    val isProductionReady: Boolean get() = true

    fun deposit(
        command: ProviderDepositCommand,
        config: ProviderConfiguration,
        credentials: ProviderCredentials?,
    ): ProviderOutcome

    fun payout(
        command: ProviderPayoutCommand,
        config: ProviderConfiguration,
        credentials: ProviderCredentials?,
    ): ProviderOutcome

    fun queryStatus(
        query: ProviderStatusQuery,
        config: ProviderConfiguration,
        credentials: ProviderCredentials?,
    ): ProviderOutcome

    fun cancel(
        command: ProviderCancelCommand,
        config: ProviderConfiguration,
        credentials: ProviderCredentials?,
    ): ProviderOutcome

    fun refund(
        command: ProviderRefundCommand,
        config: ProviderConfiguration,
        credentials: ProviderCredentials?,
    ): ProviderOutcome

    fun verifyCallback(
        callback: ProviderCallbackPayload,
        config: ProviderConfiguration,
        credentials: ProviderCredentials?,
    ): CallbackVerificationResult
}

interface ProviderPortMetrics {
    fun recordOperation(
        providerId: String,
        operationType: String,
        outcomeStatus: ProviderOutcomeStatus,
        latencyMs: Long,
    )
}

class NoOpProviderPortMetrics : ProviderPortMetrics {
    override fun recordOperation(
        providerId: String,
        operationType: String,
        outcomeStatus: ProviderOutcomeStatus,
        latencyMs: Long,
    ) {}
}
