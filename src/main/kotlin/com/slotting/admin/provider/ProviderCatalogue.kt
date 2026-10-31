package com.slotting.admin.provider

import com.slotting.admin.provider.port.ProviderEnvironment
import com.slotting.admin.wallet.InvalidCurrencyException
import com.slotting.admin.wallet.SupportedAlphaCurrencyPolicy

enum class ProviderOperation {
    DEPOSIT,
    PAYOUT,
    STATUS_LOOKUP,
    WEBHOOK_VERIFICATION,
    CANCELLATION,
    REFUND,
}

enum class ProviderSetupState {
    DISABLED,
    INVALID_CONFIG,
    NOT_VERIFIED,
    READY,
}

enum class ProviderProbeStatus {
    READY,
    INVALID_CONFIG,
    UNREACHABLE,
    UNAUTHORIZED,
    NOT_VERIFIED,
}

data class ProviderDefinition(
    val providerId: String,
    val displayName: String,
    val operations: Set<ProviderOperation>,
    val walletCurrencies: Set<String> = setOf("PKR"),
    val settlementCurrencies: Set<String> = setOf("PKR"),
    val adapterProductionReady: Boolean = false,
    val capabilityVersion: Long = 1L,
)

object ProviderCatalogue {
    val definitions: List<ProviderDefinition> = listOf(
        ProviderDefinition(
            providerId = "JAZZCASH",
            displayName = "JazzCash",
            operations = setOf(
                ProviderOperation.DEPOSIT,
                ProviderOperation.WEBHOOK_VERIFICATION,
            ),
        ),
        ProviderDefinition(
            providerId = "EASYPAISA",
            displayName = "Easypaisa",
            operations = setOf(
                ProviderOperation.DEPOSIT,
                ProviderOperation.WEBHOOK_VERIFICATION,
            ),
        ),
        ProviderDefinition(
            providerId = "SAFEPAY_RAAST",
            displayName = "Safepay Raast",
            operations = setOf(
                ProviderOperation.DEPOSIT,
                ProviderOperation.PAYOUT,
                ProviderOperation.WEBHOOK_VERIFICATION,
            ),
        ),
        ProviderDefinition(
            providerId = "ONELINK_RAAST",
            displayName = "OneLink Raast",
            operations = setOf(
                ProviderOperation.DEPOSIT,
                ProviderOperation.WEBHOOK_VERIFICATION,
                ProviderOperation.CANCELLATION,
            ),
        ),
        ProviderDefinition(
            providerId = "ONELINK_IBFT",
            displayName = "OneLink IBFT",
            operations = setOf(
                ProviderOperation.PAYOUT,
            ),
        ),
    )

    fun find(providerId: String): ProviderDefinition? =
        definitions.firstOrNull { it.providerId.equals(providerId.trim(), ignoreCase = true) }

    fun require(providerId: String): ProviderDefinition =
        find(providerId) ?: throw IllegalArgumentException("Unknown payment provider: $providerId")

    fun validateWalletCurrencies(currencies: Set<String>): Set<String> {
        if (currencies.isEmpty()) throw InvalidCurrencyException("At least one wallet currency is required")
        return currencies.map { SupportedAlphaCurrencyPolicy.validate(it) }.toSet()
    }

    fun validateSettlementCurrencies(provider: ProviderDefinition, currencies: Set<String>): Set<String> {
        if (currencies.isEmpty()) throw InvalidCurrencyException("At least one settlement currency is required")
        val validated = currencies.map { SupportedAlphaCurrencyPolicy.validate(it) }.toSet()
        val unsupported = validated - provider.settlementCurrencies
        if (unsupported.isNotEmpty()) {
            throw InvalidCurrencyException(
                "Provider ${provider.providerId} does not support settlement currency ${unsupported.joinToString(",")}"
            )
        }
        return validated
    }
}

object ProviderSetupPolicy {
    fun state(
        provider: ProviderDefinition?,
        environment: ProviderEnvironment,
        walletCurrencies: Set<String>,
        settlementCurrencies: Set<String>,
        operations: Set<String>,
        credentialsAvailable: Boolean,
        permittedUseApproved: Boolean,
        technicalVerificationApproved: Boolean,
        adapterProductionReady: Boolean,
    ): ProviderSetupState {
        if (provider == null) return ProviderSetupState.INVALID_CONFIG
        if (walletCurrencies.isEmpty() || settlementCurrencies.isEmpty() || operations.isEmpty()) {
            return ProviderSetupState.INVALID_CONFIG
        }
        if (walletCurrencies.any { !SupportedAlphaCurrencyPolicy.isSupported(it) }) {
            return ProviderSetupState.INVALID_CONFIG
        }
        if (settlementCurrencies.any { it !in provider.settlementCurrencies }) {
            return ProviderSetupState.INVALID_CONFIG
        }
        val parsedOperations = operations.mapNotNull { runCatching { ProviderOperation.valueOf(it.uppercase()) }.getOrNull() }
        if (parsedOperations.size != operations.size || parsedOperations.any { it !in provider.operations }) {
            return ProviderSetupState.INVALID_CONFIG
        }
        if (!credentialsAvailable) return ProviderSetupState.INVALID_CONFIG
        if (environment == ProviderEnvironment.PRODUCTION) {
            if (!permittedUseApproved || !technicalVerificationApproved || !adapterProductionReady) {
                return ProviderSetupState.NOT_VERIFIED
            }
        }
        return ProviderSetupState.READY
    }
}
