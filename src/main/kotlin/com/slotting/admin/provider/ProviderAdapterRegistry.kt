package com.slotting.admin.provider

class ProviderAdapterRegistry(
    productionReadyProviders: Set<String> = emptySet(),
) {
    private val productionReady = productionReadyProviders.map { it.uppercase() }.toSet()

    fun isProductionReady(providerId: String): Boolean = providerId.uppercase() in productionReady
}
