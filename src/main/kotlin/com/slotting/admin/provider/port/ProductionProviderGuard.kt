package com.slotting.admin.provider.port

object ProductionProviderGuard {
    fun assertProductionReady(adapter: PaymentProviderPort, profile: String) {
        val normalized = profile.trim().lowercase()
        val isProduction = normalized == "production" || normalized == "prod"
        if (isProduction && !adapter.isProductionReady) {
            throw IllegalStateException(
                "Fake/sandbox adapter '${adapter.providerId}' (${adapter.javaClass.simpleName}) cannot be composed in production profile"
            )
        }
    }
}
