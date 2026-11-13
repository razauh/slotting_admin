package com.slotting.admin.config

import com.slotting.admin.identity.EnvironmentJwtSigningKeyProvider
import com.slotting.admin.identity.InMemoryPlayerSessionStore
import com.slotting.admin.identity.SupabaseJwtBridgeService
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty
import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Configuration

@Configuration
class RealtimeHintTokenConfiguration {
    @Bean
    @ConditionalOnProperty(name = ["SLOTTING_REALTIME_HINTS_ENABLED"], havingValue = "true")
    fun supabaseJwtBridgeService(): SupabaseJwtBridgeService =
        SupabaseJwtBridgeService(
            sessionStore = InMemoryPlayerSessionStore(),
            signingKeys = EnvironmentJwtSigningKeyProvider(),
            enabled = true,
        )
}
