package com.slotting.admin.config

import com.slotting.admin.realtime.RealtimeBudgetGuard
import com.slotting.admin.realtime.RealtimeHintTransport
import com.slotting.admin.realtime.RealtimePublishService
import com.slotting.admin.realtime.RoundHintPublisher
import com.slotting.admin.realtime.SupabaseRealtimeBroadcastTransport
import org.slf4j.LoggerFactory
import org.springframework.beans.factory.annotation.Value
import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Configuration
import java.time.Clock

@Configuration
class RealtimeHintConfiguration {
    private val logger = LoggerFactory.getLogger(javaClass)

    @Bean
    fun realtimeBudgetGuard(clock: Clock): RealtimeBudgetGuard = RealtimeBudgetGuard(clock = clock)

    @Bean
    fun realtimeHintTransport(
        @Value("\${SLOTTING_SUPABASE_URL:}") baseUrl: String,
        @Value("\${SUPABASE_SERVICE_ROLE_KEY:}") serviceRoleKey: String,
    ): RealtimeHintTransport {
        if (baseUrl.isBlank() || serviceRoleKey.isBlank()) {
            logger.warn("realtime_hint_transport_disabled reason=missing_configuration")
            return object : RealtimeHintTransport {
                override fun send(channel: String, hints: List<com.slotting.admin.realtime.RealtimeHint>) = Unit
            }
        }
        return SupabaseRealtimeBroadcastTransport(baseUrl = baseUrl, serviceRoleKey = serviceRoleKey)
    }

    @Bean
    fun realtimePublishService(transport: RealtimeHintTransport): RealtimePublishService =
        RealtimePublishService(transport)

    @Bean
    fun roundHintPublisher(
        publishService: RealtimePublishService,
        budgetGuard: RealtimeBudgetGuard,
        @Value("\${SLOTTING_REALTIME_HINTS_ENABLED:false}") enabled: Boolean,
    ): RoundHintPublisher = RoundHintPublisher(publishService, enabled, budgetGuard)
}
