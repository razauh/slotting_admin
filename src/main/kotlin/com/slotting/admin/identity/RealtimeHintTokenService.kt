package com.slotting.admin.identity

import org.springframework.beans.factory.ObjectProvider
import org.springframework.beans.factory.annotation.Value
import org.springframework.stereotype.Service
import java.time.Instant
import java.util.UUID

@Service
class RealtimeHintTokenService(
    @Value("\${SLOTTING_REALTIME_HINTS_ENABLED:false}") private val enabled: Boolean,
    private val bridgeProvider: ObjectProvider<SupabaseJwtBridgeService>,
) {
    fun issue(tenantId: String, playerId: UUID, sessionId: UUID, sessionExpiresAt: Instant): String? {
        if (!enabled) return null
        val bridge = bridgeProvider.getIfAvailable() ?: return null
        return runCatching {
            bridge.issueForSession(tenantId, playerId, sessionId, sessionExpiresAt).token
        }.getOrNull()
    }
}
