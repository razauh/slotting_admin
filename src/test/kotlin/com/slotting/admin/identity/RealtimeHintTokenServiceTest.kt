package com.slotting.admin.identity

import org.junit.jupiter.api.Test
import org.springframework.beans.factory.support.StaticListableBeanFactory
import java.nio.charset.StandardCharsets
import java.time.Clock
import java.time.Instant
import java.time.ZoneOffset
import java.util.UUID
import kotlin.test.assertEquals
import kotlin.test.assertNotNull
import kotlin.test.assertNull

class RealtimeHintTokenServiceTest {
    private val clock = Clock.fixed(Instant.parse("2026-11-13T12:00:00Z"), ZoneOffset.UTC)
    private val bridge = SupabaseJwtBridgeService(
        sessionStore = InMemoryPlayerSessionStore(),
        signingKeys = StaticJwtSigningKeyProvider("bb8-key", "bb8-test-self-hosted-jwt-secret-0123456789".toByteArray(StandardCharsets.UTF_8)),
        clock = clock,
    )

    private fun provider(): org.springframework.beans.factory.ObjectProvider<SupabaseJwtBridgeService> =
        StaticListableBeanFactory(mapOf("bridge" to bridge)).getBeanProvider(SupabaseJwtBridgeService::class.java)

    @Test
    fun `flag off issues nothing`() {
        val service = RealtimeHintTokenService(false, provider())
        assertNull(service.issue("tenant-a", UUID.randomUUID(), UUID.randomUUID(), clock.instant().plusSeconds(600)))
    }

    @Test
    fun `flag on issues a short lived token with tenant and player claims`() {
        val player = UUID.randomUUID()
        val session = UUID.randomUUID()
        val token = RealtimeHintTokenService(true, provider()).issue("tenant-a", player, session, clock.instant().plusSeconds(600))
        assertNotNull(token)
        val claims = String(java.util.Base64.getUrlDecoder().decode(token!!.split(".")[1]))
        assertEquals(true, claims.contains("\"tenant_id\":\"tenant-a\""))
        assertEquals(true, claims.contains(player.toString()))
        assertEquals(true, claims.contains(session.toString()))
    }
}
