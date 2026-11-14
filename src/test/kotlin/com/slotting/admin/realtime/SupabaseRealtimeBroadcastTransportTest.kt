package com.slotting.admin.realtime

import org.junit.jupiter.api.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue

class SupabaseRealtimeBroadcastTransportTest {
    private data class Call(val url: String, val apikey: String, val authorization: String, val body: String)

    private class FakeSender(private val statuses: MutableList<Int>) : BroadcastHttpSender {
        val calls = mutableListOf<Call>()

        override fun post(url: String, apikey: String, authorization: String, body: String): Int {
            calls.add(Call(url, apikey, authorization, body))
            return if (statuses.isEmpty()) 200 else statuses.removeAt(0)
        }
    }

    private fun hint(id: String = "e1") = RealtimeHint(
        channel = "tenant:tA:player:pA",
        event = "phase",
        payload = mapOf("roundId" to "r1", "phase" to "FLYING", "phaseVersion" to 2, "phaseDeadlineHint" to 1234),
        eventId = id,
        sequence = 2,
    )

    @Test
    fun `one post per send with the private topic and service bearer`() {
        val sender = FakeSender(mutableListOf(200))
        val transport = SupabaseRealtimeBroadcastTransport("https://project.supabase.co", "service-role-fixture", "publishable-fixture", sender)

        transport.send("tenant:tA:player:pA", listOf(hint()))

        assertEquals(1, sender.calls.size)
        val call = sender.calls.single()
        assertEquals("https://project.supabase.co/realtime/v1/api/broadcast", call.url)
        assertEquals("publishable-fixture", call.apikey)
        assertEquals("Bearer service-role-fixture", call.authorization)
        assertTrue(call.body.contains("\"topic\":\"tenant:tA:player:pA\""))
        assertTrue(call.body.contains("\"private\":true"))
        assertTrue(call.body.contains("\"phase\":\"FLYING\""))
        assertEquals(1, transport.sent.get())
        assertEquals(0, transport.failed.get())
    }

    @Test
    fun `server error is retried once and then succeeds`() {
        val sender = FakeSender(mutableListOf(503, 200))
        val transport = SupabaseRealtimeBroadcastTransport("https://project.supabase.co", "service-role-fixture", "publishable-fixture", sender, maxAttempts = 2, retryDelayMillis = 0)

        transport.send("tenant:tA:player:pA", listOf(hint()))

        assertEquals(2, sender.calls.size)
        assertEquals(1, transport.sent.get())
        assertEquals(0, transport.failed.get())
    }

    @Test
    fun `transport failure never throws and is observable`() {
        val sender = FakeSender(mutableListOf(500, 500))
        val transport = SupabaseRealtimeBroadcastTransport("https://project.supabase.co", "service-role-fixture", "publishable-fixture", sender, maxAttempts = 2, retryDelayMillis = 0)

        transport.send("tenant:tA:player:pA", listOf(hint()))

        assertEquals(0, transport.sent.get())
        assertEquals(1, transport.failed.get())
    }

    @Test
    fun `sender exception never propagates`() {
        val transport = SupabaseRealtimeBroadcastTransport(
            "https://project.supabase.co",
            "service-role-fixture",
            "publishable-fixture",
            BroadcastHttpSender { _, _, _, _ -> throw IllegalStateException("network down") },
            maxAttempts = 1,
        )

        transport.send("tenant:tA:player:pA", listOf(hint()))

        assertEquals(1, transport.failed.get())
    }

    @Test
    fun `missing or wrong apikey surfaces a typed unauthorized failure`() {
        val sender = FakeSender(mutableListOf(401, 401))
        val transport = SupabaseRealtimeBroadcastTransport("https://project.supabase.co", "service-role-fixture", "publishable-fixture", sender, maxAttempts = 2, retryDelayMillis = 0)

        transport.send("tenant:tA:player:pA", listOf(hint()))

        assertEquals(0, transport.sent.get())
        assertEquals(1, transport.failed.get())
        assertTrue(transport.lastFailure.get() is RealtimeBroadcastFailure.Unauthorized)
    }

    @Test
    fun `batch of hints is sent in one post`() {
        val sender = FakeSender(mutableListOf(200))
        val transport = SupabaseRealtimeBroadcastTransport("https://project.supabase.co", "service-role-fixture", "publishable-fixture", sender)

        transport.send("tenant:tA:player:pA", listOf(hint("e1"), hint("e2")))

        assertEquals(1, sender.calls.size)
        val body = sender.calls.single().body
        assertTrue(body.contains("\"eventId\":\"e1\"") || body.contains("\"sequence\""))
        assertTrue(body.count { it == '{' } >= 2)
    }
}
