package com.slotting.admin.realtime

import org.junit.jupiter.api.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue

class SupabaseRealtimeBroadcastTransportTest {
    private class FakeSender(private val statuses: MutableList<Int>) : BroadcastHttpSender {
        val calls = mutableListOf<Triple<String, String, String>>()

        override fun post(url: String, authorization: String, body: String): Int {
            calls.add(Triple(url, authorization, body))
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
        val transport = SupabaseRealtimeBroadcastTransport("https://project.supabase.co", "service-role-fixture", sender)

        transport.send("tenant:tA:player:pA", listOf(hint()))

        assertEquals(1, sender.calls.size)
        val call = sender.calls.single()
        assertEquals("https://project.supabase.co/realtime/v1/api/broadcast", call.first)
        assertEquals("Bearer service-role-fixture", call.second)
        assertTrue(call.third.contains("\"topic\":\"tenant:tA:player:pA\""))
        assertTrue(call.third.contains("\"private\":true"))
        assertTrue(call.third.contains("\"phase\":\"FLYING\""))
        assertEquals(1, transport.sent.get())
        assertEquals(0, transport.failed.get())
    }

    @Test
    fun `server error is retried once and then succeeds`() {
        val sender = FakeSender(mutableListOf(503, 200))
        val transport = SupabaseRealtimeBroadcastTransport("https://project.supabase.co", "service-role-fixture", sender, maxAttempts = 2, retryDelayMillis = 0)

        transport.send("tenant:tA:player:pA", listOf(hint()))

        assertEquals(2, sender.calls.size)
        assertEquals(1, transport.sent.get())
        assertEquals(0, transport.failed.get())
    }

    @Test
    fun `transport failure never throws and is observable`() {
        val sender = FakeSender(mutableListOf(500, 500))
        val transport = SupabaseRealtimeBroadcastTransport("https://project.supabase.co", "service-role-fixture", sender, maxAttempts = 2, retryDelayMillis = 0)

        transport.send("tenant:tA:player:pA", listOf(hint()))

        assertEquals(0, transport.sent.get())
        assertEquals(1, transport.failed.get())
    }

    @Test
    fun `sender exception never propagates`() {
        val transport = SupabaseRealtimeBroadcastTransport(
            "https://project.supabase.co",
            "service-role-fixture",
            BroadcastHttpSender { _, _, _ -> throw IllegalStateException("network down") },
            maxAttempts = 1,
        )

        transport.send("tenant:tA:player:pA", listOf(hint()))

        assertEquals(1, transport.failed.get())
    }

    @Test
    fun `batch of hints is sent in one post`() {
        val sender = FakeSender(mutableListOf(200))
        val transport = SupabaseRealtimeBroadcastTransport("https://project.supabase.co", "service-role-fixture", sender)

        transport.send("tenant:tA:player:pA", listOf(hint("e1"), hint("e2")))

        assertEquals(1, sender.calls.size)
        val body = sender.calls.single().third
        assertTrue(body.contains("\"eventId\":\"e1\"") || body.contains("\"sequence\""))
        assertTrue(body.count { it == '{' } >= 2)
    }
}
