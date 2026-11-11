package com.slotting.admin.realtime

import org.junit.jupiter.api.Test
import kotlin.test.assertEquals
import kotlin.test.assertNull
import kotlin.test.assertTrue

class RoundHintPublisherTest {
    private class RecordingTransport : RealtimeHintTransport {
        val channels = mutableListOf<String>()
        val hints = mutableListOf<RealtimeHint>()

        override fun send(channel: String, hints: List<RealtimeHint>) {
            channels.add(channel)
            this.hints.addAll(hints)
        }
    }

    private fun publisher(transport: RecordingTransport, enabled: Boolean, guard: RealtimeBudgetGuard? = null) =
        RoundHintPublisher(RealtimePublishService(transport), enabled, guard)

    @Test
    fun `disabled publisher sends nothing`() {
        val transport = RecordingTransport()

        assertNull(publisher(transport, enabled = false).publish("tA", "pA", "r1", "SETTLED", 7))

        assertTrue(transport.channels.isEmpty())
    }

    @Test
    fun `enabled publisher sends the phase-only hint to the player channel`() {
        val transport = RecordingTransport()

        val decision = publisher(transport, enabled = true).publish("tA", "pA", "r1", "SETTLED", 7, 1234)

        assertEquals(PublishDecision.PUBLISHED, decision)
        assertEquals(listOf("tenant:tA:player:pA"), transport.channels)
        val payload = transport.hints.single().payload
        assertEquals("r1", payload["roundId"])
        assertEquals("SETTLED", payload["phase"])
        assertEquals(7L, payload["phaseVersion"])
        assertEquals(1234L, payload["phaseDeadlineHint"])
        assertTrue(!payload.containsKey("crashMultiplier"))
    }

    @Test
    fun `budget guard refusal never reaches the transport`() {
        val transport = RecordingTransport()
        val guard = RealtimeBudgetGuard(maxPerPlayerPerSecond = 1, clock = java.time.Clock.fixed(java.time.Instant.parse("2026-11-10T12:00:00Z"), java.time.ZoneOffset.UTC))
        guard.allowsPublish("pA")

        val decision = publisher(transport, enabled = true, guard = guard).publish("tA", "pA", "r1", "FLYING", 2)

        assertEquals(PublishDecision.DROPPED_RATE_LIMITED, decision)
        assertTrue(transport.channels.isEmpty())
    }
}
