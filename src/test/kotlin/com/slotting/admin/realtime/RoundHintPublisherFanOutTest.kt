package com.slotting.admin.realtime

import org.junit.jupiter.api.Test
import java.time.Clock
import java.time.Instant
import java.time.ZoneOffset
import kotlin.test.assertEquals
import kotlin.test.assertTrue

class RoundHintPublisherFanOutTest {
    private class RecordingTransport : RealtimeHintTransport {
        val batches = mutableListOf<Pair<String, List<RealtimeHint>>>()

        override fun send(channel: String, hints: List<RealtimeHint>) {
            batches.add(channel to hints)
        }
    }

    private val event = RoundPhaseEvent("tA", "aviator", "r1", "FLYING", 3, 1500)

    private fun publisher(transport: RecordingTransport, enabled: Boolean = true, guard: RealtimeBudgetGuard? = null, chunk: Int = 500) =
        RoundHintPublisher(RealtimePublishService(transport), enabled, guard, chunk)

    @Test
    fun `fan-out sends one hint per distinct player channel`() {
        val transport = RecordingTransport()

        val published = publisher(transport).publishRoundEvent(true, event, listOf("p1", "p2", "p1"))

        assertEquals(2, published)
        assertEquals(setOf("tenant:tA:player:p1", "tenant:tA:player:p2"), transport.batches.map { it.first }.toSet())
        assertTrue(transport.batches.all { it.second.size == 1 })
    }

    @Test
    fun `empty roster sends nothing and does not fail`() {
        val transport = RecordingTransport()

        assertEquals(0, publisher(transport).publishRoundEvent(true, event, emptyList()))
        assertTrue(transport.batches.isEmpty())
    }

    @Test
    fun `uncommitted event sends nothing`() {
        val transport = RecordingTransport()

        assertEquals(0, publisher(transport).publishRoundEvent(false, event, listOf("p1")))
        assertTrue(transport.batches.isEmpty())
    }

    @Test
    fun `disabled publisher sends nothing`() {
        val transport = RecordingTransport()

        assertEquals(0, publisher(transport, enabled = false).publishRoundEvent(true, event, listOf("p1")))
        assertTrue(transport.batches.isEmpty())
    }

    @Test
    fun `large roster is chunked by the per-post cap`() {
        val transport = RecordingTransport()
        val players = (1..3).map { "p$it" }

        val published = publisher(transport, chunk = 2).publishRoundEvent(true, event, players)

        assertEquals(3, published)
        assertEquals(3, transport.batches.size)
    }

    @Test
    fun `budget guard skips only the saturated player`() {
        val transport = RecordingTransport()
        val guard = RealtimeBudgetGuard(1, {}, Clock.fixed(Instant.parse("2026-11-10T12:00:00Z"), ZoneOffset.UTC))
        guard.allowsPublish("p1")

        val published = publisher(transport, guard = guard).publishRoundEvent(true, event, listOf("p1", "p2"))

        assertEquals(1, published)
        assertEquals(listOf("tenant:tA:player:p2"), transport.batches.map { it.first })
    }

    @Test
    fun `per-player event ids stay distinct so dedupe never drops the fan-out`() {
        val transport = RecordingTransport()

        publisher(transport).publishRoundEvent(true, event, listOf("p1", "p2"))

        val ids = transport.batches.flatMap { it.second }.map { it.eventId }
        assertEquals(ids.size, ids.toSet().size)
        assertTrue(ids.all { it.startsWith("r1:FLYING:3:") })
    }

    @Test
    fun `payload is phase-only and carries the deadline hint when supplied`() {
        val transport = RecordingTransport()

        publisher(transport).publishRoundEvent(true, event, listOf("p1"))

        val payload = transport.batches.single().second.single().payload
        assertEquals("r1", payload["roundId"])
        assertEquals("FLYING", payload["phase"])
        assertEquals(3L, payload["phaseVersion"])
        assertEquals(1500L, payload["phaseDeadlineHint"])
        assertTrue(!payload.containsKey("crashMultiplier"))
    }
}
