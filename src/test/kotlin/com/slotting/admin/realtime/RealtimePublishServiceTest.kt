package com.slotting.admin.realtime

import org.junit.jupiter.api.Test
import java.time.Clock
import java.time.Instant
import java.time.ZoneOffset
import kotlin.test.assertEquals
import kotlin.test.assertTrue

class RealtimePublishServiceTest {
    private val now = Instant.parse("2026-11-09T12:00:00Z")
    private val clock = Clock.fixed(now, ZoneOffset.UTC)

    private class RecordingTransport : RealtimeHintTransport {
        val batches = mutableListOf<Pair<String, List<RealtimeHint>>>()

        override fun send(channel: String, hints: List<RealtimeHint>) {
            batches.add(channel to hints)
        }
    }

    private fun hint(id: String, sequence: Long, channel: String = "tenant:a:player:p") =
        RealtimeHint(channel, "phase", mapOf("phase" to "BETTING"), id, sequence)

    @Test
    fun `hint is not published before commit`() {
        val transport = RecordingTransport()
        val service = RealtimePublishService(transport, 10, clock)

        assertEquals(PublishDecision.DROPPED_NOT_COMMITTED, service.publish(false, hint("e1", 1)))
        assertTrue(transport.batches.isEmpty())
    }

    @Test
    fun `committed hint is published`() {
        val transport = RecordingTransport()
        val service = RealtimePublishService(transport, 10, clock)

        assertEquals(PublishDecision.PUBLISHED, service.publish(true, hint("e1", 1)))
        assertEquals(1, transport.batches.size)
        assertEquals(1, transport.batches.single().second.size)
    }

    @Test
    fun `duplicate event id is suppressed`() {
        val transport = RecordingTransport()
        val service = RealtimePublishService(transport, 10, clock)

        assertEquals(PublishDecision.PUBLISHED, service.publish(true, hint("e1", 1)))
        assertEquals(PublishDecision.DROPPED_DUPLICATE, service.publish(true, hint("e1", 1)))
        assertEquals(1, transport.batches.size)
    }

    @Test
    fun `rate is bounded per channel`() {
        val transport = RecordingTransport()
        val service = RealtimePublishService(transport, 3, clock)

        assertEquals(PublishDecision.PUBLISHED, service.publish(true, hint("e1", 1)))
        assertEquals(PublishDecision.PUBLISHED, service.publish(true, hint("e2", 2)))
        assertEquals(PublishDecision.PUBLISHED, service.publish(true, hint("e3", 3)))
        assertEquals(PublishDecision.DROPPED_RATE_LIMITED, service.publish(true, hint("e4", 4)))
        assertEquals(3, transport.batches.size)
    }

    @Test
    fun `batch publishes once per channel`() {
        val transport = RecordingTransport()
        val service = RealtimePublishService(transport, 10, clock)

        val decisions = service.publishBatch(true, listOf(hint("e1", 1), hint("e2", 2), hint("e3", 3)))

        assertEquals(listOf(PublishDecision.PUBLISHED, PublishDecision.PUBLISHED, PublishDecision.PUBLISHED), decisions)
        assertEquals(1, transport.batches.size)
        assertEquals(3, transport.batches.single().second.size)
    }

    @Test
    fun `batch is dropped entirely when the commit did not happen`() {
        val transport = RecordingTransport()
        val service = RealtimePublishService(transport, 10, clock)

        val decisions = service.publishBatch(false, listOf(hint("e1", 1), hint("e2", 2)))

        assertEquals(listOf(PublishDecision.DROPPED_NOT_COMMITTED, PublishDecision.DROPPED_NOT_COMMITTED), decisions)
        assertTrue(transport.batches.isEmpty())
    }

    @Test
    fun `duplicate inside a batch is suppressed while the rest publish`() {
        val transport = RecordingTransport()
        val service = RealtimePublishService(transport, 10, clock)

        val decisions = service.publishBatch(true, listOf(hint("e1", 1), hint("e1", 1), hint("e2", 2)))

        assertEquals(listOf(PublishDecision.PUBLISHED, PublishDecision.DROPPED_DUPLICATE, PublishDecision.PUBLISHED), decisions)
        assertEquals(2, transport.batches.single().second.size)
    }
}
