package com.slotting.admin.storage

import org.junit.jupiter.api.Test
import java.time.Clock
import java.time.Instant
import java.time.ZoneOffset
import kotlin.test.assertEquals

class StorageRetentionServiceTest {
    private val now = Instant.parse("2026-11-09T12:00:00Z")
    private val policy = StorageRetentionPolicy(Clock.fixed(now, ZoneOffset.UTC))

    private class RecordingTransport(private val succeed: Boolean) : StorageDeleteTransport {
        val calls = mutableListOf<String>()

        override fun delete(bucket: String, objectPath: String): Boolean {
            calls.add("$bucket/$objectPath")
            return succeed
        }
    }

    private fun record(path: String, expiresAt: Instant, legalHold: Boolean = false) =
        StorageRetentionRecord("player-documents", path, expiresAt, legalHold)

    @Test
    fun `expired object is deleted`() {
        val transport = RecordingTransport(true)
        val service = StorageRetentionService(transport, policy)

        val deleted = service.purge(listOf(record("tenant/player/old.pdf", now.minusSeconds(60))))

        assertEquals(listOf("tenant/player/old.pdf"), deleted)
        assertEquals(listOf("player-documents/tenant/player/old.pdf"), transport.calls)
    }

    @Test
    fun `legal hold object is never deleted`() {
        val transport = RecordingTransport(true)
        val service = StorageRetentionService(transport, policy)

        val deleted = service.purge(listOf(record("tenant/player/held.pdf", now.minusSeconds(60), legalHold = true)))

        assertEquals(emptyList(), deleted)
        assertEquals(emptyList(), transport.calls)
    }

    @Test
    fun `missing object is not reported as deleted and the record survives`() {
        val transport = RecordingTransport(false)
        val service = StorageRetentionService(transport, policy)

        val deleted = service.purge(listOf(record("tenant/player/missing.pdf", now.minusSeconds(60))))

        assertEquals(emptyList(), deleted)
        assertEquals(listOf("player-documents/tenant/player/missing.pdf"), transport.calls)
    }

    @Test
    fun `object inside its retention window is skipped`() {
        val transport = RecordingTransport(true)
        val service = StorageRetentionService(transport, policy)

        val deleted = service.purge(listOf(record("tenant/player/fresh.pdf", now.plusSeconds(3600))))

        assertEquals(emptyList(), deleted)
        assertEquals(emptyList(), transport.calls)
    }
}
