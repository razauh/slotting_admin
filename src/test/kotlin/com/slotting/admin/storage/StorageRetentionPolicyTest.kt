package com.slotting.admin.storage

import org.junit.jupiter.api.Test
import java.time.Clock
import java.time.Instant
import java.time.ZoneOffset
import kotlin.test.assertFalse
import kotlin.test.assertTrue

class StorageRetentionPolicyTest {
    private val now = Instant.parse("2026-11-09T12:00:00Z")
    private val clock = Clock.fixed(now, ZoneOffset.UTC)
    private val policy = StorageRetentionPolicy(clock)

    private fun record(expiresAt: Instant, legalHold: Boolean = false) =
        StorageRetentionRecord("player-documents", "tenant/player/evidence.pdf", expiresAt, legalHold)

    @Test
    fun `object past its retention date is purgeable`() {
        assertTrue(policy.isExpired(record(now.minusSeconds(1))))
    }

    @Test
    fun `object inside its retention window is kept`() {
        assertFalse(policy.isExpired(record(now.plusSeconds(3600))))
    }

    @Test
    fun `object at the exact expiry boundary is purgeable`() {
        assertTrue(policy.isExpired(record(now)))
    }

    @Test
    fun `legal hold blocks purge even after expiry`() {
        assertFalse(policy.isExpired(record(now.minusSeconds(86400), legalHold = true)))
    }
}
