package com.slotting.admin.ops

import org.junit.jupiter.api.Test
import java.time.Clock
import java.time.Duration
import java.time.Instant
import java.time.ZoneOffset
import kotlin.test.assertEquals
import kotlin.test.assertTrue

class OpsWatchRetentionServiceTest {
    private val now = Instant.parse("2026-11-13T12:00:00Z")
    private val clock = Clock.fixed(now, ZoneOffset.UTC)

    private class FakeRetentionStore : RetentionStore {
        val revocations = mutableListOf<Instant>()
        val storage = mutableListOf<Instant>()

        override fun countRevocations(): Int = revocations.size
        override fun countRevocationsBefore(cutoff: Instant): Int = revocations.count { it.isBefore(cutoff) }
        override fun oldestRevocationAt(): Instant? = revocations.minOrNull()
        override fun deleteRevocationsBefore(cutoff: Instant): Int {
            val before = revocations.size
            revocations.removeAll { it.isBefore(cutoff) }
            return before - revocations.size
        }
        override fun countExpiredStorage(now: Instant): Int = storage.count { it.isBefore(now) }
        override fun countStorage(): Int = storage.size
        override fun deleteExpiredStorage(now: Instant): Int {
            val before = storage.size
            storage.removeAll { it.isBefore(now) }
            return before - storage.size
        }
    }

    @Test
    fun `revocation TTL boundary prunes older than seven days and retains newer`() {
        val store = FakeRetentionStore()
        store.revocations += now.minus(Duration.ofDays(7)).minusSeconds(1)
        store.revocations += now.minus(Duration.ofDays(7)).plusSeconds(1)
        store.storage += now.minusSeconds(1)
        store.storage += now.plusSeconds(1)
        val service = OpsWatchRetentionService(store, clock)

        val result = service.prune()

        assertEquals(1, result.revocationsDeleted)
        assertEquals(1, result.revocationsRemaining)
        assertEquals(1, result.storageDeleted)
        assertEquals(1, result.storageRemaining)
        assertTrue(result.revocationsRemaining <= 10_000)
        assertTrue(result.oldestRevocationDays <= 30)
        assertTrue(result.strandedRevocations <= 500)
    }

    @Test
    fun `prune leaves a quiet D4 state`() {
        val store = FakeRetentionStore()
        repeat(600) { store.revocations += now.minus(Duration.ofDays(8)) }
        store.revocations += now.minus(Duration.ofDays(1))
        val service = OpsWatchRetentionService(store, clock)

        val result = service.prune()

        assertEquals(600, result.revocationsDeleted)
        assertEquals(1, result.revocationsRemaining)
        assertEquals(0, result.strandedRevocations)
        assertTrue(result.oldestRevocationDays <= 30)
    }
}
