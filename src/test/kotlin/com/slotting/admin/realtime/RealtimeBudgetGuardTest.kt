package com.slotting.admin.realtime

import org.junit.jupiter.api.Test
import java.time.Clock
import java.time.Instant
import java.time.ZoneId
import java.time.ZoneOffset
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue

class RealtimeBudgetGuardTest {
    private class MutableClock(var instant: Instant) : Clock() {
        override fun getZone(): ZoneId = ZoneOffset.UTC
        override fun withZone(zone: ZoneId): Clock = this
        override fun instant(): Instant = instant
    }

    @Test
    fun `messages inside the budget are allowed`() {
        val guard = RealtimeBudgetGuard(3, {}, MutableClock(Instant.parse("2026-11-09T12:00:00Z")))

        assertTrue(guard.allowsPublish("player-a"))
        assertTrue(guard.allowsPublish("player-a"))
        assertTrue(guard.allowsPublish("player-a"))
    }

    @Test
    fun `messages over the budget are refused and alert once`() {
        val alerts = mutableListOf<String>()
        val guard = RealtimeBudgetGuard(2, { alerts.add(it) }, MutableClock(Instant.parse("2026-11-09T12:00:00Z")))

        assertTrue(guard.allowsPublish("player-a"))
        assertTrue(guard.allowsPublish("player-a"))
        assertFalse(guard.allowsPublish("player-a"))
        assertFalse(guard.allowsPublish("player-a"))
        assertEquals(1, alerts.size)
    }

    @Test
    fun `budget is per player`() {
        val guard = RealtimeBudgetGuard(1, {}, MutableClock(Instant.parse("2026-11-09T12:00:00Z")))

        assertTrue(guard.allowsPublish("player-a"))
        assertFalse(guard.allowsPublish("player-a"))
        assertTrue(guard.allowsPublish("player-b"))
    }

    @Test
    fun `budget resets on the next second`() {
        val clock = MutableClock(Instant.parse("2026-11-09T12:00:00Z"))
        val guard = RealtimeBudgetGuard(1, {}, clock)

        assertTrue(guard.allowsPublish("player-a"))
        assertFalse(guard.allowsPublish("player-a"))
        clock.instant = Instant.parse("2026-11-09T12:00:01Z")
        assertTrue(guard.allowsPublish("player-a"))
    }

    @Test
    fun `kill switch blocks every publish without alerting`() {
        val alerts = mutableListOf<String>()
        val guard = RealtimeBudgetGuard(5, { alerts.add(it) }, MutableClock(Instant.parse("2026-11-09T12:00:00Z")))

        guard.setKillSwitch(true)

        assertFalse(guard.allowsPublish("player-a"))
        assertFalse(guard.allowsPublish("player-b"))
        assertTrue(alerts.isEmpty())
    }

    @Test
    fun `kill switch can be released`() {
        val guard = RealtimeBudgetGuard(5, {}, MutableClock(Instant.parse("2026-11-09T12:00:00Z")))

        guard.setKillSwitch(true)
        guard.setKillSwitch(false)

        assertTrue(guard.allowsPublish("player-a"))
    }
}
