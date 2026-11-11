package com.slotting.admin.ops

import org.junit.jupiter.api.Test
import java.time.Clock
import java.time.Instant
import java.time.ZoneOffset
import kotlin.test.assertEquals
import kotlin.test.assertNull
import kotlin.test.assertTrue

class OpsDetectorRunnerTest {
    private val repository = InMemoryOpsNoticeRepository()
    private val clock = Clock.fixed(Instant.parse("2026-11-10T12:00:00Z"), ZoneOffset.UTC)
    private val watch = OpsWatchService(repository, clock)
    private val runner = OpsDetectorRunner(watch, clock)

    @Test
    fun `d4 quiet table raises nothing`() {
        assertNull(runner.retentionHygiene(rows = 100, oldestDays = 5, strandedRevocations = 10))
    }

    @Test
    fun `d4 row growth beyond ten thousand raises a warning`() {
        val notice = runner.retentionHygiene(rows = 10_001, oldestDays = 5, strandedRevocations = 0)
        assertEquals(OpsSeverity.WARNING, notice?.severity)
        assertEquals("RETENTION_GROWTH", notice?.classTag)
    }

    @Test
    fun `d4 stale rows and stranded revocations raise warnings`() {
        val stale = runner.retentionHygiene(rows = 100, oldestDays = 31, strandedRevocations = 0)
        val stranded = runner.retentionHygiene(rows = 100, oldestDays = 5, strandedRevocations = 501)
        assertEquals("RETENTION_GROWTH", stale?.classTag)
        assertEquals("RETENTION_GROWTH", stranded?.classTag)
    }

    @Test
    fun `d3 matrix pass is silent and a leak raises a notice`() {
        assertNull(runner.realtimeMatrix(passed = true, leaked = false, assertions = 7))
        val notice = runner.realtimeMatrix(passed = false, leaked = true, assertions = 7)
        assertEquals("REALTIME_CHANNEL", notice?.classTag)
        assertEquals(OpsSeverity.WARNING, notice?.severity)
    }

    @Test
    fun `d6 reminder fires once and dedupes by cause`() {
        val first = runner.announcementReminder()
        val second = runner.announcementReminder()
        assertEquals("ANNOUNCEMENT_REMINDER", first?.cause)
        assertNull(second)
        assertEquals(1, watch.notices().count { it.cause == "ANNOUNCEMENT_REMINDER" })
    }

    @Test
    fun `d1 expected edge is silent and rejection is critical`() {
        assertNull(runner.jwtEdge(200, "baseline", "baseline"))
        val notice = runner.jwtEdge(401, "baseline", "baseline")
        assertEquals(OpsSeverity.CRITICAL, notice?.severity)
        assertEquals("JWT_EDGE", notice?.classTag)
    }

    @Test
    fun `jwks hash change against the recorded baseline raises info`() {
        val notice = runner.jwtEdge(200, "new-hash", "recorded-baseline")
        assertEquals("JWT_EDGE_JWKS_CHANGE", notice?.cause)
        assertEquals(OpsSeverity.INFO, notice?.severity)
    }

    @Test
    fun `d2 exposure matches the expected root status and raises only on deviation`() {
        assertNull(runner.exposure(401, expected = 401))
        assertEquals("EXPOSURE_DRIFT", runner.exposure(200, expected = 401)?.classTag)
    }

    @Test
    fun `d5 flip raises a warning`() {
        assertNull(runner.budgetFlip(false, expected = false))
        assertEquals("KILLSWITCH_FLIP", runner.budgetFlip(true, expected = false)?.classTag)
    }

    @Test
    fun `cron cadences are the approved ones`() {
        assertEquals("0 15 2 * * *", OpsWatchCadences.DAILY)
        assertEquals("0 30 3 * * MON", OpsWatchCadences.WEEKLY)
        assertTrue(OpsWatchCadences.TIMEZONE.isNotBlank())
    }
}
