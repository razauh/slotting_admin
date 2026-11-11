package com.slotting.admin.ops

import org.junit.jupiter.api.Test
import java.time.Clock
import java.time.Instant
import java.time.LocalDate
import java.time.ZoneOffset
import kotlin.test.assertEquals
import kotlin.test.assertNull
import kotlin.test.assertTrue

class OpsWatchServiceTest {
    private val clock = Clock.fixed(Instant.parse("2026-11-10T09:00:00Z"), ZoneOffset.UTC)

    private fun service() = OpsWatchService(InMemoryOpsNoticeRepository(), clock)

    @Test
    fun `expected 200 opens no notice`() {
        val watch = service()

        assertNull(watch.jwtEdge(200))
        assertTrue(watch.notices().isEmpty())
    }

    @Test
    fun `edge rejection opens one critical notice and dedupes the cause`() {
        val watch = service()

        val first = watch.jwtEdge(401)
        val second = watch.jwtEdge(403)

        assertEquals(OpsSeverity.CRITICAL, first?.severity)
        assertEquals("JWT_EDGE", first?.classTag)
        assertNull(second)
        assertEquals(1, watch.notices().size)
    }

    @Test
    fun `jwks key set change opens an informational notice`() {
        val watch = service()

        val notice = watch.jwtEdge(200, jwksHash = "new-hash", previousJwksHash = "old-hash")

        assertEquals(OpsSeverity.INFO, notice?.severity)
        assertEquals("JWT_EDGE_JWKS_CHANGE", notice?.cause)
    }

    @Test
    fun `exposure drift opens a warning notice`() {
        val watch = service()

        val notice = watch.exposure(404, expected = 200)

        assertEquals(OpsSeverity.WARNING, notice?.severity)
        assertEquals("EXPOSURE_DRIFT", notice?.classTag)
    }

    @Test
    fun `budget or kill switch flip opens a warning notice`() {
        val watch = service()

        val notice = watch.budgetFlip(current = true, expected = false)

        assertEquals(OpsSeverity.WARNING, notice?.severity)
        assertEquals("KILLSWITCH_FLIP", notice?.classTag)
    }

    @Test
    fun `unscheduled decision raises a light reminder`() {
        val watch = service()
        val row = OpsDecision("JWT_KEYS_TIMELINE", owner = null, dueDate = null, status = OpsDecisionStatus.UNSCHEDULED, reopenTrigger = "secret rotation announced")

        val notices = watch.registryEscalations(listOf(row), LocalDate.parse("2026-11-10"))

        assertEquals(1, notices.size)
        assertEquals(OpsSeverity.INFO, notices.single().severity)
        assertEquals("DECISION_UNSCHEDULED:JWT_KEYS_TIMELINE", notices.single().cause)
    }

    @Test
    fun `scheduled decision escalates at T-1 and when overdue`() {
        val watch = service()
        val due = LocalDate.parse("2026-11-11")
        val row = OpsDecision("REALTIME_PAYLOAD_SCOPE", owner = "ops", dueDate = due, status = OpsDecisionStatus.SCHEDULED, reopenTrigger = "payload policy review")

        val tMinusOne = watch.registryEscalations(listOf(row), LocalDate.parse("2026-11-10"))
        val overdue = watch.registryEscalations(listOf(row), LocalDate.parse("2026-11-12"))

        assertEquals("DECISION_T_MINUS_ONE:REALTIME_PAYLOAD_SCOPE", tMinusOne.single().cause)
        assertEquals(OpsSeverity.WARNING, tMinusOne.single().severity)
        assertEquals("DECISION_OVERDUE:REALTIME_PAYLOAD_SCOPE", overdue.single().cause)
        assertEquals(OpsSeverity.CRITICAL, overdue.single().severity)
    }

    @Test
    fun `ack is idempotent`() {
        val watch = service()
        val notice = watch.jwtEdge(401)!!

        assertTrue(watch.ack(notice.cause))
        assertTrue(watch.ack(notice.cause))
        assertEquals(1, watch.notices().size)
    }
}
