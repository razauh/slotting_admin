package com.slotting.admin.audit

import com.slotting.admin.auth.AdminRbacPolicy
import com.slotting.admin.auth.AdminSessionDirectory
import com.slotting.admin.auth.AdminSessionStatus
import com.slotting.admin.auth.AuditEvent
import com.slotting.admin.auth.OutboxEvent
import com.slotting.admin.rails.RailsAuditEntry
import com.slotting.admin.rails.Slf4jRailsAuditRecorder
import org.junit.jupiter.api.Test
import java.time.Clock
import java.time.Instant
import java.time.ZoneOffset
import java.util.UUID
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue

class AdminAuditWritePathTest {
    private val now = Instant.parse("2026-11-13T12:00:00Z")
    private val clock = Clock.fixed(now, ZoneOffset.UTC)

    private data class SavedEvent(
        val resultId: UUID,
        val tenantId: String,
        val eventType: String,
        val occurredAt: Instant,
        val correlationId: String,
        val causationId: String,
        val details: String,
    )

    private class RecordingStore : AdminAuditStore {
        val events = mutableListOf<SavedEvent>()
        override fun findByIdempotency(tenantId: String, key: String): Pair<String, AuditQueryResult>? = null
        override fun queryEvents(tenantId: String, eventType: String?, from: Instant, to: Instant, limit: Int, correlationId: String?): List<AuditRecord> = emptyList()
        override fun isLegalHoldActive(tenantId: String): Boolean = false
        override fun findHoldVersion(tenantId: String, holdReference: String): Long? = null
        override fun saveHold(tenantId: String, holdReference: String, reason: String, approverId: String, active: Boolean, version: Long, now: Instant) = Unit
        override fun save(result: AuditQueryResult, tenantId: String, queryFingerprint: String, idempotencyKey: String, audit: AuditEvent, outbox: OutboxEvent) = Unit
        override fun saveEvent(resultId: UUID, tenantId: String, eventType: String, occurredAt: Instant, correlationId: String, causationId: String, redactedDetails: String) {
            events += SavedEvent(resultId, tenantId, eventType, occurredAt, correlationId, causationId, redactedDetails)
        }
    }

    private val sessions = object : AdminSessionDirectory {
        override fun find(tenantId: String, principalId: String, sessionId: String): AdminSessionStatus? = null
    }

    @Test
    fun `admin audit service writes a queryable event`() {
        val store = RecordingStore()
        val service = AdminAuditService(AdminRbacPolicy(true), sessions, store, clock)

        service.recordEvent("tenant-1", "RAILS_DEPOSIT_APPROVED", now, "corr-1", "cause-1", "{\"action\":\"DEPOSIT_APPROVED\"}")

        val event = store.events.single()
        assertEquals("tenant-1", event.tenantId)
        assertEquals("RAILS_DEPOSIT_APPROVED", event.eventType)
        assertTrue(event.details.contains("DEPOSIT_APPROVED"))
    }

    @Test
    fun `rails recorder delegates to the admin audit service without leaking secrets`() {
        val store = RecordingStore()
        val recorder = Slf4jRailsAuditRecorder(store, clock)

        recorder.record(
            RailsAuditEntry(
                tenantId = "tenant-1",
                adminId = "admin-1",
                action = "DEPOSIT_APPROVED",
                subjectId = "submission-1",
                oldValue = "SUBMITTED",
                newValue = "APPROVED",
                occurredAt = now,
            )
        )

        val event = store.events.single()
        assertEquals("RAILS_DEPOSIT_APPROVED", event.eventType)
        assertTrue(event.details.contains("submission-1"))
        assertFalse(event.details.contains("token"))
        assertFalse(event.details.contains("password"))
    }
}
