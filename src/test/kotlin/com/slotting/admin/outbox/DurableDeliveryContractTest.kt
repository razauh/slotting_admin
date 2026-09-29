package com.slotting.admin.outbox

import kotlin.test.Test
import kotlin.test.assertNotNull
import kotlin.test.assertTrue
import com.slotting.admin.worker.LeasedOutboxEventRecord
import com.slotting.admin.worker.WorkerOutboxStatus
import java.time.Instant
import java.util.UUID

class DurableDeliveryContractTest {
    @Test
    fun `durable delivery migration is versioned after TC-001`() {
        val migration = javaClass.classLoader.getResource("db/migration/V18__durable_delivery_substrate.sql")

        assertNotNull(migration, "TC-002 must add a durable delivery migration")
    }

    @Test
    fun `production outbox store is JDBC backed`() {
        val storePresent = runCatching {
            Class.forName("com.slotting.admin.outbox.JdbcLeasedOutboxStore")
        }.isSuccess

        assertTrue(storePresent, "production worker composition must not use an in-memory outbox store")
    }

    @Test
    fun `event envelope is forensic but redacts sensitive payload fields`() {
        val event = LeasedOutboxEventRecord(
            eventId = UUID.randomUUID(), tenantId = "tenant-1", topic = "audit", eventType = "AUDIT_RECORDED",
            payload = "{\"subject\":\"subject-1\",\"token\":\"do-not-store\"}",
            correlationId = "corr-1", causationId = "cause-1", idempotencyKey = "idem-1",
            status = WorkerOutboxStatus.PENDING, createdAt = Instant.parse("2026-09-24T00:00:00Z"),
        )

        val envelope = RedactedEventEnvelopeCodec.envelope(event)
        assertTrue(envelope.redactedPayload.contains("subject-1"))
        assertTrue(!envelope.redactedPayload.contains("do-not-store"))
        assertTrue(envelope.redactedPayload != "{}")
    }
}
