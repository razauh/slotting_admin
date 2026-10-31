package com.slotting.admin.observability

import com.fasterxml.jackson.databind.JsonNode
import com.fasterxml.jackson.databind.ObjectMapper
import com.slotting.admin.auth.AdminRole
import com.slotting.admin.auth.AuthErrorCode
import com.slotting.admin.auth.AuthenticatedPrincipal
import com.slotting.admin.auth.AuthenticationFailure
import com.slotting.admin.auth.PrincipalKind
import java.time.Clock
import java.time.Instant
import java.time.ZoneOffset
import java.util.UUID
import java.util.concurrent.ConcurrentHashMap
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertTrue
import org.junit.jupiter.api.Test

class AlphaTc030ContractTest {
    private val mapper = ObjectMapper()
    private val clock = Clock.fixed(Instant.parse("2026-10-31T12:00:00Z"), ZoneOffset.UTC)
    private val principal = AuthenticatedPrincipal(
        id = "player-30",
        tenantId = "tenant-30",
        kind = PrincipalKind.PLAYER,
        roles = emptySet(),
    )

    @Test
    fun `TC-030-R2 partial batch reports per-item outcomes and retry does not duplicate valid events`() {
        val store = InMemoryDiagnosticEventStore()
        val service = DiagnosticIngestionService(store, clock)
        val batch = listOf(
            item("event-valid-1", 2500, "PKR"),
            item("event-invalid", 2500, "INR"),
            item("event-valid-2", 100, "USD"),
        )

        val first = service.ingest(principal, "tenant-30", batch)
        assertEquals(3, first.receivedCount)
        assertEquals(2, first.acceptedCount)
        assertEquals(1, first.rejectedCount)
        assertEquals("INVALID_CURRENCY", first.items.single { it.outcome == DiagnosticIngestionOutcome.REJECTED }.rejectionCode)
        assertEquals(2, store.saved.size)

        val retry = service.ingest(principal, "tenant-30", listOf(batch[0], batch[2]))
        assertEquals(2, retry.duplicateCount)
        assertEquals(2, store.saved.size)
    }

    @Test
    fun `TC-030-R3 expired auth forged tenant oversized payload and rate limit fail closed`() {
        val store = InMemoryDiagnosticEventStore()
        val service = DiagnosticIngestionService(store, clock, maxBatchSize = 2)
        val expired = assertFailsWith<AuthenticationFailure.Rejected> {
            service.ingest(null, "tenant-30", listOf(item("event-auth", 1, "PKR")))
        }
        assertEquals(AuthErrorCode.UNAUTHENTICATED, expired.code)

        val forged = assertFailsWith<AuthenticationFailure.Rejected> {
            service.ingest(principal, "tenant-other", listOf(item("event-forged", 1, "PKR")))
        }
        assertEquals(AuthErrorCode.FORBIDDEN, forged.code)

        assertFailsWith<IllegalArgumentException> {
            service.ingest(principal, "tenant-30", listOf(item("a", 1, "PKR"), item("b", 1, "PKR"), item("c", 1, "PKR")))
        }
        assertEquals(0, store.saved.size)
    }

    @Test
    fun `TC-030-R3 repeated batches are rate limited without leaking tokens`() {
        val store = InMemoryDiagnosticEventStore()
        val service = DiagnosticIngestionService(store, clock, maxBatchesPerWindow = 2)
        service.ingest(principal, "tenant-30", listOf(item("rate-1", 1, "PKR")))
        service.ingest(principal, "tenant-30", listOf(item("rate-2", 1, "PKR")))
        val rate = assertFailsWith<DiagnosticRateLimitExceededException> {
            service.ingest(principal, "tenant-30", listOf(item("rate-3", 1, "PKR")))
        }
        assertTrue(!rate.message.orEmpty().contains("token"))
        assertEquals(2, store.saved.size)
    }

    @Test
    fun `client actor cannot impersonate an administrator`() {
        val store = InMemoryDiagnosticEventStore()
        val service = DiagnosticIngestionService(store, clock)
        val payload = item("event-actor", 1, "PKR").deepCopy<com.fasterxml.jackson.databind.node.ObjectNode>().apply {
            put("adminId", "forged-admin")
            put("actorRole", "SUPER_ADMIN")
        }
        val result = service.ingest(principal, "tenant-30", listOf(payload))
        assertEquals(1, result.acceptedCount)
        val stored = store.saved.values.single()
        val persisted = mapper.readTree(stored.payloadJson)
        assertTrue(persisted.path("adminId").isNull)
        assertEquals("player-30", persisted.path("userId").asText())
    }

    private fun item(id: String, amount: Long, currency: String): JsonNode = mapper.readTree(
        """
        {
          "schemaVersion": 2,
          "eventId": "${UUID.nameUUIDFromBytes(id.toByteArray())}",
          "occurredAtMillis": 1793448000000,
          "eventType": "API_TIMEOUT",
          "severity": "ERROR",
          "sourceApp": "android",
          "component": "crash-data",
          "environment": "connected",
          "correlationId": "corr-$id",
          "amountMinorUnits": $amount,
          "currency": "$currency",
          "message": "failure"
        }
        """.trimIndent()
    )

    private class InMemoryDiagnosticEventStore : DiagnosticEventStore {
        val saved = ConcurrentHashMap<UUID, StoredDiagnosticEvent>()

        override fun save(tenantId: String, envelope: DiagnosticEventEnvelope): StoredDiagnosticEvent {
            val existing = saved[envelope.eventId]
            if (existing != null && existing.payloadDigest != envelope.payloadDigest()) {
                throw DiagnosticEventConflictException("conflict")
            }
            val stored = existing ?: StoredDiagnosticEvent(
                tenantId = tenantId,
                eventId = envelope.eventId,
                payloadDigest = envelope.payloadDigest(),
                payloadJson = DiagnosticEnvelopeSerializer.toJson(envelope),
                deliveryState = DiagnosticDeliveryState.PENDING,
                attemptCount = 0,
                nextAttemptAt = null,
                lastError = null,
                sentAt = null,
                sinkReceiptId = null,
                serverReceivedAt = envelope.serverReceivedAt,
                createdAt = envelope.serverReceivedAt,
            )
            saved[envelope.eventId] = stored
            return stored
        }

        override fun find(tenantId: String, eventId: UUID): StoredDiagnosticEvent? =
            saved[eventId]?.takeIf { it.tenantId == tenantId }
    }
}
