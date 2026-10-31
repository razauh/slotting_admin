package com.slotting.admin.observability

import com.slotting.admin.infra.PostgresIntegrationSupport
import java.time.Clock
import java.time.Duration
import java.time.Instant
import java.time.ZoneOffset
import java.util.UUID
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertNotNull
import kotlin.test.assertTrue
import org.junit.jupiter.api.AfterAll
import org.junit.jupiter.api.Test
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.boot.test.context.SpringBootTest
import org.springframework.jdbc.core.JdbcTemplate
import org.springframework.test.context.DynamicPropertyRegistry
import org.springframework.test.context.DynamicPropertySource

@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.NONE)
class AlphaTc029ContractTest {
    companion object {
        private val databaseUrl = System.getenv("SLOTTING_ADMIN_DATABASE_URL")
            ?: "jdbc:postgresql://127.0.0.1:5432/slotting_admin_ci"
        private val isolatedSchema = PostgresIntegrationSupport.createIsolatedSchema(
            "tc04_${UUID.randomUUID().toString().replace("-", "").take(12)}",
        )

        @JvmStatic
        @DynamicPropertySource
        fun postgresProperties(registry: DynamicPropertyRegistry) {
            val separator = if (databaseUrl.contains('?')) '&' else '?'
            registry.add("spring.datasource.url") { "$databaseUrl${separator}currentSchema=${isolatedSchema.schemaName}" }
            registry.add("spring.datasource.username") { System.getenv("SLOTTING_ADMIN_DATABASE_USERNAME") ?: "ci_runner" }
            registry.add("spring.datasource.password") { System.getenv("SLOTTING_ADMIN_DATABASE_PASSWORD") ?: "ci_test_password_ephemeral" }
            registry.add("spring.flyway.enabled") { "true" }
        }

        @JvmStatic
        @AfterAll
        fun dropIsolatedSchema() {
            isolatedSchema.close()
        }
    }

    @Autowired
    private lateinit var jdbc: JdbcTemplate

    private val now = Instant.parse("2026-10-31T12:00:00Z")
    private val clock = Clock.fixed(now, ZoneOffset.UTC)

    @Test
    fun `TC-029-R1 event survives a new store instance on isolated PostgreSQL`() {
        val store = JdbcDiagnosticEventStore(jdbc, clock)
        val envelope = envelope("event-r1")
        store.save("tenant-29", envelope)

        val restarted = JdbcDiagnosticEventStore(jdbc, clock)
        val stored = restarted.find("tenant-29", envelope.eventId)
        assertNotNull(stored)
        assertEquals(envelope.eventId, stored.eventId)
        assertEquals(DiagnosticDeliveryState.PENDING, stored.deliveryState)
        assertEquals(1, count("tenant-29", envelope.eventId))
    }

    @Test
    fun `TC-029-R2 duplicate identity returns stable receipt while conflicting payload is refused`() {
        val store = JdbcDiagnosticEventStore(jdbc, clock)
        val envelope = envelope("event-r2")
        val first = store.save("tenant-29", envelope)
        val replay = store.save("tenant-29", envelope)
        assertEquals(first.payloadDigest, replay.payloadDigest)
        assertEquals(first.eventId, replay.eventId)
        assertEquals(1, count("tenant-29", envelope.eventId))

        val conflicting = envelope.copy(message = "changed payload")
        assertFailsWith<DiagnosticEventConflictException> {
            store.save("tenant-29", conflicting)
        }
        assertEquals(first.payloadDigest, store.find("tenant-29", envelope.eventId)?.payloadDigest)
        assertEquals(1, count("tenant-29", envelope.eventId))
    }

    @Test
    fun `TC-029-R3 sink timeout stays pending across restart and only a receipt marks sent`() {
        val store = JdbcDiagnosticEventStore(jdbc, clock)
        val envelope = envelope("event-r3")
        store.save("tenant-29", envelope)
        store.recordFailure("tenant-29", envelope.eventId, "sink timeout", now)
        val restarted = JdbcDiagnosticEventStore(jdbc, clock)
        val pending = restarted.findPending()
        assertTrue(pending.any { it.eventId == envelope.eventId && it.deliveryState == DiagnosticDeliveryState.PENDING })
        assertEquals(1, restarted.find("tenant-29", envelope.eventId)?.attemptCount)

        assertFailsWith<IllegalArgumentException> {
            restarted.markSent("tenant-29", envelope.eventId, "")
        }
        assertEquals(DiagnosticDeliveryState.PENDING, restarted.find("tenant-29", envelope.eventId)?.deliveryState)

        val sent = restarted.markSent("tenant-29", envelope.eventId, "receipt-1", now.plus(Duration.ofSeconds(31)))
        assertEquals(DiagnosticDeliveryState.SENT, sent.deliveryState)
        assertEquals("receipt-1", sent.sinkReceiptId)
        assertNotNull(sent.sentAt)
        assertFailsWith<IllegalArgumentException> {
            restarted.recordFailure("tenant-29", envelope.eventId, "late", now.plus(Duration.ofMinutes(1)))
        }
    }

    private fun envelope(eventId: String): DiagnosticEventEnvelope = DiagnosticEnvelopeParser.parse(
        rawJson = """
            {
              "schemaVersion": 2,
              "eventId": "${UUID.nameUUIDFromBytes(eventId.toByteArray())}",
              "occurredAtMillis": ${now.toEpochMilli()},
              "eventType": "API_TIMEOUT",
              "severity": "ERROR",
              "sourceApp": "android",
              "component": "crash-data",
              "environment": "connected",
              "correlationId": "corr-$eventId",
              "amountMinorUnits": 2500,
              "currency": "PKR",
              "message": "timeout"
            }
        """.trimIndent(),
        serverActorId = "player-29",
        serverTenantId = "tenant-29",
        serverActorIsAdmin = false,
        clock = clock,
    )

    private fun count(tenantId: String, eventId: UUID): Int = jdbc.queryForObject(
        "select count(*) from diagnostic_event where tenant_id = ? and event_id = ?",
        Int::class.java,
        tenantId,
        eventId,
    ) ?: 0
}
