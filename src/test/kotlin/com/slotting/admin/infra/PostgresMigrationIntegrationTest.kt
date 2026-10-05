package com.slotting.admin.infra

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue
import com.slotting.admin.outbox.RedactedEventEnvelopeCodec
import com.slotting.admin.worker.LeasedOutboxEventRecord
import com.slotting.admin.worker.WorkerOutboxStatus
import com.slotting.admin.worker.LeasedOutboxStore
import java.time.Instant
import java.util.UUID
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit
import org.testcontainers.containers.PostgreSQLContainer
import org.testcontainers.junit.jupiter.Container
import org.testcontainers.junit.jupiter.Testcontainers
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.boot.test.context.SpringBootTest
import org.springframework.jdbc.core.JdbcTemplate
import org.springframework.test.context.DynamicPropertyRegistry
import org.springframework.test.context.DynamicPropertySource

/**
 * Uses only a Testcontainers-managed ephemeral PostgreSQL instance.
 * The application never discovers or connects to an implicit/live database.
 */
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.NONE)
class PostgresMigrationIntegrationTest {
    companion object {
        @JvmStatic
        @DynamicPropertySource
        fun postgresProperties(registry: DynamicPropertyRegistry) {
            PostgresIntegrationSupport.configureProperties(registry)
        }
    }

    @Autowired
    private lateinit var jdbc: JdbcTemplate

    @Autowired
    private lateinit var outbox: LeasedOutboxStore

    @Test
    fun `clean install creates migration history and operational tables`() {
        val maxRank = jdbc.queryForObject("select max(installed_rank) from flyway_schema_history", Int::class.java)
        assertTrue(maxRank != null && maxRank >= 38)
        assertEquals("40", jdbc.queryForObject("select version from flyway_schema_history order by installed_rank desc limit 1", String::class.java))
        assertEquals(1, jdbc.queryForObject("select count(*) from information_schema.tables where table_name = 'notification_delivery_tracking'", Int::class.java))
        assertEquals(1, jdbc.queryForObject("select count(*) from information_schema.tables where table_name = 'operational_siem_events'", Int::class.java))
        assertEquals(1, jdbc.queryForObject("select count(*) from information_schema.tables where table_name = 'admin_event_envelope'", Int::class.java))
        assertEquals(1, jdbc.queryForObject("select count(*) from information_schema.tables where table_name = 'admin_inbox_consumer'", Int::class.java))
        assertEquals(1, jdbc.queryForObject("select count(*) from information_schema.tables where table_name = 'game_authoritative_round'", Int::class.java))
        assertEquals(1, jdbc.queryForObject("select count(*) from information_schema.tables where table_name = 'game_accepted_bet'", Int::class.java))
        assertEquals(1, jdbc.queryForObject("select count(*) from information_schema.tables where table_name = 'ledger_transaction'", Int::class.java))
        assertEquals(1, jdbc.queryForObject("select count(*) from information_schema.tables where table_name = 'ledger_leg'", Int::class.java))
        assertEquals(1, jdbc.queryForObject("select count(*) from information_schema.tables where table_name = 'password_reset_token'", Int::class.java))
    }

    @Test
    fun `migration health is ready after successful upgrade`() {
        val health = jdbc.queryForObject(
            "select success from flyway_schema_history where version = '38'",
            Boolean::class.java,
        )
        assertTrue(health == true)
    }

    @Test
    fun `committed envelope survives lookup and redacts sensitive fields`() {
        val event = sampleEvent()
        outbox.stageEvent(event)

        val stored = outbox.findById(event.tenantId, event.eventId)!!
        assertTrue(stored.payload.contains("[REDACTED]"))
        assertTrue(!stored.payload.contains("secret-value"))
        assertTrue(jdbc.queryForObject("select count(*) from admin_outbox_delivery where event_id = ?", Int::class.java, event.eventId) == 1)
    }

    @Test
    fun `two workers cannot claim the same delivery and an expired lease is recoverable`() {
        val event = sampleEvent()
        outbox.stageEvent(event)
        val pool = Executors.newFixedThreadPool(2)
        val claims = listOf("worker-a", "worker-b").map { worker ->
            pool.submit<List<LeasedOutboxEventRecord>> {
                outbox.acquireLeases(event.tenantId, worker, 1, 30, Instant.now())
            }
        }.flatMap { it.get() }
        pool.shutdown()
        pool.awaitTermination(10, TimeUnit.SECONDS)
        assertEquals(1, claims.size)
        assertEquals(WorkerOutboxStatus.LEASED, claims.single().status)

        val recovered = outbox.acquireLeases(event.tenantId, "worker-recovery", 1, 30, Instant.now().plusSeconds(31))
        assertEquals(1, recovered.size)
        assertEquals("worker-recovery", recovered.single().leaseOwner)
    }

    private fun sampleEvent() = LeasedOutboxEventRecord(
        eventId = UUID.randomUUID(), tenantId = "tenant-tc002-${UUID.randomUUID()}", topic = "audit",
        eventType = "AUDIT_RECORDED", payload = "{\"subject\":\"subject-1\",\"secret\":\"secret-value\"}",
        correlationId = "corr-tc002", causationId = "cause-tc002", idempotencyKey = UUID.randomUUID().toString(),
        status = WorkerOutboxStatus.PENDING, createdAt = Instant.now(),
    )

}
