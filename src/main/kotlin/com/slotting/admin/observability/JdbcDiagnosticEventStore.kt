package com.slotting.admin.observability

import org.springframework.jdbc.core.JdbcTemplate
import org.springframework.stereotype.Repository
import java.sql.ResultSet
import java.time.Clock
import java.time.Instant
import java.util.UUID

enum class DiagnosticDeliveryState {
    PENDING,
    SENT,
    FAILED,
}

data class StoredDiagnosticEvent(
    val tenantId: String,
    val eventId: UUID,
    val payloadDigest: String,
    val payloadJson: String,
    val deliveryState: DiagnosticDeliveryState,
    val attemptCount: Int,
    val nextAttemptAt: Instant?,
    val lastError: String?,
    val sentAt: Instant?,
    val sinkReceiptId: String?,
    val serverReceivedAt: Instant,
    val createdAt: Instant,
)

class DiagnosticEventConflictException(message: String) : IllegalStateException(message)

interface DiagnosticEventStore {
    fun save(tenantId: String, envelope: DiagnosticEventEnvelope): StoredDiagnosticEvent
    fun find(tenantId: String, eventId: UUID): StoredDiagnosticEvent?
}

@Repository
class JdbcDiagnosticEventStore(
    private val jdbc: JdbcTemplate,
    private val clock: Clock = Clock.systemUTC(),
) : DiagnosticEventStore {
    override fun save(tenantId: String, envelope: DiagnosticEventEnvelope): StoredDiagnosticEvent {
        require(tenantId.isNotBlank()) { "tenantId must not be blank" }
        val digest = envelope.payloadDigest()
        val payloadJson = DiagnosticEnvelopeSerializer.toJson(envelope)
        val inserted = jdbc.update(
            """
            insert into diagnostic_event(
                tenant_id, event_id, payload_digest, schema_version, occurred_at, server_received_at,
                event_type, severity, source_app, component, environment, correlation_id, payload_json,
                delivery_state, attempt_count, created_at
            ) values (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, cast(? as jsonb), ?, ?, ?)
            on conflict (tenant_id, event_id) do nothing
            """.trimIndent(),
            tenantId,
            envelope.eventId,
            digest,
            envelope.schemaVersion,
            java.sql.Timestamp.from(envelope.occurredAt),
            java.sql.Timestamp.from(envelope.serverReceivedAt),
            envelope.eventType,
            envelope.severity.name,
            envelope.sourceApp,
            envelope.component,
            envelope.environment,
            envelope.correlationId,
            payloadJson,
            DiagnosticDeliveryState.PENDING.name,
            0,
            java.sql.Timestamp.from(clock.instant()),
        )

        val stored = find(tenantId, envelope.eventId)
            ?: throw IllegalStateException("Diagnostic event insert did not persist")
        if (inserted == 0 && stored.payloadDigest != digest) {
            throw DiagnosticEventConflictException("Diagnostic event identity was reused with a conflicting payload")
        }
        return stored
    }

    override fun find(tenantId: String, eventId: UUID): StoredDiagnosticEvent? = jdbc.query(
        "select * from diagnostic_event where tenant_id = ? and event_id = ?",
        { rs, _ -> rs.toStored() },
        tenantId,
        eventId,
    ).firstOrNull()

    fun findPending(limit: Int = 100): List<StoredDiagnosticEvent> {
        require(limit in 1..1_000) { "Pending diagnostic limit must be between 1 and 1000" }
        return jdbc.query(
            """
            select * from diagnostic_event
            where delivery_state = ? and (next_attempt_at is null or next_attempt_at <= ?)
            order by created_at asc
            limit ?
            """.trimIndent(),
            { rs, _ -> rs.toStored() },
            DiagnosticDeliveryState.PENDING.name,
            java.sql.Timestamp.from(clock.instant()),
            limit,
        )
    }

    fun markSent(
        tenantId: String,
        eventId: UUID,
        sinkReceiptId: String,
        sentAt: Instant = clock.instant(),
    ): StoredDiagnosticEvent {
        require(sinkReceiptId.isNotBlank()) { "A sink receipt is required before marking delivery sent" }
        val updated = jdbc.update(
            """
            update diagnostic_event
            set delivery_state = ?, sent_at = ?, sink_receipt_id = ?, last_error = null, next_attempt_at = null
            where tenant_id = ? and event_id = ?
            """.trimIndent(),
            DiagnosticDeliveryState.SENT.name,
            java.sql.Timestamp.from(sentAt),
            sinkReceiptId,
            tenantId,
            eventId,
        )
        if (updated == 0) {
            throw IllegalArgumentException("Diagnostic event not found for tenant")
        }
        return find(tenantId, eventId) ?: throw IllegalStateException("Diagnostic event disappeared after delivery update")
    }

    fun recordFailure(
        tenantId: String,
        eventId: UUID,
        safeError: String,
        nextAttemptAt: Instant,
        terminal: Boolean = false,
    ): StoredDiagnosticEvent {
        val updated = jdbc.update(
            """
            update diagnostic_event
            set attempt_count = attempt_count + 1,
                delivery_state = ?,
                last_error = ?,
                next_attempt_at = ?
            where tenant_id = ? and event_id = ? and delivery_state = ?
            """.trimIndent(),
            if (terminal) DiagnosticDeliveryState.FAILED.name else DiagnosticDeliveryState.PENDING.name,
            safeError.take(512),
            if (terminal) null else java.sql.Timestamp.from(nextAttemptAt),
            tenantId,
            eventId,
            DiagnosticDeliveryState.PENDING.name,
        )
        if (updated == 0) {
            throw IllegalArgumentException("Diagnostic event is not pending for tenant")
        }
        return find(tenantId, eventId) ?: throw IllegalStateException("Diagnostic event disappeared after failure update")
    }

    private fun ResultSet.toStored() = StoredDiagnosticEvent(
        tenantId = getString("tenant_id"),
        eventId = getObject("event_id", UUID::class.java),
        payloadDigest = getString("payload_digest"),
        payloadJson = getString("payload_json"),
        deliveryState = DiagnosticDeliveryState.valueOf(getString("delivery_state")),
        attemptCount = getInt("attempt_count"),
        nextAttemptAt = getTimestamp("next_attempt_at")?.toInstant(),
        lastError = getString("last_error"),
        sentAt = getTimestamp("sent_at")?.toInstant(),
        sinkReceiptId = getString("sink_receipt_id"),
        serverReceivedAt = getTimestamp("server_received_at").toInstant(),
        createdAt = getTimestamp("created_at").toInstant(),
    )
}
