package com.slotting.admin.finance

import com.slotting.admin.auth.AuditEvent
import com.slotting.admin.auth.OutboxEvent
import com.slotting.admin.player.AccessReasonCode
import org.springframework.jdbc.core.JdbcTemplate
import org.springframework.stereotype.Repository
import org.springframework.transaction.annotation.Transactional
import java.sql.ResultSet
import java.time.Instant
import java.util.UUID

@Repository
class JdbcLedgerTimelineStore(private val jdbc: JdbcTemplate) : LedgerTimelineStore {
    override fun findByIdempotency(tenantId: String, key: String): Pair<String, LedgerTimelineResult>? =
        jdbc.query(
            "select result_id, query_fingerprint, state, ledger_version, entry_count, occurred_at, server_version from admin_ledger_timeline_read where tenant_id = ? and idempotency_key = ?",
            { rs, _ -> rs.toResult() }, tenantId, key,
        ).firstOrNull()

    override fun currentVersion(tenantId: String): Long =
        jdbc.queryForObject(
            "select coalesce(max(server_version), 0) from admin_ledger_timeline_read where tenant_id = ?",
            Long::class.java, tenantId,
        ) ?: 0L

    @Transactional
    override fun save(result: LedgerTimelineResult, tenantId: String, idempotencyKey: String, queryFingerprint: String, accessReason: AccessReasonCode, audit: AuditEvent, outbox: OutboxEvent) {
        jdbc.update(
            "insert into admin_ledger_timeline_read(result_id, tenant_id, query_fingerprint, access_reason, state, ledger_version, entry_count, server_version, occurred_at, idempotency_key, correlation_id, causation_id) values (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            result.resultId, tenantId, queryFingerprint, accessReason.name, result.state.name, result.ledgerVersion, result.entries.size, result.serverVersion, result.serverTime, idempotencyKey, audit.correlationId, audit.causationId,
        )
        jdbc.update("insert into admin_operation(result_id, tenant_id, operation_type, created_at) values (?, ?, ?, ?)", result.resultId, tenantId, "LEDGER_TIMELINE_READ", result.serverTime)
        jdbc.update(
            "insert into admin_audit_event(event_id, result_id, tenant_id, event_type, occurred_at, correlation_id, causation_id, redacted_details) values (?, ?, ?, ?, ?, ?, ?, cast(? as jsonb))",
            audit.eventId, audit.resultId, tenantId, audit.type, audit.occurredAt, audit.correlationId, audit.causationId, "{}",
        )
        jdbc.update(
            "insert into admin_outbox_event(event_id, result_id, tenant_id, event_type, created_at, payload) values (?, ?, ?, ?, ?, cast(? as jsonb))",
            outbox.eventId, outbox.resultId, tenantId, outbox.type, outbox.createdAt, "{}",
        )
    }

    private fun ResultSet.toResult(): Pair<String, LedgerTimelineResult> {
        val id = getObject("result_id", UUID::class.java)
        return getString("query_fingerprint") to LedgerTimelineResult(
            id,
            TimelineState.valueOf(getString("state")),
            emptyList(),
            getLong("ledger_version"),
            getTimestamp("occurred_at").toInstant(),
            getLong("server_version"),
            "ledger-timeline:$id",
        )
    }
}
