package com.slotting.admin.player

import com.slotting.admin.auth.AuditEvent
import com.slotting.admin.auth.OutboxEvent
import org.springframework.jdbc.core.JdbcTemplate
import org.springframework.stereotype.Repository
import org.springframework.transaction.annotation.Transactional
import java.sql.ResultSet
import java.time.Instant
import java.util.UUID

@Repository
class JdbcPlayerProfileSearchStore(private val jdbc: JdbcTemplate) : ProfileSearchStore {
    override fun findByIdempotency(tenantId: String, key: String): Pair<String, ProfileSearchResult>? =
        jdbc.query(
            "select result_id, query_fingerprint, state, result_count, occurred_at, server_version from admin_player_profile_search where tenant_id = ? and idempotency_key = ?",
            { rs, _ -> rs.toResult() }, tenantId, key,
        ).firstOrNull()

    override fun currentVersion(tenantId: String): Long =
        jdbc.queryForObject(
            "select coalesce(max(server_version), 0) from admin_player_profile_search where tenant_id = ?",
            Long::class.java, tenantId,
        ) ?: 0L

    @Transactional
    override fun save(result: ProfileSearchResult, tenantId: String, idempotencyKey: String, queryFingerprint: String, accessReason: AccessReasonCode, audit: AuditEvent, outbox: OutboxEvent) {
        jdbc.update(
            "insert into admin_player_profile_search(result_id, tenant_id, query_fingerprint, access_reason, state, result_count, server_version, occurred_at, idempotency_key, correlation_id, causation_id) values (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            result.resultId, tenantId, queryFingerprint, accessReason.name, result.state.name, result.profiles.size, result.serverVersion, result.serverTime, idempotencyKey, audit.correlationId, audit.causationId,
        )
        jdbc.update("insert into admin_operation(result_id, tenant_id, operation_type, created_at) values (?, ?, ?, ?)", result.resultId, tenantId, "PLAYER_PROFILE_SEARCH", result.serverTime)
        jdbc.update(
            "insert into admin_audit_event(event_id, result_id, tenant_id, event_type, occurred_at, correlation_id, causation_id, redacted_details) values (?, ?, ?, ?, ?, ?, ?, cast(? as jsonb))",
            audit.eventId, audit.resultId, tenantId, audit.type, audit.occurredAt, audit.correlationId, audit.causationId, "{}",
        )
        jdbc.update(
            "insert into admin_outbox_event(event_id, result_id, tenant_id, event_type, created_at, payload) values (?, ?, ?, ?, ?, cast(? as jsonb))",
            outbox.eventId, outbox.resultId, tenantId, outbox.type, outbox.createdAt, "{}",
        )
    }

    private fun ResultSet.toResult(): Pair<String, ProfileSearchResult> {
        val id = getObject("result_id", UUID::class.java)
        val now = getTimestamp("occurred_at").toInstant()
        return getString("query_fingerprint") to ProfileSearchResult(
            id,
            ProfileSearchState.valueOf(getString("state")),
            emptyList(),
            now,
            getLong("server_version"),
            "player-profile-search:$id",
        )
    }
}
