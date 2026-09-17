package com.slotting.admin.auth

import org.springframework.jdbc.core.JdbcTemplate
import org.springframework.stereotype.Repository
import org.springframework.transaction.annotation.Transactional
import java.sql.ResultSet
import java.time.Instant
import java.util.UUID

@Repository
class JdbcAuthorizationStore(private val jdbc: JdbcTemplate) : AuthorizationStore {
    override fun findByIdempotency(tenantId: String, key: String): Pair<String, AuthorizationResult>? =
        jdbc.query(
            "select result_id, request_fingerprint, state, decided_at, expires_at, server_version from admin_authorization_decision where tenant_id = ? and idempotency_key = ?",
            { rs, _ -> rs.toResult() }, tenantId, key,
        ).firstOrNull()

    override fun currentVersion(tenantId: String, ownerId: String): Long =
        jdbc.queryForObject(
            "select coalesce(max(server_version), 0) from admin_authorization_decision where tenant_id = ? and resource_owner_id = ?",
            Long::class.java, tenantId, ownerId,
        ) ?: 0L

    @Transactional
    override fun save(result: AuthorizationResult, tenantId: String, ownerId: String, permission: AdminPermission, idempotencyKey: String, breakGlass: Boolean, expiresAt: Instant, requestFingerprint: String, audit: AuditEvent, outbox: OutboxEvent) {
        jdbc.update(
            "insert into admin_authorization_decision(result_id, tenant_id, resource_owner_id, permission, state, server_version, decided_at, expires_at, break_glass, idempotency_key, request_fingerprint, correlation_id, causation_id) values (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            result.resultId, tenantId, ownerId, permission.name, result.state.name, result.serverVersion, result.serverTime, expiresAt, breakGlass, idempotencyKey, requestFingerprint, audit.correlationId, audit.causationId,
        )
        jdbc.update("insert into admin_operation(result_id, tenant_id, operation_type, created_at) values (?, ?, ?, ?)", result.resultId, tenantId, "ADMIN_AUTHORIZATION", result.serverTime)
        jdbc.update(
            "insert into admin_audit_event(event_id, result_id, tenant_id, event_type, occurred_at, correlation_id, causation_id, redacted_details) values (?, ?, ?, ?, ?, ?, ?, cast(? as jsonb))",
            audit.eventId, audit.resultId, tenantId, audit.type, audit.occurredAt, audit.correlationId, audit.causationId, "{}",
        )
        jdbc.update(
            "insert into admin_outbox_event(event_id, result_id, tenant_id, event_type, created_at, payload) values (?, ?, ?, ?, ?, cast(? as jsonb))",
            outbox.eventId, outbox.resultId, tenantId, outbox.type, outbox.createdAt, "{}",
        )
    }

    private fun ResultSet.toResult(): Pair<String, AuthorizationResult> {
        val id = getObject("result_id", UUID::class.java)
        return getString("request_fingerprint") to AuthorizationResult(
            id,
            AuthorizationState.valueOf(getString("state")),
            getTimestamp("decided_at").toInstant(),
            getTimestamp("expires_at").toInstant(),
            getLong("server_version"),
            evidenceReference = "admin-rbac:$id",
        )
    }
}
