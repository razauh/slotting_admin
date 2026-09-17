package com.slotting.admin.auth

import org.springframework.jdbc.core.JdbcTemplate
import org.springframework.stereotype.Repository
import org.springframework.transaction.annotation.Transactional
import java.sql.ResultSet
import java.time.Instant
import java.util.UUID

@Repository
class JdbcAuthenticationStore(private val jdbc: JdbcTemplate) : AuthenticationStore {
    override fun currentVersion(tenantId: String, principalId: String): Long =
        jdbc.queryForObject(
            "select coalesce(max(server_version), 0) from admin_mfa_authentication where tenant_id = ? and principal_id = ?",
            Long::class.java, tenantId, principalId,
        ) ?: 0L

    override fun findByIdempotency(tenantId: String, key: String): Pair<String, AuthenticationResult>? =
        jdbc.query(
            "select result_id, request_fingerprint, state, authenticated_at, expires_at, server_version from admin_mfa_authentication where tenant_id = ? and idempotency_key = ?",
            { rs, _ -> rs.toResult() }, tenantId, key,
        ).firstOrNull()

    @Transactional
    override fun save(result: AuthenticationResult, tenantId: String, principalId: String, sessionId: String, idempotencyKey: String, requestFingerprint: String, audit: AuditEvent, outbox: OutboxEvent) {
        jdbc.update(
            "insert into admin_mfa_authentication(result_id, tenant_id, principal_id, session_id, state, server_version, authenticated_at, expires_at, idempotency_key, request_fingerprint, correlation_id, causation_id) values (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            result.resultId, tenantId, principalId, sessionId, result.state.name, result.serverVersion, result.serverTime, result.expiresAt, idempotencyKey, requestFingerprint, audit.correlationId, audit.causationId,
        )
        jdbc.update("insert into admin_operation(result_id, tenant_id, operation_type, created_at) values (?, ?, ?, ?)", result.resultId, tenantId, "ADMIN_MFA_AUTHENTICATION", result.serverTime)
        jdbc.update(
            "insert into admin_audit_event(event_id, result_id, tenant_id, event_type, occurred_at, correlation_id, causation_id, redacted_details) values (?, ?, ?, ?, ?, ?, ?, cast(? as jsonb))",
            audit.eventId, audit.resultId, tenantId, audit.type, audit.occurredAt, audit.correlationId, audit.causationId, "{}",
        )
        jdbc.update(
            "insert into admin_outbox_event(event_id, result_id, tenant_id, event_type, created_at, payload) values (?, ?, ?, ?, ?, cast(? as jsonb))",
            outbox.eventId, outbox.resultId, tenantId, outbox.type, outbox.createdAt, "{}",
        )
    }

    private fun ResultSet.toResult(): Pair<String, AuthenticationResult> {
        val id = getObject("result_id", UUID::class.java)
        val result = AuthenticationResult(
            id,
            AuthenticationState.valueOf(getString("state")),
            getTimestamp("authenticated_at").toInstant(),
            getLong("server_version"),
            getTimestamp("expires_at").toInstant(),
            evidenceReference = "admin-auth:$id",
        )
        return getString("request_fingerprint") to result
    }
}
