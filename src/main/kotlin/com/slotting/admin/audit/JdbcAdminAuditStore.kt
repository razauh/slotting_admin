package com.slotting.admin.audit

import com.slotting.admin.auth.*
import org.springframework.jdbc.core.JdbcTemplate
import org.springframework.stereotype.Repository
import org.springframework.transaction.annotation.Transactional
import java.sql.ResultSet
import java.time.Instant
import java.util.UUID

@Repository
class JdbcAdminAuditStore(private val jdbc: JdbcTemplate) : AdminAuditStore {
    override fun findByIdempotency(tenantId: String, key: String) = jdbc.query(
        "select result_id, query_fingerprint, evidence_reference, action, records_count, checksum_sha256, legal_hold_active, server_version, occurred_at from admin_audit_query_result where tenant_id = ? and idempotency_key = ?",
        { rs, _ -> rs.toResult() }, tenantId, key
    ).firstOrNull()

    override fun queryEvents(tenantId: String, eventType: String?, from: Instant, to: Instant, limit: Int): List<AuditRecord> {
        val hold = isLegalHoldActive(tenantId)
        val sql = if (eventType == null) {
            "select event_id, result_id, tenant_id, event_type, occurred_at, correlation_id, causation_id, redacted_details::text from admin_audit_event where tenant_id = ? and occurred_at >= ? and occurred_at <= ? order by occurred_at desc limit ?"
        } else {
            "select event_id, result_id, tenant_id, event_type, occurred_at, correlation_id, causation_id, redacted_details::text from admin_audit_event where tenant_id = ? and event_type = ? and occurred_at >= ? and occurred_at <= ? order by occurred_at desc limit ?"
        }
        val args = if (eventType == null) arrayOf(tenantId, from, to, limit) else arrayOf(tenantId, eventType, from, to, limit)
        return jdbc.query(sql, { rs, _ ->
            AuditRecord(
                eventId = rs.getObject("event_id", UUID::class.java),
                resultId = rs.getObject("result_id", UUID::class.java),
                tenantId = rs.getString("tenant_id"),
                eventType = rs.getString("event_type"),
                occurredAt = rs.getTimestamp("occurred_at").toInstant(),
                correlationId = rs.getString("correlation_id"),
                causationId = rs.getString("causation_id"),
                redactedDetails = rs.getString("redacted_details"),
                legalHold = hold,
            )
        }, *args)
    }

    override fun isLegalHoldActive(tenantId: String): Boolean =
        jdbc.queryForObject(
            "select count(*) > 0 from admin_audit_legal_hold where tenant_id = ? and active = true",
            Boolean::class.java,
            tenantId
        ) ?: false

    override fun findHoldVersion(tenantId: String, holdReference: String): Long? =
        jdbc.query(
            "select server_version from admin_audit_legal_hold where tenant_id = ? and hold_reference = ?",
            { rs, _ -> rs.getLong("server_version") },
            tenantId, holdReference
        ).firstOrNull()

    @Transactional
    override fun saveHold(
        tenantId: String,
        holdReference: String,
        reason: String,
        approverId: String,
        active: Boolean,
        version: Long,
        now: Instant,
    ) {
        val currentVersion = findHoldVersion(tenantId, holdReference)
        if (currentVersion == null) {
            jdbc.update(
                "insert into admin_audit_legal_hold(tenant_id, hold_reference, reason, approver_id, active, applied_at, server_version, updated_at) values (?, ?, ?, ?, ?, ?, ?, ?)",
                tenantId, holdReference, reason, approverId, active, now, version, now
            )
        } else {
            jdbc.update(
                "update admin_audit_legal_hold set reason = ?, approver_id = ?, active = ?, released_at = ?, server_version = ?, updated_at = ? where tenant_id = ? and hold_reference = ? and server_version = ?",
                reason, approverId, active, if (active) null else now, version, now, tenantId, holdReference, currentVersion
            )
        }
    }

    @Transactional
    override fun save(
        result: AuditQueryResult,
        tenantId: String,
        queryFingerprint: String,
        idempotencyKey: String,
        audit: AuditEvent,
        outbox: OutboxEvent,
    ) {
        jdbc.update(
            "insert into admin_audit_query_result(result_id, tenant_id, query_fingerprint, evidence_reference, action, records_count, checksum_sha256, legal_hold_active, server_version, occurred_at, idempotency_key, correlation_id, causation_id) values (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            result.resultId, tenantId, queryFingerprint, result.evidenceReference, result.action.name, result.records.size, result.exportChecksumSha256, result.legalHoldActive, result.serverVersion, result.serverTime, idempotencyKey, audit.correlationId, audit.causationId
        )
        jdbc.update(
            "insert into admin_operation(result_id, tenant_id, operation_type, created_at) values (?, ?, ?, ?)",
            result.resultId, tenantId, "ADMIN_AUDIT", result.serverTime
        )
        jdbc.update(
            "insert into admin_audit_event(event_id, result_id, tenant_id, event_type, occurred_at, correlation_id, causation_id, redacted_details) values (?, ?, ?, ?, ?, ?, ?, cast(? as jsonb))",
            audit.eventId, audit.resultId, tenantId, audit.type, audit.occurredAt, audit.correlationId, audit.causationId, "{}"
        )
        jdbc.update(
            "insert into admin_outbox_event(event_id, result_id, tenant_id, event_type, created_at, payload) values (?, ?, ?, ?, ?, cast(? as jsonb))",
            outbox.eventId, outbox.resultId, tenantId, outbox.type, outbox.createdAt, "{}"
        )
    }

    private fun ResultSet.toResult(): Pair<String, AuditQueryResult> {
        val id = getObject("result_id", UUID::class.java)
        val res = AuditQueryResult(
            resultId = id,
            action = AuditQueryAction.valueOf(getString("action")),
            records = emptyList(),
            exportChecksumSha256 = getString("checksum_sha256"),
            legalHoldActive = getBoolean("legal_hold_active"),
            serverTime = getTimestamp("occurred_at").toInstant(),
            serverVersion = getLong("server_version"),
            evidenceReference = getString("evidence_reference"),
        )
        return getString("query_fingerprint") to res
    }
}
