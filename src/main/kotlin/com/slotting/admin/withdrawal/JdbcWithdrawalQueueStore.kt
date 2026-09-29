package com.slotting.admin.withdrawal

import com.slotting.admin.auth.AuditEvent
import com.slotting.admin.auth.OutboxEvent
import org.springframework.jdbc.core.JdbcTemplate
import org.springframework.stereotype.Repository
import org.springframework.transaction.annotation.Transactional
import java.sql.ResultSet
import java.time.Instant
import java.util.UUID

@Repository
class JdbcWithdrawalQueueStore(private val jdbc: JdbcTemplate) : WithdrawalQueueStore {
    override fun findByIdempotency(tenantId: String, key: String): Pair<String, WithdrawalReviewResult>? =
        jdbc.query(
            "select result_id, query_fingerprint, withdrawal_reference, state, claimed_by, claim_expires_at, server_version, occurred_at from admin_withdrawal_review_result where tenant_id = ? and idempotency_key = ?",
            { rs, _ -> rs.toResult() }, tenantId, key,
        ).firstOrNull()

    override fun findItem(tenantId: String, withdrawalReference: String): WithdrawalQueueItem? =
        jdbc.query(
            "select withdrawal_reference, state, claimed_by, claim_expires_at, server_version from admin_withdrawal_review_queue where tenant_id = ? and withdrawal_reference = ?",
            { rs, _ -> WithdrawalQueueItem(rs.getString("withdrawal_reference"), WithdrawalReviewState.valueOf(rs.getString("state")), rs.getString("claimed_by"), rs.getTimestamp("claim_expires_at")?.toInstant(), rs.getLong("server_version")) },
            tenantId, withdrawalReference,
        ).firstOrNull()

    override fun countPending(tenantId: String): Long {
        val count = jdbc.queryForObject(
            "select count(*) from admin_withdrawal_review_queue where tenant_id = ? and state in ('QUEUED', 'CLAIMED')",
            Long::class.java,
            tenantId
        )
        return count ?: 0L
    }

    @Transactional
    override fun save(result: WithdrawalReviewResult, tenantId: String, reason: WithdrawalReviewReason, secondApproverId: String?, queryFingerprint: String, idempotencyKey: String, audit: AuditEvent, outbox: OutboxEvent) {
        val updated = jdbc.update(
            "update admin_withdrawal_review_queue set state = ?, claimed_by = ?, claim_expires_at = ?, server_version = ? where tenant_id = ? and withdrawal_reference = ? and server_version = ?",
            result.item.state.name, result.item.claimedBy, result.item.claimExpiresAt, result.item.serverVersion, tenantId, result.item.withdrawalReference, result.item.serverVersion - 1,
        )
        com.slotting.admin.infra.VersionedCasHelper.requireUpdated(updated)
        jdbc.update(
            "insert into admin_withdrawal_review_result(result_id, tenant_id, withdrawal_reference, query_fingerprint, reason_code, state, claimed_by, second_approver_id, claim_expires_at, server_version, occurred_at, idempotency_key, correlation_id, causation_id) values (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            result.resultId, tenantId, result.item.withdrawalReference, queryFingerprint, reason.name, result.item.state.name, result.item.claimedBy, secondApproverId, result.item.claimExpiresAt, result.item.serverVersion, result.serverTime, idempotencyKey, audit.correlationId, audit.causationId,
        )
        jdbc.update("insert into admin_operation(result_id, tenant_id, operation_type, created_at) values (?, ?, ?, ?)", result.resultId, tenantId, "WITHDRAWAL_REVIEW", result.serverTime)
        jdbc.update("insert into admin_audit_event(event_id, result_id, tenant_id, event_type, occurred_at, correlation_id, causation_id, redacted_details) values (?, ?, ?, ?, ?, ?, ?, cast(? as jsonb))", audit.eventId, audit.resultId, tenantId, audit.type, audit.occurredAt, audit.correlationId, audit.causationId, com.slotting.admin.auth.RedactedEventJson.audit(audit))
        jdbc.update("insert into admin_outbox_event(event_id, result_id, tenant_id, event_type, created_at, payload) values (?, ?, ?, ?, ?, cast(? as jsonb))", outbox.eventId, outbox.resultId, tenantId, outbox.type, outbox.createdAt, com.slotting.admin.auth.RedactedEventJson.outbox(outbox, audit))
    }

    private fun ResultSet.toResult(): Pair<String, WithdrawalReviewResult> {
        val id = getObject("result_id", UUID::class.java)
        val item = WithdrawalQueueItem(getString("withdrawal_reference"), WithdrawalReviewState.valueOf(getString("state")), getString("claimed_by"), getTimestamp("claim_expires_at")?.toInstant(), getLong("server_version"))
        return getString("query_fingerprint") to WithdrawalReviewResult(id, item, getTimestamp("occurred_at").toInstant(), "withdrawal-review:$id")
    }
}
