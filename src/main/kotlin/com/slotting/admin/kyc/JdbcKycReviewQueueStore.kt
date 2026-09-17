package com.slotting.admin.kyc

import com.slotting.admin.auth.*
import org.springframework.jdbc.core.JdbcTemplate
import org.springframework.stereotype.Repository
import org.springframework.transaction.annotation.Transactional
import java.sql.ResultSet
import java.util.UUID

@Repository
class JdbcKycReviewQueueStore(private val jdbc: JdbcTemplate) : KycQueueStore {
    override fun findByIdempotency(tenantId: String, key: String) = jdbc.query("select result_id, query_fingerprint, case_reference, state, claimed_by, claim_expires_at, server_version, occurred_at from admin_kyc_review_result where tenant_id = ? and idempotency_key = ?", { rs, _ -> rs.toResult() }, tenantId, key).firstOrNull()
    override fun findItem(tenantId: String, caseReference: String) = jdbc.query("select case_reference, state, claimed_by, claim_expires_at, server_version from admin_kyc_review_queue where tenant_id = ? and case_reference = ?", { rs, _ -> KycQueueItem(rs.getString("case_reference"), KycReviewState.valueOf(rs.getString("state")), rs.getString("claimed_by"), rs.getTimestamp("claim_expires_at")?.toInstant(), rs.getLong("server_version")) }, tenantId, caseReference).firstOrNull()
    @Transactional override fun save(result: KycReviewResult, tenantId: String, reason: KycReviewReason, secondApproverId: String?, queryFingerprint: String, idempotencyKey: String, audit: AuditEvent, outbox: OutboxEvent) {
        jdbc.update("update admin_kyc_review_queue set state = ?, claimed_by = ?, claim_expires_at = ?, server_version = ? where tenant_id = ? and case_reference = ? and server_version = ?", result.item.state.name, result.item.claimedBy, result.item.claimExpiresAt, result.item.serverVersion, tenantId, result.item.caseReference, result.item.serverVersion - 1)
        jdbc.update("insert into admin_kyc_review_result(result_id, tenant_id, case_reference, query_fingerprint, reason_code, state, claimed_by, second_approver_id, claim_expires_at, server_version, occurred_at, idempotency_key, correlation_id, causation_id) values (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)", result.resultId, tenantId, result.item.caseReference, queryFingerprint, reason.name, result.item.state.name, result.item.claimedBy, secondApproverId, result.item.claimExpiresAt, result.item.serverVersion, result.serverTime, idempotencyKey, audit.correlationId, audit.causationId)
        jdbc.update("insert into admin_operation(result_id, tenant_id, operation_type, created_at) values (?, ?, ?, ?)", result.resultId, tenantId, "KYC_REVIEW", result.serverTime)
        jdbc.update("insert into admin_audit_event(event_id, result_id, tenant_id, event_type, occurred_at, correlation_id, causation_id, redacted_details) values (?, ?, ?, ?, ?, ?, ?, cast(? as jsonb))", audit.eventId, audit.resultId, tenantId, audit.type, audit.occurredAt, audit.correlationId, audit.causationId, "{}")
        jdbc.update("insert into admin_outbox_event(event_id, result_id, tenant_id, event_type, created_at, payload) values (?, ?, ?, ?, ?, cast(? as jsonb))", outbox.eventId, outbox.resultId, tenantId, outbox.type, outbox.createdAt, "{}")
    }
    private fun ResultSet.toResult(): Pair<String, KycReviewResult> { val id = getObject("result_id", UUID::class.java); val item = KycQueueItem(getString("case_reference"), KycReviewState.valueOf(getString("state")), getString("claimed_by"), getTimestamp("claim_expires_at")?.toInstant(), getLong("server_version")); return getString("query_fingerprint") to KycReviewResult(id, item, getTimestamp("occurred_at").toInstant(), "kyc-review:$id") }
}
