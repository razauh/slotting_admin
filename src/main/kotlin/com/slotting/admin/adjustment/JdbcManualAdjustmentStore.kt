package com.slotting.admin.adjustment

import com.slotting.admin.auth.*
import org.springframework.jdbc.core.JdbcTemplate
import org.springframework.stereotype.Repository
import org.springframework.transaction.annotation.Transactional
import java.sql.ResultSet
import java.util.UUID

@Repository
class JdbcManualAdjustmentStore(private val jdbc: JdbcTemplate) : ManualAdjustmentStore {
    override fun findByIdempotency(tenantId: String, key: String) = jdbc.query(
        "select result_id, query_fingerprint, adjustment_reference, state, currency_code, total_debits, total_credits, maker_id, second_approver_id, posting_reference, receipt_reference, evidence_reference, server_version, occurred_at from admin_manual_adjustment_result where tenant_id = ? and idempotency_key = ?",
        { rs, _ -> rs.toResult() }, tenantId, key
    ).firstOrNull()

    override fun findItem(tenantId: String, adjustmentReference: String) = jdbc.query(
        "select adjustment_reference, state, currency_code, total_debits, total_credits, maker_id, second_approver_id, posting_reference, server_version from admin_manual_adjustment_batch where tenant_id = ? and adjustment_reference = ?",
        { rs, _ ->
            ManualAdjustmentBatch(
                adjustmentReference = rs.getString("adjustment_reference"),
                state = ManualAdjustmentState.valueOf(rs.getString("state")),
                currencyCode = rs.getString("currency_code"),
                legs = emptyList(),
                totalDebitsMinorUnits = rs.getLong("total_debits"),
                totalCreditsMinorUnits = rs.getLong("total_credits"),
                makerId = rs.getString("maker_id"),
                secondApproverId = rs.getString("second_approver_id"),
                serverVersion = rs.getLong("server_version"),
                postingReference = rs.getString("posting_reference"),
            )
        },
        tenantId, adjustmentReference
    ).firstOrNull()

    @Transactional
    override fun save(
        result: ManualAdjustmentResult,
        tenantId: String,
        reason: ManualAdjustmentReason,
        evidenceReference: String,
        queryFingerprint: String,
        idempotencyKey: String,
        audit: AuditEvent,
        outbox: OutboxEvent,
    ) {
        val existing = findItem(tenantId, result.item.adjustmentReference)
        if (existing == null) {
            jdbc.update(
                "insert into admin_manual_adjustment_batch(tenant_id, adjustment_reference, state, currency_code, total_debits, total_credits, maker_id, second_approver_id, posting_reference, server_version, updated_at) values (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                tenantId, result.item.adjustmentReference, result.item.state.name, result.item.currencyCode, result.totalDebits, result.totalCredits, result.item.makerId, result.item.secondApproverId, result.item.postingReference, result.item.serverVersion, result.serverTime
            )
        } else {
            jdbc.update(
                "update admin_manual_adjustment_batch set state = ?, second_approver_id = ?, posting_reference = ?, server_version = ?, updated_at = ? where tenant_id = ? and adjustment_reference = ? and server_version = ?",
                result.item.state.name, result.item.secondApproverId, result.item.postingReference, result.item.serverVersion, result.serverTime, tenantId, result.item.adjustmentReference, result.item.serverVersion - 1
            )
        }

        jdbc.update(
            "insert into admin_manual_adjustment_result(result_id, tenant_id, adjustment_reference, query_fingerprint, reason_code, evidence_reference, state, currency_code, total_debits, total_credits, maker_id, second_approver_id, posting_reference, receipt_reference, server_version, occurred_at, idempotency_key, correlation_id, causation_id) values (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            result.resultId, tenantId, result.item.adjustmentReference, queryFingerprint, reason.name, evidenceReference, result.item.state.name, result.item.currencyCode, result.totalDebits, result.totalCredits, result.item.makerId, result.item.secondApproverId, result.item.postingReference, result.receiptReference, result.item.serverVersion, result.serverTime, idempotencyKey, audit.correlationId, audit.causationId
        )
        jdbc.update(
            "insert into admin_operation(result_id, tenant_id, operation_type, created_at) values (?, ?, ?, ?)",
            result.resultId, tenantId, "MANUAL_ADJUSTMENT", result.serverTime
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

    private fun ResultSet.toResult(): Pair<String, ManualAdjustmentResult> {
        val id = getObject("result_id", UUID::class.java)
        val debits = getLong("total_debits")
        val credits = getLong("total_credits")
        val batch = ManualAdjustmentBatch(
            adjustmentReference = getString("adjustment_reference"),
            state = ManualAdjustmentState.valueOf(getString("state")),
            currencyCode = getString("currency_code"),
            legs = emptyList(),
            totalDebitsMinorUnits = debits,
            totalCreditsMinorUnits = credits,
            makerId = getString("maker_id"),
            secondApproverId = getString("second_approver_id"),
            serverVersion = getLong("server_version"),
            postingReference = getString("posting_reference"),
        )
        val res = ManualAdjustmentResult(
            resultId = id,
            item = batch,
            isBalanced = debits == credits && debits > 0,
            totalDebits = debits,
            totalCredits = credits,
            receiptReference = getString("receipt_reference"),
            serverTime = getTimestamp("occurred_at").toInstant(),
            evidenceReference = getString("evidence_reference"),
        )
        return getString("query_fingerprint") to res
    }
}
