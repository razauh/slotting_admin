package com.slotting.admin.reconciliation

import com.slotting.admin.auth.*
import org.springframework.jdbc.core.JdbcTemplate
import org.springframework.stereotype.Repository
import org.springframework.transaction.annotation.Transactional
import java.sql.ResultSet
import java.util.UUID

@Repository
class JdbcReconciliationExceptionStore(private val jdbc: JdbcTemplate) : ReconciliationExceptionStore {
    override fun findByIdempotency(tenantId: String, key: String) = jdbc.query(
        "select result_id, query_fingerprint, evidence_reference, exception_reference, report_reference, currency_code, discrepancy_amount, external_reference, ledger_entry_reference, state, assignee_id, reason_code, resolution_notes, approver_id, checksum_sha256, server_version, occurred_at from admin_reconciliation_exception_result where tenant_id = ? and idempotency_key = ?",
        { rs, _ -> rs.toResult() }, tenantId, key
    ).firstOrNull()

    override fun findException(tenantId: String, exceptionReference: String) = jdbc.query(
        "select exception_reference, report_reference, currency_code, discrepancy_amount, external_reference, ledger_entry_reference, state, assignee_id, reason_code, resolution_notes, approver_id, checksum_sha256, server_version from admin_reconciliation_exception where tenant_id = ? and exception_reference = ?",
        { rs, _ ->
            ReconciliationException(
                exceptionReference = rs.getString("exception_reference"),
                reportReference = rs.getString("report_reference"),
                currencyCode = rs.getString("currency_code"),
                discrepancyMinorUnits = rs.getLong("discrepancy_amount"),
                externalReference = rs.getString("external_reference"),
                ledgerEntryReference = rs.getString("ledger_entry_reference"),
                state = ReconciliationExceptionState.valueOf(rs.getString("state")),
                assigneeId = rs.getString("assignee_id"),
                reasonCode = rs.getString("reason_code"),
                resolutionNotes = rs.getString("resolution_notes"),
                approverId = rs.getString("approver_id"),
                exportChecksumSha256 = rs.getString("checksum_sha256"),
                serverVersion = rs.getLong("server_version"),
            )
        },
        tenantId, exceptionReference
    ).firstOrNull()

    @Transactional
    override fun save(
        result: ReconciliationExceptionResult,
        tenantId: String,
        queryFingerprint: String,
        idempotencyKey: String,
        audit: AuditEvent,
        outbox: OutboxEvent,
    ) {
        val existing = findException(tenantId, result.exception.exceptionReference)
        if (existing == null) {
            jdbc.update(
                "insert into admin_reconciliation_exception(tenant_id, exception_reference, report_reference, currency_code, discrepancy_amount, external_reference, ledger_entry_reference, state, assignee_id, reason_code, resolution_notes, approver_id, checksum_sha256, server_version, updated_at) values (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                tenantId, result.exception.exceptionReference, result.exception.reportReference, result.exception.currencyCode, result.exception.discrepancyMinorUnits, result.exception.externalReference, result.exception.ledgerEntryReference, result.exception.state.name, result.exception.assigneeId, result.exception.reasonCode, result.exception.resolutionNotes, result.exception.approverId, result.exception.exportChecksumSha256, result.exception.serverVersion, result.serverTime
            )
        } else {
            jdbc.update(
                "update admin_reconciliation_exception set state = ?, assignee_id = ?, reason_code = ?, resolution_notes = ?, approver_id = ?, checksum_sha256 = ?, server_version = ?, updated_at = ? where tenant_id = ? and exception_reference = ? and server_version = ?",
                result.exception.state.name, result.exception.assigneeId, result.exception.reasonCode, result.exception.resolutionNotes, result.exception.approverId, result.exception.exportChecksumSha256, result.exception.serverVersion, result.serverTime, tenantId, result.exception.exceptionReference, result.exception.serverVersion - 1
            )
        }

        jdbc.update(
            "insert into admin_reconciliation_exception_result(result_id, tenant_id, exception_reference, query_fingerprint, evidence_reference, report_reference, currency_code, discrepancy_amount, external_reference, ledger_entry_reference, state, assignee_id, reason_code, resolution_notes, approver_id, checksum_sha256, server_version, occurred_at, idempotency_key, correlation_id, causation_id) values (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            result.resultId, tenantId, result.exception.exceptionReference, queryFingerprint, result.evidenceReference, result.exception.reportReference, result.exception.currencyCode, result.exception.discrepancyMinorUnits, result.exception.externalReference, result.exception.ledgerEntryReference, result.exception.state.name, result.exception.assigneeId, result.exception.reasonCode, result.exception.resolutionNotes, result.exception.approverId, result.exception.exportChecksumSha256, result.exception.serverVersion, result.serverTime, idempotencyKey, audit.correlationId, audit.causationId
        )
        jdbc.update(
            "insert into admin_operation(result_id, tenant_id, operation_type, created_at) values (?, ?, ?, ?)",
            result.resultId, tenantId, "RECONCILIATION_EXCEPTION", result.serverTime
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

    private fun ResultSet.toResult(): Pair<String, ReconciliationExceptionResult> {
        val id = getObject("result_id", UUID::class.java)
        val exception = ReconciliationException(
            exceptionReference = getString("exception_reference"),
            reportReference = getString("report_reference"),
            currencyCode = getString("currency_code"),
            discrepancyMinorUnits = getLong("discrepancy_amount"),
            externalReference = getString("external_reference"),
            ledgerEntryReference = getString("ledger_entry_reference"),
            state = ReconciliationExceptionState.valueOf(getString("state")),
            assigneeId = getString("assignee_id"),
            reasonCode = getString("reason_code"),
            resolutionNotes = getString("resolution_notes"),
            approverId = getString("approver_id"),
            exportChecksumSha256 = getString("checksum_sha256"),
            serverVersion = getLong("server_version"),
        )
        val res = ReconciliationExceptionResult(
            resultId = id,
            exception = exception,
            serverTime = getTimestamp("occurred_at").toInstant(),
            evidenceReference = getString("evidence_reference"),
        )
        return getString("query_fingerprint") to res
    }
}
