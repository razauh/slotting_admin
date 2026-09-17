package com.slotting.admin.reconciliation

import com.slotting.admin.auth.*
import org.springframework.jdbc.core.JdbcTemplate
import org.springframework.stereotype.Repository
import org.springframework.transaction.annotation.Transactional
import java.sql.ResultSet
import java.util.UUID

@Repository
class JdbcReconciliationReportStore(private val jdbc: JdbcTemplate) : ReconciliationReportStore {
    override fun findByIdempotency(tenantId: String, key: String) = jdbc.query(
        "select result_id, query_fingerprint, evidence_reference, report_reference, currency_code, period_start, period_end, total_ledger_debits, total_ledger_credits, total_external_debits, total_external_credits, imbalance_amount, status, reason_code, resolution_notes, approver_id, checksum_sha256, server_version, occurred_at from admin_reconciliation_report_result where tenant_id = ? and idempotency_key = ?",
        { rs, _ -> rs.toResult() }, tenantId, key
    ).firstOrNull()

    override fun findReport(tenantId: String, reportReference: String) = jdbc.query(
        "select report_reference, currency_code, period_start, period_end, total_ledger_debits, total_ledger_credits, total_external_debits, total_external_credits, imbalance_amount, status, reason_code, resolution_notes, approver_id, checksum_sha256, server_version from admin_reconciliation_report where tenant_id = ? and report_reference = ?",
        { rs, _ ->
            ReconciliationReport(
                reportReference = rs.getString("report_reference"),
                currencyCode = rs.getString("currency_code"),
                periodStart = rs.getTimestamp("period_start").toInstant(),
                periodEnd = rs.getTimestamp("period_end").toInstant(),
                totalLedgerDebits = rs.getLong("total_ledger_debits"),
                totalLedgerCredits = rs.getLong("total_ledger_credits"),
                totalExternalDebits = rs.getLong("total_external_debits"),
                totalExternalCredits = rs.getLong("total_external_credits"),
                imbalanceAmount = rs.getLong("imbalance_amount"),
                status = ReconciliationStatus.valueOf(rs.getString("status")),
                reasonCode = rs.getString("reason_code"),
                resolutionNotes = rs.getString("resolution_notes"),
                approverId = rs.getString("approver_id"),
                exportChecksumSha256 = rs.getString("checksum_sha256"),
                serverVersion = rs.getLong("server_version"),
            )
        },
        tenantId, reportReference
    ).firstOrNull()

    @Transactional
    override fun save(
        result: ReconciliationReportResult,
        tenantId: String,
        queryFingerprint: String,
        idempotencyKey: String,
        audit: AuditEvent,
        outbox: OutboxEvent,
    ) {
        val existing = findReport(tenantId, result.report.reportReference)
        if (existing == null) {
            jdbc.update(
                "insert into admin_reconciliation_report(tenant_id, report_reference, currency_code, period_start, period_end, total_ledger_debits, total_ledger_credits, total_external_debits, total_external_credits, imbalance_amount, status, reason_code, resolution_notes, approver_id, checksum_sha256, server_version, updated_at) values (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                tenantId, result.report.reportReference, result.report.currencyCode, result.report.periodStart, result.report.periodEnd, result.report.totalLedgerDebits, result.report.totalLedgerCredits, result.report.totalExternalDebits, result.report.totalExternalCredits, result.report.imbalanceAmount, result.report.status.name, result.report.reasonCode, result.report.resolutionNotes, result.report.approverId, result.report.exportChecksumSha256, result.report.serverVersion, result.serverTime
            )
        } else {
            jdbc.update(
                "update admin_reconciliation_report set currency_code = ?, period_start = ?, period_end = ?, total_ledger_debits = ?, total_ledger_credits = ?, total_external_debits = ?, total_external_credits = ?, imbalance_amount = ?, status = ?, reason_code = ?, resolution_notes = ?, approver_id = ?, checksum_sha256 = ?, server_version = ?, updated_at = ? where tenant_id = ? and report_reference = ? and server_version = ?",
                result.report.currencyCode, result.report.periodStart, result.report.periodEnd, result.report.totalLedgerDebits, result.report.totalLedgerCredits, result.report.totalExternalDebits, result.report.totalExternalCredits, result.report.imbalanceAmount, result.report.status.name, result.report.reasonCode, result.report.resolutionNotes, result.report.approverId, result.report.exportChecksumSha256, result.report.serverVersion, result.serverTime, tenantId, result.report.reportReference, result.report.serverVersion - 1
            )
        }

        jdbc.update(
            "insert into admin_reconciliation_report_result(result_id, tenant_id, report_reference, query_fingerprint, evidence_reference, currency_code, period_start, period_end, total_ledger_debits, total_ledger_credits, total_external_debits, total_external_credits, imbalance_amount, status, reason_code, resolution_notes, approver_id, checksum_sha256, server_version, occurred_at, idempotency_key, correlation_id, causation_id) values (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            result.resultId, tenantId, result.report.reportReference, queryFingerprint, result.evidenceReference, result.report.currencyCode, result.report.periodStart, result.report.periodEnd, result.report.totalLedgerDebits, result.report.totalLedgerCredits, result.report.totalExternalDebits, result.report.totalExternalCredits, result.report.imbalanceAmount, result.report.status.name, result.report.reasonCode, result.report.resolutionNotes, result.report.approverId, result.report.exportChecksumSha256, result.report.serverVersion, result.serverTime, idempotencyKey, audit.correlationId, audit.causationId
        )
        jdbc.update(
            "insert into admin_operation(result_id, tenant_id, operation_type, created_at) values (?, ?, ?, ?)",
            result.resultId, tenantId, "RECONCILIATION_REPORT", result.serverTime
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

    private fun ResultSet.toResult(): Pair<String, ReconciliationReportResult> {
        val id = getObject("result_id", UUID::class.java)
        val report = ReconciliationReport(
            reportReference = getString("report_reference"),
            currencyCode = getString("currency_code"),
            periodStart = getTimestamp("period_start").toInstant(),
            periodEnd = getTimestamp("period_end").toInstant(),
            totalLedgerDebits = getLong("total_ledger_debits"),
            totalLedgerCredits = getLong("total_ledger_credits"),
            totalExternalDebits = getLong("total_external_debits"),
            totalExternalCredits = getLong("total_external_credits"),
            imbalanceAmount = getLong("imbalance_amount"),
            status = ReconciliationStatus.valueOf(getString("status")),
            reasonCode = getString("reason_code"),
            resolutionNotes = getString("resolution_notes"),
            approverId = getString("approver_id"),
            exportChecksumSha256 = getString("checksum_sha256"),
            serverVersion = getLong("server_version"),
        )
        val res = ReconciliationReportResult(
            resultId = id,
            report = report,
            serverTime = getTimestamp("occurred_at").toInstant(),
            evidenceReference = getString("evidence_reference"),
        )
        return getString("query_fingerprint") to res
    }
}
