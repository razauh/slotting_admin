package com.slotting.admin.fraud

import com.fasterxml.jackson.core.type.TypeReference
import com.fasterxml.jackson.databind.ObjectMapper
import org.springframework.jdbc.core.JdbcTemplate
import org.springframework.jdbc.core.RowMapper
import java.sql.ResultSet
import java.sql.Timestamp
import java.time.Instant
import java.util.UUID

open class JdbcFraudCaseStore(
    private val jdbcTemplate: JdbcTemplate,
    private val objectMapper: ObjectMapper = ObjectMapper().findAndRegisterModules()
) : FraudCaseStore {

    private val stringListType = object : TypeReference<List<String>>() {}
    private val notesListType = object : TypeReference<List<FraudCaseNote>>() {}

    private val caseRowMapper = RowMapper<FraudCaseRecord> { rs: ResultSet, _ ->
        val riskDecisions = objectMapper.readValue(rs.getString("risk_decision_refs_json"), stringListType)
        val detectedReasons = objectMapper.readValue(rs.getString("detected_reasons_json"), stringListType)
        val notesJson = rs.getString("admin_notes_json")
        val adminNotes: List<FraudCaseNote> = if (!notesJson.isNullOrBlank()) {
            objectMapper.readValue(notesJson, notesListType)
        } else {
            emptyList()
        }

        FraudCaseRecord(
            caseId = rs.getObject("case_id", UUID::class.java),
            tenantId = rs.getString("tenant_id"),
            subjectReference = rs.getString("subject_reference"),
            caseReference = rs.getString("case_reference"),
            state = FraudCaseState.valueOf(rs.getString("state")),
            severity = FraudCaseSeverity.valueOf(rs.getString("severity")),
            riskDecisionReferences = riskDecisions,
            detectedReasons = detectedReasons,
            claimedBy = rs.getString("claimed_by"),
            claimExpiresAt = rs.getTimestamp("claim_expires_at")?.toInstant(),
            restrictionId = rs.getObject("restriction_id", UUID::class.java),
            dispositionReason = rs.getString("disposition_reason"),
            disposedBy = rs.getString("disposed_by"),
            disposedAt = rs.getTimestamp("disposed_at")?.toInstant(),
            secondApproverId = rs.getString("second_approver_id"),
            adminNotes = adminNotes,
            serverVersion = rs.getLong("server_version"),
            createdAt = rs.getTimestamp("created_at").toInstant(),
            updatedAt = rs.getTimestamp("updated_at").toInstant()
        )
    }

    private val actionRowMapper = RowMapper<FraudCaseActionRecord> { rs: ResultSet, _ ->
        FraudCaseActionRecord(
            actionId = rs.getObject("action_id", UUID::class.java),
            caseId = rs.getObject("case_id", UUID::class.java),
            tenantId = rs.getString("tenant_id"),
            caseReference = rs.getString("case_reference"),
            action = FraudCaseAction.valueOf(rs.getString("action")),
            actorId = rs.getString("actor_id"),
            secondApproverId = rs.getString("second_approver_id"),
            fromState = FraudCaseState.valueOf(rs.getString("from_state")),
            toState = FraudCaseState.valueOf(rs.getString("to_state")),
            reason = rs.getString("reason"),
            occurredAt = rs.getTimestamp("occurred_at").toInstant(),
            idempotencyKey = rs.getString("idempotency_key"),
            correlationId = rs.getString("correlation_id"),
            causationId = rs.getString("causation_id")
        )
    }

    override fun saveCase(caseRecord: FraudCaseRecord): Boolean {
        val sql = """
            INSERT INTO fraud_cases (
                case_id, tenant_id, subject_reference, case_reference, state, severity,
                risk_decision_refs_json, detected_reasons_json, claimed_by, claim_expires_at,
                restriction_id, disposition_reason, disposed_by, disposed_at, second_approver_id,
                admin_notes_json, server_version, created_at, updated_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT (case_reference) DO NOTHING
        """.trimIndent()

        val affected = jdbcTemplate.update(
            sql,
            caseRecord.caseId,
            caseRecord.tenantId,
            caseRecord.subjectReference,
            caseRecord.caseReference,
            caseRecord.state.name,
            caseRecord.severity.name,
            objectMapper.writeValueAsString(caseRecord.riskDecisionReferences),
            objectMapper.writeValueAsString(caseRecord.detectedReasons),
            caseRecord.claimedBy,
            caseRecord.claimExpiresAt?.let { Timestamp.from(it) },
            caseRecord.restrictionId,
            caseRecord.dispositionReason,
            caseRecord.disposedBy,
            caseRecord.disposedAt?.let { Timestamp.from(it) },
            caseRecord.secondApproverId,
            objectMapper.writeValueAsString(caseRecord.adminNotes),
            caseRecord.serverVersion,
            Timestamp.from(caseRecord.createdAt),
            Timestamp.from(caseRecord.updatedAt)
        )
        return affected > 0
    }

    override fun findCaseByReference(tenantId: String, caseReference: String): FraudCaseRecord? {
        val sql = """
            SELECT case_id, tenant_id, subject_reference, case_reference, state, severity,
                   risk_decision_refs_json, detected_reasons_json, claimed_by, claim_expires_at,
                   restriction_id, disposition_reason, disposed_by, disposed_at, second_approver_id,
                   admin_notes_json, server_version, created_at, updated_at
            FROM fraud_cases
            WHERE tenant_id = ? AND case_reference = ?
        """.trimIndent()
        return jdbcTemplate.query(sql, caseRowMapper, tenantId, caseReference).firstOrNull()
    }

    override fun findActiveCaseForSubject(tenantId: String, subjectReference: String): FraudCaseRecord? {
        val sql = """
            SELECT case_id, tenant_id, subject_reference, case_reference, state, severity,
                   risk_decision_refs_json, detected_reasons_json, claimed_by, claim_expires_at,
                   restriction_id, disposition_reason, disposed_by, disposed_at, second_approver_id,
                   admin_notes_json, server_version, created_at, updated_at
            FROM fraud_cases
            WHERE tenant_id = ?
              AND subject_reference = ?
              AND state IN ('OPEN', 'CLAIMED', 'EVIDENCE_REQUESTED', 'ESCALATED')
            ORDER BY created_at DESC
            LIMIT 1
        """.trimIndent()
        return jdbcTemplate.query(sql, caseRowMapper, tenantId, subjectReference).firstOrNull()
    }

    override fun updateCaseWithCas(caseRecord: FraudCaseRecord, expectedVersion: Long): Boolean {
        val nextVersion = expectedVersion + 1
        val sql = """
            UPDATE fraud_cases
            SET state = ?,
                severity = ?,
                risk_decision_refs_json = ?,
                detected_reasons_json = ?,
                claimed_by = ?,
                claim_expires_at = ?,
                restriction_id = ?,
                disposition_reason = ?,
                disposed_by = ?,
                disposed_at = ?,
                second_approver_id = ?,
                admin_notes_json = ?,
                server_version = ?,
                updated_at = ?
            WHERE tenant_id = ?
              AND case_reference = ?
              AND server_version = ?
        """.trimIndent()

        val affected = jdbcTemplate.update(
            sql,
            caseRecord.state.name,
            caseRecord.severity.name,
            objectMapper.writeValueAsString(caseRecord.riskDecisionReferences),
            objectMapper.writeValueAsString(caseRecord.detectedReasons),
            caseRecord.claimedBy,
            caseRecord.claimExpiresAt?.let { Timestamp.from(it) },
            caseRecord.restrictionId,
            caseRecord.dispositionReason,
            caseRecord.disposedBy,
            caseRecord.disposedAt?.let { Timestamp.from(it) },
            caseRecord.secondApproverId,
            objectMapper.writeValueAsString(caseRecord.adminNotes),
            nextVersion,
            Timestamp.from(caseRecord.updatedAt),
            caseRecord.tenantId,
            caseRecord.caseReference,
            expectedVersion
        )
        return affected == 1
    }

    override fun recordAction(actionRecord: FraudCaseActionRecord): Boolean {
        val sql = """
            INSERT INTO fraud_case_actions (
                action_id, case_id, tenant_id, case_reference, action, actor_id,
                second_approver_id, from_state, to_state, reason, occurred_at,
                idempotency_key, correlation_id, causation_id
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT (tenant_id, idempotency_key) DO NOTHING
        """.trimIndent()

        val affected = jdbcTemplate.update(
            sql,
            actionRecord.actionId,
            actionRecord.caseId,
            actionRecord.tenantId,
            actionRecord.caseReference,
            actionRecord.action.name,
            actionRecord.actorId,
            actionRecord.secondApproverId,
            actionRecord.fromState.name,
            actionRecord.toState.name,
            actionRecord.reason,
            Timestamp.from(actionRecord.occurredAt),
            actionRecord.idempotencyKey,
            actionRecord.correlationId,
            actionRecord.causationId
        )
        return affected > 0
    }

    override fun findActionByIdempotency(tenantId: String, idempotencyKey: String): FraudCaseActionRecord? {
        val sql = """
            SELECT action_id, case_id, tenant_id, case_reference, action, actor_id,
                   second_approver_id, from_state, to_state, reason, occurred_at,
                   idempotency_key, correlation_id, causation_id
            FROM fraud_case_actions
            WHERE tenant_id = ? AND idempotency_key = ?
        """.trimIndent()
        return jdbcTemplate.query(sql, actionRowMapper, tenantId, idempotencyKey).firstOrNull()
    }

    override fun countActiveCases(tenantId: String): Long {
        val sql = "SELECT count(*) FROM fraud_cases WHERE tenant_id = ? AND state IN ('OPEN', 'CLAIMED', 'EVIDENCE_REQUESTED', 'ESCALATED')"
        val count = jdbcTemplate.queryForObject(sql, Long::class.java, tenantId)
        return count ?: 0L
    }
}
