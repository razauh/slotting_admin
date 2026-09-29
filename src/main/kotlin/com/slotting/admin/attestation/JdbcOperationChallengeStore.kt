package com.slotting.admin.attestation

import org.springframework.jdbc.core.JdbcTemplate
import org.springframework.jdbc.core.RowMapper
import java.sql.ResultSet
import java.sql.Timestamp
import java.time.Instant
import java.util.UUID

open class JdbcOperationChallengeStore(
    private val jdbcTemplate: JdbcTemplate
) : DurableOperationChallengeStore {

    private val challengeRowMapper = RowMapper<OperationChallengeRecord> { rs: ResultSet, _ ->
        OperationChallengeRecord(
            challengeId = rs.getObject("challenge_id", UUID::class.java),
            tenantId = rs.getString("tenant_id"),
            userId = rs.getString("user_id"),
            sessionId = rs.getString("session_id"),
            operation = ProtectedOperation.valueOf(rs.getString("operation")),
            nonceValue = rs.getString("nonce_value"),
            issuedAt = rs.getTimestamp("issued_at").toInstant(),
            expiresAt = rs.getTimestamp("expires_at").toInstant(),
            consumed = rs.getBoolean("consumed"),
            consumedAt = rs.getTimestamp("consumed_at")?.toInstant(),
            consumedByOperationRef = rs.getString("consumed_by_operation_ref"),
            createdAt = rs.getTimestamp("created_at").toInstant(),
        )
    }

    private val auditRowMapper = RowMapper<OperationAttestationAuditRecord> { rs: ResultSet, _ ->
        OperationAttestationAuditRecord(
            auditId = rs.getObject("audit_id", UUID::class.java),
            tenantId = rs.getString("tenant_id"),
            userId = rs.getString("user_id"),
            sessionId = rs.getString("session_id"),
            operation = ProtectedOperation.valueOf(rs.getString("operation")),
            nonceValue = rs.getString("nonce_value"),
            decision = AttestationDecision.valueOf(rs.getString("decision")),
            reason = AttestationFailureReason.valueOf(rs.getString("reason")),
            appPackageName = rs.getString("app_package_name"),
            appVersionCode = rs.getObject("app_version_code")?.let { (it as Number).toLong() },
            clientReportedFingerprint = rs.getString("client_reported_fingerprint"),
            occurredAt = rs.getTimestamp("occurred_at").toInstant(),
            idempotencyKey = rs.getString("idempotency_key"),
            correlationId = rs.getString("correlation_id"),
            causationId = rs.getString("causation_id"),
            evidenceReference = rs.getString("evidence_reference"),
            detailsRedacted = rs.getString("details_redacted") ?: "",
        )
    }

    override fun saveChallenge(challenge: OperationChallengeRecord): Boolean {
        val sql = """
            INSERT INTO operation_attestation_challenges (
                challenge_id, tenant_id, user_id, session_id, operation,
                nonce_value, issued_at, expires_at, consumed, consumed_at,
                consumed_by_operation_ref, created_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT (nonce_value) DO NOTHING
        """.trimIndent()

        val affected = jdbcTemplate.update(
            sql,
            challenge.challengeId,
            challenge.tenantId,
            challenge.userId,
            challenge.sessionId,
            challenge.operation.name,
            challenge.nonceValue,
            Timestamp.from(challenge.issuedAt),
            Timestamp.from(challenge.expiresAt),
            challenge.consumed,
            challenge.consumedAt?.let { Timestamp.from(it) },
            challenge.consumedByOperationRef,
            Timestamp.from(challenge.createdAt)
        )
        return affected > 0
    }

    override fun findChallenge(tenantId: String, nonceValue: String): OperationChallengeRecord? {
        val sql = """
            SELECT challenge_id, tenant_id, user_id, session_id, operation,
                   nonce_value, issued_at, expires_at, consumed, consumed_at,
                   consumed_by_operation_ref, created_at
            FROM operation_attestation_challenges
            WHERE tenant_id = ? AND nonce_value = ?
        """.trimIndent()
        return jdbcTemplate.query(sql, challengeRowMapper, tenantId, nonceValue).firstOrNull()
    }

    override fun findChallengeByNonce(nonceValue: String): OperationChallengeRecord? {
        val sql = """
            SELECT challenge_id, tenant_id, user_id, session_id, operation,
                   nonce_value, issued_at, expires_at, consumed, consumed_at,
                   consumed_by_operation_ref, created_at
            FROM operation_attestation_challenges
            WHERE nonce_value = ?
        """.trimIndent()
        return jdbcTemplate.query(sql, challengeRowMapper, nonceValue).firstOrNull()
    }

    override fun countActiveChallenges(tenantId: String, userId: String, sessionId: String, now: Instant): Int {
        val sql = """
            SELECT count(*)
            FROM operation_attestation_challenges
            WHERE tenant_id = ?
              AND user_id = ?
              AND session_id = ?
              AND consumed = false
              AND expires_at > ?
        """.trimIndent()
        val count = jdbcTemplate.queryForObject(sql, Long::class.java, tenantId, userId, sessionId, Timestamp.from(now))
        return count?.toInt() ?: 0
    }

    override fun consumeChallenge(
        tenantId: String,
        nonceValue: String,
        operationRef: String,
        consumedAt: Instant
    ): Boolean {
        // Atomic CAS consumption: only succeeds if challenge was NOT consumed before
        val sql = """
            UPDATE operation_attestation_challenges
            SET consumed = true,
                consumed_at = ?,
                consumed_by_operation_ref = ?
            WHERE tenant_id = ?
              AND nonce_value = ?
              AND consumed = false
        """.trimIndent()

        val affected = jdbcTemplate.update(
            sql,
            Timestamp.from(consumedAt),
            operationRef,
            tenantId,
            nonceValue
        )
        return affected == 1
    }

    override fun recordAudit(audit: OperationAttestationAuditRecord): Boolean {
        val sql = """
            INSERT INTO operation_attestation_audits (
                audit_id, tenant_id, user_id, session_id, operation,
                nonce_value, decision, reason, app_package_name, app_version_code,
                client_reported_fingerprint, occurred_at, idempotency_key,
                correlation_id, causation_id, evidence_reference, details_redacted
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT (tenant_id, idempotency_key) DO NOTHING
        """.trimIndent()

        val affected = jdbcTemplate.update(
            sql,
            audit.auditId,
            audit.tenantId,
            audit.userId,
            audit.sessionId,
            audit.operation.name,
            audit.nonceValue,
            audit.decision.name,
            audit.reason.name,
            audit.appPackageName,
            audit.appVersionCode,
            audit.clientReportedFingerprint,
            Timestamp.from(audit.occurredAt),
            audit.idempotencyKey,
            audit.correlationId,
            audit.causationId,
            audit.evidenceReference,
            audit.detailsRedacted
        )
        return affected > 0
    }

    override fun findAuditByIdempotency(tenantId: String, idempotencyKey: String): OperationAttestationAuditRecord? {
        val sql = """
            SELECT audit_id, tenant_id, user_id, session_id, operation,
                   nonce_value, decision, reason, app_package_name, app_version_code,
                   client_reported_fingerprint, occurred_at, idempotency_key,
                   correlation_id, causation_id, evidence_reference, details_redacted
            FROM operation_attestation_audits
            WHERE tenant_id = ? AND idempotency_key = ?
        """.trimIndent()
        return jdbcTemplate.query(sql, auditRowMapper, tenantId, idempotencyKey).firstOrNull()
    }
}
