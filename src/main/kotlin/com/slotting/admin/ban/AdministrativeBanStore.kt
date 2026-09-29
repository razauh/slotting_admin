package com.slotting.admin.ban

import com.slotting.admin.auth.AuditEvent
import com.slotting.admin.auth.OutboxEvent
import java.time.Instant
import java.util.UUID
import java.util.concurrent.ConcurrentHashMap

interface DurableAdministrativeBanStore {
    fun findBanById(tenantId: String, banId: UUID): AdministrativeBanRecord?
    fun findActiveBanBySubject(tenantId: String, subjectReference: String, now: Instant): AdministrativeBanRecord?
    fun findAllBansForSubject(tenantId: String, subjectReference: String): List<AdministrativeBanRecord>
    fun saveBan(ban: AdministrativeBanRecord, audit: AuditEvent, outbox: OutboxEvent)
    fun updateBan(ban: AdministrativeBanRecord, audit: AuditEvent, outbox: OutboxEvent): Boolean
    fun findByIdempotency(tenantId: String, idempotencyKey: String): Pair<String, AdministrativeBanResult>?
    fun saveIdempotency(tenantId: String, idempotencyKey: String, fingerprint: String, result: AdministrativeBanResult)
}

class InMemoryAdministrativeBanStore : DurableAdministrativeBanStore {
    private val bans = ConcurrentHashMap<UUID, AdministrativeBanRecord>()
    private val idempotency = ConcurrentHashMap<String, Pair<String, AdministrativeBanResult>>()
    private val audits = mutableListOf<AuditEvent>()
    private val outboxes = mutableListOf<OutboxEvent>()

    override fun findBanById(tenantId: String, banId: UUID): AdministrativeBanRecord? =
        bans[banId]?.takeIf { it.tenantId == tenantId }

    override fun findActiveBanBySubject(
        tenantId: String,
        subjectReference: String,
        now: Instant
    ): AdministrativeBanRecord? {
        return bans.values
            .filter { it.tenantId == tenantId && it.subjectReference == subjectReference && it.isEffectiveAt(now) }
            .maxByOrNull { it.effectiveFrom }
    }

    override fun findAllBansForSubject(tenantId: String, subjectReference: String): List<AdministrativeBanRecord> =
        bans.values
            .filter { it.tenantId == tenantId && it.subjectReference == subjectReference }
            .sortedByDescending { it.createdAt }

    override fun saveBan(ban: AdministrativeBanRecord, audit: AuditEvent, outbox: OutboxEvent) {
        bans[ban.banId] = ban
        audits.add(audit)
        outboxes.add(outbox)
    }

    override fun updateBan(ban: AdministrativeBanRecord, audit: AuditEvent, outbox: OutboxEvent): Boolean {
        val existing = bans[ban.banId] ?: return false
        if (existing.tenantId != ban.tenantId) return false
        bans[ban.banId] = ban
        audits.add(audit)
        outboxes.add(outbox)
        return true
    }

    override fun findByIdempotency(tenantId: String, idempotencyKey: String): Pair<String, AdministrativeBanResult>? =
        idempotency["$tenantId:$idempotencyKey"]

    override fun saveIdempotency(
        tenantId: String,
        idempotencyKey: String,
        fingerprint: String,
        result: AdministrativeBanResult
    ) {
        idempotency["$tenantId:$idempotencyKey"] = Pair(fingerprint, result)
    }

    fun getAudits(): List<AuditEvent> = audits.toList()
    fun getOutboxEvents(): List<OutboxEvent> = outboxes.toList()
}

open class JdbcAdministrativeBanStore(
    private val jdbcTemplate: org.springframework.jdbc.core.JdbcTemplate,
    private val objectMapper: com.fasterxml.jackson.databind.ObjectMapper = com.fasterxml.jackson.databind.ObjectMapper().findAndRegisterModules()
) : DurableAdministrativeBanStore {

    override fun findBanById(tenantId: String, banId: UUID): AdministrativeBanRecord? {
        val sql = """
            SELECT ban_id, tenant_id, subject_reference, ban_type, reason_category,
                   reason_code, permitted_note, internal_note, issuer_id, effective_from,
                   expires_at, case_reference_id, status, reversed_at, reversed_by,
                   reversal_reason, version, created_at, updated_at
            FROM administrative_bans
            WHERE tenant_id = ? AND ban_id = ?
        """.trimIndent()

        val results = jdbcTemplate.query(sql, { rs, _ -> mapRow(rs) }, tenantId, banId)
        return results.firstOrNull()
    }

    override fun findActiveBanBySubject(
        tenantId: String,
        subjectReference: String,
        now: Instant
    ): AdministrativeBanRecord? {
        val sql = """
            SELECT ban_id, tenant_id, subject_reference, ban_type, reason_category,
                   reason_code, permitted_note, internal_note, issuer_id, effective_from,
                   expires_at, case_reference_id, status, reversed_at, reversed_by,
                   reversal_reason, version, created_at, updated_at
            FROM administrative_bans
            WHERE tenant_id = ?
              AND subject_reference = ?
              AND status = 'ACTIVE'
              AND effective_from <= ?
              AND (expires_at IS NULL OR expires_at > ?)
            ORDER BY effective_from DESC
            LIMIT 1
        """.trimIndent()

        val ts = java.sql.Timestamp.from(now)
        val results = jdbcTemplate.query(sql, { rs, _ -> mapRow(rs) }, tenantId, subjectReference, ts, ts)
        return results.firstOrNull()
    }

    override fun findAllBansForSubject(tenantId: String, subjectReference: String): List<AdministrativeBanRecord> {
        val sql = """
            SELECT ban_id, tenant_id, subject_reference, ban_type, reason_category,
                   reason_code, permitted_note, internal_note, issuer_id, effective_from,
                   expires_at, case_reference_id, status, reversed_at, reversed_by,
                   reversal_reason, version, created_at, updated_at
            FROM administrative_bans
            WHERE tenant_id = ? AND subject_reference = ?
            ORDER BY created_at DESC
        """.trimIndent()

        return jdbcTemplate.query(sql, { rs, _ -> mapRow(rs) }, tenantId, subjectReference)
    }

    override fun saveBan(ban: AdministrativeBanRecord, audit: AuditEvent, outbox: OutboxEvent) {
        val sql = """
            INSERT INTO administrative_bans (
                ban_id, tenant_id, subject_reference, ban_type, reason_category,
                reason_code, permitted_note, internal_note, issuer_id, effective_from,
                expires_at, case_reference_id, status, reversed_at, reversed_by,
                reversal_reason, version, created_at, updated_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT (ban_id) DO NOTHING
        """.trimIndent()

        jdbcTemplate.update(
            sql,
            ban.banId,
            ban.tenantId,
            ban.subjectReference,
            ban.banType.name,
            ban.reasonCategory.name,
            ban.reasonCode,
            ban.permittedNote,
            ban.internalNote,
            ban.issuerId,
            java.sql.Timestamp.from(ban.effectiveFrom),
            ban.expiresAt?.let { java.sql.Timestamp.from(it) },
            ban.caseReferenceId,
            ban.status.name,
            ban.reversedAt?.let { java.sql.Timestamp.from(it) },
            ban.reversedBy,
            ban.reversalReason,
            ban.version,
            java.sql.Timestamp.from(ban.createdAt),
            java.sql.Timestamp.from(ban.updatedAt)
        )
    }

    override fun updateBan(ban: AdministrativeBanRecord, audit: AuditEvent, outbox: OutboxEvent): Boolean {
        val sql = """
            UPDATE administrative_bans
            SET status = ?,
                reversed_at = ?,
                reversed_by = ?,
                reversal_reason = ?,
                version = ?,
                updated_at = ?
            WHERE tenant_id = ? AND ban_id = ? AND version = ? - 1
        """.trimIndent()

        val rows = jdbcTemplate.update(
            sql,
            ban.status.name,
            ban.reversedAt?.let { java.sql.Timestamp.from(it) },
            ban.reversedBy,
            ban.reversalReason,
            ban.version,
            java.sql.Timestamp.from(ban.updatedAt),
            ban.tenantId,
            ban.banId,
            ban.version
        )
        return rows > 0
    }

    override fun findByIdempotency(tenantId: String, idempotencyKey: String): Pair<String, AdministrativeBanResult>? {
        val sql = """
            SELECT request_fingerprint, result_json
            FROM administrative_ban_idempotency
            WHERE tenant_id = ? AND idempotency_key = ?
        """.trimIndent()

        val results = jdbcTemplate.query(sql, { rs, _ ->
            val fp = rs.getString("request_fingerprint")
            val json = rs.getString("result_json")
            val res = objectMapper.readValue(json, AdministrativeBanResult::class.java)
            Pair(fp, res)
        }, tenantId, idempotencyKey)

        return results.firstOrNull()
    }

    override fun saveIdempotency(
        tenantId: String,
        idempotencyKey: String,
        fingerprint: String,
        result: AdministrativeBanResult
    ) {
        val sql = """
            INSERT INTO administrative_ban_idempotency (
                tenant_id, idempotency_key, request_fingerprint, result_json, created_at
            ) VALUES (?, ?, ?, ?, now())
            ON CONFLICT (tenant_id, idempotency_key) DO NOTHING
        """.trimIndent()

        val json = objectMapper.writeValueAsString(result)
        jdbcTemplate.update(sql, tenantId, idempotencyKey, fingerprint, json)
    }

    private fun mapRow(rs: java.sql.ResultSet): AdministrativeBanRecord = AdministrativeBanRecord(
        banId = rs.getObject("ban_id", UUID::class.java),
        tenantId = rs.getString("tenant_id"),
        subjectReference = rs.getString("subject_reference"),
        banType = BanType.valueOf(rs.getString("ban_type")),
        reasonCategory = BanReasonCategory.valueOf(rs.getString("reason_category")),
        reasonCode = rs.getString("reason_code"),
        permittedNote = rs.getString("permitted_note"),
        internalNote = rs.getString("internal_note"),
        issuerId = rs.getString("issuer_id"),
        effectiveFrom = rs.getTimestamp("effective_from").toInstant(),
        expiresAt = rs.getTimestamp("expires_at")?.toInstant(),
        caseReferenceId = rs.getString("case_reference_id"),
        status = BanStatus.valueOf(rs.getString("status")),
        reversedAt = rs.getTimestamp("reversed_at")?.toInstant(),
        reversedBy = rs.getString("reversed_by"),
        reversalReason = rs.getString("reversal_reason"),
        version = rs.getLong("version"),
        createdAt = rs.getTimestamp("created_at").toInstant(),
        updatedAt = rs.getTimestamp("updated_at").toInstant()
    )
}
