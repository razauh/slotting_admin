package com.slotting.admin.account

import org.springframework.jdbc.core.JdbcTemplate
import org.springframework.stereotype.Repository
import java.sql.ResultSet
import java.time.Instant
import java.util.UUID
import java.util.concurrent.ConcurrentHashMap

interface AccountWorkflowStore {
    fun saveSupportCase(record: SupportCaseRecord)
    fun findSupportCase(tenantId: String, caseId: UUID): SupportCaseRecord?
    fun findSupportCaseByIdempotency(tenantId: String, idempotencyKey: String): SupportCaseRecord?
    fun findSupportCasesByOwner(tenantId: String, ownerUserId: UUID): List<SupportCaseRecord>

    fun saveClosureRecord(record: AccountClosureRecord)
    fun findClosureRecord(tenantId: String, closureId: UUID): AccountClosureRecord?
    fun findClosureRecordByIdempotency(tenantId: String, idempotencyKey: String): AccountClosureRecord?
    fun findLatestClosureByOwner(tenantId: String, ownerUserId: UUID): AccountClosureRecord?

    fun hasPendingFinancialOperations(tenantId: String, ownerUserId: UUID): Boolean
    fun hasLegalHold(tenantId: String, ownerUserId: UUID): Pair<Boolean, String?>
    fun getCoolingOffUntil(tenantId: String, ownerUserId: UUID): Instant?
    fun getSelfExclusionUntil(tenantId: String, ownerUserId: UUID): Instant?
}

open class InMemoryAccountWorkflowStore : AccountWorkflowStore {
    private val casesById = ConcurrentHashMap<String, SupportCaseRecord>()
    private val casesByIdemp = ConcurrentHashMap<String, SupportCaseRecord>()
    private val closuresById = ConcurrentHashMap<String, AccountClosureRecord>()
    private val closuresByIdemp = ConcurrentHashMap<String, AccountClosureRecord>()
    private val latestClosureByOwner = ConcurrentHashMap<String, AccountClosureRecord>()

    private val pendingOps = ConcurrentHashMap<String, Boolean>()
    private val legalHolds = ConcurrentHashMap<String, Pair<Boolean, String?>>()
    private val coolingOff = ConcurrentHashMap<String, Instant>()
    private val selfExclusions = ConcurrentHashMap<String, Instant>()

    fun setPendingFinancialOperations(tenantId: String, playerId: UUID, pending: Boolean) {
        pendingOps["$tenantId:$playerId"] = pending
    }

    fun setLegalHold(tenantId: String, playerId: UUID, active: Boolean, reason: String? = null) {
        legalHolds["$tenantId:$playerId"] = Pair(active, reason)
    }

    fun setCoolingOff(tenantId: String, playerId: UUID, until: Instant) {
        coolingOff["$tenantId:$playerId"] = until
    }

    fun setSelfExclusion(tenantId: String, playerId: UUID, until: Instant) {
        selfExclusions["$tenantId:$playerId"] = until
    }

    override fun saveSupportCase(record: SupportCaseRecord) {
        casesById["${record.tenantId}:${record.caseId}"] = record
        casesByIdemp["${record.tenantId}:${record.idempotencyKey}"] = record
    }

    override fun findSupportCase(tenantId: String, caseId: UUID): SupportCaseRecord? {
        return casesById["$tenantId:$caseId"]
    }

    override fun findSupportCaseByIdempotency(tenantId: String, idempotencyKey: String): SupportCaseRecord? {
        return casesByIdemp["$tenantId:$idempotencyKey"]
    }

    override fun findSupportCasesByOwner(tenantId: String, ownerUserId: UUID): List<SupportCaseRecord> {
        return casesById.values.filter { it.tenantId == tenantId && it.ownerUserId == ownerUserId }
            .sortedByDescending { it.createdAt }
    }

    override fun saveClosureRecord(record: AccountClosureRecord) {
        closuresById["${record.tenantId}:${record.closureId}"] = record
        closuresByIdemp["${record.tenantId}:${record.idempotencyKey}"] = record
        latestClosureByOwner["${record.tenantId}:${record.ownerUserId}"] = record
    }

    override fun findClosureRecord(tenantId: String, closureId: UUID): AccountClosureRecord? {
        return closuresById["$tenantId:$closureId"]
    }

    override fun findClosureRecordByIdempotency(tenantId: String, idempotencyKey: String): AccountClosureRecord? {
        return closuresByIdemp["$tenantId:$idempotencyKey"]
    }

    override fun findLatestClosureByOwner(tenantId: String, ownerUserId: UUID): AccountClosureRecord? {
        return latestClosureByOwner["$tenantId:$ownerUserId"]
    }

    override fun hasPendingFinancialOperations(tenantId: String, ownerUserId: UUID): Boolean {
        return pendingOps["$tenantId:$ownerUserId"] ?: false
    }

    override fun hasLegalHold(tenantId: String, ownerUserId: UUID): Pair<Boolean, String?> {
        return legalHolds["$tenantId:$ownerUserId"] ?: Pair(false, null)
    }

    override fun getCoolingOffUntil(tenantId: String, ownerUserId: UUID): Instant? {
        return coolingOff["$tenantId:$ownerUserId"]
    }

    override fun getSelfExclusionUntil(tenantId: String, ownerUserId: UUID): Instant? {
        return selfExclusions["$tenantId:$ownerUserId"]
    }
}

@Repository
open class JdbcAccountWorkflowStore(
    private val jdbc: JdbcTemplate,
) : AccountWorkflowStore {

    override fun saveSupportCase(record: SupportCaseRecord) {
        val sql = """
            insert into account_support_case (
                case_id, tenant_id, owner_user_id, category, subject, description, round_id,
                status, resolution_summary, idempotency_key, request_fingerprint, correlation_id,
                server_version, created_at, updated_at
            ) values (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            on conflict (tenant_id, idempotency_key) do update set
                status = excluded.status,
                resolution_summary = excluded.resolution_summary,
                updated_at = excluded.updated_at
        """.trimIndent()

        jdbc.update(
            sql,
            record.caseId,
            record.tenantId,
            record.ownerUserId,
            record.category,
            record.subject,
            record.description,
            record.roundId,
            record.status.name,
            record.resolutionSummary,
            record.idempotencyKey,
            record.requestFingerprint,
            record.correlationId,
            record.serverVersion,
            java.sql.Timestamp.from(record.createdAt),
            java.sql.Timestamp.from(record.updatedAt),
        )
    }

    override fun findSupportCase(tenantId: String, caseId: UUID): SupportCaseRecord? {
        val sql = "select * from account_support_case where tenant_id = ? and case_id = ?"
        return jdbc.query(sql, { rs, _ -> mapSupportCase(rs) }, tenantId, caseId).firstOrNull()
    }

    override fun findSupportCaseByIdempotency(tenantId: String, idempotencyKey: String): SupportCaseRecord? {
        val sql = "select * from account_support_case where tenant_id = ? and idempotency_key = ?"
        return jdbc.query(sql, { rs, _ -> mapSupportCase(rs) }, tenantId, idempotencyKey).firstOrNull()
    }

    override fun findSupportCasesByOwner(tenantId: String, ownerUserId: UUID): List<SupportCaseRecord> {
        val sql = "select * from account_support_case where tenant_id = ? and owner_user_id = ? order by created_at desc"
        return jdbc.query(sql, { rs, _ -> mapSupportCase(rs) }, tenantId, ownerUserId)
    }

    override fun saveClosureRecord(record: AccountClosureRecord) {
        val sql = """
            insert into account_closure_record (
                closure_id, tenant_id, owner_user_id, reason, reason_details, status,
                pending_balance_minor_units, settlement_acknowledged, has_pending_financial_ops,
                has_legal_hold, retention_policy_reference, server_receipt, idempotency_key,
                request_fingerprint, correlation_id, closed_at, server_version, created_at, updated_at
            ) values (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            on conflict (tenant_id, idempotency_key) do update set
                status = excluded.status,
                closed_at = excluded.closed_at,
                updated_at = excluded.updated_at
        """.trimIndent()

        jdbc.update(
            sql,
            record.closureId,
            record.tenantId,
            record.ownerUserId,
            record.reason,
            record.reasonDetails,
            record.status.name,
            record.pendingBalanceMinorUnits,
            record.settlementAcknowledged,
            record.hasPendingFinancialOps,
            record.hasLegalHold,
            record.retentionPolicyReference,
            record.serverReceipt,
            record.idempotencyKey,
            record.requestFingerprint,
            record.correlationId,
            record.closedAt?.let { java.sql.Timestamp.from(it) },
            record.serverVersion,
            java.sql.Timestamp.from(record.createdAt),
            java.sql.Timestamp.from(record.updatedAt),
        )
    }

    override fun findClosureRecord(tenantId: String, closureId: UUID): AccountClosureRecord? {
        val sql = "select * from account_closure_record where tenant_id = ? and closure_id = ?"
        return jdbc.query(sql, { rs, _ -> mapClosureRecord(rs) }, tenantId, closureId).firstOrNull()
    }

    override fun findClosureRecordByIdempotency(tenantId: String, idempotencyKey: String): AccountClosureRecord? {
        val sql = "select * from account_closure_record where tenant_id = ? and idempotency_key = ?"
        return jdbc.query(sql, { rs, _ -> mapClosureRecord(rs) }, tenantId, idempotencyKey).firstOrNull()
    }

    override fun findLatestClosureByOwner(tenantId: String, ownerUserId: UUID): AccountClosureRecord? {
        val sql = "select * from account_closure_record where tenant_id = ? and owner_user_id = ? order by created_at desc limit 1"
        return jdbc.query(sql, { rs, _ -> mapClosureRecord(rs) }, tenantId, ownerUserId).firstOrNull()
    }

    override fun hasPendingFinancialOperations(tenantId: String, ownerUserId: UUID): Boolean {
        // Query unresolved deposits
        val depSql = "select count(*) from admin_deposit_intent where tenant_id = ? and player_id = ? and status in ('CREATED', 'DISPATCH_PENDING', 'PROVIDER_PENDING', 'AMBIGUOUS_RECONCILING')"
        val pendingDeps = try {
            jdbc.queryForObject(depSql, Long::class.java, tenantId, ownerUserId) ?: 0L
        } catch (_: Exception) { 0L }

        // Query unresolved withdrawals
        val wdrSql = "select count(*) from admin_withdrawal_request where tenant_id = ? and owner_id = ? and status = 'REQUESTED'"
        val pendingWdrs = try {
            jdbc.queryForObject(wdrSql, Long::class.java, tenantId, ownerUserId) ?: 0L
        } catch (_: Exception) { 0L }

        return (pendingDeps + pendingWdrs) > 0L
    }

    override fun hasLegalHold(tenantId: String, ownerUserId: UUID): Pair<Boolean, String?> {
        val sql = "select reason from account_legal_hold where tenant_id = ? and owner_user_id = ? and is_active = true limit 1"
        val reasons = try {
            jdbc.query(sql, { rs, _ -> rs.getString("reason") }, tenantId, ownerUserId)
        } catch (_: Exception) { emptyList() }

        return if (reasons.isNotEmpty()) Pair(true, reasons.first()) else Pair(false, null)
    }

    override fun getCoolingOffUntil(tenantId: String, ownerUserId: UUID): Instant? {
        return null
    }

    override fun getSelfExclusionUntil(tenantId: String, ownerUserId: UUID): Instant? {
        return null
    }

    private fun mapSupportCase(rs: ResultSet): SupportCaseRecord {
        return SupportCaseRecord(
            caseId = UUID.fromString(rs.getString("case_id")),
            tenantId = rs.getString("tenant_id"),
            ownerUserId = UUID.fromString(rs.getString("owner_user_id")),
            category = rs.getString("category"),
            subject = rs.getString("subject"),
            description = rs.getString("description"),
            roundId = rs.getString("round_id"),
            status = SupportCaseStatus.valueOf(rs.getString("status")),
            resolutionSummary = rs.getString("resolution_summary"),
            idempotencyKey = rs.getString("idempotency_key"),
            requestFingerprint = rs.getString("request_fingerprint"),
            correlationId = rs.getString("correlation_id"),
            serverVersion = rs.getLong("server_version"),
            createdAt = rs.getTimestamp("created_at").toInstant(),
            updatedAt = rs.getTimestamp("updated_at").toInstant(),
        )
    }

    private fun mapClosureRecord(rs: ResultSet): AccountClosureRecord {
        return AccountClosureRecord(
            closureId = UUID.fromString(rs.getString("closure_id")),
            tenantId = rs.getString("tenant_id"),
            ownerUserId = UUID.fromString(rs.getString("owner_user_id")),
            reason = rs.getString("reason"),
            reasonDetails = rs.getString("reason_details"),
            status = ClosureStatus.valueOf(rs.getString("status")),
            pendingBalanceMinorUnits = rs.getLong("pending_balance_minor_units"),
            settlementAcknowledged = rs.getBoolean("settlement_acknowledged"),
            hasPendingFinancialOps = rs.getBoolean("has_pending_financial_ops"),
            hasLegalHold = rs.getBoolean("has_legal_hold"),
            retentionPolicyReference = rs.getString("retention_policy_reference"),
            serverReceipt = rs.getString("server_receipt"),
            idempotencyKey = rs.getString("idempotency_key"),
            requestFingerprint = rs.getString("request_fingerprint"),
            correlationId = rs.getString("correlation_id"),
            closedAt = rs.getTimestamp("closed_at")?.toInstant(),
            serverVersion = rs.getLong("server_version"),
            createdAt = rs.getTimestamp("created_at").toInstant(),
            updatedAt = rs.getTimestamp("updated_at").toInstant(),
        )
    }
}
