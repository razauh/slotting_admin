package com.slotting.admin.restriction

import java.time.Instant
import java.util.UUID
import java.util.concurrent.ConcurrentHashMap

/**
 * Port and adapters for server restriction persistence and caching.
 * Invariant: Cache loss cannot unlock. Cache miss != unrestricted.
 */

interface DurableServerRestrictionStore {
    fun findActiveRestrictions(tenantId: String, subjectReference: String, now: Instant): List<ServerRestrictionRecord>
    fun saveRestriction(restriction: ServerRestrictionRecord)
    fun revokeRestriction(tenantId: String, restrictionId: UUID, revokedBy: String, now: Instant): Boolean
    fun recordEvaluation(result: ServerRestrictionEvaluationResult)
    fun countActiveRestrictions(tenantId: String, now: Instant): Long = 0L
}

interface EphemeralRestrictionCache {
    fun get(tenantId: String, subjectReference: String): List<ServerRestrictionRecord>?
    fun put(tenantId: String, subjectReference: String, restrictions: List<ServerRestrictionRecord>)
    fun evict(tenantId: String, subjectReference: String)
    fun clear()
    fun getStats(): CacheStats
}

data class CacheStats(
    val hits: Long,
    val misses: Long,
    val evictions: Long
)

class InMemoryServerRestrictionStore : DurableServerRestrictionStore {
    private val records = ConcurrentHashMap<UUID, ServerRestrictionRecord>()
    private val evaluations = ConcurrentHashMap<UUID, ServerRestrictionEvaluationResult>()

    override fun findActiveRestrictions(
        tenantId: String,
        subjectReference: String,
        now: Instant
    ): List<ServerRestrictionRecord> {
        return records.values
            .filter { it.tenantId == tenantId && it.subjectReference == subjectReference && it.isEffectiveAt(now) }
            .sortedBy { it.effectiveFrom }
    }

    override fun saveRestriction(restriction: ServerRestrictionRecord) {
        records[restriction.restrictionId] = restriction
    }

    override fun revokeRestriction(tenantId: String, restrictionId: UUID, revokedBy: String, now: Instant): Boolean {
        val existing = records[restrictionId] ?: return false
        if (existing.tenantId != tenantId) return false
        records[restrictionId] = existing.copy(active = false)
        return true
    }

    override fun recordEvaluation(result: ServerRestrictionEvaluationResult) {
        evaluations[result.decisionId] = result
    }

    override fun countActiveRestrictions(tenantId: String, now: Instant): Long {
        return records.values.count { it.tenantId == tenantId && it.isEffectiveAt(now) }.toLong()
    }

    fun getAllRecords(): List<ServerRestrictionRecord> = records.values.toList()
    fun getAllEvaluations(): List<ServerRestrictionEvaluationResult> = evaluations.values.toList()
}

class InMemoryEphemeralRestrictionCache : EphemeralRestrictionCache {
    private val cache = ConcurrentHashMap<String, List<ServerRestrictionRecord>>()
    private var hits = 0L
    private var misses = 0L
    private var evictions = 0L

    @Synchronized
    override fun get(tenantId: String, subjectReference: String): List<ServerRestrictionRecord>? {
        val key = "$tenantId:$subjectReference"
        val found = cache[key]
        if (found != null) {
            hits++
        } else {
            misses++
        }
        return found
    }

    @Synchronized
    override fun put(tenantId: String, subjectReference: String, restrictions: List<ServerRestrictionRecord>) {
        val key = "$tenantId:$subjectReference"
        cache[key] = restrictions
    }

    @Synchronized
    override fun evict(tenantId: String, subjectReference: String) {
        val key = "$tenantId:$subjectReference"
        if (cache.remove(key) != null) {
            evictions++
        }
    }

    @Synchronized
    override fun clear() {
        evictions += cache.size
        cache.clear()
    }

    @Synchronized
    override fun getStats(): CacheStats = CacheStats(hits, misses, evictions)
}

open class JdbcServerRestrictionStore(
    private val jdbcTemplate: org.springframework.jdbc.core.JdbcTemplate,
    private val objectMapper: com.fasterxml.jackson.databind.ObjectMapper = com.fasterxml.jackson.databind.ObjectMapper().findAndRegisterModules()
) : DurableServerRestrictionStore {

    override fun findActiveRestrictions(
        tenantId: String,
        subjectReference: String,
        now: Instant
    ): List<ServerRestrictionRecord> {
        val sql = """
            SELECT restriction_id, tenant_id, subject_reference, source, reason_code,
                   safe_user_message, scope_type, scope_provider_id, scope_category, scope_surface,
                   effective_from, expires_at, evidence_reference, rule_version, issuer, active
            FROM server_restrictions
            WHERE tenant_id = ?
              AND subject_reference = ?
              AND active = true
              AND effective_from <= ?
              AND (expires_at IS NULL OR expires_at > ?)
            ORDER BY effective_from ASC
        """.trimIndent()

        val ts = java.sql.Timestamp.from(now)
        return jdbcTemplate.query(sql, { rs, _ -> mapRow(rs) }, tenantId, subjectReference, ts, ts)
    }

    override fun saveRestriction(restriction: ServerRestrictionRecord) {
        val sql = """
            INSERT INTO server_restrictions (
                restriction_id, tenant_id, subject_reference, source, reason_code,
                safe_user_message, scope_type, scope_provider_id, scope_category, scope_surface,
                effective_from, expires_at, evidence_reference, rule_version, issuer, active
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT (restriction_id) DO UPDATE SET
                active = EXCLUDED.active,
                expires_at = EXCLUDED.expires_at,
                rule_version = EXCLUDED.rule_version
        """.trimIndent()

        val (scopeType, scopeProviderId, scopeCategory, scopeSurface) = when (val s = restriction.scope) {
            is RestrictionScope.WholeAccount -> Quadruple("WHOLE_ACCOUNT", null, null, null)
            is RestrictionScope.ProviderScoped -> Quadruple("PROVIDER_SCOPED", s.providerId, s.category.name, null)
            is RestrictionScope.SurfaceScoped -> Quadruple("SURFACE_SCOPED", null, null, s.surface)
        }

        jdbcTemplate.update(
            sql,
            restriction.restrictionId,
            restriction.tenantId,
            restriction.subjectReference,
            restriction.source.name,
            restriction.reasonCode,
            restriction.safeUserMessage,
            scopeType,
            scopeProviderId,
            scopeCategory,
            scopeSurface,
            java.sql.Timestamp.from(restriction.effectiveFrom),
            restriction.expiresAt?.let { java.sql.Timestamp.from(it) },
            restriction.evidenceReference,
            restriction.ruleVersion,
            restriction.issuer,
            restriction.active
        )
    }

    override fun revokeRestriction(tenantId: String, restrictionId: UUID, revokedBy: String, now: Instant): Boolean {
        val sql = """
            UPDATE server_restrictions
            SET active = false,
                revoked_at = ?,
                revoked_by = ?
            WHERE tenant_id = ? AND restriction_id = ? AND active = true
        """.trimIndent()

        val rows = jdbcTemplate.update(sql, java.sql.Timestamp.from(now), revokedBy, tenantId, restrictionId)
        return rows > 0
    }

    override fun recordEvaluation(result: ServerRestrictionEvaluationResult) {
        val sql = """
            INSERT INTO server_restriction_evaluations (
                decision_id, tenant_id, subject_reference, operation, composite_access,
                financial_disposition, contributing_restrictions, policy_version, evaluated_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT (decision_id) DO NOTHING
        """.trimIndent()

        val json = objectMapper.writeValueAsString(result.contributingRestrictions)

        jdbcTemplate.update(
            sql,
            result.decisionId,
            result.tenantId,
            result.subjectReference,
            result.operation.name,
            result.compositeAccess.name,
            result.financialDisposition.name,
            json,
            result.policyVersion,
            java.sql.Timestamp.from(result.evaluatedAt)
        )
    }

    private fun mapRow(rs: java.sql.ResultSet): ServerRestrictionRecord {
        val scopeType = rs.getString("scope_type")
        val scope = when (scopeType) {
            "PROVIDER_SCOPED" -> {
                val providerId = rs.getString("scope_provider_id") ?: ""
                val catStr = rs.getString("scope_category")
                val category = catStr?.let { ProviderCategory.valueOf(it) } ?: ProviderCategory.ALL
                RestrictionScope.ProviderScoped(providerId, category)
            }
            "SURFACE_SCOPED" -> {
                val surface = rs.getString("scope_surface") ?: ""
                RestrictionScope.SurfaceScoped(surface)
            }
            else -> RestrictionScope.WholeAccount
        }

        return ServerRestrictionRecord(
            restrictionId = rs.getObject("restriction_id", UUID::class.java),
            tenantId = rs.getString("tenant_id"),
            subjectReference = rs.getString("subject_reference"),
            source = RestrictionSource.valueOf(rs.getString("source")),
            reasonCode = rs.getString("reason_code"),
            safeUserMessage = rs.getString("safe_user_message"),
            scope = scope,
            effectiveFrom = rs.getTimestamp("effective_from").toInstant(),
            expiresAt = rs.getTimestamp("expires_at")?.toInstant(),
            evidenceReference = rs.getString("evidence_reference"),
            ruleVersion = rs.getLong("rule_version"),
            issuer = rs.getString("issuer"),
            active = rs.getBoolean("active")
        )
    }

    override fun countActiveRestrictions(tenantId: String, now: Instant): Long {
        val sql = """
            SELECT count(*)
            FROM server_restrictions
            WHERE tenant_id = ?
              AND active = true
              AND effective_from <= ?
              AND (expires_at IS NULL OR expires_at > ?)
        """.trimIndent()
        val ts = java.sql.Timestamp.from(now)
        val count = jdbcTemplate.queryForObject(sql, Long::class.java, tenantId, ts, ts)
        return count ?: 0L
    }

    private data class Quadruple<A, B, C, D>(val first: A, val second: B, val third: C, val fourth: D)
}
