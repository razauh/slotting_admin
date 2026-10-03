package com.slotting.admin.rg

import com.fasterxml.jackson.databind.ObjectMapper
import org.springframework.jdbc.core.JdbcTemplate
import org.springframework.jdbc.core.RowMapper
import org.springframework.stereotype.Repository
import java.sql.ResultSet
import java.sql.Timestamp
import java.time.Instant
import java.util.UUID

@Repository
open class JdbcDurableResponsibleGamingStore(
    private val jdbcTemplate: JdbcTemplate,
    private val objectMapper: ObjectMapper = ObjectMapper().findAndRegisterModules()
) : DurableResponsibleGamingStore {

    private val limitConfigRowMapper = RowMapper<RgLimitConfig> { rs: ResultSet, _ ->
        RgLimitConfig(
            limitId = rs.getObject("limit_id", UUID::class.java),
            tenantId = rs.getString("tenant_id"),
            playerId = rs.getString("player_id"),
            limitType = RgLimitType.valueOf(rs.getString("limit_type")),
            period = RgLimitPeriod.valueOf(rs.getString("period")),
            limitValueMinorUnits = rs.getLong("limit_value_minor"),
            timezone = rs.getString("timezone"),
            productScope = rs.getString("product_scope"),
            pendingIncreaseValueMinorUnits = rs.getObject("pending_increase_value_minor")?.let { (it as Number).toLong() },
            pendingIncreaseEffectiveAt = rs.getTimestamp("pending_increase_effective_at")?.toInstant(),
            active = rs.getBoolean("active"),
            version = rs.getLong("version"),
            createdAt = rs.getTimestamp("created_at").toInstant(),
            updatedAt = rs.getTimestamp("updated_at").toInstant()
        )
    }

    private val usageRowMapper = RowMapper<RgLimitUsageRecord> { rs: ResultSet, _ ->
        RgLimitUsageRecord(
            usageId = rs.getObject("usage_id", UUID::class.java),
            tenantId = rs.getString("tenant_id"),
            playerId = rs.getString("player_id"),
            limitType = RgLimitType.valueOf(rs.getString("limit_type")),
            period = RgLimitPeriod.valueOf(rs.getString("period")),
            periodStart = rs.getTimestamp("period_start").toInstant(),
            periodEnd = rs.getTimestamp("period_end").toInstant(),
            timezone = rs.getString("timezone"),
            consumedMinorUnits = rs.getLong("consumed_minor"),
            version = rs.getLong("version"),
            updatedAt = rs.getTimestamp("updated_at").toInstant()
        )
    }

    private val exclusionRowMapper = RowMapper<DurableExclusionRecord> { rs: ResultSet, _ ->
        DurableExclusionRecord(
            exclusionId = rs.getObject("exclusion_id", UUID::class.java),
            tenantId = rs.getString("tenant_id"),
            playerId = rs.getString("player_id"),
            exclusionType = DurableExclusionType.valueOf(rs.getString("exclusion_type")),
            status = DurableExclusionStatus.valueOf(rs.getString("status")),
            effectiveFrom = rs.getTimestamp("effective_from").toInstant(),
            expiresAt = rs.getTimestamp("expires_at")?.toInstant(),
            reason = rs.getString("reason"),
            requestedBy = rs.getString("requested_by"),
            version = rs.getLong("version"),
            createdAt = rs.getTimestamp("created_at").toInstant(),
            updatedAt = rs.getTimestamp("updated_at").toInstant(),
            evidenceReference = rs.getString("evidence_reference")
        )
    }

    override fun findLimitConfig(tenantId: String, playerId: String, limitType: RgLimitType): RgLimitConfig? {
        val sql = """
            SELECT limit_id, tenant_id, player_id, limit_type, period, limit_value_minor,
                   pending_increase_value_minor, pending_increase_effective_at, timezone,
                   product_scope, active, version, created_at, updated_at
            FROM rg_limit_configs
            WHERE tenant_id = ? AND player_id = ? AND limit_type = ?
        """.trimIndent()
        return jdbcTemplate.query(sql, limitConfigRowMapper, tenantId, playerId, limitType.name).firstOrNull()
    }

    override fun listLimitConfigs(tenantId: String, playerId: String): List<RgLimitConfig> {
        val sql = """
            SELECT limit_id, tenant_id, player_id, limit_type, period, limit_value_minor,
                   pending_increase_value_minor, pending_increase_effective_at, timezone,
                   product_scope, active, version, created_at, updated_at
            FROM rg_limit_configs
            WHERE tenant_id = ? AND player_id = ?
            ORDER BY created_at ASC
        """.trimIndent()
        return jdbcTemplate.query(sql, limitConfigRowMapper, tenantId, playerId)
    }

    override fun saveLimitConfig(config: RgLimitConfig, expectedVersion: Long?): Boolean {
        if (expectedVersion == null) {
            val insertSql = """
                INSERT INTO rg_limit_configs (
                    limit_id, tenant_id, player_id, limit_type, period, limit_value_minor,
                    pending_increase_value_minor, pending_increase_effective_at, timezone,
                    product_scope, active, version, created_at, updated_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT (tenant_id, player_id, limit_type) DO UPDATE SET
                    period = EXCLUDED.period,
                    limit_value_minor = EXCLUDED.limit_value_minor,
                    pending_increase_value_minor = EXCLUDED.pending_increase_value_minor,
                    pending_increase_effective_at = EXCLUDED.pending_increase_effective_at,
                    timezone = EXCLUDED.timezone,
                    product_scope = EXCLUDED.product_scope,
                    active = EXCLUDED.active,
                    version = EXCLUDED.version,
                    updated_at = EXCLUDED.updated_at
            """.trimIndent()
            val rows = jdbcTemplate.update(
                insertSql,
                config.limitId,
                config.tenantId,
                config.playerId,
                config.limitType.name,
                config.period.name,
                config.limitValueMinorUnits,
                config.pendingIncreaseValueMinorUnits,
                config.pendingIncreaseEffectiveAt?.let { Timestamp.from(it) },
                config.timezone,
                config.productScope,
                config.active,
                config.version,
                Timestamp.from(config.createdAt),
                Timestamp.from(config.updatedAt)
            )
            return rows > 0
        } else {
            val updateSql = """
                UPDATE rg_limit_configs SET
                    period = ?,
                    limit_value_minor = ?,
                    pending_increase_value_minor = ?,
                    pending_increase_effective_at = ?,
                    timezone = ?,
                    product_scope = ?,
                    active = ?,
                    version = ?,
                    updated_at = ?
                WHERE tenant_id = ? AND player_id = ? AND limit_type = ? AND version = ?
            """.trimIndent()
            val rows = jdbcTemplate.update(
                updateSql,
                config.period.name,
                config.limitValueMinorUnits,
                config.pendingIncreaseValueMinorUnits,
                config.pendingIncreaseEffectiveAt?.let { Timestamp.from(it) },
                config.timezone,
                config.productScope,
                config.active,
                config.version,
                Timestamp.from(config.updatedAt),
                config.tenantId,
                config.playerId,
                config.limitType.name,
                expectedVersion
            )
            return rows > 0
        }
    }

    override fun findUsage(tenantId: String, playerId: String, limitType: RgLimitType, periodStart: Instant): RgLimitUsageRecord? {
        val sql = """
            SELECT usage_id, tenant_id, player_id, limit_type, period, period_start,
                   period_end, timezone, consumed_minor, version, updated_at
            FROM rg_limit_usages
            WHERE tenant_id = ? AND player_id = ? AND limit_type = ? AND period_start = ?
        """.trimIndent()
        return jdbcTemplate.query(
            sql,
            usageRowMapper,
            tenantId,
            playerId,
            limitType.name,
            Timestamp.from(periodStart)
        ).firstOrNull()
    }

    override fun listUsages(tenantId: String, playerId: String): List<RgLimitUsageRecord> {
        val sql = """
            SELECT usage_id, tenant_id, player_id, limit_type, period, period_start,
                   period_end, timezone, consumed_minor, version, updated_at
            FROM rg_limit_usages
            WHERE tenant_id = ? AND player_id = ?
            ORDER BY period_start DESC
        """.trimIndent()
        return jdbcTemplate.query(sql, usageRowMapper, tenantId, playerId)
    }

    override fun saveUsage(usage: RgLimitUsageRecord, expectedVersion: Long?): Boolean {
        if (expectedVersion == null) {
            val insertSql = """
                INSERT INTO rg_limit_usages (
                    usage_id, tenant_id, player_id, limit_type, period, period_start,
                    period_end, timezone, consumed_minor, version, updated_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT (tenant_id, player_id, limit_type, period_start) DO UPDATE SET
                    consumed_minor = EXCLUDED.consumed_minor,
                    version = EXCLUDED.version,
                    updated_at = EXCLUDED.updated_at
            """.trimIndent()
            val rows = jdbcTemplate.update(
                insertSql,
                usage.usageId,
                usage.tenantId,
                usage.playerId,
                usage.limitType.name,
                usage.period.name,
                Timestamp.from(usage.periodStart),
                Timestamp.from(usage.periodEnd),
                usage.timezone,
                usage.consumedMinorUnits,
                usage.version,
                Timestamp.from(usage.updatedAt)
            )
            return rows > 0
        } else {
            val updateSql = """
                UPDATE rg_limit_usages SET
                    consumed_minor = ?,
                    version = ?,
                    updated_at = ?
                WHERE tenant_id = ? AND player_id = ? AND limit_type = ? AND period_start = ? AND version = ?
            """.trimIndent()
            val rows = jdbcTemplate.update(
                updateSql,
                usage.consumedMinorUnits,
                usage.version,
                Timestamp.from(usage.updatedAt),
                usage.tenantId,
                usage.playerId,
                usage.limitType.name,
                Timestamp.from(usage.periodStart),
                expectedVersion
            )
            return rows > 0
        }
    }

    override fun findActiveExclusion(tenantId: String, playerId: String, now: Instant): DurableExclusionRecord? {
        val sql = """
            SELECT exclusion_id, tenant_id, player_id, exclusion_type, status, effective_from,
                   expires_at, reason, requested_by, evidence_reference, version, created_at, updated_at
            FROM rg_exclusions
            WHERE tenant_id = ?
              AND player_id = ?
              AND status = 'ACTIVE'
              AND effective_from <= ?
              AND (expires_at IS NULL OR expires_at > ?)
            ORDER BY effective_from DESC
            LIMIT 1
        """.trimIndent()
        val ts = Timestamp.from(now)
        return jdbcTemplate.query(sql, exclusionRowMapper, tenantId, playerId, ts, ts).firstOrNull()
    }

    override fun listExclusions(tenantId: String, playerId: String): List<DurableExclusionRecord> {
        val sql = """
            SELECT exclusion_id, tenant_id, player_id, exclusion_type, status, effective_from,
                   expires_at, reason, requested_by, evidence_reference, version, created_at, updated_at
            FROM rg_exclusions
            WHERE tenant_id = ? AND player_id = ?
            ORDER BY effective_from DESC
        """.trimIndent()
        return jdbcTemplate.query(sql, exclusionRowMapper, tenantId, playerId)
    }

    override fun saveExclusion(exclusion: DurableExclusionRecord): Boolean {
        val sql = """
            INSERT INTO rg_exclusions (
                exclusion_id, tenant_id, player_id, exclusion_type, status, effective_from,
                expires_at, reason, requested_by, evidence_reference, version, created_at, updated_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT (exclusion_id) DO NOTHING
        """.trimIndent()
        val rows = jdbcTemplate.update(
            sql,
            exclusion.exclusionId,
            exclusion.tenantId,
            exclusion.playerId,
            exclusion.exclusionType.name,
            exclusion.status.name,
            Timestamp.from(exclusion.effectiveFrom),
            exclusion.expiresAt?.let { Timestamp.from(it) },
            exclusion.reason,
            exclusion.requestedBy,
            exclusion.evidenceReference,
            exclusion.version,
            Timestamp.from(exclusion.createdAt),
            Timestamp.from(exclusion.updatedAt)
        )
        return rows > 0
    }

    override fun updateExclusion(exclusion: DurableExclusionRecord, expectedVersion: Long?): Boolean {
        val sql = """
            UPDATE rg_exclusions SET
                status = ?,
                expires_at = ?,
                version = ?,
                updated_at = ?
            WHERE exclusion_id = ? AND tenant_id = ? ${if (expectedVersion != null) "AND version = ?" else ""}
        """.trimIndent()

        val rows = if (expectedVersion != null) {
            jdbcTemplate.update(
                sql,
                exclusion.status.name,
                exclusion.expiresAt?.let { Timestamp.from(it) },
                exclusion.version,
                Timestamp.from(exclusion.updatedAt),
                exclusion.exclusionId,
                exclusion.tenantId,
                expectedVersion
            )
        } else {
            jdbcTemplate.update(
                sql,
                exclusion.status.name,
                exclusion.expiresAt?.let { Timestamp.from(it) },
                exclusion.version,
                Timestamp.from(exclusion.updatedAt),
                exclusion.exclusionId,
                exclusion.tenantId
            )
        }
        return rows > 0
    }

    override fun findIdempotency(tenantId: String, idempotencyKey: String): Pair<String, Any>? {
        val sql = """
            SELECT request_fingerprint, result_json
            FROM rg_idempotency
            WHERE tenant_id = ? AND idempotency_key = ?
        """.trimIndent()
        return jdbcTemplate.query(sql, { rs, _ ->
            val fp = rs.getString("request_fingerprint")
            val json = rs.getString("result_json")
            val obj = try {
                if (json.contains("\"receiptReference\"") && json.contains("\"effectiveLimitValueMinor\"")) {
                    objectMapper.readValue(json, RgLimitChangeReceipt::class.java)
                } else if (json.contains("\"receiptReference\"") && json.contains("\"exclusion\"")) {
                    objectMapper.readValue(json, ApplyPlayerExclusionResult::class.java)
                } else {
                    json
                }
            } catch (e: Exception) {
                json
            }
            Pair(fp, obj)
        }, tenantId, idempotencyKey).firstOrNull()
    }

    override fun saveIdempotency(tenantId: String, idempotencyKey: String, fingerprint: String, result: Any) {
        val sql = """
            INSERT INTO rg_idempotency (tenant_id, idempotency_key, request_fingerprint, result_json, created_at)
            VALUES (?, ?, ?, ?, now())
            ON CONFLICT (tenant_id, idempotency_key) DO NOTHING
        """.trimIndent()
        val json = if (result is String) result else objectMapper.writeValueAsString(result)
        jdbcTemplate.update(sql, tenantId, idempotencyKey, fingerprint, json)
    }
}
