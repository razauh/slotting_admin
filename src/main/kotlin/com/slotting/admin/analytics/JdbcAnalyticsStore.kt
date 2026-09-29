package com.slotting.admin.analytics

import org.springframework.jdbc.core.JdbcTemplate
import org.springframework.jdbc.core.RowMapper
import java.sql.Date
import java.sql.ResultSet
import java.sql.Timestamp
import java.time.Instant
import java.time.LocalDate
import java.util.UUID

open class JdbcAnalyticsStore(
    private val jdbcTemplate: JdbcTemplate
) : AnalyticsStore {

    private val factRowMapper = RowMapper<AnalyticsFact> { rs: ResultSet, _ ->
        AnalyticsFact(
            factId = rs.getObject("fact_id", UUID::class.java),
            tenantId = rs.getString("tenant_id"),
            factType = AnalyticsFactType.valueOf(rs.getString("fact_type")),
            sourceEventId = rs.getString("source_event_id"),
            sourceEventType = rs.getString("source_event_type"),
            userId = rs.getString("user_id"),
            sessionId = rs.getString("session_id"),
            gameId = rs.getString("game_id"),
            providerId = rs.getString("provider_id"),
            currency = rs.getString("currency"),
            amountMinor = rs.getObject("amount_minor")?.let { (it as Number).toLong() },
            payoutMinor = rs.getObject("payout_minor")?.let { (it as Number).toLong() },
            status = FactStatus.valueOf(rs.getString("status")),
            occurredAt = rs.getTimestamp("occurred_at").toInstant(),
            recordedAt = rs.getTimestamp("recorded_at").toInstant(),
            correlationId = rs.getString("correlation_id"),
            causationId = rs.getString("causation_id"),
            metadataJson = rs.getString("metadata_json"),
        )
    }

    private val projectionRowMapper = RowMapper<DailyProjectionRecord> { rs: ResultSet, _ ->
        DailyProjectionRecord(
            projectionId = rs.getObject("projection_id", UUID::class.java),
            tenantId = rs.getString("tenant_id"),
            dateBucket = rs.getDate("date_bucket").toLocalDate(),
            currency = rs.getString("currency"),
            dimensionType = rs.getString("dimension_type"),
            dimensionValue = rs.getString("dimension_value"),
            totalWagersMinor = rs.getLong("total_wagers_minor"),
            wagerCount = rs.getLong("wager_count"),
            totalPayoutsMinor = rs.getLong("total_payouts_minor"),
            payoutCount = rs.getLong("payout_count"),
            ggrMinor = rs.getLong("ggr_minor"),
            totalDepositsMinor = rs.getLong("total_deposits_minor"),
            depositCount = rs.getLong("deposit_count"),
            totalWithdrawalsCompletedMinor = rs.getLong("total_withdrawals_completed_minor"),
            withdrawalCompletedCount = rs.getLong("withdrawal_completed_count"),
            withdrawalRejectedCount = rs.getLong("withdrawal_rejected_count"),
            activePlayersCount = rs.getLong("active_players_count"),
            newRegistrationsCount = rs.getLong("new_registrations_count"),
            authFailuresCount = rs.getLong("auth_failures_count"),
            restrictionsPlacedCount = rs.getLong("restrictions_placed_count"),
            reconciliationExceptionsCount = rs.getLong("reconciliation_exceptions_count"),
            chargebacksUnsupportedMarker = rs.getBoolean("chargebacks_unsupported_marker"),
            version = rs.getLong("version"),
            lastProcessedFactTime = rs.getTimestamp("last_processed_fact_time").toInstant(),
            updatedAt = rs.getTimestamp("updated_at").toInstant(),
        )
    }

    override fun saveFact(fact: AnalyticsFact): Boolean {
        val sql = """
            INSERT INTO analytics_facts (
                fact_id, tenant_id, fact_type, source_event_id, source_event_type,
                user_id, session_id, game_id, provider_id, currency,
                amount_minor, payout_minor, status, occurred_at, recorded_at,
                correlation_id, causation_id, metadata_json
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT (tenant_id, source_event_id) DO NOTHING
        """.trimIndent()

        val affected = jdbcTemplate.update(
            sql,
            fact.factId,
            fact.tenantId,
            fact.factType.name,
            fact.sourceEventId,
            fact.sourceEventType,
            fact.userId,
            fact.sessionId,
            fact.gameId,
            fact.providerId,
            fact.currency,
            fact.amountMinor,
            fact.payoutMinor,
            fact.status.name,
            Timestamp.from(fact.occurredAt),
            Timestamp.from(fact.recordedAt),
            fact.correlationId,
            fact.causationId,
            fact.metadataJson
        )
        return affected > 0
    }

    override fun findFactBySource(tenantId: String, sourceEventId: String): AnalyticsFact? {
        val sql = """
            SELECT fact_id, tenant_id, fact_type, source_event_id, source_event_type,
                   user_id, session_id, game_id, provider_id, currency,
                   amount_minor, payout_minor, status, occurred_at, recorded_at,
                   correlation_id, causation_id, metadata_json
            FROM analytics_facts
            WHERE tenant_id = ? AND source_event_id = ?
        """.trimIndent()
        return jdbcTemplate.query(sql, factRowMapper, tenantId, sourceEventId).firstOrNull()
    }

    override fun listFactsForTenant(tenantId: String): List<AnalyticsFact> {
        val sql = """
            SELECT fact_id, tenant_id, fact_type, source_event_id, source_event_type,
                   user_id, session_id, game_id, provider_id, currency,
                   amount_minor, payout_minor, status, occurred_at, recorded_at,
                   correlation_id, causation_id, metadata_json
            FROM analytics_facts
            WHERE tenant_id = ?
            ORDER BY occurred_at ASC
        """.trimIndent()
        return jdbcTemplate.query(sql, factRowMapper, tenantId)
    }

    override fun saveOrUpdateProjection(projection: DailyProjectionRecord) {
        val sql = """
            INSERT INTO analytics_daily_projections (
                projection_id, tenant_id, date_bucket, currency, dimension_type, dimension_value,
                total_wagers_minor, wager_count, total_payouts_minor, payout_count, ggr_minor,
                total_deposits_minor, deposit_count, total_withdrawals_completed_minor,
                withdrawal_completed_count, withdrawal_rejected_count, active_players_count,
                new_registrations_count, auth_failures_count, restrictions_placed_count,
                reconciliation_exceptions_count, chargebacks_unsupported_marker,
                version, last_processed_fact_time, updatedAt
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT (tenant_id, date_bucket, currency, dimension_type, dimension_value) DO UPDATE SET
                total_wagers_minor = EXCLUDED.total_wagers_minor,
                wager_count = EXCLUDED.wager_count,
                total_payouts_minor = EXCLUDED.total_payouts_minor,
                payout_count = EXCLUDED.payout_count,
                ggr_minor = EXCLUDED.ggr_minor,
                total_deposits_minor = EXCLUDED.total_deposits_minor,
                deposit_count = EXCLUDED.deposit_count,
                total_withdrawals_completed_minor = EXCLUDED.total_withdrawals_completed_minor,
                withdrawal_completed_count = EXCLUDED.withdrawal_completed_count,
                withdrawal_rejected_count = EXCLUDED.withdrawal_rejected_count,
                active_players_count = EXCLUDED.active_players_count,
                new_registrations_count = EXCLUDED.new_registrations_count,
                auth_failures_count = EXCLUDED.auth_failures_count,
                restrictions_placed_count = EXCLUDED.restrictions_placed_count,
                reconciliation_exceptions_count = EXCLUDED.reconciliation_exceptions_count,
                version = analytics_daily_projections.version + 1,
                last_processed_fact_time = EXCLUDED.last_processed_fact_time,
                updatedAt = EXCLUDED.updatedAt
        """.trimIndent()

        jdbcTemplate.update(
            sql,
            projection.projectionId,
            projection.tenantId,
            Date.valueOf(projection.dateBucket),
            projection.currency,
            projection.dimensionType,
            projection.dimensionValue,
            projection.totalWagersMinor,
            projection.wagerCount,
            projection.totalPayoutsMinor,
            projection.payoutCount,
            projection.ggrMinor,
            projection.totalDepositsMinor,
            projection.depositCount,
            projection.totalWithdrawalsCompletedMinor,
            projection.withdrawalCompletedCount,
            projection.withdrawalRejectedCount,
            projection.activePlayersCount,
            projection.newRegistrationsCount,
            projection.authFailuresCount,
            projection.restrictionsPlacedCount,
            projection.reconciliationExceptionsCount,
            projection.chargebacksUnsupportedMarker,
            projection.version,
            Timestamp.from(projection.lastProcessedFactTime),
            Timestamp.from(projection.updatedAt)
        )
    }

    override fun findProjection(
        tenantId: String,
        dateBucket: LocalDate,
        currency: String,
        dimensionType: String,
        dimensionValue: String
    ): DailyProjectionRecord? {
        val sql = """
            SELECT projection_id, tenant_id, date_bucket, currency, dimension_type, dimension_value,
                   total_wagers_minor, wager_count, total_payouts_minor, payout_count, ggr_minor,
                   total_deposits_minor, deposit_count, total_withdrawals_completed_minor,
                   withdrawal_completed_count, withdrawal_rejected_count, active_players_count,
                   new_registrations_count, auth_failures_count, restrictions_placed_count,
                   reconciliation_exceptions_count, chargebacks_unsupported_marker,
                   version, last_processed_fact_time, updatedAt
            FROM analytics_daily_projections
            WHERE tenant_id = ? AND date_bucket = ? AND currency = ?
              AND dimension_type = ? AND dimension_value = ?
        """.trimIndent()
        return jdbcTemplate.query(
            sql,
            projectionRowMapper,
            tenantId,
            Date.valueOf(dateBucket),
            currency,
            dimensionType,
            dimensionValue
        ).firstOrNull()
    }

    override fun queryProjections(
        tenantId: String,
        startDate: LocalDate,
        endDate: LocalDate,
        currency: String?,
        dimensionType: String,
        dimensionValue: String
    ): List<DailyProjectionRecord> {
        val sql = StringBuilder("""
            SELECT projection_id, tenant_id, date_bucket, currency, dimension_type, dimension_value,
                   total_wagers_minor, wager_count, total_payouts_minor, payout_count, ggr_minor,
                   total_deposits_minor, deposit_count, total_withdrawals_completed_minor,
                   withdrawal_completed_count, withdrawal_rejected_count, active_players_count,
                   new_registrations_count, auth_failures_count, restrictions_placed_count,
                   reconciliation_exceptions_count, chargebacks_unsupported_marker,
                   version, last_processed_fact_time, updatedAt
            FROM analytics_daily_projections
            WHERE tenant_id = ? AND date_bucket >= ? AND date_bucket <= ?
              AND dimension_type = ? AND dimension_value = ?
        """.trimIndent())
        val params = mutableListOf<Any>(
            tenantId,
            Date.valueOf(startDate),
            Date.valueOf(endDate),
            dimensionType,
            dimensionValue
        )
        if (currency != null) {
            sql.append(" AND currency = ?")
            params.add(currency)
        }
        sql.append(" ORDER BY date_bucket ASC")
        return jdbcTemplate.query(sql.toString(), projectionRowMapper, *params.toTypedArray())
    }

    override fun recordUniquePlayer(tenantId: String, dateBucket: LocalDate, userId: String, activityAt: Instant): Boolean {
        val sql = """
            INSERT INTO analytics_unique_players (tenant_id, date_bucket, user_id, first_activity_at)
            VALUES (?, ?, ?, ?)
            ON CONFLICT (tenant_id, date_bucket, user_id) DO NOTHING
        """.trimIndent()

        val affected = jdbcTemplate.update(
            sql,
            tenantId,
            Date.valueOf(dateBucket),
            userId,
            Timestamp.from(activityAt)
        )
        return affected > 0
    }

    override fun countUniquePlayers(tenantId: String, startDate: LocalDate, endDate: LocalDate): Long {
        val sql = """
            SELECT count(DISTINCT user_id)
            FROM analytics_unique_players
            WHERE tenant_id = ?
              AND date_bucket >= ?
              AND date_bucket <= ?
        """.trimIndent()
        val count = jdbcTemplate.queryForObject(
            sql,
            Long::class.java,
            tenantId,
            Date.valueOf(startDate),
            Date.valueOf(endDate)
        )
        return count ?: 0L
    }

    override fun clearProjectionsForTenant(tenantId: String) {
        jdbcTemplate.update("DELETE FROM analytics_daily_projections WHERE tenant_id = ?", tenantId)
        jdbcTemplate.update("DELETE FROM analytics_unique_players WHERE tenant_id = ?", tenantId)
    }
}
