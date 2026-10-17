package com.slotting.admin.aml

import org.springframework.jdbc.core.JdbcTemplate
import org.springframework.stereotype.Repository
import org.springframework.transaction.annotation.Transactional
import org.springframework.transaction.annotation.Propagation
import java.time.Instant
import java.util.UUID

enum class PlayAbuseRule {
    BOT_TIMING,
    CASHOUT_VELOCITY,
    LINKED_ACCOUNT_COLLUSION
}

data class CashOutDetectionInput(
    val tenantId: String,
    val playerId: String,
    val gameId: String,
    val roundId: String,
    val handId: String,
    val eventId: UUID,
    val occurredAt: Instant
)

data class PlayAbuseAlert(
    val rule: PlayAbuseRule,
    val caseReference: String,
    val linkedPlayerReferences: List<String>
)

interface PlayAbuseDetectionStore {
    fun evaluateCashOut(input: CashOutDetectionInput): List<PlayAbuseAlert>
}

@Repository
class JdbcPlayAbuseDetectionStore(private val jdbc: JdbcTemplate) : PlayAbuseDetectionStore {
    @Transactional(propagation = Propagation.REQUIRES_NEW)
    override fun evaluateCashOut(input: CashOutDetectionInput): List<PlayAbuseAlert> {
        jdbc.update(
            "insert into play_cashout_detection_event(event_id, tenant_id, player_id, game_id, round_id, hand_id, occurred_at) values (?, ?, ?, ?, ?, ?, ?) on conflict (event_id) do nothing",
            input.eventId, input.tenantId, input.playerId, input.gameId, input.roundId, input.handId, input.occurredAt
        )
        val alerts = mutableListOf<PlayAbuseAlert>()
        val recent = jdbc.query(
            "select occurred_at from play_cashout_detection_event where tenant_id = ? and player_id = ? and occurred_at >= ? order by occurred_at desc limit 10",
            { rs, _ -> rs.getTimestamp("occurred_at").toInstant() },
            input.tenantId, input.playerId, input.occurredAt.minusSeconds(600)
        )
        if (recent.size >= 5) {
            val intervals = recent.zipWithNext { newer, older -> newer.toEpochMilli() - older.toEpochMilli() }
            if (intervals.all { it in 1..120_000 } && intervals.max() - intervals.min() <= 100L) {
                addAlert(input, PlayAbuseRule.BOT_TIMING, emptyList())?.let(alerts::add)
            }
        }
        val velocityCount = jdbc.queryForObject(
            "select count(*) from play_cashout_detection_event where tenant_id = ? and player_id = ? and occurred_at >= ?",
            Long::class.java, input.tenantId, input.playerId, input.occurredAt.minusSeconds(600)
        ) ?: 0L
        if (velocityCount >= 8L) addAlert(input, PlayAbuseRule.CASHOUT_VELOCITY, emptyList())?.let(alerts::add)
        val linkedPlayers = jdbc.query(
            "select linked_player_id from player_account_link where tenant_id = ? and player_id = ?",
            { rs, _ -> rs.getString("linked_player_id") }, input.tenantId, input.playerId
        )
        if (linkedPlayers.isNotEmpty()) {
            val placeholders = linkedPlayers.joinToString(",") { "?" }
            val parameters = arrayOf(input.tenantId, input.gameId, input.roundId, input.occurredAt.minusSeconds(120), *linkedPlayers.toTypedArray())
            val linkedCount = jdbc.queryForObject(
                "select count(distinct player_id) from play_cashout_detection_event where tenant_id = ? and game_id = ? and round_id = ? and occurred_at >= ? and player_id in ($placeholders)",
                Long::class.java, *parameters
            ) ?: 0L
            if (linkedCount > 0L) addAlert(input, PlayAbuseRule.LINKED_ACCOUNT_COLLUSION, linkedPlayers)?.let(alerts::add)
        }
        return alerts
    }

    private fun addAlert(input: CashOutDetectionInput, rule: PlayAbuseRule, linkedPlayers: List<String>): PlayAbuseAlert? {
        val windowStart = input.occurredAt.epochSecond / 600 * 600
        val caseReference = "AUTO-${rule.name}-${input.playerId}-$windowStart"
        val inserted = jdbc.update(
            "insert into play_abuse_alert(tenant_id, case_reference, player_id, rule_code, linked_player_references, window_start, created_at, session_flagged) values (?, ?, ?, ?, ?, to_timestamp(?), ?, true) on conflict (tenant_id, case_reference) do nothing",
            input.tenantId, caseReference, input.playerId, rule.name, linkedPlayers.joinToString(","), windowStart, input.occurredAt
        )
        if (inserted == 0) return null
        jdbc.update(
            "insert into admin_aml_review_queue(tenant_id, case_reference, state, claimed_by, claim_expires_at, server_version, updated_at) values (?, ?, 'QUEUED', null, null, 0, ?) on conflict (tenant_id, case_reference) do nothing",
            input.tenantId, caseReference, input.occurredAt
        )
        return PlayAbuseAlert(rule, caseReference, linkedPlayers)
    }
}
