package com.slotting.admin.gameprovider

import org.springframework.jdbc.core.JdbcTemplate

fun interface OutcomeFinalizationPort {
    fun isFinalizedOutcome(tenantId: String, gameId: String, roundId: String): Boolean
}

class JdbcOutcomeFinalizationPort(
    private val jdbc: JdbcTemplate,
) : OutcomeFinalizationPort {
    override fun isFinalizedOutcome(tenantId: String, gameId: String, roundId: String): Boolean {
        val count = jdbc.queryForObject(
            """
            select count(*) from game_authoritative_round
            where tenant_id = ? and game_id = ? and round_id = ?
              and phase in ('CRASHED', 'CLOSED')
              and crash_multiplier is not null
            """.trimIndent(),
            Int::class.java, tenantId, gameId, roundId,
        ) ?: 0
        return count > 0
    }
}
