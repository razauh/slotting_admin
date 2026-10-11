package com.slotting.admin.gameprovider

import org.springframework.jdbc.core.JdbcTemplate

internal fun closeActiveRoundsFor(
    jdbc: JdbcTemplate,
    tenantId: String,
    gameId: String,
    keepRoundId: String? = null,
) {
    if (keepRoundId == null) {
        jdbc.update(
            "update game_authoritative_round set phase = 'CLOSED', closed_at = now(), updated_at = now() where tenant_id = ? and game_id = ? and phase <> 'CLOSED'",
            tenantId,
            gameId,
        )
    } else {
        jdbc.update(
            "update game_authoritative_round set phase = 'CLOSED', closed_at = now(), updated_at = now() where tenant_id = ? and game_id = ? and phase <> 'CLOSED' and round_id <> ?",
            tenantId,
            gameId,
            keepRoundId,
        )
    }
}
