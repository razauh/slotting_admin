package com.slotting.admin.gameprovider

import org.springframework.jdbc.core.JdbcTemplate

data class DuplicateActiveRoundDiagnostic(
    val tenantId: String,
    val gameId: String,
    val count: Long,
    val roundIds: List<String>,
)

object AviatorActiveRoundDiagnostics {
    fun detectDuplicateActiveRounds(jdbc: JdbcTemplate): List<DuplicateActiveRoundDiagnostic> {
        val sql = """
            select tenant_id, game_id, count(*) as cnt, string_agg(round_id, ', ' order by round_id) as round_ids
            from game_authoritative_round
            where phase <> 'CLOSED'
            group by tenant_id, game_id
            having count(*) > 1
        """.trimIndent()
        return jdbc.query(sql) { rs, _ ->
            val roundsStr = rs.getString("round_ids") ?: ""
            DuplicateActiveRoundDiagnostic(
                tenantId = rs.getString("tenant_id"),
                gameId = rs.getString("game_id"),
                count = rs.getLong("cnt"),
                roundIds = roundsStr.split(", ").filter { it.isNotBlank() },
            )
        }
    }

    fun validateOrAbortMigration(jdbc: JdbcTemplate) {
        val duplicates = detectDuplicateActiveRounds(jdbc)
        if (duplicates.isNotEmpty()) {
            val diagnosticDetails = duplicates.joinToString("; ") {
                "${it.tenantId}/${it.gameId} count=${it.count} rounds=[${it.roundIds.joinToString(", ")}]"
            }
            throw IllegalStateException(
                "Duplicate active rounds detected: $diagnosticDetails (total conflict groups: ${duplicates.size})"
            )
        }
    }
}
