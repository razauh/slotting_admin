package com.slotting.admin.gameprovider

import org.springframework.jdbc.core.JdbcTemplate

data class DuplicateSequenceDiagnostic(
    val tenantId: String,
    val sequenceId: Long,
    val count: Long,
)

object CommandSequenceDiagnostics {
    fun detectDuplicateReceiptSequences(jdbc: JdbcTemplate): List<DuplicateSequenceDiagnostic> {
        val sql = """
            select tenant_id, server_sequence_id, count(*) as cnt
            from game_command_receipt
            group by tenant_id, server_sequence_id
            having count(*) > 1
        """.trimIndent()
        return jdbc.query(sql) { rs, _ ->
            DuplicateSequenceDiagnostic(
                tenantId = rs.getString("tenant_id"),
                sequenceId = rs.getLong("server_sequence_id"),
                count = rs.getLong("cnt"),
            )
        }
    }

    fun validateOrAbortMigration(jdbc: JdbcTemplate) {
        val duplicates = detectDuplicateReceiptSequences(jdbc)
        if (duplicates.isNotEmpty()) {
            val diagnosticDetails = duplicates.joinToString("; ") {
                "${it.tenantId}/${it.sequenceId} count=${it.count}"
            }
            throw IllegalStateException(
                "Duplicate command sequence detected: $diagnosticDetails (total conflict groups: ${duplicates.size})"
            )
        }
    }
}
