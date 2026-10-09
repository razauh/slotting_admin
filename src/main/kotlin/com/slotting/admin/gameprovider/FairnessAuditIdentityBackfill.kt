package com.slotting.admin.gameprovider

import org.springframework.jdbc.core.JdbcTemplate
import org.springframework.stereotype.Component
import java.util.UUID

data class FairnessAuditBackfillRow(
    val tenantId: String,
    val roundId: String,
    val gameId: String,
    val commitmentId: UUID,
)

data class FairnessAuditBackfillPlan(
    val eligible: List<FairnessAuditBackfillRow>,
    val blocked: List<FairnessEvidenceConflict>,
)

data class FairnessAuditBackfillResult(
    val beforeCanonical: Int,
    val afterCanonical: Int,
    val updatedRows: Int,
)

@Component
class FairnessAuditIdentityBackfill(
    private val jdbc: JdbcTemplate,
    private val diagnostic: FairnessEvidenceRepairDiagnostic,
) {
    fun plan(tenantId: String): FairnessAuditBackfillPlan {
        val blocked = diagnostic.blockingConflicts(tenantId)
        if (blocked.isNotEmpty()) {
            return FairnessAuditBackfillPlan(emptyList(), blocked)
        }

        val eligible = jdbc.query(
            """
            select a.tenant_id, a.round_id, c.game_id, c.commitment_id
            from game_fairness_audit a
            join game_fairness_commitment c
              on c.tenant_id = a.tenant_id and c.round_id = a.round_id
            where a.tenant_id = ? and a.action = ? and a.commitment_id is null
              and (select count(*) from game_fairness_commitment c2
                   where c2.tenant_id = a.tenant_id and c2.round_id = a.round_id) = 1
              and not exists (
                  select 1 from game_fairness_audit b
                  where b.tenant_id = a.tenant_id
                    and b.commitment_id = c.commitment_id
                    and b.event_key = ?
              )
            """.trimIndent(),
            { rs, _ ->
                FairnessAuditBackfillRow(
                    tenantId = rs.getString("tenant_id"),
                    roundId = rs.getString("round_id"),
                    gameId = rs.getString("game_id"),
                    commitmentId = rs.getObject("commitment_id", UUID::class.java),
                )
            },
            tenantId,
            ProvablyFairOutcomeAuthority.REVEAL_EVENT_KEY,
            ProvablyFairOutcomeAuthority.REVEAL_EVENT_KEY,
        )

        return FairnessAuditBackfillPlan(eligible, emptyList())
    }

    fun execute(tenantId: String): FairnessAuditBackfillResult {
        val beforeCanonical = canonicalCount(tenantId)
        val plan = plan(tenantId)
        if (plan.blocked.isNotEmpty()) {
            throw FairnessEvidenceReconcileException(
                conflicts = plan.blocked,
                message = "Fairness audit identity backfill refused; unresolved evidence identities: " +
                    plan.blocked.joinToString("; ") { "${it.tenantId}/${it.gameId}/${it.roundId}/${it.commitmentId}[${it.kind}]" },
            )
        }

        var updatedRows = 0
        for (row in plan.eligible) {
            updatedRows += jdbc.update(
                """
                update game_fairness_audit
                set game_id = ?, commitment_id = ?, event_key = ?
                where tenant_id = ? and round_id = ? and action = ?
                  and commitment_id is null
                """.trimIndent(),
                row.gameId,
                row.commitmentId,
                ProvablyFairOutcomeAuthority.REVEAL_EVENT_KEY,
                row.tenantId,
                row.roundId,
                ProvablyFairOutcomeAuthority.REVEAL_EVENT_KEY,
            )
        }

        return FairnessAuditBackfillResult(
            beforeCanonical = beforeCanonical,
            afterCanonical = canonicalCount(tenantId),
            updatedRows = updatedRows,
        )
    }

    private fun canonicalCount(tenantId: String): Int =
        jdbc.queryForObject(
            "select count(*) from game_fairness_audit where tenant_id = ? and commitment_id is not null and event_key is not null",
            Int::class.java,
            tenantId,
        ) ?: 0
}
