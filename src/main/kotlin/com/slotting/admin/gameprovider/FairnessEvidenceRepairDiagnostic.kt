package com.slotting.admin.gameprovider

import org.springframework.jdbc.core.JdbcTemplate
import org.springframework.stereotype.Component

enum class FairnessEvidenceConflictKind {
    DUPLICATE_REVEAL,
    DUPLICATE_AUDIT_EVENT,
    PARTIAL_REVEAL,
    DUPLICATE_LEGACY_AUDIT,
    AMBIGUOUS_AUDIT_MAPPING,
}

data class FairnessEvidenceConflict(
    val tenantId: String,
    val gameId: String?,
    val roundId: String,
    val commitmentId: java.util.UUID?,
    val kind: FairnessEvidenceConflictKind,
    val detail: String,
)

class FairnessEvidenceReconcileException(
    val conflicts: List<FairnessEvidenceConflict>,
    message: String,
) : RuntimeException(message)

@Component
class FairnessEvidenceRepairDiagnostic(
    private val jdbc: JdbcTemplate,
) {
    fun conflicts(tenantId: String): List<FairnessEvidenceConflict> {
        val found = mutableListOf<FairnessEvidenceConflict>()

        jdbc.queryForList(
            """
            select tenant_id, game_id, round_id, count(*) as cnt
            from game_fairness_reveal
            where tenant_id = ?
            group by tenant_id, game_id, round_id
            having count(*) > 1
            """.trimIndent(),
            tenantId,
        ).forEach { row ->
            found.add(
                FairnessEvidenceConflict(
                    tenantId = row["tenant_id"] as String,
                    gameId = row["game_id"] as String?,
                    roundId = row["round_id"] as String,
                    commitmentId = null,
                    kind = FairnessEvidenceConflictKind.DUPLICATE_REVEAL,
                    detail = "duplicate reveal rows count=${row["cnt"]}",
                )
            )
        }

        jdbc.queryForList(
            """
            select tenant_id, commitment_id, event_key, count(*) as cnt
            from game_fairness_audit
            where tenant_id = ? and commitment_id is not null and event_key is not null
            group by tenant_id, commitment_id, event_key
            having count(*) > 1
            """.trimIndent(),
            tenantId,
        ).forEach { row ->
            found.add(
                FairnessEvidenceConflict(
                    tenantId = row["tenant_id"] as String,
                    gameId = null,
                    roundId = "",
                    commitmentId = row["commitment_id"] as java.util.UUID?,
                    kind = FairnessEvidenceConflictKind.DUPLICATE_AUDIT_EVENT,
                    detail = "duplicate canonical audit event ${row["event_key"]} count=${row["cnt"]}",
                )
            )
        }

        jdbc.queryForList(
            """
            select a.tenant_id, a.round_id,
                   count(distinct c.commitment_id) as commitment_matches,
                   count(*) as audit_rows
            from game_fairness_audit a
            left join game_fairness_commitment c
              on c.tenant_id = a.tenant_id and c.round_id = a.round_id
            where a.tenant_id = ? and a.action = ? and a.commitment_id is null
            group by a.tenant_id, a.round_id
            """.trimIndent(),
            tenantId, ProvablyFairOutcomeAuthority.REVEAL_EVENT_KEY,
        ).forEach { row ->
            val matches = (row["commitment_matches"] as Number).toInt()
            val rows = (row["audit_rows"] as Number).toInt()
            if (matches == 0) {
                found.add(
                    FairnessEvidenceConflict(
                        tenantId = row["tenant_id"] as String,
                        gameId = null,
                        roundId = row["round_id"] as String,
                        commitmentId = null,
                        kind = FairnessEvidenceConflictKind.AMBIGUOUS_AUDIT_MAPPING,
                        detail = "legacy verified audit maps to no commitment (orphan)",
                    )
                )
            } else if (matches > 1) {
                found.add(
                    FairnessEvidenceConflict(
                        tenantId = row["tenant_id"] as String,
                        gameId = null,
                        roundId = row["round_id"] as String,
                        commitmentId = null,
                        kind = FairnessEvidenceConflictKind.AMBIGUOUS_AUDIT_MAPPING,
                        detail = "legacy verified audit maps to $matches commitments",
                    )
                )
            } else if (rows > 1) {
                found.add(
                    FairnessEvidenceConflict(
                        tenantId = row["tenant_id"] as String,
                        gameId = null,
                        roundId = row["round_id"] as String,
                        commitmentId = null,
                        kind = FairnessEvidenceConflictKind.DUPLICATE_LEGACY_AUDIT,
                        detail = "duplicate legacy verified reveal audits count=$rows",
                    )
                )
            }
        }

        jdbc.queryForList(
            """
            select a.tenant_id, a.round_id, c.commitment_id
            from game_fairness_audit a
            join game_fairness_commitment c
              on c.tenant_id = a.tenant_id and c.round_id = a.round_id
            where a.tenant_id = ? and a.action = ? and a.commitment_id is null
              and (select count(*) from game_fairness_commitment c2
                   where c2.tenant_id = a.tenant_id and c2.round_id = a.round_id) = 1
              and exists (
                  select 1 from game_fairness_audit b
                  where b.tenant_id = a.tenant_id
                    and b.commitment_id = c.commitment_id
                    and b.event_key = ?
              )
            """.trimIndent(),
            tenantId, ProvablyFairOutcomeAuthority.REVEAL_EVENT_KEY, ProvablyFairOutcomeAuthority.REVEAL_EVENT_KEY,
        ).forEach { row ->
            found.add(
                FairnessEvidenceConflict(
                    tenantId = row["tenant_id"] as String,
                    gameId = null,
                    roundId = row["round_id"] as String,
                    commitmentId = row["commitment_id"] as java.util.UUID?,
                    kind = FairnessEvidenceConflictKind.DUPLICATE_LEGACY_AUDIT,
                    detail = "legacy verified audit duplicates an existing canonical reveal event",
                )
            )
        }

        jdbc.queryForList(
            """
            select c.tenant_id, c.game_id, c.round_id
            from game_fairness_commitment c
            where c.tenant_id = ? and c.status = 'REVEALED'
              and not exists (
                  select 1 from game_fairness_reveal r
                  where r.tenant_id = c.tenant_id and r.game_id = c.game_id and r.round_id = c.round_id
              )
            """.trimIndent(),
            tenantId,
        ).forEach { row ->
            found.add(
                FairnessEvidenceConflict(
                    tenantId = row["tenant_id"] as String,
                    gameId = row["game_id"] as String?,
                    roundId = row["round_id"] as String,
                    commitmentId = null,
                    kind = FairnessEvidenceConflictKind.PARTIAL_REVEAL,
                    detail = "REVEALED commitment has no reveal evidence row",
                )
            )
        }

        return found
    }

    fun blockingConflicts(tenantId: String): List<FairnessEvidenceConflict> =
        conflicts(tenantId).filter { it.kind != FairnessEvidenceConflictKind.PARTIAL_REVEAL }

    fun assertReconcilable(tenantId: String) {
        val blocking = blockingConflicts(tenantId)
        if (blocking.isNotEmpty()) {
            throw FairnessEvidenceReconcileException(
                conflicts = blocking,
                message = "Fairness evidence duplicate identities block index creation: " +
                    blocking.joinToString("; ") { "${it.tenantId}/${it.gameId}/${it.roundId}/${it.commitmentId}[${it.kind}]" },
            )
        }
    }
}
