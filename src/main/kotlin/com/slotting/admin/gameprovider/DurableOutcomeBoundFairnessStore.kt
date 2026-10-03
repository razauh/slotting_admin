package com.slotting.admin.gameprovider

import org.springframework.jdbc.core.JdbcTemplate
import org.springframework.stereotype.Repository
import org.springframework.transaction.annotation.Transactional
import java.sql.ResultSet
import java.sql.Timestamp
import java.util.UUID
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.CopyOnWriteArrayList

interface FairnessEvidenceStore {
    fun findCommitment(tenantId: String, gameId: String, roundId: String): RoundCommitmentRecord?
    fun saveCommitment(commitment: RoundCommitmentRecord)
    fun updateCommitment(commitment: RoundCommitmentRecord)
    fun findReveal(tenantId: String, gameId: String, roundId: String): RoundRevealRecord?
    fun saveReveal(reveal: RoundRevealRecord)
    fun saveAuditEvent(event: FairnessAuditRecord)
    fun findAuditEvents(tenantId: String, roundId: String): List<FairnessAuditRecord>
}

open class InMemoryFairnessEvidenceStore : FairnessEvidenceStore {
    private val commitments = ConcurrentHashMap<String, RoundCommitmentRecord>()
    private val reveals = ConcurrentHashMap<String, RoundRevealRecord>()
    private val auditLogs = CopyOnWriteArrayList<FairnessAuditRecord>()

    private fun key(tenantId: String, gameId: String, roundId: String) = "$tenantId:$gameId:$roundId"

    override fun findCommitment(tenantId: String, gameId: String, roundId: String): RoundCommitmentRecord? {
        return commitments[key(tenantId, gameId, roundId)]?.copy()
    }

    @Synchronized
    override fun saveCommitment(commitment: RoundCommitmentRecord) {
        val k = key(commitment.tenantId, commitment.gameId, commitment.roundId)
        if (commitments.containsKey(k)) {
            throw FairnessAuthorityException("DUPLICATE_ROUND_COMMITMENT", "Commitment already exists for round ${commitment.roundId}")
        }
        commitments[k] = commitment.copy()
    }

    @Synchronized
    override fun updateCommitment(commitment: RoundCommitmentRecord) {
        val k = key(commitment.tenantId, commitment.gameId, commitment.roundId)
        commitments[k] = commitment.copy()
    }

    override fun findReveal(tenantId: String, gameId: String, roundId: String): RoundRevealRecord? {
        return reveals[key(tenantId, gameId, roundId)]?.copy()
    }

    @Synchronized
    override fun saveReveal(reveal: RoundRevealRecord) {
        val k = key(reveal.tenantId, reveal.gameId, reveal.roundId)
        if (reveals.containsKey(k)) {
            throw FairnessAuthorityException("DUPLICATE_ROUND_REVEAL", "Reveal already exists for round ${reveal.roundId}")
        }
        reveals[k] = reveal.copy()
    }

    override fun saveAuditEvent(event: FairnessAuditRecord) {
        auditLogs.add(event)
    }

    override fun findAuditEvents(tenantId: String, roundId: String): List<FairnessAuditRecord> {
        return auditLogs.filter { it.tenantId == tenantId && it.roundId == roundId }
    }
}

@Repository
open class JdbcFairnessEvidenceStore(
    private val jdbcTemplate: JdbcTemplate
) : FairnessEvidenceStore {

    override fun findCommitment(tenantId: String, gameId: String, roundId: String): RoundCommitmentRecord? {
        val sql = """
            select commitment_id, tenant_id, game_id, round_id, authority_type, algorithm_version,
                   rules_version, commitment_hash, public_salt, encrypted_secret_seed,
                   committed_at, first_bet_accepted_at, status, server_version, created_at, updated_at,
                   client_seed1, client_seed2, client_seed3
            from game_fairness_commitment
            where tenant_id = ? and game_id = ? and round_id = ?
        """.trimIndent()
        val list = jdbcTemplate.query(sql, { rs, _ -> mapCommitment(rs) }, tenantId, gameId, roundId)
        return list.firstOrNull()
    }

    @Transactional
    override fun saveCommitment(commitment: RoundCommitmentRecord) {
        val sql = """
            insert into game_fairness_commitment (
                commitment_id, tenant_id, game_id, round_id, authority_type, algorithm_version,
                rules_version, commitment_hash, public_salt, encrypted_secret_seed, committed_at,
                first_bet_accepted_at, status, server_version, created_at, updated_at,
                client_seed1, client_seed2, client_seed3
            ) values (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """.trimIndent()
        jdbcTemplate.update(
            sql,
            commitment.commitmentId,
            commitment.tenantId,
            commitment.gameId,
            commitment.roundId,
            commitment.authorityType.name,
            commitment.algorithmVersion,
            commitment.rulesVersion,
            commitment.commitmentHash,
            commitment.publicSalt,
            commitment.encryptedSecretSeed,
            Timestamp.from(commitment.committedAt),
            commitment.firstBetAcceptedAt?.let { Timestamp.from(it) },
            commitment.status.name,
            commitment.serverVersion,
            Timestamp.from(commitment.createdAt),
            Timestamp.from(commitment.updatedAt),
            commitment.clientSeed1,
            commitment.clientSeed2,
            commitment.clientSeed3
        )
    }

    @Transactional
    override fun updateCommitment(commitment: RoundCommitmentRecord) {
        val sql = """
            update game_fairness_commitment
            set first_bet_accepted_at = ?, status = ?, server_version = server_version + 1, updated_at = ?,
                client_seed1 = ?, client_seed2 = ?, client_seed3 = ?
            where commitment_id = ? and tenant_id = ?
        """.trimIndent()
        jdbcTemplate.update(
            sql,
            commitment.firstBetAcceptedAt?.let { Timestamp.from(it) },
            commitment.status.name,
            Timestamp.from(commitment.updatedAt),
            commitment.clientSeed1,
            commitment.clientSeed2,
            commitment.clientSeed3,
            commitment.commitmentId,
            commitment.tenantId
        )
    }

    override fun findReveal(tenantId: String, gameId: String, roundId: String): RoundRevealRecord? {
        val sql = """
            select reveal_id, commitment_id, tenant_id, game_id, round_id, revealed_secret_seed,
                   derived_multiplier, revealed_at, verification_status, verification_error, evidence_reference
            from game_fairness_reveal
            where tenant_id = ? and game_id = ? and round_id = ?
        """.trimIndent()
        val list = jdbcTemplate.query(sql, { rs, _ -> mapReveal(rs) }, tenantId, gameId, roundId)
        return list.firstOrNull()
    }

    @Transactional
    override fun saveReveal(reveal: RoundRevealRecord) {
        val sql = """
            insert into game_fairness_reveal (
                reveal_id, commitment_id, tenant_id, game_id, round_id, revealed_secret_seed,
                derived_multiplier, revealed_at, verification_status, verification_error, evidence_reference
            ) values (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """.trimIndent()
        jdbcTemplate.update(
            sql,
            reveal.revealId,
            reveal.commitmentId,
            reveal.tenantId,
            reveal.gameId,
            reveal.roundId,
            reveal.revealedSecretSeed,
            reveal.derivedMultiplier,
            Timestamp.from(reveal.revealedAt),
            reveal.verificationStatus.name,
            reveal.verificationError,
            reveal.evidenceReference
        )
    }

    @Transactional
    override fun saveAuditEvent(event: FairnessAuditRecord) {
        val sql = """
            insert into game_fairness_audit (
                audit_id, tenant_id, round_id, action, actor, detail, occurred_at
            ) values (?, ?, ?, ?, ?, ?, ?)
        """.trimIndent()
        jdbcTemplate.update(
            sql,
            event.auditId,
            event.tenantId,
            event.roundId,
            event.action,
            event.actor,
            event.detail,
            Timestamp.from(event.occurredAt)
        )
    }

    override fun findAuditEvents(tenantId: String, roundId: String): List<FairnessAuditRecord> {
        val sql = """
            select audit_id, tenant_id, round_id, action, actor, detail, occurred_at
            from game_fairness_audit
            where tenant_id = ? and round_id = ?
            order by occurred_at asc
        """.trimIndent()
        return jdbcTemplate.query(sql, { rs, _ -> mapAudit(rs) }, tenantId, roundId)
    }

    private fun mapCommitment(rs: ResultSet): RoundCommitmentRecord {
        return RoundCommitmentRecord(
            commitmentId = rs.getObject("commitment_id", UUID::class.java),
            tenantId = rs.getString("tenant_id"),
            gameId = rs.getString("game_id"),
            roundId = rs.getString("round_id"),
            authorityType = FairnessAuthorityType.valueOf(rs.getString("authority_type")),
            algorithmVersion = rs.getString("algorithm_version"),
            rulesVersion = rs.getString("rules_version"),
            commitmentHash = rs.getString("commitment_hash"),
            publicSalt = rs.getString("public_salt"),
            encryptedSecretSeed = rs.getString("encrypted_secret_seed"),
            committedAt = rs.getTimestamp("committed_at").toInstant(),
            firstBetAcceptedAt = rs.getTimestamp("first_bet_accepted_at")?.toInstant(),
            status = RoundCommitmentStatus.valueOf(rs.getString("status")),
            serverVersion = rs.getLong("server_version"),
            createdAt = rs.getTimestamp("created_at").toInstant(),
            updatedAt = rs.getTimestamp("updated_at").toInstant(),
            clientSeed1 = runCatching { rs.getString("client_seed1") }.getOrNull(),
            clientSeed2 = runCatching { rs.getString("client_seed2") }.getOrNull(),
            clientSeed3 = runCatching { rs.getString("client_seed3") }.getOrNull(),
        )
    }

    private fun mapReveal(rs: ResultSet): RoundRevealRecord {
        return RoundRevealRecord(
            revealId = rs.getObject("reveal_id", UUID::class.java),
            commitmentId = rs.getObject("commitment_id", UUID::class.java),
            tenantId = rs.getString("tenant_id"),
            gameId = rs.getString("game_id"),
            roundId = rs.getString("round_id"),
            revealedSecretSeed = rs.getString("revealed_secret_seed"),
            derivedMultiplier = rs.getBigDecimal("derived_multiplier"),
            revealedAt = rs.getTimestamp("revealed_at").toInstant(),
            verificationStatus = FairnessVerificationStatus.valueOf(rs.getString("verification_status")),
            verificationError = rs.getString("verification_error"),
            evidenceReference = rs.getString("evidence_reference"),
        )
    }

    private fun mapAudit(rs: ResultSet): FairnessAuditRecord {
        return FairnessAuditRecord(
            auditId = rs.getObject("audit_id", UUID::class.java),
            tenantId = rs.getString("tenant_id"),
            roundId = rs.getString("round_id"),
            action = rs.getString("action"),
            actor = rs.getString("actor"),
            detail = rs.getString("detail"),
            occurredAt = rs.getTimestamp("occurred_at").toInstant(),
        )
    }
}
