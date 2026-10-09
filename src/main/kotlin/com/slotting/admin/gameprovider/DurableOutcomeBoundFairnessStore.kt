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
    fun findAllCommitments(tenantId: String): List<RoundCommitmentRecord>
    fun saveCommitment(commitment: RoundCommitmentRecord)
    fun updateCommitment(commitment: RoundCommitmentRecord)
    fun compareAndSetCommitment(
        commitment: RoundCommitmentRecord,
        expectedServerVersion: Long,
        expectedStatuses: Set<RoundCommitmentStatus>,
    ): Boolean
    fun existsAuditEvent(tenantId: String, commitmentId: java.util.UUID, eventKey: String): Boolean
    fun rotateCommitmentEnvelope(
        commitmentId: java.util.UUID,
        tenantId: String,
        expectedServerVersion: Long,
        encryptedSeed: String,
        nonce: String,
        keyId: String,
        keyVersion: Int,
        formatVersion: Int,
        updatedAt: java.time.Instant,
    ): Boolean
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

    override fun findAllCommitments(tenantId: String): List<RoundCommitmentRecord> {
        return commitments.values.filter { it.tenantId == tenantId }.map { it.copy() }.sortedBy { it.commitmentId }
    }

    @Synchronized
    override fun rotateCommitmentEnvelope(
        commitmentId: java.util.UUID,
        tenantId: String,
        expectedServerVersion: Long,
        encryptedSeed: String,
        nonce: String,
        keyId: String,
        keyVersion: Int,
        formatVersion: Int,
        updatedAt: java.time.Instant,
    ): Boolean {
        val entry = commitments.entries.firstOrNull { it.value.commitmentId == commitmentId && it.value.tenantId == tenantId }
            ?: return false
        if (entry.value.serverVersion != expectedServerVersion) return false
        commitments[entry.key] = entry.value.copy(
            encryptedSecretSeed = encryptedSeed,
            secretNonce = nonce,
            secretKeyId = keyId,
            secretKeyVersion = keyVersion,
            secretFormatVersion = formatVersion,
            serverVersion = expectedServerVersion + 1,
            updatedAt = updatedAt,
        )
        return true
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

    @Synchronized
    override fun compareAndSetCommitment(
        commitment: RoundCommitmentRecord,
        expectedServerVersion: Long,
        expectedStatuses: Set<RoundCommitmentStatus>,
    ): Boolean {
        val entry = commitments.entries.firstOrNull { it.value.commitmentId == commitment.commitmentId && it.value.tenantId == commitment.tenantId }
            ?: return false
        val current = entry.value
        if (current.serverVersion != expectedServerVersion || current.status !in expectedStatuses) return false
        commitments[entry.key] = current.copy(
            status = commitment.status,
            firstBetAcceptedAt = commitment.firstBetAcceptedAt,
            clientSeed1 = commitment.clientSeed1,
            clientSeed2 = commitment.clientSeed2,
            clientSeed3 = commitment.clientSeed3,
            serverVersion = expectedServerVersion + 1,
            updatedAt = commitment.updatedAt,
        )
        return true
    }

    override fun existsAuditEvent(tenantId: String, commitmentId: java.util.UUID, eventKey: String): Boolean =
        auditLogs.any { it.tenantId == tenantId && it.commitmentId == commitmentId && it.eventKey == eventKey }

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
                   client_seed1, client_seed2, client_seed3,
                   secret_nonce, secret_key_id, secret_key_version, secret_format_version
            from game_fairness_commitment
            where tenant_id = ? and game_id = ? and round_id = ?
        """.trimIndent()
        val list = jdbcTemplate.query(sql, { rs, _ -> mapCommitment(rs) }, tenantId, gameId, roundId)
        return list.firstOrNull()
    }

    override fun findAllCommitments(tenantId: String): List<RoundCommitmentRecord> {
        val sql = """
            select commitment_id, tenant_id, game_id, round_id, authority_type, algorithm_version,
                   rules_version, commitment_hash, public_salt, encrypted_secret_seed,
                   committed_at, first_bet_accepted_at, status, server_version, created_at, updated_at,
                   client_seed1, client_seed2, client_seed3,
                   secret_nonce, secret_key_id, secret_key_version, secret_format_version
            from game_fairness_commitment
            where tenant_id = ?
            order by commitment_id asc
        """.trimIndent()
        return jdbcTemplate.query(sql, { rs, _ -> mapCommitment(rs) }, tenantId)
    }

    @Transactional
    override fun rotateCommitmentEnvelope(
        commitmentId: java.util.UUID,
        tenantId: String,
        expectedServerVersion: Long,
        encryptedSeed: String,
        nonce: String,
        keyId: String,
        keyVersion: Int,
        formatVersion: Int,
        updatedAt: java.time.Instant,
    ): Boolean {
        val sql = """
            update game_fairness_commitment
            set encrypted_secret_seed = ?, secret_nonce = ?, secret_key_id = ?,
                secret_key_version = ?, secret_format_version = ?,
                server_version = server_version + 1, updated_at = ?
            where commitment_id = ? and tenant_id = ? and server_version = ?
        """.trimIndent()
        val updated = jdbcTemplate.update(
            sql,
            encryptedSeed,
            nonce,
            keyId,
            keyVersion,
            formatVersion,
            Timestamp.from(updatedAt),
            commitmentId,
            tenantId,
            expectedServerVersion,
        )
        return updated == 1
    }

    @Transactional
    override fun saveCommitment(commitment: RoundCommitmentRecord) {
        val sql = """
            insert into game_fairness_commitment (
                commitment_id, tenant_id, game_id, round_id, authority_type, algorithm_version,
                rules_version, commitment_hash, public_salt, encrypted_secret_seed, committed_at,
                first_bet_accepted_at, status, server_version, created_at, updated_at,
                client_seed1, client_seed2, client_seed3,
                secret_nonce, secret_key_id, secret_key_version, secret_format_version
            ) values (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
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
            commitment.clientSeed3,
            commitment.secretNonce,
            commitment.secretKeyId,
            commitment.secretKeyVersion,
            commitment.secretFormatVersion
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

    @Transactional
    override fun compareAndSetCommitment(
        commitment: RoundCommitmentRecord,
        expectedServerVersion: Long,
        expectedStatuses: Set<RoundCommitmentStatus>,
    ): Boolean {
        val placeholders = expectedStatuses.joinToString(", ") { "?" }
        val sql = """
            update game_fairness_commitment
            set first_bet_accepted_at = ?, status = ?, server_version = server_version + 1, updated_at = ?,
                client_seed1 = ?, client_seed2 = ?, client_seed3 = ?
            where commitment_id = ? and tenant_id = ? and server_version = ?
              and status in ($placeholders)
        """.trimIndent()
        val args = ArrayList<Any?>()
        args.add(commitment.firstBetAcceptedAt?.let { Timestamp.from(it) })
        args.add(commitment.status.name)
        args.add(Timestamp.from(commitment.updatedAt))
        args.add(commitment.clientSeed1)
        args.add(commitment.clientSeed2)
        args.add(commitment.clientSeed3)
        args.add(commitment.commitmentId)
        args.add(commitment.tenantId)
        args.add(expectedServerVersion)
        expectedStatuses.forEach { args.add(it.name) }
        val updated = jdbcTemplate.update(sql, *args.toTypedArray())
        return updated == 1
    }

    override fun existsAuditEvent(tenantId: String, commitmentId: java.util.UUID, eventKey: String): Boolean {
        val count = jdbcTemplate.queryForObject(
            "select count(*) from game_fairness_audit where tenant_id = ? and commitment_id = ? and event_key = ?",
            Int::class.java, tenantId, commitmentId, eventKey,
        ) ?: 0
        return count > 0
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
                audit_id, tenant_id, round_id, action, actor, detail, occurred_at,
                game_id, commitment_id, event_key
            ) values (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            on conflict do nothing
        """.trimIndent()
        jdbcTemplate.update(
            sql,
            event.auditId,
            event.tenantId,
            event.roundId,
            event.action,
            event.actor,
            event.detail,
            Timestamp.from(event.occurredAt),
            event.gameId,
            event.commitmentId,
            event.eventKey,
        )
    }

    override fun findAuditEvents(tenantId: String, roundId: String): List<FairnessAuditRecord> {
        val sql = """
            select audit_id, tenant_id, round_id, action, actor, detail, occurred_at,
                   game_id, commitment_id, event_key
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
            secretNonce = runCatching { rs.getString("secret_nonce") }.getOrNull(),
            secretKeyId = runCatching { rs.getString("secret_key_id") }.getOrNull(),
            secretKeyVersion = runCatching { rs.getObject("secret_key_version", Integer::class.java)?.toInt() }.getOrNull(),
            secretFormatVersion = runCatching { rs.getObject("secret_format_version", Integer::class.java)?.toInt() }.getOrNull(),
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
            gameId = runCatching { rs.getString("game_id") }.getOrNull(),
            commitmentId = runCatching { rs.getObject("commitment_id", UUID::class.java) }.getOrNull(),
            eventKey = runCatching { rs.getString("event_key") }.getOrNull(),
        )
    }
}
