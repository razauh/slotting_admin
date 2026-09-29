package com.slotting.admin.identity

import org.springframework.jdbc.core.JdbcTemplate
import org.springframework.stereotype.Repository
import org.springframework.transaction.annotation.Transactional
import java.sql.ResultSet
import java.time.Instant
import java.util.UUID
import java.util.concurrent.ConcurrentHashMap

/**
 * Durable PostgreSQL implementation of PlayerRegistrationStore (TC-004, TC-040).
 * Stores player credentials in player_credential table and challenges in auth_challenge table.
 */
@Repository
class JdbcPlayerRegistrationStore(
    private val jdbc: JdbcTemplate,
) : PlayerRegistrationStore {

    // Cache idempotency for quick idempotent return while persisting to DB
    private val idempotencyMap = ConcurrentHashMap<String, Pair<Any, Any>>()

    override fun findByIdempotency(tenantId: String, key: String): Pair<Any, Any>? =
        idempotencyMap["$tenantId:$key"]

    @Transactional
    override fun saveRegistration(
        command: RegisterPlayerCommand,
        result: RegisterPlayerResult,
        record: PlayerRegistrationRecord,
        verificationCodes: List<VerificationCodeRecord>,
    ) {
        idempotencyMap["${command.tenantId}:${command.idempotencyKey}"] = Pair(command, result)

        val sql = """
            insert into player_credential (
                player_id, tenant_id, identifier, password_hash, password_algo,
                password_salt, iterations, status, version, created_at, updated_at
            ) values (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            on conflict (tenant_id, identifier) do update set
                password_hash = excluded.password_hash,
                status = excluded.status,
                version = player_credential.version + 1,
                updated_at = excluded.updated_at
        """.trimIndent()

        jdbc.update(
            sql,
            record.playerId,
            record.tenantId,
            record.emailHash,
            record.passwordHash.ifBlank { "N/A" },
            "pbkdf2_sha256",
            "salt",
            10000,
            record.status.name,
            record.version,
            record.createdAt,
            record.updatedAt,
        )

        val challengeSql = """
            insert into auth_challenge (
                challenge_id, tenant_id, player_id, purpose, code_hash,
                salt, attempts_remaining, max_attempts, expires_at, created_at
            ) values (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            on conflict (challenge_id) do nothing
        """.trimIndent()

        for (code in verificationCodes) {
            jdbc.update(
                challengeSql,
                code.verificationId,
                code.tenantId,
                code.playerId,
                "REGISTRATION_VERIFY_${code.channel.name}",
                code.codeHash,
                "salt",
                code.maxAttempts - code.attemptCount,
                code.maxAttempts,
                code.expiresAt,
                Instant.now(),
            )
        }
    }

    @Transactional
    override fun saveVerification(
        command: VerifyContactCommand,
        result: VerifyContactResult,
        record: PlayerRegistrationRecord,
        verificationCode: VerificationCodeRecord,
    ) {
        idempotencyMap["${command.tenantId}:${command.idempotencyKey}"] = Pair(command, result)

        val sql = """
            update player_credential 
            set status = ?, version = version + 1, updated_at = ?
            where tenant_id = ? and player_id = ?
        """.trimIndent()

        jdbc.update(sql, record.status.name, record.updatedAt, record.tenantId, record.playerId)

        val challengeSql = """
            update auth_challenge 
            set consumed_at = ?
            where challenge_id = ?
        """.trimIndent()

        jdbc.update(challengeSql, verificationCode.verifiedAt ?: Instant.now(), verificationCode.verificationId)
    }

    override fun findByEmailHash(tenantId: String, emailHash: String): PlayerRegistrationRecord? {
        val sql = "select * from player_credential where tenant_id = ? and identifier = ?"
        return jdbc.query(sql, { rs, _ -> rs.toRegistrationRecord(tenantId) }, tenantId, emailHash).firstOrNull()
    }

    override fun findByPhoneHash(tenantId: String, phoneHash: String): PlayerRegistrationRecord? {
        val sql = "select * from player_credential where tenant_id = ? and identifier = ?"
        return jdbc.query(sql, { rs, _ -> rs.toRegistrationRecord(tenantId) }, tenantId, phoneHash).firstOrNull()
    }

    override fun findById(tenantId: String, playerId: UUID): PlayerRegistrationRecord? {
        val sql = "select * from player_credential where tenant_id = ? and player_id = ?"
        return jdbc.query(sql, { rs, _ -> rs.toRegistrationRecord(tenantId) }, tenantId, playerId).firstOrNull()
    }

    override fun findVerificationCode(
        tenantId: String,
        playerId: UUID,
        channel: ContactVerificationChannel,
    ): VerificationCodeRecord? {
        val sql = """
            select * from auth_challenge 
            where tenant_id = ? and player_id = ? and purpose = ? 
            order by created_at desc limit 1
        """.trimIndent()

        return jdbc.query(sql, { rs, _ ->
            VerificationCodeRecord(
                verificationId = rs.getObject("challenge_id", UUID::class.java),
                playerId = rs.getObject("player_id", UUID::class.java),
                tenantId = rs.getString("tenant_id"),
                channel = channel,
                codeHash = rs.getString("code_hash"),
                status = if (rs.getTimestamp("consumed_at") != null) ContactVerificationStatus.VERIFIED else ContactVerificationStatus.UNVERIFIED,
                attemptCount = rs.getInt("max_attempts") - rs.getInt("attempts_remaining"),
                maxAttempts = rs.getInt("max_attempts"),
                expiresAt = rs.getTimestamp("expires_at").toInstant(),
                verifiedAt = rs.getTimestamp("consumed_at")?.toInstant(),
            )
        }, tenantId, playerId, "REGISTRATION_VERIFY_${channel.name}").firstOrNull()
    }

    override fun currentVersion(tenantId: String, playerId: UUID): Long {
        val sql = "select coalesce(version, 1) from player_credential where tenant_id = ? and player_id = ?"
        return jdbc.queryForObject(sql, Long::class.java, tenantId, playerId) ?: 1L
    }

    private fun ResultSet.toRegistrationRecord(tenantId: String): PlayerRegistrationRecord {
        val pId = getObject("player_id", UUID::class.java)
        val statusStr = getString("status")
        val status = runCatching { PlayerAccountStatus.valueOf(statusStr) }.getOrDefault(PlayerAccountStatus.ACTIVE)
        val createdAt = getTimestamp("created_at").toInstant()
        val updatedAt = getTimestamp("updated_at").toInstant()
        val version = getLong("version")

        return PlayerRegistrationRecord(
            playerId = pId,
            tenantId = tenantId,
            emailHash = getString("identifier"),
            phoneHash = "",
            maskedEmail = "***",
            maskedPhone = "***",
            jurisdiction = "DEFAULT",
            riskScore = 0.0,
            mfaRequired = false,
            passwordHash = getString("password_hash"),
            status = status,
            emailVerified = true,
            phoneVerified = false,
            version = version,
            createdAt = createdAt,
            updatedAt = updatedAt,
        )
    }
}
