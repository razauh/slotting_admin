package com.slotting.admin.auth.passwordreset

import org.springframework.jdbc.core.JdbcTemplate
import org.springframework.jdbc.core.RowMapper
import org.springframework.stereotype.Repository
import org.springframework.transaction.annotation.Transactional
import java.sql.ResultSet
import java.sql.Timestamp
import java.time.Instant
import java.util.UUID
import java.util.concurrent.ConcurrentHashMap

interface PasswordResetTokenStore {
    fun saveToken(record: PasswordResetTokenRecord)
    fun findByDigest(digest: String): PasswordResetTokenRecord?
    fun markTokenUsed(tokenId: UUID, usedAt: Instant): Boolean
    fun revokeAllActiveTokensForPlayer(tenantId: String, playerId: UUID, revokedAt: Instant): Int
    fun countActiveTokensForPlayer(tenantId: String, playerId: UUID, now: Instant): Int
    fun cleanExpiredTokens(olderThan: Instant): Int
}

class InMemoryPasswordResetTokenStore : PasswordResetTokenStore {
    val tokens = ConcurrentHashMap<UUID, PasswordResetTokenRecord>()
    val digestIndex = ConcurrentHashMap<String, UUID>()

    override fun saveToken(record: PasswordResetTokenRecord) {
        tokens[record.id] = record
        digestIndex[record.tokenDigest] = record.id
    }

    override fun findByDigest(digest: String): PasswordResetTokenRecord? {
        val id = digestIndex[digest] ?: return null
        return tokens[id]
    }

    @Synchronized
    override fun markTokenUsed(tokenId: UUID, usedAt: Instant): Boolean {
        val record = tokens[tokenId] ?: return false
        if (record.usedAt != null || record.revokedAt != null || usedAt.isAfter(record.expiresAt)) {
            return false
        }
        record.usedAt = usedAt
        return true
    }

    @Synchronized
    override fun revokeAllActiveTokensForPlayer(tenantId: String, playerId: UUID, revokedAt: Instant): Int {
        var count = 0
        for (rec in tokens.values) {
            if (rec.tenantId == tenantId && rec.playerId == playerId && rec.usedAt == null && rec.revokedAt == null) {
                rec.revokedAt = revokedAt
                count++
            }
        }
        return count
    }

    override fun countActiveTokensForPlayer(tenantId: String, playerId: UUID, now: Instant): Int {
        return tokens.values.count {
            it.tenantId == tenantId && it.playerId == playerId && it.usedAt == null && it.revokedAt == null && now.isBefore(it.expiresAt)
        }
    }

    @Synchronized
    override fun cleanExpiredTokens(olderThan: Instant): Int {
        var removed = 0
        val iterator = tokens.entries.iterator()
        while (iterator.hasNext()) {
            val entry = iterator.next()
            if (entry.value.expiresAt.isBefore(olderThan)) {
                digestIndex.remove(entry.value.tokenDigest)
                iterator.remove()
                removed++
            }
        }
        return removed
    }

    fun clear() {
        tokens.clear()
        digestIndex.clear()
    }
}

@Repository
class JdbcPasswordResetTokenStore(private val jdbc: JdbcTemplate) : PasswordResetTokenStore {
    override fun saveToken(record: PasswordResetTokenRecord) {
        jdbc.update(
            """
            insert into password_reset_token (
                id, player_id, tenant_id, token_digest, created_at, expires_at,
                used_at, revoked_at, request_correlation_id, ip_address, user_agent
            ) values (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """.trimIndent(),
            record.id, record.playerId, record.tenantId, record.tokenDigest,
            Timestamp.from(record.createdAt), Timestamp.from(record.expiresAt),
            record.usedAt?.let { Timestamp.from(it) }, record.revokedAt?.let { Timestamp.from(it) },
            record.requestCorrelationId, record.ipAddress, record.userAgent
        )
    }

    override fun findByDigest(digest: String): PasswordResetTokenRecord? {
        return jdbc.query(
            "select * from password_reset_token where token_digest = ?",
            rowMapper, digest
        ).firstOrNull()
    }

    @Transactional
    override fun markTokenUsed(tokenId: UUID, usedAt: Instant): Boolean {
        // Atomic compare-and-set: row must be unused, unrevoked, and unexpired
        val rows = jdbc.update(
            """
            update password_reset_token 
            set used_at = ? 
            where id = ? and used_at is null and revoked_at is null and expires_at > ?
            """.trimIndent(),
            Timestamp.from(usedAt), tokenId, Timestamp.from(usedAt)
        )
        return rows > 0
    }

    @Transactional
    override fun revokeAllActiveTokensForPlayer(tenantId: String, playerId: UUID, revokedAt: Instant): Int {
        return jdbc.update(
            """
            update password_reset_token 
            set revoked_at = ? 
            where tenant_id = ? and player_id = ? and used_at is null and revoked_at is null
            """.trimIndent(),
            Timestamp.from(revokedAt), tenantId, playerId
        )
    }

    override fun countActiveTokensForPlayer(tenantId: String, playerId: UUID, now: Instant): Int {
        return jdbc.queryForObject(
            """
            select count(*) from password_reset_token 
            where tenant_id = ? and player_id = ? and used_at is null and revoked_at is null and expires_at > ?
            """.trimIndent(),
            Int::class.java, tenantId, playerId, Timestamp.from(now)
        ) ?: 0
    }

    @Transactional
    override fun cleanExpiredTokens(olderThan: Instant): Int {
        return jdbc.update(
            "delete from password_reset_token where expires_at < ?",
            Timestamp.from(olderThan)
        )
    }

    private val rowMapper = RowMapper { rs: ResultSet, _ ->
        PasswordResetTokenRecord(
            id = rs.getObject("id", UUID::class.java),
            playerId = rs.getObject("player_id", UUID::class.java),
            tenantId = rs.getString("tenant_id"),
            tokenDigest = rs.getString("token_digest"),
            createdAt = rs.getTimestamp("created_at").toInstant(),
            expiresAt = rs.getTimestamp("expires_at").toInstant(),
            usedAt = rs.getTimestamp("used_at")?.toInstant(),
            revokedAt = rs.getTimestamp("revoked_at")?.toInstant(),
            requestCorrelationId = rs.getString("request_correlation_id"),
            ipAddress = rs.getString("ip_address"),
            userAgent = rs.getString("user_agent")
        )
    }
}
