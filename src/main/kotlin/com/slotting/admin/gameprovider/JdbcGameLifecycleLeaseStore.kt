package com.slotting.admin.gameprovider

import org.springframework.jdbc.core.JdbcTemplate
import org.springframework.stereotype.Repository
import java.sql.ResultSet
import java.sql.Timestamp
import java.time.Instant

@Repository
class JdbcGameLifecycleLeaseStore(
    private val jdbcTemplate: JdbcTemplate,
) : GameLifecycleLeaseStore {

    private fun mapLease(rs: ResultSet): GameLifecycleLeaseRecord =
        GameLifecycleLeaseRecord(
            tenantId = rs.getString("tenant_id"),
            gameId = rs.getString("game_id"),
            ownerId = rs.getString("owner_id"),
            epoch = rs.getLong("epoch"),
            leaseExpiresAt = rs.getTimestamp("lease_expires_at").toInstant(),
            createdAt = rs.getTimestamp("created_at").toInstant(),
            updatedAt = rs.getTimestamp("updated_at").toInstant(),
        )

    override fun getLease(tenantId: String, gameId: String): GameLifecycleLeaseRecord? {
        val sql = """
            select tenant_id, game_id, owner_id, epoch, lease_expires_at, created_at, updated_at
            from game_lifecycle_lease
            where tenant_id = ? and game_id = ?
        """.trimIndent()
        val list = jdbcTemplate.query(sql, { rs, _ -> mapLease(rs) }, tenantId, gameId)
        return list.firstOrNull()
    }

    override fun isLeaseValid(tenantId: String, gameId: String, ownerId: String, epoch: Long): Boolean {
        val sql = """
            select count(*)
            from game_lifecycle_lease
            where tenant_id = ? and game_id = ? and owner_id = ? and epoch = ? and lease_expires_at > now()
        """.trimIndent()
        val count = jdbcTemplate.queryForObject(sql, Int::class.java, tenantId, gameId, ownerId, epoch) ?: 0
        return count > 0
    }

    override fun acquireOrRenew(
        tenantId: String,
        gameId: String,
        ownerId: String,
        ttlMillis: Long,
        expectedEpoch: Long?,
    ): LifecycleLeaseAcquireResult {
        val upsertSql = """
            insert into game_lifecycle_lease (
                tenant_id, game_id, owner_id, epoch, lease_expires_at, created_at, updated_at
            ) values (
                ?, ?, ?, 1, now() + (cast(? as bigint) * interval '1 millisecond'), now(), now()
            )
            on conflict (tenant_id, game_id) do update
            set owner_id = excluded.owner_id,
                epoch = case
                    when game_lifecycle_lease.owner_id = excluded.owner_id then game_lifecycle_lease.epoch
                    else game_lifecycle_lease.epoch + 1
                end,
                lease_expires_at = excluded.lease_expires_at,
                updated_at = now()
            where (
                game_lifecycle_lease.owner_id = excluded.owner_id
                and (cast(? as bigint) is null or game_lifecycle_lease.epoch = cast(? as bigint))
            ) or (
                game_lifecycle_lease.lease_expires_at < now()
                and (cast(? as bigint) is null or game_lifecycle_lease.epoch = cast(? as bigint))
            )
            returning tenant_id, game_id, owner_id, epoch, lease_expires_at, created_at, updated_at
        """.trimIndent()

        val updated = jdbcTemplate.query(
            upsertSql,
            { rs, _ -> mapLease(rs) },
            tenantId,
            gameId,
            ownerId,
            ttlMillis,
            expectedEpoch,
            expectedEpoch,
            expectedEpoch,
            expectedEpoch,
        )

        val acquired = updated.firstOrNull()
        if (acquired != null) {
            return LifecycleLeaseAcquireResult(
                status = LifecycleLeaseAcquireStatus.ACQUIRED,
                lease = acquired,
            )
        }

        val current = getLease(tenantId, gameId)
        val status = if (expectedEpoch != null && current != null && current.epoch != expectedEpoch) {
            LifecycleLeaseAcquireStatus.STALE_EPOCH
        } else {
            LifecycleLeaseAcquireStatus.REJECTED_ACTIVE_LEASE
        }
        return LifecycleLeaseAcquireResult(
            status = status,
            lease = current,
        )
    }

    override fun release(tenantId: String, gameId: String, ownerId: String, epoch: Long): Boolean {
        val sql = """
            update game_lifecycle_lease
            set lease_expires_at = now() - interval '1 millisecond',
                updated_at = now()
            where tenant_id = ? and game_id = ? and owner_id = ? and epoch = ?
        """.trimIndent()
        val rows = jdbcTemplate.update(sql, tenantId, gameId, ownerId, epoch)
        return rows > 0
    }

    override fun lockAndVerify(
        tenantId: String,
        gameId: String,
        ownerId: String,
        epoch: Long,
    ): GameLifecycleLeaseRecord? {
        val sql = """
            select tenant_id, game_id, owner_id, epoch, lease_expires_at, created_at, updated_at,
                   (lease_expires_at > now()) as lease_valid
            from game_lifecycle_lease
            where tenant_id = ? and game_id = ?
            for update
        """.trimIndent()
        val row = jdbcTemplate.query(
            sql,
            { rs, _ -> mapLease(rs) to rs.getBoolean("lease_valid") },
            tenantId,
            gameId,
        ).firstOrNull() ?: return null
        val (lease, valid) = row
        if (!valid) return null
        if (lease.ownerId != ownerId || lease.epoch != epoch) return null
        return lease
    }
}
