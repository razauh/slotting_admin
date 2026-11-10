package com.slotting.admin.identity

import java.sql.Timestamp
import java.time.Instant
import java.util.UUID
import javax.sql.DataSource

class JdbcSessionRevocationWriter(
    private val dataSource: DataSource,
) : SessionRevocationWriter {
    override fun record(tenantId: String, sessionId: UUID, revokedAt: Instant, reason: String) {
        dataSource.connection.use { connection ->
            connection.autoCommit = false
            connection.prepareStatement(
                "insert into public.bridge_session_revocations (session_id, tenant_id, revoked_at, reason) values (?, ?, ?, ?) on conflict (session_id) do update set revoked_at = excluded.revoked_at, reason = excluded.reason"
            ).use { statement ->
                statement.setObject(1, sessionId)
                statement.setString(2, tenantId)
                statement.setTimestamp(3, Timestamp.from(revokedAt))
                statement.setString(4, reason)
                statement.executeUpdate()
            }
            connection.commit()
        }
    }
}
