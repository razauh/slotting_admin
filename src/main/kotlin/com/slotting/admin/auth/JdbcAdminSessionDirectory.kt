package com.slotting.admin.auth

import org.springframework.jdbc.core.JdbcTemplate
import org.springframework.stereotype.Repository
import java.time.Clock
import java.time.Instant

/**
 * Authoritative, durable PostgreSQL implementation of AdminSessionDirectory (TC-002, TC-040).
 * Queries admin_mfa_authentication table to verify session state and expiry.
 */
@Repository
class JdbcAdminSessionDirectory(
    private val jdbc: JdbcTemplate,
    private val clock: Clock = Clock.systemUTC(),
) : AdminSessionDirectory {

    override fun find(tenantId: String, principalId: String, sessionId: String): AdminSessionStatus? {
        val sql = """
            select state, expires_at 
            from admin_mfa_authentication 
            where tenant_id = ? and principal_id = ? and session_id = ? 
            order by authenticated_at desc 
            limit 1
        """.trimIndent()

        val results = jdbc.query(sql, { rs, _ ->
            val state = rs.getString("state")
            val expiresAt = rs.getTimestamp("expires_at").toInstant()
            val now = Instant.now(clock)
            val active = (state == "AUTHENTICATED" && now.isBefore(expiresAt))
            AdminSessionStatus(
                active = active,
                breakGlass = false,
                expiresAt = expiresAt,
                mfaVerified = (state == "AUTHENTICATED"),
                mfaExpiresAt = expiresAt,
            )
        }, tenantId, principalId, sessionId)

        return results.firstOrNull()
    }
}
