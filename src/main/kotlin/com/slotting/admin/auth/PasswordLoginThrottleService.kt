package com.slotting.admin.auth

import org.springframework.jdbc.core.JdbcTemplate
import org.springframework.stereotype.Service
import org.springframework.transaction.annotation.Transactional
import java.nio.charset.StandardCharsets
import javax.crypto.Mac
import javax.crypto.spec.SecretKeySpec

@Service
class PasswordLoginThrottleService(
    private val jdbc: JdbcTemplate,
    private val throttlePepper: String = System.getenv("SLOTTING_PASSWORD_PEPPER").orEmpty(),
) {
    @Transactional(readOnly = true)
    fun isBlocked(tenantId: String, identifier: String, remoteAddress: String): Boolean {
        val accountKey = digest("account:$tenantId:${identifier.trim().lowercase()}")
        val ipKey = digest("ip:$tenantId:$remoteAddress")
        val locked = jdbc.queryForObject(
            "select exists(select 1 from player_login_lockout where tenant_id = ? and account_key = ? and locked_until > now())",
            Boolean::class.java,
            tenantId,
            accountKey,
        ) ?: false
        val ipAttempts = runCatching {
            jdbc.queryForObject(
                "select attempt_count from player_login_attempt where tenant_id = ? and subject_key = ? and expires_at > now()",
                Int::class.java,
                tenantId,
                ipKey,
            )
        }.getOrNull() ?: 0
        return locked || ipAttempts >= 20
    }

    @Transactional
    fun recordFailure(tenantId: String, identifier: String, remoteAddress: String) {
        val accountKey = digest("account:$tenantId:${identifier.trim().lowercase()}")
        val ipKey = digest("ip:$tenantId:$remoteAddress")
        jdbc.update(
            """
            insert into player_login_attempt (tenant_id, subject_key, attempt_count, expires_at)
            values (?, ?, 1, now() + interval '15 minutes')
            on conflict (tenant_id, subject_key) do update
            set attempt_count = case when player_login_attempt.expires_at <= now() then 1 else player_login_attempt.attempt_count + 1 end,
                expires_at = now() + interval '15 minutes'
            """.trimIndent(),
            tenantId,
            accountKey,
        )
        val accountAttempts = runCatching {
            jdbc.queryForObject(
                "select attempt_count from player_login_attempt where tenant_id = ? and subject_key = ?",
                Int::class.java,
                tenantId,
                accountKey,
            )
        }.getOrNull() ?: 0
        jdbc.update(
            """
            insert into player_login_attempt (tenant_id, subject_key, attempt_count, expires_at)
            values (?, ?, 1, now() + interval '15 minutes')
            on conflict (tenant_id, subject_key) do update
            set attempt_count = case when player_login_attempt.expires_at <= now() then 1 else player_login_attempt.attempt_count + 1 end,
                expires_at = now() + interval '15 minutes'
            """.trimIndent(),
            tenantId,
            ipKey,
        )
        if (accountAttempts >= 5) {
            jdbc.update(
                """
                insert into player_login_lockout (tenant_id, account_key, locked_until)
                values (?, ?, now() + interval '30 minutes')
                on conflict (tenant_id, account_key) do update set locked_until = excluded.locked_until
                """.trimIndent(),
                tenantId,
                accountKey,
            )
        }
    }

    @Transactional
    fun recordSuccess(tenantId: String, identifier: String) {
        val accountKey = digest("account:$tenantId:${identifier.trim().lowercase()}")
        jdbc.update("delete from player_login_attempt where tenant_id = ? and subject_key = ?", tenantId, accountKey)
    }

    private fun digest(value: String): String {
        check(throttlePepper.isNotBlank())
        val mac = Mac.getInstance("HmacSHA256")
        mac.init(SecretKeySpec(throttlePepper.toByteArray(StandardCharsets.UTF_8), "HmacSHA256"))
        return mac.doFinal(value.toByteArray(StandardCharsets.UTF_8))
            .joinToString("") { "%02x".format(it) }
    }
}
