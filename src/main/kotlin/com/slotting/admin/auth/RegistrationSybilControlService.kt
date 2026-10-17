package com.slotting.admin.auth

import org.springframework.jdbc.core.JdbcTemplate
import org.springframework.stereotype.Service
import org.springframework.transaction.annotation.Transactional
import java.nio.charset.StandardCharsets
import javax.crypto.Mac
import javax.crypto.spec.SecretKeySpec
import java.sql.Timestamp
import java.time.Clock
import java.time.Duration
import java.time.Instant
import java.util.UUID

data class RegistrationAssessment(
    val credential: PlayerCredentialRecord,
    val heldForReview: Boolean,
)

data class RegistrationReview(
    val playerId: UUID,
    val tenantId: String,
    val identifier: String,
    val reason: String,
    val createdAt: Instant,
)

interface RegistrationSybilControl {
    fun register(tenantId: String, identifier: String, password: String, deviceFingerprint: String?, ipAddress: String?): RegistrationAssessment
    fun openReviews(tenantId: String): List<RegistrationReview>
    fun clearReview(tenantId: String, playerId: UUID, reviewerId: String, reason: String): Boolean
}

@Service
class RegistrationSybilControlService(
    private val jdbc: JdbcTemplate,
    private val authService: DurableAuthService,
    private val clock: Clock = Clock.systemUTC(),
    private val signalPepper: String = System.getenv("SLOTTING_PASSWORD_PEPPER").orEmpty(),
) : RegistrationSybilControl {
    companion object {
        const val MAX_REGISTRATIONS_PER_IP_PER_HOUR = 10
    }

    @Transactional
    override fun register(
        tenantId: String,
        identifier: String,
        password: String,
        deviceFingerprint: String?,
        ipAddress: String?,
    ): RegistrationAssessment {
        val now = Instant.now(clock)
        val deviceHash = deviceFingerprint?.trim()?.takeIf { it.length in 16..512 }?.let { digest("device", it) }
        val ipHash = ipAddress?.trim()?.takeIf { it.isNotEmpty() }?.let { digest("ip", it) }
        if (deviceHash != null) {
            jdbc.query("select pg_advisory_xact_lock(hashtextextended(?, 0))", { rs, _ -> rs.getObject(1) }, "$tenantId:$deviceHash")
        }
        if (ipHash != null) {
            jdbc.query("select pg_advisory_xact_lock(hashtextextended(?, 0))", { rs, _ -> rs.getObject(1) }, "$tenantId:ip:$ipHash")
        }
        val cutoff = Timestamp.from(now.minus(Duration.ofHours(1)))
        val priorRegistrations = if (deviceHash == null) 0 else jdbc.queryForObject(
            "select count(*) from registration_risk_signal where tenant_id = ? and device_hash = ? and created_at >= ?",
            Long::class.java,
            tenantId,
            deviceHash,
            cutoff,
        )?.toInt() ?: 0
        val priorIpRegistrations = if (ipHash == null) 0 else jdbc.queryForObject(
            "select count(*) from registration_risk_signal where tenant_id = ? and ip_hash = ? and created_at >= ?",
            Long::class.java,
            tenantId,
            ipHash,
            cutoff,
        )?.toInt() ?: 0
        val reason = when {
            deviceHash == null -> "DEVICE_SIGNAL_MISSING"
            priorRegistrations > 0 -> "DEVICE_REUSE"
            priorIpRegistrations >= MAX_REGISTRATIONS_PER_IP_PER_HOUR -> "IP_VELOCITY"
            else -> null
        }
        val playerId = UUID.randomUUID()
        val credential = authService.registerPlayer(
            tenantId = tenantId,
            identifier = identifier,
            password = password,
            status = if (reason == null) "ACTIVE" else "PENDING_REVIEW",
            playerId = playerId,
        )
        jdbc.update(
            "insert into registration_risk_signal (tenant_id, player_id, device_hash, ip_hash, created_at) values (?, ?, ?, ?, ?)",
            tenantId,
            playerId,
            deviceHash,
            ipHash,
            Timestamp.from(now),
        )
        if (reason != null) {
            jdbc.update(
                "insert into registration_risk_review (tenant_id, player_id, identifier, reason, state, created_at) values (?, ?, ?, ?, 'OPEN', ?)",
                tenantId,
                playerId,
                identifier,
                reason,
                Timestamp.from(now),
            )
            jdbc.update(
                "insert into registration_risk_review_audit (tenant_id, player_id, event_type, reviewer_id, reason, occurred_at) values (?, ?, 'HELD', null, ?, ?)",
                tenantId,
                playerId,
                reason,
                Timestamp.from(now),
            )
        }
        return RegistrationAssessment(credential, reason != null)
    }

    override fun openReviews(tenantId: String): List<RegistrationReview> = jdbc.query(
        "select player_id, tenant_id, identifier, reason, created_at from registration_risk_review where tenant_id = ? and state = 'OPEN' order by created_at, player_id",
        { rs, _ ->
            RegistrationReview(
                playerId = rs.getObject("player_id", UUID::class.java),
                tenantId = rs.getString("tenant_id"),
                identifier = rs.getString("identifier"),
                reason = rs.getString("reason"),
                createdAt = rs.getTimestamp("created_at").toInstant(),
            )
        },
        tenantId,
    )

    @Transactional
    override fun clearReview(tenantId: String, playerId: UUID, reviewerId: String, reason: String): Boolean {
        val now = Timestamp.from(Instant.now(clock))
        val changed = jdbc.update(
            "update registration_risk_review set state = 'CLEARED', cleared_at = ?, reviewer_id = ?, reviewer_reason = ? where tenant_id = ? and player_id = ? and state = 'OPEN'",
            now,
            reviewerId,
            reason.trim(),
            tenantId,
            playerId,
        )
        if (changed == 0) return false
        val activated = jdbc.update(
            "update player_credential set status = 'ACTIVE', updated_at = ?, version = version + 1 where tenant_id = ? and player_id = ? and status = 'PENDING_REVIEW'",
            now,
            tenantId,
            playerId,
        )
        check(activated == 1)
        jdbc.update(
            "insert into registration_risk_review_audit (tenant_id, player_id, event_type, reviewer_id, reason, occurred_at) values (?, ?, 'CLEARED', ?, ?, ?)",
            tenantId,
            playerId,
            reviewerId,
            reason.trim(),
            now,
        )
        return true
    }

    private fun digest(kind: String, value: String): String {
        check(signalPepper.isNotBlank())
        val mac = Mac.getInstance("HmacSHA256")
        mac.init(SecretKeySpec(signalPepper.toByteArray(StandardCharsets.UTF_8), "HmacSHA256"))
        val bytes = mac.doFinal("$kind:$value".toByteArray(StandardCharsets.UTF_8))
        return bytes.joinToString("") { "%02x".format(it) }
    }
}
