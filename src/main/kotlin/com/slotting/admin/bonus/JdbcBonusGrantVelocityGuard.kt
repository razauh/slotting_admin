package com.slotting.admin.bonus

import org.springframework.jdbc.core.JdbcTemplate
import org.springframework.stereotype.Repository
import org.springframework.transaction.annotation.Transactional
import java.time.Instant
import java.util.UUID

@Repository
class JdbcBonusGrantVelocityGuard(private val jdbc: JdbcTemplate) : BonusGrantVelocityGuard {
    @Transactional
    override fun reserve(tenantId: String, playerId: UUID, adminId: String, amountMinorUnits: Long, at: Instant) {
        val windowStart = at.minusSeconds(600)
        val playerLock = "player:$tenantId:$playerId"
        val adminLock = "admin:$tenantId:$adminId"
        jdbc.queryForObject("select pg_advisory_xact_lock(hashtext(?))", Any::class.java, playerLock)
        jdbc.queryForObject("select pg_advisory_xact_lock(hashtext(?))", Any::class.java, adminLock)
        val playerTotal = jdbc.queryForObject(
            "select coalesce(sum(amount_minor_units), 0) from admin_bonus_grant_velocity where tenant_id = ? and player_id = ? and created_at > ?",
            Long::class.java, tenantId, playerId, windowStart,
        ) ?: 0L
        val adminTotal = jdbc.queryForObject(
            "select coalesce(sum(amount_minor_units), 0) from admin_bonus_grant_velocity where tenant_id = ? and admin_id = ? and created_at > ?",
            Long::class.java, tenantId, adminId, windowStart,
        ) ?: 0L
        if (amountMinorUnits > 50_000L - playerTotal) throw BonusGrantDecisionFailure(BonusGrantDecisionCode.PLAYER_CAP_EXCEEDED)
        if (amountMinorUnits > 100_000L - adminTotal) throw BonusGrantDecisionFailure(BonusGrantDecisionCode.ADMIN_CAP_EXCEEDED)
        jdbc.update(
            "insert into admin_bonus_grant_velocity (tenant_id, player_id, admin_id, amount_minor_units, created_at) values (?, ?, ?, ?, ?)",
            tenantId, playerId, adminId, amountMinorUnits, at,
        )
    }
}
