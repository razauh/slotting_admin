package com.slotting.admin.rg

import com.slotting.admin.auth.AuthenticatedPrincipal
import com.slotting.admin.restriction.AccessDecision
import com.slotting.admin.restriction.FinancialDisposition
import com.slotting.admin.restriction.ServerOperation
import java.time.Instant
import java.util.UUID

/**
 * TC-029: Durable Responsible Gaming Models, Commands, Receipts, and Status.
 * Implements server-owned limits, exclusions, cooling rules, and authoritative receipts.
 */

enum class DurableExclusionType {
    COOL_OFF,
    SELF_EXCLUSION_DEFINITE,
    SELF_EXCLUSION_PERMANENT
}

enum class DurableExclusionStatus {
    ACTIVE,
    EXPIRED,
    REVOKED
}

data class DurableExclusionRecord(
    val exclusionId: UUID = UUID.randomUUID(),
    val tenantId: String,
    val playerId: String,
    val exclusionType: DurableExclusionType,
    val status: DurableExclusionStatus = DurableExclusionStatus.ACTIVE,
    val effectiveFrom: Instant,
    val expiresAt: Instant? = null,
    val reason: String,
    val requestedBy: String,
    val version: Long = 1L,
    val createdAt: Instant,
    val updatedAt: Instant,
    val evidenceReference: String
) {
    init {
        require(tenantId.isNotBlank()) { "tenantId must not be blank" }
        require(playerId.isNotBlank()) { "playerId must not be blank" }
        require(reason.isNotBlank()) { "reason must not be blank" }
        require(evidenceReference.isNotBlank()) { "evidenceReference must not be blank" }
        if (exclusionType == DurableExclusionType.SELF_EXCLUSION_PERMANENT) {
            require(expiresAt == null) { "Permanent self-exclusion must not have an expiry timestamp" }
        } else {
            require(expiresAt != null && expiresAt.isAfter(effectiveFrom)) {
                "Definite exclusion/cool-off must have an expiresAt strictly after effectiveFrom"
            }
        }
    }

    fun isEffectiveAt(now: Instant): Boolean {
        if (status != DurableExclusionStatus.ACTIVE) return false
        if (now.isBefore(effectiveFrom)) return false
        if (expiresAt != null && !now.isBefore(expiresAt)) return false
        return true
    }
}

data class ApplyPlayerExclusionCommand(
    val tenantId: String,
    val playerId: String,
    val exclusionType: DurableExclusionType,
    val durationDays: Int? = null,
    val reason: String,
    val idempotencyKey: String,
    val correlationId: String,
    val causationId: String,
    val expectedVersion: Long = 1L,
    val principal: AuthenticatedPrincipal? = null
) {
    init {
        require(tenantId.isNotBlank()) { "tenantId must not be blank" }
        require(playerId.isNotBlank()) { "playerId must not be blank" }
        require(reason.isNotBlank()) { "reason must not be blank" }
        require(idempotencyKey.isNotBlank()) { "idempotencyKey must not be blank" }
        require(correlationId.isNotBlank()) { "correlationId must not be blank" }
        require(causationId.isNotBlank()) { "causationId must not be blank" }
        if (exclusionType != DurableExclusionType.SELF_EXCLUSION_PERMANENT) {
            require(durationDays != null && durationDays > 0) {
                "durationDays must be positive for definite exclusion or cool-off"
            }
        }
    }
}

data class ApplyPlayerExclusionResult(
    val receiptId: UUID = UUID.randomUUID(),
    val exclusion: DurableExclusionRecord,
    val serverTime: Instant,
    val isDuplicate: Boolean = false,
    val receiptReference: String
)

data class ChangeLimitCommand(
    val tenantId: String,
    val playerId: String,
    val limitType: RgLimitType,
    val period: RgLimitPeriod,
    val limitValueMinor: Long,
    val timezone: String = "UTC",
    val idempotencyKey: String,
    val correlationId: String,
    val causationId: String,
    val expectedVersion: Long = 1L,
    val principal: AuthenticatedPrincipal? = null
) {
    init {
        require(tenantId.isNotBlank()) { "tenantId must not be blank" }
        require(playerId.isNotBlank()) { "playerId must not be blank" }
        require(limitValueMinor > 0L) { "limitValueMinor must be strictly positive" }
        require(idempotencyKey.isNotBlank()) { "idempotencyKey must not be blank" }
        require(correlationId.isNotBlank()) { "correlationId must not be blank" }
        require(causationId.isNotBlank()) { "causationId must not be blank" }
    }
}

data class RgLimitChangeReceipt(
    val receiptId: UUID = UUID.randomUUID(),
    val tenantId: String,
    val playerId: String,
    val limitType: RgLimitType,
    val period: RgLimitPeriod,
    val effectiveLimitValueMinor: Long,
    val pendingIncreaseValueMinor: Long? = null,
    val pendingIncreaseEffectiveAt: Instant? = null,
    val isImmediate: Boolean,
    val coolingOffDurationHours: Long = 0L,
    val version: Long,
    val serverTime: Instant,
    val receiptReference: String
)

data class PlayerRgStatus(
    val playerId: String,
    val tenantId: String,
    val activeExclusion: DurableExclusionRecord?,
    val isExcluded: Boolean,
    val limits: List<RgLimitConfig>,
    val currentUsages: List<RgLimitUsageRecord>,
    val canAccessGame: Boolean,
    val canWager: Boolean,
    val canDeposit: Boolean,
    val canWithdraw: Boolean,
    val isPromotionSuppressed: Boolean,
    val serverTime: Instant
)
