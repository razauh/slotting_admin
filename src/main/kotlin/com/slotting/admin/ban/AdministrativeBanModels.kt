package com.slotting.admin.ban

import com.slotting.admin.auth.AuditEvent
import com.slotting.admin.auth.AuthenticatedPrincipal
import com.slotting.admin.auth.OutboxEvent
import com.slotting.admin.restriction.ServerRestrictionRecord
import java.time.Instant
import java.util.UUID

enum class BanType {
    TEMPORARY,
    PERMANENT
}

enum class BanStatus {
    ACTIVE,
    EXPIRED,
    REVERSED
}

enum class BanReasonCategory {
    TERMS_OF_SERVICE_VIOLATION,
    UNDERAGE_GAMING,
    COLLUSION_OR_CHEATING,
    PAYMENT_ABUSE,
    ACCOUNT_SECURITY_COMPROMISE,
    ADMINISTRATIVE_DISCRETION
}

data class AdministrativeBanRecord(
    val banId: UUID = UUID.randomUUID(),
    val tenantId: String,
    val subjectReference: String,
    val banType: BanType,
    val reasonCategory: BanReasonCategory,
    val reasonCode: String,
    val permittedNote: String,
    val internalNote: String? = null,
    val issuerId: String,
    val effectiveFrom: Instant,
    val expiresAt: Instant? = null,
    val caseReferenceId: String,
    val status: BanStatus = BanStatus.ACTIVE,
    val reversedAt: Instant? = null,
    val reversedBy: String? = null,
    val reversalReason: String? = null,
    val version: Long = 1L,
    val createdAt: Instant,
    val updatedAt: Instant
) {
    init {
        require(tenantId.isNotBlank()) { "tenantId must not be blank" }
        require(subjectReference.isNotBlank()) { "subjectReference must not be blank" }
        require(reasonCode.isNotBlank()) { "reasonCode must not be blank" }
        require(permittedNote.isNotBlank()) { "permittedNote must not be blank" }
        require(issuerId.isNotBlank()) { "issuerId must not be blank" }
        require(caseReferenceId.isNotBlank()) { "caseReferenceId must not be blank" }
        if (banType == BanType.PERMANENT) {
            require(expiresAt == null) { "Permanent ban must not have an expiry timestamp" }
        } else {
            require(expiresAt != null) { "Temporary ban must have an expiry timestamp" }
            require(expiresAt.isAfter(effectiveFrom)) { "expiresAt must be after effectiveFrom" }
        }
    }

    fun isEffectiveAt(now: Instant): Boolean {
        if (status != BanStatus.ACTIVE) return false
        if (now.isBefore(effectiveFrom)) return false
        if (expiresAt != null && !now.isBefore(expiresAt)) return false
        return true
    }
}

data class IssueBanCommand(
    val principal: AuthenticatedPrincipal?,
    val sessionId: String,
    val tenantId: String,
    val subjectReference: String,
    val banType: BanType,
    val reasonCategory: BanReasonCategory,
    val reasonCode: String,
    val permittedNote: String,
    val internalNote: String? = null,
    val effectiveFrom: Instant,
    val expiresAt: Instant? = null,
    val caseReferenceId: String,
    val correlationId: String,
    val causationId: String,
    val expectedVersion: Long = 1L,
    val idempotencyKey: String,
    val secondApproverId: String? = null
) {
    init {
        if (banType == BanType.PERMANENT) {
            require(expiresAt == null) { "Permanent ban must not have an expiry timestamp" }
        } else {
            require(expiresAt != null) { "Temporary ban must have an expiry timestamp" }
            require(expiresAt.isAfter(effectiveFrom)) { "expiresAt must be after effectiveFrom" }
        }
    }
}

data class ReverseBanCommand(
    val principal: AuthenticatedPrincipal?,
    val sessionId: String,
    val tenantId: String,
    val subjectReference: String,
    val banId: UUID,
    val reversalReason: String,
    val caseReferenceId: String,
    val correlationId: String,
    val causationId: String,
    val expectedVersion: Long,
    val idempotencyKey: String,
    val secondApproverId: String? = null
)

data class AdministrativeBanResult(
    val ban: AdministrativeBanRecord,
    val auditEvent: AuditEvent,
    val outboxEvent: OutboxEvent,
    val sessionsRevokedCount: Int,
    val restrictionRecord: ServerRestrictionRecord
)
