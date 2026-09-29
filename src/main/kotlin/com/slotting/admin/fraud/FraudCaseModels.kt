package com.slotting.admin.fraud

import com.slotting.admin.auth.AuthenticatedPrincipal
import com.slotting.admin.auth.DualControlReceipt
import java.time.Instant
import java.util.UUID

enum class FraudCaseState {
    OPEN,
    CLAIMED,
    EVIDENCE_REQUESTED,
    ESCALATED,
    DISPOSED_RESTRICTED,
    DISPOSED_CLEARED,
}

enum class FraudCaseSeverity {
    LOW,
    MEDIUM,
    HIGH,
    CRITICAL,
}

enum class FraudCaseAction {
    CLAIM,
    RELEASE,
    REQUEST_EVIDENCE,
    ESCALATE,
    CONFIRM_RESTRICTION,
    DISPOSE_CLEAR,
}

data class FraudCaseNote(
    val noteId: UUID = UUID.randomUUID(),
    val adminId: String,
    val content: String,
    val timestamp: Instant,
)

data class FraudCaseRecord(
    val caseId: UUID = UUID.randomUUID(),
    val tenantId: String,
    val subjectReference: String,
    val caseReference: String,
    val state: FraudCaseState,
    val severity: FraudCaseSeverity,
    val riskDecisionReferences: List<String> = emptyList(),
    val detectedReasons: List<String> = emptyList(),
    val claimedBy: String? = null,
    val claimExpiresAt: Instant? = null,
    val restrictionId: UUID? = null,
    val dispositionReason: String? = null,
    val disposedBy: String? = null,
    val disposedAt: Instant? = null,
    val secondApproverId: String? = null,
    val adminNotes: List<FraudCaseNote> = emptyList(),
    val serverVersion: Long = 1L,
    val createdAt: Instant,
    val updatedAt: Instant,
) {
    init {
        require(tenantId.isNotBlank()) { "tenantId must not be blank" }
        require(subjectReference.isNotBlank()) { "subjectReference must not be blank" }
        require(caseReference.isNotBlank()) { "caseReference must not be blank" }
    }
}

data class FraudCaseActionRecord(
    val actionId: UUID = UUID.randomUUID(),
    val caseId: UUID,
    val tenantId: String,
    val caseReference: String,
    val action: FraudCaseAction,
    val actorId: String,
    val secondApproverId: String? = null,
    val fromState: FraudCaseState,
    val toState: FraudCaseState,
    val reason: String?,
    val occurredAt: Instant,
    val idempotencyKey: String,
    val correlationId: String,
    val causationId: String,
)

data class OpenOrMergeCaseCommand(
    val tenantId: String,
    val subjectReference: String,
    val decisionReference: String,
    val severity: FraudCaseSeverity,
    val detectedReasons: List<String>,
    val requiresRestriction: Boolean,
    val restrictionDuration: java.time.Duration? = null,
    val idempotencyKey: String,
    val correlationId: String,
    val causationId: String,
)

data class OperateFraudCaseCommand(
    val principal: AuthenticatedPrincipal?,
    val sessionId: String,
    val tenantId: String,
    val caseReference: String,
    val action: FraudCaseAction,
    val reason: String? = null,
    val note: String? = null,
    val secondApproverId: String? = null,
    val dualControlReceipt: DualControlReceipt? = null,
    val expectedVersion: Long,
    val idempotencyKey: String,
    val correlationId: String,
    val causationId: String,
)
