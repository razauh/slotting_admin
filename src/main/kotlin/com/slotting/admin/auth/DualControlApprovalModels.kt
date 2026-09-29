package com.slotting.admin.auth

import java.time.Instant
import java.util.UUID

enum class DualControlStatus {
    PENDING_CHECKER,
    APPROVED,
    REJECTED,
}

enum class DualControlAction {
    APPROVE,
    REJECT,
}

data class DecisionActor(
    val principalId: String,
    val tenantId: String,
    val roles: Set<AdminRole>,
    val sessionId: String,
    val mfaVerified: Boolean,
    val decidedAt: Instant,
)

data class DualControlProposalRecord(
    val proposalId: UUID,
    val tenantId: String,
    val operationId: String,
    val operationType: String,
    val resourceReference: String,
    val payloadDigest: String,
    val requiredPermission: AdminPermission,
    val targetVersion: Long,
    val status: DualControlStatus,
    val maker: DecisionActor,
    val notes: String? = null,
    val proposedAt: Instant,
    val expiresAt: Instant,
    val version: Long = 1L,
)

data class DualControlReceipt(
    val receiptId: UUID,
    val proposalId: UUID,
    val tenantId: String,
    val operationId: String,
    val operationType: String,
    val resourceReference: String,
    val payloadDigest: String,
    val requiredPermission: AdminPermission,
    val targetVersion: Long,
    val status: DualControlStatus,
    val maker: DecisionActor,
    val checker: DecisionActor,
    val notes: String? = null,
    val decidedAt: Instant,
    val expiresAt: Instant,
    val evidenceReference: String,
)

data class ProposeDualControlCommand(
    val principal: AuthenticatedPrincipal?,
    val sessionId: String,
    val tenantId: String,
    val operationId: String,
    val operationType: String,
    val resourceReference: String,
    val payloadDigest: String,
    val requiredPermission: AdminPermission,
    val targetVersion: Long,
    val idempotencyKey: String,
    val correlationId: String,
    val causationId: String,
    val notes: String? = null,
)

data class ReviewDualControlCommand(
    val principal: AuthenticatedPrincipal?,
    val sessionId: String,
    val tenantId: String,
    val operationId: String,
    val action: DualControlAction,
    val payloadDigest: String,
    val expectedTargetVersion: Long,
    val idempotencyKey: String,
    val correlationId: String,
    val causationId: String,
    val notes: String? = null,
)

interface DualControlStore {
    fun findProposalByIdempotency(tenantId: String, idempotencyKey: String): Pair<String, DualControlProposalRecord>?
    fun findReceiptByIdempotency(tenantId: String, idempotencyKey: String): Pair<String, DualControlReceipt>?
    fun findProposalByOperationId(tenantId: String, operationId: String): DualControlProposalRecord?
    fun saveProposal(
        proposal: DualControlProposalRecord,
        idempotencyKey: String,
        fingerprint: String,
        audit: AuditEvent,
        outbox: OutboxEvent,
    )
    fun saveReceipt(
        receipt: DualControlReceipt,
        updatedProposal: DualControlProposalRecord,
        idempotencyKey: String,
        fingerprint: String,
        audit: AuditEvent,
        outbox: OutboxEvent,
    )
}

class InMemoryDualControlStore : DualControlStore {
    private val proposalsByOperation = mutableMapOf<String, DualControlProposalRecord>()
    private val proposalsByIdempotency = mutableMapOf<String, Pair<String, DualControlProposalRecord>>()
    private val receiptsByIdempotency = mutableMapOf<String, Pair<String, DualControlReceipt>>()
    val auditEvents = mutableListOf<AuditEvent>()
    val outboxEvents = mutableListOf<OutboxEvent>()

    @Synchronized
    override fun findProposalByIdempotency(tenantId: String, idempotencyKey: String): Pair<String, DualControlProposalRecord>? =
        proposalsByIdempotency["$tenantId:$idempotencyKey"]

    @Synchronized
    override fun findReceiptByIdempotency(tenantId: String, idempotencyKey: String): Pair<String, DualControlReceipt>? =
        receiptsByIdempotency["$tenantId:$idempotencyKey"]

    @Synchronized
    override fun findProposalByOperationId(tenantId: String, operationId: String): DualControlProposalRecord? =
        proposalsByOperation["$tenantId:$operationId"]

    @Synchronized
    override fun saveProposal(
        proposal: DualControlProposalRecord,
        idempotencyKey: String,
        fingerprint: String,
        audit: AuditEvent,
        outbox: OutboxEvent
    ) {
        proposalsByOperation["${proposal.tenantId}:${proposal.operationId}"] = proposal
        proposalsByIdempotency["${proposal.tenantId}:$idempotencyKey"] = fingerprint to proposal
        auditEvents += audit
        outboxEvents += outbox
    }

    @Synchronized
    override fun saveReceipt(
        receipt: DualControlReceipt,
        updatedProposal: DualControlProposalRecord,
        idempotencyKey: String,
        fingerprint: String,
        audit: AuditEvent,
        outbox: OutboxEvent
    ) {
        proposalsByOperation["${updatedProposal.tenantId}:${updatedProposal.operationId}"] = updatedProposal
        receiptsByIdempotency["${receipt.tenantId}:$idempotencyKey"] = fingerprint to receipt
        auditEvents += audit
        outboxEvents += outbox
    }
}
