package com.slotting.admin.auth

import java.security.MessageDigest
import java.time.Clock
import java.time.Duration
import java.time.Instant
import java.util.UUID

class DualControlApprovalService(
    private val sessions: AdminSessionDirectory,
    private val store: DualControlStore,
    private val policy: AdminRbacPolicy,
    private val alerts: AlertSink,
    private val clock: Clock = Clock.systemUTC(),
    private val proposalTtl: Duration = Duration.ofHours(24),
) {
    @Synchronized
    fun propose(command: ProposeDualControlCommand): DualControlProposalRecord {
        val principal = command.principal ?: throw AuthenticationFailure.Rejected(AuthErrorCode.UNAUTHENTICATED)
        if (principal.kind != PrincipalKind.ADMIN || principal.tenantId != command.tenantId) {
            throw AuthenticationFailure.Rejected(AuthErrorCode.FORBIDDEN)
        }
        if (command.operationId.isBlank() || command.operationType.isBlank() || command.payloadDigest.isBlank() ||
            command.sessionId.isBlank() || command.correlationId.isBlank() || command.causationId.isBlank()) {
            throw AuthenticationFailure.Rejected(AuthErrorCode.INVALID)
        }
        val now = Instant.now(clock)
        val session = sessions.find(command.tenantId, principal.id, command.sessionId)
        if (session == null || !session.active || !session.expiresAt.isAfter(now) ||
            !session.mfaVerified || (session.mfaExpiresAt != null && !session.mfaExpiresAt.isAfter(now))) {
            throw AuthenticationFailure.Rejected(AuthErrorCode.FORBIDDEN)
        }
        if (!policy.isPermitted(principal, command.requiredPermission)) {
            throw AuthenticationFailure.Rejected(AuthErrorCode.FORBIDDEN)
        }

        val fingerprint = fingerprint(command)
        store.findProposalByIdempotency(command.tenantId, command.idempotencyKey)?.let { replay ->
            if (replay.first != fingerprint) throw AuthenticationFailure.Rejected(AuthErrorCode.CONFLICT)
            return replay.second
        }

        if (store.findProposalByOperationId(command.tenantId, command.operationId) != null) {
            throw AuthenticationFailure.Rejected(AuthErrorCode.CONFLICT)
        }

        val proposalId = UUID.randomUUID()
        val expiresAt = now.plus(proposalTtl)
        val maker = DecisionActor(
            principalId = principal.id,
            tenantId = principal.tenantId,
            roles = principal.roles,
            sessionId = command.sessionId,
            mfaVerified = session.mfaVerified,
            decidedAt = now
        )
        val proposal = DualControlProposalRecord(
            proposalId = proposalId,
            tenantId = command.tenantId,
            operationId = command.operationId,
            operationType = command.operationType,
            resourceReference = command.resourceReference,
            payloadDigest = command.payloadDigest,
            requiredPermission = command.requiredPermission,
            targetVersion = command.targetVersion,
            status = DualControlStatus.PENDING_CHECKER,
            maker = maker,
            notes = command.notes,
            proposedAt = now,
            expiresAt = expiresAt,
            version = 1L
        )

        val audit = AuditEvent(UUID.randomUUID(), proposalId, command.tenantId, "DUAL_CONTROL_PROPOSED", now, command.correlationId, command.causationId)
        val outbox = OutboxEvent(UUID.randomUUID(), proposalId, command.tenantId, "DUAL_CONTROL_PROPOSED", now)
        store.saveProposal(proposal, command.idempotencyKey, fingerprint, audit, outbox)
        return proposal
    }

    @Synchronized
    fun review(command: ReviewDualControlCommand): DualControlReceipt {
        val principal = command.principal ?: throw AuthenticationFailure.Rejected(AuthErrorCode.UNAUTHENTICATED)
        if (principal.kind != PrincipalKind.ADMIN || principal.tenantId != command.tenantId) {
            throw AuthenticationFailure.Rejected(AuthErrorCode.FORBIDDEN)
        }
        if (command.operationId.isBlank() || command.payloadDigest.isBlank() ||
            command.sessionId.isBlank() || command.correlationId.isBlank() || command.causationId.isBlank()) {
            throw AuthenticationFailure.Rejected(AuthErrorCode.INVALID)
        }
        val now = Instant.now(clock)
        val session = sessions.find(command.tenantId, principal.id, command.sessionId)
        if (session == null || !session.active || !session.expiresAt.isAfter(now) ||
            !session.mfaVerified || (session.mfaExpiresAt != null && !session.mfaExpiresAt.isAfter(now))) {
            throw AuthenticationFailure.Rejected(AuthErrorCode.FORBIDDEN)
        }

        val fingerprint = fingerprint(command)
        store.findReceiptByIdempotency(command.tenantId, command.idempotencyKey)?.let { replay ->
            if (replay.first != fingerprint) throw AuthenticationFailure.Rejected(AuthErrorCode.CONFLICT)
            return replay.second
        }

        val proposal = store.findProposalByOperationId(command.tenantId, command.operationId)
            ?: throw AuthenticationFailure.Rejected(AuthErrorCode.FORBIDDEN)

        if (proposal.status != DualControlStatus.PENDING_CHECKER) {
            throw AuthenticationFailure.Rejected(AuthErrorCode.CONFLICT)
        }

        if (proposal.maker.principalId == principal.id) {
            val alertEvent = AuditEvent(UUID.randomUUID(), proposal.proposalId, command.tenantId, "DUAL_CONTROL_SELF_APPROVAL_ATTEMPT", now, command.correlationId, command.causationId)
            alerts.alert(alertEvent)
            throw AuthenticationFailure.Rejected(AuthErrorCode.FORBIDDEN)
        }

        if (proposal.payloadDigest != command.payloadDigest) {
            val alertEvent = AuditEvent(UUID.randomUUID(), proposal.proposalId, command.tenantId, "DUAL_CONTROL_PAYLOAD_MISMATCH", now, command.correlationId, command.causationId)
            alerts.alert(alertEvent)
            throw AuthenticationFailure.Rejected(AuthErrorCode.CONFLICT)
        }

        if (proposal.targetVersion != command.expectedTargetVersion) {
            throw AuthenticationFailure.Rejected(AuthErrorCode.STALE)
        }

        if (!policy.isPermitted(principal, proposal.requiredPermission)) {
            throw AuthenticationFailure.Rejected(AuthErrorCode.FORBIDDEN)
        }

        val checker = DecisionActor(
            principalId = principal.id,
            tenantId = principal.tenantId,
            roles = principal.roles,
            sessionId = command.sessionId,
            mfaVerified = session.mfaVerified,
            decidedAt = now
        )

        val nextStatus = if (command.action == DualControlAction.APPROVE) DualControlStatus.APPROVED else DualControlStatus.REJECTED
        val receiptId = UUID.randomUUID()
        val receipt = DualControlReceipt(
            receiptId = receiptId,
            proposalId = proposal.proposalId,
            tenantId = command.tenantId,
            operationId = command.operationId,
            operationType = proposal.operationType,
            resourceReference = proposal.resourceReference,
            payloadDigest = proposal.payloadDigest,
            requiredPermission = proposal.requiredPermission,
            targetVersion = proposal.targetVersion,
            status = nextStatus,
            maker = proposal.maker,
            checker = checker,
            notes = command.notes,
            decidedAt = now,
            expiresAt = proposal.expiresAt,
            evidenceReference = "dual-control:$receiptId"
        )

        val updatedProposal = proposal.copy(status = nextStatus, version = proposal.version + 1)
        val eventType = if (nextStatus == DualControlStatus.APPROVED) "DUAL_CONTROL_APPROVED" else "DUAL_CONTROL_REJECTED"
        val audit = AuditEvent(UUID.randomUUID(), receiptId, command.tenantId, eventType, now, command.correlationId, command.causationId)
        val outbox = OutboxEvent(UUID.randomUUID(), receiptId, command.tenantId, eventType, now)
        store.saveReceipt(receipt, updatedProposal, command.idempotencyKey, fingerprint, audit, outbox)
        return receipt
    }

    fun validateReceipt(
        receipt: DualControlReceipt,
        tenantId: String,
        operationId: String,
        payloadDigest: String,
        targetVersion: Long
    ): Boolean {
        val now = Instant.now(clock)
        return receipt.tenantId == tenantId &&
            receipt.operationId == operationId &&
            receipt.payloadDigest == payloadDigest &&
            receipt.targetVersion == targetVersion &&
            receipt.status == DualControlStatus.APPROVED &&
            receipt.maker.principalId != receipt.checker.principalId &&
            receipt.expiresAt.isAfter(now)
    }

    private fun fingerprint(command: ProposeDualControlCommand): String = listOf(
        command.tenantId,
        command.operationId,
        command.operationType,
        command.resourceReference,
        command.payloadDigest,
        command.requiredPermission,
        command.targetVersion,
        command.principal?.id,
    ).joinToString("|")

    private fun fingerprint(command: ReviewDualControlCommand): String = listOf(
        command.tenantId,
        command.operationId,
        command.action,
        command.payloadDigest,
        command.expectedTargetVersion,
        command.principal?.id,
    ).joinToString("|")
}
