package com.slotting.admin.auth

import java.security.MessageDigest
import java.time.Clock
import java.time.Instant
import java.util.UUID
import java.util.concurrent.ConcurrentHashMap

/**
 * Gate to enforce AUTHZ-003: Four-eyes primitives.
 * Semantic contract: "Configured high-risk actions cannot execute before second approval; immutable record."
 * Protected risk: "maker self-approves/replay"
 */
object FourEyesPrimitivesBinding {
    var isBound: Boolean = true

    fun checkBound() {
        if (!isBound) {
            throw AssertionError("maker self-approves/replay")
        }
    }
}

enum class FourEyesActionType {
    CHANGE_ROLES,
    MANUAL_BALANCE_ADJUSTMENT,
    SYSTEM_SETTLEMENT_OVERRIDE,
    BREAK_GLASS_ACCESS,
    POLICY_EXCEPTION,
    PLAYER_ACCOUNT_CLOSE,
    LIMIT_INCREASE
}

enum class FourEyesProposalStatus {
    PENDING_APPROVAL,
    APPROVED,
    REJECTED,
    EXPIRED,
    CANCELLED
}

data class FourEyesProposal(
    val proposalId: UUID,
    val tenantId: String,
    val actionType: FourEyesActionType,
    val makerPrincipal: AuthenticatedPrincipal,
    val makerReason: String,
    val payloadDigest: String,
    val payloadDetails: Map<String, String>,
    val status: FourEyesProposalStatus,
    val checkerPrincipal: AuthenticatedPrincipal? = null,
    val checkerReason: String? = null,
    val version: Long = 1L,
    val createdAt: Instant,
    val expiresAt: Instant,
    val decidedAt: Instant? = null
)

data class ProposeHighRiskActionCommand(
    val makerPrincipal: AuthenticatedPrincipal?,
    val tenantId: String,
    val actionType: FourEyesActionType,
    val makerReason: String,
    val payloadDetails: Map<String, String>,
    val ttlSeconds: Long = 3600L,
    val idempotencyKey: String,
    val correlationId: String,
    val causationId: String,
    val expectedVersion: Long = 1L
)

data class ReviewProposalCommand(
    val checkerPrincipal: AuthenticatedPrincipal?,
    val tenantId: String,
    val proposalId: UUID,
    val approve: Boolean,
    val checkerReason: String,
    val idempotencyKey: String,
    val correlationId: String,
    val causationId: String,
    val expectedVersion: Long
)

data class FourEyesDecisionResult(
    val resultId: UUID,
    val proposalId: UUID,
    val status: FourEyesProposalStatus,
    val tenantId: String,
    val actionType: FourEyesActionType,
    val makerId: String,
    val checkerId: String?,
    val serverTime: Instant,
    val serverVersion: Long,
    val evidenceReference: String,
    val auditEvent: AuditEvent,
    val outboxEvent: OutboxEvent
)

interface FourEyesProposalStore {
    fun findById(tenantId: String, proposalId: UUID): FourEyesProposal?
    fun saveProposal(proposal: FourEyesProposal)
    fun findByIdempotency(tenantId: String, idempotencyKey: String): Pair<String, FourEyesDecisionResult>?
    fun saveIdempotency(tenantId: String, idempotencyKey: String, fingerprint: String, result: FourEyesDecisionResult)
}

class InMemoryFourEyesProposalStore : FourEyesProposalStore {
    val proposals = ConcurrentHashMap<UUID, FourEyesProposal>()
    val idempotency = ConcurrentHashMap<String, Pair<String, FourEyesDecisionResult>>()

    override fun findById(tenantId: String, proposalId: UUID): FourEyesProposal? {
        val p = proposals[proposalId]
        return if (p?.tenantId == tenantId) p else null
    }

    override fun saveProposal(proposal: FourEyesProposal) {
        proposals[proposal.proposalId] = proposal
    }

    override fun findByIdempotency(tenantId: String, idempotencyKey: String): Pair<String, FourEyesDecisionResult>? {
        return idempotency["$tenantId:$idempotencyKey"]
    }

    override fun saveIdempotency(tenantId: String, idempotencyKey: String, fingerprint: String, result: FourEyesDecisionResult) {
        idempotency["$tenantId:$idempotencyKey"] = fingerprint to result
    }
}

interface FourEyesAlertSink {
    fun sendAlert(tenantId: String, alertType: String, message: String)
}

class InMemoryFourEyesAlertSink : FourEyesAlertSink {
    val alerts = mutableListOf<String>()
    override fun sendAlert(tenantId: String, alertType: String, message: String) {
        alerts.add("$tenantId:$alertType:$message")
    }
}

class FourEyesPrimitivesService(
    private val store: FourEyesProposalStore,
    private val alertSink: FourEyesAlertSink = InMemoryFourEyesAlertSink(),
    private val clock: Clock = Clock.systemUTC()
) {

    private fun validateHeaders(
        tenantId: String,
        correlationId: String,
        causationId: String,
        idempotencyKey: String,
        expectedVersion: Long
    ) {
        if (tenantId.isBlank() || correlationId.isBlank() || causationId.isBlank() || idempotencyKey.isBlank()) {
            throw AuthenticationFailure.Rejected(AuthErrorCode.INVALID)
        }
        if (expectedVersion <= 0L) {
            throw AuthenticationFailure.Rejected(AuthErrorCode.INVALID)
        }
    }

    private fun sha256(input: String): String {
        val bytes = MessageDigest.getInstance("SHA-256").digest(input.toByteArray())
        return bytes.joinToString("") { "%02x".format(it) }
    }

    private fun computeFingerprint(command: ProposeHighRiskActionCommand): String {
        return listOf(
            command.makerPrincipal?.tenantId,
            command.makerPrincipal?.id,
            command.tenantId,
            command.actionType.name,
            command.makerReason,
            command.payloadDetails.entries.sortedBy { it.key }.joinToString(",") { "${it.key}=${it.value}" },
            command.expectedVersion
        ).joinToString("|")
    }

    private fun computeFingerprint(command: ReviewProposalCommand): String {
        return listOf(
            command.checkerPrincipal?.tenantId,
            command.checkerPrincipal?.id,
            command.tenantId,
            command.proposalId.toString(),
            command.approve.toString(),
            command.checkerReason,
            command.expectedVersion
        ).joinToString("|")
    }

    fun proposeAction(command: ProposeHighRiskActionCommand): FourEyesDecisionResult = synchronized(store) {
        // 1. Fail-closed binding check
        FourEyesPrimitivesBinding.checkBound()

        // 2. Header validations
        validateHeaders(
            tenantId = command.tenantId,
            correlationId = command.correlationId,
            causationId = command.causationId,
            idempotencyKey = command.idempotencyKey,
            expectedVersion = command.expectedVersion
        )

        // 3. Idempotency check
        val fingerprint = computeFingerprint(command)
        store.findByIdempotency(command.tenantId, command.idempotencyKey)?.let { (cachedFp, cachedRes) ->
            if (cachedFp == fingerprint) {
                return cachedRes
            } else {
                throw AuthenticationFailure.Rejected(AuthErrorCode.CONFLICT)
            }
        }

        // 4. Maker authentication and tenant check
        val maker = command.makerPrincipal ?: throw AuthenticationFailure.Rejected(AuthErrorCode.UNAUTHENTICATED)
        if (maker.tenantId != command.tenantId) {
            throw AuthenticationFailure.Rejected(AuthErrorCode.FORBIDDEN)
        }
        if (maker.kind != PrincipalKind.ADMIN) {
            alertSink.sendAlert(
                tenantId = command.tenantId,
                alertType = "UNAUTHORIZED_MAKER_ATTEMPT",
                message = "Player ${maker.id} attempted high-risk action proposal ${command.actionType}"
            )
            throw AuthenticationFailure.Rejected(AuthErrorCode.FORBIDDEN)
        }

        if (command.makerReason.isBlank()) {
            throw AuthenticationFailure.Rejected(AuthErrorCode.INVALID)
        }

        val proposalId = UUID.randomUUID()
        val now = clock.instant()
        val expiresAt = now.plusSeconds(command.ttlSeconds)
        val payloadDigest = sha256(command.payloadDetails.entries.sortedBy { it.key }.joinToString(",") { "${it.key}=${it.value}" })

        val proposal = FourEyesProposal(
            proposalId = proposalId,
            tenantId = command.tenantId,
            actionType = command.actionType,
            makerPrincipal = maker,
            makerReason = command.makerReason,
            payloadDigest = payloadDigest,
            payloadDetails = command.payloadDetails,
            status = FourEyesProposalStatus.PENDING_APPROVAL,
            version = 1L,
            createdAt = now,
            expiresAt = expiresAt
        )

        store.saveProposal(proposal)

        val resultId = UUID.randomUUID()
        val evidenceReference = "four-eyes:${command.tenantId}:${proposal.actionType}:$proposalId:1:PROPOSED"

        val auditEvent = AuditEvent(
            eventId = UUID.randomUUID(),
            resultId = resultId,
            tenantId = command.tenantId,
            type = "FOUR_EYES_PROPOSAL_CREATED",
            occurredAt = now,
            correlationId = command.correlationId,
            causationId = command.causationId
        )

        val outboxEvent = OutboxEvent(
            eventId = UUID.randomUUID(),
            resultId = resultId,
            tenantId = command.tenantId,
            type = "FOUR_EYES_PROPOSAL_CREATED",
            createdAt = now
        )

        val result = FourEyesDecisionResult(
            resultId = resultId,
            proposalId = proposalId,
            status = FourEyesProposalStatus.PENDING_APPROVAL,
            tenantId = command.tenantId,
            actionType = command.actionType,
            makerId = maker.id,
            checkerId = null,
            serverTime = now,
            serverVersion = 1L,
            evidenceReference = evidenceReference,
            auditEvent = auditEvent,
            outboxEvent = outboxEvent
        )

        store.saveIdempotency(command.tenantId, command.idempotencyKey, fingerprint, result)
        return result
    }

    fun reviewProposal(command: ReviewProposalCommand): FourEyesDecisionResult = synchronized(store) {
        // 1. Fail-closed binding check
        FourEyesPrimitivesBinding.checkBound()

        // 2. Header validations
        validateHeaders(
            tenantId = command.tenantId,
            correlationId = command.correlationId,
            causationId = command.causationId,
            idempotencyKey = command.idempotencyKey,
            expectedVersion = command.expectedVersion
        )

        // 3. Idempotency check (prevents duplicate execution/replay)
        val fingerprint = computeFingerprint(command)
        store.findByIdempotency(command.tenantId, command.idempotencyKey)?.let { (cachedFp, cachedRes) ->
            if (cachedFp == fingerprint) {
                return cachedRes
            } else {
                throw AuthenticationFailure.Rejected(AuthErrorCode.CONFLICT)
            }
        }

        // 4. Checker authentication and tenant check
        val checker = command.checkerPrincipal ?: throw AuthenticationFailure.Rejected(AuthErrorCode.UNAUTHENTICATED)
        if (checker.tenantId != command.tenantId) {
            throw AuthenticationFailure.Rejected(AuthErrorCode.FORBIDDEN)
        }
        if (checker.kind != PrincipalKind.ADMIN) {
            throw AuthenticationFailure.Rejected(AuthErrorCode.FORBIDDEN)
        }

        if (command.checkerReason.isBlank()) {
            throw AuthenticationFailure.Rejected(AuthErrorCode.INVALID)
        }

        // 5. Fetch proposal
        val proposal = store.findById(command.tenantId, command.proposalId)
            ?: throw AuthenticationFailure.Rejected(AuthErrorCode.INVALID)

        if (proposal.tenantId != command.tenantId) {
            throw AuthenticationFailure.Rejected(AuthErrorCode.FORBIDDEN)
        }

        // 6. Version and Staleness Check
        if (command.expectedVersion != proposal.version) {
            throw AuthenticationFailure.Rejected(AuthErrorCode.STALE)
        }

        val now = clock.instant()

        // 7. Status Check - cannot review already approved or rejected proposal (prevents replay / state tampering)
        if (proposal.status != FourEyesProposalStatus.PENDING_APPROVAL) {
            throw AuthenticationFailure.Rejected(AuthErrorCode.CONFLICT)
        }

        // 8. Expiration / TTL Check
        if (now.isAfter(proposal.expiresAt)) {
            val expiredProposal = proposal.copy(
                status = FourEyesProposalStatus.EXPIRED,
                decidedAt = now,
                version = proposal.version + 1
            )
            store.saveProposal(expiredProposal)
            throw AuthenticationFailure.Rejected(AuthErrorCode.STALE)
        }

        // 9. Core Protection: Maker cannot self-approve
        if (checker.id == proposal.makerPrincipal.id) {
            alertSink.sendAlert(
                tenantId = command.tenantId,
                alertType = "MAKER_SELF_APPROVAL_ATTEMPT",
                message = "Maker ${proposal.makerPrincipal.id} attempted to self-approve proposal ${proposal.proposalId}"
            )
            throw AuthenticationFailure.Rejected(AuthErrorCode.FORBIDDEN)
        }

        // 10. Checker Least-Privilege Role Check
        val canCheck = checker.roles.contains(AdminRole.SUPER_ADMIN) ||
            checker.roles.contains(AdminRole.SECURITY) ||
            checker.roles.contains(AdminRole.SUPPORT)
        if (!canCheck) {
            alertSink.sendAlert(
                tenantId = command.tenantId,
                alertType = "UNAUTHORIZED_CHECKER_ATTEMPT",
                message = "Admin ${checker.id} lacking authority to review action ${proposal.actionType}"
            )
            throw AuthenticationFailure.Rejected(AuthErrorCode.FORBIDDEN)
        }

        val newStatus = if (command.approve) FourEyesProposalStatus.APPROVED else FourEyesProposalStatus.REJECTED
        val nextVersion = proposal.version + 1
        val updatedProposal = proposal.copy(
            status = newStatus,
            checkerPrincipal = checker,
            checkerReason = command.checkerReason,
            version = nextVersion,
            decidedAt = now
        )
        store.saveProposal(updatedProposal)

        val resultId = UUID.randomUUID()
        val evidenceReference = "four-eyes:${command.tenantId}:${proposal.actionType}:${proposal.proposalId}:$nextVersion:${newStatus.name}"

        val auditEvent = AuditEvent(
            eventId = UUID.randomUUID(),
            resultId = resultId,
            tenantId = command.tenantId,
            type = if (command.approve) "FOUR_EYES_PROPOSAL_APPROVED" else "FOUR_EYES_PROPOSAL_REJECTED",
            occurredAt = now,
            correlationId = command.correlationId,
            causationId = command.causationId
        )

        val outboxEvent = OutboxEvent(
            eventId = UUID.randomUUID(),
            resultId = resultId,
            tenantId = command.tenantId,
            type = if (command.approve) "FOUR_EYES_PROPOSAL_APPROVED" else "FOUR_EYES_PROPOSAL_REJECTED",
            createdAt = now
        )

        val result = FourEyesDecisionResult(
            resultId = resultId,
            proposalId = proposal.proposalId,
            status = newStatus,
            tenantId = command.tenantId,
            actionType = proposal.actionType,
            makerId = proposal.makerPrincipal.id,
            checkerId = checker.id,
            serverTime = now,
            serverVersion = nextVersion,
            evidenceReference = evidenceReference,
            auditEvent = auditEvent,
            outboxEvent = outboxEvent
        )

        store.saveIdempotency(command.tenantId, command.idempotencyKey, fingerprint, result)
        return result
    }
}
