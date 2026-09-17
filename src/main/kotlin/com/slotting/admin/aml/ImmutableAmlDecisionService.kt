package com.slotting.admin.aml

import com.slotting.admin.auth.*
import java.security.MessageDigest
import java.time.Clock
import java.time.Duration
import java.time.Instant
import java.util.UUID

enum class AmlDecisionType {
    APPROVE,
    REJECT,
    ESCALATE,
}

enum class AmlDecisionPayoutStatus {
    PAYOUT_PERMITTED,
    BLOCKED_PENDING_REVIEW,
    BLOCKED_REJECTED,
    BLOCKED_EXPIRED,
}

data class RecordAmlDecisionCommand(
    val principal: AuthenticatedPrincipal?,
    val sessionId: String,
    val tenantId: String,
    val caseReference: String,
    val subjectReference: String,
    val decisionType: AmlDecisionType,
    val reason: AmlReviewReason,
    val justification: String,
    val evidenceReference: String,
    val secondApproverId: String? = null,
    val supersedesDecisionId: UUID? = null,
    val idempotencyKey: String,
    val correlationId: String,
    val causationId: String,
    val expectedVersion: Long = 1L,
)

data class ImmutableAmlDecisionRecord(
    val decisionId: UUID,
    val tenantId: String,
    val caseReference: String,
    val subjectReference: String,
    val decisionType: AmlDecisionType,
    val reason: AmlReviewReason,
    val justification: String,
    val evidenceReference: String,
    val signedByPrincipalId: String,
    val secondApproverId: String?,
    val supersedesDecisionId: UUID?,
    val retentionExpiresAt: Instant,
    val serverVersion: Long,
    val decidedAt: Instant,
    val isSuperseded: Boolean = false,
)

data class AmlDecisionResult(
    val resultId: UUID,
    val decisionId: UUID,
    val tenantId: String,
    val caseReference: String,
    val subjectReference: String,
    val decisionType: AmlDecisionType,
    val supersedesDecisionId: UUID?,
    val retentionExpiresAt: Instant,
    val updatedQueueItem: AmlQueueItem,
    val financialAuthorityCreated: Boolean, // Invariant: must be false
    val moneyMutated: Boolean,             // Invariant: must be false
    val evidenceReference: String,
    val decidedAt: Instant,
)

data class VerifyAmlPayoutClearanceCommand(
    val tenantId: String,
    val subjectReference: String,
    val amountMinorUnits: Long,
)

data class AmlPayoutClearanceDecision(
    val payoutPermitted: Boolean,
    val status: AmlDecisionPayoutStatus,
    val activeDecisionId: UUID?,
    val denialReason: String?,
    val evaluatedAt: Instant,
)

interface ImmutableAmlDecisionStore {
    fun findByIdempotency(tenantId: String, idempotencyKey: String): Pair<String, AmlDecisionResult>?
    fun findLatestDecision(tenantId: String, subjectReference: String): ImmutableAmlDecisionRecord?
    fun findDecisionById(tenantId: String, decisionId: UUID): ImmutableAmlDecisionRecord?
    fun findQueueItem(tenantId: String, caseReference: String): AmlQueueItem?
    fun save(
        decision: ImmutableAmlDecisionRecord,
        result: AmlDecisionResult,
        tenantId: String,
        queryFingerprint: String,
        idempotencyKey: String,
        audit: AuditEvent,
        outbox: OutboxEvent,
        updatedQueueItem: AmlQueueItem,
        supersededDecision: ImmutableAmlDecisionRecord? = null,
    )
}

class ImmutableAmlDecisionService(
    private val policy: AdminRbacPolicy,
    private val sessions: AdminSessionDirectory,
    private val store: ImmutableAmlDecisionStore,
    private val clock: Clock = Clock.systemUTC(),
    private val retentionDuration: Duration = Duration.ofDays(365 * 5), // 5 years minimal retention per approved policy
) {
    @Synchronized
    fun recordDecision(command: RecordAmlDecisionCommand): AmlDecisionResult {
        val principal = command.principal ?: throw AuthenticationFailure.Rejected(AuthErrorCode.UNAUTHENTICATED)
        if (principal.kind != PrincipalKind.ADMIN || principal.tenantId != command.tenantId) {
            throw AuthenticationFailure.Rejected(AuthErrorCode.FORBIDDEN)
        }

        val session = try {
            sessions.find(command.tenantId, principal.id, command.sessionId)
        } catch (_: Exception) {
            throw AuthenticationFailure.Rejected(AuthErrorCode.DEPENDENCY_UNAVAILABLE)
        } ?: throw AuthenticationFailure.Rejected(AuthErrorCode.FORBIDDEN)

        if (!session.active || session.expiresAt.isBefore(clock.instant())) {
            throw AuthenticationFailure.Rejected(AuthErrorCode.FORBIDDEN)
        }

        if (!policy.isPermitted(principal, AdminPermission.MANAGE_SECURITY)) {
            throw AuthenticationFailure.Rejected(AuthErrorCode.FORBIDDEN)
        }

        if (command.caseReference.isBlank() ||
            command.subjectReference.isBlank() ||
            command.justification.isBlank() ||
            command.evidenceReference.isBlank() ||
            command.sessionId.isBlank() ||
            command.correlationId.isBlank() ||
            command.causationId.isBlank()
        ) {
            throw AuthenticationFailure.Rejected(AuthErrorCode.INVALID)
        }

        // Segregation of duties: second approver cannot be the same as primary approver
        if (command.secondApproverId != null && command.secondApproverId == principal.id) {
            throw AuthenticationFailure.Rejected(AuthErrorCode.INVALID)
        }

        if (command.expectedVersion != 1L) {
            throw AuthenticationFailure.Rejected(AuthErrorCode.STALE)
        }

        val supersededDecision = if (command.supersedesDecisionId != null) {
            val old = store.findDecisionById(command.tenantId, command.supersedesDecisionId)
                ?: throw AuthenticationFailure.Rejected(AuthErrorCode.INVALID)
            // Decision immutable: prior record remains intact, marked superseded
            old.copy(isSuperseded = true)
        } else {
            null
        }

        val fp = fingerprint(command)
        store.findByIdempotency(command.tenantId, command.idempotencyKey)?.let { (cachedFp, cachedResult) ->
            if (cachedFp != fp) throw AuthenticationFailure.Rejected(AuthErrorCode.CONFLICT)
            return cachedResult
        }

        val now = clock.instant()
        val resultId = UUID.randomUUID()
        val decisionId = UUID.randomUUID()
        val retentionExpiresAt = now.plus(retentionDuration)
        val serverVersion = if (supersededDecision != null) supersededDecision.serverVersion + 1L else 1L

        val existingQueueItem = store.findQueueItem(command.tenantId, command.caseReference)
            ?: AmlQueueItem(command.caseReference, AmlReviewState.QUEUED, null, null, 0L)

        val nextReviewState = when (command.decisionType) {
            AmlDecisionType.APPROVE -> AmlReviewState.APPROVED
            AmlDecisionType.REJECT -> AmlReviewState.REJECTED
            AmlDecisionType.ESCALATE -> AmlReviewState.QUEUED
        }

        val updatedQueueItem = existingQueueItem.copy(
            state = nextReviewState,
            claimedBy = null,
            claimExpiresAt = null,
            serverVersion = existingQueueItem.serverVersion + 1L,
        )

        val decision = ImmutableAmlDecisionRecord(
            decisionId = decisionId,
            tenantId = command.tenantId,
            caseReference = command.caseReference,
            subjectReference = command.subjectReference,
            decisionType = command.decisionType,
            reason = command.reason,
            justification = command.justification,
            evidenceReference = command.evidenceReference,
            signedByPrincipalId = principal.id,
            secondApproverId = command.secondApproverId,
            supersedesDecisionId = command.supersedesDecisionId,
            retentionExpiresAt = retentionExpiresAt,
            serverVersion = serverVersion,
            decidedAt = now,
            isSuperseded = false,
        )

        val result = AmlDecisionResult(
            resultId = resultId,
            decisionId = decisionId,
            tenantId = command.tenantId,
            caseReference = command.caseReference,
            subjectReference = command.subjectReference,
            decisionType = command.decisionType,
            supersedesDecisionId = command.supersedesDecisionId,
            retentionExpiresAt = retentionExpiresAt,
            updatedQueueItem = updatedQueueItem,
            financialAuthorityCreated = false, // Invariant: No financial authority created
            moneyMutated = false,             // Invariant: Cannot mutate money
            evidenceReference = "EVID-AML-DECISION-${command.subjectReference}",
            decidedAt = now,
        )

        val audit = AuditEvent(
            eventId = UUID.randomUUID(),
            resultId = resultId,
            tenantId = command.tenantId,
            type = "AML_DECISION_RECORDED",
            occurredAt = now,
            correlationId = command.correlationId,
            causationId = command.causationId,
        )

        val outbox = OutboxEvent(
            eventId = UUID.randomUUID(),
            resultId = resultId,
            tenantId = command.tenantId,
            type = "AML_DECISION_RECORDED",
            createdAt = now,
        )

        store.save(decision, result, command.tenantId, fp, command.idempotencyKey, audit, outbox, updatedQueueItem, supersededDecision)
        return result
    }

    @Synchronized
    fun verifyPayoutClearance(command: VerifyAmlPayoutClearanceCommand): AmlPayoutClearanceDecision {
        val latest = store.findLatestDecision(command.tenantId, command.subjectReference)
        val now = clock.instant()

        if (latest == null) {
            return AmlPayoutClearanceDecision(
                payoutPermitted = false,
                status = AmlDecisionPayoutStatus.BLOCKED_PENDING_REVIEW,
                activeDecisionId = null,
                denialReason = "Payout blocked: Required AML review decision has not been recorded",
                evaluatedAt = now,
            )
        }

        if (latest.decisionType == AmlDecisionType.REJECT) {
            return AmlPayoutClearanceDecision(
                payoutPermitted = false,
                status = AmlDecisionPayoutStatus.BLOCKED_REJECTED,
                activeDecisionId = latest.decisionId,
                denialReason = "Payout blocked: Subject AML decision is REJECTED",
                evaluatedAt = now,
            )
        }

        if (latest.decisionType == AmlDecisionType.ESCALATE) {
            return AmlPayoutClearanceDecision(
                payoutPermitted = false,
                status = AmlDecisionPayoutStatus.BLOCKED_PENDING_REVIEW,
                activeDecisionId = latest.decisionId,
                denialReason = "Payout blocked: AML decision escalated for compliance review",
                evaluatedAt = now,
            )
        }

        if (latest.retentionExpiresAt.isBefore(now)) {
            return AmlPayoutClearanceDecision(
                payoutPermitted = false,
                status = AmlDecisionPayoutStatus.BLOCKED_EXPIRED,
                activeDecisionId = latest.decisionId,
                denialReason = "Payout blocked: AML decision has expired per minimal retention policy",
                evaluatedAt = now,
            )
        }

        return AmlPayoutClearanceDecision(
            payoutPermitted = true,
            status = AmlDecisionPayoutStatus.PAYOUT_PERMITTED,
            activeDecisionId = latest.decisionId,
            denialReason = null,
            evaluatedAt = now,
        )
    }

    private fun fingerprint(command: RecordAmlDecisionCommand): String {
        val md = MessageDigest.getInstance("SHA-256")
        val raw = "${command.tenantId}:${command.caseReference}:${command.subjectReference}:${command.decisionType}:${command.reason}:${command.justification}:${command.evidenceReference}:${command.secondApproverId}:${command.supersedesDecisionId}:${command.expectedVersion}"
        return md.digest(raw.toByteArray(Charsets.UTF_8)).joinToString("") { "%02x".format(it) }
    }
}
