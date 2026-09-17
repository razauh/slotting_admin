package com.slotting.admin.aml

import com.slotting.admin.auth.*
import java.security.MessageDigest
import java.time.Clock
import java.time.Duration
import java.time.Instant
import java.util.UUID

enum class AmlReviewState { QUEUED, CLAIMED, APPROVED, REJECTED }
enum class AmlReviewAction { CLAIM, RELEASE, APPROVE, REJECT }
enum class AmlReviewReason { REVIEW_REQUIRED, HIGH_RISK_ACTION, SUSPICIOUS_ACTIVITY, SANCTION_SCREENING, STRUCTURING_ALERT }

data class AmlReviewCommand(
    val principal: AuthenticatedPrincipal?,
    val sessionId: String,
    val tenantId: String,
    val caseReference: String,
    val action: AmlReviewAction,
    val reason: AmlReviewReason,
    val idempotencyKey: String,
    val correlationId: String,
    val causationId: String,
    val expectedVersion: Long,
    val secondApproverId: String? = null,
)

data class AmlQueueItem(
    val caseReference: String,
    val state: AmlReviewState,
    val claimedBy: String?,
    val claimExpiresAt: Instant?,
    val serverVersion: Long,
)

data class AmlReviewResult(
    val resultId: UUID,
    val item: AmlQueueItem,
    val serverTime: Instant,
    val evidenceReference: String,
)

interface AmlQueueStore {
    fun findByIdempotency(tenantId: String, key: String): Pair<String, AmlReviewResult>?
    fun findItem(tenantId: String, caseReference: String): AmlQueueItem?
    fun save(
        result: AmlReviewResult,
        tenantId: String,
        reason: AmlReviewReason,
        secondApproverId: String?,
        queryFingerprint: String,
        idempotencyKey: String,
        audit: AuditEvent,
        outbox: OutboxEvent,
    )
}

class AmlReviewQueue(
    private val policy: AdminRbacPolicy,
    private val sessions: AdminSessionDirectory,
    private val store: AmlQueueStore,
    private val clock: Clock = Clock.systemUTC(),
    private val claimLease: Duration = Duration.ofMinutes(15),
    private val dualApprovalRequired: Boolean = true,
) {
    @Synchronized
    fun operate(command: AmlReviewCommand): AmlReviewResult {
        val principal = command.principal ?: throw AuthenticationFailure.Rejected(AuthErrorCode.UNAUTHENTICATED)
        val fingerprint = fingerprint(command)
        store.findByIdempotency(command.tenantId, command.idempotencyKey)?.let { replay ->
            if (replay.first != fingerprint) throw AuthenticationFailure.Rejected(AuthErrorCode.CONFLICT)
            return replay.second
        }
        if (principal.kind != PrincipalKind.ADMIN || principal.tenantId != command.tenantId) {
            throw AuthenticationFailure.Rejected(AuthErrorCode.FORBIDDEN)
        }
        if (command.caseReference.isBlank() || command.caseReference.length > 128 ||
            command.sessionId.isBlank() || command.correlationId.isBlank() || command.causationId.isBlank()) {
            throw AuthenticationFailure.Rejected(AuthErrorCode.INVALID)
        }
        val now = Instant.now(clock)
        val session = try {
            sessions.find(command.tenantId, principal.id, command.sessionId)
        } catch (_: Exception) {
            throw AuthenticationFailure.Rejected(AuthErrorCode.DEPENDENCY_UNAVAILABLE)
        }
        if (session == null || !session.active || !session.expiresAt.isAfter(now) ||
            !policy.isPermitted(principal, AdminPermission.MANAGE_SECURITY)) {
            throw AuthenticationFailure.Rejected(AuthErrorCode.FORBIDDEN)
        }
        val current = store.findItem(command.tenantId, command.caseReference)
            ?: throw AuthenticationFailure.Rejected(AuthErrorCode.FORBIDDEN)
        val next = transition(current, command, principal.id, now)
        val resultId = UUID.randomUUID()
        val result = AmlReviewResult(resultId, next, now, "aml-review:$resultId")
        val type = "AML_REVIEW_${command.action.name}"
        val audit = AuditEvent(UUID.randomUUID(), resultId, command.tenantId, type, now, command.correlationId, command.causationId)
        val outbox = OutboxEvent(UUID.randomUUID(), resultId, command.tenantId, type, now)
        store.save(result, command.tenantId, command.reason, command.secondApproverId, fingerprint, command.idempotencyKey, audit, outbox)
        return result
    }

    private fun transition(item: AmlQueueItem, command: AmlReviewCommand, principalId: String, now: Instant): AmlQueueItem {
        if (item.serverVersion != command.expectedVersion) throw AuthenticationFailure.Rejected(AuthErrorCode.STALE)
        return when (command.action) {
            AmlReviewAction.CLAIM -> {
                if (item.state == AmlReviewState.QUEUED || (item.state == AmlReviewState.CLAIMED && item.claimExpiresAt?.isBefore(now) == true)) {
                    item.copy(
                        state = AmlReviewState.CLAIMED,
                        claimedBy = principalId,
                        claimExpiresAt = now.plus(claimLease),
                        serverVersion = item.serverVersion + 1,
                    )
                } else {
                    throw AuthenticationFailure.Rejected(AuthErrorCode.CONFLICT)
                }
            }
            AmlReviewAction.RELEASE -> {
                if (item.state == AmlReviewState.CLAIMED && item.claimedBy == principalId) {
                    item.copy(
                        state = AmlReviewState.QUEUED,
                        claimedBy = null,
                        claimExpiresAt = null,
                        serverVersion = item.serverVersion + 1,
                    )
                } else {
                    throw AuthenticationFailure.Rejected(AuthErrorCode.FORBIDDEN)
                }
            }
            AmlReviewAction.APPROVE, AmlReviewAction.REJECT -> {
                if (item.state != AmlReviewState.CLAIMED || item.claimedBy != principalId) {
                    throw AuthenticationFailure.Rejected(AuthErrorCode.FORBIDDEN)
                }
                if (dualApprovalRequired && (command.secondApproverId.isNullOrBlank() || command.secondApproverId == principalId)) {
                    throw AuthenticationFailure.Rejected(AuthErrorCode.FORBIDDEN)
                }
                item.copy(
                    state = if (command.action == AmlReviewAction.APPROVE) AmlReviewState.APPROVED else AmlReviewState.REJECTED,
                    claimedBy = null,
                    claimExpiresAt = null,
                    serverVersion = item.serverVersion + 1,
                )
            }
        }
    }

    private fun fingerprint(command: AmlReviewCommand) = listOf(
        command.tenantId, command.caseReference, command.action, command.reason, command.expectedVersion, command.secondApproverId,
    ).joinToString("|") { sha256(it.toString()) }

    private fun sha256(value: String) = MessageDigest.getInstance("SHA-256")
        .digest(value.toByteArray(Charsets.UTF_8))
        .joinToString("") { "%02x".format(it) }
}
