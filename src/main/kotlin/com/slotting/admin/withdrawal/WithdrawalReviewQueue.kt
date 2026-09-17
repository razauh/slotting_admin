package com.slotting.admin.withdrawal

import com.slotting.admin.auth.AdminPermission
import com.slotting.admin.auth.AdminRbacPolicy
import com.slotting.admin.auth.AdminSessionDirectory
import com.slotting.admin.auth.AuthErrorCode
import com.slotting.admin.auth.AuthenticatedPrincipal
import com.slotting.admin.auth.AuthenticationFailure
import com.slotting.admin.auth.AuditEvent
import com.slotting.admin.auth.OutboxEvent
import java.security.MessageDigest
import java.time.Clock
import java.time.Duration
import java.time.Instant
import java.util.UUID

enum class WithdrawalReviewState { QUEUED, CLAIMED, APPROVED, REJECTED }
enum class WithdrawalReviewAction { CLAIM, RELEASE, APPROVE, REJECT }
enum class WithdrawalReviewReason { REVIEW_REQUIRED, KYC_REVIEW, FRAUD_REVIEW, CUSTOMER_REQUEST }

data class WithdrawalReviewCommand(
    val principal: AuthenticatedPrincipal?,
    val sessionId: String,
    val tenantId: String,
    val withdrawalReference: String,
    val action: WithdrawalReviewAction,
    val reason: WithdrawalReviewReason,
    val idempotencyKey: String,
    val correlationId: String,
    val causationId: String,
    val expectedVersion: Long,
    val secondApproverId: String? = null,
)

data class WithdrawalQueueItem(
    val withdrawalReference: String,
    val state: WithdrawalReviewState,
    val claimedBy: String?,
    val claimExpiresAt: Instant?,
    val serverVersion: Long,
)

data class WithdrawalReviewResult(
    val resultId: UUID,
    val item: WithdrawalQueueItem,
    val serverTime: Instant,
    val evidenceReference: String,
)

interface WithdrawalQueueStore {
    fun findByIdempotency(tenantId: String, key: String): Pair<String, WithdrawalReviewResult>?
    fun findItem(tenantId: String, withdrawalReference: String): WithdrawalQueueItem?
    fun save(
        result: WithdrawalReviewResult,
        tenantId: String,
        reason: WithdrawalReviewReason,
        secondApproverId: String?,
        queryFingerprint: String,
        idempotencyKey: String,
        audit: AuditEvent,
        outbox: OutboxEvent,
    )
}

class WithdrawalReviewQueue(
    private val policy: AdminRbacPolicy,
    private val sessions: AdminSessionDirectory,
    private val store: WithdrawalQueueStore,
    private val clock: Clock = Clock.systemUTC(),
    private val claimLease: Duration = Duration.ofMinutes(15),
    private val dualApprovalRequired: Boolean = true,
) {
    @Synchronized
    fun operate(command: WithdrawalReviewCommand): WithdrawalReviewResult {
        val principal = command.principal ?: throw AuthenticationFailure.Rejected(AuthErrorCode.UNAUTHENTICATED)
        val fingerprint = fingerprint(command)
        store.findByIdempotency(command.tenantId, command.idempotencyKey)?.let { replay ->
            if (replay.first != fingerprint) throw AuthenticationFailure.Rejected(AuthErrorCode.CONFLICT)
            return replay.second
        }
        if (principal.kind != com.slotting.admin.auth.PrincipalKind.ADMIN || principal.tenantId != command.tenantId) {
            throw AuthenticationFailure.Rejected(AuthErrorCode.FORBIDDEN)
        }
        if (command.withdrawalReference.isBlank() || command.withdrawalReference.length > 128 ||
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
            !policy.isPermitted(principal, AdminPermission.MANAGE_SUPPORT)) {
            throw AuthenticationFailure.Rejected(AuthErrorCode.FORBIDDEN)
        }
        val current = store.findItem(command.tenantId, command.withdrawalReference)
            ?: throw AuthenticationFailure.Rejected(AuthErrorCode.FORBIDDEN)
        val next = transition(current, command, principal.id, now)
        val resultId = UUID.randomUUID()
        val result = WithdrawalReviewResult(resultId, next, now, "withdrawal-review:$resultId")
        val audit = AuditEvent(UUID.randomUUID(), resultId, command.tenantId, "WITHDRAWAL_REVIEW_${command.action.name}", now, command.correlationId, command.causationId)
        val outbox = OutboxEvent(UUID.randomUUID(), resultId, command.tenantId, "WITHDRAWAL_REVIEW_${command.action.name}", now)
        store.save(result, command.tenantId, command.reason, command.secondApproverId, fingerprint, command.idempotencyKey, audit, outbox)
        return result
    }

    private fun transition(item: WithdrawalQueueItem, command: WithdrawalReviewCommand, principalId: String, now: Instant): WithdrawalQueueItem {
        if (item.serverVersion != command.expectedVersion) throw AuthenticationFailure.Rejected(AuthErrorCode.STALE)
        return when (command.action) {
            WithdrawalReviewAction.CLAIM -> {
                if (item.state != WithdrawalReviewState.QUEUED &&
                    !(item.state == WithdrawalReviewState.CLAIMED && item.claimExpiresAt?.isBefore(now) == true)) {
                    throw AuthenticationFailure.Rejected(AuthErrorCode.CONFLICT)
                }
                item.copy(state = WithdrawalReviewState.CLAIMED, claimedBy = principalId, claimExpiresAt = now.plus(claimLease), serverVersion = item.serverVersion + 1)
            }
            WithdrawalReviewAction.RELEASE -> {
                if (item.state != WithdrawalReviewState.CLAIMED || item.claimedBy != principalId) throw AuthenticationFailure.Rejected(AuthErrorCode.FORBIDDEN)
                item.copy(state = WithdrawalReviewState.QUEUED, claimedBy = null, claimExpiresAt = null, serverVersion = item.serverVersion + 1)
            }
            WithdrawalReviewAction.APPROVE, WithdrawalReviewAction.REJECT -> {
                if (item.state != WithdrawalReviewState.CLAIMED || item.claimedBy != principalId) throw AuthenticationFailure.Rejected(AuthErrorCode.FORBIDDEN)
                if (dualApprovalRequired && (command.secondApproverId.isNullOrBlank() || command.secondApproverId == principalId)) {
                    throw AuthenticationFailure.Rejected(AuthErrorCode.FORBIDDEN)
                }
                item.copy(
                    state = if (command.action == WithdrawalReviewAction.APPROVE) WithdrawalReviewState.APPROVED else WithdrawalReviewState.REJECTED,
                    claimExpiresAt = null,
                    serverVersion = item.serverVersion + 1,
                )
            }
        }
    }

    private fun fingerprint(command: WithdrawalReviewCommand) = listOf(
        command.tenantId, command.withdrawalReference, command.action, command.reason, command.expectedVersion, command.secondApproverId,
    ).joinToString("|") { sha256(it.toString()) }

    private fun sha256(value: String): String = MessageDigest.getInstance("SHA-256")
        .digest(value.toByteArray(Charsets.UTF_8))
        .joinToString("") { "%02x".format(it) }
}
