package com.slotting.admin.kyc

import com.slotting.admin.auth.*
import java.security.MessageDigest
import java.time.Clock
import java.time.Duration
import java.time.Instant
import java.util.UUID

enum class KycReviewState { QUEUED, CLAIMED, APPROVED, REJECTED }
enum class KycReviewAction { CLAIM, RELEASE, APPROVE, REJECT }
enum class KycReviewReason { REVIEW_REQUIRED, IDENTITY_REVIEW, DOCUMENT_REVIEW, RISK_REVIEW }

data class KycReviewCommand(
    val principal: AuthenticatedPrincipal?, val sessionId: String, val tenantId: String,
    val caseReference: String, val action: KycReviewAction, val reason: KycReviewReason,
    val idempotencyKey: String, val correlationId: String, val causationId: String,
    val expectedVersion: Long, val secondApproverId: String? = null,
)
data class KycQueueItem(val caseReference: String, val state: KycReviewState, val claimedBy: String?, val claimExpiresAt: Instant?, val serverVersion: Long)
data class KycReviewResult(val resultId: UUID, val item: KycQueueItem, val serverTime: Instant, val evidenceReference: String)

interface KycQueueStore {
    fun findByIdempotency(tenantId: String, key: String): Pair<String, KycReviewResult>?
    fun findItem(tenantId: String, caseReference: String): KycQueueItem?
    fun save(result: KycReviewResult, tenantId: String, reason: KycReviewReason, secondApproverId: String?, queryFingerprint: String, idempotencyKey: String, audit: AuditEvent, outbox: OutboxEvent)
}

class KycReviewQueue(
    private val policy: AdminRbacPolicy, private val sessions: AdminSessionDirectory, private val store: KycQueueStore,
    private val clock: Clock = Clock.systemUTC(), private val claimLease: Duration = Duration.ofMinutes(15), private val dualApprovalRequired: Boolean = true,
) {
    @Synchronized
    fun operate(command: KycReviewCommand): KycReviewResult {
        val principal = command.principal ?: throw AuthenticationFailure.Rejected(AuthErrorCode.UNAUTHENTICATED)
        val fingerprint = fingerprint(command)
        store.findByIdempotency(command.tenantId, command.idempotencyKey)?.let { replay ->
            if (replay.first != fingerprint) throw AuthenticationFailure.Rejected(AuthErrorCode.CONFLICT)
            return replay.second
        }
        if (principal.kind != PrincipalKind.ADMIN || principal.tenantId != command.tenantId) throw AuthenticationFailure.Rejected(AuthErrorCode.FORBIDDEN)
        if (command.caseReference.isBlank() || command.caseReference.length > 128 || command.sessionId.isBlank() || command.correlationId.isBlank() || command.causationId.isBlank()) throw AuthenticationFailure.Rejected(AuthErrorCode.INVALID)
        val now = Instant.now(clock)
        val session = try { sessions.find(command.tenantId, principal.id, command.sessionId) } catch (_: Exception) { throw AuthenticationFailure.Rejected(AuthErrorCode.DEPENDENCY_UNAVAILABLE) }
        if (session == null || !session.active || !session.expiresAt.isAfter(now) || !policy.isPermitted(principal, AdminPermission.MANAGE_SECURITY)) throw AuthenticationFailure.Rejected(AuthErrorCode.FORBIDDEN)
        val current = store.findItem(command.tenantId, command.caseReference) ?: throw AuthenticationFailure.Rejected(AuthErrorCode.FORBIDDEN)
        val next = transition(current, command, principal.id, now)
        val resultId = UUID.randomUUID()
        val result = KycReviewResult(resultId, next, now, "kyc-review:$resultId")
        val type = "KYC_REVIEW_${command.action.name}"
        val audit = AuditEvent(UUID.randomUUID(), resultId, command.tenantId, type, now, command.correlationId, command.causationId)
        val outbox = OutboxEvent(UUID.randomUUID(), resultId, command.tenantId, type, now)
        store.save(result, command.tenantId, command.reason, command.secondApproverId, fingerprint, command.idempotencyKey, audit, outbox)
        return result
    }

    private fun transition(item: KycQueueItem, command: KycReviewCommand, principalId: String, now: Instant): KycQueueItem {
        if (item.serverVersion != command.expectedVersion) throw AuthenticationFailure.Rejected(AuthErrorCode.STALE)
        return when (command.action) {
            KycReviewAction.CLAIM -> if (item.state == KycReviewState.QUEUED || (item.state == KycReviewState.CLAIMED && item.claimExpiresAt?.isBefore(now) == true)) item.copy(state = KycReviewState.CLAIMED, claimedBy = principalId, claimExpiresAt = now.plus(claimLease), serverVersion = item.serverVersion + 1) else throw AuthenticationFailure.Rejected(AuthErrorCode.CONFLICT)
            KycReviewAction.RELEASE -> if (item.state == KycReviewState.CLAIMED && item.claimedBy == principalId) item.copy(state = KycReviewState.QUEUED, claimedBy = null, claimExpiresAt = null, serverVersion = item.serverVersion + 1) else throw AuthenticationFailure.Rejected(AuthErrorCode.FORBIDDEN)
            KycReviewAction.APPROVE, KycReviewAction.REJECT -> {
                if (item.state != KycReviewState.CLAIMED || item.claimedBy != principalId) throw AuthenticationFailure.Rejected(AuthErrorCode.FORBIDDEN)
                if (dualApprovalRequired && (command.secondApproverId.isNullOrBlank() || command.secondApproverId == principalId)) throw AuthenticationFailure.Rejected(AuthErrorCode.FORBIDDEN)
                item.copy(state = if (command.action == KycReviewAction.APPROVE) KycReviewState.APPROVED else KycReviewState.REJECTED, claimedBy = null, claimExpiresAt = null, serverVersion = item.serverVersion + 1)
            }
        }
    }

    private fun fingerprint(command: KycReviewCommand) = listOf(command.tenantId, command.caseReference, command.action, command.reason, command.expectedVersion, command.secondApproverId).joinToString("|") { sha256(it.toString()) }
    private fun sha256(value: String) = MessageDigest.getInstance("SHA-256").digest(value.toByteArray()).joinToString("") { "%02x".format(it) }
}
