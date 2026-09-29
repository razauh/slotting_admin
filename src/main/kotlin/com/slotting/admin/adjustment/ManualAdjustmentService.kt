package com.slotting.admin.adjustment

import com.slotting.admin.auth.*
import java.security.MessageDigest
import java.time.Clock
import java.time.Instant
import java.util.UUID

enum class AdjustmentLegDirection { DEBIT, CREDIT }

data class AdjustmentLeg(
    val accountReference: String,
    val amountMinorUnits: Long,
    val direction: AdjustmentLegDirection,
)

enum class ManualAdjustmentState { DRAFT, PREVIEWED, PENDING_APPROVAL, APPROVED, REJECTED }
enum class ManualAdjustmentAction { PREVIEW, PROPOSE, APPROVE, REJECT }
enum class ManualAdjustmentReason { GOODWILL_CREDIT, DISPUTE_RESOLUTION, SYSTEM_ERROR_CORRECTION, PROMOTION_ADJUSTMENT, REGULATORY_SETTLEMENT }

data class ManualAdjustmentCommand(
    val principal: AuthenticatedPrincipal?,
    val sessionId: String,
    val tenantId: String,
    val adjustmentReference: String,
    val action: ManualAdjustmentAction,
    val reason: ManualAdjustmentReason,
    val evidenceReference: String,
    val currencyCode: String,
    val legs: List<AdjustmentLeg>,
    val idempotencyKey: String,
    val correlationId: String,
    val causationId: String,
    val expectedVersion: Long,
    val secondApproverId: String? = null,
)

data class ManualAdjustmentBatch(
    val adjustmentReference: String,
    val state: ManualAdjustmentState,
    val currencyCode: String,
    val legs: List<AdjustmentLeg>,
    val totalDebitsMinorUnits: Long,
    val totalCreditsMinorUnits: Long,
    val makerId: String,
    val secondApproverId: String?,
    val serverVersion: Long,
    val postingReference: String?,
)

data class ManualAdjustmentResult(
    val resultId: UUID,
    val item: ManualAdjustmentBatch,
    val isBalanced: Boolean,
    val totalDebits: Long,
    val totalCredits: Long,
    val receiptReference: String,
    val serverTime: Instant,
    val evidenceReference: String,
)

interface ManualAdjustmentStore {
    fun findByIdempotency(tenantId: String, key: String): Pair<String, ManualAdjustmentResult>?
    fun findItem(tenantId: String, adjustmentReference: String): ManualAdjustmentBatch?
    fun save(
        result: ManualAdjustmentResult,
        tenantId: String,
        reason: ManualAdjustmentReason,
        evidenceReference: String,
        queryFingerprint: String,
        idempotencyKey: String,
        audit: AuditEvent,
        outbox: OutboxEvent,
    )
}

class ManualAdjustmentService(
    private val policy: AdminRbacPolicy,
    private val sessions: AdminSessionDirectory,
    private val store: ManualAdjustmentStore,
    private val clock: Clock = Clock.systemUTC(),
    private val dualApprovalRequired: Boolean = true,
) {
    @Synchronized
    fun operate(command: ManualAdjustmentCommand): ManualAdjustmentResult {
        // 1. Authorize principal and context BEFORE checking idempotency store or disclosing cached state
        val principal = command.principal ?: throw AuthenticationFailure.Rejected(AuthErrorCode.UNAUTHENTICATED)
        if (principal.kind != PrincipalKind.ADMIN || principal.tenantId != command.tenantId) {
            throw AuthenticationFailure.Rejected(AuthErrorCode.FORBIDDEN)
        }
        if (command.adjustmentReference.isBlank() || command.adjustmentReference.length > 128 ||
            command.evidenceReference.isBlank() || command.evidenceReference.length > 128 ||
            command.sessionId.isBlank() || command.correlationId.isBlank() || command.causationId.isBlank() ||
            !command.currencyCode.matches(Regex("[A-Z]{3}"))) {
            throw AuthenticationFailure.Rejected(AuthErrorCode.INVALID)
        }
        if (command.legs.isEmpty() || command.legs.any { it.amountMinorUnits <= 0 || it.accountReference.isBlank() }) {
            throw AuthenticationFailure.Rejected(AuthErrorCode.INVALID)
        }

        var debits = 0L
        var credits = 0L
        try {
            for (leg in command.legs) {
                when (leg.direction) {
                    AdjustmentLegDirection.DEBIT -> debits = Math.addExact(debits, leg.amountMinorUnits)
                    AdjustmentLegDirection.CREDIT -> credits = Math.addExact(credits, leg.amountMinorUnits)
                }
            }
        } catch (_: ArithmeticException) {
            throw AuthenticationFailure.Rejected(AuthErrorCode.INVALID)
        }
        if (debits != credits || debits <= 0) {
            throw AuthenticationFailure.Rejected(AuthErrorCode.INVALID)
        }

        val now = Instant.now(clock)
        val session = try {
            sessions.find(command.tenantId, principal.id, command.sessionId)
        } catch (_: Exception) {
            throw AuthenticationFailure.Rejected(AuthErrorCode.DEPENDENCY_UNAVAILABLE)
        }
        if (session == null || !session.active || !session.expiresAt.isAfter(now) ||
            !session.mfaVerified || (session.mfaExpiresAt != null && !session.mfaExpiresAt.isAfter(now)) ||
            (!policy.isPermitted(principal, AdminPermission.MANAGE_SUPPORT) &&
             !policy.isPermitted(principal, AdminPermission.MANAGE_SECURITY))) {
            throw AuthenticationFailure.Rejected(AuthErrorCode.FORBIDDEN)
        }

        // 2. Verified caller: now check idempotency cache
        val fingerprint = fingerprint(command)
        store.findByIdempotency(command.tenantId, command.idempotencyKey)?.let { replay ->
            if (replay.first != fingerprint) throw AuthenticationFailure.Rejected(AuthErrorCode.CONFLICT)
            return replay.second
        }

        val resultId = UUID.randomUUID()
        val (nextBatch, receipt) = when (command.action) {
            ManualAdjustmentAction.PREVIEW -> {
                val batch = ManualAdjustmentBatch(
                    adjustmentReference = command.adjustmentReference,
                    state = ManualAdjustmentState.PREVIEWED,
                    currencyCode = command.currencyCode,
                    legs = command.legs,
                    totalDebitsMinorUnits = debits,
                    totalCreditsMinorUnits = credits,
                    makerId = principal.id,
                    secondApproverId = null,
                    serverVersion = 0L,
                    postingReference = null,
                )
                batch to "preview:$resultId"
            }
            ManualAdjustmentAction.PROPOSE -> {
                val existing = store.findItem(command.tenantId, command.adjustmentReference)
                if (existing != null && existing.state != ManualAdjustmentState.PREVIEWED) {
                    throw AuthenticationFailure.Rejected(AuthErrorCode.CONFLICT)
                }
                val batch = ManualAdjustmentBatch(
                    adjustmentReference = command.adjustmentReference,
                    state = ManualAdjustmentState.PENDING_APPROVAL,
                    currencyCode = command.currencyCode,
                    legs = command.legs,
                    totalDebitsMinorUnits = debits,
                    totalCreditsMinorUnits = credits,
                    makerId = principal.id,
                    secondApproverId = null,
                    serverVersion = 1L,
                    postingReference = null,
                )
                batch to "propose:$resultId"
            }
            ManualAdjustmentAction.APPROVE -> {
                val current = store.findItem(command.tenantId, command.adjustmentReference)
                    ?: throw AuthenticationFailure.Rejected(AuthErrorCode.FORBIDDEN)
                if (current.serverVersion != command.expectedVersion) throw AuthenticationFailure.Rejected(AuthErrorCode.STALE)
                if (current.state != ManualAdjustmentState.PENDING_APPROVAL) throw AuthenticationFailure.Rejected(AuthErrorCode.FORBIDDEN)
                if (principal.id == current.makerId) throw AuthenticationFailure.Rejected(AuthErrorCode.FORBIDDEN)
                if (dualApprovalRequired) {
                    if (command.secondApproverId.isNullOrBlank() ||
                        command.secondApproverId == current.makerId) {
                        throw AuthenticationFailure.Rejected(AuthErrorCode.FORBIDDEN)
                    }
                }
                val postingRef = "posting:$resultId"
                val batch = current.copy(
                    state = ManualAdjustmentState.APPROVED,
                    secondApproverId = command.secondApproverId,
                    serverVersion = current.serverVersion + 1,
                    postingReference = postingRef,
                )
                batch to "receipt:$resultId"
            }
            ManualAdjustmentAction.REJECT -> {
                val current = store.findItem(command.tenantId, command.adjustmentReference)
                    ?: throw AuthenticationFailure.Rejected(AuthErrorCode.FORBIDDEN)
                if (current.serverVersion != command.expectedVersion) throw AuthenticationFailure.Rejected(AuthErrorCode.STALE)
                if (current.state != ManualAdjustmentState.PENDING_APPROVAL) throw AuthenticationFailure.Rejected(AuthErrorCode.FORBIDDEN)
                if (principal.id == current.makerId) throw AuthenticationFailure.Rejected(AuthErrorCode.FORBIDDEN)
                val batch = current.copy(
                    state = ManualAdjustmentState.REJECTED,
                    secondApproverId = command.secondApproverId,
                    serverVersion = current.serverVersion + 1,
                )
                batch to "reject:$resultId"
            }
        }

        val result = ManualAdjustmentResult(
            resultId = resultId,
            item = nextBatch,
            isBalanced = true,
            totalDebits = debits,
            totalCredits = credits,
            receiptReference = receipt,
            serverTime = now,
            evidenceReference = command.evidenceReference,
        )

        val type = "ADJUSTMENT_${command.action.name}"
        val audit = AuditEvent(UUID.randomUUID(), resultId, command.tenantId, type, now, command.correlationId, command.causationId)
        val outbox = OutboxEvent(UUID.randomUUID(), resultId, command.tenantId, type, now)
        store.save(result, command.tenantId, command.reason, command.evidenceReference, fingerprint, command.idempotencyKey, audit, outbox)
        return result
    }

    private fun fingerprint(command: ManualAdjustmentCommand): String {
        val canonical = listOf(
            command.tenantId,
            command.adjustmentReference,
            command.action.name,
            command.reason.name,
            command.currencyCode,
            command.legs.joinToString(",") { "${it.accountReference}:${it.amountMinorUnits}:${it.direction.name}" },
            command.expectedVersion.toString(),
            command.secondApproverId ?: "",
            command.evidenceReference,
        ).joinToString("|")
        return sha256(canonical)
    }

    private fun sha256(value: String) = MessageDigest.getInstance("SHA-256")
        .digest(value.toByteArray(Charsets.UTF_8))
        .joinToString("") { "%02x".format(it) }
}
