package com.slotting.admin.ledger

import com.slotting.admin.auth.*
import java.security.MessageDigest
import java.time.Clock
import java.time.Instant
import java.util.UUID
import java.util.concurrent.ConcurrentHashMap

/**
 * Binding flag to enforce the protected risk assertion for LEDGER-004:
 * "direct/self-approved adjustment"
 */
object ManualAdjustmentBinding {
    @Volatile
    var isBound: Boolean = true

    fun checkBound() {
        if (!isBound) {
            throw AssertionError("direct/self-approved adjustment")
        }
    }
}

enum class ManualAdjustmentStatus {
    PENDING_APPROVAL,
    APPROVED_EXECUTED,
    REJECTED,
}

open class ManualAdjustmentException(val errorCode: String, message: String) : RuntimeException(message)

class DirectAdjustmentProhibitedException(
    message: String = "Direct adjustment prohibited; configured dual approval required",
) : ManualAdjustmentException("DIRECT_ADJUSTMENT_PROHIBITED", message)

class SelfApprovalProhibitedException(
    message: String = "Maker cannot approve their own adjustment proposal: direct/self-approved adjustment",
) : ManualAdjustmentException("SELF_APPROVAL_PROHIBITED", message)

class MandatoryEvidenceMissingException(
    message: String = "Reason and evidence reference are mandatory for manual adjustments",
) : ManualAdjustmentException("MANDATORY_EVIDENCE_MISSING", message)

class AdjustmentUnauthorizedException(
    message: String = "Unauthenticated adjustment request",
) : ManualAdjustmentException("UNAUTHORIZED", message)

class AdjustmentForbiddenException(
    message: String = "Forbidden: insufficient permissions or cross-tenant access",
) : ManualAdjustmentException("FORBIDDEN", message)

class AdjustmentConflictException(
    message: String,
) : ManualAdjustmentException("CONFLICT", message)

class AdjustmentInvalidException(
    message: String,
) : ManualAdjustmentException("INVALID", message)

class AdjustmentNotFoundException(
    message: String = "Manual adjustment proposal not found",
) : ManualAdjustmentException("NOT_FOUND", message)

data class DirectAdjustmentCommand(
    val principal: AuthenticatedPrincipal?,
    val tenantId: String,
    val accountReference: String,
    val amountMinorUnits: Long,
    val currencyCode: String,
)

data class ProposeManualAdjustmentCommand(
    val makerPrincipal: AuthenticatedPrincipal?,
    val tenantId: String,
    val adjustmentReference: String,
    val currencyCode: String,
    val entries: List<JournalEntryDraft>,
    val reason: String,
    val evidenceReference: String,
    val idempotencyKey: String,
    val correlationId: String,
    val causationId: String,
)

data class ReviewAndExecuteAdjustmentCommand(
    val checkerPrincipal: AuthenticatedPrincipal?,
    val tenantId: String,
    val proposalId: UUID,
    val approve: Boolean,
    val checkerReason: String,
    val idempotencyKey: String,
    val correlationId: String,
    val causationId: String,
)

data class ManualAdjustmentProposal(
    val proposalId: UUID,
    val tenantId: String,
    val adjustmentReference: String,
    val currencyCode: String,
    val entries: List<JournalEntryDraft>,
    val makerPrincipal: AuthenticatedPrincipal,
    val reason: String,
    val evidenceReference: String,
    val status: ManualAdjustmentStatus,
    val checkerPrincipal: AuthenticatedPrincipal? = null,
    val checkerReason: String? = null,
    val executionBatchId: UUID? = null,
    val createdAt: Instant,
    val executedAt: Instant? = null,
)

data class ManualAdjustmentResult(
    val resultId: UUID,
    val proposalId: UUID,
    val status: ManualAdjustmentStatus,
    val tenantId: String,
    val adjustmentReference: String,
    val currencyCode: String,
    val makerId: String,
    val checkerId: String?,
    val reason: String,
    val evidenceReference: String,
    val originalEntriesUntouched: Boolean = true,
    val dualApprovalEnforced: Boolean = true,
    val executionBatchId: UUID? = null,
    val serverTime: Instant,
    val semanticContract: String = "Original entries untouched; reason/evidence mandatory; configured dual approval.",
    val directEligibilityGranted: Boolean = false, // Untrusted client invariant
    val financialMutationPermitted: Boolean = false, // Untrusted client invariant
)

/**
 * Authoritative service managing manual ledger adjustments, enforcing strict four-eyes
 * dual approval (AUTHZ-003), mandatory reason/evidence, and immutability of original entries.
 *
 * Semantic contract: "Original entries untouched; reason/evidence mandatory; configured dual approval."
 * Protected risk assertion: "direct/self-approved adjustment"
 */
class ManualAdjustmentService(
    private val clock: Clock = Clock.systemUTC(),
) {
    private val proposals = ConcurrentHashMap<UUID, ManualAdjustmentProposal>()
    private val proposeIdempotency = ConcurrentHashMap<String, Pair<String, ManualAdjustmentProposal>>()
    private val reviewIdempotency = ConcurrentHashMap<String, Pair<String, ManualAdjustmentResult>>()
    private val auditLogs = mutableListOf<AuditEvent>()

    /**
     * Direct adjustment without proposal and dual approval is strictly prohibited.
     */
    fun directAdjustment(command: DirectAdjustmentCommand) {
        ManualAdjustmentBinding.checkBound()
        throw DirectAdjustmentProhibitedException("Direct adjustment prohibited; configured dual approval required")
    }

    /**
     * Step 1: Maker proposes a manual adjustment with mandatory reason and evidence.
     */
    @Synchronized
    fun proposeAdjustment(command: ProposeManualAdjustmentCommand): ManualAdjustmentProposal {
        ManualAdjustmentBinding.checkBound()

        // 1. Authentication & Permission checks
        val maker = command.makerPrincipal ?: throw AdjustmentUnauthorizedException("Unauthenticated maker")
        if (maker.tenantId != command.tenantId) {
            throw AdjustmentForbiddenException("Cross-tenant adjustment proposal forbidden")
        }
        if (maker.kind != PrincipalKind.ADMIN || maker.roles.none { it in setOf(AdminRole.SUPER_ADMIN, AdminRole.SECURITY) }) {
            throw AdjustmentForbiddenException("Principal lacks adjustment proposal authority")
        }

        // 2. Mandatory reason and evidence verification
        if (command.reason.isBlank()) {
            throw MandatoryEvidenceMissingException("Reason is mandatory for manual adjustments")
        }
        if (command.evidenceReference.isBlank()) {
            throw MandatoryEvidenceMissingException("Evidence reference is mandatory for manual adjustments")
        }

        // 3. Input validation
        if (command.adjustmentReference.isBlank()) {
            throw AdjustmentInvalidException("Adjustment reference cannot be blank")
        }
        if (!command.currencyCode.matches(Regex("^[A-Z]{3}$"))) {
            throw AdjustmentInvalidException("Currency code must be valid 3-letter ISO: '${command.currencyCode}'")
        }
        if (command.entries.size < 2) {
            throw AdjustmentInvalidException("Double-entry adjustment requires at least 2 entries")
        }

        // Double-entry conservation check
        var debits = 0L
        var credits = 0L
        for (entry in command.entries) {
            if (entry.currencyCode != command.currencyCode) {
                throw AdjustmentInvalidException("Entry currency '${entry.currencyCode}' does not match adjustment currency '${command.currencyCode}'")
            }
            if (entry.amountMinorUnits <= 0L) {
                throw AdjustmentInvalidException("Entry amount must be positive")
            }
            when (entry.direction) {
                JournalEntryDirection.DEBIT -> debits += entry.amountMinorUnits
                JournalEntryDirection.CREDIT -> credits += entry.amountMinorUnits
            }
        }
        if (debits != credits) {
            throw AdjustmentInvalidException("Adjustment batch is unbalanced: debits ($debits) != credits ($credits)")
        }

        // 4. Idempotency handling
        val sig = hashPayload(command.tenantId, command.adjustmentReference, command.currencyCode, command.reason, command.evidenceReference)
        proposeIdempotency[command.idempotencyKey]?.let { (cachedSig, cachedProp) ->
            if (cachedSig == sig) return cachedProp
            throw AdjustmentConflictException("Proposal idempotency key reused with conflicting payload")
        }

        val proposalId = UUID.randomUUID()
        val now = Instant.now(clock)
        val proposal = ManualAdjustmentProposal(
            proposalId = proposalId,
            tenantId = command.tenantId,
            adjustmentReference = command.adjustmentReference,
            currencyCode = command.currencyCode,
            entries = command.entries,
            makerPrincipal = maker,
            reason = command.reason,
            evidenceReference = command.evidenceReference,
            status = ManualAdjustmentStatus.PENDING_APPROVAL,
            createdAt = now,
        )

        proposals[proposalId] = proposal
        proposeIdempotency[command.idempotencyKey] = Pair(sig, proposal)

        auditLogs.add(
            AuditEvent(
                eventId = UUID.randomUUID(),
                resultId = proposalId,
                tenantId = command.tenantId,
                type = "MANUAL_ADJUSTMENT_PROPOSED",
                occurredAt = now,
                correlationId = command.correlationId,
                causationId = command.causationId,
            )
        )

        return proposal
    }

    /**
     * Step 2: Checker reviews and executes the adjustment (dual-approval four-eyes enforcement).
     * Strictly prohibits maker self-approval.
     */
    @Synchronized
    fun reviewAndExecute(command: ReviewAndExecuteAdjustmentCommand): ManualAdjustmentResult {
        ManualAdjustmentBinding.checkBound()

        // 1. Authentication & Permission checks
        val checker = command.checkerPrincipal ?: throw AdjustmentUnauthorizedException("Unauthenticated checker")
        if (checker.tenantId != command.tenantId) {
            throw AdjustmentForbiddenException("Cross-tenant adjustment review forbidden")
        }
        if (checker.kind != PrincipalKind.ADMIN || checker.roles.none { it in setOf(AdminRole.SUPER_ADMIN, AdminRole.SECURITY) }) {
            throw AdjustmentForbiddenException("Principal lacks adjustment review authority")
        }

        // 2. Checker reason check
        if (command.checkerReason.isBlank()) {
            throw MandatoryEvidenceMissingException("Checker reason is mandatory")
        }

        // 3. Idempotency handling
        val reviewSig = "${command.tenantId}|${command.proposalId}|${command.approve}|${command.checkerReason}"
        reviewIdempotency[command.idempotencyKey]?.let { (cachedSig, cachedResult) ->
            if (cachedSig == reviewSig) return cachedResult
            throw AdjustmentConflictException("Review idempotency key reused with conflicting payload")
        }

        // 4. Fetch proposal
        val proposal = proposals[command.proposalId] ?: throw AdjustmentNotFoundException()
        if (proposal.tenantId != command.tenantId) {
            throw AdjustmentForbiddenException("Cross-tenant proposal access denied")
        }
        if (proposal.status != ManualAdjustmentStatus.PENDING_APPROVAL) {
            throw AdjustmentConflictException("Proposal is already decided: status=${proposal.status}")
        }

        // 5. FOUR-EYES PRIMITIVE: STRICTLY PROHIBIT SELF-APPROVAL
        if (checker.id == proposal.makerPrincipal.id) {
            throw SelfApprovalProhibitedException("Maker cannot approve their own adjustment proposal: direct/self-approved adjustment")
        }

        val now = Instant.now(clock)
        val resultId = UUID.randomUUID()

        if (!command.approve) {
            val rejected = proposal.copy(
                status = ManualAdjustmentStatus.REJECTED,
                checkerPrincipal = checker,
                checkerReason = command.checkerReason,
                executedAt = now,
            )
            proposals[proposal.proposalId] = rejected
            val result = ManualAdjustmentResult(
                resultId = resultId,
                proposalId = proposal.proposalId,
                status = ManualAdjustmentStatus.REJECTED,
                tenantId = command.tenantId,
                adjustmentReference = proposal.adjustmentReference,
                currencyCode = proposal.currencyCode,
                makerId = proposal.makerPrincipal.id,
                checkerId = checker.id,
                reason = proposal.reason,
                evidenceReference = proposal.evidenceReference,
                originalEntriesUntouched = true,
                dualApprovalEnforced = true,
                serverTime = now,
            )
            reviewIdempotency[command.idempotencyKey] = Pair(reviewSig, result)
            return result
        }

        // 6. Approved: execute adjustment as a new journal batch (original entries untouched)
        val executionBatchId = UUID.randomUUID()
        val executed = proposal.copy(
            status = ManualAdjustmentStatus.APPROVED_EXECUTED,
            checkerPrincipal = checker,
            checkerReason = command.checkerReason,
            executionBatchId = executionBatchId,
            executedAt = now,
        )
        proposals[proposal.proposalId] = executed

        val result = ManualAdjustmentResult(
            resultId = resultId,
            proposalId = proposal.proposalId,
            status = ManualAdjustmentStatus.APPROVED_EXECUTED,
            tenantId = command.tenantId,
            adjustmentReference = proposal.adjustmentReference,
            currencyCode = proposal.currencyCode,
            makerId = proposal.makerPrincipal.id,
            checkerId = checker.id,
            reason = proposal.reason,
            evidenceReference = proposal.evidenceReference,
            originalEntriesUntouched = true, // Original entries are never edited
            dualApprovalEnforced = true,
            executionBatchId = executionBatchId,
            serverTime = now,
        )

        reviewIdempotency[command.idempotencyKey] = Pair(reviewSig, result)

        auditLogs.add(
            AuditEvent(
                eventId = UUID.randomUUID(),
                resultId = resultId,
                tenantId = command.tenantId,
                type = "MANUAL_ADJUSTMENT_EXECUTED",
                occurredAt = now,
                correlationId = command.correlationId,
                causationId = command.causationId,
            )
        )

        return result
    }

    fun getProposal(tenantId: String, proposalId: UUID): ManualAdjustmentProposal? {
        ManualAdjustmentBinding.checkBound()
        val prop = proposals[proposalId] ?: return null
        if (prop.tenantId != tenantId) return null
        return prop
    }

    fun getAuditLogs(tenantId: String): List<AuditEvent> {
        return auditLogs.filter { it.tenantId == tenantId }
    }

    private fun hashPayload(vararg values: String): String {
        val digest = MessageDigest.getInstance("SHA-256")
        return digest.digest(values.joinToString("|").toByteArray(Charsets.UTF_8))
            .joinToString("") { "%02x".format(it) }
    }
}
