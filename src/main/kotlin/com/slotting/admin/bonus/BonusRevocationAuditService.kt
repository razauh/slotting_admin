package com.slotting.admin.bonus

import com.slotting.admin.auth.AdminRole
import com.slotting.admin.auth.AuditEvent
import com.slotting.admin.auth.AuthErrorCode
import com.slotting.admin.auth.AuthenticationFailure
import com.slotting.admin.auth.AuthenticatedPrincipal
import com.slotting.admin.auth.OutboxEvent
import com.slotting.admin.auth.PrincipalKind
import java.time.Clock
import java.time.Instant
import java.util.UUID
import java.util.concurrent.ConcurrentHashMap

/**
 * Gate to enforce BONUS-003-02: Audit bonus revocation.
 * Semantic contract: "High-value threshold decision gate; never direct projection edit."
 * Protected risk: "self/unreasoned grant"
 */
object BonusRevocationAuditBinding {
    var isBound: Boolean = true

    fun checkBound() {
        if (!isBound) {
            throw AssertionError("self/unreasoned grant")
        }
    }
}

enum class BonusRevocationProposalStatus {
    PENDING_APPROVAL,
    APPROVED,
    REJECTED,
    CANCELLED
}

data class BonusRevocationProposal(
    val proposalId: UUID,
    val tenantId: String,
    val grantId: UUID,
    val playerId: UUID,
    val currencyCode: String,
    val revocationAmountMinorUnits: Long,
    val makerPrincipalId: String,
    val makerReason: String,
    var status: BonusRevocationProposalStatus,
    var checkerPrincipalId: String? = null,
    var checkerReason: String? = null,
    var revocationId: UUID? = null,
    val createdAt: Instant,
    val expiresAt: Instant,
    var decidedAt: Instant? = null,
    var version: Long = 1L
)

data class BonusRevocationAuditRecord(
    val revocationId: UUID,
    val tenantId: String,
    val grantId: UUID,
    val playerId: UUID,
    val currencyCode: String,
    val revokedAmountMinorUnits: Long,
    val makerPrincipalId: String,
    val checkerPrincipalId: String?,
    val revocationReason: String,
    val isHighValue: Boolean,
    val proposalId: UUID?,
    val timestamp: Instant,
    val serverVersion: Long,
    val evidenceReference: String,
    val remainingCashMinorUnits: Long,
    val remainingBonusMinorUnits: Long
)

data class RevokeBonusCommand(
    val principal: AuthenticatedPrincipal?,
    val tenantId: String,
    val grantId: UUID,
    val playerId: UUID,
    val currencyCode: String,
    val revocationReason: String,
    val idempotencyKey: String,
    val correlationId: String,
    val causationId: String,
    val expectedVersion: Long
)

data class RevokeBonusResult(
    val resultId: UUID,
    val tenantId: String,
    val grantId: UUID,
    val playerId: UUID,
    val revokedAmountMinorUnits: Long,
    val requiresApproval: Boolean,
    val proposalId: UUID?,
    val revocationId: UUID?,
    val serverTime: Instant,
    val serverVersion: Long,
    val evidenceReference: String,
    val auditRecord: BonusRevocationAuditRecord?,
    val auditEvent: AuditEvent,
    val outboxEvent: OutboxEvent
)

data class ApproveRevocationProposalCommand(
    val checkerPrincipal: AuthenticatedPrincipal?,
    val tenantId: String,
    val proposalId: UUID,
    val checkerReason: String,
    val idempotencyKey: String,
    val correlationId: String,
    val causationId: String,
    val expectedWalletVersion: Long
)

data class ApproveRevocationProposalResult(
    val resultId: UUID,
    val proposalId: UUID,
    val revocationId: UUID,
    val tenantId: String,
    val grantId: UUID,
    val playerId: UUID,
    val revokedAmountMinorUnits: Long,
    val makerId: String,
    val checkerId: String,
    val serverTime: Instant,
    val serverVersion: Long,
    val evidenceReference: String,
    val auditRecord: BonusRevocationAuditRecord,
    val auditEvent: AuditEvent,
    val outboxEvent: OutboxEvent
)

data class RejectRevocationProposalCommand(
    val checkerPrincipal: AuthenticatedPrincipal?,
    val tenantId: String,
    val proposalId: UUID,
    val rejectionReason: String,
    val idempotencyKey: String,
    val correlationId: String,
    val causationId: String
)

data class RejectRevocationProposalResult(
    val resultId: UUID,
    val proposalId: UUID,
    val tenantId: String,
    val status: BonusRevocationProposalStatus,
    val checkerId: String,
    val rejectionReason: String,
    val serverTime: Instant,
    val evidenceReference: String,
    val auditEvent: AuditEvent
)

interface BonusRevocationStore : BonusGrantStore {
    fun saveRevocationProposal(proposal: BonusRevocationProposal)
    fun findRevocationProposal(tenantId: String, proposalId: UUID): BonusRevocationProposal?
    fun findPendingRevocationProposals(tenantId: String): List<BonusRevocationProposal>
    fun saveRevocationAudit(record: BonusRevocationAuditRecord)
    fun findRevocationAudit(tenantId: String, revocationId: UUID): BonusRevocationAuditRecord?
    fun findRevocationAuditsForPlayer(tenantId: String, playerId: UUID): List<BonusRevocationAuditRecord>
    fun findAllRevocationAudits(tenantId: String): List<BonusRevocationAuditRecord>
}

class InMemoryBonusRevocationStore(
    private val delegate: InMemoryBonusGrantStore = InMemoryBonusGrantStore()
) : BonusRevocationStore, BonusGrantStore by delegate {
    val proposals = ConcurrentHashMap<UUID, BonusRevocationProposal>()
    val auditRecords = ConcurrentHashMap<UUID, BonusRevocationAuditRecord>()

    override fun saveRevocationProposal(proposal: BonusRevocationProposal) {
        proposals[proposal.proposalId] = proposal
    }

    override fun findRevocationProposal(tenantId: String, proposalId: UUID): BonusRevocationProposal? {
        val p = proposals[proposalId]
        return if (p?.tenantId == tenantId) p else null
    }

    override fun findPendingRevocationProposals(tenantId: String): List<BonusRevocationProposal> {
        return proposals.values.filter { it.tenantId == tenantId && it.status == BonusRevocationProposalStatus.PENDING_APPROVAL }
    }

    override fun saveRevocationAudit(record: BonusRevocationAuditRecord) {
        auditRecords[record.revocationId] = record
    }

    override fun findRevocationAudit(tenantId: String, revocationId: UUID): BonusRevocationAuditRecord? {
        val r = auditRecords[revocationId]
        return if (r?.tenantId == tenantId) r else null
    }

    override fun findRevocationAuditsForPlayer(tenantId: String, playerId: UUID): List<BonusRevocationAuditRecord> {
        return auditRecords.values.filter { it.tenantId == tenantId && it.playerId == playerId }
    }

    override fun findAllRevocationAudits(tenantId: String): List<BonusRevocationAuditRecord> {
        return auditRecords.values.filter { it.tenantId == tenantId }
    }
}

class BonusRevocationAuditService(
    private val store: BonusRevocationStore,
    private val highValueThresholdMinorUnits: Long = 10_000L, // $100.00
    private val alertSink: BonusAlertSink = InMemoryBonusAlertSink(),
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

    private fun computeFingerprint(command: RevokeBonusCommand): String {
        return listOf(
            command.principal?.tenantId,
            command.principal?.id,
            command.tenantId,
            command.grantId.toString(),
            command.playerId.toString(),
            command.currencyCode,
            command.revocationReason,
            command.expectedVersion
        ).joinToString("|")
    }

    private fun computeFingerprint(command: ApproveRevocationProposalCommand): String {
        return listOf(
            command.checkerPrincipal?.tenantId,
            command.checkerPrincipal?.id,
            command.tenantId,
            command.proposalId.toString(),
            command.checkerReason,
            command.expectedWalletVersion
        ).joinToString("|")
    }

    private fun computeFingerprint(command: RejectRevocationProposalCommand): String {
        return listOf(
            command.checkerPrincipal?.tenantId,
            command.checkerPrincipal?.id,
            command.tenantId,
            command.proposalId.toString(),
            command.rejectionReason
        ).joinToString("|")
    }

    /**
     * Revoke a bonus grant.
     * Enforces:
     * 1. Self-action prevention: Admin cannot act on own player account.
     * 2. Unreasoned action prevention: Structured business reason required (>= 10 chars).
     * 3. High-value threshold decision gate: Revocations > highValueThresholdMinorUnits route to four-eyes proposal queue.
     * 4. Never direct projection edit: Balances updated via atomic double-entry ledger journals.
     * 5. Double-forfeit prevention: Only ACTIVE grants can be revoked.
     */
    fun revokeBonus(command: RevokeBonusCommand): RevokeBonusResult = synchronized(store) {
        BonusRevocationAuditBinding.checkBound()

        validateHeaders(
            tenantId = command.tenantId,
            correlationId = command.correlationId,
            causationId = command.causationId,
            idempotencyKey = command.idempotencyKey,
            expectedVersion = command.expectedVersion
        )

        // Reason validation: Unreasoned revocation is strictly forbidden
        if (command.revocationReason.isBlank() || command.revocationReason.trim().length < 10) {
            alertSink.sendAlert(
                tenantId = command.tenantId,
                alertType = "UNREASONED_BONUS_REVOCATION_REJECTED",
                message = "Revocation rejected: structured business justification is required"
            )
            throw AuthenticationFailure.Rejected(AuthErrorCode.INVALID)
        }

        val fingerprint = computeFingerprint(command)
        store.findByIdempotency(command.tenantId, command.idempotencyKey)?.let { (cachedFp, cachedRes) ->
            if (cachedFp == fingerprint && cachedRes is RevokeBonusResult) {
                return cachedRes
            } else {
                throw AuthenticationFailure.Rejected(AuthErrorCode.CONFLICT)
            }
        }

        val principal = command.principal ?: throw AuthenticationFailure.Rejected(AuthErrorCode.UNAUTHENTICATED)
        if (principal.tenantId != command.tenantId || principal.kind != PrincipalKind.ADMIN) {
            throw AuthenticationFailure.Rejected(AuthErrorCode.FORBIDDEN)
        }

        // SELF-ACTION PREVENTION: Admin cannot revoke on own player account
        if (principal.id == command.playerId.toString()) {
            alertSink.sendAlert(
                tenantId = command.tenantId,
                alertType = "SELF_BONUS_REVOCATION_DENIED",
                message = "Admin ${principal.id} attempted to revoke own bonus account"
            )
            throw AuthenticationFailure.Rejected(AuthErrorCode.FORBIDDEN)
        }

        val grant = store.findGrant(command.tenantId, command.grantId)
            ?: throw AuthenticationFailure.Rejected(AuthErrorCode.INVALID)

        if (grant.playerId != command.playerId || grant.currencyCode != command.currencyCode) {
            throw AuthenticationFailure.Rejected(AuthErrorCode.INVALID)
        }

        // DOUBLE FORFEIT PREVENTION: Grant must be in ACTIVE status
        if (grant.status != BonusGrantStatus.ACTIVE) {
            alertSink.sendAlert(
                tenantId = command.tenantId,
                alertType = "DOUBLE_FORFEIT_OR_REVOCATION_ATTEMPT",
                message = "Grant ${grant.grantId} is already in state ${grant.status}; cannot revoke"
            )
            throw AuthenticationFailure.Rejected(AuthErrorCode.FORBIDDEN)
        }

        val wallet = store.findWallet(command.tenantId, command.playerId, command.currencyCode)
            ?: throw AuthenticationFailure.Rejected(AuthErrorCode.INVALID)

        if (command.expectedVersion != wallet.version) {
            throw AuthenticationFailure.Rejected(AuthErrorCode.STALE)
        }

        val now = clock.instant()
        val resultId = UUID.randomUUID()
        val amountToRevoke = minOf(grant.amountMinorUnits, wallet.bonusMinorUnits)

        // HIGH-VALUE THRESHOLD DECISION GATE:
        // If amountToRevoke > highValueThresholdMinorUnits, route to four-eyes proposal queue!
        if (amountToRevoke > highValueThresholdMinorUnits) {
            val proposalId = UUID.randomUUID()
            val proposal = BonusRevocationProposal(
                proposalId = proposalId,
                tenantId = command.tenantId,
                grantId = command.grantId,
                playerId = command.playerId,
                currencyCode = command.currencyCode,
                revocationAmountMinorUnits = amountToRevoke,
                makerPrincipalId = principal.id,
                makerReason = command.revocationReason,
                status = BonusRevocationProposalStatus.PENDING_APPROVAL,
                createdAt = now,
                expiresAt = now.plusSeconds(86400 * 7),
                version = 1L
            )
            store.saveRevocationProposal(proposal)

            val evidenceReference = "bonus-revocation-proposal:${command.tenantId}:${command.grantId}:$proposalId:pending"

            val auditEvent = AuditEvent(
                eventId = UUID.randomUUID(),
                resultId = resultId,
                tenantId = command.tenantId,
                type = "BONUS_REVOCATION_PROPOSAL_SUBMITTED",
                occurredAt = now,
                correlationId = command.correlationId,
                causationId = command.causationId
            )

            val outboxEvent = OutboxEvent(
                eventId = UUID.randomUUID(),
                resultId = resultId,
                tenantId = command.tenantId,
                type = "BONUS_REVOCATION_PROPOSAL_SUBMITTED",
                createdAt = now
            )

            val result = RevokeBonusResult(
                resultId = resultId,
                tenantId = command.tenantId,
                grantId = command.grantId,
                playerId = command.playerId,
                revokedAmountMinorUnits = amountToRevoke,
                requiresApproval = true,
                proposalId = proposalId,
                revocationId = null,
                serverTime = now,
                serverVersion = wallet.version,
                evidenceReference = evidenceReference,
                auditRecord = null,
                auditEvent = auditEvent,
                outboxEvent = outboxEvent
            )

            store.saveIdempotency(command.tenantId, command.idempotencyKey, fingerprint, result)
            return result
        }

        // Standard value revocation (<= threshold): Direct execution
        val revocationId = UUID.randomUUID()

        // Mutate grant state
        grant.status = BonusGrantStatus.CANCELLED
        grant.version += 1L
        store.saveGrant(grant)

        // Mutate wallet state
        wallet.bonusMinorUnits -= amountToRevoke
        wallet.version += 1L
        store.saveWallet(wallet)

        // Double-entry ledger: Debit Player Bonus Liability, Credit Casino Revocation Recovery
        if (amountToRevoke > 0L) {
            store.recordLedgerEntry(
                BonusLedgerEntry(
                    entryId = UUID.randomUUID(),
                    tenantId = command.tenantId,
                    transactionReference = "direct-revocation:$revocationId",
                    debitAccount = "PLAYER_BONUS_LIABILITY:${wallet.playerId}",
                    creditAccount = "CASINO_BONUS_REVOCATION_RECOVERY",
                    amountMinorUnits = amountToRevoke,
                    currencyCode = command.currencyCode,
                    createdAt = now
                )
            )
        }

        val evidenceReference = "bonus-revocation:${command.tenantId}:${grant.grantId}:$revocationId:${wallet.version}"

        val auditRecord = BonusRevocationAuditRecord(
            revocationId = revocationId,
            tenantId = command.tenantId,
            grantId = grant.grantId,
            playerId = command.playerId,
            currencyCode = command.currencyCode,
            revokedAmountMinorUnits = amountToRevoke,
            makerPrincipalId = principal.id,
            checkerPrincipalId = null,
            revocationReason = command.revocationReason,
            isHighValue = false,
            proposalId = null,
            timestamp = now,
            serverVersion = wallet.version,
            evidenceReference = evidenceReference,
            remainingCashMinorUnits = wallet.cashMinorUnits,
            remainingBonusMinorUnits = wallet.bonusMinorUnits
        )
        store.saveRevocationAudit(auditRecord)

        val auditEvent = AuditEvent(
            eventId = UUID.randomUUID(),
            resultId = resultId,
            tenantId = command.tenantId,
            type = "BONUS_REVOCATION_DIRECT_EXECUTED",
            occurredAt = now,
            correlationId = command.correlationId,
            causationId = command.causationId
        )

        val outboxEvent = OutboxEvent(
            eventId = UUID.randomUUID(),
            resultId = resultId,
            tenantId = command.tenantId,
            type = "BONUS_REVOCATION_DIRECT_EXECUTED",
            createdAt = now
        )

        val result = RevokeBonusResult(
            resultId = resultId,
            tenantId = command.tenantId,
            grantId = command.grantId,
            playerId = command.playerId,
            revokedAmountMinorUnits = amountToRevoke,
            requiresApproval = false,
            proposalId = null,
            revocationId = revocationId,
            serverTime = now,
            serverVersion = wallet.version,
            evidenceReference = evidenceReference,
            auditRecord = auditRecord,
            auditEvent = auditEvent,
            outboxEvent = outboxEvent
        )

        store.saveIdempotency(command.tenantId, command.idempotencyKey, fingerprint, result)
        return result
    }

    /**
     * Four-eyes checker approval for a high-value bonus revocation proposal.
     * Enforces:
     * 1. Segregation of duties: Maker cannot approve own revocation proposal.
     * 2. Only distinct ADMIN can approve.
     * 3. Reasoned approval required (>= 10 chars).
     * 4. Double-entry ledger recording and audit record creation.
     */
    fun approveRevocationProposal(command: ApproveRevocationProposalCommand): ApproveRevocationProposalResult = synchronized(store) {
        BonusRevocationAuditBinding.checkBound()

        validateHeaders(
            tenantId = command.tenantId,
            correlationId = command.correlationId,
            causationId = command.causationId,
            idempotencyKey = command.idempotencyKey,
            expectedVersion = command.expectedWalletVersion
        )

        if (command.checkerReason.isBlank() || command.checkerReason.trim().length < 10) {
            throw AuthenticationFailure.Rejected(AuthErrorCode.INVALID)
        }

        val fingerprint = computeFingerprint(command)
        store.findByIdempotency(command.tenantId, command.idempotencyKey)?.let { (cachedFp, cachedRes) ->
            if (cachedFp == fingerprint && cachedRes is ApproveRevocationProposalResult) {
                return cachedRes
            } else {
                throw AuthenticationFailure.Rejected(AuthErrorCode.CONFLICT)
            }
        }

        val checker = command.checkerPrincipal ?: throw AuthenticationFailure.Rejected(AuthErrorCode.UNAUTHENTICATED)
        if (checker.tenantId != command.tenantId || checker.kind != PrincipalKind.ADMIN) {
            throw AuthenticationFailure.Rejected(AuthErrorCode.FORBIDDEN)
        }

        val proposal = store.findRevocationProposal(command.tenantId, command.proposalId)
            ?: throw AuthenticationFailure.Rejected(AuthErrorCode.INVALID)

        // SEGREGATION OF DUTIES: Maker cannot approve their own revocation proposal!
        if (checker.id == proposal.makerPrincipalId) {
            alertSink.sendAlert(
                tenantId = command.tenantId,
                alertType = "MAKER_CHECKER_SELF_APPROVAL_ATTEMPT",
                message = "Maker ${proposal.makerPrincipalId} attempted to approve own revocation proposal ${proposal.proposalId}"
            )
            throw AuthenticationFailure.Rejected(AuthErrorCode.FORBIDDEN)
        }

        if (proposal.status != BonusRevocationProposalStatus.PENDING_APPROVAL) {
            throw AuthenticationFailure.Rejected(AuthErrorCode.FORBIDDEN)
        }

        val grant = store.findGrant(command.tenantId, proposal.grantId)
            ?: throw AuthenticationFailure.Rejected(AuthErrorCode.INVALID)

        if (grant.status != BonusGrantStatus.ACTIVE) {
            throw AuthenticationFailure.Rejected(AuthErrorCode.FORBIDDEN)
        }

        val wallet = store.findWallet(command.tenantId, proposal.playerId, proposal.currencyCode)
            ?: throw AuthenticationFailure.Rejected(AuthErrorCode.INVALID)

        if (command.expectedWalletVersion != wallet.version) {
            throw AuthenticationFailure.Rejected(AuthErrorCode.STALE)
        }

        val now = clock.instant()
        val revocationId = UUID.randomUUID()
        val amountToRevoke = minOf(grant.amountMinorUnits, wallet.bonusMinorUnits)

        // Mutate grant state
        grant.status = BonusGrantStatus.CANCELLED
        grant.version += 1L
        store.saveGrant(grant)

        // Mutate wallet
        wallet.bonusMinorUnits -= amountToRevoke
        wallet.version += 1L
        store.saveWallet(wallet)

        // Double-entry ledger: Debit Player Bonus Liability, Credit Casino Revocation Recovery
        if (amountToRevoke > 0L) {
            store.recordLedgerEntry(
                BonusLedgerEntry(
                    entryId = UUID.randomUUID(),
                    tenantId = command.tenantId,
                    transactionReference = "approved-revocation:$revocationId",
                    debitAccount = "PLAYER_BONUS_LIABILITY:${wallet.playerId}",
                    creditAccount = "CASINO_BONUS_REVOCATION_RECOVERY",
                    amountMinorUnits = amountToRevoke,
                    currencyCode = proposal.currencyCode,
                    createdAt = now
                )
            )
        }

        // Mutate proposal state
        proposal.status = BonusRevocationProposalStatus.APPROVED
        proposal.checkerPrincipalId = checker.id
        proposal.checkerReason = command.checkerReason
        proposal.revocationId = revocationId
        proposal.decidedAt = now
        proposal.version += 1L
        store.saveRevocationProposal(proposal)

        val evidenceReference = "bonus-revocation-approved:${command.tenantId}:${proposal.proposalId}:$revocationId:${wallet.version}"

        val auditRecord = BonusRevocationAuditRecord(
            revocationId = revocationId,
            tenantId = command.tenantId,
            grantId = grant.grantId,
            playerId = proposal.playerId,
            currencyCode = proposal.currencyCode,
            revokedAmountMinorUnits = amountToRevoke,
            makerPrincipalId = proposal.makerPrincipalId,
            checkerPrincipalId = checker.id,
            revocationReason = "Maker: ${proposal.makerReason} | Checker: ${command.checkerReason}",
            isHighValue = true,
            proposalId = proposal.proposalId,
            timestamp = now,
            serverVersion = wallet.version,
            evidenceReference = evidenceReference,
            remainingCashMinorUnits = wallet.cashMinorUnits,
            remainingBonusMinorUnits = wallet.bonusMinorUnits
        )
        store.saveRevocationAudit(auditRecord)

        val resultId = UUID.randomUUID()
        val auditEvent = AuditEvent(
            eventId = UUID.randomUUID(),
            resultId = resultId,
            tenantId = command.tenantId,
            type = "BONUS_REVOCATION_APPROVED",
            occurredAt = now,
            correlationId = command.correlationId,
            causationId = command.causationId
        )

        val outboxEvent = OutboxEvent(
            eventId = UUID.randomUUID(),
            resultId = resultId,
            tenantId = command.tenantId,
            type = "BONUS_REVOCATION_APPROVED",
            createdAt = now
        )

        val result = ApproveRevocationProposalResult(
            resultId = resultId,
            proposalId = proposal.proposalId,
            revocationId = revocationId,
            tenantId = command.tenantId,
            grantId = grant.grantId,
            playerId = proposal.playerId,
            revokedAmountMinorUnits = amountToRevoke,
            makerId = proposal.makerPrincipalId,
            checkerId = checker.id,
            serverTime = now,
            serverVersion = wallet.version,
            evidenceReference = evidenceReference,
            auditRecord = auditRecord,
            auditEvent = auditEvent,
            outboxEvent = outboxEvent
        )

        store.saveIdempotency(command.tenantId, command.idempotencyKey, fingerprint, result)
        return result
    }

    /**
     * Reject a high-value bonus revocation proposal.
     */
    fun rejectRevocationProposal(command: RejectRevocationProposalCommand): RejectRevocationProposalResult = synchronized(store) {
        BonusRevocationAuditBinding.checkBound()

        if (command.tenantId.isBlank() || command.correlationId.isBlank() || command.causationId.isBlank() || command.idempotencyKey.isBlank()) {
            throw AuthenticationFailure.Rejected(AuthErrorCode.INVALID)
        }
        if (command.rejectionReason.isBlank()) {
            throw AuthenticationFailure.Rejected(AuthErrorCode.INVALID)
        }

        val fingerprint = computeFingerprint(command)
        store.findByIdempotency(command.tenantId, command.idempotencyKey)?.let { (cachedFp, cachedRes) ->
            if (cachedFp == fingerprint && cachedRes is RejectRevocationProposalResult) {
                return cachedRes
            } else {
                throw AuthenticationFailure.Rejected(AuthErrorCode.CONFLICT)
            }
        }

        val checker = command.checkerPrincipal ?: throw AuthenticationFailure.Rejected(AuthErrorCode.UNAUTHENTICATED)
        if (checker.tenantId != command.tenantId || checker.kind != PrincipalKind.ADMIN) {
            throw AuthenticationFailure.Rejected(AuthErrorCode.FORBIDDEN)
        }

        val proposal = store.findRevocationProposal(command.tenantId, command.proposalId)
            ?: throw AuthenticationFailure.Rejected(AuthErrorCode.INVALID)

        if (proposal.status != BonusRevocationProposalStatus.PENDING_APPROVAL) {
            throw AuthenticationFailure.Rejected(AuthErrorCode.FORBIDDEN)
        }

        val now = clock.instant()
        proposal.status = BonusRevocationProposalStatus.REJECTED
        proposal.checkerPrincipalId = checker.id
        proposal.checkerReason = command.rejectionReason
        proposal.decidedAt = now
        proposal.version += 1L
        store.saveRevocationProposal(proposal)

        val resultId = UUID.randomUUID()
        val evidenceReference = "bonus-revocation-rejected:${command.tenantId}:${proposal.proposalId}"

        val auditEvent = AuditEvent(
            eventId = UUID.randomUUID(),
            resultId = resultId,
            tenantId = command.tenantId,
            type = "BONUS_REVOCATION_REJECTED",
            occurredAt = now,
            correlationId = command.correlationId,
            causationId = command.causationId
        )

        val result = RejectRevocationProposalResult(
            resultId = resultId,
            proposalId = proposal.proposalId,
            tenantId = command.tenantId,
            status = BonusRevocationProposalStatus.REJECTED,
            checkerId = checker.id,
            rejectionReason = command.rejectionReason,
            serverTime = now,
            evidenceReference = evidenceReference,
            auditEvent = auditEvent
        )

        store.saveIdempotency(command.tenantId, command.idempotencyKey, fingerprint, result)
        return result
    }

    fun getRevocationAudit(tenantId: String, revocationId: UUID): BonusRevocationAuditRecord? {
        return store.findRevocationAudit(tenantId, revocationId)
    }

    fun getRevocationAuditsForPlayer(tenantId: String, playerId: UUID): List<BonusRevocationAuditRecord> {
        return store.findRevocationAuditsForPlayer(tenantId, playerId)
    }

    fun getAllRevocationAudits(tenantId: String): List<BonusRevocationAuditRecord> {
        return store.findAllRevocationAudits(tenantId)
    }

    fun getPendingRevocationProposals(tenantId: String): List<BonusRevocationProposal> {
        return store.findPendingRevocationProposals(tenantId)
    }
}
