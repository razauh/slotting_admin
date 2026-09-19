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
 * Gate to enforce BONUS-003-01: Administer approved bonus grants.
 * Semantic contract: "High-value threshold decision gate; never direct projection edit."
 * Protected risk: "self/unreasoned grant"
 */
object BonusAdministrationBinding {
    var isBound: Boolean = true

    fun checkBound() {
        if (!isBound) {
            throw AssertionError("self/unreasoned grant")
        }
    }
}

enum class BonusProposalStatus {
    PENDING_APPROVAL,
    APPROVED,
    REJECTED,
    CANCELLED
}

data class BonusGrantProposal(
    val proposalId: UUID,
    val tenantId: String,
    val playerId: UUID,
    val bonusType: BonusGrantType,
    val amountMinorUnits: Long,
    val currencyCode: String,
    val wageringRequirementMultiplier: Double,
    val makerPrincipalId: String,
    val makerReason: String,
    var status: BonusProposalStatus,
    var checkerPrincipalId: String? = null,
    var checkerReason: String? = null,
    var grantId: UUID? = null,
    val createdAt: Instant,
    val expiresAt: Instant,
    var decidedAt: Instant? = null,
    var version: Long = 1L
)

data class AdministerBonusGrantCommand(
    val principal: AuthenticatedPrincipal?,
    val tenantId: String,
    val playerId: UUID,
    val bonusType: BonusGrantType,
    val amountMinorUnits: Long,
    val currencyCode: String,
    val wageringRequirementMultiplier: Double = 0.0,
    val ttlSeconds: Long = 86400L * 30, // 30 days
    val grantReason: String,
    val idempotencyKey: String,
    val correlationId: String,
    val causationId: String,
    val expectedVersion: Long
)

data class AdministerBonusGrantResult(
    val resultId: UUID,
    val tenantId: String,
    val playerId: UUID,
    val amountMinorUnits: Long,
    val currencyCode: String,
    val requiresApproval: Boolean,
    val proposalId: UUID?,
    val grantId: UUID?,
    val newCashBalanceMinorUnits: Long,
    val newBonusBalanceMinorUnits: Long,
    val serverTime: Instant,
    val serverVersion: Long,
    val evidenceReference: String,
    val auditEvent: AuditEvent,
    val outboxEvent: OutboxEvent
)

data class ApproveBonusProposalCommand(
    val checkerPrincipal: AuthenticatedPrincipal?,
    val tenantId: String,
    val proposalId: UUID,
    val checkerReason: String,
    val idempotencyKey: String,
    val correlationId: String,
    val causationId: String,
    val expectedWalletVersion: Long
)

data class ApproveBonusProposalResult(
    val resultId: UUID,
    val proposalId: UUID,
    val grantId: UUID,
    val tenantId: String,
    val playerId: UUID,
    val approvedAmountMinorUnits: Long,
    val makerId: String,
    val checkerId: String,
    val newBonusBalanceMinorUnits: Long,
    val serverTime: Instant,
    val serverVersion: Long,
    val evidenceReference: String,
    val auditEvent: AuditEvent,
    val outboxEvent: OutboxEvent
)

data class RejectBonusProposalCommand(
    val checkerPrincipal: AuthenticatedPrincipal?,
    val tenantId: String,
    val proposalId: UUID,
    val rejectionReason: String,
    val idempotencyKey: String,
    val correlationId: String,
    val causationId: String
)

data class RejectBonusProposalResult(
    val resultId: UUID,
    val proposalId: UUID,
    val tenantId: String,
    val status: BonusProposalStatus,
    val checkerId: String,
    val rejectionReason: String,
    val serverTime: Instant,
    val evidenceReference: String,
    val auditEvent: AuditEvent
)

interface BonusAdministrationStore : BonusGrantStore {
    fun saveProposal(proposal: BonusGrantProposal)
    fun findProposal(tenantId: String, proposalId: UUID): BonusGrantProposal?
    fun findPendingProposals(tenantId: String): List<BonusGrantProposal>
}

class InMemoryBonusAdministrationStore(
    private val delegate: InMemoryBonusGrantStore = InMemoryBonusGrantStore()
) : BonusAdministrationStore, BonusGrantStore by delegate {
    val proposals = ConcurrentHashMap<UUID, BonusGrantProposal>()

    override fun saveProposal(proposal: BonusGrantProposal) {
        proposals[proposal.proposalId] = proposal
    }

    override fun findProposal(tenantId: String, proposalId: UUID): BonusGrantProposal? {
        val p = proposals[proposalId]
        return if (p?.tenantId == tenantId) p else null
    }

    override fun findPendingProposals(tenantId: String): List<BonusGrantProposal> {
        return proposals.values.filter { it.tenantId == tenantId && it.status == BonusProposalStatus.PENDING_APPROVAL }
    }
}

class BonusAdministrationService(
    private val store: BonusAdministrationStore,
    private val highValueThresholdMinorUnits: Long = 10_000L, // $100.00 threshold requires 4-eyes approval
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

    private fun computeFingerprint(command: AdministerBonusGrantCommand): String {
        return listOf(
            command.principal?.tenantId,
            command.principal?.id,
            command.tenantId,
            command.playerId.toString(),
            command.bonusType.name,
            command.amountMinorUnits,
            command.currencyCode,
            command.wageringRequirementMultiplier,
            command.grantReason,
            command.expectedVersion
        ).joinToString("|")
    }

    private fun computeFingerprint(command: ApproveBonusProposalCommand): String {
        return listOf(
            command.checkerPrincipal?.tenantId,
            command.checkerPrincipal?.id,
            command.tenantId,
            command.proposalId.toString(),
            command.checkerReason,
            command.expectedWalletVersion
        ).joinToString("|")
    }

    private fun computeFingerprint(command: RejectBonusProposalCommand): String {
        return listOf(
            command.checkerPrincipal?.tenantId,
            command.checkerPrincipal?.id,
            command.tenantId,
            command.proposalId.toString(),
            command.rejectionReason
        ).joinToString("|")
    }

    /**
     * Administer a bonus grant.
     * Enforces:
     * 1. Self-grant prevention: Admin cannot grant bonus to own player account.
     * 2. Unreasoned grant prevention: Must provide a structured, non-blank business reason (>= 10 chars).
     * 3. High-value threshold decision gate: Grants > highValueThresholdMinorUnits cannot be directly executed;
     *    they create a proposal requiring maker-checker approval.
     * 4. Never direct projection edit: Balances are strictly updated via atomic double-entry ledger journals.
     */
    fun administerGrant(command: AdministerBonusGrantCommand): AdministerBonusGrantResult = synchronized(store) {
        BonusAdministrationBinding.checkBound()

        validateHeaders(
            tenantId = command.tenantId,
            correlationId = command.correlationId,
            causationId = command.causationId,
            idempotencyKey = command.idempotencyKey,
            expectedVersion = command.expectedVersion
        )

        // Reason validation: Unreasoned grants are strictly forbidden
        if (command.grantReason.isBlank() || command.grantReason.trim().length < 10) {
            alertSink.sendAlert(
                tenantId = command.tenantId,
                alertType = "UNREASONED_BONUS_GRANT_REJECTED",
                message = "Grant rejected: structured business justification is required"
            )
            throw AuthenticationFailure.Rejected(AuthErrorCode.INVALID)
        }

        if (command.amountMinorUnits <= 0L || command.wageringRequirementMultiplier < 0.0) {
            throw AuthenticationFailure.Rejected(AuthErrorCode.INVALID)
        }

        val fingerprint = computeFingerprint(command)
        store.findByIdempotency(command.tenantId, command.idempotencyKey)?.let { (cachedFp, cachedRes) ->
            if (cachedFp == fingerprint && cachedRes is AdministerBonusGrantResult) {
                return cachedRes
            } else {
                throw AuthenticationFailure.Rejected(AuthErrorCode.CONFLICT)
            }
        }

        val principal = command.principal ?: throw AuthenticationFailure.Rejected(AuthErrorCode.UNAUTHENTICATED)
        if (principal.tenantId != command.tenantId) {
            throw AuthenticationFailure.Rejected(AuthErrorCode.FORBIDDEN)
        }

        // Only ADMIN principal can administer bonus grants
        if (principal.kind != PrincipalKind.ADMIN) {
            throw AuthenticationFailure.Rejected(AuthErrorCode.FORBIDDEN)
        }

        // SELF-GRANT PREVENTION: Admin cannot grant bonus to own account
        if (principal.id == command.playerId.toString()) {
            alertSink.sendAlert(
                tenantId = command.tenantId,
                alertType = "SELF_BONUS_GRANT_ATTEMPT_DENIED",
                message = "Admin ${principal.id} attempted to grant bonus to self ${command.playerId}"
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

        // HIGH-VALUE THRESHOLD DECISION GATE:
        // If amount > highValueThresholdMinorUnits, route to four-eyes proposal queue!
        if (command.amountMinorUnits > highValueThresholdMinorUnits) {
            val proposalId = UUID.randomUUID()
            val proposal = BonusGrantProposal(
                proposalId = proposalId,
                tenantId = command.tenantId,
                playerId = command.playerId,
                bonusType = command.bonusType,
                amountMinorUnits = command.amountMinorUnits,
                currencyCode = command.currencyCode,
                wageringRequirementMultiplier = command.wageringRequirementMultiplier,
                makerPrincipalId = principal.id,
                makerReason = command.grantReason,
                status = BonusProposalStatus.PENDING_APPROVAL,
                createdAt = now,
                expiresAt = now.plusSeconds(86400 * 7), // 7 day approval window
                version = 1L
            )
            store.saveProposal(proposal)

            val evidenceReference = "bonus-proposal:${command.tenantId}:${command.playerId}:$proposalId:pending"

            val auditEvent = AuditEvent(
                eventId = UUID.randomUUID(),
                resultId = resultId,
                tenantId = command.tenantId,
                type = "BONUS_GRANT_PROPOSAL_SUBMITTED",
                occurredAt = now,
                correlationId = command.correlationId,
                causationId = command.causationId
            )

            val outboxEvent = OutboxEvent(
                eventId = UUID.randomUUID(),
                resultId = resultId,
                tenantId = command.tenantId,
                type = "BONUS_GRANT_PROPOSAL_SUBMITTED",
                createdAt = now
            )

            val result = AdministerBonusGrantResult(
                resultId = resultId,
                tenantId = command.tenantId,
                playerId = command.playerId,
                amountMinorUnits = command.amountMinorUnits,
                currencyCode = command.currencyCode,
                requiresApproval = true,
                proposalId = proposalId,
                grantId = null,
                newCashBalanceMinorUnits = wallet.cashMinorUnits,
                newBonusBalanceMinorUnits = wallet.bonusMinorUnits,
                serverTime = now,
                serverVersion = wallet.version,
                evidenceReference = evidenceReference,
                auditEvent = auditEvent,
                outboxEvent = outboxEvent
            )

            store.saveIdempotency(command.tenantId, command.idempotencyKey, fingerprint, result)
            return result
        }

        // Standard value grant (<= threshold): Direct execution with full double-entry ledger recording
        val grantId = UUID.randomUUID()
        val wageringRequired = (command.amountMinorUnits * command.wageringRequirementMultiplier).toLong()

        wallet.bonusMinorUnits += command.amountMinorUnits
        wallet.version += 1L
        store.saveWallet(wallet)

        // Double-entry ledger: Debit Casino Promotion Expense, Credit Player Bonus Liability
        store.recordLedgerEntry(
            BonusLedgerEntry(
                entryId = UUID.randomUUID(),
                tenantId = command.tenantId,
                transactionReference = "admin-grant:$grantId",
                debitAccount = "CASINO_PROMOTION_EXPENSE",
                creditAccount = "PLAYER_BONUS_LIABILITY:${wallet.playerId}",
                amountMinorUnits = command.amountMinorUnits,
                currencyCode = command.currencyCode,
                createdAt = now
            )
        )

        val grantRecord = BonusGrantRecord(
            grantId = grantId,
            tenantId = command.tenantId,
            playerId = command.playerId,
            bonusType = command.bonusType,
            amountMinorUnits = command.amountMinorUnits,
            currencyCode = command.currencyCode,
            wageringRequirementMultiplier = command.wageringRequirementMultiplier,
            wageringRequirementMinorUnits = wageringRequired,
            wageringProgressMinorUnits = 0L,
            status = BonusGrantStatus.ACTIVE,
            reason = command.grantReason,
            createdAt = now,
            expiresAt = now.plusSeconds(command.ttlSeconds),
            version = 1L
        )
        store.saveGrant(grantRecord)

        val evidenceReference = "bonus-direct-grant:${command.tenantId}:${command.playerId}:$grantId:${wallet.version}"

        val auditEvent = AuditEvent(
            eventId = UUID.randomUUID(),
            resultId = resultId,
            tenantId = command.tenantId,
            type = "BONUS_GRANT_DIRECT_POSTED",
            occurredAt = now,
            correlationId = command.correlationId,
            causationId = command.causationId
        )

        val outboxEvent = OutboxEvent(
            eventId = UUID.randomUUID(),
            resultId = resultId,
            tenantId = command.tenantId,
            type = "BONUS_GRANT_DIRECT_POSTED",
            createdAt = now
        )

        val result = AdministerBonusGrantResult(
            resultId = resultId,
            tenantId = command.tenantId,
            playerId = command.playerId,
            amountMinorUnits = command.amountMinorUnits,
            currencyCode = command.currencyCode,
            requiresApproval = false,
            proposalId = null,
            grantId = grantId,
            newCashBalanceMinorUnits = wallet.cashMinorUnits,
            newBonusBalanceMinorUnits = wallet.bonusMinorUnits,
            serverTime = now,
            serverVersion = wallet.version,
            evidenceReference = evidenceReference,
            auditEvent = auditEvent,
            outboxEvent = outboxEvent
        )

        store.saveIdempotency(command.tenantId, command.idempotencyKey, fingerprint, result)
        return result
    }

    /**
     * Four-eyes checker approval for a high-value bonus grant proposal.
     * Enforces:
     * 1. Segregation of duties: Proposer (maker) cannot approve own proposal.
     * 2. Only distinct ADMIN can approve.
     * 3. Reasoned approval required (>= 10 chars).
     * 4. Double-entry ledger recording and atomic wallet mutation.
     */
    fun approveProposal(command: ApproveBonusProposalCommand): ApproveBonusProposalResult = synchronized(store) {
        BonusAdministrationBinding.checkBound()

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
            if (cachedFp == fingerprint && cachedRes is ApproveBonusProposalResult) {
                return cachedRes
            } else {
                throw AuthenticationFailure.Rejected(AuthErrorCode.CONFLICT)
            }
        }

        val checker = command.checkerPrincipal ?: throw AuthenticationFailure.Rejected(AuthErrorCode.UNAUTHENTICATED)
        if (checker.tenantId != command.tenantId || checker.kind != PrincipalKind.ADMIN) {
            throw AuthenticationFailure.Rejected(AuthErrorCode.FORBIDDEN)
        }

        val proposal = store.findProposal(command.tenantId, command.proposalId)
            ?: throw AuthenticationFailure.Rejected(AuthErrorCode.INVALID)

        // SEGREGATION OF DUTIES: Maker cannot approve their own proposal!
        if (checker.id == proposal.makerPrincipalId) {
            alertSink.sendAlert(
                tenantId = command.tenantId,
                alertType = "MAKER_CHECKER_SELF_APPROVAL_ATTEMPT",
                message = "Maker ${proposal.makerPrincipalId} attempted to approve own bonus proposal ${proposal.proposalId}"
            )
            throw AuthenticationFailure.Rejected(AuthErrorCode.FORBIDDEN)
        }

        if (proposal.status != BonusProposalStatus.PENDING_APPROVAL) {
            throw AuthenticationFailure.Rejected(AuthErrorCode.FORBIDDEN)
        }

        val wallet = store.findWallet(command.tenantId, proposal.playerId, proposal.currencyCode)
            ?: throw AuthenticationFailure.Rejected(AuthErrorCode.INVALID)

        if (command.expectedWalletVersion != wallet.version) {
            throw AuthenticationFailure.Rejected(AuthErrorCode.STALE)
        }

        val now = clock.instant()
        val grantId = UUID.randomUUID()
        val wageringRequired = (proposal.amountMinorUnits * proposal.wageringRequirementMultiplier).toLong()

        // Mutate wallet
        wallet.bonusMinorUnits += proposal.amountMinorUnits
        wallet.version += 1L
        store.saveWallet(wallet)

        // Double-entry ledger: Debit Casino Promotion Expense, Credit Player Bonus Liability
        store.recordLedgerEntry(
            BonusLedgerEntry(
                entryId = UUID.randomUUID(),
                tenantId = command.tenantId,
                transactionReference = "four-eyes-grant:$grantId",
                debitAccount = "CASINO_PROMOTION_EXPENSE",
                creditAccount = "PLAYER_BONUS_LIABILITY:${wallet.playerId}",
                amountMinorUnits = proposal.amountMinorUnits,
                currencyCode = proposal.currencyCode,
                createdAt = now
            )
        )

        // Save Grant Record
        val grantRecord = BonusGrantRecord(
            grantId = grantId,
            tenantId = command.tenantId,
            playerId = proposal.playerId,
            bonusType = proposal.bonusType,
            amountMinorUnits = proposal.amountMinorUnits,
            currencyCode = proposal.currencyCode,
            wageringRequirementMultiplier = proposal.wageringRequirementMultiplier,
            wageringRequirementMinorUnits = wageringRequired,
            wageringProgressMinorUnits = 0L,
            status = BonusGrantStatus.ACTIVE,
            reason = "Approved proposal ${proposal.proposalId}: ${command.checkerReason}",
            createdAt = now,
            expiresAt = now.plusSeconds(86400L * 30),
            version = 1L
        )
        store.saveGrant(grantRecord)

        // Mutate proposal state
        proposal.status = BonusProposalStatus.APPROVED
        proposal.checkerPrincipalId = checker.id
        proposal.checkerReason = command.checkerReason
        proposal.grantId = grantId
        proposal.decidedAt = now
        proposal.version += 1L
        store.saveProposal(proposal)

        val resultId = UUID.randomUUID()
        val evidenceReference = "bonus-approved:${command.tenantId}:${proposal.proposalId}:$grantId:${wallet.version}"

        val auditEvent = AuditEvent(
            eventId = UUID.randomUUID(),
            resultId = resultId,
            tenantId = command.tenantId,
            type = "BONUS_GRANT_APPROVED",
            occurredAt = now,
            correlationId = command.correlationId,
            causationId = command.causationId
        )

        val outboxEvent = OutboxEvent(
            eventId = UUID.randomUUID(),
            resultId = resultId,
            tenantId = command.tenantId,
            type = "BONUS_GRANT_APPROVED",
            createdAt = now
        )

        val result = ApproveBonusProposalResult(
            resultId = resultId,
            proposalId = proposal.proposalId,
            grantId = grantId,
            tenantId = command.tenantId,
            playerId = proposal.playerId,
            approvedAmountMinorUnits = proposal.amountMinorUnits,
            makerId = proposal.makerPrincipalId,
            checkerId = checker.id,
            newBonusBalanceMinorUnits = wallet.bonusMinorUnits,
            serverTime = now,
            serverVersion = wallet.version,
            evidenceReference = evidenceReference,
            auditEvent = auditEvent,
            outboxEvent = outboxEvent
        )

        store.saveIdempotency(command.tenantId, command.idempotencyKey, fingerprint, result)
        return result
    }

    /**
     * Reject a bonus grant proposal.
     */
    fun rejectProposal(command: RejectBonusProposalCommand): RejectBonusProposalResult = synchronized(store) {
        BonusAdministrationBinding.checkBound()

        if (command.tenantId.isBlank() || command.correlationId.isBlank() || command.causationId.isBlank() || command.idempotencyKey.isBlank()) {
            throw AuthenticationFailure.Rejected(AuthErrorCode.INVALID)
        }
        if (command.rejectionReason.isBlank()) {
            throw AuthenticationFailure.Rejected(AuthErrorCode.INVALID)
        }

        val fingerprint = computeFingerprint(command)
        store.findByIdempotency(command.tenantId, command.idempotencyKey)?.let { (cachedFp, cachedRes) ->
            if (cachedFp == fingerprint && cachedRes is RejectBonusProposalResult) {
                return cachedRes
            } else {
                throw AuthenticationFailure.Rejected(AuthErrorCode.CONFLICT)
            }
        }

        val checker = command.checkerPrincipal ?: throw AuthenticationFailure.Rejected(AuthErrorCode.UNAUTHENTICATED)
        if (checker.tenantId != command.tenantId || checker.kind != PrincipalKind.ADMIN) {
            throw AuthenticationFailure.Rejected(AuthErrorCode.FORBIDDEN)
        }

        val proposal = store.findProposal(command.tenantId, command.proposalId)
            ?: throw AuthenticationFailure.Rejected(AuthErrorCode.INVALID)

        if (proposal.status != BonusProposalStatus.PENDING_APPROVAL) {
            throw AuthenticationFailure.Rejected(AuthErrorCode.FORBIDDEN)
        }

        val now = clock.instant()
        proposal.status = BonusProposalStatus.REJECTED
        proposal.checkerPrincipalId = checker.id
        proposal.checkerReason = command.rejectionReason
        proposal.decidedAt = now
        proposal.version += 1L
        store.saveProposal(proposal)

        val resultId = UUID.randomUUID()
        val evidenceReference = "bonus-rejected:${command.tenantId}:${proposal.proposalId}"

        val auditEvent = AuditEvent(
            eventId = UUID.randomUUID(),
            resultId = resultId,
            tenantId = command.tenantId,
            type = "BONUS_GRANT_REJECTED",
            occurredAt = now,
            correlationId = command.correlationId,
            causationId = command.causationId
        )

        val result = RejectBonusProposalResult(
            resultId = resultId,
            proposalId = proposal.proposalId,
            tenantId = command.tenantId,
            status = BonusProposalStatus.REJECTED,
            checkerId = checker.id,
            rejectionReason = command.rejectionReason,
            serverTime = now,
            evidenceReference = evidenceReference,
            auditEvent = auditEvent
        )

        store.saveIdempotency(command.tenantId, command.idempotencyKey, fingerprint, result)
        return result
    }

    fun getPendingProposals(tenantId: String): List<BonusGrantProposal> {
        return store.findPendingProposals(tenantId)
    }

    fun getProposal(tenantId: String, proposalId: UUID): BonusGrantProposal? {
        return store.findProposal(tenantId, proposalId)
    }
}
