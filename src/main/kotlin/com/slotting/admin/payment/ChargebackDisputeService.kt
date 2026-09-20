package com.slotting.admin.payment

import com.slotting.admin.auth.*
import com.slotting.admin.ledger.*
import java.nio.charset.StandardCharsets
import java.security.MessageDigest
import java.time.Clock
import java.time.Instant
import java.util.UUID
import java.util.concurrent.ConcurrentHashMap

/**
 * Fail-closed verification gate for PAYMENT-006-02: Manage chargeback disputes.
 * Throws expected RED failure until contract bindings and invariant protections are verified.
 * Protected risk: False completion or non-authoritative implementation of Manage chargeback disputes.
 * Rationale: It exists to prevent: edit/delete credit or duplicate reversal.
 */
object ManageChargebackDisputesBinding {
    @Volatile
    var isBound: Boolean = false

    fun checkBound() {
        if (!isBound) {
            throw AssertionError("edit/delete credit or duplicate reversal")
        }
    }
}

/**
 * Outcome-specific semantic contract for PAYMENT-006-02.
 */
const val MANAGE_CHARGEBACK_DISPUTES_CONTRACT =
    "Insufficient funds becomes risk/recovery case, never hidden negative mutation."

enum class DisputeStatus {
    OPENED,
    EVIDENCE_SUBMITTED,
    RESOLVED_WON,
    RESOLVED_LOST,
}

enum class DisputeResolution {
    WON,
    LOST,
}

data class OpenDisputeCommand(
    val tenantId: String,
    val playerId: UUID,
    val originalPaymentReference: String,
    val externalDisputeId: String,
    val providerId: String,
    val providerTransactionId: String,
    val amountMinorUnits: Long,
    val currencyCode: String,
    val reason: String,
    val availablePlayerWalletBalanceMinorUnits: Long? = null,
    val idempotencyKey: String,
    val correlationId: String,
    val causationId: String,
    val expectedVersion: Long = 1L,
    val principal: AuthenticatedPrincipal? = null,
)

data class SubmitDisputeEvidenceCommand(
    val tenantId: String,
    val externalDisputeId: String,
    val evidenceType: String,
    val evidenceDocumentReference: String,
    val notes: String,
    val idempotencyKey: String,
    val correlationId: String,
    val causationId: String,
    val expectedVersion: Long,
    val principal: AuthenticatedPrincipal? = null,
)

data class ResolveDisputeCommand(
    val tenantId: String,
    val externalDisputeId: String,
    val resolution: DisputeResolution,
    val providerResolutionReference: String,
    val resolutionNotes: String,
    val idempotencyKey: String,
    val correlationId: String,
    val causationId: String,
    val expectedVersion: Long,
    val principal: AuthenticatedPrincipal? = null,
)

data class DisputeOperationResult(
    val disputeId: UUID,
    val tenantId: String,
    val playerId: UUID,
    val originalPaymentReference: String,
    val externalDisputeId: String,
    val amountMinorUnits: Long,
    val currencyCode: String,
    val status: DisputeStatus,
    val version: Long,
    val isDeficitRiskCase: Boolean,
    val deficitMinorUnits: Long,
    val recoveredFromWalletMinorUnits: Long,
    val recoveryCaseReference: String?,
    val ledgerTransactionReference: String,
    val isDuplicate: Boolean,
    val conserved: Boolean,
    val evidenceReference: String,
    val serverTime: Instant,
    val semanticContract: String = MANAGE_CHARGEBACK_DISPUTES_CONTRACT,
)

data class ChargebackDisputeRecord(
    val disputeId: UUID,
    val tenantId: String,
    val playerId: UUID,
    val originalPaymentReference: String,
    val externalDisputeId: String,
    val providerId: String,
    val providerTransactionId: String,
    val amountMinorUnits: Long,
    val currencyCode: String,
    val reason: String,
    val status: DisputeStatus,
    val isDeficitRiskCase: Boolean,
    val deficitMinorUnits: Long,
    val recoveredFromWalletMinorUnits: Long,
    val recoveryCaseReference: String?,
    val ledgerTransactionReference: String,
    val evidenceDocumentReference: String? = null,
    val providerResolutionReference: String? = null,
    val version: Long,
    val createdAt: Instant,
    val updatedAt: Instant,
    val semanticContract: String = MANAGE_CHARGEBACK_DISPUTES_CONTRACT,
)

data class ChargebackDisputeSnapshot(
    val disputes: Map<String, ChargebackDisputeRecord>,
    val disputesByExtId: Map<String, ChargebackDisputeRecord>,
    val idempotencyMap: Map<String, Pair<String, DisputeOperationResult>>,
    val auditEvents: List<AuditEvent>,
    val outboxEvents: List<OutboxEvent>,
)

interface ChargebackDisputeAlertSink {
    fun sendAlert(tenantId: String, disputeId: String, alertType: String, reason: String, detail: String)
}

class InMemoryChargebackDisputeAlertSink : ChargebackDisputeAlertSink {
    val alerts = mutableListOf<String>()

    @Synchronized
    override fun sendAlert(tenantId: String, disputeId: String, alertType: String, reason: String, detail: String) {
        alerts.add("$tenantId:$disputeId:$alertType:$reason:$detail")
    }
}

interface ChargebackDisputeStore {
    fun findDisputeById(tenantId: String, disputeId: UUID): ChargebackDisputeRecord?
    fun findDisputeByExternalId(tenantId: String, externalDisputeId: String): ChargebackDisputeRecord?
    fun findByIdempotency(tenantId: String, idempotencyKey: String): Pair<String, DisputeOperationResult>?
    fun listDisputesForPayment(tenantId: String, originalPaymentReference: String): List<ChargebackDisputeRecord>
    fun saveDispute(
        record: ChargebackDisputeRecord,
        result: DisputeOperationResult,
        idempotencyKey: String,
        fingerprint: String,
        audit: AuditEvent,
        outbox: OutboxEvent,
    )
    fun updateDispute(
        record: ChargebackDisputeRecord,
        result: DisputeOperationResult,
        idempotencyKey: String,
        fingerprint: String,
        audit: AuditEvent,
        outbox: OutboxEvent,
    )
    fun getAuditEvents(): List<AuditEvent>
    fun getOutboxEvents(): List<OutboxEvent>
    fun exportSnapshot(): ChargebackDisputeSnapshot
    fun importSnapshot(snapshot: ChargebackDisputeSnapshot)
}

class InMemoryChargebackDisputeStore : ChargebackDisputeStore {
    private val disputes = ConcurrentHashMap<UUID, ChargebackDisputeRecord>()
    private val disputesByExtId = ConcurrentHashMap<String, ChargebackDisputeRecord>()
    private val idempotencyResults = ConcurrentHashMap<String, Pair<String, DisputeOperationResult>>()
    private val auditEvents = mutableListOf<AuditEvent>()
    private val outboxEvents = mutableListOf<OutboxEvent>()

    private fun extKey(tenantId: String, extId: String) = "$tenantId:$extId"
    private fun idKey(tenantId: String, idemp: String) = "$tenantId:$idemp"

    @Synchronized
    override fun findDisputeById(tenantId: String, disputeId: UUID): ChargebackDisputeRecord? =
        disputes[disputeId]?.takeIf { it.tenantId == tenantId }?.copy()

    @Synchronized
    override fun findDisputeByExternalId(tenantId: String, externalDisputeId: String): ChargebackDisputeRecord? =
        disputesByExtId[extKey(tenantId, externalDisputeId)]?.copy()

    @Synchronized
    override fun findByIdempotency(tenantId: String, idempotencyKey: String): Pair<String, DisputeOperationResult>? =
        idempotencyResults[idKey(tenantId, idempotencyKey)]

    @Synchronized
    override fun listDisputesForPayment(tenantId: String, originalPaymentReference: String): List<ChargebackDisputeRecord> =
        disputes.values.filter { it.tenantId == tenantId && it.originalPaymentReference == originalPaymentReference }.map { it.copy() }

    @Synchronized
    override fun saveDispute(
        record: ChargebackDisputeRecord,
        result: DisputeOperationResult,
        idempotencyKey: String,
        fingerprint: String,
        audit: AuditEvent,
        outbox: OutboxEvent,
    ) {
        disputes[record.disputeId] = record.copy()
        disputesByExtId[extKey(record.tenantId, record.externalDisputeId)] = record.copy()
        idempotencyResults[idKey(record.tenantId, idempotencyKey)] = fingerprint to result
        auditEvents.add(audit)
        outboxEvents.add(outbox)
    }

    @Synchronized
    override fun updateDispute(
        record: ChargebackDisputeRecord,
        result: DisputeOperationResult,
        idempotencyKey: String,
        fingerprint: String,
        audit: AuditEvent,
        outbox: OutboxEvent,
    ) {
        disputes[record.disputeId] = record.copy()
        disputesByExtId[extKey(record.tenantId, record.externalDisputeId)] = record.copy()
        idempotencyResults[idKey(record.tenantId, idempotencyKey)] = fingerprint to result
        auditEvents.add(audit)
        outboxEvents.add(outbox)
    }

    @Synchronized
    override fun getAuditEvents(): List<AuditEvent> = auditEvents.toList()

    @Synchronized
    override fun getOutboxEvents(): List<OutboxEvent> = outboxEvents.toList()

    @Synchronized
    override fun exportSnapshot(): ChargebackDisputeSnapshot {
        val idMap = HashMap<String, ChargebackDisputeRecord>()
        for ((k, v) in disputes) {
            idMap[k.toString()] = v.copy()
        }
        return ChargebackDisputeSnapshot(
            disputes = idMap,
            disputesByExtId = HashMap(disputesByExtId),
            idempotencyMap = HashMap(idempotencyResults),
            auditEvents = ArrayList(auditEvents),
            outboxEvents = ArrayList(outboxEvents),
        )
    }

    @Synchronized
    override fun importSnapshot(snapshot: ChargebackDisputeSnapshot) {
        disputes.clear()
        for ((k, v) in snapshot.disputes) {
            disputes[UUID.fromString(k)] = v.copy()
        }
        disputesByExtId.clear()
        disputesByExtId.putAll(snapshot.disputesByExtId)
        idempotencyResults.clear()
        idempotencyResults.putAll(snapshot.idempotencyMap)
        auditEvents.clear()
        auditEvents.addAll(snapshot.auditEvents)
        outboxEvents.clear()
        outboxEvents.addAll(snapshot.outboxEvents)
    }
}

class ChargebackDisputeService(
    private val depositCreditStore: ServerDepositCreditStore,
    private val compensationService: RefundReversalCompensationService,
    private val ledgerPostingService: LedgerPostingService,
    private val store: ChargebackDisputeStore,
    private val alertSink: ChargebackDisputeAlertSink = InMemoryChargebackDisputeAlertSink(),
    private val clock: Clock = Clock.systemUTC(),
) {
    private fun sha256(input: String): String {
        val digest = MessageDigest.getInstance("SHA-256")
        val hash = digest.digest(input.toByteArray(StandardCharsets.UTF_8))
        return hash.joinToString("") { "%02x".format(it) }
    }

    private fun fingerprintOpen(cmd: OpenDisputeCommand): String {
        return sha256("${cmd.tenantId}:${cmd.playerId}:${cmd.originalPaymentReference}:${cmd.externalDisputeId}:${cmd.providerId}:${cmd.providerTransactionId}:${cmd.amountMinorUnits}:${cmd.currencyCode}:${cmd.expectedVersion}")
    }

    private fun fingerprintEvidence(cmd: SubmitDisputeEvidenceCommand): String {
        return sha256("${cmd.tenantId}:${cmd.externalDisputeId}:${cmd.evidenceType}:${cmd.evidenceDocumentReference}:${cmd.expectedVersion}")
    }

    private fun fingerprintResolve(cmd: ResolveDisputeCommand): String {
        return sha256("${cmd.tenantId}:${cmd.externalDisputeId}:${cmd.resolution}:${cmd.providerResolutionReference}:${cmd.expectedVersion}")
    }

    private fun validateAdminPrincipal(principal: AuthenticatedPrincipal?, tenantId: String) {
        principal?.let {
            if (it.tenantId != tenantId) {
                throw AuthenticationFailure.Rejected(AuthErrorCode.FORBIDDEN)
            }
            if (it.kind != PrincipalKind.ADMIN) {
                throw AuthenticationFailure.Rejected(AuthErrorCode.FORBIDDEN)
            }
            if (it.roles.none { role -> role in setOf(AdminRole.SUPER_ADMIN, AdminRole.SECURITY) }) {
                throw AuthenticationFailure.Rejected(AuthErrorCode.FORBIDDEN)
            }
        }
    }

    @Synchronized
    fun openDispute(command: OpenDisputeCommand): DisputeOperationResult {
        ManageChargebackDisputesBinding.checkBound()

        // 1. Mandatory Input Validation
        if (command.tenantId.isBlank() ||
            command.originalPaymentReference.isBlank() ||
            command.externalDisputeId.isBlank() ||
            command.providerId.isBlank() ||
            command.providerTransactionId.isBlank() ||
            command.reason.isBlank() ||
            command.idempotencyKey.isBlank() ||
            command.correlationId.isBlank() ||
            command.causationId.isBlank()
        ) {
            alertSink.sendAlert(
                tenantId = command.tenantId.ifBlank { "UNKNOWN" },
                disputeId = command.externalDisputeId.ifBlank { "UNKNOWN" },
                alertType = "DISPUTE_INVALID_INPUT",
                reason = "BLANK_MANDATORY_FIELDS",
                detail = "Open dispute command rejected due to blank mandatory fields",
            )
            throw AuthenticationFailure.Rejected(AuthErrorCode.INVALID)
        }

        if (command.amountMinorUnits <= 0L || !command.currencyCode.matches(Regex("^[A-Z]{3}$"))) {
            throw AuthenticationFailure.Rejected(AuthErrorCode.INVALID)
        }

        if (command.expectedVersion != 1L) {
            throw AuthenticationFailure.Rejected(AuthErrorCode.STALE)
        }

        validateAdminPrincipal(command.principal, command.tenantId)

        val fp = fingerprintOpen(command)
        val now = clock.instant()

        // 2. Idempotency Check
        val existingIdemp = store.findByIdempotency(command.tenantId, command.idempotencyKey)
        if (existingIdemp != null) {
            val (cachedFp, cachedResult) = existingIdemp
            if (cachedFp != fp) {
                alertSink.sendAlert(
                    tenantId = command.tenantId,
                    disputeId = command.externalDisputeId,
                    alertType = "DISPUTE_IDEMPOTENCY_CONFLICT",
                    reason = "PAYLOAD_MISMATCH",
                    detail = "Payload mismatch detected for idempotency key ${command.idempotencyKey}",
                )
                throw AuthenticationFailure.Rejected(AuthErrorCode.CONFLICT)
            }
            return cachedResult.copy(isDuplicate = true)
        }

        // 3. Collision Check on External Dispute ID
        val existingDispute = store.findDisputeByExternalId(command.tenantId, command.externalDisputeId)
        if (existingDispute != null) {
            if (existingDispute.originalPaymentReference != command.originalPaymentReference ||
                existingDispute.amountMinorUnits != command.amountMinorUnits ||
                existingDispute.currencyCode != command.currencyCode
            ) {
                alertSink.sendAlert(
                    tenantId = command.tenantId,
                    disputeId = command.externalDisputeId,
                    alertType = "DISPUTE_EXTERNAL_ID_COLLISION",
                    reason = "EXTERNAL_DISPUTE_CONFLICT",
                    detail = "External dispute ID ${command.externalDisputeId} already opened with different details",
                )
                throw AuthenticationFailure.Rejected(AuthErrorCode.CONFLICT)
            }
            val cachedResult = store.findByIdempotency(command.tenantId, command.idempotencyKey)?.second
            if (cachedResult != null) return cachedResult.copy(isDuplicate = true)
        }

        // 4. Verify Original Deposit Credit
        val originalDeposit = depositCreditStore.findCreditByPaymentRef(command.tenantId, command.originalPaymentReference)
            ?: run {
                alertSink.sendAlert(
                    tenantId = command.tenantId,
                    disputeId = command.externalDisputeId,
                    alertType = "ORIGINAL_DEPOSIT_NOT_FOUND",
                    reason = "DEPOSIT_MISSING",
                    detail = "Original deposit ${command.originalPaymentReference} not found for dispute",
                )
                throw AuthenticationFailure.Rejected(AuthErrorCode.INVALID)
            }

        if (originalDeposit.playerId != command.playerId || originalDeposit.currencyCode != command.currencyCode) {
            throw AuthenticationFailure.Rejected(AuthErrorCode.INVALID)
        }

        // 5. Cumulative Dispute Over-Reversal Protection
        val existingDisputes = store.listDisputesForPayment(command.tenantId, command.originalPaymentReference)
        val alreadyDisputedMinorUnits = existingDisputes.sumOf { it.amountMinorUnits }
        val remainingDisputableMinorUnits = originalDeposit.amountMinorUnits - alreadyDisputedMinorUnits

        if (command.amountMinorUnits > remainingDisputableMinorUnits) {
            alertSink.sendAlert(
                tenantId = command.tenantId,
                disputeId = command.externalDisputeId,
                alertType = "OVER_DISPUTE_EXCEEDS_DEPOSIT_DENIED",
                reason = "EXCEEDS_ORIGINAL_DEPOSIT_AMOUNT",
                detail = "Dispute amount ${command.amountMinorUnits} exceeds remaining disputable amount $remainingDisputableMinorUnits",
            )
            throw AuthenticationFailure.Rejected(AuthErrorCode.CONFLICT)
        }

        // 6. Authoritative Compensation & Insufficient Funds Handling via PAYMENT-006-01
        // "Insufficient funds becomes risk/recovery case, never hidden negative mutation."
        val compCmd = PostCompensationCommand(
            tenantId = command.tenantId,
            playerId = command.playerId,
            originalPaymentReference = command.originalPaymentReference,
            compensationReference = "DISP-${command.externalDisputeId}",
            providerId = command.providerId,
            providerTransactionId = command.providerTransactionId,
            amountMinorUnits = command.amountMinorUnits,
            currencyCode = command.currencyCode,
            type = CompensationType.CHARGEBACK,
            reason = "Chargeback dispute opened: ${command.reason}",
            availablePlayerWalletBalanceMinorUnits = command.availablePlayerWalletBalanceMinorUnits,
            idempotencyKey = "comp-disp-${command.idempotencyKey}",
            correlationId = command.correlationId,
            causationId = command.causationId,
            expectedVersion = 1L,
            principal = command.principal,
        )

        val compResult = compensationService.postCompensation(compCmd)

        val disputeId = UUID.randomUUID()
        val evidenceRef = "DISP-EVID-$disputeId"

        val record = ChargebackDisputeRecord(
            disputeId = disputeId,
            tenantId = command.tenantId,
            playerId = command.playerId,
            originalPaymentReference = command.originalPaymentReference,
            externalDisputeId = command.externalDisputeId,
            providerId = command.providerId,
            providerTransactionId = command.providerTransactionId,
            amountMinorUnits = command.amountMinorUnits,
            currencyCode = command.currencyCode,
            reason = command.reason,
            status = DisputeStatus.OPENED,
            isDeficitRiskCase = compResult.isDeficitRiskCase,
            deficitMinorUnits = compResult.deficitMinorUnits,
            recoveredFromWalletMinorUnits = compResult.recoveredFromWalletMinorUnits,
            recoveryCaseReference = compResult.recoveryCaseReference,
            ledgerTransactionReference = compResult.ledgerTransactionReference,
            version = 1L,
            createdAt = now,
            updatedAt = now,
            semanticContract = MANAGE_CHARGEBACK_DISPUTES_CONTRACT,
        )

        val result = DisputeOperationResult(
            disputeId = disputeId,
            tenantId = command.tenantId,
            playerId = command.playerId,
            originalPaymentReference = command.originalPaymentReference,
            externalDisputeId = command.externalDisputeId,
            amountMinorUnits = command.amountMinorUnits,
            currencyCode = command.currencyCode,
            status = DisputeStatus.OPENED,
            version = 1L,
            isDeficitRiskCase = compResult.isDeficitRiskCase,
            deficitMinorUnits = compResult.deficitMinorUnits,
            recoveredFromWalletMinorUnits = compResult.recoveredFromWalletMinorUnits,
            recoveryCaseReference = compResult.recoveryCaseReference,
            ledgerTransactionReference = compResult.ledgerTransactionReference,
            isDuplicate = false,
            conserved = compResult.conserved,
            evidenceReference = evidenceRef,
            serverTime = now,
            semanticContract = MANAGE_CHARGEBACK_DISPUTES_CONTRACT,
        )

        val audit = AuditEvent(UUID.randomUUID(), disputeId, command.tenantId, "CHARGEBACK_DISPUTE_OPENED", now, command.correlationId, command.causationId)
        val outbox = OutboxEvent(UUID.randomUUID(), disputeId, command.tenantId, "CHARGEBACK_DISPUTE_OPENED", now)
        store.saveDispute(record, result, command.idempotencyKey, fp, audit, outbox)

        return result
    }

    @Synchronized
    fun submitEvidence(command: SubmitDisputeEvidenceCommand): DisputeOperationResult {
        ManageChargebackDisputesBinding.checkBound()

        if (command.tenantId.isBlank() ||
            command.externalDisputeId.isBlank() ||
            command.evidenceType.isBlank() ||
            command.evidenceDocumentReference.isBlank() ||
            command.idempotencyKey.isBlank() ||
            command.correlationId.isBlank() ||
            command.causationId.isBlank()
        ) {
            throw AuthenticationFailure.Rejected(AuthErrorCode.INVALID)
        }

        validateAdminPrincipal(command.principal, command.tenantId)

        val fp = fingerprintEvidence(command)
        val now = clock.instant()

        val existingIdemp = store.findByIdempotency(command.tenantId, command.idempotencyKey)
        if (existingIdemp != null) {
            val (cachedFp, cachedResult) = existingIdemp
            if (cachedFp != fp) {
                throw AuthenticationFailure.Rejected(AuthErrorCode.CONFLICT)
            }
            return cachedResult.copy(isDuplicate = true)
        }

        val dispute = store.findDisputeByExternalId(command.tenantId, command.externalDisputeId)
            ?: throw AuthenticationFailure.Rejected(AuthErrorCode.INVALID)

        if (dispute.version != command.expectedVersion) {
            throw AuthenticationFailure.Rejected(AuthErrorCode.STALE)
        }

        if (dispute.status != DisputeStatus.OPENED) {
            throw AuthenticationFailure.Rejected(AuthErrorCode.CONFLICT)
        }

        val updatedRecord = dispute.copy(
            status = DisputeStatus.EVIDENCE_SUBMITTED,
            evidenceDocumentReference = command.evidenceDocumentReference,
            version = dispute.version + 1,
            updatedAt = now,
        )

        val result = DisputeOperationResult(
            disputeId = dispute.disputeId,
            tenantId = dispute.tenantId,
            playerId = dispute.playerId,
            originalPaymentReference = dispute.originalPaymentReference,
            externalDisputeId = dispute.externalDisputeId,
            amountMinorUnits = dispute.amountMinorUnits,
            currencyCode = dispute.currencyCode,
            status = DisputeStatus.EVIDENCE_SUBMITTED,
            version = updatedRecord.version,
            isDeficitRiskCase = dispute.isDeficitRiskCase,
            deficitMinorUnits = dispute.deficitMinorUnits,
            recoveredFromWalletMinorUnits = dispute.recoveredFromWalletMinorUnits,
            recoveryCaseReference = dispute.recoveryCaseReference,
            ledgerTransactionReference = dispute.ledgerTransactionReference,
            isDuplicate = false,
            conserved = true,
            evidenceReference = command.evidenceDocumentReference,
            serverTime = now,
            semanticContract = MANAGE_CHARGEBACK_DISPUTES_CONTRACT,
        )

        val audit = AuditEvent(UUID.randomUUID(), dispute.disputeId, command.tenantId, "DISPUTE_EVIDENCE_SUBMITTED", now, command.correlationId, command.causationId)
        val outbox = OutboxEvent(UUID.randomUUID(), dispute.disputeId, command.tenantId, "DISPUTE_EVIDENCE_SUBMITTED", now)
        store.updateDispute(updatedRecord, result, command.idempotencyKey, fp, audit, outbox)

        return result
    }

    @Synchronized
    fun resolveDispute(command: ResolveDisputeCommand): DisputeOperationResult {
        ManageChargebackDisputesBinding.checkBound()

        if (command.tenantId.isBlank() ||
            command.externalDisputeId.isBlank() ||
            command.providerResolutionReference.isBlank() ||
            command.idempotencyKey.isBlank() ||
            command.correlationId.isBlank() ||
            command.causationId.isBlank()
        ) {
            throw AuthenticationFailure.Rejected(AuthErrorCode.INVALID)
        }

        validateAdminPrincipal(command.principal, command.tenantId)

        val fp = fingerprintResolve(command)
        val now = clock.instant()

        val existingIdemp = store.findByIdempotency(command.tenantId, command.idempotencyKey)
        if (existingIdemp != null) {
            val (cachedFp, cachedResult) = existingIdemp
            if (cachedFp != fp) {
                throw AuthenticationFailure.Rejected(AuthErrorCode.CONFLICT)
            }
            return cachedResult.copy(isDuplicate = true)
        }

        val dispute = store.findDisputeByExternalId(command.tenantId, command.externalDisputeId)
            ?: throw AuthenticationFailure.Rejected(AuthErrorCode.INVALID)

        if (dispute.version != command.expectedVersion) {
            throw AuthenticationFailure.Rejected(AuthErrorCode.STALE)
        }

        if (dispute.status == DisputeStatus.RESOLVED_WON || dispute.status == DisputeStatus.RESOLVED_LOST) {
            throw AuthenticationFailure.Rejected(AuthErrorCode.CONFLICT)
        }

        val nextStatus = when (command.resolution) {
            DisputeResolution.WON -> DisputeStatus.RESOLVED_WON
            DisputeResolution.LOST -> DisputeStatus.RESOLVED_LOST
        }

        var ledgerTxRef = dispute.ledgerTransactionReference

        // When dispute is WON, the merchant proved valid deposit!
        // We post a restorative double-entry batch:
        // Debit: gateway clearing
        // Credit: player wallet (for recovered amount) + risk recovery (for deficit amount)
        if (command.resolution == DisputeResolution.WON) {
            val restoreTxRef = "TX-DISP-WON-${command.externalDisputeId}"
            val entries = mutableListOf<JournalEntryDraft>()

            entries.add(
                JournalEntryDraft(
                    accountReference = "gateway:clearing:${dispute.providerId}",
                    direction = JournalEntryDirection.DEBIT,
                    amountMinorUnits = dispute.amountMinorUnits,
                    currencyCode = dispute.currencyCode,
                    narration = "Restoring funds from gateway clearing: dispute ${dispute.externalDisputeId} WON",
                )
            )

            if (dispute.recoveredFromWalletMinorUnits > 0L) {
                entries.add(
                    JournalEntryDraft(
                        accountReference = "player:wallet:${dispute.playerId}",
                        direction = JournalEntryDirection.CREDIT,
                        amountMinorUnits = dispute.recoveredFromWalletMinorUnits,
                        currencyCode = dispute.currencyCode,
                        narration = "Restoring recovered funds to player wallet: dispute ${dispute.externalDisputeId} WON",
                    )
                )
            }

            if (dispute.deficitMinorUnits > 0L) {
                entries.add(
                    JournalEntryDraft(
                        accountReference = "risk:recovery:${dispute.playerId}",
                        direction = JournalEntryDirection.CREDIT,
                        amountMinorUnits = dispute.deficitMinorUnits,
                        currencyCode = dispute.currencyCode,
                        narration = "Clearing deficit risk receivable: dispute ${dispute.externalDisputeId} WON",
                    )
                )
            }

            val adminPrincipal = command.principal ?: AuthenticatedPrincipal(
                id = "sys-dispute-worker",
                tenantId = command.tenantId,
                kind = PrincipalKind.ADMIN,
                roles = setOf(AdminRole.SUPER_ADMIN),
            )

            val postCommand = PostTransactionCommand(
                principal = adminPrincipal,
                tenantId = command.tenantId,
                transactionReference = restoreTxRef,
                currencyCode = dispute.currencyCode,
                entries = entries,
                idempotencyKey = "ledger-disp-won-${command.idempotencyKey}",
                correlationId = command.correlationId,
                causationId = command.causationId,
            )

            try {
                ledgerPostingService.postTransaction(postCommand)
                ledgerTxRef = restoreTxRef
                alertSink.sendAlert(
                    tenantId = command.tenantId,
                    disputeId = command.externalDisputeId,
                    alertType = "DISPUTE_WON_FUNDS_RESTORED",
                    reason = "DISPUTE_WON",
                    detail = "Dispute ${command.externalDisputeId} resolved WON. Restored ${dispute.amountMinorUnits} ${dispute.currencyCode} from gateway.",
                )
            } catch (e: Exception) {
                alertSink.sendAlert(
                    tenantId = command.tenantId,
                    disputeId = command.externalDisputeId,
                    alertType = "DISPUTE_RESOLUTION_LEDGER_FAILED",
                    reason = "LEDGER_FAILURE",
                    detail = "Failed to post dispute won restoration transaction: ${e.message}",
                )
                throw AuthenticationFailure.Rejected(AuthErrorCode.DEPENDENCY_UNAVAILABLE)
            }
        }

        val updatedRecord = dispute.copy(
            status = nextStatus,
            providerResolutionReference = command.providerResolutionReference,
            ledgerTransactionReference = ledgerTxRef,
            version = dispute.version + 1,
            updatedAt = now,
        )

        val result = DisputeOperationResult(
            disputeId = dispute.disputeId,
            tenantId = dispute.tenantId,
            playerId = dispute.playerId,
            originalPaymentReference = dispute.originalPaymentReference,
            externalDisputeId = dispute.externalDisputeId,
            amountMinorUnits = dispute.amountMinorUnits,
            currencyCode = dispute.currencyCode,
            status = nextStatus,
            version = updatedRecord.version,
            isDeficitRiskCase = dispute.isDeficitRiskCase,
            deficitMinorUnits = dispute.deficitMinorUnits,
            recoveredFromWalletMinorUnits = dispute.recoveredFromWalletMinorUnits,
            recoveryCaseReference = dispute.recoveryCaseReference,
            ledgerTransactionReference = ledgerTxRef,
            isDuplicate = false,
            conserved = true,
            evidenceReference = "RES-EVID-${UUID.randomUUID()}",
            serverTime = now,
            semanticContract = MANAGE_CHARGEBACK_DISPUTES_CONTRACT,
        )

        val eventType = if (nextStatus == DisputeStatus.RESOLVED_WON) "DISPUTE_RESOLVED_WON" else "DISPUTE_RESOLVED_LOST"
        val audit = AuditEvent(UUID.randomUUID(), dispute.disputeId, command.tenantId, eventType, now, command.correlationId, command.causationId)
        val outbox = OutboxEvent(UUID.randomUUID(), dispute.disputeId, command.tenantId, eventType, now)
        store.updateDispute(updatedRecord, result, command.idempotencyKey, fp, audit, outbox)

        return result
    }
}
