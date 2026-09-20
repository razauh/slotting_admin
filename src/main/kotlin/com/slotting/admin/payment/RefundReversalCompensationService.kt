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
 * Fail-closed verification gate for PAYMENT-006-01: Post refund and reversal compensation.
 * Throws expected RED failure until contract bindings and invariant protections are verified.
 * Protected risk: False completion or non-authoritative implementation of Post refund and reversal compensation.
 * Rationale: It exists to prevent: edit/delete credit or duplicate reversal.
 */
object RefundReversalCompensationBinding {
    @Volatile
    var isBound: Boolean = false

    fun checkBound() {
        if (!isBound) {
            throw AssertionError("edit/delete credit or duplicate reversal")
        }
    }
}

/**
 * Outcome-specific semantic contract for PAYMENT-006-01.
 */
const val REFUND_REVERSAL_COMPENSATION_CONTRACT =
    "Insufficient funds becomes risk/recovery case, never hidden negative mutation."

enum class CompensationType {
    REFUND,
    REVERSAL,
    CHARGEBACK,
}

enum class CompensationStatus {
    COMPLETED,
    RECOVERY_CASE_OPENED,
}

data class PostCompensationCommand(
    val tenantId: String,
    val playerId: UUID,
    val originalPaymentReference: String,
    val compensationReference: String,
    val providerId: String,
    val providerTransactionId: String,
    val amountMinorUnits: Long,
    val currencyCode: String,
    val type: CompensationType,
    val reason: String,
    val availablePlayerWalletBalanceMinorUnits: Long? = null,
    val idempotencyKey: String,
    val correlationId: String,
    val causationId: String,
    val expectedVersion: Long = 1L,
    val principal: AuthenticatedPrincipal? = null,
)

data class CompensationResult(
    val compensationId: UUID,
    val tenantId: String,
    val playerId: UUID,
    val originalPaymentReference: String,
    val compensationReference: String,
    val providerTransactionId: String,
    val amountMinorUnits: Long,
    val currencyCode: String,
    val type: CompensationType,
    val status: CompensationStatus,
    val isDeficitRiskCase: Boolean,
    val deficitMinorUnits: Long,
    val recoveredFromWalletMinorUnits: Long,
    val recoveryCaseReference: String?,
    val ledgerTransactionReference: String,
    val isDuplicate: Boolean,
    val conserved: Boolean,
    val totalDebitsMinorUnits: Long,
    val totalCreditsMinorUnits: Long,
    val evidenceReference: String,
    val serverTime: Instant,
    val semanticContract: String = REFUND_REVERSAL_COMPENSATION_CONTRACT,
)

data class RefundReversalRecord(
    val compensationId: UUID,
    val tenantId: String,
    val playerId: UUID,
    val originalPaymentReference: String,
    val compensationReference: String,
    val providerTransactionId: String,
    val amountMinorUnits: Long,
    val currencyCode: String,
    val type: CompensationType,
    val status: CompensationStatus,
    val isDeficitRiskCase: Boolean,
    val deficitMinorUnits: Long,
    val recoveredFromWalletMinorUnits: Long,
    val recoveryCaseReference: String?,
    val ledgerTransactionReference: String,
    val idempotencyKey: String,
    val evidenceReference: String,
    val createdAt: Instant,
    val version: Long = 1L,
    val semanticContract: String = REFUND_REVERSAL_COMPENSATION_CONTRACT,
)

data class RefundReversalSnapshot(
    val compensations: Map<String, RefundReversalRecord>,
    val compensationsByRef: Map<String, RefundReversalRecord>,
    val compensationsByTx: Map<String, RefundReversalRecord>,
    val idempotencyMap: Map<String, Pair<String, CompensationResult>>,
    val auditEvents: List<AuditEvent>,
    val outboxEvents: List<OutboxEvent>,
)

interface RefundReversalAlertSink {
    fun sendAlert(tenantId: String, paymentReference: String, alertType: String, reason: String, detail: String)
}

class InMemoryRefundReversalAlertSink : RefundReversalAlertSink {
    val alerts = mutableListOf<String>()

    @Synchronized
    override fun sendAlert(tenantId: String, paymentReference: String, alertType: String, reason: String, detail: String) {
        alerts.add("$tenantId:$paymentReference:$alertType:$reason:$detail")
    }
}

interface RefundReversalStore {
    fun findCompensationById(tenantId: String, compensationId: UUID): RefundReversalRecord?
    fun findCompensationByRef(tenantId: String, compensationReference: String): RefundReversalRecord?
    fun findCompensationByTxId(tenantId: String, providerTransactionId: String): RefundReversalRecord?
    fun findByIdempotency(tenantId: String, idempotencyKey: String): Pair<String, CompensationResult>?
    fun listCompensationsForDeposit(tenantId: String, originalPaymentReference: String): List<RefundReversalRecord>
    fun saveCompensation(
        record: RefundReversalRecord,
        result: CompensationResult,
        idempotencyKey: String,
        fingerprint: String,
        audit: AuditEvent,
        outbox: OutboxEvent,
    )
    fun getAuditEvents(): List<AuditEvent>
    fun getOutboxEvents(): List<OutboxEvent>
    fun exportSnapshot(): RefundReversalSnapshot
    fun importSnapshot(snapshot: RefundReversalSnapshot)
}

class InMemoryRefundReversalStore : RefundReversalStore {
    private val compensations = ConcurrentHashMap<UUID, RefundReversalRecord>()
    private val compensationsByRef = ConcurrentHashMap<String, RefundReversalRecord>()
    private val compensationsByTx = ConcurrentHashMap<String, RefundReversalRecord>()
    private val idempotencyResults = ConcurrentHashMap<String, Pair<String, CompensationResult>>()
    private val auditEvents = mutableListOf<AuditEvent>()
    private val outboxEvents = mutableListOf<OutboxEvent>()

    private fun refKey(tenantId: String, ref: String) = "$tenantId:$ref"
    private fun txKey(tenantId: String, txId: String) = "$tenantId:$txId"
    private fun idempKey(tenantId: String, key: String) = "$tenantId:$key"

    @Synchronized
    override fun findCompensationById(tenantId: String, compensationId: UUID): RefundReversalRecord? =
        compensations[compensationId]?.takeIf { it.tenantId == tenantId }?.copy()

    @Synchronized
    override fun findCompensationByRef(tenantId: String, compensationReference: String): RefundReversalRecord? =
        compensationsByRef[refKey(tenantId, compensationReference)]?.copy()

    @Synchronized
    override fun findCompensationByTxId(tenantId: String, providerTransactionId: String): RefundReversalRecord? =
        compensationsByTx[txKey(tenantId, providerTransactionId)]?.copy()

    @Synchronized
    override fun findByIdempotency(tenantId: String, idempotencyKey: String): Pair<String, CompensationResult>? =
        idempotencyResults[idempKey(tenantId, idempotencyKey)]

    @Synchronized
    override fun listCompensationsForDeposit(tenantId: String, originalPaymentReference: String): List<RefundReversalRecord> =
        compensations.values.filter { it.tenantId == tenantId && it.originalPaymentReference == originalPaymentReference }.map { it.copy() }

    @Synchronized
    override fun saveCompensation(
        record: RefundReversalRecord,
        result: CompensationResult,
        idempotencyKey: String,
        fingerprint: String,
        audit: AuditEvent,
        outbox: OutboxEvent,
    ) {
        compensations[record.compensationId] = record.copy()
        compensationsByRef[refKey(record.tenantId, record.compensationReference)] = record.copy()
        compensationsByTx[txKey(record.tenantId, record.providerTransactionId)] = record.copy()
        idempotencyResults[idempKey(record.tenantId, idempotencyKey)] = fingerprint to result
        auditEvents.add(audit)
        outboxEvents.add(outbox)
    }

    @Synchronized
    override fun getAuditEvents(): List<AuditEvent> = auditEvents.toList()

    @Synchronized
    override fun getOutboxEvents(): List<OutboxEvent> = outboxEvents.toList()

    @Synchronized
    override fun exportSnapshot(): RefundReversalSnapshot {
        val idMap = HashMap<String, RefundReversalRecord>()
        for ((k, v) in compensations) {
            idMap[k.toString()] = v.copy()
        }
        return RefundReversalSnapshot(
            compensations = idMap,
            compensationsByRef = HashMap(compensationsByRef),
            compensationsByTx = HashMap(compensationsByTx),
            idempotencyMap = HashMap(idempotencyResults),
            auditEvents = ArrayList(auditEvents),
            outboxEvents = ArrayList(outboxEvents),
        )
    }

    @Synchronized
    override fun importSnapshot(snapshot: RefundReversalSnapshot) {
        compensations.clear()
        for ((k, v) in snapshot.compensations) {
            compensations[UUID.fromString(k)] = v.copy()
        }
        compensationsByRef.clear()
        compensationsByRef.putAll(snapshot.compensationsByRef)
        compensationsByTx.clear()
        compensationsByTx.putAll(snapshot.compensationsByTx)
        idempotencyResults.clear()
        idempotencyResults.putAll(snapshot.idempotencyMap)
        auditEvents.clear()
        auditEvents.addAll(snapshot.auditEvents)
        outboxEvents.clear()
        outboxEvents.addAll(snapshot.outboxEvents)
    }
}

class RefundReversalCompensationService(
    private val depositCreditStore: ServerDepositCreditStore,
    private val ledgerPostingService: LedgerPostingService,
    private val store: RefundReversalStore,
    private val alertSink: RefundReversalAlertSink = InMemoryRefundReversalAlertSink(),
    private val clock: Clock = Clock.systemUTC(),
) {
    private fun sha256(input: String): String {
        val digest = MessageDigest.getInstance("SHA-256")
        val hash = digest.digest(input.toByteArray(StandardCharsets.UTF_8))
        return hash.joinToString("") { "%02x".format(it) }
    }

    private fun fingerprint(cmd: PostCompensationCommand): String {
        return sha256("${cmd.tenantId}:${cmd.playerId}:${cmd.originalPaymentReference}:${cmd.compensationReference}:${cmd.providerId}:${cmd.providerTransactionId}:${cmd.amountMinorUnits}:${cmd.currencyCode}:${cmd.type}:${cmd.expectedVersion}")
    }

    @Synchronized
    fun postCompensation(command: PostCompensationCommand): CompensationResult {
        // Protected risk assertion: edit/delete credit or duplicate reversal
        RefundReversalCompensationBinding.checkBound()

        // 1. Mandatory Input Validation
        if (command.tenantId.isBlank() ||
            command.originalPaymentReference.isBlank() ||
            command.compensationReference.isBlank() ||
            command.providerId.isBlank() ||
            command.providerTransactionId.isBlank() ||
            command.reason.isBlank() ||
            command.idempotencyKey.isBlank() ||
            command.correlationId.isBlank() ||
            command.causationId.isBlank()
        ) {
            alertSink.sendAlert(
                tenantId = command.tenantId.ifBlank { "UNKNOWN" },
                paymentReference = command.originalPaymentReference.ifBlank { "UNKNOWN" },
                alertType = "COMPENSATION_INVALID_INPUT",
                reason = "BLANK_MANDATORY_FIELDS",
                detail = "Post compensation command rejected due to blank mandatory fields",
            )
            throw AuthenticationFailure.Rejected(AuthErrorCode.INVALID)
        }

        if (command.amountMinorUnits <= 0L || !command.currencyCode.matches(Regex("^[A-Z]{3}$"))) {
            throw AuthenticationFailure.Rejected(AuthErrorCode.INVALID)
        }

        if (command.expectedVersion != 1L) {
            throw AuthenticationFailure.Rejected(AuthErrorCode.STALE)
        }

        // 2. Principal Authorization Check
        command.principal?.let { principal ->
            if (principal.tenantId != command.tenantId) {
                throw AuthenticationFailure.Rejected(AuthErrorCode.FORBIDDEN)
            }
            if (principal.kind != PrincipalKind.ADMIN) {
                throw AuthenticationFailure.Rejected(AuthErrorCode.FORBIDDEN)
            }
            if (principal.roles.none { it in setOf(AdminRole.SUPER_ADMIN, AdminRole.SECURITY) }) {
                throw AuthenticationFailure.Rejected(AuthErrorCode.FORBIDDEN)
            }
        }

        val fp = fingerprint(command)
        val now = clock.instant()

        // 3. Idempotency Check: By Idempotency Key
        val existingIdemp = store.findByIdempotency(command.tenantId, command.idempotencyKey)
        if (existingIdemp != null) {
            val (cachedFp, cachedResult) = existingIdemp
            if (cachedFp != fp) {
                alertSink.sendAlert(
                    tenantId = command.tenantId,
                    paymentReference = command.originalPaymentReference,
                    alertType = "COMPENSATION_IDEMPOTENCY_CONFLICT",
                    reason = "PAYLOAD_MISMATCH",
                    detail = "Payload conflict detected under idempotency key ${command.idempotencyKey}",
                )
                throw AuthenticationFailure.Rejected(AuthErrorCode.CONFLICT)
            }
            return cachedResult.copy(isDuplicate = true)
        }

        // 4. Duplicate Reversal Check: Same compensation reference already used
        val existingByRef = store.findCompensationByRef(command.tenantId, command.compensationReference)
        if (existingByRef != null) {
            if (existingByRef.providerTransactionId != command.providerTransactionId ||
                existingByRef.amountMinorUnits != command.amountMinorUnits ||
                existingByRef.currencyCode != command.currencyCode ||
                existingByRef.originalPaymentReference != command.originalPaymentReference
            ) {
                alertSink.sendAlert(
                    tenantId = command.tenantId,
                    paymentReference = command.originalPaymentReference,
                    alertType = "DUPLICATE_REVERSAL_CONFLICT",
                    reason = "COMPENSATION_REFERENCE_COLLISION",
                    detail = "Compensation reference ${command.compensationReference} already exists with differing payload",
                )
                throw AuthenticationFailure.Rejected(AuthErrorCode.CONFLICT)
            }
            val cachedResult = store.findByIdempotency(command.tenantId, existingByRef.idempotencyKey)?.second
            if (cachedResult != null) {
                return cachedResult.copy(isDuplicate = true)
            }
        }

        // Check providerTransactionId uniqueness across tenant
        val existingByTx = store.findCompensationByTxId(command.tenantId, command.providerTransactionId)
        if (existingByTx != null) {
            if (existingByTx.compensationReference != command.compensationReference ||
                existingByTx.amountMinorUnits != command.amountMinorUnits
            ) {
                alertSink.sendAlert(
                    tenantId = command.tenantId,
                    paymentReference = command.originalPaymentReference,
                    alertType = "DUPLICATE_REVERSAL_CONFLICT",
                    reason = "PROVIDER_TRANSACTION_COLLISION",
                    detail = "Provider transaction ${command.providerTransactionId} already used for compensation",
                )
                throw AuthenticationFailure.Rejected(AuthErrorCode.CONFLICT)
            }
        }

        // 5. Original Deposit Verification: Never edit or delete deposit credit
        val originalDeposit = depositCreditStore.findCreditByPaymentRef(command.tenantId, command.originalPaymentReference)
            ?: run {
                alertSink.sendAlert(
                    tenantId = command.tenantId,
                    paymentReference = command.originalPaymentReference,
                    alertType = "ORIGINAL_DEPOSIT_NOT_FOUND",
                    reason = "DEPOSIT_MISSING",
                    detail = "Original deposit ${command.originalPaymentReference} not found for compensation",
                )
                throw AuthenticationFailure.Rejected(AuthErrorCode.INVALID)
            }

        if (originalDeposit.playerId != command.playerId || originalDeposit.currencyCode != command.currencyCode) {
            throw AuthenticationFailure.Rejected(AuthErrorCode.INVALID)
        }

        // 6. Cumulative Reversal Over-Reversal Protection:
        // Prevents reversing more money than was originally deposited
        val existingCompensations = store.listCompensationsForDeposit(command.tenantId, command.originalPaymentReference)
        val alreadyReversedMinorUnits = existingCompensations.sumOf { it.amountMinorUnits }
        val remainingReversibleMinorUnits = originalDeposit.amountMinorUnits - alreadyReversedMinorUnits

        if (command.amountMinorUnits > remainingReversibleMinorUnits) {
            alertSink.sendAlert(
                tenantId = command.tenantId,
                paymentReference = command.originalPaymentReference,
                alertType = "OVER_REVERSAL_EXCEEDS_DEPOSIT_DENIED",
                reason = "EXCEEDS_ORIGINAL_DEPOSIT_AMOUNT",
                detail = "Attempted reversal of ${command.amountMinorUnits} exceeds remaining reversible amount $remainingReversibleMinorUnits (original deposit: ${originalDeposit.amountMinorUnits}, already reversed: $alreadyReversedMinorUnits)",
            )
            throw AuthenticationFailure.Rejected(AuthErrorCode.CONFLICT)
        }

        // 7. Outcome-specific semantic contract:
        // "Insufficient funds becomes risk/recovery case, never hidden negative mutation."
        val availableWalletBalance = command.availablePlayerWalletBalanceMinorUnits ?: Long.MAX_VALUE
        val isDeficit = availableWalletBalance < command.amountMinorUnits

        val recoveredFromWalletMinorUnits: Long
        val deficitMinorUnits: Long
        val status: CompensationStatus
        val recoveryCaseReference: String?

        if (isDeficit) {
            recoveredFromWalletMinorUnits = maxOf(0L, availableWalletBalance)
            deficitMinorUnits = command.amountMinorUnits - recoveredFromWalletMinorUnits
            status = CompensationStatus.RECOVERY_CASE_OPENED
            recoveryCaseReference = "RCV-CASE-${UUID.randomUUID()}"

            alertSink.sendAlert(
                tenantId = command.tenantId,
                paymentReference = command.originalPaymentReference,
                alertType = "INSUFFICIENT_FUNDS_RECOVERY_CASE_CREATED",
                reason = "DEFICIT_ROUTED_TO_RECOVERY",
                detail = "Player available balance ($availableWalletBalance) insufficient for compensation (${command.amountMinorUnits}). Created recovery case $recoveryCaseReference for deficit $deficitMinorUnits.",
            )
        } else {
            recoveredFromWalletMinorUnits = command.amountMinorUnits
            deficitMinorUnits = 0L
            status = CompensationStatus.COMPLETED
            recoveryCaseReference = null
        }

        // 8. Construct Balanced Double-Entry Journal Entries
        // Total Debits = recoveredFromWalletMinorUnits + deficitMinorUnits = command.amountMinorUnits
        // Total Credits = command.amountMinorUnits
        val ledgerTxRef = "TX-COMP-${command.compensationReference}"
        val journalEntries = mutableListOf<JournalEntryDraft>()

        if (recoveredFromWalletMinorUnits > 0L) {
            journalEntries.add(
                JournalEntryDraft(
                    accountReference = "player:wallet:${command.playerId}",
                    direction = JournalEntryDirection.DEBIT,
                    amountMinorUnits = recoveredFromWalletMinorUnits,
                    currencyCode = command.currencyCode,
                    narration = "Reversal compensation from wallet for ${command.originalPaymentReference} (${command.type})",
                )
            )
        }

        if (deficitMinorUnits > 0L) {
            journalEntries.add(
                JournalEntryDraft(
                    accountReference = "risk:recovery:${command.playerId}",
                    direction = JournalEntryDirection.DEBIT,
                    amountMinorUnits = deficitMinorUnits,
                    currencyCode = command.currencyCode,
                    narration = "Deficit recovery receivable for ${command.originalPaymentReference} case $recoveryCaseReference",
                )
            )
        }

        journalEntries.add(
            JournalEntryDraft(
                accountReference = "gateway:clearing:${command.providerId}",
                direction = JournalEntryDirection.CREDIT,
                amountMinorUnits = command.amountMinorUnits,
                currencyCode = command.currencyCode,
                narration = "Gateway clearing credit compensation for ${command.originalPaymentReference}",
            )
        )

        val adminPrincipal = command.principal ?: AuthenticatedPrincipal(
            id = "sys-reversal-worker",
            tenantId = command.tenantId,
            kind = PrincipalKind.ADMIN,
            roles = setOf(AdminRole.SUPER_ADMIN),
        )

        val postCommand = PostTransactionCommand(
            principal = adminPrincipal,
            tenantId = command.tenantId,
            transactionReference = ledgerTxRef,
            currencyCode = command.currencyCode,
            entries = journalEntries,
            idempotencyKey = "ledger-comp-${command.idempotencyKey}",
            correlationId = command.correlationId,
            causationId = command.causationId,
        )

        val postingResult = try {
            ledgerPostingService.postTransaction(postCommand)
        } catch (e: Exception) {
            alertSink.sendAlert(
                tenantId = command.tenantId,
                paymentReference = command.originalPaymentReference,
                alertType = "COMPENSATION_LEDGER_POSTING_FAILED",
                reason = "LEDGER_FAILURE",
                detail = "Failed to post compensation transaction to ledger: ${e.message}",
            )
            throw AuthenticationFailure.Rejected(AuthErrorCode.DEPENDENCY_UNAVAILABLE)
        }

        val compensationId = UUID.randomUUID()
        val evidenceRef = "COMP-EVID-$compensationId"

        val record = RefundReversalRecord(
            compensationId = compensationId,
            tenantId = command.tenantId,
            playerId = command.playerId,
            originalPaymentReference = command.originalPaymentReference,
            compensationReference = command.compensationReference,
            providerTransactionId = command.providerTransactionId,
            amountMinorUnits = command.amountMinorUnits,
            currencyCode = command.currencyCode,
            type = command.type,
            status = status,
            isDeficitRiskCase = isDeficit,
            deficitMinorUnits = deficitMinorUnits,
            recoveredFromWalletMinorUnits = recoveredFromWalletMinorUnits,
            recoveryCaseReference = recoveryCaseReference,
            ledgerTransactionReference = ledgerTxRef,
            idempotencyKey = command.idempotencyKey,
            evidenceReference = evidenceRef,
            createdAt = now,
            version = 1L,
            semanticContract = REFUND_REVERSAL_COMPENSATION_CONTRACT,
        )

        val result = CompensationResult(
            compensationId = compensationId,
            tenantId = command.tenantId,
            playerId = command.playerId,
            originalPaymentReference = command.originalPaymentReference,
            compensationReference = command.compensationReference,
            providerTransactionId = command.providerTransactionId,
            amountMinorUnits = command.amountMinorUnits,
            currencyCode = command.currencyCode,
            type = command.type,
            status = status,
            isDeficitRiskCase = isDeficit,
            deficitMinorUnits = deficitMinorUnits,
            recoveredFromWalletMinorUnits = recoveredFromWalletMinorUnits,
            recoveryCaseReference = recoveryCaseReference,
            ledgerTransactionReference = ledgerTxRef,
            isDuplicate = false,
            conserved = postingResult.isBalanced,
            totalDebitsMinorUnits = postingResult.totalDebitsMinorUnits,
            totalCreditsMinorUnits = postingResult.totalCreditsMinorUnits,
            evidenceReference = evidenceRef,
            serverTime = now,
            semanticContract = REFUND_REVERSAL_COMPENSATION_CONTRACT,
        )

        val eventType = if (isDeficit) "REVERSAL_RECOVERY_CASE_OPENED" else "COMPENSATION_POSTED"
        val audit = AuditEvent(UUID.randomUUID(), compensationId, command.tenantId, eventType, now, command.correlationId, command.causationId)
        val outbox = OutboxEvent(UUID.randomUUID(), compensationId, command.tenantId, eventType, now)

        store.saveCompensation(record, result, command.idempotencyKey, fp, audit, outbox)

        return result
    }
}
