package com.slotting.admin.payment

import com.slotting.admin.auth.*
import com.slotting.admin.identity.ServerEligibilityStore
import java.security.MessageDigest
import java.time.Clock
import java.time.Instant
import java.util.UUID
import java.util.concurrent.ConcurrentHashMap

/**
 * Fail-closed verification gate for PAYMENT-002: Deposit state machine.
 * Throws expected RED failure until contract bindings and invariant protections are verified.
 * Protected risk: False completion or non-authoritative implementation of Deposit state machine.
 * Rationale: It exists to prevent: illegal transition/replay.
 */
object DepositStateMachineBinding {
    @Volatile
    var isBound: Boolean = false

    fun checkBound() {
        if (!isBound) {
            throw AssertionError("illegal transition/replay")
        }
    }
}

/**
 * Outcome-specific semantic contract for PAYMENT-002.
 */
const val DEPOSIT_STATE_MACHINE_CONTRACT =
    "Amount/currency/routing server validated; return URL is informational only."

enum class DepositStatus {
    INITIATED,
    PENDING,
    SUCCEEDED,
    FAILED,
    REVERSED,
}

data class InitiateDepositCommand(
    val principal: AuthenticatedPrincipal?,
    val sessionId: String,
    val tenantId: String,
    val playerId: UUID,
    val depositReference: String,
    val amountMinorUnits: Long,
    val currencyCode: String,
    val providerId: String,
    val returnUrl: String,
    val eligibilityDecisionId: UUID,
    val eligibilityDecisionVersion: Long,
    val idempotencyKey: String,
    val correlationId: String,
    val causationId: String,
    val expectedVersion: Long = 1L,
)

data class TransitionDepositCommand(
    val principal: AuthenticatedPrincipal? = null,
    val sessionId: String? = null,
    val tenantId: String,
    val depositReference: String,
    val targetStatus: DepositStatus,
    val externalTransactionReference: String? = null,
    val failureReason: String? = null,
    val returnUrlParameterPayload: String? = null,
    val idempotencyKey: String,
    val correlationId: String,
    val causationId: String,
    val expectedVersion: Long,
    val deliverySequence: Long = 1L,
)

data class CompensateDepositCommand(
    val principal: AuthenticatedPrincipal?,
    val sessionId: String,
    val tenantId: String,
    val depositReference: String,
    val originalDebitMinorUnits: Long,
    val compensatingCreditMinorUnits: Long,
    val currencyCode: String,
    val reason: String,
    val idempotencyKey: String,
    val correlationId: String,
    val causationId: String,
    val expectedVersion: Long,
)

data class ProcessDepositWebhookCommand(
    val tenantId: String,
    val providerId: String,
    val signatureHeader: String,
    val rawPayload: String,
    val idempotencyKey: String,
    val correlationId: String,
    val causationId: String,
    val expectedVersion: Long = 1L,
    val deliverySequence: Long = 1L,
)

data class DepositRecord(
    val depositId: UUID,
    val depositReference: String,
    val tenantId: String,
    val playerId: UUID,
    val amountMinorUnits: Long,
    val currencyCode: String,
    val providerId: String,
    val returnUrl: String,
    val returnUrlIsInformationalOnly: Boolean = true,
    val status: DepositStatus,
    val externalTransactionReference: String? = null,
    val safeReasonCode: String,
    val debitMinorUnits: Long,
    val creditMinorUnits: Long,
    val conserved: Boolean,
    val eligibilityDecisionId: UUID,
    val eligibilityDecisionVersion: Long,
    val version: Long,
    val createdAt: Instant,
    val updatedAt: Instant,
    val evidenceReference: String,
    val semanticContract: String = DEPOSIT_STATE_MACHINE_CONTRACT,
)

data class DepositCompensationResult(
    val resultId: UUID,
    val depositReference: String,
    val tenantId: String,
    val playerId: UUID,
    val debitMinorUnits: Long,
    val creditMinorUnits: Long,
    val conserved: Boolean,
    val immutableCompensationReference: String,
    val serverTime: Instant,
    val evidenceReference: String,
    val semanticContract: String = DEPOSIT_STATE_MACHINE_CONTRACT,
)

data class DepositStoreSnapshot(
    val deposits: Map<String, DepositRecord>,
    val idempotencyMap: Map<String, Pair<String, DepositRecord>>,
    val compensations: Map<String, Pair<String, DepositCompensationResult>>,
    val sequences: Map<String, Long>,
    val auditEvents: List<AuditEvent>,
    val outboxEvents: List<OutboxEvent>,
)

interface DepositAlertSink {
    fun sendAlert(tenantId: String, depositReference: String, alertType: String, message: String)
}

class InMemoryDepositAlertSink : DepositAlertSink {
    val alerts = mutableListOf<String>()
    override fun sendAlert(tenantId: String, depositReference: String, alertType: String, message: String) {
        alerts.add("$tenantId:$depositReference:$alertType:$message")
    }
}

interface DepositStateMachineStore {
    fun findDeposit(tenantId: String, depositReference: String): DepositRecord?
    fun findByIdempotency(tenantId: String, idempotencyKey: String): Pair<String, DepositRecord>?
    fun findCompensationByIdempotency(tenantId: String, idempotencyKey: String): Pair<String, DepositCompensationResult>?
    fun getLastSequence(tenantId: String, depositReference: String): Long
    fun saveDeposit(
        record: DepositRecord,
        tenantId: String,
        queryFingerprint: String,
        idempotencyKey: String,
        sequence: Long,
        audit: AuditEvent,
        outbox: OutboxEvent,
    )
    fun saveCompensation(
        result: DepositCompensationResult,
        tenantId: String,
        queryFingerprint: String,
        idempotencyKey: String,
        audit: AuditEvent,
        outbox: OutboxEvent,
    )
    fun getAuditEvents(): List<AuditEvent>
    fun getOutboxEvents(): List<OutboxEvent>
    fun exportState(): DepositStoreSnapshot
    fun importState(snapshot: DepositStoreSnapshot)
}

class InMemoryDepositStateMachineStore : DepositStateMachineStore {
    val deposits = ConcurrentHashMap<String, DepositRecord>()
    val idempotencyResults = ConcurrentHashMap<String, Pair<String, DepositRecord>>()
    val compensations = ConcurrentHashMap<String, Pair<String, DepositCompensationResult>>()
    val sequences = ConcurrentHashMap<String, Long>()
    val audit = mutableListOf<AuditEvent>()
    val outbox = mutableListOf<OutboxEvent>()

    override fun findDeposit(tenantId: String, depositReference: String): DepositRecord? =
        deposits["$tenantId:$depositReference"]

    override fun findByIdempotency(tenantId: String, idempotencyKey: String): Pair<String, DepositRecord>? =
        idempotencyResults["$tenantId:$idempotencyKey"]

    override fun findCompensationByIdempotency(tenantId: String, idempotencyKey: String): Pair<String, DepositCompensationResult>? =
        compensations["$tenantId:$idempotencyKey"]

    override fun getLastSequence(tenantId: String, depositReference: String): Long =
        sequences["$tenantId:$depositReference"] ?: 0L

    @Synchronized
    override fun saveDeposit(
        record: DepositRecord,
        tenantId: String,
        queryFingerprint: String,
        idempotencyKey: String,
        sequence: Long,
        audit: AuditEvent,
        outbox: OutboxEvent,
    ) {
        deposits["$tenantId:${record.depositReference}"] = record
        idempotencyResults["$tenantId:$idempotencyKey"] = queryFingerprint to record
        if (sequence > 0L) {
            sequences["$tenantId:${record.depositReference}"] = sequence
        }
        this.audit += audit
        this.outbox += outbox
    }

    @Synchronized
    override fun saveCompensation(
        result: DepositCompensationResult,
        tenantId: String,
        queryFingerprint: String,
        idempotencyKey: String,
        audit: AuditEvent,
        outbox: OutboxEvent,
    ) {
        compensations["$tenantId:$idempotencyKey"] = queryFingerprint to result
        this.audit += audit
        this.outbox += outbox
    }

    @Synchronized
    override fun getAuditEvents(): List<AuditEvent> = audit.toList()

    @Synchronized
    override fun getOutboxEvents(): List<OutboxEvent> = outbox.toList()

    @Synchronized
    override fun exportState(): DepositStoreSnapshot = DepositStoreSnapshot(
        deposits = HashMap(deposits),
        idempotencyMap = HashMap(idempotencyResults),
        compensations = HashMap(compensations),
        sequences = HashMap(sequences),
        auditEvents = ArrayList(audit),
        outboxEvents = ArrayList(outbox),
    )

    @Synchronized
    override fun importState(snapshot: DepositStoreSnapshot) {
        deposits.clear()
        deposits.putAll(snapshot.deposits)
        idempotencyResults.clear()
        idempotencyResults.putAll(snapshot.idempotencyMap)
        compensations.clear()
        compensations.putAll(snapshot.compensations)
        sequences.clear()
        sequences.putAll(snapshot.sequences)
        audit.clear()
        audit.addAll(snapshot.auditEvents)
        outbox.clear()
        outbox.addAll(snapshot.outboxEvents)
    }
}

class DepositStateMachineService(
    private val sessions: AdminSessionDirectory,
    private val eligibilityStore: ServerEligibilityStore,
    private val store: DepositStateMachineStore,
    private val adapters: Map<String, CanonicalPaymentProviderPort>,
    private val alertSink: DepositAlertSink = InMemoryDepositAlertSink(),
    private val clock: Clock = Clock.systemUTC(),
) {

    @Synchronized
    fun initiateDeposit(command: InitiateDepositCommand): DepositRecord {
        DepositStateMachineBinding.checkBound()

        // 1. Authenticate principal
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

        // 2. Validate parameters: amount, currency, routing
        if (command.amountMinorUnits <= 0L ||
            !command.currencyCode.matches(Regex("^[A-Z]{3}$")) ||
            command.depositReference.isBlank() ||
            command.correlationId.isBlank() ||
            command.causationId.isBlank()) {
            throw AuthenticationFailure.Rejected(AuthErrorCode.INVALID)
        }

        if (command.expectedVersion != 1L) {
            throw AuthenticationFailure.Rejected(AuthErrorCode.STALE)
        }

        // Server routing check: provider must be registered and authorized
        if (!adapters.containsKey(command.providerId)) {
            alertSink.sendAlert(command.tenantId, command.depositReference, "UNAUTHORIZED_ROUTING", "Provider ${command.providerId} not authorized")
            throw AuthenticationFailure.Rejected(AuthErrorCode.FORBIDDEN)
        }

        // 3. AUTHZ-001 Prerequisite check: Server eligibility verdict
        val verdict = eligibilityStore.findVerdict(command.tenantId, command.eligibilityDecisionId)
        if (verdict == null || verdict.playerId != command.playerId || !verdict.eligible) {
            alertSink.sendAlert(command.tenantId, command.depositReference, "ELIGIBILITY_DENIED", "Missing or ineligible verdict")
            throw AuthenticationFailure.Rejected(AuthErrorCode.FORBIDDEN)
        }
        if (verdict.version != command.eligibilityDecisionVersion) {
            alertSink.sendAlert(command.tenantId, command.depositReference, "ELIGIBILITY_STALE", "Verdict version mismatch")
            throw AuthenticationFailure.Rejected(AuthErrorCode.STALE)
        }
        if (verdict.expiresAt.isBefore(clock.instant())) {
            alertSink.sendAlert(command.tenantId, command.depositReference, "ELIGIBILITY_EXPIRED", "Verdict expired at ${verdict.expiresAt}")
            throw AuthenticationFailure.Rejected(AuthErrorCode.STALE)
        }

        // 4. Idempotency check
        val fp = fingerprintInitiate(command)
        store.findByIdempotency(command.tenantId, command.idempotencyKey)?.let { (cachedFp, cachedRecord) ->
            if (cachedFp != fp) throw AuthenticationFailure.Rejected(AuthErrorCode.CONFLICT)
            return cachedRecord
        }

        // 5. Existing deposit check
        if (store.findDeposit(command.tenantId, command.depositReference) != null) {
            throw AuthenticationFailure.Rejected(AuthErrorCode.CONFLICT)
        }

        val now = clock.instant()
        val depositId = UUID.randomUUID()
        val evidenceRef = "DEP-EVID-$depositId"

        // Initial financial conservation: debit minor units tracked, 0 credited until SUCCEEDED
        val record = DepositRecord(
            depositId = depositId,
            depositReference = command.depositReference,
            tenantId = command.tenantId,
            playerId = command.playerId,
            amountMinorUnits = command.amountMinorUnits,
            currencyCode = command.currencyCode,
            providerId = command.providerId,
            returnUrl = command.returnUrl,
            returnUrlIsInformationalOnly = true,
            status = DepositStatus.INITIATED,
            externalTransactionReference = null,
            safeReasonCode = "INITIATED",
            debitMinorUnits = command.amountMinorUnits,
            creditMinorUnits = 0L,
            conserved = true,
            eligibilityDecisionId = command.eligibilityDecisionId,
            eligibilityDecisionVersion = command.eligibilityDecisionVersion,
            version = 1L,
            createdAt = now,
            updatedAt = now,
            evidenceReference = evidenceRef,
            semanticContract = DEPOSIT_STATE_MACHINE_CONTRACT,
        )

        val audit = AuditEvent(
            eventId = UUID.randomUUID(),
            resultId = depositId,
            tenantId = command.tenantId,
            type = "DEPOSIT_INITIATED",
            occurredAt = now,
            correlationId = command.correlationId,
            causationId = command.causationId,
        )
        val outbox = OutboxEvent(
            eventId = UUID.randomUUID(),
            resultId = depositId,
            tenantId = command.tenantId,
            type = "DEPOSIT_INITIATED",
            createdAt = now,
        )

        store.saveDeposit(record, command.tenantId, fp, command.idempotencyKey, 1L, audit, outbox)
        return record
    }

    @Synchronized
    fun transitionDeposit(command: TransitionDepositCommand): DepositRecord {
        DepositStateMachineBinding.checkBound()

        // 1. Authenticate principal if present
        command.principal?.let { principal ->
            if (principal.kind != PrincipalKind.ADMIN || principal.tenantId != command.tenantId) {
                throw AuthenticationFailure.Rejected(AuthErrorCode.FORBIDDEN)
            }
            command.sessionId?.let { sid ->
                val session = try {
                    sessions.find(command.tenantId, principal.id, sid)
                } catch (_: Exception) {
                    throw AuthenticationFailure.Rejected(AuthErrorCode.DEPENDENCY_UNAVAILABLE)
                } ?: throw AuthenticationFailure.Rejected(AuthErrorCode.FORBIDDEN)
                if (!session.active || session.expiresAt.isBefore(clock.instant())) {
                    throw AuthenticationFailure.Rejected(AuthErrorCode.FORBIDDEN)
                }
            }
        }

        if (command.depositReference.isBlank() ||
            command.correlationId.isBlank() ||
            command.causationId.isBlank()) {
            throw AuthenticationFailure.Rejected(AuthErrorCode.INVALID)
        }

        // 2. Idempotency check
        val fp = fingerprintTransition(command)
        store.findByIdempotency(command.tenantId, command.idempotencyKey)?.let { (cachedFp, cachedRecord) ->
            if (cachedFp != fp) throw AuthenticationFailure.Rejected(AuthErrorCode.CONFLICT)
            return cachedRecord
        }

        // 3. Find current deposit
        val existing = store.findDeposit(command.tenantId, command.depositReference)
            ?: throw AuthenticationFailure.Rejected(AuthErrorCode.FORBIDDEN)

        if (existing.version != command.expectedVersion) {
            throw AuthenticationFailure.Rejected(AuthErrorCode.STALE)
        }

        // 4. Return URL informational check:
        // Even if client attempts to submit return URL payload with success, transitions cannot bypass valid state machine rules.
        // Return URL is informational only.

        // 5. State machine transition rules:
        // Allowed:
        // INITIATED -> PENDING
        // PENDING -> SUCCEEDED
        // PENDING -> FAILED
        // SUCCEEDED -> REVERSED (via compensateDeposit or explicit reversal)
        val valid = isValidTransition(existing.status, command.targetStatus)
        if (!valid) {
            alertSink.sendAlert(
                command.tenantId,
                command.depositReference,
                "ILLEGAL_STATE_TRANSITION",
                "Illegal transition from ${existing.status} to ${command.targetStatus}"
            )
            throw AuthenticationFailure.Rejected(AuthErrorCode.CONFLICT)
        }

        // 6. Delivery sequence validation
        val lastSeq = store.getLastSequence(command.tenantId, command.depositReference)
        if (lastSeq > 0L && command.deliverySequence <= lastSeq) {
            alertSink.sendAlert(
                command.tenantId,
                command.depositReference,
                "OUT_OF_ORDER_SEQUENCE",
                "Sequence ${command.deliverySequence} <= last $lastSeq"
            )
            throw AuthenticationFailure.Rejected(AuthErrorCode.CONFLICT)
        }

        val now = clock.instant()
        val newVersion = existing.version + 1L

        // Calculate financial credits/debits:
        val (debitUnits, creditUnits) = when (command.targetStatus) {
            DepositStatus.SUCCEEDED -> existing.amountMinorUnits to existing.amountMinorUnits
            DepositStatus.FAILED -> 0L to 0L
            DepositStatus.PENDING -> existing.amountMinorUnits to 0L
            DepositStatus.REVERSED -> existing.amountMinorUnits to existing.amountMinorUnits
            DepositStatus.INITIATED -> existing.amountMinorUnits to 0L
        }

        val safeReason = command.failureReason ?: when (command.targetStatus) {
            DepositStatus.SUCCEEDED -> "SUCCESS"
            DepositStatus.PENDING -> "PENDING_PROVIDER"
            DepositStatus.FAILED -> "FAILED"
            DepositStatus.REVERSED -> "REVERSED"
            DepositStatus.INITIATED -> "INITIATED"
        }

        val updatedRecord = existing.copy(
            status = command.targetStatus,
            externalTransactionReference = command.externalTransactionReference ?: existing.externalTransactionReference,
            safeReasonCode = safeReason,
            debitMinorUnits = debitUnits,
            creditMinorUnits = creditUnits,
            conserved = (command.targetStatus != DepositStatus.SUCCEEDED || debitUnits == creditUnits),
            version = newVersion,
            updatedAt = now,
        )

        val audit = AuditEvent(
            eventId = UUID.randomUUID(),
            resultId = updatedRecord.depositId,
            tenantId = command.tenantId,
            type = "DEPOSIT_TRANSITION_${command.targetStatus.name}",
            occurredAt = now,
            correlationId = command.correlationId,
            causationId = command.causationId,
        )
        val outbox = OutboxEvent(
            eventId = UUID.randomUUID(),
            resultId = updatedRecord.depositId,
            tenantId = command.tenantId,
            type = "DEPOSIT_TRANSITION_${command.targetStatus.name}",
            createdAt = now,
        )

        store.saveDeposit(updatedRecord, command.tenantId, fp, command.idempotencyKey, command.deliverySequence, audit, outbox)
        return updatedRecord
    }

    @Synchronized
    fun compensateDeposit(command: CompensateDepositCommand): DepositCompensationResult {
        DepositStateMachineBinding.checkBound()

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

        if (command.depositReference.isBlank() ||
            command.currencyCode.isBlank() ||
            command.reason.isBlank() ||
            command.correlationId.isBlank() ||
            command.causationId.isBlank() ||
            command.originalDebitMinorUnits <= 0L ||
            command.compensatingCreditMinorUnits <= 0L ||
            command.originalDebitMinorUnits != command.compensatingCreditMinorUnits) {
            throw AuthenticationFailure.Rejected(AuthErrorCode.INVALID)
        }

        val fp = fingerprintCompensation(command)
        store.findCompensationByIdempotency(command.tenantId, command.idempotencyKey)?.let { (cachedFp, cachedResult) ->
            if (cachedFp != fp) throw AuthenticationFailure.Rejected(AuthErrorCode.CONFLICT)
            return cachedResult
        }

        val deposit = store.findDeposit(command.tenantId, command.depositReference)
            ?: throw AuthenticationFailure.Rejected(AuthErrorCode.FORBIDDEN)

        if (deposit.version != command.expectedVersion) {
            throw AuthenticationFailure.Rejected(AuthErrorCode.STALE)
        }

        // Only SUCCEEDED deposits can be compensated/reversed
        if (deposit.status != DepositStatus.SUCCEEDED) {
            alertSink.sendAlert(
                command.tenantId,
                command.depositReference,
                "ILLEGAL_COMPENSATION_STATE",
                "Cannot reverse deposit in status ${deposit.status}"
            )
            throw AuthenticationFailure.Rejected(AuthErrorCode.CONFLICT)
        }

        val now = clock.instant()
        val resultId = UUID.randomUUID()
        val compRef = "COMP-REV-$resultId"
        val evidenceRef = "COMP-DEP-EVID-$resultId"

        val compensationResult = DepositCompensationResult(
            resultId = resultId,
            depositReference = command.depositReference,
            tenantId = command.tenantId,
            playerId = deposit.playerId,
            debitMinorUnits = command.originalDebitMinorUnits,
            creditMinorUnits = command.compensatingCreditMinorUnits,
            conserved = true,
            immutableCompensationReference = compRef,
            serverTime = now,
            evidenceReference = evidenceRef,
            semanticContract = DEPOSIT_STATE_MACHINE_CONTRACT,
        )

        val updatedDeposit = deposit.copy(
            status = DepositStatus.REVERSED,
            safeReasonCode = "REVERSED: ${command.reason}",
            version = deposit.version + 1L,
            updatedAt = now,
        )

        val audit = AuditEvent(
            eventId = UUID.randomUUID(),
            resultId = resultId,
            tenantId = command.tenantId,
            type = "DEPOSIT_COMPENSATED_REVERSED",
            occurredAt = now,
            correlationId = command.correlationId,
            causationId = command.causationId,
        )
        val outbox = OutboxEvent(
            eventId = UUID.randomUUID(),
            resultId = resultId,
            tenantId = command.tenantId,
            type = "DEPOSIT_COMPENSATED_REVERSED",
            createdAt = now,
        )

        // Save updated deposit and immutable compensation record
        store.saveDeposit(updatedDeposit, command.tenantId, fp + ":record", "dep-upd-$resultId", 0L, audit, outbox)
        store.saveCompensation(compensationResult, command.tenantId, fp, command.idempotencyKey, audit, outbox)
        return compensationResult
    }

    @Synchronized
    fun processWebhook(command: ProcessDepositWebhookCommand): DepositRecord {
        DepositStateMachineBinding.checkBound()

        if (command.providerId.isBlank() || command.correlationId.isBlank() || command.causationId.isBlank()) {
            throw AuthenticationFailure.Rejected(AuthErrorCode.INVALID)
        }

        val fp = fingerprintWebhook(command)
        store.findByIdempotency(command.tenantId, command.idempotencyKey)?.let { (cachedFp, cachedRecord) ->
            if (cachedFp != fp) throw AuthenticationFailure.Rejected(AuthErrorCode.CONFLICT)
            return cachedRecord
        }

        val adapter = adapters[command.providerId]
            ?: throw AuthenticationFailure.Rejected(AuthErrorCode.FORBIDDEN)

        val webhookEvent = try {
            adapter.verifyWebhook(command.signatureHeader, command.rawPayload)
        } catch (_: Exception) {
            throw AuthenticationFailure.Rejected(AuthErrorCode.DEPENDENCY_UNAVAILABLE)
        } ?: throw AuthenticationFailure.Rejected(AuthErrorCode.FORBIDDEN)

        val deposit = store.findDeposit(command.tenantId, webhookEvent.paymentReference)
            ?: throw AuthenticationFailure.Rejected(AuthErrorCode.FORBIDDEN)

        if (deposit.version != command.expectedVersion) {
            throw AuthenticationFailure.Rejected(AuthErrorCode.STALE)
        }

        val lastSeq = store.getLastSequence(command.tenantId, webhookEvent.paymentReference)
        if (lastSeq > 0L && webhookEvent.sequenceNumber <= lastSeq) {
            alertSink.sendAlert(
                command.tenantId,
                webhookEvent.paymentReference,
                "OUT_OF_ORDER_WEBHOOK",
                "Webhook sequence ${webhookEvent.sequenceNumber} <= $lastSeq"
            )
            throw AuthenticationFailure.Rejected(AuthErrorCode.CONFLICT)
        }

        val targetStatus = when (webhookEvent.status) {
            CanonicalPaymentStatus.CAPTURED, CanonicalPaymentStatus.AUTHORIZED -> DepositStatus.SUCCEEDED
            CanonicalPaymentStatus.FAILED -> DepositStatus.FAILED
            CanonicalPaymentStatus.REFUNDED, CanonicalPaymentStatus.VOIDED -> DepositStatus.REVERSED
            CanonicalPaymentStatus.PENDING -> DepositStatus.PENDING
        }

        if (!isValidTransition(deposit.status, targetStatus)) {
            alertSink.sendAlert(
                command.tenantId,
                webhookEvent.paymentReference,
                "ILLEGAL_WEBHOOK_TRANSITION",
                "Cannot transition ${deposit.status} to $targetStatus"
            )
            throw AuthenticationFailure.Rejected(AuthErrorCode.CONFLICT)
        }

        val now = clock.instant()
        val newVersion = deposit.version + 1L

        val (debitUnits, creditUnits) = when (targetStatus) {
            DepositStatus.SUCCEEDED -> deposit.amountMinorUnits to deposit.amountMinorUnits
            DepositStatus.FAILED -> 0L to 0L
            DepositStatus.REVERSED -> deposit.amountMinorUnits to deposit.amountMinorUnits
            DepositStatus.PENDING -> deposit.amountMinorUnits to 0L
            DepositStatus.INITIATED -> deposit.amountMinorUnits to 0L
        }

        val updatedRecord = deposit.copy(
            status = targetStatus,
            externalTransactionReference = webhookEvent.externalTransactionReference,
            safeReasonCode = "WEBHOOK_${targetStatus.name}",
            debitMinorUnits = debitUnits,
            creditMinorUnits = creditUnits,
            conserved = (targetStatus != DepositStatus.SUCCEEDED || debitUnits == creditUnits),
            version = newVersion,
            updatedAt = now,
        )

        val audit = AuditEvent(
            eventId = UUID.randomUUID(),
            resultId = updatedRecord.depositId,
            tenantId = command.tenantId,
            type = "DEPOSIT_WEBHOOK_${targetStatus.name}",
            occurredAt = now,
            correlationId = command.correlationId,
            causationId = command.causationId,
        )
        val outbox = OutboxEvent(
            eventId = UUID.randomUUID(),
            resultId = updatedRecord.depositId,
            tenantId = command.tenantId,
            type = "DEPOSIT_WEBHOOK_${targetStatus.name}",
            createdAt = now,
        )

        store.saveDeposit(updatedRecord, command.tenantId, fp, command.idempotencyKey, webhookEvent.sequenceNumber, audit, outbox)
        return updatedRecord
    }

    @Synchronized
    fun getDeposit(tenantId: String, depositReference: String): DepositRecord? =
        store.findDeposit(tenantId, depositReference)

    private fun isValidTransition(from: DepositStatus, to: DepositStatus): Boolean =
        when (from) {
            DepositStatus.INITIATED -> to == DepositStatus.PENDING
            DepositStatus.PENDING -> to == DepositStatus.SUCCEEDED || to == DepositStatus.FAILED
            DepositStatus.SUCCEEDED -> to == DepositStatus.REVERSED
            DepositStatus.FAILED -> false
            DepositStatus.REVERSED -> false
        }

    private fun fingerprintInitiate(cmd: InitiateDepositCommand): String {
        val raw = "${cmd.tenantId}:${cmd.playerId}:${cmd.depositReference}:${cmd.amountMinorUnits}:${cmd.currencyCode}:${cmd.providerId}:${cmd.expectedVersion}"
        return sha256(raw)
    }

    private fun fingerprintTransition(cmd: TransitionDepositCommand): String {
        val raw = "${cmd.tenantId}:${cmd.depositReference}:${cmd.targetStatus}:${cmd.externalTransactionReference}:${cmd.expectedVersion}:${cmd.deliverySequence}"
        return sha256(raw)
    }

    private fun fingerprintCompensation(cmd: CompensateDepositCommand): String {
        val raw = "${cmd.tenantId}:${cmd.depositReference}:${cmd.originalDebitMinorUnits}:${cmd.compensatingCreditMinorUnits}:${cmd.currencyCode}:${cmd.expectedVersion}"
        return sha256(raw)
    }

    private fun fingerprintWebhook(cmd: ProcessDepositWebhookCommand): String {
        val raw = "${cmd.tenantId}:${cmd.providerId}:${cmd.signatureHeader}:${cmd.rawPayload}:${cmd.expectedVersion}"
        return sha256(raw)
    }

    private fun sha256(raw: String): String {
        val digest = MessageDigest.getInstance("SHA-256")
        return digest.digest(raw.toByteArray(Charsets.UTF_8)).joinToString("") { "%02x".format(it) }
    }
}
