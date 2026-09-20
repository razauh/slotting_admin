package com.slotting.admin.payment

import com.slotting.admin.auth.*
import java.nio.charset.StandardCharsets
import java.security.MessageDigest
import java.time.Clock
import java.time.Instant
import java.util.UUID
import java.util.concurrent.ConcurrentHashMap

/**
 * Fail-closed verification gate for PAYMENT-004: Webhook ordering/idempotency.
 * Throws expected RED failure until contract bindings and invariant protections are verified.
 * Protected risk: False completion or non-authoritative implementation of Webhook ordering/idempotency.
 * Rationale: It exists to prevent: late pending regresses success.
 */
object WebhookOrderingIdempotencyBinding {
    @Volatile
    var isBound: Boolean = false

    fun checkBound() {
        if (!isBound) {
            throw AssertionError("late pending regresses success")
        }
    }
}

/**
 * Outcome-specific semantic contract for PAYMENT-004.
 */
const val WEBHOOK_ORDERING_IDEMPOTENCY_CONTRACT =
    "Duplicates same outcome; conflicts alert/reconcile; never guess missing provider state."

enum class CanonicalWebhookPaymentStatus(val rank: Int) {
    INITIATED(1),
    PENDING(2),
    SUCCEEDED(3),
    FAILED(3),
    REVERSED(4),
}

enum class ReducerAction {
    APPLIED,
    DUPLICATE_ACCEPTED,
    LATE_IGNORED,
    CONFLICT_RECONCILE,
    UNKNOWN_HELD,
}

data class ProcessOrderedWebhookCommand(
    val tenantId: String,
    val providerId: String,
    val paymentReference: String,
    val externalEventId: String,
    val incomingStatus: CanonicalWebhookPaymentStatus,
    val amountMinorUnits: Long,
    val currencyCode: String,
    val deliverySequence: Long,
    val idempotencyKey: String,
    val correlationId: String,
    val causationId: String,
    val expectedVersion: Long = 1L,
    val rawPayload: String = "",
)

data class OrderedPaymentRecord(
    val paymentId: UUID,
    val tenantId: String,
    val providerId: String,
    val paymentReference: String,
    val status: CanonicalWebhookPaymentStatus,
    val amountMinorUnits: Long,
    val currencyCode: String,
    val currentSequence: Long,
    val debitMinorUnits: Long,
    val creditMinorUnits: Long,
    val conserved: Boolean,
    val requiresReconciliation: Boolean,
    val safeReasonCode: String,
    val lastEventId: String,
    val version: Long,
    val createdAt: Instant,
    val updatedAt: Instant,
    val evidenceReference: String,
    val semanticContract: String = WEBHOOK_ORDERING_IDEMPOTENCY_CONTRACT,
)

data class OrderedWebhookResult(
    val resultId: UUID,
    val tenantId: String,
    val paymentReference: String,
    val previousStatus: CanonicalWebhookPaymentStatus?,
    val currentStatus: CanonicalWebhookPaymentStatus,
    val action: ReducerAction,
    val isDuplicate: Boolean,
    val debitMinorUnits: Long,
    val creditMinorUnits: Long,
    val conserved: Boolean,
    val currentSequence: Long,
    val requiresReconciliation: Boolean,
    val safeReasonCode: String,
    val serverTime: Instant,
    val evidenceReference: String,
    val semanticContract: String = WEBHOOK_ORDERING_IDEMPOTENCY_CONTRACT,
)

data class WebhookOrderingSnapshot(
    val payments: Map<String, OrderedPaymentRecord>,
    val idempotencyMap: Map<String, Pair<String, OrderedWebhookResult>>,
    val auditEvents: List<AuditEvent>,
    val outboxEvents: List<OutboxEvent>,
)

interface WebhookOrderingAlertSink {
    fun sendAlert(tenantId: String, paymentReference: String, alertType: String, reason: String, detail: String)
}

class InMemoryWebhookOrderingAlertSink : WebhookOrderingAlertSink {
    val alerts = mutableListOf<String>()

    @Synchronized
    override fun sendAlert(tenantId: String, paymentReference: String, alertType: String, reason: String, detail: String) {
        alerts.add("$tenantId:$paymentReference:$alertType:$reason:$detail")
    }
}

interface WebhookOrderingStore {
    fun findPayment(tenantId: String, paymentReference: String): OrderedPaymentRecord?
    fun findByIdempotency(tenantId: String, idempotencyKey: String): Pair<String, OrderedWebhookResult>?
    fun savePayment(
        record: OrderedPaymentRecord,
        result: OrderedWebhookResult,
        idempotencyKey: String,
        fingerprint: String,
        audit: AuditEvent,
        outbox: OutboxEvent,
    )
    fun listReconciliationHold(tenantId: String): List<OrderedPaymentRecord>
    fun getAuditEvents(): List<AuditEvent>
    fun getOutboxEvents(): List<OutboxEvent>
    fun exportSnapshot(): WebhookOrderingSnapshot
    fun importSnapshot(snapshot: WebhookOrderingSnapshot)
}

class InMemoryWebhookOrderingStore : WebhookOrderingStore {
    private val payments = ConcurrentHashMap<String, OrderedPaymentRecord>()
    private val idempotencyResults = ConcurrentHashMap<String, Pair<String, OrderedWebhookResult>>()
    private val auditEvents = mutableListOf<AuditEvent>()
    private val outboxEvents = mutableListOf<OutboxEvent>()

    private fun pKey(tenantId: String, ref: String) = "$tenantId:$ref"
    private fun idKey(tenantId: String, idemp: String) = "$tenantId:$idemp"

    @Synchronized
    override fun findPayment(tenantId: String, paymentReference: String): OrderedPaymentRecord? =
        payments[pKey(tenantId, paymentReference)]?.copy()

    @Synchronized
    override fun findByIdempotency(tenantId: String, idempotencyKey: String): Pair<String, OrderedWebhookResult>? =
        idempotencyResults[idKey(tenantId, idempotencyKey)]

    @Synchronized
    override fun savePayment(
        record: OrderedPaymentRecord,
        result: OrderedWebhookResult,
        idempotencyKey: String,
        fingerprint: String,
        audit: AuditEvent,
        outbox: OutboxEvent,
    ) {
        payments[pKey(record.tenantId, record.paymentReference)] = record.copy()
        idempotencyResults[idKey(record.tenantId, idempotencyKey)] = fingerprint to result
        auditEvents.add(audit)
        outboxEvents.add(outbox)
    }

    @Synchronized
    override fun listReconciliationHold(tenantId: String): List<OrderedPaymentRecord> =
        payments.values.filter { it.tenantId == tenantId && it.requiresReconciliation }.map { it.copy() }

    @Synchronized
    override fun getAuditEvents(): List<AuditEvent> = auditEvents.toList()

    @Synchronized
    override fun getOutboxEvents(): List<OutboxEvent> = outboxEvents.toList()

    @Synchronized
    override fun exportSnapshot(): WebhookOrderingSnapshot = WebhookOrderingSnapshot(
        payments = HashMap(payments),
        idempotencyMap = HashMap(idempotencyResults),
        auditEvents = ArrayList(auditEvents),
        outboxEvents = ArrayList(outboxEvents),
    )

    @Synchronized
    override fun importSnapshot(snapshot: WebhookOrderingSnapshot) {
        payments.clear()
        payments.putAll(snapshot.payments)
        idempotencyResults.clear()
        idempotencyResults.putAll(snapshot.idempotencyMap)
        auditEvents.clear()
        auditEvents.addAll(snapshot.auditEvents)
        outboxEvents.clear()
        outboxEvents.addAll(snapshot.outboxEvents)
    }
}

class WebhookOrderingIdempotencyService(
    private val store: WebhookOrderingStore,
    private val alertSink: WebhookOrderingAlertSink = InMemoryWebhookOrderingAlertSink(),
    private val clock: Clock = Clock.systemUTC(),
) {
    private fun sha256(input: String): String {
        val digest = MessageDigest.getInstance("SHA-256")
        val hash = digest.digest(input.toByteArray(StandardCharsets.UTF_8))
        return hash.joinToString("") { "%02x".format(it) }
    }

    private fun fingerprint(cmd: ProcessOrderedWebhookCommand): String {
        return sha256("${cmd.tenantId}:${cmd.providerId}:${cmd.paymentReference}:${cmd.externalEventId}:${cmd.incomingStatus}:${cmd.amountMinorUnits}:${cmd.currencyCode}:${cmd.deliverySequence}:${cmd.expectedVersion}")
    }

    @Synchronized
    fun processWebhook(command: ProcessOrderedWebhookCommand): OrderedWebhookResult {
        // Protected risk assertion: late pending regresses success
        WebhookOrderingIdempotencyBinding.checkBound()

        // 1. Mandatory Input Validation
        if (command.tenantId.isBlank() ||
            command.providerId.isBlank() ||
            command.paymentReference.isBlank() ||
            command.externalEventId.isBlank() ||
            command.idempotencyKey.isBlank() ||
            command.correlationId.isBlank() ||
            command.causationId.isBlank()
        ) {
            alertSink.sendAlert(
                tenantId = command.tenantId.ifBlank { "UNKNOWN" },
                paymentReference = command.paymentReference.ifBlank { "UNKNOWN" },
                alertType = "WEBHOOK_ORDERING_INVALID_INPUT",
                reason = "BLANK_MANDATORY_FIELDS",
                detail = "Ordered webhook rejected due to blank mandatory fields",
            )
            throw AuthenticationFailure.Rejected(AuthErrorCode.INVALID)
        }

        if (command.amountMinorUnits <= 0L || !command.currencyCode.matches(Regex("^[A-Z]{3}$")) || command.deliverySequence <= 0L) {
            throw AuthenticationFailure.Rejected(AuthErrorCode.INVALID)
        }

        if (command.expectedVersion != 1L) {
            throw AuthenticationFailure.Rejected(AuthErrorCode.STALE)
        }

        val fp = fingerprint(command)
        val now = clock.instant()

        // 2. Idempotency Check: Duplicates same outcome
        val existingIdemp = store.findByIdempotency(command.tenantId, command.idempotencyKey)
        if (existingIdemp != null) {
            val (cachedFp, cachedResult) = existingIdemp
            if (cachedFp != fp) {
                alertSink.sendAlert(
                    tenantId = command.tenantId,
                    paymentReference = command.paymentReference,
                    alertType = "WEBHOOK_ORDERING_IDEMPOTENCY_CONFLICT",
                    reason = "PAYLOAD_MISMATCH",
                    detail = "Payload conflict detected under idempotency key ${command.idempotencyKey}",
                )
                throw AuthenticationFailure.Rejected(AuthErrorCode.CONFLICT)
            }
            return cachedResult.copy(isDuplicate = true)
        }

        // 3. Find Existing Payment Record
        val existing = store.findPayment(command.tenantId, command.paymentReference)

        // "never guess missing provider state":
        // If payment reference does not exist in our authoritative records:
        if (existing == null) {
            if (command.incomingStatus == CanonicalWebhookPaymentStatus.INITIATED) {
                val paymentId = UUID.randomUUID()
                val resultId = UUID.randomUUID()
                val evidenceRef = "DEP-ORD-EVID-$paymentId"

                val newRecord = OrderedPaymentRecord(
                    paymentId = paymentId,
                    tenantId = command.tenantId,
                    providerId = command.providerId,
                    paymentReference = command.paymentReference,
                    status = CanonicalWebhookPaymentStatus.INITIATED,
                    amountMinorUnits = command.amountMinorUnits,
                    currencyCode = command.currencyCode,
                    currentSequence = command.deliverySequence,
                    debitMinorUnits = command.amountMinorUnits,
                    creditMinorUnits = 0L,
                    conserved = true,
                    requiresReconciliation = false,
                    safeReasonCode = "INITIATED",
                    lastEventId = command.externalEventId,
                    version = 1L,
                    createdAt = now,
                    updatedAt = now,
                    evidenceReference = evidenceRef,
                )

                val result = OrderedWebhookResult(
                    resultId = resultId,
                    tenantId = command.tenantId,
                    paymentReference = command.paymentReference,
                    previousStatus = null,
                    currentStatus = CanonicalWebhookPaymentStatus.INITIATED,
                    action = ReducerAction.APPLIED,
                    isDuplicate = false,
                    debitMinorUnits = command.amountMinorUnits,
                    creditMinorUnits = 0L,
                    conserved = true,
                    currentSequence = command.deliverySequence,
                    requiresReconciliation = false,
                    safeReasonCode = "INITIATED",
                    serverTime = now,
                    evidenceReference = evidenceRef,
                )

                val audit = AuditEvent(UUID.randomUUID(), paymentId, command.tenantId, "ORDERED_PAYMENT_INITIATED", now, command.correlationId, command.causationId)
                val outbox = OutboxEvent(UUID.randomUUID(), paymentId, command.tenantId, "ORDERED_PAYMENT_INITIATED", now)
                store.savePayment(newRecord, result, command.idempotencyKey, fp, audit, outbox)
                return result
            } else {
                // Incoming webhook for missing/unknown payment state:
                // "never guess missing provider state": Quarantine/hold for reconciliation; do not guess success or create unauthoritative credit!
                alertSink.sendAlert(
                    tenantId = command.tenantId,
                    paymentReference = command.paymentReference,
                    alertType = "UNKNOWN_PROVIDER_STATE",
                    reason = "MISSING_PAYMENT_REFERENCE",
                    detail = "Webhook received with status ${command.incomingStatus} for non-existent payment reference",
                )

                val paymentId = UUID.randomUUID()
                val resultId = UUID.randomUUID()
                val evidenceRef = "DEP-ORD-HOLD-$paymentId"

                val heldRecord = OrderedPaymentRecord(
                    paymentId = paymentId,
                    tenantId = command.tenantId,
                    providerId = command.providerId,
                    paymentReference = command.paymentReference,
                    status = command.incomingStatus,
                    amountMinorUnits = command.amountMinorUnits,
                    currencyCode = command.currencyCode,
                    currentSequence = command.deliverySequence,
                    debitMinorUnits = 0L,
                    creditMinorUnits = 0L,
                    conserved = true,
                    requiresReconciliation = true,
                    safeReasonCode = "MISSING_PROVIDER_STATE_HELD_FOR_RECONCILIATION",
                    lastEventId = command.externalEventId,
                    version = 1L,
                    createdAt = now,
                    updatedAt = now,
                    evidenceReference = evidenceRef,
                )

                val result = OrderedWebhookResult(
                    resultId = resultId,
                    tenantId = command.tenantId,
                    paymentReference = command.paymentReference,
                    previousStatus = null,
                    currentStatus = command.incomingStatus,
                    action = ReducerAction.UNKNOWN_HELD,
                    isDuplicate = false,
                    debitMinorUnits = 0L,
                    creditMinorUnits = 0L,
                    conserved = true,
                    currentSequence = command.deliverySequence,
                    requiresReconciliation = true,
                    safeReasonCode = "MISSING_PROVIDER_STATE_HELD_FOR_RECONCILIATION",
                    serverTime = now,
                    evidenceReference = evidenceRef,
                )

                val audit = AuditEvent(UUID.randomUUID(), paymentId, command.tenantId, "ORDERED_PAYMENT_UNKNOWN_HELD", now, command.correlationId, command.causationId)
                val outbox = OutboxEvent(UUID.randomUUID(), paymentId, command.tenantId, "ORDERED_PAYMENT_UNKNOWN_HELD", now)
                store.savePayment(heldRecord, result, command.idempotencyKey, fp, audit, outbox)
                return result
            }
        }

        // 4. Existing Payment Record: Monotonic Canonical Reducer
        // Check duplicate externalEventId:
        if (existing.lastEventId == command.externalEventId) {
            val resultId = UUID.randomUUID()
            val result = OrderedWebhookResult(
                resultId = resultId,
                tenantId = command.tenantId,
                paymentReference = command.paymentReference,
                previousStatus = existing.status,
                currentStatus = existing.status,
                action = ReducerAction.DUPLICATE_ACCEPTED,
                isDuplicate = true,
                debitMinorUnits = existing.debitMinorUnits,
                creditMinorUnits = existing.creditMinorUnits,
                conserved = existing.conserved,
                currentSequence = existing.currentSequence,
                requiresReconciliation = existing.requiresReconciliation,
                safeReasonCode = "DUPLICATE_EVENT_ACCEPTED",
                serverTime = now,
                evidenceReference = existing.evidenceReference,
            )
            return result
        }

        // Monotonic state reduction rules to prevent: "late pending regresses success"
        var newStatus = existing.status
        var newAction = ReducerAction.APPLIED
        var newRequiresReconciliation = existing.requiresReconciliation
        var newReasonCode = "TRANSITION_${command.incomingStatus.name}"
        var newDebitMinor = existing.debitMinorUnits
        var newCreditMinor = existing.creditMinorUnits
        val maxSequence = maxOf(existing.currentSequence, command.deliverySequence)

        when (existing.status) {
            CanonicalWebhookPaymentStatus.SUCCEEDED -> {
                when (command.incomingStatus) {
                    CanonicalWebhookPaymentStatus.PENDING,
                    CanonicalWebhookPaymentStatus.INITIATED -> {
                        // Protected risk core defense: LATE PENDING REGRESSES SUCCESS!
                        // A late pending or initiated event must NEVER regress a succeeded payment!
                        newStatus = CanonicalWebhookPaymentStatus.SUCCEEDED
                        newAction = ReducerAction.LATE_IGNORED
                        newReasonCode = "LATE_PENDING_IGNORED_RETAINED_SUCCESS"
                        newDebitMinor = existing.amountMinorUnits
                        newCreditMinor = existing.amountMinorUnits
                        alertSink.sendAlert(
                            tenantId = command.tenantId,
                            paymentReference = command.paymentReference,
                            alertType = "LATE_WEBHOOK_DELIVERY",
                            reason = "LATE_PENDING_AFTER_SUCCESS",
                            detail = "Late event ${command.externalEventId} with status ${command.incomingStatus} ignored; retaining SUCCEEDED",
                        )
                    }
                    CanonicalWebhookPaymentStatus.REVERSED -> {
                        // Lawful refund/reversal of a succeeded payment
                        newStatus = CanonicalWebhookPaymentStatus.REVERSED
                        newAction = ReducerAction.APPLIED
                        newReasonCode = "REVERSED"
                        newDebitMinor = existing.amountMinorUnits
                        newCreditMinor = existing.amountMinorUnits
                    }
                    CanonicalWebhookPaymentStatus.FAILED -> {
                        // Conflict: Provider reports FAILED after SUCCEEDED!
                        // "conflicts alert/reconcile"
                        newStatus = CanonicalWebhookPaymentStatus.SUCCEEDED // retain success, hold for reconciliation
                        newAction = ReducerAction.CONFLICT_RECONCILE
                        newRequiresReconciliation = true
                        newReasonCode = "CONFLICT_FAILED_AFTER_SUCCESS_HELD"
                        alertSink.sendAlert(
                            tenantId = command.tenantId,
                            paymentReference = command.paymentReference,
                            alertType = "PAYMENT_STATUS_CONFLICT",
                            reason = "FAILED_AFTER_SUCCESS",
                            detail = "Conflict detected: provider reported FAILED after payment already SUCCEEDED",
                        )
                    }
                    CanonicalWebhookPaymentStatus.SUCCEEDED -> {
                        newAction = ReducerAction.DUPLICATE_ACCEPTED
                        newReasonCode = "DUPLICATE_SUCCESS_ACCEPTED"
                    }
                }
            }

            CanonicalWebhookPaymentStatus.FAILED -> {
                when (command.incomingStatus) {
                    CanonicalWebhookPaymentStatus.PENDING,
                    CanonicalWebhookPaymentStatus.INITIATED -> {
                        newStatus = CanonicalWebhookPaymentStatus.FAILED
                        newAction = ReducerAction.LATE_IGNORED
                        newReasonCode = "LATE_EVENT_IGNORED_RETAINED_FAILED"
                    }
                    CanonicalWebhookPaymentStatus.SUCCEEDED -> {
                        // Conflict: SUCCEEDED after FAILED!
                        // "conflicts alert/reconcile"
                        newAction = ReducerAction.CONFLICT_RECONCILE
                        newRequiresReconciliation = true
                        newReasonCode = "CONFLICT_SUCCESS_AFTER_FAILED_HELD"
                        alertSink.sendAlert(
                            tenantId = command.tenantId,
                            paymentReference = command.paymentReference,
                            alertType = "PAYMENT_STATUS_CONFLICT",
                            reason = "SUCCESS_AFTER_FAILED",
                            detail = "Conflict detected: provider reported SUCCEEDED after payment was marked FAILED",
                        )
                    }
                    CanonicalWebhookPaymentStatus.FAILED -> {
                        newAction = ReducerAction.DUPLICATE_ACCEPTED
                        newReasonCode = "DUPLICATE_FAILED_ACCEPTED"
                    }
                    CanonicalWebhookPaymentStatus.REVERSED -> {
                        newAction = ReducerAction.LATE_IGNORED
                        newReasonCode = "CANNOT_REVERSE_FAILED_PAYMENT"
                    }
                }
            }

            CanonicalWebhookPaymentStatus.PENDING -> {
                when (command.incomingStatus) {
                    CanonicalWebhookPaymentStatus.INITIATED -> {
                        newStatus = CanonicalWebhookPaymentStatus.PENDING
                        newAction = ReducerAction.LATE_IGNORED
                        newReasonCode = "LATE_INITIATED_IGNORED"
                    }
                    CanonicalWebhookPaymentStatus.PENDING -> {
                        newAction = ReducerAction.DUPLICATE_ACCEPTED
                        newReasonCode = "DUPLICATE_PENDING_ACCEPTED"
                    }
                    CanonicalWebhookPaymentStatus.SUCCEEDED -> {
                        newStatus = CanonicalWebhookPaymentStatus.SUCCEEDED
                        newAction = ReducerAction.APPLIED
                        newReasonCode = "SUCCEEDED"
                        newDebitMinor = command.amountMinorUnits
                        newCreditMinor = command.amountMinorUnits
                    }
                    CanonicalWebhookPaymentStatus.FAILED -> {
                        newStatus = CanonicalWebhookPaymentStatus.FAILED
                        newAction = ReducerAction.APPLIED
                        newReasonCode = "FAILED"
                        newDebitMinor = 0L
                        newCreditMinor = 0L
                    }
                    CanonicalWebhookPaymentStatus.REVERSED -> {
                        newAction = ReducerAction.CONFLICT_RECONCILE
                        newRequiresReconciliation = true
                        newReasonCode = "CANNOT_REVERSE_PENDING_PAYMENT"
                        alertSink.sendAlert(
                            tenantId = command.tenantId,
                            paymentReference = command.paymentReference,
                            alertType = "PAYMENT_STATUS_CONFLICT",
                            reason = "REVERSAL_ON_PENDING",
                            detail = "Cannot reverse a pending payment",
                        )
                    }
                }
            }

            CanonicalWebhookPaymentStatus.INITIATED -> {
                when (command.incomingStatus) {
                    CanonicalWebhookPaymentStatus.INITIATED -> {
                        newAction = ReducerAction.DUPLICATE_ACCEPTED
                        newReasonCode = "DUPLICATE_INITIATED_ACCEPTED"
                    }
                    CanonicalWebhookPaymentStatus.PENDING -> {
                        newStatus = CanonicalWebhookPaymentStatus.PENDING
                        newAction = ReducerAction.APPLIED
                        newReasonCode = "PENDING"
                        newDebitMinor = command.amountMinorUnits
                        newCreditMinor = 0L
                    }
                    CanonicalWebhookPaymentStatus.SUCCEEDED -> {
                        newStatus = CanonicalWebhookPaymentStatus.SUCCEEDED
                        newAction = ReducerAction.APPLIED
                        newReasonCode = "SUCCEEDED"
                        newDebitMinor = command.amountMinorUnits
                        newCreditMinor = command.amountMinorUnits
                    }
                    CanonicalWebhookPaymentStatus.FAILED -> {
                        newStatus = CanonicalWebhookPaymentStatus.FAILED
                        newAction = ReducerAction.APPLIED
                        newReasonCode = "FAILED"
                        newDebitMinor = 0L
                        newCreditMinor = 0L
                    }
                    CanonicalWebhookPaymentStatus.REVERSED -> {
                        newAction = ReducerAction.CONFLICT_RECONCILE
                        newRequiresReconciliation = true
                        newReasonCode = "CANNOT_REVERSE_INITIATED_PAYMENT"
                    }
                }
            }

            CanonicalWebhookPaymentStatus.REVERSED -> {
                // Reversed is terminal; ignore late events
                newAction = ReducerAction.LATE_IGNORED
                newReasonCode = "LATE_EVENT_IGNORED_RETAINED_REVERSED"
            }
        }

        // Financial conservation: when succeeded or reversed, debits must equal credits
        val conserved = if (newStatus == CanonicalWebhookPaymentStatus.SUCCEEDED || newStatus == CanonicalWebhookPaymentStatus.REVERSED) {
            newDebitMinor == newCreditMinor && newDebitMinor > 0L
        } else {
            true
        }

        val resultId = UUID.randomUUID()
        val updatedRecord = existing.copy(
            status = newStatus,
            currentSequence = maxSequence,
            debitMinorUnits = newDebitMinor,
            creditMinorUnits = newCreditMinor,
            conserved = conserved,
            requiresReconciliation = newRequiresReconciliation,
            safeReasonCode = newReasonCode,
            lastEventId = command.externalEventId,
            version = existing.version + 1L,
            updatedAt = now,
        )

        val result = OrderedWebhookResult(
            resultId = resultId,
            tenantId = command.tenantId,
            paymentReference = command.paymentReference,
            previousStatus = existing.status,
            currentStatus = newStatus,
            action = newAction,
            isDuplicate = (newAction == ReducerAction.DUPLICATE_ACCEPTED),
            debitMinorUnits = newDebitMinor,
            creditMinorUnits = newCreditMinor,
            conserved = conserved,
            currentSequence = maxSequence,
            requiresReconciliation = newRequiresReconciliation,
            safeReasonCode = newReasonCode,
            serverTime = now,
            evidenceReference = existing.evidenceReference,
        )

        val audit = AuditEvent(UUID.randomUUID(), existing.paymentId, command.tenantId, "ORDERED_WEBHOOK_REDUCED_${newAction.name}", now, command.correlationId, command.causationId)
        val outbox = OutboxEvent(UUID.randomUUID(), existing.paymentId, command.tenantId, "ORDERED_WEBHOOK_REDUCED_${newAction.name}", now)
        store.savePayment(updatedRecord, result, command.idempotencyKey, fp, audit, outbox)
        return result
    }
}
