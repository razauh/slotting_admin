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
 * Fail-closed verification gate for PAYMENT-007-01: Reconcile provider and ledger items.
 * Throws expected RED failure until contract bindings and invariant protections are verified.
 * Protected risk: False completion or non-authoritative implementation of Reconcile provider and ledger items.
 * Rationale: It exists to prevent: mismatch omitted.
 */
object ProviderLedgerReconciliationBinding {
    @Volatile
    var isBound: Boolean = false

    fun checkBound() {
        if (!isBound) {
            throw AssertionError("mismatch omitted")
        }
    }
}

/**
 * Outcome-specific semantic contract for PAYMENT-007-01.
 */
const val RECONCILE_PROVIDER_LEDGER_CONTRACT =
    "Totals and item-level evidence; close requires reason/approver."

enum class ReconciliationItemType {
    DEPOSIT,
    PAYOUT,
    REFUND,
    REVERSAL,
    FEE,
}

enum class ItemMatchStatus {
    MATCHED,
    AMOUNT_MISMATCH,
    MISSING_IN_LEDGER,
    MISSING_IN_PROVIDER,
    CURRENCY_MISMATCH,
}

enum class ReconciliationBatchStatus {
    BALANCED,
    DISCREPANCY_DETECTED,
    CLOSED,
    WAIVED,
}

data class ProviderSettlementItem(
    val itemReference: String,
    val providerTransactionId: String,
    val paymentReference: String? = null,
    val itemType: ReconciliationItemType,
    val amountMinorUnits: Long,
    val feeMinorUnits: Long = 0L,
    val currencyCode: String,
    val settlementTime: Instant,
)

data class LedgerReconciliationItem(
    val transactionReference: String,
    val accountReference: String,
    val itemType: ReconciliationItemType,
    val amountMinorUnits: Long,
    val currencyCode: String,
    val postedTime: Instant,
)

data class ReconciliationItemEvidence(
    val evidenceId: UUID,
    val itemReference: String,
    val providerTransactionId: String?,
    val ledgerTransactionReference: String?,
    val itemType: ReconciliationItemType,
    val currencyCode: String,
    val providerAmountMinorUnits: Long,
    val ledgerAmountMinorUnits: Long,
    val discrepancyMinorUnits: Long,
    val matchStatus: ItemMatchStatus,
    val discrepancyNotes: String? = null,
)

data class RunReconciliationCommand(
    val tenantId: String,
    val reconciliationReference: String,
    val providerId: String,
    val currencyCode: String,
    val periodStart: Instant,
    val periodEnd: Instant,
    val providerItems: List<ProviderSettlementItem>,
    val ledgerItems: List<LedgerReconciliationItem>,
    val idempotencyKey: String,
    val correlationId: String,
    val causationId: String,
    val expectedVersion: Long = 1L,
    val principal: AuthenticatedPrincipal? = null,
)

data class CloseDiscrepancyCommand(
    val tenantId: String,
    val reconciliationReference: String,
    val reasonCode: String,
    val approverId: String,
    val resolutionNotes: String,
    val idempotencyKey: String,
    val correlationId: String,
    val causationId: String,
    val expectedVersion: Long,
    val principal: AuthenticatedPrincipal? = null,
)

data class ReconciliationResult(
    val resultId: UUID,
    val tenantId: String,
    val reconciliationReference: String,
    val providerId: String,
    val currencyCode: String,
    val periodStart: Instant,
    val periodEnd: Instant,
    val status: ReconciliationBatchStatus,
    val totalProviderAmountMinorUnits: Long,
    val totalLedgerAmountMinorUnits: Long,
    val netDiscrepancyMinorUnits: Long,
    val totalItemsCompared: Int,
    val matchedItemCount: Int,
    val discrepancyItemCount: Int,
    val itemEvidence: List<ReconciliationItemEvidence>,
    val reasonCode: String?,
    val approverId: String?,
    val resolutionNotes: String?,
    val version: Long,
    val isDuplicate: Boolean,
    val evidenceReference: String,
    val serverTime: Instant,
    val semanticContract: String = RECONCILE_PROVIDER_LEDGER_CONTRACT,
)

data class ProviderLedgerReconciliationRecord(
    val recordId: UUID,
    val tenantId: String,
    val reconciliationReference: String,
    val providerId: String,
    val currencyCode: String,
    val periodStart: Instant,
    val periodEnd: Instant,
    val status: ReconciliationBatchStatus,
    val totalProviderAmountMinorUnits: Long,
    val totalLedgerAmountMinorUnits: Long,
    val netDiscrepancyMinorUnits: Long,
    val totalItemsCompared: Int,
    val matchedItemCount: Int,
    val discrepancyItemCount: Int,
    val itemEvidence: List<ReconciliationItemEvidence>,
    val reasonCode: String? = null,
    val approverId: String? = null,
    val resolutionNotes: String? = null,
    val version: Long,
    val evidenceReference: String,
    val createdAt: Instant,
    val updatedAt: Instant,
    val semanticContract: String = RECONCILE_PROVIDER_LEDGER_CONTRACT,
)

data class ProviderLedgerReconciliationSnapshot(
    val reconciliations: Map<String, ProviderLedgerReconciliationRecord>,
    val idempotencyMap: Map<String, Pair<String, ReconciliationResult>>,
    val auditEvents: List<AuditEvent>,
    val outboxEvents: List<OutboxEvent>,
)

interface ProviderLedgerReconciliationAlertSink {
    fun sendAlert(tenantId: String, reference: String, alertType: String, reason: String, detail: String)
}

class InMemoryProviderLedgerReconciliationAlertSink : ProviderLedgerReconciliationAlertSink {
    val alerts = mutableListOf<String>()

    @Synchronized
    override fun sendAlert(tenantId: String, reference: String, alertType: String, reason: String, detail: String) {
        alerts.add("$tenantId:$reference:$alertType:$reason:$detail")
    }
}

interface ProviderLedgerReconciliationStore {
    fun findByReference(tenantId: String, reconciliationReference: String): ProviderLedgerReconciliationRecord?
    fun findByIdempotency(tenantId: String, idempotencyKey: String): Pair<String, ReconciliationResult>?
    fun saveReconciliation(
        record: ProviderLedgerReconciliationRecord,
        result: ReconciliationResult,
        idempotencyKey: String,
        fingerprint: String,
        audit: AuditEvent,
        outbox: OutboxEvent,
    )
    fun updateReconciliation(
        record: ProviderLedgerReconciliationRecord,
        result: ReconciliationResult,
        idempotencyKey: String,
        fingerprint: String,
        audit: AuditEvent,
        outbox: OutboxEvent,
    )
    fun getAuditEvents(): List<AuditEvent>
    fun getOutboxEvents(): List<OutboxEvent>
    fun exportSnapshot(): ProviderLedgerReconciliationSnapshot
    fun importSnapshot(snapshot: ProviderLedgerReconciliationSnapshot)
}

open class InMemoryProviderLedgerReconciliationStore : ProviderLedgerReconciliationStore {
    private val records = ConcurrentHashMap<String, ProviderLedgerReconciliationRecord>()
    private val idempotencyResults = ConcurrentHashMap<String, Pair<String, ReconciliationResult>>()
    private val auditEvents = mutableListOf<AuditEvent>()
    private val outboxEvents = mutableListOf<OutboxEvent>()

    private fun recKey(tenantId: String, ref: String) = "$tenantId:$ref"
    private fun idKey(tenantId: String, idemp: String) = "$tenantId:$idemp"

    @Synchronized
    override fun findByReference(tenantId: String, reconciliationReference: String): ProviderLedgerReconciliationRecord? =
        records[recKey(tenantId, reconciliationReference)]?.copy()

    @Synchronized
    override fun findByIdempotency(tenantId: String, idempotencyKey: String): Pair<String, ReconciliationResult>? =
        idempotencyResults[idKey(tenantId, idempotencyKey)]

    @Synchronized
    open override fun saveReconciliation(
        record: ProviderLedgerReconciliationRecord,
        result: ReconciliationResult,
        idempotencyKey: String,
        fingerprint: String,
        audit: AuditEvent,
        outbox: OutboxEvent,
    ) {
        records[recKey(record.tenantId, record.reconciliationReference)] = record.copy()
        idempotencyResults[idKey(record.tenantId, idempotencyKey)] = fingerprint to result
        auditEvents.add(audit)
        outboxEvents.add(outbox)
    }

    @Synchronized
    override fun updateReconciliation(
        record: ProviderLedgerReconciliationRecord,
        result: ReconciliationResult,
        idempotencyKey: String,
        fingerprint: String,
        audit: AuditEvent,
        outbox: OutboxEvent,
    ) {
        records[recKey(record.tenantId, record.reconciliationReference)] = record.copy()
        idempotencyResults[idKey(record.tenantId, idempotencyKey)] = fingerprint to result
        auditEvents.add(audit)
        outboxEvents.add(outbox)
    }

    @Synchronized
    override fun getAuditEvents(): List<AuditEvent> = auditEvents.toList()

    @Synchronized
    override fun getOutboxEvents(): List<OutboxEvent> = outboxEvents.toList()

    @Synchronized
    override fun exportSnapshot(): ProviderLedgerReconciliationSnapshot = ProviderLedgerReconciliationSnapshot(
        reconciliations = HashMap(records),
        idempotencyMap = HashMap(idempotencyResults),
        auditEvents = ArrayList(auditEvents),
        outboxEvents = ArrayList(outboxEvents),
    )

    @Synchronized
    override fun importSnapshot(snapshot: ProviderLedgerReconciliationSnapshot) {
        records.clear()
        records.putAll(snapshot.reconciliations)
        idempotencyResults.clear()
        idempotencyResults.putAll(snapshot.idempotencyMap)
        auditEvents.clear()
        auditEvents.addAll(snapshot.auditEvents)
        outboxEvents.clear()
        outboxEvents.addAll(snapshot.outboxEvents)
    }
}

class ProviderLedgerReconciliationService(
    private val store: ProviderLedgerReconciliationStore,
    private val alertSink: ProviderLedgerReconciliationAlertSink = InMemoryProviderLedgerReconciliationAlertSink(),
    private val clock: Clock = Clock.systemUTC(),
) {
    private fun sha256(input: String): String {
        val digest = MessageDigest.getInstance("SHA-256")
        val hash = digest.digest(input.toByteArray(StandardCharsets.UTF_8))
        return hash.joinToString("") { "%02x".format(it) }
    }

    private fun fingerprintRun(cmd: RunReconciliationCommand): String {
        val providerHash = cmd.providerItems.joinToString(";") { "${it.itemReference}:${it.providerTransactionId}:${it.amountMinorUnits}:${it.currencyCode}" }
        val ledgerHash = cmd.ledgerItems.joinToString(";") { "${it.transactionReference}:${it.amountMinorUnits}:${it.currencyCode}" }
        return sha256("${cmd.tenantId}:${cmd.reconciliationReference}:${cmd.providerId}:${cmd.currencyCode}:${cmd.periodStart}:${cmd.periodEnd}:$providerHash:$ledgerHash:${cmd.expectedVersion}")
    }

    private fun fingerprintClose(cmd: CloseDiscrepancyCommand): String {
        return sha256("${cmd.tenantId}:${cmd.reconciliationReference}:${cmd.reasonCode}:${cmd.approverId}:${cmd.resolutionNotes}:${cmd.expectedVersion}")
    }

    private fun validateAdminPrincipal(principal: AuthenticatedPrincipal?, tenantId: String) {
        principal?.let {
            if (it.tenantId != tenantId) {
                throw AuthenticationFailure.Rejected(AuthErrorCode.FORBIDDEN)
            }
            if (it.kind != PrincipalKind.ADMIN) {
                throw AuthenticationFailure.Rejected(AuthErrorCode.FORBIDDEN)
            }
            if (it.roles.none { role -> role in setOf(AdminRole.SUPER_ADMIN, AdminRole.SECURITY, AdminRole.AUDITOR) }) {
                throw AuthenticationFailure.Rejected(AuthErrorCode.FORBIDDEN)
            }
        }
    }

    @Synchronized
    fun runReconciliation(command: RunReconciliationCommand): ReconciliationResult {
        // Protected risk assertion: mismatch omitted
        ProviderLedgerReconciliationBinding.checkBound()

        // 1. Mandatory Input Validation
        if (command.tenantId.isBlank() ||
            command.reconciliationReference.isBlank() ||
            command.providerId.isBlank() ||
            command.idempotencyKey.isBlank() ||
            command.correlationId.isBlank() ||
            command.causationId.isBlank()
        ) {
            alertSink.sendAlert(
                tenantId = command.tenantId.ifBlank { "UNKNOWN" },
                reference = command.reconciliationReference.ifBlank { "UNKNOWN" },
                alertType = "RECONCILIATION_INVALID_INPUT",
                reason = "BLANK_MANDATORY_FIELDS",
                detail = "Run reconciliation rejected due to blank mandatory fields",
            )
            throw AuthenticationFailure.Rejected(AuthErrorCode.INVALID)
        }

        if (!command.currencyCode.matches(Regex("^[A-Z]{3}$"))) {
            throw AuthenticationFailure.Rejected(AuthErrorCode.INVALID)
        }

        if (!command.periodStart.isBefore(command.periodEnd)) {
            throw AuthenticationFailure.Rejected(AuthErrorCode.INVALID)
        }

        if (command.expectedVersion != 1L) {
            throw AuthenticationFailure.Rejected(AuthErrorCode.STALE)
        }

        // Validate items non-negative
        if (command.providerItems.any { it.amountMinorUnits < 0L || it.feeMinorUnits < 0L || !it.currencyCode.matches(Regex("^[A-Z]{3}$")) }) {
            throw AuthenticationFailure.Rejected(AuthErrorCode.INVALID)
        }
        if (command.ledgerItems.any { it.amountMinorUnits < 0L || !it.currencyCode.matches(Regex("^[A-Z]{3}$")) }) {
            throw AuthenticationFailure.Rejected(AuthErrorCode.INVALID)
        }

        validateAdminPrincipal(command.principal, command.tenantId)

        val fp = fingerprintRun(command)
        val now = clock.instant()

        // 2. Idempotency Check
        val existingIdemp = store.findByIdempotency(command.tenantId, command.idempotencyKey)
        if (existingIdemp != null) {
            val (cachedFp, cachedResult) = existingIdemp
            if (cachedFp != fp) {
                alertSink.sendAlert(
                    tenantId = command.tenantId,
                    reference = command.reconciliationReference,
                    alertType = "RECONCILIATION_IDEMPOTENCY_CONFLICT",
                    reason = "PAYLOAD_MISMATCH",
                    detail = "Payload mismatch detected for reconciliation idempotency key ${command.idempotencyKey}",
                )
                throw AuthenticationFailure.Rejected(AuthErrorCode.CONFLICT)
            }
            return cachedResult.copy(isDuplicate = true)
        }

        val existingRec = store.findByReference(command.tenantId, command.reconciliationReference)
        if (existingRec != null) {
            alertSink.sendAlert(
                tenantId = command.tenantId,
                reference = command.reconciliationReference,
                alertType = "RECONCILIATION_REFERENCE_CONFLICT",
                reason = "REFERENCE_ALREADY_EXISTS",
                detail = "Reconciliation reference ${command.reconciliationReference} already exists",
            )
            throw AuthenticationFailure.Rejected(AuthErrorCode.CONFLICT)
        }

        // 3. Item-Level Matching & Evidence Assembly
        // Index ledger items by transaction reference
        val ledgerByTx = command.ledgerItems.associateBy { it.transactionReference }
        val matchedLedgerTxs = mutableSetOf<String>()
        val evidenceList = mutableListOf<ReconciliationItemEvidence>()

        var totalProviderMinorUnits = 0L
        var totalLedgerMinorUnits = 0L
        var matchedCount = 0

        // Process all provider items
        for (pItem in command.providerItems) {
            totalProviderMinorUnits += pItem.amountMinorUnits

            // Look up corresponding ledger entry
            val candidateKeys = listOfNotNull(
                pItem.providerTransactionId,
                pItem.paymentReference,
                "TX-DEP-${pItem.paymentReference}",
                "TX-COMP-${pItem.paymentReference}",
                pItem.itemReference,
            )
            val matchedLedger = candidateKeys.firstNotNullOfOrNull { ledgerByTx[it] }

            if (matchedLedger != null) {
                matchedLedgerTxs.add(matchedLedger.transactionReference)
                val isAmountMatch = matchedLedger.amountMinorUnits == pItem.amountMinorUnits
                val isCurrencyMatch = matchedLedger.currencyCode == pItem.currencyCode

                val matchStatus = when {
                    !isCurrencyMatch -> ItemMatchStatus.CURRENCY_MISMATCH
                    !isAmountMatch -> ItemMatchStatus.AMOUNT_MISMATCH
                    else -> ItemMatchStatus.MATCHED
                }

                val discrepancy = pItem.amountMinorUnits - matchedLedger.amountMinorUnits
                if (matchStatus == ItemMatchStatus.MATCHED) {
                    matchedCount++
                }

                evidenceList.add(
                    ReconciliationItemEvidence(
                        evidenceId = UUID.randomUUID(),
                        itemReference = pItem.itemReference,
                        providerTransactionId = pItem.providerTransactionId,
                        ledgerTransactionReference = matchedLedger.transactionReference,
                        itemType = pItem.itemType,
                        currencyCode = pItem.currencyCode,
                        providerAmountMinorUnits = pItem.amountMinorUnits,
                        ledgerAmountMinorUnits = matchedLedger.amountMinorUnits,
                        discrepancyMinorUnits = discrepancy,
                        matchStatus = matchStatus,
                        discrepancyNotes = if (matchStatus != ItemMatchStatus.MATCHED) "Mismatch between provider (${pItem.amountMinorUnits}) and ledger (${matchedLedger.amountMinorUnits})" else null,
                    )
                )
            } else {
                // Provider item completely missing in ledger
                evidenceList.add(
                    ReconciliationItemEvidence(
                        evidenceId = UUID.randomUUID(),
                        itemReference = pItem.itemReference,
                        providerTransactionId = pItem.providerTransactionId,
                        ledgerTransactionReference = null,
                        itemType = pItem.itemType,
                        currencyCode = pItem.currencyCode,
                        providerAmountMinorUnits = pItem.amountMinorUnits,
                        ledgerAmountMinorUnits = 0L,
                        discrepancyMinorUnits = pItem.amountMinorUnits,
                        matchStatus = ItemMatchStatus.MISSING_IN_LEDGER,
                        discrepancyNotes = "Provider settlement item missing in double-entry ledger",
                    )
                )
            }
        }

        // Process remaining ledger items missing in provider report
        for (lItem in command.ledgerItems) {
            totalLedgerMinorUnits += lItem.amountMinorUnits
            if (lItem.transactionReference !in matchedLedgerTxs) {
                evidenceList.add(
                    ReconciliationItemEvidence(
                        evidenceId = UUID.randomUUID(),
                        itemReference = "LEDGER-${lItem.transactionReference}",
                        providerTransactionId = null,
                        ledgerTransactionReference = lItem.transactionReference,
                        itemType = lItem.itemType,
                        currencyCode = lItem.currencyCode,
                        providerAmountMinorUnits = 0L,
                        ledgerAmountMinorUnits = lItem.amountMinorUnits,
                        discrepancyMinorUnits = -lItem.amountMinorUnits,
                        matchStatus = ItemMatchStatus.MISSING_IN_PROVIDER,
                        discrepancyNotes = "Ledger transaction missing in provider settlement statement",
                    )
                )
            }
        }

        // 4. Totals and Discrepancy Calculation
        // Semantic contract: "Totals and item-level evidence; close requires reason/approver."
        val discrepancyCount = evidenceList.count { it.matchStatus != ItemMatchStatus.MATCHED }
        val netDiscrepancy = totalProviderMinorUnits - totalLedgerMinorUnits
        val status = if (discrepancyCount == 0) ReconciliationBatchStatus.BALANCED else ReconciliationBatchStatus.DISCREPANCY_DETECTED

        if (status == ReconciliationBatchStatus.DISCREPANCY_DETECTED) {
            alertSink.sendAlert(
                tenantId = command.tenantId,
                reference = command.reconciliationReference,
                alertType = "RECONCILIATION_MISMATCH_DETECTED",
                reason = "DISCREPANCIES_FOUND",
                detail = "Detected $discrepancyCount discrepancy items. Provider total: $totalProviderMinorUnits, Ledger total: $totalLedgerMinorUnits, Net difference: $netDiscrepancy.",
            )
        }

        val recordId = UUID.randomUUID()
        val resultId = UUID.randomUUID()
        val evidenceRef = "REC-EVID-$recordId"

        val record = ProviderLedgerReconciliationRecord(
            recordId = recordId,
            tenantId = command.tenantId,
            reconciliationReference = command.reconciliationReference,
            providerId = command.providerId,
            currencyCode = command.currencyCode,
            periodStart = command.periodStart,
            periodEnd = command.periodEnd,
            status = status,
            totalProviderAmountMinorUnits = totalProviderMinorUnits,
            totalLedgerAmountMinorUnits = totalLedgerMinorUnits,
            netDiscrepancyMinorUnits = netDiscrepancy,
            totalItemsCompared = evidenceList.size,
            matchedItemCount = matchedCount,
            discrepancyItemCount = discrepancyCount,
            itemEvidence = evidenceList,
            version = 1L,
            evidenceReference = evidenceRef,
            createdAt = now,
            updatedAt = now,
            semanticContract = RECONCILE_PROVIDER_LEDGER_CONTRACT,
        )

        val result = ReconciliationResult(
            resultId = resultId,
            tenantId = command.tenantId,
            reconciliationReference = command.reconciliationReference,
            providerId = command.providerId,
            currencyCode = command.currencyCode,
            periodStart = command.periodStart,
            periodEnd = command.periodEnd,
            status = status,
            totalProviderAmountMinorUnits = totalProviderMinorUnits,
            totalLedgerAmountMinorUnits = totalLedgerMinorUnits,
            netDiscrepancyMinorUnits = netDiscrepancy,
            totalItemsCompared = evidenceList.size,
            matchedItemCount = matchedCount,
            discrepancyItemCount = discrepancyCount,
            itemEvidence = evidenceList,
            reasonCode = null,
            approverId = null,
            resolutionNotes = null,
            version = 1L,
            isDuplicate = false,
            evidenceReference = evidenceRef,
            serverTime = now,
            semanticContract = RECONCILE_PROVIDER_LEDGER_CONTRACT,
        )

        val eventType = if (status == ReconciliationBatchStatus.BALANCED) "RECONCILIATION_BALANCED" else "RECONCILIATION_DISCREPANCIES_DETECTED"
        val audit = AuditEvent(UUID.randomUUID(), recordId, command.tenantId, eventType, now, command.correlationId, command.causationId)
        val outbox = OutboxEvent(UUID.randomUUID(), recordId, command.tenantId, eventType, now)

        try {
            store.saveReconciliation(record, result, command.idempotencyKey, fp, audit, outbox)
        } catch (e: Exception) {
            alertSink.sendAlert(
                tenantId = command.tenantId,
                reference = command.reconciliationReference,
                alertType = "RECONCILIATION_STORAGE_FAILED",
                reason = "STORE_FAILURE",
                detail = "Failed to save reconciliation batch: ${e.message}",
            )
            throw AuthenticationFailure.Rejected(AuthErrorCode.DEPENDENCY_UNAVAILABLE)
        }

        return result
    }

    @Synchronized
    fun closeDiscrepancy(command: CloseDiscrepancyCommand): ReconciliationResult {
        // Protected risk assertion: mismatch omitted
        ProviderLedgerReconciliationBinding.checkBound()

        // Semantic contract requirement: "close requires reason/approver"
        if (command.reasonCode.isBlank() || command.approverId.isBlank()) {
            alertSink.sendAlert(
                tenantId = command.tenantId.ifBlank { "UNKNOWN" },
                reference = command.reconciliationReference.ifBlank { "UNKNOWN" },
                alertType = "RECONCILIATION_CLOSE_REJECTED",
                reason = "MISSING_REASON_OR_APPROVER",
                detail = "Discrepancy close rejected: reasonCode and approverId are mandatory under dual-control contract",
            )
            throw AuthenticationFailure.Rejected(AuthErrorCode.INVALID)
        }

        if (command.tenantId.isBlank() ||
            command.reconciliationReference.isBlank() ||
            command.resolutionNotes.isBlank() ||
            command.idempotencyKey.isBlank() ||
            command.correlationId.isBlank() ||
            command.causationId.isBlank()
        ) {
            throw AuthenticationFailure.Rejected(AuthErrorCode.INVALID)
        }

        validateAdminPrincipal(command.principal, command.tenantId)

        val fp = fingerprintClose(command)
        val now = clock.instant()

        val existingIdemp = store.findByIdempotency(command.tenantId, command.idempotencyKey)
        if (existingIdemp != null) {
            val (cachedFp, cachedResult) = existingIdemp
            if (cachedFp != fp) {
                throw AuthenticationFailure.Rejected(AuthErrorCode.CONFLICT)
            }
            return cachedResult.copy(isDuplicate = true)
        }

        val existingRecord = store.findByReference(command.tenantId, command.reconciliationReference)
            ?: throw AuthenticationFailure.Rejected(AuthErrorCode.INVALID)

        if (existingRecord.version != command.expectedVersion) {
            throw AuthenticationFailure.Rejected(AuthErrorCode.STALE)
        }

        if (existingRecord.status == ReconciliationBatchStatus.CLOSED || existingRecord.status == ReconciliationBatchStatus.WAIVED) {
            throw AuthenticationFailure.Rejected(AuthErrorCode.CONFLICT)
        }

        val updatedRecord = existingRecord.copy(
            status = ReconciliationBatchStatus.CLOSED,
            reasonCode = command.reasonCode,
            approverId = command.approverId,
            resolutionNotes = command.resolutionNotes,
            version = existingRecord.version + 1,
            updatedAt = now,
        )

        val result = ReconciliationResult(
            resultId = UUID.randomUUID(),
            tenantId = updatedRecord.tenantId,
            reconciliationReference = updatedRecord.reconciliationReference,
            providerId = updatedRecord.providerId,
            currencyCode = updatedRecord.currencyCode,
            periodStart = updatedRecord.periodStart,
            periodEnd = updatedRecord.periodEnd,
            status = ReconciliationBatchStatus.CLOSED,
            totalProviderAmountMinorUnits = updatedRecord.totalProviderAmountMinorUnits,
            totalLedgerAmountMinorUnits = updatedRecord.totalLedgerAmountMinorUnits,
            netDiscrepancyMinorUnits = updatedRecord.netDiscrepancyMinorUnits,
            totalItemsCompared = updatedRecord.totalItemsCompared,
            matchedItemCount = updatedRecord.matchedItemCount,
            discrepancyItemCount = updatedRecord.discrepancyItemCount,
            itemEvidence = updatedRecord.itemEvidence,
            reasonCode = command.reasonCode,
            approverId = command.approverId,
            resolutionNotes = command.resolutionNotes,
            version = updatedRecord.version,
            isDuplicate = false,
            evidenceReference = "REC-CLOSE-EVID-${UUID.randomUUID()}",
            serverTime = now,
            semanticContract = RECONCILE_PROVIDER_LEDGER_CONTRACT,
        )

        alertSink.sendAlert(
            tenantId = command.tenantId,
            reference = command.reconciliationReference,
            alertType = "RECONCILIATION_DISCREPANCY_CLOSED",
            reason = command.reasonCode,
            detail = "Discrepancy closed by approver ${command.approverId}: ${command.resolutionNotes}",
        )

        val audit = AuditEvent(UUID.randomUUID(), existingRecord.recordId, command.tenantId, "RECONCILIATION_DISCREPANCY_CLOSED", now, command.correlationId, command.causationId)
        val outbox = OutboxEvent(UUID.randomUUID(), existingRecord.recordId, command.tenantId, "RECONCILIATION_DISCREPANCY_CLOSED", now)

        try {
            store.updateReconciliation(updatedRecord, result, command.idempotencyKey, fp, audit, outbox)
        } catch (e: Exception) {
            alertSink.sendAlert(
                tenantId = command.tenantId,
                reference = command.reconciliationReference,
                alertType = "RECONCILIATION_STORAGE_FAILED",
                reason = "STORE_FAILURE",
                detail = "Failed to update reconciliation batch: ${e.message}",
            )
            throw AuthenticationFailure.Rejected(AuthErrorCode.DEPENDENCY_UNAVAILABLE)
        }

        return result
    }
}
