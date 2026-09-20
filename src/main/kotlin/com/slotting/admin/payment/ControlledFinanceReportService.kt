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
 * Fail-closed verification gate for PAYMENT-007-02: Produce controlled finance reconciliation reports.
 * Throws expected RED failure until contract bindings and invariant protections are verified.
 * Protected risk: False completion or non-authoritative implementation of Controlled finance reconciliation reports.
 * Rationale: It exists to prevent: mismatch omitted.
 */
object ControlledFinanceReportBinding {
    @Volatile
    var isBound: Boolean = false

    fun checkBound() {
        if (!isBound) {
            throw AssertionError("mismatch omitted")
        }
    }
}

/**
 * Outcome-specific semantic contract for PAYMENT-007-02.
 */
const val CONTROLLED_FINANCE_REPORT_CONTRACT =
    "Totals and item-level evidence; close requires reason/approver."

enum class ControlledReportStatus {
    BALANCED,
    IMBALANCED,
    RESOLVED,
    CLOSED,
}

enum class ControlledReportAction {
    GENERATE,
    CLOSE_MISMATCH,
    WAIVE,
}

data class FinanceItemEvidence(
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

data class FinanceSummaryTotals(
    val totalGrossDepositsMinorUnits: Long,
    val totalPayoutsMinorUnits: Long,
    val totalRefundsMinorUnits: Long,
    val totalReversalsMinorUnits: Long,
    val totalFeesMinorUnits: Long,
    val totalProviderAmountMinorUnits: Long,
    val totalLedgerAmountMinorUnits: Long,
    val netDiscrepancyMinorUnits: Long,
    val totalItemCount: Int,
    val matchedItemCount: Int,
    val discrepancyItemCount: Int,
)

data class ControlledFinanceReportRecord(
    val reportId: UUID,
    val tenantId: String,
    val reportReference: String,
    val providerId: String,
    val currencyCode: String,
    val periodStart: Instant,
    val periodEnd: Instant,
    val status: ControlledReportStatus,
    val totals: FinanceSummaryTotals,
    val itemEvidence: List<FinanceItemEvidence>,
    val reasonCode: String? = null,
    val approverId: String? = null,
    val resolutionNotes: String? = null,
    val exportChecksumSha256: String,
    val version: Long,
    val evidenceReference: String,
    val createdAt: Instant,
    val updatedAt: Instant,
    val semanticContract: String = CONTROLLED_FINANCE_REPORT_CONTRACT,
)

data class ControlledFinanceReportResult(
    val resultId: UUID,
    val report: ControlledFinanceReportRecord,
    val serverTime: Instant,
    val isDuplicate: Boolean,
    val semanticContract: String = CONTROLLED_FINANCE_REPORT_CONTRACT,
)

data class GenerateControlledFinanceReportCommand(
    val tenantId: String,
    val reportReference: String,
    val providerId: String,
    val currencyCode: String,
    val periodStart: Instant,
    val periodEnd: Instant,
    val providerItems: List<ProviderSettlementItem> = emptyList(),
    val ledgerItems: List<LedgerReconciliationItem> = emptyList(),
    val reconciliationReference: String? = null,
    val idempotencyKey: String,
    val correlationId: String,
    val causationId: String,
    val expectedVersion: Long = 1L,
    val principal: AuthenticatedPrincipal? = null,
)

data class CloseFinanceReportMismatchCommand(
    val tenantId: String,
    val reportReference: String,
    val reasonCode: String,
    val approverId: String,
    val resolutionNotes: String,
    val idempotencyKey: String,
    val correlationId: String,
    val causationId: String,
    val expectedVersion: Long,
    val principal: AuthenticatedPrincipal? = null,
)

data class WaiveFinanceReportCommand(
    val tenantId: String,
    val reportReference: String,
    val idempotencyKey: String,
    val correlationId: String,
    val causationId: String,
    val expectedVersion: Long,
    val principal: AuthenticatedPrincipal? = null,
)

data class ControlledFinanceReportSnapshot(
    val reports: Map<String, ControlledFinanceReportRecord>,
    val idempotencyMap: Map<String, Pair<String, ControlledFinanceReportResult>>,
    val auditEvents: List<AuditEvent>,
    val outboxEvents: List<OutboxEvent>,
)

interface ControlledFinanceReportAlertSink {
    fun sendAlert(tenantId: String, reference: String, alertType: String, reason: String, detail: String)
}

class InMemoryControlledFinanceReportAlertSink : ControlledFinanceReportAlertSink {
    val alerts = mutableListOf<String>()

    @Synchronized
    override fun sendAlert(tenantId: String, reference: String, alertType: String, reason: String, detail: String) {
        alerts.add("$tenantId:$reference:$alertType:$reason:$detail")
    }
}

interface ControlledFinanceReportStore {
    fun findByReference(tenantId: String, reportReference: String): ControlledFinanceReportRecord?
    fun findByIdempotency(tenantId: String, idempotencyKey: String): Pair<String, ControlledFinanceReportResult>?
    fun saveReport(
        record: ControlledFinanceReportRecord,
        result: ControlledFinanceReportResult,
        idempotencyKey: String,
        fingerprint: String,
        audit: AuditEvent,
        outbox: OutboxEvent,
    )
    fun updateReport(
        record: ControlledFinanceReportRecord,
        result: ControlledFinanceReportResult,
        idempotencyKey: String,
        fingerprint: String,
        audit: AuditEvent,
        outbox: OutboxEvent,
    )
    fun getAuditEvents(): List<AuditEvent>
    fun getOutboxEvents(): List<OutboxEvent>
    fun exportSnapshot(): ControlledFinanceReportSnapshot
    fun importSnapshot(snapshot: ControlledFinanceReportSnapshot)
}

open class InMemoryControlledFinanceReportStore : ControlledFinanceReportStore {
    private val records = ConcurrentHashMap<String, ControlledFinanceReportRecord>()
    private val idempotencyResults = ConcurrentHashMap<String, Pair<String, ControlledFinanceReportResult>>()
    private val auditEvents = mutableListOf<AuditEvent>()
    private val outboxEvents = mutableListOf<OutboxEvent>()

    private fun repKey(tenantId: String, ref: String) = "$tenantId:$ref"
    private fun idKey(tenantId: String, idemp: String) = "$tenantId:$idemp"

    @Synchronized
    override fun findByReference(tenantId: String, reportReference: String): ControlledFinanceReportRecord? =
        records[repKey(tenantId, reportReference)]?.copy()

    @Synchronized
    override fun findByIdempotency(tenantId: String, idempotencyKey: String): Pair<String, ControlledFinanceReportResult>? =
        idempotencyResults[idKey(tenantId, idempotencyKey)]

    @Synchronized
    open override fun saveReport(
        record: ControlledFinanceReportRecord,
        result: ControlledFinanceReportResult,
        idempotencyKey: String,
        fingerprint: String,
        audit: AuditEvent,
        outbox: OutboxEvent,
    ) {
        records[repKey(record.tenantId, record.reportReference)] = record.copy()
        idempotencyResults[idKey(record.tenantId, idempotencyKey)] = fingerprint to result
        auditEvents.add(audit)
        outboxEvents.add(outbox)
    }

    @Synchronized
    override fun updateReport(
        record: ControlledFinanceReportRecord,
        result: ControlledFinanceReportResult,
        idempotencyKey: String,
        fingerprint: String,
        audit: AuditEvent,
        outbox: OutboxEvent,
    ) {
        records[repKey(record.tenantId, record.reportReference)] = record.copy()
        idempotencyResults[idKey(record.tenantId, idempotencyKey)] = fingerprint to result
        auditEvents.add(audit)
        outboxEvents.add(outbox)
    }

    @Synchronized
    override fun getAuditEvents(): List<AuditEvent> = auditEvents.toList()

    @Synchronized
    override fun getOutboxEvents(): List<OutboxEvent> = outboxEvents.toList()

    @Synchronized
    override fun exportSnapshot(): ControlledFinanceReportSnapshot = ControlledFinanceReportSnapshot(
        reports = HashMap(records),
        idempotencyMap = HashMap(idempotencyResults),
        auditEvents = ArrayList(auditEvents),
        outboxEvents = ArrayList(outboxEvents),
    )

    @Synchronized
    override fun importSnapshot(snapshot: ControlledFinanceReportSnapshot) {
        records.clear()
        records.putAll(snapshot.reports)
        idempotencyResults.clear()
        idempotencyResults.putAll(snapshot.idempotencyMap)
        auditEvents.clear()
        auditEvents.addAll(snapshot.auditEvents)
        outboxEvents.clear()
        outboxEvents.addAll(snapshot.outboxEvents)
    }
}

class ControlledFinanceReportService(
    private val store: ControlledFinanceReportStore,
    private val alertSink: ControlledFinanceReportAlertSink = InMemoryControlledFinanceReportAlertSink(),
    private val reconciliationStore: ProviderLedgerReconciliationStore? = null,
    private val clock: Clock = Clock.systemUTC(),
) {
    private fun sha256(input: String): String {
        val digest = MessageDigest.getInstance("SHA-256")
        val hash = digest.digest(input.toByteArray(StandardCharsets.UTF_8))
        return hash.joinToString("") { "%02x".format(it) }
    }

    private fun computeChecksum(
        tenantId: String,
        reportReference: String,
        providerId: String,
        currencyCode: String,
        periodStart: Instant,
        periodEnd: Instant,
        totals: FinanceSummaryTotals,
        evidence: List<FinanceItemEvidence>,
        status: ControlledReportStatus,
        reasonCode: String?,
        approverId: String?,
    ): String {
        val evidenceDigest = evidence
            .sortedBy { it.itemReference }
            .joinToString("|") {
                "${it.evidenceId}:${it.itemReference}:${it.providerTransactionId}:${it.ledgerTransactionReference}:${it.itemType}:${it.currencyCode}:${it.providerAmountMinorUnits}:${it.ledgerAmountMinorUnits}:${it.discrepancyMinorUnits}:${it.matchStatus}"
            }
        val totalsDigest = "${totals.totalGrossDepositsMinorUnits}:${totals.totalPayoutsMinorUnits}:${totals.totalRefundsMinorUnits}:${totals.totalReversalsMinorUnits}:${totals.totalFeesMinorUnits}:${totals.totalProviderAmountMinorUnits}:${totals.totalLedgerAmountMinorUnits}:${totals.netDiscrepancyMinorUnits}:${totals.totalItemCount}:${totals.matchedItemCount}:${totals.discrepancyItemCount}"
        val raw = "$tenantId:$reportReference:$providerId:$currencyCode:$periodStart:$periodEnd:$status:$reasonCode:$approverId:$totalsDigest:$evidenceDigest"
        return sha256(raw)
    }

    private fun fingerprintGenerate(cmd: GenerateControlledFinanceReportCommand): String {
        val providerHash = cmd.providerItems.joinToString(";") { "${it.itemReference}:${it.providerTransactionId}:${it.amountMinorUnits}:${it.currencyCode}" }
        val ledgerHash = cmd.ledgerItems.joinToString(";") { "${it.transactionReference}:${it.amountMinorUnits}:${it.currencyCode}" }
        return sha256("${cmd.tenantId}:${cmd.reportReference}:${cmd.providerId}:${cmd.currencyCode}:${cmd.periodStart}:${cmd.periodEnd}:${cmd.reconciliationReference}:$providerHash:$ledgerHash:${cmd.expectedVersion}")
    }

    private fun fingerprintClose(cmd: CloseFinanceReportMismatchCommand): String {
        return sha256("${cmd.tenantId}:${cmd.reportReference}:${cmd.reasonCode}:${cmd.approverId}:${cmd.resolutionNotes}:${cmd.expectedVersion}")
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
    fun generateReport(command: GenerateControlledFinanceReportCommand): ControlledFinanceReportResult {
        // Protected risk assertion: mismatch omitted
        ControlledFinanceReportBinding.checkBound()

        // 1. Mandatory Input Validation
        if (command.tenantId.isBlank() ||
            command.reportReference.isBlank() ||
            command.providerId.isBlank() ||
            command.idempotencyKey.isBlank() ||
            command.correlationId.isBlank() ||
            command.causationId.isBlank()
        ) {
            alertSink.sendAlert(
                tenantId = command.tenantId.ifBlank { "UNKNOWN" },
                reference = command.reportReference.ifBlank { "UNKNOWN" },
                alertType = "FINANCE_REPORT_INVALID_INPUT",
                reason = "BLANK_MANDATORY_FIELDS",
                detail = "Report generation rejected due to blank mandatory fields",
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

        if (command.providerItems.any { it.amountMinorUnits < 0L || it.feeMinorUnits < 0L || !it.currencyCode.matches(Regex("^[A-Z]{3}$")) }) {
            throw AuthenticationFailure.Rejected(AuthErrorCode.INVALID)
        }
        if (command.ledgerItems.any { it.amountMinorUnits < 0L || !it.currencyCode.matches(Regex("^[A-Z]{3}$")) }) {
            throw AuthenticationFailure.Rejected(AuthErrorCode.INVALID)
        }

        validateAdminPrincipal(command.principal, command.tenantId)

        val fp = fingerprintGenerate(command)
        val now = clock.instant()

        // 2. Idempotency Check
        val existingIdemp = store.findByIdempotency(command.tenantId, command.idempotencyKey)
        if (existingIdemp != null) {
            val (cachedFp, cachedResult) = existingIdemp
            if (cachedFp != fp) {
                alertSink.sendAlert(
                    tenantId = command.tenantId,
                    reference = command.reportReference,
                    alertType = "FINANCE_REPORT_IDEMPOTENCY_CONFLICT",
                    reason = "PAYLOAD_MISMATCH",
                    detail = "Payload mismatch detected for finance report idempotency key ${command.idempotencyKey}",
                )
                throw AuthenticationFailure.Rejected(AuthErrorCode.CONFLICT)
            }
            return cachedResult.copy(isDuplicate = true)
        }

        val existingReport = store.findByReference(command.tenantId, command.reportReference)
        if (existingReport != null) {
            alertSink.sendAlert(
                tenantId = command.tenantId,
                reference = command.reportReference,
                alertType = "FINANCE_REPORT_REFERENCE_CONFLICT",
                reason = "REFERENCE_ALREADY_EXISTS",
                detail = "Report reference ${command.reportReference} already exists",
            )
            throw AuthenticationFailure.Rejected(AuthErrorCode.CONFLICT)
        }

        // 3. Assemble Items & Reconciliation Evidence
        val effectiveProviderItems = mutableListOf<ProviderSettlementItem>()
        val effectiveLedgerItems = mutableListOf<LedgerReconciliationItem>()

        effectiveProviderItems.addAll(command.providerItems)
        effectiveLedgerItems.addAll(command.ledgerItems)

        // If reconciliationReference is specified and store is available, integrate existing reconciliation items
        val sourceReconciliation = if (!command.reconciliationReference.isNullOrBlank() && reconciliationStore != null) {
            reconciliationStore.findByReference(command.tenantId, command.reconciliationReference)
        } else null

        val ledgerByTx = effectiveLedgerItems.associateBy { it.transactionReference }
        val matchedLedgerTxs = mutableSetOf<String>()
        val evidenceList = mutableListOf<FinanceItemEvidence>()

        var totalDeposits = 0L
        var totalPayouts = 0L
        var totalRefunds = 0L
        var totalReversals = 0L
        var totalFees = 0L
        var totalProviderAmount = 0L
        var totalLedgerAmount = 0L
        var matchedCount = 0

        // If we have an existing source reconciliation record, incorporate its item evidence directly
        if (sourceReconciliation != null) {
            for (ev in sourceReconciliation.itemEvidence) {
                totalProviderAmount += ev.providerAmountMinorUnits
                totalLedgerAmount += ev.ledgerAmountMinorUnits
                when (ev.itemType) {
                    ReconciliationItemType.DEPOSIT -> totalDeposits += ev.providerAmountMinorUnits
                    ReconciliationItemType.PAYOUT -> totalPayouts += ev.providerAmountMinorUnits
                    ReconciliationItemType.REFUND -> totalRefunds += ev.providerAmountMinorUnits
                    ReconciliationItemType.REVERSAL -> totalReversals += ev.providerAmountMinorUnits
                    ReconciliationItemType.FEE -> totalFees += ev.providerAmountMinorUnits
                }
                if (ev.matchStatus == ItemMatchStatus.MATCHED) {
                    matchedCount++
                }
                evidenceList.add(
                    FinanceItemEvidence(
                        evidenceId = ev.evidenceId,
                        itemReference = ev.itemReference,
                        providerTransactionId = ev.providerTransactionId,
                        ledgerTransactionReference = ev.ledgerTransactionReference,
                        itemType = ev.itemType,
                        currencyCode = ev.currencyCode,
                        providerAmountMinorUnits = ev.providerAmountMinorUnits,
                        ledgerAmountMinorUnits = ev.ledgerAmountMinorUnits,
                        discrepancyMinorUnits = ev.discrepancyMinorUnits,
                        matchStatus = ev.matchStatus,
                        discrepancyNotes = ev.discrepancyNotes,
                    )
                )
            }
        }

        // Process explicit provider items
        for (pItem in effectiveProviderItems) {
            totalProviderAmount += pItem.amountMinorUnits
            totalFees += pItem.feeMinorUnits
            when (pItem.itemType) {
                ReconciliationItemType.DEPOSIT -> totalDeposits += pItem.amountMinorUnits
                ReconciliationItemType.PAYOUT -> totalPayouts += pItem.amountMinorUnits
                ReconciliationItemType.REFUND -> totalRefunds += pItem.amountMinorUnits
                ReconciliationItemType.REVERSAL -> totalReversals += pItem.amountMinorUnits
                ReconciliationItemType.FEE -> totalFees += pItem.amountMinorUnits
            }

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
                    FinanceItemEvidence(
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
                        discrepancyNotes = if (matchStatus != ItemMatchStatus.MATCHED) "Discrepancy: provider=${pItem.amountMinorUnits}, ledger=${matchedLedger.amountMinorUnits}" else null,
                    )
                )
            } else {
                evidenceList.add(
                    FinanceItemEvidence(
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

        // Process remaining ledger items
        for (lItem in effectiveLedgerItems) {
            totalLedgerAmount += lItem.amountMinorUnits
            if (lItem.transactionReference !in matchedLedgerTxs) {
                evidenceList.add(
                    FinanceItemEvidence(
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
                        discrepancyNotes = "Ledger transaction missing in provider settlement",
                    )
                )
            }
        }

        // 4. Totals and Controlled Finance Summary
        val discrepancyCount = evidenceList.count { it.matchStatus != ItemMatchStatus.MATCHED }
        val netDiscrepancy = totalProviderAmount - totalLedgerAmount

        val totals = FinanceSummaryTotals(
            totalGrossDepositsMinorUnits = totalDeposits,
            totalPayoutsMinorUnits = totalPayouts,
            totalRefundsMinorUnits = totalRefunds,
            totalReversalsMinorUnits = totalReversals,
            totalFeesMinorUnits = totalFees,
            totalProviderAmountMinorUnits = totalProviderAmount,
            totalLedgerAmountMinorUnits = totalLedgerAmount,
            netDiscrepancyMinorUnits = netDiscrepancy,
            totalItemCount = evidenceList.size,
            matchedItemCount = matchedCount,
            discrepancyItemCount = discrepancyCount,
        )

        val status = if (discrepancyCount == 0 && netDiscrepancy == 0L) {
            ControlledReportStatus.BALANCED
        } else {
            ControlledReportStatus.IMBALANCED
        }

        if (status == ControlledReportStatus.IMBALANCED) {
            alertSink.sendAlert(
                tenantId = command.tenantId,
                reference = command.reportReference,
                alertType = "FINANCE_REPORT_IMBALANCE_DETECTED",
                reason = "DISCREPANCIES_PRESENT",
                detail = "Finance report ${command.reportReference} has $discrepancyCount discrepancies, net difference $netDiscrepancy",
            )
        }

        val reportId = UUID.randomUUID()
        val resultId = UUID.randomUUID()
        val checksum = computeChecksum(
            tenantId = command.tenantId,
            reportReference = command.reportReference,
            providerId = command.providerId,
            currencyCode = command.currencyCode,
            periodStart = command.periodStart,
            periodEnd = command.periodEnd,
            totals = totals,
            evidence = evidenceList,
            status = status,
            reasonCode = null,
            approverId = null,
        )

        val record = ControlledFinanceReportRecord(
            reportId = reportId,
            tenantId = command.tenantId,
            reportReference = command.reportReference,
            providerId = command.providerId,
            currencyCode = command.currencyCode,
            periodStart = command.periodStart,
            periodEnd = command.periodEnd,
            status = status,
            totals = totals,
            itemEvidence = evidenceList,
            reasonCode = null,
            approverId = null,
            resolutionNotes = null,
            exportChecksumSha256 = checksum,
            version = 1L,
            evidenceReference = "EVID-FIN-$reportId",
            createdAt = now,
            updatedAt = now,
            semanticContract = CONTROLLED_FINANCE_REPORT_CONTRACT,
        )

        val result = ControlledFinanceReportResult(
            resultId = resultId,
            report = record,
            serverTime = now,
            isDuplicate = false,
            semanticContract = CONTROLLED_FINANCE_REPORT_CONTRACT,
        )

        val eventType = if (status == ControlledReportStatus.BALANCED) "FINANCE_REPORT_BALANCED" else "FINANCE_REPORT_IMBALANCED"
        val audit = AuditEvent(UUID.randomUUID(), reportId, command.tenantId, eventType, now, command.correlationId, command.causationId)
        val outbox = OutboxEvent(UUID.randomUUID(), reportId, command.tenantId, eventType, now)

        try {
            store.saveReport(record, result, command.idempotencyKey, fp, audit, outbox)
        } catch (e: Exception) {
            alertSink.sendAlert(
                tenantId = command.tenantId,
                reference = command.reportReference,
                alertType = "FINANCE_REPORT_STORAGE_FAILED",
                reason = "STORE_FAILURE",
                detail = "Failed to store finance report: ${e.message}",
            )
            throw AuthenticationFailure.Rejected(AuthErrorCode.DEPENDENCY_UNAVAILABLE)
        }

        return result
    }

    @Synchronized
    fun closeMismatch(command: CloseFinanceReportMismatchCommand): ControlledFinanceReportResult {
        // Protected risk assertion: mismatch omitted
        ControlledFinanceReportBinding.checkBound()

        // Semantic contract requirement: "close requires reason/approver"
        if (command.reasonCode.isBlank() || command.approverId.isBlank()) {
            alertSink.sendAlert(
                tenantId = command.tenantId.ifBlank { "UNKNOWN" },
                reference = command.reportReference.ifBlank { "UNKNOWN" },
                alertType = "FINANCE_REPORT_CLOSE_REJECTED",
                reason = "MISSING_REASON_OR_APPROVER",
                detail = "Finance report close rejected: reasonCode and approverId are mandatory under dual-control contract",
            )
            throw AuthenticationFailure.Rejected(AuthErrorCode.INVALID)
        }

        if (command.tenantId.isBlank() ||
            command.reportReference.isBlank() ||
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

        val existingReport = store.findByReference(command.tenantId, command.reportReference)
            ?: throw AuthenticationFailure.Rejected(AuthErrorCode.INVALID)

        if (existingReport.version != command.expectedVersion) {
            throw AuthenticationFailure.Rejected(AuthErrorCode.STALE)
        }

        if (existingReport.status == ControlledReportStatus.CLOSED || existingReport.status == ControlledReportStatus.RESOLVED) {
            throw AuthenticationFailure.Rejected(AuthErrorCode.CONFLICT)
        }

        val updatedStatus = ControlledReportStatus.RESOLVED
        val updatedChecksum = computeChecksum(
            tenantId = existingReport.tenantId,
            reportReference = existingReport.reportReference,
            providerId = existingReport.providerId,
            currencyCode = existingReport.currencyCode,
            periodStart = existingReport.periodStart,
            periodEnd = existingReport.periodEnd,
            totals = existingReport.totals,
            evidence = existingReport.itemEvidence,
            status = updatedStatus,
            reasonCode = command.reasonCode,
            approverId = command.approverId,
        )

        val updatedRecord = existingReport.copy(
            status = updatedStatus,
            reasonCode = command.reasonCode,
            approverId = command.approverId,
            resolutionNotes = command.resolutionNotes,
            exportChecksumSha256 = updatedChecksum,
            version = existingReport.version + 1,
            updatedAt = now,
        )

        val result = ControlledFinanceReportResult(
            resultId = UUID.randomUUID(),
            report = updatedRecord,
            serverTime = now,
            isDuplicate = false,
            semanticContract = CONTROLLED_FINANCE_REPORT_CONTRACT,
        )

        alertSink.sendAlert(
            tenantId = command.tenantId,
            reference = command.reportReference,
            alertType = "FINANCE_REPORT_MISMATCH_CLOSED",
            reason = command.reasonCode,
            detail = "Report mismatch closed by approver ${command.approverId}: ${command.resolutionNotes}",
        )

        val audit = AuditEvent(UUID.randomUUID(), existingReport.reportId, command.tenantId, "FINANCE_REPORT_MISMATCH_CLOSED", now, command.correlationId, command.causationId)
        val outbox = OutboxEvent(UUID.randomUUID(), existingReport.reportId, command.tenantId, "FINANCE_REPORT_MISMATCH_CLOSED", now)

        try {
            store.updateReport(updatedRecord, result, command.idempotencyKey, fp, audit, outbox)
        } catch (e: Exception) {
            alertSink.sendAlert(
                tenantId = command.tenantId,
                reference = command.reportReference,
                alertType = "FINANCE_REPORT_STORAGE_FAILED",
                reason = "STORE_FAILURE",
                detail = "Failed to update finance report: ${e.message}",
            )
            throw AuthenticationFailure.Rejected(AuthErrorCode.DEPENDENCY_UNAVAILABLE)
        }

        return result
    }

    @Synchronized
    fun waive(command: WaiveFinanceReportCommand): Nothing {
        // Protected risk assertion: mismatch omitted
        ControlledFinanceReportBinding.checkBound()

        // Invariant: Financial imbalances or discrepancies cannot be waived without authorized resolution
        alertSink.sendAlert(
            tenantId = command.tenantId,
            reference = command.reportReference,
            alertType = "FINANCE_REPORT_WAIVE_FORBIDDEN",
            reason = "WAIVE_DISALLOWED",
            detail = "Finance report discrepancy waiving is forbidden under dual-control policy",
        )
        throw AuthenticationFailure.Rejected(AuthErrorCode.FORBIDDEN)
    }
}
