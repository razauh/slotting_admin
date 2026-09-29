package com.slotting.admin.privacy

import com.slotting.admin.auth.AdminPermission
import com.slotting.admin.auth.AdminRbacPolicy
import com.slotting.admin.auth.AuditEvent
import com.slotting.admin.auth.AuthenticatedPrincipal
import java.time.Clock
import java.time.Instant
import java.util.UUID
import java.util.concurrent.ConcurrentHashMap

data class ExecuteDsarCommand(
    val tenantId: String,
    val subjectId: String,
    val requestedAction: PostRetentionAction = PostRetentionAction.DELETE,
    val categories: Set<DataCategory> = emptySet(),
    val idempotencyKey: String,
    val correlationId: String,
    val causationId: String,
    val notes: String? = null,
)

class DsarOrchestrationService(
    private val rbacPolicy: AdminRbacPolicy,
    private val complianceService: ComplianceGovernanceService,
    private val adapters: List<StorePrivacyAdapter>,
    private val clock: Clock = Clock.systemUTC(),
    private val auditSink: ((AuditEvent) -> Unit)? = null,
) {
    private val executions = ConcurrentHashMap<UUID, PrivacyDsarExecutionRecord>()
    private val idempotencyIndex = ConcurrentHashMap<String, UUID>() // tenantId:idempotencyKey -> dsarId

    fun executeDsar(
        principal: AuthenticatedPrincipal,
        command: ExecuteDsarCommand,
    ): PrivacyDsarExecutionRecord {
        requirePermission(principal, AdminPermission.EXECUTE_DSAR)

        val idempotencyToken = "${command.tenantId}:${command.idempotencyKey}"
        val existingId = idempotencyIndex[idempotencyToken]
        if (existingId != null) {
            val existing = executions[existingId]
            if (existing != null) return existing
        }

        val dsarId = UUID.randomUUID()
        val targetCategories = if (command.categories.isEmpty()) {
            adapters.flatMap { it.supportedCategories }.toSet()
        } else {
            command.categories
        }

        val receipts = mutableListOf<StoreActionReceipt>()

        for (category in targetCategories) {
            // 1. Legal Hold Precedence check
            if (complianceService.isHeld(command.subjectId, category)) {
                receipts.add(
                    StoreActionReceipt(
                        receiptId = UUID.randomUUID(),
                        dsarId = dsarId,
                        storeId = "governance-policy-guard",
                        dataCategory = category,
                        requestedAction = command.requestedAction,
                        executedAction = PostRetentionAction.HOLD,
                        status = StoreActionStatus.HELD,
                        recordCount = 1,
                        details = "Action blocked: Active scoped legal hold applies to subject '${command.subjectId}' and category '${category.name}'.",
                        occurredAt = Instant.now(clock),
                    )
                )
                continue
            }

            // 2. Locate adapters supporting this category
            val matchingAdapters = adapters.filter { category in it.supportedCategories }
            if (matchingAdapters.isEmpty()) {
                receipts.add(
                    StoreActionReceipt(
                        receiptId = UUID.randomUUID(),
                        dsarId = dsarId,
                        storeId = "unknown-store",
                        dataCategory = category,
                        requestedAction = command.requestedAction,
                        executedAction = command.requestedAction,
                        status = StoreActionStatus.NOT_APPLICABLE,
                        recordCount = 0,
                        details = "No store adapter bound for category ${category.name}.",
                        occurredAt = Instant.now(clock),
                    )
                )
                continue
            }

            // 3. Execute action on matching adapters
            for (adapter in matchingAdapters) {
                val actionCmd = StoreActionCommand(
                    tenantId = command.tenantId,
                    subjectId = command.subjectId,
                    dataCategory = category,
                    requestedAction = command.requestedAction,
                    policyReference = "DSAR_REQUEST_${command.idempotencyKey}",
                    correlationId = command.correlationId,
                    causationId = command.causationId,
                )
                val receipt = adapter.executeAction(actionCmd).copy(dsarId = dsarId)
                receipts.add(receipt)
            }
        }

        // 4. Truthful aggregate status computation
        val overallStatus = computeOverallStatus(receipts)
        val now = Instant.now(clock)
        val record = PrivacyDsarExecutionRecord(
            dsarId = dsarId,
            tenantId = command.tenantId,
            subjectId = command.subjectId,
            requestedAction = command.requestedAction,
            overallStatus = overallStatus,
            receipts = receipts,
            submittedBy = principal.id,
            executedAt = now,
            completedAt = if (overallStatus != OverallDsarStatus.FAILED_PARTIAL) now else null,
            notes = command.notes,
        )

        executions[dsarId] = record
        idempotencyIndex[idempotencyToken] = dsarId

        recordAudit(
            principal,
            "EXECUTE_DSAR",
            "Executed DSAR ${record.dsarId} for subject ${record.subjectId} with status ${record.overallStatus}"
        )

        return record
    }

    fun retryDsar(principal: AuthenticatedPrincipal, dsarId: UUID): PrivacyDsarExecutionRecord {
        requirePermission(principal, AdminPermission.RETRY_DSAR)
        val existing = executions[dsarId] ?: throw IllegalArgumentException("DSAR $dsarId not found")

        val updatedReceipts = existing.receipts.map { receipt ->
            if (receipt.status == StoreActionStatus.RETRYABLE_FAILURE) {
                val adapter = adapters.find { it.storeId == receipt.storeId }
                if (adapter != null) {
                    val cmd = StoreActionCommand(
                        tenantId = existing.tenantId,
                        subjectId = existing.subjectId,
                        dataCategory = receipt.dataCategory,
                        requestedAction = receipt.requestedAction,
                        policyReference = "RETRY_${dsarId}",
                        correlationId = UUID.randomUUID().toString(),
                        causationId = dsarId.toString(),
                    )
                    adapter.executeAction(cmd).copy(dsarId = dsarId)
                } else {
                    receipt
                }
            } else {
                receipt
            }
        }

        val newOverallStatus = computeOverallStatus(updatedReceipts)
        val now = Instant.now(clock)
        val updated = existing.copy(
            receipts = updatedReceipts,
            overallStatus = newOverallStatus,
            completedAt = if (newOverallStatus != OverallDsarStatus.FAILED_PARTIAL) now else null,
        )
        executions[dsarId] = updated

        recordAudit(principal, "RETRY_DSAR", "Retried DSAR $dsarId; new status: $newOverallStatus")
        return updated
    }

    fun confirmManualAction(
        principal: AuthenticatedPrincipal,
        dsarId: UUID,
        receiptId: UUID,
        notes: String,
    ): PrivacyDsarExecutionRecord {
        requirePermission(principal, AdminPermission.EXECUTE_DSAR)
        val existing = executions[dsarId] ?: throw IllegalArgumentException("DSAR $dsarId not found")

        val updatedReceipts = existing.receipts.map { receipt ->
            if (receipt.receiptId == receiptId) {
                receipt.copy(
                    status = StoreActionStatus.COMPLETED,
                    manualConfirmationBy = principal.id,
                    manualConfirmationNotes = notes,
                    details = "Manual action completed and confirmed by administrator: $notes",
                )
            } else {
                receipt
            }
        }

        val newOverallStatus = computeOverallStatus(updatedReceipts)
        val updated = existing.copy(
            receipts = updatedReceipts,
            overallStatus = newOverallStatus,
            completedAt = if (newOverallStatus != OverallDsarStatus.FAILED_PARTIAL) Instant.now(clock) else null,
        )
        executions[dsarId] = updated

        recordAudit(principal, "CONFIRM_MANUAL_DSAR_ACTION", "Manually confirmed receipt $receiptId for DSAR $dsarId: $notes")
        return updated
    }

    fun querySubjectData(
        principal: AuthenticatedPrincipal,
        tenantId: String,
        subjectId: String,
        categories: Set<DataCategory>,
    ): List<StoreDataExportReceipt> {
        requirePermission(principal, AdminPermission.VIEW_DSAR)
        val results = mutableListOf<StoreDataExportReceipt>()
        for (category in categories) {
            val matchingAdapters = adapters.filter { category in it.supportedCategories }
            for (adapter in matchingAdapters) {
                results.add(adapter.queryData(tenantId, subjectId, category))
            }
        }
        return results
    }

    fun getReceipts(principal: AuthenticatedPrincipal, dsarId: UUID): List<StoreActionReceipt> {
        requirePermission(principal, AdminPermission.VIEW_PRIVACY_RECEIPTS)
        return executions[dsarId]?.receipts ?: emptyList()
    }

    private fun computeOverallStatus(receipts: List<StoreActionReceipt>): OverallDsarStatus {
        if (receipts.any { it.status == StoreActionStatus.RETRYABLE_FAILURE || it.status == StoreActionStatus.PERMANENT_FAILURE || it.status == StoreActionStatus.MANUAL_ACTION_REQUIRED }) {
            return OverallDsarStatus.FAILED_PARTIAL
        }
        if (receipts.any { it.status == StoreActionStatus.HELD }) {
            return OverallDsarStatus.RESTRICTED_BY_HOLD
        }
        if (receipts.any { it.status == StoreActionStatus.STATUTORY_OVERRIDE || it.executedAction == PostRetentionAction.RETAIN }) {
            return OverallDsarStatus.COMPLETED_WITH_RETENTION
        }
        if (receipts.all { it.status == StoreActionStatus.COMPLETED }) {
            return OverallDsarStatus.FULFILLED
        }
        return OverallDsarStatus.COMPLETED_PARTIAL
    }

    private fun requirePermission(principal: AuthenticatedPrincipal, permission: AdminPermission) {
        if (!rbacPolicy.isPermitted(principal, permission)) {
            throw SecurityException("Principal ${principal.id} lacks required permission: ${permission.name}")
        }
    }

    private fun recordAudit(principal: AuthenticatedPrincipal, action: String, details: String) {
        val event = AuditEvent(
            eventId = UUID.randomUUID(),
            resultId = UUID.randomUUID(),
            tenantId = principal.tenantId,
            type = action,
            occurredAt = Instant.now(clock),
            correlationId = UUID.randomUUID().toString(),
            causationId = principal.id,
        )
        auditSink?.invoke(event)
    }
}
