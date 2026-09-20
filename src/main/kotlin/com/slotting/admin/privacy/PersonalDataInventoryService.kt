package com.slotting.admin.privacy

import com.slotting.admin.auth.*
import java.nio.charset.StandardCharsets
import java.security.MessageDigest
import java.time.Clock
import java.time.Instant
import java.util.UUID
import java.util.concurrent.ConcurrentHashMap

/**
 * Fail-closed verification gate for PRIV-001-01: Maintain personal-data inventory.
 * Throws expected RED failure until contract bindings and invariant protections are verified.
 * Protected risk: False completion or non-authoritative implementation of Maintain personal-data inventory.
 * Rationale: It exists to prevent: missed copy/illegal delete/hold bypass.
 */
object PersonalDataInventoryBinding {
    @Volatile
    var isBound: Boolean = false

    fun checkBound() {
        if (!isBound) {
            throw AssertionError("missed copy/illegal delete/hold bypass")
        }
    }
}

/**
 * Outcome-specific semantic contract for PRIV-001-01.
 */
const val PERSONAL_DATA_INVENTORY_CONTRACT =
    "Ledger retention/legal obligations override deletion only with approved basis; actions audited."

enum class DataCategory {
    IDENTITY,
    PAYMENT,
    LEDGER,
    GAMING_ACTIVITY,
    DEVICE_SESSION,
    COMMUNICATION,
    KYC_DOCUMENT,
}

enum class DataClassification {
    PII,
    SENSITIVE_PII,
    FINANCIAL,
    REGULATORY_AUDIT,
    TECHNICAL,
}

enum class ProcessingLegalBasis {
    CONSENT,
    CONTRACT_PERFORMANCE,
    LEGAL_OBLIGATION,
    LEGITIMATE_INTEREST,
    STATUTORY_RETENTION,
}

enum class DeletionOverrideReason {
    NONE,
    LEGAL_HOLD_ACTIVE,
    STATUTORY_LEDGER_RETENTION,
    REGULATORY_AML_COMPLIANCE,
    APPROVED_LEGAL_OVERRIDE,
}

enum class DeletionEligibilityStatus {
    ELIGIBLE_FOR_DELETION,
    OVERRIDDEN_BY_LEGAL_OBLIGATION,
    BLOCKED_BY_LEGAL_HOLD,
    APPROVED_OVERRIDE_EXECUTABLE,
}

enum class InventoryItemStatus {
    ACTIVE,
    UNDER_LEGAL_HOLD,
    RESTRICTED_PROCESSING,
    DEPRECATED,
}

data class PersonalDataInventoryItem(
    val itemId: UUID,
    val tenantId: String,
    val inventoryReference: String,
    val dataCategory: DataCategory,
    val classification: DataClassification,
    val storageSystem: String,
    val dataOwner: String,
    val legalBasis: ProcessingLegalBasis,
    val retentionDays: Int,
    val statutoryRetentionOverride: Boolean,
    val activeLegalHold: Boolean,
    val legalHoldReference: String? = null,
    val status: InventoryItemStatus,
    val version: Long,
    val createdAt: Instant,
    val updatedAt: Instant,
    val semanticContract: String = PERSONAL_DATA_INVENTORY_CONTRACT,
)

data class LegalHoldRecord(
    val holdId: UUID,
    val tenantId: String,
    val holdReference: String,
    val subjectId: String?,
    val inventoryReference: String?,
    val caseReference: String,
    val reason: String,
    val approverId: String,
    val active: Boolean,
    val createdAt: Instant,
    val releasedAt: Instant? = null,
    val releaseReason: String? = null,
    val releaseApproverId: String? = null,
)

data class RegisterInventoryItemCommand(
    val tenantId: String,
    val inventoryReference: String,
    val dataCategory: DataCategory,
    val classification: DataClassification,
    val storageSystem: String,
    val dataOwner: String,
    val legalBasis: ProcessingLegalBasis,
    val retentionDays: Int,
    val statutoryRetentionOverride: Boolean = false,
    val idempotencyKey: String,
    val correlationId: String,
    val causationId: String,
    val expectedVersion: Long = 1L,
    val principal: AuthenticatedPrincipal? = null,
)

data class InventoryItemResult(
    val resultId: UUID,
    val item: PersonalDataInventoryItem,
    val serverTime: Instant,
    val isDuplicate: Boolean,
    val evidenceReference: String,
    val isFinancialAuthorityCreated: Boolean = false,
    val semanticContract: String = PERSONAL_DATA_INVENTORY_CONTRACT,
)

data class ApplyLegalHoldCommand(
    val tenantId: String,
    val holdReference: String,
    val inventoryReference: String? = null,
    val subjectId: String? = null,
    val caseReference: String,
    val reason: String,
    val approverId: String,
    val idempotencyKey: String,
    val correlationId: String,
    val causationId: String,
    val principal: AuthenticatedPrincipal? = null,
)

data class ReleaseLegalHoldCommand(
    val tenantId: String,
    val holdReference: String,
    val releaseReason: String,
    val approverId: String,
    val idempotencyKey: String,
    val correlationId: String,
    val causationId: String,
    val principal: AuthenticatedPrincipal? = null,
)

data class LegalHoldResult(
    val resultId: UUID,
    val hold: LegalHoldRecord,
    val serverTime: Instant,
    val isDuplicate: Boolean,
    val evidenceReference: String,
    val isFinancialAuthorityCreated: Boolean = false,
    val semanticContract: String = PERSONAL_DATA_INVENTORY_CONTRACT,
)

data class EvaluateDeletionEligibilityCommand(
    val tenantId: String,
    val inventoryReference: String,
    val subjectId: String? = null,
    val recordAgeDays: Int,
    val approvedBasisReference: String? = null,
    val approvedBasisJustification: String? = null,
    val approverId: String? = null,
    val idempotencyKey: String,
    val correlationId: String,
    val causationId: String,
    val expectedVersion: Long = 1L,
    val principal: AuthenticatedPrincipal? = null,
)

data class DeletionEvaluationResult(
    val evaluationId: UUID,
    val tenantId: String,
    val inventoryReference: String,
    val subjectId: String?,
    val eligibilityStatus: DeletionEligibilityStatus,
    val overrideReason: DeletionOverrideReason,
    val legalHoldReference: String?,
    val statutoryRetentionDaysRemaining: Int?,
    val approvedBasisReference: String?,
    val approverId: String?,
    val serverTime: Instant,
    val isDuplicate: Boolean,
    val evidenceReference: String,
    val isFinancialAuthorityCreated: Boolean = false,
    val semanticContract: String = PERSONAL_DATA_INVENTORY_CONTRACT,
)

data class PersonalDataInventorySnapshot(
    val items: Map<String, PersonalDataInventoryItem>,
    val holds: Map<String, LegalHoldRecord>,
    val idempotencyMap: Map<String, Pair<String, Any>>,
    val auditEvents: List<AuditEvent>,
    val outboxEvents: List<OutboxEvent>,
)

interface PersonalDataInventoryAlertSink {
    fun sendAlert(tenantId: String, reference: String, alertType: String, reason: String, detail: String)
}

class InMemoryPersonalDataInventoryAlertSink : PersonalDataInventoryAlertSink {
    val alerts = mutableListOf<String>()

    @Synchronized
    override fun sendAlert(tenantId: String, reference: String, alertType: String, reason: String, detail: String) {
        alerts.add("$tenantId:$reference:$alertType:$reason:$detail")
    }
}

interface PersonalDataInventoryStore {
    fun findItemByReference(tenantId: String, inventoryReference: String): PersonalDataInventoryItem?
    fun findHoldByReference(tenantId: String, holdReference: String): LegalHoldRecord?
    fun findActiveHoldFor(tenantId: String, inventoryReference: String?, subjectId: String?): LegalHoldRecord?
    fun findByIdempotency(tenantId: String, idempotencyKey: String): Pair<String, Any>?
    fun saveItem(
        item: PersonalDataInventoryItem,
        result: InventoryItemResult,
        idempotencyKey: String,
        fingerprint: String,
        audit: AuditEvent,
        outbox: OutboxEvent,
    )
    fun updateItem(
        item: PersonalDataInventoryItem,
        result: InventoryItemResult,
        idempotencyKey: String,
        fingerprint: String,
        audit: AuditEvent,
        outbox: OutboxEvent,
    )
    fun saveHold(
        hold: LegalHoldRecord,
        result: LegalHoldResult,
        idempotencyKey: String,
        fingerprint: String,
        audit: AuditEvent,
        outbox: OutboxEvent,
    )
    fun updateHold(
        hold: LegalHoldRecord,
        result: LegalHoldResult,
        idempotencyKey: String,
        fingerprint: String,
        audit: AuditEvent,
        outbox: OutboxEvent,
    )
    fun saveEvaluation(
        result: DeletionEvaluationResult,
        idempotencyKey: String,
        fingerprint: String,
        audit: AuditEvent,
        outbox: OutboxEvent,
    )
    fun listItems(tenantId: String): List<PersonalDataInventoryItem>
    fun getAuditEvents(): List<AuditEvent>
    fun getOutboxEvents(): List<OutboxEvent>
    fun exportSnapshot(): PersonalDataInventorySnapshot
    fun importSnapshot(snapshot: PersonalDataInventorySnapshot)
}

open class InMemoryPersonalDataInventoryStore : PersonalDataInventoryStore {
    private val items = ConcurrentHashMap<String, PersonalDataInventoryItem>()
    private val holds = ConcurrentHashMap<String, LegalHoldRecord>()
    private val idempotencyResults = ConcurrentHashMap<String, Pair<String, Any>>()
    private val auditEvents = mutableListOf<AuditEvent>()
    private val outboxEvents = mutableListOf<OutboxEvent>()

    private fun itemKey(tenantId: String, ref: String) = "$tenantId:$ref"
    private fun holdKey(tenantId: String, ref: String) = "$tenantId:$ref"
    private fun idKey(tenantId: String, idemp: String) = "$tenantId:$idemp"

    @Synchronized
    override fun findItemByReference(tenantId: String, inventoryReference: String): PersonalDataInventoryItem? =
        items[itemKey(tenantId, inventoryReference)]?.copy()

    @Synchronized
    override fun findHoldByReference(tenantId: String, holdReference: String): LegalHoldRecord? =
        holds[holdKey(tenantId, holdReference)]?.copy()

    @Synchronized
    override fun findActiveHoldFor(tenantId: String, inventoryReference: String?, subjectId: String?): LegalHoldRecord? {
        return holds.values.firstOrNull { hold ->
            if (hold.tenantId != tenantId || !hold.active) return@firstOrNull false
            val inventoryMatches = hold.inventoryReference == null || hold.inventoryReference == inventoryReference
            val subjectMatches = hold.subjectId == null || hold.subjectId == subjectId
            inventoryMatches && subjectMatches
        }?.copy()
    }

    @Synchronized
    override fun findByIdempotency(tenantId: String, idempotencyKey: String): Pair<String, Any>? =
        idempotencyResults[idKey(tenantId, idempotencyKey)]

    @Synchronized
    open override fun saveItem(
        item: PersonalDataInventoryItem,
        result: InventoryItemResult,
        idempotencyKey: String,
        fingerprint: String,
        audit: AuditEvent,
        outbox: OutboxEvent,
    ) {
        items[itemKey(item.tenantId, item.inventoryReference)] = item.copy()
        idempotencyResults[idKey(item.tenantId, idempotencyKey)] = fingerprint to result
        auditEvents.add(audit)
        outboxEvents.add(outbox)
    }

    @Synchronized
    override fun updateItem(
        item: PersonalDataInventoryItem,
        result: InventoryItemResult,
        idempotencyKey: String,
        fingerprint: String,
        audit: AuditEvent,
        outbox: OutboxEvent,
    ) {
        items[itemKey(item.tenantId, item.inventoryReference)] = item.copy()
        idempotencyResults[idKey(item.tenantId, idempotencyKey)] = fingerprint to result
        auditEvents.add(audit)
        outboxEvents.add(outbox)
    }

    @Synchronized
    override fun saveHold(
        hold: LegalHoldRecord,
        result: LegalHoldResult,
        idempotencyKey: String,
        fingerprint: String,
        audit: AuditEvent,
        outbox: OutboxEvent,
    ) {
        holds[holdKey(hold.tenantId, hold.holdReference)] = hold.copy()
        idempotencyResults[idKey(hold.tenantId, idempotencyKey)] = fingerprint to result
        auditEvents.add(audit)
        outboxEvents.add(outbox)
    }

    @Synchronized
    override fun updateHold(
        hold: LegalHoldRecord,
        result: LegalHoldResult,
        idempotencyKey: String,
        fingerprint: String,
        audit: AuditEvent,
        outbox: OutboxEvent,
    ) {
        holds[holdKey(hold.tenantId, hold.holdReference)] = hold.copy()
        idempotencyResults[idKey(hold.tenantId, idempotencyKey)] = fingerprint to result
        auditEvents.add(audit)
        outboxEvents.add(outbox)
    }

    @Synchronized
    override fun saveEvaluation(
        result: DeletionEvaluationResult,
        idempotencyKey: String,
        fingerprint: String,
        audit: AuditEvent,
        outbox: OutboxEvent,
    ) {
        idempotencyResults[idKey(result.tenantId, idempotencyKey)] = fingerprint to result
        auditEvents.add(audit)
        outboxEvents.add(outbox)
    }

    @Synchronized
    override fun listItems(tenantId: String): List<PersonalDataInventoryItem> =
        items.values.filter { it.tenantId == tenantId }.map { it.copy() }

    @Synchronized
    override fun getAuditEvents(): List<AuditEvent> = auditEvents.toList()

    @Synchronized
    override fun getOutboxEvents(): List<OutboxEvent> = outboxEvents.toList()

    @Synchronized
    override fun exportSnapshot(): PersonalDataInventorySnapshot = PersonalDataInventorySnapshot(
        items = HashMap(items),
        holds = HashMap(holds),
        idempotencyMap = HashMap(idempotencyResults),
        auditEvents = ArrayList(auditEvents),
        outboxEvents = ArrayList(outboxEvents),
    )

    @Synchronized
    override fun importSnapshot(snapshot: PersonalDataInventorySnapshot) {
        items.clear()
        items.putAll(snapshot.items)
        holds.clear()
        holds.putAll(snapshot.holds)
        idempotencyResults.clear()
        idempotencyResults.putAll(snapshot.idempotencyMap)
        auditEvents.clear()
        auditEvents.addAll(snapshot.auditEvents)
        outboxEvents.clear()
        outboxEvents.addAll(snapshot.outboxEvents)
    }
}

class PersonalDataInventoryService(
    private val store: PersonalDataInventoryStore,
    private val alertSink: PersonalDataInventoryAlertSink = InMemoryPersonalDataInventoryAlertSink(),
    private val clock: Clock = Clock.systemUTC(),
) {
    private fun sha256(input: String): String {
        val digest = MessageDigest.getInstance("SHA-256")
        val hash = digest.digest(input.toByteArray(StandardCharsets.UTF_8))
        return hash.joinToString("") { "%02x".format(it) }
    }

    private fun fingerprintRegister(cmd: RegisterInventoryItemCommand): String =
        sha256("${cmd.tenantId}:${cmd.inventoryReference}:${cmd.dataCategory}:${cmd.classification}:${cmd.storageSystem}:${cmd.dataOwner}:${cmd.legalBasis}:${cmd.retentionDays}:${cmd.statutoryRetentionOverride}:${cmd.expectedVersion}")

    private fun fingerprintHold(cmd: ApplyLegalHoldCommand): String =
        sha256("${cmd.tenantId}:${cmd.holdReference}:${cmd.inventoryReference}:${cmd.subjectId}:${cmd.caseReference}:${cmd.reason}:${cmd.approverId}")

    private fun fingerprintReleaseHold(cmd: ReleaseLegalHoldCommand): String =
        sha256("${cmd.tenantId}:${cmd.holdReference}:${cmd.releaseReason}:${cmd.approverId}")

    private fun fingerprintEvaluation(cmd: EvaluateDeletionEligibilityCommand): String =
        sha256("${cmd.tenantId}:${cmd.inventoryReference}:${cmd.subjectId}:${cmd.recordAgeDays}:${cmd.approvedBasisReference}:${cmd.approverId}:${cmd.expectedVersion}")

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
    fun registerItem(command: RegisterInventoryItemCommand): InventoryItemResult {
        // Protected risk assertion: missed copy/illegal delete/hold bypass
        PersonalDataInventoryBinding.checkBound()

        // 1. Mandatory Input Validation
        if (command.tenantId.isBlank() ||
            command.inventoryReference.isBlank() ||
            command.storageSystem.isBlank() ||
            command.dataOwner.isBlank() ||
            command.idempotencyKey.isBlank() ||
            command.correlationId.isBlank() ||
            command.causationId.isBlank()
        ) {
            alertSink.sendAlert(
                tenantId = command.tenantId.ifBlank { "UNKNOWN" },
                reference = command.inventoryReference.ifBlank { "UNKNOWN" },
                alertType = "INVENTORY_INVALID_INPUT",
                reason = "BLANK_MANDATORY_FIELDS",
                detail = "Register inventory item rejected due to blank mandatory fields",
            )
            throw AuthenticationFailure.Rejected(AuthErrorCode.INVALID)
        }

        if (command.retentionDays < 0) {
            throw AuthenticationFailure.Rejected(AuthErrorCode.INVALID)
        }

        if (command.expectedVersion != 1L) {
            throw AuthenticationFailure.Rejected(AuthErrorCode.STALE)
        }

        validateAdminPrincipal(command.principal, command.tenantId)

        val fp = fingerprintRegister(command)
        val now = clock.instant()

        // 2. Idempotency Check
        val existingIdemp = store.findByIdempotency(command.tenantId, command.idempotencyKey)
        if (existingIdemp != null) {
            val (cachedFp, cachedResult) = existingIdemp
            if (cachedFp != fp) {
                alertSink.sendAlert(
                    tenantId = command.tenantId,
                    reference = command.inventoryReference,
                    alertType = "INVENTORY_IDEMPOTENCY_CONFLICT",
                    reason = "PAYLOAD_MISMATCH",
                    detail = "Payload mismatch detected for inventory idempotency key ${command.idempotencyKey}",
                )
                throw AuthenticationFailure.Rejected(AuthErrorCode.CONFLICT)
            }
            val res = cachedResult as InventoryItemResult
            return res.copy(isDuplicate = true)
        }

        val existingItem = store.findItemByReference(command.tenantId, command.inventoryReference)
        if (existingItem != null) {
            alertSink.sendAlert(
                tenantId = command.tenantId,
                reference = command.inventoryReference,
                alertType = "INVENTORY_REFERENCE_CONFLICT",
                reason = "REFERENCE_ALREADY_EXISTS",
                detail = "Inventory reference ${command.inventoryReference} already exists",
            )
            throw AuthenticationFailure.Rejected(AuthErrorCode.CONFLICT)
        }

        // Check if there is an active legal hold applicable to this inventory reference
        val activeHold = store.findActiveHoldFor(command.tenantId, command.inventoryReference, null)

        val itemId = UUID.randomUUID()
        val resultId = UUID.randomUUID()
        val evidenceRef = "EVID-INV-$itemId"

        val item = PersonalDataInventoryItem(
            itemId = itemId,
            tenantId = command.tenantId,
            inventoryReference = command.inventoryReference,
            dataCategory = command.dataCategory,
            classification = command.classification,
            storageSystem = command.storageSystem,
            dataOwner = command.dataOwner,
            legalBasis = command.legalBasis,
            retentionDays = command.retentionDays,
            statutoryRetentionOverride = command.statutoryRetentionOverride,
            activeLegalHold = activeHold != null,
            legalHoldReference = activeHold?.holdReference,
            status = if (activeHold != null) InventoryItemStatus.UNDER_LEGAL_HOLD else InventoryItemStatus.ACTIVE,
            version = 1L,
            createdAt = now,
            updatedAt = now,
            semanticContract = PERSONAL_DATA_INVENTORY_CONTRACT,
        )

        val result = InventoryItemResult(
            resultId = resultId,
            item = item,
            serverTime = now,
            isDuplicate = false,
            evidenceReference = evidenceRef,
            isFinancialAuthorityCreated = false,
            semanticContract = PERSONAL_DATA_INVENTORY_CONTRACT,
        )

        val audit = AuditEvent(UUID.randomUUID(), itemId, command.tenantId, "PERSONAL_DATA_INVENTORY_REGISTERED", now, command.correlationId, command.causationId)
        val outbox = OutboxEvent(UUID.randomUUID(), itemId, command.tenantId, "PERSONAL_DATA_INVENTORY_REGISTERED", now)

        try {
            store.saveItem(item, result, command.idempotencyKey, fp, audit, outbox)
        } catch (e: Exception) {
            alertSink.sendAlert(
                tenantId = command.tenantId,
                reference = command.inventoryReference,
                alertType = "INVENTORY_STORAGE_FAILED",
                reason = "STORE_FAILURE",
                detail = "Failed to store inventory item: ${e.message}",
            )
            throw AuthenticationFailure.Rejected(AuthErrorCode.DEPENDENCY_UNAVAILABLE)
        }

        return result
    }

    @Synchronized
    fun applyLegalHold(command: ApplyLegalHoldCommand): LegalHoldResult {
        // Protected risk assertion: missed copy/illegal delete/hold bypass
        PersonalDataInventoryBinding.checkBound()

        if (command.tenantId.isBlank() ||
            command.holdReference.isBlank() ||
            command.caseReference.isBlank() ||
            command.reason.isBlank() ||
            command.approverId.isBlank() ||
            command.idempotencyKey.isBlank() ||
            command.correlationId.isBlank() ||
            command.causationId.isBlank()
        ) {
            throw AuthenticationFailure.Rejected(AuthErrorCode.INVALID)
        }

        if (command.inventoryReference == null && command.subjectId == null) {
            throw AuthenticationFailure.Rejected(AuthErrorCode.INVALID)
        }

        validateAdminPrincipal(command.principal, command.tenantId)

        val fp = fingerprintHold(command)
        val now = clock.instant()

        val existingIdemp = store.findByIdempotency(command.tenantId, command.idempotencyKey)
        if (existingIdemp != null) {
            val (cachedFp, cachedResult) = existingIdemp
            if (cachedFp != fp) {
                throw AuthenticationFailure.Rejected(AuthErrorCode.CONFLICT)
            }
            val res = cachedResult as LegalHoldResult
            return res.copy(isDuplicate = true)
        }

        val existingHold = store.findHoldByReference(command.tenantId, command.holdReference)
        if (existingHold != null) {
            throw AuthenticationFailure.Rejected(AuthErrorCode.CONFLICT)
        }

        val holdId = UUID.randomUUID()
        val resultId = UUID.randomUUID()
        val evidenceRef = "EVID-HOLD-$holdId"

        val hold = LegalHoldRecord(
            holdId = holdId,
            tenantId = command.tenantId,
            holdReference = command.holdReference,
            subjectId = command.subjectId,
            inventoryReference = command.inventoryReference,
            caseReference = command.caseReference,
            reason = command.reason,
            approverId = command.approverId,
            active = true,
            createdAt = now,
        )

        // If inventory item exists, update its hold flag
        if (command.inventoryReference != null) {
            val item = store.findItemByReference(command.tenantId, command.inventoryReference)
            if (item != null) {
                val updatedItem = item.copy(
                    activeLegalHold = true,
                    legalHoldReference = command.holdReference,
                    status = InventoryItemStatus.UNDER_LEGAL_HOLD,
                    version = item.version + 1,
                    updatedAt = now,
                )
                val itemResult = InventoryItemResult(
                    resultId = UUID.randomUUID(),
                    item = updatedItem,
                    serverTime = now,
                    isDuplicate = false,
                    evidenceReference = "EVID-INV-HOLD-${updatedItem.itemId}",
                    isFinancialAuthorityCreated = false,
                    semanticContract = PERSONAL_DATA_INVENTORY_CONTRACT,
                )
                val itemAudit = AuditEvent(UUID.randomUUID(), updatedItem.itemId, command.tenantId, "INVENTORY_ITEM_LEGAL_HOLD_APPLIED", now, command.correlationId, command.causationId)
                val itemOutbox = OutboxEvent(UUID.randomUUID(), updatedItem.itemId, command.tenantId, "INVENTORY_ITEM_LEGAL_HOLD_APPLIED", now)
                store.updateItem(updatedItem, itemResult, "${command.idempotencyKey}:item", fp, itemAudit, itemOutbox)
            }
        }

        val result = LegalHoldResult(
            resultId = resultId,
            hold = hold,
            serverTime = now,
            isDuplicate = false,
            evidenceReference = evidenceRef,
            isFinancialAuthorityCreated = false,
            semanticContract = PERSONAL_DATA_INVENTORY_CONTRACT,
        )

        alertSink.sendAlert(
            tenantId = command.tenantId,
            reference = command.holdReference,
            alertType = "LEGAL_HOLD_APPLIED",
            reason = command.caseReference,
            detail = "Legal hold applied on target: ${command.reason}",
        )

        val audit = AuditEvent(UUID.randomUUID(), holdId, command.tenantId, "LEGAL_HOLD_APPLIED", now, command.correlationId, command.causationId)
        val outbox = OutboxEvent(UUID.randomUUID(), holdId, command.tenantId, "LEGAL_HOLD_APPLIED", now)

        try {
            store.saveHold(hold, result, command.idempotencyKey, fp, audit, outbox)
        } catch (e: Exception) {
            throw AuthenticationFailure.Rejected(AuthErrorCode.DEPENDENCY_UNAVAILABLE)
        }

        return result
    }

    @Synchronized
    fun releaseLegalHold(command: ReleaseLegalHoldCommand): LegalHoldResult {
        // Protected risk assertion: missed copy/illegal delete/hold bypass
        PersonalDataInventoryBinding.checkBound()

        if (command.tenantId.isBlank() ||
            command.holdReference.isBlank() ||
            command.releaseReason.isBlank() ||
            command.approverId.isBlank() ||
            command.idempotencyKey.isBlank() ||
            command.correlationId.isBlank() ||
            command.causationId.isBlank()
        ) {
            throw AuthenticationFailure.Rejected(AuthErrorCode.INVALID)
        }

        validateAdminPrincipal(command.principal, command.tenantId)

        val fp = fingerprintReleaseHold(command)
        val now = clock.instant()

        val existingIdemp = store.findByIdempotency(command.tenantId, command.idempotencyKey)
        if (existingIdemp != null) {
            val (cachedFp, cachedResult) = existingIdemp
            if (cachedFp != fp) {
                throw AuthenticationFailure.Rejected(AuthErrorCode.CONFLICT)
            }
            val res = cachedResult as LegalHoldResult
            return res.copy(isDuplicate = true)
        }

        val existingHold = store.findHoldByReference(command.tenantId, command.holdReference)
            ?: throw AuthenticationFailure.Rejected(AuthErrorCode.INVALID)

        if (!existingHold.active) {
            throw AuthenticationFailure.Rejected(AuthErrorCode.CONFLICT)
        }

        val updatedHold = existingHold.copy(
            active = false,
            releasedAt = now,
            releaseReason = command.releaseReason,
            releaseApproverId = command.approverId,
        )

        // If inventory item exists, release its hold flag
        if (existingHold.inventoryReference != null) {
            val item = store.findItemByReference(command.tenantId, existingHold.inventoryReference)
            if (item != null) {
                val updatedItem = item.copy(
                    activeLegalHold = false,
                    legalHoldReference = null,
                    status = InventoryItemStatus.ACTIVE,
                    version = item.version + 1,
                    updatedAt = now,
                )
                val itemResult = InventoryItemResult(
                    resultId = UUID.randomUUID(),
                    item = updatedItem,
                    serverTime = now,
                    isDuplicate = false,
                    evidenceReference = "EVID-INV-REL-${updatedItem.itemId}",
                    isFinancialAuthorityCreated = false,
                    semanticContract = PERSONAL_DATA_INVENTORY_CONTRACT,
                )
                val itemAudit = AuditEvent(UUID.randomUUID(), updatedItem.itemId, command.tenantId, "INVENTORY_ITEM_LEGAL_HOLD_RELEASED", now, command.correlationId, command.causationId)
                val itemOutbox = OutboxEvent(UUID.randomUUID(), updatedItem.itemId, command.tenantId, "INVENTORY_ITEM_LEGAL_HOLD_RELEASED", now)
                store.updateItem(updatedItem, itemResult, "${command.idempotencyKey}:item", fp, itemAudit, itemOutbox)
            }
        }

        val result = LegalHoldResult(
            resultId = UUID.randomUUID(),
            hold = updatedHold,
            serverTime = now,
            isDuplicate = false,
            evidenceReference = "EVID-HOLD-REL-${updatedHold.holdId}",
            isFinancialAuthorityCreated = false,
            semanticContract = PERSONAL_DATA_INVENTORY_CONTRACT,
        )

        alertSink.sendAlert(
            tenantId = command.tenantId,
            reference = command.holdReference,
            alertType = "LEGAL_HOLD_RELEASED",
            reason = command.releaseReason,
            detail = "Legal hold released by ${command.approverId}",
        )

        val audit = AuditEvent(UUID.randomUUID(), existingHold.holdId, command.tenantId, "LEGAL_HOLD_RELEASED", now, command.correlationId, command.causationId)
        val outbox = OutboxEvent(UUID.randomUUID(), existingHold.holdId, command.tenantId, "LEGAL_HOLD_RELEASED", now)

        try {
            store.updateHold(updatedHold, result, command.idempotencyKey, fp, audit, outbox)
        } catch (e: Exception) {
            throw AuthenticationFailure.Rejected(AuthErrorCode.DEPENDENCY_UNAVAILABLE)
        }

        return result
    }

    @Synchronized
    fun evaluateDeletionEligibility(command: EvaluateDeletionEligibilityCommand): DeletionEvaluationResult {
        // Protected risk assertion: missed copy/illegal delete/hold bypass
        PersonalDataInventoryBinding.checkBound()

        if (command.tenantId.isBlank() ||
            command.inventoryReference.isBlank() ||
            command.idempotencyKey.isBlank() ||
            command.correlationId.isBlank() ||
            command.causationId.isBlank()
        ) {
            throw AuthenticationFailure.Rejected(AuthErrorCode.INVALID)
        }

        if (command.recordAgeDays < 0) {
            throw AuthenticationFailure.Rejected(AuthErrorCode.INVALID)
        }

        if (command.expectedVersion != 1L) {
            throw AuthenticationFailure.Rejected(AuthErrorCode.STALE)
        }

        validateAdminPrincipal(command.principal, command.tenantId)

        val fp = fingerprintEvaluation(command)
        val now = clock.instant()

        val existingIdemp = store.findByIdempotency(command.tenantId, command.idempotencyKey)
        if (existingIdemp != null) {
            val (cachedFp, cachedResult) = existingIdemp
            if (cachedFp != fp) {
                throw AuthenticationFailure.Rejected(AuthErrorCode.CONFLICT)
            }
            val res = cachedResult as DeletionEvaluationResult
            return res.copy(isDuplicate = true)
        }

        val item = store.findItemByReference(command.tenantId, command.inventoryReference)
            ?: throw AuthenticationFailure.Rejected(AuthErrorCode.INVALID)

        // Check for active legal holds (hold bypass prevention)
        val activeHold = store.findActiveHoldFor(command.tenantId, command.inventoryReference, command.subjectId)

        val evaluationId = UUID.randomUUID()
        val evidenceRef = "EVID-EVAL-$evaluationId"

        // Semantic contract logic:
        // "Ledger retention/legal obligations override deletion only with approved basis; actions audited."
        val (eligibilityStatus, overrideReason, statutoryDaysRemaining) = when {
            // 1. Legal hold active -> BLOCKED_BY_LEGAL_HOLD (Hold bypass strictly prevented)
            activeHold != null -> {
                alertSink.sendAlert(
                    tenantId = command.tenantId,
                    reference = command.inventoryReference,
                    alertType = "DELETION_BLOCKED_LEGAL_HOLD",
                    reason = activeHold.caseReference,
                    detail = "Deletion evaluation blocked due to active legal hold ${activeHold.holdReference}",
                )
                Triple(DeletionEligibilityStatus.BLOCKED_BY_LEGAL_HOLD, DeletionOverrideReason.LEGAL_HOLD_ACTIVE, null)
            }

            // 2. Statutory ledger retention or statutory legal obligation
            item.statutoryRetentionOverride || item.dataCategory == DataCategory.LEDGER -> {
                val remainingDays = item.retentionDays - command.recordAgeDays
                if (remainingDays > 0) {
                    // Check if an approved basis override is provided with authorized approver
                    if (!command.approvedBasisReference.isNullOrBlank() &&
                        !command.approverId.isNullOrBlank() &&
                        !command.approvedBasisJustification.isNullOrBlank()
                    ) {
                        // Authorized approved basis override
                        alertSink.sendAlert(
                            tenantId = command.tenantId,
                            reference = command.inventoryReference,
                            alertType = "DELETION_APPROVED_LEGAL_OVERRIDE",
                            reason = command.approvedBasisReference,
                            detail = "Statutory deletion override approved by ${command.approverId}: ${command.approvedBasisJustification}",
                        )
                        Triple(DeletionEligibilityStatus.APPROVED_OVERRIDE_EXECUTABLE, DeletionOverrideReason.APPROVED_LEGAL_OVERRIDE, remainingDays)
                    } else {
                        // Legal obligation overrides deletion
                        alertSink.sendAlert(
                            tenantId = command.tenantId,
                            reference = command.inventoryReference,
                            alertType = "DELETION_OVERRIDDEN_LEGAL_OBLIGATION",
                            reason = "STATUTORY_LEDGER_RETENTION",
                            detail = "Deletion overridden by statutory ledger retention ($remainingDays days remaining)",
                        )
                        Triple(DeletionEligibilityStatus.OVERRIDDEN_BY_LEGAL_OBLIGATION, DeletionOverrideReason.STATUTORY_LEDGER_RETENTION, remainingDays)
                    }
                } else {
                    // Retention period fully satisfied
                    Triple(DeletionEligibilityStatus.ELIGIBLE_FOR_DELETION, DeletionOverrideReason.NONE, 0)
                }
            }

            // 3. Standard retention check
            command.recordAgeDays < item.retentionDays -> {
                val remaining = item.retentionDays - command.recordAgeDays
                Triple(DeletionEligibilityStatus.OVERRIDDEN_BY_LEGAL_OBLIGATION, DeletionOverrideReason.REGULATORY_AML_COMPLIANCE, remaining)
            }

            // 4. Record age exceeds retention, no holds, no overrides
            else -> {
                Triple(DeletionEligibilityStatus.ELIGIBLE_FOR_DELETION, DeletionOverrideReason.NONE, 0)
            }
        }

        val result = DeletionEvaluationResult(
            evaluationId = evaluationId,
            tenantId = command.tenantId,
            inventoryReference = command.inventoryReference,
            subjectId = command.subjectId,
            eligibilityStatus = eligibilityStatus,
            overrideReason = overrideReason,
            legalHoldReference = activeHold?.holdReference,
            statutoryRetentionDaysRemaining = statutoryDaysRemaining,
            approvedBasisReference = command.approvedBasisReference,
            approverId = command.approverId,
            serverTime = now,
            isDuplicate = false,
            evidenceReference = evidenceRef,
            isFinancialAuthorityCreated = false,
            semanticContract = PERSONAL_DATA_INVENTORY_CONTRACT,
        )

        val eventType = "DELETION_ELIGIBILITY_EVALUATED_${eligibilityStatus.name}"
        val audit = AuditEvent(UUID.randomUUID(), evaluationId, command.tenantId, eventType, now, command.correlationId, command.causationId)
        val outbox = OutboxEvent(UUID.randomUUID(), evaluationId, command.tenantId, eventType, now)

        try {
            store.saveEvaluation(result, command.idempotencyKey, fp, audit, outbox)
        } catch (e: Exception) {
            alertSink.sendAlert(
                tenantId = command.tenantId,
                reference = command.inventoryReference,
                alertType = "INVENTORY_STORAGE_FAILED",
                reason = "STORE_FAILURE",
                detail = "Failed to store deletion evaluation: ${e.message}",
            )
            throw AuthenticationFailure.Rejected(AuthErrorCode.DEPENDENCY_UNAVAILABLE)
        }

        return result
    }
}
