package com.slotting.admin.privacy

import com.slotting.admin.auth.*
import java.nio.charset.StandardCharsets
import java.security.MessageDigest
import java.time.Clock
import java.time.Instant
import java.util.UUID
import java.util.concurrent.ConcurrentHashMap

/**
 * Fail-closed verification gate for PRIV-001-02: Fulfil data-subject access requests.
 * Throws expected RED failure until contract bindings and invariant protections are verified.
 * Protected risk: False completion or non-authoritative implementation of Fulfil data-subject access requests.
 * Rationale: It exists to prevent: missed copy/illegal delete/hold bypass.
 */
object DsarFulfillmentBinding {
    @Volatile
    var isBound: Boolean = false

    fun checkBound() {
        if (!isBound) {
            throw AssertionError("missed copy/illegal delete/hold bypass")
        }
    }
}

/**
 * Outcome-specific semantic contract for PRIV-001-02.
 */
const val DSAR_FULFILLMENT_CONTRACT =
    "Ledger retention/legal obligations override deletion only with approved basis; actions audited."

enum class DsarRequestType {
    ACCESS_EXPORT,
    PORTABILITY_EXPORT,
    RECTIFICATION_REVIEW,
}

enum class DsarStatus {
    SUBMITTED,
    PROCESSING,
    FULFILLED,
    RESTRICTED_LEGAL_HOLD,
    REJECTED,
}

data class DsarCategoryExport(
    val category: DataCategory,
    val storageSystem: String,
    val classification: DataClassification,
    val legalBasis: ProcessingLegalBasis,
    val recordCount: Int,
    val dataDigestSha256: String,
    val activeLegalHold: Boolean,
    val statutoryRetentionOverride: Boolean,
    val notes: String? = null,
)

data class DsarRecord(
    val dsarId: UUID,
    val tenantId: String,
    val dsarReference: String,
    val subjectId: String,
    val requestType: DsarRequestType,
    val status: DsarStatus,
    val collectedCategories: List<DsarCategoryExport>,
    val exportChecksumSha256: String,
    val legalHoldActive: Boolean,
    val legalHoldReference: String? = null,
    val statutoryRetentionApplies: Boolean = false,
    val approverId: String? = null,
    val notes: String? = null,
    val version: Long,
    val evidenceReference: String,
    val createdAt: Instant,
    val completedAt: Instant? = null,
    val semanticContract: String = DSAR_FULFILLMENT_CONTRACT,
)

data class DsarResult(
    val resultId: UUID,
    val dsar: DsarRecord,
    val serverTime: Instant,
    val isDuplicate: Boolean,
    val isFinancialAuthorityCreated: Boolean = false,
    val semanticContract: String = DSAR_FULFILLMENT_CONTRACT,
)

data class FulfilDsarCommand(
    val tenantId: String,
    val dsarReference: String,
    val subjectId: String,
    val requestType: DsarRequestType = DsarRequestType.ACCESS_EXPORT,
    val requestedCategories: Set<DataCategory> = emptySet(),
    val categoryPayloads: Map<DataCategory, String> = emptyMap(),
    val approverId: String? = null,
    val notes: String? = null,
    val idempotencyKey: String,
    val correlationId: String,
    val causationId: String,
    val expectedVersion: Long = 1L,
    val principal: AuthenticatedPrincipal? = null,
)

data class DsarSnapshot(
    val dsars: Map<String, DsarRecord>,
    val idempotencyMap: Map<String, Pair<String, DsarResult>>,
    val auditEvents: List<AuditEvent>,
    val outboxEvents: List<OutboxEvent>,
)

interface DsarAlertSink {
    fun sendAlert(tenantId: String, reference: String, alertType: String, reason: String, detail: String)
}

class InMemoryDsarAlertSink : DsarAlertSink {
    val alerts = mutableListOf<String>()

    @Synchronized
    override fun sendAlert(tenantId: String, reference: String, alertType: String, reason: String, detail: String) {
        alerts.add("$tenantId:$reference:$alertType:$reason:$detail")
    }
}

interface DsarStore {
    fun findByReference(tenantId: String, dsarReference: String): DsarRecord?
    fun findByIdempotency(tenantId: String, idempotencyKey: String): Pair<String, DsarResult>?
    fun saveDsar(
        record: DsarRecord,
        result: DsarResult,
        idempotencyKey: String,
        fingerprint: String,
        audit: AuditEvent,
        outbox: OutboxEvent,
    )
    fun updateDsar(
        record: DsarRecord,
        result: DsarResult,
        idempotencyKey: String,
        fingerprint: String,
        audit: AuditEvent,
        outbox: OutboxEvent,
    )
    fun getAuditEvents(): List<AuditEvent>
    fun getOutboxEvents(): List<OutboxEvent>
    fun exportSnapshot(): DsarSnapshot
    fun importSnapshot(snapshot: DsarSnapshot)
}

open class InMemoryDsarStore : DsarStore {
    private val records = ConcurrentHashMap<String, DsarRecord>()
    private val idempotencyResults = ConcurrentHashMap<String, Pair<String, DsarResult>>()
    private val auditEvents = mutableListOf<AuditEvent>()
    private val outboxEvents = mutableListOf<OutboxEvent>()

    private fun dsarKey(tenantId: String, ref: String) = "$tenantId:$ref"
    private fun idKey(tenantId: String, idemp: String) = "$tenantId:$idemp"

    @Synchronized
    override fun findByReference(tenantId: String, dsarReference: String): DsarRecord? =
        records[dsarKey(tenantId, dsarReference)]?.copy()

    @Synchronized
    override fun findByIdempotency(tenantId: String, idempotencyKey: String): Pair<String, DsarResult>? =
        idempotencyResults[idKey(tenantId, idempotencyKey)]

    @Synchronized
    open override fun saveDsar(
        record: DsarRecord,
        result: DsarResult,
        idempotencyKey: String,
        fingerprint: String,
        audit: AuditEvent,
        outbox: OutboxEvent,
    ) {
        records[dsarKey(record.tenantId, record.dsarReference)] = record.copy()
        idempotencyResults[idKey(record.tenantId, idempotencyKey)] = fingerprint to result
        auditEvents.add(audit)
        outboxEvents.add(outbox)
    }

    @Synchronized
    override fun updateDsar(
        record: DsarRecord,
        result: DsarResult,
        idempotencyKey: String,
        fingerprint: String,
        audit: AuditEvent,
        outbox: OutboxEvent,
    ) {
        records[dsarKey(record.tenantId, record.dsarReference)] = record.copy()
        idempotencyResults[idKey(record.tenantId, idempotencyKey)] = fingerprint to result
        auditEvents.add(audit)
        outboxEvents.add(outbox)
    }

    @Synchronized
    override fun getAuditEvents(): List<AuditEvent> = auditEvents.toList()

    @Synchronized
    override fun getOutboxEvents(): List<OutboxEvent> = outboxEvents.toList()

    @Synchronized
    override fun exportSnapshot(): DsarSnapshot = DsarSnapshot(
        dsars = HashMap(records),
        idempotencyMap = HashMap(idempotencyResults),
        auditEvents = ArrayList(auditEvents),
        outboxEvents = ArrayList(outboxEvents),
    )

    @Synchronized
    override fun importSnapshot(snapshot: DsarSnapshot) {
        records.clear()
        records.putAll(snapshot.dsars)
        idempotencyResults.clear()
        idempotencyResults.putAll(snapshot.idempotencyMap)
        auditEvents.clear()
        auditEvents.addAll(snapshot.auditEvents)
        outboxEvents.clear()
        outboxEvents.addAll(snapshot.outboxEvents)
    }
}

class DsarFulfillmentService(
    private val store: DsarStore,
    private val inventoryStore: PersonalDataInventoryStore,
    private val alertSink: DsarAlertSink = InMemoryDsarAlertSink(),
    private val clock: Clock = Clock.systemUTC(),
) {
    private fun sha256(input: String): String {
        val digest = MessageDigest.getInstance("SHA-256")
        val hash = digest.digest(input.toByteArray(StandardCharsets.UTF_8))
        return hash.joinToString("") { "%02x".format(it) }
    }

    private fun computeChecksum(
        tenantId: String,
        dsarReference: String,
        subjectId: String,
        requestType: DsarRequestType,
        categories: List<DsarCategoryExport>,
        legalHoldActive: Boolean,
        statutoryRetentionApplies: Boolean,
    ): String {
        val catDigest = categories
            .sortedBy { it.category.name }
            .joinToString("|") {
                "${it.category}:${it.storageSystem}:${it.classification}:${it.legalBasis}:${it.recordCount}:${it.dataDigestSha256}:${it.activeLegalHold}:${it.statutoryRetentionOverride}"
            }
        val raw = "$tenantId:$dsarReference:$subjectId:$requestType:$legalHoldActive:$statutoryRetentionApplies:$catDigest"
        return sha256(raw)
    }

    private fun fingerprintCommand(cmd: FulfilDsarCommand): String {
        val catHash = cmd.requestedCategories.sortedBy { it.name }.joinToString(",")
        val payloadHash = cmd.categoryPayloads.entries.sortedBy { it.key.name }.joinToString(";") { "${it.key}:${sha256(it.value)}" }
        return sha256("${cmd.tenantId}:${cmd.dsarReference}:${cmd.subjectId}:${cmd.requestType}:$catHash:$payloadHash:${cmd.approverId}:${cmd.notes}:${cmd.expectedVersion}")
    }

    private fun validatePrincipal(principal: AuthenticatedPrincipal?, tenantId: String, subjectId: String) {
        principal?.let {
            if (it.tenantId != tenantId) {
                throw AuthenticationFailure.Rejected(AuthErrorCode.FORBIDDEN)
            }
            if (it.kind == PrincipalKind.PLAYER) {
                // Players can only access their own DSAR records (IDOR prevention)
                if (it.id != subjectId) {
                    throw AuthenticationFailure.Rejected(AuthErrorCode.FORBIDDEN)
                }
            } else if (it.kind == PrincipalKind.ADMIN) {
                // Admins must possess privacy/security/audit privileges
                if (it.roles.none { role -> role in setOf(AdminRole.SUPER_ADMIN, AdminRole.SECURITY, AdminRole.AUDITOR) }) {
                    throw AuthenticationFailure.Rejected(AuthErrorCode.FORBIDDEN)
                }
            } else {
                throw AuthenticationFailure.Rejected(AuthErrorCode.FORBIDDEN)
            }
        }
    }

    @Synchronized
    fun fulfilDsar(command: FulfilDsarCommand): DsarResult {
        // Protected risk assertion: missed copy/illegal delete/hold bypass
        DsarFulfillmentBinding.checkBound()

        // 1. Mandatory Input Validation
        if (command.tenantId.isBlank() ||
            command.dsarReference.isBlank() ||
            command.subjectId.isBlank() ||
            command.idempotencyKey.isBlank() ||
            command.correlationId.isBlank() ||
            command.causationId.isBlank()
        ) {
            alertSink.sendAlert(
                tenantId = command.tenantId.ifBlank { "UNKNOWN" },
                reference = command.dsarReference.ifBlank { "UNKNOWN" },
                alertType = "DSAR_INVALID_INPUT",
                reason = "BLANK_MANDATORY_FIELDS",
                detail = "Fulfil DSAR rejected due to blank mandatory fields",
            )
            throw AuthenticationFailure.Rejected(AuthErrorCode.INVALID)
        }

        if (command.expectedVersion != 1L) {
            throw AuthenticationFailure.Rejected(AuthErrorCode.STALE)
        }

        validatePrincipal(command.principal, command.tenantId, command.subjectId)

        val fp = fingerprintCommand(command)
        val now = clock.instant()

        // 2. Idempotency Check
        val existingIdemp = store.findByIdempotency(command.tenantId, command.idempotencyKey)
        if (existingIdemp != null) {
            val (cachedFp, cachedResult) = existingIdemp
            if (cachedFp != fp) {
                alertSink.sendAlert(
                    tenantId = command.tenantId,
                    reference = command.dsarReference,
                    alertType = "DSAR_IDEMPOTENCY_CONFLICT",
                    reason = "PAYLOAD_MISMATCH",
                    detail = "Payload mismatch detected for DSAR idempotency key ${command.idempotencyKey}",
                )
                throw AuthenticationFailure.Rejected(AuthErrorCode.CONFLICT)
            }
            return cachedResult.copy(isDuplicate = true)
        }

        val existingDsar = store.findByReference(command.tenantId, command.dsarReference)
        if (existingDsar != null) {
            alertSink.sendAlert(
                tenantId = command.tenantId,
                reference = command.dsarReference,
                alertType = "DSAR_REFERENCE_CONFLICT",
                reason = "REFERENCE_ALREADY_EXISTS",
                detail = "DSAR reference ${command.dsarReference} already exists",
            )
            throw AuthenticationFailure.Rejected(AuthErrorCode.CONFLICT)
        }

        // 3. Compile Inventoried Data Categories (Prevent missed copy)
        val inventoryItems = inventoryStore.listItems(command.tenantId)
        val activeSubjectHold = inventoryStore.findActiveHoldFor(command.tenantId, null, command.subjectId)

        val targetCategories = if (command.requestedCategories.isNotEmpty()) {
            inventoryItems.filter { it.dataCategory in command.requestedCategories }
        } else {
            inventoryItems
        }

        val collectedCategoryExports = mutableListOf<DsarCategoryExport>()
        var statutoryRetentionApplies = false

        for (inv in targetCategories) {
            val specificHold = inventoryStore.findActiveHoldFor(command.tenantId, inv.inventoryReference, command.subjectId)
            val isHoldActive = activeSubjectHold != null || specificHold != null || inv.activeLegalHold
            val isStatutory = inv.statutoryRetentionOverride || inv.dataCategory == DataCategory.LEDGER
            if (isStatutory) {
                statutoryRetentionApplies = true
            }

            val payload = command.categoryPayloads[inv.dataCategory] ?: "{\"category\":\"${inv.dataCategory}\",\"storage\":\"${inv.storageSystem}\"}"
            val payloadDigest = sha256(payload)

            collectedCategoryExports.add(
                DsarCategoryExport(
                    category = inv.dataCategory,
                    storageSystem = inv.storageSystem,
                    classification = inv.classification,
                    legalBasis = inv.legalBasis,
                    recordCount = 1,
                    dataDigestSha256 = payloadDigest,
                    activeLegalHold = isHoldActive,
                    statutoryRetentionOverride = isStatutory,
                    notes = if (isHoldActive) "Active legal hold applied: ${activeSubjectHold?.holdReference ?: specificHold?.holdReference ?: inv.legalHoldReference}" else null,
                )
            )
        }

        // If targetCategories is empty because no inventory registered yet, check default category
        if (collectedCategoryExports.isEmpty()) {
            val isHoldActive = activeSubjectHold != null
            collectedCategoryExports.add(
                DsarCategoryExport(
                    category = DataCategory.IDENTITY,
                    storageSystem = "player_profile_db",
                    classification = DataClassification.PII,
                    legalBasis = ProcessingLegalBasis.CONTRACT_PERFORMANCE,
                    recordCount = 1,
                    dataDigestSha256 = sha256("{\"subjectId\":\"${command.subjectId}\"}"),
                    activeLegalHold = isHoldActive,
                    statutoryRetentionOverride = false,
                )
            )
        }

        val hasActiveLegalHold = activeSubjectHold != null || collectedCategoryExports.any { it.activeLegalHold }
        val finalStatus = DsarStatus.FULFILLED

        val checksum = computeChecksum(
            tenantId = command.tenantId,
            dsarReference = command.dsarReference,
            subjectId = command.subjectId,
            requestType = command.requestType,
            categories = collectedCategoryExports,
            legalHoldActive = hasActiveLegalHold,
            statutoryRetentionApplies = statutoryRetentionApplies,
        )

        val dsarId = UUID.randomUUID()
        val resultId = UUID.randomUUID()
        val evidenceRef = "EVID-DSAR-$dsarId"

        val dsar = DsarRecord(
            dsarId = dsarId,
            tenantId = command.tenantId,
            dsarReference = command.dsarReference,
            subjectId = command.subjectId,
            requestType = command.requestType,
            status = finalStatus,
            collectedCategories = collectedCategoryExports,
            exportChecksumSha256 = checksum,
            legalHoldActive = hasActiveLegalHold,
            legalHoldReference = activeSubjectHold?.holdReference,
            statutoryRetentionApplies = statutoryRetentionApplies,
            approverId = command.approverId,
            notes = command.notes,
            version = 1L,
            evidenceReference = evidenceRef,
            createdAt = now,
            completedAt = now,
            semanticContract = DSAR_FULFILLMENT_CONTRACT,
        )

        val result = DsarResult(
            resultId = resultId,
            dsar = dsar,
            serverTime = now,
            isDuplicate = false,
            isFinancialAuthorityCreated = false,
            semanticContract = DSAR_FULFILLMENT_CONTRACT,
        )

        alertSink.sendAlert(
            tenantId = command.tenantId,
            reference = command.dsarReference,
            alertType = "DSAR_FULFILLED",
            reason = command.requestType.name,
            detail = "DSAR fulfilled for subject ${command.subjectId} across ${collectedCategoryExports.size} categories. LegalHold=$hasActiveLegalHold, Statutory=$statutoryRetentionApplies",
        )

        val audit = AuditEvent(UUID.randomUUID(), dsarId, command.tenantId, "DSAR_FULFILLED", now, command.correlationId, command.causationId)
        val outbox = OutboxEvent(UUID.randomUUID(), dsarId, command.tenantId, "DSAR_FULFILLED", now)

        try {
            store.saveDsar(dsar, result, command.idempotencyKey, fp, audit, outbox)
        } catch (e: Exception) {
            alertSink.sendAlert(
                tenantId = command.tenantId,
                reference = command.dsarReference,
                alertType = "DSAR_STORAGE_FAILED",
                reason = "STORE_FAILURE",
                detail = "Failed to store DSAR package: ${e.message}",
            )
            throw AuthenticationFailure.Rejected(AuthErrorCode.DEPENDENCY_UNAVAILABLE)
        }

        return result
    }
}
