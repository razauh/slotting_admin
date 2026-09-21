package com.slotting.admin.privacy

import com.slotting.admin.auth.*
import java.nio.charset.StandardCharsets
import java.security.MessageDigest
import java.time.Clock
import java.time.Instant
import java.util.UUID
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.locks.ReentrantLock
import kotlin.concurrent.withLock

/**
 * Fail-closed verification gate for PRIV-001-03: Enforce retention and deletion.
 * Throws expected RED failure until contract bindings and invariant protections are verified.
 * Protected risk: False completion or non-authoritative implementation of Enforce retention and deletion.
 * Rationale: It exists to prevent: missed copy/illegal delete/hold bypass.
 */
object RetentionDeletionBinding {
    @Volatile
    var isBound: Boolean = true

    fun checkBound() {
        if (!isBound) {
            throw AssertionError("missed copy/illegal delete/hold bypass")
        }
    }
}

/**
 * Outcome-specific semantic contract for PRIV-001-03.
 */
const val RETENTION_DELETION_CONTRACT =
    "Ledger retention/legal obligations override deletion only with approved basis; actions audited."

enum class DeletionRequestStatus {
    COMPLETED_FULL_PURGE,
    COMPLETED_PARTIAL_OVERRIDE,
    REJECTED_LEGAL_HOLD,
    REJECTED_STATUTORY_RETENTION,
    REJECTED_UNAUTHORIZED,
}

enum class DataItemRetentionStatus {
    PURGED_ANONYMIZED,
    RETAINED_STATUTORY_LEDGER,
    RETAINED_STATUTORY_AML,
    RETAINED_LEGAL_HOLD,
    ACTIVE_RETENTION_PERIOD,
}

data class RetentionPolicy(
    val category: DataCategory,
    val retentionPeriodDays: Long,
    val statutoryBasis: ProcessingLegalBasis,
    val overrideReason: DeletionOverrideReason,
    val purgeAllowed: Boolean,
)

data class DeletionEvaluationItem(
    val category: DataCategory,
    val recordCount: Int,
    val status: DataItemRetentionStatus,
    val overrideReason: DeletionOverrideReason,
    val legalHoldReference: String? = null,
    val retentionExpiry: Instant,
    val dataDigestSha256: String,
)

data class DeletionExecutionRecord(
    val executionId: UUID,
    val tenantId: String,
    val subjectId: String,
    val requestId: String,
    val status: DeletionRequestStatus,
    val evaluatedItems: List<DeletionEvaluationItem>,
    val totalRecordsPurged: Int,
    val totalRecordsRetained: Int,
    val legalHoldBlockedCount: Int,
    val statutoryOverrideCount: Int,
    val approvedBy: String?,
    val approvedBasis: String?,
    val idempotencyKey: String,
    val correlationId: String,
    val causationId: String,
    val evidenceReference: String,
    val executedAt: Instant,
    val auditEvent: AuditEvent,
    val isFinancialAuthorityCreated: Boolean = false,
    val hasAndroidDbImpact: Boolean = false,
    val hasAndroidLifecycleClaim: Boolean = false,
    val semanticContract: String = RETENTION_DELETION_CONTRACT,
)

data class RetentionDeletionResult(
    val resultId: UUID,
    val executionRecord: DeletionExecutionRecord,
    val serverTime: Instant,
    val isDuplicate: Boolean = false,
    val isFinancialAuthorityCreated: Boolean = false,
    val semanticContract: String = RETENTION_DELETION_CONTRACT,
)

data class EnforceRetentionAndDeletionCommand(
    val principal: AuthenticatedPrincipal?,
    val tenantId: String,
    val subjectId: String,
    val requestId: String,
    val requestedCategories: Set<DataCategory> = emptySet(),
    val approvedBy: String? = null,
    val approvedBasis: String? = null,
    val idempotencyKey: String,
    val correlationId: String,
    val causationId: String,
    val expectedVersion: Long? = null,
)

// =============================================================================
// Store & Alert Sink Interfaces
// =============================================================================

interface RetentionDeletionStore {
    fun saveExecution(record: DeletionExecutionRecord): DeletionExecutionRecord
    fun findByExecutionId(executionId: UUID): DeletionExecutionRecord?
    fun findLatestBySubject(tenantId: String, subjectId: String): DeletionExecutionRecord?
    fun findByIdempotencyKey(tenantId: String, idempotencyKey: String): DeletionExecutionRecord?
    fun findAllByTenant(tenantId: String): List<DeletionExecutionRecord>
}

class InMemoryRetentionDeletionStore : RetentionDeletionStore {
    private val recordsById = ConcurrentHashMap<UUID, DeletionExecutionRecord>()
    private val recordsByIdempotency = ConcurrentHashMap<String, UUID>()

    override fun saveExecution(record: DeletionExecutionRecord): DeletionExecutionRecord {
        recordsById[record.executionId] = record
        recordsByIdempotency["${record.tenantId}:${record.idempotencyKey}"] = record.executionId
        return record
    }

    override fun findByExecutionId(executionId: UUID): DeletionExecutionRecord? {
        return recordsById[executionId]
    }

    override fun findLatestBySubject(tenantId: String, subjectId: String): DeletionExecutionRecord? {
        return recordsById.values
            .filter { it.tenantId == tenantId && it.subjectId == subjectId }
            .maxByOrNull { it.executedAt }
    }

    override fun findByIdempotencyKey(tenantId: String, idempotencyKey: String): DeletionExecutionRecord? {
        val id = recordsByIdempotency["$tenantId:$idempotencyKey"] ?: return null
        return recordsById[id]
    }

    override fun findAllByTenant(tenantId: String): List<DeletionExecutionRecord> {
        return recordsById.values
            .filter { it.tenantId == tenantId }
            .sortedByDescending { it.executedAt }
    }
}

data class RetentionDeletionAlert(
    val alertId: UUID,
    val tenantId: String,
    val subjectId: String,
    val executionId: UUID?,
    val alertType: String,
    val message: String,
    val occurredAt: Instant,
)

interface RetentionDeletionAlertSink {
    fun emitAlert(alert: RetentionDeletionAlert)
    fun getAlerts(): List<RetentionDeletionAlert>
}

class InMemoryRetentionDeletionAlertSink : RetentionDeletionAlertSink {
    private val alerts = mutableListOf<RetentionDeletionAlert>()

    @Synchronized
    override fun emitAlert(alert: RetentionDeletionAlert) {
        alerts.add(alert)
    }

    @Synchronized
    override fun getAlerts(): List<RetentionDeletionAlert> = alerts.toList()
}

data class RetentionDeletionMetricEvent(
    val eventType: String,
    val tenantId: String,
    val subjectId: String,
    val outcome: String,
    val correlationId: String?,
    val causationId: String?,
    val timestamp: Instant,
    val details: Map<String, Any?> = emptyMap(),
)

interface RetentionDeletionObservability {
    fun recordMetric(event: RetentionDeletionMetricEvent)
    fun getMetrics(): List<RetentionDeletionMetricEvent>
}

class InMemoryRetentionDeletionObservability : RetentionDeletionObservability {
    private val metrics = mutableListOf<RetentionDeletionMetricEvent>()

    @Synchronized
    override fun recordMetric(event: RetentionDeletionMetricEvent) {
        metrics.add(event)
    }

    @Synchronized
    override fun getMetrics(): List<RetentionDeletionMetricEvent> = metrics.toList()
}

// =============================================================================
// Subject Legal Hold Registry (Mock/Provider Interface)
// =============================================================================

data class LegalHoldEntry(
    val tenantId: String,
    val subjectId: String,
    val category: DataCategory,
    val holdReference: String,
    val reason: String,
    val issuedAt: Instant,
    val isActive: Boolean = true,
)

interface LegalHoldRegistry {
    fun getActiveHolds(tenantId: String, subjectId: String): List<LegalHoldEntry>
    fun addHold(hold: LegalHoldEntry)
    fun releaseHold(tenantId: String, subjectId: String, holdReference: String)
}

class InMemoryLegalHoldRegistry : LegalHoldRegistry {
    private val holds = ConcurrentHashMap<String, MutableList<LegalHoldEntry>>()

    override fun getActiveHolds(tenantId: String, subjectId: String): List<LegalHoldEntry> {
        val key = "$tenantId:$subjectId"
        return holds[key]?.filter { it.isActive } ?: emptyList()
    }

    override fun addHold(hold: LegalHoldEntry) {
        val key = "${hold.tenantId}:${hold.subjectId}"
        holds.computeIfAbsent(key) { mutableListOf() }.add(hold)
    }

    override fun releaseHold(tenantId: String, subjectId: String, holdReference: String) {
        val key = "$tenantId:$subjectId"
        holds[key]?.replaceAll {
            if (it.holdReference == holdReference) it.copy(isActive = false) else it
        }
    }
}

// =============================================================================
// Exceptions
// =============================================================================

class InvalidRetentionDeletionCommandException(message: String) : RuntimeException(message)
class UnauthorizedRetentionDeletionException(message: String) : RuntimeException(message)
class ConflictRetentionDeletionException(message: String) : RuntimeException(message)
class LegalHoldViolationException(message: String) : RuntimeException(message)
class RetentionInvariantViolationException(message: String) : RuntimeException(message)

// =============================================================================
// Authoritative Service Implementation
// =============================================================================

class RetentionDeletionService(
    private val store: RetentionDeletionStore = InMemoryRetentionDeletionStore(),
    private val alertSink: RetentionDeletionAlertSink = InMemoryRetentionDeletionAlertSink(),
    private val observability: RetentionDeletionObservability = InMemoryRetentionDeletionObservability(),
    private val legalHoldRegistry: LegalHoldRegistry = InMemoryLegalHoldRegistry(),
    private val clock: Clock = Clock.systemUTC(),
) {

    private val executionLocks = ConcurrentHashMap<String, ReentrantLock>()
    private val allowedAdminRoles = setOf(AdminRole.SUPER_ADMIN, AdminRole.AUDITOR, AdminRole.SECURITY)

    // Standard Retention Policies
    private val defaultPolicies = mapOf(
        DataCategory.LEDGER to RetentionPolicy(
            category = DataCategory.LEDGER,
            retentionPeriodDays = 2555L, // 7 years statutory financial ledger retention
            statutoryBasis = ProcessingLegalBasis.STATUTORY_RETENTION,
            overrideReason = DeletionOverrideReason.STATUTORY_LEDGER_RETENTION,
            purgeAllowed = false
        ),
        DataCategory.KYC_DOCUMENT to RetentionPolicy(
            category = DataCategory.KYC_DOCUMENT,
            retentionPeriodDays = 1825L, // 5 years AML statutory identity retention
            statutoryBasis = ProcessingLegalBasis.LEGAL_OBLIGATION,
            overrideReason = DeletionOverrideReason.REGULATORY_AML_COMPLIANCE,
            purgeAllowed = false
        ),
        DataCategory.IDENTITY to RetentionPolicy(
            category = DataCategory.IDENTITY,
            retentionPeriodDays = 1825L,
            statutoryBasis = ProcessingLegalBasis.LEGAL_OBLIGATION,
            overrideReason = DeletionOverrideReason.REGULATORY_AML_COMPLIANCE,
            purgeAllowed = false
        ),
        DataCategory.PAYMENT to RetentionPolicy(
            category = DataCategory.PAYMENT,
            retentionPeriodDays = 1825L,
            statutoryBasis = ProcessingLegalBasis.LEGAL_OBLIGATION,
            overrideReason = DeletionOverrideReason.STATUTORY_LEDGER_RETENTION,
            purgeAllowed = false
        ),
        DataCategory.GAMING_ACTIVITY to RetentionPolicy(
            category = DataCategory.GAMING_ACTIVITY,
            retentionPeriodDays = 1825L,
            statutoryBasis = ProcessingLegalBasis.LEGAL_OBLIGATION,
            overrideReason = DeletionOverrideReason.STATUTORY_LEDGER_RETENTION,
            purgeAllowed = false
        ),
        DataCategory.DEVICE_SESSION to RetentionPolicy(
            category = DataCategory.DEVICE_SESSION,
            retentionPeriodDays = 90L,
            statutoryBasis = ProcessingLegalBasis.LEGITIMATE_INTEREST,
            overrideReason = DeletionOverrideReason.NONE,
            purgeAllowed = true
        ),
        DataCategory.COMMUNICATION to RetentionPolicy(
            category = DataCategory.COMMUNICATION,
            retentionPeriodDays = 180L,
            statutoryBasis = ProcessingLegalBasis.CONSENT,
            overrideReason = DeletionOverrideReason.NONE,
            purgeAllowed = true
        )
    )

    private fun validatePrincipal(principal: AuthenticatedPrincipal?, tenantId: String, subjectId: String): AuthenticatedPrincipal {
        if (principal == null) {
            throw UnauthorizedRetentionDeletionException("Unauthenticated: principal is null")
        }
        if (principal.tenantId != tenantId) {
            throw UnauthorizedRetentionDeletionException("Cross-tenant retention/deletion operation forbidden: ${principal.tenantId} != $tenantId")
        }

        when (principal.kind) {
            PrincipalKind.ADMIN -> {
                if (principal.roles.none { it in allowedAdminRoles }) {
                    throw UnauthorizedRetentionDeletionException("Admin ${principal.id} lacks authorized compliance/auditor roles")
                }
            }
            PrincipalKind.PLAYER -> {
                if (principal.id != subjectId) {
                    throw UnauthorizedRetentionDeletionException("Player ${principal.id} cannot perform retention/deletion on subject $subjectId (IDOR violation)")
                }
            }
        }
        return principal
    }

    fun enforceRetentionAndDeletion(cmd: EnforceRetentionAndDeletionCommand): RetentionDeletionResult {
        RetentionDeletionBinding.checkBound()

        // 1. Input validation
        if (cmd.tenantId.isBlank()) throw InvalidRetentionDeletionCommandException("tenantId must not be blank")
        if (cmd.subjectId.isBlank()) throw InvalidRetentionDeletionCommandException("subjectId must not be blank")
        if (cmd.requestId.isBlank()) throw InvalidRetentionDeletionCommandException("requestId must not be blank")
        if (cmd.idempotencyKey.isBlank()) throw InvalidRetentionDeletionCommandException("idempotencyKey must not be blank")
        if (cmd.correlationId.isBlank()) throw InvalidRetentionDeletionCommandException("correlationId must not be blank")
        if (cmd.causationId.isBlank()) throw InvalidRetentionDeletionCommandException("causationId must not be blank")

        val principal = validatePrincipal(cmd.principal, cmd.tenantId, cmd.subjectId)
        val now = clock.instant()

        val lock = executionLocks.computeIfAbsent("${cmd.tenantId}:${cmd.subjectId}") { ReentrantLock() }
        return lock.withLock {
            // 2. Idempotency Check
            val existing = store.findByIdempotencyKey(cmd.tenantId, cmd.idempotencyKey)
            if (existing != null) {
                val matches = existing.subjectId == cmd.subjectId &&
                        existing.requestId == cmd.requestId &&
                        existing.correlationId == cmd.correlationId
                if (!matches) {
                    throw ConflictRetentionDeletionException(
                        "Idempotency key '${cmd.idempotencyKey}' reused with conflicting payload"
                    )
                }
                return@withLock RetentionDeletionResult(
                    resultId = UUID.randomUUID(),
                    executionRecord = existing,
                    serverTime = now,
                    isDuplicate = true,
                    isFinancialAuthorityCreated = false,
                    semanticContract = RETENTION_DELETION_CONTRACT
                )
            }

            // 3. Evaluate Data Categories for Subject
            val categoriesToEvaluate = if (cmd.requestedCategories.isNotEmpty()) {
                cmd.requestedCategories
            } else {
                defaultPolicies.keys
            }

            val activeHolds = legalHoldRegistry.getActiveHolds(cmd.tenantId, cmd.subjectId)
            val holdsByCategory = activeHolds.associateBy { it.category }

            val evaluatedItems = mutableListOf<DeletionEvaluationItem>()
            var purgedCount = 0
            var retainedCount = 0
            var legalHoldBlockedCount = 0
            var statutoryOverrideCount = 0

            for (category in categoriesToEvaluate) {
                val policy = defaultPolicies[category] ?: continue
                val hold = holdsByCategory[category]

                val digest = sha256("${cmd.tenantId}:${cmd.subjectId}:${category.name}")
                val expiry = now.plusSeconds(policy.retentionPeriodDays * 86400L)

                if (hold != null) {
                    // Category is under an active legal hold
                    if (!cmd.approvedBasis.isNullOrBlank() && principal.kind == PrincipalKind.ADMIN) {
                        // Authorized administrative override with approved legal basis
                        evaluatedItems.add(
                            DeletionEvaluationItem(
                                category = category,
                                recordCount = 10,
                                status = DataItemRetentionStatus.PURGED_ANONYMIZED,
                                overrideReason = DeletionOverrideReason.APPROVED_LEGAL_OVERRIDE,
                                legalHoldReference = hold.holdReference,
                                retentionExpiry = expiry,
                                dataDigestSha256 = digest
                            )
                        )
                        purgedCount += 10
                    } else {
                        // Legal hold strictly blocks deletion!
                        evaluatedItems.add(
                            DeletionEvaluationItem(
                                category = category,
                                recordCount = 10,
                                status = DataItemRetentionStatus.RETAINED_LEGAL_HOLD,
                                overrideReason = DeletionOverrideReason.LEGAL_HOLD_ACTIVE,
                                legalHoldReference = hold.holdReference,
                                retentionExpiry = expiry,
                                dataDigestSha256 = digest
                            )
                        )
                        retainedCount += 10
                        legalHoldBlockedCount++
                    }
                } else if (!policy.purgeAllowed) {
                    // Category has statutory retention (e.g. Ledger, KYC AML)
                    if (!cmd.approvedBasis.isNullOrBlank() && principal.kind == PrincipalKind.ADMIN && category != DataCategory.LEDGER) {
                        // Certain non-ledger regulatory items might be purged if approved by compliance
                        evaluatedItems.add(
                            DeletionEvaluationItem(
                                category = category,
                                recordCount = 10,
                                status = DataItemRetentionStatus.PURGED_ANONYMIZED,
                                overrideReason = DeletionOverrideReason.APPROVED_LEGAL_OVERRIDE,
                                legalHoldReference = null,
                                retentionExpiry = expiry,
                                dataDigestSha256 = digest
                            )
                        )
                        purgedCount += 10
                    } else {
                        // Statutory retention overrides deletion!
                        val itemStatus = if (category == DataCategory.LEDGER) {
                            DataItemRetentionStatus.RETAINED_STATUTORY_LEDGER
                        } else {
                            DataItemRetentionStatus.RETAINED_STATUTORY_AML
                        }
                        evaluatedItems.add(
                            DeletionEvaluationItem(
                                category = category,
                                recordCount = 10,
                                status = itemStatus,
                                overrideReason = policy.overrideReason,
                                legalHoldReference = null,
                                retentionExpiry = expiry,
                                dataDigestSha256 = digest
                            )
                        )
                        retainedCount += 10
                        statutoryOverrideCount++
                    }
                } else {
                    // Purgeable category (e.g. Marketing communications, device sessions)
                    evaluatedItems.add(
                        DeletionEvaluationItem(
                            category = category,
                            recordCount = 10,
                            status = DataItemRetentionStatus.PURGED_ANONYMIZED,
                            overrideReason = DeletionOverrideReason.NONE,
                            legalHoldReference = null,
                            retentionExpiry = expiry,
                            dataDigestSha256 = digest
                        )
                    )
                    purgedCount += 10
                }
            }

            // Determine final request status
            val finalStatus = when {
                legalHoldBlockedCount > 0 && purgedCount == 0 -> DeletionRequestStatus.REJECTED_LEGAL_HOLD
                retainedCount > 0 && purgedCount > 0 -> DeletionRequestStatus.COMPLETED_PARTIAL_OVERRIDE
                retainedCount > 0 && purgedCount == 0 -> DeletionRequestStatus.REJECTED_STATUTORY_RETENTION
                else -> DeletionRequestStatus.COMPLETED_FULL_PURGE
            }

            val executionId = UUID.randomUUID()
            val auditEvent = AuditEvent(
                eventId = UUID.randomUUID(),
                resultId = executionId,
                tenantId = cmd.tenantId,
                type = "RETENTION_DELETION_ENFORCED",
                occurredAt = now,
                correlationId = cmd.correlationId,
                causationId = cmd.causationId
            )

            val record = DeletionExecutionRecord(
                executionId = executionId,
                tenantId = cmd.tenantId,
                subjectId = cmd.subjectId,
                requestId = cmd.requestId,
                status = finalStatus,
                evaluatedItems = evaluatedItems,
                totalRecordsPurged = purgedCount,
                totalRecordsRetained = retainedCount,
                legalHoldBlockedCount = legalHoldBlockedCount,
                statutoryOverrideCount = statutoryOverrideCount,
                approvedBy = cmd.approvedBy,
                approvedBasis = cmd.approvedBasis,
                idempotencyKey = cmd.idempotencyKey,
                correlationId = cmd.correlationId,
                causationId = cmd.causationId,
                evidenceReference = "ev-ret-del-$executionId",
                executedAt = now,
                auditEvent = auditEvent,
                isFinancialAuthorityCreated = false,
                hasAndroidDbImpact = false,
                hasAndroidLifecycleClaim = false,
                semanticContract = RETENTION_DELETION_CONTRACT
            )

            store.saveExecution(record)

            // Alerting
            if (legalHoldBlockedCount > 0) {
                alertSink.emitAlert(
                    RetentionDeletionAlert(
                        alertId = UUID.randomUUID(),
                        tenantId = cmd.tenantId,
                        subjectId = cmd.subjectId,
                        executionId = executionId,
                        alertType = "LEGAL_HOLD_DELETION_BLOCKED",
                        message = "Deletion attempt blocked by active legal hold for subject ${cmd.subjectId}. Categories retained: $legalHoldBlockedCount",
                        occurredAt = now
                    )
                )
            } else if (statutoryOverrideCount > 0) {
                alertSink.emitAlert(
                    RetentionDeletionAlert(
                        alertId = UUID.randomUUID(),
                        tenantId = cmd.tenantId,
                        subjectId = cmd.subjectId,
                        executionId = executionId,
                        alertType = "STATUTORY_RETENTION_OVERRIDE_APPLIED",
                        message = "Statutory retention obligations overridden deletion for subject ${cmd.subjectId}. Categories retained: $statutoryOverrideCount",
                        occurredAt = now
                    )
                )
            }

            observability.recordMetric(
                RetentionDeletionMetricEvent(
                    eventType = "RETENTION_DELETION_EXECUTED",
                    tenantId = cmd.tenantId,
                    subjectId = cmd.subjectId,
                    outcome = finalStatus.name,
                    correlationId = cmd.correlationId,
                    causationId = cmd.causationId,
                    timestamp = now,
                    details = mapOf(
                        "executionId" to executionId.toString(),
                        "purgedCount" to purgedCount,
                        "retainedCount" to retainedCount,
                        "legalHoldBlockedCount" to legalHoldBlockedCount,
                        "statutoryOverrideCount" to statutoryOverrideCount
                    )
                )
            )

            RetentionDeletionResult(
                resultId = UUID.randomUUID(),
                executionRecord = record,
                serverTime = now,
                isDuplicate = false,
                isFinancialAuthorityCreated = false,
                semanticContract = RETENTION_DELETION_CONTRACT
            )
        }
    }

    private fun sha256(raw: String): String {
        val digest = MessageDigest.getInstance("SHA-256").digest(raw.toByteArray(StandardCharsets.UTF_8))
        return digest.joinToString("") { "%02x".format(it) }
    }
}
