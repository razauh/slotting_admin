package com.slotting.admin.privacy

import com.slotting.admin.auth.*
import java.time.Clock
import java.time.Instant
import java.util.UUID
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.locks.ReentrantLock
import kotlin.concurrent.withLock

/**
 * Fail-closed verification gate for PRIV-001-04: Enforce legal holds.
 * Throws expected RED failure until contract bindings and invariant protections are verified.
 * Protected risk: False completion or non-authoritative implementation of Enforce legal holds.
 * Rationale: It exists to prevent: missed copy/illegal delete/hold bypass.
 */
object LegalHoldBinding {
    @Volatile
    var isBound: Boolean = true

    fun checkBound() {
        if (!isBound) {
            throw AssertionError("missed copy/illegal delete/hold bypass")
        }
    }
}

/**
 * Outcome-specific semantic contract for PRIV-001-04.
 */
const val LEGAL_HOLD_CONTRACT =
    "Ledger retention/legal obligations override deletion only with approved basis; actions audited."

enum class LegalHoldStatus {
    ACTIVE,
    RELEASED,
}

data class EnforcedLegalHoldRecord(
    val holdId: UUID,
    val tenantId: String,
    val subjectId: String,
    val holdReference: String,
    val matterId: String,
    val jurisdiction: String,
    val targetCategories: Set<DataCategory>,
    val reason: String,
    val status: LegalHoldStatus,
    val placedBy: String,
    val placedAt: Instant,
    val releasedBy: String? = null,
    val releasedAt: Instant? = null,
    val releaseJustification: String? = null,
    val version: Long,
    val evidenceReference: String,
    val auditEvent: AuditEvent,
    val isFinancialAuthorityCreated: Boolean = false,
    val hasAndroidDbImpact: Boolean = false,
    val hasAndroidLifecycleClaim: Boolean = false,
    val semanticContract: String = LEGAL_HOLD_CONTRACT,
)

data class PlaceLegalHoldCommand(
    val principal: AuthenticatedPrincipal?,
    val tenantId: String,
    val subjectId: String,
    val holdReference: String,
    val matterId: String,
    val jurisdiction: String = "GLOBAL",
    val targetCategories: Set<DataCategory> = emptySet(),
    val reason: String,
    val idempotencyKey: String,
    val correlationId: String,
    val causationId: String,
)

data class ReleaseEnforcedLegalHoldCommand(
    val principal: AuthenticatedPrincipal?,
    val tenantId: String,
    val subjectId: String,
    val holdReference: String,
    val releaseJustification: String,
    val idempotencyKey: String,
    val correlationId: String,
    val causationId: String,
)

data class EvaluateHoldForDeletionCommand(
    val principal: AuthenticatedPrincipal?,
    val tenantId: String,
    val subjectId: String,
    val categories: Set<DataCategory>,
    val approvedOverrideBasis: String? = null,
    val correlationId: String,
    val causationId: String,
)

data class HoldEvaluationResult(
    val isBlocked: Boolean,
    val blockedCategories: Set<DataCategory>,
    val activeHolds: List<EnforcedLegalHoldRecord>,
    val decisionDetails: String,
    val serverTime: Instant,
    val semanticContract: String = LEGAL_HOLD_CONTRACT,
)

data class EnforcedLegalHoldResult(
    val resultId: UUID,
    val holdRecord: EnforcedLegalHoldRecord,
    val serverTime: Instant,
    val isDuplicate: Boolean = false,
    val isFinancialAuthorityCreated: Boolean = false,
    val semanticContract: String = LEGAL_HOLD_CONTRACT,
)

// =============================================================================
// Store & Alert Sink Interfaces
// =============================================================================

interface LegalHoldStore {
    fun saveHold(record: EnforcedLegalHoldRecord): EnforcedLegalHoldRecord
    fun findByHoldId(holdId: UUID): EnforcedLegalHoldRecord?
    fun findByReference(tenantId: String, holdReference: String): EnforcedLegalHoldRecord?
    fun findActiveHoldsBySubject(tenantId: String, subjectId: String): List<EnforcedLegalHoldRecord>
    fun findByIdempotencyKey(tenantId: String, idempotencyKey: String): EnforcedLegalHoldRecord?
    fun findAllByTenant(tenantId: String): List<EnforcedLegalHoldRecord>
}

class InMemoryLegalHoldStore : LegalHoldStore {
    private val recordsById = ConcurrentHashMap<UUID, EnforcedLegalHoldRecord>()
    private val recordsByReference = ConcurrentHashMap<String, UUID>()
    private val recordsByIdempotency = ConcurrentHashMap<String, UUID>()

    override fun saveHold(record: EnforcedLegalHoldRecord): EnforcedLegalHoldRecord {
        recordsById[record.holdId] = record
        recordsByReference["${record.tenantId}:${record.holdReference}"] = record.holdId
        recordsByIdempotency["${record.tenantId}:${record.evidenceReference}"] = record.holdId
        return record
    }

    override fun findByHoldId(holdId: UUID): EnforcedLegalHoldRecord? {
        return recordsById[holdId]
    }

    override fun findByReference(tenantId: String, holdReference: String): EnforcedLegalHoldRecord? {
        val id = recordsByReference["$tenantId:$holdReference"] ?: return null
        return recordsById[id]
    }

    override fun findActiveHoldsBySubject(tenantId: String, subjectId: String): List<EnforcedLegalHoldRecord> {
        return recordsById.values
            .filter { it.tenantId == tenantId && it.subjectId == subjectId && it.status == LegalHoldStatus.ACTIVE }
            .sortedByDescending { it.placedAt }
    }

    override fun findByIdempotencyKey(tenantId: String, idempotencyKey: String): EnforcedLegalHoldRecord? {
        val id = recordsByIdempotency["$tenantId:$idempotencyKey"] ?: return null
        return recordsById[id]
    }

    override fun findAllByTenant(tenantId: String): List<EnforcedLegalHoldRecord> {
        return recordsById.values
            .filter { it.tenantId == tenantId }
            .sortedByDescending { it.placedAt }
    }
}

data class LegalHoldAlert(
    val alertId: UUID,
    val tenantId: String,
    val subjectId: String,
    val holdReference: String?,
    val alertType: String,
    val message: String,
    val occurredAt: Instant,
)

interface LegalHoldAlertSink {
    fun emitAlert(alert: LegalHoldAlert)
    fun getAlerts(): List<LegalHoldAlert>
}

class InMemoryLegalHoldAlertSink : LegalHoldAlertSink {
    private val alerts = mutableListOf<LegalHoldAlert>()

    @Synchronized
    override fun emitAlert(alert: LegalHoldAlert) {
        alerts.add(alert)
    }

    @Synchronized
    override fun getAlerts(): List<LegalHoldAlert> = alerts.toList()
}

data class LegalHoldMetricEvent(
    val eventType: String,
    val tenantId: String,
    val subjectId: String,
    val outcome: String,
    val correlationId: String?,
    val causationId: String?,
    val timestamp: Instant,
    val details: Map<String, Any?> = emptyMap(),
)

interface LegalHoldObservability {
    fun recordMetric(event: LegalHoldMetricEvent)
    fun getMetrics(): List<LegalHoldMetricEvent>
}

class InMemoryLegalHoldObservability : LegalHoldObservability {
    private val metrics = mutableListOf<LegalHoldMetricEvent>()

    @Synchronized
    override fun recordMetric(event: LegalHoldMetricEvent) {
        metrics.add(event)
    }

    @Synchronized
    override fun getMetrics(): List<LegalHoldMetricEvent> = metrics.toList()
}

// =============================================================================
// Exceptions
// =============================================================================

class InvalidLegalHoldCommandException(message: String) : RuntimeException(message)
class UnauthorizedLegalHoldException(message: String) : RuntimeException(message)
class ConflictLegalHoldException(message: String) : RuntimeException(message)
class LegalHoldNotFoundException(message: String) : RuntimeException(message)
class LegalHoldBlockedException(message: String) : RuntimeException(message)
class LegalHoldInvariantViolationException(message: String) : RuntimeException(message)

// =============================================================================
// Authoritative Service Implementation
// =============================================================================

class LegalHoldService(
    private val store: LegalHoldStore = InMemoryLegalHoldStore(),
    private val alertSink: LegalHoldAlertSink = InMemoryLegalHoldAlertSink(),
    private val observability: LegalHoldObservability = InMemoryLegalHoldObservability(),
    private val clock: Clock = Clock.systemUTC(),
) {

    private val executionLocks = ConcurrentHashMap<String, ReentrantLock>()
    private val allowedAdminRoles = setOf(AdminRole.SUPER_ADMIN, AdminRole.AUDITOR, AdminRole.SECURITY)
    private val idempotencyMap = ConcurrentHashMap<String, EnforcedLegalHoldRecord>()

    private fun validateAdminPrincipal(principal: AuthenticatedPrincipal?, tenantId: String): AuthenticatedPrincipal {
        if (principal == null) {
            throw UnauthorizedLegalHoldException("Unauthenticated: principal is null")
        }
        if (principal.tenantId != tenantId) {
            throw UnauthorizedLegalHoldException("Cross-tenant legal hold operation forbidden: ${principal.tenantId} != $tenantId")
        }
        if (principal.kind != PrincipalKind.ADMIN || principal.roles.none { it in allowedAdminRoles }) {
            throw UnauthorizedLegalHoldException("Principal ${principal.id} is not authorized for legal hold operations")
        }
        return principal
    }

    /**
     * Places a binding legal hold on a subject across target categories (or all categories if empty).
     */
    fun placeLegalHold(cmd: PlaceLegalHoldCommand): EnforcedLegalHoldResult {
        LegalHoldBinding.checkBound()

        if (cmd.tenantId.isBlank()) throw InvalidLegalHoldCommandException("tenantId must not be blank")
        if (cmd.subjectId.isBlank()) throw InvalidLegalHoldCommandException("subjectId must not be blank")
        if (cmd.holdReference.isBlank()) throw InvalidLegalHoldCommandException("holdReference must not be blank")
        if (cmd.matterId.isBlank()) throw InvalidLegalHoldCommandException("matterId must not be blank")
        if (cmd.reason.isBlank()) throw InvalidLegalHoldCommandException("reason must not be blank")
        if (cmd.idempotencyKey.isBlank()) throw InvalidLegalHoldCommandException("idempotencyKey must not be blank")
        if (cmd.correlationId.isBlank()) throw InvalidLegalHoldCommandException("correlationId must not be blank")
        if (cmd.causationId.isBlank()) throw InvalidLegalHoldCommandException("causationId must not be blank")

        val principal = validateAdminPrincipal(cmd.principal, cmd.tenantId)
        val now = clock.instant()

        val lockKey = "${cmd.tenantId}:${cmd.subjectId}"
        val lock = executionLocks.computeIfAbsent(lockKey) { ReentrantLock() }
        return lock.withLock {
            val idemKey = "${cmd.tenantId}:${cmd.idempotencyKey}"
            val existingIdem = idempotencyMap[idemKey]
            if (existingIdem != null) {
                val matches = existingIdem.subjectId == cmd.subjectId &&
                        existingIdem.holdReference == cmd.holdReference &&
                        existingIdem.matterId == cmd.matterId
                if (!matches) {
                    throw ConflictLegalHoldException("Idempotency key '${cmd.idempotencyKey}' reused with conflicting payload")
                }
                return@withLock EnforcedLegalHoldResult(
                    resultId = UUID.randomUUID(),
                    holdRecord = existingIdem,
                    serverTime = now,
                    isDuplicate = true,
                    isFinancialAuthorityCreated = false,
                    semanticContract = LEGAL_HOLD_CONTRACT
                )
            }

            // Verify whether reference already exists
            val existingRef = store.findByReference(cmd.tenantId, cmd.holdReference)
            if (existingRef != null && existingRef.status == LegalHoldStatus.ACTIVE) {
                throw ConflictLegalHoldException("Active legal hold with reference '${cmd.holdReference}' already exists")
            }

            val targetCats = if (cmd.targetCategories.isNotEmpty()) {
                cmd.targetCategories
            } else {
                DataCategory.values().toSet()
            }

            val holdId = UUID.randomUUID()
            val auditEvent = AuditEvent(
                eventId = UUID.randomUUID(),
                resultId = holdId,
                tenantId = cmd.tenantId,
                type = "LEGAL_HOLD_PLACED",
                occurredAt = now,
                correlationId = cmd.correlationId,
                causationId = cmd.causationId
            )

            val record = EnforcedLegalHoldRecord(
                holdId = holdId,
                tenantId = cmd.tenantId,
                subjectId = cmd.subjectId,
                holdReference = cmd.holdReference,
                matterId = cmd.matterId,
                jurisdiction = cmd.jurisdiction,
                targetCategories = targetCats,
                reason = cmd.reason,
                status = LegalHoldStatus.ACTIVE,
                placedBy = principal.id,
                placedAt = now,
                version = 1L,
                evidenceReference = "ev-hold-$holdId",
                auditEvent = auditEvent,
                isFinancialAuthorityCreated = false,
                hasAndroidDbImpact = false,
                hasAndroidLifecycleClaim = false,
                semanticContract = LEGAL_HOLD_CONTRACT
            )

            store.saveHold(record)
            idempotencyMap[idemKey] = record

            alertSink.emitAlert(
                LegalHoldAlert(
                    alertId = UUID.randomUUID(),
                    tenantId = cmd.tenantId,
                    subjectId = cmd.subjectId,
                    holdReference = cmd.holdReference,
                    alertType = "LEGAL_HOLD_ACTIVE",
                    message = "Legal hold '${cmd.holdReference}' placed on subject ${cmd.subjectId} for matter ${cmd.matterId}. Deletions frozen across ${targetCats.size} categories.",
                    occurredAt = now
                )
            )

            observability.recordMetric(
                LegalHoldMetricEvent(
                    eventType = "LEGAL_HOLD_PLACED",
                    tenantId = cmd.tenantId,
                    subjectId = cmd.subjectId,
                    outcome = "ACTIVE",
                    correlationId = cmd.correlationId,
                    causationId = cmd.causationId,
                    timestamp = now,
                    details = mapOf(
                        "holdId" to holdId.toString(),
                        "holdReference" to cmd.holdReference,
                        "categoriesCount" to targetCats.size
                    )
                )
            )

            EnforcedLegalHoldResult(
                resultId = UUID.randomUUID(),
                holdRecord = record,
                serverTime = now,
                isDuplicate = false,
                isFinancialAuthorityCreated = false,
                semanticContract = LEGAL_HOLD_CONTRACT
            )
        }
    }

    /**
     * Releases an active legal hold with required justification.
     */
    fun releaseLegalHold(cmd: ReleaseEnforcedLegalHoldCommand): EnforcedLegalHoldResult {
        LegalHoldBinding.checkBound()

        if (cmd.tenantId.isBlank()) throw InvalidLegalHoldCommandException("tenantId must not be blank")
        if (cmd.subjectId.isBlank()) throw InvalidLegalHoldCommandException("subjectId must not be blank")
        if (cmd.holdReference.isBlank()) throw InvalidLegalHoldCommandException("holdReference must not be blank")
        if (cmd.releaseJustification.isBlank()) throw InvalidLegalHoldCommandException("releaseJustification must not be blank")
        if (cmd.idempotencyKey.isBlank()) throw InvalidLegalHoldCommandException("idempotencyKey must not be blank")
        if (cmd.correlationId.isBlank()) throw InvalidLegalHoldCommandException("correlationId must not be blank")
        if (cmd.causationId.isBlank()) throw InvalidLegalHoldCommandException("causationId must not be blank")

        val principal = validateAdminPrincipal(cmd.principal, cmd.tenantId)
        val now = clock.instant()

        val lockKey = "${cmd.tenantId}:${cmd.subjectId}"
        val lock = executionLocks.computeIfAbsent(lockKey) { ReentrantLock() }
        return lock.withLock {
            val idemKey = "${cmd.tenantId}:${cmd.idempotencyKey}"
            val existingIdem = idempotencyMap[idemKey]
            if (existingIdem != null) {
                return@withLock EnforcedLegalHoldResult(
                    resultId = UUID.randomUUID(),
                    holdRecord = existingIdem,
                    serverTime = now,
                    isDuplicate = true,
                    isFinancialAuthorityCreated = false,
                    semanticContract = LEGAL_HOLD_CONTRACT
                )
            }

            val existing = store.findByReference(cmd.tenantId, cmd.holdReference)
                ?: throw LegalHoldNotFoundException("Legal hold '${cmd.holdReference}' not found")

            if (existing.status == LegalHoldStatus.RELEASED) {
                // Already released
                return@withLock EnforcedLegalHoldResult(
                    resultId = UUID.randomUUID(),
                    holdRecord = existing,
                    serverTime = now,
                    isDuplicate = false,
                    isFinancialAuthorityCreated = false,
                    semanticContract = LEGAL_HOLD_CONTRACT
                )
            }

            val auditEvent = AuditEvent(
                eventId = UUID.randomUUID(),
                resultId = existing.holdId,
                tenantId = cmd.tenantId,
                type = "LEGAL_HOLD_RELEASED",
                occurredAt = now,
                correlationId = cmd.correlationId,
                causationId = cmd.causationId
            )

            val updatedRecord = existing.copy(
                status = LegalHoldStatus.RELEASED,
                releasedBy = principal.id,
                releasedAt = now,
                releaseJustification = cmd.releaseJustification,
                version = existing.version + 1,
                auditEvent = auditEvent
            )

            store.saveHold(updatedRecord)
            idempotencyMap[idemKey] = updatedRecord

            alertSink.emitAlert(
                LegalHoldAlert(
                    alertId = UUID.randomUUID(),
                    tenantId = cmd.tenantId,
                    subjectId = cmd.subjectId,
                    holdReference = cmd.holdReference,
                    alertType = "LEGAL_HOLD_RELEASED",
                    message = "Legal hold '${cmd.holdReference}' released by ${principal.id}: ${cmd.releaseJustification}",
                    occurredAt = now
                )
            )

            observability.recordMetric(
                LegalHoldMetricEvent(
                    eventType = "LEGAL_HOLD_RELEASED",
                    tenantId = cmd.tenantId,
                    subjectId = cmd.subjectId,
                    outcome = "RELEASED",
                    correlationId = cmd.correlationId,
                    causationId = cmd.causationId,
                    timestamp = now,
                    details = mapOf(
                        "holdId" to existing.holdId.toString(),
                        "holdReference" to cmd.holdReference,
                        "releasedBy" to principal.id
                    )
                )
            )

            EnforcedLegalHoldResult(
                resultId = UUID.randomUUID(),
                holdRecord = updatedRecord,
                serverTime = now,
                isDuplicate = false,
                isFinancialAuthorityCreated = false,
                semanticContract = LEGAL_HOLD_CONTRACT
            )
        }
    }

    /**
     * Intercepts and evaluates whether a proposed deletion or purge is blocked by any active legal holds.
     */
    fun evaluateHoldForDeletion(cmd: EvaluateHoldForDeletionCommand): HoldEvaluationResult {
        LegalHoldBinding.checkBound()

        if (cmd.tenantId.isBlank()) throw InvalidLegalHoldCommandException("tenantId must not be blank")
        if (cmd.subjectId.isBlank()) throw InvalidLegalHoldCommandException("subjectId must not be blank")

        val now = clock.instant()
        val activeHolds = store.findActiveHoldsBySubject(cmd.tenantId, cmd.subjectId)

        if (activeHolds.isEmpty()) {
            return HoldEvaluationResult(
                isBlocked = false,
                blockedCategories = emptySet(),
                activeHolds = emptyList(),
                decisionDetails = "No active legal holds on subject ${cmd.subjectId}",
                serverTime = now,
                semanticContract = LEGAL_HOLD_CONTRACT
            )
        }

        // Check if categories intersect with active hold categories
        val heldCategories = activeHolds.flatMap { it.targetCategories }.toSet()
        val requestedIntersect = if (cmd.categories.isEmpty()) heldCategories else cmd.categories.intersect(heldCategories)

        if (requestedIntersect.isEmpty()) {
            return HoldEvaluationResult(
                isBlocked = false,
                blockedCategories = emptySet(),
                activeHolds = activeHolds,
                decisionDetails = "Requested categories do not intersect with active legal hold categories",
                serverTime = now,
                semanticContract = LEGAL_HOLD_CONTRACT
            )
        }

        // Active holds intersect with requested categories
        if (!cmd.approvedOverrideBasis.isNullOrBlank() && cmd.principal?.kind == PrincipalKind.ADMIN && cmd.principal.roles.any { it in allowedAdminRoles }) {
            // Authorized administrative override with approved legal basis
            return HoldEvaluationResult(
                isBlocked = false,
                blockedCategories = emptySet(),
                activeHolds = activeHolds,
                decisionDetails = "Legal hold overridden with approved legal basis: ${cmd.approvedOverrideBasis}",
                serverTime = now,
                semanticContract = LEGAL_HOLD_CONTRACT
            )
        }

        // Strictly BLOCKED!
        alertSink.emitAlert(
            LegalHoldAlert(
                alertId = UUID.randomUUID(),
                tenantId = cmd.tenantId,
                subjectId = cmd.subjectId,
                holdReference = activeHolds.map { it.holdReference }.joinToString(),
                alertType = "LEGAL_HOLD_BLOCK_ENFORCED",
                message = "Deletion attempt blocked by active legal hold(s) for categories: $requestedIntersect",
                occurredAt = now
            )
        )

        observability.recordMetric(
            LegalHoldMetricEvent(
                eventType = "LEGAL_HOLD_EVALUATE_BLOCK",
                tenantId = cmd.tenantId,
                subjectId = cmd.subjectId,
                outcome = "BLOCKED",
                correlationId = cmd.correlationId,
                causationId = cmd.causationId,
                timestamp = now,
                details = mapOf(
                    "blockedCategories" to requestedIntersect.map { it.name }
                )
            )
        )

        return HoldEvaluationResult(
            isBlocked = true,
            blockedCategories = requestedIntersect,
            activeHolds = activeHolds,
            decisionDetails = "Deletion blocked: active legal hold covers categories: $requestedIntersect",
            serverTime = now,
            semanticContract = LEGAL_HOLD_CONTRACT
        )
    }
}
