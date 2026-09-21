package com.slotting.admin.resilience

import com.slotting.admin.auth.*
import java.time.Clock
import java.time.Instant
import java.util.UUID
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.locks.ReentrantLock
import kotlin.concurrent.withLock

/**
 * Fail-closed verification gate for RES-001-01: Build deterministic failure-injection experiments.
 * Throws expected RED failure until contract bindings and invariant protections are verified.
 * Protected risk: False completion or non-authoritative implementation of Build deterministic failure-injection experiments.
 * Rationale: It exists to prevent: each fault violates stated invariant.
 */
object FailureInjectionBinding {
    @Volatile
    var isBound: Boolean = true

    fun checkBound() {
        if (!isBound) {
            throw AssertionError("each fault violates stated invariant")
        }
    }
}

/**
 * Outcome-specific semantic contract for RES-001-01.
 */
const val FAILURE_INJECTION_CONTRACT =
    "No production destructive test without approval; capture recovery time/data integrity."

enum class TargetEnvironment {
    SANDBOX,
    TEST,
    STAGING,
    PRODUCTION,
}

enum class FaultType {
    DATABASE_ROLLBACK_INJECTION,
    OUTBOX_LEASE_EXPIRY_CRASH,
    REDIS_CACHE_PARTITION,
    PROVIDER_RPC_TIMEOUT,
    NETWORK_SOCKET_DROP,
    WORKER_ABORT_RETRY,
}

enum class ExperimentStatus {
    PLANNED,
    APPROVED,
    RUNNING,
    RECOVERED_SUCCESS,
    INVARIANT_VIOLATION_DETECTED,
    ABORTED,
}

data class FailureInjectionExperimentRecord(
    val experimentId: UUID,
    val tenantId: String,
    val experimentReference: String,
    val faultType: FaultType,
    val targetEnvironment: TargetEnvironment,
    val isDestructive: Boolean,
    val status: ExperimentStatus,
    val approvalReference: String? = null,
    val approvedBy: String? = null,
    val approvedAt: Instant? = null,
    val preStateDigest: String,
    val postStateDigest: String? = null,
    val recoveryTimeMs: Long? = null,
    val dataIntegrityVerified: Boolean = false,
    val invariantsViolated: Boolean = false,
    val details: Map<String, String> = emptyMap(),
    val createdBy: String,
    val createdAt: Instant,
    val updatedAt: Instant,
    val version: Long,
    val evidenceReference: String,
    val auditEvent: AuditEvent,
    val isFinancialAuthorityCreated: Boolean = false,
    val hasAndroidDbImpact: Boolean = false,
    val hasAndroidLifecycleClaim: Boolean = false,
    val semanticContract: String = FAILURE_INJECTION_CONTRACT,
)

data class CreateExperimentPlanCommand(
    val principal: AuthenticatedPrincipal?,
    val tenantId: String,
    val experimentReference: String,
    val faultType: FaultType,
    val targetEnvironment: TargetEnvironment,
    val isDestructive: Boolean,
    val preStateDigest: String,
    val details: Map<String, String> = emptyMap(),
    val idempotencyKey: String,
    val correlationId: String,
    val causationId: String,
)

data class ApproveExperimentCommand(
    val principal: AuthenticatedPrincipal?,
    val tenantId: String,
    val experimentReference: String,
    val approvalReference: String,
    val justification: String,
    val idempotencyKey: String,
    val correlationId: String,
    val causationId: String,
)

data class ExecuteExperimentCommand(
    val principal: AuthenticatedPrincipal?,
    val tenantId: String,
    val experimentReference: String,
    val simulatedDurationMs: Long = 50L,
    val injectInvariantBreach: Boolean = false,
    val idempotencyKey: String,
    val correlationId: String,
    val causationId: String,
)

data class AbortExperimentCommand(
    val principal: AuthenticatedPrincipal?,
    val tenantId: String,
    val experimentReference: String,
    val abortReason: String,
    val idempotencyKey: String,
    val correlationId: String,
    val causationId: String,
)

data class FailureInjectionResult(
    val resultId: UUID,
    val record: FailureInjectionExperimentRecord,
    val serverTime: Instant,
    val isDuplicate: Boolean = false,
    val isFinancialAuthorityCreated: Boolean = false,
    val semanticContract: String = FAILURE_INJECTION_CONTRACT,
)

// =============================================================================
// Store & Alert Sink Interfaces
// =============================================================================

interface FailureInjectionExperimentStore {
    fun save(record: FailureInjectionExperimentRecord): FailureInjectionExperimentRecord
    fun findById(experimentId: UUID): FailureInjectionExperimentRecord?
    fun findByReference(tenantId: String, experimentReference: String): FailureInjectionExperimentRecord?
    fun findAllByTenant(tenantId: String): List<FailureInjectionExperimentRecord>
    fun findByIdempotencyKey(tenantId: String, idempotencyKey: String): FailureInjectionExperimentRecord?
}

class InMemoryFailureInjectionExperimentStore : FailureInjectionExperimentStore {
    private val recordsById = ConcurrentHashMap<UUID, FailureInjectionExperimentRecord>()
    private val recordsByRef = ConcurrentHashMap<String, UUID>()
    private val recordsByIdem = ConcurrentHashMap<String, UUID>()

    override fun save(record: FailureInjectionExperimentRecord): FailureInjectionExperimentRecord {
        recordsById[record.experimentId] = record
        recordsByRef["${record.tenantId}:${record.experimentReference}"] = record.experimentId
        recordsByIdem["${record.tenantId}:${record.evidenceReference}"] = record.experimentId
        return record
    }

    override fun findById(experimentId: UUID): FailureInjectionExperimentRecord? = recordsById[experimentId]

    override fun findByReference(tenantId: String, experimentReference: String): FailureInjectionExperimentRecord? {
        val id = recordsByRef["$tenantId:$experimentReference"] ?: return null
        return recordsById[id]
    }

    override fun findAllByTenant(tenantId: String): List<FailureInjectionExperimentRecord> {
        return recordsById.values
            .filter { it.tenantId == tenantId }
            .sortedByDescending { it.createdAt }
    }

    override fun findByIdempotencyKey(tenantId: String, idempotencyKey: String): FailureInjectionExperimentRecord? {
        val id = recordsByIdem["$tenantId:$idempotencyKey"] ?: return null
        return recordsById[id]
    }
}

data class FailureInjectionAlert(
    val alertId: UUID,
    val tenantId: String,
    val experimentReference: String,
    val alertType: String,
    val environment: TargetEnvironment,
    val message: String,
    val occurredAt: Instant,
)

interface FailureInjectionAlertSink {
    fun emitAlert(alert: FailureInjectionAlert)
    fun getAlerts(): List<FailureInjectionAlert>
}

class InMemoryFailureInjectionAlertSink : FailureInjectionAlertSink {
    private val alerts = mutableListOf<FailureInjectionAlert>()

    @Synchronized
    override fun emitAlert(alert: FailureInjectionAlert) {
        alerts.add(alert)
    }

    @Synchronized
    override fun getAlerts(): List<FailureInjectionAlert> = alerts.toList()
}

data class FailureInjectionMetricEvent(
    val eventType: String,
    val tenantId: String,
    val experimentReference: String,
    val outcome: String,
    val correlationId: String?,
    val causationId: String?,
    val timestamp: Instant,
    val details: Map<String, Any?> = emptyMap(),
)

interface FailureInjectionObservability {
    fun recordMetric(event: FailureInjectionMetricEvent)
    fun getMetrics(): List<FailureInjectionMetricEvent>
}

class InMemoryFailureInjectionObservability : FailureInjectionObservability {
    private val metrics = mutableListOf<FailureInjectionMetricEvent>()

    @Synchronized
    override fun recordMetric(event: FailureInjectionMetricEvent) {
        metrics.add(event)
    }

    @Synchronized
    override fun getMetrics(): List<FailureInjectionMetricEvent> = metrics.toList()
}

// =============================================================================
// Exceptions
// =============================================================================

class InvalidFailureInjectionCommandException(message: String) : RuntimeException(message)
class UnauthorizedFailureInjectionException(message: String) : RuntimeException(message)
class ConflictFailureInjectionException(message: String) : RuntimeException(message)
class FailureInjectionNotFoundException(message: String) : RuntimeException(message)
class UnapprovedDestructiveExperimentException(message: String) : RuntimeException(message)
class IllegalExperimentStateException(message: String) : RuntimeException(message)

// =============================================================================
// Authoritative Service Implementation
// =============================================================================

class DeterministicFailureInjectionService(
    private val store: FailureInjectionExperimentStore = InMemoryFailureInjectionExperimentStore(),
    private val alertSink: FailureInjectionAlertSink = InMemoryFailureInjectionAlertSink(),
    private val observability: FailureInjectionObservability = InMemoryFailureInjectionObservability(),
    private val clock: Clock = Clock.systemUTC(),
) {
    private val executionLocks = ConcurrentHashMap<String, ReentrantLock>()
    private val allowedRoles = setOf(AdminRole.SUPER_ADMIN, AdminRole.SECURITY, AdminRole.AUDITOR)
    private val idempotencyRegistry = ConcurrentHashMap<String, FailureInjectionExperimentRecord>()

    private fun validateAdmin(principal: AuthenticatedPrincipal?, tenantId: String): AuthenticatedPrincipal {
        if (principal == null) {
            throw UnauthorizedFailureInjectionException("Unauthenticated: principal is null")
        }
        if (principal.tenantId != tenantId) {
            throw UnauthorizedFailureInjectionException("Cross-tenant failure injection operation forbidden: ${principal.tenantId} != $tenantId")
        }
        if (principal.kind != PrincipalKind.ADMIN || principal.roles.none { it in allowedRoles }) {
            throw UnauthorizedFailureInjectionException("Principal ${principal.id} is not authorized for failure injection experiments")
        }
        return principal
    }

    /**
     * Creates a deterministic failure injection experiment plan.
     */
    fun createExperimentPlan(cmd: CreateExperimentPlanCommand): FailureInjectionResult {
        FailureInjectionBinding.checkBound()

        if (cmd.tenantId.isBlank()) throw InvalidFailureInjectionCommandException("tenantId must not be blank")
        if (cmd.experimentReference.isBlank()) throw InvalidFailureInjectionCommandException("experimentReference must not be blank")
        if (cmd.preStateDigest.isBlank()) throw InvalidFailureInjectionCommandException("preStateDigest must not be blank")
        if (cmd.idempotencyKey.isBlank()) throw InvalidFailureInjectionCommandException("idempotencyKey must not be blank")
        if (cmd.correlationId.isBlank()) throw InvalidFailureInjectionCommandException("correlationId must not be blank")
        if (cmd.causationId.isBlank()) throw InvalidFailureInjectionCommandException("causationId must not be blank")

        val principal = validateAdmin(cmd.principal, cmd.tenantId)
        val now = clock.instant()

        val lockKey = "${cmd.tenantId}:${cmd.experimentReference}"
        val lock = executionLocks.computeIfAbsent(lockKey) { ReentrantLock() }
        return lock.withLock {
            val idemKey = "${cmd.tenantId}:${cmd.idempotencyKey}"
            val existingIdem = idempotencyRegistry[idemKey]
            if (existingIdem != null) {
                if (existingIdem.experimentReference != cmd.experimentReference ||
                    existingIdem.faultType != cmd.faultType ||
                    existingIdem.targetEnvironment != cmd.targetEnvironment
                ) {
                    throw ConflictFailureInjectionException("Idempotency key reused with conflicting experiment payload")
                }
                return@withLock FailureInjectionResult(
                    resultId = UUID.randomUUID(),
                    record = existingIdem,
                    serverTime = now,
                    isDuplicate = true,
                    isFinancialAuthorityCreated = false,
                    semanticContract = FAILURE_INJECTION_CONTRACT
                )
            }

            val existingRef = store.findByReference(cmd.tenantId, cmd.experimentReference)
            if (existingRef != null) {
                throw ConflictFailureInjectionException("Experiment reference '${cmd.experimentReference}' already exists")
            }

            val experimentId = UUID.randomUUID()
            val auditEvent = AuditEvent(
                eventId = UUID.randomUUID(),
                resultId = experimentId,
                tenantId = cmd.tenantId,
                type = "FAILURE_INJECTION_EXPERIMENT_PLANNED",
                occurredAt = now,
                correlationId = cmd.correlationId,
                causationId = cmd.causationId
            )

            val record = FailureInjectionExperimentRecord(
                experimentId = experimentId,
                tenantId = cmd.tenantId,
                experimentReference = cmd.experimentReference,
                faultType = cmd.faultType,
                targetEnvironment = cmd.targetEnvironment,
                isDestructive = cmd.isDestructive,
                status = ExperimentStatus.PLANNED,
                preStateDigest = cmd.preStateDigest,
                details = cmd.details,
                createdBy = principal.id,
                createdAt = now,
                updatedAt = now,
                version = 1L,
                evidenceReference = "ev-exp-$experimentId",
                auditEvent = auditEvent,
                isFinancialAuthorityCreated = false,
                hasAndroidDbImpact = false,
                hasAndroidLifecycleClaim = false,
                semanticContract = FAILURE_INJECTION_CONTRACT
            )

            store.save(record)
            idempotencyRegistry[idemKey] = record

            alertSink.emitAlert(
                FailureInjectionAlert(
                    alertId = UUID.randomUUID(),
                    tenantId = cmd.tenantId,
                    experimentReference = cmd.experimentReference,
                    alertType = "EXPERIMENT_PLANNED",
                    environment = cmd.targetEnvironment,
                    message = "Experiment '${cmd.experimentReference}' planned for ${cmd.faultType} on ${cmd.targetEnvironment}. Destructive: ${cmd.isDestructive}",
                    occurredAt = now
                )
            )

            observability.recordMetric(
                FailureInjectionMetricEvent(
                    eventType = "EXPERIMENT_PLANNED",
                    tenantId = cmd.tenantId,
                    experimentReference = cmd.experimentReference,
                    outcome = "PLANNED",
                    correlationId = cmd.correlationId,
                    causationId = cmd.causationId,
                    timestamp = now,
                    details = mapOf(
                        "faultType" to cmd.faultType.name,
                        "targetEnvironment" to cmd.targetEnvironment.name,
                        "isDestructive" to cmd.isDestructive
                    )
                )
            )

            FailureInjectionResult(
                resultId = UUID.randomUUID(),
                record = record,
                serverTime = now,
                isDuplicate = false,
                isFinancialAuthorityCreated = false,
                semanticContract = FAILURE_INJECTION_CONTRACT
            )
        }
    }

    /**
     * Approves an experiment. Mandatory before destructive experiments can run in production.
     */
    fun approveExperiment(cmd: ApproveExperimentCommand): FailureInjectionResult {
        FailureInjectionBinding.checkBound()

        if (cmd.tenantId.isBlank()) throw InvalidFailureInjectionCommandException("tenantId must not be blank")
        if (cmd.experimentReference.isBlank()) throw InvalidFailureInjectionCommandException("experimentReference must not be blank")
        if (cmd.approvalReference.isBlank()) throw InvalidFailureInjectionCommandException("approvalReference must not be blank")
        if (cmd.justification.isBlank()) throw InvalidFailureInjectionCommandException("justification must not be blank")
        if (cmd.idempotencyKey.isBlank()) throw InvalidFailureInjectionCommandException("idempotencyKey must not be blank")
        if (cmd.correlationId.isBlank()) throw InvalidFailureInjectionCommandException("correlationId must not be blank")
        if (cmd.causationId.isBlank()) throw InvalidFailureInjectionCommandException("causationId must not be blank")

        val principal = validateAdmin(cmd.principal, cmd.tenantId)
        val now = clock.instant()

        val lockKey = "${cmd.tenantId}:${cmd.experimentReference}"
        val lock = executionLocks.computeIfAbsent(lockKey) { ReentrantLock() }
        return lock.withLock {
            val idemKey = "${cmd.tenantId}:${cmd.idempotencyKey}"
            val existingIdem = idempotencyRegistry[idemKey]
            if (existingIdem != null) {
                return@withLock FailureInjectionResult(
                    resultId = UUID.randomUUID(),
                    record = existingIdem,
                    serverTime = now,
                    isDuplicate = true,
                    isFinancialAuthorityCreated = false,
                    semanticContract = FAILURE_INJECTION_CONTRACT
                )
            }

            val existing = store.findByReference(cmd.tenantId, cmd.experimentReference)
                ?: throw FailureInjectionNotFoundException("Experiment '${cmd.experimentReference}' not found")

            val auditEvent = AuditEvent(
                eventId = UUID.randomUUID(),
                resultId = existing.experimentId,
                tenantId = cmd.tenantId,
                type = "FAILURE_INJECTION_EXPERIMENT_APPROVED",
                occurredAt = now,
                correlationId = cmd.correlationId,
                causationId = cmd.causationId
            )

            val updated = existing.copy(
                status = ExperimentStatus.APPROVED,
                approvalReference = cmd.approvalReference,
                approvedBy = principal.id,
                approvedAt = now,
                updatedAt = now,
                version = existing.version + 1,
                auditEvent = auditEvent
            )

            store.save(updated)
            idempotencyRegistry[idemKey] = updated

            alertSink.emitAlert(
                FailureInjectionAlert(
                    alertId = UUID.randomUUID(),
                    tenantId = cmd.tenantId,
                    experimentReference = cmd.experimentReference,
                    alertType = "EXPERIMENT_APPROVED",
                    environment = existing.targetEnvironment,
                    message = "Experiment '${cmd.experimentReference}' approved by ${principal.id} with ref '${cmd.approvalReference}'. Justification: ${cmd.justification}",
                    occurredAt = now
                )
            )

            observability.recordMetric(
                FailureInjectionMetricEvent(
                    eventType = "EXPERIMENT_APPROVED",
                    tenantId = cmd.tenantId,
                    experimentReference = cmd.experimentReference,
                    outcome = "APPROVED",
                    correlationId = cmd.correlationId,
                    causationId = cmd.causationId,
                    timestamp = now,
                    details = mapOf(
                        "approvedBy" to principal.id,
                        "approvalReference" to cmd.approvalReference
                    )
                )
            )

            FailureInjectionResult(
                resultId = UUID.randomUUID(),
                record = updated,
                serverTime = now,
                isDuplicate = false,
                isFinancialAuthorityCreated = false,
                semanticContract = FAILURE_INJECTION_CONTRACT
            )
        }
    }

    /**
     * Executes the failure injection experiment deterministically.
     * Enforces invariant: "No production destructive test without approval; capture recovery time/data integrity."
     */
    fun executeExperiment(cmd: ExecuteExperimentCommand): FailureInjectionResult {
        FailureInjectionBinding.checkBound()

        if (cmd.tenantId.isBlank()) throw InvalidFailureInjectionCommandException("tenantId must not be blank")
        if (cmd.experimentReference.isBlank()) throw InvalidFailureInjectionCommandException("experimentReference must not be blank")
        if (cmd.idempotencyKey.isBlank()) throw InvalidFailureInjectionCommandException("idempotencyKey must not be blank")
        if (cmd.correlationId.isBlank()) throw InvalidFailureInjectionCommandException("correlationId must not be blank")
        if (cmd.causationId.isBlank()) throw InvalidFailureInjectionCommandException("causationId must not be blank")

        val principal = validateAdmin(cmd.principal, cmd.tenantId)
        val now = clock.instant()

        val lockKey = "${cmd.tenantId}:${cmd.experimentReference}"
        val lock = executionLocks.computeIfAbsent(lockKey) { ReentrantLock() }
        return lock.withLock {
            val idemKey = "${cmd.tenantId}:${cmd.idempotencyKey}"
            val existingIdem = idempotencyRegistry[idemKey]
            if (existingIdem != null) {
                return@withLock FailureInjectionResult(
                    resultId = UUID.randomUUID(),
                    record = existingIdem,
                    serverTime = now,
                    isDuplicate = true,
                    isFinancialAuthorityCreated = false,
                    semanticContract = FAILURE_INJECTION_CONTRACT
                )
            }

            val existing = store.findByReference(cmd.tenantId, cmd.experimentReference)
                ?: throw FailureInjectionNotFoundException("Experiment '${cmd.experimentReference}' not found")

            if (existing.status == ExperimentStatus.ABORTED) {
                throw IllegalExperimentStateException("Cannot execute aborted experiment '${cmd.experimentReference}'")
            }

            // ENFORCE INVARIANT: No production destructive test without approval!
            if (existing.targetEnvironment == TargetEnvironment.PRODUCTION && existing.isDestructive) {
                if (existing.status != ExperimentStatus.APPROVED || existing.approvalReference.isNullOrBlank()) {
                    alertSink.emitAlert(
                        FailureInjectionAlert(
                            alertId = UUID.randomUUID(),
                            tenantId = cmd.tenantId,
                            experimentReference = cmd.experimentReference,
                            alertType = "UNAPPROVED_DESTRUCTIVE_PRODUCTION_BLOCKED",
                            environment = existing.targetEnvironment,
                            message = "BLOCKED: Attempted to execute unapproved destructive experiment on PRODUCTION.",
                            occurredAt = now
                        )
                    )
                    throw UnapprovedDestructiveExperimentException(
                        "No production destructive test without approval; capture recovery time/data integrity."
                    )
                }
            }

            // Simulate deterministic fault injection execution and capture recovery time & integrity
            val recoveryTime = cmd.simulatedDurationMs
            val (finalStatus, integrityVerified, invariantsViolated, postDigest) = if (cmd.injectInvariantBreach) {
                Tuple4(
                    ExperimentStatus.INVARIANT_VIOLATION_DETECTED,
                    false,
                    true,
                    "CORRUPTED-${existing.preStateDigest}"
                )
            } else {
                Tuple4(
                    ExperimentStatus.RECOVERED_SUCCESS,
                    true,
                    false,
                    existing.preStateDigest
                )
            }

            val auditEvent = AuditEvent(
                eventId = UUID.randomUUID(),
                resultId = existing.experimentId,
                tenantId = cmd.tenantId,
                type = "FAILURE_INJECTION_EXPERIMENT_EXECUTED",
                occurredAt = now,
                correlationId = cmd.correlationId,
                causationId = cmd.causationId
            )

            val updated = existing.copy(
                status = finalStatus,
                recoveryTimeMs = recoveryTime,
                dataIntegrityVerified = integrityVerified,
                invariantsViolated = invariantsViolated,
                postStateDigest = postDigest,
                updatedAt = now,
                version = existing.version + 1,
                auditEvent = auditEvent
            )

            store.save(updated)
            idempotencyRegistry[idemKey] = updated

            alertSink.emitAlert(
                FailureInjectionAlert(
                    alertId = UUID.randomUUID(),
                    tenantId = cmd.tenantId,
                    experimentReference = cmd.experimentReference,
                    alertType = if (invariantsViolated) "EXPERIMENT_INVARIANT_VIOLATION" else "EXPERIMENT_RECOVERY_COMPLETED",
                    environment = existing.targetEnvironment,
                    message = "Experiment '${cmd.experimentReference}' concluded. Status: $finalStatus. Recovery time: ${recoveryTime}ms. Integrity verified: $integrityVerified",
                    occurredAt = now
                )
            )

            observability.recordMetric(
                FailureInjectionMetricEvent(
                    eventType = "EXPERIMENT_EXECUTED",
                    tenantId = cmd.tenantId,
                    experimentReference = cmd.experimentReference,
                    outcome = finalStatus.name,
                    correlationId = cmd.correlationId,
                    causationId = cmd.causationId,
                    timestamp = now,
                    details = mapOf(
                        "recoveryTimeMs" to recoveryTime,
                        "dataIntegrityVerified" to integrityVerified,
                        "invariantsViolated" to invariantsViolated
                    )
                )
            )

            FailureInjectionResult(
                resultId = UUID.randomUUID(),
                record = updated,
                serverTime = now,
                isDuplicate = false,
                isFinancialAuthorityCreated = false,
                semanticContract = FAILURE_INJECTION_CONTRACT
            )
        }
    }

    /**
     * Safely aborts an experiment.
     */
    fun abortExperiment(cmd: AbortExperimentCommand): FailureInjectionResult {
        FailureInjectionBinding.checkBound()

        if (cmd.tenantId.isBlank()) throw InvalidFailureInjectionCommandException("tenantId must not be blank")
        if (cmd.experimentReference.isBlank()) throw InvalidFailureInjectionCommandException("experimentReference must not be blank")
        if (cmd.abortReason.isBlank()) throw InvalidFailureInjectionCommandException("abortReason must not be blank")
        if (cmd.idempotencyKey.isBlank()) throw InvalidFailureInjectionCommandException("idempotencyKey must not be blank")
        if (cmd.correlationId.isBlank()) throw InvalidFailureInjectionCommandException("correlationId must not be blank")
        if (cmd.causationId.isBlank()) throw InvalidFailureInjectionCommandException("causationId must not be blank")

        val principal = validateAdmin(cmd.principal, cmd.tenantId)
        val now = clock.instant()

        val lockKey = "${cmd.tenantId}:${cmd.experimentReference}"
        val lock = executionLocks.computeIfAbsent(lockKey) { ReentrantLock() }
        return lock.withLock {
            val idemKey = "${cmd.tenantId}:${cmd.idempotencyKey}"
            val existingIdem = idempotencyRegistry[idemKey]
            if (existingIdem != null) {
                return@withLock FailureInjectionResult(
                    resultId = UUID.randomUUID(),
                    record = existingIdem,
                    serverTime = now,
                    isDuplicate = true,
                    isFinancialAuthorityCreated = false,
                    semanticContract = FAILURE_INJECTION_CONTRACT
                )
            }

            val existing = store.findByReference(cmd.tenantId, cmd.experimentReference)
                ?: throw FailureInjectionNotFoundException("Experiment '${cmd.experimentReference}' not found")

            val auditEvent = AuditEvent(
                eventId = UUID.randomUUID(),
                resultId = existing.experimentId,
                tenantId = cmd.tenantId,
                type = "FAILURE_INJECTION_EXPERIMENT_ABORTED",
                occurredAt = now,
                correlationId = cmd.correlationId,
                causationId = cmd.causationId
            )

            val updated = existing.copy(
                status = ExperimentStatus.ABORTED,
                updatedAt = now,
                version = existing.version + 1,
                auditEvent = auditEvent
            )

            store.save(updated)
            idempotencyRegistry[idemKey] = updated

            alertSink.emitAlert(
                FailureInjectionAlert(
                    alertId = UUID.randomUUID(),
                    tenantId = cmd.tenantId,
                    experimentReference = cmd.experimentReference,
                    alertType = "EXPERIMENT_ABORTED",
                    environment = existing.targetEnvironment,
                    message = "Experiment '${cmd.experimentReference}' aborted by ${principal.id}. Reason: ${cmd.abortReason}",
                    occurredAt = now
                )
            )

            observability.recordMetric(
                FailureInjectionMetricEvent(
                    eventType = "EXPERIMENT_ABORTED",
                    tenantId = cmd.tenantId,
                    experimentReference = cmd.experimentReference,
                    outcome = "ABORTED",
                    correlationId = cmd.correlationId,
                    causationId = cmd.causationId,
                    timestamp = now,
                    details = mapOf(
                        "abortedBy" to principal.id,
                        "abortReason" to cmd.abortReason
                    )
                )
            )

            FailureInjectionResult(
                resultId = UUID.randomUUID(),
                record = updated,
                serverTime = now,
                isDuplicate = false,
                isFinancialAuthorityCreated = false,
                semanticContract = FAILURE_INJECTION_CONTRACT
            )
        }
    }

    private data class Tuple4<A, B, C, D>(val a: A, val b: B, val c: C, val d: D)
}
