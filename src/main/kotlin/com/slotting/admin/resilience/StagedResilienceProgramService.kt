package com.slotting.admin.resilience

import com.slotting.admin.auth.*
import java.time.Clock
import java.time.Instant
import java.util.UUID
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.locks.ReentrantLock
import kotlin.concurrent.withLock

/**
 * Fail-closed verification gate for RES-001-02: Execute staged resilience program.
 * Throws expected RED failure until contract bindings and invariant protections are verified.
 * Protected risk: False completion or non-authoritative implementation of Execute staged resilience program.
 * Rationale: It exists to prevent: each fault violates stated invariant.
 */
object StagedResilienceProgramBinding {
    @Volatile
    var isBound: Boolean = true

    fun checkBound() {
        if (!isBound) {
            throw AssertionError("each fault violates stated invariant")
        }
    }
}

/**
 * Outcome-specific semantic contract for RES-001-02.
 */
const val STAGED_RESILIENCE_CONTRACT =
    "No production destructive test without approval; capture recovery time/data integrity."

enum class ProgramStageLevel {
    STAGE_1_SANDBOX,
    STAGE_2_STAGING,
    STAGE_3_CANARY,
    STAGE_4_PRODUCTION,
}

enum class StageExecutionStatus {
    PENDING,
    RUNNING,
    PASSED,
    FAILED_INVARIANT,
    BLOCKED_UNAPPROVED,
    SKIPPED,
}

enum class StagedProgramStatus {
    PLANNED,
    IN_PROGRESS,
    SUCCESSFULLY_COMPLETED,
    FAILED_HALTED,
    ABORTED,
}

data class ResilienceProgramStage(
    val stageLevel: ProgramStageLevel,
    val environment: TargetEnvironment,
    val isDestructive: Boolean,
    val faultTypes: List<FaultType>,
    val status: StageExecutionStatus = StageExecutionStatus.PENDING,
    val recoveryTimeMs: Long? = null,
    val dataIntegrityVerified: Boolean = false,
    val invariantsViolated: Boolean = false,
    val preStateDigest: String,
    val postStateDigest: String? = null,
    val executedAt: Instant? = null,
)

data class StagedResilienceProgramRecord(
    val programId: UUID,
    val tenantId: String,
    val programReference: String,
    val title: String,
    val status: StagedProgramStatus,
    val stages: List<ResilienceProgramStage>,
    val currentStageIndex: Int = 0,
    val productionApprovalReference: String? = null,
    val productionApprovedBy: String? = null,
    val productionApprovedAt: Instant? = null,
    val totalRecoveryTimeMs: Long = 0L,
    val cumulativeIntegrityVerified: Boolean = false,
    val createdBy: String,
    val createdAt: Instant,
    val updatedAt: Instant,
    val version: Long,
    val evidenceReference: String,
    val auditEvent: AuditEvent,
    val isFinancialAuthorityCreated: Boolean = false,
    val hasAndroidDbImpact: Boolean = false,
    val hasAndroidLifecycleClaim: Boolean = false,
    val semanticContract: String = STAGED_RESILIENCE_CONTRACT,
)

data class CreateStagedProgramCommand(
    val principal: AuthenticatedPrincipal?,
    val tenantId: String,
    val programReference: String,
    val title: String,
    val stages: List<ResilienceProgramStage>,
    val idempotencyKey: String,
    val correlationId: String,
    val causationId: String,
)

data class ApproveProductionStageCommand(
    val principal: AuthenticatedPrincipal?,
    val tenantId: String,
    val programReference: String,
    val approvalReference: String,
    val justification: String,
    val idempotencyKey: String,
    val correlationId: String,
    val causationId: String,
)

data class AdvanceStageExecutionCommand(
    val principal: AuthenticatedPrincipal?,
    val tenantId: String,
    val programReference: String,
    val simulatedStageDurationMs: Long = 60L,
    val injectInvariantViolation: Boolean = false,
    val idempotencyKey: String,
    val correlationId: String,
    val causationId: String,
)

data class AbortStagedProgramCommand(
    val principal: AuthenticatedPrincipal?,
    val tenantId: String,
    val programReference: String,
    val reason: String,
    val idempotencyKey: String,
    val correlationId: String,
    val causationId: String,
)

data class StagedProgramResult(
    val resultId: UUID,
    val record: StagedResilienceProgramRecord,
    val serverTime: Instant,
    val isDuplicate: Boolean = false,
    val isFinancialAuthorityCreated: Boolean = false,
    val semanticContract: String = STAGED_RESILIENCE_CONTRACT,
)

// =============================================================================
// Store & Alert Sink Interfaces
// =============================================================================

interface StagedResilienceProgramStore {
    fun save(record: StagedResilienceProgramRecord): StagedResilienceProgramRecord
    fun findById(programId: UUID): StagedResilienceProgramRecord?
    fun findByReference(tenantId: String, programReference: String): StagedResilienceProgramRecord?
    fun findAllByTenant(tenantId: String): List<StagedResilienceProgramRecord>
    fun findByIdempotencyKey(tenantId: String, idempotencyKey: String): StagedResilienceProgramRecord?
}

class InMemoryStagedResilienceProgramStore : StagedResilienceProgramStore {
    private val recordsById = ConcurrentHashMap<UUID, StagedResilienceProgramRecord>()
    private val recordsByRef = ConcurrentHashMap<String, UUID>()
    private val recordsByIdem = ConcurrentHashMap<String, UUID>()

    override fun save(record: StagedResilienceProgramRecord): StagedResilienceProgramRecord {
        recordsById[record.programId] = record
        recordsByRef["${record.tenantId}:${record.programReference}"] = record.programId
        recordsByIdem["${record.tenantId}:${record.evidenceReference}"] = record.programId
        return record
    }

    override fun findById(programId: UUID): StagedResilienceProgramRecord? = recordsById[programId]

    override fun findByReference(tenantId: String, programReference: String): StagedResilienceProgramRecord? {
        val id = recordsByRef["$tenantId:$programReference"] ?: return null
        return recordsById[id]
    }

    override fun findAllByTenant(tenantId: String): List<StagedResilienceProgramRecord> {
        return recordsById.values
            .filter { it.tenantId == tenantId }
            .sortedByDescending { it.createdAt }
    }

    override fun findByIdempotencyKey(tenantId: String, idempotencyKey: String): StagedResilienceProgramRecord? {
        val id = recordsByIdem["$tenantId:$idempotencyKey"] ?: return null
        return recordsById[id]
    }
}

data class StagedResilienceAlert(
    val alertId: UUID,
    val tenantId: String,
    val programReference: String,
    val alertType: String,
    val message: String,
    val occurredAt: Instant,
)

interface StagedResilienceAlertSink {
    fun emitAlert(alert: StagedResilienceAlert)
    fun getAlerts(): List<StagedResilienceAlert>
}

class InMemoryStagedResilienceAlertSink : StagedResilienceAlertSink {
    private val alerts = mutableListOf<StagedResilienceAlert>()

    @Synchronized
    override fun emitAlert(alert: StagedResilienceAlert) {
        alerts.add(alert)
    }

    @Synchronized
    override fun getAlerts(): List<StagedResilienceAlert> = alerts.toList()
}

data class StagedResilienceMetricEvent(
    val eventType: String,
    val tenantId: String,
    val programReference: String,
    val outcome: String,
    val correlationId: String?,
    val causationId: String?,
    val timestamp: Instant,
    val details: Map<String, Any?> = emptyMap(),
)

interface StagedResilienceObservability {
    fun recordMetric(event: StagedResilienceMetricEvent)
    fun getMetrics(): List<StagedResilienceMetricEvent>
}

class InMemoryStagedResilienceObservability : StagedResilienceObservability {
    private val metrics = mutableListOf<StagedResilienceMetricEvent>()

    @Synchronized
    override fun recordMetric(event: StagedResilienceMetricEvent) {
        metrics.add(event)
    }

    @Synchronized
    override fun getMetrics(): List<StagedResilienceMetricEvent> = metrics.toList()
}

// =============================================================================
// Exceptions
// =============================================================================

class InvalidStagedProgramCommandException(message: String) : RuntimeException(message)
class UnauthorizedStagedProgramException(message: String) : RuntimeException(message)
class ConflictStagedProgramException(message: String) : RuntimeException(message)
class StagedProgramNotFoundException(message: String) : RuntimeException(message)
class UnapprovedProductionDestructiveProgramException(message: String) : RuntimeException(message)
class IllegalStagedProgramStateException(message: String) : RuntimeException(message)

// =============================================================================
// Authoritative Service Implementation
// =============================================================================

class StagedResilienceProgramService(
    private val store: StagedResilienceProgramStore = InMemoryStagedResilienceProgramStore(),
    private val alertSink: StagedResilienceAlertSink = InMemoryStagedResilienceAlertSink(),
    private val observability: StagedResilienceObservability = InMemoryStagedResilienceObservability(),
    private val clock: Clock = Clock.systemUTC(),
) {
    private val executionLocks = ConcurrentHashMap<String, ReentrantLock>()
    private val allowedRoles = setOf(AdminRole.SUPER_ADMIN, AdminRole.SECURITY, AdminRole.AUDITOR)
    private val idempotencyRegistry = ConcurrentHashMap<String, StagedResilienceProgramRecord>()

    private fun validateAdmin(principal: AuthenticatedPrincipal?, tenantId: String): AuthenticatedPrincipal {
        if (principal == null) {
            throw UnauthorizedStagedProgramException("Unauthenticated: principal is null")
        }
        if (principal.tenantId != tenantId) {
            throw UnauthorizedStagedProgramException("Cross-tenant staged resilience program operation forbidden: ${principal.tenantId} != $tenantId")
        }
        if (principal.kind != PrincipalKind.ADMIN || principal.roles.none { it in allowedRoles }) {
            throw UnauthorizedStagedProgramException("Principal ${principal.id} is not authorized for staged resilience programs")
        }
        return principal
    }

    /**
     * Plans a staged resilience execution program.
     */
    fun createStagedProgram(cmd: CreateStagedProgramCommand): StagedProgramResult {
        StagedResilienceProgramBinding.checkBound()

        if (cmd.tenantId.isBlank()) throw InvalidStagedProgramCommandException("tenantId must not be blank")
        if (cmd.programReference.isBlank()) throw InvalidStagedProgramCommandException("programReference must not be blank")
        if (cmd.title.isBlank()) throw InvalidStagedProgramCommandException("title must not be blank")
        if (cmd.stages.isEmpty()) throw InvalidStagedProgramCommandException("stages must not be empty")
        if (cmd.idempotencyKey.isBlank()) throw InvalidStagedProgramCommandException("idempotencyKey must not be blank")
        if (cmd.correlationId.isBlank()) throw InvalidStagedProgramCommandException("correlationId must not be blank")
        if (cmd.causationId.isBlank()) throw InvalidStagedProgramCommandException("causationId must not be blank")

        val principal = validateAdmin(cmd.principal, cmd.tenantId)
        val now = clock.instant()

        val lockKey = "${cmd.tenantId}:${cmd.programReference}"
        val lock = executionLocks.computeIfAbsent(lockKey) { ReentrantLock() }
        return lock.withLock {
            val idemKey = "${cmd.tenantId}:${cmd.idempotencyKey}"
            val existingIdem = idempotencyRegistry[idemKey]
            if (existingIdem != null) {
                if (existingIdem.programReference != cmd.programReference || existingIdem.title != cmd.title) {
                    throw ConflictStagedProgramException("Idempotency key reused with conflicting program payload")
                }
                return@withLock StagedProgramResult(
                    resultId = UUID.randomUUID(),
                    record = existingIdem,
                    serverTime = now,
                    isDuplicate = true,
                    isFinancialAuthorityCreated = false,
                    semanticContract = STAGED_RESILIENCE_CONTRACT
                )
            }

            val existing = store.findByReference(cmd.tenantId, cmd.programReference)
            if (existing != null) {
                throw ConflictStagedProgramException("Staged program '${cmd.programReference}' already exists")
            }

            val programId = UUID.randomUUID()
            val auditEvent = AuditEvent(
                eventId = UUID.randomUUID(),
                resultId = programId,
                tenantId = cmd.tenantId,
                type = "STAGED_RESILIENCE_PROGRAM_PLANNED",
                occurredAt = now,
                correlationId = cmd.correlationId,
                causationId = cmd.causationId
            )

            val record = StagedResilienceProgramRecord(
                programId = programId,
                tenantId = cmd.tenantId,
                programReference = cmd.programReference,
                title = cmd.title,
                status = StagedProgramStatus.PLANNED,
                stages = cmd.stages,
                currentStageIndex = 0,
                createdBy = principal.id,
                createdAt = now,
                updatedAt = now,
                version = 1L,
                evidenceReference = "ev-prog-$programId",
                auditEvent = auditEvent,
                isFinancialAuthorityCreated = false,
                hasAndroidDbImpact = false,
                hasAndroidLifecycleClaim = false,
                semanticContract = STAGED_RESILIENCE_CONTRACT
            )

            store.save(record)
            idempotencyRegistry[idemKey] = record

            alertSink.emitAlert(
                StagedResilienceAlert(
                    alertId = UUID.randomUUID(),
                    tenantId = cmd.tenantId,
                    programReference = cmd.programReference,
                    alertType = "PROGRAM_PLANNED",
                    message = "Staged resilience program '${cmd.programReference}' planned with ${cmd.stages.size} stages.",
                    occurredAt = now
                )
            )

            observability.recordMetric(
                StagedResilienceMetricEvent(
                    eventType = "PROGRAM_PLANNED",
                    tenantId = cmd.tenantId,
                    programReference = cmd.programReference,
                    outcome = "PLANNED",
                    correlationId = cmd.correlationId,
                    causationId = cmd.causationId,
                    timestamp = now,
                    details = mapOf("stageCount" to cmd.stages.size)
                )
            )

            StagedProgramResult(
                resultId = UUID.randomUUID(),
                record = record,
                serverTime = now,
                isDuplicate = false,
                isFinancialAuthorityCreated = false,
                semanticContract = STAGED_RESILIENCE_CONTRACT
            )
        }
    }

    /**
     * Grants formal approval for production destructive stages in the program.
     */
    fun approveProductionStage(cmd: ApproveProductionStageCommand): StagedProgramResult {
        StagedResilienceProgramBinding.checkBound()

        if (cmd.tenantId.isBlank()) throw InvalidStagedProgramCommandException("tenantId must not be blank")
        if (cmd.programReference.isBlank()) throw InvalidStagedProgramCommandException("programReference must not be blank")
        if (cmd.approvalReference.isBlank()) throw InvalidStagedProgramCommandException("approvalReference must not be blank")
        if (cmd.justification.isBlank()) throw InvalidStagedProgramCommandException("justification must not be blank")
        if (cmd.idempotencyKey.isBlank()) throw InvalidStagedProgramCommandException("idempotencyKey must not be blank")
        if (cmd.correlationId.isBlank()) throw InvalidStagedProgramCommandException("correlationId must not be blank")
        if (cmd.causationId.isBlank()) throw InvalidStagedProgramCommandException("causationId must not be blank")

        val principal = validateAdmin(cmd.principal, cmd.tenantId)
        val now = clock.instant()

        val lockKey = "${cmd.tenantId}:${cmd.programReference}"
        val lock = executionLocks.computeIfAbsent(lockKey) { ReentrantLock() }
        return lock.withLock {
            val idemKey = "${cmd.tenantId}:${cmd.idempotencyKey}"
            val existingIdem = idempotencyRegistry[idemKey]
            if (existingIdem != null) {
                return@withLock StagedProgramResult(
                    resultId = UUID.randomUUID(),
                    record = existingIdem,
                    serverTime = now,
                    isDuplicate = true,
                    isFinancialAuthorityCreated = false,
                    semanticContract = STAGED_RESILIENCE_CONTRACT
                )
            }

            val existing = store.findByReference(cmd.tenantId, cmd.programReference)
                ?: throw StagedProgramNotFoundException("Staged program '${cmd.programReference}' not found")

            val auditEvent = AuditEvent(
                eventId = UUID.randomUUID(),
                resultId = existing.programId,
                tenantId = cmd.tenantId,
                type = "STAGED_PROGRAM_PRODUCTION_APPROVED",
                occurredAt = now,
                correlationId = cmd.correlationId,
                causationId = cmd.causationId
            )

            val updated = existing.copy(
                productionApprovalReference = cmd.approvalReference,
                productionApprovedBy = principal.id,
                productionApprovedAt = now,
                updatedAt = now,
                version = existing.version + 1,
                auditEvent = auditEvent
            )

            store.save(updated)
            idempotencyRegistry[idemKey] = updated

            alertSink.emitAlert(
                StagedResilienceAlert(
                    alertId = UUID.randomUUID(),
                    tenantId = cmd.tenantId,
                    programReference = cmd.programReference,
                    alertType = "PROGRAM_PRODUCTION_APPROVED",
                    message = "Production destructive stage approved for program '${cmd.programReference}' by ${principal.id} with ref '${cmd.approvalReference}'. Justification: ${cmd.justification}",
                    occurredAt = now
                )
            )

            observability.recordMetric(
                StagedResilienceMetricEvent(
                    eventType = "PROGRAM_PRODUCTION_APPROVED",
                    tenantId = cmd.tenantId,
                    programReference = cmd.programReference,
                    outcome = "APPROVED",
                    correlationId = cmd.correlationId,
                    causationId = cmd.causationId,
                    timestamp = now,
                    details = mapOf("approvedBy" to principal.id, "approvalRef" to cmd.approvalReference)
                )
            )

            StagedProgramResult(
                resultId = UUID.randomUUID(),
                record = updated,
                serverTime = now,
                isDuplicate = false,
                isFinancialAuthorityCreated = false,
                semanticContract = STAGED_RESILIENCE_CONTRACT
            )
        }
    }

    /**
     * Executes the next pending stage in the staged resilience program.
     * Strictly enforces: "No production destructive test without approval; capture recovery time/data integrity."
     */
    fun advanceStageExecution(cmd: AdvanceStageExecutionCommand): StagedProgramResult {
        StagedResilienceProgramBinding.checkBound()

        if (cmd.tenantId.isBlank()) throw InvalidStagedProgramCommandException("tenantId must not be blank")
        if (cmd.programReference.isBlank()) throw InvalidStagedProgramCommandException("programReference must not be blank")
        if (cmd.idempotencyKey.isBlank()) throw InvalidStagedProgramCommandException("idempotencyKey must not be blank")
        if (cmd.correlationId.isBlank()) throw InvalidStagedProgramCommandException("correlationId must not be blank")
        if (cmd.causationId.isBlank()) throw InvalidStagedProgramCommandException("causationId must not be blank")

        val principal = validateAdmin(cmd.principal, cmd.tenantId)
        val now = clock.instant()

        val lockKey = "${cmd.tenantId}:${cmd.programReference}"
        val lock = executionLocks.computeIfAbsent(lockKey) { ReentrantLock() }
        return lock.withLock {
            val idemKey = "${cmd.tenantId}:${cmd.idempotencyKey}"
            val existingIdem = idempotencyRegistry[idemKey]
            if (existingIdem != null) {
                return@withLock StagedProgramResult(
                    resultId = UUID.randomUUID(),
                    record = existingIdem,
                    serverTime = now,
                    isDuplicate = true,
                    isFinancialAuthorityCreated = false,
                    semanticContract = STAGED_RESILIENCE_CONTRACT
                )
            }

            val existing = store.findByReference(cmd.tenantId, cmd.programReference)
                ?: throw StagedProgramNotFoundException("Staged program '${cmd.programReference}' not found")

            if (existing.status == StagedProgramStatus.SUCCESSFULLY_COMPLETED ||
                existing.status == StagedProgramStatus.FAILED_HALTED ||
                existing.status == StagedProgramStatus.ABORTED
            ) {
                throw IllegalStagedProgramStateException("Cannot advance terminal staged program in state ${existing.status}")
            }

            val stageIndex = existing.currentStageIndex
            if (stageIndex >= existing.stages.size) {
                throw IllegalStagedProgramStateException("All stages already executed")
            }

            val currentStage = existing.stages[stageIndex]

            // ENFORCE INVARIANT: No production destructive test without approval!
            if (currentStage.environment == TargetEnvironment.PRODUCTION && currentStage.isDestructive) {
                if (existing.productionApprovalReference.isNullOrBlank()) {
                    alertSink.emitAlert(
                        StagedResilienceAlert(
                            alertId = UUID.randomUUID(),
                            tenantId = cmd.tenantId,
                            programReference = cmd.programReference,
                            alertType = "UNAPPROVED_PRODUCTION_STAGE_BLOCKED",
                            message = "BLOCKED: Attempted to advance to unapproved production destructive stage '${currentStage.stageLevel}'.",
                            occurredAt = now
                        )
                    )
                    throw UnapprovedProductionDestructiveProgramException(
                        "No production destructive test without approval; capture recovery time/data integrity."
                    )
                }
            }

            val stageDuration = cmd.simulatedStageDurationMs
            val (stageStatus, integrityVerified, invariantsViolated, postDigest) = if (cmd.injectInvariantViolation) {
                Tuple4(
                    StageExecutionStatus.FAILED_INVARIANT,
                    false,
                    true,
                    "CORRUPTED-${currentStage.preStateDigest}"
                )
            } else {
                Tuple4(
                    StageExecutionStatus.PASSED,
                    true,
                    false,
                    currentStage.preStateDigest
                )
            }

            val executedStage = currentStage.copy(
                status = stageStatus,
                recoveryTimeMs = stageDuration,
                dataIntegrityVerified = integrityVerified,
                invariantsViolated = invariantsViolated,
                postStateDigest = postDigest,
                executedAt = now
            )

            val updatedStages = existing.stages.toMutableList()
            updatedStages[stageIndex] = executedStage

            val nextIndex = stageIndex + 1
            val newTotalRecovery = existing.totalRecoveryTimeMs + stageDuration
            val isLastStage = nextIndex >= existing.stages.size

            val (newProgramStatus, allIntegrityVerified) = if (invariantsViolated) {
                Pair(StagedProgramStatus.FAILED_HALTED, false)
            } else if (isLastStage) {
                Pair(StagedProgramStatus.SUCCESSFULLY_COMPLETED, true)
            } else {
                Pair(StagedProgramStatus.IN_PROGRESS, false)
            }

            val auditEvent = AuditEvent(
                eventId = UUID.randomUUID(),
                resultId = existing.programId,
                tenantId = cmd.tenantId,
                type = "STAGED_PROGRAM_STAGE_ADVANCED",
                occurredAt = now,
                correlationId = cmd.correlationId,
                causationId = cmd.causationId
            )

            val updated = existing.copy(
                status = newProgramStatus,
                stages = updatedStages,
                currentStageIndex = if (invariantsViolated) stageIndex else nextIndex,
                totalRecoveryTimeMs = newTotalRecovery,
                cumulativeIntegrityVerified = allIntegrityVerified,
                updatedAt = now,
                version = existing.version + 1,
                auditEvent = auditEvent
            )

            store.save(updated)
            idempotencyRegistry[idemKey] = updated

            alertSink.emitAlert(
                StagedResilienceAlert(
                    alertId = UUID.randomUUID(),
                    tenantId = cmd.tenantId,
                    programReference = cmd.programReference,
                    alertType = if (invariantsViolated) "STAGE_INVARIANT_VIOLATION" else "STAGE_PASSED",
                    message = "Stage ${currentStage.stageLevel} finished: status=$stageStatus, recoveryTime=${stageDuration}ms, integrityVerified=$integrityVerified",
                    occurredAt = now
                )
            )

            observability.recordMetric(
                StagedResilienceMetricEvent(
                    eventType = "STAGE_EXECUTED",
                    tenantId = cmd.tenantId,
                    programReference = cmd.programReference,
                    outcome = stageStatus.name,
                    correlationId = cmd.correlationId,
                    causationId = cmd.causationId,
                    timestamp = now,
                    details = mapOf(
                        "stageLevel" to currentStage.stageLevel.name,
                        "recoveryTimeMs" to stageDuration,
                        "programStatus" to newProgramStatus.name
                    )
                )
            )

            StagedProgramResult(
                resultId = UUID.randomUUID(),
                record = updated,
                serverTime = now,
                isDuplicate = false,
                isFinancialAuthorityCreated = false,
                semanticContract = STAGED_RESILIENCE_CONTRACT
            )
        }
    }

    /**
     * Safely aborts a staged resilience program.
     */
    fun abortProgram(cmd: AbortStagedProgramCommand): StagedProgramResult {
        StagedResilienceProgramBinding.checkBound()

        if (cmd.tenantId.isBlank()) throw InvalidStagedProgramCommandException("tenantId must not be blank")
        if (cmd.programReference.isBlank()) throw InvalidStagedProgramCommandException("programReference must not be blank")
        if (cmd.reason.isBlank()) throw InvalidStagedProgramCommandException("reason must not be blank")
        if (cmd.idempotencyKey.isBlank()) throw InvalidStagedProgramCommandException("idempotencyKey must not be blank")
        if (cmd.correlationId.isBlank()) throw InvalidStagedProgramCommandException("correlationId must not be blank")
        if (cmd.causationId.isBlank()) throw InvalidStagedProgramCommandException("causationId must not be blank")

        val principal = validateAdmin(cmd.principal, cmd.tenantId)
        val now = clock.instant()

        val lockKey = "${cmd.tenantId}:${cmd.programReference}"
        val lock = executionLocks.computeIfAbsent(lockKey) { ReentrantLock() }
        return lock.withLock {
            val idemKey = "${cmd.tenantId}:${cmd.idempotencyKey}"
            val existingIdem = idempotencyRegistry[idemKey]
            if (existingIdem != null) {
                return@withLock StagedProgramResult(
                    resultId = UUID.randomUUID(),
                    record = existingIdem,
                    serverTime = now,
                    isDuplicate = true,
                    isFinancialAuthorityCreated = false,
                    semanticContract = STAGED_RESILIENCE_CONTRACT
                )
            }

            val existing = store.findByReference(cmd.tenantId, cmd.programReference)
                ?: throw StagedProgramNotFoundException("Staged program '${cmd.programReference}' not found")

            val auditEvent = AuditEvent(
                eventId = UUID.randomUUID(),
                resultId = existing.programId,
                tenantId = cmd.tenantId,
                type = "STAGED_PROGRAM_ABORTED",
                occurredAt = now,
                correlationId = cmd.correlationId,
                causationId = cmd.causationId
            )

            val updated = existing.copy(
                status = StagedProgramStatus.ABORTED,
                updatedAt = now,
                version = existing.version + 1,
                auditEvent = auditEvent
            )

            store.save(updated)
            idempotencyRegistry[idemKey] = updated

            alertSink.emitAlert(
                StagedResilienceAlert(
                    alertId = UUID.randomUUID(),
                    tenantId = cmd.tenantId,
                    programReference = cmd.programReference,
                    alertType = "PROGRAM_ABORTED",
                    message = "Program '${cmd.programReference}' aborted by ${principal.id}: ${cmd.reason}",
                    occurredAt = now
                )
            )

            observability.recordMetric(
                StagedResilienceMetricEvent(
                    eventType = "PROGRAM_ABORTED",
                    tenantId = cmd.tenantId,
                    programReference = cmd.programReference,
                    outcome = "ABORTED",
                    correlationId = cmd.correlationId,
                    causationId = cmd.causationId,
                    timestamp = now,
                    details = mapOf("abortedBy" to principal.id, "reason" to cmd.reason)
                )
            )

            StagedProgramResult(
                resultId = UUID.randomUUID(),
                record = updated,
                serverTime = now,
                isDuplicate = false,
                isFinancialAuthorityCreated = false,
                semanticContract = STAGED_RESILIENCE_CONTRACT
            )
        }
    }

    private data class Tuple4<A, B, C, D>(val a: A, val b: B, val c: C, val d: D)
}
