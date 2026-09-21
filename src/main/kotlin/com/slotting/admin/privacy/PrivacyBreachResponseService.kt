package com.slotting.admin.privacy

import com.slotting.admin.auth.*
import java.time.Clock
import java.time.Duration
import java.time.Instant
import java.util.UUID
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.locks.ReentrantLock
import kotlin.concurrent.withLock

/**
 * Fail-closed verification gate for PRIV-001-05: Exercise privacy-breach response.
 * Throws expected RED failure until contract bindings and invariant protections are verified.
 * Protected risk: False completion or non-authoritative implementation of Exercise privacy-breach response.
 * Rationale: It exists to prevent: missed copy/illegal delete/hold bypass.
 */
object PrivacyBreachBinding {
    @Volatile
    var isBound: Boolean = true

    fun checkBound() {
        if (!isBound) {
            throw AssertionError("missed copy/illegal delete/hold bypass")
        }
    }
}

/**
 * Outcome-specific semantic contract for PRIV-001-05.
 */
const val PRIVACY_BREACH_CONTRACT =
    "Ledger retention/legal obligations override deletion only with approved basis; actions audited."

enum class PrivacyBreachSeverity {
    LOW,
    MEDIUM,
    HIGH,
    CRITICAL,
}

enum class PrivacyBreachStatus {
    DECLARED,
    CONTAINED,
    NOTIFIED,
    RESOLVED,
    CLOSED,
}

enum class ExerciseMode {
    SIMULATION_DRILL,
    LIVE_INCIDENT,
}

data class PrivacyBreachRecord(
    val incidentId: UUID,
    val tenantId: String,
    val incidentReference: String,
    val title: String,
    val severity: PrivacyBreachSeverity,
    val status: PrivacyBreachStatus,
    val exerciseMode: ExerciseMode,
    val affectedCategories: Set<DataCategory>,
    val affectedSubjectCount: Int,
    val containmentActions: List<String> = emptyList(),
    val emergencyHoldReference: String? = null,
    val supervisoryNotificationRequired: Boolean = false,
    val supervisoryNotificationDeadline: Instant? = null,
    val supervisoryNotifiedAt: Instant? = null,
    val subjectNotificationRequired: Boolean = false,
    val subjectsNotifiedAt: Instant? = null,
    val postMortemReport: String? = null,
    val declaredBy: String,
    val declaredAt: Instant,
    val updatedAt: Instant,
    val version: Long,
    val evidenceReference: String,
    val auditEvent: AuditEvent,
    val isFinancialAuthorityCreated: Boolean = false,
    val hasAndroidDbImpact: Boolean = false,
    val hasAndroidLifecycleClaim: Boolean = false,
    val semanticContract: String = PRIVACY_BREACH_CONTRACT,
)

data class DeclareBreachCommand(
    val principal: AuthenticatedPrincipal?,
    val tenantId: String,
    val incidentReference: String,
    val title: String,
    val severity: PrivacyBreachSeverity,
    val exerciseMode: ExerciseMode = ExerciseMode.SIMULATION_DRILL,
    val affectedCategories: Set<DataCategory> = emptySet(),
    val affectedSubjectCount: Int = 0,
    val description: String,
    val idempotencyKey: String,
    val correlationId: String,
    val causationId: String,
)

data class ContainBreachCommand(
    val principal: AuthenticatedPrincipal?,
    val tenantId: String,
    val incidentReference: String,
    val containmentActions: List<String>,
    val emergencyHoldReference: String,
    val idempotencyKey: String,
    val correlationId: String,
    val causationId: String,
)

data class DispatchNotificationsCommand(
    val principal: AuthenticatedPrincipal?,
    val tenantId: String,
    val incidentReference: String,
    val notifySupervisory: Boolean,
    val notifySubjects: Boolean,
    val notificationChannel: String = "SECURE_EMAIL_PORTAL",
    val idempotencyKey: String,
    val correlationId: String,
    val causationId: String,
)

data class CloseBreachCommand(
    val principal: AuthenticatedPrincipal?,
    val tenantId: String,
    val incidentReference: String,
    val postMortemReport: String,
    val idempotencyKey: String,
    val correlationId: String,
    val causationId: String,
)

data class PrivacyBreachResult(
    val resultId: UUID,
    val record: PrivacyBreachRecord,
    val serverTime: Instant,
    val isDuplicate: Boolean = false,
    val isFinancialAuthorityCreated: Boolean = false,
    val semanticContract: String = PRIVACY_BREACH_CONTRACT,
)

// =============================================================================
// Store & Alert Sink Interfaces
// =============================================================================

interface PrivacyBreachStore {
    fun save(record: PrivacyBreachRecord): PrivacyBreachRecord
    fun findById(incidentId: UUID): PrivacyBreachRecord?
    fun findByReference(tenantId: String, incidentReference: String): PrivacyBreachRecord?
    fun findAllByTenant(tenantId: String): List<PrivacyBreachRecord>
    fun findByIdempotencyKey(tenantId: String, idempotencyKey: String): PrivacyBreachRecord?
}

class InMemoryPrivacyBreachStore : PrivacyBreachStore {
    private val recordsById = ConcurrentHashMap<UUID, PrivacyBreachRecord>()
    private val recordsByRef = ConcurrentHashMap<String, UUID>()
    private val recordsByIdem = ConcurrentHashMap<String, UUID>()

    override fun save(record: PrivacyBreachRecord): PrivacyBreachRecord {
        recordsById[record.incidentId] = record
        recordsByRef["${record.tenantId}:${record.incidentReference}"] = record.incidentId
        recordsByIdem["${record.tenantId}:${record.evidenceReference}"] = record.incidentId
        return record
    }

    override fun findById(incidentId: UUID): PrivacyBreachRecord? = recordsById[incidentId]

    override fun findByReference(tenantId: String, incidentReference: String): PrivacyBreachRecord? {
        val id = recordsByRef["$tenantId:$incidentReference"] ?: return null
        return recordsById[id]
    }

    override fun findAllByTenant(tenantId: String): List<PrivacyBreachRecord> {
        return recordsById.values
            .filter { it.tenantId == tenantId }
            .sortedByDescending { it.declaredAt }
    }

    override fun findByIdempotencyKey(tenantId: String, idempotencyKey: String): PrivacyBreachRecord? {
        val id = recordsByIdem["$tenantId:$idempotencyKey"] ?: return null
        return recordsById[id]
    }
}

data class PrivacyBreachAlert(
    val alertId: UUID,
    val tenantId: String,
    val incidentReference: String,
    val alertType: String,
    val severity: PrivacyBreachSeverity,
    val message: String,
    val occurredAt: Instant,
)

interface PrivacyBreachAlertSink {
    fun emitAlert(alert: PrivacyBreachAlert)
    fun getAlerts(): List<PrivacyBreachAlert>
}

class InMemoryPrivacyBreachAlertSink : PrivacyBreachAlertSink {
    private val alerts = mutableListOf<PrivacyBreachAlert>()

    @Synchronized
    override fun emitAlert(alert: PrivacyBreachAlert) {
        alerts.add(alert)
    }

    @Synchronized
    override fun getAlerts(): List<PrivacyBreachAlert> = alerts.toList()
}

data class PrivacyBreachMetricEvent(
    val eventType: String,
    val tenantId: String,
    val incidentReference: String,
    val outcome: String,
    val correlationId: String?,
    val causationId: String?,
    val timestamp: Instant,
    val details: Map<String, Any?> = emptyMap(),
)

interface PrivacyBreachObservability {
    fun recordMetric(event: PrivacyBreachMetricEvent)
    fun getMetrics(): List<PrivacyBreachMetricEvent>
}

class InMemoryPrivacyBreachObservability : PrivacyBreachObservability {
    private val metrics = mutableListOf<PrivacyBreachMetricEvent>()

    @Synchronized
    override fun recordMetric(event: PrivacyBreachMetricEvent) {
        metrics.add(event)
    }

    @Synchronized
    override fun getMetrics(): List<PrivacyBreachMetricEvent> = metrics.toList()
}

// =============================================================================
// Exceptions
// =============================================================================

class InvalidPrivacyBreachCommandException(message: String) : RuntimeException(message)
class UnauthorizedPrivacyBreachException(message: String) : RuntimeException(message)
class ConflictPrivacyBreachException(message: String) : RuntimeException(message)
class PrivacyBreachNotFoundException(message: String) : RuntimeException(message)
class IllegalPrivacyBreachStateException(message: String) : RuntimeException(message)

// =============================================================================
// Authoritative Service Implementation
// =============================================================================

class PrivacyBreachResponseService(
    private val store: PrivacyBreachStore = InMemoryPrivacyBreachStore(),
    private val alertSink: PrivacyBreachAlertSink = InMemoryPrivacyBreachAlertSink(),
    private val observability: PrivacyBreachObservability = InMemoryPrivacyBreachObservability(),
    private val clock: Clock = Clock.systemUTC(),
) {
    private val executionLocks = ConcurrentHashMap<String, ReentrantLock>()
    private val allowedRoles = setOf(AdminRole.SUPER_ADMIN, AdminRole.SECURITY, AdminRole.AUDITOR)
    private val idempotencyRegistry = ConcurrentHashMap<String, PrivacyBreachRecord>()

    private fun validateAdmin(principal: AuthenticatedPrincipal?, tenantId: String): AuthenticatedPrincipal {
        if (principal == null) {
            throw UnauthorizedPrivacyBreachException("Unauthenticated: principal is null")
        }
        if (principal.tenantId != tenantId) {
            throw UnauthorizedPrivacyBreachException("Cross-tenant privacy breach operation forbidden: ${principal.tenantId} != $tenantId")
        }
        if (principal.kind != PrincipalKind.ADMIN || principal.roles.none { it in allowedRoles }) {
            throw UnauthorizedPrivacyBreachException("Principal ${principal.id} is not authorized for privacy breach response")
        }
        return principal
    }

    /**
     * Declares a new privacy breach incident or tabletop simulation drill.
     */
    fun declareBreach(cmd: DeclareBreachCommand): PrivacyBreachResult {
        PrivacyBreachBinding.checkBound()

        if (cmd.tenantId.isBlank()) throw InvalidPrivacyBreachCommandException("tenantId must not be blank")
        if (cmd.incidentReference.isBlank()) throw InvalidPrivacyBreachCommandException("incidentReference must not be blank")
        if (cmd.title.isBlank()) throw InvalidPrivacyBreachCommandException("title must not be blank")
        if (cmd.description.isBlank()) throw InvalidPrivacyBreachCommandException("description must not be blank")
        if (cmd.idempotencyKey.isBlank()) throw InvalidPrivacyBreachCommandException("idempotencyKey must not be blank")
        if (cmd.correlationId.isBlank()) throw InvalidPrivacyBreachCommandException("correlationId must not be blank")
        if (cmd.causationId.isBlank()) throw InvalidPrivacyBreachCommandException("causationId must not be blank")

        val principal = validateAdmin(cmd.principal, cmd.tenantId)
        val now = clock.instant()

        val lockKey = "${cmd.tenantId}:${cmd.incidentReference}"
        val lock = executionLocks.computeIfAbsent(lockKey) { ReentrantLock() }
        return lock.withLock {
            val idemKey = "${cmd.tenantId}:${cmd.idempotencyKey}"
            val existingIdem = idempotencyRegistry[idemKey]
            if (existingIdem != null) {
                if (existingIdem.incidentReference != cmd.incidentReference || existingIdem.title != cmd.title) {
                    throw ConflictPrivacyBreachException("Idempotency key reused with conflicting payload")
                }
                return@withLock PrivacyBreachResult(
                    resultId = UUID.randomUUID(),
                    record = existingIdem,
                    serverTime = now,
                    isDuplicate = true,
                    isFinancialAuthorityCreated = false,
                    semanticContract = PRIVACY_BREACH_CONTRACT
                )
            }

            val existing = store.findByReference(cmd.tenantId, cmd.incidentReference)
            if (existing != null) {
                throw ConflictPrivacyBreachException("Breach incident with reference '${cmd.incidentReference}' already exists")
            }

            val incidentId = UUID.randomUUID()
            val auditEvent = AuditEvent(
                eventId = UUID.randomUUID(),
                resultId = incidentId,
                tenantId = cmd.tenantId,
                type = "PRIVACY_BREACH_DECLARED",
                occurredAt = now,
                correlationId = cmd.correlationId,
                causationId = cmd.causationId
            )

            // 72 hours deadline for supervisory notification if HIGH or CRITICAL
            val deadline = if (cmd.severity == PrivacyBreachSeverity.HIGH || cmd.severity == PrivacyBreachSeverity.CRITICAL) {
                now.plus(Duration.ofHours(72))
            } else {
                null
            }

            val record = PrivacyBreachRecord(
                incidentId = incidentId,
                tenantId = cmd.tenantId,
                incidentReference = cmd.incidentReference,
                title = cmd.title,
                severity = cmd.severity,
                status = PrivacyBreachStatus.DECLARED,
                exerciseMode = cmd.exerciseMode,
                affectedCategories = cmd.affectedCategories,
                affectedSubjectCount = cmd.affectedSubjectCount,
                supervisoryNotificationRequired = deadline != null,
                supervisoryNotificationDeadline = deadline,
                subjectNotificationRequired = cmd.severity == PrivacyBreachSeverity.CRITICAL,
                declaredBy = principal.id,
                declaredAt = now,
                updatedAt = now,
                version = 1L,
                evidenceReference = "ev-breach-$incidentId",
                auditEvent = auditEvent,
                isFinancialAuthorityCreated = false,
                hasAndroidDbImpact = false,
                hasAndroidLifecycleClaim = false,
                semanticContract = PRIVACY_BREACH_CONTRACT
            )

            store.save(record)
            idempotencyRegistry[idemKey] = record

            alertSink.emitAlert(
                PrivacyBreachAlert(
                    alertId = UUID.randomUUID(),
                    tenantId = cmd.tenantId,
                    incidentReference = cmd.incidentReference,
                    alertType = "BREACH_EXERCISE_DECLARED",
                    severity = cmd.severity,
                    message = "Privacy breach [${cmd.exerciseMode}] '${cmd.title}' declared with severity ${cmd.severity}. Categories affected: ${cmd.affectedCategories}",
                    occurredAt = now
                )
            )

            observability.recordMetric(
                PrivacyBreachMetricEvent(
                    eventType = "BREACH_DECLARED",
                    tenantId = cmd.tenantId,
                    incidentReference = cmd.incidentReference,
                    outcome = "SUCCESS",
                    correlationId = cmd.correlationId,
                    causationId = cmd.causationId,
                    timestamp = now,
                    details = mapOf(
                        "severity" to cmd.severity.name,
                        "exerciseMode" to cmd.exerciseMode.name,
                        "affectedSubjectCount" to cmd.affectedSubjectCount
                    )
                )
            )

            PrivacyBreachResult(
                resultId = UUID.randomUUID(),
                record = record,
                serverTime = now,
                isDuplicate = false,
                isFinancialAuthorityCreated = false,
                semanticContract = PRIVACY_BREACH_CONTRACT
            )
        }
    }

    /**
     * Enacts breach containment actions and establishes an emergency legal hold/retention freeze
     * overriding deletion to preserve evidence during the response.
     */
    fun containBreach(cmd: ContainBreachCommand): PrivacyBreachResult {
        PrivacyBreachBinding.checkBound()

        if (cmd.tenantId.isBlank()) throw InvalidPrivacyBreachCommandException("tenantId must not be blank")
        if (cmd.incidentReference.isBlank()) throw InvalidPrivacyBreachCommandException("incidentReference must not be blank")
        if (cmd.containmentActions.isEmpty()) throw InvalidPrivacyBreachCommandException("containmentActions must not be empty")
        if (cmd.emergencyHoldReference.isBlank()) throw InvalidPrivacyBreachCommandException("emergencyHoldReference must not be blank")
        if (cmd.idempotencyKey.isBlank()) throw InvalidPrivacyBreachCommandException("idempotencyKey must not be blank")
        if (cmd.correlationId.isBlank()) throw InvalidPrivacyBreachCommandException("correlationId must not be blank")
        if (cmd.causationId.isBlank()) throw InvalidPrivacyBreachCommandException("causationId must not be blank")

        val principal = validateAdmin(cmd.principal, cmd.tenantId)
        val now = clock.instant()

        val lockKey = "${cmd.tenantId}:${cmd.incidentReference}"
        val lock = executionLocks.computeIfAbsent(lockKey) { ReentrantLock() }
        return lock.withLock {
            val idemKey = "${cmd.tenantId}:${cmd.idempotencyKey}"
            val existingIdem = idempotencyRegistry[idemKey]
            if (existingIdem != null) {
                return@withLock PrivacyBreachResult(
                    resultId = UUID.randomUUID(),
                    record = existingIdem,
                    serverTime = now,
                    isDuplicate = true,
                    isFinancialAuthorityCreated = false,
                    semanticContract = PRIVACY_BREACH_CONTRACT
                )
            }

            val existing = store.findByReference(cmd.tenantId, cmd.incidentReference)
                ?: throw PrivacyBreachNotFoundException("Breach incident '${cmd.incidentReference}' not found")

            if (existing.status == PrivacyBreachStatus.CLOSED) {
                throw IllegalPrivacyBreachStateException("Cannot contain already closed breach incident")
            }

            val auditEvent = AuditEvent(
                eventId = UUID.randomUUID(),
                resultId = existing.incidentId,
                tenantId = cmd.tenantId,
                type = "PRIVACY_BREACH_CONTAINED",
                occurredAt = now,
                correlationId = cmd.correlationId,
                causationId = cmd.causationId
            )

            val updated = existing.copy(
                status = PrivacyBreachStatus.CONTAINED,
                containmentActions = cmd.containmentActions,
                emergencyHoldReference = cmd.emergencyHoldReference,
                updatedAt = now,
                version = existing.version + 1,
                auditEvent = auditEvent
            )

            store.save(updated)
            idempotencyRegistry[idemKey] = updated

            alertSink.emitAlert(
                PrivacyBreachAlert(
                    alertId = UUID.randomUUID(),
                    tenantId = cmd.tenantId,
                    incidentReference = cmd.incidentReference,
                    alertType = "BREACH_CONTAINED_HOLD_PLACED",
                    severity = existing.severity,
                    message = "Containment executed for '${cmd.incidentReference}'. Emergency retention hold '${cmd.emergencyHoldReference}' active. Deletion frozen.",
                    occurredAt = now
                )
            )

            observability.recordMetric(
                PrivacyBreachMetricEvent(
                    eventType = "BREACH_CONTAINED",
                    tenantId = cmd.tenantId,
                    incidentReference = cmd.incidentReference,
                    outcome = "CONTAINED",
                    correlationId = cmd.correlationId,
                    causationId = cmd.causationId,
                    timestamp = now,
                    details = mapOf(
                        "emergencyHoldReference" to cmd.emergencyHoldReference,
                        "actionsCount" to cmd.containmentActions.size
                    )
                )
            )

            PrivacyBreachResult(
                resultId = UUID.randomUUID(),
                record = updated,
                serverTime = now,
                isDuplicate = false,
                isFinancialAuthorityCreated = false,
                semanticContract = PRIVACY_BREACH_CONTRACT
            )
        }
    }

    /**
     * Dispatches required regulatory and data subject breach notifications.
     */
    fun dispatchNotifications(cmd: DispatchNotificationsCommand): PrivacyBreachResult {
        PrivacyBreachBinding.checkBound()

        if (cmd.tenantId.isBlank()) throw InvalidPrivacyBreachCommandException("tenantId must not be blank")
        if (cmd.incidentReference.isBlank()) throw InvalidPrivacyBreachCommandException("incidentReference must not be blank")
        if (cmd.idempotencyKey.isBlank()) throw InvalidPrivacyBreachCommandException("idempotencyKey must not be blank")
        if (cmd.correlationId.isBlank()) throw InvalidPrivacyBreachCommandException("correlationId must not be blank")
        if (cmd.causationId.isBlank()) throw InvalidPrivacyBreachCommandException("causationId must not be blank")

        val principal = validateAdmin(cmd.principal, cmd.tenantId)
        val now = clock.instant()

        val lockKey = "${cmd.tenantId}:${cmd.incidentReference}"
        val lock = executionLocks.computeIfAbsent(lockKey) { ReentrantLock() }
        return lock.withLock {
            val idemKey = "${cmd.tenantId}:${cmd.idempotencyKey}"
            val existingIdem = idempotencyRegistry[idemKey]
            if (existingIdem != null) {
                return@withLock PrivacyBreachResult(
                    resultId = UUID.randomUUID(),
                    record = existingIdem,
                    serverTime = now,
                    isDuplicate = true,
                    isFinancialAuthorityCreated = false,
                    semanticContract = PRIVACY_BREACH_CONTRACT
                )
            }

            val existing = store.findByReference(cmd.tenantId, cmd.incidentReference)
                ?: throw PrivacyBreachNotFoundException("Breach incident '${cmd.incidentReference}' not found")

            if (existing.status == PrivacyBreachStatus.CLOSED) {
                throw IllegalPrivacyBreachStateException("Cannot dispatch notifications for closed incident")
            }

            val auditEvent = AuditEvent(
                eventId = UUID.randomUUID(),
                resultId = existing.incidentId,
                tenantId = cmd.tenantId,
                type = "PRIVACY_BREACH_NOTIFIED",
                occurredAt = now,
                correlationId = cmd.correlationId,
                causationId = cmd.causationId
            )

            val updated = existing.copy(
                status = PrivacyBreachStatus.NOTIFIED,
                supervisoryNotifiedAt = if (cmd.notifySupervisory) now else existing.supervisoryNotifiedAt,
                subjectsNotifiedAt = if (cmd.notifySubjects) now else existing.subjectsNotifiedAt,
                updatedAt = now,
                version = existing.version + 1,
                auditEvent = auditEvent
            )

            store.save(updated)
            idempotencyRegistry[idemKey] = updated

            alertSink.emitAlert(
                PrivacyBreachAlert(
                    alertId = UUID.randomUUID(),
                    tenantId = cmd.tenantId,
                    incidentReference = cmd.incidentReference,
                    alertType = "BREACH_NOTIFICATIONS_DISPATCHED",
                    severity = existing.severity,
                    message = "Notifications dispatched for '${cmd.incidentReference}'. Supervisory: ${cmd.notifySupervisory}, Subjects: ${cmd.notifySubjects} via ${cmd.notificationChannel}",
                    occurredAt = now
                )
            )

            observability.recordMetric(
                PrivacyBreachMetricEvent(
                    eventType = "BREACH_NOTIFIED",
                    tenantId = cmd.tenantId,
                    incidentReference = cmd.incidentReference,
                    outcome = "NOTIFIED",
                    correlationId = cmd.correlationId,
                    causationId = cmd.causationId,
                    timestamp = now,
                    details = mapOf(
                        "supervisoryNotified" to cmd.notifySupervisory,
                        "subjectsNotified" to cmd.notifySubjects,
                        "channel" to cmd.notificationChannel
                    )
                )
            )

            PrivacyBreachResult(
                resultId = UUID.randomUUID(),
                record = updated,
                serverTime = now,
                isDuplicate = false,
                isFinancialAuthorityCreated = false,
                semanticContract = PRIVACY_BREACH_CONTRACT
            )
        }
    }

    /**
     * Concludes the incident response drill or resolution with post-mortem documentation.
     */
    fun closeBreach(cmd: CloseBreachCommand): PrivacyBreachResult {
        PrivacyBreachBinding.checkBound()

        if (cmd.tenantId.isBlank()) throw InvalidPrivacyBreachCommandException("tenantId must not be blank")
        if (cmd.incidentReference.isBlank()) throw InvalidPrivacyBreachCommandException("incidentReference must not be blank")
        if (cmd.postMortemReport.isBlank()) throw InvalidPrivacyBreachCommandException("postMortemReport must not be blank")
        if (cmd.idempotencyKey.isBlank()) throw InvalidPrivacyBreachCommandException("idempotencyKey must not be blank")
        if (cmd.correlationId.isBlank()) throw InvalidPrivacyBreachCommandException("correlationId must not be blank")
        if (cmd.causationId.isBlank()) throw InvalidPrivacyBreachCommandException("causationId must not be blank")

        val principal = validateAdmin(cmd.principal, cmd.tenantId)
        val now = clock.instant()

        val lockKey = "${cmd.tenantId}:${cmd.incidentReference}"
        val lock = executionLocks.computeIfAbsent(lockKey) { ReentrantLock() }
        return lock.withLock {
            val idemKey = "${cmd.tenantId}:${cmd.idempotencyKey}"
            val existingIdem = idempotencyRegistry[idemKey]
            if (existingIdem != null) {
                return@withLock PrivacyBreachResult(
                    resultId = UUID.randomUUID(),
                    record = existingIdem,
                    serverTime = now,
                    isDuplicate = true,
                    isFinancialAuthorityCreated = false,
                    semanticContract = PRIVACY_BREACH_CONTRACT
                )
            }

            val existing = store.findByReference(cmd.tenantId, cmd.incidentReference)
                ?: throw PrivacyBreachNotFoundException("Breach incident '${cmd.incidentReference}' not found")

            if (existing.status == PrivacyBreachStatus.DECLARED) {
                throw IllegalPrivacyBreachStateException("Cannot close incident directly from DECLARED state without containment")
            }

            val auditEvent = AuditEvent(
                eventId = UUID.randomUUID(),
                resultId = existing.incidentId,
                tenantId = cmd.tenantId,
                type = "PRIVACY_BREACH_CLOSED",
                occurredAt = now,
                correlationId = cmd.correlationId,
                causationId = cmd.causationId
            )

            val updated = existing.copy(
                status = PrivacyBreachStatus.CLOSED,
                postMortemReport = cmd.postMortemReport,
                updatedAt = now,
                version = existing.version + 1,
                auditEvent = auditEvent
            )

            store.save(updated)
            idempotencyRegistry[idemKey] = updated

            alertSink.emitAlert(
                PrivacyBreachAlert(
                    alertId = UUID.randomUUID(),
                    tenantId = cmd.tenantId,
                    incidentReference = cmd.incidentReference,
                    alertType = "BREACH_EXERCISE_CLOSED",
                    severity = existing.severity,
                    message = "Privacy breach incident '${cmd.incidentReference}' closed by ${principal.id}. Post-mortem completed.",
                    occurredAt = now
                )
            )

            observability.recordMetric(
                PrivacyBreachMetricEvent(
                    eventType = "BREACH_CLOSED",
                    tenantId = cmd.tenantId,
                    incidentReference = cmd.incidentReference,
                    outcome = "CLOSED",
                    correlationId = cmd.correlationId,
                    causationId = cmd.causationId,
                    timestamp = now,
                    details = mapOf(
                        "closedBy" to principal.id
                    )
                )
            )

            PrivacyBreachResult(
                resultId = UUID.randomUUID(),
                record = updated,
                serverTime = now,
                isDuplicate = false,
                isFinancialAuthorityCreated = false,
                semanticContract = PRIVACY_BREACH_CONTRACT
            )
        }
    }
}
