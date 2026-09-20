package com.slotting.admin.rg

import com.slotting.admin.auth.*
import java.nio.charset.StandardCharsets
import java.security.MessageDigest
import java.time.Clock
import java.time.Duration
import java.time.Instant
import java.time.ZoneId
import java.util.UUID
import java.util.concurrent.ConcurrentHashMap

/**
 * Fail-closed verification gate for RG-003-01: Delay responsible-gaming limit increases.
 * Throws expected RED failure until contract bindings and invariant protections are verified.
 * Protected risk: False completion or non-authoritative implementation of Delay responsible-gaming limit increases.
 * Rationale: It exists to prevent: increase immediate or clock manipulation.
 */
object DelayedLimitIncreaseBinding {
    @Volatile
    var isBound: Boolean = false

    fun checkBound() {
        if (!isBound) {
            throw AssertionError("increase immediate or clock manipulation")
        }
    }
}

/**
 * Outcome-specific semantic contract for RG-003-01.
 */
const val DELAYED_LIMIT_INCREASE_CONTRACT =
    "Legal values configured; decrease may be immediate; restart cannot skip reality check."

/**
 * Maximum legal limit value permitted in minor units (e.g. 100,000,000 = $1,000,000.00).
 */
const val MAX_LEGAL_LIMIT_MINOR_UNITS = 100_000_000L

/**
 * Standard cooling-off delay duration for limit increases (default 24 hours).
 */
val DEFAULT_COOLING_OFF_DURATION: Duration = Duration.ofHours(24)

/**
 * Lifecycle status of a responsible gaming limit with delayed increases.
 */
enum class DelayedLimitStatus {
    ACTIVE,
    PENDING_COOLING_OFF,
    PENDING_REALITY_CHECK,
    CANCELLED,
    SUPERSEDED,
}

/**
 * Authoritative persisted record for a responsible gaming limit.
 */
data class DelayedLimitRecord(
    val recordId: UUID,
    val tenantId: String,
    val playerId: String,
    val limitType: RgLimitType,
    val period: RgLimitPeriod,
    val currentLimitValueMinorUnits: Long,
    val pendingLimitValueMinorUnits: Long? = null,
    val status: DelayedLimitStatus,
    val coolingDelayStartsAt: Instant? = null,
    val coolingDelayExpiresAt: Instant? = null,
    val realityCheckRequired: Boolean = false,
    val realityCheckAcknowledgedAt: Instant? = null,
    val timezone: String,
    val version: Long,
    val evidenceReference: String,
    val createdAt: Instant,
    val updatedAt: Instant,
    val semanticContract: String = DELAYED_LIMIT_INCREASE_CONTRACT,
)

/**
 * Authoritative persisted session reality check tracking record.
 */
data class RealityCheckSessionRecord(
    val sessionId: UUID,
    val tenantId: String,
    val playerId: String,
    val intervalMinutes: Int,
    val sessionStartedAt: Instant,
    val lastPromptAt: Instant? = null,
    val lastAcknowledgedAt: Instant? = null,
    val acknowledgmentCount: Int = 0,
    val pendingAcknowledgment: Boolean = false,
    val version: Long,
    val evidenceReference: String,
    val createdAt: Instant,
    val updatedAt: Instant,
    val semanticContract: String = DELAYED_LIMIT_INCREASE_CONTRACT,
)

/**
 * Command to configure an initial limit or update an existing limit.
 * Decreases are applied immediately.
 * Increases enter a mandatory cooling-off delay.
 */
data class ConfigureOrUpdateLimitCommand(
    val tenantId: String,
    val playerId: String,
    val limitType: RgLimitType,
    val period: RgLimitPeriod,
    val limitValueMinorUnits: Long,
    val timezone: String,
    val coolingDelayDuration: Duration = DEFAULT_COOLING_OFF_DURATION,
    val idempotencyKey: String,
    val correlationId: String,
    val causationId: String,
    val expectedVersion: Long? = null,
    val principal: AuthenticatedPrincipal? = null,
    val clientReportedTimestamp: Instant? = null,
)

/**
 * Command to acknowledge reality check and promote a mature limit increase.
 */
data class AcknowledgeRealityCheckCommand(
    val tenantId: String,
    val playerId: String,
    val limitType: RgLimitType,
    val idempotencyKey: String,
    val correlationId: String,
    val causationId: String,
    val expectedVersion: Long,
    val principal: AuthenticatedPrincipal? = null,
    val clientReportedTimestamp: Instant? = null,
)

/**
 * Command to cancel a pending limit increase during cooling-off or reality check.
 */
data class CancelPendingIncreaseCommand(
    val tenantId: String,
    val playerId: String,
    val limitType: RgLimitType,
    val reason: String,
    val idempotencyKey: String,
    val correlationId: String,
    val causationId: String,
    val expectedVersion: Long,
    val principal: AuthenticatedPrincipal? = null,
)

/**
 * Command to record or update reality check session state.
 */
data class UpdateRealityCheckSessionCommand(
    val tenantId: String,
    val playerId: String,
    val intervalMinutes: Int = 60,
    val idempotencyKey: String,
    val correlationId: String,
    val causationId: String,
    val expectedVersion: Long? = null,
    val principal: AuthenticatedPrincipal? = null,
)

/**
 * Command to acknowledge periodic session reality check.
 */
data class AcknowledgeSessionRealityCheckCommand(
    val tenantId: String,
    val playerId: String,
    val idempotencyKey: String,
    val correlationId: String,
    val causationId: String,
    val expectedVersion: Long,
    val principal: AuthenticatedPrincipal? = null,
)

/**
 * Query for active effective limit.
 */
data class CheckEffectiveLimitQuery(
    val tenantId: String,
    val playerId: String,
    val limitType: RgLimitType,
    val principal: AuthenticatedPrincipal? = null,
)

/**
 * Query result for active effective limit.
 */
data class EffectiveLimitResult(
    val effectiveLimitValueMinorUnits: Long,
    val status: DelayedLimitStatus,
    val pendingLimitValueMinorUnits: Long?,
    val coolingDelayExpiresAt: Instant?,
    val realityCheckPending: Boolean,
    val evidenceReference: String,
    val serverTime: Instant,
    val semanticContract: String = DELAYED_LIMIT_INCREASE_CONTRACT,
)

/**
 * Result of configuring or updating a limit.
 */
data class DelayedLimitResult(
    val resultId: UUID,
    val record: DelayedLimitRecord,
    val serverTime: Instant,
    val isDuplicate: Boolean,
    val isImmediate: Boolean,
    val isFinancialAuthorityCreated: Boolean = false,
    val semanticContract: String = DELAYED_LIMIT_INCREASE_CONTRACT,
)

/**
 * Result of reality check session operations.
 */
data class RealityCheckSessionResult(
    val resultId: UUID,
    val record: RealityCheckSessionRecord,
    val serverTime: Instant,
    val isDuplicate: Boolean,
    val isFinancialAuthorityCreated: Boolean = false,
    val semanticContract: String = DELAYED_LIMIT_INCREASE_CONTRACT,
)

/**
 * Snapshot for state recovery and migration across server restarts.
 */
data class DelayedLimitIncreaseSnapshot(
    val records: Map<String, DelayedLimitRecord>,
    val sessions: Map<String, RealityCheckSessionRecord>,
    val idempotencyMap: Map<String, Pair<String, Any>>,
    val auditEvents: List<AuditEvent>,
    val outboxEvents: List<OutboxEvent>,
)

/**
 * Sink for structured alerts and observability.
 */
interface DelayedLimitIncreaseAlertSink {
    fun sendAlert(tenantId: String, reference: String, alertType: String, reason: String, detail: String)
}

class InMemoryDelayedLimitIncreaseAlertSink : DelayedLimitIncreaseAlertSink {
    val alerts = mutableListOf<Map<String, String>>()

    @Synchronized
    override fun sendAlert(tenantId: String, reference: String, alertType: String, reason: String, detail: String) {
        alerts.add(
            mapOf(
                "tenantId" to tenantId,
                "reference" to reference,
                "alertType" to alertType,
                "reason" to reason,
                "detail" to detail,
            )
        )
    }
}

/**
 * Persistence store interface for delayed limit increases and reality checks.
 */
interface DelayedLimitIncreaseStore {
    fun findRecord(tenantId: String, playerId: String, limitType: RgLimitType): DelayedLimitRecord?
    fun saveRecord(
        record: DelayedLimitRecord,
        result: DelayedLimitResult,
        idempotencyKey: String,
        fingerprint: String,
        audit: AuditEvent,
        outbox: OutboxEvent,
    )
    fun updateRecord(
        record: DelayedLimitRecord,
        result: DelayedLimitResult,
        idempotencyKey: String,
        fingerprint: String,
        audit: AuditEvent,
        outbox: OutboxEvent,
    )
    fun findSession(tenantId: String, playerId: String): RealityCheckSessionRecord?
    fun saveSession(
        session: RealityCheckSessionRecord,
        result: RealityCheckSessionResult,
        idempotencyKey: String,
        fingerprint: String,
        audit: AuditEvent,
        outbox: OutboxEvent,
    )
    fun updateSession(
        session: RealityCheckSessionRecord,
        result: RealityCheckSessionResult,
        idempotencyKey: String,
        fingerprint: String,
        audit: AuditEvent,
        outbox: OutboxEvent,
    )
    fun findByIdempotency(tenantId: String, idempotencyKey: String): Pair<String, Any>?
    fun exportSnapshot(): DelayedLimitIncreaseSnapshot
    fun importSnapshot(snapshot: DelayedLimitIncreaseSnapshot)
}

/**
 * In-memory thread-safe implementation of DelayedLimitIncreaseStore.
 */
class InMemoryDelayedLimitIncreaseStore : DelayedLimitIncreaseStore {
    private val records = ConcurrentHashMap<String, DelayedLimitRecord>()
    private val sessions = ConcurrentHashMap<String, RealityCheckSessionRecord>()
    private val idempotencyResults = ConcurrentHashMap<String, Pair<String, Any>>()
    val auditEvents = mutableListOf<AuditEvent>()
    val outboxEvents = mutableListOf<OutboxEvent>()

    private fun recordKey(tenantId: String, playerId: String, limitType: RgLimitType) =
        "$tenantId:$playerId:${limitType.name}"

    private fun sessionKey(tenantId: String, playerId: String) =
        "$tenantId:$playerId"

    private fun idempKey(tenantId: String, idempotencyKey: String) =
        "$tenantId:$idempotencyKey"

    @Synchronized
    override fun findRecord(tenantId: String, playerId: String, limitType: RgLimitType): DelayedLimitRecord? =
        records[recordKey(tenantId, playerId, limitType)]

    @Synchronized
    override fun saveRecord(
        record: DelayedLimitRecord,
        result: DelayedLimitResult,
        idempotencyKey: String,
        fingerprint: String,
        audit: AuditEvent,
        outbox: OutboxEvent,
    ) {
        records[recordKey(record.tenantId, record.playerId, record.limitType)] = record
        idempotencyResults[idempKey(record.tenantId, idempotencyKey)] = fingerprint to result
        auditEvents.add(audit)
        outboxEvents.add(outbox)
    }

    @Synchronized
    override fun updateRecord(
        record: DelayedLimitRecord,
        result: DelayedLimitResult,
        idempotencyKey: String,
        fingerprint: String,
        audit: AuditEvent,
        outbox: OutboxEvent,
    ) {
        records[recordKey(record.tenantId, record.playerId, record.limitType)] = record
        idempotencyResults[idempKey(record.tenantId, idempotencyKey)] = fingerprint to result
        auditEvents.add(audit)
        outboxEvents.add(outbox)
    }

    @Synchronized
    override fun findSession(tenantId: String, playerId: String): RealityCheckSessionRecord? =
        sessions[sessionKey(tenantId, playerId)]

    @Synchronized
    override fun saveSession(
        session: RealityCheckSessionRecord,
        result: RealityCheckSessionResult,
        idempotencyKey: String,
        fingerprint: String,
        audit: AuditEvent,
        outbox: OutboxEvent,
    ) {
        sessions[sessionKey(session.tenantId, session.playerId)] = session
        idempotencyResults[idempKey(session.tenantId, idempotencyKey)] = fingerprint to result
        auditEvents.add(audit)
        outboxEvents.add(outbox)
    }

    @Synchronized
    override fun updateSession(
        session: RealityCheckSessionRecord,
        result: RealityCheckSessionResult,
        idempotencyKey: String,
        fingerprint: String,
        audit: AuditEvent,
        outbox: OutboxEvent,
    ) {
        sessions[sessionKey(session.tenantId, session.playerId)] = session
        idempotencyResults[idempKey(session.tenantId, idempotencyKey)] = fingerprint to result
        auditEvents.add(audit)
        outboxEvents.add(outbox)
    }

    @Synchronized
    override fun findByIdempotency(tenantId: String, idempotencyKey: String): Pair<String, Any>? =
        idempotencyResults[idempKey(tenantId, idempotencyKey)]

    @Synchronized
    override fun exportSnapshot(): DelayedLimitIncreaseSnapshot = DelayedLimitIncreaseSnapshot(
        records = HashMap(records),
        sessions = HashMap(sessions),
        idempotencyMap = HashMap(idempotencyResults),
        auditEvents = ArrayList(auditEvents),
        outboxEvents = ArrayList(outboxEvents),
    )

    @Synchronized
    override fun importSnapshot(snapshot: DelayedLimitIncreaseSnapshot) {
        records.clear()
        records.putAll(snapshot.records)
        sessions.clear()
        sessions.putAll(snapshot.sessions)
        idempotencyResults.clear()
        idempotencyResults.putAll(snapshot.idempotencyMap)
        auditEvents.clear()
        auditEvents.addAll(snapshot.auditEvents)
        outboxEvents.clear()
        outboxEvents.addAll(snapshot.outboxEvents)
    }
}

/**
 * Authoritative backend service implementing RG-003-01: Delay responsible-gaming limit increases.
 */
class DelayedLimitIncreaseService(
    private val store: DelayedLimitIncreaseStore,
    private val alertSink: DelayedLimitIncreaseAlertSink = InMemoryDelayedLimitIncreaseAlertSink(),
    private val clock: Clock = Clock.systemUTC(),
) {
    private fun sha256(input: String): String {
        val digest = MessageDigest.getInstance("SHA-256")
        val hash = digest.digest(input.toByteArray(StandardCharsets.UTF_8))
        return hash.joinToString("") { "%02x".format(it) }
    }

    private fun validatePrincipal(principal: AuthenticatedPrincipal?, tenantId: String, playerId: String) {
        principal?.let {
            if (it.tenantId != tenantId) {
                throw AuthenticationFailure.Rejected(AuthErrorCode.FORBIDDEN)
            }
            if (it.kind == PrincipalKind.PLAYER) {
                if (it.id != playerId) {
                    throw AuthenticationFailure.Rejected(AuthErrorCode.FORBIDDEN)
                }
            } else if (it.kind == PrincipalKind.ADMIN) {
                if (it.roles.none { role -> role in setOf(AdminRole.SUPER_ADMIN, AdminRole.SECURITY, AdminRole.AUDITOR) }) {
                    throw AuthenticationFailure.Rejected(AuthErrorCode.FORBIDDEN)
                }
            } else {
                throw AuthenticationFailure.Rejected(AuthErrorCode.FORBIDDEN)
            }
        }
    }

    @Synchronized
    fun configureOrUpdateLimit(command: ConfigureOrUpdateLimitCommand): DelayedLimitResult {
        // Protected risk assertion: increase immediate or clock manipulation
        DelayedLimitIncreaseBinding.checkBound()

        // 1. Mandatory Input Validation
        if (command.tenantId.isBlank() ||
            command.playerId.isBlank() ||
            command.timezone.isBlank() ||
            command.idempotencyKey.isBlank() ||
            command.correlationId.isBlank() ||
            command.causationId.isBlank()
        ) {
            alertSink.sendAlert(
                tenantId = command.tenantId.ifBlank { "UNKNOWN" },
                reference = command.playerId.ifBlank { "UNKNOWN" },
                alertType = "DELAYED_LIMIT_INVALID_INPUT",
                reason = "BLANK_MANDATORY_FIELDS",
                detail = "Rejected due to blank mandatory fields",
            )
            throw AuthenticationFailure.Rejected(AuthErrorCode.INVALID)
        }

        // Legal values configured: limitValueMinorUnits must be strictly > 0 and <= MAX_LEGAL_LIMIT_MINOR_UNITS
        if (command.limitValueMinorUnits <= 0L || command.limitValueMinorUnits > MAX_LEGAL_LIMIT_MINOR_UNITS) {
            alertSink.sendAlert(
                tenantId = command.tenantId,
                reference = command.playerId,
                alertType = "DELAYED_LIMIT_ILLEGAL_VALUE",
                reason = "ILLEGAL_LIMIT_VALUE",
                detail = "Limit value ${command.limitValueMinorUnits} is outside legal bounds (0, $MAX_LEGAL_LIMIT_MINOR_UNITS]",
            )
            throw AuthenticationFailure.Rejected(AuthErrorCode.INVALID)
        }

        // Validate timezone
        try {
            ZoneId.of(command.timezone)
        } catch (e: Exception) {
            throw AuthenticationFailure.Rejected(AuthErrorCode.INVALID)
        }

        validatePrincipal(command.principal, command.tenantId, command.playerId)

        val now = clock.instant()

        // Clock manipulation prevention: reject client-reported timestamps that deviate from authoritative server time
        command.clientReportedTimestamp?.let { clientTime ->
            val diff = Duration.between(now, clientTime).abs()
            if (diff > Duration.ofSeconds(60)) {
                alertSink.sendAlert(
                    tenantId = command.tenantId,
                    reference = command.playerId,
                    alertType = "CLOCK_MANIPULATION_DETECTED",
                    reason = "CLIENT_TIMESTAMP_SKEW",
                    detail = "Client reported timestamp deviates by ${diff.toMillis()}ms from server time",
                )
                throw AuthenticationFailure.Rejected(AuthErrorCode.INVALID)
            }
        }

        val fp = sha256("${command.tenantId}:${command.playerId}:${command.limitType}:${command.period}:${command.limitValueMinorUnits}:${command.timezone}:${command.expectedVersion}")

        // 2. Idempotency Check
        val existingIdemp = store.findByIdempotency(command.tenantId, command.idempotencyKey)
        if (existingIdemp != null) {
            val (cachedFp, cachedResult) = existingIdemp
            if (cachedFp != fp) {
                alertSink.sendAlert(
                    tenantId = command.tenantId,
                    reference = command.playerId,
                    alertType = "DELAYED_LIMIT_IDEMPOTENCY_CONFLICT",
                    reason = "PAYLOAD_MISMATCH",
                    detail = "Payload mismatch detected for idempotency key ${command.idempotencyKey}",
                )
                throw AuthenticationFailure.Rejected(AuthErrorCode.CONFLICT)
            }
            val res = cachedResult as DelayedLimitResult
            return res.copy(isDuplicate = true)
        }

        val existingRecord = store.findRecord(command.tenantId, command.playerId, command.limitType)

        // Versioning check
        if (existingRecord != null) {
            if (command.expectedVersion != null && existingRecord.version != command.expectedVersion) {
                throw AuthenticationFailure.Rejected(AuthErrorCode.STALE)
            }
        } else {
            if (command.expectedVersion != null && command.expectedVersion != 1L) {
                throw AuthenticationFailure.Rejected(AuthErrorCode.STALE)
            }
        }

        val recordId = existingRecord?.recordId ?: UUID.randomUUID()
        val newVersion = (existingRecord?.version ?: 0L) + 1L
        val evidenceRef = "EVID-DELAYED-LIMIT-$recordId-v$newVersion"

        val (updatedRecord, isImmediate) = if (existingRecord == null) {
            // Initial configuration of legal values: applies immediately
            DelayedLimitRecord(
                recordId = recordId,
                tenantId = command.tenantId,
                playerId = command.playerId,
                limitType = command.limitType,
                period = command.period,
                currentLimitValueMinorUnits = command.limitValueMinorUnits,
                pendingLimitValueMinorUnits = null,
                status = DelayedLimitStatus.ACTIVE,
                coolingDelayStartsAt = null,
                coolingDelayExpiresAt = null,
                realityCheckRequired = false,
                realityCheckAcknowledgedAt = null,
                timezone = command.timezone,
                version = newVersion,
                evidenceReference = evidenceRef,
                createdAt = now,
                updatedAt = now,
                semanticContract = DELAYED_LIMIT_INCREASE_CONTRACT,
            ) to true
        } else if (command.limitValueMinorUnits < existingRecord.currentLimitValueMinorUnits) {
            // Decrease may be immediate: immediately update active limit, cancel/supersede any pending increase
            existingRecord.copy(
                currentLimitValueMinorUnits = command.limitValueMinorUnits,
                pendingLimitValueMinorUnits = null,
                status = DelayedLimitStatus.ACTIVE,
                coolingDelayStartsAt = null,
                coolingDelayExpiresAt = null,
                realityCheckRequired = false,
                realityCheckAcknowledgedAt = null,
                timezone = command.timezone,
                version = newVersion,
                evidenceReference = evidenceRef,
                updatedAt = now,
            ) to true
        } else if (command.limitValueMinorUnits > existingRecord.currentLimitValueMinorUnits) {
            // Increase MUST be delayed by mandatory cooling-off period
            val coolingDelay = if (command.coolingDelayDuration < Duration.ofHours(24)) {
                // Cannot bypass legal cooling-off delay
                DEFAULT_COOLING_OFF_DURATION
            } else {
                command.coolingDelayDuration
            }
            val expiresAt = now.plus(coolingDelay)

            existingRecord.copy(
                pendingLimitValueMinorUnits = command.limitValueMinorUnits,
                status = DelayedLimitStatus.PENDING_COOLING_OFF,
                coolingDelayStartsAt = now,
                coolingDelayExpiresAt = expiresAt,
                realityCheckRequired = true,
                realityCheckAcknowledgedAt = null,
                timezone = command.timezone,
                version = newVersion,
                evidenceReference = evidenceRef,
                updatedAt = now,
            ) to false
        } else {
            // Unchanged limit value
            existingRecord.copy(
                version = newVersion,
                evidenceReference = evidenceRef,
                updatedAt = now,
            ) to true
        }

        val resultId = UUID.randomUUID()
        val result = DelayedLimitResult(
            resultId = resultId,
            record = updatedRecord,
            serverTime = now,
            isDuplicate = false,
            isImmediate = isImmediate,
            isFinancialAuthorityCreated = false,
            semanticContract = DELAYED_LIMIT_INCREASE_CONTRACT,
        )

        val eventType = if (isImmediate) "RG_LIMIT_UPDATED_IMMEDIATE" else "RG_LIMIT_INCREASE_DELAYED"
        val audit = AuditEvent(UUID.randomUUID(), recordId, command.tenantId, eventType, now, command.correlationId, command.causationId)
        val outbox = OutboxEvent(UUID.randomUUID(), recordId, command.tenantId, eventType, now)

        try {
            if (existingRecord == null) {
                store.saveRecord(updatedRecord, result, command.idempotencyKey, fp, audit, outbox)
            } else {
                store.updateRecord(updatedRecord, result, command.idempotencyKey, fp, audit, outbox)
            }
        } catch (e: Exception) {
            alertSink.sendAlert(
                tenantId = command.tenantId,
                reference = command.playerId,
                alertType = "DELAYED_LIMIT_STORE_FAILED",
                reason = "STORAGE_FAILURE",
                detail = "Store failed: ${e.message}",
            )
            throw AuthenticationFailure.Rejected(AuthErrorCode.DEPENDENCY_UNAVAILABLE)
        }

        return result
    }

    @Synchronized
    fun acknowledgeRealityCheck(command: AcknowledgeRealityCheckCommand): DelayedLimitResult {
        // Protected risk assertion: increase immediate or clock manipulation
        DelayedLimitIncreaseBinding.checkBound()

        if (command.tenantId.isBlank() || command.playerId.isBlank() || command.idempotencyKey.isBlank()) {
            throw AuthenticationFailure.Rejected(AuthErrorCode.INVALID)
        }

        validatePrincipal(command.principal, command.tenantId, command.playerId)

        val now = clock.instant()

        // Clock manipulation prevention
        command.clientReportedTimestamp?.let { clientTime ->
            val diff = Duration.between(now, clientTime).abs()
            if (diff > Duration.ofSeconds(60)) {
                alertSink.sendAlert(
                    tenantId = command.tenantId,
                    reference = command.playerId,
                    alertType = "CLOCK_MANIPULATION_DETECTED",
                    reason = "CLIENT_TIMESTAMP_SKEW",
                    detail = "Client reported timestamp skew on reality check confirmation",
                )
                throw AuthenticationFailure.Rejected(AuthErrorCode.INVALID)
            }
        }

        val fp = sha256("${command.tenantId}:${command.playerId}:${command.limitType}:${command.expectedVersion}")

        val existingIdemp = store.findByIdempotency(command.tenantId, command.idempotencyKey)
        if (existingIdemp != null) {
            val (cachedFp, cachedResult) = existingIdemp
            if (cachedFp != fp) {
                throw AuthenticationFailure.Rejected(AuthErrorCode.CONFLICT)
            }
            val res = cachedResult as DelayedLimitResult
            return res.copy(isDuplicate = true)
        }

        val existingRecord = store.findRecord(command.tenantId, command.playerId, command.limitType)
            ?: throw AuthenticationFailure.Rejected(AuthErrorCode.INVALID)

        if (existingRecord.version != command.expectedVersion) {
            throw AuthenticationFailure.Rejected(AuthErrorCode.STALE)
        }

        if (existingRecord.pendingLimitValueMinorUnits == null) {
            throw AuthenticationFailure.Rejected(AuthErrorCode.INVALID)
        }

        val expiresAt = existingRecord.coolingDelayExpiresAt
            ?: throw AuthenticationFailure.Rejected(AuthErrorCode.INVALID)

        // Monotonic server clock check: cooling delay must be fully elapsed
        if (now.isBefore(expiresAt)) {
            alertSink.sendAlert(
                tenantId = command.tenantId,
                reference = command.playerId,
                alertType = "PREMATURE_INCREASE_ATTEMPT",
                reason = "COOLING_DELAY_ACTIVE",
                detail = "Attempt to confirm limit increase before cooling delay expiry at $expiresAt (server time $now)",
            )
            throw AuthenticationFailure.Rejected(AuthErrorCode.FORBIDDEN)
        }

        // Clock manipulation / anomaly check: server clock cannot be before start time
        existingRecord.coolingDelayStartsAt?.let { startsAt ->
            if (now.isBefore(startsAt)) {
                alertSink.sendAlert(
                    tenantId = command.tenantId,
                    reference = command.playerId,
                    alertType = "CLOCK_MANIPULATION_DETECTED",
                    reason = "MONOTONIC_CLOCK_VIOLATION",
                    detail = "Server time $now is before cooling delay start time $startsAt",
                )
                throw AuthenticationFailure.Rejected(AuthErrorCode.INVALID)
            }
        }

        // Reality check acknowledged: promote pending increase to active limit
        val newVersion = existingRecord.version + 1L
        val evidenceRef = "EVID-DELAYED-LIMIT-${existingRecord.recordId}-v$newVersion"

        val updatedRecord = existingRecord.copy(
            currentLimitValueMinorUnits = existingRecord.pendingLimitValueMinorUnits,
            pendingLimitValueMinorUnits = null,
            status = DelayedLimitStatus.ACTIVE,
            coolingDelayStartsAt = null,
            coolingDelayExpiresAt = null,
            realityCheckRequired = false,
            realityCheckAcknowledgedAt = now,
            version = newVersion,
            evidenceReference = evidenceRef,
            updatedAt = now,
        )

        val resultId = UUID.randomUUID()
        val result = DelayedLimitResult(
            resultId = resultId,
            record = updatedRecord,
            serverTime = now,
            isDuplicate = false,
            isImmediate = false,
            isFinancialAuthorityCreated = false,
            semanticContract = DELAYED_LIMIT_INCREASE_CONTRACT,
        )

        val audit = AuditEvent(UUID.randomUUID(), existingRecord.recordId, command.tenantId, "RG_LIMIT_INCREASE_CONFIRMED", now, command.correlationId, command.causationId)
        val outbox = OutboxEvent(UUID.randomUUID(), existingRecord.recordId, command.tenantId, "RG_LIMIT_INCREASE_CONFIRMED", now)

        try {
            store.updateRecord(updatedRecord, result, command.idempotencyKey, fp, audit, outbox)
        } catch (e: Exception) {
            throw AuthenticationFailure.Rejected(AuthErrorCode.DEPENDENCY_UNAVAILABLE)
        }

        return result
    }

    @Synchronized
    fun cancelPendingIncrease(command: CancelPendingIncreaseCommand): DelayedLimitResult {
        DelayedLimitIncreaseBinding.checkBound()

        if (command.tenantId.isBlank() || command.playerId.isBlank() || command.idempotencyKey.isBlank()) {
            throw AuthenticationFailure.Rejected(AuthErrorCode.INVALID)
        }

        validatePrincipal(command.principal, command.tenantId, command.playerId)

        val now = clock.instant()
        val fp = sha256("${command.tenantId}:${command.playerId}:${command.limitType}:${command.reason}:${command.expectedVersion}")

        val existingIdemp = store.findByIdempotency(command.tenantId, command.idempotencyKey)
        if (existingIdemp != null) {
            val (cachedFp, cachedResult) = existingIdemp
            if (cachedFp != fp) {
                throw AuthenticationFailure.Rejected(AuthErrorCode.CONFLICT)
            }
            val res = cachedResult as DelayedLimitResult
            return res.copy(isDuplicate = true)
        }

        val existingRecord = store.findRecord(command.tenantId, command.playerId, command.limitType)
            ?: throw AuthenticationFailure.Rejected(AuthErrorCode.INVALID)

        if (existingRecord.version != command.expectedVersion) {
            throw AuthenticationFailure.Rejected(AuthErrorCode.STALE)
        }

        if (existingRecord.status !in setOf(DelayedLimitStatus.PENDING_COOLING_OFF, DelayedLimitStatus.PENDING_REALITY_CHECK)) {
            throw AuthenticationFailure.Rejected(AuthErrorCode.INVALID)
        }

        val newVersion = existingRecord.version + 1L
        val evidenceRef = "EVID-DELAYED-LIMIT-${existingRecord.recordId}-v$newVersion"

        val updatedRecord = existingRecord.copy(
            pendingLimitValueMinorUnits = null,
            status = DelayedLimitStatus.CANCELLED,
            coolingDelayStartsAt = null,
            coolingDelayExpiresAt = null,
            realityCheckRequired = false,
            version = newVersion,
            evidenceReference = evidenceRef,
            updatedAt = now,
        )

        val resultId = UUID.randomUUID()
        val result = DelayedLimitResult(
            resultId = resultId,
            record = updatedRecord,
            serverTime = now,
            isDuplicate = false,
            isImmediate = false,
            isFinancialAuthorityCreated = false,
            semanticContract = DELAYED_LIMIT_INCREASE_CONTRACT,
        )

        val audit = AuditEvent(UUID.randomUUID(), existingRecord.recordId, command.tenantId, "RG_LIMIT_INCREASE_CANCELLED", now, command.correlationId, command.causationId)
        val outbox = OutboxEvent(UUID.randomUUID(), existingRecord.recordId, command.tenantId, "RG_LIMIT_INCREASE_CANCELLED", now)

        try {
            store.updateRecord(updatedRecord, result, command.idempotencyKey, fp, audit, outbox)
        } catch (e: Exception) {
            throw AuthenticationFailure.Rejected(AuthErrorCode.DEPENDENCY_UNAVAILABLE)
        }

        return result
    }

    @Synchronized
    fun checkEffectiveLimit(query: CheckEffectiveLimitQuery): EffectiveLimitResult {
        DelayedLimitIncreaseBinding.checkBound()

        if (query.tenantId.isBlank() || query.playerId.isBlank()) {
            throw AuthenticationFailure.Rejected(AuthErrorCode.INVALID)
        }

        validatePrincipal(query.principal, query.tenantId, query.playerId)

        val record = store.findRecord(query.tenantId, query.playerId, query.limitType)
            ?: throw AuthenticationFailure.Rejected(AuthErrorCode.INVALID)

        val now = clock.instant()

        val isRealityCheckPending = if (record.pendingLimitValueMinorUnits != null && record.coolingDelayExpiresAt != null) {
            now >= record.coolingDelayExpiresAt
        } else {
            false
        }

        val status = if (record.pendingLimitValueMinorUnits != null && record.coolingDelayExpiresAt != null) {
            if (now >= record.coolingDelayExpiresAt) {
                DelayedLimitStatus.PENDING_REALITY_CHECK
            } else {
                DelayedLimitStatus.PENDING_COOLING_OFF
            }
        } else {
            record.status
        }

        return EffectiveLimitResult(
            effectiveLimitValueMinorUnits = record.currentLimitValueMinorUnits,
            status = status,
            pendingLimitValueMinorUnits = record.pendingLimitValueMinorUnits,
            coolingDelayExpiresAt = record.coolingDelayExpiresAt,
            realityCheckPending = isRealityCheckPending,
            evidenceReference = record.evidenceReference,
            serverTime = now,
            semanticContract = DELAYED_LIMIT_INCREASE_CONTRACT,
        )
    }

    @Synchronized
    fun updateRealityCheckSession(command: UpdateRealityCheckSessionCommand): RealityCheckSessionResult {
        DelayedLimitIncreaseBinding.checkBound()

        if (command.tenantId.isBlank() || command.playerId.isBlank() || command.idempotencyKey.isBlank()) {
            throw AuthenticationFailure.Rejected(AuthErrorCode.INVALID)
        }

        if (command.intervalMinutes <= 0 || command.intervalMinutes > 1440) {
            throw AuthenticationFailure.Rejected(AuthErrorCode.INVALID)
        }

        validatePrincipal(command.principal, command.tenantId, command.playerId)

        val now = clock.instant()
        val fp = sha256("${command.tenantId}:${command.playerId}:${command.intervalMinutes}:${command.expectedVersion}")

        val existingIdemp = store.findByIdempotency(command.tenantId, command.idempotencyKey)
        if (existingIdemp != null) {
            val (cachedFp, cachedResult) = existingIdemp
            if (cachedFp != fp) {
                throw AuthenticationFailure.Rejected(AuthErrorCode.CONFLICT)
            }
            val res = cachedResult as RealityCheckSessionResult
            return res.copy(isDuplicate = true)
        }

        val existingSession = store.findSession(command.tenantId, command.playerId)

        if (existingSession != null) {
            if (command.expectedVersion != null && existingSession.version != command.expectedVersion) {
                throw AuthenticationFailure.Rejected(AuthErrorCode.STALE)
            }
        }

        val sessionId = existingSession?.sessionId ?: UUID.randomUUID()
        val newVersion = (existingSession?.version ?: 0L) + 1L
        val evidenceRef = "EVID-REALITY-SESSION-$sessionId-v$newVersion"

        val updatedSession = existingSession?.copy(
            intervalMinutes = command.intervalMinutes,
            version = newVersion,
            evidenceReference = evidenceRef,
            updatedAt = now,
        ) ?: RealityCheckSessionRecord(
            sessionId = sessionId,
            tenantId = command.tenantId,
            playerId = command.playerId,
            intervalMinutes = command.intervalMinutes,
            sessionStartedAt = now,
            lastPromptAt = null,
            lastAcknowledgedAt = null,
            acknowledgmentCount = 0,
            pendingAcknowledgment = false,
            version = newVersion,
            evidenceReference = evidenceRef,
            createdAt = now,
            updatedAt = now,
            semanticContract = DELAYED_LIMIT_INCREASE_CONTRACT,
        )

        val resultId = UUID.randomUUID()
        val result = RealityCheckSessionResult(
            resultId = resultId,
            record = updatedSession,
            serverTime = now,
            isDuplicate = false,
            isFinancialAuthorityCreated = false,
            semanticContract = DELAYED_LIMIT_INCREASE_CONTRACT,
        )

        val audit = AuditEvent(UUID.randomUUID(), sessionId, command.tenantId, "REALITY_CHECK_SESSION_CONFIGURED", now, command.correlationId, command.causationId)
        val outbox = OutboxEvent(UUID.randomUUID(), sessionId, command.tenantId, "REALITY_CHECK_SESSION_CONFIGURED", now)

        try {
            if (existingSession == null) {
                store.saveSession(updatedSession, result, command.idempotencyKey, fp, audit, outbox)
            } else {
                store.updateSession(updatedSession, result, command.idempotencyKey, fp, audit, outbox)
            }
        } catch (e: Exception) {
            throw AuthenticationFailure.Rejected(AuthErrorCode.DEPENDENCY_UNAVAILABLE)
        }

        return result
    }

    @Synchronized
    fun acknowledgeSessionRealityCheck(command: AcknowledgeSessionRealityCheckCommand): RealityCheckSessionResult {
        DelayedLimitIncreaseBinding.checkBound()

        if (command.tenantId.isBlank() || command.playerId.isBlank() || command.idempotencyKey.isBlank()) {
            throw AuthenticationFailure.Rejected(AuthErrorCode.INVALID)
        }

        validatePrincipal(command.principal, command.tenantId, command.playerId)

        val now = clock.instant()
        val fp = sha256("${command.tenantId}:${command.playerId}:${command.expectedVersion}")

        val existingIdemp = store.findByIdempotency(command.tenantId, command.idempotencyKey)
        if (existingIdemp != null) {
            val (cachedFp, cachedResult) = existingIdemp
            if (cachedFp != fp) {
                throw AuthenticationFailure.Rejected(AuthErrorCode.CONFLICT)
            }
            val res = cachedResult as RealityCheckSessionResult
            return res.copy(isDuplicate = true)
        }

        val existingSession = store.findSession(command.tenantId, command.playerId)
            ?: throw AuthenticationFailure.Rejected(AuthErrorCode.INVALID)

        if (existingSession.version != command.expectedVersion) {
            throw AuthenticationFailure.Rejected(AuthErrorCode.STALE)
        }

        val newVersion = existingSession.version + 1L
        val evidenceRef = "EVID-REALITY-SESSION-${existingSession.sessionId}-v$newVersion"

        val updatedSession = existingSession.copy(
            lastAcknowledgedAt = now,
            acknowledgmentCount = existingSession.acknowledgmentCount + 1,
            pendingAcknowledgment = false,
            version = newVersion,
            evidenceReference = evidenceRef,
            updatedAt = now,
        )

        val resultId = UUID.randomUUID()
        val result = RealityCheckSessionResult(
            resultId = resultId,
            record = updatedSession,
            serverTime = now,
            isDuplicate = false,
            isFinancialAuthorityCreated = false,
            semanticContract = DELAYED_LIMIT_INCREASE_CONTRACT,
        )

        val audit = AuditEvent(UUID.randomUUID(), existingSession.sessionId, command.tenantId, "REALITY_CHECK_SESSION_ACKNOWLEDGED", now, command.correlationId, command.causationId)
        val outbox = OutboxEvent(UUID.randomUUID(), existingSession.sessionId, command.tenantId, "REALITY_CHECK_SESSION_ACKNOWLEDGED", now)

        try {
            store.updateSession(updatedSession, result, command.idempotencyKey, fp, audit, outbox)
        } catch (e: Exception) {
            throw AuthenticationFailure.Rejected(AuthErrorCode.DEPENDENCY_UNAVAILABLE)
        }

        return result
    }
}
