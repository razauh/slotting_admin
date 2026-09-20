package com.slotting.admin.rg

import com.slotting.admin.auth.*
import java.nio.charset.StandardCharsets
import java.security.MessageDigest
import java.time.Clock
import java.time.Duration
import java.time.Instant
import java.util.UUID
import java.util.concurrent.ConcurrentHashMap

/**
 * Fail-closed verification gate for RG-003-03: Deliver server-timed reality checks.
 * Throws expected RED failure until contract bindings and invariant protections are verified.
 * Protected risk: False completion or non-authoritative implementation of Deliver server-timed reality checks.
 * Rationale: It exists to prevent: increase immediate or clock manipulation.
 */
object ServerTimedRealityCheckBinding {
    @Volatile
    var isBound: Boolean = false

    fun checkBound() {
        if (!isBound) {
            throw AssertionError("increase immediate or clock manipulation")
        }
    }
}

/**
 * Outcome-specific semantic contract for RG-003-03.
 */
const val SERVER_TIMED_REALITY_CHECK_CONTRACT =
    "Legal values configured; decrease may be immediate; restart cannot skip reality check."

/**
 * Minimum and maximum legal reality check intervals in minutes.
 */
const val MIN_LEGAL_REALITY_CHECK_INTERVAL_MINUTES = 15
const val MAX_LEGAL_REALITY_CHECK_INTERVAL_MINUTES = 1440 // 24 hours

/**
 * Standard cooling-off delay duration for interval loosening / increases (24 hours).
 */
val DEFAULT_INTERVAL_INCREASE_COOLING_DELAY: Duration = Duration.ofHours(24)

/**
 * Player choice submitted upon acknowledging reality check prompt.
 */
enum class RealityCheckChoice {
    CONTINUE_PLAYING,
    STOP_PLAYING_AND_LOGOUT,
    SET_STRICTER_LIMITS,
}

/**
 * Configuration record for player's reality check interval.
 */
data class RealityCheckConfigRecord(
    val configId: UUID,
    val tenantId: String,
    val playerId: String,
    val intervalMinutes: Int,
    val pendingIntervalMinutes: Int? = null,
    val coolingDelayStartsAt: Instant? = null,
    val coolingDelayExpiresAt: Instant? = null,
    val version: Long,
    val evidenceReference: String,
    val createdAt: Instant,
    val updatedAt: Instant,
    val semanticContract: String = SERVER_TIMED_REALITY_CHECK_CONTRACT,
)

/**
 * Authoritative session tracking record with server-timed reality checks.
 */
data class ServerTimedSessionRecord(
    val sessionId: UUID,
    val tenantId: String,
    val playerId: String,
    val sessionStartedAt: Instant,
    val intervalMinutes: Int,
    val totalWagersMinorUnits: Long = 0L,
    val totalPayoutsMinorUnits: Long = 0L,
    val netLossMinorUnits: Long = 0L,
    val lastPromptDeliveredAt: Instant? = null,
    val lastAcknowledgedAt: Instant? = null,
    val acknowledgmentCount: Int = 0,
    val isRealityCheckDue: Boolean = false,
    val isGameplaySuspended: Boolean = false,
    val version: Long,
    val evidenceReference: String,
    val createdAt: Instant,
    val updatedAt: Instant,
    val semanticContract: String = SERVER_TIMED_REALITY_CHECK_CONTRACT,
)

/**
 * Reality check prompt presented to player containing server-verified statistics.
 */
data class RealityCheckPrompt(
    val promptId: UUID,
    val sessionId: UUID,
    val tenantId: String,
    val playerId: String,
    val elapsedMinutes: Long,
    val totalWagersMinorUnits: Long,
    val totalPayoutsMinorUnits: Long,
    val netLossMinorUnits: Long,
    val deliveredAt: Instant,
    val isGameplaySuspended: Boolean = true,
    val semanticContract: String = SERVER_TIMED_REALITY_CHECK_CONTRACT,
)

/**
 * Result of configuring reality check interval.
 */
data class RealityCheckConfigResult(
    val resultId: UUID,
    val record: RealityCheckConfigRecord,
    val serverTime: Instant,
    val isDuplicate: Boolean,
    val isImmediate: Boolean,
    val isFinancialAuthorityCreated: Boolean = false,
    val semanticContract: String = SERVER_TIMED_REALITY_CHECK_CONTRACT,
)

/**
 * Result of session actions (start, activity, evaluation, acknowledgment).
 */
data class ServerTimedSessionResult(
    val resultId: UUID,
    val session: ServerTimedSessionRecord,
    val activePrompt: RealityCheckPrompt? = null,
    val serverTime: Instant,
    val isDuplicate: Boolean,
    val isFinancialAuthorityCreated: Boolean = false,
    val semanticContract: String = SERVER_TIMED_REALITY_CHECK_CONTRACT,
)

/**
 * Command to configure player's reality check interval.
 * Decreases apply immediately.
 * Increases enter mandatory cooling-off delay.
 */
data class ConfigureRealityCheckIntervalCommand(
    val tenantId: String,
    val playerId: String,
    val intervalMinutes: Int,
    val idempotencyKey: String,
    val correlationId: String,
    val causationId: String,
    val expectedVersion: Long? = null,
    val principal: AuthenticatedPrincipal? = null,
    val clientReportedTimestamp: Instant? = null,
)

/**
 * Command to start or resume a player gaming session.
 */
data class StartOrResumeSessionCommand(
    val tenantId: String,
    val playerId: String,
    val sessionId: UUID = UUID.randomUUID(),
    val idempotencyKey: String,
    val correlationId: String,
    val causationId: String,
    val principal: AuthenticatedPrincipal? = null,
    val clientReportedTimestamp: Instant? = null,
)

/**
 * Command to record game round activity (wagers and payouts) and evaluate reality check delivery.
 */
data class RecordSessionActivityCommand(
    val tenantId: String,
    val playerId: String,
    val wagerMinorUnits: Long,
    val payoutMinorUnits: Long,
    val idempotencyKey: String,
    val correlationId: String,
    val causationId: String,
    val expectedVersion: Long,
    val principal: AuthenticatedPrincipal? = null,
    val clientReportedTimestamp: Instant? = null,
)

/**
 * Command to evaluate if reality check is due.
 */
data class EvaluateRealityCheckCommand(
    val tenantId: String,
    val playerId: String,
    val idempotencyKey: String,
    val correlationId: String,
    val causationId: String,
    val principal: AuthenticatedPrincipal? = null,
    val clientReportedTimestamp: Instant? = null,
)

/**
 * Command to acknowledge reality check prompt and resume gameplay.
 */
data class AcknowledgeRealityCheckPromptCommand(
    val tenantId: String,
    val playerId: String,
    val promptId: UUID,
    val choice: RealityCheckChoice,
    val idempotencyKey: String,
    val correlationId: String,
    val causationId: String,
    val expectedVersion: Long,
    val principal: AuthenticatedPrincipal? = null,
    val clientReportedTimestamp: Instant? = null,
)

/**
 * Snapshot for state recovery and migration across server restarts.
 */
data class ServerTimedRealityCheckSnapshot(
    val configs: Map<String, RealityCheckConfigRecord>,
    val sessions: Map<String, ServerTimedSessionRecord>,
    val idempotencyMap: Map<String, Pair<String, Any>>,
    val auditEvents: List<AuditEvent>,
    val outboxEvents: List<OutboxEvent>,
)

/**
 * Persistence store interface for server-timed reality checks.
 */
interface ServerTimedRealityCheckStore {
    fun findConfig(tenantId: String, playerId: String): RealityCheckConfigRecord?
    fun saveConfig(
        record: RealityCheckConfigRecord,
        result: RealityCheckConfigResult,
        idempotencyKey: String,
        fingerprint: String,
        audit: AuditEvent,
        outbox: OutboxEvent,
    )
    fun updateConfig(
        record: RealityCheckConfigRecord,
        result: RealityCheckConfigResult,
        idempotencyKey: String,
        fingerprint: String,
        audit: AuditEvent,
        outbox: OutboxEvent,
    )
    fun findSession(tenantId: String, playerId: String): ServerTimedSessionRecord?
    fun saveSession(
        record: ServerTimedSessionRecord,
        result: ServerTimedSessionResult,
        idempotencyKey: String,
        fingerprint: String,
        audit: AuditEvent,
        outbox: OutboxEvent,
    )
    fun updateSession(
        record: ServerTimedSessionRecord,
        result: ServerTimedSessionResult,
        idempotencyKey: String,
        fingerprint: String,
        audit: AuditEvent,
        outbox: OutboxEvent,
    )
    fun findByIdempotency(tenantId: String, idempotencyKey: String): Pair<String, Any>?
    fun exportSnapshot(): ServerTimedRealityCheckSnapshot
    fun importSnapshot(snapshot: ServerTimedRealityCheckSnapshot)
}

/**
 * Observability alert sink for server-timed reality checks.
 */
interface ServerTimedRealityCheckAlertSink {
    fun sendAlert(tenantId: String, reference: String, alertType: String, reason: String, detail: String)
}

class InMemoryServerTimedRealityCheckAlertSink : ServerTimedRealityCheckAlertSink {
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
 * In-memory thread-safe implementation of ServerTimedRealityCheckStore.
 */
class InMemoryServerTimedRealityCheckStore : ServerTimedRealityCheckStore {
    private val configs = ConcurrentHashMap<String, RealityCheckConfigRecord>()
    private val sessions = ConcurrentHashMap<String, ServerTimedSessionRecord>()
    private val idempotencyResults = ConcurrentHashMap<String, Pair<String, Any>>()
    val auditEvents = mutableListOf<AuditEvent>()
    val outboxEvents = mutableListOf<OutboxEvent>()

    private fun configKey(tenantId: String, playerId: String) = "$tenantId:$playerId"
    private fun sessionKey(tenantId: String, playerId: String) = "$tenantId:$playerId"
    private fun idempKey(tenantId: String, idempotencyKey: String) = "$tenantId:$idempotencyKey"

    @Synchronized
    override fun findConfig(tenantId: String, playerId: String): RealityCheckConfigRecord? =
        configs[configKey(tenantId, playerId)]

    @Synchronized
    override fun saveConfig(
        record: RealityCheckConfigRecord,
        result: RealityCheckConfigResult,
        idempotencyKey: String,
        fingerprint: String,
        audit: AuditEvent,
        outbox: OutboxEvent,
    ) {
        configs[configKey(record.tenantId, record.playerId)] = record
        idempotencyResults[idempKey(record.tenantId, idempotencyKey)] = fingerprint to result
        auditEvents.add(audit)
        outboxEvents.add(outbox)
    }

    @Synchronized
    override fun updateConfig(
        record: RealityCheckConfigRecord,
        result: RealityCheckConfigResult,
        idempotencyKey: String,
        fingerprint: String,
        audit: AuditEvent,
        outbox: OutboxEvent,
    ) {
        configs[configKey(record.tenantId, record.playerId)] = record
        idempotencyResults[idempKey(record.tenantId, idempotencyKey)] = fingerprint to result
        auditEvents.add(audit)
        outboxEvents.add(outbox)
    }

    @Synchronized
    override fun findSession(tenantId: String, playerId: String): ServerTimedSessionRecord? =
        sessions[sessionKey(tenantId, playerId)]

    @Synchronized
    override fun saveSession(
        record: ServerTimedSessionRecord,
        result: ServerTimedSessionResult,
        idempotencyKey: String,
        fingerprint: String,
        audit: AuditEvent,
        outbox: OutboxEvent,
    ) {
        sessions[sessionKey(record.tenantId, record.playerId)] = record
        idempotencyResults[idempKey(record.tenantId, idempotencyKey)] = fingerprint to result
        auditEvents.add(audit)
        outboxEvents.add(outbox)
    }

    @Synchronized
    override fun updateSession(
        record: ServerTimedSessionRecord,
        result: ServerTimedSessionResult,
        idempotencyKey: String,
        fingerprint: String,
        audit: AuditEvent,
        outbox: OutboxEvent,
    ) {
        sessions[sessionKey(record.tenantId, record.playerId)] = record
        idempotencyResults[idempKey(record.tenantId, idempotencyKey)] = fingerprint to result
        auditEvents.add(audit)
        outboxEvents.add(outbox)
    }

    @Synchronized
    override fun findByIdempotency(tenantId: String, idempotencyKey: String): Pair<String, Any>? =
        idempotencyResults[idempKey(tenantId, idempotencyKey)]

    @Synchronized
    override fun exportSnapshot(): ServerTimedRealityCheckSnapshot = ServerTimedRealityCheckSnapshot(
        configs = HashMap(configs),
        sessions = HashMap(sessions),
        idempotencyMap = HashMap(idempotencyResults),
        auditEvents = ArrayList(auditEvents),
        outboxEvents = ArrayList(outboxEvents),
    )

    @Synchronized
    override fun importSnapshot(snapshot: ServerTimedRealityCheckSnapshot) {
        configs.clear()
        configs.putAll(snapshot.configs)
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
 * Authoritative backend service implementing RG-003-03: Deliver server-timed reality checks.
 */
class ServerTimedRealityCheckService(
    private val store: ServerTimedRealityCheckStore,
    private val alertSink: ServerTimedRealityCheckAlertSink = InMemoryServerTimedRealityCheckAlertSink(),
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
    fun configureRealityCheckInterval(command: ConfigureRealityCheckIntervalCommand): RealityCheckConfigResult {
        ServerTimedRealityCheckBinding.checkBound()

        if (command.tenantId.isBlank() || command.playerId.isBlank() || command.idempotencyKey.isBlank()) {
            throw AuthenticationFailure.Rejected(AuthErrorCode.INVALID)
        }

        // Legal values configured: interval must be within [MIN_LEGAL_REALITY_CHECK_INTERVAL_MINUTES, MAX_LEGAL_REALITY_CHECK_INTERVAL_MINUTES]
        if (command.intervalMinutes < MIN_LEGAL_REALITY_CHECK_INTERVAL_MINUTES ||
            command.intervalMinutes > MAX_LEGAL_REALITY_CHECK_INTERVAL_MINUTES
        ) {
            alertSink.sendAlert(
                tenantId = command.tenantId,
                reference = command.playerId,
                alertType = "REALITY_CHECK_ILLEGAL_INTERVAL",
                reason = "ILLEGAL_INTERVAL_VALUE",
                detail = "Interval ${command.intervalMinutes} is outside legal bounds [$MIN_LEGAL_REALITY_CHECK_INTERVAL_MINUTES, $MAX_LEGAL_REALITY_CHECK_INTERVAL_MINUTES]",
            )
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
                    detail = "Client reported timestamp skew on interval configuration",
                )
                throw AuthenticationFailure.Rejected(AuthErrorCode.INVALID)
            }
        }

        val fp = sha256("${command.tenantId}:${command.playerId}:${command.intervalMinutes}:${command.expectedVersion}")

        val existingIdemp = store.findByIdempotency(command.tenantId, command.idempotencyKey)
        if (existingIdemp != null) {
            val (cachedFp, cachedResult) = existingIdemp
            if (cachedFp != fp) {
                throw AuthenticationFailure.Rejected(AuthErrorCode.CONFLICT)
            }
            val res = cachedResult as RealityCheckConfigResult
            return res.copy(isDuplicate = true)
        }

        val existing = store.findConfig(command.tenantId, command.playerId)
        if (existing != null) {
            if (command.expectedVersion != null && existing.version != command.expectedVersion) {
                throw AuthenticationFailure.Rejected(AuthErrorCode.STALE)
            }
        }

        val configId = existing?.configId ?: UUID.randomUUID()
        val newVersion = (existing?.version ?: 0L) + 1L
        val evidenceRef = "EVID-RC-CONFIG-$configId-v$newVersion"

        val (updatedRecord, isImmediate) = if (existing == null) {
            // Initial configuration of legal values: applies immediately
            RealityCheckConfigRecord(
                configId = configId,
                tenantId = command.tenantId,
                playerId = command.playerId,
                intervalMinutes = command.intervalMinutes,
                pendingIntervalMinutes = null,
                coolingDelayStartsAt = null,
                coolingDelayExpiresAt = null,
                version = newVersion,
                evidenceReference = evidenceRef,
                createdAt = now,
                updatedAt = now,
                semanticContract = SERVER_TIMED_REALITY_CHECK_CONTRACT,
            ) to true
        } else if (command.intervalMinutes < existing.intervalMinutes) {
            // Decrease may be immediate: stricter interval takes effect immediately, cancels pending increases
            existing.copy(
                intervalMinutes = command.intervalMinutes,
                pendingIntervalMinutes = null,
                coolingDelayStartsAt = null,
                coolingDelayExpiresAt = null,
                version = newVersion,
                evidenceReference = evidenceRef,
                updatedAt = now,
            ) to true
        } else if (command.intervalMinutes > existing.intervalMinutes) {
            // Increase MUST be delayed by mandatory cooling-off delay (prevent: increase immediate)
            val expiresAt = now.plus(DEFAULT_INTERVAL_INCREASE_COOLING_DELAY)
            existing.copy(
                pendingIntervalMinutes = command.intervalMinutes,
                coolingDelayStartsAt = now,
                coolingDelayExpiresAt = expiresAt,
                version = newVersion,
                evidenceReference = evidenceRef,
                updatedAt = now,
            ) to false
        } else {
            existing.copy(
                version = newVersion,
                evidenceReference = evidenceRef,
                updatedAt = now,
            ) to true
        }

        val resultId = UUID.randomUUID()
        val result = RealityCheckConfigResult(
            resultId = resultId,
            record = updatedRecord,
            serverTime = now,
            isDuplicate = false,
            isImmediate = isImmediate,
            isFinancialAuthorityCreated = false,
            semanticContract = SERVER_TIMED_REALITY_CHECK_CONTRACT,
        )

        val eventType = if (isImmediate) "RC_INTERVAL_DECREASED_IMMEDIATE" else "RC_INTERVAL_INCREASE_DELAYED"
        val audit = AuditEvent(UUID.randomUUID(), configId, command.tenantId, eventType, now, command.correlationId, command.causationId)
        val outbox = OutboxEvent(UUID.randomUUID(), configId, command.tenantId, eventType, now)

        try {
            if (existing == null) {
                store.saveConfig(updatedRecord, result, command.idempotencyKey, fp, audit, outbox)
            } else {
                store.updateConfig(updatedRecord, result, command.idempotencyKey, fp, audit, outbox)
            }
        } catch (e: Exception) {
            throw AuthenticationFailure.Rejected(AuthErrorCode.DEPENDENCY_UNAVAILABLE)
        }

        return result
    }

    @Synchronized
    fun startOrResumeSession(command: StartOrResumeSessionCommand): ServerTimedSessionResult {
        ServerTimedRealityCheckBinding.checkBound()

        if (command.tenantId.isBlank() || command.playerId.isBlank() || command.idempotencyKey.isBlank()) {
            throw AuthenticationFailure.Rejected(AuthErrorCode.INVALID)
        }

        validatePrincipal(command.principal, command.tenantId, command.playerId)

        val now = clock.instant()

        // Clock manipulation prevention
        command.clientReportedTimestamp?.let { clientTime ->
            val diff = Duration.between(now, clientTime).abs()
            if (diff > Duration.ofSeconds(60)) {
                throw AuthenticationFailure.Rejected(AuthErrorCode.INVALID)
            }
        }

        val fp = sha256("${command.tenantId}:${command.playerId}:${command.sessionId}")

        val existingIdemp = store.findByIdempotency(command.tenantId, command.idempotencyKey)
        if (existingIdemp != null) {
            val (cachedFp, cachedResult) = existingIdemp
            if (cachedFp != fp) {
                throw AuthenticationFailure.Rejected(AuthErrorCode.CONFLICT)
            }
            val res = cachedResult as ServerTimedSessionResult
            return res.copy(isDuplicate = true)
        }

        val config = store.findConfig(command.tenantId, command.playerId)
        val intervalMinutes = config?.intervalMinutes ?: 60

        val existingSession = store.findSession(command.tenantId, command.playerId)

        val newVersion = (existingSession?.version ?: 0L) + 1L
        val evidenceRef = "EVID-RC-SESSION-${command.sessionId}-v$newVersion"

        // Check if session has elapsed its interval
        val referenceTime = existingSession?.lastAcknowledgedAt ?: existingSession?.sessionStartedAt ?: now
        val elapsedDuration = Duration.between(referenceTime, now)
        val intervalDuration = Duration.ofMinutes(intervalMinutes.toLong())

        val isDue = if (existingSession != null) {
            existingSession.isRealityCheckDue || elapsedDuration >= intervalDuration
        } else {
            false
        }

        val isSuspended = isDue

        val sessionRecord = existingSession?.copy(
            intervalMinutes = intervalMinutes,
            isRealityCheckDue = isDue,
            isGameplaySuspended = isSuspended,
            version = newVersion,
            evidenceReference = evidenceRef,
            updatedAt = now,
        ) ?: ServerTimedSessionRecord(
            sessionId = command.sessionId,
            tenantId = command.tenantId,
            playerId = command.playerId,
            sessionStartedAt = now,
            intervalMinutes = intervalMinutes,
            totalWagersMinorUnits = 0L,
            totalPayoutsMinorUnits = 0L,
            netLossMinorUnits = 0L,
            lastPromptDeliveredAt = null,
            lastAcknowledgedAt = null,
            acknowledgmentCount = 0,
            isRealityCheckDue = false,
            isGameplaySuspended = false,
            version = newVersion,
            evidenceReference = evidenceRef,
            createdAt = now,
            updatedAt = now,
            semanticContract = SERVER_TIMED_REALITY_CHECK_CONTRACT,
        )

        val activePrompt = if (sessionRecord.isRealityCheckDue) {
            val totalElapsed = Duration.between(sessionRecord.sessionStartedAt, now).toMinutes()
            RealityCheckPrompt(
                promptId = UUID.randomUUID(),
                sessionId = sessionRecord.sessionId,
                tenantId = sessionRecord.tenantId,
                playerId = sessionRecord.playerId,
                elapsedMinutes = totalElapsed,
                totalWagersMinorUnits = sessionRecord.totalWagersMinorUnits,
                totalPayoutsMinorUnits = sessionRecord.totalPayoutsMinorUnits,
                netLossMinorUnits = sessionRecord.netLossMinorUnits,
                deliveredAt = now,
                isGameplaySuspended = true,
                semanticContract = SERVER_TIMED_REALITY_CHECK_CONTRACT,
            )
        } else {
            null
        }

        val resultId = UUID.randomUUID()
        val result = ServerTimedSessionResult(
            resultId = resultId,
            session = sessionRecord,
            activePrompt = activePrompt,
            serverTime = now,
            isDuplicate = false,
            isFinancialAuthorityCreated = false,
            semanticContract = SERVER_TIMED_REALITY_CHECK_CONTRACT,
        )

        val audit = AuditEvent(UUID.randomUUID(), sessionRecord.sessionId, command.tenantId, "RC_SESSION_STARTED_OR_RESUMED", now, command.correlationId, command.causationId)
        val outbox = OutboxEvent(UUID.randomUUID(), sessionRecord.sessionId, command.tenantId, "RC_SESSION_STARTED_OR_RESUMED", now)

        try {
            if (existingSession == null) {
                store.saveSession(sessionRecord, result, command.idempotencyKey, fp, audit, outbox)
            } else {
                store.updateSession(sessionRecord, result, command.idempotencyKey, fp, audit, outbox)
            }
        } catch (e: Exception) {
            throw AuthenticationFailure.Rejected(AuthErrorCode.DEPENDENCY_UNAVAILABLE)
        }

        return result
    }

    @Synchronized
    fun recordSessionActivity(command: RecordSessionActivityCommand): ServerTimedSessionResult {
        ServerTimedRealityCheckBinding.checkBound()

        if (command.tenantId.isBlank() || command.playerId.isBlank() || command.idempotencyKey.isBlank()) {
            throw AuthenticationFailure.Rejected(AuthErrorCode.INVALID)
        }

        if (command.wagerMinorUnits < 0L || command.payoutMinorUnits < 0L) {
            throw AuthenticationFailure.Rejected(AuthErrorCode.INVALID)
        }

        validatePrincipal(command.principal, command.tenantId, command.playerId)

        val now = clock.instant()

        // Clock manipulation prevention
        command.clientReportedTimestamp?.let { clientTime ->
            val diff = Duration.between(now, clientTime).abs()
            if (diff > Duration.ofSeconds(60)) {
                throw AuthenticationFailure.Rejected(AuthErrorCode.INVALID)
            }
        }

        val fp = sha256("${command.tenantId}:${command.playerId}:${command.wagerMinorUnits}:${command.payoutMinorUnits}:${command.expectedVersion}")

        val existingIdemp = store.findByIdempotency(command.tenantId, command.idempotencyKey)
        if (existingIdemp != null) {
            val (cachedFp, cachedResult) = existingIdemp
            if (cachedFp != fp) {
                throw AuthenticationFailure.Rejected(AuthErrorCode.CONFLICT)
            }
            val res = cachedResult as ServerTimedSessionResult
            return res.copy(isDuplicate = true)
        }

        val existing = store.findSession(command.tenantId, command.playerId)
            ?: throw AuthenticationFailure.Rejected(AuthErrorCode.INVALID)

        if (existing.version != command.expectedVersion) {
            throw AuthenticationFailure.Rejected(AuthErrorCode.STALE)
        }

        // If reality check is due, no new activity can be recorded until acknowledged!
        if (existing.isRealityCheckDue || existing.isGameplaySuspended) {
            alertSink.sendAlert(
                tenantId = command.tenantId,
                reference = command.playerId,
                alertType = "GAMEPLAY_SUSPENDED_REALITY_CHECK_DUE",
                reason = "UNACKNOWLEDGED_REALITY_CHECK",
                detail = "Gameplay activity blocked because reality check is due and unacknowledged",
            )
            throw AuthenticationFailure.Rejected(AuthErrorCode.FORBIDDEN)
        }

        val newWagers = existing.totalWagersMinorUnits + command.wagerMinorUnits
        val newPayouts = existing.totalPayoutsMinorUnits + command.payoutMinorUnits
        val newNetLoss = (newWagers - newPayouts).coerceAtLeast(0L)

        // Server-timed evaluation
        val referenceTime = existing.lastAcknowledgedAt ?: existing.sessionStartedAt
        val elapsed = Duration.between(referenceTime, now)
        val intervalDuration = Duration.ofMinutes(existing.intervalMinutes.toLong())

        val isDue = elapsed >= intervalDuration
        val isSuspended = isDue

        val newVersion = existing.version + 1L
        val evidenceRef = "EVID-RC-SESSION-${existing.sessionId}-v$newVersion"

        val updated = existing.copy(
            totalWagersMinorUnits = newWagers,
            totalPayoutsMinorUnits = newPayouts,
            netLossMinorUnits = newNetLoss,
            lastPromptDeliveredAt = if (isDue) now else existing.lastPromptDeliveredAt,
            isRealityCheckDue = isDue,
            isGameplaySuspended = isSuspended,
            version = newVersion,
            evidenceReference = evidenceRef,
            updatedAt = now,
        )

        val activePrompt = if (isDue) {
            val totalElapsed = Duration.between(existing.sessionStartedAt, now).toMinutes()
            RealityCheckPrompt(
                promptId = UUID.randomUUID(),
                sessionId = existing.sessionId,
                tenantId = existing.tenantId,
                playerId = existing.playerId,
                elapsedMinutes = totalElapsed,
                totalWagersMinorUnits = newWagers,
                totalPayoutsMinorUnits = newPayouts,
                netLossMinorUnits = newNetLoss,
                deliveredAt = now,
                isGameplaySuspended = true,
                semanticContract = SERVER_TIMED_REALITY_CHECK_CONTRACT,
            )
        } else {
            null
        }

        val resultId = UUID.randomUUID()
        val result = ServerTimedSessionResult(
            resultId = resultId,
            session = updated,
            activePrompt = activePrompt,
            serverTime = now,
            isDuplicate = false,
            isFinancialAuthorityCreated = false,
            semanticContract = SERVER_TIMED_REALITY_CHECK_CONTRACT,
        )

        val audit = AuditEvent(UUID.randomUUID(), existing.sessionId, command.tenantId, "RC_SESSION_ACTIVITY_RECORDED", now, command.correlationId, command.causationId)
        val outbox = OutboxEvent(UUID.randomUUID(), existing.sessionId, command.tenantId, "RC_SESSION_ACTIVITY_RECORDED", now)

        try {
            store.updateSession(updated, result, command.idempotencyKey, fp, audit, outbox)
        } catch (e: Exception) {
            throw AuthenticationFailure.Rejected(AuthErrorCode.DEPENDENCY_UNAVAILABLE)
        }

        return result
    }

    @Synchronized
    fun evaluateRealityCheck(command: EvaluateRealityCheckCommand): ServerTimedSessionResult {
        ServerTimedRealityCheckBinding.checkBound()

        if (command.tenantId.isBlank() || command.playerId.isBlank() || command.idempotencyKey.isBlank()) {
            throw AuthenticationFailure.Rejected(AuthErrorCode.INVALID)
        }

        validatePrincipal(command.principal, command.tenantId, command.playerId)

        val now = clock.instant()
        val fp = sha256("${command.tenantId}:${command.playerId}:EVALUATE")

        val existingIdemp = store.findByIdempotency(command.tenantId, command.idempotencyKey)
        if (existingIdemp != null) {
            val (cachedFp, cachedResult) = existingIdemp
            if (cachedFp != fp) {
                throw AuthenticationFailure.Rejected(AuthErrorCode.CONFLICT)
            }
            val res = cachedResult as ServerTimedSessionResult
            return res.copy(isDuplicate = true)
        }

        val existing = store.findSession(command.tenantId, command.playerId)
            ?: throw AuthenticationFailure.Rejected(AuthErrorCode.INVALID)

        val referenceTime = existing.lastAcknowledgedAt ?: existing.sessionStartedAt
        val elapsed = Duration.between(referenceTime, now)
        val intervalDuration = Duration.ofMinutes(existing.intervalMinutes.toLong())

        val isDue = existing.isRealityCheckDue || (elapsed >= intervalDuration)
        val isSuspended = isDue

        val newVersion = existing.version + 1L
        val evidenceRef = "EVID-RC-SESSION-${existing.sessionId}-v$newVersion"

        val updated = existing.copy(
            isRealityCheckDue = isDue,
            isGameplaySuspended = isSuspended,
            lastPromptDeliveredAt = if (isDue && existing.lastPromptDeliveredAt == null) now else existing.lastPromptDeliveredAt,
            version = newVersion,
            evidenceReference = evidenceRef,
            updatedAt = now,
        )

        val activePrompt = if (isDue) {
            val totalElapsed = Duration.between(existing.sessionStartedAt, now).toMinutes()
            RealityCheckPrompt(
                promptId = UUID.randomUUID(),
                sessionId = existing.sessionId,
                tenantId = existing.tenantId,
                playerId = existing.playerId,
                elapsedMinutes = totalElapsed,
                totalWagersMinorUnits = existing.totalWagersMinorUnits,
                totalPayoutsMinorUnits = existing.totalPayoutsMinorUnits,
                netLossMinorUnits = existing.netLossMinorUnits,
                deliveredAt = now,
                isGameplaySuspended = true,
                semanticContract = SERVER_TIMED_REALITY_CHECK_CONTRACT,
            )
        } else {
            null
        }

        val resultId = UUID.randomUUID()
        val result = ServerTimedSessionResult(
            resultId = resultId,
            session = updated,
            activePrompt = activePrompt,
            serverTime = now,
            isDuplicate = false,
            isFinancialAuthorityCreated = false,
            semanticContract = SERVER_TIMED_REALITY_CHECK_CONTRACT,
        )

        val audit = AuditEvent(UUID.randomUUID(), existing.sessionId, command.tenantId, "RC_EVALUATION_PERFORMED", now, command.correlationId, command.causationId)
        val outbox = OutboxEvent(UUID.randomUUID(), existing.sessionId, command.tenantId, "RC_EVALUATION_PERFORMED", now)

        try {
            store.updateSession(updated, result, command.idempotencyKey, fp, audit, outbox)
        } catch (e: Exception) {
            throw AuthenticationFailure.Rejected(AuthErrorCode.DEPENDENCY_UNAVAILABLE)
        }

        return result
    }

    @Synchronized
    fun acknowledgeRealityCheckPrompt(command: AcknowledgeRealityCheckPromptCommand): ServerTimedSessionResult {
        ServerTimedRealityCheckBinding.checkBound()

        if (command.tenantId.isBlank() || command.playerId.isBlank() || command.idempotencyKey.isBlank()) {
            throw AuthenticationFailure.Rejected(AuthErrorCode.INVALID)
        }

        validatePrincipal(command.principal, command.tenantId, command.playerId)

        val now = clock.instant()

        // Clock manipulation check
        command.clientReportedTimestamp?.let { clientTime ->
            val diff = Duration.between(now, clientTime).abs()
            if (diff > Duration.ofSeconds(60)) {
                throw AuthenticationFailure.Rejected(AuthErrorCode.INVALID)
            }
        }

        val fp = sha256("${command.tenantId}:${command.playerId}:${command.promptId}:${command.choice}:${command.expectedVersion}")

        val existingIdemp = store.findByIdempotency(command.tenantId, command.idempotencyKey)
        if (existingIdemp != null) {
            val (cachedFp, cachedResult) = existingIdemp
            if (cachedFp != fp) {
                throw AuthenticationFailure.Rejected(AuthErrorCode.CONFLICT)
            }
            val res = cachedResult as ServerTimedSessionResult
            return res.copy(isDuplicate = true)
        }

        val existing = store.findSession(command.tenantId, command.playerId)
            ?: throw AuthenticationFailure.Rejected(AuthErrorCode.INVALID)

        if (existing.version != command.expectedVersion) {
            throw AuthenticationFailure.Rejected(AuthErrorCode.STALE)
        }

        if (!existing.isRealityCheckDue) {
            // Cannot acknowledge a reality check that is not due
            throw AuthenticationFailure.Rejected(AuthErrorCode.INVALID)
        }

        val newVersion = existing.version + 1L
        val evidenceRef = "EVID-RC-SESSION-${existing.sessionId}-v$newVersion"

        val updated = existing.copy(
            lastAcknowledgedAt = now,
            acknowledgmentCount = existing.acknowledgmentCount + 1,
            isRealityCheckDue = false,
            isGameplaySuspended = false,
            version = newVersion,
            evidenceReference = evidenceRef,
            updatedAt = now,
        )

        val resultId = UUID.randomUUID()
        val result = ServerTimedSessionResult(
            resultId = resultId,
            session = updated,
            activePrompt = null,
            serverTime = now,
            isDuplicate = false,
            isFinancialAuthorityCreated = false,
            semanticContract = SERVER_TIMED_REALITY_CHECK_CONTRACT,
        )

        val audit = AuditEvent(UUID.randomUUID(), existing.sessionId, command.tenantId, "RC_PROMPT_ACKNOWLEDGED", now, command.correlationId, command.causationId)
        val outbox = OutboxEvent(UUID.randomUUID(), existing.sessionId, command.tenantId, "RC_PROMPT_ACKNOWLEDGED", now)

        try {
            store.updateSession(updated, result, command.idempotencyKey, fp, audit, outbox)
        } catch (e: Exception) {
            throw AuthenticationFailure.Rejected(AuthErrorCode.DEPENDENCY_UNAVAILABLE)
        }

        return result
    }
}
