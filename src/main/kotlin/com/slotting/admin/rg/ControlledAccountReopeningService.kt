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
 * Fail-closed verification gate for RG-003-02: Control account reopening.
 * Throws expected RED failure until contract bindings and invariant protections are verified.
 * Protected risk: False completion or non-authoritative implementation of Control account reopening.
 * Rationale: It exists to prevent: increase immediate or clock manipulation.
 */
object ControlledAccountReopeningBinding {
    @Volatile
    var isBound: Boolean = false

    fun checkBound() {
        if (!isBound) {
            throw AssertionError("increase immediate or clock manipulation")
        }
    }
}

/**
 * Outcome-specific semantic contract for RG-003-02.
 */
const val CONTROLLED_ACCOUNT_REOPENING_CONTRACT =
    "Legal values configured; decrease may be immediate; restart cannot skip reality check."

/**
 * Default mandatory cooling-off delay for account reopening (24 hours).
 */
val DEFAULT_REOPENING_COOLING_DELAY: Duration = Duration.ofHours(24)

/**
 * Account restriction classifications subject to controlled reopening.
 */
enum class AccountRestrictionType {
    TEMPORARY_CLOSURE,
    COOLING_OFF,
    SELF_EXCLUSION_DEFINITE,
    SELF_EXCLUSION_PERMANENT,
}

/**
 * Strict workflow states governing controlled account reopening.
 */
enum class ControlledReopeningStatus {
    CLOSED_OR_EXCLUDED,
    PENDING_REOPENING_COOLING_OFF,
    PENDING_OPERATOR_REVIEW,
    PENDING_REALITY_CHECK_ACK,
    REOPENED,
    REJECTED,
}

/**
 * Persisted authoritative record for controlled account reopening.
 */
data class ControlledAccountReopeningRecord(
    val recordId: UUID,
    val tenantId: String,
    val playerId: String,
    val restrictionType: AccountRestrictionType,
    val status: ControlledReopeningStatus,
    val closedAt: Instant,
    val closureExpiresAt: Instant?,
    val closureReason: String,
    val reopeningRequestedAt: Instant? = null,
    val reopeningCoolingDelayExpiresAt: Instant? = null,
    val coolingDelayDuration: Duration = DEFAULT_REOPENING_COOLING_DELAY,
    val operatorReviewedAt: Instant? = null,
    val operatorReviewerId: String? = null,
    val operatorNotes: String? = null,
    val realityCheckRequired: Boolean = true,
    val realityCheckAcknowledgedAt: Instant? = null,
    val reopenedAt: Instant? = null,
    val initialDepositLimitMinorUnits: Long? = null,
    val version: Long,
    val evidenceReference: String,
    val createdAt: Instant,
    val updatedAt: Instant,
    val semanticContract: String = CONTROLLED_ACCOUNT_REOPENING_CONTRACT,
)

/**
 * Result of controlled account reopening operations.
 */
data class ControlledAccountReopeningResult(
    val resultId: UUID,
    val record: ControlledAccountReopeningRecord,
    val serverTime: Instant,
    val isDuplicate: Boolean,
    val isFinancialAuthorityCreated: Boolean = false,
    val semanticContract: String = CONTROLLED_ACCOUNT_REOPENING_CONTRACT,
)

/**
 * Read model status for account reopening.
 */
data class CheckReopeningStatusResult(
    val isReopened: Boolean,
    val status: ControlledReopeningStatus,
    val restrictionType: AccountRestrictionType,
    val coolingDelayActive: Boolean,
    val coolingDelayExpiresAt: Instant?,
    val realityCheckPending: Boolean,
    val evidenceReference: String,
    val serverTime: Instant,
    val semanticContract: String = CONTROLLED_ACCOUNT_REOPENING_CONTRACT,
)

/**
 * Command to record account closure or self-exclusion.
 */
data class CloseOrExcludeAccountCommand(
    val tenantId: String,
    val playerId: String,
    val restrictionType: AccountRestrictionType,
    val durationDays: Int?,
    val reason: String,
    val idempotencyKey: String,
    val correlationId: String,
    val causationId: String,
    val expectedVersion: Long? = null,
    val principal: AuthenticatedPrincipal? = null,
)

/**
 * Command to submit a formal request to reopen an account.
 */
data class RequestAccountReopeningCommand(
    val tenantId: String,
    val playerId: String,
    val reason: String,
    val idempotencyKey: String,
    val correlationId: String,
    val causationId: String,
    val expectedVersion: Long,
    val principal: AuthenticatedPrincipal? = null,
    val clientReportedTimestamp: Instant? = null,
)

/**
 * Command for operator review and approval/rejection of reopening request.
 */
data class ReviewAccountReopeningCommand(
    val tenantId: String,
    val playerId: String,
    val approved: Boolean,
    val operatorNotes: String,
    val initialDepositLimitMinorUnits: Long? = null,
    val idempotencyKey: String,
    val correlationId: String,
    val causationId: String,
    val expectedVersion: Long,
    val principal: AuthenticatedPrincipal? = null,
    val clientReportedTimestamp: Instant? = null,
)

/**
 * Command to acknowledge reality check and complete account reopening.
 */
data class AcknowledgeReopeningRealityCheckCommand(
    val tenantId: String,
    val playerId: String,
    val idempotencyKey: String,
    val correlationId: String,
    val causationId: String,
    val expectedVersion: Long,
    val principal: AuthenticatedPrincipal? = null,
    val clientReportedTimestamp: Instant? = null,
)

/**
 * Command to cancel a pending reopening request.
 */
data class CancelReopeningRequestCommand(
    val tenantId: String,
    val playerId: String,
    val reason: String,
    val idempotencyKey: String,
    val correlationId: String,
    val causationId: String,
    val expectedVersion: Long,
    val principal: AuthenticatedPrincipal? = null,
)

/**
 * Query reopening status.
 */
data class CheckReopeningStatusQuery(
    val tenantId: String,
    val playerId: String,
    val principal: AuthenticatedPrincipal? = null,
)

/**
 * Persistence store interface for controlled account reopening.
 */
interface ControlledAccountReopeningStore {
    fun findRecord(tenantId: String, playerId: String): ControlledAccountReopeningRecord?
    fun saveRecord(
        record: ControlledAccountReopeningRecord,
        result: ControlledAccountReopeningResult,
        idempotencyKey: String,
        fingerprint: String,
        audit: AuditEvent,
        outbox: OutboxEvent,
    )
    fun updateRecord(
        record: ControlledAccountReopeningRecord,
        result: ControlledAccountReopeningResult,
        idempotencyKey: String,
        fingerprint: String,
        audit: AuditEvent,
        outbox: OutboxEvent,
    )
    fun findByIdempotency(tenantId: String, idempotencyKey: String): Pair<String, Any>?
    fun exportSnapshot(): ControlledReopeningSnapshot
    fun importSnapshot(snapshot: ControlledReopeningSnapshot)
}

/**
 * Snapshot for state recovery and migration across server restarts.
 */
data class ControlledReopeningSnapshot(
    val records: Map<String, ControlledAccountReopeningRecord>,
    val idempotencyMap: Map<String, Pair<String, Any>>,
    val auditEvents: List<AuditEvent>,
    val outboxEvents: List<OutboxEvent>,
)

/**
 * Observability alert sink for account reopening.
 */
interface ControlledAccountReopeningAlertSink {
    fun sendAlert(tenantId: String, reference: String, alertType: String, reason: String, detail: String)
}

class InMemoryControlledAccountReopeningAlertSink : ControlledAccountReopeningAlertSink {
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
 * In-memory thread-safe implementation of ControlledAccountReopeningStore.
 */
class InMemoryControlledAccountReopeningStore : ControlledAccountReopeningStore {
    private val records = ConcurrentHashMap<String, ControlledAccountReopeningRecord>()
    private val idempotencyResults = ConcurrentHashMap<String, Pair<String, Any>>()
    val auditEvents = mutableListOf<AuditEvent>()
    val outboxEvents = mutableListOf<OutboxEvent>()

    private fun key(tenantId: String, playerId: String) = "$tenantId:$playerId"
    private fun idempKey(tenantId: String, idempotencyKey: String) = "$tenantId:$idempotencyKey"

    @Synchronized
    override fun findRecord(tenantId: String, playerId: String): ControlledAccountReopeningRecord? =
        records[key(tenantId, playerId)]

    @Synchronized
    override fun saveRecord(
        record: ControlledAccountReopeningRecord,
        result: ControlledAccountReopeningResult,
        idempotencyKey: String,
        fingerprint: String,
        audit: AuditEvent,
        outbox: OutboxEvent,
    ) {
        records[key(record.tenantId, record.playerId)] = record
        idempotencyResults[idempKey(record.tenantId, idempotencyKey)] = fingerprint to result
        auditEvents.add(audit)
        outboxEvents.add(outbox)
    }

    @Synchronized
    override fun updateRecord(
        record: ControlledAccountReopeningRecord,
        result: ControlledAccountReopeningResult,
        idempotencyKey: String,
        fingerprint: String,
        audit: AuditEvent,
        outbox: OutboxEvent,
    ) {
        records[key(record.tenantId, record.playerId)] = record
        idempotencyResults[idempKey(record.tenantId, idempotencyKey)] = fingerprint to result
        auditEvents.add(audit)
        outboxEvents.add(outbox)
    }

    @Synchronized
    override fun findByIdempotency(tenantId: String, idempotencyKey: String): Pair<String, Any>? =
        idempotencyResults[idempKey(tenantId, idempotencyKey)]

    @Synchronized
    override fun exportSnapshot(): ControlledReopeningSnapshot = ControlledReopeningSnapshot(
        records = HashMap(records),
        idempotencyMap = HashMap(idempotencyResults),
        auditEvents = ArrayList(auditEvents),
        outboxEvents = ArrayList(outboxEvents),
    )

    @Synchronized
    override fun importSnapshot(snapshot: ControlledReopeningSnapshot) {
        records.clear()
        records.putAll(snapshot.records)
        idempotencyResults.clear()
        idempotencyResults.putAll(snapshot.idempotencyMap)
        auditEvents.clear()
        auditEvents.addAll(snapshot.auditEvents)
        outboxEvents.clear()
        outboxEvents.addAll(snapshot.outboxEvents)
    }
}

/**
 * Authoritative backend service implementing RG-003-02: Control account reopening.
 */
class ControlledAccountReopeningService(
    private val store: ControlledAccountReopeningStore,
    private val alertSink: ControlledAccountReopeningAlertSink = InMemoryControlledAccountReopeningAlertSink(),
    private val clock: Clock = Clock.systemUTC(),
) {
    private fun sha256(input: String): String {
        val digest = MessageDigest.getInstance("SHA-256")
        val hash = digest.digest(input.toByteArray(StandardCharsets.UTF_8))
        return hash.joinToString("") { "%02x".format(it) }
    }

    private fun validatePrincipal(principal: AuthenticatedPrincipal?, tenantId: String, playerId: String, requireAdmin: Boolean = false) {
        principal?.let {
            if (it.tenantId != tenantId) {
                throw AuthenticationFailure.Rejected(AuthErrorCode.FORBIDDEN)
            }
            if (requireAdmin) {
                if (it.kind != PrincipalKind.ADMIN || it.roles.none { role -> role in setOf(AdminRole.SUPER_ADMIN, AdminRole.SECURITY, AdminRole.AUDITOR) }) {
                    throw AuthenticationFailure.Rejected(AuthErrorCode.FORBIDDEN)
                }
            } else {
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
    }

    @Synchronized
    fun closeOrExcludeAccount(command: CloseOrExcludeAccountCommand): ControlledAccountReopeningResult {
        ControlledAccountReopeningBinding.checkBound()

        if (command.tenantId.isBlank() || command.playerId.isBlank() || command.idempotencyKey.isBlank()) {
            throw AuthenticationFailure.Rejected(AuthErrorCode.INVALID)
        }

        validatePrincipal(command.principal, command.tenantId, command.playerId)

        val now = clock.instant()
        val fp = sha256("${command.tenantId}:${command.playerId}:${command.restrictionType}:${command.durationDays}:${command.reason}:${command.expectedVersion}")

        val existingIdemp = store.findByIdempotency(command.tenantId, command.idempotencyKey)
        if (existingIdemp != null) {
            val (cachedFp, cachedResult) = existingIdemp
            if (cachedFp != fp) {
                throw AuthenticationFailure.Rejected(AuthErrorCode.CONFLICT)
            }
            val res = cachedResult as ControlledAccountReopeningResult
            return res.copy(isDuplicate = true)
        }

        val existing = store.findRecord(command.tenantId, command.playerId)
        if (existing != null) {
            if (command.expectedVersion != null && existing.version != command.expectedVersion) {
                throw AuthenticationFailure.Rejected(AuthErrorCode.STALE)
            }
        }

        val expiresAt = if (command.restrictionType == AccountRestrictionType.SELF_EXCLUSION_PERMANENT) {
            null
        } else if (command.durationDays != null && command.durationDays > 0) {
            now.plus(Duration.ofDays(command.durationDays.toLong()))
        } else {
            null
        }

        val recordId = existing?.recordId ?: UUID.randomUUID()
        val newVersion = (existing?.version ?: 0L) + 1L
        val evidenceRef = "EVID-REOPENING-$recordId-v$newVersion"

        val record = ControlledAccountReopeningRecord(
            recordId = recordId,
            tenantId = command.tenantId,
            playerId = command.playerId,
            restrictionType = command.restrictionType,
            status = ControlledReopeningStatus.CLOSED_OR_EXCLUDED,
            closedAt = now,
            closureExpiresAt = expiresAt,
            closureReason = command.reason,
            reopeningRequestedAt = null,
            reopeningCoolingDelayExpiresAt = null,
            coolingDelayDuration = DEFAULT_REOPENING_COOLING_DELAY,
            operatorReviewedAt = null,
            operatorReviewerId = null,
            operatorNotes = null,
            realityCheckRequired = true,
            realityCheckAcknowledgedAt = null,
            reopenedAt = null,
            initialDepositLimitMinorUnits = null,
            version = newVersion,
            evidenceReference = evidenceRef,
            createdAt = existing?.createdAt ?: now,
            updatedAt = now,
            semanticContract = CONTROLLED_ACCOUNT_REOPENING_CONTRACT,
        )

        val resultId = UUID.randomUUID()
        val result = ControlledAccountReopeningResult(
            resultId = resultId,
            record = record,
            serverTime = now,
            isDuplicate = false,
            isFinancialAuthorityCreated = false,
            semanticContract = CONTROLLED_ACCOUNT_REOPENING_CONTRACT,
        )

        val audit = AuditEvent(UUID.randomUUID(), recordId, command.tenantId, "ACCOUNT_CLOSED_OR_EXCLUDED", now, command.correlationId, command.causationId)
        val outbox = OutboxEvent(UUID.randomUUID(), recordId, command.tenantId, "ACCOUNT_CLOSED_OR_EXCLUDED", now)

        try {
            if (existing == null) {
                store.saveRecord(record, result, command.idempotencyKey, fp, audit, outbox)
            } else {
                store.updateRecord(record, result, command.idempotencyKey, fp, audit, outbox)
            }
        } catch (e: Exception) {
            throw AuthenticationFailure.Rejected(AuthErrorCode.DEPENDENCY_UNAVAILABLE)
        }

        return result
    }

    @Synchronized
    fun requestAccountReopening(command: RequestAccountReopeningCommand): ControlledAccountReopeningResult {
        ControlledAccountReopeningBinding.checkBound()

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
                    detail = "Client timestamp skew on reopening request",
                )
                throw AuthenticationFailure.Rejected(AuthErrorCode.INVALID)
            }
        }

        val fp = sha256("${command.tenantId}:${command.playerId}:${command.reason}:${command.expectedVersion}")

        val existingIdemp = store.findByIdempotency(command.tenantId, command.idempotencyKey)
        if (existingIdemp != null) {
            val (cachedFp, cachedResult) = existingIdemp
            if (cachedFp != fp) {
                throw AuthenticationFailure.Rejected(AuthErrorCode.CONFLICT)
            }
            val res = cachedResult as ControlledAccountReopeningResult
            return res.copy(isDuplicate = true)
        }

        val existing = store.findRecord(command.tenantId, command.playerId)
            ?: throw AuthenticationFailure.Rejected(AuthErrorCode.INVALID)

        if (existing.version != command.expectedVersion) {
            throw AuthenticationFailure.Rejected(AuthErrorCode.STALE)
        }

        // Permanent self-exclusion can NEVER be reopened
        if (existing.restrictionType == AccountRestrictionType.SELF_EXCLUSION_PERMANENT) {
            alertSink.sendAlert(
                tenantId = command.tenantId,
                reference = command.playerId,
                alertType = "PERMANENT_EXCLUSION_BREACH_ATTEMPT",
                reason = "PERMANENT_SELF_EXCLUSION_IRREVERSIBLE",
                detail = "Attempt to reopen permanent self-exclusion rejected",
            )
            throw AuthenticationFailure.Rejected(AuthErrorCode.FORBIDDEN)
        }

        // Premature reopening request before closure period has elapsed fails closed
        existing.closureExpiresAt?.let { expiresAt ->
            if (now.isBefore(expiresAt)) {
                alertSink.sendAlert(
                    tenantId = command.tenantId,
                    reference = command.playerId,
                    alertType = "PREMATURE_REOPENING_REQUEST",
                    reason = "CLOSURE_PERIOD_ACTIVE",
                    detail = "Reopening request attempted before definite exclusion expired at $expiresAt",
                )
                throw AuthenticationFailure.Rejected(AuthErrorCode.FORBIDDEN)
            }
        }

        // Reopening is delayed: enters mandatory cooling-off delay
        val coolingDelayExpiresAt = now.plus(existing.coolingDelayDuration)
        val newVersion = existing.version + 1L
        val evidenceRef = "EVID-REOPENING-${existing.recordId}-v$newVersion"

        val updated = existing.copy(
            status = ControlledReopeningStatus.PENDING_REOPENING_COOLING_OFF,
            reopeningRequestedAt = now,
            reopeningCoolingDelayExpiresAt = coolingDelayExpiresAt,
            version = newVersion,
            evidenceReference = evidenceRef,
            updatedAt = now,
        )

        val resultId = UUID.randomUUID()
        val result = ControlledAccountReopeningResult(
            resultId = resultId,
            record = updated,
            serverTime = now,
            isDuplicate = false,
            isFinancialAuthorityCreated = false,
            semanticContract = CONTROLLED_ACCOUNT_REOPENING_CONTRACT,
        )

        val audit = AuditEvent(UUID.randomUUID(), existing.recordId, command.tenantId, "ACCOUNT_REOPENING_REQUESTED", now, command.correlationId, command.causationId)
        val outbox = OutboxEvent(UUID.randomUUID(), existing.recordId, command.tenantId, "ACCOUNT_REOPENING_REQUESTED", now)

        try {
            store.updateRecord(updated, result, command.idempotencyKey, fp, audit, outbox)
        } catch (e: Exception) {
            throw AuthenticationFailure.Rejected(AuthErrorCode.DEPENDENCY_UNAVAILABLE)
        }

        return result
    }

    @Synchronized
    fun reviewAccountReopening(command: ReviewAccountReopeningCommand): ControlledAccountReopeningResult {
        ControlledAccountReopeningBinding.checkBound()

        if (command.tenantId.isBlank() || command.playerId.isBlank() || command.idempotencyKey.isBlank()) {
            throw AuthenticationFailure.Rejected(AuthErrorCode.INVALID)
        }

        // Operator review requires ADMIN role
        validatePrincipal(command.principal, command.tenantId, command.playerId, requireAdmin = true)

        val now = clock.instant()

        // Clock manipulation check
        command.clientReportedTimestamp?.let { clientTime ->
            val diff = Duration.between(now, clientTime).abs()
            if (diff > Duration.ofSeconds(60)) {
                alertSink.sendAlert(
                    tenantId = command.tenantId,
                    reference = command.playerId,
                    alertType = "CLOCK_MANIPULATION_DETECTED",
                    reason = "OPERATOR_TIMESTAMP_SKEW",
                    detail = "Operator timestamp skew detected on reopening review",
                )
                throw AuthenticationFailure.Rejected(AuthErrorCode.INVALID)
            }
        }

        // Legal values configured: initial deposit limit if set must be strictly positive and within legal bound
        command.initialDepositLimitMinorUnits?.let { limitVal ->
            if (limitVal <= 0L || limitVal > MAX_LEGAL_LIMIT_MINOR_UNITS) {
                throw AuthenticationFailure.Rejected(AuthErrorCode.INVALID)
            }
        }

        val fp = sha256("${command.tenantId}:${command.playerId}:${command.approved}:${command.operatorNotes}:${command.initialDepositLimitMinorUnits}:${command.expectedVersion}")

        val existingIdemp = store.findByIdempotency(command.tenantId, command.idempotencyKey)
        if (existingIdemp != null) {
            val (cachedFp, cachedResult) = existingIdemp
            if (cachedFp != fp) {
                throw AuthenticationFailure.Rejected(AuthErrorCode.CONFLICT)
            }
            val res = cachedResult as ControlledAccountReopeningResult
            return res.copy(isDuplicate = true)
        }

        val existing = store.findRecord(command.tenantId, command.playerId)
            ?: throw AuthenticationFailure.Rejected(AuthErrorCode.INVALID)

        if (existing.version != command.expectedVersion) {
            throw AuthenticationFailure.Rejected(AuthErrorCode.STALE)
        }

        val coolingExpires = existing.reopeningCoolingDelayExpiresAt
            ?: throw AuthenticationFailure.Rejected(AuthErrorCode.INVALID)

        // Monotonic server clock check: reopening cooling-off delay must have elapsed
        if (now.isBefore(coolingExpires)) {
            alertSink.sendAlert(
                tenantId = command.tenantId,
                reference = command.playerId,
                alertType = "PREMATURE_REOPENING_REVIEW",
                reason = "REOPENING_COOLING_DELAY_ACTIVE",
                detail = "Review attempted before cooling delay expiration at $coolingExpires (server time $now)",
            )
            throw AuthenticationFailure.Rejected(AuthErrorCode.FORBIDDEN)
        }

        // Monotonic progression check
        existing.reopeningRequestedAt?.let { reqAt ->
            if (now.isBefore(reqAt)) {
                alertSink.sendAlert(
                    tenantId = command.tenantId,
                    reference = command.playerId,
                    alertType = "CLOCK_MANIPULATION_DETECTED",
                    reason = "MONOTONIC_CLOCK_VIOLATION",
                    detail = "Server time $now is before reopening requested at $reqAt",
                )
                throw AuthenticationFailure.Rejected(AuthErrorCode.INVALID)
            }
        }

        val newVersion = existing.version + 1L
        val evidenceRef = "EVID-REOPENING-${existing.recordId}-v$newVersion"
        val reviewerId = command.principal?.id ?: "OPERATOR_ADMIN"

        val updated = if (command.approved) {
            // Reopening approved: enters mandatory reality check acknowledgment state
            // Initial lower deposit limit configured takes effect immediately ("decrease may be immediate")
            existing.copy(
                status = ControlledReopeningStatus.PENDING_REALITY_CHECK_ACK,
                operatorReviewedAt = now,
                operatorReviewerId = reviewerId,
                operatorNotes = command.operatorNotes,
                realityCheckRequired = true,
                initialDepositLimitMinorUnits = command.initialDepositLimitMinorUnits,
                version = newVersion,
                evidenceReference = evidenceRef,
                updatedAt = now,
            )
        } else {
            existing.copy(
                status = ControlledReopeningStatus.REJECTED,
                operatorReviewedAt = now,
                operatorReviewerId = reviewerId,
                operatorNotes = command.operatorNotes,
                version = newVersion,
                evidenceReference = evidenceRef,
                updatedAt = now,
            )
        }

        val resultId = UUID.randomUUID()
        val result = ControlledAccountReopeningResult(
            resultId = resultId,
            record = updated,
            serverTime = now,
            isDuplicate = false,
            isFinancialAuthorityCreated = false,
            semanticContract = CONTROLLED_ACCOUNT_REOPENING_CONTRACT,
        )

        val eventType = if (command.approved) "ACCOUNT_REOPENING_APPROVED" else "ACCOUNT_REOPENING_REJECTED"
        val audit = AuditEvent(UUID.randomUUID(), existing.recordId, command.tenantId, eventType, now, command.correlationId, command.causationId)
        val outbox = OutboxEvent(UUID.randomUUID(), existing.recordId, command.tenantId, eventType, now)

        try {
            store.updateRecord(updated, result, command.idempotencyKey, fp, audit, outbox)
        } catch (e: Exception) {
            throw AuthenticationFailure.Rejected(AuthErrorCode.DEPENDENCY_UNAVAILABLE)
        }

        return result
    }

    @Synchronized
    fun acknowledgeReopeningRealityCheck(command: AcknowledgeReopeningRealityCheckCommand): ControlledAccountReopeningResult {
        ControlledAccountReopeningBinding.checkBound()

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

        val fp = sha256("${command.tenantId}:${command.playerId}:${command.expectedVersion}")

        val existingIdemp = store.findByIdempotency(command.tenantId, command.idempotencyKey)
        if (existingIdemp != null) {
            val (cachedFp, cachedResult) = existingIdemp
            if (cachedFp != fp) {
                throw AuthenticationFailure.Rejected(AuthErrorCode.CONFLICT)
            }
            val res = cachedResult as ControlledAccountReopeningResult
            return res.copy(isDuplicate = true)
        }

        val existing = store.findRecord(command.tenantId, command.playerId)
            ?: throw AuthenticationFailure.Rejected(AuthErrorCode.INVALID)

        if (existing.version != command.expectedVersion) {
            throw AuthenticationFailure.Rejected(AuthErrorCode.STALE)
        }

        if (existing.status != ControlledReopeningStatus.PENDING_REALITY_CHECK_ACK) {
            throw AuthenticationFailure.Rejected(AuthErrorCode.INVALID)
        }

        val newVersion = existing.version + 1L
        val evidenceRef = "EVID-REOPENING-${existing.recordId}-v$newVersion"

        val updated = existing.copy(
            status = ControlledReopeningStatus.REOPENED,
            realityCheckAcknowledgedAt = now,
            realityCheckRequired = false,
            reopenedAt = now,
            version = newVersion,
            evidenceReference = evidenceRef,
            updatedAt = now,
        )

        val resultId = UUID.randomUUID()
        val result = ControlledAccountReopeningResult(
            resultId = resultId,
            record = updated,
            serverTime = now,
            isDuplicate = false,
            isFinancialAuthorityCreated = false,
            semanticContract = CONTROLLED_ACCOUNT_REOPENING_CONTRACT,
        )

        val audit = AuditEvent(UUID.randomUUID(), existing.recordId, command.tenantId, "ACCOUNT_REOPENED_CONFIRMED", now, command.correlationId, command.causationId)
        val outbox = OutboxEvent(UUID.randomUUID(), existing.recordId, command.tenantId, "ACCOUNT_REOPENED_CONFIRMED", now)

        try {
            store.updateRecord(updated, result, command.idempotencyKey, fp, audit, outbox)
        } catch (e: Exception) {
            throw AuthenticationFailure.Rejected(AuthErrorCode.DEPENDENCY_UNAVAILABLE)
        }

        return result
    }

    @Synchronized
    fun cancelReopeningRequest(command: CancelReopeningRequestCommand): ControlledAccountReopeningResult {
        ControlledAccountReopeningBinding.checkBound()

        if (command.tenantId.isBlank() || command.playerId.isBlank() || command.idempotencyKey.isBlank()) {
            throw AuthenticationFailure.Rejected(AuthErrorCode.INVALID)
        }

        validatePrincipal(command.principal, command.tenantId, command.playerId)

        val now = clock.instant()
        val fp = sha256("${command.tenantId}:${command.playerId}:${command.reason}:${command.expectedVersion}")

        val existingIdemp = store.findByIdempotency(command.tenantId, command.idempotencyKey)
        if (existingIdemp != null) {
            val (cachedFp, cachedResult) = existingIdemp
            if (cachedFp != fp) {
                throw AuthenticationFailure.Rejected(AuthErrorCode.CONFLICT)
            }
            val res = cachedResult as ControlledAccountReopeningResult
            return res.copy(isDuplicate = true)
        }

        val existing = store.findRecord(command.tenantId, command.playerId)
            ?: throw AuthenticationFailure.Rejected(AuthErrorCode.INVALID)

        if (existing.version != command.expectedVersion) {
            throw AuthenticationFailure.Rejected(AuthErrorCode.STALE)
        }

        if (existing.status !in setOf(
                ControlledReopeningStatus.PENDING_REOPENING_COOLING_OFF,
                ControlledReopeningStatus.PENDING_OPERATOR_REVIEW,
                ControlledReopeningStatus.PENDING_REALITY_CHECK_ACK,
            )
        ) {
            throw AuthenticationFailure.Rejected(AuthErrorCode.INVALID)
        }

        val newVersion = existing.version + 1L
        val evidenceRef = "EVID-REOPENING-${existing.recordId}-v$newVersion"

        val updated = existing.copy(
            status = ControlledReopeningStatus.CLOSED_OR_EXCLUDED,
            reopeningRequestedAt = null,
            reopeningCoolingDelayExpiresAt = null,
            operatorReviewedAt = null,
            operatorReviewerId = null,
            operatorNotes = null,
            realityCheckRequired = true,
            version = newVersion,
            evidenceReference = evidenceRef,
            updatedAt = now,
        )

        val resultId = UUID.randomUUID()
        val result = ControlledAccountReopeningResult(
            resultId = resultId,
            record = updated,
            serverTime = now,
            isDuplicate = false,
            isFinancialAuthorityCreated = false,
            semanticContract = CONTROLLED_ACCOUNT_REOPENING_CONTRACT,
        )

        val audit = AuditEvent(UUID.randomUUID(), existing.recordId, command.tenantId, "ACCOUNT_REOPENING_CANCELLED", now, command.correlationId, command.causationId)
        val outbox = OutboxEvent(UUID.randomUUID(), existing.recordId, command.tenantId, "ACCOUNT_REOPENING_CANCELLED", now)

        try {
            store.updateRecord(updated, result, command.idempotencyKey, fp, audit, outbox)
        } catch (e: Exception) {
            throw AuthenticationFailure.Rejected(AuthErrorCode.DEPENDENCY_UNAVAILABLE)
        }

        return result
    }

    @Synchronized
    fun checkReopeningStatus(query: CheckReopeningStatusQuery): CheckReopeningStatusResult {
        ControlledAccountReopeningBinding.checkBound()

        if (query.tenantId.isBlank() || query.playerId.isBlank()) {
            throw AuthenticationFailure.Rejected(AuthErrorCode.INVALID)
        }

        validatePrincipal(query.principal, query.tenantId, query.playerId)

        val existing = store.findRecord(query.tenantId, query.playerId)
            ?: throw AuthenticationFailure.Rejected(AuthErrorCode.INVALID)

        val now = clock.instant()

        val isCoolingActive = if (existing.status == ControlledReopeningStatus.PENDING_REOPENING_COOLING_OFF && existing.reopeningCoolingDelayExpiresAt != null) {
            now.isBefore(existing.reopeningCoolingDelayExpiresAt)
        } else {
            false
        }

        val realityCheckPending = existing.status == ControlledReopeningStatus.PENDING_REALITY_CHECK_ACK

        return CheckReopeningStatusResult(
            isReopened = existing.status == ControlledReopeningStatus.REOPENED,
            status = existing.status,
            restrictionType = existing.restrictionType,
            coolingDelayActive = isCoolingActive,
            coolingDelayExpiresAt = existing.reopeningCoolingDelayExpiresAt,
            realityCheckPending = realityCheckPending,
            evidenceReference = existing.evidenceReference,
            serverTime = now,
            semanticContract = CONTROLLED_ACCOUNT_REOPENING_CONTRACT,
        )
    }
}
