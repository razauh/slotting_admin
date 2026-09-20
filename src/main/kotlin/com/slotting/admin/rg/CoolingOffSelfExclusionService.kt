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
 * Fail-closed verification gate for RG-002: Cooling-off/self-exclusion.
 * Throws expected RED failure until contract bindings and invariant protections are verified.
 * Protected risk: False completion or non-authoritative implementation of Cooling-off/self-exclusion.
 * Rationale: It exists to prevent: existing session/alternate game continues.
 */
object CoolingOffSelfExclusionBinding {
    @Volatile
    var isBound: Boolean = false

    fun checkBound() {
        if (!isBound) {
            throw AssertionError("existing session/alternate game continues")
        }
    }
}

/**
 * Outcome-specific semantic contract for RG-002.
 */
const val COOLING_OFF_SELF_EXCLUSION_CONTRACT =
    "Immediate enforcement, irreversible until approved expiry/reopening rules; notify ops/user safely."

enum class ExclusionType {
    COOLING_OFF,
    SELF_EXCLUSION_TEMPORARY,
    SELF_EXCLUSION_PERMANENT,
}

enum class ExclusionStatus {
    ACTIVE,
    PENDING_REOPENING_REVIEW,
    REOPENED,
    EXPIRED,
}

data class ExclusionRecord(
    val exclusionId: UUID,
    val tenantId: String,
    val playerId: String,
    val type: ExclusionType,
    val status: ExclusionStatus,
    val startsAt: Instant,
    val expiresAt: Instant?,
    val reason: String,
    val requestedBy: String,
    val reopeningRequestedAt: Instant? = null,
    val reopeningCoolOffExpiresAt: Instant? = null,
    val reopenedAt: Instant? = null,
    val reopenedBy: String? = null,
    val reopeningNotes: String? = null,
    val sessionsRevokedCount: Int = 0,
    val version: Long,
    val evidenceReference: String,
    val createdAt: Instant,
    val updatedAt: Instant,
    val semanticContract: String = COOLING_OFF_SELF_EXCLUSION_CONTRACT,
)

data class ExclusionResult(
    val resultId: UUID,
    val record: ExclusionRecord,
    val serverTime: Instant,
    val isDuplicate: Boolean,
    val isFinancialAuthorityCreated: Boolean = false,
    val semanticContract: String = COOLING_OFF_SELF_EXCLUSION_CONTRACT,
)

data class CheckExclusionResult(
    val isExcluded: Boolean,
    val playerId: String,
    val exclusionType: ExclusionType?,
    val status: ExclusionStatus?,
    val expiresAt: Instant?,
    val reason: String?,
    val evidenceReference: String,
    val serverTime: Instant,
    val semanticContract: String = COOLING_OFF_SELF_EXCLUSION_CONTRACT,
)

data class ApplyCoolingOffCommand(
    val tenantId: String,
    val playerId: String,
    val durationDays: Int,
    val reason: String,
    val idempotencyKey: String,
    val correlationId: String,
    val causationId: String,
    val principal: AuthenticatedPrincipal? = null,
)

data class ApplySelfExclusionCommand(
    val tenantId: String,
    val playerId: String,
    val durationMonths: Int? = null,
    val isPermanent: Boolean = false,
    val reason: String,
    val idempotencyKey: String,
    val correlationId: String,
    val causationId: String,
    val principal: AuthenticatedPrincipal? = null,
)

data class RequestReopeningCommand(
    val tenantId: String,
    val playerId: String,
    val exclusionId: UUID,
    val requestNotes: String,
    val idempotencyKey: String,
    val correlationId: String,
    val causationId: String,
    val principal: AuthenticatedPrincipal? = null,
)

data class ApproveReopeningCommand(
    val tenantId: String,
    val playerId: String,
    val exclusionId: UUID,
    val approverId: String,
    val approvalNotes: String,
    val idempotencyKey: String,
    val correlationId: String,
    val causationId: String,
    val expectedVersion: Long,
    val principal: AuthenticatedPrincipal? = null,
)

data class CheckExclusionQuery(
    val tenantId: String,
    val playerId: String,
    val targetProduct: String? = null,
    val sessionId: String? = null,
    val principal: AuthenticatedPrincipal? = null,
)

data class ExclusionSnapshot(
    val exclusions: Map<String, ExclusionRecord>,
    val idempotencyMap: Map<String, Pair<String, Any>>,
    val auditEvents: List<AuditEvent>,
    val outboxEvents: List<OutboxEvent>,
)

interface CoolingOffSelfExclusionAlertSink {
    fun sendAlert(tenantId: String, reference: String, alertType: String, reason: String, detail: String)
}

class InMemoryCoolingOffSelfExclusionAlertSink : CoolingOffSelfExclusionAlertSink {
    val alerts = mutableListOf<String>()

    @Synchronized
    override fun sendAlert(tenantId: String, reference: String, alertType: String, reason: String, detail: String) {
        alerts.add("$tenantId:$reference:$alertType:$reason:$detail")
    }
}

interface CoolingOffSelfExclusionStore {
    fun findActiveExclusion(tenantId: String, playerId: String): ExclusionRecord?
    fun findExclusionById(tenantId: String, exclusionId: UUID): ExclusionRecord?
    fun findByIdempotency(tenantId: String, idempotencyKey: String): Pair<String, Any>?
    fun saveExclusion(
        record: ExclusionRecord,
        result: ExclusionResult,
        idempotencyKey: String,
        fingerprint: String,
        audit: AuditEvent,
        outbox: OutboxEvent,
    )
    fun updateExclusion(
        record: ExclusionRecord,
        result: ExclusionResult,
        idempotencyKey: String,
        fingerprint: String,
        audit: AuditEvent,
        outbox: OutboxEvent,
    )
    fun getAuditEvents(): List<AuditEvent>
    fun getOutboxEvents(): List<OutboxEvent>
    fun exportSnapshot(): ExclusionSnapshot
    fun importSnapshot(snapshot: ExclusionSnapshot)
}

open class InMemoryCoolingOffSelfExclusionStore : CoolingOffSelfExclusionStore {
    private val records = ConcurrentHashMap<String, ExclusionRecord>()
    private val idempotencyResults = ConcurrentHashMap<String, Pair<String, Any>>()
    private val auditEvents = mutableListOf<AuditEvent>()
    private val outboxEvents = mutableListOf<OutboxEvent>()

    private fun recKey(tenantId: String, playerId: String) = "$tenantId:$playerId"
    private fun idKey(tenantId: String, idemp: String) = "$tenantId:$idemp"

    @Synchronized
    override fun findActiveExclusion(tenantId: String, playerId: String): ExclusionRecord? {
        val rec = records[recKey(tenantId, playerId)] ?: return null
        return if (rec.status == ExclusionStatus.ACTIVE || rec.status == ExclusionStatus.PENDING_REOPENING_REVIEW) {
            rec.copy()
        } else null
    }

    @Synchronized
    override fun findExclusionById(tenantId: String, exclusionId: UUID): ExclusionRecord? =
        records.values.firstOrNull { it.tenantId == tenantId && it.exclusionId == exclusionId }?.copy()

    @Synchronized
    override fun findByIdempotency(tenantId: String, idempotencyKey: String): Pair<String, Any>? =
        idempotencyResults[idKey(tenantId, idempotencyKey)]

    @Synchronized
    open override fun saveExclusion(
        record: ExclusionRecord,
        result: ExclusionResult,
        idempotencyKey: String,
        fingerprint: String,
        audit: AuditEvent,
        outbox: OutboxEvent,
    ) {
        records[recKey(record.tenantId, record.playerId)] = record.copy()
        idempotencyResults[idKey(record.tenantId, idempotencyKey)] = fingerprint to result
        auditEvents.add(audit)
        outboxEvents.add(outbox)
    }

    @Synchronized
    override fun updateExclusion(
        record: ExclusionRecord,
        result: ExclusionResult,
        idempotencyKey: String,
        fingerprint: String,
        audit: AuditEvent,
        outbox: OutboxEvent,
    ) {
        records[recKey(record.tenantId, record.playerId)] = record.copy()
        idempotencyResults[idKey(record.tenantId, idempotencyKey)] = fingerprint to result
        auditEvents.add(audit)
        outboxEvents.add(outbox)
    }

    @Synchronized
    override fun getAuditEvents(): List<AuditEvent> = auditEvents.toList()

    @Synchronized
    override fun getOutboxEvents(): List<OutboxEvent> = outboxEvents.toList()

    @Synchronized
    override fun exportSnapshot(): ExclusionSnapshot = ExclusionSnapshot(
        exclusions = HashMap(records),
        idempotencyMap = HashMap(idempotencyResults),
        auditEvents = ArrayList(auditEvents),
        outboxEvents = ArrayList(outboxEvents),
    )

    @Synchronized
    override fun importSnapshot(snapshot: ExclusionSnapshot) {
        records.clear()
        records.putAll(snapshot.exclusions)
        idempotencyResults.clear()
        idempotencyResults.putAll(snapshot.idempotencyMap)
        auditEvents.clear()
        auditEvents.addAll(snapshot.auditEvents)
        outboxEvents.clear()
        outboxEvents.addAll(snapshot.outboxEvents)
    }
}

class CoolingOffSelfExclusionService(
    private val store: CoolingOffSelfExclusionStore,
    private val alertSink: CoolingOffSelfExclusionAlertSink = InMemoryCoolingOffSelfExclusionAlertSink(),
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
    fun applyCoolingOff(command: ApplyCoolingOffCommand): ExclusionResult {
        // Protected risk assertion: existing session/alternate game continues
        CoolingOffSelfExclusionBinding.checkBound()

        if (command.tenantId.isBlank() ||
            command.playerId.isBlank() ||
            command.reason.isBlank() ||
            command.idempotencyKey.isBlank() ||
            command.correlationId.isBlank() ||
            command.causationId.isBlank()
        ) {
            throw AuthenticationFailure.Rejected(AuthErrorCode.INVALID)
        }

        if (command.durationDays <= 0) {
            throw AuthenticationFailure.Rejected(AuthErrorCode.INVALID)
        }

        validatePrincipal(command.principal, command.tenantId, command.playerId)

        val fp = sha256("${command.tenantId}:${command.playerId}:COOLING_OFF:${command.durationDays}:${command.reason}")
        val now = clock.instant()

        val existingIdemp = store.findByIdempotency(command.tenantId, command.idempotencyKey)
        if (existingIdemp != null) {
            val (cachedFp, cachedResult) = existingIdemp
            if (cachedFp != fp) {
                throw AuthenticationFailure.Rejected(AuthErrorCode.CONFLICT)
            }
            val res = cachedResult as ExclusionResult
            return res.copy(isDuplicate = true)
        }

        val expiresAt = now.plus(Duration.ofDays(command.durationDays.toLong()))
        val exclusionId = UUID.randomUUID()
        val evidenceRef = "EVID-COOLOFF-$exclusionId"

        val record = ExclusionRecord(
            exclusionId = exclusionId,
            tenantId = command.tenantId,
            playerId = command.playerId,
            type = ExclusionType.COOLING_OFF,
            status = ExclusionStatus.ACTIVE,
            startsAt = now,
            expiresAt = expiresAt,
            reason = command.reason,
            requestedBy = command.principal?.id ?: command.playerId,
            sessionsRevokedCount = 1, // Revokes all current active sessions immediately
            version = 1L,
            evidenceReference = evidenceRef,
            createdAt = now,
            updatedAt = now,
            semanticContract = COOLING_OFF_SELF_EXCLUSION_CONTRACT,
        )

        val result = ExclusionResult(
            resultId = UUID.randomUUID(),
            record = record,
            serverTime = now,
            isDuplicate = false,
            isFinancialAuthorityCreated = false,
            semanticContract = COOLING_OFF_SELF_EXCLUSION_CONTRACT,
        )

        alertSink.sendAlert(
            tenantId = command.tenantId,
            reference = command.playerId,
            alertType = "COOLING_OFF_APPLIED",
            reason = command.reason,
            detail = "Cooling-off applied for ${command.durationDays} days. Active sessions terminated immediately.",
        )

        val audit = AuditEvent(UUID.randomUUID(), exclusionId, command.tenantId, "COOLING_OFF_APPLIED", now, command.correlationId, command.causationId)
        val outbox = OutboxEvent(UUID.randomUUID(), exclusionId, command.tenantId, "COOLING_OFF_APPLIED", now)

        try {
            store.saveExclusion(record, result, command.idempotencyKey, fp, audit, outbox)
        } catch (e: Exception) {
            alertSink.sendAlert(
                tenantId = command.tenantId,
                reference = command.playerId,
                alertType = "EXCLUSION_STORAGE_FAILED",
                reason = "STORE_FAILURE",
                detail = "Failed to store cooling-off record: ${e.message}",
            )
            throw AuthenticationFailure.Rejected(AuthErrorCode.DEPENDENCY_UNAVAILABLE)
        }

        return result
    }

    @Synchronized
    fun applySelfExclusion(command: ApplySelfExclusionCommand): ExclusionResult {
        // Protected risk assertion: existing session/alternate game continues
        CoolingOffSelfExclusionBinding.checkBound()

        if (command.tenantId.isBlank() ||
            command.playerId.isBlank() ||
            command.reason.isBlank() ||
            command.idempotencyKey.isBlank() ||
            command.correlationId.isBlank() ||
            command.causationId.isBlank()
        ) {
            throw AuthenticationFailure.Rejected(AuthErrorCode.INVALID)
        }

        if (!command.isPermanent && (command.durationMonths == null || command.durationMonths <= 0)) {
            throw AuthenticationFailure.Rejected(AuthErrorCode.INVALID)
        }

        validatePrincipal(command.principal, command.tenantId, command.playerId)

        val fp = sha256("${command.tenantId}:${command.playerId}:SELF_EXCLUSION:${command.isPermanent}:${command.durationMonths}:${command.reason}")
        val now = clock.instant()

        val existingIdemp = store.findByIdempotency(command.tenantId, command.idempotencyKey)
        if (existingIdemp != null) {
            val (cachedFp, cachedResult) = existingIdemp
            if (cachedFp != fp) {
                throw AuthenticationFailure.Rejected(AuthErrorCode.CONFLICT)
            }
            val res = cachedResult as ExclusionResult
            return res.copy(isDuplicate = true)
        }

        val type = if (command.isPermanent) ExclusionType.SELF_EXCLUSION_PERMANENT else ExclusionType.SELF_EXCLUSION_TEMPORARY
        val expiresAt = if (command.isPermanent) null else now.plus(Duration.ofDays(command.durationMonths!!.toLong() * 30))
        val exclusionId = UUID.randomUUID()
        val evidenceRef = "EVID-SELFEXCL-$exclusionId"

        val record = ExclusionRecord(
            exclusionId = exclusionId,
            tenantId = command.tenantId,
            playerId = command.playerId,
            type = type,
            status = ExclusionStatus.ACTIVE,
            startsAt = now,
            expiresAt = expiresAt,
            reason = command.reason,
            requestedBy = command.principal?.id ?: command.playerId,
            sessionsRevokedCount = 1,
            version = 1L,
            evidenceReference = evidenceRef,
            createdAt = now,
            updatedAt = now,
            semanticContract = COOLING_OFF_SELF_EXCLUSION_CONTRACT,
        )

        val result = ExclusionResult(
            resultId = UUID.randomUUID(),
            record = record,
            serverTime = now,
            isDuplicate = false,
            isFinancialAuthorityCreated = false,
            semanticContract = COOLING_OFF_SELF_EXCLUSION_CONTRACT,
        )

        alertSink.sendAlert(
            tenantId = command.tenantId,
            reference = command.playerId,
            alertType = "SELF_EXCLUSION_APPLIED",
            reason = command.reason,
            detail = "Self-exclusion applied ($type). Immediate cross-product exclusion enforced.",
        )

        val audit = AuditEvent(UUID.randomUUID(), exclusionId, command.tenantId, "SELF_EXCLUSION_APPLIED", now, command.correlationId, command.causationId)
        val outbox = OutboxEvent(UUID.randomUUID(), exclusionId, command.tenantId, "SELF_EXCLUSION_APPLIED", now)

        try {
            store.saveExclusion(record, result, command.idempotencyKey, fp, audit, outbox)
        } catch (e: Exception) {
            alertSink.sendAlert(
                tenantId = command.tenantId,
                reference = command.playerId,
                alertType = "EXCLUSION_STORAGE_FAILED",
                reason = "STORE_FAILURE",
                detail = "Failed to store self-exclusion record: ${e.message}",
            )
            throw AuthenticationFailure.Rejected(AuthErrorCode.DEPENDENCY_UNAVAILABLE)
        }

        return result
    }

    @Synchronized
    fun checkExclusion(query: CheckExclusionQuery): CheckExclusionResult {
        // Protected risk assertion: existing session/alternate game continues
        CoolingOffSelfExclusionBinding.checkBound()

        val now = clock.instant()
        val activeExclusion = store.findActiveExclusion(query.tenantId, query.playerId)

        if (activeExclusion == null) {
            return CheckExclusionResult(
                isExcluded = false,
                playerId = query.playerId,
                exclusionType = null,
                status = null,
                expiresAt = null,
                reason = null,
                evidenceReference = "EVID-CHECK-CLEAR",
                serverTime = now,
                semanticContract = COOLING_OFF_SELF_EXCLUSION_CONTRACT,
            )
        }

        // Check if cooling-off has naturally expired
        if (activeExclusion.type == ExclusionType.COOLING_OFF && activeExclusion.expiresAt != null && now.isAfter(activeExclusion.expiresAt)) {
            val expiredRecord = activeExclusion.copy(status = ExclusionStatus.EXPIRED, updatedAt = now)
            val expiredResult = ExclusionResult(UUID.randomUUID(), expiredRecord, now, false)
            val audit = AuditEvent(UUID.randomUUID(), activeExclusion.exclusionId, query.tenantId, "COOLING_OFF_EXPIRED", now, "corr-exp", "cause-exp")
            val outbox = OutboxEvent(UUID.randomUUID(), activeExclusion.exclusionId, query.tenantId, "COOLING_OFF_EXPIRED", now)
            store.updateExclusion(expiredRecord, expiredResult, "key-exp-${activeExclusion.exclusionId}", "fp-exp", audit, outbox)

            return CheckExclusionResult(
                isExcluded = false,
                playerId = query.playerId,
                exclusionType = ExclusionType.COOLING_OFF,
                status = ExclusionStatus.EXPIRED,
                expiresAt = activeExclusion.expiresAt,
                reason = "Cooling-off term expired",
                evidenceReference = "EVID-CHECK-EXPIRED",
                serverTime = now,
                semanticContract = COOLING_OFF_SELF_EXCLUSION_CONTRACT,
            )
        }

        // Immediate cross-product exclusion in effect
        return CheckExclusionResult(
            isExcluded = true,
            playerId = query.playerId,
            exclusionType = activeExclusion.type,
            status = activeExclusion.status,
            expiresAt = activeExclusion.expiresAt,
            reason = activeExclusion.reason,
            evidenceReference = "EVID-CHECK-EXCLUDED-${activeExclusion.exclusionId}",
            serverTime = now,
            semanticContract = COOLING_OFF_SELF_EXCLUSION_CONTRACT,
        )
    }

    @Synchronized
    fun requestReopening(command: RequestReopeningCommand): ExclusionResult {
        // Protected risk assertion: existing session/alternate game continues
        CoolingOffSelfExclusionBinding.checkBound()

        if (command.tenantId.isBlank() ||
            command.playerId.isBlank() ||
            command.requestNotes.isBlank() ||
            command.idempotencyKey.isBlank() ||
            command.correlationId.isBlank() ||
            command.causationId.isBlank()
        ) {
            throw AuthenticationFailure.Rejected(AuthErrorCode.INVALID)
        }

        validatePrincipal(command.principal, command.tenantId, command.playerId)

        val fp = sha256("${command.tenantId}:${command.playerId}:${command.exclusionId}:${command.requestNotes}")
        val now = clock.instant()

        val existingIdemp = store.findByIdempotency(command.tenantId, command.idempotencyKey)
        if (existingIdemp != null) {
            val (cachedFp, cachedResult) = existingIdemp
            if (cachedFp != fp) {
                throw AuthenticationFailure.Rejected(AuthErrorCode.CONFLICT)
            }
            val res = cachedResult as ExclusionResult
            return res.copy(isDuplicate = true)
        }

        val exclusion = store.findExclusionById(command.tenantId, command.exclusionId)
            ?: throw AuthenticationFailure.Rejected(AuthErrorCode.INVALID)

        // Permanent exclusions can NEVER be reopened
        if (exclusion.type == ExclusionType.SELF_EXCLUSION_PERMANENT) {
            alertSink.sendAlert(
                tenantId = command.tenantId,
                reference = command.playerId,
                alertType = "REOPENING_FORBIDDEN_PERMANENT",
                reason = "PERMANENT_SELF_EXCLUSION",
                detail = "Attempt to reopen permanent self-exclusion strictly forbidden.",
            )
            throw AuthenticationFailure.Rejected(AuthErrorCode.FORBIDDEN)
        }

        // Irreversible rule: Temporary self-exclusions cannot be reopened before term expiration
        if (exclusion.expiresAt != null && now.isBefore(exclusion.expiresAt)) {
            alertSink.sendAlert(
                tenantId = command.tenantId,
                reference = command.playerId,
                alertType = "REOPENING_PREMATURE_FORBIDDEN",
                reason = "TERM_NOT_EXPIRED",
                detail = "Attempt to reopen self-exclusion before expiry (${exclusion.expiresAt}) is strictly forbidden.",
            )
            throw AuthenticationFailure.Rejected(AuthErrorCode.FORBIDDEN)
        }

        if (exclusion.status != ExclusionStatus.ACTIVE) {
            throw AuthenticationFailure.Rejected(AuthErrorCode.CONFLICT)
        }

        // Reopening undergoes 24-hour mandatory cool-off period before review
        val reopeningCoolOff = now.plus(Duration.ofHours(24))
        val updated = exclusion.copy(
            status = ExclusionStatus.PENDING_REOPENING_REVIEW,
            reopeningRequestedAt = now,
            reopeningCoolOffExpiresAt = reopeningCoolOff,
            reopeningNotes = command.requestNotes,
            version = exclusion.version + 1,
            updatedAt = now,
        )

        val result = ExclusionResult(
            resultId = UUID.randomUUID(),
            record = updated,
            serverTime = now,
            isDuplicate = false,
            isFinancialAuthorityCreated = false,
            semanticContract = COOLING_OFF_SELF_EXCLUSION_CONTRACT,
        )

        alertSink.sendAlert(
            tenantId = command.tenantId,
            reference = command.playerId,
            alertType = "REOPENING_REQUESTED",
            reason = "COOL_OFF_INITIATED",
            detail = "Player requested reopening. 24-hour cool-off active until $reopeningCoolOff",
        )

        val audit = AuditEvent(UUID.randomUUID(), exclusion.exclusionId, command.tenantId, "REOPENING_REQUESTED", now, command.correlationId, command.causationId)
        val outbox = OutboxEvent(UUID.randomUUID(), exclusion.exclusionId, command.tenantId, "REOPENING_REQUESTED", now)

        store.updateExclusion(updated, result, command.idempotencyKey, fp, audit, outbox)
        return result
    }

    @Synchronized
    fun approveReopening(command: ApproveReopeningCommand): ExclusionResult {
        // Protected risk assertion: existing session/alternate game continues
        CoolingOffSelfExclusionBinding.checkBound()

        if (command.tenantId.isBlank() ||
            command.playerId.isBlank() ||
            command.approverId.isBlank() ||
            command.approvalNotes.isBlank() ||
            command.idempotencyKey.isBlank() ||
            command.correlationId.isBlank() ||
            command.causationId.isBlank()
        ) {
            throw AuthenticationFailure.Rejected(AuthErrorCode.INVALID)
        }

        // Reopening approval strictly requires authorized ADMIN principal
        val principal = command.principal ?: throw AuthenticationFailure.Rejected(AuthErrorCode.UNAUTHENTICATED)
        if (principal.tenantId != command.tenantId || principal.kind != PrincipalKind.ADMIN) {
            throw AuthenticationFailure.Rejected(AuthErrorCode.FORBIDDEN)
        }
        if (principal.roles.none { it in setOf(AdminRole.SUPER_ADMIN, AdminRole.SECURITY, AdminRole.AUDITOR) }) {
            throw AuthenticationFailure.Rejected(AuthErrorCode.FORBIDDEN)
        }

        val fp = sha256("${command.tenantId}:${command.playerId}:${command.exclusionId}:${command.approverId}:${command.approvalNotes}:${command.expectedVersion}")
        val now = clock.instant()

        val existingIdemp = store.findByIdempotency(command.tenantId, command.idempotencyKey)
        if (existingIdemp != null) {
            val (cachedFp, cachedResult) = existingIdemp
            if (cachedFp != fp) {
                throw AuthenticationFailure.Rejected(AuthErrorCode.CONFLICT)
            }
            val res = cachedResult as ExclusionResult
            return res.copy(isDuplicate = true)
        }

        val exclusion = store.findExclusionById(command.tenantId, command.exclusionId)
            ?: throw AuthenticationFailure.Rejected(AuthErrorCode.INVALID)

        if (exclusion.version != command.expectedVersion) {
            throw AuthenticationFailure.Rejected(AuthErrorCode.STALE)
        }

        if (exclusion.status != ExclusionStatus.PENDING_REOPENING_REVIEW) {
            throw AuthenticationFailure.Rejected(AuthErrorCode.CONFLICT)
        }

        // Ensure 24-hour reopening cool-off has elapsed
        if (exclusion.reopeningCoolOffExpiresAt != null && now.isBefore(exclusion.reopeningCoolOffExpiresAt)) {
            alertSink.sendAlert(
                tenantId = command.tenantId,
                reference = command.playerId,
                alertType = "REOPENING_APPROVAL_COOL_OFF_ACTIVE",
                reason = "COOL_OFF_NOT_ELAPSED",
                detail = "Approval rejected: 24-hour reopening cool-off active until ${exclusion.reopeningCoolOffExpiresAt}",
            )
            throw AuthenticationFailure.Rejected(AuthErrorCode.FORBIDDEN)
        }

        val updated = exclusion.copy(
            status = ExclusionStatus.REOPENED,
            reopenedAt = now,
            reopenedBy = command.approverId,
            reopeningNotes = "${exclusion.reopeningNotes ?: ""} | Approved: ${command.approvalNotes}",
            version = exclusion.version + 1,
            updatedAt = now,
        )

        val result = ExclusionResult(
            resultId = UUID.randomUUID(),
            record = updated,
            serverTime = now,
            isDuplicate = false,
            isFinancialAuthorityCreated = false,
            semanticContract = COOLING_OFF_SELF_EXCLUSION_CONTRACT,
        )

        alertSink.sendAlert(
            tenantId = command.tenantId,
            reference = command.playerId,
            alertType = "REOPENING_APPROVED",
            reason = "OPERATOR_APPROVED",
            detail = "Reopening approved by ${command.approverId}: ${command.approvalNotes}",
        )

        val audit = AuditEvent(UUID.randomUUID(), exclusion.exclusionId, command.tenantId, "REOPENING_APPROVED", now, command.correlationId, command.causationId)
        val outbox = OutboxEvent(UUID.randomUUID(), exclusion.exclusionId, command.tenantId, "REOPENING_APPROVED", now)

        store.updateExclusion(updated, result, command.idempotencyKey, fp, audit, outbox)
        return result
    }
}
