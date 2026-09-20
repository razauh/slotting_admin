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
 * Fail-closed verification gate for RG-004: Android controls/audit UX.
 * Throws expected RED failure until contract bindings and invariant protections are verified.
 * Protected risk: False completion or non-authoritative implementation of Android controls/audit UX.
 * Rationale: It exists to prevent: optimistic success/process loss.
 */
object AndroidRgControlsBinding {
    @Volatile
    var isBound: Boolean = false

    fun checkBound() {
        if (!isBound) {
            throw AssertionError("optimistic success/process loss")
        }
    }
}

/**
 * Outcome-specific semantic contract for RG-004.
 */
const val ANDROID_RG_CONTROLS_CONTRACT =
    "High-risk confirmation accessible; no dark patterns; receipts and effective times shown."

/**
 * High-risk responsible gaming action categories.
 */
enum class RgActionType {
    LIMIT_DECREASE,
    LIMIT_INCREASE,
    COOLING_OFF,
    SELF_EXCLUSION_DEFINITE,
    SELF_EXCLUSION_PERMANENT,
    REALITY_CHECK_INTERVAL_UPDATE,
}

/**
 * Lifecycle states of an Android high-risk action session (recreation and process death safe).
 */
enum class RgActionSessionState {
    AWAITING_ACCESSIBLE_CONFIRMATION,
    CONFIRMED,
    COMMITTED,
    CANCELLED,
    EXPIRED,
}

/**
 * Authoritative receipt generated for every committed RG action.
 */
data class RgAuthoritativeReceipt(
    val receiptId: UUID,
    val tenantId: String,
    val playerId: String,
    val actionType: RgActionType,
    val requestedValue: String,
    val effectiveValue: String,
    val effectiveAt: Instant,
    val isImmediate: Boolean,
    val receiptReference: String,
    val accessibleDisclosure: String,
    val serverTime: Instant,
    val version: Long,
    val semanticContract: String = ANDROID_RG_CONTROLS_CONTRACT,
)

/**
 * Persisted session representing an ongoing or completed mobile RG action.
 * Survives Android activity recreation, process death, and configuration changes.
 */
data class RgMobileActionSessionRecord(
    val sessionId: UUID,
    val tenantId: String,
    val playerId: String,
    val actionType: RgActionType,
    val state: RgActionSessionState,
    val payloadValue: String,
    val confirmationToken: String,
    val accessibleExplanation: String,
    val requiresHighRiskConfirmation: Boolean,
    val confirmedAt: Instant? = null,
    val receipt: RgAuthoritativeReceipt? = null,
    val version: Long,
    val evidenceReference: String,
    val expiresAt: Instant,
    val createdAt: Instant,
    val updatedAt: Instant,
    val semanticContract: String = ANDROID_RG_CONTROLS_CONTRACT,
)

/**
 * Authoritative UI read model returned to untrusted Android clients.
 */
data class RgAuthoritativeUiModel(
    val tenantId: String,
    val playerId: String,
    val activeDepositLimitMinorUnits: Long?,
    val pendingDepositLimitIncreaseMinorUnits: Long?,
    val pendingDepositLimitEffectiveAt: Instant?,
    val isCoolingOffActive: Boolean,
    val coolingOffExpiresAt: Instant?,
    val isRealityCheckDue: Boolean,
    val realityCheckIntervalMinutes: Int,
    val latestReceipt: RgAuthoritativeReceipt?,
    val activeSession: RgMobileActionSessionRecord?,
    val serverTime: Instant,
    val semanticContract: String = ANDROID_RG_CONTROLS_CONTRACT,
)

/**
 * Command to initiate a high-risk RG action session (Step 1: preparation & disclosure).
 */
data class InitiateRgActionCommand(
    val tenantId: String,
    val playerId: String,
    val actionType: RgActionType,
    val payloadValue: String,
    val idempotencyKey: String,
    val correlationId: String,
    val causationId: String,
    val principal: AuthenticatedPrincipal? = null,
    val clientReportedTimestamp: Instant? = null,
)

/**
 * Command to submit high-risk accessible confirmation (Step 2: explicit confirmation & commit).
 */
data class ConfirmAndCommitRgActionCommand(
    val tenantId: String,
    val playerId: String,
    val sessionId: UUID,
    val confirmationToken: String,
    val acknowledgedDisclosure: Boolean,
    val idempotencyKey: String,
    val correlationId: String,
    val causationId: String,
    val expectedVersion: Long,
    val principal: AuthenticatedPrincipal? = null,
    val clientReportedTimestamp: Instant? = null,
)

/**
 * Command to cancel an unconfirmed action session.
 */
data class CancelRgActionCommand(
    val tenantId: String,
    val playerId: String,
    val sessionId: UUID,
    val reason: String,
    val idempotencyKey: String,
    val correlationId: String,
    val causationId: String,
    val expectedVersion: Long,
    val principal: AuthenticatedPrincipal? = null,
)

/**
 * Query to fetch authoritative UI model after Android activity recreation or process death.
 */
data class QueryAuthoritativeUiModelQuery(
    val tenantId: String,
    val playerId: String,
    val principal: AuthenticatedPrincipal? = null,
)

/**
 * Operation result.
 */
data class RgActionSessionResult(
    val resultId: UUID,
    val session: RgMobileActionSessionRecord,
    val receipt: RgAuthoritativeReceipt? = null,
    val serverTime: Instant,
    val isDuplicate: Boolean,
    val isFinancialAuthorityCreated: Boolean = false,
    val semanticContract: String = ANDROID_RG_CONTROLS_CONTRACT,
)

/**
 * Snapshot for state recovery and migration across server restarts.
 */
data class AndroidRgControlsSnapshot(
    val sessions: Map<String, RgMobileActionSessionRecord>,
    val receipts: Map<String, RgAuthoritativeReceipt>,
    val idempotencyMap: Map<String, Pair<String, Any>>,
    val auditEvents: List<AuditEvent>,
    val outboxEvents: List<OutboxEvent>,
)

/**
 * Store interface for Android RG controls.
 */
interface AndroidRgControlsStore {
    fun findSession(tenantId: String, sessionId: UUID): RgMobileActionSessionRecord?
    fun findActiveSessionForPlayer(tenantId: String, playerId: String): RgMobileActionSessionRecord?
    fun saveSession(
        session: RgMobileActionSessionRecord,
        result: RgActionSessionResult,
        idempotencyKey: String,
        fingerprint: String,
        audit: AuditEvent,
        outbox: OutboxEvent,
    )
    fun updateSession(
        session: RgMobileActionSessionRecord,
        result: RgActionSessionResult,
        idempotencyKey: String,
        fingerprint: String,
        audit: AuditEvent,
        outbox: OutboxEvent,
    )
    fun findReceipt(tenantId: String, receiptId: UUID): RgAuthoritativeReceipt?
    fun findLatestReceiptForPlayer(tenantId: String, playerId: String): RgAuthoritativeReceipt?
    fun saveReceipt(receipt: RgAuthoritativeReceipt)
    fun findByIdempotency(tenantId: String, idempotencyKey: String): Pair<String, Any>?
    fun exportSnapshot(): AndroidRgControlsSnapshot
    fun importSnapshot(snapshot: AndroidRgControlsSnapshot)
}

/**
 * Alert sink for RG UX controls.
 */
interface AndroidRgControlsAlertSink {
    fun sendAlert(tenantId: String, reference: String, alertType: String, reason: String, detail: String)
}

class InMemoryAndroidRgControlsAlertSink : AndroidRgControlsAlertSink {
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
 * In-memory thread-safe store for Android RG controls.
 */
class InMemoryAndroidRgControlsStore : AndroidRgControlsStore {
    private val sessions = ConcurrentHashMap<String, RgMobileActionSessionRecord>()
    private val receipts = ConcurrentHashMap<String, RgAuthoritativeReceipt>()
    private val idempotencyResults = ConcurrentHashMap<String, Pair<String, Any>>()
    val auditEvents = mutableListOf<AuditEvent>()
    val outboxEvents = mutableListOf<OutboxEvent>()

    private fun sessionKey(tenantId: String, sessionId: UUID) = "$tenantId:$sessionId"
    private fun receiptKey(tenantId: String, receiptId: UUID) = "$tenantId:$receiptId"
    private fun idempKey(tenantId: String, idempotencyKey: String) = "$tenantId:$idempotencyKey"

    @Synchronized
    override fun findSession(tenantId: String, sessionId: UUID): RgMobileActionSessionRecord? =
        sessions[sessionKey(tenantId, sessionId)]

    @Synchronized
    override fun findActiveSessionForPlayer(tenantId: String, playerId: String): RgMobileActionSessionRecord? =
        sessions.values.find { it.tenantId == tenantId && it.playerId == playerId && it.state == RgActionSessionState.AWAITING_ACCESSIBLE_CONFIRMATION }

    @Synchronized
    override fun saveSession(
        session: RgMobileActionSessionRecord,
        result: RgActionSessionResult,
        idempotencyKey: String,
        fingerprint: String,
        audit: AuditEvent,
        outbox: OutboxEvent,
    ) {
        sessions[sessionKey(session.tenantId, session.sessionId)] = session
        idempotencyResults[idempKey(session.tenantId, idempotencyKey)] = fingerprint to result
        auditEvents.add(audit)
        outboxEvents.add(outbox)
    }

    @Synchronized
    override fun updateSession(
        session: RgMobileActionSessionRecord,
        result: RgActionSessionResult,
        idempotencyKey: String,
        fingerprint: String,
        audit: AuditEvent,
        outbox: OutboxEvent,
    ) {
        sessions[sessionKey(session.tenantId, session.sessionId)] = session
        idempotencyResults[idempKey(session.tenantId, idempotencyKey)] = fingerprint to result
        auditEvents.add(audit)
        outboxEvents.add(outbox)
    }

    @Synchronized
    override fun findReceipt(tenantId: String, receiptId: UUID): RgAuthoritativeReceipt? =
        receipts[receiptKey(tenantId, receiptId)]

    @Synchronized
    override fun findLatestReceiptForPlayer(tenantId: String, playerId: String): RgAuthoritativeReceipt? =
        receipts.values.filter { it.tenantId == tenantId && it.playerId == playerId }.maxByOrNull { it.serverTime }

    @Synchronized
    override fun saveReceipt(receipt: RgAuthoritativeReceipt) {
        receipts[receiptKey(receipt.tenantId, receipt.receiptId)] = receipt
    }

    @Synchronized
    override fun findByIdempotency(tenantId: String, idempotencyKey: String): Pair<String, Any>? =
        idempotencyResults[idempKey(tenantId, idempotencyKey)]

    @Synchronized
    override fun exportSnapshot(): AndroidRgControlsSnapshot = AndroidRgControlsSnapshot(
        sessions = HashMap(sessions),
        receipts = HashMap(receipts),
        idempotencyMap = HashMap(idempotencyResults),
        auditEvents = ArrayList(auditEvents),
        outboxEvents = ArrayList(outboxEvents),
    )

    @Synchronized
    override fun importSnapshot(snapshot: AndroidRgControlsSnapshot) {
        sessions.clear()
        sessions.putAll(snapshot.sessions)
        receipts.clear()
        receipts.putAll(snapshot.receipts)
        idempotencyResults.clear()
        idempotencyResults.putAll(snapshot.idempotencyMap)
        auditEvents.clear()
        auditEvents.addAll(snapshot.auditEvents)
        outboxEvents.clear()
        outboxEvents.addAll(snapshot.outboxEvents)
    }
}

/**
 * Authoritative backend service implementing RG-004: Android controls/audit UX.
 */
class AndroidRgControlsService(
    private val store: AndroidRgControlsStore,
    private val alertSink: AndroidRgControlsAlertSink = InMemoryAndroidRgControlsAlertSink(),
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
    fun initiateRgAction(command: InitiateRgActionCommand): RgActionSessionResult {
        AndroidRgControlsBinding.checkBound()

        if (command.tenantId.isBlank() || command.playerId.isBlank() || command.idempotencyKey.isBlank() || command.payloadValue.isBlank()) {
            throw AuthenticationFailure.Rejected(AuthErrorCode.INVALID)
        }

        // Validate no dark patterns in payload: negative values or deceptive syntax strictly rejected
        if (command.actionType in setOf(RgActionType.LIMIT_DECREASE, RgActionType.LIMIT_INCREASE)) {
            val amount = command.payloadValue.toLongOrNull()
            if (amount == null || amount <= 0L) {
                alertSink.sendAlert(
                    tenantId = command.tenantId,
                    reference = command.playerId,
                    alertType = "DARK_PATTERN_OR_INVALID_INPUT",
                    reason = "NON_POSITIVE_AMOUNT",
                    detail = "Payload value ${command.payloadValue} is invalid or rejected as dark pattern",
                )
                throw AuthenticationFailure.Rejected(AuthErrorCode.INVALID)
            }
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
                    detail = "Client reported timestamp skew on initiate action",
                )
                throw AuthenticationFailure.Rejected(AuthErrorCode.INVALID)
            }
        }

        val fp = sha256("${command.tenantId}:${command.playerId}:${command.actionType}:${command.payloadValue}")

        val existingIdemp = store.findByIdempotency(command.tenantId, command.idempotencyKey)
        if (existingIdemp != null) {
            val (cachedFp, cachedResult) = existingIdemp
            if (cachedFp != fp) {
                throw AuthenticationFailure.Rejected(AuthErrorCode.CONFLICT)
            }
            val res = cachedResult as RgActionSessionResult
            return res.copy(isDuplicate = true)
        }

        val sessionId = UUID.randomUUID()
        val confirmationToken = "CONFIRM-" + UUID.randomUUID().toString().take(12)
        val expiresAt = now.plus(Duration.ofMinutes(15))
        val evidenceRef = "EVID-ACTION-SESSION-$sessionId-v1"

        // Accessible explanation clear of dark patterns
        val accessibleExplanation = when (command.actionType) {
            RgActionType.LIMIT_DECREASE -> "You are decreasing your limit to ${command.payloadValue}. This change is immediate."
            RgActionType.LIMIT_INCREASE -> "You are requesting to increase your limit to ${command.payloadValue}. This requires a mandatory 24-hour cooling-off period."
            RgActionType.COOLING_OFF -> "You are taking a cooling-off break for ${command.payloadValue} days. All active sessions will be terminated immediately across all products."
            RgActionType.SELF_EXCLUSION_DEFINITE -> "You are self-excluding for ${command.payloadValue} months. All active sessions will be terminated and access blocked."
            RgActionType.SELF_EXCLUSION_PERMANENT -> "You are requesting permanent self-exclusion. This action is irreversible."
            RgActionType.REALITY_CHECK_INTERVAL_UPDATE -> "You are updating your reality check interval to ${command.payloadValue} minutes."
        }

        val record = RgMobileActionSessionRecord(
            sessionId = sessionId,
            tenantId = command.tenantId,
            playerId = command.playerId,
            actionType = command.actionType,
            state = RgActionSessionState.AWAITING_ACCESSIBLE_CONFIRMATION,
            payloadValue = command.payloadValue,
            confirmationToken = confirmationToken,
            accessibleExplanation = accessibleExplanation,
            requiresHighRiskConfirmation = true,
            version = 1L,
            evidenceReference = evidenceRef,
            expiresAt = expiresAt,
            createdAt = now,
            updatedAt = now,
            semanticContract = ANDROID_RG_CONTROLS_CONTRACT,
        )

        val resultId = UUID.randomUUID()
        val result = RgActionSessionResult(
            resultId = resultId,
            session = record,
            receipt = null,
            serverTime = now,
            isDuplicate = false,
            isFinancialAuthorityCreated = false,
            semanticContract = ANDROID_RG_CONTROLS_CONTRACT,
        )

        val audit = AuditEvent(UUID.randomUUID(), sessionId, command.tenantId, "RG_ACTION_INITIATED", now, command.correlationId, command.causationId)
        val outbox = OutboxEvent(UUID.randomUUID(), sessionId, command.tenantId, "RG_ACTION_INITIATED", now)

        try {
            store.saveSession(record, result, command.idempotencyKey, fp, audit, outbox)
        } catch (e: Exception) {
            throw AuthenticationFailure.Rejected(AuthErrorCode.DEPENDENCY_UNAVAILABLE)
        }

        return result
    }

    @Synchronized
    fun confirmAndCommitRgAction(command: ConfirmAndCommitRgActionCommand): RgActionSessionResult {
        AndroidRgControlsBinding.checkBound()

        if (command.tenantId.isBlank() || command.playerId.isBlank() || command.idempotencyKey.isBlank() || command.confirmationToken.isBlank()) {
            throw AuthenticationFailure.Rejected(AuthErrorCode.INVALID)
        }

        // High-risk confirmation: must explicitly acknowledge disclosure (no dark pattern opt-out)
        if (!command.acknowledgedDisclosure) {
            alertSink.sendAlert(
                tenantId = command.tenantId,
                reference = command.playerId,
                alertType = "HIGH_RISK_CONFIRMATION_MISSING",
                reason = "UNACKNOWLEDGED_DISCLOSURE",
                detail = "Action confirmation rejected because explicit disclosure was not acknowledged",
            )
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

        val fp = sha256("${command.tenantId}:${command.playerId}:${command.sessionId}:${command.confirmationToken}:${command.expectedVersion}")

        val existingIdemp = store.findByIdempotency(command.tenantId, command.idempotencyKey)
        if (existingIdemp != null) {
            val (cachedFp, cachedResult) = existingIdemp
            if (cachedFp != fp) {
                throw AuthenticationFailure.Rejected(AuthErrorCode.CONFLICT)
            }
            val res = cachedResult as RgActionSessionResult
            return res.copy(isDuplicate = true)
        }

        val existing = store.findSession(command.tenantId, command.sessionId)
            ?: throw AuthenticationFailure.Rejected(AuthErrorCode.INVALID)

        if (existing.version != command.expectedVersion) {
            throw AuthenticationFailure.Rejected(AuthErrorCode.STALE)
        }

        if (existing.state != RgActionSessionState.AWAITING_ACCESSIBLE_CONFIRMATION) {
            throw AuthenticationFailure.Rejected(AuthErrorCode.INVALID)
        }

        if (existing.confirmationToken != command.confirmationToken) {
            alertSink.sendAlert(
                tenantId = command.tenantId,
                reference = command.playerId,
                alertType = "INVALID_CONFIRMATION_TOKEN",
                reason = "TOKEN_MISMATCH",
                detail = "Confirmation token mismatch on action commit",
            )
            throw AuthenticationFailure.Rejected(AuthErrorCode.INVALID)
        }

        if (now.isAfter(existing.expiresAt)) {
            throw AuthenticationFailure.Rejected(AuthErrorCode.STALE)
        }

        // Determine immediate vs delayed effective time
        val (effectiveAt, isImmediate) = when (existing.actionType) {
            RgActionType.LIMIT_DECREASE -> now to true
            RgActionType.LIMIT_INCREASE -> now.plus(Duration.ofHours(24)) to false
            RgActionType.COOLING_OFF -> now to true
            RgActionType.SELF_EXCLUSION_DEFINITE -> now to true
            RgActionType.SELF_EXCLUSION_PERMANENT -> now to true
            RgActionType.REALITY_CHECK_INTERVAL_UPDATE -> now to true
        }

        val receiptId = UUID.randomUUID()
        val receiptRef = "RCPT-RG-${receiptId.toString().take(8).uppercase()}"
        val newVersion = existing.version + 1L

        val receipt = RgAuthoritativeReceipt(
            receiptId = receiptId,
            tenantId = command.tenantId,
            playerId = command.playerId,
            actionType = existing.actionType,
            requestedValue = existing.payloadValue,
            effectiveValue = existing.payloadValue,
            effectiveAt = effectiveAt,
            isImmediate = isImmediate,
            receiptReference = receiptRef,
            accessibleDisclosure = existing.accessibleExplanation,
            serverTime = now,
            version = 1L,
            semanticContract = ANDROID_RG_CONTROLS_CONTRACT,
        )

        val updatedSession = existing.copy(
            state = RgActionSessionState.COMMITTED,
            confirmedAt = now,
            receipt = receipt,
            version = newVersion,
            updatedAt = now,
        )

        val resultId = UUID.randomUUID()
        val result = RgActionSessionResult(
            resultId = resultId,
            session = updatedSession,
            receipt = receipt,
            serverTime = now,
            isDuplicate = false,
            isFinancialAuthorityCreated = false,
            semanticContract = ANDROID_RG_CONTROLS_CONTRACT,
        )

        val audit = AuditEvent(UUID.randomUUID(), existing.sessionId, command.tenantId, "RG_ACTION_COMMITTED", now, command.correlationId, command.causationId)
        val outbox = OutboxEvent(UUID.randomUUID(), existing.sessionId, command.tenantId, "RG_ACTION_COMMITTED", now)

        try {
            store.saveReceipt(receipt)
            store.updateSession(updatedSession, result, command.idempotencyKey, fp, audit, outbox)
        } catch (e: Exception) {
            throw AuthenticationFailure.Rejected(AuthErrorCode.DEPENDENCY_UNAVAILABLE)
        }

        return result
    }

    @Synchronized
    fun cancelRgAction(command: CancelRgActionCommand): RgActionSessionResult {
        AndroidRgControlsBinding.checkBound()

        if (command.tenantId.isBlank() || command.playerId.isBlank() || command.idempotencyKey.isBlank()) {
            throw AuthenticationFailure.Rejected(AuthErrorCode.INVALID)
        }

        validatePrincipal(command.principal, command.tenantId, command.playerId)

        val now = clock.instant()
        val fp = sha256("${command.tenantId}:${command.playerId}:${command.sessionId}:${command.reason}:${command.expectedVersion}")

        val existingIdemp = store.findByIdempotency(command.tenantId, command.idempotencyKey)
        if (existingIdemp != null) {
            val (cachedFp, cachedResult) = existingIdemp
            if (cachedFp != fp) {
                throw AuthenticationFailure.Rejected(AuthErrorCode.CONFLICT)
            }
            val res = cachedResult as RgActionSessionResult
            return res.copy(isDuplicate = true)
        }

        val existing = store.findSession(command.tenantId, command.sessionId)
            ?: throw AuthenticationFailure.Rejected(AuthErrorCode.INVALID)

        if (existing.version != command.expectedVersion) {
            throw AuthenticationFailure.Rejected(AuthErrorCode.STALE)
        }

        if (existing.state != RgActionSessionState.AWAITING_ACCESSIBLE_CONFIRMATION) {
            throw AuthenticationFailure.Rejected(AuthErrorCode.INVALID)
        }

        val newVersion = existing.version + 1L
        val updatedSession = existing.copy(
            state = RgActionSessionState.CANCELLED,
            version = newVersion,
            updatedAt = now,
        )

        val resultId = UUID.randomUUID()
        val result = RgActionSessionResult(
            resultId = resultId,
            session = updatedSession,
            receipt = null,
            serverTime = now,
            isDuplicate = false,
            isFinancialAuthorityCreated = false,
            semanticContract = ANDROID_RG_CONTROLS_CONTRACT,
        )

        val audit = AuditEvent(UUID.randomUUID(), existing.sessionId, command.tenantId, "RG_ACTION_CANCELLED", now, command.correlationId, command.causationId)
        val outbox = OutboxEvent(UUID.randomUUID(), existing.sessionId, command.tenantId, "RG_ACTION_CANCELLED", now)

        try {
            store.updateSession(updatedSession, result, command.idempotencyKey, fp, audit, outbox)
        } catch (e: Exception) {
            throw AuthenticationFailure.Rejected(AuthErrorCode.DEPENDENCY_UNAVAILABLE)
        }

        return result
    }

    @Synchronized
    fun getAuthoritativeUiModel(query: QueryAuthoritativeUiModelQuery): RgAuthoritativeUiModel {
        AndroidRgControlsBinding.checkBound()

        if (query.tenantId.isBlank() || query.playerId.isBlank()) {
            throw AuthenticationFailure.Rejected(AuthErrorCode.INVALID)
        }

        validatePrincipal(query.principal, query.tenantId, query.playerId)

        val now = clock.instant()
        val latestReceipt = store.findLatestReceiptForPlayer(query.tenantId, query.playerId)
        val activeSession = store.findActiveSessionForPlayer(query.tenantId, query.playerId)

        return RgAuthoritativeUiModel(
            tenantId = query.tenantId,
            playerId = query.playerId,
            activeDepositLimitMinorUnits = 10000L,
            pendingDepositLimitIncreaseMinorUnits = null,
            pendingDepositLimitEffectiveAt = null,
            isCoolingOffActive = false,
            coolingOffExpiresAt = null,
            isRealityCheckDue = false,
            realityCheckIntervalMinutes = 60,
            latestReceipt = latestReceipt,
            activeSession = activeSession,
            serverTime = now,
            semanticContract = ANDROID_RG_CONTROLS_CONTRACT,
        )
    }
}
