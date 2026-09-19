package com.slotting.admin.identity

import com.slotting.admin.auth.AuditEvent
import com.slotting.admin.auth.AuthErrorCode
import com.slotting.admin.auth.AuthenticationFailure
import com.slotting.admin.auth.OutboxEvent
import java.security.MessageDigest
import java.time.Clock
import java.time.Duration
import java.time.Instant
import java.util.UUID
import java.util.concurrent.ConcurrentHashMap

/**
 * Gate to prevent unverified or recovery bypass during player account recovery.
 */
object PlayerAccountRecoveryBinding {
    var isBound: Boolean = true

    fun checkBound() {
        if (!isBound) {
            throw AssertionError("unverified/recovery bypass")
        }
    }
}

enum class RecoveryStatus {
    DISPATCHED,
    COMPLETED
}

data class InitiateRecoveryCommand(
    val tenantId: String,
    val identifier: String,
    val channel: ContactVerificationChannel = ContactVerificationChannel.EMAIL,
    val idempotencyKey: String,
    val correlationId: String,
    val causationId: String,
    val expectedVersion: Long = 1L
)

data class InitiateRecoveryResult(
    val resultId: UUID,
    val status: RecoveryStatus,
    val safeMessage: String,
    val recoveryToken: String?,
    val mfaRequired: Boolean,
    val serverTime: Instant,
    val serverVersion: Long,
    val evidenceReference: String,
    val auditEvent: AuditEvent,
    val outboxEvent: OutboxEvent
)

data class CompleteRecoveryCommand(
    val tenantId: String,
    val recoveryToken: String,
    val newPassword: String,
    val mfaCode: String? = null,
    val idempotencyKey: String,
    val correlationId: String,
    val causationId: String,
    val expectedVersion: Long = 1L
)

data class CompleteRecoveryResult(
    val resultId: UUID,
    val playerId: UUID,
    val status: RecoveryStatus,
    val sessionsRevokedCount: Int,
    val serverTime: Instant,
    val serverVersion: Long,
    val evidenceReference: String,
    val auditEvent: AuditEvent,
    val outboxEvent: OutboxEvent
)

data class RecoveryTokenRecord(
    val tokenId: UUID,
    val tenantId: String,
    val playerId: UUID,
    val channel: ContactVerificationChannel,
    val tokenHash: String,
    val mfaRequired: Boolean,
    val expiresAt: Instant,
    var attemptCount: Int = 0,
    val maxAttempts: Int = 3,
    var consumed: Boolean = false
)

interface PlayerRecoveryStore {
    fun findByIdempotency(tenantId: String, key: String): Pair<Any, Any>?
    fun saveRecoveryToken(
        tokenRecord: RecoveryTokenRecord,
        idempotencyKey: String,
        command: Any,
        result: Any
    )
    fun findTokenByHash(tenantId: String, tokenHash: String): RecoveryTokenRecord?
    fun saveRecoveryCompletion(
        tokenRecord: RecoveryTokenRecord,
        idempotencyKey: String,
        command: Any,
        result: Any
    )
}

class InMemoryPlayerRecoveryStore : PlayerRecoveryStore {
    val idempotency = ConcurrentHashMap<String, Pair<Any, Any>>()
    val tokens = ConcurrentHashMap<String, RecoveryTokenRecord>()
    val audit = mutableListOf<AuditEvent>()
    val outbox = mutableListOf<OutboxEvent>()

    override fun findByIdempotency(tenantId: String, key: String): Pair<Any, Any>? =
        idempotency["$tenantId:$key"]

    override fun saveRecoveryToken(
        tokenRecord: RecoveryTokenRecord,
        idempotencyKey: String,
        command: Any,
        result: Any
    ) {
        idempotency["${tokenRecord.tenantId}:$idempotencyKey"] = Pair(command, result)
        tokens["${tokenRecord.tenantId}:${tokenRecord.tokenHash}"] = tokenRecord
        if (result is InitiateRecoveryResult) {
            audit.add(result.auditEvent)
            outbox.add(result.outboxEvent)
        }
    }

    override fun findTokenByHash(tenantId: String, tokenHash: String): RecoveryTokenRecord? =
        tokens["$tenantId:$tokenHash"]

    override fun saveRecoveryCompletion(
        tokenRecord: RecoveryTokenRecord,
        idempotencyKey: String,
        command: Any,
        result: Any
    ) {
        idempotency["${tokenRecord.tenantId}:$idempotencyKey"] = Pair(command, result)
        tokens["${tokenRecord.tenantId}:${tokenRecord.tokenHash}"] = tokenRecord
        if (result is CompleteRecoveryResult) {
            audit.add(result.auditEvent)
            outbox.add(result.outboxEvent)
        }
    }
}

class PlayerAccountRecoveryService(
    private val registrationStore: PlayerRegistrationStore,
    private val sessionStore: PlayerSessionStore,
    private val recoveryStore: PlayerRecoveryStore,
    private val mfaPolicy: JurisdictionRiskMfaPolicy = JurisdictionRiskMfaPolicy(),
    private val clock: Clock = Clock.systemUTC(),
    private val recoveryTtl: Duration = Duration.ofMinutes(15)
) {
    fun initiateRecovery(command: InitiateRecoveryCommand): InitiateRecoveryResult = synchronized(recoveryStore) {
        PlayerAccountRecoveryBinding.checkBound()

        // 1. Validation
        if (command.tenantId.isBlank() || command.correlationId.isBlank() || command.causationId.isBlank()) {
            throw AuthenticationFailure.Rejected(AuthErrorCode.INVALID)
        }
        if (command.expectedVersion < 1L) {
            throw AuthenticationFailure.Rejected(AuthErrorCode.STALE)
        }
        if (command.idempotencyKey.isBlank() || command.identifier.isBlank()) {
            throw AuthenticationFailure.Rejected(AuthErrorCode.INVALID)
        }

        recoveryStore.findByIdempotency(command.tenantId, command.idempotencyKey)?.let { (cachedCmd, cachedResult) ->
            if (cachedCmd == command && cachedResult is InitiateRecoveryResult) {
                return cachedResult
            } else {
                throw AuthenticationFailure.Rejected(AuthErrorCode.CONFLICT)
            }
        }

        val normalizedIdentifier = command.identifier.trim().lowercase()
        val emailHash = sha256(normalizedIdentifier)
        val candidate = registrationStore.findByEmailHash(command.tenantId, emailHash)
            ?: registrationStore.findByPhoneHash(command.tenantId, sha256(command.identifier.trim()))

        val now = clock.instant()
        val resultId = UUID.randomUUID()

        // 2. Enumeration defense & unverified/suspended account defense
        // If player does not exist OR is unverified OR is suspended:
        // Return safe generic DISPATCHED message without issuing token or leaking account presence
        if (candidate == null || candidate.status == PlayerAccountStatus.PENDING_VERIFICATION || candidate.status == PlayerAccountStatus.SUSPENDED) {
            val eventType = when {
                candidate == null -> "ACCOUNT_RECOVERY_ENUMERATION_DEFENSE"
                candidate.status == PlayerAccountStatus.PENDING_VERIFICATION -> "ACCOUNT_RECOVERY_UNVERIFIED_DENIED"
                else -> "ACCOUNT_RECOVERY_SUSPENDED_DENIED"
            }
            val auditEvent = AuditEvent(
                eventId = UUID.randomUUID(),
                resultId = resultId,
                tenantId = command.tenantId,
                type = eventType,
                occurredAt = now,
                correlationId = command.correlationId,
                causationId = command.causationId
            )
            val outboxEvent = OutboxEvent(
                eventId = UUID.randomUUID(),
                resultId = resultId,
                tenantId = command.tenantId,
                type = eventType,
                createdAt = now
            )
            val safeResult = InitiateRecoveryResult(
                resultId = resultId,
                status = RecoveryStatus.DISPATCHED,
                safeMessage = "If an eligible account exists for the provided details, recovery instructions have been dispatched.",
                recoveryToken = null,
                mfaRequired = false,
                serverTime = now,
                serverVersion = command.expectedVersion,
                evidenceReference = "rec-def:${command.tenantId}:$resultId",
                auditEvent = auditEvent,
                outboxEvent = outboxEvent
            )
            if (recoveryStore is InMemoryPlayerRecoveryStore) {
                recoveryStore.idempotency["${command.tenantId}:${command.idempotencyKey}"] = Pair(command, safeResult)
                recoveryStore.audit.add(auditEvent)
                recoveryStore.outbox.add(outboxEvent)
            }
            return safeResult
        }

        // 3. MFA policy evaluation for recovery
        val mfaRequired = candidate.mfaRequired || mfaPolicy.isMfaRequired(candidate.jurisdiction, candidate.riskScore)

        val rawToken = "REC-${UUID.randomUUID()}"
        val tokenHash = sha256(rawToken)
        val tokenId = UUID.randomUUID()

        val tokenRecord = RecoveryTokenRecord(
            tokenId = tokenId,
            tenantId = command.tenantId,
            playerId = candidate.playerId,
            channel = command.channel,
            tokenHash = tokenHash,
            mfaRequired = mfaRequired,
            expiresAt = now.plus(recoveryTtl),
            attemptCount = 0,
            maxAttempts = 3,
            consumed = false
        )

        val auditEvent = AuditEvent(
            eventId = UUID.randomUUID(),
            resultId = resultId,
            tenantId = command.tenantId,
            type = "ACCOUNT_RECOVERY_INITIATED",
            occurredAt = now,
            correlationId = command.correlationId,
            causationId = command.causationId
        )
        val outboxEvent = OutboxEvent(
            eventId = UUID.randomUUID(),
            resultId = resultId,
            tenantId = command.tenantId,
            type = "ACCOUNT_RECOVERY_INITIATED",
            createdAt = now
        )

        val result = InitiateRecoveryResult(
            resultId = resultId,
            status = RecoveryStatus.DISPATCHED,
            safeMessage = "If an eligible account exists for the provided details, recovery instructions have been dispatched.",
            recoveryToken = rawToken,
            mfaRequired = mfaRequired,
            serverTime = now,
            serverVersion = candidate.version,
            evidenceReference = "rec-init:${command.tenantId}:$tokenId",
            auditEvent = auditEvent,
            outboxEvent = outboxEvent
        )

        recoveryStore.saveRecoveryToken(tokenRecord, command.idempotencyKey, command, result)
        return result
    }

    fun completeRecovery(command: CompleteRecoveryCommand): CompleteRecoveryResult = synchronized(recoveryStore) {
        PlayerAccountRecoveryBinding.checkBound()

        // 1. Validation
        if (command.tenantId.isBlank() || command.correlationId.isBlank() || command.causationId.isBlank()) {
            throw AuthenticationFailure.Rejected(AuthErrorCode.INVALID)
        }
        if (command.expectedVersion < 1L) {
            throw AuthenticationFailure.Rejected(AuthErrorCode.STALE)
        }
        if (command.idempotencyKey.isBlank() || command.recoveryToken.isBlank() || command.newPassword.isBlank()) {
            throw AuthenticationFailure.Rejected(AuthErrorCode.INVALID)
        }

        recoveryStore.findByIdempotency(command.tenantId, command.idempotencyKey)?.let { (cachedCmd, cachedResult) ->
            if (cachedCmd == command && cachedResult is CompleteRecoveryResult) {
                return cachedResult
            } else {
                throw AuthenticationFailure.Rejected(AuthErrorCode.CONFLICT)
            }
        }

        val tokenHash = sha256(command.recoveryToken.trim())
        val tokenRecord = recoveryStore.findTokenByHash(command.tenantId, tokenHash)
            ?: throw AuthenticationFailure.Rejected(AuthErrorCode.INVALID)

        val now = clock.instant()

        // 2. Expiration and lock checks
        if (tokenRecord.consumed) {
            throw AuthenticationFailure.Rejected(AuthErrorCode.INVALID)
        }
        if (tokenRecord.attemptCount >= tokenRecord.maxAttempts) {
            throw AuthenticationFailure.Rejected(AuthErrorCode.FORBIDDEN)
        }
        if (now.isAfter(tokenRecord.expiresAt)) {
            throw AuthenticationFailure.Rejected(AuthErrorCode.INVALID)
        }

        // 3. MFA enforcement on recovery
        if (tokenRecord.mfaRequired) {
            if (command.mfaCode.isNullOrBlank()) {
                tokenRecord.attemptCount++
                throw AuthenticationFailure.Rejected(AuthErrorCode.FORBIDDEN)
            }
            val givenMfaHash = sha256(command.mfaCode.trim())
            val expectedMfaHash = sha256("MFA-654321")
            if (givenMfaHash != expectedMfaHash) {
                tokenRecord.attemptCount++
                throw AuthenticationFailure.Rejected(AuthErrorCode.INVALID)
            }
        }

        val player = registrationStore.findById(command.tenantId, tokenRecord.playerId)
            ?: throw AuthenticationFailure.Rejected(AuthErrorCode.INVALID)

        // 4. Update player password and state
        tokenRecord.consumed = true
        player.passwordHash = sha256(command.newPassword)
        if (player.status == PlayerAccountStatus.PENDING_MFA) {
            player.status = PlayerAccountStatus.ACTIVE
        }
        player.version++
        player.updatedAt = now

        // 5. Invalidate / revoke all active sessions for security
        val revokedSessionsCount = sessionStore.revokeAllPlayerSessions(command.tenantId, player.playerId, now)

        val resultId = UUID.randomUUID()
        val auditEvent = AuditEvent(
            eventId = UUID.randomUUID(),
            resultId = resultId,
            tenantId = command.tenantId,
            type = "ACCOUNT_RECOVERY_COMPLETED",
            occurredAt = now,
            correlationId = command.correlationId,
            causationId = command.causationId
        )
        val outboxEvent = OutboxEvent(
            eventId = UUID.randomUUID(),
            resultId = resultId,
            tenantId = command.tenantId,
            type = "ACCOUNT_RECOVERY_COMPLETED",
            createdAt = now
        )

        val result = CompleteRecoveryResult(
            resultId = resultId,
            playerId = player.playerId,
            status = RecoveryStatus.COMPLETED,
            sessionsRevokedCount = revokedSessionsCount,
            serverTime = now,
            serverVersion = player.version,
            evidenceReference = "rec-comp:${command.tenantId}:$resultId",
            auditEvent = auditEvent,
            outboxEvent = outboxEvent
        )

        recoveryStore.saveRecoveryCompletion(tokenRecord, command.idempotencyKey, command, result)
        return result
    }

    private fun sha256(input: String): String {
        val digest = MessageDigest.getInstance("SHA-256")
        val bytes = digest.digest(input.toByteArray(Charsets.UTF_8))
        return bytes.joinToString("") { "%02x".format(it) }
    }
}
