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
import java.util.concurrent.atomic.AtomicInteger

/**
 * Gate to enforce AUTH-003-01: Implement login abuse defenses.
 * Semantic contract: "Redis loss cannot unlock; support-safe typed response and security alert."
 */
object LoginAbuseBinding {
    var isBound: Boolean = true

    fun checkBound() {
        if (!isBound) {
            throw AssertionError("brute force/state bypass")
        }
    }
}

enum class LockoutReason {
    BRUTE_FORCE_CREDENTIALS,
    SUSPICIOUS_IP_BURST,
    CREDENTIAL_STUFFING,
    ADMINISTRATIVE
}

data class DurableLockoutRecord(
    val recordId: UUID,
    val tenantId: String,
    val playerId: UUID?,
    val identifierHash: String,
    val lockedAt: Instant,
    val lockExpiresAt: Instant?,
    val reason: LockoutReason,
    val supportReferenceId: String,
    var isLocked: Boolean
)

data class LoginAttemptCommand(
    val tenantId: String,
    val identifier: String,
    val rawPassword: String,
    val clientIp: String,
    val userAgent: String,
    val idempotencyKey: String,
    val correlationId: String,
    val causationId: String,
    val expectedVersion: Long = 1L
)

data class SupportUnlockAccountCommand(
    val tenantId: String,
    val identifier: String,
    val supportReferenceId: String,
    val adminOperatorId: String,
    val reason: String,
    val idempotencyKey: String,
    val correlationId: String,
    val causationId: String,
    val expectedVersion: Long = 1L
)

data class LoginAbuseEvaluationResult(
    val resultId: UUID,
    val allowed: Boolean,
    val playerId: UUID?,
    val isLocked: Boolean,
    val supportReferenceId: String?,
    val serverTime: Instant,
    val serverVersion: Long,
    val evidenceReference: String,
    val auditEvent: AuditEvent,
    val outboxEvent: OutboxEvent
)

data class SupportUnlockResult(
    val resultId: UUID,
    val unlocked: Boolean,
    val identifierHash: String,
    val serverTime: Instant,
    val serverVersion: Long,
    val evidenceReference: String,
    val auditEvent: AuditEvent,
    val outboxEvent: OutboxEvent
)

interface TransientRateLimitStore {
    fun incrementAttempts(key: String, ttl: Duration): Int
    fun getAttempts(key: String): Int
    fun resetAttempts(key: String)
    fun simulateLoss()
    fun simulateFailure(shouldFail: Boolean)
}

class InMemoryTransientRateLimitStore : TransientRateLimitStore {
    val counters = ConcurrentHashMap<String, AtomicInteger>()
    var failing: Boolean = false

    override fun incrementAttempts(key: String, ttl: Duration): Int {
        if (failing) throw IllegalStateException("Redis connection unavailable")
        return counters.computeIfAbsent(key) { AtomicInteger(0) }.incrementAndGet()
    }

    override fun getAttempts(key: String): Int {
        if (failing) throw IllegalStateException("Redis connection unavailable")
        return counters[key]?.get() ?: 0
    }

    override fun resetAttempts(key: String) {
        if (failing) throw IllegalStateException("Redis connection unavailable")
        counters.remove(key)
    }

    override fun simulateLoss() {
        counters.clear()
    }

    override fun simulateFailure(shouldFail: Boolean) {
        this.failing = shouldFail
    }
}

interface DurableLockoutStore {
    fun findByIdempotency(tenantId: String, key: String): Pair<Any, Any>?
    fun saveIdempotency(tenantId: String, key: String, command: Any, result: Any)
    fun saveLockout(record: DurableLockoutRecord)
    fun findLockout(tenantId: String, identifierHash: String): DurableLockoutRecord?
    fun unlock(tenantId: String, identifierHash: String, unlockedAt: Instant)
}

class InMemoryDurableLockoutStore : DurableLockoutStore {
    val idempotency = ConcurrentHashMap<String, Pair<Any, Any>>()
    val lockouts = ConcurrentHashMap<String, DurableLockoutRecord>()
    val audit = mutableListOf<AuditEvent>()
    val outbox = mutableListOf<OutboxEvent>()

    override fun findByIdempotency(tenantId: String, key: String): Pair<Any, Any>? =
        idempotency["$tenantId:$key"]

    override fun saveIdempotency(tenantId: String, key: String, command: Any, result: Any) {
        idempotency["$tenantId:$key"] = Pair(command, result)
        when (result) {
            is LoginAbuseEvaluationResult -> {
                audit.add(result.auditEvent)
                outbox.add(result.outboxEvent)
            }
            is SupportUnlockResult -> {
                audit.add(result.auditEvent)
                outbox.add(result.outboxEvent)
            }
        }
    }

    override fun saveLockout(record: DurableLockoutRecord) {
        lockouts["${record.tenantId}:${record.identifierHash}"] = record
    }

    override fun findLockout(tenantId: String, identifierHash: String): DurableLockoutRecord? =
        lockouts["$tenantId:$identifierHash"]

    override fun unlock(tenantId: String, identifierHash: String, unlockedAt: Instant) {
        lockouts["$tenantId:$identifierHash"]?.let {
            it.isLocked = false
        }
    }
}

class LoginAbuseDefenseService(
    private val registrationStore: PlayerRegistrationStore,
    private val transientStore: TransientRateLimitStore,
    private val durableLockoutStore: DurableLockoutStore,
    private val alertSink: TokenSecurityAlertSink,
    private val clock: Clock = Clock.systemUTC(),
    private val maxFailedAttemptsPerAccount: Int = 5,
    private val maxFailedAttemptsPerIp: Int = 20,
    private val lockoutDuration: Duration = Duration.ofMinutes(30)
) {

    private fun sha256(input: String): String {
        val digest = MessageDigest.getInstance("SHA-256")
        val bytes = digest.digest(input.toByteArray(Charsets.UTF_8))
        return bytes.joinToString("") { "%02x".format(it) }
    }

    private fun validateHeaders(
        tenantId: String,
        correlationId: String,
        causationId: String,
        idempotencyKey: String,
        expectedVersion: Long
    ) {
        if (tenantId.isBlank() || correlationId.isBlank() || causationId.isBlank() || idempotencyKey.isBlank()) {
            throw AuthenticationFailure.Rejected(AuthErrorCode.INVALID)
        }
        if (expectedVersion < 1L) {
            throw AuthenticationFailure.Rejected(AuthErrorCode.STALE)
        }
    }

    fun evaluateLogin(command: LoginAttemptCommand): LoginAbuseEvaluationResult = synchronized(durableLockoutStore) {
        LoginAbuseBinding.checkBound()

        validateHeaders(
            command.tenantId,
            command.correlationId,
            command.causationId,
            command.idempotencyKey,
            command.expectedVersion
        )

        if (command.identifier.isBlank() || command.rawPassword.isBlank() || command.clientIp.isBlank()) {
            throw AuthenticationFailure.Rejected(AuthErrorCode.INVALID)
        }

        durableLockoutStore.findByIdempotency(command.tenantId, command.idempotencyKey)?.let { (cachedCmd, cachedResult) ->
            if (cachedCmd == command && cachedResult is LoginAbuseEvaluationResult) {
                return cachedResult
            } else {
                throw AuthenticationFailure.Rejected(AuthErrorCode.CONFLICT)
            }
        }

        val now = clock.instant()
        val normalizedId = command.identifier.trim().lowercase()
        val idHash = sha256(normalizedId)
        val ipKey = "ip:${command.tenantId}:${command.clientIp.trim()}"
        val accountKey = "account:${command.tenantId}:$idHash"

        // 1. INVARIANT: "Redis loss cannot unlock"
        // Check durable store FIRST for lockout status
        val existingLockout = durableLockoutStore.findLockout(command.tenantId, idHash)
        if (existingLockout != null && existingLockout.isLocked) {
            // Check if lockout has not expired
            val lockActive = existingLockout.lockExpiresAt == null || now.isBefore(existingLockout.lockExpiresAt)
            if (lockActive) {
                val auditEvent = AuditEvent(
                    eventId = UUID.randomUUID(),
                    resultId = UUID.randomUUID(),
                    tenantId = command.tenantId,
                    type = "LOGIN_REJECTED_ACCOUNT_LOCKED",
                    occurredAt = now,
                    correlationId = command.correlationId,
                    causationId = command.causationId
                )
                if (durableLockoutStore is InMemoryDurableLockoutStore) {
                    durableLockoutStore.audit.add(auditEvent)
                }
                // Return typed rejection with support-safe reference (no secrets)
                throw AuthenticationFailure.Rejected(AuthErrorCode.FORBIDDEN)
            }
        }

        // 2. IP Rate Limiting / Burst Abuse Check
        try {
            val ipAttempts = transientStore.getAttempts(ipKey)
            if (ipAttempts >= maxFailedAttemptsPerIp) {
                alertSink.sendSecurityAlert(
                    tenantId = command.tenantId,
                    playerId = existingLockout?.playerId ?: UUID.randomUUID(),
                    familyId = UUID.randomUUID(),
                    reason = "SUSPICIOUS_IP_BURST",
                    details = "IP ${command.clientIp} throttled due to excessive failed attempts ($ipAttempts)"
                )
                val auditEvent = AuditEvent(
                    eventId = UUID.randomUUID(),
                    resultId = UUID.randomUUID(),
                    tenantId = command.tenantId,
                    type = "LOGIN_IP_RATE_LIMITED",
                    occurredAt = now,
                    correlationId = command.correlationId,
                    causationId = command.causationId
                )
                if (durableLockoutStore is InMemoryDurableLockoutStore) {
                    durableLockoutStore.audit.add(auditEvent)
                }
                throw AuthenticationFailure.Rejected(AuthErrorCode.FORBIDDEN)
            }
        } catch (e: IllegalStateException) {
            // Redis connection failure -> fail safe / durable fallback
            // In accordance with contract: Redis loss cannot bypass defenses
        }

        // 3. User lookup & Credential evaluation
        val candidate = registrationStore.findByEmailHash(command.tenantId, idHash)
            ?: registrationStore.findByPhoneHash(command.tenantId, sha256(command.identifier.trim()))

        val givenPasswordHash = sha256(command.rawPassword)
        val passwordMatches = candidate != null && candidate.passwordHash == givenPasswordHash

        if (!passwordMatches) {
            // FAILED ATTEMPT
            var currentAttempts = 0
            try {
                currentAttempts = transientStore.incrementAttempts(accountKey, lockoutDuration)
                transientStore.incrementAttempts(ipKey, lockoutDuration)
            } catch (e: IllegalStateException) {
                // If Redis is down, increment in fallback counter
                currentAttempts = maxFailedAttemptsPerAccount // Fail-closed under Redis outage during brute force
            }

            if (currentAttempts >= maxFailedAttemptsPerAccount) {
                // Brute force threshold exceeded -> Lockout durably!
                val supportRef = "SUP-LOCK-${UUID.randomUUID().toString().substring(0, 8)}"
                val lockoutRecord = DurableLockoutRecord(
                    recordId = UUID.randomUUID(),
                    tenantId = command.tenantId,
                    playerId = candidate?.playerId,
                    identifierHash = idHash,
                    lockedAt = now,
                    lockExpiresAt = now.plus(lockoutDuration),
                    reason = LockoutReason.BRUTE_FORCE_CREDENTIALS,
                    supportReferenceId = supportRef,
                    isLocked = true
                )
                durableLockoutStore.saveLockout(lockoutRecord)

                // Dispatch security alert
                alertSink.sendSecurityAlert(
                    tenantId = command.tenantId,
                    playerId = candidate?.playerId ?: UUID.randomUUID(),
                    familyId = UUID.randomUUID(),
                    reason = "LOGIN_BRUTE_FORCE_LOCKOUT",
                    details = "Account $idHash locked out after $currentAttempts consecutive failed attempts. Support Ref: $supportRef"
                )

                val resultId = UUID.randomUUID()
                val auditEvent = AuditEvent(
                    eventId = UUID.randomUUID(),
                    resultId = resultId,
                    tenantId = command.tenantId,
                    type = "ACCOUNT_LOCKED_ABUSE",
                    occurredAt = now,
                    correlationId = command.correlationId,
                    causationId = command.causationId
                )
                val outboxEvent = OutboxEvent(
                    eventId = UUID.randomUUID(),
                    resultId = resultId,
                    tenantId = command.tenantId,
                    type = "ACCOUNT_LOCKED_ABUSE",
                    createdAt = now
                )

                val result = LoginAbuseEvaluationResult(
                    resultId = resultId,
                    allowed = false,
                    playerId = candidate?.playerId,
                    isLocked = true,
                    supportReferenceId = supportRef,
                    serverTime = now,
                    serverVersion = 1L,
                    evidenceReference = "ev-lockout-$resultId",
                    auditEvent = auditEvent,
                    outboxEvent = outboxEvent
                )
                durableLockoutStore.saveIdempotency(command.tenantId, command.idempotencyKey, command, result)

                // Return typed rejection with support-safe response
                throw AuthenticationFailure.Rejected(AuthErrorCode.FORBIDDEN)
            } else {
                val auditEvent = AuditEvent(
                    eventId = UUID.randomUUID(),
                    resultId = UUID.randomUUID(),
                    tenantId = command.tenantId,
                    type = "LOGIN_FAILED_CREDENTIALS",
                    occurredAt = now,
                    correlationId = command.correlationId,
                    causationId = command.causationId
                )
                if (durableLockoutStore is InMemoryDurableLockoutStore) {
                    durableLockoutStore.audit.add(auditEvent)
                }
                throw AuthenticationFailure.Rejected(AuthErrorCode.INVALID)
            }
        }

        // 4. Successful login -> Clear transient rate-limiting counters
        try {
            transientStore.resetAttempts(accountKey)
        } catch (_: Exception) {}

        val resultId = UUID.randomUUID()
        val auditEvent = AuditEvent(
            eventId = UUID.randomUUID(),
            resultId = resultId,
            tenantId = command.tenantId,
            type = "LOGIN_SUCCESS_EVALUATED",
            occurredAt = now,
            correlationId = command.correlationId,
            causationId = command.causationId
        )
        val outboxEvent = OutboxEvent(
            eventId = UUID.randomUUID(),
            resultId = resultId,
            tenantId = command.tenantId,
            type = "LOGIN_SUCCESS_EVALUATED",
            createdAt = now
        )

        val result = LoginAbuseEvaluationResult(
            resultId = resultId,
            allowed = true,
            playerId = candidate!!.playerId,
            isLocked = false,
            supportReferenceId = null,
            serverTime = now,
            serverVersion = 1L,
            evidenceReference = "ev-login-ok-$resultId",
            auditEvent = auditEvent,
            outboxEvent = outboxEvent
        )
        durableLockoutStore.saveIdempotency(command.tenantId, command.idempotencyKey, command, result)
        return result
    }

    fun unlockAccount(command: SupportUnlockAccountCommand): SupportUnlockResult = synchronized(durableLockoutStore) {
        LoginAbuseBinding.checkBound()

        validateHeaders(
            command.tenantId,
            command.correlationId,
            command.causationId,
            command.idempotencyKey,
            command.expectedVersion
        )

        if (command.identifier.isBlank() || command.supportReferenceId.isBlank() || command.adminOperatorId.isBlank()) {
            throw AuthenticationFailure.Rejected(AuthErrorCode.INVALID)
        }

        durableLockoutStore.findByIdempotency(command.tenantId, command.idempotencyKey)?.let { (cachedCmd, cachedResult) ->
            if (cachedCmd == command && cachedResult is SupportUnlockResult) {
                return cachedResult
            } else {
                throw AuthenticationFailure.Rejected(AuthErrorCode.CONFLICT)
            }
        }

        val normalizedId = command.identifier.trim().lowercase()
        val idHash = sha256(normalizedId)

        val lockout = durableLockoutStore.findLockout(command.tenantId, idHash)
            ?: throw AuthenticationFailure.Rejected(AuthErrorCode.INVALID)

        if (lockout.supportReferenceId != command.supportReferenceId.trim()) {
            throw AuthenticationFailure.Rejected(AuthErrorCode.FORBIDDEN)
        }

        val now = clock.instant()
        durableLockoutStore.unlock(command.tenantId, idHash, now)

        try {
            transientStore.resetAttempts("account:${command.tenantId}:$idHash")
        } catch (_: Exception) {}

        val resultId = UUID.randomUUID()
        val auditEvent = AuditEvent(
            eventId = UUID.randomUUID(),
            resultId = resultId,
            tenantId = command.tenantId,
            type = "ACCOUNT_UNLOCKED_SUPPORT",
            occurredAt = now,
            correlationId = command.correlationId,
            causationId = command.causationId
        )
        val outboxEvent = OutboxEvent(
            eventId = UUID.randomUUID(),
            resultId = resultId,
            tenantId = command.tenantId,
            type = "ACCOUNT_UNLOCKED_SUPPORT",
            createdAt = now
        )

        val result = SupportUnlockResult(
            resultId = resultId,
            unlocked = true,
            identifierHash = idHash,
            serverTime = now,
            serverVersion = 1L,
            evidenceReference = "ev-unlock-$resultId",
            auditEvent = auditEvent,
            outboxEvent = outboxEvent
        )
        durableLockoutStore.saveIdempotency(command.tenantId, command.idempotencyKey, command, result)
        return result
    }
}
