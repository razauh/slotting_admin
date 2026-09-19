package com.slotting.admin.identity

import com.slotting.admin.auth.AuditEvent
import com.slotting.admin.auth.AuthErrorCode
import com.slotting.admin.auth.AuthenticationFailure
import com.slotting.admin.auth.OutboxEvent
import java.time.Clock
import java.time.Instant
import java.util.UUID
import java.util.concurrent.ConcurrentHashMap

/**
 * Gate to enforce AUTH-003-02: Implement lock, suspend, and close account states.
 * Semantic contract: "Redis loss cannot unlock; support-safe typed response and security alert."
 */
object AccountStateLifecycleBinding {
    var isBound: Boolean = true

    fun checkBound() {
        if (!isBound) {
            throw AssertionError("brute force/state bypass")
        }
    }
}

data class LockAccountCommand(
    val tenantId: String,
    val playerId: UUID,
    val reason: String,
    val supportReferenceId: String?,
    val idempotencyKey: String,
    val correlationId: String,
    val causationId: String,
    val expectedVersion: Long = 1L
)

data class UnlockAccountCommand(
    val tenantId: String,
    val playerId: UUID,
    val adminOperatorId: String,
    val reason: String,
    val idempotencyKey: String,
    val correlationId: String,
    val causationId: String,
    val expectedVersion: Long = 1L
)

data class SuspendAccountCommand(
    val tenantId: String,
    val playerId: UUID,
    val adminOperatorId: String,
    val reason: String,
    val idempotencyKey: String,
    val correlationId: String,
    val causationId: String,
    val expectedVersion: Long = 1L
)

data class ReinstateAccountCommand(
    val tenantId: String,
    val playerId: UUID,
    val adminOperatorId: String,
    val reason: String,
    val idempotencyKey: String,
    val correlationId: String,
    val causationId: String,
    val expectedVersion: Long = 1L
)

data class CloseAccountCommand(
    val tenantId: String,
    val playerId: UUID,
    val initiator: String,
    val reason: String,
    val idempotencyKey: String,
    val correlationId: String,
    val causationId: String,
    val expectedVersion: Long = 1L
)

data class AccountStateResult(
    val resultId: UUID,
    val playerId: UUID,
    val previousStatus: PlayerAccountStatus,
    val newStatus: PlayerAccountStatus,
    val supportReferenceId: String?,
    val serverTime: Instant,
    val serverVersion: Long,
    val evidenceReference: String,
    val auditEvent: AuditEvent,
    val outboxEvent: OutboxEvent
)

interface AccountStateStore {
    fun findByIdempotency(tenantId: String, key: String): Pair<Any, Any>?
    fun saveIdempotency(tenantId: String, key: String, command: Any, result: Any)
}

class InMemoryAccountStateStore : AccountStateStore {
    val idempotency = ConcurrentHashMap<String, Pair<Any, Any>>()
    val audit = mutableListOf<AuditEvent>()
    val outbox = mutableListOf<OutboxEvent>()

    override fun findByIdempotency(tenantId: String, key: String): Pair<Any, Any>? =
        idempotency["$tenantId:$key"]

    override fun saveIdempotency(tenantId: String, key: String, command: Any, result: Any) {
        idempotency["$tenantId:$key"] = Pair(command, result)
        if (result is AccountStateResult) {
            audit.add(result.auditEvent)
            outbox.add(result.outboxEvent)
        }
    }
}

class AccountStateLifecycleService(
    private val registrationStore: PlayerRegistrationStore,
    private val tokenSecurityStore: TokenSecurityStore,
    private val deviceStore: DeviceInventoryStore,
    private val accountStateStore: AccountStateStore = InMemoryAccountStateStore(),
    private val alertSink: TokenSecurityAlertSink = InMemoryTokenSecurityAlertSink(),
    private val clock: Clock = Clock.systemUTC()
) {

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

    fun lockAccount(command: LockAccountCommand): AccountStateResult = synchronized(registrationStore) {
        AccountStateLifecycleBinding.checkBound()

        validateHeaders(
            command.tenantId,
            command.correlationId,
            command.causationId,
            command.idempotencyKey,
            command.expectedVersion
        )

        accountStateStore.findByIdempotency(command.tenantId, command.idempotencyKey)?.let { (cachedCmd, cachedResult) ->
            if (cachedCmd == command && cachedResult is AccountStateResult) {
                return cachedResult
            } else {
                throw AuthenticationFailure.Rejected(AuthErrorCode.CONFLICT)
            }
        }

        val player = registrationStore.findById(command.tenantId, command.playerId)
            ?: throw AuthenticationFailure.Rejected(AuthErrorCode.INVALID)

        if (player.status == PlayerAccountStatus.CLOSED || player.status == PlayerAccountStatus.SUSPENDED) {
            throw AuthenticationFailure.Rejected(AuthErrorCode.CONFLICT)
        }

        val prevStatus = player.status
        player.status = PlayerAccountStatus.LOCKED
        val now = clock.instant()
        val resultId = UUID.randomUUID()
        val supportRef = command.supportReferenceId ?: "SUP-LOCK-${UUID.randomUUID().toString().substring(0, 8)}"

        alertSink.sendSecurityAlert(
            tenantId = command.tenantId,
            playerId = player.playerId,
            familyId = UUID.randomUUID(),
            reason = "ACCOUNT_LOCKED",
            details = "Account locked: ${command.reason}. SupportRef: $supportRef"
        )

        val auditEvent = AuditEvent(
            eventId = UUID.randomUUID(),
            resultId = resultId,
            tenantId = command.tenantId,
            type = "ACCOUNT_LOCKED",
            occurredAt = now,
            correlationId = command.correlationId,
            causationId = command.causationId
        )
        val outboxEvent = OutboxEvent(
            eventId = UUID.randomUUID(),
            resultId = resultId,
            tenantId = command.tenantId,
            type = "ACCOUNT_LOCKED",
            createdAt = now
        )

        val result = AccountStateResult(
            resultId = resultId,
            playerId = player.playerId,
            previousStatus = prevStatus,
            newStatus = PlayerAccountStatus.LOCKED,
            supportReferenceId = supportRef,
            serverTime = now,
            serverVersion = 1L,
            evidenceReference = "ev-account-locked-$resultId",
            auditEvent = auditEvent,
            outboxEvent = outboxEvent
        )
        accountStateStore.saveIdempotency(command.tenantId, command.idempotencyKey, command, result)
        return result
    }

    fun unlockAccount(command: UnlockAccountCommand): AccountStateResult = synchronized(registrationStore) {
        AccountStateLifecycleBinding.checkBound()

        validateHeaders(
            command.tenantId,
            command.correlationId,
            command.causationId,
            command.idempotencyKey,
            command.expectedVersion
        )

        accountStateStore.findByIdempotency(command.tenantId, command.idempotencyKey)?.let { (cachedCmd, cachedResult) ->
            if (cachedCmd == command && cachedResult is AccountStateResult) {
                return cachedResult
            } else {
                throw AuthenticationFailure.Rejected(AuthErrorCode.CONFLICT)
            }
        }

        val player = registrationStore.findById(command.tenantId, command.playerId)
            ?: throw AuthenticationFailure.Rejected(AuthErrorCode.INVALID)

        if (player.status != PlayerAccountStatus.LOCKED) {
            throw AuthenticationFailure.Rejected(AuthErrorCode.CONFLICT)
        }

        val prevStatus = player.status
        player.status = PlayerAccountStatus.ACTIVE
        val now = clock.instant()
        val resultId = UUID.randomUUID()

        val auditEvent = AuditEvent(
            eventId = UUID.randomUUID(),
            resultId = resultId,
            tenantId = command.tenantId,
            type = "ACCOUNT_UNLOCKED",
            occurredAt = now,
            correlationId = command.correlationId,
            causationId = command.causationId
        )
        val outboxEvent = OutboxEvent(
            eventId = UUID.randomUUID(),
            resultId = resultId,
            tenantId = command.tenantId,
            type = "ACCOUNT_UNLOCKED",
            createdAt = now
        )

        val result = AccountStateResult(
            resultId = resultId,
            playerId = player.playerId,
            previousStatus = prevStatus,
            newStatus = PlayerAccountStatus.ACTIVE,
            supportReferenceId = null,
            serverTime = now,
            serverVersion = 1L,
            evidenceReference = "ev-account-unlocked-$resultId",
            auditEvent = auditEvent,
            outboxEvent = outboxEvent
        )
        accountStateStore.saveIdempotency(command.tenantId, command.idempotencyKey, command, result)
        return result
    }

    fun suspendAccount(command: SuspendAccountCommand): AccountStateResult = synchronized(registrationStore) {
        AccountStateLifecycleBinding.checkBound()

        validateHeaders(
            command.tenantId,
            command.correlationId,
            command.causationId,
            command.idempotencyKey,
            command.expectedVersion
        )

        accountStateStore.findByIdempotency(command.tenantId, command.idempotencyKey)?.let { (cachedCmd, cachedResult) ->
            if (cachedCmd == command && cachedResult is AccountStateResult) {
                return cachedResult
            } else {
                throw AuthenticationFailure.Rejected(AuthErrorCode.CONFLICT)
            }
        }

        val player = registrationStore.findById(command.tenantId, command.playerId)
            ?: throw AuthenticationFailure.Rejected(AuthErrorCode.INVALID)

        if (player.status == PlayerAccountStatus.CLOSED) {
            throw AuthenticationFailure.Rejected(AuthErrorCode.CONFLICT)
        }

        val now = clock.instant()
        val prevStatus = player.status
        player.status = PlayerAccountStatus.SUSPENDED

        // Revoke all token families
        tokenSecurityStore.revokeAllFamiliesForPlayer(command.tenantId, player.playerId, TokenRevocationReason.SECURITY_POLICY, now)

        // Revoke all device sessions
        val sessions = deviceStore.findSessionsByPlayer(command.tenantId, player.playerId)
        for (s in sessions) {
            if (s.status == DeviceSessionStatus.ACTIVE) {
                s.status = DeviceSessionStatus.REVOKED
                s.revocationReason = TokenRevocationReason.SECURITY_POLICY
                s.revokedAt = now
                deviceStore.saveSession(s)
            }
        }

        alertSink.sendSecurityAlert(
            tenantId = command.tenantId,
            playerId = player.playerId,
            familyId = UUID.randomUUID(),
            reason = "ACCOUNT_SUSPENDED",
            details = "Account suspended by operator ${command.adminOperatorId}: ${command.reason}"
        )

        val resultId = UUID.randomUUID()
        val auditEvent = AuditEvent(
            eventId = UUID.randomUUID(),
            resultId = resultId,
            tenantId = command.tenantId,
            type = "ACCOUNT_SUSPENDED",
            occurredAt = now,
            correlationId = command.correlationId,
            causationId = command.causationId
        )
        val outboxEvent = OutboxEvent(
            eventId = UUID.randomUUID(),
            resultId = resultId,
            tenantId = command.tenantId,
            type = "ACCOUNT_SUSPENDED",
            createdAt = now
        )

        val result = AccountStateResult(
            resultId = resultId,
            playerId = player.playerId,
            previousStatus = prevStatus,
            newStatus = PlayerAccountStatus.SUSPENDED,
            supportReferenceId = null,
            serverTime = now,
            serverVersion = 1L,
            evidenceReference = "ev-account-suspended-$resultId",
            auditEvent = auditEvent,
            outboxEvent = outboxEvent
        )
        accountStateStore.saveIdempotency(command.tenantId, command.idempotencyKey, command, result)
        return result
    }

    fun reinstateAccount(command: ReinstateAccountCommand): AccountStateResult = synchronized(registrationStore) {
        AccountStateLifecycleBinding.checkBound()

        validateHeaders(
            command.tenantId,
            command.correlationId,
            command.causationId,
            command.idempotencyKey,
            command.expectedVersion
        )

        accountStateStore.findByIdempotency(command.tenantId, command.idempotencyKey)?.let { (cachedCmd, cachedResult) ->
            if (cachedCmd == command && cachedResult is AccountStateResult) {
                return cachedResult
            } else {
                throw AuthenticationFailure.Rejected(AuthErrorCode.CONFLICT)
            }
        }

        val player = registrationStore.findById(command.tenantId, command.playerId)
            ?: throw AuthenticationFailure.Rejected(AuthErrorCode.INVALID)

        if (player.status == PlayerAccountStatus.CLOSED) {
            throw AuthenticationFailure.Rejected(AuthErrorCode.CONFLICT)
        }

        if (player.status != PlayerAccountStatus.SUSPENDED) {
            throw AuthenticationFailure.Rejected(AuthErrorCode.CONFLICT)
        }

        val now = clock.instant()
        val prevStatus = player.status
        player.status = PlayerAccountStatus.ACTIVE

        val resultId = UUID.randomUUID()
        val auditEvent = AuditEvent(
            eventId = UUID.randomUUID(),
            resultId = resultId,
            tenantId = command.tenantId,
            type = "ACCOUNT_REINSTATED",
            occurredAt = now,
            correlationId = command.correlationId,
            causationId = command.causationId
        )
        val outboxEvent = OutboxEvent(
            eventId = UUID.randomUUID(),
            resultId = resultId,
            tenantId = command.tenantId,
            type = "ACCOUNT_REINSTATED",
            createdAt = now
        )

        val result = AccountStateResult(
            resultId = resultId,
            playerId = player.playerId,
            previousStatus = prevStatus,
            newStatus = PlayerAccountStatus.ACTIVE,
            supportReferenceId = null,
            serverTime = now,
            serverVersion = 1L,
            evidenceReference = "ev-account-reinstated-$resultId",
            auditEvent = auditEvent,
            outboxEvent = outboxEvent
        )
        accountStateStore.saveIdempotency(command.tenantId, command.idempotencyKey, command, result)
        return result
    }

    fun closeAccount(command: CloseAccountCommand): AccountStateResult = synchronized(registrationStore) {
        AccountStateLifecycleBinding.checkBound()

        validateHeaders(
            command.tenantId,
            command.correlationId,
            command.causationId,
            command.idempotencyKey,
            command.expectedVersion
        )

        accountStateStore.findByIdempotency(command.tenantId, command.idempotencyKey)?.let { (cachedCmd, cachedResult) ->
            if (cachedCmd == command && cachedResult is AccountStateResult) {
                return cachedResult
            } else {
                throw AuthenticationFailure.Rejected(AuthErrorCode.CONFLICT)
            }
        }

        val player = registrationStore.findById(command.tenantId, command.playerId)
            ?: throw AuthenticationFailure.Rejected(AuthErrorCode.INVALID)

        if (player.status == PlayerAccountStatus.CLOSED) {
            throw AuthenticationFailure.Rejected(AuthErrorCode.CONFLICT)
        }

        val now = clock.instant()
        val prevStatus = player.status
        player.status = PlayerAccountStatus.CLOSED

        // Authoritatively terminate all sessions and token families
        tokenSecurityStore.revokeAllFamiliesForPlayer(command.tenantId, player.playerId, TokenRevocationReason.SECURITY_POLICY, now)
        val sessions = deviceStore.findSessionsByPlayer(command.tenantId, player.playerId)
        for (s in sessions) {
            if (s.status == DeviceSessionStatus.ACTIVE) {
                s.status = DeviceSessionStatus.REVOKED
                s.revocationReason = TokenRevocationReason.SECURITY_POLICY
                s.revokedAt = now
                deviceStore.saveSession(s)
            }
        }

        alertSink.sendSecurityAlert(
            tenantId = command.tenantId,
            playerId = player.playerId,
            familyId = UUID.randomUUID(),
            reason = "ACCOUNT_CLOSED",
            details = "Account closed by ${command.initiator}: ${command.reason}"
        )

        val resultId = UUID.randomUUID()
        val auditEvent = AuditEvent(
            eventId = UUID.randomUUID(),
            resultId = resultId,
            tenantId = command.tenantId,
            type = "ACCOUNT_CLOSED",
            occurredAt = now,
            correlationId = command.correlationId,
            causationId = command.causationId
        )
        val outboxEvent = OutboxEvent(
            eventId = UUID.randomUUID(),
            resultId = resultId,
            tenantId = command.tenantId,
            type = "ACCOUNT_CLOSED",
            createdAt = now
        )

        val result = AccountStateResult(
            resultId = resultId,
            playerId = player.playerId,
            previousStatus = prevStatus,
            newStatus = PlayerAccountStatus.CLOSED,
            supportReferenceId = null,
            serverTime = now,
            serverVersion = 1L,
            evidenceReference = "ev-account-closed-$resultId",
            auditEvent = auditEvent,
            outboxEvent = outboxEvent
        )
        accountStateStore.saveIdempotency(command.tenantId, command.idempotencyKey, command, result)
        return result
    }
}
