package com.slotting.admin.locking

import com.slotting.admin.auth.*
import java.security.MessageDigest
import java.time.Clock
import java.time.Instant
import java.util.UUID

enum class SpendOperationType { DEBIT, CREDIT }

data class LockingAccount(
    val accountId: String,
    val tenantId: String,
    val balanceMinorUnits: Long,
    val currencyCode: String,
    val version: Long,
)

data class LockingCommand(
    val principal: AuthenticatedPrincipal?,
    val sessionId: String,
    val tenantId: String,
    val accountId: String,
    val amountMinorUnits: Long,
    val operationType: SpendOperationType,
    val idempotencyKey: String,
    val correlationId: String,
    val causationId: String,
    val expectedVersion: Long,
)

data class LockingResult(
    val resultId: UUID,
    val accountId: String,
    val appliedAmountMinorUnits: Long,
    val balanceAfterMinorUnits: Long,
    val accountVersionAfter: Long,
    val serverTime: Instant,
    val evidenceReference: String,
)

interface LockingStrategyStore {
    fun findByIdempotency(tenantId: String, key: String): Pair<String, LockingResult>?
    fun getAccount(tenantId: String, accountId: String): LockingAccount?
    fun save(
        result: LockingResult,
        updatedAccount: LockingAccount,
        tenantId: String,
        queryFingerprint: String,
        idempotencyKey: String,
        audit: AuditEvent,
        outbox: OutboxEvent,
    )
}

class LockingStrategyService(
    private val policy: AdminRbacPolicy,
    private val sessions: AdminSessionDirectory,
    private val store: LockingStrategyStore,
    private val clock: Clock = Clock.systemUTC(),
) {
    @Synchronized
    fun operate(command: LockingCommand): LockingResult {
        val principal = command.principal ?: throw AuthenticationFailure.Rejected(AuthErrorCode.UNAUTHENTICATED)
        if (principal.kind != PrincipalKind.ADMIN || principal.tenantId != command.tenantId) {
            throw AuthenticationFailure.Rejected(AuthErrorCode.FORBIDDEN)
        }

        val session = try {
            sessions.find(command.tenantId, principal.id, command.sessionId)
        } catch (e: Exception) {
            throw AuthenticationFailure.Rejected(AuthErrorCode.DEPENDENCY_UNAVAILABLE)
        } ?: throw AuthenticationFailure.Rejected(AuthErrorCode.FORBIDDEN)

        if (!session.active || session.expiresAt.isBefore(clock.instant())) {
            throw AuthenticationFailure.Rejected(AuthErrorCode.FORBIDDEN)
        }

        val fp = fingerprint(command)
        store.findByIdempotency(command.tenantId, command.idempotencyKey)?.let { (cachedFp, cachedResult) ->
            if (cachedFp != fp) {
                throw AuthenticationFailure.Rejected(AuthErrorCode.CONFLICT)
            }
            return cachedResult
        }

        if (command.amountMinorUnits <= 0L) {
            throw AuthenticationFailure.Rejected(AuthErrorCode.INVALID)
        }

        val account = store.getAccount(command.tenantId, command.accountId)
            ?: throw AuthenticationFailure.Rejected(AuthErrorCode.FORBIDDEN)

        if (account.version != command.expectedVersion) {
            throw AuthenticationFailure.Rejected(AuthErrorCode.STALE)
        }

        if (command.operationType == SpendOperationType.DEBIT && account.balanceMinorUnits < command.amountMinorUnits) {
            throw AuthenticationFailure.Rejected(AuthErrorCode.INVALID)
        }

        val newBalance = when (command.operationType) {
            SpendOperationType.DEBIT -> account.balanceMinorUnits - command.amountMinorUnits
            SpendOperationType.CREDIT -> account.balanceMinorUnits + command.amountMinorUnits
        }
        val newVersion = account.version + 1L
        val resultId = UUID.randomUUID()
        val now = clock.instant()
        val evidenceRef = "LOCK-EVID-$resultId"

        val updatedAccount = account.copy(
            balanceMinorUnits = newBalance,
            version = newVersion,
        )
        val result = LockingResult(
            resultId = resultId,
            accountId = account.accountId,
            appliedAmountMinorUnits = command.amountMinorUnits,
            balanceAfterMinorUnits = newBalance,
            accountVersionAfter = newVersion,
            serverTime = now,
            evidenceReference = evidenceRef,
        )
        val audit = AuditEvent(
            eventId = UUID.randomUUID(),
            resultId = resultId,
            tenantId = command.tenantId,
            type = "LOCKING_SPEND_${command.operationType.name}",
            occurredAt = now,
            correlationId = command.correlationId,
            causationId = command.causationId,
        )
        val outbox = OutboxEvent(
            eventId = UUID.randomUUID(),
            resultId = resultId,
            tenantId = command.tenantId,
            type = "LOCKING_SPEND_${command.operationType.name}",
            createdAt = now,
        )

        store.save(
            result = result,
            updatedAccount = updatedAccount,
            tenantId = command.tenantId,
            queryFingerprint = fp,
            idempotencyKey = command.idempotencyKey,
            audit = audit,
            outbox = outbox,
        )

        return result
    }

    private fun fingerprint(cmd: LockingCommand): String {
        val digest = MessageDigest.getInstance("SHA-256")
        val payload = "${cmd.tenantId}:${cmd.accountId}:${cmd.amountMinorUnits}:${cmd.operationType}:${cmd.expectedVersion}"
        return digest.digest(payload.toByteArray(Charsets.UTF_8)).joinToString("") { "%02x".format(it) }
    }
}
