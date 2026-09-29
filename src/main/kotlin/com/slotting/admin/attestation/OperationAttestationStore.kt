package com.slotting.admin.attestation

import java.time.Instant
import java.util.concurrent.ConcurrentHashMap

interface DurableOperationChallengeStore {
    fun saveChallenge(challenge: OperationChallengeRecord): Boolean
    fun findChallenge(tenantId: String, nonceValue: String): OperationChallengeRecord?
    fun findChallengeByNonce(nonceValue: String): OperationChallengeRecord?
    fun countActiveChallenges(tenantId: String, userId: String, sessionId: String, now: Instant): Int
    fun consumeChallenge(tenantId: String, nonceValue: String, operationRef: String, consumedAt: Instant): Boolean
    fun recordAudit(audit: OperationAttestationAuditRecord): Boolean
    fun findAuditByIdempotency(tenantId: String, idempotencyKey: String): OperationAttestationAuditRecord?
}

class InMemoryOperationChallengeStore : DurableOperationChallengeStore {
    private val challenges = ConcurrentHashMap<String, OperationChallengeRecord>()
    private val auditsByIdempotency = ConcurrentHashMap<String, OperationAttestationAuditRecord>()

    private fun challengeKey(tenantId: String, nonceValue: String): String = "$tenantId:$nonceValue"
    private fun auditKey(tenantId: String, idempotencyKey: String): String = "$tenantId:$idempotencyKey"

    @Synchronized
    override fun saveChallenge(challenge: OperationChallengeRecord): Boolean {
        val key = challengeKey(challenge.tenantId, challenge.nonceValue)
        return challenges.putIfAbsent(key, challenge) == null
    }

    override fun findChallenge(tenantId: String, nonceValue: String): OperationChallengeRecord? {
        return challenges[challengeKey(tenantId, nonceValue)]
    }

    override fun findChallengeByNonce(nonceValue: String): OperationChallengeRecord? {
        return challenges.values.find { it.nonceValue == nonceValue }
    }

    @Synchronized
    override fun countActiveChallenges(tenantId: String, userId: String, sessionId: String, now: Instant): Int {
        return challenges.values.count {
            it.tenantId == tenantId &&
                it.userId == userId &&
                it.sessionId == sessionId &&
                !it.consumed &&
                it.expiresAt.isAfter(now)
        }
    }

    @Synchronized
    override fun consumeChallenge(
        tenantId: String,
        nonceValue: String,
        operationRef: String,
        consumedAt: Instant
    ): Boolean {
        val key = challengeKey(tenantId, nonceValue)
        val existing = challenges[key] ?: return false
        if (existing.consumed) {
            return false // Already consumed! Replay prevented.
        }
        val updated = existing.copy(
            consumed = true,
            consumedAt = consumedAt,
            consumedByOperationRef = operationRef
        )
        challenges[key] = updated
        return true
    }

    @Synchronized
    override fun recordAudit(audit: OperationAttestationAuditRecord): Boolean {
        val key = auditKey(audit.tenantId, audit.idempotencyKey)
        return auditsByIdempotency.putIfAbsent(key, audit) == null
    }

    override fun findAuditByIdempotency(tenantId: String, idempotencyKey: String): OperationAttestationAuditRecord? {
        return auditsByIdempotency[auditKey(tenantId, idempotencyKey)]
    }
}
