package com.slotting.admin.gameprovider

import java.time.Instant

data class GameLifecycleLeaseRecord(
    val tenantId: String,
    val gameId: String,
    val ownerId: String,
    val epoch: Long,
    val leaseExpiresAt: Instant,
    val createdAt: Instant,
    val updatedAt: Instant,
)

enum class LifecycleLeaseAcquireStatus {
    ACQUIRED,
    REJECTED_ACTIVE_LEASE,
    STALE_EPOCH,
}

data class LifecycleLeaseAcquireResult(
    val status: LifecycleLeaseAcquireStatus,
    val lease: GameLifecycleLeaseRecord?,
)

data class LifecycleLeaseToken(
    val ownerId: String,
    val epoch: Long,
)

enum class LifecycleNotOwnerReason {
    LEASE_HELD_BY_OTHER,
    LEASE_EXPIRED_OR_SUPERSEDED,
    LEASE_MISSING,
    ROUND_ALREADY_ACTIVE,
}

class LifecycleNotOwnerException(
    val reason: LifecycleNotOwnerReason,
    override val message: String,
) : RuntimeException(message)

interface GameLifecycleLeaseStore {
    fun getLease(tenantId: String, gameId: String): GameLifecycleLeaseRecord?
    fun isLeaseValid(tenantId: String, gameId: String, ownerId: String, epoch: Long): Boolean
    fun acquireOrRenew(
        tenantId: String,
        gameId: String,
        ownerId: String,
        ttlMillis: Long,
        expectedEpoch: Long? = null,
    ): LifecycleLeaseAcquireResult
    fun release(
        tenantId: String,
        gameId: String,
        ownerId: String,
        epoch: Long,
    ): Boolean
    fun lockAndVerify(
        tenantId: String,
        gameId: String,
        ownerId: String,
        epoch: Long,
    ): GameLifecycleLeaseRecord?
}
