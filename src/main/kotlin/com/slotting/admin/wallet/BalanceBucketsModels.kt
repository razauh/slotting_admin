package com.slotting.admin.wallet

import com.slotting.admin.auth.AuditEvent
import com.slotting.admin.auth.AuthenticatedPrincipal
import com.slotting.admin.auth.OutboxEvent
import java.time.Instant
import java.util.UUID

/**
 * Outcome-specific semantic contract for WALLET-002.
 */
const val BALANCE_BUCKETS_CONTRACT = "Bucket semantics versioned; no generic mutable `balance`."

// =============================================================================
// Bucket Types & Records
// =============================================================================

enum class BalanceBucketType {
    AVAILABLE_CASH,
    LOCKED_CASH,
    PENDING_WITHDRAWAL_CASH,
    ACTIVE_BONUS,
    LOCKED_BONUS,
    PENDING_BONUS
}

enum class BucketOperationType {
    CREDIT,
    DEBIT,
    BUCKET_TRANSFER,
    WAGER_DEDUCTION,
    BONUS_CONVERSION
}

/**
 * Sub-buckets for cash balances.
 * Invariant: all balances >= 0.
 */
data class CashBuckets(
    val availableMinorUnits: Long = 0L,
    val lockedMinorUnits: Long = 0L,
    val pendingWithdrawalMinorUnits: Long = 0L
) {
    val totalCashMinorUnits: Long
        get() = availableMinorUnits + lockedMinorUnits + pendingWithdrawalMinorUnits

    init {
        if (availableMinorUnits < 0L) {
            throw NegativeBucketBalanceException(
                "bucket sum/negative invariants break: Available cash cannot be negative ($availableMinorUnits)",
                mapOf("availableMinorUnits" to availableMinorUnits)
            )
        }
        if (lockedMinorUnits < 0L) {
            throw NegativeBucketBalanceException(
                "bucket sum/negative invariants break: Locked cash cannot be negative ($lockedMinorUnits)",
                mapOf("lockedMinorUnits" to lockedMinorUnits)
            )
        }
        if (pendingWithdrawalMinorUnits < 0L) {
            throw NegativeBucketBalanceException(
                "bucket sum/negative invariants break: Pending withdrawal cash cannot be negative ($pendingWithdrawalMinorUnits)",
                mapOf("pendingWithdrawalMinorUnits" to pendingWithdrawalMinorUnits)
            )
        }
    }
}

/**
 * Sub-buckets for bonus balances.
 * Invariant: all balances >= 0.
 */
data class BonusBuckets(
    val activeMinorUnits: Long = 0L,
    val lockedMinorUnits: Long = 0L,
    val pendingMinorUnits: Long = 0L
) {
    val totalBonusMinorUnits: Long
        get() = activeMinorUnits + lockedMinorUnits + pendingMinorUnits

    init {
        if (activeMinorUnits < 0L) {
            throw NegativeBucketBalanceException(
                "bucket sum/negative invariants break: Active bonus cannot be negative ($activeMinorUnits)",
                mapOf("activeMinorUnits" to activeMinorUnits)
            )
        }
        if (lockedMinorUnits < 0L) {
            throw NegativeBucketBalanceException(
                "bucket sum/negative invariants break: Locked bonus cannot be negative ($lockedMinorUnits)",
                mapOf("lockedMinorUnits" to lockedMinorUnits)
            )
        }
        if (pendingMinorUnits < 0L) {
            throw NegativeBucketBalanceException(
                "bucket sum/negative invariants break: Pending bonus cannot be negative ($pendingMinorUnits)",
                mapOf("pendingMinorUnits" to pendingMinorUnits)
            )
        }
    }
}

/**
 * Authoritative versioned balance buckets record for a player and currency.
 * Eliminates generic mutable `balance` in favor of discrete, typed, non-negative buckets.
 */
data class WalletBalanceBucketsRecord(
    val walletId: UUID,
    val tenantId: String,
    val ownerId: UUID,
    val currencyCode: String,
    val cash: CashBuckets = CashBuckets(),
    val bonus: BonusBuckets = BonusBuckets(),
    val version: Long = 1L,
    val createdAt: Instant,
    val updatedAt: Instant
) {
    val totalBalanceMinorUnits: Long
        get() = cash.totalCashMinorUnits + bonus.totalBonusMinorUnits

    val availableWageringMinorUnits: Long
        get() = cash.availableMinorUnits + bonus.activeMinorUnits

    val lockedBalanceMinorUnits: Long
        get() = cash.lockedMinorUnits + bonus.lockedMinorUnits

    val pendingBalanceMinorUnits: Long
        get() = cash.pendingWithdrawalMinorUnits + bonus.pendingMinorUnits

    val withdrawableCashMinorUnits: Long
        get() = cash.availableMinorUnits // Bonus funds are strictly non-withdrawable

    init {
        val sumOfBuckets = cash.availableMinorUnits +
            cash.lockedMinorUnits +
            cash.pendingWithdrawalMinorUnits +
            bonus.activeMinorUnits +
            bonus.lockedMinorUnits +
            bonus.pendingMinorUnits

        if (totalBalanceMinorUnits != sumOfBuckets) {
            throw BucketSumInvariantException(
                "bucket sum/negative invariants break: Total balance ($totalBalanceMinorUnits) does not equal sum of buckets ($sumOfBuckets)",
                mapOf("totalBalance" to totalBalanceMinorUnits, "sumOfBuckets" to sumOfBuckets)
            )
        }
        if (version < 1L) {
            throw InvalidAmountException("Version must be positive: $version", mapOf("version" to version))
        }
    }
}

// =============================================================================
// Commands & Results
// =============================================================================

data class InitializeWalletBucketsCommand(
    val principal: AuthenticatedPrincipal?,
    val tenantId: String,
    val ownerId: UUID,
    val currencyCode: String,
    val initialCashMinorUnits: Long = 0L,
    val initialBonusMinorUnits: Long = 0L,
    val idempotencyKey: String,
    val correlationId: String,
    val causationId: String,
    val expectedVersion: Long = 1L
)

data class MutateBucketCommand(
    val principal: AuthenticatedPrincipal?,
    val tenantId: String,
    val walletId: UUID,
    val operationType: BucketOperationType,
    val amountMinorUnits: Long,
    val targetBucket: BalanceBucketType,
    val sourceBucket: BalanceBucketType? = null,
    val reference: String? = null,
    val idempotencyKey: String,
    val correlationId: String,
    val causationId: String,
    val expectedVersion: Long
)

data class WagerDeductionCommand(
    val principal: AuthenticatedPrincipal?,
    val tenantId: String,
    val walletId: UUID,
    val totalWagerMinorUnits: Long,
    val preferCashFirst: Boolean = true,
    val reference: String? = null,
    val idempotencyKey: String,
    val correlationId: String,
    val causationId: String,
    val expectedVersion: Long
)

data class ConvertBonusToCashCommand(
    val principal: AuthenticatedPrincipal?,
    val tenantId: String,
    val walletId: UUID,
    val amountMinorUnits: Long,
    val reference: String? = null,
    val idempotencyKey: String,
    val correlationId: String,
    val causationId: String,
    val expectedVersion: Long
)

data class BalanceBucketsResult(
    val resultId: UUID,
    val wallet: WalletBalanceBucketsRecord,
    val operationType: BucketOperationType,
    val debitsEqualCredits: Boolean,
    val totalMinorUnitsConserved: Boolean,
    val serverTime: Instant,
    val serverVersion: Long,
    val evidenceReference: String,
    val auditEvent: AuditEvent,
    val outboxEvent: OutboxEvent,
    val hasAndroidDbImpact: Boolean = false,
    val hasAndroidLifecycleClaim: Boolean = false
)

// =============================================================================
// Domain Exceptions
// =============================================================================

class BucketSumInvariantException(
    message: String,
    details: Map<String, Any?> = emptyMap()
) : WalletException(message, "BUCKET_SUM_INVARIANT_BROKEN", details)

class NegativeBucketBalanceException(
    message: String,
    details: Map<String, Any?> = emptyMap()
) : WalletException(message, "NEGATIVE_BUCKET_BALANCE", details)

class InsufficientBucketBalanceException(
    message: String,
    details: Map<String, Any?> = emptyMap()
) : WalletException(message, "INSUFFICIENT_BUCKET_BALANCE", details)

class InvalidBucketOperationException(
    message: String,
    details: Map<String, Any?> = emptyMap()
) : WalletException(message, "INVALID_BUCKET_OPERATION", details)

class DuplicateWalletException(
    message: String,
    details: Map<String, Any?> = emptyMap()
) : WalletException(message, "DUPLICATE_WALLET", details)

class WalletNotFoundException(
    message: String,
    details: Map<String, Any?> = emptyMap()
) : WalletException(message, "WALLET_NOT_FOUND", details)
