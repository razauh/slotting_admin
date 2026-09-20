package com.slotting.admin.wallet

import com.slotting.admin.auth.AuditEvent
import com.slotting.admin.auth.AuthenticatedPrincipal
import com.slotting.admin.auth.OutboxEvent
import java.security.MessageDigest
import java.time.Clock
import java.time.Instant
import java.util.UUID
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.locks.ReentrantLock
import kotlin.concurrent.withLock

// =============================================================================
// Store Interfaces
// =============================================================================

interface BalanceBucketsStore {
    fun findWalletById(tenantId: String, walletId: UUID): WalletBalanceBucketsRecord?
    fun findWalletByOwnerAndCurrency(tenantId: String, ownerId: UUID, currencyCode: String): WalletBalanceBucketsRecord?
    fun saveWallet(wallet: WalletBalanceBucketsRecord)
    fun findIdempotency(tenantId: String, key: String): Pair<String, Any>?
    fun saveIdempotency(tenantId: String, key: String, signature: String, result: Any)
    fun listWalletsByOwner(tenantId: String, ownerId: UUID): List<WalletBalanceBucketsRecord>
    fun clear()
}

class InMemoryBalanceBucketsStore : BalanceBucketsStore {
    private val walletsById = ConcurrentHashMap<String, WalletBalanceBucketsRecord>()
    private val walletsByOwnerCurrency = ConcurrentHashMap<String, UUID>()
    private val idempotencyRecords = ConcurrentHashMap<String, Pair<String, Any>>()
    val auditEvents = mutableListOf<AuditEvent>()
    val outboxEvents = mutableListOf<OutboxEvent>()

    private val globalLock = ReentrantLock()

    private fun ownerCurrencyKey(tenantId: String, ownerId: UUID, currencyCode: String): String =
        "$tenantId:$ownerId:$currencyCode"

    override fun findWalletById(tenantId: String, walletId: UUID): WalletBalanceBucketsRecord? {
        val record = walletsById["$tenantId:$walletId"]
        return if (record != null && record.tenantId == tenantId) record else null
    }

    override fun findWalletByOwnerAndCurrency(
        tenantId: String,
        ownerId: UUID,
        currencyCode: String
    ): WalletBalanceBucketsRecord? {
        val walletId = walletsByOwnerCurrency[ownerCurrencyKey(tenantId, ownerId, currencyCode)]
            ?: return null
        return findWalletById(tenantId, walletId)
    }

    override fun saveWallet(wallet: WalletBalanceBucketsRecord) {
        globalLock.withLock {
            walletsById["${wallet.tenantId}:${wallet.walletId}"] = wallet
            walletsByOwnerCurrency[ownerCurrencyKey(wallet.tenantId, wallet.ownerId, wallet.currencyCode)] = wallet.walletId
        }
    }

    override fun findIdempotency(tenantId: String, key: String): Pair<String, Any>? =
        idempotencyRecords["$tenantId:$key"]

    override fun saveIdempotency(tenantId: String, key: String, signature: String, result: Any) {
        globalLock.withLock {
            idempotencyRecords["$tenantId:$key"] = Pair(signature, result)
            if (result is BalanceBucketsResult) {
                auditEvents.add(result.auditEvent)
                outboxEvents.add(result.outboxEvent)
            }
        }
    }

    override fun listWalletsByOwner(tenantId: String, ownerId: UUID): List<WalletBalanceBucketsRecord> {
        return walletsById.values
            .filter { it.tenantId == tenantId && it.ownerId == ownerId }
            .toList()
    }

    override fun clear() {
        globalLock.withLock {
            walletsById.clear()
            walletsByOwnerCurrency.clear()
            idempotencyRecords.clear()
            auditEvents.clear()
            outboxEvents.clear()
        }
    }
}

// =============================================================================
// Authoritative Balance Buckets Service
// =============================================================================

class BalanceBucketsService(
    private val store: BalanceBucketsStore = InMemoryBalanceBucketsStore(),
    private val clock: Clock = Clock.systemUTC()
) {
    private val executionLock = ReentrantLock()

    fun checkAndroidDbImpact(): Boolean = false
    fun hasAndroidLifecycleClaim(): Boolean = false

    private fun validatePrincipal(principal: AuthenticatedPrincipal?, tenantId: String) {
        if (principal == null) {
            throw UnauthorizedException(
                "Unauthenticated principal: request must provide an authenticated principal.",
                mapOf("reason" to "NULL_PRINCIPAL")
            )
        }
        if (principal.tenantId != tenantId) {
            throw IdorForbiddenException(
                "Cross-tenant IDOR access forbidden. Principal tenant '${principal.tenantId}' != target tenant '$tenantId'.",
                mapOf("principalTenant" to principal.tenantId, "targetTenant" to tenantId)
            )
        }
    }

    private fun sha256(input: String): String {
        val digest = MessageDigest.getInstance("SHA-256")
        val bytes = digest.digest(input.toByteArray(Charsets.UTF_8))
        return bytes.joinToString("") { "%02x".format(it) }
    }

    /**
     * Initializes a player's versioned balance buckets for a currency.
     */
    fun initializeWallet(command: InitializeWalletBucketsCommand): BalanceBucketsResult {
        BalanceBucketsBinding.checkBound()
        validatePrincipal(command.principal, command.tenantId)

        val normalizedCurrency = IsoCurrencyValidator.validate(command.currencyCode)

        if (command.initialCashMinorUnits < 0L) {
            throw NegativeBucketBalanceException(
                "bucket sum/negative invariants break: Initial cash cannot be negative (${command.initialCashMinorUnits})",
                mapOf("initialCash" to command.initialCashMinorUnits)
            )
        }
        if (command.initialBonusMinorUnits < 0L) {
            throw NegativeBucketBalanceException(
                "bucket sum/negative invariants break: Initial bonus cannot be negative (${command.initialBonusMinorUnits})",
                mapOf("initialBonus" to command.initialBonusMinorUnits)
            )
        }

        val payloadSignature = sha256(
            "${command.tenantId}:${command.ownerId}:$normalizedCurrency:${command.initialCashMinorUnits}:${command.initialBonusMinorUnits}:${command.expectedVersion}"
        )

        executionLock.withLock {
            val cached = store.findIdempotency(command.tenantId, command.idempotencyKey)
            if (cached != null) {
                if (cached.first == payloadSignature) {
                    return cached.second as BalanceBucketsResult
                } else {
                    throw ConcurrencyConflictException(
                        "Idempotency conflict for key '${command.idempotencyKey}'. Cached signature does not match replayed payload.",
                        mapOf("idempotencyKey" to command.idempotencyKey)
                    )
                }
            }

            val existing = store.findWalletByOwnerAndCurrency(
                command.tenantId,
                command.ownerId,
                normalizedCurrency
            )
            if (existing != null) {
                throw DuplicateWalletException(
                    "Wallet already exists for owner '${command.ownerId}' and currency '$normalizedCurrency'.",
                    mapOf("walletId" to existing.walletId, "ownerId" to command.ownerId, "currency" to normalizedCurrency)
                )
            }

            val now = Instant.now(clock)
            val newWalletId = UUID.randomUUID()
            val wallet = WalletBalanceBucketsRecord(
                walletId = newWalletId,
                tenantId = command.tenantId,
                ownerId = command.ownerId,
                currencyCode = normalizedCurrency,
                cash = CashBuckets(availableMinorUnits = command.initialCashMinorUnits),
                bonus = BonusBuckets(activeMinorUnits = command.initialBonusMinorUnits),
                version = command.expectedVersion,
                createdAt = now,
                updatedAt = now
            )

            store.saveWallet(wallet)

            val resultId = UUID.randomUUID()
            val auditEvent = AuditEvent(
                eventId = UUID.randomUUID(),
                resultId = resultId,
                tenantId = command.tenantId,
                type = "BALANCE_BUCKETS_INITIALIZED",
                occurredAt = now,
                correlationId = command.correlationId,
                causationId = command.causationId
            )

            val outboxEvent = OutboxEvent(
                eventId = UUID.randomUUID(),
                resultId = resultId,
                tenantId = command.tenantId,
                type = "balance.buckets.initialized",
                createdAt = now
            )

            val result = BalanceBucketsResult(
                resultId = resultId,
                wallet = wallet,
                operationType = BucketOperationType.CREDIT,
                debitsEqualCredits = true,
                totalMinorUnitsConserved = true,
                serverTime = now,
                serverVersion = wallet.version,
                evidenceReference = "evidence/wallet/buckets/${wallet.walletId}",
                auditEvent = auditEvent,
                outboxEvent = outboxEvent,
                hasAndroidDbImpact = false,
                hasAndroidLifecycleClaim = false
            )

            store.saveIdempotency(command.tenantId, command.idempotencyKey, payloadSignature, result)
            return result
        }
    }

    /**
     * Mutates balance buckets with versioned state transitions and strict non-negative invariants.
     */
    fun mutateBucket(command: MutateBucketCommand): BalanceBucketsResult {
        BalanceBucketsBinding.checkBound()
        validatePrincipal(command.principal, command.tenantId)

        if (command.amountMinorUnits <= 0L) {
            throw InvalidAmountException(
                "Mutation amount must be strictly positive: ${command.amountMinorUnits}",
                mapOf("amountMinorUnits" to command.amountMinorUnits)
            )
        }

        val payloadSignature = sha256(
            "${command.tenantId}:${command.walletId}:${command.operationType}:${command.targetBucket}:${command.sourceBucket}:${command.amountMinorUnits}:${command.expectedVersion}"
        )

        executionLock.withLock {
            val cached = store.findIdempotency(command.tenantId, command.idempotencyKey)
            if (cached != null) {
                if (cached.first == payloadSignature) {
                    return cached.second as BalanceBucketsResult
                } else {
                    throw ConcurrencyConflictException(
                        "Idempotency conflict for key '${command.idempotencyKey}'. Cached signature does not match replayed payload.",
                        mapOf("idempotencyKey" to command.idempotencyKey)
                    )
                }
            }

            val wallet = store.findWalletById(command.tenantId, command.walletId)
                ?: throw WalletNotFoundException(
                    "Wallet not found: '${command.walletId}'",
                    mapOf("walletId" to command.walletId)
                )

            if (wallet.version != command.expectedVersion) {
                throw StaleVersionException(
                    "Stale version for wallet ${wallet.walletId}: expected ${command.expectedVersion}, found ${wallet.version}",
                    mapOf("expectedVersion" to command.expectedVersion, "actualVersion" to wallet.version)
                )
            }

            val now = Instant.now(clock)
            val updatedWallet: WalletBalanceBucketsRecord

            when (command.operationType) {
                BucketOperationType.CREDIT -> {
                    // Credit directly into target bucket
                    val newCash: CashBuckets
                    val newBonus: BonusBuckets

                    when (command.targetBucket) {
                        BalanceBucketType.AVAILABLE_CASH -> {
                            newCash = wallet.cash.copy(availableMinorUnits = wallet.cash.availableMinorUnits + command.amountMinorUnits)
                            newBonus = wallet.bonus
                        }
                        BalanceBucketType.LOCKED_CASH -> {
                            newCash = wallet.cash.copy(lockedMinorUnits = wallet.cash.lockedMinorUnits + command.amountMinorUnits)
                            newBonus = wallet.bonus
                        }
                        BalanceBucketType.PENDING_WITHDRAWAL_CASH -> {
                            newCash = wallet.cash.copy(pendingWithdrawalMinorUnits = wallet.cash.pendingWithdrawalMinorUnits + command.amountMinorUnits)
                            newBonus = wallet.bonus
                        }
                        BalanceBucketType.ACTIVE_BONUS -> {
                            newCash = wallet.cash
                            newBonus = wallet.bonus.copy(activeMinorUnits = wallet.bonus.activeMinorUnits + command.amountMinorUnits)
                        }
                        BalanceBucketType.LOCKED_BONUS -> {
                            newCash = wallet.cash
                            newBonus = wallet.bonus.copy(lockedMinorUnits = wallet.bonus.lockedMinorUnits + command.amountMinorUnits)
                        }
                        BalanceBucketType.PENDING_BONUS -> {
                            newCash = wallet.cash
                            newBonus = wallet.bonus.copy(pendingMinorUnits = wallet.bonus.pendingMinorUnits + command.amountMinorUnits)
                        }
                    }

                    updatedWallet = wallet.copy(
                        cash = newCash,
                        bonus = newBonus,
                        version = wallet.version + 1,
                        updatedAt = now
                    )
                }

                BucketOperationType.DEBIT -> {
                    // Debit directly from target bucket
                    var newCash = wallet.cash
                    var newBonus = wallet.bonus

                    when (command.targetBucket) {
                        BalanceBucketType.AVAILABLE_CASH -> {
                            if (wallet.cash.availableMinorUnits < command.amountMinorUnits) {
                                throw InsufficientBucketBalanceException(
                                    "bucket sum/negative invariants break: Insufficient available cash: ${wallet.cash.availableMinorUnits} < ${command.amountMinorUnits}",
                                    mapOf("available" to wallet.cash.availableMinorUnits, "required" to command.amountMinorUnits)
                                )
                            }
                            newCash = wallet.cash.copy(availableMinorUnits = wallet.cash.availableMinorUnits - command.amountMinorUnits)
                        }
                        BalanceBucketType.LOCKED_CASH -> {
                            if (wallet.cash.lockedMinorUnits < command.amountMinorUnits) {
                                throw InsufficientBucketBalanceException(
                                    "bucket sum/negative invariants break: Insufficient locked cash: ${wallet.cash.lockedMinorUnits} < ${command.amountMinorUnits}",
                                    mapOf("locked" to wallet.cash.lockedMinorUnits, "required" to command.amountMinorUnits)
                                )
                            }
                            newCash = wallet.cash.copy(lockedMinorUnits = wallet.cash.lockedMinorUnits - command.amountMinorUnits)
                        }
                        BalanceBucketType.PENDING_WITHDRAWAL_CASH -> {
                            if (wallet.cash.pendingWithdrawalMinorUnits < command.amountMinorUnits) {
                                throw InsufficientBucketBalanceException(
                                    "bucket sum/negative invariants break: Insufficient pending withdrawal cash: ${wallet.cash.pendingWithdrawalMinorUnits} < ${command.amountMinorUnits}",
                                    mapOf("pendingWithdrawal" to wallet.cash.pendingWithdrawalMinorUnits, "required" to command.amountMinorUnits)
                                )
                            }
                            newCash = wallet.cash.copy(pendingWithdrawalMinorUnits = wallet.cash.pendingWithdrawalMinorUnits - command.amountMinorUnits)
                        }
                        BalanceBucketType.ACTIVE_BONUS -> {
                            if (wallet.bonus.activeMinorUnits < command.amountMinorUnits) {
                                throw InsufficientBucketBalanceException(
                                    "bucket sum/negative invariants break: Insufficient active bonus: ${wallet.bonus.activeMinorUnits} < ${command.amountMinorUnits}",
                                    mapOf("activeBonus" to wallet.bonus.activeMinorUnits, "required" to command.amountMinorUnits)
                                )
                            }
                            newBonus = wallet.bonus.copy(activeMinorUnits = wallet.bonus.activeMinorUnits - command.amountMinorUnits)
                        }
                        BalanceBucketType.LOCKED_BONUS -> {
                            if (wallet.bonus.lockedMinorUnits < command.amountMinorUnits) {
                                throw InsufficientBucketBalanceException(
                                    "bucket sum/negative invariants break: Insufficient locked bonus: ${wallet.bonus.lockedMinorUnits} < ${command.amountMinorUnits}",
                                    mapOf("lockedBonus" to wallet.bonus.lockedMinorUnits, "required" to command.amountMinorUnits)
                                )
                            }
                            newBonus = wallet.bonus.copy(lockedMinorUnits = wallet.bonus.lockedMinorUnits - command.amountMinorUnits)
                        }
                        BalanceBucketType.PENDING_BONUS -> {
                            if (wallet.bonus.pendingMinorUnits < command.amountMinorUnits) {
                                throw InsufficientBucketBalanceException(
                                    "bucket sum/negative invariants break: Insufficient pending bonus: ${wallet.bonus.pendingMinorUnits} < ${command.amountMinorUnits}",
                                    mapOf("pendingBonus" to wallet.bonus.pendingMinorUnits, "required" to command.amountMinorUnits)
                                )
                            }
                            newBonus = wallet.bonus.copy(pendingMinorUnits = wallet.bonus.pendingMinorUnits - command.amountMinorUnits)
                        }
                    }

                    updatedWallet = wallet.copy(
                        cash = newCash,
                        bonus = newBonus,
                        version = wallet.version + 1,
                        updatedAt = now
                    )
                }

                BucketOperationType.BUCKET_TRANSFER -> {
                    val src = command.sourceBucket
                        ?: throw InvalidBucketOperationException("BUCKET_TRANSFER requires a non-null sourceBucket")

                    // Cannot transfer between unrelated cash and bonus directly via generic BUCKET_TRANSFER
                    // (e.g. bonus cannot become cash without conversion rule)
                    if ((src == BalanceBucketType.ACTIVE_BONUS || src == BalanceBucketType.LOCKED_BONUS || src == BalanceBucketType.PENDING_BONUS) &&
                        (command.targetBucket == BalanceBucketType.AVAILABLE_CASH || command.targetBucket == BalanceBucketType.LOCKED_CASH || command.targetBucket == BalanceBucketType.PENDING_WITHDRAWAL_CASH)
                    ) {
                        throw InvalidBucketOperationException("Cannot transfer bonus bucket to cash bucket without formal BONUS_CONVERSION")
                    }

                    var intermediateCash = wallet.cash
                    var intermediateBonus = wallet.bonus

                    // Debit source
                    when (src) {
                        BalanceBucketType.AVAILABLE_CASH -> {
                            if (intermediateCash.availableMinorUnits < command.amountMinorUnits) {
                                throw InsufficientBucketBalanceException(
                                    "bucket sum/negative invariants break: Insufficient available cash: ${intermediateCash.availableMinorUnits} < ${command.amountMinorUnits}",
                                    mapOf("available" to intermediateCash.availableMinorUnits, "required" to command.amountMinorUnits)
                                )
                            }
                            intermediateCash = intermediateCash.copy(availableMinorUnits = intermediateCash.availableMinorUnits - command.amountMinorUnits)
                        }
                        BalanceBucketType.LOCKED_CASH -> {
                            if (intermediateCash.lockedMinorUnits < command.amountMinorUnits) {
                                throw InsufficientBucketBalanceException(
                                    "bucket sum/negative invariants break: Insufficient locked cash: ${intermediateCash.lockedMinorUnits} < ${command.amountMinorUnits}",
                                    mapOf("locked" to intermediateCash.lockedMinorUnits, "required" to command.amountMinorUnits)
                                )
                            }
                            intermediateCash = intermediateCash.copy(lockedMinorUnits = intermediateCash.lockedMinorUnits - command.amountMinorUnits)
                        }
                        BalanceBucketType.PENDING_WITHDRAWAL_CASH -> {
                            if (intermediateCash.pendingWithdrawalMinorUnits < command.amountMinorUnits) {
                                throw InsufficientBucketBalanceException(
                                    "bucket sum/negative invariants break: Insufficient pending withdrawal cash: ${intermediateCash.pendingWithdrawalMinorUnits} < ${command.amountMinorUnits}",
                                    mapOf("pendingWithdrawal" to intermediateCash.pendingWithdrawalMinorUnits, "required" to command.amountMinorUnits)
                                )
                            }
                            intermediateCash = intermediateCash.copy(pendingWithdrawalMinorUnits = intermediateCash.pendingWithdrawalMinorUnits - command.amountMinorUnits)
                        }
                        BalanceBucketType.ACTIVE_BONUS -> {
                            if (intermediateBonus.activeMinorUnits < command.amountMinorUnits) {
                                throw InsufficientBucketBalanceException(
                                    "bucket sum/negative invariants break: Insufficient active bonus: ${intermediateBonus.activeMinorUnits} < ${command.amountMinorUnits}",
                                    mapOf("activeBonus" to intermediateBonus.activeMinorUnits, "required" to command.amountMinorUnits)
                                )
                            }
                            intermediateBonus = intermediateBonus.copy(activeMinorUnits = intermediateBonus.activeMinorUnits - command.amountMinorUnits)
                        }
                        BalanceBucketType.LOCKED_BONUS -> {
                            if (intermediateBonus.lockedMinorUnits < command.amountMinorUnits) {
                                throw InsufficientBucketBalanceException(
                                    "bucket sum/negative invariants break: Insufficient locked bonus: ${intermediateBonus.lockedMinorUnits} < ${command.amountMinorUnits}",
                                    mapOf("lockedBonus" to intermediateBonus.lockedMinorUnits, "required" to command.amountMinorUnits)
                                )
                            }
                            intermediateBonus = intermediateBonus.copy(lockedMinorUnits = intermediateBonus.lockedMinorUnits - command.amountMinorUnits)
                        }
                        BalanceBucketType.PENDING_BONUS -> {
                            if (intermediateBonus.pendingMinorUnits < command.amountMinorUnits) {
                                throw InsufficientBucketBalanceException(
                                    "bucket sum/negative invariants break: Insufficient pending bonus: ${intermediateBonus.pendingMinorUnits} < ${command.amountMinorUnits}",
                                    mapOf("pendingBonus" to intermediateBonus.pendingMinorUnits, "required" to command.amountMinorUnits)
                                )
                            }
                            intermediateBonus = intermediateBonus.copy(pendingMinorUnits = intermediateBonus.pendingMinorUnits - command.amountMinorUnits)
                        }
                    }

                    // Credit destination
                    when (command.targetBucket) {
                        BalanceBucketType.AVAILABLE_CASH -> {
                            intermediateCash = intermediateCash.copy(availableMinorUnits = intermediateCash.availableMinorUnits + command.amountMinorUnits)
                        }
                        BalanceBucketType.LOCKED_CASH -> {
                            intermediateCash = intermediateCash.copy(lockedMinorUnits = intermediateCash.lockedMinorUnits + command.amountMinorUnits)
                        }
                        BalanceBucketType.PENDING_WITHDRAWAL_CASH -> {
                            intermediateCash = intermediateCash.copy(pendingWithdrawalMinorUnits = intermediateCash.pendingWithdrawalMinorUnits + command.amountMinorUnits)
                        }
                        BalanceBucketType.ACTIVE_BONUS -> {
                            intermediateBonus = intermediateBonus.copy(activeMinorUnits = intermediateBonus.activeMinorUnits + command.amountMinorUnits)
                        }
                        BalanceBucketType.LOCKED_BONUS -> {
                            intermediateBonus = intermediateBonus.copy(lockedMinorUnits = intermediateBonus.lockedMinorUnits + command.amountMinorUnits)
                        }
                        BalanceBucketType.PENDING_BONUS -> {
                            intermediateBonus = intermediateBonus.copy(pendingMinorUnits = intermediateBonus.pendingMinorUnits + command.amountMinorUnits)
                        }
                    }

                    updatedWallet = wallet.copy(
                        cash = intermediateCash,
                        bonus = intermediateBonus,
                        version = wallet.version + 1,
                        updatedAt = now
                    )
                }

                else -> throw InvalidBucketOperationException("Unsupported operation type in mutateBucket: ${command.operationType}")
            }

            store.saveWallet(updatedWallet)

            val resultId = UUID.randomUUID()
            val auditEvent = AuditEvent(
                eventId = UUID.randomUUID(),
                resultId = resultId,
                tenantId = command.tenantId,
                type = "BALANCE_BUCKETS_MUTATED",
                occurredAt = now,
                correlationId = command.correlationId,
                causationId = command.causationId
            )

            val outboxEvent = OutboxEvent(
                eventId = UUID.randomUUID(),
                resultId = resultId,
                tenantId = command.tenantId,
                type = "balance.buckets.mutated",
                createdAt = now
            )

            val result = BalanceBucketsResult(
                resultId = resultId,
                wallet = updatedWallet,
                operationType = command.operationType,
                debitsEqualCredits = true,
                totalMinorUnitsConserved = true,
                serverTime = now,
                serverVersion = updatedWallet.version,
                evidenceReference = "evidence/wallet/buckets/${updatedWallet.walletId}",
                auditEvent = auditEvent,
                outboxEvent = outboxEvent,
                hasAndroidDbImpact = false,
                hasAndroidLifecycleClaim = false
            )

            store.saveIdempotency(command.tenantId, command.idempotencyKey, payloadSignature, result)
            return result
        }
    }

    /**
     * Wagering deduction according to precedence rules (cash first, then active bonus).
     */
    fun deductWager(command: WagerDeductionCommand): BalanceBucketsResult {
        BalanceBucketsBinding.checkBound()
        validatePrincipal(command.principal, command.tenantId)

        if (command.totalWagerMinorUnits <= 0L) {
            throw InvalidAmountException(
                "Wager deduction amount must be strictly positive: ${command.totalWagerMinorUnits}",
                mapOf("totalWagerMinorUnits" to command.totalWagerMinorUnits)
            )
        }

        val payloadSignature = sha256(
            "${command.tenantId}:${command.walletId}:${command.totalWagerMinorUnits}:${command.preferCashFirst}:${command.expectedVersion}"
        )

        executionLock.withLock {
            val cached = store.findIdempotency(command.tenantId, command.idempotencyKey)
            if (cached != null) {
                if (cached.first == payloadSignature) {
                    return cached.second as BalanceBucketsResult
                } else {
                    throw ConcurrencyConflictException(
                        "Idempotency conflict for key '${command.idempotencyKey}'. Cached signature does not match replayed payload.",
                        mapOf("idempotencyKey" to command.idempotencyKey)
                    )
                }
            }

            val wallet = store.findWalletById(command.tenantId, command.walletId)
                ?: throw WalletNotFoundException(
                    "Wallet not found: '${command.walletId}'",
                    mapOf("walletId" to command.walletId)
                )

            if (wallet.version != command.expectedVersion) {
                throw StaleVersionException(
                    "Stale version for wallet: expected ${command.expectedVersion}, found ${wallet.version}",
                    mapOf("expectedVersion" to command.expectedVersion, "actualVersion" to wallet.version)
                )
            }

            val totalAvailable = wallet.availableWageringMinorUnits
            if (totalAvailable < command.totalWagerMinorUnits) {
                throw InsufficientBucketBalanceException(
                    "bucket sum/negative invariants break: Insufficient wagering balance: available=$totalAvailable, required=${command.totalWagerMinorUnits}",
                    mapOf("totalAvailable" to totalAvailable, "required" to command.totalWagerMinorUnits)
                )
            }

            var cashDebit = 0L
            var bonusDebit = 0L

            if (command.preferCashFirst) {
                if (wallet.cash.availableMinorUnits >= command.totalWagerMinorUnits) {
                    cashDebit = command.totalWagerMinorUnits
                } else {
                    cashDebit = wallet.cash.availableMinorUnits
                    bonusDebit = command.totalWagerMinorUnits - cashDebit
                }
            } else {
                if (wallet.bonus.activeMinorUnits >= command.totalWagerMinorUnits) {
                    bonusDebit = command.totalWagerMinorUnits
                } else {
                    bonusDebit = wallet.bonus.activeMinorUnits
                    cashDebit = command.totalWagerMinorUnits - bonusDebit
                }
            }

            val now = Instant.now(clock)
            val updatedCash = wallet.cash.copy(availableMinorUnits = wallet.cash.availableMinorUnits - cashDebit)
            val updatedBonus = wallet.bonus.copy(activeMinorUnits = wallet.bonus.activeMinorUnits - bonusDebit)

            val updatedWallet = wallet.copy(
                cash = updatedCash,
                bonus = updatedBonus,
                version = wallet.version + 1,
                updatedAt = now
            )

            store.saveWallet(updatedWallet)

            val resultId = UUID.randomUUID()
            val auditEvent = AuditEvent(
                eventId = UUID.randomUUID(),
                resultId = resultId,
                tenantId = command.tenantId,
                type = "WAGER_DEDUCTED",
                occurredAt = now,
                correlationId = command.correlationId,
                causationId = command.causationId
            )

            val outboxEvent = OutboxEvent(
                eventId = UUID.randomUUID(),
                resultId = resultId,
                tenantId = command.tenantId,
                type = "wallet.wager.deducted",
                createdAt = now
            )

            val result = BalanceBucketsResult(
                resultId = resultId,
                wallet = updatedWallet,
                operationType = BucketOperationType.WAGER_DEDUCTION,
                debitsEqualCredits = true,
                totalMinorUnitsConserved = true,
                serverTime = now,
                serverVersion = updatedWallet.version,
                evidenceReference = "evidence/wallet/wager/${updatedWallet.walletId}",
                auditEvent = auditEvent,
                outboxEvent = outboxEvent,
                hasAndroidDbImpact = false,
                hasAndroidLifecycleClaim = false
            )

            store.saveIdempotency(command.tenantId, command.idempotencyKey, payloadSignature, result)
            return result
        }
    }

    /**
     * Converts bonus funds into withdrawable cash upon meeting wagering playthrough requirements.
     */
    fun convertBonusToCash(command: ConvertBonusToCashCommand): BalanceBucketsResult {
        BalanceBucketsBinding.checkBound()
        validatePrincipal(command.principal, command.tenantId)

        if (command.amountMinorUnits <= 0L) {
            throw InvalidAmountException(
                "Conversion amount must be strictly positive: ${command.amountMinorUnits}",
                mapOf("amountMinorUnits" to command.amountMinorUnits)
            )
        }

        val payloadSignature = sha256(
            "${command.tenantId}:${command.walletId}:${command.amountMinorUnits}:${command.expectedVersion}"
        )

        executionLock.withLock {
            val cached = store.findIdempotency(command.tenantId, command.idempotencyKey)
            if (cached != null) {
                if (cached.first == payloadSignature) {
                    return cached.second as BalanceBucketsResult
                } else {
                    throw ConcurrencyConflictException(
                        "Idempotency conflict for key '${command.idempotencyKey}'. Cached signature does not match replayed payload.",
                        mapOf("idempotencyKey" to command.idempotencyKey)
                    )
                }
            }

            val wallet = store.findWalletById(command.tenantId, command.walletId)
                ?: throw WalletNotFoundException(
                    "Wallet not found: '${command.walletId}'",
                    mapOf("walletId" to command.walletId)
                )

            if (wallet.version != command.expectedVersion) {
                throw StaleVersionException(
                    "Stale version for wallet: expected ${command.expectedVersion}, found ${wallet.version}",
                    mapOf("expectedVersion" to command.expectedVersion, "actualVersion" to wallet.version)
                )
            }

            if (wallet.bonus.activeMinorUnits < command.amountMinorUnits) {
                throw InsufficientBucketBalanceException(
                    "bucket sum/negative invariants break: Insufficient active bonus to convert: ${wallet.bonus.activeMinorUnits} < ${command.amountMinorUnits}",
                    mapOf("activeBonus" to wallet.bonus.activeMinorUnits, "required" to command.amountMinorUnits)
                )
            }

            val now = Instant.now(clock)
            val updatedBonus = wallet.bonus.copy(activeMinorUnits = wallet.bonus.activeMinorUnits - command.amountMinorUnits)
            val updatedCash = wallet.cash.copy(availableMinorUnits = wallet.cash.availableMinorUnits + command.amountMinorUnits)

            val updatedWallet = wallet.copy(
                cash = updatedCash,
                bonus = updatedBonus,
                version = wallet.version + 1,
                updatedAt = now
            )

            store.saveWallet(updatedWallet)

            val resultId = UUID.randomUUID()
            val auditEvent = AuditEvent(
                eventId = UUID.randomUUID(),
                resultId = resultId,
                tenantId = command.tenantId,
                type = "BONUS_CONVERTED_TO_CASH",
                occurredAt = now,
                correlationId = command.correlationId,
                causationId = command.causationId
            )

            val outboxEvent = OutboxEvent(
                eventId = UUID.randomUUID(),
                resultId = resultId,
                tenantId = command.tenantId,
                type = "wallet.bonus.converted",
                createdAt = now
            )

            val result = BalanceBucketsResult(
                resultId = resultId,
                wallet = updatedWallet,
                operationType = BucketOperationType.BONUS_CONVERSION,
                debitsEqualCredits = true,
                totalMinorUnitsConserved = true,
                serverTime = now,
                serverVersion = updatedWallet.version,
                evidenceReference = "evidence/wallet/conversion/${updatedWallet.walletId}",
                auditEvent = auditEvent,
                outboxEvent = outboxEvent,
                hasAndroidDbImpact = false,
                hasAndroidLifecycleClaim = false
            )

            store.saveIdempotency(command.tenantId, command.idempotencyKey, payloadSignature, result)
            return result
        }
    }

    fun getWallet(tenantId: String, walletId: UUID, principal: AuthenticatedPrincipal?): WalletBalanceBucketsRecord {
        validatePrincipal(principal, tenantId)
        return store.findWalletById(tenantId, walletId)
            ?: throw WalletNotFoundException("Wallet not found: '$walletId'", mapOf("walletId" to walletId))
    }
}
