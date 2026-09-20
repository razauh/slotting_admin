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

interface WalletAccountStore {
    fun findAccountById(tenantId: String, accountId: UUID): WalletAccountRecord?
    fun findAccountByComposite(
        tenantId: String,
        ownerId: UUID,
        currencyCode: String,
        accountType: WalletAccountType
    ): WalletAccountRecord?

    fun saveAccount(account: WalletAccountRecord)
    fun saveTransfer(
        source: WalletAccountRecord,
        destination: WalletAccountRecord,
        transaction: WalletTransactionRecord
    )

    fun findIdempotency(tenantId: String, key: String): Pair<String, Any>?
    fun saveIdempotency(tenantId: String, key: String, signature: String, result: Any)

    fun listAccountsByOwner(tenantId: String, ownerId: UUID): List<WalletAccountRecord>
    fun clear()
}

class InMemoryWalletAccountStore : WalletAccountStore {
    private val accountsById = ConcurrentHashMap<String, WalletAccountRecord>()
    private val accountsByComposite = ConcurrentHashMap<String, UUID>()
    private val transactions = ConcurrentHashMap<UUID, WalletTransactionRecord>()
    private val idempotencyRecords = ConcurrentHashMap<String, Pair<String, Any>>()
    val auditEvents = mutableListOf<AuditEvent>()
    val outboxEvents = mutableListOf<OutboxEvent>()

    private val globalLock = ReentrantLock()

    private fun compositeKey(
        tenantId: String,
        ownerId: UUID,
        currencyCode: String,
        accountType: WalletAccountType
    ): String = "$tenantId:$ownerId:$currencyCode:$accountType"

    override fun findAccountById(tenantId: String, accountId: UUID): WalletAccountRecord? {
        val record = accountsById["$tenantId:$accountId"]
        return if (record != null && record.tenantId == tenantId) record else null
    }

    override fun findAccountByComposite(
        tenantId: String,
        ownerId: UUID,
        currencyCode: String,
        accountType: WalletAccountType
    ): WalletAccountRecord? {
        val accountId = accountsByComposite[compositeKey(tenantId, ownerId, currencyCode, accountType)]
            ?: return null
        return findAccountById(tenantId, accountId)
    }

    override fun saveAccount(account: WalletAccountRecord) {
        globalLock.withLock {
            val key = "$account.tenantId:${account.accountId}"
            val comp = compositeKey(account.tenantId, account.ownerId, account.currencyCode, account.accountType)
            accountsById["${account.tenantId}:${account.accountId}"] = account
            accountsByComposite[comp] = account.accountId
        }
    }

    override fun saveTransfer(
        source: WalletAccountRecord,
        destination: WalletAccountRecord,
        transaction: WalletTransactionRecord
    ) {
        globalLock.withLock {
            accountsById["${source.tenantId}:${source.accountId}"] = source
            accountsById["${destination.tenantId}:${destination.accountId}"] = destination
            transactions[transaction.transactionId] = transaction
        }
    }

    override fun findIdempotency(tenantId: String, key: String): Pair<String, Any>? =
        idempotencyRecords["$tenantId:$key"]

    override fun saveIdempotency(tenantId: String, key: String, signature: String, result: Any) {
        globalLock.withLock {
            idempotencyRecords["$tenantId:$key"] = Pair(signature, result)
            if (result is WalletAccountResult) {
                auditEvents.add(result.auditEvent)
                outboxEvents.add(result.outboxEvent)
            } else if (result is WalletTransferResult) {
                auditEvents.add(result.auditEvent)
                outboxEvents.add(result.outboxEvent)
            } else if (result is WalletHoldResult) {
                auditEvents.add(result.auditEvent)
                outboxEvents.add(result.outboxEvent)
            }
        }
    }

    override fun listAccountsByOwner(tenantId: String, ownerId: UUID): List<WalletAccountRecord> {
        return accountsById.values
            .filter { it.tenantId == tenantId && it.ownerId == ownerId }
            .toList()
    }

    override fun clear() {
        globalLock.withLock {
            accountsById.clear()
            accountsByComposite.clear()
            transactions.clear()
            idempotencyRecords.clear()
            auditEvents.clear()
            outboxEvents.clear()
        }
    }
}

// =============================================================================
// Authoritative Wallet Account Service
// =============================================================================

class WalletAccountService(
    private val store: WalletAccountStore = InMemoryWalletAccountStore(),
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
     * Creates an authoritative wallet account for owner and currency.
     * Enforces unique owner/currency/account type.
     */
    fun createAccount(command: CreateWalletAccountCommand): WalletAccountResult {
        WalletAccountBinding.checkBound()
        validatePrincipal(command.principal, command.tenantId)

        val normalizedCurrency = IsoCurrencyValidator.validate(command.currencyCode)

        if (command.initialBalanceMinorUnits < 0L) {
            throw InvalidAmountException(
                "Initial balance cannot be negative: ${command.initialBalanceMinorUnits}",
                mapOf("initialBalanceMinorUnits" to command.initialBalanceMinorUnits)
            )
        }

        val payloadSignature = sha256(
            "${command.tenantId}:${command.ownerId}:$normalizedCurrency:${command.accountType}:${command.initialBalanceMinorUnits}:${command.expectedVersion}"
        )

        executionLock.withLock {
            // Check idempotency
            val cached = store.findIdempotency(command.tenantId, command.idempotencyKey)
            if (cached != null) {
                if (cached.first == payloadSignature) {
                    return cached.second as WalletAccountResult
                } else {
                    throw ConcurrencyConflictException(
                        "Idempotency conflict for key '${command.idempotencyKey}'. Cached signature does not match replayed payload.",
                        mapOf("idempotencyKey" to command.idempotencyKey)
                    )
                }
            }

            // Check duplicate account constraint: unique (tenantId, ownerId, currencyCode, accountType)
            val existing = store.findAccountByComposite(
                command.tenantId,
                command.ownerId,
                normalizedCurrency,
                command.accountType
            )
            if (existing != null) {
                throw DuplicateAccountException(
                    "cross-currency/duplicate account allowed: Account already exists for owner '${command.ownerId}', currency '$normalizedCurrency', accountType '${command.accountType}'.",
                    mapOf(
                        "existingAccountId" to existing.accountId,
                        "ownerId" to command.ownerId,
                        "currencyCode" to normalizedCurrency,
                        "accountType" to command.accountType
                    )
                )
            }

            val now = Instant.now(clock)
            val newAccountId = UUID.randomUUID()
            val account = WalletAccountRecord(
                accountId = newAccountId,
                tenantId = command.tenantId,
                ownerId = command.ownerId,
                currencyCode = normalizedCurrency,
                accountType = command.accountType,
                status = WalletAccountStatus.ACTIVE,
                currentBalanceMinorUnits = command.initialBalanceMinorUnits,
                availableBalanceMinorUnits = command.initialBalanceMinorUnits,
                reservedBalanceMinorUnits = 0L,
                version = command.expectedVersion,
                createdAt = now,
                updatedAt = now
            )

            store.saveAccount(account)

            val resultId = UUID.randomUUID()
            val auditEvent = AuditEvent(
                eventId = UUID.randomUUID(),
                resultId = resultId,
                tenantId = command.tenantId,
                type = "WALLET_ACCOUNT_CREATED",
                occurredAt = now,
                correlationId = command.correlationId,
                causationId = command.causationId
            )

            val outboxEvent = OutboxEvent(
                eventId = UUID.randomUUID(),
                resultId = resultId,
                tenantId = command.tenantId,
                type = "wallet.account.created",
                createdAt = now
            )

            val result = WalletAccountResult(
                resultId = resultId,
                account = account,
                serverTime = now,
                serverVersion = account.version,
                evidenceReference = "evidence/wallet/accounts/${account.accountId}",
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
     * Executes an authoritative transfer between two accounts.
     * Enforces that both accounts have the exact same currency and total debits equal credits.
     */
    fun transferFunds(command: TransferFundsCommand): WalletTransferResult {
        WalletAccountBinding.checkBound()
        validatePrincipal(command.principal, command.tenantId)

        val normalizedCurrency = IsoCurrencyValidator.validate(command.currencyCode)

        if (command.amountMinorUnits <= 0L) {
            throw InvalidAmountException(
                "Transfer amount must be strictly positive: ${command.amountMinorUnits}",
                mapOf("amountMinorUnits" to command.amountMinorUnits)
            )
        }

        val payloadSignature = sha256(
            "${command.tenantId}:${command.sourceAccountId}:${command.destinationAccountId}:$normalizedCurrency:${command.amountMinorUnits}:${command.expectedVersion}"
        )

        executionLock.withLock {
            // Check idempotency
            val cached = store.findIdempotency(command.tenantId, command.idempotencyKey)
            if (cached != null) {
                if (cached.first == payloadSignature) {
                    return cached.second as WalletTransferResult
                } else {
                    throw ConcurrencyConflictException(
                        "Idempotency conflict for key '${command.idempotencyKey}'. Cached signature does not match replayed payload.",
                        mapOf("idempotencyKey" to command.idempotencyKey)
                    )
                }
            }

            val sourceAccount = store.findAccountById(command.tenantId, command.sourceAccountId)
                ?: throw AccountNotFoundException(
                    "Source account not found: '${command.sourceAccountId}'",
                    mapOf("accountId" to command.sourceAccountId)
                )

            val destAccount = store.findAccountById(command.tenantId, command.destinationAccountId)
                ?: throw AccountNotFoundException(
                    "Destination account not found: '${command.destinationAccountId}'",
                    mapOf("accountId" to command.destinationAccountId)
                )

            // Cross-currency prevention: both accounts and command must match
            if (sourceAccount.currencyCode != normalizedCurrency ||
                destAccount.currencyCode != normalizedCurrency ||
                sourceAccount.currencyCode != destAccount.currencyCode
            ) {
                throw CrossCurrencyNotAllowedException(
                    "cross-currency/duplicate account allowed: Cross-currency transfer forbidden between source (${sourceAccount.currencyCode}) and destination (${destAccount.currencyCode}) using command currency ($normalizedCurrency).",
                    mapOf(
                        "sourceCurrency" to sourceAccount.currencyCode,
                        "destinationCurrency" to destAccount.currencyCode,
                        "commandCurrency" to normalizedCurrency
                    )
                )
            }

            // Account status validation
            if (sourceAccount.status != WalletAccountStatus.ACTIVE) {
                throw AccountFrozenException(
                    "Source account is not ACTIVE: status=${sourceAccount.status}",
                    mapOf("accountId" to sourceAccount.accountId, "status" to sourceAccount.status)
                )
            }
            if (destAccount.status != WalletAccountStatus.ACTIVE) {
                throw AccountFrozenException(
                    "Destination account is not ACTIVE: status=${destAccount.status}",
                    mapOf("accountId" to destAccount.accountId, "status" to destAccount.status)
                )
            }

            // Version check (optimistic locking)
            if (sourceAccount.version != command.expectedVersion) {
                throw StaleVersionException(
                    "Stale version for source account. Expected ${command.expectedVersion}, found ${sourceAccount.version}.",
                    mapOf("expectedVersion" to command.expectedVersion, "actualVersion" to sourceAccount.version)
                )
            }

            // Solvency check
            if (sourceAccount.availableBalanceMinorUnits < command.amountMinorUnits) {
                throw InsufficientFundsException(
                    "Insufficient available funds in source account: available=${sourceAccount.availableBalanceMinorUnits}, required=${command.amountMinorUnits}",
                    mapOf(
                        "available" to sourceAccount.availableBalanceMinorUnits,
                        "required" to command.amountMinorUnits
                    )
                )
            }

            val now = Instant.now(clock)

            // Debit source
            val updatedSource = sourceAccount.copy(
                currentBalanceMinorUnits = sourceAccount.currentBalanceMinorUnits - command.amountMinorUnits,
                availableBalanceMinorUnits = sourceAccount.availableBalanceMinorUnits - command.amountMinorUnits,
                version = sourceAccount.version + 1,
                updatedAt = now
            )

            // Credit destination
            val updatedDest = destAccount.copy(
                currentBalanceMinorUnits = destAccount.currentBalanceMinorUnits + command.amountMinorUnits,
                availableBalanceMinorUnits = destAccount.availableBalanceMinorUnits + command.amountMinorUnits,
                version = destAccount.version + 1,
                updatedAt = now
            )

            val transaction = WalletTransactionRecord(
                transactionId = UUID.randomUUID(),
                tenantId = command.tenantId,
                sourceAccountId = command.sourceAccountId,
                destinationAccountId = command.destinationAccountId,
                amountMinorUnits = command.amountMinorUnits,
                currencyCode = normalizedCurrency,
                reference = command.reference,
                idempotencyKey = command.idempotencyKey,
                correlationId = command.correlationId,
                causationId = command.causationId,
                createdAt = now
            )

            store.saveTransfer(updatedSource, updatedDest, transaction)

            val resultId = UUID.randomUUID()
            val auditEvent = AuditEvent(
                eventId = UUID.randomUUID(),
                resultId = resultId,
                tenantId = command.tenantId,
                type = "WALLET_FUNDS_TRANSFERRED",
                occurredAt = now,
                correlationId = command.correlationId,
                causationId = command.causationId
            )

            val outboxEvent = OutboxEvent(
                eventId = UUID.randomUUID(),
                resultId = resultId,
                tenantId = command.tenantId,
                type = "wallet.funds.transferred",
                createdAt = now
            )

            val result = WalletTransferResult(
                resultId = resultId,
                sourceAccount = updatedSource,
                destinationAccount = updatedDest,
                transferredMinorUnits = command.amountMinorUnits,
                currencyCode = normalizedCurrency,
                debitsEqualCredits = true,
                totalMinorUnitsConserved = true,
                serverTime = now,
                serverVersion = updatedSource.version,
                evidenceReference = "evidence/wallet/transfers/${transaction.transactionId}",
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
     * Holds funds by moving them from available to reserved balance.
     */
    fun holdFunds(command: HoldFundsCommand): WalletHoldResult {
        WalletAccountBinding.checkBound()
        validatePrincipal(command.principal, command.tenantId)

        val normalizedCurrency = IsoCurrencyValidator.validate(command.currencyCode)

        if (command.amountMinorUnits <= 0L) {
            throw InvalidAmountException(
                "Hold amount must be positive: ${command.amountMinorUnits}",
                mapOf("amountMinorUnits" to command.amountMinorUnits)
            )
        }

        val payloadSignature = sha256(
            "${command.tenantId}:${command.accountId}:$normalizedCurrency:${command.amountMinorUnits}:${command.expectedVersion}"
        )

        executionLock.withLock {
            val cached = store.findIdempotency(command.tenantId, command.idempotencyKey)
            if (cached != null) {
                if (cached.first == payloadSignature) {
                    return cached.second as WalletHoldResult
                } else {
                    throw ConcurrencyConflictException(
                        "Idempotency conflict for key '${command.idempotencyKey}'.",
                        mapOf("idempotencyKey" to command.idempotencyKey)
                    )
                }
            }

            val account = store.findAccountById(command.tenantId, command.accountId)
                ?: throw AccountNotFoundException(
                    "Account not found: '${command.accountId}'",
                    mapOf("accountId" to command.accountId)
                )

            if (account.currencyCode != normalizedCurrency) {
                throw CrossCurrencyNotAllowedException(
                    "cross-currency/duplicate account allowed: Currency mismatch: account is ${account.currencyCode}, command is $normalizedCurrency",
                    mapOf("accountCurrency" to account.currencyCode, "commandCurrency" to normalizedCurrency)
                )
            }

            if (account.status != WalletAccountStatus.ACTIVE) {
                throw AccountFrozenException("Account is not ACTIVE", mapOf("status" to account.status))
            }

            if (account.version != command.expectedVersion) {
                throw StaleVersionException(
                    "Stale version: expected ${command.expectedVersion}, found ${account.version}",
                    mapOf("expectedVersion" to command.expectedVersion, "actualVersion" to account.version)
                )
            }

            if (account.availableBalanceMinorUnits < command.amountMinorUnits) {
                throw InsufficientFundsException(
                    "Insufficient available funds to hold: available=${account.availableBalanceMinorUnits}, required=${command.amountMinorUnits}",
                    mapOf("available" to account.availableBalanceMinorUnits, "required" to command.amountMinorUnits)
                )
            }

            val now = Instant.now(clock)
            val updated = account.copy(
                availableBalanceMinorUnits = account.availableBalanceMinorUnits - command.amountMinorUnits,
                reservedBalanceMinorUnits = account.reservedBalanceMinorUnits + command.amountMinorUnits,
                version = account.version + 1,
                updatedAt = now
            )

            store.saveAccount(updated)

            val resultId = UUID.randomUUID()
            val auditEvent = AuditEvent(
                eventId = UUID.randomUUID(),
                resultId = resultId,
                tenantId = command.tenantId,
                type = "WALLET_FUNDS_HELD",
                occurredAt = now,
                correlationId = command.correlationId,
                causationId = command.causationId
            )

            val outboxEvent = OutboxEvent(
                eventId = UUID.randomUUID(),
                resultId = resultId,
                tenantId = command.tenantId,
                type = "wallet.funds.held",
                createdAt = now
            )

            val result = WalletHoldResult(
                resultId = resultId,
                account = updated,
                heldMinorUnits = command.amountMinorUnits,
                currencyCode = normalizedCurrency,
                serverTime = now,
                serverVersion = updated.version,
                evidenceReference = "evidence/wallet/holds/${account.accountId}",
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
     * Releases held funds back to available balance.
     */
    fun releaseFunds(command: ReleaseFundsCommand): WalletHoldResult {
        WalletAccountBinding.checkBound()
        validatePrincipal(command.principal, command.tenantId)

        val normalizedCurrency = IsoCurrencyValidator.validate(command.currencyCode)

        if (command.amountMinorUnits <= 0L) {
            throw InvalidAmountException(
                "Release amount must be positive: ${command.amountMinorUnits}",
                mapOf("amountMinorUnits" to command.amountMinorUnits)
            )
        }

        val payloadSignature = sha256(
            "${command.tenantId}:${command.accountId}:$normalizedCurrency:${command.amountMinorUnits}:${command.expectedVersion}"
        )

        executionLock.withLock {
            val cached = store.findIdempotency(command.tenantId, command.idempotencyKey)
            if (cached != null) {
                if (cached.first == payloadSignature) {
                    return cached.second as WalletHoldResult
                } else {
                    throw ConcurrencyConflictException(
                        "Idempotency conflict for key '${command.idempotencyKey}'.",
                        mapOf("idempotencyKey" to command.idempotencyKey)
                    )
                }
            }

            val account = store.findAccountById(command.tenantId, command.accountId)
                ?: throw AccountNotFoundException(
                    "Account not found: '${command.accountId}'",
                    mapOf("accountId" to command.accountId)
                )

            if (account.currencyCode != normalizedCurrency) {
                throw CrossCurrencyNotAllowedException(
                    "cross-currency/duplicate account allowed: Currency mismatch: account is ${account.currencyCode}, command is $normalizedCurrency",
                    mapOf("accountCurrency" to account.currencyCode, "commandCurrency" to normalizedCurrency)
                )
            }

            if (account.reservedBalanceMinorUnits < command.amountMinorUnits) {
                throw InsufficientFundsException(
                    "Insufficient reserved funds to release: reserved=${account.reservedBalanceMinorUnits}, required=${command.amountMinorUnits}",
                    mapOf("reserved" to account.reservedBalanceMinorUnits, "required" to command.amountMinorUnits)
                )
            }

            val now = Instant.now(clock)
            val updated = account.copy(
                availableBalanceMinorUnits = account.availableBalanceMinorUnits + command.amountMinorUnits,
                reservedBalanceMinorUnits = account.reservedBalanceMinorUnits - command.amountMinorUnits,
                version = account.version + 1,
                updatedAt = now
            )

            store.saveAccount(updated)

            val resultId = UUID.randomUUID()
            val auditEvent = AuditEvent(
                eventId = UUID.randomUUID(),
                resultId = resultId,
                tenantId = command.tenantId,
                type = "WALLET_FUNDS_RELEASED",
                occurredAt = now,
                correlationId = command.correlationId,
                causationId = command.causationId
            )

            val outboxEvent = OutboxEvent(
                eventId = UUID.randomUUID(),
                resultId = resultId,
                tenantId = command.tenantId,
                type = "wallet.funds.released",
                createdAt = now
            )

            val result = WalletHoldResult(
                resultId = resultId,
                account = updated,
                heldMinorUnits = command.amountMinorUnits,
                currencyCode = normalizedCurrency,
                serverTime = now,
                serverVersion = updated.version,
                evidenceReference = "evidence/wallet/releases/${account.accountId}",
                auditEvent = auditEvent,
                outboxEvent = outboxEvent,
                hasAndroidDbImpact = false,
                hasAndroidLifecycleClaim = false
            )

            store.saveIdempotency(command.tenantId, command.idempotencyKey, payloadSignature, result)
            return result
        }
    }

    fun getAccount(tenantId: String, accountId: UUID, principal: AuthenticatedPrincipal?): WalletAccountRecord {
        validatePrincipal(principal, tenantId)
        return store.findAccountById(tenantId, accountId)
            ?: throw AccountNotFoundException("Account not found: '$accountId'", mapOf("accountId" to accountId))
    }
}
