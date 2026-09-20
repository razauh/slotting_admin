package com.slotting.admin.wallet

import com.slotting.admin.auth.AdminRole
import com.slotting.admin.auth.AuditEvent
import com.slotting.admin.auth.AuthenticatedPrincipal
import com.slotting.admin.auth.OutboxEvent
import com.slotting.admin.auth.PrincipalKind
import java.time.Instant
import java.util.Currency
import java.util.UUID

/**
 * Outcome-specific semantic contract for WALLET-001.
 */
const val WALLET_ACCOUNTS_AND_CURRENCY_CONTRACT =
    "ISO currency + integer minor units; unique owner/currency/account type; no Android DB impact."

// =============================================================================
// Domain Enums & Entities
// =============================================================================

/**
 * Categorization of wallet accounts.
 */
enum class WalletAccountType {
    CASH,
    BONUS,
    RESTRICTED,
    ESCROW
}

/**
 * Lifecycle status of a wallet account.
 */
enum class WalletAccountStatus {
    ACTIVE,
    FROZEN,
    CLOSED
}

/**
 * Authoritative persisted wallet account record.
 * Invariant: currentBalanceMinorUnits = availableBalanceMinorUnits + reservedBalanceMinorUnits.
 */
data class WalletAccountRecord(
    val accountId: UUID,
    val tenantId: String,
    val ownerId: UUID,
    val currencyCode: String,
    val accountType: WalletAccountType,
    val status: WalletAccountStatus = WalletAccountStatus.ACTIVE,
    val currentBalanceMinorUnits: Long = 0L,
    val availableBalanceMinorUnits: Long = 0L,
    val reservedBalanceMinorUnits: Long = 0L,
    val version: Long = 1L,
    val createdAt: Instant,
    val updatedAt: Instant
) {
    init {
        require(currentBalanceMinorUnits == availableBalanceMinorUnits + reservedBalanceMinorUnits) {
            "Balance invariant broken: current ($currentBalanceMinorUnits) != available ($availableBalanceMinorUnits) + reserved ($reservedBalanceMinorUnits)"
        }
        require(availableBalanceMinorUnits >= 0L) {
            "Available balance cannot be negative: $availableBalanceMinorUnits"
        }
        require(reservedBalanceMinorUnits >= 0L) {
            "Reserved balance cannot be negative: $reservedBalanceMinorUnits"
        }
    }
}

/**
 * Authoritative immutable transaction record.
 */
data class WalletTransactionRecord(
    val transactionId: UUID,
    val tenantId: String,
    val sourceAccountId: UUID?,
    val destinationAccountId: UUID?,
    val amountMinorUnits: Long,
    val currencyCode: String,
    val reference: String?,
    val idempotencyKey: String,
    val correlationId: String,
    val causationId: String,
    val createdAt: Instant
)

// =============================================================================
// Commands & Results
// =============================================================================

data class CreateWalletAccountCommand(
    val principal: AuthenticatedPrincipal?,
    val tenantId: String,
    val ownerId: UUID,
    val currencyCode: String,
    val accountType: WalletAccountType = WalletAccountType.CASH,
    val initialBalanceMinorUnits: Long = 0L,
    val idempotencyKey: String,
    val correlationId: String,
    val causationId: String,
    val expectedVersion: Long = 1L
)

data class CreditWalletAccountCommand(
    val principal: AuthenticatedPrincipal?,
    val tenantId: String,
    val accountId: UUID,
    val amountMinorUnits: Long,
    val currencyCode: String,
    val reference: String? = null,
    val idempotencyKey: String,
    val correlationId: String,
    val causationId: String,
    val expectedVersion: Long = 1L
)

data class DebitWalletAccountCommand(
    val principal: AuthenticatedPrincipal?,
    val tenantId: String,
    val accountId: UUID,
    val amountMinorUnits: Long,
    val currencyCode: String,
    val reference: String? = null,
    val idempotencyKey: String,
    val correlationId: String,
    val causationId: String,
    val expectedVersion: Long = 1L
)

data class TransferFundsCommand(
    val principal: AuthenticatedPrincipal?,
    val tenantId: String,
    val sourceAccountId: UUID,
    val destinationAccountId: UUID,
    val amountMinorUnits: Long,
    val currencyCode: String,
    val reference: String? = null,
    val idempotencyKey: String,
    val correlationId: String,
    val causationId: String,
    val expectedVersion: Long = 1L
)

data class HoldFundsCommand(
    val principal: AuthenticatedPrincipal?,
    val tenantId: String,
    val accountId: UUID,
    val amountMinorUnits: Long,
    val currencyCode: String,
    val reference: String? = null,
    val idempotencyKey: String,
    val correlationId: String,
    val causationId: String,
    val expectedVersion: Long = 1L
)

data class ReleaseFundsCommand(
    val principal: AuthenticatedPrincipal?,
    val tenantId: String,
    val accountId: UUID,
    val amountMinorUnits: Long,
    val currencyCode: String,
    val reference: String? = null,
    val idempotencyKey: String,
    val correlationId: String,
    val causationId: String,
    val expectedVersion: Long = 1L
)

data class WalletAccountResult(
    val resultId: UUID,
    val account: WalletAccountRecord,
    val serverTime: Instant,
    val serverVersion: Long,
    val evidenceReference: String,
    val auditEvent: AuditEvent,
    val outboxEvent: OutboxEvent,
    val hasAndroidDbImpact: Boolean = false,
    val hasAndroidLifecycleClaim: Boolean = false
)

data class WalletTransferResult(
    val resultId: UUID,
    val sourceAccount: WalletAccountRecord,
    val destinationAccount: WalletAccountRecord,
    val transferredMinorUnits: Long,
    val currencyCode: String,
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

data class WalletHoldResult(
    val resultId: UUID,
    val account: WalletAccountRecord,
    val heldMinorUnits: Long,
    val currencyCode: String,
    val serverTime: Instant,
    val serverVersion: Long,
    val evidenceReference: String,
    val auditEvent: AuditEvent,
    val outboxEvent: OutboxEvent,
    val hasAndroidDbImpact: Boolean = false,
    val hasAndroidLifecycleClaim: Boolean = false
)

// =============================================================================
// Exceptions
// =============================================================================

open class WalletException(
    message: String,
    val errorCode: String,
    val details: Map<String, Any?> = emptyMap()
) : RuntimeException(message)

class DuplicateAccountException(
    message: String,
    details: Map<String, Any?> = emptyMap()
) : WalletException(message, "DUPLICATE_ACCOUNT", details)

class CrossCurrencyNotAllowedException(
    message: String,
    details: Map<String, Any?> = emptyMap()
) : WalletException(message, "CROSS_CURRENCY_NOT_ALLOWED", details)

class InvalidCurrencyException(
    message: String,
    details: Map<String, Any?> = emptyMap()
) : WalletException(message, "INVALID_CURRENCY", details)

class InvalidAmountException(
    message: String,
    details: Map<String, Any?> = emptyMap()
) : WalletException(message, "INVALID_AMOUNT", details)

class InsufficientFundsException(
    message: String,
    details: Map<String, Any?> = emptyMap()
) : WalletException(message, "INSUFFICIENT_FUNDS", details)

class AccountNotFoundException(
    message: String,
    details: Map<String, Any?> = emptyMap()
) : WalletException(message, "ACCOUNT_NOT_FOUND", details)

class AccountFrozenException(
    message: String,
    details: Map<String, Any?> = emptyMap()
) : WalletException(message, "ACCOUNT_FROZEN", details)

class UnauthorizedException(
    message: String,
    details: Map<String, Any?> = emptyMap()
) : WalletException(message, "UNAUTHORIZED", details)

class IdorForbiddenException(
    message: String,
    details: Map<String, Any?> = emptyMap()
) : WalletException(message, "IDOR_FORBIDDEN", details)

class StaleVersionException(
    message: String,
    details: Map<String, Any?> = emptyMap()
) : WalletException(message, "STALE_VERSION", details)

class ConcurrencyConflictException(
    message: String,
    details: Map<String, Any?> = emptyMap()
) : WalletException(message, "IDEMPOTENCY_CONFLICT", details)

// =============================================================================
// Helper for ISO Currency Validation
// =============================================================================

object IsoCurrencyValidator {
    private val validCodes: Set<String> by lazy {
        Currency.getAvailableCurrencies().map { it.currencyCode }.toSet()
    }

    fun isValidIso4217(code: String): Boolean {
        if (!code.matches(Regex("^[A-Z]{3}$"))) return false
        return validCodes.contains(code)
    }

    fun validate(code: String): String {
        val trimmed = code.trim()
        if (!isValidIso4217(trimmed)) {
            throw InvalidCurrencyException(
                "Invalid ISO 4217 currency code: '$code'. Must be a 3-letter uppercase valid currency.",
                mapOf("providedCode" to code)
            )
        }
        return trimmed
    }
}
