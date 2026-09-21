package com.slotting.admin.withdrawal

import com.slotting.admin.auth.AuditEvent
import com.slotting.admin.auth.AuthenticatedPrincipal
import com.slotting.admin.auth.OutboxEvent
import java.time.Instant
import java.util.UUID

// =============================================================================
// Enums & Breakdowns
// =============================================================================

enum class WithdrawalPaymentMethod {
    BANK_TRANSFER,
    SEPA_INSTANT,
    CRYPTO_USDT,
    CARD_OCT
}

enum class WithdrawalQuoteStatus {
    ACTIVE,
    CONSUMED,
    EXPIRED,
    CANCELLED
}

data class WithdrawalFeeBreakdown(
    val fixedFeeMinorUnits: Long = 0L,
    val percentageFeeBps: Long = 0L, // 100 bps = 1.0%
    val calculatedVariableFeeMinorUnits: Long = 0L,
    val totalFeeMinorUnits: Long = 0L
) {
    init {
        require(fixedFeeMinorUnits >= 0L) { "Fixed fee cannot be negative ($fixedFeeMinorUnits)" }
        require(percentageFeeBps >= 0L) { "Percentage fee cannot be negative ($percentageFeeBps)" }
        require(calculatedVariableFeeMinorUnits >= 0L) { "Variable fee cannot be negative ($calculatedVariableFeeMinorUnits)" }
        require(totalFeeMinorUnits == fixedFeeMinorUnits + calculatedVariableFeeMinorUnits) {
            "Total fee ($totalFeeMinorUnits) must equal fixed ($fixedFeeMinorUnits) + variable ($calculatedVariableFeeMinorUnits)"
        }
    }
}

// =============================================================================
// Authoritative Quote Record
// =============================================================================

data class WithdrawalQuoteRecord(
    val quoteId: UUID,
    val tenantId: String,
    val ownerId: UUID,
    val currencyCode: String,
    val paymentMethod: WithdrawalPaymentMethod,
    val destinationReference: String,
    val destinationVerified: Boolean,
    val grossAmountMinorUnits: Long,
    val feeBreakdown: WithdrawalFeeBreakdown,
    val netPayoutAmountMinorUnits: Long,
    val exchangeRate: Double = 1.0,
    val payoutCurrencyCode: String,
    val stepUpRequired: Boolean,
    val stepUpChallengeType: String? = null,
    val status: WithdrawalQuoteStatus = WithdrawalQuoteStatus.ACTIVE,
    val quotedAt: Instant,
    val expiresAt: Instant,
    val consumedAt: Instant? = null,
    val eligibilityDecisionId: String,
    val eligibilityDecisionVersion: Long,
    val idempotencyKey: String,
    val correlationId: String,
    val causationId: String,
    val evidenceReference: String,
    val version: Long = 1L
) {
    init {
        require(grossAmountMinorUnits > 0L) { "Gross amount must be positive: $grossAmountMinorUnits" }
        require(netPayoutAmountMinorUnits > 0L) { "Net payout amount must be positive: $netPayoutAmountMinorUnits" }
        require(grossAmountMinorUnits == netPayoutAmountMinorUnits + feeBreakdown.totalFeeMinorUnits) {
            "Gross amount ($grossAmountMinorUnits) must equal net payout ($netPayoutAmountMinorUnits) + fee (${feeBreakdown.totalFeeMinorUnits})"
        }
        require(expiresAt.isAfter(quotedAt)) { "Expiry must be strictly after quotedAt" }
        require(destinationReference.isNotBlank()) { "Destination reference must not be blank" }
        require(eligibilityDecisionId.isNotBlank()) { "Eligibility decision ID must not be blank" }
    }
}

// =============================================================================
// Commands & Results
// =============================================================================

data class QuoteWithdrawalCommand(
    val principal: AuthenticatedPrincipal?,
    val tenantId: String,
    val ownerId: UUID,
    val currencyCode: String,
    val grossAmountMinorUnits: Long,
    val paymentMethod: WithdrawalPaymentMethod,
    val destinationReference: String,
    val destinationVerified: Boolean = true,
    val eligibilityDecisionId: String,
    val eligibilityDecisionVersion: Long = 1L,
    val ttlSeconds: Long = 900L,
    val idempotencyKey: String,
    val correlationId: String,
    val causationId: String
)

data class WithdrawalQuoteResult(
    val resultId: UUID,
    val quote: WithdrawalQuoteRecord,
    val debitsEqualCredits: Boolean = true,
    val serverTime: Instant,
    val serverVersion: Long,
    val evidenceReference: String,
    val auditEvent: AuditEvent,
    val outboxEvent: OutboxEvent,
    val hasAndroidDbImpact: Boolean = false,
    val hasAndroidLifecycleClaim: Boolean = false
)

// =============================================================================
// Observability Models
// =============================================================================

data class WithdrawalQuoteMetricEvent(
    val eventType: String, // "attempt", "accept", "reject", "duplicate", "conflict"
    val tenantId: String,
    val ownerId: UUID?,
    val quoteId: UUID?,
    val correlationId: String,
    val causationId: String,
    val timestamp: Instant,
    val details: Map<String, Any?> = emptyMap()
)

interface WithdrawalQuoteObservability {
    fun recordMetric(event: WithdrawalQuoteMetricEvent)
    fun getMetrics(): List<WithdrawalQuoteMetricEvent>
}

class InMemoryWithdrawalQuoteObservability : WithdrawalQuoteObservability {
    private val metrics = mutableListOf<WithdrawalQuoteMetricEvent>()

    @Synchronized
    override fun recordMetric(event: WithdrawalQuoteMetricEvent) {
        metrics.add(event)
    }

    @Synchronized
    override fun getMetrics(): List<WithdrawalQuoteMetricEvent> = metrics.toList()
}

// =============================================================================
// Store Interface & In-Memory Implementation
// =============================================================================

interface WithdrawalQuoteStore {
    fun save(quote: WithdrawalQuoteRecord): WithdrawalQuoteRecord
    fun findById(quoteId: UUID): WithdrawalQuoteRecord?
    fun findByOwnerId(ownerId: UUID): List<WithdrawalQuoteRecord>
}

class InMemoryWithdrawalQuoteStore : WithdrawalQuoteStore {
    private val store = java.util.concurrent.ConcurrentHashMap<UUID, WithdrawalQuoteRecord>()

    override fun save(quote: WithdrawalQuoteRecord): WithdrawalQuoteRecord {
        store[quote.quoteId] = quote
        return quote
    }

    override fun findById(quoteId: UUID): WithdrawalQuoteRecord? = store[quoteId]

    override fun findByOwnerId(ownerId: UUID): List<WithdrawalQuoteRecord> =
        store.values.filter { it.ownerId == ownerId }
}

// =============================================================================
// Domain Exceptions
// =============================================================================

open class WithdrawalQuoteException(
    message: String,
    val errorCode: String,
    val details: Map<String, Any?> = emptyMap()
) : RuntimeException(message)

class UnverifiedDestinationException(
    message: String,
    details: Map<String, Any?> = emptyMap()
) : WithdrawalQuoteException(message, "UNVERIFIED_DESTINATION", details)

class StaleQuoteException(
    message: String,
    details: Map<String, Any?> = emptyMap()
) : WithdrawalQuoteException(message, "STALE_QUOTE", details)

class WithdrawalLimitExceededException(
    message: String,
    details: Map<String, Any?> = emptyMap()
) : WithdrawalQuoteException(message, "WITHDRAWAL_LIMIT_EXCEEDED", details)

class EligibilityDeniedException(
    message: String,
    details: Map<String, Any?> = emptyMap()
) : WithdrawalQuoteException(message, "ELIGIBILITY_DENIED", details)

class InsufficientWithdrawableFundsException(
    message: String,
    details: Map<String, Any?> = emptyMap()
) : WithdrawalQuoteException(message, "INSUFFICIENT_WITHDRAWABLE_FUNDS", details)

class UnauthorizedWithdrawalAccessException(
    message: String,
    details: Map<String, Any?> = emptyMap()
) : WithdrawalQuoteException(message, "UNAUTHORIZED", details)

class CrossTenantWithdrawalAccessException(
    message: String,
    details: Map<String, Any?> = emptyMap()
) : WithdrawalQuoteException(message, "CROSS_TENANT_ACCESS_DENIED", details)

class IdorWithdrawalForbiddenException(
    message: String,
    details: Map<String, Any?> = emptyMap()
) : WithdrawalQuoteException(message, "IDOR_FORBIDDEN", details)

class IdempotencyConflictException(
    message: String,
    details: Map<String, Any?> = emptyMap()
) : WithdrawalQuoteException(message, "IDEMPOTENCY_CONFLICT", details)
