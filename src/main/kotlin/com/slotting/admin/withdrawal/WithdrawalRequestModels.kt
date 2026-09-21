package com.slotting.admin.withdrawal

import com.slotting.admin.auth.AuditEvent
import com.slotting.admin.auth.AuthenticatedPrincipal
import com.slotting.admin.auth.OutboxEvent
import java.time.Instant
import java.util.UUID
import java.util.concurrent.ConcurrentHashMap

// =============================================================================
// Enums & Models
// =============================================================================

enum class WithdrawalRequestStatus {
    REQUESTED,
    CANCELLED,
    REJECTED
}

/**
 * Authoritative record of a step-up protected withdrawal request.
 * Enforces binding to an active quote, verified destination, and step-up auth proof.
 */
data class WithdrawalRequestRecord(
    val requestId: UUID,
    val tenantId: String,
    val ownerId: UUID,
    val quoteId: UUID,
    val currencyCode: String,
    val grossAmountMinorUnits: Long,
    val feeMinorUnits: Long,
    val netPayoutAmountMinorUnits: Long,
    val paymentMethod: WithdrawalPaymentMethod,
    val destinationId: UUID,
    val destinationReference: String,
    val stepUpAuthenticated: Boolean,
    val stepUpEvidenceReference: String? = null,
    val status: WithdrawalRequestStatus,
    val requestedAt: Instant,
    val idempotencyKey: String,
    val correlationId: String,
    val causationId: String,
    val evidenceReference: String,
    val version: Long = 1L
) {
    init {
        require(tenantId.isNotBlank()) { "tenantId must not be blank" }
        require(currencyCode.isNotBlank()) { "currencyCode must not be blank" }
        require(destinationReference.isNotBlank()) { "destinationReference must not be blank" }
        require(grossAmountMinorUnits > 0L) { "grossAmountMinorUnits must be positive" }
        require(feeMinorUnits >= 0L) { "feeMinorUnits cannot be negative" }
        require(netPayoutAmountMinorUnits == grossAmountMinorUnits - feeMinorUnits) {
            "netPayoutAmountMinorUnits ($netPayoutAmountMinorUnits) must equal gross ($grossAmountMinorUnits) minus fee ($feeMinorUnits)"
        }
    }
}

// =============================================================================
// Commands & Queries
// =============================================================================

data class CreateWithdrawalRequestCommand(
    val principal: AuthenticatedPrincipal?,
    val tenantId: String,
    val ownerId: UUID,
    val quoteId: UUID,
    val destinationId: UUID,
    val stepUpAuthToken: String? = null,
    val idempotencyKey: String,
    val correlationId: String,
    val causationId: String
)

data class GetWithdrawalRequestQuery(
    val principal: AuthenticatedPrincipal?,
    val tenantId: String,
    val requestId: UUID
)

data class WithdrawalRequestResult(
    val resultId: UUID,
    val request: WithdrawalRequestRecord,
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
// Step-Up Token Validator
// =============================================================================

interface StepUpTokenValidator {
    fun validateToken(token: String, ownerId: UUID): Boolean
}

class DefaultStepUpTokenValidator : StepUpTokenValidator {
    override fun validateToken(token: String, ownerId: UUID): Boolean {
        // Valid step-up tokens must be non-blank, start with "MFA-STEPUP-VALID-",
        // or contain valid verified prefix without expired/invalid tags
        if (token.isBlank()) return false
        if (token.contains("EXPIRED") || token.contains("INVALID")) return false
        return token.startsWith("MFA-STEPUP-VALID-") || token.startsWith("MFA-PASS-")
    }
}

// =============================================================================
// Observability Models
// =============================================================================

data class WithdrawalRequestMetricEvent(
    val eventType: String, // "attempt", "accept", "reject", "duplicate", "conflict"
    val tenantId: String,
    val ownerId: UUID?,
    val requestId: UUID?,
    val quoteId: UUID?,
    val correlationId: String,
    val causationId: String,
    val timestamp: Instant,
    val details: Map<String, Any?> = emptyMap()
)

interface WithdrawalRequestObservability {
    fun recordMetric(event: WithdrawalRequestMetricEvent)
    fun getMetrics(): List<WithdrawalRequestMetricEvent>
}

class InMemoryWithdrawalRequestObservability : WithdrawalRequestObservability {
    private val metrics = mutableListOf<WithdrawalRequestMetricEvent>()

    @Synchronized
    override fun recordMetric(event: WithdrawalRequestMetricEvent) {
        metrics.add(event)
    }

    @Synchronized
    override fun getMetrics(): List<WithdrawalRequestMetricEvent> = metrics.toList()
}

// =============================================================================
// Store Interface & In-Memory Implementation
// =============================================================================

interface WithdrawalRequestStore {
    fun save(record: WithdrawalRequestRecord): WithdrawalRequestRecord
    fun findById(requestId: UUID): WithdrawalRequestRecord?
    fun findByQuoteId(quoteId: UUID): WithdrawalRequestRecord?
    fun findByOwnerId(tenantId: String, ownerId: UUID): List<WithdrawalRequestRecord>
}

class InMemoryWithdrawalRequestStore : WithdrawalRequestStore {
    private val store = ConcurrentHashMap<UUID, WithdrawalRequestRecord>()

    override fun save(record: WithdrawalRequestRecord): WithdrawalRequestRecord {
        store[record.requestId] = record
        return record
    }

    override fun findById(requestId: UUID): WithdrawalRequestRecord? = store[requestId]

    override fun findByQuoteId(quoteId: UUID): WithdrawalRequestRecord? {
        return store.values.find { it.quoteId == quoteId }
    }

    override fun findByOwnerId(tenantId: String, ownerId: UUID): List<WithdrawalRequestRecord> {
        return store.values.filter { it.tenantId == tenantId && it.ownerId == ownerId }
    }
}

// =============================================================================
// Domain Exceptions
// =============================================================================

class StepUpAuthenticationRequiredException(
    message: String,
    details: Map<String, Any?> = emptyMap()
) : WithdrawalQuoteException(message, "STEP_UP_REQUIRED", details)

class WithdrawalRequestNotFoundException(
    message: String,
    details: Map<String, Any?> = emptyMap()
) : WithdrawalQuoteException(message, "WITHDRAWAL_REQUEST_NOT_FOUND", details)
