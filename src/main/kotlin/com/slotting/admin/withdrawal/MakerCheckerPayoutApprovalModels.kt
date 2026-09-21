package com.slotting.admin.withdrawal

import com.slotting.admin.auth.AuditEvent
import com.slotting.admin.auth.AuthenticatedPrincipal
import com.slotting.admin.auth.OutboxEvent
import com.slotting.admin.wallet.WalletBalanceBucketsRecord
import java.time.Instant
import java.util.UUID
import java.util.concurrent.ConcurrentHashMap

// =============================================================================
// Enums & Domain Models
// =============================================================================

enum class PayoutApprovalStatus {
    PENDING_REVIEW,
    APPROVED,
    REJECTED,
    CANCELLED,
    EXPIRED
}

enum class PayoutDecisionAction {
    APPROVE,
    REJECT
}

/**
 * Authoritative record of maker-checker approval for withdrawal payouts.
 * Ensures dual control (four-eyes principle) before provider payout dispatch.
 */
data class PayoutApprovalRecord(
    val approvalId: UUID,
    val tenantId: String,
    val ownerId: UUID,
    val walletId: UUID,
    val requestId: UUID,
    val reservationId: UUID,
    val currencyCode: String,
    val grossAmountMinorUnits: Long,
    val status: PayoutApprovalStatus,
    val makerPrincipal: AuthenticatedPrincipal,
    val makerNotes: String,
    val checkerPrincipal: AuthenticatedPrincipal? = null,
    val checkerNotes: String? = null,
    val createdAt: Instant,
    val decidedAt: Instant? = null,
    val expiresAt: Instant,
    val idempotencyKey: String,
    val correlationId: String,
    val causationId: String,
    val evidenceReference: String,
    val version: Long = 1L
) {
    init {
        require(tenantId.isNotBlank()) { "tenantId must not be blank" }
        require(currencyCode.isNotBlank()) { "currencyCode must not be blank" }
        require(grossAmountMinorUnits > 0L) { "grossAmountMinorUnits must be positive" }
    }
}

// =============================================================================
// Commands & Queries
// =============================================================================

data class ProposePayoutApprovalCommand(
    val principal: AuthenticatedPrincipal?,
    val tenantId: String,
    val ownerId: UUID,
    val reservationId: UUID,
    val makerNotes: String,
    val ttlSeconds: Long = 86400L,
    val idempotencyKey: String,
    val correlationId: String,
    val causationId: String
)

data class ReviewPayoutApprovalCommand(
    val principal: AuthenticatedPrincipal?,
    val tenantId: String,
    val approvalId: UUID,
    val action: PayoutDecisionAction,
    val checkerNotes: String,
    val idempotencyKey: String,
    val correlationId: String,
    val causationId: String
)

data class CancelPayoutApprovalCommand(
    val principal: AuthenticatedPrincipal?,
    val tenantId: String,
    val approvalId: UUID,
    val cancellationReason: String,
    val idempotencyKey: String,
    val correlationId: String,
    val causationId: String
)

data class GetPayoutApprovalQuery(
    val principal: AuthenticatedPrincipal?,
    val tenantId: String,
    val approvalId: UUID
)

// =============================================================================
// Results
// =============================================================================

data class PayoutApprovalResult(
    val resultId: UUID,
    val approval: PayoutApprovalRecord,
    val reservationState: WithdrawalReservationState,
    val walletBalance: WalletBalanceBucketsRecord,
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
// Observability
// =============================================================================

data class PayoutApprovalMetricEvent(
    val eventType: String, // "attempt", "accept", "reject", "duplicate", "conflict", "violation"
    val tenantId: String,
    val ownerId: UUID?,
    val approvalId: UUID?,
    val reservationId: UUID?,
    val makerId: String?,
    val checkerId: String?,
    val correlationId: String,
    val causationId: String,
    val timestamp: Instant,
    val details: Map<String, Any?> = emptyMap()
)

interface PayoutApprovalObservability {
    fun recordMetric(event: PayoutApprovalMetricEvent)
    fun getMetrics(): List<PayoutApprovalMetricEvent>
}

class InMemoryPayoutApprovalObservability : PayoutApprovalObservability {
    private val metrics = mutableListOf<PayoutApprovalMetricEvent>()

    @Synchronized
    override fun recordMetric(event: PayoutApprovalMetricEvent) {
        metrics.add(event)
    }

    @Synchronized
    override fun getMetrics(): List<PayoutApprovalMetricEvent> = metrics.toList()
}

// =============================================================================
// Store Interface & In-Memory Implementation
// =============================================================================

interface PayoutApprovalStore {
    fun save(record: PayoutApprovalRecord): PayoutApprovalRecord
    fun findById(tenantId: String, approvalId: UUID): PayoutApprovalRecord?
    fun findByReservationId(tenantId: String, reservationId: UUID): PayoutApprovalRecord?
    fun findByIdempotency(tenantId: String, idempotencyKey: String): Pair<String, PayoutApprovalResult>?
    fun saveIdempotency(tenantId: String, idempotencyKey: String, fingerprint: String, result: PayoutApprovalResult)
}

class InMemoryPayoutApprovalStore : PayoutApprovalStore {
    private val store = ConcurrentHashMap<UUID, PayoutApprovalRecord>()
    private val idempotency = ConcurrentHashMap<String, Pair<String, PayoutApprovalResult>>()

    override fun save(record: PayoutApprovalRecord): PayoutApprovalRecord {
        store[record.approvalId] = record
        return record
    }

    override fun findById(tenantId: String, approvalId: UUID): PayoutApprovalRecord? {
        val record = store[approvalId]
        return if (record?.tenantId == tenantId) record else null
    }

    override fun findByReservationId(tenantId: String, reservationId: UUID): PayoutApprovalRecord? {
        return store.values.find { it.tenantId == tenantId && it.reservationId == reservationId }
    }

    override fun findByIdempotency(tenantId: String, idempotencyKey: String): Pair<String, PayoutApprovalResult>? {
        return idempotency["$tenantId:$idempotencyKey"]
    }

    override fun saveIdempotency(tenantId: String, idempotencyKey: String, fingerprint: String, result: PayoutApprovalResult) {
        idempotency["$tenantId:$idempotencyKey"] = fingerprint to result
    }
}

// =============================================================================
// Exceptions
// =============================================================================

class PayoutApprovalNotFoundException(message: String) : RuntimeException(message)
class PayoutApprovalConflictException(message: String) : RuntimeException(message)
class MakerSelfApprovalForbiddenException(message: String) : RuntimeException(message)
class UnauthorizedApprovalAccessException(message: String) : RuntimeException(message)
class InvalidReservationStateException(message: String) : RuntimeException(message)
