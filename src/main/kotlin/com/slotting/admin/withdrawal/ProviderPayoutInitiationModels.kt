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

enum class PayoutProviderStatus {
    SUCCESS,
    REJECTED,
    UNKNOWN_PENDING
}

enum class PayoutExecutionStatus {
    PENDING_DISPATCH,
    CAPTURED,
    RELEASED,
    PENDING_RECONCILIATION
}

data class PayoutProviderRequest(
    val payoutId: UUID,
    val tenantId: String,
    val ownerId: UUID,
    val reservationId: UUID,
    val destinationId: UUID?,
    val amountMinorUnits: Long,
    val currencyCode: String,
    val idempotencyKey: String,
    val simulatedOutcome: PayoutProviderStatus? = null
)

data class PayoutProviderResponse(
    val providerTransactionId: String?,
    val status: PayoutProviderStatus,
    val rawResponseCode: String,
    val safeReason: String,
    val isAmbiguous: Boolean
)

interface PayoutProviderPort {
    fun initiatePayout(request: PayoutProviderRequest): PayoutProviderResponse
}

class FakePayoutProviderAdapter : PayoutProviderPort {
    var forcedOutcome: PayoutProviderStatus? = null

    override fun initiatePayout(request: PayoutProviderRequest): PayoutProviderResponse {
        val outcome = request.simulatedOutcome ?: forcedOutcome ?: PayoutProviderStatus.SUCCESS
        return when (outcome) {
            PayoutProviderStatus.SUCCESS -> PayoutProviderResponse(
                providerTransactionId = "prov-tx-${UUID.randomUUID()}",
                status = PayoutProviderStatus.SUCCESS,
                rawResponseCode = "200_OK",
                safeReason = "Payout executed successfully",
                isAmbiguous = false
            )
            PayoutProviderStatus.REJECTED -> PayoutProviderResponse(
                providerTransactionId = null,
                status = PayoutProviderStatus.REJECTED,
                rawResponseCode = "400_BENEFICIARY_DECLINED",
                safeReason = "Beneficiary account rejected by destination clearing house",
                isAmbiguous = false
            )
            PayoutProviderStatus.UNKNOWN_PENDING -> PayoutProviderResponse(
                providerTransactionId = "prov-pending-${UUID.randomUUID()}",
                status = PayoutProviderStatus.UNKNOWN_PENDING,
                rawResponseCode = "504_GATEWAY_TIMEOUT",
                safeReason = "Upstream banking rail timeout; payout in unknown in-flight state",
                isAmbiguous = true
            )
        }
    }
}

/**
 * Authoritative record of payout initiation and dispatch outcome.
 * Enforces: "Unknown stays pending/reconcile; only definitive rejection releases; success captures lock."
 */
data class PayoutExecutionRecord(
    val payoutId: UUID,
    val tenantId: String,
    val ownerId: UUID,
    val walletId: UUID,
    val requestId: UUID,
    val reservationId: UUID,
    val approvalId: UUID,
    val currencyCode: String,
    val grossAmountMinorUnits: Long,
    val status: PayoutExecutionStatus,
    val providerTransactionId: String? = null,
    val providerReason: String? = null,
    val initiatedAt: Instant,
    val completedAt: Instant? = null,
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

data class InitiateProviderPayoutCommand(
    val principal: AuthenticatedPrincipal?,
    val tenantId: String,
    val ownerId: UUID,
    val reservationId: UUID,
    val approvalId: UUID,
    val providerId: String = "default-payout-provider",
    val destinationId: UUID? = null,
    val idempotencyKey: String,
    val correlationId: String,
    val causationId: String,
    val simulatedOutcome: PayoutProviderStatus? = null
)

data class GetPayoutExecutionQuery(
    val principal: AuthenticatedPrincipal?,
    val tenantId: String,
    val payoutId: UUID
)

// =============================================================================
// Results
// =============================================================================

data class PayoutInitiationResult(
    val resultId: UUID,
    val execution: PayoutExecutionRecord,
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

data class PayoutInitiationMetricEvent(
    val eventType: String, // "attempt", "accept", "reject", "duplicate", "conflict", "reconciliation_required"
    val tenantId: String,
    val ownerId: UUID?,
    val payoutId: UUID?,
    val reservationId: UUID?,
    val status: String,
    val correlationId: String,
    val causationId: String,
    val timestamp: Instant,
    val details: Map<String, Any?> = emptyMap()
)

interface PayoutInitiationObservability {
    fun recordMetric(event: PayoutInitiationMetricEvent)
    fun getMetrics(): List<PayoutInitiationMetricEvent>
}

class InMemoryPayoutInitiationObservability : PayoutInitiationObservability {
    private val metrics = mutableListOf<PayoutInitiationMetricEvent>()

    @Synchronized
    override fun recordMetric(event: PayoutInitiationMetricEvent) {
        metrics.add(event)
    }

    @Synchronized
    override fun getMetrics(): List<PayoutInitiationMetricEvent> = metrics.toList()
}

// =============================================================================
// Store Interface & In-Memory Implementation
// =============================================================================

interface PayoutExecutionStore {
    fun save(record: PayoutExecutionRecord): PayoutExecutionRecord
    fun findById(tenantId: String, payoutId: UUID): PayoutExecutionRecord?
    fun findByReservationId(tenantId: String, reservationId: UUID): PayoutExecutionRecord?
    fun findByProviderTransactionId(tenantId: String, providerTransactionId: String): PayoutExecutionRecord?
    fun findByIdempotency(tenantId: String, idempotencyKey: String): Pair<String, PayoutInitiationResult>?
    fun saveIdempotency(tenantId: String, idempotencyKey: String, fingerprint: String, result: PayoutInitiationResult)
}

class InMemoryPayoutExecutionStore : PayoutExecutionStore {
    private val store = ConcurrentHashMap<UUID, PayoutExecutionRecord>()
    private val idempotency = ConcurrentHashMap<String, Pair<String, PayoutInitiationResult>>()

    override fun save(record: PayoutExecutionRecord): PayoutExecutionRecord {
        store[record.payoutId] = record
        return record
    }

    override fun findById(tenantId: String, payoutId: UUID): PayoutExecutionRecord? {
        val record = store[payoutId]
        return if (record?.tenantId == tenantId) record else null
    }

    override fun findByReservationId(tenantId: String, reservationId: UUID): PayoutExecutionRecord? {
        return store.values.find { it.tenantId == tenantId && it.reservationId == reservationId }
    }

    override fun findByProviderTransactionId(tenantId: String, providerTransactionId: String): PayoutExecutionRecord? {
        return store.values.find { it.tenantId == tenantId && it.providerTransactionId == providerTransactionId }
    }

    override fun findByIdempotency(tenantId: String, idempotencyKey: String): Pair<String, PayoutInitiationResult>? {
        return idempotency["$tenantId:$idempotencyKey"]
    }

    override fun saveIdempotency(tenantId: String, idempotencyKey: String, fingerprint: String, result: PayoutInitiationResult) {
        idempotency["$tenantId:$idempotencyKey"] = fingerprint to result
    }
}

// =============================================================================
// Exceptions
// =============================================================================

class PayoutNotApprovedException(message: String) : RuntimeException(message)
class PayoutInitiationConflictException(message: String) : RuntimeException(message)
class PayoutInitiationNotFoundException(message: String) : RuntimeException(message)
class UnauthorizedPayoutInitiationException(message: String) : RuntimeException(message)
