package com.slotting.admin.withdrawal

import com.slotting.admin.auth.AuditEvent
import com.slotting.admin.auth.AuthenticatedPrincipal
import com.slotting.admin.auth.OutboxEvent
import com.slotting.admin.wallet.WalletBalanceBucketsRecord
import java.time.Instant
import java.util.UUID
import java.util.concurrent.ConcurrentHashMap

// =============================================================================
// Semantic Contract & Enums
// =============================================================================

const val PAYOUT_RECONCILIATION_CONTRACT =
    "Unknown stays pending/reconcile; only definitive rejection releases; success captures lock."

enum class ReconciliationTrigger {
    AUTOMATED_POLL,
    OPERATOR_MANUAL,
    FAILURE_RETRY
}

enum class ProviderReconciliationStatus {
    SUCCESS_CONFIRMED,
    REJECTION_CONFIRMED,
    STILL_UNKNOWN_PENDING
}

enum class PayoutReconciliationAction {
    CAPTURED,
    RELEASED,
    REMAINED_PENDING,
    DUPLICATE_ACCEPTED,
    CONFLICT_HELD
}

// =============================================================================
// Provider Inquiry Port
// =============================================================================

data class ProviderReconciliationResponse(
    val status: ProviderReconciliationStatus,
    val providerTransactionId: String?,
    val rawResponseCode: String,
    val safeReason: String
)

interface PayoutReconciliationProviderPort {
    fun queryPayoutStatus(
        tenantId: String,
        payoutId: UUID,
        providerTransactionId: String?
    ): ProviderReconciliationResponse
}

class FakePayoutReconciliationProviderAdapter : PayoutReconciliationProviderPort {
    var forcedStatus: ProviderReconciliationStatus? = null
    var shouldFail: Boolean = false

    override fun queryPayoutStatus(
        tenantId: String,
        payoutId: UUID,
        providerTransactionId: String?
    ): ProviderReconciliationResponse {
        if (shouldFail) {
            throw PayoutReconciliationDependencyException("Upstream banking provider query failed with timeout / 503")
        }
        val status = forcedStatus ?: ProviderReconciliationStatus.SUCCESS_CONFIRMED
        return when (status) {
            ProviderReconciliationStatus.SUCCESS_CONFIRMED -> ProviderReconciliationResponse(
                status = ProviderReconciliationStatus.SUCCESS_CONFIRMED,
                providerTransactionId = providerTransactionId ?: "reconciled-tx-${UUID.randomUUID()}",
                rawResponseCode = "SETTLED_200",
                safeReason = "External bank cleared settlement confirmed"
            )
            ProviderReconciliationStatus.REJECTION_CONFIRMED -> ProviderReconciliationResponse(
                status = ProviderReconciliationStatus.REJECTION_CONFIRMED,
                providerTransactionId = providerTransactionId,
                rawResponseCode = "DECLINED_400",
                safeReason = "Beneficiary bank definitively declined payout"
            )
            ProviderReconciliationStatus.STILL_UNKNOWN_PENDING -> ProviderReconciliationResponse(
                status = ProviderReconciliationStatus.STILL_UNKNOWN_PENDING,
                providerTransactionId = providerTransactionId,
                rawResponseCode = "IN_FLIGHT_202",
                safeReason = "Payout still in-flight through clearing network"
            )
        }
    }
}

// =============================================================================
// Commands
// =============================================================================

data class ReconcileAmbiguousPayoutCommand(
    val principal: AuthenticatedPrincipal?,
    val tenantId: String,
    val payoutId: UUID,
    val trigger: ReconciliationTrigger = ReconciliationTrigger.AUTOMATED_POLL,
    val manualResolution: ProviderReconciliationStatus? = null,
    val manualReason: String? = null,
    val idempotencyKey: String,
    val correlationId: String,
    val causationId: String,
    val expectedVersion: Long = 1L
)

// =============================================================================
// Domain Records & Results
// =============================================================================

data class PayoutReconciliationRecord(
    val reconciliationId: UUID,
    val tenantId: String,
    val payoutId: UUID,
    val reservationId: UUID,
    val trigger: ReconciliationTrigger,
    val providerStatus: ProviderReconciliationStatus,
    val action: PayoutReconciliationAction,
    val resolvedStatus: PayoutExecutionStatus,
    val safeReason: String,
    val reconciledAt: Instant,
    val idempotencyKey: String,
    val correlationId: String,
    val causationId: String,
    val evidenceReference: String,
    val version: Long = 1L
)

data class PayoutReconciliationResult(
    val resultId: UUID,
    val tenantId: String,
    val payoutId: UUID,
    val reservationId: UUID,
    val previousStatus: PayoutExecutionStatus,
    val currentStatus: PayoutExecutionStatus,
    val reservationState: WithdrawalReservationState,
    val action: PayoutReconciliationAction,
    val isDuplicate: Boolean,
    val debitsEqualCredits: Boolean = true,
    val walletBalance: WalletBalanceBucketsRecord?,
    val serverTime: Instant,
    val serverVersion: Long,
    val evidenceReference: String,
    val auditEvent: AuditEvent,
    val outboxEvent: OutboxEvent,
    val hasAndroidDbImpact: Boolean = false,
    val hasAndroidLifecycleClaim: Boolean = false,
    val semanticContract: String = PAYOUT_RECONCILIATION_CONTRACT
)

// =============================================================================
// Store Interface & In-Memory Implementation
// =============================================================================

interface PayoutReconciliationStore {
    fun save(record: PayoutReconciliationRecord): PayoutReconciliationRecord
    fun findById(tenantId: String, reconciliationId: UUID): PayoutReconciliationRecord?
    fun findLatestByPayoutId(tenantId: String, payoutId: UUID): PayoutReconciliationRecord?
    fun findByIdempotency(tenantId: String, idempotencyKey: String): Pair<String, PayoutReconciliationResult>?
    fun saveIdempotency(tenantId: String, idempotencyKey: String, fingerprint: String, result: PayoutReconciliationResult)
}

class InMemoryPayoutReconciliationStore : PayoutReconciliationStore {
    private val records = ConcurrentHashMap<UUID, PayoutReconciliationRecord>()
    private val idempotency = ConcurrentHashMap<String, Pair<String, PayoutReconciliationResult>>()

    override fun save(record: PayoutReconciliationRecord): PayoutReconciliationRecord {
        records[record.reconciliationId] = record
        return record
    }

    override fun findById(tenantId: String, reconciliationId: UUID): PayoutReconciliationRecord? {
        val record = records[reconciliationId]
        return if (record?.tenantId == tenantId) record else null
    }

    override fun findLatestByPayoutId(tenantId: String, payoutId: UUID): PayoutReconciliationRecord? {
        return records.values
            .filter { it.tenantId == tenantId && it.payoutId == payoutId }
            .maxByOrNull { it.reconciledAt }
    }

    override fun findByIdempotency(tenantId: String, idempotencyKey: String): Pair<String, PayoutReconciliationResult>? {
        return idempotency["$tenantId:$idempotencyKey"]
    }

    override fun saveIdempotency(tenantId: String, idempotencyKey: String, fingerprint: String, result: PayoutReconciliationResult) {
        idempotency["$tenantId:$idempotencyKey"] = fingerprint to result
    }
}

// =============================================================================
// Observability
// =============================================================================

data class PayoutReconciliationMetricEvent(
    val eventType: String, // "attempt", "accept", "reject", "duplicate", "conflict", "reconciliation_required", "exhausted_alert"
    val tenantId: String,
    val payoutId: UUID?,
    val reservationId: UUID?,
    val status: String,
    val correlationId: String,
    val causationId: String,
    val timestamp: Instant,
    val details: Map<String, Any?> = emptyMap()
)

interface PayoutReconciliationObservability {
    fun recordMetric(event: PayoutReconciliationMetricEvent)
    fun getMetrics(): List<PayoutReconciliationMetricEvent>
}

class InMemoryPayoutReconciliationObservability : PayoutReconciliationObservability {
    private val metrics = mutableListOf<PayoutReconciliationMetricEvent>()

    @Synchronized
    override fun recordMetric(event: PayoutReconciliationMetricEvent) {
        metrics.add(event)
    }

    @Synchronized
    override fun getMetrics(): List<PayoutReconciliationMetricEvent> = metrics.toList()
}

// =============================================================================
// Exceptions
// =============================================================================

class UnauthorizedPayoutReconciliationException(message: String) : RuntimeException(message)
class PayoutReconciliationNotFoundException(message: String) : RuntimeException(message)
class PayoutReconciliationConflictException(message: String) : RuntimeException(message)
class PayoutReconciliationDependencyException(message: String) : RuntimeException(message)
