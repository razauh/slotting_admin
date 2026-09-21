package com.slotting.admin.withdrawal

import com.slotting.admin.auth.AuditEvent
import com.slotting.admin.auth.OutboxEvent
import com.slotting.admin.wallet.WalletBalanceBucketsRecord
import java.time.Instant
import java.util.UUID
import java.util.concurrent.ConcurrentHashMap

// =============================================================================
// Semantic Contract & Enums
// =============================================================================

const val PAYOUT_CALLBACK_REDUCTION_CONTRACT =
    "Unknown stays pending/reconcile; only definitive rejection releases; success captures lock."

enum class ProviderCallbackStatus {
    COMPLETED,
    REJECTED,
    IN_FLIGHT
}

enum class PayoutCallbackAction {
    CAPTURED,
    RELEASED,
    HELD_PENDING,
    DUPLICATE_ACCEPTED,
    STALE_IGNORED,
    CONFLICT_HELD
}

// =============================================================================
// Commands & Payloads
// =============================================================================

data class ProcessPayoutCallbackCommand(
    val tenantId: String,
    val providerId: String,
    val signatureHeader: String,
    val timestampHeader: String,
    val rawPayload: String,
    val deliverySequence: Long,
    val idempotencyKey: String,
    val correlationId: String,
    val causationId: String,
    val expectedVersion: Long = 1L
)

// =============================================================================
// Domain Records & Results
// =============================================================================

data class PayoutCallbackRecord(
    val callbackId: UUID,
    val tenantId: String,
    val providerId: String,
    val payoutId: UUID,
    val reservationId: UUID,
    val incomingStatus: ProviderCallbackStatus,
    val deliverySequence: Long,
    val action: PayoutCallbackAction,
    val payloadHash: String,
    val receivedAt: Instant,
    val idempotencyKey: String,
    val correlationId: String,
    val causationId: String,
    val evidenceReference: String,
    val version: Long = 1L
)

data class PayoutCallbackResult(
    val resultId: UUID,
    val tenantId: String,
    val payoutId: UUID,
    val reservationId: UUID,
    val previousStatus: PayoutExecutionStatus,
    val currentStatus: PayoutExecutionStatus,
    val reservationState: WithdrawalReservationState,
    val action: PayoutCallbackAction,
    val isDuplicate: Boolean,
    val deliverySequence: Long,
    val debitsEqualCredits: Boolean = true,
    val walletBalance: WalletBalanceBucketsRecord?,
    val serverTime: Instant,
    val serverVersion: Long,
    val evidenceReference: String,
    val auditEvent: AuditEvent,
    val outboxEvent: OutboxEvent,
    val hasAndroidDbImpact: Boolean = false,
    val hasAndroidLifecycleClaim: Boolean = false,
    val semanticContract: String = PAYOUT_CALLBACK_REDUCTION_CONTRACT
)

// =============================================================================
// Secret Resolver
// =============================================================================

interface ProviderSecretResolver {
    fun resolveSecret(tenantId: String, providerId: String): String?
}

class InMemoryProviderSecretResolver(
    private val secrets: MutableMap<String, String> = ConcurrentHashMap()
) : ProviderSecretResolver {
    fun registerSecret(tenantId: String, providerId: String, secret: String) {
        secrets["$tenantId:$providerId"] = secret
    }

    override fun resolveSecret(tenantId: String, providerId: String): String? {
        return secrets["$tenantId:$providerId"]
    }
}

// =============================================================================
// Observability
// =============================================================================

data class PayoutCallbackMetricEvent(
    val eventType: String, // "attempt", "accept", "reject", "duplicate", "conflict", "stale_ignored", "reconciliation_required"
    val tenantId: String,
    val providerId: String,
    val payoutId: UUID?,
    val reservationId: UUID?,
    val status: String,
    val deliverySequence: Long,
    val correlationId: String,
    val causationId: String,
    val timestamp: Instant,
    val details: Map<String, Any?> = emptyMap()
)

interface PayoutCallbackObservability {
    fun recordMetric(event: PayoutCallbackMetricEvent)
    fun getMetrics(): List<PayoutCallbackMetricEvent>
}

class InMemoryPayoutCallbackObservability : PayoutCallbackObservability {
    private val metrics = mutableListOf<PayoutCallbackMetricEvent>()

    @Synchronized
    override fun recordMetric(event: PayoutCallbackMetricEvent) {
        metrics.add(event)
    }

    @Synchronized
    override fun getMetrics(): List<PayoutCallbackMetricEvent> = metrics.toList()
}

// =============================================================================
// Store Interface & In-Memory Implementation
// =============================================================================

interface PayoutCallbackStore {
    fun save(record: PayoutCallbackRecord): PayoutCallbackRecord
    fun findById(tenantId: String, callbackId: UUID): PayoutCallbackRecord?
    fun findLastSequenceByPayoutId(tenantId: String, payoutId: UUID): Long?
    fun findByIdempotency(tenantId: String, idempotencyKey: String): Pair<String, PayoutCallbackResult>?
    fun saveIdempotency(tenantId: String, idempotencyKey: String, fingerprint: String, result: PayoutCallbackResult)
}

class InMemoryPayoutCallbackStore : PayoutCallbackStore {
    private val callbacks = ConcurrentHashMap<UUID, PayoutCallbackRecord>()
    private val maxSequencePerPayout = ConcurrentHashMap<String, Long>()
    private val idempotency = ConcurrentHashMap<String, Pair<String, PayoutCallbackResult>>()

    override fun save(record: PayoutCallbackRecord): PayoutCallbackRecord {
        callbacks[record.callbackId] = record
        val key = "${record.tenantId}:${record.payoutId}"
        maxSequencePerPayout.compute(key) { _, current ->
            if (current == null || record.deliverySequence > current) record.deliverySequence else current
        }
        return record
    }

    override fun findById(tenantId: String, callbackId: UUID): PayoutCallbackRecord? {
        val record = callbacks[callbackId]
        return if (record?.tenantId == tenantId) record else null
    }

    override fun findLastSequenceByPayoutId(tenantId: String, payoutId: UUID): Long? {
        return maxSequencePerPayout["$tenantId:$payoutId"]
    }

    override fun findByIdempotency(tenantId: String, idempotencyKey: String): Pair<String, PayoutCallbackResult>? {
        return idempotency["$tenantId:$idempotencyKey"]
    }

    override fun saveIdempotency(tenantId: String, idempotencyKey: String, fingerprint: String, result: PayoutCallbackResult) {
        idempotency["$tenantId:$idempotencyKey"] = fingerprint to result
    }
}

// =============================================================================
// Exceptions
// =============================================================================

class BadCallbackSignatureException(message: String) : RuntimeException(message)
class ExpiredCallbackTimestampException(message: String) : RuntimeException(message)
class UnknownPayoutProviderException(message: String) : RuntimeException(message)
class PayoutExecutionNotFoundException(message: String) : RuntimeException(message)
class StaleCallbackSequenceException(message: String) : RuntimeException(message)
class PayoutCallbackConflictException(message: String) : RuntimeException(message)
class InvalidPayoutCallbackPayloadException(message: String) : RuntimeException(message)
