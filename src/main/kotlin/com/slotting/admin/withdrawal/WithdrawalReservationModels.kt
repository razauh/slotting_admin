package com.slotting.admin.withdrawal

import com.slotting.admin.auth.AuditEvent
import com.slotting.admin.auth.AuthenticatedPrincipal
import com.slotting.admin.auth.OutboxEvent
import com.slotting.admin.wallet.WalletBalanceBucketsRecord
import java.time.Instant
import java.util.UUID
import java.util.concurrent.ConcurrentHashMap

// =============================================================================
// Enums & Models
// =============================================================================

enum class WithdrawalReservationState {
    RESERVED,
    ON_HOLD,
    RELEASED,
    CAPTURED
}

enum class WithdrawalReleaseReason {
    PLAYER_CANCELLED,
    AML_REJECTED,
    MAKER_CHECKER_REJECTED,
    PROVIDER_REJECTED,
    EXPIRED,
    OPERATOR_CANCELLED
}

/**
 * Authoritative record of funds locked for a withdrawal request.
 * Enforces exact locking in wallet balance buckets and explicit release policies.
 */
data class WithdrawalReservationRecord(
    val reservationId: UUID,
    val tenantId: String,
    val ownerId: UUID,
    val walletId: UUID,
    val requestId: UUID,
    val currencyCode: String,
    val grossAmountMinorUnits: Long,
    val state: WithdrawalReservationState,
    val releaseReason: WithdrawalReleaseReason? = null,
    val reservedAt: Instant,
    val expiresAt: Instant,
    val releasedAt: Instant? = null,
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

data class ReserveWithdrawalFundsCommand(
    val principal: AuthenticatedPrincipal?,
    val tenantId: String,
    val ownerId: UUID,
    val requestId: UUID,
    val ttlSeconds: Long = 86400L,
    val idempotencyKey: String,
    val correlationId: String,
    val causationId: String
)

data class ReleaseWithdrawalFundsCommand(
    val principal: AuthenticatedPrincipal?,
    val tenantId: String,
    val ownerId: UUID,
    val reservationId: UUID,
    val reason: WithdrawalReleaseReason,
    val idempotencyKey: String,
    val correlationId: String,
    val causationId: String
)

data class GetWithdrawalReservationQuery(
    val principal: AuthenticatedPrincipal?,
    val tenantId: String,
    val reservationId: UUID
)

data class WithdrawalReservationResult(
    val resultId: UUID,
    val reservation: WithdrawalReservationRecord,
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
// Observability Models
// =============================================================================

data class WithdrawalReservationMetricEvent(
    val eventType: String, // "attempt", "accept", "reject", "duplicate", "conflict"
    val tenantId: String,
    val ownerId: UUID?,
    val reservationId: UUID?,
    val requestId: UUID?,
    val correlationId: String,
    val causationId: String,
    val timestamp: Instant,
    val details: Map<String, Any?> = emptyMap()
)

interface WithdrawalReservationObservability {
    fun recordMetric(event: WithdrawalReservationMetricEvent)
    fun getMetrics(): List<WithdrawalReservationMetricEvent>
}

class InMemoryWithdrawalReservationObservability : WithdrawalReservationObservability {
    private val metrics = mutableListOf<WithdrawalReservationMetricEvent>()

    @Synchronized
    override fun recordMetric(event: WithdrawalReservationMetricEvent) {
        metrics.add(event)
    }

    @Synchronized
    override fun getMetrics(): List<WithdrawalReservationMetricEvent> = metrics.toList()
}

// =============================================================================
// Store Interface & In-Memory Implementation
// =============================================================================

interface WithdrawalReservationStore {
    fun save(record: WithdrawalReservationRecord): WithdrawalReservationRecord
    fun findById(reservationId: UUID): WithdrawalReservationRecord?
    fun findByRequestId(requestId: UUID): WithdrawalReservationRecord?
    fun findByOwnerId(tenantId: String, ownerId: UUID): List<WithdrawalReservationRecord>
}

class InMemoryWithdrawalReservationStore : WithdrawalReservationStore {
    private val store = ConcurrentHashMap<UUID, WithdrawalReservationRecord>()

    override fun save(record: WithdrawalReservationRecord): WithdrawalReservationRecord {
        store[record.reservationId] = record
        return record
    }

    override fun findById(reservationId: UUID): WithdrawalReservationRecord? = store[reservationId]

    override fun findByRequestId(requestId: UUID): WithdrawalReservationRecord? {
        return store.values.find { it.requestId == requestId }
    }

    override fun findByOwnerId(tenantId: String, ownerId: UUID): List<WithdrawalReservationRecord> {
        return store.values.filter { it.tenantId == tenantId && it.ownerId == ownerId }
    }
}

// =============================================================================
// Domain Exceptions
// =============================================================================

class WithdrawalReservationNotFoundException(
    message: String,
    details: Map<String, Any?> = emptyMap()
) : WithdrawalQuoteException(message, "WITHDRAWAL_RESERVATION_NOT_FOUND", details)

class WithdrawalReservationConflictException(
    message: String,
    details: Map<String, Any?> = emptyMap()
) : WithdrawalQuoteException(message, "WITHDRAWAL_RESERVATION_CONFLICT", details)

class AlreadyReservedException(
    message: String,
    details: Map<String, Any?> = emptyMap()
) : WithdrawalQuoteException(message, "ALREADY_RESERVED", details)

class WithdrawalRequestInvalidStateException(
    message: String,
    details: Map<String, Any?> = emptyMap()
) : WithdrawalQuoteException(message, "INVALID_REQUEST_STATE", details)
