package com.slotting.admin.wallet

import com.slotting.admin.auth.AuditEvent
import com.slotting.admin.auth.AuthenticatedPrincipal
import com.slotting.admin.auth.OutboxEvent
import java.time.Instant
import java.util.UUID

// =============================================================================
// Reservation Enums & Data Structures
// =============================================================================

enum class ReservationType {
    WAGER,
    WITHDRAWAL
}

enum class ReservationStatus {
    RESERVED,
    CAPTURED,
    RELEASED,
    EXPIRED;

    val isTerminal: Boolean
        get() = this == CAPTURED || this == RELEASED || this == EXPIRED
}

data class ReservationBucketBreakdown(
    val cashMinorUnits: Long = 0L,
    val bonusMinorUnits: Long = 0L
) {
    val totalMinorUnits: Long
        get() = cashMinorUnits + bonusMinorUnits

    init {
        require(cashMinorUnits >= 0L) { "Cash breakdown cannot be negative ($cashMinorUnits)" }
        require(bonusMinorUnits >= 0L) { "Bonus breakdown cannot be negative ($bonusMinorUnits)" }
    }
}

/**
 * Authoritative persisted reservation record.
 * Terminal transitions are idempotent; expiry is an audited worker command, never silent deletion.
 */
data class WalletReservationRecord(
    val reservationId: UUID,
    val tenantId: String,
    val walletId: UUID,
    val ownerId: UUID,
    val currencyCode: String,
    val type: ReservationType,
    val amountMinorUnits: Long,
    val breakdown: ReservationBucketBreakdown,
    val status: ReservationStatus,
    val reference: String,
    val expiresAt: Instant,
    val reservedAt: Instant,
    val capturedAt: Instant? = null,
    val releasedAt: Instant? = null,
    val expiredAt: Instant? = null,
    val idempotencyKey: String,
    val correlationId: String,
    val causationId: String,
    val evidenceReference: String,
    val version: Long = 1L
) {
    init {
        require(amountMinorUnits > 0L) { "Reservation amount must be positive: $amountMinorUnits" }
        require(amountMinorUnits == breakdown.totalMinorUnits) {
            "Reservation amount ($amountMinorUnits) must equal breakdown sum (${breakdown.totalMinorUnits})"
        }
        require(tenantId.isNotBlank()) { "tenantId must not be blank" }
        require(reference.isNotBlank()) { "reference must not be blank" }
    }
}

// =============================================================================
// Commands & Results
// =============================================================================

data class CreateReservationCommand(
    val principal: AuthenticatedPrincipal?,
    val tenantId: String,
    val walletId: UUID,
    val type: ReservationType,
    val amountMinorUnits: Long,
    val ttlSeconds: Long,
    val reference: String,
    val preferCashFirst: Boolean = true,
    val idempotencyKey: String,
    val correlationId: String,
    val causationId: String,
    val expectedVersion: Long = 0L
)

data class CaptureReservationCommand(
    val principal: AuthenticatedPrincipal?,
    val tenantId: String,
    val reservationId: UUID,
    val idempotencyKey: String,
    val correlationId: String,
    val causationId: String,
    val expectedVersion: Long = 0L
)

data class ReleaseReservationCommand(
    val principal: AuthenticatedPrincipal?,
    val tenantId: String,
    val reservationId: UUID,
    val reason: String,
    val idempotencyKey: String,
    val correlationId: String,
    val causationId: String,
    val expectedVersion: Long = 0L
)

data class ExpireReservationCommand(
    val principal: AuthenticatedPrincipal?,
    val tenantId: String,
    val reservationId: UUID,
    val workerId: String,
    val idempotencyKey: String,
    val correlationId: String,
    val causationId: String,
    val expectedVersion: Long = 0L
)

data class WalletReservationResult(
    val resultId: UUID,
    val reservation: WalletReservationRecord,
    val previousStatus: ReservationStatus?,
    val debitsEqualCredits: Boolean,
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

data class ReservationMetricEvent(
    val eventType: String, // "attempt", "accept", "reject", "duplicate", "conflict", "terminal_result", "invariant_failure"
    val tenantId: String,
    val reservationId: UUID?,
    val correlationId: String,
    val causationId: String,
    val timestamp: Instant,
    val details: Map<String, Any?> = emptyMap()
)

data class ReservationAlertEvent(
    val alertName: String,
    val tenantId: String,
    val message: String,
    val timestamp: Instant,
    val details: Map<String, Any?> = emptyMap()
)

interface WalletReservationObservability {
    fun recordMetric(event: ReservationMetricEvent)
    fun recordAlert(alert: ReservationAlertEvent)
    fun getMetrics(): List<ReservationMetricEvent>
    fun getAlerts(): List<ReservationAlertEvent>
}

class InMemoryWalletReservationObservability : WalletReservationObservability {
    private val metrics = mutableListOf<ReservationMetricEvent>()
    private val alerts = mutableListOf<ReservationAlertEvent>()

    @Synchronized
    override fun recordMetric(event: ReservationMetricEvent) {
        metrics.add(event)
    }

    @Synchronized
    override fun recordAlert(alert: ReservationAlertEvent) {
        alerts.add(alert)
    }

    @Synchronized
    override fun getMetrics(): List<ReservationMetricEvent> = metrics.toList()

    @Synchronized
    override fun getAlerts(): List<ReservationAlertEvent> = alerts.toList()
}

// =============================================================================
// Reservation Store Interface & In-Memory Implementation
// =============================================================================

interface WalletReservationStore {
    fun findById(reservationId: UUID): WalletReservationRecord?
    fun save(record: WalletReservationRecord): WalletReservationRecord
    fun findByWalletId(walletId: UUID): List<WalletReservationRecord>
    fun findByOwnerId(ownerId: UUID): List<WalletReservationRecord>
    fun delete(reservationId: UUID): Boolean // For testing that silent deletion never occurs
}

class InMemoryWalletReservationStore : WalletReservationStore {
    private val store = java.util.concurrent.ConcurrentHashMap<UUID, WalletReservationRecord>()

    override fun findById(reservationId: UUID): WalletReservationRecord? = store[reservationId]

    override fun save(record: WalletReservationRecord): WalletReservationRecord {
        store[record.reservationId] = record
        return record
    }

    override fun findByWalletId(walletId: UUID): List<WalletReservationRecord> =
        store.values.filter { it.walletId == walletId }

    override fun findByOwnerId(ownerId: UUID): List<WalletReservationRecord> =
        store.values.filter { it.ownerId == ownerId }

    override fun delete(reservationId: UUID): Boolean = store.remove(reservationId) != null
}

// =============================================================================
// Domain Exceptions
// =============================================================================

open class WalletReservationException(
    message: String,
    errorCode: String,
    details: Map<String, Any?> = emptyMap()
) : WalletException(message, errorCode, details)

class InsufficientReservationBalanceException(
    message: String,
    details: Map<String, Any?> = emptyMap()
) : WalletReservationException(message, "INSUFFICIENT_RESERVATION_BALANCE", details)

class InvalidReservationAmountException(
    message: String,
    details: Map<String, Any?> = emptyMap()
) : WalletReservationException(message, "INVALID_RESERVATION_AMOUNT", details)

class ReservationNotFoundException(
    message: String,
    details: Map<String, Any?> = emptyMap()
) : WalletReservationException(message, "RESERVATION_NOT_FOUND", details)

class TerminalReservationTransitionException(
    message: String,
    details: Map<String, Any?> = emptyMap()
) : WalletReservationException(message, "TERMINAL_RESERVATION_TRANSITION", details)

class ReservationExpiredException(
    message: String,
    details: Map<String, Any?> = emptyMap()
) : WalletReservationException(message, "RESERVATION_EXPIRED", details)

class IdempotencyConflictException(
    message: String,
    details: Map<String, Any?> = emptyMap()
) : WalletReservationException(message, "IDEMPOTENCY_CONFLICT", details)

class UnauthorizedWalletAccessException(
    message: String,
    details: Map<String, Any?> = emptyMap()
) : WalletReservationException(message, "UNAUTHORIZED_WALLET_ACCESS", details)

class CrossTenantAccessException(
    message: String,
    details: Map<String, Any?> = emptyMap()
) : WalletReservationException(message, "CROSS_TENANT_ACCESS_DENIED", details)

class BonusWithdrawalNotAllowedException(
    message: String,
    details: Map<String, Any?> = emptyMap()
) : WalletReservationException(message, "BONUS_WITHDRAWAL_NOT_ALLOWED", details)

