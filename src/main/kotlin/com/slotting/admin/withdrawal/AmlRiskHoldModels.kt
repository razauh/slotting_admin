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

enum class AmlHoldStatus {
    ACTIVE,
    CLEARED,
    REJECTED
}

enum class AmlHoldReason {
    SUSPICIOUS_VELOCITY,
    LARGE_TRANSACTION_STRUCTURING,
    SANCTIONS_PEP_MATCH,
    FRAUD_SIGNAL_DETECTED,
    COMPLIANCE_MANUAL_HOLD
}

/**
 * Authoritative record of an AML Risk Hold on a withdrawal reservation.
 * Prevents payout without compliance review and ensures fund conservation.
 */
data class AmlRiskHoldRecord(
    val holdId: UUID,
    val tenantId: String,
    val ownerId: UUID,
    val requestId: UUID,
    val reservationId: UUID,
    val status: AmlHoldStatus,
    val reason: AmlHoldReason,
    val riskScore: Int,
    val breachedRules: List<String>,
    val heldAt: Instant,
    val clearedAt: Instant? = null,
    val rejectedAt: Instant? = null,
    val complianceOfficerId: String? = null,
    val justification: String? = null,
    val idempotencyKey: String,
    val correlationId: String,
    val causationId: String,
    val evidenceReference: String,
    val version: Long = 1L
) {
    init {
        require(tenantId.isNotBlank()) { "tenantId must not be blank" }
        require(riskScore >= 0) { "riskScore cannot be negative ($riskScore)" }
    }
}

// =============================================================================
// Commands & Queries
// =============================================================================

data class ApplyAmlRiskHoldCommand(
    val principal: AuthenticatedPrincipal?,
    val tenantId: String,
    val ownerId: UUID,
    val reservationId: UUID,
    val reason: AmlHoldReason,
    val riskScore: Int,
    val breachedRules: List<String>,
    val idempotencyKey: String,
    val correlationId: String,
    val causationId: String
)

data class ClearAmlRiskHoldCommand(
    val principal: AuthenticatedPrincipal?,
    val tenantId: String,
    val holdId: UUID,
    val justification: String,
    val idempotencyKey: String,
    val correlationId: String,
    val causationId: String
)

data class RejectAmlRiskHoldCommand(
    val principal: AuthenticatedPrincipal?,
    val tenantId: String,
    val holdId: UUID,
    val reason: String,
    val releaseFundsBackToWallet: Boolean = true,
    val idempotencyKey: String,
    val correlationId: String,
    val causationId: String
)

data class GetAmlRiskHoldQuery(
    val principal: AuthenticatedPrincipal?,
    val tenantId: String,
    val holdId: UUID
)

data class AmlRiskHoldResult(
    val resultId: UUID,
    val hold: AmlRiskHoldRecord,
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

data class AmlRiskHoldMetricEvent(
    val eventType: String, // "attempt", "accept", "reject", "duplicate", "conflict"
    val tenantId: String,
    val ownerId: UUID?,
    val holdId: UUID?,
    val reservationId: UUID?,
    val correlationId: String,
    val causationId: String,
    val timestamp: Instant,
    val details: Map<String, Any?> = emptyMap()
)

interface AmlRiskHoldObservability {
    fun recordMetric(event: AmlRiskHoldMetricEvent)
    fun getMetrics(): List<AmlRiskHoldMetricEvent>
}

class InMemoryAmlRiskHoldObservability : AmlRiskHoldObservability {
    private val metrics = mutableListOf<AmlRiskHoldMetricEvent>()

    @Synchronized
    override fun recordMetric(event: AmlRiskHoldMetricEvent) {
        metrics.add(event)
    }

    @Synchronized
    override fun getMetrics(): List<AmlRiskHoldMetricEvent> = metrics.toList()
}

// =============================================================================
// Store Interface & In-Memory Implementation
// =============================================================================

interface AmlRiskHoldStore {
    fun save(record: AmlRiskHoldRecord): AmlRiskHoldRecord
    fun findById(holdId: UUID): AmlRiskHoldRecord?
    fun findByReservationId(reservationId: UUID): AmlRiskHoldRecord?
    fun findByOwnerId(tenantId: String, ownerId: UUID): List<AmlRiskHoldRecord>
}

class InMemoryAmlRiskHoldStore : AmlRiskHoldStore {
    private val store = ConcurrentHashMap<UUID, AmlRiskHoldRecord>()

    override fun save(record: AmlRiskHoldRecord): AmlRiskHoldRecord {
        store[record.holdId] = record
        return record
    }

    override fun findById(holdId: UUID): AmlRiskHoldRecord? = store[holdId]

    override fun findByReservationId(reservationId: UUID): AmlRiskHoldRecord? {
        return store.values.find { it.reservationId == reservationId }
    }

    override fun findByOwnerId(tenantId: String, ownerId: UUID): List<AmlRiskHoldRecord> {
        return store.values.filter { it.tenantId == tenantId && it.ownerId == ownerId }
    }
}

// =============================================================================
// Domain Exceptions
// =============================================================================

class AmlHoldNotFoundException(
    message: String,
    details: Map<String, Any?> = emptyMap()
) : WithdrawalQuoteException(message, "AML_HOLD_NOT_FOUND", details)

class AmlHoldConflictException(
    message: String,
    details: Map<String, Any?> = emptyMap()
) : WithdrawalQuoteException(message, "AML_HOLD_CONFLICT", details)

class UnauthorizedComplianceAccessException(
    message: String,
    details: Map<String, Any?> = emptyMap()
) : WithdrawalQuoteException(message, "UNAUTHORIZED_COMPLIANCE_ACCESS", details)
