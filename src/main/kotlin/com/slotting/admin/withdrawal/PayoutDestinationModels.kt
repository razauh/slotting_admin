package com.slotting.admin.withdrawal

import com.slotting.admin.auth.AuditEvent
import com.slotting.admin.auth.AuthenticatedPrincipal
import com.slotting.admin.auth.OutboxEvent
import java.time.Instant
import java.util.UUID

// =============================================================================
// Enums & Models
// =============================================================================

enum class DestinationVerificationMethod {
    CLOSED_LOOP_DEPOSIT,
    OPEN_BANKING_NAME_MATCH,
    MICRO_DEPOSIT,
    MANUAL_DOCUMENT_VERIFICATION
}

enum class DestinationVerificationStatus {
    PENDING_VERIFICATION,
    VERIFIED,
    REJECTED,
    REVOKED
}

/**
 * Authoritative destination record verifying payout instrument ownership by player.
 * Enforces closed-loop rules, name matching, and non-repudiation.
 */
data class PayoutDestinationRecord(
    val destinationId: UUID,
    val tenantId: String,
    val ownerId: UUID,
    val paymentMethod: WithdrawalPaymentMethod,
    val destinationReference: String,
    val accountHolderName: String,
    val verificationMethod: DestinationVerificationMethod,
    val status: DestinationVerificationStatus,
    val registeredAt: Instant,
    val verifiedAt: Instant? = null,
    val rejectionReason: String? = null,
    val verificationEvidenceReference: String? = null,
    val idempotencyKey: String,
    val correlationId: String,
    val causationId: String,
    val version: Long = 1L
) {
    init {
        require(tenantId.isNotBlank()) { "tenantId must not be blank" }
        require(destinationReference.isNotBlank()) { "destinationReference must not be blank" }
        require(accountHolderName.isNotBlank()) { "accountHolderName must not be blank" }
    }
}

// =============================================================================
// Commands & Queries
// =============================================================================

data class RegisterPayoutDestinationCommand(
    val principal: AuthenticatedPrincipal?,
    val tenantId: String,
    val ownerId: UUID,
    val paymentMethod: WithdrawalPaymentMethod,
    val destinationReference: String,
    val accountHolderName: String,
    val verificationMethod: DestinationVerificationMethod,
    val autoVerifyIfNameMatches: Boolean = true,
    val playerKycVerifiedName: String? = null,
    val idempotencyKey: String,
    val correlationId: String,
    val causationId: String
)

data class VerifyPayoutDestinationCommand(
    val principal: AuthenticatedPrincipal?,
    val tenantId: String,
    val destinationId: UUID,
    val ownerKycFullName: String,
    val proofReference: String,
    val idempotencyKey: String,
    val correlationId: String,
    val causationId: String
)

data class CheckDestinationOwnershipQuery(
    val principal: AuthenticatedPrincipal?,
    val tenantId: String,
    val ownerId: UUID,
    val destinationReference: String,
    val correlationId: String,
    val causationId: String
)

data class PayoutDestinationResult(
    val resultId: UUID,
    val destination: PayoutDestinationRecord,
    val isVerified: Boolean,
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

data class PayoutDestinationMetricEvent(
    val eventType: String, // "attempt", "accept", "reject", "duplicate", "conflict"
    val tenantId: String,
    val ownerId: UUID?,
    val destinationId: UUID?,
    val correlationId: String,
    val causationId: String,
    val timestamp: Instant,
    val details: Map<String, Any?> = emptyMap()
)

interface PayoutDestinationObservability {
    fun recordMetric(event: PayoutDestinationMetricEvent)
    fun getMetrics(): List<PayoutDestinationMetricEvent>
}

class InMemoryPayoutDestinationObservability : PayoutDestinationObservability {
    private val metrics = mutableListOf<PayoutDestinationMetricEvent>()

    @Synchronized
    override fun recordMetric(event: PayoutDestinationMetricEvent) {
        metrics.add(event)
    }

    @Synchronized
    override fun getMetrics(): List<PayoutDestinationMetricEvent> = metrics.toList()
}

// =============================================================================
// Store Interface & In-Memory Implementation
// =============================================================================

interface PayoutDestinationStore {
    fun save(record: PayoutDestinationRecord): PayoutDestinationRecord
    fun findById(destinationId: UUID): PayoutDestinationRecord?
    fun findByOwnerAndReference(
        tenantId: String,
        ownerId: UUID,
        destinationReference: String
    ): PayoutDestinationRecord?
    fun findByOwnerId(tenantId: String, ownerId: UUID): List<PayoutDestinationRecord>
}

class InMemoryPayoutDestinationStore : PayoutDestinationStore {
    private val store = java.util.concurrent.ConcurrentHashMap<UUID, PayoutDestinationRecord>()

    override fun save(record: PayoutDestinationRecord): PayoutDestinationRecord {
        store[record.destinationId] = record
        return record
    }

    override fun findById(destinationId: UUID): PayoutDestinationRecord? = store[destinationId]

    override fun findByOwnerAndReference(
        tenantId: String,
        ownerId: UUID,
        destinationReference: String
    ): PayoutDestinationRecord? {
        return store.values.find {
            it.tenantId == tenantId && it.ownerId == ownerId && it.destinationReference == destinationReference
        }
    }

    override fun findByOwnerId(tenantId: String, ownerId: UUID): List<PayoutDestinationRecord> {
        return store.values.filter { it.tenantId == tenantId && it.ownerId == ownerId }
    }
}

// =============================================================================
// Domain Exceptions
// =============================================================================

class DestinationOwnershipMismatchException(
    message: String,
    details: Map<String, Any?> = emptyMap()
) : WithdrawalQuoteException(message, "DESTINATION_OWNERSHIP_MISMATCH", details)

class InvalidDestinationException(
    message: String,
    details: Map<String, Any?> = emptyMap()
) : WithdrawalQuoteException(message, "INVALID_DESTINATION", details)

class DestinationNotFoundException(
    message: String,
    details: Map<String, Any?> = emptyMap()
) : WithdrawalQuoteException(message, "DESTINATION_NOT_FOUND", details)
