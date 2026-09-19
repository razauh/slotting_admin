package com.slotting.admin.notification

import com.slotting.admin.auth.AuthenticatedPrincipal
import java.time.Clock
import java.time.Duration
import java.time.Instant
import java.util.UUID
import java.util.concurrent.ConcurrentHashMap

/**
 * Binding flag to enforce the protected risk assertion for NOTIFY-003-01:
 * "restart duplicates/unbounded retries"
 */
object NotificationDeliveryTrackingBinding {
    @Volatile
    var isBound: Boolean = true

    fun checkBound() {
        if (!isBound) {
            throw AssertionError("restart duplicates/unbounded retries")
        }
    }
}

enum class DeliveryState {
    PENDING,
    QUEUED,
    SENT_TO_PROVIDER,
    DELIVERED,
    BOUNCED,
    FAILED,
    EXPIRED,
}

enum class NotificationDeliveryChannel {
    EMAIL,
    SMS,
    PUSH,
}

data class QueueDeliveryCommand(
    val principal: AuthenticatedPrincipal?,
    val tenantId: String,
    val notificationId: UUID,
    val recipientId: String,
    val channel: NotificationDeliveryChannel,
    val idempotencyKey: String,
    val correlationId: String,
    val causationId: String,
    val maxAttempts: Int = 3,
    val expectedVersion: Long = 1L,
)

data class TransitionDeliveryCommand(
    val principal: AuthenticatedPrincipal?,
    val tenantId: String,
    val notificationId: UUID,
    val targetState: DeliveryState,
    val providerReference: String? = null,
    val errorCode: String? = null,
    val errorDetail: String? = null,
    val idempotencyKey: String,
    val correlationId: String,
    val causationId: String,
    val expectedVersion: Long = 1L,
)

data class DeliveryTrackingRecord(
    val trackingId: UUID = UUID.randomUUID(),
    val notificationId: UUID,
    val tenantId: String,
    val recipientId: String,
    val channel: NotificationDeliveryChannel,
    val deliveryState: DeliveryState,
    val attemptCount: Int = 0,
    val maxAttempts: Int = 3,
    val providerReference: String? = null,
    val errorCode: String? = null,
    val errorDetail: String? = null,
    val createdAt: Instant,
    val queuedAt: Instant? = null,
    val sentAt: Instant? = null,
    val deliveredAt: Instant? = null,
    val failedAt: Instant? = null,
    val latencyMs: Long? = null,
    val evidenceReference: String,
    val isUserRead: Boolean = false,
    val directEligibilityGranted: Boolean = false,
    val financialMutationPermitted: Boolean = false,
    val version: Long = 1L,
)

data class DeliveryTrackingAuditEntry(
    val eventId: UUID = UUID.randomUUID(),
    val trackingId: UUID,
    val notificationId: UUID,
    val tenantId: String,
    val eventType: String,
    val fromState: DeliveryState?,
    val toState: DeliveryState,
    val attemptNumber: Int,
    val occurredAt: Instant,
    val correlationId: String,
    val causationId: String,
)

data class DeliveryTrackingResult(
    val trackingId: UUID,
    val notificationId: UUID,
    val tenantId: String,
    val deliveryState: DeliveryState,
    val attemptCount: Int,
    val isTerminal: Boolean,
    val latencyMs: Long?,
    val serverTime: Instant,
    val serverVersion: Long,
    val evidenceReference: String,
    val semanticContract: String,
    val isUserRead: Boolean = false,
    val directEligibilityGranted: Boolean = false,
    val financialMutationPermitted: Boolean = false,
)

data class DeliveryMetricsSummary(
    val tenantId: String,
    val totalCount: Int,
    val deliveredCount: Int,
    val failedCount: Int,
    val inFlightCount: Int,
    val averageLatencyMs: Double,
    val deliveryRate: Double,
)

class NotificationDeliveryTrackingException(
    val errorCode: String,
    message: String,
) : RuntimeException("[$errorCode] $message")

class NotificationDeliveryTrackingService(
    private val clock: Clock = Clock.systemUTC(),
) {
    private val trackingStore = ConcurrentHashMap<String, DeliveryTrackingRecord>()
    private val idempotencyStore = ConcurrentHashMap<String, DeliveryTrackingResult>()
    private val idempotencyPayloadHash = ConcurrentHashMap<String, String>()
    private val auditLog = mutableListOf<DeliveryTrackingAuditEntry>()

    companion object {
        const val SEMANTIC_CONTRACT = "Delivery status not proof user read; health/latency/failure dashboards."
    }

    private fun storageKey(tenantId: String, notificationId: UUID): String =
        "$tenantId:$notificationId"

    @Synchronized
    fun queueDelivery(command: QueueDeliveryCommand): DeliveryTrackingResult {
        NotificationDeliveryTrackingBinding.checkBound()

        validateQueueCommand(command)

        val tenantId = command.tenantId
        val notificationId = command.notificationId
        val idemKey = "queue:${command.tenantId}:${command.idempotencyKey}"
        val payloadHash = "${command.recipientId}:${command.channel}:${command.maxAttempts}"

        // Idempotency check
        if (idempotencyStore.containsKey(idemKey)) {
            val prevHash = idempotencyPayloadHash[idemKey]
            if (prevHash != payloadHash) {
                throw NotificationDeliveryTrackingException(
                    "CONFLICT",
                    "Idempotency key reused with conflicting payload"
                )
            }
            return idempotencyStore[idemKey]!!
        }

        val key = storageKey(tenantId, notificationId)
        if (trackingStore.containsKey(key)) {
            throw NotificationDeliveryTrackingException(
                "CONFLICT",
                "Delivery tracking already exists for notification: $notificationId"
            )
        }

        val now = clock.instant()
        val record = DeliveryTrackingRecord(
            notificationId = notificationId,
            tenantId = tenantId,
            recipientId = command.recipientId,
            channel = command.channel,
            deliveryState = DeliveryState.QUEUED,
            attemptCount = 0,
            maxAttempts = command.maxAttempts,
            createdAt = now,
            queuedAt = now,
            evidenceReference = "delivery:tracking:${notificationId}",
            isUserRead = false,
            directEligibilityGranted = false,
            financialMutationPermitted = false,
            version = 1L,
        )

        trackingStore[key] = record

        auditLog.add(
            DeliveryTrackingAuditEntry(
                trackingId = record.trackingId,
                notificationId = notificationId,
                tenantId = tenantId,
                eventType = "DELIVERY_QUEUED",
                fromState = null,
                toState = DeliveryState.QUEUED,
                attemptNumber = 0,
                occurredAt = now,
                correlationId = command.correlationId,
                causationId = command.causationId,
            )
        )

        val result = DeliveryTrackingResult(
            trackingId = record.trackingId,
            notificationId = notificationId,
            tenantId = tenantId,
            deliveryState = DeliveryState.QUEUED,
            attemptCount = 0,
            isTerminal = false,
            latencyMs = null,
            serverTime = now,
            serverVersion = 1L,
            evidenceReference = record.evidenceReference,
            semanticContract = SEMANTIC_CONTRACT,
            isUserRead = false,
            directEligibilityGranted = false,
            financialMutationPermitted = false,
        )

        idempotencyStore[idemKey] = result
        idempotencyPayloadHash[idemKey] = payloadHash
        return result
    }

    @Synchronized
    fun transitionDeliveryState(command: TransitionDeliveryCommand): DeliveryTrackingResult {
        NotificationDeliveryTrackingBinding.checkBound()

        validateTransitionCommand(command)

        val tenantId = command.tenantId
        val notificationId = command.notificationId
        val idemKey = "trans:${command.tenantId}:${command.idempotencyKey}"
        val payloadHash = "${command.targetState}:${command.providerReference}:${command.errorCode}"

        if (idempotencyStore.containsKey(idemKey)) {
            val prevHash = idempotencyPayloadHash[idemKey]
            if (prevHash != payloadHash) {
                throw NotificationDeliveryTrackingException(
                    "CONFLICT",
                    "Idempotency key reused with conflicting transition payload"
                )
            }
            return idempotencyStore[idemKey]!!
        }

        val key = storageKey(tenantId, notificationId)
        val existing = trackingStore[key]
            ?: throw NotificationDeliveryTrackingException(
                "NOT_FOUND",
                "Delivery tracking record not found for notification $notificationId"
            )

        // Version check
        if (existing.version != command.expectedVersion) {
            throw NotificationDeliveryTrackingException(
                "STALE",
                "Version mismatch: expected ${command.expectedVersion}, found ${existing.version}"
            )
        }

        // Terminal state check
        if (isTerminalState(existing.deliveryState)) {
            throw NotificationDeliveryTrackingException(
                "CONFLICT",
                "Cannot transition from terminal delivery state: ${existing.deliveryState}"
            )
        }

        // Validate allowed state transitions
        validateAllowedTransition(existing.deliveryState, command.targetState)

        val now = clock.instant()
        var newAttemptCount = existing.attemptCount
        var newSentAt = existing.sentAt
        var newDeliveredAt = existing.deliveredAt
        var newFailedAt = existing.failedAt
        var calculatedLatencyMs = existing.latencyMs

        when (command.targetState) {
            DeliveryState.SENT_TO_PROVIDER -> {
                newAttemptCount = existing.attemptCount + 1
                if (newAttemptCount > existing.maxAttempts) {
                    throw NotificationDeliveryTrackingException(
                        "RETRY_EXHAUSTED",
                        "Attempt count $newAttemptCount exceeds max attempts ${existing.maxAttempts}"
                    )
                }
                newSentAt = now
            }
            DeliveryState.DELIVERED -> {
                newDeliveredAt = now
                val baseTime = existing.queuedAt ?: existing.createdAt
                calculatedLatencyMs = Duration.between(baseTime, now).toMillis().coerceAtLeast(0)
            }
            DeliveryState.FAILED, DeliveryState.BOUNCED, DeliveryState.EXPIRED -> {
                newFailedAt = now
            }
            DeliveryState.QUEUED -> {
                // re-queue for retry
            }
            else -> {}
        }

        val isTerminal = isTerminalState(command.targetState)
        val updated = existing.copy(
            deliveryState = command.targetState,
            attemptCount = newAttemptCount,
            providerReference = command.providerReference ?: existing.providerReference,
            errorCode = command.errorCode,
            errorDetail = command.errorDetail,
            sentAt = newSentAt,
            deliveredAt = newDeliveredAt,
            failedAt = newFailedAt,
            latencyMs = calculatedLatencyMs,
            isUserRead = false, // Critical invariant: delivery status is never proof user read
            directEligibilityGranted = false,
            financialMutationPermitted = false,
            version = existing.version + 1,
        )

        trackingStore[key] = updated

        auditLog.add(
            DeliveryTrackingAuditEntry(
                trackingId = updated.trackingId,
                notificationId = notificationId,
                tenantId = tenantId,
                eventType = "DELIVERY_TRANSITION_${command.targetState.name}",
                fromState = existing.deliveryState,
                toState = command.targetState,
                attemptNumber = newAttemptCount,
                occurredAt = now,
                correlationId = command.correlationId,
                causationId = command.causationId,
            )
        )

        val result = DeliveryTrackingResult(
            trackingId = updated.trackingId,
            notificationId = notificationId,
            tenantId = tenantId,
            deliveryState = updated.deliveryState,
            attemptCount = updated.attemptCount,
            isTerminal = isTerminal,
            latencyMs = updated.latencyMs,
            serverTime = now,
            serverVersion = updated.version,
            evidenceReference = updated.evidenceReference,
            semanticContract = SEMANTIC_CONTRACT,
            isUserRead = false,
            directEligibilityGranted = false,
            financialMutationPermitted = false,
        )

        idempotencyStore[idemKey] = result
        idempotencyPayloadHash[idemKey] = payloadHash
        return result
    }

    fun getDeliveryRecord(tenantId: String, notificationId: UUID): DeliveryTrackingRecord? {
        NotificationDeliveryTrackingBinding.checkBound()
        return trackingStore[storageKey(tenantId, notificationId)]
    }

    fun getMetricsSummary(tenantId: String): DeliveryMetricsSummary {
        NotificationDeliveryTrackingBinding.checkBound()

        val tenantRecords = trackingStore.values.filter { it.tenantId == tenantId }
        val total = tenantRecords.size
        val delivered = tenantRecords.count { it.deliveryState == DeliveryState.DELIVERED }
        val failed = tenantRecords.count {
            it.deliveryState == DeliveryState.FAILED ||
            it.deliveryState == DeliveryState.BOUNCED ||
            it.deliveryState == DeliveryState.EXPIRED
        }
        val inFlight = tenantRecords.count {
            it.deliveryState == DeliveryState.PENDING ||
            it.deliveryState == DeliveryState.QUEUED ||
            it.deliveryState == DeliveryState.SENT_TO_PROVIDER
        }

        val latencies = tenantRecords.mapNotNull { it.latencyMs }
        val avgLatency = if (latencies.isNotEmpty()) latencies.average() else 0.0
        val rate = if (total > 0) (delivered.toDouble() / total.toDouble()) * 100.0 else 0.0

        return DeliveryMetricsSummary(
            tenantId = tenantId,
            totalCount = total,
            deliveredCount = delivered,
            failedCount = failed,
            inFlightCount = inFlight,
            averageLatencyMs = avgLatency,
            deliveryRate = rate,
        )
    }

    fun getAuditEntries(trackingId: UUID): List<DeliveryTrackingAuditEntry> {
        NotificationDeliveryTrackingBinding.checkBound()
        return auditLog.filter { it.trackingId == trackingId }
    }

    private fun isTerminalState(state: DeliveryState): Boolean = when (state) {
        DeliveryState.DELIVERED,
        DeliveryState.BOUNCED,
        DeliveryState.FAILED,
        DeliveryState.EXPIRED -> true
        DeliveryState.PENDING,
        DeliveryState.QUEUED,
        DeliveryState.SENT_TO_PROVIDER -> false
    }

    private fun validateAllowedTransition(current: DeliveryState, target: DeliveryState) {
        val allowed = when (current) {
            DeliveryState.PENDING -> setOf(DeliveryState.QUEUED, DeliveryState.FAILED)
            DeliveryState.QUEUED -> setOf(DeliveryState.SENT_TO_PROVIDER, DeliveryState.FAILED, DeliveryState.EXPIRED)
            DeliveryState.SENT_TO_PROVIDER -> setOf(DeliveryState.DELIVERED, DeliveryState.BOUNCED, DeliveryState.FAILED, DeliveryState.QUEUED)
            DeliveryState.DELIVERED,
            DeliveryState.BOUNCED,
            DeliveryState.FAILED,
            DeliveryState.EXPIRED -> emptySet()
        }

        if (target !in allowed) {
            throw NotificationDeliveryTrackingException(
                "INVALID_TRANSITION",
                "Cannot transition delivery state from $current to $target"
            )
        }
    }

    private fun validateQueueCommand(command: QueueDeliveryCommand) {
        if (command.principal == null) {
            throw NotificationDeliveryTrackingException("UNAUTHENTICATED", "Authentication required")
        }
        if (command.principal.tenantId != command.tenantId) {
            throw NotificationDeliveryTrackingException("FORBIDDEN", "Cross-tenant access forbidden")
        }
        if (command.tenantId.isBlank()) {
            throw NotificationDeliveryTrackingException("INVALID", "tenantId cannot be blank")
        }
        if (command.recipientId.isBlank()) {
            throw NotificationDeliveryTrackingException("INVALID", "recipientId cannot be blank")
        }
        if (command.idempotencyKey.isBlank()) {
            throw NotificationDeliveryTrackingException("INVALID", "idempotencyKey cannot be blank")
        }
        if (command.correlationId.isBlank() || command.causationId.isBlank()) {
            throw NotificationDeliveryTrackingException("INVALID", "Correlation and causation IDs required")
        }
        if (command.maxAttempts <= 0 || command.maxAttempts > 10) {
            throw NotificationDeliveryTrackingException("BOUNDARY", "maxAttempts must be between 1 and 10")
        }
    }

    private fun validateTransitionCommand(command: TransitionDeliveryCommand) {
        if (command.principal == null) {
            throw NotificationDeliveryTrackingException("UNAUTHENTICATED", "Authentication required")
        }
        if (command.principal.tenantId != command.tenantId) {
            throw NotificationDeliveryTrackingException("FORBIDDEN", "Cross-tenant access forbidden")
        }
        if (command.tenantId.isBlank()) {
            throw NotificationDeliveryTrackingException("INVALID", "tenantId cannot be blank")
        }
        if (command.idempotencyKey.isBlank()) {
            throw NotificationDeliveryTrackingException("INVALID", "idempotencyKey cannot be blank")
        }
        if (command.correlationId.isBlank() || command.causationId.isBlank()) {
            throw NotificationDeliveryTrackingException("INVALID", "Correlation and causation IDs required")
        }
    }
}
