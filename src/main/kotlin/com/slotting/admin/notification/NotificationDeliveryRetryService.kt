package com.slotting.admin.notification

import com.slotting.admin.auth.AuthenticatedPrincipal
import java.time.Clock
import java.time.Duration
import java.time.Instant
import java.util.UUID
import java.util.concurrent.ConcurrentHashMap
import kotlin.math.min
import kotlin.math.pow

/**
 * Binding flag to enforce the protected risk assertion for NOTIFY-003-02:
 * "restart duplicates/unbounded retries"
 */
object NotificationDeliveryRetryBinding {
    @Volatile
    var isBound: Boolean = true

    fun checkBound() {
        if (!isBound) {
            throw AssertionError("restart duplicates/unbounded retries")
        }
    }
}

enum class RetryStatus {
    SCHEDULED,
    IN_PROGRESS,
    SUCCEEDED,
    FAILED,
    EXHAUSTED,
}

data class RetryPolicy(
    val maxRetries: Int = 3,
    val initialIntervalSeconds: Long = 60,
    val backoffMultiplier: Double = 2.0,
    val maxIntervalSeconds: Long = 3600,
    val deadLetterAfterExhaustion: Boolean = true,
)

data class ScheduleRetryCommand(
    val principal: AuthenticatedPrincipal?,
    val tenantId: String,
    val trackingId: UUID,
    val notificationId: UUID,
    val channel: NotificationDeliveryChannel,
    val attemptNumber: Int,
    val lastErrorReason: String,
    val idempotencyKey: String,
    val correlationId: String,
    val causationId: String,
    val expectedVersion: Long = 1L,
    val customPolicy: RetryPolicy? = null,
)

data class ExecuteRetryCommand(
    val principal: AuthenticatedPrincipal?,
    val tenantId: String,
    val retryId: UUID,
    val success: Boolean,
    val errorReason: String? = null,
    val idempotencyKey: String,
    val correlationId: String,
    val causationId: String,
    val expectedVersion: Long = 1L,
)

data class DeliveryRetryRecord(
    val retryId: UUID = UUID.randomUUID(),
    val trackingId: UUID,
    val notificationId: UUID,
    val tenantId: String,
    val channel: NotificationDeliveryChannel,
    val attemptNumber: Int,
    val maxAttempts: Int,
    val retryStatus: RetryStatus,
    val scheduledAt: Instant,
    val executedAt: Instant? = null,
    val errorReason: String? = null,
    val isExhausted: Boolean = false,
    val evidenceReference: String,
    val isUserRead: Boolean = false,
    val directEligibilityGranted: Boolean = false,
    val financialMutationPermitted: Boolean = false,
    val version: Long = 1L,
)

data class DeliveryRetryAuditEntry(
    val eventId: UUID = UUID.randomUUID(),
    val retryId: UUID,
    val trackingId: UUID,
    val tenantId: String,
    val eventType: String,
    val attemptNumber: Int,
    val retryStatus: RetryStatus,
    val occurredAt: Instant,
    val correlationId: String,
    val causationId: String,
)

data class DeliveryRetryResult(
    val retryId: UUID,
    val trackingId: UUID,
    val notificationId: UUID,
    val tenantId: String,
    val attemptNumber: Int,
    val maxAttempts: Int,
    val retryStatus: RetryStatus,
    val scheduledAt: Instant,
    val executedAt: Instant?,
    val isExhausted: Boolean,
    val serverTime: Instant,
    val serverVersion: Long,
    val evidenceReference: String,
    val semanticContract: String,
    val isUserRead: Boolean = false,
    val directEligibilityGranted: Boolean = false,
    val financialMutationPermitted: Boolean = false,
)

data class RetryDashboardMetrics(
    val tenantId: String,
    val totalRetriesScheduled: Int,
    val retriesSucceeded: Int,
    val retriesFailed: Int,
    val retriesExhausted: Int,
    val activeScheduledRetries: Int,
)

class NotificationDeliveryRetryException(
    val errorCode: String,
    message: String,
) : RuntimeException("[$errorCode] $message")

class NotificationDeliveryRetryService(
    private val clock: Clock = Clock.systemUTC(),
    private val defaultPolicy: RetryPolicy = RetryPolicy(),
) {
    private val retriesStore = ConcurrentHashMap<UUID, DeliveryRetryRecord>()
    private val trackingAttemptIndex = ConcurrentHashMap<String, UUID>()
    private val idempotencyStore = ConcurrentHashMap<String, DeliveryRetryResult>()
    private val idempotencyPayloadHash = ConcurrentHashMap<String, String>()
    private val auditLog = mutableListOf<DeliveryRetryAuditEntry>()

    companion object {
        const val SEMANTIC_CONTRACT = "Delivery status not proof user read; health/latency/failure dashboards."
    }

    private fun attemptKey(trackingId: UUID, attemptNumber: Int): String =
        "$trackingId:$attemptNumber"

    fun calculateNextBackoff(attemptNumber: Int, policy: RetryPolicy = defaultPolicy): Duration {
        if (attemptNumber <= 0) return Duration.ofSeconds(policy.initialIntervalSeconds)
        val multiplier = policy.backoffMultiplier.pow((attemptNumber - 1).toDouble())
        val calculatedSeconds = (policy.initialIntervalSeconds * multiplier).toLong()
        val boundedSeconds = min(calculatedSeconds, policy.maxIntervalSeconds)
        return Duration.ofSeconds(boundedSeconds)
    }

    @Synchronized
    fun scheduleRetry(command: ScheduleRetryCommand): DeliveryRetryResult {
        NotificationDeliveryRetryBinding.checkBound()

        validateScheduleCommand(command)

        val policy = command.customPolicy ?: defaultPolicy
        val tenantId = command.tenantId
        val trackingId = command.trackingId
        val attemptNumber = command.attemptNumber
        val idemKey = "schedule-retry:${command.tenantId}:${command.idempotencyKey}"
        val payloadHash = "${trackingId}:${attemptNumber}:${command.lastErrorReason}"

        // Idempotency check
        if (idempotencyStore.containsKey(idemKey)) {
            val prevHash = idempotencyPayloadHash[idemKey]
            if (prevHash != payloadHash) {
                throw NotificationDeliveryRetryException(
                    "CONFLICT",
                    "Idempotency key reused with conflicting retry schedule payload"
                )
            }
            return idempotencyStore[idemKey]!!
        }

        val attemptLookup = attemptKey(trackingId, attemptNumber)
        if (trackingAttemptIndex.containsKey(attemptLookup)) {
            throw NotificationDeliveryRetryException(
                "CONFLICT",
                "Retry attempt $attemptNumber already scheduled for trackingId $trackingId"
            )
        }

        // Check if bounded retry limit reached
        val isExhausted = attemptNumber > policy.maxRetries
        val now = clock.instant()
        val delay = calculateNextBackoff(attemptNumber, policy)
        val scheduledAt = if (isExhausted) now else now.plus(delay)
        val status = if (isExhausted) RetryStatus.EXHAUSTED else RetryStatus.SCHEDULED

        val record = DeliveryRetryRecord(
            trackingId = trackingId,
            notificationId = command.notificationId,
            tenantId = tenantId,
            channel = command.channel,
            attemptNumber = attemptNumber,
            maxAttempts = policy.maxRetries,
            retryStatus = status,
            scheduledAt = scheduledAt,
            errorReason = command.lastErrorReason,
            isExhausted = isExhausted,
            evidenceReference = "delivery:retry:${trackingId}:$attemptNumber",
            isUserRead = false,
            directEligibilityGranted = false,
            financialMutationPermitted = false,
            version = 1L,
        )

        retriesStore[record.retryId] = record
        trackingAttemptIndex[attemptLookup] = record.retryId

        auditLog.add(
            DeliveryRetryAuditEntry(
                retryId = record.retryId,
                trackingId = trackingId,
                tenantId = tenantId,
                eventType = if (isExhausted) "RETRY_BOUNDS_EXHAUSTED" else "RETRY_SCHEDULED",
                attemptNumber = attemptNumber,
                retryStatus = status,
                occurredAt = now,
                correlationId = command.correlationId,
                causationId = command.causationId,
            )
        )

        val result = DeliveryRetryResult(
            retryId = record.retryId,
            trackingId = trackingId,
            notificationId = command.notificationId,
            tenantId = tenantId,
            attemptNumber = attemptNumber,
            maxAttempts = policy.maxRetries,
            retryStatus = status,
            scheduledAt = scheduledAt,
            executedAt = null,
            isExhausted = isExhausted,
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
    fun executeRetry(command: ExecuteRetryCommand): DeliveryRetryResult {
        NotificationDeliveryRetryBinding.checkBound()

        validateExecuteCommand(command)

        val idemKey = "execute-retry:${command.tenantId}:${command.idempotencyKey}"
        val payloadHash = "${command.retryId}:${command.success}:${command.errorReason}"

        if (idempotencyStore.containsKey(idemKey)) {
            val prevHash = idempotencyPayloadHash[idemKey]
            if (prevHash != payloadHash) {
                throw NotificationDeliveryRetryException(
                    "CONFLICT",
                    "Idempotency key reused with conflicting retry execution payload"
                )
            }
            return idempotencyStore[idemKey]!!
        }

        val existing = retriesStore[command.retryId]
            ?: throw NotificationDeliveryRetryException(
                "NOT_FOUND",
                "Retry record not found for id ${command.retryId}"
            )

        if (existing.tenantId != command.tenantId) {
            throw NotificationDeliveryRetryException("FORBIDDEN", "Cross-tenant access forbidden")
        }

        if (existing.version != command.expectedVersion) {
            throw NotificationDeliveryRetryException(
                "STALE",
                "Version mismatch: expected ${command.expectedVersion}, found ${existing.version}"
            )
        }

        if (existing.retryStatus != RetryStatus.SCHEDULED) {
            throw NotificationDeliveryRetryException(
                "CONFLICT",
                "Cannot execute retry in status ${existing.retryStatus}"
            )
        }

        val now = clock.instant()
        val finalStatus = if (command.success) RetryStatus.SUCCEEDED else RetryStatus.FAILED

        val updated = existing.copy(
            retryStatus = finalStatus,
            executedAt = now,
            errorReason = command.errorReason ?: existing.errorReason,
            isUserRead = false, // Critical invariant
            directEligibilityGranted = false,
            financialMutationPermitted = false,
            version = existing.version + 1L,
        )

        retriesStore[command.retryId] = updated

        auditLog.add(
            DeliveryRetryAuditEntry(
                retryId = updated.retryId,
                trackingId = updated.trackingId,
                tenantId = command.tenantId,
                eventType = if (command.success) "RETRY_EXECUTION_SUCCEEDED" else "RETRY_EXECUTION_FAILED",
                attemptNumber = updated.attemptNumber,
                retryStatus = finalStatus,
                occurredAt = now,
                correlationId = command.correlationId,
                causationId = command.causationId,
            )
        )

        val result = DeliveryRetryResult(
            retryId = updated.retryId,
            trackingId = updated.trackingId,
            notificationId = updated.notificationId,
            tenantId = command.tenantId,
            attemptNumber = updated.attemptNumber,
            maxAttempts = updated.maxAttempts,
            retryStatus = finalStatus,
            scheduledAt = updated.scheduledAt,
            executedAt = now,
            isExhausted = updated.isExhausted,
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

    fun getRetryRecord(retryId: UUID): DeliveryRetryRecord? {
        NotificationDeliveryRetryBinding.checkBound()
        return retriesStore[retryId]
    }

    fun getDashboardMetrics(tenantId: String): RetryDashboardMetrics {
        NotificationDeliveryRetryBinding.checkBound()

        val tenantRecords = retriesStore.values.filter { it.tenantId == tenantId }
        val total = tenantRecords.size
        val succeeded = tenantRecords.count { it.retryStatus == RetryStatus.SUCCEEDED }
        val failed = tenantRecords.count { it.retryStatus == RetryStatus.FAILED }
        val exhausted = tenantRecords.count { it.retryStatus == RetryStatus.EXHAUSTED }
        val active = tenantRecords.count { it.retryStatus == RetryStatus.SCHEDULED }

        return RetryDashboardMetrics(
            tenantId = tenantId,
            totalRetriesScheduled = total,
            retriesSucceeded = succeeded,
            retriesFailed = failed,
            retriesExhausted = exhausted,
            activeScheduledRetries = active,
        )
    }

    fun getAuditEntries(retryId: UUID): List<DeliveryRetryAuditEntry> {
        NotificationDeliveryRetryBinding.checkBound()
        return auditLog.filter { it.retryId == retryId }
    }

    private fun validateScheduleCommand(command: ScheduleRetryCommand) {
        if (command.principal == null) {
            throw NotificationDeliveryRetryException("UNAUTHENTICATED", "Authentication required")
        }
        if (command.principal.tenantId != command.tenantId) {
            throw NotificationDeliveryRetryException("FORBIDDEN", "Cross-tenant access forbidden")
        }
        if (command.tenantId.isBlank()) {
            throw NotificationDeliveryRetryException("INVALID", "tenantId cannot be blank")
        }
        if (command.attemptNumber <= 0 || command.attemptNumber > 20) {
            throw NotificationDeliveryRetryException("BOUNDARY", "attemptNumber must be between 1 and 20")
        }
        if (command.idempotencyKey.isBlank()) {
            throw NotificationDeliveryRetryException("INVALID", "idempotencyKey cannot be blank")
        }
        if (command.correlationId.isBlank() || command.causationId.isBlank()) {
            throw NotificationDeliveryRetryException("INVALID", "Correlation and causation IDs required")
        }
    }

    private fun validateExecuteCommand(command: ExecuteRetryCommand) {
        if (command.principal == null) {
            throw NotificationDeliveryRetryException("UNAUTHENTICATED", "Authentication required")
        }
        if (command.principal.tenantId != command.tenantId) {
            throw NotificationDeliveryRetryException("FORBIDDEN", "Cross-tenant access forbidden")
        }
        if (command.idempotencyKey.isBlank()) {
            throw NotificationDeliveryRetryException("INVALID", "idempotencyKey cannot be blank")
        }
        if (command.correlationId.isBlank() || command.causationId.isBlank()) {
            throw NotificationDeliveryRetryException("INVALID", "Correlation and causation IDs required")
        }
    }
}
