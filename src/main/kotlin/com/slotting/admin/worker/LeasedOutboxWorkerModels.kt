package com.slotting.admin.worker

import com.slotting.admin.auth.AuditEvent
import com.slotting.admin.auth.AuthenticatedPrincipal
import java.time.Duration
import java.time.Instant
import java.util.UUID
import java.util.concurrent.ConcurrentHashMap

// =============================================================================
// Semantic Contract & Enums
// =============================================================================

const val LEASED_OUTBOX_WORKER_CONTRACT =
    "Bounded exponential retry; replay authorized/audited; lag/oldest-age health."

enum class WorkerOutboxStatus {
    PENDING,
    LEASED,
    PUBLISHED,
    QUARANTINED
}

enum class WorkerHealthStatus {
    HEALTHY,
    DEGRADED,
    CRITICAL
}

enum class WorkerDeliveryOutcome {
    PUBLISHED,
    RETRY_SCHEDULED,
    POISON_QUARANTINED,
    EXHAUSTED_QUARANTINED,
    LEASE_EXPIRED_SKIPPED
}

// =============================================================================
// Domain Records & Payloads
// =============================================================================

data class LeasedOutboxEventRecord(
    val eventId: UUID,
    val tenantId: String,
    val topic: String,
    val eventType: String,
    val payload: String,
    val correlationId: String,
    val causationId: String,
    val idempotencyKey: String,
    val status: WorkerOutboxStatus,
    val retryCount: Int = 0,
    val maxRetries: Int = 3,
    val nextRetryAt: Instant? = null,
    val lastError: String? = null,
    val leaseOwner: String? = null,
    val leaseExpiresAt: Instant? = null,
    val createdAt: Instant,
    val publishedAt: Instant? = null,
    val replayedAt: Instant? = null,
    val replayedBy: String? = null,
    val version: Long = 1L
)

data class ProcessedEventSummary(
    val eventId: UUID,
    val topic: String,
    val outcome: WorkerDeliveryOutcome,
    val retryCount: Int,
    val error: String? = null
)

// =============================================================================
// Commands & Queries
// =============================================================================

data class PollAndProcessOutboxCommand(
    val tenantId: String,
    val workerId: String,
    val batchSize: Int = 10,
    val leaseDurationSeconds: Long = 30L,
    val correlationId: String,
    val causationId: String
)

data class ReplayQuarantinedOutboxCommand(
    val principal: AuthenticatedPrincipal?,
    val tenantId: String,
    val eventId: UUID,
    val idempotencyKey: String,
    val correlationId: String,
    val causationId: String
)

data class GetOutboxWorkerHealthQuery(
    val tenantId: String
)

// =============================================================================
// Results
// =============================================================================

data class PollAndProcessResult(
    val resultId: UUID,
    val tenantId: String,
    val workerId: String,
    val polledCount: Int,
    val processedCount: Int,
    val publishedCount: Int,
    val retryCount: Int,
    val quarantinedCount: Int,
    val processedEvents: List<ProcessedEventSummary>,
    val serverTime: Instant,
    val evidenceReference: String,
    val hasFinancialAuthorityImpact: Boolean = false,
    val hasAndroidDbImpact: Boolean = false,
    val hasAndroidLifecycleClaim: Boolean = false,
    val semanticContract: String = LEASED_OUTBOX_WORKER_CONTRACT
)

data class ReplayOutboxResult(
    val resultId: UUID,
    val eventId: UUID,
    val tenantId: String,
    val status: WorkerOutboxStatus,
    val replayedBy: String,
    val replayedAt: Instant,
    val serverTime: Instant,
    val evidenceReference: String,
    val auditEvent: AuditEvent,
    val hasFinancialAuthorityImpact: Boolean = false,
    val hasAndroidDbImpact: Boolean = false,
    val hasAndroidLifecycleClaim: Boolean = false,
    val semanticContract: String = LEASED_OUTBOX_WORKER_CONTRACT
)

data class OutboxWorkerHealthReport(
    val tenantId: String,
    val status: WorkerHealthStatus,
    val pendingCount: Long,
    val activeLeasesCount: Long,
    val publishedCount: Long,
    val quarantinedCount: Long,
    val oldestPendingAgeSeconds: Long,
    val alerts: List<String>,
    val timestamp: Instant,
    val semanticContract: String = LEASED_OUTBOX_WORKER_CONTRACT
)

// =============================================================================
// Broker Sink & Alert Sink
// =============================================================================

interface WorkerOutboxBrokerSink {
    fun publish(event: LeasedOutboxEventRecord)
}

class FakeWorkerOutboxBrokerSink : WorkerOutboxBrokerSink {
    val publishedEvents = mutableListOf<LeasedOutboxEventRecord>()
    var shouldFail: Boolean = false
    var failurePredicate: ((LeasedOutboxEventRecord) -> Boolean)? = null

    @Synchronized
    override fun publish(event: LeasedOutboxEventRecord) {
        if (shouldFail || failurePredicate?.invoke(event) == true) {
            throw RuntimeException("Broker downstream connectivity failure 503")
        }
        publishedEvents.add(event)
    }
}

data class WorkerOutboxAlert(
    val alertId: UUID,
    val tenantId: String,
    val eventId: UUID?,
    val reason: String,
    val occurredAt: Instant
)

interface WorkerOutboxAlertSink {
    fun emitAlert(alert: WorkerOutboxAlert)
    fun getAlerts(): List<WorkerOutboxAlert>
}

class InMemoryWorkerOutboxAlertSink : WorkerOutboxAlertSink {
    private val alerts = mutableListOf<WorkerOutboxAlert>()

    @Synchronized
    override fun emitAlert(alert: WorkerOutboxAlert) {
        alerts.add(alert)
    }

    @Synchronized
    override fun getAlerts(): List<WorkerOutboxAlert> = alerts.toList()
}

// =============================================================================
// Store Interface & In-Memory Implementation
// =============================================================================

interface LeasedOutboxStore {
    fun stageEvent(event: LeasedOutboxEventRecord): LeasedOutboxEventRecord
    fun findById(tenantId: String, eventId: UUID): LeasedOutboxEventRecord?
    fun acquireLeases(tenantId: String, workerId: String, limit: Int, leaseDurationSeconds: Long, now: Instant): List<LeasedOutboxEventRecord>
    fun updateEvent(event: LeasedOutboxEventRecord): LeasedOutboxEventRecord
    fun getHealthMetrics(tenantId: String, now: Instant): OutboxWorkerHealthReport
    fun findReplayByIdempotency(tenantId: String, idempotencyKey: String): Pair<String, ReplayOutboxResult>?
    fun saveReplayIdempotency(tenantId: String, idempotencyKey: String, fingerprint: String, result: ReplayOutboxResult)
}

class InMemoryLeasedOutboxStore : LeasedOutboxStore {
    private val events = ConcurrentHashMap<UUID, LeasedOutboxEventRecord>()
    private val replayIdempotency = ConcurrentHashMap<String, Pair<String, ReplayOutboxResult>>()

    override fun stageEvent(event: LeasedOutboxEventRecord): LeasedOutboxEventRecord {
        events[event.eventId] = event
        return event
    }

    override fun findById(tenantId: String, eventId: UUID): LeasedOutboxEventRecord? {
        val event = events[eventId]
        return if (event?.tenantId == tenantId) event else null
    }

    @Synchronized
    override fun acquireLeases(
        tenantId: String,
        workerId: String,
        limit: Int,
        leaseDurationSeconds: Long,
        now: Instant
    ): List<LeasedOutboxEventRecord> {
        val eligible = events.values
            .filter { it.tenantId == tenantId }
            .filter { record ->
                val isPending = record.status == WorkerOutboxStatus.PENDING &&
                        (record.nextRetryAt == null || !record.nextRetryAt.isAfter(now))
                val isLeaseExpired = record.status == WorkerOutboxStatus.LEASED &&
                        record.leaseExpiresAt != null && record.leaseExpiresAt.isBefore(now)
                isPending || isLeaseExpired
            }
            .sortedBy { it.createdAt }
            .take(limit)

        val leasedBatch = mutableListOf<LeasedOutboxEventRecord>()
        for (record in eligible) {
            val leased = record.copy(
                status = WorkerOutboxStatus.LEASED,
                leaseOwner = workerId,
                leaseExpiresAt = now.plusSeconds(leaseDurationSeconds),
                version = record.version + 1
            )
            events[record.eventId] = leased
            leasedBatch.add(leased)
        }
        return leasedBatch
    }

    override fun updateEvent(event: LeasedOutboxEventRecord): LeasedOutboxEventRecord {
        events[event.eventId] = event
        return event
    }

    override fun getHealthMetrics(tenantId: String, now: Instant): OutboxWorkerHealthReport {
        val tenantEvents = events.values.filter { it.tenantId == tenantId }
        val pendingEvents = tenantEvents.filter { it.status == WorkerOutboxStatus.PENDING }
        val leasedEvents = tenantEvents.filter { it.status == WorkerOutboxStatus.LEASED && (it.leaseExpiresAt == null || it.leaseExpiresAt.isAfter(now)) }
        val publishedEvents = tenantEvents.filter { it.status == WorkerOutboxStatus.PUBLISHED }
        val quarantinedEvents = tenantEvents.filter { it.status == WorkerOutboxStatus.QUARANTINED }

        val activeLeasesCount = leasedEvents.size.toLong()
        val pendingCount = (pendingEvents.size + leasedEvents.size).toLong()
        val publishedCount = publishedEvents.size.toLong()
        val quarantinedCount = quarantinedEvents.size.toLong()

        val oldestPending = (pendingEvents + leasedEvents).minByOrNull { it.createdAt }
        val oldestPendingAgeSeconds = if (oldestPending != null) {
            Duration.between(oldestPending.createdAt, now).seconds
        } else {
            0L
        }

        val alerts = mutableListOf<String>()
        val healthStatus: WorkerHealthStatus = when {
            oldestPendingAgeSeconds > 300L || pendingCount > 500L || quarantinedCount > 10L -> {
                if (oldestPendingAgeSeconds > 300L) alerts.add("CRITICAL_LAG_OLDEST_AGE: ${oldestPendingAgeSeconds}s exceeds 300s")
                if (pendingCount > 500L) alerts.add("CRITICAL_LAG_QUEUE_DEPTH: $pendingCount exceeds 500")
                if (quarantinedCount > 10L) alerts.add("CRITICAL_DLQ_DEPTH: $quarantinedCount quarantined events")
                WorkerHealthStatus.CRITICAL
            }
            oldestPendingAgeSeconds > 60L || pendingCount > 50L || quarantinedCount > 0L -> {
                if (oldestPendingAgeSeconds > 60L) alerts.add("DEGRADED_LAG_OLDEST_AGE: ${oldestPendingAgeSeconds}s exceeds 60s")
                if (pendingCount > 50L) alerts.add("DEGRADED_LAG_QUEUE_DEPTH: $pendingCount exceeds 50")
                if (quarantinedCount > 0L) alerts.add("DEGRADED_DLQ_NONZERO: $quarantinedCount quarantined events")
                WorkerHealthStatus.DEGRADED
            }
            else -> WorkerHealthStatus.HEALTHY
        }

        return OutboxWorkerHealthReport(
            tenantId = tenantId,
            status = healthStatus,
            pendingCount = pendingCount,
            activeLeasesCount = activeLeasesCount,
            publishedCount = publishedCount,
            quarantinedCount = quarantinedCount,
            oldestPendingAgeSeconds = oldestPendingAgeSeconds,
            alerts = alerts,
            timestamp = now
        )
    }

    override fun findReplayByIdempotency(tenantId: String, idempotencyKey: String): Pair<String, ReplayOutboxResult>? {
        return replayIdempotency["$tenantId:$idempotencyKey"]
    }

    override fun saveReplayIdempotency(tenantId: String, idempotencyKey: String, fingerprint: String, result: ReplayOutboxResult) {
        replayIdempotency["$tenantId:$idempotencyKey"] = fingerprint to result
    }
}

// =============================================================================
// Observability
// =============================================================================

data class OutboxWorkerMetricEvent(
    val eventType: String, // "poll", "lease_acquired", "published", "retry_scheduled", "quarantined", "replayed", "health_check"
    val tenantId: String,
    val workerId: String?,
    val eventId: UUID?,
    val outcome: String,
    val correlationId: String? = null,
    val causationId: String? = null,
    val timestamp: Instant,
    val details: Map<String, Any?> = emptyMap()
)

interface OutboxWorkerObservability {
    fun recordMetric(event: OutboxWorkerMetricEvent)
    fun getMetrics(): List<OutboxWorkerMetricEvent>
}

class InMemoryOutboxWorkerObservability : OutboxWorkerObservability {
    private val metrics = mutableListOf<OutboxWorkerMetricEvent>()

    @Synchronized
    override fun recordMetric(event: OutboxWorkerMetricEvent) {
        metrics.add(event)
    }

    @Synchronized
    override fun getMetrics(): List<OutboxWorkerMetricEvent> = metrics.toList()
}

// =============================================================================
// Exceptions
// =============================================================================

class UnauthorizedWorkerActionException(message: String) : RuntimeException(message)
class StaleWorkerLeaseException(message: String) : RuntimeException(message)
class OutboxEventNotFoundException(message: String) : RuntimeException(message)
class OutboxWorkerConflictException(message: String) : RuntimeException(message)
class InvalidWorkerParametersException(message: String) : RuntimeException(message)
