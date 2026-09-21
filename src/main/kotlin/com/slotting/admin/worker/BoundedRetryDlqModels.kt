package com.slotting.admin.worker

import com.slotting.admin.auth.AuditEvent
import com.slotting.admin.auth.AuthenticatedPrincipal
import java.time.Duration
import java.time.Instant
import java.util.UUID
import java.util.concurrent.ConcurrentHashMap
import kotlin.math.min
import kotlin.math.pow

// =============================================================================
// Semantic Contract & Enums
// =============================================================================

const val BOUNDED_RETRY_DLQ_CONTRACT =
    "Bounded exponential retry; replay authorized/audited; lag/oldest-age health."

enum class DlqItemStatus {
    QUARANTINED,
    REDELIVERED,
    DISCARDED
}

enum class DlqHealthStatus {
    HEALTHY,
    DEGRADED,
    CRITICAL
}

enum class DlqDiscardReason {
    CORRUPTED_PAYLOAD,
    INVALID_SCHEMA,
    OBSOLETE_EVENT,
    MANUAL_PURGE,
    OTHER
}

// =============================================================================
// Bounded Exponential Retry Policy
// =============================================================================

data class BoundedRetryPolicy(
    val baseDelaySeconds: Long = 1L,
    val maxDelaySeconds: Long = 60L,
    val multiplier: Double = 2.0,
    val maxRetries: Int = 3
) {
    init {
        require(baseDelaySeconds > 0) { "baseDelaySeconds must be positive" }
        require(maxDelaySeconds >= baseDelaySeconds) { "maxDelaySeconds must be >= baseDelaySeconds" }
        require(multiplier >= 1.0) { "multiplier must be >= 1.0" }
        require(maxRetries > 0) { "maxRetries must be positive" }
    }

    fun calculateBackoff(attempt: Int): Duration {
        if (attempt <= 0) return Duration.ofSeconds(baseDelaySeconds)
        val computed = (baseDelaySeconds * (multiplier.pow((attempt - 1).toDouble()))).toLong()
        val bounded = min(computed, maxDelaySeconds)
        return Duration.ofSeconds(bounded)
    }

    fun isRetryable(attempt: Int, isPoison: Boolean = false): Boolean {
        if (isPoison) return false
        return attempt < maxRetries
    }
}

// =============================================================================
// Domain Records & Payloads
// =============================================================================

data class DlqItemRecord(
    val eventId: UUID,
    val tenantId: String,
    val topic: String,
    val eventType: String,
    val payload: String,
    val correlationId: String,
    val causationId: String,
    val status: DlqItemStatus,
    val retryCount: Int = 0,
    val maxRetries: Int = 3,
    val lastError: String? = null,
    val quarantinedAt: Instant,
    val redeliveredAt: Instant? = null,
    val redeliveredBy: String? = null,
    val discardedAt: Instant? = null,
    val discardedBy: String? = null,
    val discardReason: String? = null,
    val discardNotes: String? = null,
    val version: Long = 1L
)

// =============================================================================
// Commands & Queries
// =============================================================================

data class QueryDlqQueueCommand(
    val principal: AuthenticatedPrincipal?,
    val tenantId: String,
    val statusFilter: DlqItemStatus? = null,
    val topicFilter: String? = null,
    val limit: Int = 50,
    val offset: Int = 0
)

data class GetDlqItemDetailsQuery(
    val principal: AuthenticatedPrincipal?,
    val tenantId: String,
    val eventId: UUID
)

data class RedeliverDlqEventCommand(
    val principal: AuthenticatedPrincipal?,
    val tenantId: String,
    val eventId: UUID,
    val idempotencyKey: String,
    val correlationId: String,
    val causationId: String,
    val expectedVersion: Long? = null
)

data class DiscardDlqEventCommand(
    val principal: AuthenticatedPrincipal?,
    val tenantId: String,
    val eventId: UUID,
    val reasonCode: String,
    val operatorNotes: String,
    val idempotencyKey: String,
    val correlationId: String,
    val causationId: String,
    val expectedVersion: Long? = null
)

data class GetDlqHealthCommand(
    val principal: AuthenticatedPrincipal?,
    val tenantId: String
)

// =============================================================================
// Results
// =============================================================================

data class DlqQueryResult(
    val items: List<DlqItemRecord>,
    val totalCount: Long,
    val limit: Int,
    val offset: Int,
    val serverTime: Instant,
    val evidenceReference: String,
    val semanticContract: String = BOUNDED_RETRY_DLQ_CONTRACT
)

data class DlqRedeliverResult(
    val resultId: UUID,
    val eventId: UUID,
    val tenantId: String,
    val status: DlqItemStatus,
    val replayedBy: String,
    val replayedAt: Instant,
    val serverTime: Instant,
    val evidenceReference: String,
    val auditEvent: AuditEvent,
    val hasFinancialAuthorityImpact: Boolean = false,
    val hasAndroidDbImpact: Boolean = false,
    val hasAndroidLifecycleClaim: Boolean = false,
    val semanticContract: String = BOUNDED_RETRY_DLQ_CONTRACT
)

data class DlqDiscardResult(
    val resultId: UUID,
    val eventId: UUID,
    val tenantId: String,
    val status: DlqItemStatus,
    val discardedBy: String,
    val discardedAt: Instant,
    val reasonCode: String,
    val operatorNotes: String,
    val serverTime: Instant,
    val evidenceReference: String,
    val auditEvent: AuditEvent,
    val hasFinancialAuthorityImpact: Boolean = false,
    val hasAndroidDbImpact: Boolean = false,
    val hasAndroidLifecycleClaim: Boolean = false,
    val semanticContract: String = BOUNDED_RETRY_DLQ_CONTRACT
)

data class DlqQueueHealthReport(
    val tenantId: String,
    val status: DlqHealthStatus,
    val quarantinedCount: Long,
    val discardedCount: Long,
    val oldestQuarantinedAgeSeconds: Long,
    val alerts: List<String>,
    val timestamp: Instant,
    val hasFinancialAuthorityImpact: Boolean = false,
    val hasAndroidDbImpact: Boolean = false,
    val hasAndroidLifecycleClaim: Boolean = false,
    val semanticContract: String = BOUNDED_RETRY_DLQ_CONTRACT
)

// =============================================================================
// Alert Sink
// =============================================================================

data class DlqAlert(
    val alertId: UUID,
    val tenantId: String,
    val eventId: UUID?,
    val reason: String,
    val occurredAt: Instant
)

interface DlqAlertSink {
    fun emitAlert(alert: DlqAlert)
    fun getAlerts(): List<DlqAlert>
}

class InMemoryDlqAlertSink : DlqAlertSink {
    private val alerts = mutableListOf<DlqAlert>()

    @Synchronized
    override fun emitAlert(alert: DlqAlert) {
        alerts.add(alert)
    }

    @Synchronized
    override fun getAlerts(): List<DlqAlert> = alerts.toList()
}

// =============================================================================
// Observability
// =============================================================================

data class DlqMetricEvent(
    val eventType: String,
    val tenantId: String,
    val operatorId: String?,
    val eventId: UUID?,
    val outcome: String,
    val correlationId: String? = null,
    val causationId: String? = null,
    val timestamp: Instant,
    val details: Map<String, Any?> = emptyMap()
)

interface DlqObservability {
    fun recordMetric(event: DlqMetricEvent)
    fun getMetrics(): List<DlqMetricEvent>
}

class InMemoryDlqObservability : DlqObservability {
    private val metrics = mutableListOf<DlqMetricEvent>()

    @Synchronized
    override fun recordMetric(event: DlqMetricEvent) {
        metrics.add(event)
    }

    @Synchronized
    override fun getMetrics(): List<DlqMetricEvent> = metrics.toList()
}

// =============================================================================
// Store Interface & In-Memory Implementation
// =============================================================================

interface BoundedRetryDlqStore {
    fun save(record: DlqItemRecord): DlqItemRecord
    fun findById(tenantId: String, eventId: UUID): DlqItemRecord?
    fun query(tenantId: String, status: DlqItemStatus?, topic: String?, limit: Int, offset: Int): Pair<List<DlqItemRecord>, Long>
    fun update(record: DlqItemRecord): DlqItemRecord
    fun getHealthMetrics(tenantId: String, now: Instant): DlqQueueHealthReport
    fun findIdempotency(tenantId: String, idempotencyKey: String): Pair<String, Any>?
    fun saveIdempotency(tenantId: String, idempotencyKey: String, fingerprint: String, result: Any)
}

class InMemoryBoundedRetryDlqStore : BoundedRetryDlqStore {
    private val records = ConcurrentHashMap<UUID, DlqItemRecord>()
    private val idempotency = ConcurrentHashMap<String, Pair<String, Any>>()

    override fun save(record: DlqItemRecord): DlqItemRecord {
        records[record.eventId] = record
        return record
    }

    override fun findById(tenantId: String, eventId: UUID): DlqItemRecord? {
        val record = records[eventId]
        return if (record?.tenantId == tenantId) record else null
    }

    @Synchronized
    override fun query(
        tenantId: String,
        status: DlqItemStatus?,
        topic: String?,
        limit: Int,
        offset: Int
    ): Pair<List<DlqItemRecord>, Long> {
        val filtered = records.values
            .filter { it.tenantId == tenantId }
            .filter { status == null || it.status == status }
            .filter { topic == null || it.topic == topic }
            .sortedByDescending { it.quarantinedAt }

        val total = filtered.size.toLong()
        val page = filtered.drop(offset).take(limit)
        return page to total
    }

    override fun update(record: DlqItemRecord): DlqItemRecord {
        records[record.eventId] = record
        return record
    }

    override fun getHealthMetrics(tenantId: String, now: Instant): DlqQueueHealthReport {
        val tenantRecords = records.values.filter { it.tenantId == tenantId }
        val quarantined = tenantRecords.filter { it.status == DlqItemStatus.QUARANTINED }
        val discarded = tenantRecords.filter { it.status == DlqItemStatus.DISCARDED }

        val oldestQuarantined = quarantined.minByOrNull { it.quarantinedAt }
        val oldestAgeSeconds = if (oldestQuarantined != null) {
            Duration.between(oldestQuarantined.quarantinedAt, now).seconds
        } else {
            0L
        }

        val quarantinedCount = quarantined.size.toLong()
        val discardedCount = discarded.size.toLong()

        val alerts = mutableListOf<String>()
        val healthStatus: DlqHealthStatus = when {
            oldestAgeSeconds > 300L || quarantinedCount > 10L -> {
                if (oldestAgeSeconds > 300L) alerts.add("CRITICAL_DLQ_LAG_AGE: ${oldestAgeSeconds}s exceeds 300s")
                if (quarantinedCount > 10L) alerts.add("CRITICAL_DLQ_DEPTH: $quarantinedCount quarantined events exceeds 10")
                DlqHealthStatus.CRITICAL
            }
            oldestAgeSeconds > 60L || quarantinedCount > 0L -> {
                if (oldestAgeSeconds > 60L) alerts.add("DEGRADED_DLQ_LAG_AGE: ${oldestAgeSeconds}s exceeds 60s")
                if (quarantinedCount > 0L) alerts.add("DEGRADED_DLQ_DEPTH: $quarantinedCount quarantined events")
                DlqHealthStatus.DEGRADED
            }
            else -> DlqHealthStatus.HEALTHY
        }

        return DlqQueueHealthReport(
            tenantId = tenantId,
            status = healthStatus,
            quarantinedCount = quarantinedCount,
            discardedCount = discardedCount,
            oldestQuarantinedAgeSeconds = oldestAgeSeconds,
            alerts = alerts,
            timestamp = now
        )
    }

    override fun findIdempotency(tenantId: String, idempotencyKey: String): Pair<String, Any>? {
        return idempotency["$tenantId:$idempotencyKey"]
    }

    override fun saveIdempotency(tenantId: String, idempotencyKey: String, fingerprint: String, result: Any) {
        idempotency["$tenantId:$idempotencyKey"] = fingerprint to result
    }
}

// =============================================================================
// Exceptions
// =============================================================================

class UnauthorizedDlqOperationException(message: String) : RuntimeException(message)
class DlqEventNotFoundException(message: String) : RuntimeException(message)
class DlqOperationConflictException(message: String) : RuntimeException(message)
class DlqStaleVersionException(message: String) : RuntimeException(message)
class InvalidDlqParametersException(message: String) : RuntimeException(message)
