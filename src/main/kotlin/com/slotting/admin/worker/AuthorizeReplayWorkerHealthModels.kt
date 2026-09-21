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

const val WORKER_HEALTH_REPLAY_CONTRACT =
    "Bounded exponential retry; replay authorized/audited; lag/oldest-age health."

enum class ReplayAuthorizationStatus {
    AUTHORIZED,
    REJECTED,
    CONFLICT,
    STALE
}

enum class WorkerClusterHealthStatus {
    HEALTHY,
    DEGRADED,
    CRITICAL
}

// =============================================================================
// Domain Records & Commands
// =============================================================================

data class WorkerHeartbeatRecord(
    val workerId: String,
    val tenantId: String,
    val hostname: String,
    val lastHeartbeatAt: Instant,
    val activeLeaseCount: Int = 0,
    val status: String = "ACTIVE"
)

data class AuthorizeReplayCommand(
    val principal: AuthenticatedPrincipal?,
    val tenantId: String,
    val eventId: UUID,
    val justification: String,
    val idempotencyKey: String,
    val correlationId: String,
    val causationId: String,
    val expectedVersion: Long? = null
)

data class PublishWorkerHealthCommand(
    val principal: AuthenticatedPrincipal?,
    val tenantId: String,
    val correlationId: String,
    val causationId: String
)

data class RegisterWorkerHeartbeatCommand(
    val workerId: String,
    val tenantId: String,
    val hostname: String,
    val activeLeaseCount: Int = 0,
    val correlationId: String
)

// =============================================================================
// Results
// =============================================================================

data class AuthorizeReplayResult(
    val resultId: UUID,
    val eventId: UUID,
    val tenantId: String,
    val status: ReplayAuthorizationStatus,
    val authorizedBy: String,
    val authorizedAt: Instant,
    val justification: String,
    val serverTime: Instant,
    val evidenceReference: String,
    val auditEvent: AuditEvent,
    val hasFinancialAuthorityImpact: Boolean = false,
    val hasAndroidDbImpact: Boolean = false,
    val hasAndroidLifecycleClaim: Boolean = false,
    val semanticContract: String = WORKER_HEALTH_REPLAY_CONTRACT
)

data class PublishedWorkerHealthReport(
    val reportId: UUID,
    val tenantId: String,
    val clusterStatus: WorkerClusterHealthStatus,
    val activeWorkersCount: Int,
    val activeWorkers: List<WorkerHeartbeatRecord>,
    val pendingCount: Long,
    val activeLeasesCount: Long,
    val quarantinedCount: Long,
    val oldestPendingAgeSeconds: Long,
    val alerts: List<String>,
    val publishedAt: Instant,
    val evidenceReference: String,
    val hasFinancialAuthorityImpact: Boolean = false,
    val hasAndroidDbImpact: Boolean = false,
    val hasAndroidLifecycleClaim: Boolean = false,
    val semanticContract: String = WORKER_HEALTH_REPLAY_CONTRACT
)

// =============================================================================
// Publisher & Alert Sinks
// =============================================================================

interface WorkerHealthPublisherSink {
    fun publishReport(report: PublishedWorkerHealthReport)
    fun getPublishedReports(): List<PublishedWorkerHealthReport>
}

class InMemoryWorkerHealthPublisherSink : WorkerHealthPublisherSink {
    private val reports = mutableListOf<PublishedWorkerHealthReport>()

    @Synchronized
    override fun publishReport(report: PublishedWorkerHealthReport) {
        reports.add(report)
    }

    @Synchronized
    override fun getPublishedReports(): List<PublishedWorkerHealthReport> = reports.toList()
}

interface WorkerHealthAlertSink {
    fun emitAlert(alert: String, tenantId: String, timestamp: Instant)
    fun getAlerts(): List<String>
}

class InMemoryWorkerHealthAlertSink : WorkerHealthAlertSink {
    private val alerts = mutableListOf<String>()

    @Synchronized
    override fun emitAlert(alert: String, tenantId: String, timestamp: Instant) {
        alerts.add(alert)
    }

    @Synchronized
    override fun getAlerts(): List<String> = alerts.toList()
}

// =============================================================================
// Observability
// =============================================================================

interface WorkerReplayHealthObservability {
    fun recordEvent(
        eventType: String,
        tenantId: String,
        outcome: String,
        correlationId: String?,
        causationId: String?,
        timestamp: Instant,
        details: Map<String, Any?> = emptyMap()
    )
    fun getEvents(): List<Map<String, Any?>>
}

class InMemoryWorkerReplayHealthObservability : WorkerReplayHealthObservability {
    private val recordedEvents = mutableListOf<Map<String, Any?>>()

    @Synchronized
    override fun recordEvent(
        eventType: String,
        tenantId: String,
        outcome: String,
        correlationId: String?,
        causationId: String?,
        timestamp: Instant,
        details: Map<String, Any?>
    ) {
        recordedEvents.add(
            mapOf(
                "eventType" to eventType,
                "tenantId" to tenantId,
                "outcome" to outcome,
                "correlationId" to correlationId,
                "causationId" to causationId,
                "timestamp" to timestamp,
                "details" to details
            )
        )
    }

    @Synchronized
    override fun getEvents(): List<Map<String, Any?>> = recordedEvents.toList()
}

// =============================================================================
// Store Interface & In-Memory Implementation
// =============================================================================

interface AuthorizeReplayWorkerHealthStore {
    fun saveEvent(event: LeasedOutboxEventRecord): LeasedOutboxEventRecord
    fun findEvent(tenantId: String, eventId: UUID): LeasedOutboxEventRecord?
    fun updateEvent(event: LeasedOutboxEventRecord): LeasedOutboxEventRecord
    fun recordHeartbeat(heartbeat: WorkerHeartbeatRecord)
    fun getActiveWorkers(tenantId: String, cutoff: Instant): List<WorkerHeartbeatRecord>
    fun getQueueStats(tenantId: String, now: Instant): Triple<Long, Long, Long> // pending, leased, quarantined
    fun getOldestPendingAge(tenantId: String, now: Instant): Long
    fun findReplayIdempotency(tenantId: String, idempotencyKey: String): Pair<String, AuthorizeReplayResult>?
    fun saveReplayIdempotency(tenantId: String, idempotencyKey: String, fingerprint: String, result: AuthorizeReplayResult)
}

class InMemoryAuthorizeReplayWorkerHealthStore : AuthorizeReplayWorkerHealthStore {
    private val events = ConcurrentHashMap<UUID, LeasedOutboxEventRecord>()
    private val heartbeats = ConcurrentHashMap<String, WorkerHeartbeatRecord>()
    private val replayIdempotency = ConcurrentHashMap<String, Pair<String, AuthorizeReplayResult>>()

    override fun saveEvent(event: LeasedOutboxEventRecord): LeasedOutboxEventRecord {
        events[event.eventId] = event
        return event
    }

    override fun findEvent(tenantId: String, eventId: UUID): LeasedOutboxEventRecord? {
        val event = events[eventId]
        return if (event?.tenantId == tenantId) event else null
    }

    override fun updateEvent(event: LeasedOutboxEventRecord): LeasedOutboxEventRecord {
        events[event.eventId] = event
        return event
    }

    override fun recordHeartbeat(heartbeat: WorkerHeartbeatRecord) {
        heartbeats["${heartbeat.tenantId}:${heartbeat.workerId}"] = heartbeat
    }

    override fun getActiveWorkers(tenantId: String, cutoff: Instant): List<WorkerHeartbeatRecord> {
        return heartbeats.values
            .filter { it.tenantId == tenantId && !it.lastHeartbeatAt.isBefore(cutoff) }
            .sortedBy { it.workerId }
    }

    override fun getQueueStats(tenantId: String, now: Instant): Triple<Long, Long, Long> {
        val tenantEvents = events.values.filter { it.tenantId == tenantId }
        val pending = tenantEvents.count { it.status == WorkerOutboxStatus.PENDING }.toLong()
        val leased = tenantEvents.count {
            it.status == WorkerOutboxStatus.LEASED && (it.leaseExpiresAt == null || it.leaseExpiresAt.isAfter(now))
        }.toLong()
        val quarantined = tenantEvents.count { it.status == WorkerOutboxStatus.QUARANTINED }.toLong()
        return Triple(pending, leased, quarantined)
    }

    override fun getOldestPendingAge(tenantId: String, now: Instant): Long {
        val pending = events.values
            .filter { it.tenantId == tenantId && (it.status == WorkerOutboxStatus.PENDING || it.status == WorkerOutboxStatus.LEASED) }
            .minByOrNull { it.createdAt }
        return if (pending != null) {
            Duration.between(pending.createdAt, now).seconds
        } else {
            0L
        }
    }

    override fun findReplayIdempotency(tenantId: String, idempotencyKey: String): Pair<String, AuthorizeReplayResult>? {
        return replayIdempotency["$tenantId:$idempotencyKey"]
    }

    override fun saveReplayIdempotency(tenantId: String, idempotencyKey: String, fingerprint: String, result: AuthorizeReplayResult) {
        replayIdempotency["$tenantId:$idempotencyKey"] = fingerprint to result
    }
}

// =============================================================================
// Exceptions
// =============================================================================

class UnauthorizedReplayActionException(message: String) : RuntimeException(message)
class ReplayEventNotFoundException(message: String) : RuntimeException(message)
class ReplayConflictException(message: String) : RuntimeException(message)
class ReplayStaleVersionException(message: String) : RuntimeException(message)
class InvalidReplayParametersException(message: String) : RuntimeException(message)
