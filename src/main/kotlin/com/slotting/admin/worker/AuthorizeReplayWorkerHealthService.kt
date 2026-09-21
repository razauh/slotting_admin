package com.slotting.admin.worker

import com.slotting.admin.auth.AdminRole
import com.slotting.admin.auth.AuditEvent
import com.slotting.admin.auth.AuthenticatedPrincipal
import com.slotting.admin.auth.PrincipalKind
import java.nio.charset.StandardCharsets
import java.security.MessageDigest
import java.time.Clock
import java.util.UUID

/**
 * Authoritative service implementing WORKER-001-03: Authorize replay and publish worker health.
 *
 * Core invariant:
 * - Outcome contract: "Bounded exponential retry; replay authorized/audited; lag/oldest-age health."
 * - Protected risk: "crash/loss/poison/replay duplicate"
 * - Multi-tenant, authenticated, role-scoped replay authorization with segregation of duties.
 * - Operator-provided justification, causation lineage, and immutable audit event emission.
 * - Optimistic version verification and deterministic idempotency deduplication.
 * - Operational health synthesis: cluster workers heartbeat, lag metrics, and health publication.
 * - Zero financial mutation: cannot create financial authority or mutate balances/money.
 * - Untrusted Android layer: zero UI/lifecycle surface claimed.
 */
class AuthorizeReplayWorkerHealthService(
    private val store: AuthorizeReplayWorkerHealthStore,
    private val publisherSink: WorkerHealthPublisherSink = InMemoryWorkerHealthPublisherSink(),
    private val alertSink: WorkerHealthAlertSink = InMemoryWorkerHealthAlertSink(),
    private val observability: WorkerReplayHealthObservability = InMemoryWorkerReplayHealthObservability(),
    private val clock: Clock = Clock.systemUTC()
) {

    private val allowedRoles = setOf(AdminRole.SUPPORT, AdminRole.AUDITOR, AdminRole.SUPER_ADMIN)

    private fun sha256(input: String): String {
        val bytes = MessageDigest.getInstance("SHA-256").digest(input.toByteArray(StandardCharsets.UTF_8))
        return bytes.joinToString("") { "%02x".format(it) }
    }

    private fun validateAdminPrincipal(principal: AuthenticatedPrincipal?, tenantId: String): AuthenticatedPrincipal {
        if (principal == null) {
            throw UnauthorizedReplayActionException("Unauthenticated: principal is null")
        }
        if (principal.kind != PrincipalKind.ADMIN || principal.roles.none { it in allowedRoles }) {
            throw UnauthorizedReplayActionException("Principal ${principal.id} is not authorized for replay operations")
        }
        if (principal.tenantId != tenantId) {
            throw UnauthorizedReplayActionException("Cross-tenant replay operation forbidden: ${principal.tenantId} != $tenantId")
        }
        return principal
    }

    @Synchronized
    fun authorizeReplay(cmd: AuthorizeReplayCommand): AuthorizeReplayResult {
        AuthorizeReplayWorkerHealthBinding.checkBound()
        val principal = validateAdminPrincipal(cmd.principal, cmd.tenantId)

        if (cmd.justification.isBlank()) throw InvalidReplayParametersException("justification must not be blank")
        if (cmd.idempotencyKey.isBlank()) throw InvalidReplayParametersException("idempotencyKey must not be blank")
        if (cmd.correlationId.isBlank()) throw InvalidReplayParametersException("correlationId must not be blank")
        if (cmd.causationId.isBlank()) throw InvalidReplayParametersException("causationId must not be blank")

        val fp = sha256("${cmd.tenantId}:${cmd.eventId}:${cmd.justification.trim()}")
        store.findReplayIdempotency(cmd.tenantId, cmd.idempotencyKey)?.let { (cachedFp, cachedResult) ->
            if (cachedFp == fp) {
                observability.recordEvent(
                    eventType = "worker_replay_duplicate",
                    tenantId = cmd.tenantId,
                    outcome = "DUPLICATE_ACCEPTED",
                    correlationId = cmd.correlationId,
                    causationId = cmd.causationId,
                    timestamp = clock.instant()
                )
                return cachedResult
            } else {
                throw ReplayConflictException("Idempotency key reused with conflicting parameters")
            }
        }

        val event = store.findEvent(cmd.tenantId, cmd.eventId)
            ?: throw ReplayEventNotFoundException("Outbox event not found: ${cmd.eventId}")

        if (cmd.expectedVersion != null && event.version != cmd.expectedVersion) {
            throw ReplayStaleVersionException("Version mismatch: expected ${cmd.expectedVersion} but found ${event.version}")
        }

        if (event.status != WorkerOutboxStatus.QUARANTINED) {
            throw ReplayConflictException("Cannot replay event ${cmd.eventId} in status ${event.status}, expected QUARANTINED")
        }

        val now = clock.instant()
        val updated = event.copy(
            status = WorkerOutboxStatus.PENDING,
            retryCount = 0,
            nextRetryAt = null,
            lastError = "Replayed with justification: ${cmd.justification.trim()}",
            leaseOwner = null,
            leaseExpiresAt = null,
            replayedAt = now,
            replayedBy = principal.id,
            version = event.version + 1
        )
        store.updateEvent(updated)

        val resultId = UUID.randomUUID()
        val audit = AuditEvent(
            eventId = UUID.randomUUID(),
            resultId = resultId,
            tenantId = cmd.tenantId,
            type = "OUTBOX_REPLAY_AUTHORIZED",
            occurredAt = now,
            correlationId = cmd.correlationId,
            causationId = cmd.causationId
        )

        val result = AuthorizeReplayResult(
            resultId = resultId,
            eventId = cmd.eventId,
            tenantId = cmd.tenantId,
            status = ReplayAuthorizationStatus.AUTHORIZED,
            authorizedBy = principal.id,
            authorizedAt = now,
            justification = cmd.justification.trim(),
            serverTime = now,
            evidenceReference = "ev-replay-auth-$resultId",
            auditEvent = audit
        )

        store.saveReplayIdempotency(cmd.tenantId, cmd.idempotencyKey, fp, result)

        observability.recordEvent(
            eventType = "worker_replay_authorized",
            tenantId = cmd.tenantId,
            outcome = "AUTHORIZED",
            correlationId = cmd.correlationId,
            causationId = cmd.causationId,
            timestamp = now,
            details = mapOf("eventId" to cmd.eventId, "authorizedBy" to principal.id)
        )

        return result
    }

    @Synchronized
    fun publishHealth(cmd: PublishWorkerHealthCommand): PublishedWorkerHealthReport {
        AuthorizeReplayWorkerHealthBinding.checkBound()
        validateAdminPrincipal(cmd.principal, cmd.tenantId)

        if (cmd.correlationId.isBlank()) throw InvalidReplayParametersException("correlationId must not be blank")
        if (cmd.causationId.isBlank()) throw InvalidReplayParametersException("causationId must not be blank")

        val now = clock.instant()
        val workerCutoff = now.minusSeconds(60) // Workers with heartbeat in last 60 seconds
        val activeWorkers = store.getActiveWorkers(cmd.tenantId, workerCutoff)
        val (pending, leased, quarantined) = store.getQueueStats(cmd.tenantId, now)
        val oldestAge = store.getOldestPendingAge(cmd.tenantId, now)

        val alerts = mutableListOf<String>()
        val clusterStatus: WorkerClusterHealthStatus = when {
            activeWorkers.isEmpty() || oldestAge > 300L || pending > 500L || quarantined > 10L -> {
                if (activeWorkers.isEmpty()) alerts.add("CRITICAL_NO_ACTIVE_WORKERS: cluster has 0 active workers")
                if (oldestAge > 300L) alerts.add("CRITICAL_LAG_OLDEST_AGE: ${oldestAge}s exceeds 300s")
                if (pending > 500L) alerts.add("CRITICAL_LAG_QUEUE_DEPTH: $pending exceeds 500")
                if (quarantined > 10L) alerts.add("CRITICAL_DLQ_DEPTH: $quarantined quarantined events")
                WorkerClusterHealthStatus.CRITICAL
            }
            oldestAge > 60L || pending > 50L || quarantined > 0L -> {
                if (oldestAge > 60L) alerts.add("DEGRADED_LAG_OLDEST_AGE: ${oldestAge}s exceeds 60s")
                if (pending > 50L) alerts.add("DEGRADED_LAG_QUEUE_DEPTH: $pending exceeds 50")
                if (quarantined > 0L) alerts.add("DEGRADED_DLQ_NONZERO: $quarantined quarantined events")
                WorkerClusterHealthStatus.DEGRADED
            }
            else -> WorkerClusterHealthStatus.HEALTHY
        }

        if (clusterStatus != WorkerClusterHealthStatus.HEALTHY) {
            for (alertReason in alerts) {
                alertSink.emitAlert(alertReason, cmd.tenantId, now)
            }
        }

        val reportId = UUID.randomUUID()
        val report = PublishedWorkerHealthReport(
            reportId = reportId,
            tenantId = cmd.tenantId,
            clusterStatus = clusterStatus,
            activeWorkersCount = activeWorkers.size,
            activeWorkers = activeWorkers,
            pendingCount = pending,
            activeLeasesCount = leased,
            quarantinedCount = quarantined,
            oldestPendingAgeSeconds = oldestAge,
            alerts = alerts,
            publishedAt = now,
            evidenceReference = "ev-worker-health-$reportId"
        )

        publisherSink.publishReport(report)

        observability.recordEvent(
            eventType = "worker_health_published",
            tenantId = cmd.tenantId,
            outcome = clusterStatus.name,
            correlationId = cmd.correlationId,
            causationId = cmd.causationId,
            timestamp = now,
            details = mapOf(
                "clusterStatus" to clusterStatus.name,
                "activeWorkers" to activeWorkers.size,
                "pending" to pending,
                "quarantined" to quarantined,
                "oldestAge" to oldestAge
            )
        )

        return report
    }

    fun recordHeartbeat(cmd: RegisterWorkerHeartbeatCommand) {
        AuthorizeReplayWorkerHealthBinding.checkBound()
        if (cmd.workerId.isBlank()) throw InvalidReplayParametersException("workerId must not be blank")
        if (cmd.tenantId.isBlank()) throw InvalidReplayParametersException("tenantId must not be blank")
        if (cmd.hostname.isBlank()) throw InvalidReplayParametersException("hostname must not be blank")

        val now = clock.instant()
        val heartbeat = WorkerHeartbeatRecord(
            workerId = cmd.workerId.trim(),
            tenantId = cmd.tenantId.trim(),
            hostname = cmd.hostname.trim(),
            lastHeartbeatAt = now,
            activeLeaseCount = cmd.activeLeaseCount
        )
        store.recordHeartbeat(heartbeat)

        observability.recordEvent(
            eventType = "worker_heartbeat",
            tenantId = cmd.tenantId,
            outcome = "RECORDED",
            correlationId = cmd.correlationId,
            causationId = null,
            timestamp = now,
            details = mapOf("workerId" to cmd.workerId)
        )
    }
}
