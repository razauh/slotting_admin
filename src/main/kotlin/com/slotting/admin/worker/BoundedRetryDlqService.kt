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
 * Authoritative service implementing WORKER-001-02: Operate bounded retry and dead-letter queues.
 *
 * Core invariant:
 * - Outcome contract: "Bounded exponential retry; replay authorized/audited; lag/oldest-age health."
 * - Protected risk: "crash/loss/poison/replay duplicate"
 * - Multi-tenant, authenticated, role-scoped queue inspection and operation.
 * - Operator-guided redelivery (quarantine -> redelivered) and discard (quarantine -> discarded) workflows.
 * - Idempotent, audited mutation boundaries with optimistic concurrency control.
 * - Queue depth and lag/oldest-age telemetry with actionable alerts.
 * - Zero financial mutation: cannot create financial authority or mutate balances/money.
 * - Untrusted Android layer: zero UI/lifecycle surface claimed.
 */
class BoundedRetryDlqService(
    private val store: BoundedRetryDlqStore,
    val retryPolicy: BoundedRetryPolicy = BoundedRetryPolicy(),
    private val alertSink: DlqAlertSink = InMemoryDlqAlertSink(),
    private val observability: DlqObservability = InMemoryDlqObservability(),
    private val clock: Clock = Clock.systemUTC()
) {

    private val allowedRoles = setOf(AdminRole.SUPPORT, AdminRole.AUDITOR, AdminRole.SUPER_ADMIN)

    private fun sha256(input: String): String {
        val bytes = MessageDigest.getInstance("SHA-256").digest(input.toByteArray(StandardCharsets.UTF_8))
        return bytes.joinToString("") { "%02x".format(it) }
    }

    private fun validateAdminPrincipal(principal: AuthenticatedPrincipal?, tenantId: String): AuthenticatedPrincipal {
        if (principal == null) {
            throw UnauthorizedDlqOperationException("Unauthenticated: principal is null")
        }
        if (principal.kind != PrincipalKind.ADMIN || principal.roles.none { it in allowedRoles }) {
            throw UnauthorizedDlqOperationException("Principal ${principal.id} is not authorized for DLQ operations")
        }
        if (principal.tenantId != tenantId) {
            throw UnauthorizedDlqOperationException("Cross-tenant DLQ operation forbidden: ${principal.tenantId} != $tenantId")
        }
        return principal
    }

    fun queryDlq(cmd: QueryDlqQueueCommand): DlqQueryResult {
        BoundedRetryDlqBinding.checkBound()
        validateAdminPrincipal(cmd.principal, cmd.tenantId)

        if (cmd.limit <= 0) throw InvalidDlqParametersException("limit must be positive: ${cmd.limit}")
        if (cmd.offset < 0) throw InvalidDlqParametersException("offset must not be negative: ${cmd.offset}")

        val now = clock.instant()
        val (page, total) = store.query(
            tenantId = cmd.tenantId,
            status = cmd.statusFilter,
            topic = cmd.topicFilter,
            limit = cmd.limit,
            offset = cmd.offset
        )

        observability.recordMetric(
            DlqMetricEvent(
                eventType = "dlq_query",
                tenantId = cmd.tenantId,
                operatorId = cmd.principal?.id,
                eventId = null,
                outcome = "SUCCESS",
                timestamp = now,
                details = mapOf("total" to total, "returned" to page.size)
            )
        )

        return DlqQueryResult(
            items = page,
            totalCount = total,
            limit = cmd.limit,
            offset = cmd.offset,
            serverTime = now,
            evidenceReference = "ev-dlq-query-${UUID.randomUUID()}"
        )
    }

    fun getDlqItemDetails(query: GetDlqItemDetailsQuery): DlqItemRecord {
        BoundedRetryDlqBinding.checkBound()
        validateAdminPrincipal(query.principal, query.tenantId)

        val item = store.findById(query.tenantId, query.eventId)
            ?: throw DlqEventNotFoundException("DLQ item not found: ${query.eventId}")

        observability.recordMetric(
            DlqMetricEvent(
                eventType = "dlq_inspect",
                tenantId = query.tenantId,
                operatorId = query.principal?.id,
                eventId = query.eventId,
                outcome = "SUCCESS",
                timestamp = clock.instant()
            )
        )

        return item
    }

    @Synchronized
    fun redeliver(cmd: RedeliverDlqEventCommand): DlqRedeliverResult {
        BoundedRetryDlqBinding.checkBound()
        val principal = validateAdminPrincipal(cmd.principal, cmd.tenantId)

        if (cmd.idempotencyKey.isBlank()) throw InvalidDlqParametersException("idempotencyKey must not be blank")
        if (cmd.correlationId.isBlank()) throw InvalidDlqParametersException("correlationId must not be blank")
        if (cmd.causationId.isBlank()) throw InvalidDlqParametersException("causationId must not be blank")

        val fp = sha256("${cmd.tenantId}:${cmd.eventId}:redeliver")
        store.findIdempotency(cmd.tenantId, cmd.idempotencyKey)?.let { (cachedFp, cachedResult) ->
            if (cachedFp == fp && cachedResult is DlqRedeliverResult) {
                observability.recordMetric(
                    DlqMetricEvent(
                        eventType = "dlq_redeliver_duplicate",
                        tenantId = cmd.tenantId,
                        operatorId = principal.id,
                        eventId = cmd.eventId,
                        outcome = "DUPLICATE_ACCEPTED",
                        correlationId = cmd.correlationId,
                        causationId = cmd.causationId,
                        timestamp = clock.instant()
                    )
                )
                return cachedResult
            } else {
                throw DlqOperationConflictException("Idempotency key reused with conflicting parameters")
            }
        }

        val item = store.findById(cmd.tenantId, cmd.eventId)
            ?: throw DlqEventNotFoundException("DLQ item not found: ${cmd.eventId}")

        if (cmd.expectedVersion != null && item.version != cmd.expectedVersion) {
            throw DlqStaleVersionException("Version mismatch: expected ${cmd.expectedVersion} but found ${item.version}")
        }

        if (item.status != DlqItemStatus.QUARANTINED) {
            throw DlqOperationConflictException("Cannot redeliver event ${cmd.eventId} in status ${item.status}, expected QUARANTINED")
        }

        val now = clock.instant()
        val updated = item.copy(
            status = DlqItemStatus.REDELIVERED,
            retryCount = 0,
            redeliveredAt = now,
            redeliveredBy = principal.id,
            version = item.version + 1
        )
        store.update(updated)

        val resultId = UUID.randomUUID()
        val audit = AuditEvent(
            eventId = UUID.randomUUID(),
            resultId = resultId,
            tenantId = cmd.tenantId,
            type = "OUTBOX_DLQ_EVENT_REDELIVERED",
            occurredAt = now,
            correlationId = cmd.correlationId,
            causationId = cmd.causationId
        )

        val result = DlqRedeliverResult(
            resultId = resultId,
            eventId = cmd.eventId,
            tenantId = cmd.tenantId,
            status = DlqItemStatus.REDELIVERED,
            replayedBy = principal.id,
            replayedAt = now,
            serverTime = now,
            evidenceReference = "ev-dlq-redeliver-$resultId",
            auditEvent = audit
        )

        store.saveIdempotency(cmd.tenantId, cmd.idempotencyKey, fp, result)

        observability.recordMetric(
            DlqMetricEvent(
                eventType = "dlq_redelivered",
                tenantId = cmd.tenantId,
                operatorId = principal.id,
                eventId = cmd.eventId,
                outcome = "REDELIVERED",
                correlationId = cmd.correlationId,
                causationId = cmd.causationId,
                timestamp = now
            )
        )

        return result
    }

    @Synchronized
    fun discard(cmd: DiscardDlqEventCommand): DlqDiscardResult {
        BoundedRetryDlqBinding.checkBound()
        val principal = validateAdminPrincipal(cmd.principal, cmd.tenantId)

        if (cmd.reasonCode.isBlank()) throw InvalidDlqParametersException("reasonCode must not be blank")
        if (cmd.operatorNotes.isBlank()) throw InvalidDlqParametersException("operatorNotes must not be blank")
        if (cmd.idempotencyKey.isBlank()) throw InvalidDlqParametersException("idempotencyKey must not be blank")
        if (cmd.correlationId.isBlank()) throw InvalidDlqParametersException("correlationId must not be blank")
        if (cmd.causationId.isBlank()) throw InvalidDlqParametersException("causationId must not be blank")

        val fp = sha256("${cmd.tenantId}:${cmd.eventId}:discard:${cmd.reasonCode.trim()}")
        store.findIdempotency(cmd.tenantId, cmd.idempotencyKey)?.let { (cachedFp, cachedResult) ->
            if (cachedFp == fp && cachedResult is DlqDiscardResult) {
                observability.recordMetric(
                    DlqMetricEvent(
                        eventType = "dlq_discard_duplicate",
                        tenantId = cmd.tenantId,
                        operatorId = principal.id,
                        eventId = cmd.eventId,
                        outcome = "DUPLICATE_ACCEPTED",
                        correlationId = cmd.correlationId,
                        causationId = cmd.causationId,
                        timestamp = clock.instant()
                    )
                )
                return cachedResult
            } else {
                throw DlqOperationConflictException("Idempotency key reused with conflicting parameters")
            }
        }

        val item = store.findById(cmd.tenantId, cmd.eventId)
            ?: throw DlqEventNotFoundException("DLQ item not found: ${cmd.eventId}")

        if (cmd.expectedVersion != null && item.version != cmd.expectedVersion) {
            throw DlqStaleVersionException("Version mismatch: expected ${cmd.expectedVersion} but found ${item.version}")
        }

        if (item.status != DlqItemStatus.QUARANTINED) {
            throw DlqOperationConflictException("Cannot discard event ${cmd.eventId} in status ${item.status}, expected QUARANTINED")
        }

        val now = clock.instant()
        val updated = item.copy(
            status = DlqItemStatus.DISCARDED,
            discardedAt = now,
            discardedBy = principal.id,
            discardReason = cmd.reasonCode.trim(),
            discardNotes = cmd.operatorNotes.trim(),
            version = item.version + 1
        )
        store.update(updated)

        val resultId = UUID.randomUUID()
        val audit = AuditEvent(
            eventId = UUID.randomUUID(),
            resultId = resultId,
            tenantId = cmd.tenantId,
            type = "OUTBOX_DLQ_EVENT_DISCARDED",
            occurredAt = now,
            correlationId = cmd.correlationId,
            causationId = cmd.causationId
        )

        val result = DlqDiscardResult(
            resultId = resultId,
            eventId = cmd.eventId,
            tenantId = cmd.tenantId,
            status = DlqItemStatus.DISCARDED,
            discardedBy = principal.id,
            discardedAt = now,
            reasonCode = cmd.reasonCode.trim(),
            operatorNotes = cmd.operatorNotes.trim(),
            serverTime = now,
            evidenceReference = "ev-dlq-discard-$resultId",
            auditEvent = audit
        )

        store.saveIdempotency(cmd.tenantId, cmd.idempotencyKey, fp, result)

        observability.recordMetric(
            DlqMetricEvent(
                eventType = "dlq_discarded",
                tenantId = cmd.tenantId,
                operatorId = principal.id,
                eventId = cmd.eventId,
                outcome = "DISCARDED",
                correlationId = cmd.correlationId,
                causationId = cmd.causationId,
                timestamp = now
            )
        )

        return result
    }

    fun getHealth(cmd: GetDlqHealthCommand): DlqQueueHealthReport {
        BoundedRetryDlqBinding.checkBound()
        validateAdminPrincipal(cmd.principal, cmd.tenantId)

        val now = clock.instant()
        val report = store.getHealthMetrics(cmd.tenantId, now)

        if (report.status != DlqHealthStatus.HEALTHY) {
            for (alertReason in report.alerts) {
                alertSink.emitAlert(
                    DlqAlert(
                        alertId = UUID.randomUUID(),
                        tenantId = cmd.tenantId,
                        eventId = null,
                        reason = alertReason,
                        occurredAt = now
                    )
                )
            }
        }

        observability.recordMetric(
            DlqMetricEvent(
                eventType = "dlq_health_checked",
                tenantId = cmd.tenantId,
                operatorId = cmd.principal?.id,
                eventId = null,
                outcome = report.status.name,
                timestamp = now,
                details = mapOf(
                    "quarantinedCount" to report.quarantinedCount,
                    "discardedCount" to report.discardedCount,
                    "oldestAgeSeconds" to report.oldestQuarantinedAgeSeconds
                )
            )
        )

        return report
    }
}
