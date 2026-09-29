package com.slotting.admin.outbox

import com.fasterxml.jackson.databind.JsonNode
import com.fasterxml.jackson.databind.ObjectMapper
import com.slotting.admin.auth.AuditEvent
import com.slotting.admin.worker.LeasedOutboxEventRecord
import com.slotting.admin.worker.LeasedOutboxStore
import com.slotting.admin.worker.OutboxEventNotFoundException
import com.slotting.admin.worker.OutboxWorkerConflictException
import com.slotting.admin.worker.ReplayOutboxResult
import com.slotting.admin.worker.StaleWorkerLeaseException
import com.slotting.admin.worker.WorkerOutboxStatus
import org.springframework.jdbc.core.JdbcTemplate
import org.springframework.stereotype.Repository
import org.springframework.transaction.annotation.Transactional
import java.nio.charset.StandardCharsets
import java.security.MessageDigest
import java.sql.ResultSet
import java.time.Instant
import java.util.UUID

data class DurableEventEnvelope(
    val eventId: UUID,
    val tenantId: String,
    val aggregateType: String,
    val aggregateId: String,
    val operationId: UUID,
    val eventType: String,
    val schemaVersion: Int,
    val occurredAt: Instant,
    val correlationId: String,
    val causationId: String,
    val redactedPayload: String,
    val payloadSha256: String,
)

object RedactedEventEnvelopeCodec {
    private val mapper = ObjectMapper()
    private val sensitiveKey = Regex("(?i)(password|secret|token|signature|credential|authorization|rawpayload|cvv|pan)")

    fun envelope(event: LeasedOutboxEventRecord): DurableEventEnvelope {
        require(event.payload.isNotBlank() && event.payload.trim() != "{}") {
            "outbox payload must contain a redacted forensic envelope"
        }
        val hash = sha256(event.payload)
        val root = mapper.createObjectNode()
        root.put("eventType", event.eventType)
        root.put("aggregateType", "OUTBOX_EVENT")
        root.put("aggregateId", event.eventId.toString())
        root.put("operationId", event.eventId.toString())
        root.put("payloadSha256", hash)
        root.set<JsonNode>("payload", redactPayload(event.payload, hash))
        return DurableEventEnvelope(
            eventId = event.eventId,
            tenantId = event.tenantId,
            aggregateType = "OUTBOX_EVENT",
            aggregateId = event.eventId.toString(),
            operationId = event.eventId,
            eventType = event.eventType,
            schemaVersion = 1,
            occurredAt = event.createdAt,
            correlationId = event.correlationId,
            causationId = event.causationId,
            redactedPayload = mapper.writeValueAsString(root),
            payloadSha256 = hash,
        )
    }

    private fun redactPayload(payload: String, hash: String): JsonNode {
        val parsed = runCatching { mapper.readTree(payload) }.getOrNull()
        if (parsed == null || !parsed.isObject) {
            return mapper.createObjectNode()
                .put("payloadType", "opaque")
                .put("payloadSha256", hash)
        }
        return redactNode(parsed)
    }

    private fun redactNode(node: JsonNode): JsonNode = when {
        node.isObject -> {
            val output = mapper.createObjectNode()
            node.fields().forEach { (key, value) ->
                output.set<JsonNode>(key, if (sensitiveKey.containsMatchIn(key)) {
                    mapper.nodeFactory.textNode("[REDACTED]")
                } else {
                    redactNode(value)
                })
            }
            output
        }
        node.isArray -> mapper.createArrayNode().also { output -> node.forEach { output.add(redactNode(it)) } }
        else -> node
    }

    fun sha256(value: String): String = sha256(value.toByteArray(StandardCharsets.UTF_8))

    private fun sha256(value: ByteArray): String =
        MessageDigest.getInstance("SHA-256").digest(value).joinToString("") { "%02x".format(it) }
}

@Repository
class JdbcLeasedOutboxStore(private val jdbc: JdbcTemplate) : LeasedOutboxStore {
    @Transactional
    override fun stageEvent(event: LeasedOutboxEventRecord): LeasedOutboxEventRecord {
        val envelope = RedactedEventEnvelopeCodec.envelope(event)
        jdbc.update(
            """
            insert into admin_event_envelope
                (event_id, tenant_id, aggregate_type, aggregate_id, operation_id, event_type,
                 schema_version, occurred_at, correlation_id, causation_id, redacted_payload,
                 payload_sha256, created_at)
            values (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, cast(? as jsonb), ?, ?)
            on conflict (event_id) do nothing
            """.trimIndent(),
            envelope.eventId, envelope.tenantId, envelope.aggregateType, envelope.aggregateId,
            envelope.operationId, envelope.eventType, envelope.schemaVersion, envelope.occurredAt,
            envelope.correlationId, envelope.causationId, envelope.redactedPayload,
            envelope.payloadSha256, event.createdAt,
        )
        jdbc.update(
            """
            insert into admin_outbox_delivery
                (event_id, tenant_id, topic, status, retry_count, max_retries, next_attempt_at, created_at, version)
            values (?, ?, ?, ?, ?, ?, ?, ?, ?)
            on conflict (event_id) do nothing
            """.trimIndent(),
            event.eventId, event.tenantId, event.topic, event.status.name, event.retryCount,
            event.maxRetries, event.nextRetryAt ?: event.createdAt, event.createdAt, event.version,
        )
        return findById(event.tenantId, event.eventId) ?: event
    }

    override fun findById(tenantId: String, eventId: UUID): LeasedOutboxEventRecord? = jdbc.query(
        """
        select e.event_id, e.tenant_id, e.event_type, d.topic, e.redacted_payload::text,
               e.correlation_id, e.causation_id, e.event_id::text, d.status, d.retry_count,
               d.max_retries, d.next_attempt_at, d.last_error, d.lease_owner, d.lease_expires_at,
               e.created_at, d.published_at, d.version
        from admin_event_envelope e join admin_outbox_delivery d on d.event_id = e.event_id
        where e.tenant_id = ? and e.event_id = ?
        """.trimIndent(), { rs, _ -> rs.toEvent() }, tenantId, eventId,
    ).firstOrNull()

    @Transactional
    override fun acquireLeases(
        tenantId: String,
        workerId: String,
        limit: Int,
        leaseDurationSeconds: Long,
        now: Instant,
    ): List<LeasedOutboxEventRecord> {
        val candidates = jdbc.query(
            """
            select e.event_id, e.tenant_id, e.event_type, d.topic, e.redacted_payload::text,
                   e.correlation_id, e.causation_id, e.event_id::text, d.status, d.retry_count,
                   d.max_retries, d.next_attempt_at, d.last_error, d.lease_owner, d.lease_expires_at,
                   e.created_at, d.published_at, d.version
            from admin_event_envelope e join admin_outbox_delivery d on d.event_id = e.event_id
            where e.tenant_id = ? and (
                (d.status = 'PENDING' and d.next_attempt_at <= ?)
                or (d.status = 'LEASED' and d.lease_expires_at < ?)
            )
            order by d.created_at, d.event_id
            limit ?
            for update of d skip locked
            """.trimIndent(), { rs, _ -> rs.toEvent() }, tenantId, now, now, limit,
        )
        return candidates.mapNotNull { candidate ->
            val leased = candidate.copy(
                status = WorkerOutboxStatus.LEASED,
                leaseOwner = workerId,
                leaseExpiresAt = now.plusSeconds(leaseDurationSeconds),
                version = candidate.version + 1,
            )
            val changed = jdbc.update(
                """
                update admin_outbox_delivery
                set status = 'LEASED', lease_owner = ?, lease_expires_at = ?, version = version + 1
                where event_id = ? and tenant_id = ? and version = ?
                  and ((status = 'PENDING' and next_attempt_at <= ?) or
                       (status = 'LEASED' and lease_expires_at < ?))
                """.trimIndent(),
                workerId, leased.leaseExpiresAt, candidate.eventId, tenantId, candidate.version, now, now,
            )
            if (changed == 1) {
                jdbc.update(
                    "update admin_delivery_attempt set status = 'EXPIRED', finished_at = ? where tenant_id = ? and event_id = ? and status = 'CLAIMED'",
                    now, tenantId, candidate.eventId,
                )
                jdbc.update(
                    "insert into admin_delivery_attempt(attempt_id, tenant_id, event_id, attempt_number, worker_id, status, started_at, correlation_id, causation_id) values (?, ?, ?, ?, ?, 'CLAIMED', ?, ?, ?)",
                    UUID.randomUUID(), tenantId, candidate.eventId, candidate.retryCount + 1, workerId, now, candidate.correlationId, candidate.causationId,
                )
                leased
            } else null
        }
    }

    @Transactional
    override fun updateEvent(event: LeasedOutboxEventRecord): LeasedOutboxEventRecord {
        val changed = jdbc.update(
            """
            update admin_outbox_delivery
            set status = ?, retry_count = ?, next_attempt_at = ?, last_error = ?,
                lease_owner = ?, lease_expires_at = ?, published_at = ?, version = ?
            where event_id = ? and tenant_id = ? and version = ? - 1
              and (lease_expires_at is null or lease_expires_at > now())
            """.trimIndent(),
            event.status.name, event.retryCount, event.nextRetryAt ?: event.createdAt, event.lastError,
            event.leaseOwner, event.leaseExpiresAt, event.publishedAt, event.version,
            event.eventId, event.tenantId, event.version,
        )
        if (changed != 1) throw StaleWorkerLeaseException("outbox event ${event.eventId} lease or version is stale")
        jdbc.update(
            """
            update admin_delivery_attempt
               set status = ?, finished_at = ?, error_type = ?, error_detail = ?
             where attempt_id = (
                 select attempt_id from admin_delivery_attempt
                  where tenant_id = ? and event_id = ? and status = 'CLAIMED'
                  order by started_at desc limit 1
             )
            """.trimIndent(),
            when (event.status) {
                WorkerOutboxStatus.PUBLISHED -> "ACKNOWLEDGED"
                WorkerOutboxStatus.QUARANTINED -> "QUARANTINED"
                else -> "FAILED"
            }, Instant.now(), event.lastError?.substringBefore(":") ?: null, event.lastError?.take(512),
            event.tenantId, event.eventId,
        )
        return event
    }

    override fun getHealthMetrics(tenantId: String, now: Instant) = JdbcWorkerHealthMetrics(jdbc).read(tenantId, now)

    override fun tenantsWithPendingWork(): List<String> = jdbc.queryForList(
        "select distinct tenant_id from admin_outbox_delivery where status in ('PENDING', 'LEASED')",
        String::class.java,
    )

    override fun findReplayByIdempotency(tenantId: String, idempotencyKey: String): Pair<String, ReplayOutboxResult>? = jdbc.query(
        "select fingerprint, result_id, event_id, status, replayed_by, replayed_at, evidence_reference, correlation_id, causation_id from admin_delivery_replay where tenant_id = ? and idempotency_key = ?",
        { rs, _ ->
            val resultId = rs.getObject("result_id", UUID::class.java)
            rs.getString("fingerprint") to ReplayOutboxResult(
                resultId = resultId,
                eventId = rs.getObject("event_id", UUID::class.java),
                tenantId = tenantId,
                status = WorkerOutboxStatus.valueOf(rs.getString("status")),
                replayedBy = rs.getString("replayed_by"),
                replayedAt = rs.getTimestamp("replayed_at").toInstant(),
                serverTime = rs.getTimestamp("replayed_at").toInstant(),
                evidenceReference = rs.getString("evidence_reference"),
                auditEvent = AuditEvent(UUID.randomUUID(), resultId, tenantId, "OUTBOX_WORKER_EVENT_REPLAYED", rs.getTimestamp("replayed_at").toInstant(), rs.getString("correlation_id"), rs.getString("causation_id")),
            )
        }, tenantId, idempotencyKey,
    ).firstOrNull()

    @Transactional
    override fun saveReplayIdempotency(tenantId: String, idempotencyKey: String, fingerprint: String, result: ReplayOutboxResult) {
        jdbc.update(
            """
            insert into admin_delivery_replay
                (tenant_id, idempotency_key, fingerprint, result_id, event_id, replayed_by, replayed_at,
                 status, evidence_reference, correlation_id, causation_id)
            values (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """.trimIndent(),
            tenantId, idempotencyKey, fingerprint, result.resultId, result.eventId, result.replayedBy,
            result.replayedAt, result.status.name, result.evidenceReference,
            result.auditEvent.correlationId, result.auditEvent.causationId,
        )
    }

    private fun ResultSet.toEvent(): LeasedOutboxEventRecord = LeasedOutboxEventRecord(
        eventId = getObject(1, UUID::class.java), tenantId = getString(2), eventType = getString(3),
        topic = getString(4), payload = getString(5), correlationId = getString(6), causationId = getString(7),
        idempotencyKey = getString(8), status = WorkerOutboxStatus.valueOf(getString(9)), retryCount = getInt(10),
        maxRetries = getInt(11), nextRetryAt = getTimestamp(12)?.toInstant(), lastError = getString(13),
        leaseOwner = getString(14), leaseExpiresAt = getTimestamp(15)?.toInstant(), createdAt = getTimestamp(16).toInstant(),
        publishedAt = getTimestamp(17)?.toInstant(), version = getLong(18),
    )
}

private class JdbcWorkerHealthMetrics(private val jdbc: JdbcTemplate) {
    fun read(tenantId: String, now: Instant) = com.slotting.admin.worker.OutboxWorkerHealthReport(
        tenantId = tenantId,
        status = com.slotting.admin.worker.WorkerHealthStatus.HEALTHY,
        pendingCount = jdbc.queryForObject("select count(*) from admin_outbox_delivery where tenant_id = ? and status in ('PENDING', 'LEASED')", Long::class.java, tenantId) ?: 0L,
        activeLeasesCount = jdbc.queryForObject("select count(*) from admin_outbox_delivery where tenant_id = ? and status = 'LEASED' and lease_expires_at > ?", Long::class.java, tenantId, now) ?: 0L,
        publishedCount = jdbc.queryForObject("select count(*) from admin_outbox_delivery where tenant_id = ? and status = 'PUBLISHED'", Long::class.java, tenantId) ?: 0L,
        quarantinedCount = jdbc.queryForObject("select count(*) from admin_outbox_delivery where tenant_id = ? and status = 'QUARANTINED'", Long::class.java, tenantId) ?: 0L,
        oldestPendingAgeSeconds = 0L,
        alerts = emptyList(),
        timestamp = now,
    )
}

data class DurableInboxClaim(
    val tenantId: String,
    val eventId: UUID,
    val consumerName: String,
    val domainEffectKey: String,
    val attemptCount: Int,
    val version: Long,
    val leaseOwner: String,
    val leaseExpiresAt: Instant,
)

@Repository
class JdbcDurableInboxStore(private val jdbc: JdbcTemplate) {
    @Transactional
    fun claim(tenantId: String, eventId: UUID, consumerName: String, workerId: String, leaseDurationSeconds: Long, now: Instant, domainEffectKey: String): DurableInboxClaim {
        jdbc.update(
            """
            insert into admin_inbox_consumer(tenant_id, event_id, consumer_name, status, attempt_count, domain_effect_key, version)
            values (?, ?, ?, 'RECEIVED', 0, ?, 1)
            on conflict (tenant_id, event_id, consumer_name) do nothing
            """.trimIndent(), tenantId, eventId, consumerName, domainEffectKey,
        )
        val current = jdbc.queryForObject(
            "select status, attempt_count, version, lease_expires_at from admin_inbox_consumer where tenant_id = ? and event_id = ? and consumer_name = ? for update",
            { rs, _ -> arrayOf(rs.getString(1), rs.getInt(2), rs.getLong(3), rs.getTimestamp(4)?.toInstant()) },
            tenantId, eventId, consumerName,
        ) ?: throw OutboxEventNotFoundException("inbox event $eventId not found")
        val status = current[0] as String
        val leaseExpiresAt = current[3] as Instant?
        if (status == "PROCESSED" || status == "QUARANTINED" ||
            (status == "PROCESSING" && leaseExpiresAt != null && leaseExpiresAt.isAfter(now))) {
            throw OutboxWorkerConflictException("inbox message is already claimed or finalized")
        }
        val currentVersion = current[2] as Long
        val changed = jdbc.update(
            """
            update admin_inbox_consumer
            set status = 'PROCESSING', attempt_count = attempt_count + 1, lease_owner = ?,
                lease_expires_at = ?, version = version + 1
            where tenant_id = ? and event_id = ? and consumer_name = ?
              and version = ? and (status in ('RECEIVED', 'FAILED') or (status = 'PROCESSING' and lease_expires_at < ?))
            """.trimIndent(), workerId, now.plusSeconds(leaseDurationSeconds), tenantId, eventId, consumerName,
            currentVersion, now,
        )
        if (changed != 1) throw OutboxWorkerConflictException("inbox message is already claimed or processed")
        return jdbc.queryForObject(
            "select tenant_id, event_id, consumer_name, domain_effect_key, attempt_count, version, lease_owner, lease_expires_at from admin_inbox_consumer where tenant_id = ? and event_id = ? and consumer_name = ?",
            { rs, _ -> DurableInboxClaim(rs.getString(1), rs.getObject(2, UUID::class.java), rs.getString(3), rs.getString(4), rs.getInt(5), rs.getLong(6), rs.getString(7), rs.getTimestamp(8).toInstant()) },
            tenantId, eventId, consumerName,
        )!!
    }

    @Transactional
    fun complete(claim: DurableInboxClaim, now: Instant) {
        val changed = jdbc.update(
            "update admin_inbox_consumer set status = 'PROCESSED', processed_at = ?, lease_owner = null, lease_expires_at = null, version = version + 1 where tenant_id = ? and event_id = ? and consumer_name = ? and version = ? and lease_owner = ? and lease_expires_at > now()",
            now, claim.tenantId, claim.eventId, claim.consumerName, claim.version, claim.leaseOwner,
        )
        if (changed != 1) throw StaleWorkerLeaseException("inbox claim ${claim.eventId} lease or version is stale")
    }

    @Transactional
    fun fail(claim: DurableInboxClaim, errorType: String, detail: String, quarantine: Boolean, now: Instant) {
        val status = if (quarantine) "QUARANTINED" else "FAILED"
        val changed = jdbc.update(
            "update admin_inbox_consumer set status = ?, last_error = ?, lease_owner = null, lease_expires_at = null, version = version + 1 where tenant_id = ? and event_id = ? and consumer_name = ? and version = ? and lease_owner = ? and lease_expires_at > now()",
            status, "$errorType: ${detail.take(480)}", claim.tenantId, claim.eventId, claim.consumerName, claim.version, claim.leaseOwner,
        )
        if (changed != 1) throw StaleWorkerLeaseException("inbox claim ${claim.eventId} lease or version is stale")
        if (quarantine) {
            jdbc.update(
                "insert into admin_delivery_dead_letter(dead_letter_id, tenant_id, event_id, consumer_name, reason, failure_detail, quarantined_at) values (?, ?, ?, ?, ?, ?, ?)",
                UUID.randomUUID(), claim.tenantId, claim.eventId, claim.consumerName, errorType, detail.take(512), now,
            )
        }
    }
}
