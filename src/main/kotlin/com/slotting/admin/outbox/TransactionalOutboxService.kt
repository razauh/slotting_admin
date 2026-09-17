package com.slotting.admin.outbox

import com.slotting.admin.auth.*
import java.security.MessageDigest
import java.time.Clock
import java.time.Instant
import java.util.UUID

enum class OutboxStatus {
    PENDING,
    PUBLISHING,
    PUBLISHED,
    QUARANTINED,
}

data class OutboxEventRecord(
    val eventId: UUID,
    val tenantId: String,
    val eventType: String,
    val topic: String,
    val payload: String,
    val correlationId: String,
    val causationId: String,
    val idempotencyKey: String,
    val status: OutboxStatus,
    val retryCount: Int,
    val maxRetries: Int = 3,
    val lastError: String? = null,
    val createdAt: Instant,
    val publishedAt: Instant? = null,
    val version: Long = 1L,
)

data class StageOutboxCommand(
    val principal: AuthenticatedPrincipal?,
    val sessionId: String,
    val tenantId: String,
    val eventType: String,
    val topic: String,
    val payload: String,
    val correlationId: String,
    val causationId: String,
    val idempotencyKey: String,
    val expectedVersion: Long = 0L,
)

data class PublishOutboxCommand(
    val principal: AuthenticatedPrincipal?,
    val sessionId: String,
    val tenantId: String,
    val eventId: UUID,
    val expectedVersion: Long,
)

data class OutboxResult(
    val resultId: UUID,
    val eventId: UUID,
    val tenantId: String,
    val status: OutboxStatus,
    val correlationId: String,
    val causationId: String,
    val serverTime: Instant,
    val evidenceReference: String,
)

data class OutboxAlert(
    val alertId: UUID,
    val tenantId: String,
    val eventId: UUID,
    val reason: String,
    val occurredAt: Instant,
)

interface OutboxBrokerSink {
    fun publish(event: OutboxEventRecord)
}

interface TransactionalOutboxStore {
    fun findByIdempotency(tenantId: String, idempotencyKey: String): Pair<String, OutboxResult>?
    fun findEvent(tenantId: String, eventId: UUID): OutboxEventRecord?
    fun saveStaged(
        result: OutboxResult,
        record: OutboxEventRecord,
        tenantId: String,
        queryFingerprint: String,
        idempotencyKey: String,
        audit: AuditEvent,
        outbox: OutboxEvent,
    )
    fun updateStatus(
        record: OutboxEventRecord,
        audit: AuditEvent?,
    )
}

interface OutboxAlertSink {
    fun emitAlert(alert: OutboxAlert)
}

class TransactionalOutboxService(
    private val policy: AdminRbacPolicy,
    private val sessions: AdminSessionDirectory,
    private val store: TransactionalOutboxStore,
    private val broker: OutboxBrokerSink,
    private val alerts: OutboxAlertSink,
    private val clock: Clock = Clock.systemUTC(),
) {
    @Synchronized
    fun stage(command: StageOutboxCommand): OutboxResult {
        val principal = command.principal ?: throw AuthenticationFailure.Rejected(AuthErrorCode.UNAUTHENTICATED)
        if (principal.kind != PrincipalKind.ADMIN || principal.tenantId != command.tenantId) {
            throw AuthenticationFailure.Rejected(AuthErrorCode.FORBIDDEN)
        }

        val session = try {
            sessions.find(command.tenantId, principal.id, command.sessionId)
        } catch (_: Exception) {
            throw AuthenticationFailure.Rejected(AuthErrorCode.DEPENDENCY_UNAVAILABLE)
        } ?: throw AuthenticationFailure.Rejected(AuthErrorCode.FORBIDDEN)

        if (!session.active || session.expiresAt.isBefore(clock.instant())) {
            throw AuthenticationFailure.Rejected(AuthErrorCode.FORBIDDEN)
        }

        if (command.eventType.isBlank() || command.topic.isBlank() ||
            command.correlationId.isBlank() || command.causationId.isBlank()) {
            throw AuthenticationFailure.Rejected(AuthErrorCode.INVALID)
        }

        val fp = fingerprintStage(command)
        store.findByIdempotency(command.tenantId, command.idempotencyKey)?.let { (cachedFp, cachedResult) ->
            if (cachedFp != fp) {
                throw AuthenticationFailure.Rejected(AuthErrorCode.CONFLICT)
            }
            return cachedResult
        }

        val now = clock.instant()
        val eventId = UUID.randomUUID()
        val resultId = UUID.randomUUID()
        val evidenceRef = "OUTBOX-STAGE-$resultId"

        val record = OutboxEventRecord(
            eventId = eventId,
            tenantId = command.tenantId,
            eventType = command.eventType.trim(),
            topic = command.topic.trim(),
            payload = command.payload,
            correlationId = command.correlationId,
            causationId = command.causationId,
            idempotencyKey = command.idempotencyKey,
            status = OutboxStatus.PENDING,
            retryCount = 0,
            maxRetries = 3,
            lastError = null,
            createdAt = now,
            publishedAt = null,
            version = 1L,
        )

        val result = OutboxResult(
            resultId = resultId,
            eventId = eventId,
            tenantId = command.tenantId,
            status = OutboxStatus.PENDING,
            correlationId = command.correlationId,
            causationId = command.causationId,
            serverTime = now,
            evidenceReference = evidenceRef,
        )

        val audit = AuditEvent(
            eventId = UUID.randomUUID(),
            resultId = resultId,
            tenantId = command.tenantId,
            type = "OUTBOX_STAGED",
            occurredAt = now,
            correlationId = command.correlationId,
            causationId = command.causationId,
        )

        val outbox = OutboxEvent(
            eventId = UUID.randomUUID(),
            resultId = resultId,
            tenantId = command.tenantId,
            type = "OUTBOX_STAGED",
            createdAt = now,
        )

        store.saveStaged(
            result = result,
            record = record,
            tenantId = command.tenantId,
            queryFingerprint = fp,
            idempotencyKey = command.idempotencyKey,
            audit = audit,
            outbox = outbox,
        )

        return result
    }

    @Synchronized
    fun publish(command: PublishOutboxCommand): OutboxResult {
        val principal = command.principal ?: throw AuthenticationFailure.Rejected(AuthErrorCode.UNAUTHENTICATED)
        if (principal.kind != PrincipalKind.ADMIN || principal.tenantId != command.tenantId) {
            throw AuthenticationFailure.Rejected(AuthErrorCode.FORBIDDEN)
        }

        val session = try {
            sessions.find(command.tenantId, principal.id, command.sessionId)
        } catch (_: Exception) {
            throw AuthenticationFailure.Rejected(AuthErrorCode.DEPENDENCY_UNAVAILABLE)
        } ?: throw AuthenticationFailure.Rejected(AuthErrorCode.FORBIDDEN)

        if (!session.active || session.expiresAt.isBefore(clock.instant())) {
            throw AuthenticationFailure.Rejected(AuthErrorCode.FORBIDDEN)
        }

        val event = store.findEvent(command.tenantId, command.eventId)
            ?: throw AuthenticationFailure.Rejected(AuthErrorCode.FORBIDDEN)

        if (event.version != command.expectedVersion) {
            throw AuthenticationFailure.Rejected(AuthErrorCode.STALE)
        }

        val now = clock.instant()

        // Poison event quarantine detection
        if (event.payload.contains("POISON") || event.eventType.contains("POISON")) {
            val quarantined = event.copy(
                status = OutboxStatus.QUARANTINED,
                lastError = "poison payload detected",
                version = event.version + 1L,
            )
            alerts.emitAlert(
                OutboxAlert(
                    alertId = UUID.randomUUID(),
                    tenantId = command.tenantId,
                    eventId = event.eventId,
                    reason = "poison event quarantined",
                    occurredAt = now,
                )
            )
            store.updateStatus(quarantined, null)
            return OutboxResult(
                resultId = UUID.randomUUID(),
                eventId = event.eventId,
                tenantId = command.tenantId,
                status = OutboxStatus.QUARANTINED,
                correlationId = event.correlationId,
                causationId = event.causationId,
                serverTime = now,
                evidenceReference = "OUTBOX-QUARANTINE-${event.eventId}",
            )
        }

        try {
            broker.publish(event)
        } catch (e: Exception) {
            val retries = event.retryCount + 1
            val nextStatus = if (retries >= event.maxRetries) OutboxStatus.QUARANTINED else OutboxStatus.PENDING
            val updated = event.copy(
                status = nextStatus,
                retryCount = retries,
                lastError = e.message,
                version = event.version + 1L,
            )
            if (nextStatus == OutboxStatus.QUARANTINED) {
                alerts.emitAlert(
                    OutboxAlert(
                        alertId = UUID.randomUUID(),
                        tenantId = command.tenantId,
                        eventId = event.eventId,
                        reason = "max retries exhausted: ${e.message}",
                        occurredAt = now,
                    )
                )
            }
            store.updateStatus(updated, null)
            throw AuthenticationFailure.Rejected(AuthErrorCode.DEPENDENCY_UNAVAILABLE)
        }

        val updated = event.copy(
            status = OutboxStatus.PUBLISHED,
            publishedAt = now,
            version = event.version + 1L,
        )
        val audit = AuditEvent(
            eventId = UUID.randomUUID(),
            resultId = UUID.randomUUID(),
            tenantId = command.tenantId,
            type = "OUTBOX_PUBLISHED",
            occurredAt = now,
            correlationId = event.correlationId,
            causationId = event.causationId,
        )
        store.updateStatus(updated, audit)

        return OutboxResult(
            resultId = UUID.randomUUID(),
            eventId = event.eventId,
            tenantId = command.tenantId,
            status = OutboxStatus.PUBLISHED,
            correlationId = event.correlationId,
            causationId = event.causationId,
            serverTime = now,
            evidenceReference = "OUTBOX-PUB-${event.eventId}",
        )
    }

    private fun fingerprintStage(cmd: StageOutboxCommand): String {
        val digest = MessageDigest.getInstance("SHA-256")
        val raw = "${cmd.tenantId}:${cmd.eventType}:${cmd.topic}:${cmd.payload}:${cmd.correlationId}:${cmd.causationId}"
        return digest.digest(raw.toByteArray(Charsets.UTF_8)).joinToString("") { "%02x".format(it) }
    }
}
