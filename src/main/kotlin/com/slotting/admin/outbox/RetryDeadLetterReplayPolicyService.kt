package com.slotting.admin.outbox

import com.slotting.admin.auth.*
import java.security.MessageDigest
import java.time.Clock
import java.time.Instant
import java.util.UUID

enum class DeadLetterReason {
    RETRY_EXHAUSTED,
    POISON_PAYLOAD,
    SCHEMA_VIOLATION,
    UNROUTABLE,
}

enum class PolicyDeliveryOutcome {
    PUBLISHED,
    RETRY_SCHEDULED,
    QUARANTINED,
    REPLAYED,
}

data class DeadLetterRecord(
    val deadLetterId: UUID,
    val eventId: UUID,
    val tenantId: String,
    val topic: String,
    val payload: String,
    val correlationId: String,
    val causationId: String,
    val reason: DeadLetterReason,
    val failureDetail: String,
    val retryCount: Int,
    val quarantinedAt: Instant,
    val replayedAt: Instant? = null,
    val replayedBy: String? = null,
    val version: Long = 1L,
)

data class DeliveryAttemptCommand(
    val principal: AuthenticatedPrincipal?,
    val sessionId: String,
    val tenantId: String,
    val eventId: UUID,
    val topic: String,
    val payload: String,
    val correlationId: String,
    val causationId: String,
    val idempotencyKey: String,
    val currentRetryCount: Int = 0,
    val maxRetries: Int = 3,
    val simulateTransientFailure: Boolean = false,
    val isPoisonPayload: Boolean = false,
    val expectedVersion: Long = 1L,
)

data class ReplayPolicyCommand(
    val principal: AuthenticatedPrincipal?,
    val sessionId: String,
    val tenantId: String,
    val deadLetterId: UUID,
    val idempotencyKey: String,
    val expectedVersion: Long,
)

data class PolicyResult(
    val resultId: UUID,
    val eventId: UUID,
    val tenantId: String,
    val outcome: PolicyDeliveryOutcome,
    val correlationId: String,
    val causationId: String,
    val retryCount: Int,
    val serverTime: Instant,
    val evidenceReference: String,
)

interface DeadLetterStore {
    fun findByIdempotency(tenantId: String, idempotencyKey: String): Pair<String, PolicyResult>?
    fun findDeadLetter(tenantId: String, deadLetterId: UUID): DeadLetterRecord?
    fun findByEventId(tenantId: String, eventId: UUID): DeadLetterRecord?
    fun saveQuarantined(
        record: DeadLetterRecord,
        result: PolicyResult,
        queryFingerprint: String,
        idempotencyKey: String,
        audit: AuditEvent,
        outbox: OutboxEvent,
    )
    fun saveReplayed(
        updatedRecord: DeadLetterRecord,
        result: PolicyResult,
        queryFingerprint: String,
        idempotencyKey: String,
        audit: AuditEvent,
        outbox: OutboxEvent,
    )
    fun recordSuccess(
        result: PolicyResult,
        queryFingerprint: String,
        idempotencyKey: String,
        audit: AuditEvent,
        outbox: OutboxEvent,
    )
}

class RetryDeadLetterReplayPolicyService(
    private val policy: AdminRbacPolicy,
    private val sessions: AdminSessionDirectory,
    private val store: DeadLetterStore,
    private val alerts: OutboxAlertSink,
    private val clock: Clock = Clock.systemUTC(),
) {
    @Synchronized
    fun executeDelivery(command: DeliveryAttemptCommand): PolicyResult {
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

        if (command.topic.isBlank() || command.correlationId.isBlank() ||
            command.causationId.isBlank() || command.currentRetryCount < 0) {
            throw AuthenticationFailure.Rejected(AuthErrorCode.INVALID)
        }

        val fp = fingerprintDelivery(command)
        store.findByIdempotency(command.tenantId, command.idempotencyKey)?.let { (cachedFp, cachedResult) ->
            if (cachedFp != fp) throw AuthenticationFailure.Rejected(AuthErrorCode.CONFLICT)
            return cachedResult
        }

        val now = clock.instant()
        val resultId = UUID.randomUUID()

        // 1. Poison payload detection
        if (command.isPoisonPayload || command.payload.contains("POISON")) {
            val dlRecord = DeadLetterRecord(
                deadLetterId = UUID.randomUUID(),
                eventId = command.eventId,
                tenantId = command.tenantId,
                topic = command.topic.trim(),
                payload = command.payload,
                correlationId = command.correlationId,
                causationId = command.causationId,
                reason = DeadLetterReason.POISON_PAYLOAD,
                failureDetail = "poison payload quarantined",
                retryCount = command.currentRetryCount,
                quarantinedAt = now,
                version = 1L,
            )
            alerts.emitAlert(
                OutboxAlert(
                    alertId = UUID.randomUUID(),
                    tenantId = command.tenantId,
                    eventId = command.eventId,
                    reason = "poison payload quarantined",
                    occurredAt = now,
                )
            )
            val result = PolicyResult(
                resultId = resultId,
                eventId = command.eventId,
                tenantId = command.tenantId,
                outcome = PolicyDeliveryOutcome.QUARANTINED,
                correlationId = command.correlationId,
                causationId = command.causationId,
                retryCount = command.currentRetryCount,
                serverTime = now,
                evidenceReference = "POLICY-QUARANTINE-$resultId",
            )
            val audit = AuditEvent(
                eventId = UUID.randomUUID(),
                resultId = resultId,
                tenantId = command.tenantId,
                type = "OUTBOX_POLICY_POISON_QUARANTINED",
                occurredAt = now,
                correlationId = command.correlationId,
                causationId = command.causationId,
            )
            val outbox = OutboxEvent(
                eventId = UUID.randomUUID(),
                resultId = resultId,
                tenantId = command.tenantId,
                type = "OUTBOX_POLICY_POISON_QUARANTINED",
                createdAt = now,
            )
            store.saveQuarantined(dlRecord, result, fp, command.idempotencyKey, audit, outbox)
            return result
        }

        // 2. Transient failure handling
        if (command.simulateTransientFailure) {
            val nextRetryCount = command.currentRetryCount + 1
            if (nextRetryCount >= command.maxRetries) {
                // Retry limit exhausted -> Dead Letter quarantine
                val dlRecord = DeadLetterRecord(
                    deadLetterId = UUID.randomUUID(),
                    eventId = command.eventId,
                    tenantId = command.tenantId,
                    topic = command.topic.trim(),
                    payload = command.payload,
                    correlationId = command.correlationId,
                    causationId = command.causationId,
                    reason = DeadLetterReason.RETRY_EXHAUSTED,
                    failureDetail = "max retries exhausted: ${command.maxRetries}",
                    retryCount = nextRetryCount,
                    quarantinedAt = now,
                    version = 1L,
                )
                alerts.emitAlert(
                    OutboxAlert(
                        alertId = UUID.randomUUID(),
                        tenantId = command.tenantId,
                        eventId = command.eventId,
                        reason = "retry limit exhausted: ${command.maxRetries}",
                        occurredAt = now,
                    )
                )
                val result = PolicyResult(
                    resultId = resultId,
                    eventId = command.eventId,
                    tenantId = command.tenantId,
                    outcome = PolicyDeliveryOutcome.QUARANTINED,
                    correlationId = command.correlationId,
                    causationId = command.causationId,
                    retryCount = nextRetryCount,
                    serverTime = now,
                    evidenceReference = "POLICY-EXHAUST-$resultId",
                )
                val audit = AuditEvent(
                    eventId = UUID.randomUUID(),
                    resultId = resultId,
                    tenantId = command.tenantId,
                    type = "OUTBOX_POLICY_EXHAUSTED_QUARANTINED",
                    occurredAt = now,
                    correlationId = command.correlationId,
                    causationId = command.causationId,
                )
                val outbox = OutboxEvent(
                    eventId = UUID.randomUUID(),
                    resultId = resultId,
                    tenantId = command.tenantId,
                    type = "OUTBOX_POLICY_EXHAUSTED_QUARANTINED",
                    createdAt = now,
                )
                store.saveQuarantined(dlRecord, result, fp, command.idempotencyKey, audit, outbox)
                return result
            } else {
                // Retry scheduled
                val result = PolicyResult(
                    resultId = resultId,
                    eventId = command.eventId,
                    tenantId = command.tenantId,
                    outcome = PolicyDeliveryOutcome.RETRY_SCHEDULED,
                    correlationId = command.correlationId,
                    causationId = command.causationId,
                    retryCount = nextRetryCount,
                    serverTime = now,
                    evidenceReference = "POLICY-RETRY-$resultId",
                )
                val audit = AuditEvent(
                    eventId = UUID.randomUUID(),
                    resultId = resultId,
                    tenantId = command.tenantId,
                    type = "OUTBOX_POLICY_RETRY_SCHEDULED",
                    occurredAt = now,
                    correlationId = command.correlationId,
                    causationId = command.causationId,
                )
                val outbox = OutboxEvent(
                    eventId = UUID.randomUUID(),
                    resultId = resultId,
                    tenantId = command.tenantId,
                    type = "OUTBOX_POLICY_RETRY_SCHEDULED",
                    createdAt = now,
                )
                store.recordSuccess(result, fp, command.idempotencyKey, audit, outbox)
                return result
            }
        }

        // 3. Successful delivery
        val result = PolicyResult(
            resultId = resultId,
            eventId = command.eventId,
            tenantId = command.tenantId,
            outcome = PolicyDeliveryOutcome.PUBLISHED,
            correlationId = command.correlationId,
            causationId = command.causationId,
            retryCount = command.currentRetryCount,
            serverTime = now,
            evidenceReference = "POLICY-PUB-$resultId",
        )
        val audit = AuditEvent(
            eventId = UUID.randomUUID(),
            resultId = resultId,
            tenantId = command.tenantId,
            type = "OUTBOX_POLICY_PUBLISHED",
            occurredAt = now,
            correlationId = command.correlationId,
            causationId = command.causationId,
        )
        val outbox = OutboxEvent(
            eventId = UUID.randomUUID(),
            resultId = resultId,
            tenantId = command.tenantId,
            type = "OUTBOX_POLICY_PUBLISHED",
            createdAt = now,
        )
        store.recordSuccess(result, fp, command.idempotencyKey, audit, outbox)
        return result
    }

    @Synchronized
    fun replayDeadLetter(command: ReplayPolicyCommand): PolicyResult {
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

        val fp = fingerprintReplay(command)
        store.findByIdempotency(command.tenantId, command.idempotencyKey)?.let { (cachedFp, cachedResult) ->
            if (cachedFp != fp) throw AuthenticationFailure.Rejected(AuthErrorCode.CONFLICT)
            return cachedResult
        }

        val dl = store.findDeadLetter(command.tenantId, command.deadLetterId)
            ?: throw AuthenticationFailure.Rejected(AuthErrorCode.FORBIDDEN)

        if (dl.version != command.expectedVersion) {
            throw AuthenticationFailure.Rejected(AuthErrorCode.STALE)
        }

        val now = clock.instant()
        val resultId = UUID.randomUUID()
        val updatedRecord = dl.copy(
            replayedAt = now,
            replayedBy = principal.id,
            version = dl.version + 1L,
        )

        // Replay strictly preserves causation
        val result = PolicyResult(
            resultId = resultId,
            eventId = dl.eventId,
            tenantId = command.tenantId,
            outcome = PolicyDeliveryOutcome.REPLAYED,
            correlationId = dl.correlationId,
            causationId = dl.causationId,
            retryCount = dl.retryCount,
            serverTime = now,
            evidenceReference = "POLICY-REPLAY-$resultId",
        )
        val audit = AuditEvent(
            eventId = UUID.randomUUID(),
            resultId = resultId,
            tenantId = command.tenantId,
            type = "OUTBOX_POLICY_REPLAYED",
            occurredAt = now,
            correlationId = dl.correlationId,
            causationId = dl.causationId,
        )
        val outbox = OutboxEvent(
            eventId = UUID.randomUUID(),
            resultId = resultId,
            tenantId = command.tenantId,
            type = "OUTBOX_POLICY_REPLAYED",
            createdAt = now,
        )

        store.saveReplayed(updatedRecord, result, fp, command.idempotencyKey, audit, outbox)
        return result
    }

    private fun fingerprintDelivery(cmd: DeliveryAttemptCommand): String {
        val digest = MessageDigest.getInstance("SHA-256")
        val raw = "${cmd.tenantId}:${cmd.eventId}:${cmd.topic}:${cmd.payload}:${cmd.currentRetryCount}:${cmd.simulateTransientFailure}:${cmd.isPoisonPayload}"
        return digest.digest(raw.toByteArray(Charsets.UTF_8)).joinToString("") { "%02x".format(it) }
    }

    private fun fingerprintReplay(cmd: ReplayPolicyCommand): String {
        val digest = MessageDigest.getInstance("SHA-256")
        val raw = "${cmd.tenantId}:${cmd.deadLetterId}:${cmd.expectedVersion}"
        return digest.digest(raw.toByteArray(Charsets.UTF_8)).joinToString("") { "%02x".format(it) }
    }
}
