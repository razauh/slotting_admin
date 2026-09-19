package com.slotting.admin.gameprovider

import com.slotting.admin.auth.AuditEvent
import com.slotting.admin.auth.AuthErrorCode
import com.slotting.admin.auth.AuthenticationFailure
import com.slotting.admin.auth.OutboxEvent
import java.nio.charset.StandardCharsets
import java.security.MessageDigest
import java.time.Clock
import java.time.Instant
import java.util.UUID
import java.util.concurrent.ConcurrentHashMap

/**
 * Gate enforcing GAME-008-02: Deduplicate casino callbacks in a durable inbox.
 * Protected risk: "spoof/duplicate/stale payload"
 * Semantic contract: "Bad events no mutation and alert; response/retry contract provider-specific."
 */
object CasinoDurableInboxBinding {
    var isBound: Boolean = false

    fun checkBound() {
        if (!isBound) {
            throw AssertionError("spoof/duplicate/stale payload")
        }
    }
}

enum class InboxMessageStatus {
    RECEIVED,
    PROCESSING,
    PROCESSED,
    FAILED,
    DEAD_LETTER,
}

data class InboxCallbackMessage(
    val messageId: UUID,
    val tenantId: String,
    val providerId: String,
    val externalMessageId: String,
    val externalRoundId: String,
    val externalTransactionId: String,
    val idempotencyKey: String,
    val fingerprint: String,
    val payload: String,
    var status: InboxMessageStatus,
    val receivedAt: Instant,
    var processedAt: Instant?,
    var retryCount: Int = 0,
    val maxRetries: Int = 3,
    var lastError: String? = null,
    var responseBody: String? = null,
    var httpStatusCode: Int? = null,
    val evidenceReference: String,
    val correlationId: String,
    val causationId: String,
    var version: Long = 1L,
)

data class ReceiveCallbackCommand(
    val tenantId: String,
    val providerId: String,
    val protocol: CallbackProviderProtocol = CallbackProviderProtocol.GENERIC_HMAC,
    val externalMessageId: String,
    val externalRoundId: String,
    val externalTransactionId: String,
    val rawPayload: String,
    val idempotencyKey: String,
    val correlationId: String,
    val causationId: String,
    val expectedVersion: Long = 1L,
)

data class InboxProcessingResult(
    val messageId: UUID,
    val tenantId: String,
    val providerId: String,
    val status: InboxMessageStatus,
    val isDuplicate: Boolean,
    val response: ProviderCallbackResponse,
    val evidenceReference: String,
    val processedAt: Instant,
)

fun interface InboxPayloadHandler {
    fun handle(tenantId: String, providerId: String, payload: String): ProviderCallbackResponse
}

interface CasinoInboxAlertSink {
    fun sendAlert(tenantId: String, severity: String, alertType: String, detail: String)
}

class InMemoryCasinoInboxAlertSink : CasinoInboxAlertSink {
    val alerts = mutableListOf<String>()

    @Synchronized
    override fun sendAlert(tenantId: String, severity: String, alertType: String, detail: String) {
        alerts.add("$tenantId:$severity:$alertType:$detail")
    }
}

interface CasinoDurableInboxStore {
    fun findMessageById(tenantId: String, messageId: UUID): InboxCallbackMessage?
    fun findMessageByExternalId(tenantId: String, providerId: String, externalMessageId: String): InboxCallbackMessage?
    fun findMessageByIdempotency(tenantId: String, idempotencyKey: String): InboxCallbackMessage?
    fun saveMessage(
        message: InboxCallbackMessage,
        audit: AuditEvent,
        outbox: OutboxEvent,
    )
    fun updateMessage(
        message: InboxCallbackMessage,
        audit: AuditEvent,
        outbox: OutboxEvent,
    )
    fun listPendingMessages(tenantId: String): List<InboxCallbackMessage>
    fun listDeadLetterMessages(tenantId: String): List<InboxCallbackMessage>
}

class InMemoryCasinoDurableInboxStore : CasinoDurableInboxStore {
    private val messages = ConcurrentHashMap<UUID, InboxCallbackMessage>()
    private val messagesByExtId = ConcurrentHashMap<String, InboxCallbackMessage>()
    private val messagesByIdemp = ConcurrentHashMap<String, InboxCallbackMessage>()
    val auditEvents = mutableListOf<AuditEvent>()
    val outboxEvents = mutableListOf<OutboxEvent>()

    private fun extKey(tenantId: String, providerId: String, extId: String) = "$tenantId:$providerId:$extId"
    private fun idempKey(tenantId: String, idemp: String) = "$tenantId:$idemp"

    @Synchronized
    override fun findMessageById(tenantId: String, messageId: UUID): InboxCallbackMessage? {
        return messages[messageId]?.takeIf { it.tenantId == tenantId }?.copy()
    }

    @Synchronized
    override fun findMessageByExternalId(tenantId: String, providerId: String, externalMessageId: String): InboxCallbackMessage? {
        return messagesByExtId[extKey(tenantId, providerId, externalMessageId)]?.copy()
    }

    @Synchronized
    override fun findMessageByIdempotency(tenantId: String, idempotencyKey: String): InboxCallbackMessage? {
        return messagesByIdemp[idempKey(tenantId, idempotencyKey)]?.copy()
    }

    @Synchronized
    override fun saveMessage(message: InboxCallbackMessage, audit: AuditEvent, outbox: OutboxEvent) {
        messages[message.messageId] = message.copy()
        messagesByExtId[extKey(message.tenantId, message.providerId, message.externalMessageId)] = message.copy()
        messagesByIdemp[idempKey(message.tenantId, message.idempotencyKey)] = message.copy()
        auditEvents.add(audit)
        outboxEvents.add(outbox)
    }

    @Synchronized
    override fun updateMessage(message: InboxCallbackMessage, audit: AuditEvent, outbox: OutboxEvent) {
        messages[message.messageId] = message.copy()
        messagesByExtId[extKey(message.tenantId, message.providerId, message.externalMessageId)] = message.copy()
        messagesByIdemp[idempKey(message.tenantId, message.idempotencyKey)] = message.copy()
        auditEvents.add(audit)
        outboxEvents.add(outbox)
    }

    @Synchronized
    override fun listPendingMessages(tenantId: String): List<InboxCallbackMessage> {
        return messages.values
            .filter { it.tenantId == tenantId && (it.status == InboxMessageStatus.RECEIVED || it.status == InboxMessageStatus.FAILED) }
            .map { it.copy() }
    }

    @Synchronized
    override fun listDeadLetterMessages(tenantId: String): List<InboxCallbackMessage> {
        return messages.values
            .filter { it.tenantId == tenantId && it.status == InboxMessageStatus.DEAD_LETTER }
            .map { it.copy() }
    }
}

class CasinoDurableInboxService(
    private val store: CasinoDurableInboxStore,
    private val payloadHandler: InboxPayloadHandler,
    private val alertSink: CasinoInboxAlertSink = InMemoryCasinoInboxAlertSink(),
    private val clock: Clock = Clock.systemUTC(),
) {
    private fun sha256(input: String): String {
        val digest = MessageDigest.getInstance("SHA-256")
        val hash = digest.digest(input.toByteArray(StandardCharsets.UTF_8))
        return hash.joinToString("") { "%02x".format(it) }
    }

    private fun fingerprint(cmd: ReceiveCallbackCommand): String {
        return sha256("${cmd.tenantId}:${cmd.providerId}:${cmd.protocol}:${cmd.externalMessageId}:${cmd.externalRoundId}:${cmd.externalTransactionId}:${cmd.rawPayload}:${cmd.expectedVersion}")
    }

    private fun defaultSuccessResponse(protocol: CallbackProviderProtocol, messageId: UUID): ProviderCallbackResponse {
        return when (protocol) {
            CallbackProviderProtocol.PRAGMATIC_PLAY -> ProviderCallbackResponse(
                httpStatusCode = 200,
                responseBody = """{"error":0,"description":"Success","inboxMessageId":"$messageId"}""",
                retryable = false,
            )
            CallbackProviderProtocol.EVOLUTION -> ProviderCallbackResponse(
                httpStatusCode = 200,
                responseBody = """{"status":"OK","inboxMessageId":"$messageId"}""",
                retryable = false,
            )
            CallbackProviderProtocol.GENERIC_HMAC -> ProviderCallbackResponse(
                httpStatusCode = 200,
                responseBody = """{"status":"PROCESSED","inboxMessageId":"$messageId"}""",
                retryable = false,
            )
        }
    }

    @Synchronized
    fun receiveAndProcessCallback(command: ReceiveCallbackCommand): InboxProcessingResult {
        CasinoDurableInboxBinding.checkBound()

        // 1. Input Validation
        if (command.tenantId.isBlank() ||
            command.providerId.isBlank() ||
            command.externalMessageId.isBlank() ||
            command.externalRoundId.isBlank() ||
            command.externalTransactionId.isBlank() ||
            command.rawPayload.isBlank() ||
            command.idempotencyKey.isBlank() ||
            command.correlationId.isBlank() ||
            command.causationId.isBlank()
        ) {
            alertSink.sendAlert(
                tenantId = command.tenantId.ifBlank { "UNKNOWN" },
                severity = "MEDIUM",
                alertType = "CASINO_INBOX_INVALID_INPUT",
                detail = "Callback rejected due to blank required fields",
            )
            throw AuthenticationFailure.Rejected(AuthErrorCode.INVALID)
        }

        if (command.expectedVersion != 1L) {
            throw AuthenticationFailure.Rejected(AuthErrorCode.STALE)
        }

        val fp = fingerprint(command)
        val now = clock.instant()

        // 2. Durable Deduplication Check (By Idempotency Key)
        val existingByIdemp = store.findMessageByIdempotency(command.tenantId, command.idempotencyKey)
        if (existingByIdemp != null) {
            if (existingByIdemp.fingerprint != fp) {
                // Conflicting payload under same idempotency key (Protected Risk: spoof/duplicate/stale payload)
                alertSink.sendAlert(
                    tenantId = command.tenantId,
                    severity = "HIGH",
                    alertType = "CASINO_INBOX_IDEMPOTENCY_CONFLICT",
                    detail = "Payload conflict detected under idempotency key ${command.idempotencyKey} for provider ${command.providerId}",
                )
                throw AuthenticationFailure.Rejected(AuthErrorCode.CONFLICT)
            }

            // Exactly identical replay
            val response = ProviderCallbackResponse(
                httpStatusCode = existingByIdemp.httpStatusCode ?: 200,
                responseBody = existingByIdemp.responseBody ?: defaultSuccessResponse(command.protocol, existingByIdemp.messageId).responseBody,
                retryable = false,
            )
            return InboxProcessingResult(
                messageId = existingByIdemp.messageId,
                tenantId = existingByIdemp.tenantId,
                providerId = existingByIdemp.providerId,
                status = existingByIdemp.status,
                isDuplicate = true,
                response = response,
                evidenceReference = existingByIdemp.evidenceReference,
                processedAt = existingByIdemp.processedAt ?: now,
            )
        }

        // 3. Durable Deduplication Check (By External Message ID)
        val existingByExtId = store.findMessageByExternalId(command.tenantId, command.providerId, command.externalMessageId)
        if (existingByExtId != null) {
            if (existingByExtId.fingerprint != fp) {
                alertSink.sendAlert(
                    tenantId = command.tenantId,
                    severity = "HIGH",
                    alertType = "CASINO_INBOX_EXTERNAL_ID_CONFLICT",
                    detail = "External message ID ${command.externalMessageId} already received with different payload",
                )
                throw AuthenticationFailure.Rejected(AuthErrorCode.CONFLICT)
            }

            val response = ProviderCallbackResponse(
                httpStatusCode = existingByExtId.httpStatusCode ?: 200,
                responseBody = existingByExtId.responseBody ?: defaultSuccessResponse(command.protocol, existingByExtId.messageId).responseBody,
                retryable = false,
            )
            return InboxProcessingResult(
                messageId = existingByExtId.messageId,
                tenantId = existingByExtId.tenantId,
                providerId = existingByExtId.providerId,
                status = existingByExtId.status,
                isDuplicate = true,
                response = response,
                evidenceReference = existingByExtId.evidenceReference,
                processedAt = existingByExtId.processedAt ?: now,
            )
        }

        // 4. Ingest new message into Durable Inbox in RECEIVED status
        val messageId = UUID.randomUUID()
        val evidenceRef = sha256("${command.tenantId}:$messageId:${command.externalMessageId}:${now.toEpochMilli()}")

        val inboxMessage = InboxCallbackMessage(
            messageId = messageId,
            tenantId = command.tenantId,
            providerId = command.providerId,
            externalMessageId = command.externalMessageId,
            externalRoundId = command.externalRoundId,
            externalTransactionId = command.externalTransactionId,
            idempotencyKey = command.idempotencyKey,
            fingerprint = fp,
            payload = command.rawPayload,
            status = InboxMessageStatus.RECEIVED,
            receivedAt = now,
            processedAt = null,
            retryCount = 0,
            maxRetries = 3,
            lastError = null,
            responseBody = null,
            httpStatusCode = null,
            evidenceReference = evidenceRef,
            correlationId = command.correlationId,
            causationId = command.causationId,
            version = 1L,
        )

        val intakeAudit = AuditEvent(
            eventId = UUID.randomUUID(),
            resultId = messageId,
            tenantId = command.tenantId,
            type = "CASINO_INBOX_MESSAGE_RECEIVED",
            occurredAt = now,
            correlationId = command.correlationId,
            causationId = command.causationId,
        )
        val intakeOutbox = OutboxEvent(
            eventId = UUID.randomUUID(),
            resultId = messageId,
            tenantId = command.tenantId,
            type = "CASINO_INBOX_MESSAGE_RECEIVED",
            createdAt = now,
        )

        store.saveMessage(inboxMessage, intakeAudit, intakeOutbox)

        // 5. Execute Handler Atomically
        inboxMessage.status = InboxMessageStatus.PROCESSING

        val handlerResponse = try {
            payloadHandler.handle(command.tenantId, command.providerId, command.rawPayload)
        } catch (e: Exception) {
            // Handler failure: preserve message in inbox for retry or DLQ
            inboxMessage.status = InboxMessageStatus.FAILED
            inboxMessage.retryCount += 1
            inboxMessage.lastError = e.message ?: "Unknown handler error"
            inboxMessage.httpStatusCode = 500
            inboxMessage.responseBody = """{"status":"FAILED","error":"${inboxMessage.lastError}"}"""

            if (inboxMessage.retryCount >= inboxMessage.maxRetries) {
                inboxMessage.status = InboxMessageStatus.DEAD_LETTER
                alertSink.sendAlert(
                    tenantId = command.tenantId,
                    severity = "HIGH",
                    alertType = "CASINO_INBOX_DEAD_LETTER_THRESHOLD_EXCEEDED",
                    detail = "Message $messageId reached max retries (${inboxMessage.maxRetries}): ${inboxMessage.lastError}",
                )
            } else {
                alertSink.sendAlert(
                    tenantId = command.tenantId,
                    severity = "MEDIUM",
                    alertType = "CASINO_INBOX_PROCESSING_FAILED",
                    detail = "Message $messageId failed on attempt ${inboxMessage.retryCount}: ${inboxMessage.lastError}",
                )
            }

            val failAudit = AuditEvent(
                eventId = UUID.randomUUID(),
                resultId = messageId,
                tenantId = command.tenantId,
                type = "CASINO_INBOX_MESSAGE_FAILED",
                occurredAt = clock.instant(),
                correlationId = command.correlationId,
                causationId = command.causationId,
            )
            val failOutbox = OutboxEvent(
                eventId = UUID.randomUUID(),
                resultId = messageId,
                tenantId = command.tenantId,
                type = "CASINO_INBOX_MESSAGE_FAILED",
                createdAt = clock.instant(),
            )
            store.updateMessage(inboxMessage, failAudit, failOutbox)

            throw AuthenticationFailure.Rejected(AuthErrorCode.DEPENDENCY_UNAVAILABLE)
        }

        // 6. Successful Processing Outcome
        val completionTime = clock.instant()
        inboxMessage.status = InboxMessageStatus.PROCESSED
        inboxMessage.processedAt = completionTime
        inboxMessage.httpStatusCode = handlerResponse.httpStatusCode
        inboxMessage.responseBody = handlerResponse.responseBody
        inboxMessage.version += 1L

        val successAudit = AuditEvent(
            eventId = UUID.randomUUID(),
            resultId = messageId,
            tenantId = command.tenantId,
            type = "CASINO_INBOX_MESSAGE_PROCESSED",
            occurredAt = completionTime,
            correlationId = command.correlationId,
            causationId = command.causationId,
        )
        val successOutbox = OutboxEvent(
            eventId = UUID.randomUUID(),
            resultId = messageId,
            tenantId = command.tenantId,
            type = "CASINO_INBOX_MESSAGE_PROCESSED",
            createdAt = completionTime,
        )

        store.updateMessage(inboxMessage, successAudit, successOutbox)

        return InboxProcessingResult(
            messageId = messageId,
            tenantId = command.tenantId,
            providerId = command.providerId,
            status = InboxMessageStatus.PROCESSED,
            isDuplicate = false,
            response = handlerResponse,
            evidenceReference = evidenceRef,
            processedAt = completionTime,
        )
    }

    @Synchronized
    fun retryFailedMessages(tenantId: String): List<InboxProcessingResult> {
        val pending = store.listPendingMessages(tenantId)
        val results = mutableListOf<InboxProcessingResult>()

        for (msg in pending) {
            if (msg.retryCount >= msg.maxRetries) continue

            val res = try {
                val handlerRes = payloadHandler.handle(msg.tenantId, msg.providerId, msg.payload)
                val now = clock.instant()
                msg.status = InboxMessageStatus.PROCESSED
                msg.processedAt = now
                msg.httpStatusCode = handlerRes.httpStatusCode
                msg.responseBody = handlerRes.responseBody
                msg.version += 1L

                val audit = AuditEvent(UUID.randomUUID(), msg.messageId, msg.tenantId, "CASINO_INBOX_MESSAGE_RETRIED", now, msg.correlationId, msg.causationId)
                val outbox = OutboxEvent(UUID.randomUUID(), msg.messageId, msg.tenantId, "CASINO_INBOX_MESSAGE_RETRIED", now)
                store.updateMessage(msg, audit, outbox)

                InboxProcessingResult(
                    messageId = msg.messageId,
                    tenantId = msg.tenantId,
                    providerId = msg.providerId,
                    status = InboxMessageStatus.PROCESSED,
                    isDuplicate = false,
                    response = handlerRes,
                    evidenceReference = msg.evidenceReference,
                    processedAt = now,
                )
            } catch (e: Exception) {
                msg.retryCount += 1
                msg.lastError = e.message
                if (msg.retryCount >= msg.maxRetries) {
                    msg.status = InboxMessageStatus.DEAD_LETTER
                    alertSink.sendAlert(
                        tenantId = msg.tenantId,
                        severity = "HIGH",
                        alertType = "CASINO_INBOX_DEAD_LETTER_THRESHOLD_EXCEEDED",
                        detail = "Message ${msg.messageId} reached max retries (${msg.maxRetries}) during batch retry",
                    )
                }
                val now = clock.instant()
                val audit = AuditEvent(UUID.randomUUID(), msg.messageId, msg.tenantId, "CASINO_INBOX_RETRY_FAILED", now, msg.correlationId, msg.causationId)
                val outbox = OutboxEvent(UUID.randomUUID(), msg.messageId, msg.tenantId, "CASINO_INBOX_RETRY_FAILED", now)
                store.updateMessage(msg, audit, outbox)
                null
            }
            if (res != null) results.add(res)
        }
        return results
    }
}
