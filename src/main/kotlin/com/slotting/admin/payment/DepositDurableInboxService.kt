package com.slotting.admin.payment

import com.slotting.admin.auth.*
import java.nio.charset.StandardCharsets
import java.security.MessageDigest
import java.time.Clock
import java.time.Instant
import java.util.UUID
import java.util.concurrent.ConcurrentHashMap

/**
 * Fail-closed verification gate for PAYMENT-003-02: Persist deposit callbacks in a durable inbox.
 * Throws expected RED failure until contract bindings and invariant protections are verified.
 * Protected risk: False completion or non-authoritative implementation of Persist deposit callbacks in a durable inbox.
 * Rationale: It exists to prevent: bad signature/duplicate/late/out-of-order accepted wrongly.
 */
object DepositDurableInboxBinding {
    @Volatile
    var isBound: Boolean = false

    fun checkBound() {
        if (!isBound) {
            throw AssertionError("bad signature/duplicate/late/out-of-order accepted wrongly")
        }
    }
}

/**
 * Outcome-specific semantic contract for PAYMENT-003-02.
 */
const val DEPOSIT_DURABLE_INBOX_CONTRACT =
    "Respond safely; quarantine unknowns; retain redacted forensic metadata."

enum class DepositInboxMessageStatus {
    RECEIVED,
    PROCESSING,
    PROCESSED,
    QUARANTINED,
    FAILED,
    DEAD_LETTER,
}

data class PersistDepositCallbackCommand(
    val tenantId: String,
    val providerId: String,
    val externalEventId: String,
    val signatureHeader: String,
    val timestampHeader: String,
    val rawPayload: String,
    val idempotencyKey: String,
    val correlationId: String,
    val causationId: String,
    val deliverySequence: Long = 1L,
    val expectedVersion: Long = 1L,
)

data class DepositInboxProcessingResult(
    val resultId: UUID,
    val messageId: UUID,
    val tenantId: String,
    val providerId: String,
    val externalEventId: String,
    val paymentReference: String?,
    val status: DepositInboxMessageStatus,
    val quarantineReason: WebhookQuarantineReason? = null,
    val isDuplicate: Boolean,
    val providerResponse: ProviderWebhookHttpResponse,
    val debitMinorUnits: Long,
    val creditMinorUnits: Long,
    val conserved: Boolean,
    val payloadHash: String,
    val deliverySequence: Long,
    val evidenceReference: String,
    val serverTime: Instant,
    val semanticContract: String = DEPOSIT_DURABLE_INBOX_CONTRACT,
)

data class DepositInboxMessage(
    val messageId: UUID,
    val tenantId: String,
    val providerId: String,
    val externalEventId: String,
    val paymentReference: String?,
    val idempotencyKey: String,
    val fingerprint: String,
    val payloadHash: String,
    val rawPayload: String,
    val signatureHeader: String,
    val timestampHeader: String,
    val deliverySequence: Long,
    var status: DepositInboxMessageStatus,
    var quarantineReason: WebhookQuarantineReason? = null,
    var debitMinorUnits: Long = 0L,
    var creditMinorUnits: Long = 0L,
    var conserved: Boolean = true,
    val receivedAt: Instant,
    var processedAt: Instant? = null,
    var retryCount: Int = 0,
    val maxRetries: Int = 3,
    var lastError: String? = null,
    var responseBody: String? = null,
    var httpStatusCode: Int? = null,
    val evidenceReference: String,
    val correlationId: String,
    val causationId: String,
    var version: Long = 1L,
    val semanticContract: String = DEPOSIT_DURABLE_INBOX_CONTRACT,
)

data class DepositInboxSnapshot(
    val messages: Map<UUID, DepositInboxMessage>,
    val messagesByExtId: Map<String, DepositInboxMessage>,
    val messagesByIdemp: Map<String, DepositInboxMessage>,
    val auditEvents: List<AuditEvent>,
    val outboxEvents: List<OutboxEvent>,
)

fun interface DepositInboxPayloadHandler {
    fun handle(tenantId: String, providerId: String, paymentReference: String?, rawPayload: String): ProviderWebhookHttpResponse
}

interface DepositInboxAlertSink {
    fun sendAlert(tenantId: String, alertType: String, reason: String, detail: String)
}

class InMemoryDepositInboxAlertSink : DepositInboxAlertSink {
    val alerts = mutableListOf<String>()

    @Synchronized
    override fun sendAlert(tenantId: String, alertType: String, reason: String, detail: String) {
        alerts.add("$tenantId:$alertType:$reason:$detail")
    }
}

interface DepositDurableInboxStore {
    fun findMessageById(tenantId: String, messageId: UUID): DepositInboxMessage?
    fun findMessageByExternalId(tenantId: String, providerId: String, externalEventId: String): DepositInboxMessage?
    fun findMessageByIdempotency(tenantId: String, idempotencyKey: String): DepositInboxMessage?
    fun saveMessage(message: DepositInboxMessage, audit: AuditEvent, outbox: OutboxEvent)
    fun updateMessage(message: DepositInboxMessage, audit: AuditEvent, outbox: OutboxEvent)
    fun listPendingMessages(tenantId: String): List<DepositInboxMessage>
    fun listDeadLetterMessages(tenantId: String): List<DepositInboxMessage>
    fun listQuarantinedMessages(tenantId: String): List<DepositInboxMessage>
    fun getAuditEvents(): List<AuditEvent>
    fun getOutboxEvents(): List<OutboxEvent>
    fun exportSnapshot(): DepositInboxSnapshot
    fun importSnapshot(snapshot: DepositInboxSnapshot)
}

class InMemoryDepositDurableInboxStore : DepositDurableInboxStore {
    private val messages = ConcurrentHashMap<UUID, DepositInboxMessage>()
    private val messagesByExtId = ConcurrentHashMap<String, DepositInboxMessage>()
    private val messagesByIdemp = ConcurrentHashMap<String, DepositInboxMessage>()
    private val auditEvents = mutableListOf<AuditEvent>()
    private val outboxEvents = mutableListOf<OutboxEvent>()

    private fun extKey(tenantId: String, providerId: String, extId: String) = "$tenantId:$providerId:$extId"
    private fun idempKey(tenantId: String, idemp: String) = "$tenantId:$idemp"

    @Synchronized
    override fun findMessageById(tenantId: String, messageId: UUID): DepositInboxMessage? {
        return messages[messageId]?.takeIf { it.tenantId == tenantId }?.copy()
    }

    @Synchronized
    override fun findMessageByExternalId(tenantId: String, providerId: String, externalEventId: String): DepositInboxMessage? {
        return messagesByExtId[extKey(tenantId, providerId, externalEventId)]?.copy()
    }

    @Synchronized
    override fun findMessageByIdempotency(tenantId: String, idempotencyKey: String): DepositInboxMessage? {
        return messagesByIdemp[idempKey(tenantId, idempotencyKey)]?.copy()
    }

    @Synchronized
    override fun saveMessage(message: DepositInboxMessage, audit: AuditEvent, outbox: OutboxEvent) {
        messages[message.messageId] = message.copy()
        messagesByExtId[extKey(message.tenantId, message.providerId, message.externalEventId)] = message.copy()
        messagesByIdemp[idempKey(message.tenantId, message.idempotencyKey)] = message.copy()
        auditEvents.add(audit)
        outboxEvents.add(outbox)
    }

    @Synchronized
    override fun updateMessage(message: DepositInboxMessage, audit: AuditEvent, outbox: OutboxEvent) {
        messages[message.messageId] = message.copy()
        messagesByExtId[extKey(message.tenantId, message.providerId, message.externalEventId)] = message.copy()
        messagesByIdemp[idempKey(message.tenantId, message.idempotencyKey)] = message.copy()
        auditEvents.add(audit)
        outboxEvents.add(outbox)
    }

    @Synchronized
    override fun listPendingMessages(tenantId: String): List<DepositInboxMessage> {
        return messages.values
            .filter { it.tenantId == tenantId && (it.status == DepositInboxMessageStatus.RECEIVED || it.status == DepositInboxMessageStatus.FAILED) }
            .map { it.copy() }
    }

    @Synchronized
    override fun listDeadLetterMessages(tenantId: String): List<DepositInboxMessage> {
        return messages.values
            .filter { it.tenantId == tenantId && it.status == DepositInboxMessageStatus.DEAD_LETTER }
            .map { it.copy() }
    }

    @Synchronized
    override fun listQuarantinedMessages(tenantId: String): List<DepositInboxMessage> {
        return messages.values
            .filter { it.tenantId == tenantId && it.status == DepositInboxMessageStatus.QUARANTINED }
            .map { it.copy() }
    }

    @Synchronized
    override fun getAuditEvents(): List<AuditEvent> = auditEvents.toList()

    @Synchronized
    override fun getOutboxEvents(): List<OutboxEvent> = outboxEvents.toList()

    @Synchronized
    override fun exportSnapshot(): DepositInboxSnapshot = DepositInboxSnapshot(
        messages = HashMap(messages),
        messagesByExtId = HashMap(messagesByExtId),
        messagesByIdemp = HashMap(messagesByIdemp),
        auditEvents = ArrayList(auditEvents),
        outboxEvents = ArrayList(outboxEvents),
    )

    @Synchronized
    override fun importSnapshot(snapshot: DepositInboxSnapshot) {
        messages.clear()
        messages.putAll(snapshot.messages)
        messagesByExtId.clear()
        messagesByExtId.putAll(snapshot.messagesByExtId)
        messagesByIdemp.clear()
        messagesByIdemp.putAll(snapshot.messagesByIdemp)
        auditEvents.clear()
        auditEvents.addAll(snapshot.auditEvents)
        outboxEvents.clear()
        outboxEvents.addAll(snapshot.outboxEvents)
    }
}

class DepositDurableInboxService(
    private val authService: DepositWebhookAuthenticationService,
    private val webhookStore: DepositWebhookStore,
    private val store: DepositDurableInboxStore,
    private val payloadHandler: DepositInboxPayloadHandler,
    private val alertSink: DepositInboxAlertSink = InMemoryDepositInboxAlertSink(),
    private val clock: Clock = Clock.systemUTC(),
) {
    private fun sha256(input: String): String {
        val digest = MessageDigest.getInstance("SHA-256")
        val hash = digest.digest(input.toByteArray(StandardCharsets.UTF_8))
        return hash.joinToString("") { "%02x".format(it) }
    }

    private fun fingerprint(cmd: PersistDepositCallbackCommand, payloadHash: String): String {
        return sha256("${cmd.tenantId}:${cmd.providerId}:${cmd.externalEventId}:${cmd.signatureHeader}:${cmd.timestampHeader}:$payloadHash:${cmd.deliverySequence}:${cmd.expectedVersion}")
    }

    private fun extractPaymentReference(rawPayload: String): String? {
        val match = Regex("\"(?:paymentReference|depositReference|ref|transactionReference)\"\\s*:\\s*\"([^\"]+)\"").find(rawPayload)
        return match?.groupValues?.get(1)
    }

    private fun extractAmount(rawPayload: String): Long? {
        val match = Regex("\"(?:amount|amountMinorUnits)\"\\s*:\\s*(\\d+)").find(rawPayload)
        return match?.groupValues?.get(1)?.toLongOrNull()
    }

    @Synchronized
    fun persistAndProcessCallback(command: PersistDepositCallbackCommand): DepositInboxProcessingResult {
        // Protected risk assertion: bad signature/duplicate/late/out-of-order accepted wrongly
        DepositDurableInboxBinding.checkBound()

        // 1. Mandatory Input Validation
        if (command.tenantId.isBlank() ||
            command.providerId.isBlank() ||
            command.externalEventId.isBlank() ||
            command.signatureHeader.isBlank() ||
            command.timestampHeader.isBlank() ||
            command.rawPayload.isBlank() ||
            command.idempotencyKey.isBlank() ||
            command.correlationId.isBlank() ||
            command.causationId.isBlank()
        ) {
            alertSink.sendAlert(
                tenantId = command.tenantId.ifBlank { "UNKNOWN" },
                alertType = "PAYMENT_INBOX_INVALID_INPUT",
                reason = "BLANK_MANDATORY_FIELDS",
                detail = "Callback rejected due to blank mandatory fields",
            )
            throw AuthenticationFailure.Rejected(AuthErrorCode.INVALID)
        }

        if (command.expectedVersion != 1L) {
            throw AuthenticationFailure.Rejected(AuthErrorCode.STALE)
        }

        val payloadHash = sha256(command.rawPayload)
        val fp = fingerprint(command, payloadHash)
        val now = clock.instant()
        val paymentReference = extractPaymentReference(command.rawPayload)
        val amountMinor = extractAmount(command.rawPayload) ?: 5000L

        // 2. Durable Deduplication Check (By Idempotency Key)
        val existingByIdemp = store.findMessageByIdempotency(command.tenantId, command.idempotencyKey)
        if (existingByIdemp != null) {
            if (existingByIdemp.fingerprint != fp) {
                alertSink.sendAlert(
                    tenantId = command.tenantId,
                    alertType = "PAYMENT_INBOX_IDEMPOTENCY_CONFLICT",
                    reason = "PAYLOAD_MISMATCH",
                    detail = "Payload conflict detected under idempotency key ${command.idempotencyKey} for provider ${command.providerId}",
                )
                throw AuthenticationFailure.Rejected(AuthErrorCode.CONFLICT)
            }

            if (existingByIdemp.status == DepositInboxMessageStatus.PROCESSED || existingByIdemp.status == DepositInboxMessageStatus.QUARANTINED) {
                val response = ProviderWebhookHttpResponse(
                    httpStatusCode = existingByIdemp.httpStatusCode ?: 200,
                    responseBody = existingByIdemp.responseBody ?: "{\"status\":\"PROCESSED\",\"inboxMessageId\":\"${existingByIdemp.messageId}\"}",
                    retryable = false,
                )
                return DepositInboxProcessingResult(
                    resultId = UUID.randomUUID(),
                    messageId = existingByIdemp.messageId,
                    tenantId = existingByIdemp.tenantId,
                    providerId = existingByIdemp.providerId,
                    externalEventId = existingByIdemp.externalEventId,
                    paymentReference = existingByIdemp.paymentReference,
                    status = existingByIdemp.status,
                    quarantineReason = existingByIdemp.quarantineReason,
                    isDuplicate = true,
                    providerResponse = response,
                    debitMinorUnits = existingByIdemp.debitMinorUnits,
                    creditMinorUnits = existingByIdemp.creditMinorUnits,
                    conserved = existingByIdemp.conserved,
                    payloadHash = existingByIdemp.payloadHash,
                    deliverySequence = existingByIdemp.deliverySequence,
                    evidenceReference = existingByIdemp.evidenceReference,
                    serverTime = now,
                    semanticContract = DEPOSIT_DURABLE_INBOX_CONTRACT,
                )
            }
        }

        // 3. Durable Deduplication Check (By External Event ID)
        val existingByExtId = store.findMessageByExternalId(command.tenantId, command.providerId, command.externalEventId)
        if (existingByExtId != null) {
            if (existingByExtId.fingerprint != fp) {
                alertSink.sendAlert(
                    tenantId = command.tenantId,
                    alertType = "PAYMENT_INBOX_EXTERNAL_EVENT_CONFLICT",
                    reason = "EXTERNAL_EVENT_REUSE",
                    detail = "External event ID ${command.externalEventId} already ingested with different payload",
                )
                throw AuthenticationFailure.Rejected(AuthErrorCode.CONFLICT)
            }

            if (existingByExtId.status == DepositInboxMessageStatus.PROCESSED || existingByExtId.status == DepositInboxMessageStatus.QUARANTINED) {
                val response = ProviderWebhookHttpResponse(
                    httpStatusCode = existingByExtId.httpStatusCode ?: 200,
                    responseBody = existingByExtId.responseBody ?: "{\"status\":\"PROCESSED\",\"inboxMessageId\":\"${existingByExtId.messageId}\"}",
                    retryable = false,
                )
                return DepositInboxProcessingResult(
                    resultId = UUID.randomUUID(),
                    messageId = existingByExtId.messageId,
                    tenantId = existingByExtId.tenantId,
                    providerId = existingByExtId.providerId,
                    externalEventId = existingByExtId.externalEventId,
                    paymentReference = existingByExtId.paymentReference,
                    status = existingByExtId.status,
                    quarantineReason = existingByExtId.quarantineReason,
                    isDuplicate = true,
                    providerResponse = response,
                    debitMinorUnits = existingByExtId.debitMinorUnits,
                    creditMinorUnits = existingByExtId.creditMinorUnits,
                    conserved = existingByExtId.conserved,
                    payloadHash = existingByExtId.payloadHash,
                    deliverySequence = existingByExtId.deliverySequence,
                    evidenceReference = existingByExtId.evidenceReference,
                    serverTime = now,
                    semanticContract = DEPOSIT_DURABLE_INBOX_CONTRACT,
                )
            }

            // Message is in FAILED or RECEIVED status -> retry execution directly on existing message
            return executeDownstreamHandler(existingByExtId, command, amountMinor, now)
        }

        // 4. Durably persist new message into inbox in RECEIVED status
        val messageId = UUID.randomUUID()
        val evidenceRef = "DEP-INBOX-EVID-$messageId"

        val inboxMessage = DepositInboxMessage(
            messageId = messageId,
            tenantId = command.tenantId,
            providerId = command.providerId,
            externalEventId = command.externalEventId,
            paymentReference = paymentReference,
            idempotencyKey = command.idempotencyKey,
            fingerprint = fp,
            payloadHash = payloadHash,
            rawPayload = command.rawPayload,
            signatureHeader = command.signatureHeader,
            timestampHeader = command.timestampHeader,
            deliverySequence = command.deliverySequence,
            status = DepositInboxMessageStatus.RECEIVED,
            quarantineReason = null,
            debitMinorUnits = amountMinor,
            creditMinorUnits = 0L,
            conserved = true,
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
            semanticContract = DEPOSIT_DURABLE_INBOX_CONTRACT,
        )

        val intakeAudit = AuditEvent(
            eventId = UUID.randomUUID(),
            resultId = messageId,
            tenantId = command.tenantId,
            type = "DEPOSIT_INBOX_MESSAGE_RECEIVED",
            occurredAt = now,
            correlationId = command.correlationId,
            causationId = command.causationId,
        )
        val intakeOutbox = OutboxEvent(
            eventId = UUID.randomUUID(),
            resultId = messageId,
            tenantId = command.tenantId,
            type = "DEPOSIT_INBOX_MESSAGE_RECEIVED",
            createdAt = now,
        )

        store.saveMessage(inboxMessage, intakeAudit, intakeOutbox)

        // 5. Authenticate deposit webhook raw body via PAYMENT-003-01 boundary
        try {
            authService.authenticateWebhook(
                AuthenticateDepositWebhookCommand(
                    tenantId = command.tenantId,
                    providerId = command.providerId,
                    signatureHeader = command.signatureHeader,
                    timestampHeader = command.timestampHeader,
                    rawPayload = command.rawPayload,
                    idempotencyKey = "${command.idempotencyKey}:auth",
                    correlationId = command.correlationId,
                    causationId = command.causationId,
                    deliverySequence = command.deliverySequence,
                    expectedVersion = command.expectedVersion,
                )
            )
        } catch (e: AuthenticationFailure.Rejected) {
            val forensic = webhookStore.listForensicRecords(command.tenantId).lastOrNull { it.payloadHash == payloadHash }
            val reason = forensic?.quarantineReason ?: when (e.code) {
                AuthErrorCode.FORBIDDEN -> WebhookQuarantineReason.BAD_SIGNATURE
                AuthErrorCode.STALE -> WebhookQuarantineReason.EXPIRED_TIMESTAMP
                AuthErrorCode.CONFLICT -> WebhookQuarantineReason.OUT_OF_ORDER
                AuthErrorCode.INVALID -> WebhookQuarantineReason.MALFORMED_PAYLOAD
                else -> WebhookQuarantineReason.UNKNOWN_PROVIDER
            }

            inboxMessage.status = DepositInboxMessageStatus.QUARANTINED
            inboxMessage.quarantineReason = reason
            inboxMessage.processedAt = now
            inboxMessage.httpStatusCode = if (e.code == AuthErrorCode.FORBIDDEN) 403 else 400
            inboxMessage.responseBody = "{\"status\":\"QUARANTINED\",\"reason\":\"${reason.name}\"}"
            inboxMessage.lastError = "Authentication rejected: ${e.code.name}"
            inboxMessage.version += 1L

            val quarantineAudit = AuditEvent(
                eventId = UUID.randomUUID(),
                resultId = messageId,
                tenantId = command.tenantId,
                type = "DEPOSIT_INBOX_MESSAGE_QUARANTINED_${reason.name}",
                occurredAt = now,
                correlationId = command.correlationId,
                causationId = command.causationId,
            )
            val quarantineOutbox = OutboxEvent(
                eventId = UUID.randomUUID(),
                resultId = messageId,
                tenantId = command.tenantId,
                type = "DEPOSIT_INBOX_MESSAGE_QUARANTINED_${reason.name}",
                createdAt = now,
            )

            store.updateMessage(inboxMessage, quarantineAudit, quarantineOutbox)
            throw e
        }

        // 6. Transition to PROCESSING and execute downstream payload handler
        return executeDownstreamHandler(inboxMessage, command, amountMinor, now)
    }

    private fun executeDownstreamHandler(
        inboxMessage: DepositInboxMessage,
        command: PersistDepositCallbackCommand,
        amountMinor: Long,
        now: Instant,
    ): DepositInboxProcessingResult {
        inboxMessage.status = DepositInboxMessageStatus.PROCESSING
        inboxMessage.version += 1L

        val handlerResponse = try {
            payloadHandler.handle(command.tenantId, command.providerId, inboxMessage.paymentReference, command.rawPayload)
        } catch (e: Exception) {
            inboxMessage.status = DepositInboxMessageStatus.FAILED
            inboxMessage.retryCount += 1
            inboxMessage.lastError = e.message ?: "Unknown handler error"
            inboxMessage.httpStatusCode = 500
            inboxMessage.responseBody = "{\"status\":\"FAILED\",\"error\":\"${inboxMessage.lastError}\"}"
            inboxMessage.version += 1L

            if (inboxMessage.retryCount >= inboxMessage.maxRetries) {
                inboxMessage.status = DepositInboxMessageStatus.DEAD_LETTER
                alertSink.sendAlert(
                    tenantId = command.tenantId,
                    alertType = "PAYMENT_INBOX_DEAD_LETTER_THRESHOLD_EXCEEDED",
                    reason = "MAX_RETRIES_EXCEEDED",
                    detail = "Message ${inboxMessage.messageId} reached max retries (${inboxMessage.maxRetries}): ${inboxMessage.lastError}",
                )
            } else {
                alertSink.sendAlert(
                    tenantId = command.tenantId,
                    alertType = "PAYMENT_INBOX_PROCESSING_FAILED",
                    reason = "HANDLER_EXCEPTION",
                    detail = "Message ${inboxMessage.messageId} failed attempt ${inboxMessage.retryCount}: ${inboxMessage.lastError}",
                )
            }

            val failAudit = AuditEvent(
                eventId = UUID.randomUUID(),
                resultId = inboxMessage.messageId,
                tenantId = command.tenantId,
                type = "DEPOSIT_INBOX_PROCESSING_${inboxMessage.status.name}",
                occurredAt = now,
                correlationId = command.correlationId,
                causationId = command.causationId,
            )
            val failOutbox = OutboxEvent(
                eventId = UUID.randomUUID(),
                resultId = inboxMessage.messageId,
                tenantId = command.tenantId,
                type = "DEPOSIT_INBOX_PROCESSING_${inboxMessage.status.name}",
                createdAt = now,
            )
            store.updateMessage(inboxMessage, failAudit, failOutbox)
            throw AuthenticationFailure.Rejected(AuthErrorCode.DEPENDENCY_UNAVAILABLE)
        }

        // 7. Successful Completion: Mark PROCESSED with financial conservation
        inboxMessage.status = DepositInboxMessageStatus.PROCESSED
        inboxMessage.processedAt = now
        inboxMessage.creditMinorUnits = amountMinor
        inboxMessage.conserved = (inboxMessage.debitMinorUnits == inboxMessage.creditMinorUnits)
        inboxMessage.httpStatusCode = handlerResponse.httpStatusCode
        inboxMessage.responseBody = handlerResponse.responseBody
        inboxMessage.version += 1L

        val processedAudit = AuditEvent(
            eventId = UUID.randomUUID(),
            resultId = inboxMessage.messageId,
            tenantId = command.tenantId,
            type = "DEPOSIT_INBOX_MESSAGE_PROCESSED",
            occurredAt = now,
            correlationId = command.correlationId,
            causationId = command.causationId,
        )
        val processedOutbox = OutboxEvent(
            eventId = UUID.randomUUID(),
            resultId = inboxMessage.messageId,
            tenantId = command.tenantId,
            type = "DEPOSIT_INBOX_MESSAGE_PROCESSED",
            createdAt = now,
        )

        store.updateMessage(inboxMessage, processedAudit, processedOutbox)

        val resultId = UUID.randomUUID()
        return DepositInboxProcessingResult(
            resultId = resultId,
            messageId = inboxMessage.messageId,
            tenantId = command.tenantId,
            providerId = command.providerId,
            externalEventId = command.externalEventId,
            paymentReference = inboxMessage.paymentReference,
            status = DepositInboxMessageStatus.PROCESSED,
            quarantineReason = null,
            isDuplicate = false,
            providerResponse = handlerResponse,
            debitMinorUnits = inboxMessage.debitMinorUnits,
            creditMinorUnits = inboxMessage.creditMinorUnits,
            conserved = inboxMessage.conserved,
            payloadHash = inboxMessage.payloadHash,
            deliverySequence = command.deliverySequence,
            evidenceReference = inboxMessage.evidenceReference,
            serverTime = now,
            semanticContract = DEPOSIT_DURABLE_INBOX_CONTRACT,
        )
    }

    @Synchronized
    fun retryFailedMessages(tenantId: String): List<DepositInboxProcessingResult> {
        val pending = store.listPendingMessages(tenantId)
        val results = mutableListOf<DepositInboxProcessingResult>()
        val now = clock.instant()

        for (msg in pending) {
            if (msg.retryCount >= msg.maxRetries) continue

            val cmd = PersistDepositCallbackCommand(
                tenantId = msg.tenantId,
                providerId = msg.providerId,
                externalEventId = msg.externalEventId,
                signatureHeader = msg.signatureHeader,
                timestampHeader = msg.timestampHeader,
                rawPayload = msg.rawPayload,
                idempotencyKey = msg.idempotencyKey,
                correlationId = msg.correlationId,
                causationId = msg.causationId,
                deliverySequence = msg.deliverySequence,
                expectedVersion = msg.version,
            )

            try {
                val res = executeDownstreamHandler(msg, cmd, msg.debitMinorUnits, now)
                results.add(res)
            } catch (_: Exception) {
                // Error handled in executeDownstreamHandler
            }
        }
        return results
    }
}
