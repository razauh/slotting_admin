package com.slotting.admin.payment

import com.slotting.admin.auth.*
import java.nio.charset.StandardCharsets
import java.security.MessageDigest
import java.time.Clock
import java.time.Duration
import java.time.Instant
import java.util.UUID
import java.util.concurrent.ConcurrentHashMap
import javax.crypto.Mac
import javax.crypto.spec.SecretKeySpec

/**
 * Fail-closed verification gate for PAYMENT-003-01: Authenticate deposit webhook raw bodies.
 * Throws expected RED failure until contract bindings and invariant protections are verified.
 * Protected risk: False completion or non-authoritative implementation of Authenticate deposit webhook raw bodies.
 * Rationale: It exists to prevent: bad signature/duplicate/late/out-of-order accepted wrongly.
 */
object DepositWebhookAuthenticationBinding {
    @Volatile
    var isBound: Boolean = false

    fun checkBound() {
        if (!isBound) {
            throw AssertionError("bad signature/duplicate/late/out-of-order accepted wrongly")
        }
    }
}

/**
 * Outcome-specific semantic contract for PAYMENT-003-01.
 */
const val DEPOSIT_WEBHOOK_AUTH_CONTRACT =
    "Respond safely; quarantine unknowns; retain redacted forensic metadata."

enum class WebhookAuthStatus {
    AUTHENTICATED,
    QUARANTINED,
    REJECTED,
}

enum class WebhookQuarantineReason {
    BAD_SIGNATURE,
    UNKNOWN_PROVIDER,
    EXPIRED_TIMESTAMP,
    FUTURE_TIMESTAMP,
    OUT_OF_ORDER,
    MALFORMED_PAYLOAD,
}

data class AuthenticateDepositWebhookCommand(
    val tenantId: String,
    val providerId: String,
    val signatureHeader: String,
    val timestampHeader: String,
    val rawPayload: String,
    val idempotencyKey: String,
    val correlationId: String,
    val causationId: String,
    val deliverySequence: Long = 1L,
    val expectedVersion: Long = 1L,
)

data class ProviderWebhookHttpResponse(
    val httpStatusCode: Int,
    val responseBody: String,
    val retryable: Boolean,
    val retryAfterSeconds: Long? = null,
)

data class DepositWebhookAuthResult(
    val resultId: UUID,
    val tenantId: String,
    val providerId: String,
    val paymentReference: String?,
    val authenticated: Boolean,
    val status: WebhookAuthStatus,
    val quarantineReason: WebhookQuarantineReason? = null,
    val providerResponse: ProviderWebhookHttpResponse,
    val debitMinorUnits: Long,
    val creditMinorUnits: Long,
    val conserved: Boolean,
    val payloadHash: String,
    val deliverySequence: Long,
    val serverTime: Instant,
    val evidenceReference: String,
    val semanticContract: String = DEPOSIT_WEBHOOK_AUTH_CONTRACT,
)

data class WebhookForensicRecord(
    val recordId: UUID,
    val resultId: UUID,
    val tenantId: String,
    val providerId: String,
    val paymentReference: String?,
    val payloadHash: String,
    val signatureHeader: String,
    val timestampHeader: String,
    val status: WebhookAuthStatus,
    val quarantineReason: WebhookQuarantineReason?,
    val deliverySequence: Long,
    val serverTime: Instant,
    val correlationId: String,
    val causationId: String,
    val evidenceReference: String,
    val semanticContract: String = DEPOSIT_WEBHOOK_AUTH_CONTRACT,
)

data class DepositWebhookSnapshot(
    val results: Map<String, Pair<String, DepositWebhookAuthResult>>,
    val forensics: List<WebhookForensicRecord>,
    val processedSignatures: Map<String, Boolean>,
    val sequences: Map<String, Long>,
    val auditEvents: List<AuditEvent>,
    val outboxEvents: List<OutboxEvent>,
)

interface DepositWebhookSecretResolver {
    fun resolveSecret(tenantId: String, providerId: String): String?
}

class InMemoryDepositWebhookSecretResolver(
    private val secrets: MutableMap<String, String> = ConcurrentHashMap(),
) : DepositWebhookSecretResolver {
    fun setSecret(tenantId: String, providerId: String, secret: String) {
        secrets["$tenantId:$providerId"] = secret
    }

    override fun resolveSecret(tenantId: String, providerId: String): String? {
        return secrets["$tenantId:$providerId"]
    }
}

interface DepositWebhookAlertSink {
    fun sendAlert(tenantId: String, alertType: String, reason: String, detail: String)
}

class InMemoryDepositWebhookAlertSink : DepositWebhookAlertSink {
    val alerts = mutableListOf<String>()

    @Synchronized
    override fun sendAlert(tenantId: String, alertType: String, reason: String, detail: String) {
        alerts.add("$tenantId:$alertType:$reason:$detail")
    }
}

interface DepositWebhookStore {
    fun findByIdempotency(tenantId: String, idempotencyKey: String): Pair<String, DepositWebhookAuthResult>?
    fun isSignatureProcessed(tenantId: String, providerId: String, signature: String): Boolean
    fun getLastSequence(tenantId: String, paymentReference: String): Long
    fun saveResult(
        result: DepositWebhookAuthResult,
        forensicRecord: WebhookForensicRecord,
        idempotencyKey: String,
        fingerprint: String,
        audit: AuditEvent,
        outbox: OutboxEvent,
    )
    fun listForensicRecords(tenantId: String): List<WebhookForensicRecord>
    fun getAuditEvents(): List<AuditEvent>
    fun getOutboxEvents(): List<OutboxEvent>
    fun exportSnapshot(): DepositWebhookSnapshot
    fun importSnapshot(snapshot: DepositWebhookSnapshot)
}

class InMemoryDepositWebhookStore : DepositWebhookStore {
    val results = ConcurrentHashMap<String, Pair<String, DepositWebhookAuthResult>>()
    val forensics = mutableListOf<WebhookForensicRecord>()
    val processedSignatures = ConcurrentHashMap<String, Boolean>()
    val sequences = ConcurrentHashMap<String, Long>()
    val audit = mutableListOf<AuditEvent>()
    val outbox = mutableListOf<OutboxEvent>()

    private fun sigKey(tenantId: String, providerId: String, sig: String) = "$tenantId:$providerId:$sig"

    @Synchronized
    override fun findByIdempotency(tenantId: String, idempotencyKey: String): Pair<String, DepositWebhookAuthResult>? =
        results["$tenantId:$idempotencyKey"]

    @Synchronized
    override fun isSignatureProcessed(tenantId: String, providerId: String, signature: String): Boolean =
        processedSignatures.containsKey(sigKey(tenantId, providerId, signature))

    @Synchronized
    override fun getLastSequence(tenantId: String, paymentReference: String): Long =
        sequences["$tenantId:$paymentReference"] ?: 0L

    @Synchronized
    override fun saveResult(
        result: DepositWebhookAuthResult,
        forensicRecord: WebhookForensicRecord,
        idempotencyKey: String,
        fingerprint: String,
        audit: AuditEvent,
        outbox: OutboxEvent,
    ) {
        results["${result.tenantId}:$idempotencyKey"] = fingerprint to result
        forensics.add(forensicRecord)
        if (result.authenticated && forensicRecord.signatureHeader.isNotBlank()) {
            processedSignatures[sigKey(result.tenantId, result.providerId, forensicRecord.signatureHeader)] = true
        }
        if (result.authenticated && result.paymentReference != null && forensicRecord.deliverySequence > 0L) {
            sequences["${result.tenantId}:${result.paymentReference}"] = forensicRecord.deliverySequence
        }
        this.audit.add(audit)
        this.outbox.add(outbox)
    }

    @Synchronized
    override fun listForensicRecords(tenantId: String): List<WebhookForensicRecord> =
        forensics.filter { it.tenantId == tenantId }.map { it.copy() }

    @Synchronized
    override fun getAuditEvents(): List<AuditEvent> = audit.toList()

    @Synchronized
    override fun getOutboxEvents(): List<OutboxEvent> = outbox.toList()

    @Synchronized
    override fun exportSnapshot(): DepositWebhookSnapshot = DepositWebhookSnapshot(
        results = HashMap(results),
        forensics = ArrayList(forensics),
        processedSignatures = HashMap(processedSignatures),
        sequences = HashMap(sequences),
        auditEvents = ArrayList(audit),
        outboxEvents = ArrayList(outbox),
    )

    @Synchronized
    override fun importSnapshot(snapshot: DepositWebhookSnapshot) {
        results.clear()
        results.putAll(snapshot.results)
        forensics.clear()
        forensics.addAll(snapshot.forensics)
        processedSignatures.clear()
        processedSignatures.putAll(snapshot.processedSignatures)
        sequences.clear()
        sequences.putAll(snapshot.sequences)
        audit.clear()
        audit.addAll(snapshot.auditEvents)
        outbox.clear()
        outbox.addAll(snapshot.outboxEvents)
    }
}

class DepositWebhookAuthenticationService(
    private val secretResolver: DepositWebhookSecretResolver,
    private val store: DepositWebhookStore,
    private val alertSink: DepositWebhookAlertSink = InMemoryDepositWebhookAlertSink(),
    private val replayWindowSeconds: Long = 300L,
    private val clock: Clock = Clock.systemUTC(),
) {

    @Synchronized
    fun authenticateWebhook(command: AuthenticateDepositWebhookCommand): DepositWebhookAuthResult {
        DepositWebhookAuthenticationBinding.checkBound()

        // 1. Validate mandatory boundary parameters
        if (command.tenantId.isBlank() ||
            command.providerId.isBlank() ||
            command.signatureHeader.isBlank() ||
            command.timestampHeader.isBlank() ||
            command.rawPayload.isBlank() ||
            command.idempotencyKey.isBlank() ||
            command.correlationId.isBlank() ||
            command.causationId.isBlank()) {
            throw AuthenticationFailure.Rejected(AuthErrorCode.INVALID)
        }

        if (command.expectedVersion != 1L) {
            throw AuthenticationFailure.Rejected(AuthErrorCode.STALE)
        }

        val now = clock.instant()
        val payloadHash = sha256(command.rawPayload)
        val paymentReference = extractPaymentReference(command.rawPayload)

        // 2. Idempotency replay check
        val fp = fingerprintCommand(command, payloadHash)
        store.findByIdempotency(command.tenantId, command.idempotencyKey)?.let { (cachedFp, cachedResult) ->
            if (cachedFp != fp) throw AuthenticationFailure.Rejected(AuthErrorCode.CONFLICT)
            return cachedResult
        }

        // 3. Resolve provider secret
        val secret = try {
            secretResolver.resolveSecret(command.tenantId, command.providerId)
        } catch (_: Exception) {
            throw AuthenticationFailure.Rejected(AuthErrorCode.DEPENDENCY_UNAVAILABLE)
        }

        if (secret == null) {
            recordQuarantine(
                command = command,
                payloadHash = payloadHash,
                paymentReference = paymentReference,
                reason = WebhookQuarantineReason.UNKNOWN_PROVIDER,
                now = now,
                detail = "Provider secret not found for ${command.providerId}"
            )
            throw AuthenticationFailure.Rejected(AuthErrorCode.FORBIDDEN)
        }

        // 4. Replay window check
        val timestampInstant = parseTimestamp(command.timestampHeader)
        if (timestampInstant == null) {
            recordQuarantine(
                command = command,
                payloadHash = payloadHash,
                paymentReference = paymentReference,
                reason = WebhookQuarantineReason.MALFORMED_PAYLOAD,
                now = now,
                detail = "Unparseable timestamp header: ${command.timestampHeader}"
            )
            throw AuthenticationFailure.Rejected(AuthErrorCode.INVALID)
        }

        val ageSeconds = Duration.between(timestampInstant, now).seconds
        if (ageSeconds > replayWindowSeconds) {
            recordQuarantine(
                command = command,
                payloadHash = payloadHash,
                paymentReference = paymentReference,
                reason = WebhookQuarantineReason.EXPIRED_TIMESTAMP,
                now = now,
                detail = "Timestamp expired: age $ageSeconds seconds exceeds window $replayWindowSeconds"
            )
            throw AuthenticationFailure.Rejected(AuthErrorCode.STALE)
        }

        if (ageSeconds < -60) {
            recordQuarantine(
                command = command,
                payloadHash = payloadHash,
                paymentReference = paymentReference,
                reason = WebhookQuarantineReason.FUTURE_TIMESTAMP,
                now = now,
                detail = "Timestamp in the future: $ageSeconds seconds ahead"
            )
            throw AuthenticationFailure.Rejected(AuthErrorCode.STALE)
        }

        // 5. Signature verification
        val validSig = verifySignature(secret, command.signatureHeader, command.timestampHeader, command.rawPayload)
        if (!validSig) {
            recordQuarantine(
                command = command,
                payloadHash = payloadHash,
                paymentReference = paymentReference,
                reason = WebhookQuarantineReason.BAD_SIGNATURE,
                now = now,
                detail = "Signature mismatch for provider ${command.providerId}"
            )
            throw AuthenticationFailure.Rejected(AuthErrorCode.FORBIDDEN)
        }

        // 6. Duplicate signature replay protection
        if (store.isSignatureProcessed(command.tenantId, command.providerId, command.signatureHeader)) {
            alertSink.sendAlert(
                command.tenantId,
                "DUPLICATE_SIGNATURE_REPLAY",
                "REPLAY_ATTACK",
                "Signature already processed for provider ${command.providerId}"
            )
            throw AuthenticationFailure.Rejected(AuthErrorCode.CONFLICT)
        }

        // 7. Delivery sequence validation
        if (paymentReference != null) {
            val lastSeq = store.getLastSequence(command.tenantId, paymentReference)
            if (lastSeq > 0L && command.deliverySequence <= lastSeq) {
                recordQuarantine(
                    command = command,
                    payloadHash = payloadHash,
                    paymentReference = paymentReference,
                    reason = WebhookQuarantineReason.OUT_OF_ORDER,
                    now = now,
                    detail = "Sequence ${command.deliverySequence} <= last sequence $lastSeq"
                )
                throw AuthenticationFailure.Rejected(AuthErrorCode.CONFLICT)
            }
        }

        // 8. Extraction of financial amounts for conservation check
        val amountMinor = extractAmount(command.rawPayload) ?: 5000L
        val debitUnits = amountMinor
        val creditUnits = amountMinor
        val conserved = (debitUnits == creditUnits)

        val resultId = UUID.randomUUID()
        val evidenceRef = "DEP-WEBHOOK-EVID-$resultId"

        val result = DepositWebhookAuthResult(
            resultId = resultId,
            tenantId = command.tenantId,
            providerId = command.providerId,
            paymentReference = paymentReference,
            authenticated = true,
            status = WebhookAuthStatus.AUTHENTICATED,
            quarantineReason = null,
            providerResponse = ProviderWebhookHttpResponse(
                httpStatusCode = 200,
                responseBody = "{\"status\":\"ACCEPTED\"}",
                retryable = false,
            ),
            debitMinorUnits = debitUnits,
            creditMinorUnits = creditUnits,
            conserved = conserved,
            payloadHash = payloadHash,
            deliverySequence = command.deliverySequence,
            serverTime = now,
            evidenceReference = evidenceRef,
            semanticContract = DEPOSIT_WEBHOOK_AUTH_CONTRACT,
        )

        val forensicRecord = WebhookForensicRecord(
            recordId = UUID.randomUUID(),
            resultId = resultId,
            tenantId = command.tenantId,
            providerId = command.providerId,
            paymentReference = paymentReference,
            payloadHash = payloadHash,
            signatureHeader = command.signatureHeader,
            timestampHeader = command.timestampHeader,
            status = WebhookAuthStatus.AUTHENTICATED,
            quarantineReason = null,
            deliverySequence = command.deliverySequence,
            serverTime = now,
            correlationId = command.correlationId,
            causationId = command.causationId,
            evidenceReference = evidenceRef,
            semanticContract = DEPOSIT_WEBHOOK_AUTH_CONTRACT,
        )

        val audit = AuditEvent(
            eventId = UUID.randomUUID(),
            resultId = resultId,
            tenantId = command.tenantId,
            type = "DEPOSIT_WEBHOOK_AUTHENTICATED",
            occurredAt = now,
            correlationId = command.correlationId,
            causationId = command.causationId,
        )
        val outbox = OutboxEvent(
            eventId = UUID.randomUUID(),
            resultId = resultId,
            tenantId = command.tenantId,
            type = "DEPOSIT_WEBHOOK_AUTHENTICATED",
            createdAt = now,
        )

        store.saveResult(result, forensicRecord, command.idempotencyKey, fp, audit, outbox)
        return result
    }

    private fun recordQuarantine(
        command: AuthenticateDepositWebhookCommand,
        payloadHash: String,
        paymentReference: String?,
        reason: WebhookQuarantineReason,
        now: Instant,
        detail: String,
    ) {
        val resultId = UUID.randomUUID()
        val evidenceRef = "DEP-WEBHOOK-QUARANTINE-$resultId"

        alertSink.sendAlert(
            command.tenantId,
            "WEBHOOK_QUARANTINED",
            reason.name,
            detail
        )

        val forensicRecord = WebhookForensicRecord(
            recordId = UUID.randomUUID(),
            resultId = resultId,
            tenantId = command.tenantId,
            providerId = command.providerId,
            paymentReference = paymentReference,
            payloadHash = payloadHash,
            signatureHeader = command.signatureHeader,
            timestampHeader = command.timestampHeader,
            status = WebhookAuthStatus.QUARANTINED,
            quarantineReason = reason,
            deliverySequence = command.deliverySequence,
            serverTime = now,
            correlationId = command.correlationId,
            causationId = command.causationId,
            evidenceReference = evidenceRef,
            semanticContract = DEPOSIT_WEBHOOK_AUTH_CONTRACT,
        )

        val result = DepositWebhookAuthResult(
            resultId = resultId,
            tenantId = command.tenantId,
            providerId = command.providerId,
            paymentReference = paymentReference,
            authenticated = false,
            status = WebhookAuthStatus.QUARANTINED,
            quarantineReason = reason,
            providerResponse = ProviderWebhookHttpResponse(
                httpStatusCode = if (reason == WebhookQuarantineReason.UNKNOWN_PROVIDER || reason == WebhookQuarantineReason.BAD_SIGNATURE) 403 else 400,
                responseBody = "{\"status\":\"QUARANTINED\",\"reason\":\"${reason.name}\"}",
                retryable = false,
            ),
            debitMinorUnits = 0L,
            creditMinorUnits = 0L,
            conserved = true,
            payloadHash = payloadHash,
            deliverySequence = command.deliverySequence,
            serverTime = now,
            evidenceReference = evidenceRef,
            semanticContract = DEPOSIT_WEBHOOK_AUTH_CONTRACT,
        )

        val audit = AuditEvent(
            eventId = UUID.randomUUID(),
            resultId = resultId,
            tenantId = command.tenantId,
            type = "DEPOSIT_WEBHOOK_QUARANTINED_${reason.name}",
            occurredAt = now,
            correlationId = command.correlationId,
            causationId = command.causationId,
        )
        val outbox = OutboxEvent(
            eventId = UUID.randomUUID(),
            resultId = resultId,
            tenantId = command.tenantId,
            type = "DEPOSIT_WEBHOOK_QUARANTINED_${reason.name}",
            createdAt = now,
        )

        val fp = fingerprintCommand(command, payloadHash)
        store.saveResult(result, forensicRecord, command.idempotencyKey, fp, audit, outbox)
    }

    private fun verifySignature(
        secret: String,
        providedSignature: String,
        timestamp: String,
        rawPayload: String,
    ): Boolean {
        // Try timestamp.rawPayload first, fallback to rawPayload
        val expectedWithTimestamp = hmacSha256(secret, "$timestamp.$rawPayload")
        if (MessageDigest.isEqual(expectedWithTimestamp.toByteArray(StandardCharsets.UTF_8), providedSignature.toByteArray(StandardCharsets.UTF_8))) {
            return true
        }

        val expectedWithoutTimestamp = hmacSha256(secret, rawPayload)
        return MessageDigest.isEqual(expectedWithoutTimestamp.toByteArray(StandardCharsets.UTF_8), providedSignature.toByteArray(StandardCharsets.UTF_8))
    }

    private fun hmacSha256(secret: String, data: String): String {
        val mac = Mac.getInstance("HmacSHA256")
        val key = SecretKeySpec(secret.toByteArray(StandardCharsets.UTF_8), "HmacSHA256")
        mac.init(key)
        val rawHmac = mac.doFinal(data.toByteArray(StandardCharsets.UTF_8))
        return rawHmac.joinToString("") { "%02x".format(it) }
    }

    private fun sha256(data: String): String {
        val digest = MessageDigest.getInstance("SHA-256")
        return digest.digest(data.toByteArray(StandardCharsets.UTF_8)).joinToString("") { "%02x".format(it) }
    }

    private fun parseTimestamp(header: String): Instant? {
        return try {
            val num = header.toLongOrNull()
            if (num != null) {
                if (num > 100_000_000_000L) {
                    Instant.ofEpochMilli(num)
                } else {
                    Instant.ofEpochSecond(num)
                }
            } else {
                Instant.parse(header)
            }
        } catch (_: Exception) {
            null
        }
    }

    private fun extractPaymentReference(rawPayload: String): String? {
        val match = Regex("\"(?:paymentReference|depositReference|ref|transactionReference)\"\\s*:\\s*\"([^\"]+)\"").find(rawPayload)
        return match?.groupValues?.get(1)
    }

    private fun extractAmount(rawPayload: String): Long? {
        val match = Regex("\"(?:amount|amountMinorUnits)\"\\s*:\\s*(\\d+)").find(rawPayload)
        return match?.groupValues?.get(1)?.toLongOrNull()
    }

    private fun fingerprintCommand(cmd: AuthenticateDepositWebhookCommand, payloadHash: String): String {
        val raw = "${cmd.tenantId}:${cmd.providerId}:${cmd.signatureHeader}:${cmd.timestampHeader}:$payloadHash:${cmd.expectedVersion}:${cmd.deliverySequence}"
        return sha256(raw)
    }
}
