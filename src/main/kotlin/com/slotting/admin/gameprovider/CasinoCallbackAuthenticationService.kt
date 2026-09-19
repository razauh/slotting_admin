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
import javax.crypto.Mac
import javax.crypto.spec.SecretKeySpec

/**
 * Gate enforcing GAME-008-01: Authenticate casino callbacks.
 * Protected risk: "spoof/duplicate/stale payload"
 * Semantic contract: "Bad events no mutation and alert; response/retry contract provider-specific."
 */
object CasinoCallbackAuthenticationBinding {
    var isBound: Boolean = false

    fun checkBound() {
        if (!isBound) {
            throw AssertionError("spoof/duplicate/stale payload")
        }
    }
}

enum class CallbackProviderProtocol {
    PRAGMATIC_PLAY,
    EVOLUTION,
    GENERIC_HMAC,
}

data class AuthenticatedCallbackRequest(
    val tenantId: String,
    val providerId: String,
    val protocol: CallbackProviderProtocol = CallbackProviderProtocol.GENERIC_HMAC,
    val externalRoundId: String,
    val externalTransactionId: String,
    val signatureHeader: String,
    val timestampHeader: String,
    val rawPayload: String,
    val idempotencyKey: String,
    val correlationId: String,
    val causationId: String,
    val expectedVersion: Long = 1L,
)

data class ProviderCallbackResponse(
    val httpStatusCode: Int,
    val responseBody: String,
    val retryable: Boolean,
    val retryAfterSeconds: Long? = null,
)

data class AuthenticatedCallbackResult(
    val resultId: UUID,
    val tenantId: String,
    val providerId: String,
    val protocol: CallbackProviderProtocol,
    val externalRoundId: String,
    val externalTransactionId: String,
    val authenticated: Boolean,
    val providerResponse: ProviderCallbackResponse,
    val verifiedAt: Instant,
    val serverTime: Instant,
    val evidenceReference: String,
)

data class CasinoCallbackAuditRecord(
    val recordId: UUID,
    val tenantId: String,
    val providerId: String,
    val externalRoundId: String,
    val externalTransactionId: String,
    val signature: String,
    val timestamp: Long,
    val authenticated: Boolean,
    val outcome: String,
    val recordedAt: Instant,
    val correlationId: String,
    val causationId: String,
    val evidenceReference: String,
)

interface CasinoCallbackAlertSink {
    fun sendAlert(tenantId: String, severity: String, alertType: String, detail: String)
}

class InMemoryCasinoCallbackAlertSink : CasinoCallbackAlertSink {
    val alerts = mutableListOf<String>()

    @Synchronized
    override fun sendAlert(tenantId: String, severity: String, alertType: String, detail: String) {
        alerts.add("$tenantId:$severity:$alertType:$detail")
    }
}

interface CasinoCallbackSecretResolver {
    fun resolveSecret(tenantId: String, providerId: String): String?
}

class InMemoryCasinoCallbackSecretResolver(
    private val secrets: MutableMap<String, String> = ConcurrentHashMap(),
) : CasinoCallbackSecretResolver {
    fun setSecret(tenantId: String, providerId: String, secret: String) {
        secrets["$tenantId:$providerId"] = secret
    }

    override fun resolveSecret(tenantId: String, providerId: String): String? {
        return secrets["$tenantId:$providerId"]
    }
}

interface CasinoCallbackStore {
    fun findByIdempotency(tenantId: String, idempotencyKey: String): Pair<String, AuthenticatedCallbackResult>?
    fun isSignatureProcessed(tenantId: String, providerId: String, signature: String): Boolean
    fun saveCallback(
        record: CasinoCallbackAuditRecord,
        result: AuthenticatedCallbackResult,
        idempotencyKey: String,
        fingerprint: String,
        audit: AuditEvent,
        outbox: OutboxEvent,
    )
    fun listAuditRecords(tenantId: String): List<CasinoCallbackAuditRecord>
}

class InMemoryCasinoCallbackStore : CasinoCallbackStore {
    private val auditRecords = ConcurrentHashMap<UUID, CasinoCallbackAuditRecord>()
    private val idempotency = ConcurrentHashMap<String, Pair<String, AuthenticatedCallbackResult>>()
    private val processedSignatures = ConcurrentHashMap<String, Boolean>()
    val auditEvents = mutableListOf<AuditEvent>()
    val outboxEvents = mutableListOf<OutboxEvent>()

    private fun sigKey(tenantId: String, providerId: String, sig: String) = "$tenantId:$providerId:$sig"

    @Synchronized
    override fun findByIdempotency(tenantId: String, idempotencyKey: String): Pair<String, AuthenticatedCallbackResult>? {
        return idempotency["$tenantId:$idempotencyKey"]
    }

    @Synchronized
    override fun isSignatureProcessed(tenantId: String, providerId: String, signature: String): Boolean {
        return processedSignatures.containsKey(sigKey(tenantId, providerId, signature))
    }

    @Synchronized
    override fun saveCallback(
        record: CasinoCallbackAuditRecord,
        result: AuthenticatedCallbackResult,
        idempotencyKey: String,
        fingerprint: String,
        audit: AuditEvent,
        outbox: OutboxEvent,
    ) {
        auditRecords[record.recordId] = record.copy()
        idempotency["${record.tenantId}:$idempotencyKey"] = fingerprint to result
        processedSignatures[sigKey(record.tenantId, record.providerId, record.signature)] = true
        auditEvents.add(audit)
        outboxEvents.add(outbox)
    }

    @Synchronized
    override fun listAuditRecords(tenantId: String): List<CasinoCallbackAuditRecord> {
        return auditRecords.values.filter { it.tenantId == tenantId }.map { it.copy() }
    }
}

class CasinoCallbackAuthenticationService(
    private val secretResolver: CasinoCallbackSecretResolver,
    private val store: CasinoCallbackStore,
    private val alertSink: CasinoCallbackAlertSink = InMemoryCasinoCallbackAlertSink(),
    private val clock: Clock = Clock.systemUTC(),
    private val maxTimestampSkewSeconds: Long = 300L,
) {
    private fun sha256(input: String): String {
        val digest = MessageDigest.getInstance("SHA-256")
        val hash = digest.digest(input.toByteArray(StandardCharsets.UTF_8))
        return hash.joinToString("") { "%02x".format(it) }
    }

    private fun computeHmac(secret: String, data: String): String {
        val mac = Mac.getInstance("HmacSHA256")
        mac.init(SecretKeySpec(secret.toByteArray(StandardCharsets.UTF_8), "HmacSHA256"))
        return mac.doFinal(data.toByteArray(StandardCharsets.UTF_8)).joinToString("") { "%02x".format(it) }
    }

    private fun fingerprint(req: AuthenticatedCallbackRequest): String {
        return sha256("${req.tenantId}:${req.providerId}:${req.protocol}:${req.externalRoundId}:${req.externalTransactionId}:${req.rawPayload}:${req.timestampHeader}:${req.expectedVersion}")
    }

    private fun formatProviderSuccessResponse(protocol: CallbackProviderProtocol, resultId: UUID): ProviderCallbackResponse {
        return when (protocol) {
            CallbackProviderProtocol.PRAGMATIC_PLAY -> ProviderCallbackResponse(
                httpStatusCode = 200,
                responseBody = """{"error":0,"description":"Success","resultId":"$resultId"}""",
                retryable = false,
            )
            CallbackProviderProtocol.EVOLUTION -> ProviderCallbackResponse(
                httpStatusCode = 200,
                responseBody = """{"status":"OK","sid":"$resultId"}""",
                retryable = false,
            )
            CallbackProviderProtocol.GENERIC_HMAC -> ProviderCallbackResponse(
                httpStatusCode = 200,
                responseBody = """{"authenticated":true,"resultId":"$resultId","code":"PROCESSED"}""",
                retryable = false,
            )
        }
    }

    private fun formatProviderFailureResponse(protocol: CallbackProviderProtocol, errorCode: AuthErrorCode, reason: String): ProviderCallbackResponse {
        return when (protocol) {
            CallbackProviderProtocol.PRAGMATIC_PLAY -> {
                val pErrCode = when (errorCode) {
                    AuthErrorCode.FORBIDDEN -> 5 // Invalid hash / signature
                    AuthErrorCode.INVALID -> 4 // Bad parameter / timestamp
                    AuthErrorCode.DEPENDENCY_UNAVAILABLE -> 120 // Internal service error
                    else -> 1
                }
                ProviderCallbackResponse(
                    httpStatusCode = if (errorCode == AuthErrorCode.DEPENDENCY_UNAVAILABLE) 503 else 400,
                    responseBody = """{"error":$pErrCode,"description":"$reason"}""",
                    retryable = (errorCode == AuthErrorCode.DEPENDENCY_UNAVAILABLE),
                    retryAfterSeconds = if (errorCode == AuthErrorCode.DEPENDENCY_UNAVAILABLE) 5L else null,
                )
            }
            CallbackProviderProtocol.EVOLUTION -> {
                val status = when (errorCode) {
                    AuthErrorCode.FORBIDDEN -> "INVALID_SIGNATURE"
                    AuthErrorCode.INVALID -> "INVALID_PARAMETER"
                    AuthErrorCode.DEPENDENCY_UNAVAILABLE -> "TEMPORARY_ERROR"
                    else -> "ERROR"
                }
                ProviderCallbackResponse(
                    httpStatusCode = if (errorCode == AuthErrorCode.DEPENDENCY_UNAVAILABLE) 503 else 400,
                    responseBody = """{"status":"$status","error":"$reason"}""",
                    retryable = (errorCode == AuthErrorCode.DEPENDENCY_UNAVAILABLE),
                    retryAfterSeconds = if (errorCode == AuthErrorCode.DEPENDENCY_UNAVAILABLE) 5L else null,
                )
            }
            CallbackProviderProtocol.GENERIC_HMAC -> {
                ProviderCallbackResponse(
                    httpStatusCode = if (errorCode == AuthErrorCode.DEPENDENCY_UNAVAILABLE) 503 else 403,
                    responseBody = """{"authenticated":false,"code":"${errorCode.name}","reason":"$reason"}""",
                    retryable = (errorCode == AuthErrorCode.DEPENDENCY_UNAVAILABLE),
                    retryAfterSeconds = if (errorCode == AuthErrorCode.DEPENDENCY_UNAVAILABLE) 5L else null,
                )
            }
        }
    }

    @Synchronized
    fun authenticateCallback(request: AuthenticatedCallbackRequest): AuthenticatedCallbackResult {
        // Protected risk assertion: spoof/duplicate/stale payload
        CasinoCallbackAuthenticationBinding.checkBound()

        // 1. Basic Validation
        if (request.tenantId.isBlank() ||
            request.providerId.isBlank() ||
            request.externalRoundId.isBlank() ||
            request.externalTransactionId.isBlank() ||
            request.signatureHeader.isBlank() ||
            request.timestampHeader.isBlank() ||
            request.rawPayload.isBlank() ||
            request.idempotencyKey.isBlank() ||
            request.correlationId.isBlank() ||
            request.causationId.isBlank()
        ) {
            alertSink.sendAlert(
                tenantId = request.tenantId.ifBlank { "UNKNOWN" },
                severity = "MEDIUM",
                alertType = "CASINO_CALLBACK_INVALID_PAYLOAD",
                detail = "Callback rejected due to blank required fields",
            )
            throw AuthenticationFailure.Rejected(AuthErrorCode.INVALID)
        }

        if (request.expectedVersion != 1L) {
            throw AuthenticationFailure.Rejected(AuthErrorCode.STALE)
        }

        val now = clock.instant()

        // 2. Timestamp Skew / Stale Payload Defense (Protected Risk: stale payload)
        val timestampSec = request.timestampHeader.toLongOrNull()
        if (timestampSec == null) {
            alertSink.sendAlert(
                tenantId = request.tenantId,
                severity = "HIGH",
                alertType = "CASINO_CALLBACK_MALFORMED_TIMESTAMP",
                detail = "Non-numeric timestamp header in callback from ${request.providerId}",
            )
            throw AuthenticationFailure.Rejected(AuthErrorCode.INVALID)
        }

        val skew = Math.abs(now.epochSecond - timestampSec)
        if (skew > maxTimestampSkewSeconds) {
            // Stale or future payload!
            alertSink.sendAlert(
                tenantId = request.tenantId,
                severity = "HIGH",
                alertType = "CASINO_CALLBACK_STALE_PAYLOAD",
                detail = "Timestamp skew of $skew seconds exceeds threshold of $maxTimestampSkewSeconds for provider ${request.providerId}",
            )
            throw AuthenticationFailure.Rejected(AuthErrorCode.INVALID)
        }

        // 3. Idempotency Check (Protected Risk: duplicate delivery)
        val fp = fingerprint(request)
        store.findByIdempotency(request.tenantId, request.idempotencyKey)?.let { (cachedFp, cachedResult) ->
            if (cachedFp != fp) {
                // Changed payload under existing idempotency key
                alertSink.sendAlert(
                    tenantId = request.tenantId,
                    severity = "HIGH",
                    alertType = "CASINO_CALLBACK_IDEMPOTENCY_CONFLICT",
                    detail = "Different payload submitted under existing idempotency key ${request.idempotencyKey}",
                )
                throw AuthenticationFailure.Rejected(AuthErrorCode.CONFLICT)
            }
            return cachedResult
        }

        // 4. Resolve Provider Secret
        val secret = try {
            secretResolver.resolveSecret(request.tenantId, request.providerId)
        } catch (e: Exception) {
            alertSink.sendAlert(
                tenantId = request.tenantId,
                severity = "HIGH",
                alertType = "CASINO_CALLBACK_VAULT_FAILURE",
                detail = "Secret resolution failed for provider ${request.providerId}: ${e.message}",
            )
            throw AuthenticationFailure.Rejected(AuthErrorCode.DEPENDENCY_UNAVAILABLE)
        }

        if (secret == null) {
            alertSink.sendAlert(
                tenantId = request.tenantId,
                severity = "HIGH",
                alertType = "CASINO_CALLBACK_UNKNOWN_PROVIDER",
                detail = "No configured secret found for tenant ${request.tenantId} and provider ${request.providerId}",
            )
            throw AuthenticationFailure.Rejected(AuthErrorCode.FORBIDDEN)
        }

        // 5. Signature Verification (Protected Risk: spoof payload)
        val expectedDataToSign = "${request.timestampHeader}.${request.rawPayload}"
        val computedSignature = computeHmac(secret, expectedDataToSign)

        val isSigValid = MessageDigest.isEqual(
            computedSignature.toByteArray(StandardCharsets.UTF_8),
            request.signatureHeader.toByteArray(StandardCharsets.UTF_8),
        )

        if (!isSigValid) {
            // Bad event! Spoofing or corrupted signature detected.
            // Semantic contract: Bad events no mutation and alert!
            alertSink.sendAlert(
                tenantId = request.tenantId,
                severity = "HIGH",
                alertType = "CASINO_CALLBACK_SPOOF_ATTEMPT",
                detail = "Signature mismatch detected on callback for round ${request.externalRoundId}, tx ${request.externalTransactionId} from provider ${request.providerId}",
            )
            throw AuthenticationFailure.Rejected(AuthErrorCode.FORBIDDEN)
        }

        // 6. Successful Authentication Outcome
        val resultId = UUID.randomUUID()
        val recordId = UUID.randomUUID()
        val evidenceRef = sha256("${request.tenantId}:$resultId:${request.externalRoundId}:${request.externalTransactionId}:${now.toEpochMilli()}")

        val providerResponse = formatProviderSuccessResponse(request.protocol, resultId)

        val result = AuthenticatedCallbackResult(
            resultId = resultId,
            tenantId = request.tenantId,
            providerId = request.providerId,
            protocol = request.protocol,
            externalRoundId = request.externalRoundId,
            externalTransactionId = request.externalTransactionId,
            authenticated = true,
            providerResponse = providerResponse,
            verifiedAt = now,
            serverTime = now,
            evidenceReference = evidenceRef,
        )

        val record = CasinoCallbackAuditRecord(
            recordId = recordId,
            tenantId = request.tenantId,
            providerId = request.providerId,
            externalRoundId = request.externalRoundId,
            externalTransactionId = request.externalTransactionId,
            signature = request.signatureHeader,
            timestamp = timestampSec,
            authenticated = true,
            outcome = "VERIFIED_AUTHENTIC",
            recordedAt = now,
            correlationId = request.correlationId,
            causationId = request.causationId,
            evidenceReference = evidenceRef,
        )

        val audit = AuditEvent(
            eventId = UUID.randomUUID(),
            resultId = resultId,
            tenantId = request.tenantId,
            type = "CASINO_CALLBACK_AUTHENTICATED",
            occurredAt = now,
            correlationId = request.correlationId,
            causationId = request.causationId,
        )

        val outbox = OutboxEvent(
            eventId = UUID.randomUUID(),
            resultId = resultId,
            tenantId = request.tenantId,
            type = "CASINO_CALLBACK_AUTHENTICATED",
            createdAt = now,
        )

        store.saveCallback(record, result, request.idempotencyKey, fp, audit, outbox)
        return result
    }

    fun getFailureResponse(protocol: CallbackProviderProtocol, errorCode: AuthErrorCode, reason: String): ProviderCallbackResponse {
        return formatProviderFailureResponse(protocol, errorCode, reason)
    }
}
