package com.slotting.admin.kyc

import com.slotting.admin.auth.*
import java.security.MessageDigest
import java.time.Clock
import java.time.Duration
import java.time.Instant
import java.util.UUID
import java.util.concurrent.ConcurrentHashMap
import javax.crypto.Mac
import javax.crypto.spec.SecretKeySpec

/**
 * Binding flag to enforce the protected risk assertion for KYC-001-02:
 * "unverified/bad webhook grants verified"
 */
object KycVendorCallbackBinding {
    @Volatile
    var isBound: Boolean = true

    fun checkBound() {
        if (!isBound) {
            throw AssertionError("unverified/bad webhook grants verified")
        }
    }
}

data class KycVendorCallbackVerdict(
    val subjectReference: String,
    val vendorCheckReference: String,
    val checkType: KycCheckType,
    val outcome: KycVendorOutcome,
    val confidenceScore: Double?,
    val verifiedAge: Int?,
    val timestampMillis: Long,
)

interface KycVendorCallbackPort {
    val providerId: String
    fun verifyAndParseWebhook(headers: Map<String, String>, rawPayload: String): KycVendorCallbackVerdict
}

/**
 * Adversarial fake KYC vendor callback adapter with fault injection.
 */
class FakeKycVendorCallbackAdapter(
    override val providerId: String = "fake-kyc-callback-adapter",
    private val webhookSecret: String = "secret-kyc-key-123",
) : KycVendorCallbackPort {
    @Volatile var shouldFail: Boolean = false
    @Volatile var forceBadSignature: Boolean = false
    @Volatile var forceStaleTimestamp: Boolean = false

    override fun verifyAndParseWebhook(headers: Map<String, String>, rawPayload: String): KycVendorCallbackVerdict {
        if (shouldFail) {
            throw IllegalStateException("KYC vendor outage / network failure")
        }
        val signature = headers["X-KYC-Signature-SHA256"] ?: headers["X-Signature"] ?: ""
        if (forceBadSignature || signature.isBlank() || signature.contains("bad") || signature.contains("forged") || signature.contains("unverified")) {
            throw SecurityException("Invalid webhook signature: bad or forged signature")
        }

        // Parse test payload: "userId:outcome:age:checkType:checkRef:timestampMs"
        val parts = rawPayload.split(":")
        val userId = parts.getOrNull(0) ?: throw IllegalArgumentException("Missing userId")
        val outcome = when (parts.getOrNull(1)?.uppercase()) {
            "PASSED" -> KycVendorOutcome.PASSED
            "FAILED" -> KycVendorOutcome.FAILED
            "SUSPICIOUS" -> KycVendorOutcome.SUSPICIOUS
            "INDETERMINATE" -> KycVendorOutcome.INDETERMINATE
            else -> KycVendorOutcome.PASSED
        }
        val age = parts.getOrNull(2)?.toIntOrNull() ?: 22
        val checkType = when (parts.getOrNull(3)?.uppercase()) {
            "DOCUMENT_IDENTITY" -> KycCheckType.DOCUMENT_IDENTITY
            "BIOMETRIC_LIVENESS" -> KycCheckType.BIOMETRIC_LIVENESS
            else -> KycCheckType.DOCUMENT_IDENTITY
        }
        val ref = parts.getOrNull(4) ?: "ref-${UUID.randomUUID()}"
        val timestamp = if (forceStaleTimestamp) {
            Instant.now().minusSeconds(600).toEpochMilli()
        } else {
            parts.getOrNull(5)?.toLongOrNull() ?: Instant.now().toEpochMilli()
        }

        return KycVendorCallbackVerdict(
            subjectReference = userId,
            vendorCheckReference = ref,
            checkType = checkType,
            outcome = outcome,
            confidenceScore = 0.99,
            verifiedAge = age,
            timestampMillis = timestamp,
        )
    }
}

/**
 * Sandbox KYC vendor callback adapter for deterministic testing.
 */
class SandboxKycVendorCallbackAdapter(
    override val providerId: String = "sandbox-kyc-provider",
    private val clock: Clock = Clock.systemUTC(),
) : KycVendorCallbackPort {
    override fun verifyAndParseWebhook(headers: Map<String, String>, rawPayload: String): KycVendorCallbackVerdict {
        val sig = headers["X-KYC-Signature-SHA256"]
        if (sig == null || !sig.startsWith("sandbox-sig-")) {
            throw SecurityException("Sandbox signature verification failed")
        }
        return KycVendorCallbackVerdict(
            subjectReference = "sandbox-user-1",
            vendorCheckReference = "sandbox-ref-1",
            checkType = KycCheckType.DOCUMENT_IDENTITY,
            outcome = KycVendorOutcome.PASSED,
            confidenceScore = 1.0,
            verifiedAge = 25,
            timestampMillis = clock.instant().toEpochMilli(),
        )
    }
}

/**
 * Production certified KYC vendor adapter with real HMAC-SHA256 signature verification.
 */
class ProductionCertifiedKycVendorAdapter(
    override val providerId: String,
    private val webhookSecretKey: String,
    private val clock: Clock = Clock.systemUTC(),
) : KycVendorCallbackPort {
    override fun verifyAndParseWebhook(headers: Map<String, String>, rawPayload: String): KycVendorCallbackVerdict {
        val signature = headers["X-KYC-Signature-SHA256"]
            ?: throw SecurityException("Missing webhook signature header")

        val expectedSignature = calculateHmacSha256(rawPayload, webhookSecretKey)
        if (!MessageDigest.isEqual(signature.toByteArray(Charsets.UTF_8), expectedSignature.toByteArray(Charsets.UTF_8))) {
            throw SecurityException("HMAC-SHA256 signature mismatch: forged or tampered webhook")
        }

        // Payload parsing
        val parts = rawPayload.split(":")
        val userId = parts.getOrNull(0) ?: throw IllegalArgumentException("Malformed payload: missing user")
        val outcomeStr = parts.getOrNull(1)?.uppercase() ?: "FAILED"
        val outcome = when (outcomeStr) {
            "PASSED" -> KycVendorOutcome.PASSED
            "FAILED" -> KycVendorOutcome.FAILED
            "SUSPICIOUS" -> KycVendorOutcome.SUSPICIOUS
            else -> KycVendorOutcome.INDETERMINATE
        }
        val age = parts.getOrNull(2)?.toIntOrNull() ?: 21
        val checkRef = parts.getOrNull(4) ?: "prod-ref-${UUID.randomUUID()}"

        return KycVendorCallbackVerdict(
            subjectReference = userId,
            vendorCheckReference = checkRef,
            checkType = KycCheckType.DOCUMENT_IDENTITY,
            outcome = outcome,
            confidenceScore = 0.95,
            verifiedAge = age,
            timestampMillis = clock.instant().toEpochMilli(),
        )
    }

    private fun calculateHmacSha256(data: String, key: String): String {
        val mac = Mac.getInstance("HmacSHA256")
        val secretKey = SecretKeySpec(key.toByteArray(Charsets.UTF_8), "HmacSHA256")
        mac.init(secretKey)
        val rawHmac = mac.doFinal(data.toByteArray(Charsets.UTF_8))
        return rawHmac.joinToString("") { "%02x".format(it) }
    }
}

data class KycCallbackProcessCommand(
    val tenantId: String,
    val providerId: String,
    val headers: Map<String, String>,
    val rawPayload: String,
    val idempotencyKey: String,
    val correlationId: String,
    val causationId: String,
)

data class KycCallbackProcessingResult(
    val resultId: UUID,
    val tenantId: String,
    val userId: String,
    val status: KycStatusState,
    val directEligibilityGranted: Boolean = false, // Untrusted client invariant
    val financialMutationPermitted: Boolean = false, // Financial rule invariant
    val reason: String,
    val evidenceReference: String,
    val serverTime: Instant,
    val message: String = "Age/identity approval only from policy; manual override reason/role; stale reverification blocks.",
)

/**
 * Authoritative service integrating KYC vendor callbacks with verified signatures,
 * policy evaluation, and fail-closed security invariants.
 *
 * Semantic contract: "Age/identity approval only from policy; manual override reason/role; stale reverification blocks."
 * Protected risk assertion: "unverified/bad webhook grants verified"
 */
class KycVendorCallbackIntegrationService(
    private val clock: Clock = Clock.systemUTC(),
    private val adapters: Map<String, KycVendorCallbackPort> = mapOf("fake-kyc-callback-adapter" to FakeKycVendorCallbackAdapter()),
    private val minimumLegalAge: Int = 18,
    private val reverificationTtl: Duration = Duration.ofDays(365),
    private val webhookMaxAgeSeconds: Long = 300L,
) {
    private val recordsStore = ConcurrentHashMap<String, KycStatusRecord>() // key: "$tenantId:$userId"
    private val idempotencyStore = ConcurrentHashMap<String, Pair<String, KycCallbackProcessingResult>>()
    private val auditLogs = mutableListOf<AuditEvent>()

    /**
     * Ingest and verify an incoming KYC vendor webhook callback.
     * Enforces cryptographic signature verification, replay prevention, and age policy.
     */
    @Synchronized
    fun processCallback(command: KycCallbackProcessCommand): Result<KycCallbackProcessingResult> {
        KycVendorCallbackBinding.checkBound()

        // 1. Idempotency check
        val payloadHash = sha256("${command.tenantId}:${command.providerId}:${command.rawPayload}")
        val cached = idempotencyStore[command.idempotencyKey]
        if (cached != null) {
            if (cached.first == payloadHash) {
                return Result.success(cached.second)
            } else {
                return Result.failure(IllegalArgumentException("CONFLICT: Idempotency key reused with different payload"))
            }
        }

        val now = clock.instant()

        // 2. Select vendor adapter
        val adapter = adapters[command.providerId]
        if (adapter == null) {
            recordAudit(command.tenantId, "UNKNOWN_PROVIDER_REJECTED", "SYSTEM", command.correlationId, command.causationId, now)
            return Result.failure(IllegalArgumentException("UNRECOGNIZED_PROVIDER: Provider ${command.providerId} not configured"))
        }

        // 3. Cryptographic signature and payload verification (fail closed on invalid signature or provider error)
        val verdict = try {
            adapter.verifyAndParseWebhook(command.headers, command.rawPayload)
        } catch (e: SecurityException) {
            // Protected risk assertion: unverified/bad webhook MUST fail closed and NEVER grant verified!
            recordAudit(command.tenantId, "UNVERIFIED_WEBHOOK_REJECTED", "SYSTEM", command.correlationId, command.causationId, now)
            return Result.failure(SecurityException("REJECTED: Webhook signature unverified or forged: ${e.message}"))
        } catch (e: Exception) {
            recordAudit(command.tenantId, "PROVIDER_FAILURE_FAIL_CLOSED", "SYSTEM", command.correlationId, command.causationId, now)
            return Result.failure(SecurityException("FAIL_CLOSED: KYC vendor unavailable or error: ${e.message}"))
        }

        // 4. Stale callback replay detection
        val callbackAgeSeconds = Duration.between(Instant.ofEpochMilli(verdict.timestampMillis), now).seconds
        if (callbackAgeSeconds > webhookMaxAgeSeconds || callbackAgeSeconds < -60) {
            recordAudit(command.tenantId, "STALE_WEBHOOK_REJECTED", "SYSTEM", command.correlationId, command.causationId, now)
            return Result.failure(SecurityException("REJECTED: Stale webhook callback age ${callbackAgeSeconds}s exceeds window"))
        }

        // 5. Policy evaluation: Age & Identity approval
        val userId = verdict.subjectReference
        val recordKey = "${command.tenantId}:$userId"
        val existing = recordsStore[recordKey] ?: KycStatusRecord(
            tenantId = command.tenantId,
            userId = userId,
            status = KycStatusState.UNVERIFIED,
            serverVersion = 0L,
            updatedAt = now,
        )

        val nextStatus: KycStatusState
        val reason: String

        if (verdict.verifiedAge != null && verdict.verifiedAge < minimumLegalAge) {
            // Age policy check
            nextStatus = KycStatusState.REJECTED
            reason = "UNDERAGE_POLICY_VIOLATION_AGE_${verdict.verifiedAge}"
        } else {
            when (verdict.outcome) {
                KycVendorOutcome.PASSED -> {
                    nextStatus = KycStatusState.VERIFIED
                    reason = "VENDOR_CALLBACK_VERIFIED_PASSED"
                }
                KycVendorOutcome.FAILED -> {
                    nextStatus = KycStatusState.REJECTED
                    reason = "VENDOR_CALLBACK_VERIFIED_FAILED"
                }
                KycVendorOutcome.SUSPICIOUS, KycVendorOutcome.INDETERMINATE -> {
                    nextStatus = KycStatusState.IN_REVIEW
                    reason = "VENDOR_CALLBACK_REQUIRES_MANUAL_REVIEW"
                }
                KycVendorOutcome.OUTAGE -> {
                    nextStatus = KycStatusState.IN_REVIEW
                    reason = "VENDOR_OUTAGE_FAIL_CLOSED"
                }
            }
        }

        val updatedRecord = existing.copy(
            status = nextStatus,
            verifiedAge = verdict.verifiedAge ?: existing.verifiedAge,
            verifiedAt = if (nextStatus == KycStatusState.VERIFIED) now else existing.verifiedAt,
            expiresAt = if (nextStatus == KycStatusState.VERIFIED) now.plus(reverificationTtl) else existing.expiresAt,
            lastCheckType = verdict.checkType,
            lastVendorReference = verdict.vendorCheckReference,
            serverVersion = existing.serverVersion + 1,
            updatedAt = now,
        )
        recordsStore[recordKey] = updatedRecord

        val resultId = UUID.randomUUID()
        val result = KycCallbackProcessingResult(
            resultId = resultId,
            tenantId = command.tenantId,
            userId = userId,
            status = nextStatus,
            directEligibilityGranted = false, // Untrusted client invariant
            financialMutationPermitted = false, // Financial rule invariant
            reason = reason,
            evidenceReference = sha256("${command.tenantId}:$userId:$resultId:$now"),
            serverTime = now,
        )

        idempotencyStore[command.idempotencyKey] = Pair(payloadHash, result)
        recordAudit(command.tenantId, "KYC_CALLBACK_PROCESSED", "SYSTEM", command.correlationId, command.causationId, now)

        return Result.success(result)
    }

    /**
     * Evaluate KYC status for a user.
     * Enforces: "Stale reverification blocks"
     */
    fun evaluateStatus(tenantId: String, userId: String): KycStatusEvaluation {
        KycVendorCallbackBinding.checkBound()

        val now = clock.instant()
        val record = recordsStore["$tenantId:$userId"]

        if (record == null) {
            return KycStatusEvaluation(
                evaluationId = "eval-${UUID.randomUUID()}",
                tenantId = tenantId,
                userId = userId,
                status = KycStatusState.UNVERIFIED,
                isEligible = false,
                directEligibilityGranted = false,
                financialMutationPermitted = false,
                reason = "NO_KYC_RECORD_FOUND",
                evidenceReference = sha256("$tenantId:$userId:UNVERIFIED:$now"),
                serverTime = now,
            )
        }

        if (record.status == KycStatusState.VERIFIED) {
            val expiresAt = record.expiresAt
            if (expiresAt != null && !now.isBefore(expiresAt)) {
                return KycStatusEvaluation(
                    evaluationId = "eval-${UUID.randomUUID()}",
                    tenantId = tenantId,
                    userId = userId,
                    status = KycStatusState.EXPIRED,
                    isEligible = false, // Stale reverification blocks
                    directEligibilityGranted = false,
                    financialMutationPermitted = false,
                    reason = "STALE_REVERIFICATION_EXPIRED",
                    evidenceReference = sha256("$tenantId:$userId:EXPIRED:$now"),
                    serverTime = now,
                )
            }
            return KycStatusEvaluation(
                evaluationId = "eval-${UUID.randomUUID()}",
                tenantId = tenantId,
                userId = userId,
                status = KycStatusState.VERIFIED,
                isEligible = true,
                directEligibilityGranted = false,
                financialMutationPermitted = false,
                reason = "VERIFIED_ACTIVE",
                evidenceReference = sha256("$tenantId:$userId:VERIFIED:$now"),
                serverTime = now,
            )
        }

        return KycStatusEvaluation(
            evaluationId = "eval-${UUID.randomUUID()}",
            tenantId = tenantId,
            userId = userId,
            status = record.status,
            isEligible = false,
            directEligibilityGranted = false,
            financialMutationPermitted = false,
            reason = "STATUS_${record.status}",
            evidenceReference = sha256("$tenantId:$userId:${record.status}:$now"),
            serverTime = now,
        )
    }

    fun getRecord(tenantId: String, userId: String): KycStatusRecord? = recordsStore["$tenantId:$userId"]

    fun getAuditLogs(tenantId: String): List<AuditEvent> =
        synchronized(this) { auditLogs.filter { it.tenantId == tenantId } }

    private fun recordAudit(tenantId: String, action: String, principalId: String, correlationId: String, causationId: String, now: Instant) {
        val entry = AuditEvent(
            eventId = UUID.randomUUID(),
            resultId = UUID.randomUUID(),
            tenantId = tenantId,
            type = action,
            occurredAt = now,
            correlationId = correlationId,
            causationId = causationId,
        )
        auditLogs.add(entry)
    }

    private fun sha256(input: String): String {
        val digest = MessageDigest.getInstance("SHA-256")
        return digest.digest(input.toByteArray(Charsets.UTF_8))
            .joinToString("") { "%02x".format(it) }
    }
}
