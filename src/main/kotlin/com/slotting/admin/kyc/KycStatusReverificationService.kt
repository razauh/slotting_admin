package com.slotting.admin.kyc

import com.slotting.admin.auth.*
import java.security.MessageDigest
import java.time.Clock
import java.time.Duration
import java.time.Instant
import java.util.UUID
import java.util.concurrent.ConcurrentHashMap

/**
 * Binding flag to enforce the protected risk assertion for KYC-001-01:
 * "unverified/bad webhook grants verified"
 */
object KycStatusBinding {
    @Volatile
    var isBound: Boolean = true

    fun checkBound() {
        if (!isBound) {
            throw AssertionError("unverified/bad webhook grants verified")
        }
    }
}

enum class KycStatusState {
    UNVERIFIED,
    PENDING,
    IN_REVIEW,
    VERIFIED,
    REJECTED,
    REVERIFICATION_REQUIRED,
    EXPIRED,
}

enum class KycTriggerSource {
    VENDOR_WEBHOOK,
    MANUAL_OVERRIDE,
    AUTOMATED_EXPIRY_SWEEP,
    CLIENT_REVERIFICATION_REQUEST,
}

data class KycStatusRecord(
    val tenantId: String,
    val userId: String,
    val status: KycStatusState,
    val verifiedAge: Int? = null,
    val verifiedAt: Instant? = null,
    val expiresAt: Instant? = null,
    val lastCheckType: KycCheckType? = null,
    val lastVendorReference: String? = null,
    val serverVersion: Long = 0L,
    val updatedAt: Instant,
)

data class KycManualOverrideRecord(
    val overrideId: UUID,
    val tenantId: String,
    val userId: String,
    val adminId: String,
    val adminRole: AdminRole,
    val targetStatus: KycStatusState,
    val reason: String,
    val createdAt: Instant,
    val idempotencyKey: String,
    val correlationId: String,
    val causationId: String,
)

data class KycStatusTransitionLog(
    val transitionId: UUID,
    val tenantId: String,
    val userId: String,
    val fromStatus: KycStatusState,
    val toStatus: KycStatusState,
    val triggerSource: KycTriggerSource,
    val reason: String,
    val occurredAt: Instant,
    val correlationId: String,
    val causationId: String,
)

data class KycWebhookCommand(
    val tenantId: String,
    val providerId: String,
    val signature: String,
    val rawPayload: String,
    val idempotencyKey: String,
    val correlationId: String,
    val causationId: String,
)

data class KycManualOverrideCommand(
    val principal: AuthenticatedPrincipal?,
    val sessionId: String,
    val tenantId: String,
    val userId: String,
    val targetStatus: KycStatusState,
    val reason: String,
    val idempotencyKey: String,
    val correlationId: String,
    val causationId: String,
    val expectedVersion: Long,
)

data class KycReverificationCommand(
    val tenantId: String,
    val userId: String,
    val reason: String,
    val idempotencyKey: String,
    val correlationId: String,
    val causationId: String,
)

data class KycStatusEvaluation(
    val evaluationId: String,
    val tenantId: String,
    val userId: String,
    val status: KycStatusState,
    val isEligible: Boolean,
    val directEligibilityGranted: Boolean = false, // Invariant: no direct authority granted to untrusted callers
    val financialMutationPermitted: Boolean = false, // Invariant: KYC cannot mutate money
    val reason: String,
    val evidenceReference: String,
    val serverTime: Instant,
    val message: String = "Age/identity approval only from policy; manual override reason/role; stale reverification blocks.",
)

data class KycStatusTransitionResult(
    val resultId: UUID,
    val tenantId: String,
    val userId: String,
    val fromStatus: KycStatusState,
    val toStatus: KycStatusState,
    val directEligibilityGranted: Boolean = false,
    val financialMutationPermitted: Boolean = false,
    val evidenceReference: String,
    val serverTime: Instant,
    val message: String = "Age/identity approval only from policy; manual override reason/role; stale reverification blocks.",
)

data class KycVerifiedWebhookPayload(
    val subjectReference: String, // User ID
    val checkType: KycCheckType,
    val outcome: KycVendorOutcome,
    val confidenceScore: Double?,
    val vendorCheckReference: String,
    val verifiedAge: Int? = null,
)

interface KycStatusVendorAdapter {
    val providerId: String
    fun verifyWebhook(signature: String, rawPayload: String): KycVerifiedWebhookPayload?
}

/**
 * In-memory adversarial fake for KYC vendor adapter.
 */
class FakeKycStatusVendorAdapter(
    override val providerId: String = "fake-kyc-vendor-1"
) : KycStatusVendorAdapter {
    @Volatile var shouldFail: Boolean = false
    @Volatile var forceInvalidSignature: Boolean = false

    override fun verifyWebhook(signature: String, rawPayload: String): KycVerifiedWebhookPayload? {
        if (shouldFail) {
            throw IllegalStateException("KYC vendor outage/unavailable")
        }
        if (forceInvalidSignature || signature.isBlank() || signature.contains("bad") || signature.contains("forged") || signature.contains("unverified")) {
            return null
        }

        // Parse simple synthetic payload format: "userId:outcome:age:checkType:ref"
        val parts = rawPayload.split(":")
        val userId = parts.getOrNull(0) ?: return null
        val outcome = when (parts.getOrNull(1)?.uppercase()) {
            "PASSED" -> KycVendorOutcome.PASSED
            "FAILED" -> KycVendorOutcome.FAILED
            "SUSPICIOUS" -> KycVendorOutcome.SUSPICIOUS
            "INDETERMINATE" -> KycVendorOutcome.INDETERMINATE
            else -> KycVendorOutcome.PASSED
        }
        val age = parts.getOrNull(2)?.toIntOrNull() ?: 21
        val checkType = when (parts.getOrNull(3)?.uppercase()) {
            "DOCUMENT_IDENTITY" -> KycCheckType.DOCUMENT_IDENTITY
            "BIOMETRIC_LIVENESS" -> KycCheckType.BIOMETRIC_LIVENESS
            else -> KycCheckType.DOCUMENT_IDENTITY
        }
        val ref = parts.getOrNull(4) ?: "vnd-ref-${UUID.randomUUID()}"

        return KycVerifiedWebhookPayload(
            subjectReference = userId,
            checkType = checkType,
            outcome = outcome,
            confidenceScore = 0.98,
            vendorCheckReference = ref,
            verifiedAge = age,
        )
    }
}

/**
 * Authoritative KYC Status and Reverification Service.
 *
 * Semantic contract: "Age/identity approval only from policy; manual override reason/role; stale reverification blocks."
 * Protected risk assertion: "unverified/bad webhook grants verified"
 */
class KycStatusReverificationService(
    private val clock: Clock = Clock.systemUTC(),
    private val vendorAdapter: KycStatusVendorAdapter = FakeKycStatusVendorAdapter(),
    private val policy: AdminRbacPolicy = AdminRbacPolicy(dualControlRequired = false),
    private val sessionDirectory: AdminSessionDirectory = object : AdminSessionDirectory {
        override fun find(tenantId: String, principalId: String, sessionId: String): AdminSessionStatus? {
            return AdminSessionStatus(active = true, breakGlass = false, expiresAt = clock.instant().plus(Duration.ofHours(1)))
        }
    },
    private val minimumLegalAge: Int = 18,
    private val reverificationTtl: Duration = Duration.ofDays(365),
) {
    private val recordsStore = ConcurrentHashMap<String, KycStatusRecord>() // key: "$tenantId:$userId"
    private val overridesStore = ConcurrentHashMap<UUID, KycManualOverrideRecord>()
    private val transitionsLog = mutableListOf<KycStatusTransitionLog>()
    private val idempotencyStore = ConcurrentHashMap<String, Pair<String, Any>>()
    private val auditLogs = mutableListOf<AuditEvent>()

    /**
     * Process an incoming KYC vendor webhook.
     * Enforces fail-closed validation: unverified or bad webhooks never grant verified.
     * Enforces age/identity check per policy.
     */
    @Synchronized
    fun processWebhook(command: KycWebhookCommand): Result<KycStatusTransitionResult> {
        KycStatusBinding.checkBound()

        // 1. Idempotency check
        val payloadHash = sha256("${command.tenantId}:${command.providerId}:${command.signature}:${command.rawPayload}")
        val cached = idempotencyStore[command.idempotencyKey]
        if (cached != null) {
            if (cached.first == payloadHash) {
                @Suppress("UNCHECKED_CAST")
                return Result.success(cached.second as KycStatusTransitionResult)
            } else {
                return Result.failure(IllegalArgumentException("CONFLICT: Idempotency key reused with different payload"))
            }
        }

        val now = clock.instant()

        // 2. Verify webhook with vendor adapter (fail closed on signature mismatch or vendor outage)
        val verifiedPayload = try {
            vendorAdapter.verifyWebhook(command.signature, command.rawPayload)
        } catch (e: Exception) {
            recordAudit(command.tenantId, "KYC_WEBHOOK_FAILURE", "SYSTEM", command.correlationId, command.causationId, now)
            return Result.failure(SecurityException("FAIL_CLOSED: Vendor webhook verification failed: ${e.message}"))
        }

        if (verifiedPayload == null) {
            // Protected risk assertion: unverified/bad webhook must NEVER grant verified!
            recordAudit(command.tenantId, "KYC_WEBHOOK_UNVERIFIED_REJECTED", "SYSTEM", command.correlationId, command.causationId, now)
            return Result.failure(SecurityException("REJECTED: Webhook signature unverified or payload forged"))
        }

        val userId = verifiedPayload.subjectReference
        val recordKey = "${command.tenantId}:$userId"
        val existing = recordsStore[recordKey] ?: KycStatusRecord(
            tenantId = command.tenantId,
            userId = userId,
            status = KycStatusState.UNVERIFIED,
            serverVersion = 0L,
            updatedAt = now,
        )

        // 3. Policy evaluation: Age & Identity approval
        val nextStatus: KycStatusState
        val reason: String

        if (verifiedPayload.verifiedAge != null && verifiedPayload.verifiedAge < minimumLegalAge) {
            // Age policy violation -> REJECTED
            nextStatus = KycStatusState.REJECTED
            reason = "UNDERAGE_POLICY_VIOLATION_AGE_${verifiedPayload.verifiedAge}"
        } else {
            when (verifiedPayload.outcome) {
                KycVendorOutcome.PASSED -> {
                    nextStatus = KycStatusState.VERIFIED
                    reason = "VENDOR_CHECK_PASSED_AGE_VERIFIED"
                }
                KycVendorOutcome.FAILED -> {
                    nextStatus = KycStatusState.REJECTED
                    reason = "VENDOR_CHECK_FAILED"
                }
                KycVendorOutcome.SUSPICIOUS, KycVendorOutcome.INDETERMINATE -> {
                    nextStatus = KycStatusState.IN_REVIEW
                    reason = "VENDOR_CHECK_FLAGGED_FOR_MANUAL_REVIEW"
                }
                KycVendorOutcome.OUTAGE -> {
                    nextStatus = KycStatusState.IN_REVIEW
                    reason = "VENDOR_OUTAGE_FAIL_CLOSED"
                }
            }
        }

        val updatedRecord = existing.copy(
            status = nextStatus,
            verifiedAge = verifiedPayload.verifiedAge ?: existing.verifiedAge,
            verifiedAt = if (nextStatus == KycStatusState.VERIFIED) now else existing.verifiedAt,
            expiresAt = if (nextStatus == KycStatusState.VERIFIED) now.plus(reverificationTtl) else existing.expiresAt,
            lastCheckType = verifiedPayload.checkType,
            lastVendorReference = verifiedPayload.vendorCheckReference,
            serverVersion = existing.serverVersion + 1,
            updatedAt = now,
        )
        recordsStore[recordKey] = updatedRecord

        val resultId = UUID.randomUUID()
        val transitionResult = KycStatusTransitionResult(
            resultId = resultId,
            tenantId = command.tenantId,
            userId = userId,
            fromStatus = existing.status,
            toStatus = nextStatus,
            directEligibilityGranted = false, // Untrusted client invariant
            financialMutationPermitted = false, // Financial rule invariant
            evidenceReference = sha256("${command.tenantId}:$userId:$resultId:$now"),
            serverTime = now,
        )

        val logEntry = KycStatusTransitionLog(
            transitionId = UUID.randomUUID(),
            tenantId = command.tenantId,
            userId = userId,
            fromStatus = existing.status,
            toStatus = nextStatus,
            triggerSource = KycTriggerSource.VENDOR_WEBHOOK,
            reason = reason,
            occurredAt = now,
            correlationId = command.correlationId,
            causationId = command.causationId,
        )
        transitionsLog.add(logEntry)
        idempotencyStore[command.idempotencyKey] = Pair(payloadHash, transitionResult)
        recordAudit(command.tenantId, "KYC_STATUS_TRANSITION", "SYSTEM", command.correlationId, command.causationId, now)

        return Result.success(transitionResult)
    }

    /**
     * Apply manual KYC override with strict role check and explicit reason.
     */
    @Synchronized
    fun applyManualOverride(command: KycManualOverrideCommand): Result<KycStatusTransitionResult> {
        KycStatusBinding.checkBound()

        val principal = command.principal
            ?: return Result.failure(AuthenticationFailure.Rejected(AuthErrorCode.UNAUTHENTICATED))

        if (principal.kind != PrincipalKind.ADMIN || principal.tenantId != command.tenantId) {
            return Result.failure(AuthenticationFailure.Rejected(AuthErrorCode.FORBIDDEN))
        }

        // Validate role permission
        if (!policy.isPermitted(principal, AdminPermission.MANAGE_SECURITY)) {
            return Result.failure(AuthenticationFailure.Rejected(AuthErrorCode.FORBIDDEN))
        }

        val now = clock.instant()
        val session = try {
            sessionDirectory.find(command.tenantId, principal.id, command.sessionId)
        } catch (e: Exception) {
            return Result.failure(AuthenticationFailure.Rejected(AuthErrorCode.DEPENDENCY_UNAVAILABLE))
        }
        if (session == null || !session.active || !session.expiresAt.isAfter(now)) {
            return Result.failure(AuthenticationFailure.Rejected(AuthErrorCode.FORBIDDEN))
        }

        // Validate explicit non-blank reason (minimum 10 characters)
        if (command.reason.isBlank() || command.reason.trim().length < 10) {
            return Result.failure(IllegalArgumentException("INVALID: Manual override requires explicit business justification (minimum 10 characters)"))
        }

        // Idempotency check
        val payloadHash = sha256("${command.tenantId}:${command.userId}:${command.targetStatus}:${command.reason}:${command.expectedVersion}")
        val cached = idempotencyStore[command.idempotencyKey]
        if (cached != null) {
            if (cached.first == payloadHash) {
                @Suppress("UNCHECKED_CAST")
                return Result.success(cached.second as KycStatusTransitionResult)
            } else {
                return Result.failure(IllegalArgumentException("CONFLICT: Idempotency key reused with different payload"))
            }
        }

        val recordKey = "${command.tenantId}:${command.userId}"
        val existing = recordsStore[recordKey] ?: KycStatusRecord(
            tenantId = command.tenantId,
            userId = command.userId,
            status = KycStatusState.UNVERIFIED,
            serverVersion = 0L,
            updatedAt = now,
        )

        // Optimistic locking version check
        if (existing.serverVersion != command.expectedVersion) {
            return Result.failure(IllegalStateException("STALE: Expected version ${command.expectedVersion} does not match current version ${existing.serverVersion}"))
        }

        val updatedRecord = existing.copy(
            status = command.targetStatus,
            verifiedAt = if (command.targetStatus == KycStatusState.VERIFIED) now else existing.verifiedAt,
            expiresAt = if (command.targetStatus == KycStatusState.VERIFIED) now.plus(reverificationTtl) else existing.expiresAt,
            serverVersion = existing.serverVersion + 1,
            updatedAt = now,
        )
        recordsStore[recordKey] = updatedRecord

        val overrideRecord = KycManualOverrideRecord(
            overrideId = UUID.randomUUID(),
            tenantId = command.tenantId,
            userId = command.userId,
            adminId = principal.id,
            adminRole = principal.roles.firstOrNull() ?: AdminRole.SECURITY,
            targetStatus = command.targetStatus,
            reason = command.reason,
            createdAt = now,
            idempotencyKey = command.idempotencyKey,
            correlationId = command.correlationId,
            causationId = command.causationId,
        )
        overridesStore[overrideRecord.overrideId] = overrideRecord

        val resultId = UUID.randomUUID()
        val transitionResult = KycStatusTransitionResult(
            resultId = resultId,
            tenantId = command.tenantId,
            userId = command.userId,
            fromStatus = existing.status,
            toStatus = command.targetStatus,
            directEligibilityGranted = false,
            financialMutationPermitted = false,
            evidenceReference = sha256("${command.tenantId}:${command.userId}:$resultId:$now"),
            serverTime = now,
        )

        val logEntry = KycStatusTransitionLog(
            transitionId = UUID.randomUUID(),
            tenantId = command.tenantId,
            userId = command.userId,
            fromStatus = existing.status,
            toStatus = command.targetStatus,
            triggerSource = KycTriggerSource.MANUAL_OVERRIDE,
            reason = "MANUAL_OVERRIDE_BY_${principal.id}_REASON_${command.reason}",
            occurredAt = now,
            correlationId = command.correlationId,
            causationId = command.causationId,
        )
        transitionsLog.add(logEntry)
        idempotencyStore[command.idempotencyKey] = Pair(payloadHash, transitionResult)
        recordAudit(command.tenantId, "KYC_MANUAL_OVERRIDE", principal.id, command.correlationId, command.causationId, now)

        return Result.success(transitionResult)
    }

    /**
     * Evaluate KYC status for a user.
     * Enforces: "Stale reverification blocks"
     */
    fun evaluateStatus(tenantId: String, userId: String): KycStatusEvaluation {
        KycStatusBinding.checkBound()

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

        // Check if verification has expired -> stale reverification blocks!
        if (record.status == KycStatusState.VERIFIED) {
            val expiresAt = record.expiresAt
            if (expiresAt != null && !now.isBefore(expiresAt)) {
                return KycStatusEvaluation(
                    evaluationId = "eval-${UUID.randomUUID()}",
                    tenantId = tenantId,
                    userId = userId,
                    status = KycStatusState.EXPIRED,
                    isEligible = false, // Stale reverification blocks eligibility
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
                reason = "VERIFIED_AGE_AND_IDENTITY_ACTIVE",
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

    /**
     * Request reverification for a user.
     */
    @Synchronized
    fun requestReverification(command: KycReverificationCommand): Result<KycStatusTransitionResult> {
        KycStatusBinding.checkBound()

        val now = clock.instant()
        val recordKey = "${command.tenantId}:${command.userId}"
        val existing = recordsStore[recordKey] ?: KycStatusRecord(
            tenantId = command.tenantId,
            userId = command.userId,
            status = KycStatusState.UNVERIFIED,
            serverVersion = 0L,
            updatedAt = now,
        )

        val updated = existing.copy(
            status = KycStatusState.REVERIFICATION_REQUIRED,
            serverVersion = existing.serverVersion + 1,
            updatedAt = now,
        )
        recordsStore[recordKey] = updated

        val resultId = UUID.randomUUID()
        val result = KycStatusTransitionResult(
            resultId = resultId,
            tenantId = command.tenantId,
            userId = command.userId,
            fromStatus = existing.status,
            toStatus = KycStatusState.REVERIFICATION_REQUIRED,
            directEligibilityGranted = false,
            financialMutationPermitted = false,
            evidenceReference = sha256("${command.tenantId}:${command.userId}:$resultId:$now"),
            serverTime = now,
        )

        val logEntry = KycStatusTransitionLog(
            transitionId = UUID.randomUUID(),
            tenantId = command.tenantId,
            userId = command.userId,
            fromStatus = existing.status,
            toStatus = KycStatusState.REVERIFICATION_REQUIRED,
            triggerSource = KycTriggerSource.CLIENT_REVERIFICATION_REQUEST,
            reason = command.reason,
            occurredAt = now,
            correlationId = command.correlationId,
            causationId = command.causationId,
        )
        transitionsLog.add(logEntry)
        return Result.success(result)
    }

    fun getRecord(tenantId: String, userId: String): KycStatusRecord? = recordsStore["$tenantId:$userId"]

    fun getTransitionLogs(tenantId: String, userId: String): List<KycStatusTransitionLog> =
        synchronized(this) { transitionsLog.filter { it.tenantId == tenantId && it.userId == userId } }

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
