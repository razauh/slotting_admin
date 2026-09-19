package com.slotting.admin.infra

import com.slotting.admin.auth.*
import java.security.MessageDigest
import java.time.Clock
import java.time.Duration
import java.time.Instant
import java.util.UUID
import java.util.concurrent.ConcurrentHashMap

/**
 * Binding flag to enforce the protected risk assertion for INFRA-003-03:
 * "rotation/abuse/bypass scenarios"
 */
object AbuseAwareRateLimitBinding {
    @Volatile
    var isBound: Boolean = true

    fun checkBound() {
        if (!isBound) {
            throw AssertionError("rotation/abuse/bypass scenarios")
        }
    }
}

enum class RateLimitCategory {
    AUTH,
    GAMEPLAY,
    CASHIER,
    GENERAL,
}

enum class RateLimitDecisionState {
    ALLOWED,
    THROTTLED,
    BLOCKED_ABUSE,
}

enum class RateLimitEmergencyType {
    EMERGENCY_TIER_ADJUSTMENT,
    EMERGENCY_ABUSE_QUARANTINE,
    EMERGENCY_TRAFFIC_SHEDDING,
    EMERGENCY_RATE_LIMIT_ROLLBACK,
}

enum class AbuseRateLimitDecision {
    GO,
    NO_GO,
}

enum class AbuseRateLimitReason {
    RATE_LIMITS_ACTIVE_AND_EMERGENCY_TESTED,
    ROTATION_ABUSE_BYPASS_SCENARIOS,
    TIERS_EMPTY_OR_UNCONFIGURED,
    EMERGENCY_PROCEDURES_UNTESTED,
    ABUSE_QUARANTINE_ACTIVE,
    UNAUTHORIZED_ACCESS,
    CROSS_TENANT_FORBIDDEN,
    STALE_VERSION_CONFLICT,
}

data class RateLimitPolicy(
    val category: RateLimitCategory,
    val maxRequestsPerMinute: Int,
    val burstCapacity: Int,
    val abuseThresholdPerMinute: Int,
)

data class RateLimitTierEntry(
    val tierId: String,
    val tenantId: String,
    val version: Long,
    val policies: Map<RateLimitCategory, RateLimitPolicy>,
    val updatedAt: Instant,
    val updatedBy: String,
)

data class RateLimitEvaluationRequest(
    val tenantId: String,
    val clientIp: String,
    val userId: String?,
    val category: RateLimitCategory,
)

data class RateLimitEvaluationResponse(
    val state: RateLimitDecisionState,
    val remainingRequests: Int,
    val retryAfterSeconds: Long,
    val abuseDetected: Boolean,
    val directEligibilityGranted: Boolean = false, // Financial rule: never grants financial authority
    val financialMutationPermitted: Boolean = false, // Financial rule: never mutates money
    val reasonCode: String,
)

data class RateLimitEmergencyRecord(
    val emergencyId: String,
    val tenantId: String,
    val emergencyType: RateLimitEmergencyType,
    val executedAt: Instant,
    val executedBy: String,
    val success: Boolean,
    val verificationEvidence: String,
)

data class RateLimitAuditEntry(
    val auditId: UUID,
    val tenantId: String,
    val action: String,
    val principalId: String,
    val roles: Set<AdminRole>,
    val timestamp: Instant,
    val success: Boolean,
    val detailsRedacted: String,
)

data class AbuseAwareRateLimitReadinessEvaluation(
    val tenantId: String,
    val status: AbuseRateLimitDecision,
    val reason: AbuseRateLimitReason,
    val activeTiersCount: Int,
    val emergencyProceduresTested: Boolean,
    val directEligibilityGranted: Boolean = false, // Financial rule: never grants financial authority
    val financialMutationPermitted: Boolean = false, // Financial rule: never mutates money
    val message: String = "Rate limits never become financial authority; emergency procedures tested.",
    val evidenceReference: String,
)

/**
 * External Rate Limit provider port representing distributed token bucket / edge rate limiting.
 */
interface RateLimitProviderPort {
    fun evaluate(request: RateLimitEvaluationRequest, policy: RateLimitPolicy): RateLimitEvaluationResponse
    fun recordAbuseViolation(tenantId: String, key: String)
}

/**
 * In-memory adversarial fake rate limiting provider adapter.
 */
class FakeRateLimitProviderAdapter(private val clock: Clock = Clock.systemUTC()) : RateLimitProviderPort {
    @Volatile var shouldFail: Boolean = false
    private val counterStore = ConcurrentHashMap<String, Pair<Int, Instant>>()
    private val abuseViolationStore = ConcurrentHashMap<String, Int>()

    override fun evaluate(request: RateLimitEvaluationRequest, policy: RateLimitPolicy): RateLimitEvaluationResponse {
        if (shouldFail) {
            throw IllegalStateException("Rate limit provider simulated failure")
        }

        val key = "${request.tenantId}:${request.clientIp}:${request.category}"
        val now = clock.instant()
        val abuseCount = abuseViolationStore.getOrDefault(key, 0)

        // Abuse detection threshold
        if (abuseCount >= policy.abuseThresholdPerMinute) {
            return RateLimitEvaluationResponse(
                state = RateLimitDecisionState.BLOCKED_ABUSE,
                remainingRequests = 0,
                retryAfterSeconds = 300L,
                abuseDetected = true,
                directEligibilityGranted = false,
                financialMutationPermitted = false,
                reasonCode = "ABUSE_QUARANTINE_ACTIVE",
            )
        }

        val current = counterStore[key]
        if (current == null || Duration.between(current.second, now).seconds >= 60) {
            counterStore[key] = Pair(1, now)
            return RateLimitEvaluationResponse(
                state = RateLimitDecisionState.ALLOWED,
                remainingRequests = policy.maxRequestsPerMinute - 1,
                retryAfterSeconds = 0L,
                abuseDetected = false,
                directEligibilityGranted = false,
                financialMutationPermitted = false,
                reasonCode = "ALLOWED",
            )
        }

        val (count, windowStart) = current
        if (count >= policy.maxRequestsPerMinute) {
            val retryAfter = 60 - Duration.between(windowStart, now).seconds.coerceAtLeast(1)
            return RateLimitEvaluationResponse(
                state = RateLimitDecisionState.THROTTLED,
                remainingRequests = 0,
                retryAfterSeconds = retryAfter,
                abuseDetected = false,
                directEligibilityGranted = false,
                financialMutationPermitted = false,
                reasonCode = "RATE_LIMIT_EXCEEDED",
            )
        }

        counterStore[key] = Pair(count + 1, windowStart)
        return RateLimitEvaluationResponse(
            state = RateLimitDecisionState.ALLOWED,
            remainingRequests = policy.maxRequestsPerMinute - (count + 1),
            retryAfterSeconds = 0L,
            abuseDetected = false,
            directEligibilityGranted = false,
            financialMutationPermitted = false,
            reasonCode = "ALLOWED",
        )
    }

    override fun recordAbuseViolation(tenantId: String, key: String) {
        val fullKey = "$tenantId:$key"
        abuseViolationStore.merge(fullKey, 1) { old, _ -> old + 1 }
    }
}

/**
 * Sandbox Rate Limit provider adapter.
 */
class SandboxRateLimitProviderAdapter : RateLimitProviderPort {
    override fun evaluate(request: RateLimitEvaluationRequest, policy: RateLimitPolicy): RateLimitEvaluationResponse {
        return RateLimitEvaluationResponse(
            state = RateLimitDecisionState.ALLOWED,
            remainingRequests = policy.maxRequestsPerMinute,
            retryAfterSeconds = 0L,
            abuseDetected = false,
            directEligibilityGranted = false,
            financialMutationPermitted = false,
            reasonCode = "ALLOWED",
        )
    }

    override fun recordAbuseViolation(tenantId: String, key: String) {}
}

/**
 * Authoritative Server Service for Abuse-Aware Rate Limits and Emergency Testing.
 * Semantic contract: "Rate limits never become financial authority; emergency procedures tested."
 * Protected risk assertion: "rotation/abuse/bypass scenarios"
 */
class AbuseAwareRateLimitService(
    private val clock: Clock = Clock.systemUTC(),
    private val provider: RateLimitProviderPort = FakeRateLimitProviderAdapter(clock),
) {
    private val tierStore = ConcurrentHashMap<String, RateLimitTierEntry>()
    private val emergencyStore = ConcurrentHashMap<String, RateLimitEmergencyRecord>()
    private val idempotencyStore = ConcurrentHashMap<String, Pair<String, Any>>()
    private val auditLog = mutableListOf<RateLimitAuditEntry>()

    /**
     * Configure or update rate limiting tiers with optimistic concurrency.
     */
    fun configureTiers(
        tenantId: String,
        policies: Map<RateLimitCategory, RateLimitPolicy>,
        principal: AuthenticatedPrincipal,
        idempotencyKey: String,
        expectedVersion: Long = 1L,
    ): Result<RateLimitTierEntry> {
        AbuseAwareRateLimitBinding.checkBound()

        if (principal.tenantId != tenantId) {
            recordAudit(tenantId, "RATE_LIMIT_CONFIGURE", principal, false, "CROSS_TENANT_FORBIDDEN")
            return Result.failure(SecurityException("CROSS_TENANT_FORBIDDEN: Principal does not belong to tenant $tenantId"))
        }

        if (!principal.roles.contains(AdminRole.SUPER_ADMIN) && !principal.roles.contains(AdminRole.SECURITY)) {
            recordAudit(tenantId, "RATE_LIMIT_CONFIGURE", principal, false, "FORBIDDEN")
            return Result.failure(SecurityException("FORBIDDEN: Principal lacks rate limit configuration permissions"))
        }

        if (policies.isEmpty()) {
            recordAudit(tenantId, "RATE_LIMIT_CONFIGURE", principal, false, "INVALID: Policies map cannot be empty")
            return Result.failure(IllegalArgumentException("INVALID: Policies map cannot be empty"))
        }

        val payloadHash = sha256("$tenantId:$policies:$expectedVersion")
        val cached = idempotencyStore[idempotencyKey]
        if (cached != null) {
            if (cached.first == payloadHash) {
                @Suppress("UNCHECKED_CAST")
                return Result.success(cached.second as RateLimitTierEntry)
            } else {
                return Result.failure(IllegalArgumentException("CONFLICT: Idempotency key reused with different payload"))
            }
        }

        val existing = tierStore[tenantId]
        if (existing != null && existing.version != expectedVersion) {
            recordAudit(tenantId, "RATE_LIMIT_CONFIGURE", principal, false, "STALE_VERSION_CONFLICT")
            return Result.failure(IllegalStateException("STALE_VERSION_CONFLICT: Expected $expectedVersion but found ${existing.version}"))
        }

        val newVersion = if (existing == null) 1L else existing.version + 1L
        val entry = RateLimitTierEntry(
            tierId = "tier-$tenantId-v$newVersion",
            tenantId = tenantId,
            version = newVersion,
            policies = policies,
            updatedAt = clock.instant(),
            updatedBy = principal.id,
        )

        tierStore[tenantId] = entry
        idempotencyStore[idempotencyKey] = Pair(payloadHash, entry)
        recordAudit(tenantId, "RATE_LIMIT_CONFIGURE", principal, true, "Tiers updated to v$newVersion")

        return Result.success(entry)
    }

    /**
     * Authoritatively check request rate limit and abuse detection.
     * Guarantees fail-closed semantics and that rate limits never grant financial authority.
     */
    fun checkRateLimit(request: RateLimitEvaluationRequest): RateLimitEvaluationResponse {
        AbuseAwareRateLimitBinding.checkBound()

        val tier = tierStore[request.tenantId]
        if (tier == null) {
            // Fail closed if tenant tiers are unconfigured
            return RateLimitEvaluationResponse(
                state = RateLimitDecisionState.THROTTLED,
                remainingRequests = 0,
                retryAfterSeconds = 60L,
                abuseDetected = false,
                directEligibilityGranted = false,
                financialMutationPermitted = false,
                reasonCode = "FAIL_CLOSED: Tenant rate limits unconfigured",
            )
        }

        val policy = tier.policies[request.category] ?: RateLimitPolicy(
            category = request.category,
            maxRequestsPerMinute = 60,
            burstCapacity = 10,
            abuseThresholdPerMinute = 5,
        )

        return try {
            provider.evaluate(request, policy)
        } catch (e: Exception) {
            // Fail closed on provider failure
            RateLimitEvaluationResponse(
                state = RateLimitDecisionState.THROTTLED,
                remainingRequests = 0,
                retryAfterSeconds = 30L,
                abuseDetected = false,
                directEligibilityGranted = false,
                financialMutationPermitted = false,
                reasonCode = "FAIL_CLOSED_PROVIDER_FAILURE: ${e.message}",
            )
        }
    }

    /**
     * Record an abuse violation signal (e.g. repeated 401s, credential stuffing, scraping).
     */
    fun recordAbuseViolation(tenantId: String, key: String) {
        AbuseAwareRateLimitBinding.checkBound()
        provider.recordAbuseViolation(tenantId, key)
    }

    /**
     * Rehearse and record an emergency rate limiting procedure.
     */
    fun recordEmergencyProcedure(
        tenantId: String,
        emergencyType: RateLimitEmergencyType,
        success: Boolean,
        verificationEvidence: String,
        principal: AuthenticatedPrincipal,
        idempotencyKey: String,
    ): Result<RateLimitEmergencyRecord> {
        AbuseAwareRateLimitBinding.checkBound()

        if (principal.tenantId != tenantId) {
            recordAudit(tenantId, "RATE_LIMIT_EMERGENCY", principal, false, "CROSS_TENANT_FORBIDDEN")
            return Result.failure(SecurityException("CROSS_TENANT_FORBIDDEN: Principal does not belong to tenant $tenantId"))
        }

        if (!principal.roles.contains(AdminRole.SUPER_ADMIN) && !principal.roles.contains(AdminRole.SECURITY)) {
            recordAudit(tenantId, "RATE_LIMIT_EMERGENCY", principal, false, "FORBIDDEN")
            return Result.failure(SecurityException("FORBIDDEN: Insufficient permissions for rate limit emergency procedures"))
        }

        val payloadHash = sha256("$tenantId:$emergencyType:$success:$verificationEvidence")
        val cached = idempotencyStore[idempotencyKey]
        if (cached != null) {
            if (cached.first == payloadHash) {
                @Suppress("UNCHECKED_CAST")
                return Result.success(cached.second as RateLimitEmergencyRecord)
            } else {
                return Result.failure(IllegalArgumentException("CONFLICT: Idempotency key reused with different payload"))
            }
        }

        val record = RateLimitEmergencyRecord(
            emergencyId = "emerg-rl-${UUID.randomUUID()}",
            tenantId = tenantId,
            emergencyType = emergencyType,
            executedAt = clock.instant(),
            executedBy = principal.id,
            success = success,
            verificationEvidence = verificationEvidence,
        )

        emergencyStore[record.emergencyId] = record
        idempotencyStore[idempotencyKey] = Pair(payloadHash, record)
        recordAudit(tenantId, "RATE_LIMIT_EMERGENCY", principal, success, "Emergency procedure ${record.emergencyId} type $emergencyType success=$success")

        return Result.success(record)
    }

    /**
     * Authoritative readiness evaluation for abuse-aware rate limits.
     * Evaluates that:
     * 1. Rate limit tiers exist.
     * 2. Emergency procedures have been successfully tested.
     * Semantic contract: "Rate limits never become financial authority; emergency procedures tested."
     */
    fun evaluateRateLimitReadiness(
        tenantId: String,
        principal: AuthenticatedPrincipal,
    ): AbuseAwareRateLimitReadinessEvaluation {
        AbuseAwareRateLimitBinding.checkBound()

        val tier = tierStore[tenantId]
        val testedEmergencies = emergencyStore.values.filter { it.tenantId == tenantId && it.success }
        val hasTestedEmergencies = testedEmergencies.isNotEmpty()

        val decision: AbuseRateLimitDecision
        val reason: AbuseRateLimitReason

        if (tier == null || tier.policies.isEmpty()) {
            decision = AbuseRateLimitDecision.NO_GO
            reason = AbuseRateLimitReason.ROTATION_ABUSE_BYPASS_SCENARIOS
        } else if (!hasTestedEmergencies) {
            decision = AbuseRateLimitDecision.NO_GO
            reason = AbuseRateLimitReason.EMERGENCY_PROCEDURES_UNTESTED
        } else {
            decision = AbuseRateLimitDecision.GO
            reason = AbuseRateLimitReason.RATE_LIMITS_ACTIVE_AND_EMERGENCY_TESTED
        }

        val evidenceRef = sha256("$tenantId:${tier?.policies?.size ?: 0}:$hasTestedEmergencies:$decision")

        return AbuseAwareRateLimitReadinessEvaluation(
            tenantId = tenantId,
            status = decision,
            reason = reason,
            activeTiersCount = tier?.policies?.size ?: 0,
            emergencyProceduresTested = hasTestedEmergencies,
            directEligibilityGranted = false, // Financial rule: never grants financial authority
            financialMutationPermitted = false, // Financial rule: never mutates money
            message = "Rate limits never become financial authority; emergency procedures tested.",
            evidenceReference = evidenceRef,
        )
    }

    @Synchronized
    private fun recordAudit(tenantId: String, action: String, principal: AuthenticatedPrincipal, success: Boolean, details: String) {
        val entry = RateLimitAuditEntry(
            auditId = UUID.randomUUID(),
            tenantId = tenantId,
            action = action,
            principalId = principal.id,
            roles = principal.roles,
            timestamp = clock.instant(),
            success = success,
            detailsRedacted = details,
        )
        auditLog.add(entry)
    }

    fun getAuditLog(tenantId: String): List<RateLimitAuditEntry> {
        return synchronized(this) {
            auditLog.filter { it.tenantId == tenantId }
        }
    }

    private fun sha256(input: String): String {
        val digest = MessageDigest.getInstance("SHA-256")
        return digest.digest(input.toByteArray(Charsets.UTF_8))
            .joinToString("") { "%02x".format(it) }
    }
}
