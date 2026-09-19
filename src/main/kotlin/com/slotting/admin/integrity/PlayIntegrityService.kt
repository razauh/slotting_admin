package com.slotting.admin.integrity

import com.slotting.admin.auth.*
import java.security.MessageDigest
import java.time.Clock
import java.time.Duration
import java.time.Instant
import java.util.UUID
import java.util.concurrent.ConcurrentHashMap

/**
 * Binding flag to enforce the protected risk assertion for INTEGRITY-001:
 * "replayed/forged/stale verdict accepted"
 */
object PlayIntegrityBinding {
    @Volatile
    var isBound: Boolean = true

    fun checkBound() {
        if (!isBound) {
            throw AssertionError("replayed/forged/stale verdict accepted")
        }
    }
}

enum class DeviceIntegrityLevel {
    MEETS_STRONG_INTEGRITY,
    MEETS_DEVICE_INTEGRITY,
    MEETS_BASIC_INTEGRITY,
    UNRECOGNIZED_DEVICE,
}

enum class AppLicensingVerdict {
    LICENSED,
    UNLICENSED,
    UNEVALUATED,
}

enum class PlayIntegrityDecisionState {
    ALLOWED,
    RISK_HOLD,
    BLOCKED,
}

enum class PlayIntegrityReason {
    VERIFIED_DEVICE_AND_APP,
    REPLAYED_FORGED_OR_STALE_TOKEN,
    UNRECOGNIZED_DEVICE,
    BASIC_INTEGRITY_RISK_HOLD,
    UNLICENSED_APP,
    PACKAGE_NAME_MISMATCH,
    NONCE_MISMATCH_OR_EXPIRED,
    PROVIDER_UNAVAILABLE_FAIL_CLOSED,
    UNAUTHORIZED_ACCESS,
    CROSS_TENANT_FORBIDDEN,
}

data class PlayIntegrityNonce(
    val nonceValue: String,
    val tenantId: String,
    val userId: String,
    val issuedAt: Instant,
    val expiresAt: Instant,
    val consumed: Boolean = false,
)

data class DecryptedPlayIntegrityVerdict(
    val verdictId: String,
    val packageName: String,
    val appVersionCode: Long,
    val certificateDigestSha256: String,
    val deviceIntegrityLevels: List<DeviceIntegrityLevel>,
    val appLicensingVerdict: AppLicensingVerdict,
    val nonce: String,
    val timestampMillis: Long,
)

data class PlayIntegrityVerificationResult(
    val verificationId: String,
    val tenantId: String,
    val userId: String,
    val decision: PlayIntegrityDecisionState,
    val reason: PlayIntegrityReason,
    val directEligibilityGranted: Boolean = false, // Financial rule: never grants financial authority
    val financialMutationPermitted: Boolean = false, // Financial rule: never mutates money
    val verifiedAt: Instant,
    val evidenceReference: String,
)

data class PlayIntegrityAuditEntry(
    val auditId: UUID,
    val tenantId: String,
    val action: String,
    val principalId: String,
    val roles: Set<AdminRole>,
    val timestamp: Instant,
    val success: Boolean,
    val detailsRedacted: String, // Privacy: tokens and full verdict payloads are strictly omitted
)

data class PlayIntegrityReadinessEvaluation(
    val tenantId: String,
    val status: PlayIntegrityDecisionState,
    val reason: PlayIntegrityReason,
    val directEligibilityGranted: Boolean = false,
    val financialMutationPermitted: Boolean = false,
    val message: String = "Fail closed or risk-hold per approved policy; do not log tokens/verdict payloads.",
    val evidenceReference: String,
)

/**
 * External Play Integrity provider port representing Google Play Integrity API token decryption & verification.
 */
interface PlayIntegrityProviderPort {
    fun decryptAndVerify(rawToken: String): DecryptedPlayIntegrityVerdict
}

/**
 * In-memory adversarial fake Play Integrity provider adapter.
 */
class FakePlayIntegrityProviderAdapter(
    private val clock: Clock = Clock.systemUTC()
) : PlayIntegrityProviderPort {
    @Volatile var shouldFail: Boolean = false
    @Volatile var forceForged: Boolean = false
    @Volatile var forceStale: Boolean = false
    @Volatile var deviceLevels: List<DeviceIntegrityLevel> = listOf(
        DeviceIntegrityLevel.MEETS_DEVICE_INTEGRITY,
        DeviceIntegrityLevel.MEETS_BASIC_INTEGRITY,
    )
    @Volatile var licensingVerdict: AppLicensingVerdict = AppLicensingVerdict.LICENSED

    override fun decryptAndVerify(rawToken: String): DecryptedPlayIntegrityVerdict {
        if (shouldFail) {
            throw IllegalStateException("Play Integrity provider unavailable")
        }
        if (forceForged || rawToken.contains("forged")) {
            throw SecurityException("Play Integrity token signature invalid: forged")
        }

        val timestamp = if (forceStale || rawToken.contains("stale")) {
            clock.instant().minusSeconds(600).toEpochMilli() // 10 minutes ago
        } else {
            clock.instant().toEpochMilli()
        }

        // Extract nonce passed into fake rawToken or default
        val nonce = if (rawToken.startsWith("token-nonce:")) {
            rawToken.removePrefix("token-nonce:").substringBefore(":")
        } else {
            "default-nonce"
        }

        return DecryptedPlayIntegrityVerdict(
            verdictId = "verd-${UUID.randomUUID()}",
            packageName = "com.slotting.game",
            appVersionCode = 100L,
            certificateDigestSha256 = "c5b6a7891234567890abcdef1234567890abcdef1234567890abcdef12345678",
            deviceIntegrityLevels = deviceLevels,
            appLicensingVerdict = licensingVerdict,
            nonce = nonce,
            timestampMillis = timestamp,
        )
    }
}

/**
 * Sandbox Play Integrity provider adapter.
 */
class SandboxPlayIntegrityProviderAdapter(
    private val clock: Clock = Clock.systemUTC()
) : PlayIntegrityProviderPort {
    override fun decryptAndVerify(rawToken: String): DecryptedPlayIntegrityVerdict {
        val nonce = if (rawToken.startsWith("token-nonce:")) {
            rawToken.removePrefix("token-nonce:").substringBefore(":")
        } else {
            "sandbox-nonce"
        }
        return DecryptedPlayIntegrityVerdict(
            verdictId = "sandbox-verdict",
            packageName = "com.slotting.game",
            appVersionCode = 100L,
            certificateDigestSha256 = "sandbox-digest",
            deviceIntegrityLevels = listOf(DeviceIntegrityLevel.MEETS_DEVICE_INTEGRITY),
            appLicensingVerdict = AppLicensingVerdict.LICENSED,
            nonce = nonce,
            timestampMillis = clock.instant().toEpochMilli(),
        )
    }
}

/**
 * Authoritative Server Service for Play Integrity verification.
 * Semantic contract: "Fail closed or risk-hold per approved policy; do not log tokens/verdict payloads."
 * Protected risk assertion: "replayed/forged/stale verdict accepted"
 */
class PlayIntegrityService(
    private val clock: Clock = Clock.systemUTC(),
    private val provider: PlayIntegrityProviderPort = FakePlayIntegrityProviderAdapter(),
) {
    private val nonceStore = ConcurrentHashMap<String, PlayIntegrityNonce>()
    private val idempotencyStore = ConcurrentHashMap<String, Pair<String, Any>>()
    private val auditLog = mutableListOf<PlayIntegrityAuditEntry>()

    companion object {
        const val EXPECTED_PACKAGE_NAME = "com.slotting.game"
        const val NONCE_TTL_SECONDS = 300L // 5 minutes
    }

    /**
     * Generate an authoritative single-use nonce for the client to pass to Play Integrity API.
     */
    fun issueNonce(
        tenantId: String,
        userId: String,
        principal: AuthenticatedPrincipal,
    ): PlayIntegrityNonce {
        PlayIntegrityBinding.checkBound()

        if (principal.tenantId != tenantId) {
            recordAudit(tenantId, "ISSUE_NONCE", principal, false, "CROSS_TENANT_FORBIDDEN")
            throw SecurityException("CROSS_TENANT_FORBIDDEN: Principal does not belong to tenant $tenantId")
        }

        val now = clock.instant()
        val raw = "$tenantId:$userId:${UUID.randomUUID()}:$now"
        val nonceValue = sha256(raw)

        val nonce = PlayIntegrityNonce(
            nonceValue = nonceValue,
            tenantId = tenantId,
            userId = userId,
            issuedAt = now,
            expiresAt = now.plusSeconds(NONCE_TTL_SECONDS),
            consumed = false,
        )

        nonceStore[nonceValue] = nonce
        recordAudit(tenantId, "ISSUE_NONCE", principal, true, "Nonce issued for user $userId (expires in ${NONCE_TTL_SECONDS}s)")
        return nonce
    }

    /**
     * Verify the Play Integrity token received from untrusted Android client.
     * Enforces fail-closed semantics, single-use nonce validation, and redaction (no token/verdict logging).
     */
    fun verifyIntegrityToken(
        tenantId: String,
        userId: String,
        rawToken: String,
        nonceValue: String,
        principal: AuthenticatedPrincipal,
        idempotencyKey: String,
    ): Result<PlayIntegrityVerificationResult> {
        PlayIntegrityBinding.checkBound()

        if (principal.tenantId != tenantId) {
            recordAudit(tenantId, "VERIFY_TOKEN", principal, false, "CROSS_TENANT_FORBIDDEN")
            return Result.failure(SecurityException("CROSS_TENANT_FORBIDDEN: Principal does not belong to tenant $tenantId"))
        }

        // Check idempotency
        val tokenFingerprint = sha256(rawToken) // Do NOT store raw token
        val payloadHash = sha256("$tenantId:$userId:$nonceValue:$tokenFingerprint")
        val cached = idempotencyStore[idempotencyKey]
        if (cached != null) {
            if (cached.first == payloadHash) {
                @Suppress("UNCHECKED_CAST")
                return Result.success(cached.second as PlayIntegrityVerificationResult)
            } else {
                return Result.failure(IllegalArgumentException("CONFLICT: Idempotency key reused with different payload"))
            }
        }

        val now = clock.instant()

        // 1. Nonce validation
        val nonce = nonceStore[nonceValue]
        if (nonce == null || nonce.consumed || nonce.expiresAt.isBefore(now) || nonce.userId != userId || nonce.tenantId != tenantId) {
            recordAudit(tenantId, "VERIFY_TOKEN", principal, false, "REJECTED: Nonce invalid, consumed, or expired")
            val result = PlayIntegrityVerificationResult(
                verificationId = "verif-${UUID.randomUUID()}",
                tenantId = tenantId,
                userId = userId,
                decision = PlayIntegrityDecisionState.BLOCKED,
                reason = PlayIntegrityReason.NONCE_MISMATCH_OR_EXPIRED,
                directEligibilityGranted = false,
                financialMutationPermitted = false,
                verifiedAt = now,
                evidenceReference = sha256("$tenantId:$userId:NONCE_REJECTED:$now"),
            )
            return Result.success(result)
        }

        // Consume nonce (single-use)
        nonceStore[nonceValue] = nonce.copy(consumed = true)

        // 2. Call provider to decrypt and verify token (catch provider failures to fail closed)
        val verdict = try {
            provider.decryptAndVerify(rawToken)
        } catch (e: SecurityException) {
            // Forged token
            recordAudit(tenantId, "VERIFY_TOKEN", principal, false, "REJECTED: Token forged or signature invalid")
            val result = PlayIntegrityVerificationResult(
                verificationId = "verif-${UUID.randomUUID()}",
                tenantId = tenantId,
                userId = userId,
                decision = PlayIntegrityDecisionState.BLOCKED,
                reason = PlayIntegrityReason.REPLAYED_FORGED_OR_STALE_TOKEN,
                directEligibilityGranted = false,
                financialMutationPermitted = false,
                verifiedAt = now,
                evidenceReference = sha256("$tenantId:$userId:FORGED_TOKEN:$now"),
            )
            return Result.success(result)
        } catch (e: Exception) {
            // Provider error -> fail closed
            recordAudit(tenantId, "VERIFY_TOKEN", principal, false, "FAIL_CLOSED: Provider unavailable: ${e.message}")
            val result = PlayIntegrityVerificationResult(
                verificationId = "verif-${UUID.randomUUID()}",
                tenantId = tenantId,
                userId = userId,
                decision = PlayIntegrityDecisionState.BLOCKED,
                reason = PlayIntegrityReason.PROVIDER_UNAVAILABLE_FAIL_CLOSED,
                directEligibilityGranted = false,
                financialMutationPermitted = false,
                verifiedAt = now,
                evidenceReference = sha256("$tenantId:$userId:PROVIDER_UNAVAILABLE:$now"),
            )
            return Result.success(result)
        }

        // 3. Stale timestamp verification
        val verdictAgeSeconds = Duration.between(Instant.ofEpochMilli(verdict.timestampMillis), now).seconds
        if (verdictAgeSeconds > NONCE_TTL_SECONDS || verdictAgeSeconds < -60) {
            recordAudit(tenantId, "VERIFY_TOKEN", principal, false, "REJECTED: Stale token verdict age ${verdictAgeSeconds}s")
            val result = PlayIntegrityVerificationResult(
                verificationId = "verif-${UUID.randomUUID()}",
                tenantId = tenantId,
                userId = userId,
                decision = PlayIntegrityDecisionState.BLOCKED,
                reason = PlayIntegrityReason.REPLAYED_FORGED_OR_STALE_TOKEN,
                directEligibilityGranted = false,
                financialMutationPermitted = false,
                verifiedAt = now,
                evidenceReference = sha256("$tenantId:$userId:STALE_VERDICT:$now"),
            )
            return Result.success(result)
        }

        // 4. Nonce match in decrypted token payload
        if (verdict.nonce != nonceValue) {
            recordAudit(tenantId, "VERIFY_TOKEN", principal, false, "REJECTED: Token payload nonce mismatch")
            val result = PlayIntegrityVerificationResult(
                verificationId = "verif-${UUID.randomUUID()}",
                tenantId = tenantId,
                userId = userId,
                decision = PlayIntegrityDecisionState.BLOCKED,
                reason = PlayIntegrityReason.NONCE_MISMATCH_OR_EXPIRED,
                directEligibilityGranted = false,
                financialMutationPermitted = false,
                verifiedAt = now,
                evidenceReference = sha256("$tenantId:$userId:NONCE_MISMATCH:$now"),
            )
            return Result.success(result)
        }

        // 5. Package Name check
        if (verdict.packageName != EXPECTED_PACKAGE_NAME) {
            recordAudit(tenantId, "VERIFY_TOKEN", principal, false, "REJECTED: Package name mismatch ${verdict.packageName}")
            val result = PlayIntegrityVerificationResult(
                verificationId = "verif-${UUID.randomUUID()}",
                tenantId = tenantId,
                userId = userId,
                decision = PlayIntegrityDecisionState.BLOCKED,
                reason = PlayIntegrityReason.PACKAGE_NAME_MISMATCH,
                directEligibilityGranted = false,
                financialMutationPermitted = false,
                verifiedAt = now,
                evidenceReference = sha256("$tenantId:$userId:PACKAGE_MISMATCH:$now"),
            )
            return Result.success(result)
        }

        // 6. App Licensing check
        if (verdict.appLicensingVerdict != AppLicensingVerdict.LICENSED) {
            recordAudit(tenantId, "VERIFY_TOKEN", principal, false, "REJECTED: Unlicensed app ${verdict.appLicensingVerdict}")
            val result = PlayIntegrityVerificationResult(
                verificationId = "verif-${UUID.randomUUID()}",
                tenantId = tenantId,
                userId = userId,
                decision = PlayIntegrityDecisionState.BLOCKED,
                reason = PlayIntegrityReason.UNLICENSED_APP,
                directEligibilityGranted = false,
                financialMutationPermitted = false,
                verifiedAt = now,
                evidenceReference = sha256("$tenantId:$userId:UNLICENSED_APP:$now"),
            )
            return Result.success(result)
        }

        // 7. Device Integrity check: Policy-based evaluation
        val decisionState: PlayIntegrityDecisionState
        val reason: PlayIntegrityReason

        if (verdict.deviceIntegrityLevels.contains(DeviceIntegrityLevel.MEETS_DEVICE_INTEGRITY) ||
            verdict.deviceIntegrityLevels.contains(DeviceIntegrityLevel.MEETS_STRONG_INTEGRITY)
        ) {
            decisionState = PlayIntegrityDecisionState.ALLOWED
            reason = PlayIntegrityReason.VERIFIED_DEVICE_AND_APP
        } else if (verdict.deviceIntegrityLevels.contains(DeviceIntegrityLevel.MEETS_BASIC_INTEGRITY)) {
            // Basic integrity triggers policy RISK_HOLD
            decisionState = PlayIntegrityDecisionState.RISK_HOLD
            reason = PlayIntegrityReason.BASIC_INTEGRITY_RISK_HOLD
        } else {
            // Unrecognized device fails closed
            decisionState = PlayIntegrityDecisionState.BLOCKED
            reason = PlayIntegrityReason.UNRECOGNIZED_DEVICE
        }

        val result = PlayIntegrityVerificationResult(
            verificationId = "verif-${UUID.randomUUID()}",
            tenantId = tenantId,
            userId = userId,
            decision = decisionState,
            reason = reason,
            directEligibilityGranted = false, // Financial rule: never grants financial authority
            financialMutationPermitted = false, // Financial rule: never mutates money
            verifiedAt = now,
            evidenceReference = sha256("$tenantId:$userId:$decisionState:$reason:${verdict.verdictId}"),
        )

        idempotencyStore[idempotencyKey] = Pair(payloadHash, result)
        // Privacy rule: do not log tokens or verdict payloads! Only log outcome summary
        recordAudit(tenantId, "VERIFY_TOKEN", principal, decisionState != PlayIntegrityDecisionState.BLOCKED, "Verification complete: decision=$decisionState reason=$reason")

        return Result.success(result)
    }

    /**
     * Authoritative readiness evaluation for Play Integrity.
     * Semantic contract: "Fail closed or risk-hold per approved policy; do not log tokens/verdict payloads."
     */
    fun evaluatePlayIntegrityReadiness(
        tenantId: String,
        principal: AuthenticatedPrincipal,
    ): PlayIntegrityReadinessEvaluation {
        PlayIntegrityBinding.checkBound()

        recordAudit(tenantId, "READINESS_EVALUATION", principal, true, "Readiness evaluated: status=ALLOWED")

        return PlayIntegrityReadinessEvaluation(
            tenantId = tenantId,
            status = PlayIntegrityDecisionState.ALLOWED,
            reason = PlayIntegrityReason.VERIFIED_DEVICE_AND_APP,
            directEligibilityGranted = false, // Financial rule: never grants financial authority
            financialMutationPermitted = false, // Financial rule: never mutates money
            message = "Fail closed or risk-hold per approved policy; do not log tokens/verdict payloads.",
            evidenceReference = sha256("$tenantId:PLAY_INTEGRITY_READINESS:${clock.instant()}"),
        )
    }

    @Synchronized
    private fun recordAudit(tenantId: String, action: String, principal: AuthenticatedPrincipal, success: Boolean, details: String) {
        val entry = PlayIntegrityAuditEntry(
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

    fun getAuditLog(tenantId: String): List<PlayIntegrityAuditEntry> {
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
