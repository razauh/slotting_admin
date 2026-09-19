package com.slotting.admin.crm

import com.slotting.admin.auth.*
import java.security.MessageDigest
import java.time.Clock
import java.time.Instant
import java.util.UUID

/**
 * Fail-closed verification gate for CRM-002-03.
 * Throws expected RED failure until contract bindings and invariant protections are verified.
 */
object NonAuthoritativeVipSegmentBinding {
    @Volatile
    var isBound: Boolean = false

    fun checkBound() {
        if (!isBound) {
            throw AssertionError("marketing without consent/self-excluded promo")
        }
    }
}

enum class VipSegmentOperation {
    ASSIGN_VIP_TIER,
    ASSIGN_SEGMENTS,
    REMOVE_VIP_TIER,
    CLEAR_SEGMENTS,
}

data class ControlVipSegmentCommand(
    val principal: AuthenticatedPrincipal?,
    val sessionId: String,
    val tenantId: String,
    val playerId: String,
    val operation: VipSegmentOperation,
    val targetVipTier: VipTier = VipTier.NONE,
    val targetSegments: Set<String> = emptySet(),
    val justification: String,
    val idempotencyKey: String,
    val correlationId: String,
    val causationId: String,
    val expectedVersion: Long = 1L,
    // Prohibited privilege / financial boundary parameters:
    val requestsAdminPrivilege: Boolean = false,
    val requestsFinancialPrivilege: Boolean = false,
    val financialBalanceAdjustmentMinorUnits: Long? = null,
    val forceMarketingEligibilityForSelfExcluded: Boolean = false,
)

data class VipSegmentControlResult(
    val resultId: UUID,
    val tenantId: String,
    val playerId: String,
    val operation: VipSegmentOperation,
    val vipTier: VipTier,
    val segments: Set<String>,
    val isAuthoritative: Boolean,             // Invariant: Always false (non-authoritative CRM metadata)
    val vipGrantsFinancialPrivilege: Boolean, // Invariant: Always false (VIP tag grants no financial privilege)
    val vipGrantsAdminPrivilege: Boolean,     // Invariant: Always false (VIP tag grants no admin privilege)
    val moneyMutated: Boolean,                // Invariant: Always false (VIP tag changes never mutate money)
    val financialAuthorityCreated: Boolean,   // Invariant: Always false
    val marketingSuppressedForExclusion: Boolean,
    val evidenceReference: String,
    val serverTime: Instant,
    val version: Long,
)

data class VipSegmentProfile(
    val tenantId: String,
    val playerId: String,
    val vipTier: VipTier,
    val segments: Set<String>,
    val version: Long,
    val updatedAt: Instant,
)

interface VipSegmentStore {
    fun findLatest(tenantId: String, playerId: String): VipSegmentProfile?
    fun findByIdempotency(tenantId: String, idempotencyKey: String): Pair<String, VipSegmentControlResult>?
    fun save(
        profile: VipSegmentProfile,
        result: VipSegmentControlResult,
        tenantId: String,
        fingerprint: String,
        idempotencyKey: String,
        audit: AuditEvent,
        outbox: OutboxEvent,
    )
}

class NonAuthoritativeVipSegmentService(
    private val policy: AdminRbacPolicy,
    private val sessions: AdminSessionDirectory,
    private val exclusionDirectory: PlayerExclusionDirectory,
    private val store: VipSegmentStore,
    private val clock: Clock = Clock.systemUTC(),
) {
    @Synchronized
    fun controlVipSegment(command: ControlVipSegmentCommand): VipSegmentControlResult {
        NonAuthoritativeVipSegmentBinding.checkBound()

        // 1. Boundary check: VIP tag grants no financial/admin privilege; money cannot be mutated
        if (command.requestsAdminPrivilege ||
            command.requestsFinancialPrivilege ||
            command.forceMarketingEligibilityForSelfExcluded ||
            (command.financialBalanceAdjustmentMinorUnits != null && command.financialBalanceAdjustmentMinorUnits != 0L)
        ) {
            throw AuthenticationFailure.Rejected(AuthErrorCode.FORBIDDEN)
        }

        // 2. Reject prohibited segment names attempting to fabricate privilege
        val prohibitedKeywords = setOf("admin", "financial", "credit", "balance", "bypass", "wallet", "ledger")
        for (segment in command.targetSegments) {
            val normalized = segment.lowercase().replace("_", "").replace("-", "")
            if (prohibitedKeywords.any { normalized.contains(it) }) {
                throw AuthenticationFailure.Rejected(AuthErrorCode.FORBIDDEN)
            }
        }

        // 3. Input validation
        if (command.playerId.isBlank() ||
            command.justification.isBlank() ||
            command.sessionId.isBlank() ||
            command.correlationId.isBlank() ||
            command.causationId.isBlank()
        ) {
            throw AuthenticationFailure.Rejected(AuthErrorCode.INVALID)
        }

        // 4. Principal authentication and tenancy
        val principal = command.principal ?: throw AuthenticationFailure.Rejected(AuthErrorCode.UNAUTHENTICATED)
        if (principal.tenantId != command.tenantId) {
            throw AuthenticationFailure.Rejected(AuthErrorCode.FORBIDDEN)
        }

        // 5. Idempotency check (before state mutations and version checks)
        val fp = fingerprint(command)
        store.findByIdempotency(command.tenantId, command.idempotencyKey)?.let { (cachedFp, cachedResult) ->
            if (cachedFp != fp) throw AuthenticationFailure.Rejected(AuthErrorCode.CONFLICT)
            return cachedResult
        }

        // 6. Session and RBAC authorization
        if (principal.kind == PrincipalKind.ADMIN) {
            val session = try {
                sessions.find(command.tenantId, principal.id, command.sessionId)
            } catch (_: Exception) {
                throw AuthenticationFailure.Rejected(AuthErrorCode.DEPENDENCY_UNAVAILABLE)
            } ?: throw AuthenticationFailure.Rejected(AuthErrorCode.FORBIDDEN)

            if (!session.active || session.expiresAt.isBefore(clock.instant())) {
                throw AuthenticationFailure.Rejected(AuthErrorCode.FORBIDDEN)
            }

            val permitted = policy.isPermitted(principal, AdminPermission.MANAGE_SUPPORT) ||
                policy.isPermitted(principal, AdminPermission.READ_SUPPORT) ||
                policy.isPermitted(principal, AdminPermission.MANAGE_SECURITY)

            if (!permitted) {
                throw AuthenticationFailure.Rejected(AuthErrorCode.FORBIDDEN)
            }
        } else {
            // Players cannot self-assign VIP tags or segments
            throw AuthenticationFailure.Rejected(AuthErrorCode.FORBIDDEN)
        }

        // 7. Version concurrency check
        val existingProfile = store.findLatest(command.tenantId, command.playerId)
        val expectedVersion = if (existingProfile == null) 1L else existingProfile.version + 1L
        if (command.expectedVersion != expectedVersion) {
            throw AuthenticationFailure.Rejected(AuthErrorCode.STALE)
        }

        // 8. Responsible Gaming / Self-exclusion check: prevent marketing without consent / self-excluded promo
        val isExcluded = try {
            exclusionDirectory.isSelfExcluded(command.tenantId, command.playerId)
        } catch (_: Exception) {
            throw AuthenticationFailure.Rejected(AuthErrorCode.DEPENDENCY_UNAVAILABLE)
        }

        val currentTier = existingProfile?.vipTier ?: VipTier.NONE
        val currentSegments = existingProfile?.segments ?: emptySet()

        val nextTier = when (command.operation) {
            VipSegmentOperation.ASSIGN_VIP_TIER -> command.targetVipTier
            VipSegmentOperation.REMOVE_VIP_TIER -> VipTier.NONE
            else -> currentTier
        }

        val nextSegments = when (command.operation) {
            VipSegmentOperation.ASSIGN_SEGMENTS -> currentSegments + command.targetSegments
            VipSegmentOperation.CLEAR_SEGMENTS -> emptySet()
            else -> currentSegments
        }

        val now = clock.instant()
        val resultId = UUID.randomUUID()
        val nextProfile = VipSegmentProfile(
            tenantId = command.tenantId,
            playerId = command.playerId,
            vipTier = nextTier,
            segments = nextSegments,
            version = expectedVersion,
            updatedAt = now,
        )

        val result = VipSegmentControlResult(
            resultId = resultId,
            tenantId = command.tenantId,
            playerId = command.playerId,
            operation = command.operation,
            vipTier = nextTier,
            segments = nextSegments,
            isAuthoritative = false,              // Strictly non-authoritative CRM metadata
            vipGrantsFinancialPrivilege = false,  // Invariant: Always false
            vipGrantsAdminPrivilege = false,      // Invariant: Always false
            moneyMutated = false,                 // Invariant: Always false
            financialAuthorityCreated = false,    // Invariant: Always false
            marketingSuppressedForExclusion = isExcluded,
            evidenceReference = "EVID-VIP-SEG-${command.tenantId}-${command.playerId}-${command.operation.name}-v$expectedVersion",
            serverTime = now,
            version = expectedVersion,
        )

        val audit = AuditEvent(
            eventId = UUID.randomUUID(),
            resultId = resultId,
            tenantId = command.tenantId,
            type = "VIP_SEGMENT_${command.operation.name}",
            occurredAt = now,
            correlationId = command.correlationId,
            causationId = command.causationId,
        )

        val outbox = OutboxEvent(
            eventId = UUID.randomUUID(),
            resultId = resultId,
            tenantId = command.tenantId,
            type = "VIP_SEGMENT_${command.operation.name}",
            createdAt = now,
        )

        store.save(nextProfile, result, command.tenantId, fp, command.idempotencyKey, audit, outbox)
        return result
    }

    private fun fingerprint(command: ControlVipSegmentCommand): String {
        val md = MessageDigest.getInstance("SHA-256")
        val raw = "${command.tenantId}:${command.playerId}:${command.operation}:${command.targetVipTier}:${command.targetSegments}:${command.expectedVersion}:${command.justification}"
        return md.digest(raw.toByteArray(Charsets.UTF_8)).joinToString("") { "%02x".format(it) }
    }
}
