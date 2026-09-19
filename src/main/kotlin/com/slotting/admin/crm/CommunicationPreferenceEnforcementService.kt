package com.slotting.admin.crm

import com.slotting.admin.auth.*
import java.security.MessageDigest
import java.time.Clock
import java.time.Instant
import java.util.UUID

/**
 * Fail-closed verification gate for CRM-002-02.
 * Throws expected RED failure until contract bindings and invariant protections are verified.
 */
object CommunicationPreferenceEnforcementBinding {
    @Volatile
    var isBound: Boolean = false

    fun checkBound() {
        if (!isBound) {
            throw AssertionError("marketing without consent/self-excluded promo")
        }
    }
}

enum class EnforcementDecision {
    ALLOWED,
    BLOCKED_NO_CONSENT,
    BLOCKED_SELF_EXCLUDED,
    BLOCKED_WITHDRAWN,
}

data class EnforceCommunicationPreferenceCommand(
    val principal: AuthenticatedPrincipal?,
    val sessionId: String,
    val tenantId: String,
    val playerId: String,
    val channel: ConsentChannel,
    val purpose: ConsentPurpose,
    val campaignReference: String,
    val idempotencyKey: String,
    val correlationId: String,
    val causationId: String,
    val expectedVersion: Long = 1L,
    // Prohibited boundary parameters:
    val requestsAdminPrivilege: Boolean = false,
    val requestsFinancialPrivilege: Boolean = false,
    val financialBalanceAdjustmentMinorUnits: Long? = null,
    val bypassConsentForVip: Boolean = false,
)

data class CommunicationEnforcementResult(
    val resultId: UUID,
    val tenantId: String,
    val playerId: String,
    val channel: ConsentChannel,
    val purpose: ConsentPurpose,
    val campaignReference: String,
    val decision: EnforcementDecision,
    val isAllowed: Boolean,
    val effectiveVipTier: VipTier,
    val vipGrantsFinancialPrivilege: Boolean, // Invariant: Always false
    val vipGrantsAdminPrivilege: Boolean,     // Invariant: Always false
    val moneyMutated: Boolean,                // Invariant: Always false
    val financialAuthorityCreated: Boolean,   // Invariant: Always false
    val evidenceReference: String,
    val serverTime: Instant,
    val version: Long,
)

data class CommunicationDispatchOutcome(
    val dispatched: Boolean,
    val dispatchToken: String,
    val timestamp: Instant,
)

interface CommunicationDispatchPort {
    fun dispatchMessage(
        tenantId: String,
        playerId: String,
        channel: ConsentChannel,
        purpose: ConsentPurpose,
        campaignReference: String,
    ): CommunicationDispatchOutcome
}

interface CommunicationEnforcementStore {
    fun findByIdempotency(
        tenantId: String,
        idempotencyKey: String,
    ): Pair<String, CommunicationEnforcementResult>?

    fun save(
        result: CommunicationEnforcementResult,
        tenantId: String,
        fingerprint: String,
        idempotencyKey: String,
        audit: AuditEvent,
        outbox: OutboxEvent,
    )
}

class CommunicationPreferenceEnforcementService(
    private val policy: AdminRbacPolicy,
    private val sessions: AdminSessionDirectory,
    private val exclusionDirectory: PlayerExclusionDirectory,
    private val consentStore: VersionedConsentStore,
    private val enforcementStore: CommunicationEnforcementStore,
    private val dispatchPort: CommunicationDispatchPort? = null,
    private val clock: Clock = Clock.systemUTC(),
) {
    @Synchronized
    fun enforcePreference(command: EnforceCommunicationPreferenceCommand): CommunicationEnforcementResult {
        CommunicationPreferenceEnforcementBinding.checkBound()

        // 1. Boundary check: VIP tag grants no financial/admin privilege; consent bypass prohibited
        if (command.requestsAdminPrivilege ||
            command.requestsFinancialPrivilege ||
            command.bypassConsentForVip ||
            (command.financialBalanceAdjustmentMinorUnits != null && command.financialBalanceAdjustmentMinorUnits != 0L)
        ) {
            throw AuthenticationFailure.Rejected(AuthErrorCode.FORBIDDEN)
        }

        // 2. Input validation
        if (command.playerId.isBlank() ||
            command.campaignReference.isBlank() ||
            command.sessionId.isBlank() ||
            command.correlationId.isBlank() ||
            command.causationId.isBlank()
        ) {
            throw AuthenticationFailure.Rejected(AuthErrorCode.INVALID)
        }

        // 3. Principal authentication and tenancy
        val principal = command.principal ?: throw AuthenticationFailure.Rejected(AuthErrorCode.UNAUTHENTICATED)
        if (principal.tenantId != command.tenantId) {
            throw AuthenticationFailure.Rejected(AuthErrorCode.FORBIDDEN)
        }

        // 4. Idempotency check (before state lookup / version checks)
        val fp = fingerprint(command)
        enforcementStore.findByIdempotency(command.tenantId, command.idempotencyKey)?.let { (cachedFp, cachedResult) ->
            if (cachedFp != fp) throw AuthenticationFailure.Rejected(AuthErrorCode.CONFLICT)
            return cachedResult
        }

        // 5. Session and authorization
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
            // Player kind cannot trigger operator preference enforcement
            throw AuthenticationFailure.Rejected(AuthErrorCode.FORBIDDEN)
        }

        // 6. Version check
        if (command.expectedVersion != 1L) {
            throw AuthenticationFailure.Rejected(AuthErrorCode.STALE)
        }

        // 7. Authoritative self-exclusion check (Responsible gaming override)
        val isExcluded = try {
            exclusionDirectory.isSelfExcluded(command.tenantId, command.playerId)
        } catch (_: Exception) {
            throw AuthenticationFailure.Rejected(AuthErrorCode.DEPENDENCY_UNAVAILABLE)
        }

        // Retrieve existing consent record for player/channel/purpose
        val consentRecord = consentStore.findLatest(command.tenantId, command.playerId, command.channel, command.purpose)
        val effectiveVipTier = consentRecord?.vipTier ?: VipTier.NONE

        // Decision logic: marketing without consent / self-excluded promo strictly prevented
        val decision = when {
            isExcluded && command.purpose != ConsentPurpose.TRANSACTIONAL_ESSENTIAL ->
                EnforcementDecision.BLOCKED_SELF_EXCLUDED
            command.purpose == ConsentPurpose.TRANSACTIONAL_ESSENTIAL ->
                EnforcementDecision.ALLOWED
            consentRecord == null ->
                EnforcementDecision.BLOCKED_NO_CONSENT
            consentRecord.state == ConsentState.WITHDRAWN ->
                EnforcementDecision.BLOCKED_WITHDRAWN
            consentRecord.state == ConsentState.SUPPRESSED_SELF_EXCLUSION ->
                EnforcementDecision.BLOCKED_SELF_EXCLUDED
            consentRecord.state == ConsentState.CONSENTED ->
                EnforcementDecision.ALLOWED
            else ->
                EnforcementDecision.BLOCKED_NO_CONSENT
        }

        val isAllowed = decision == EnforcementDecision.ALLOWED

        // If allowed and dispatch port configured, perform dispatch
        if (isAllowed && dispatchPort != null) {
            val dispatchOutcome = try {
                dispatchPort.dispatchMessage(
                    command.tenantId,
                    command.playerId,
                    command.channel,
                    command.purpose,
                    command.campaignReference,
                )
            } catch (_: Exception) {
                throw AuthenticationFailure.Rejected(AuthErrorCode.DEPENDENCY_UNAVAILABLE)
            }

            if (!dispatchOutcome.dispatched) {
                throw AuthenticationFailure.Rejected(AuthErrorCode.DEPENDENCY_UNAVAILABLE)
            }
        }

        val now = clock.instant()
        val resultId = UUID.randomUUID()
        val result = CommunicationEnforcementResult(
            resultId = resultId,
            tenantId = command.tenantId,
            playerId = command.playerId,
            channel = command.channel,
            purpose = command.purpose,
            campaignReference = command.campaignReference,
            decision = decision,
            isAllowed = isAllowed,
            effectiveVipTier = effectiveVipTier,
            vipGrantsFinancialPrivilege = false, // Invariant: Always false
            vipGrantsAdminPrivilege = false,     // Invariant: Always false
            moneyMutated = false,                // Invariant: Always false
            financialAuthorityCreated = false,   // Invariant: Always false
            evidenceReference = "EVID-ENFORCE-${command.tenantId}-${command.playerId}-${command.channel.name}-${decision.name}",
            serverTime = now,
            version = 1L,
        )

        val audit = AuditEvent(
            eventId = UUID.randomUUID(),
            resultId = resultId,
            tenantId = command.tenantId,
            type = "COMMUNICATION_ENFORCEMENT_${decision.name}",
            occurredAt = now,
            correlationId = command.correlationId,
            causationId = command.causationId,
        )

        val outbox = OutboxEvent(
            eventId = UUID.randomUUID(),
            resultId = resultId,
            tenantId = command.tenantId,
            type = "COMMUNICATION_ENFORCEMENT_${decision.name}",
            createdAt = now,
        )

        enforcementStore.save(result, command.tenantId, fp, command.idempotencyKey, audit, outbox)
        return result
    }

    private fun fingerprint(command: EnforceCommunicationPreferenceCommand): String {
        val md = MessageDigest.getInstance("SHA-256")
        val raw = "${command.tenantId}:${command.playerId}:${command.channel}:${command.purpose}:${command.campaignReference}:${command.expectedVersion}"
        return md.digest(raw.toByteArray(Charsets.UTF_8)).joinToString("") { "%02x".format(it) }
    }
}
