package com.slotting.admin.crm

import com.slotting.admin.auth.*
import java.security.MessageDigest
import java.time.Clock
import java.time.Instant
import java.util.UUID

/**
 * Fail-closed verification gate for CRM-002-01.
 * Throws expected RED failure until contract bindings and invariant protections are verified.
 */
object VersionedConsentBinding {
    @Volatile
    var isBound: Boolean = false

    fun checkBound() {
        if (!isBound) {
            throw AssertionError("marketing without consent/self-excluded promo")
        }
    }
}

enum class ConsentChannel {
    EMAIL,
    SMS,
    PUSH_NOTIFICATION,
    IN_APP,
    DIRECT_MAIL,
}

enum class ConsentPurpose {
    MARKETING_PROMOTIONS,
    NEWSLETTER,
    THIRD_PARTY_OFFERS,
    TRANSACTIONAL_ESSENTIAL,
}

enum class ConsentState {
    CONSENTED,
    WITHDRAWN,
    SUPPRESSED_SELF_EXCLUSION,
}

enum class VipTier {
    NONE,
    STANDARD,
    VIP_BRONZE,
    VIP_SILVER,
    VIP_GOLD,
    VIP_PLATINUM,
}

data class VersionedConsentRecord(
    val recordId: UUID,
    val tenantId: String,
    val playerId: String,
    val channel: ConsentChannel,
    val purpose: ConsentPurpose,
    val state: ConsentState,
    val policyVersion: String,
    val vipTier: VipTier,
    val vipGrantsFinancialPrivilege: Boolean, // Invariant: Always false (VIP tag grants no financial privilege)
    val vipGrantsAdminPrivilege: Boolean,     // Invariant: Always false (VIP tag grants no admin privilege)
    val moneyMutated: Boolean,                // Invariant: Always false (consent records never mutate money)
    val financialAuthorityCreated: Boolean,   // Invariant: Always false
    val version: Long,
    val updatedAt: Instant,
    val evidenceReference: String,
)

data class RecordVersionedConsentCommand(
    val principal: AuthenticatedPrincipal?,
    val sessionId: String,
    val tenantId: String,
    val playerId: String,
    val channel: ConsentChannel,
    val purpose: ConsentPurpose,
    val state: ConsentState,
    val policyVersion: String,
    val vipTier: VipTier = VipTier.NONE,
    val idempotencyKey: String,
    val correlationId: String,
    val causationId: String,
    val expectedVersion: Long = 1L,
    // Prohibited boundary parameters:
    val requestsAdminPrivilege: Boolean = false,
    val requestsFinancialPrivilege: Boolean = false,
    val financialBalanceAdjustmentMinorUnits: Long? = null,
)

interface PlayerExclusionDirectory {
    fun isSelfExcluded(tenantId: String, playerId: String): Boolean
}

interface VersionedConsentStore {
    fun findLatest(
        tenantId: String,
        playerId: String,
        channel: ConsentChannel,
        purpose: ConsentPurpose,
    ): VersionedConsentRecord?

    fun findByIdempotency(
        tenantId: String,
        idempotencyKey: String,
    ): Pair<String, VersionedConsentRecord>?

    fun save(
        record: VersionedConsentRecord,
        tenantId: String,
        fingerprint: String,
        idempotencyKey: String,
        audit: AuditEvent,
        outbox: OutboxEvent,
    )
}

class VersionedConsentService(
    private val policy: AdminRbacPolicy,
    private val sessions: AdminSessionDirectory,
    private val exclusionDirectory: PlayerExclusionDirectory,
    private val store: VersionedConsentStore,
    private val clock: Clock = Clock.systemUTC(),
) {
    @Synchronized
    fun recordConsent(command: RecordVersionedConsentCommand): VersionedConsentRecord {
        VersionedConsentBinding.checkBound()

        // 1. Boundary check: VIP tag grants no financial/admin privilege; money cannot be mutated
        if (command.requestsAdminPrivilege ||
            command.requestsFinancialPrivilege ||
            (command.financialBalanceAdjustmentMinorUnits != null && command.financialBalanceAdjustmentMinorUnits != 0L)
        ) {
            throw AuthenticationFailure.Rejected(AuthErrorCode.FORBIDDEN)
        }

        // 2. Input validation
        if (command.playerId.isBlank() ||
            command.policyVersion.isBlank() ||
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

        // 4. Idempotency check
        val fp = fingerprint(command)
        store.findByIdempotency(command.tenantId, command.idempotencyKey)?.let { (cachedFp, cachedRecord) ->
            if (cachedFp != fp) throw AuthenticationFailure.Rejected(AuthErrorCode.CONFLICT)
            return cachedRecord
        }

        // 5. Session and role authorization
        val currentRecord = store.findLatest(command.tenantId, command.playerId, command.channel, command.purpose)
        val currentVipTier = currentRecord?.vipTier ?: VipTier.NONE

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
        } else if (principal.kind == PrincipalKind.PLAYER) {
            // Player can only modify their own consent
            if (principal.id != command.playerId) {
                throw AuthenticationFailure.Rejected(AuthErrorCode.FORBIDDEN)
            }
            // Players cannot self-assign or modify VIP tags
            if (command.vipTier != VipTier.NONE && command.vipTier != currentVipTier) {
                throw AuthenticationFailure.Rejected(AuthErrorCode.FORBIDDEN)
            }
        } else {
            throw AuthenticationFailure.Rejected(AuthErrorCode.FORBIDDEN)
        }

        // 6. Version concurrency check
        val expectedVersion = if (currentRecord == null) 1L else currentRecord.version + 1L
        if (command.expectedVersion != expectedVersion) {
            throw AuthenticationFailure.Rejected(AuthErrorCode.STALE)
        }

        // 7. Responsible gaming / self-exclusion check: prevent marketing without consent / self-excluded promo
        val isExcluded = try {
            exclusionDirectory.isSelfExcluded(command.tenantId, command.playerId)
        } catch (_: Exception) {
            throw AuthenticationFailure.Rejected(AuthErrorCode.DEPENDENCY_UNAVAILABLE)
        }

        if (isExcluded && command.purpose != ConsentPurpose.TRANSACTIONAL_ESSENTIAL) {
            if (command.state == ConsentState.CONSENTED) {
                // Reject marketing consent for self-excluded player fail-closed
                throw AuthenticationFailure.Rejected(AuthErrorCode.FORBIDDEN)
            }
        }

        // 8. Build authoritative versioned record
        val now = clock.instant()
        val recordId = UUID.randomUUID()
        val effectiveState = if (isExcluded && command.purpose != ConsentPurpose.TRANSACTIONAL_ESSENTIAL) {
            ConsentState.SUPPRESSED_SELF_EXCLUSION
        } else {
            command.state
        }

        val effectiveVipTier = if (principal.kind == PrincipalKind.PLAYER) {
            currentVipTier
        } else {
            command.vipTier
        }

        val record = VersionedConsentRecord(
            recordId = recordId,
            tenantId = command.tenantId,
            playerId = command.playerId,
            channel = command.channel,
            purpose = command.purpose,
            state = effectiveState,
            policyVersion = command.policyVersion,
            vipTier = effectiveVipTier,
            vipGrantsFinancialPrivilege = false, // Invariant: Always false
            vipGrantsAdminPrivilege = false,     // Invariant: Always false
            moneyMutated = false,                // Invariant: Always false
            financialAuthorityCreated = false,   // Invariant: Always false
            version = expectedVersion,
            updatedAt = now,
            evidenceReference = "EVID-CONSENT-${command.tenantId}-${command.playerId}-${command.channel.name}-${command.purpose.name}-v$expectedVersion",
        )

        val audit = AuditEvent(
            eventId = UUID.randomUUID(),
            resultId = recordId,
            tenantId = command.tenantId,
            type = "COMMUNICATION_CONSENT_${effectiveState.name}",
            occurredAt = now,
            correlationId = command.correlationId,
            causationId = command.causationId,
        )

        val outbox = OutboxEvent(
            eventId = UUID.randomUUID(),
            resultId = recordId,
            tenantId = command.tenantId,
            type = "COMMUNICATION_CONSENT_${effectiveState.name}",
            createdAt = now,
        )

        store.save(record, command.tenantId, fp, command.idempotencyKey, audit, outbox)
        return record
    }

    private fun fingerprint(command: RecordVersionedConsentCommand): String {
        val md = MessageDigest.getInstance("SHA-256")
        val raw = "${command.tenantId}:${command.playerId}:${command.channel}:${command.purpose}:${command.state}:${command.policyVersion}:${command.vipTier}:${command.expectedVersion}"
        return md.digest(raw.toByteArray(Charsets.UTF_8)).joinToString("") { "%02x".format(it) }
    }
}
