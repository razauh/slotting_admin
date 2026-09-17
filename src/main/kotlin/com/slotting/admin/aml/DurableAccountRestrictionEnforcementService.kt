package com.slotting.admin.aml

import com.slotting.admin.auth.*
import java.security.MessageDigest
import java.time.Clock
import java.time.Instant
import java.util.UUID

enum class AccountRestrictionType {
    NONE,
    FLAGGED,
    SUSPENDED_DEPOSITS,
    SUSPENDED_WITHDRAWALS,
    ACCOUNT_FROZEN,
}

enum class RestrictedActionType {
    LOGIN,
    DEPOSIT,
    WITHDRAWAL,
    WAGER,
}

enum class RestrictionEnforcementOutcome {
    ALLOWED,
    BLOCKED,
    MONITORED,
}

data class AccountRestrictionRecord(
    val tenantId: String,
    val subjectReference: String,
    val restrictionType: AccountRestrictionType,
    val reason: AmlReviewReason,
    val amlCaseReference: String?,
    val placedBy: String,
    val placedAt: Instant,
    val serverVersion: Long,
)

data class ApplyAccountRestrictionCommand(
    val principal: AuthenticatedPrincipal?,
    val sessionId: String,
    val tenantId: String,
    val subjectReference: String,
    val restrictionType: AccountRestrictionType,
    val reason: AmlReviewReason,
    val amlCaseReference: String? = null,
    val justification: String,
    val idempotencyKey: String,
    val correlationId: String,
    val causationId: String,
    val expectedVersion: Long = 1L,
)

data class AccountRestrictionResult(
    val resultId: UUID,
    val tenantId: String,
    val subjectReference: String,
    val restrictionType: AccountRestrictionType,
    val amlCaseReference: String,
    val queuedAmlItem: AmlQueueItem,
    val financialAuthorityCreated: Boolean, // Invariant: must be false
    val moneyMutated: Boolean,             // Invariant: must be false
    val evidenceReference: String,
    val serverTime: Instant,
)

data class EnforceRestrictionCommand(
    val tenantId: String,
    val subjectReference: String,
    val actionType: RestrictedActionType,
)

data class EnforcementDecision(
    val outcome: RestrictionEnforcementOutcome,
    val currentRestriction: AccountRestrictionType,
    val denialReason: String?,
    val evaluatedAt: Instant,
)

interface EphemeralRestrictionCache {
    fun getRestriction(tenantId: String, subjectReference: String): AccountRestrictionType?
    fun putRestriction(tenantId: String, subjectReference: String, restriction: AccountRestrictionType)
    fun evict(tenantId: String, subjectReference: String)
    fun flushAll()
}

interface DurableAccountRestrictionStore {
    fun findByIdempotency(tenantId: String, idempotencyKey: String): Pair<String, AccountRestrictionResult>?
    fun findRestriction(tenantId: String, subjectReference: String): AccountRestrictionRecord?
    fun save(
        record: AccountRestrictionRecord,
        result: AccountRestrictionResult,
        tenantId: String,
        queryFingerprint: String,
        idempotencyKey: String,
        audit: AuditEvent,
        outbox: OutboxEvent,
        queueItem: AmlQueueItem,
    )
}

class DurableAccountRestrictionEnforcementService(
    private val policy: AdminRbacPolicy,
    private val sessions: AdminSessionDirectory,
    private val store: DurableAccountRestrictionStore,
    private val cache: EphemeralRestrictionCache,
    private val clock: Clock = Clock.systemUTC(),
) {
    @Synchronized
    fun applyRestriction(command: ApplyAccountRestrictionCommand): AccountRestrictionResult {
        val principal = command.principal ?: throw AuthenticationFailure.Rejected(AuthErrorCode.UNAUTHENTICATED)
        if (principal.kind != PrincipalKind.ADMIN || principal.tenantId != command.tenantId) {
            throw AuthenticationFailure.Rejected(AuthErrorCode.FORBIDDEN)
        }

        val session = try {
            sessions.find(command.tenantId, principal.id, command.sessionId)
        } catch (_: Exception) {
            throw AuthenticationFailure.Rejected(AuthErrorCode.DEPENDENCY_UNAVAILABLE)
        } ?: throw AuthenticationFailure.Rejected(AuthErrorCode.FORBIDDEN)

        if (!session.active || session.expiresAt.isBefore(clock.instant())) {
            throw AuthenticationFailure.Rejected(AuthErrorCode.FORBIDDEN)
        }

        if (!policy.isPermitted(principal, AdminPermission.MANAGE_SECURITY)) {
            throw AuthenticationFailure.Rejected(AuthErrorCode.FORBIDDEN)
        }

        if (command.subjectReference.isBlank() ||
            command.justification.isBlank() ||
            command.sessionId.isBlank() ||
            command.correlationId.isBlank() ||
            command.causationId.isBlank()
        ) {
            throw AuthenticationFailure.Rejected(AuthErrorCode.INVALID)
        }

        if (command.expectedVersion != 1L) {
            throw AuthenticationFailure.Rejected(AuthErrorCode.STALE)
        }

        val fp = fingerprint(command)
        store.findByIdempotency(command.tenantId, command.idempotencyKey)?.let { (cachedFp, cachedResult) ->
            if (cachedFp != fp) throw AuthenticationFailure.Rejected(AuthErrorCode.CONFLICT)
            return cachedResult
        }

        val now = clock.instant()
        val resultId = UUID.randomUUID()
        val caseReference = command.amlCaseReference ?: "AML-CASE-${command.subjectReference}"

        // "Alert no case" prevented: Every restriction is backed by an atomic queued review case
        val caseItem = AmlQueueItem(
            caseReference = caseReference,
            state = AmlReviewState.QUEUED,
            claimedBy = null,
            claimExpiresAt = null,
            serverVersion = 0L,
        )

        val existing = store.findRestriction(command.tenantId, command.subjectReference)
        val newVersion = (existing?.serverVersion ?: 0L) + 1L

        val record = AccountRestrictionRecord(
            tenantId = command.tenantId,
            subjectReference = command.subjectReference,
            restrictionType = command.restrictionType,
            reason = command.reason,
            amlCaseReference = caseReference,
            placedBy = principal.id,
            placedAt = now,
            serverVersion = newVersion,
        )

        // Ephemeral cache write: Populated in cache, but durable store is source of truth
        cache.putRestriction(command.tenantId, command.subjectReference, command.restrictionType)

        val result = AccountRestrictionResult(
            resultId = resultId,
            tenantId = command.tenantId,
            subjectReference = command.subjectReference,
            restrictionType = command.restrictionType,
            amlCaseReference = caseReference,
            queuedAmlItem = caseItem,
            financialAuthorityCreated = false, // Invariant: No financial authority created
            moneyMutated = false,             // Invariant: Cannot mutate money
            evidenceReference = "EVID-RESTRICT-${command.subjectReference}",
            serverTime = now,
        )

        val audit = AuditEvent(
            eventId = UUID.randomUUID(),
            resultId = resultId,
            tenantId = command.tenantId,
            type = "AML_ACCOUNT_RESTRICTION_APPLIED",
            occurredAt = now,
            correlationId = command.correlationId,
            causationId = command.causationId,
        )

        val outbox = OutboxEvent(
            eventId = UUID.randomUUID(),
            resultId = resultId,
            tenantId = command.tenantId,
            type = "AML_ACCOUNT_RESTRICTION_APPLIED",
            createdAt = now,
        )

        store.save(record, result, command.tenantId, fp, command.idempotencyKey, audit, outbox, caseItem)
        return result
    }

    private fun fingerprint(command: ApplyAccountRestrictionCommand): String {
        val md = MessageDigest.getInstance("SHA-256")
        val raw = "${command.tenantId}:${command.subjectReference}:${command.restrictionType}:${command.reason}:${command.justification}:${command.expectedVersion}"
        return md.digest(raw.toByteArray(Charsets.UTF_8)).joinToString("") { "%02x".format(it) }
    }

    @Synchronized
    fun enforceAction(command: EnforceRestrictionCommand): EnforcementDecision {
        val cached = cache.getRestriction(command.tenantId, command.subjectReference)
        val restriction = if (cached != null) {
            cached
        } else {
            // Ephemeral cache loss never erases restriction: fall back to durable store
            val durable = store.findRestriction(command.tenantId, command.subjectReference)
            val r = durable?.restrictionType ?: AccountRestrictionType.NONE
            cache.putRestriction(command.tenantId, command.subjectReference, r)
            r
        }

        val (outcome, reason) = when (restriction) {
            AccountRestrictionType.ACCOUNT_FROZEN -> {
                if (command.actionType in setOf(RestrictedActionType.DEPOSIT, RestrictedActionType.WITHDRAWAL, RestrictedActionType.WAGER)) {
                    RestrictionEnforcementOutcome.BLOCKED to "Account is FROZEN due to AML/fraud restriction"
                } else {
                    RestrictionEnforcementOutcome.ALLOWED to null
                }
            }
            AccountRestrictionType.SUSPENDED_WITHDRAWALS -> {
                if (command.actionType == RestrictedActionType.WITHDRAWAL) {
                    RestrictionEnforcementOutcome.BLOCKED to "Withdrawals are SUSPENDED on this account"
                } else {
                    RestrictionEnforcementOutcome.ALLOWED to null
                }
            }
            AccountRestrictionType.SUSPENDED_DEPOSITS -> {
                if (command.actionType == RestrictedActionType.DEPOSIT) {
                    RestrictionEnforcementOutcome.BLOCKED to "Deposits are SUSPENDED on this account"
                } else {
                    RestrictionEnforcementOutcome.ALLOWED to null
                }
            }
            AccountRestrictionType.FLAGGED -> {
                RestrictionEnforcementOutcome.MONITORED to "Account is FLAGGED for heightened surveillance"
            }
            AccountRestrictionType.NONE -> {
                RestrictionEnforcementOutcome.ALLOWED to null
            }
        }

        return EnforcementDecision(
            outcome = outcome,
            currentRestriction = restriction,
            denialReason = reason,
            evaluatedAt = clock.instant(),
        )
    }
}
