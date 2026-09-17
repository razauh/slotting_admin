package com.slotting.admin.aml

import com.slotting.admin.auth.*
import java.security.MessageDigest
import java.time.Clock
import java.time.Instant
import java.util.UUID

enum class AmlAlertType {
    SUSPICIOUS_TRANSACTION,
    STRUCTURING_DETECTED,
    SANCTIONS_HIT,
    PEP_MATCH,
    DEVICE_COMPROMISE,
    VELOCITY_SPIKE,
    MANUAL_FLAG,
}

enum class AmlAlertSeverity {
    LOW,
    MEDIUM,
    HIGH,
    CRITICAL,
}

enum class AmlAccountRestriction {
    NONE,
    FLAGGED,
    SUSPENDED_DEPOSITS,
    SUSPENDED_WITHDRAWALS,
    ACCOUNT_FROZEN,
}

data class CreateAmlAlertCommand(
    val principal: AuthenticatedPrincipal?,
    val sessionId: String,
    val tenantId: String,
    val subjectReference: String,
    val alertType: AmlAlertType,
    val severity: AmlAlertSeverity,
    val reason: AmlReviewReason,
    val description: String,
    val restrictionApplied: AmlAccountRestriction = AmlAccountRestriction.NONE,
    val evidenceMetadata: Map<String, String> = emptyMap(),
    val idempotencyKey: String,
    val correlationId: String,
    val causationId: String,
    val expectedVersion: Long = 1L,
)

data class AmlAlertRecord(
    val alertId: UUID,
    val tenantId: String,
    val subjectReference: String,
    val caseReference: String,
    val alertType: AmlAlertType,
    val severity: AmlAlertSeverity,
    val reason: AmlReviewReason,
    val description: String,
    val restriction: AmlAccountRestriction,
    val createdAt: Instant,
)

data class AmlAlertCaseResult(
    val resultId: UUID,
    val alertId: UUID,
    val tenantId: String,
    val subjectReference: String,
    val caseReference: String,
    val alertType: AmlAlertType,
    val severity: AmlAlertSeverity,
    val restrictionApplied: AmlAccountRestriction,
    val caseItem: AmlQueueItem,
    val financialAuthorityCreated: Boolean, // Invariant: must be false
    val moneyMutated: Boolean,             // Invariant: must be false
    val evidenceReference: String,
    val createdAt: Instant,
)

interface EphemeralAmlRestrictionCache {
    fun getRestriction(tenantId: String, subjectReference: String): AmlAccountRestriction?
    fun putRestriction(tenantId: String, subjectReference: String, restriction: AmlAccountRestriction)
    fun evict(tenantId: String, subjectReference: String)
    fun flushAll()
}

interface AmlAlertCaseStore {
    fun findByIdempotency(tenantId: String, idempotencyKey: String): Pair<String, AmlAlertCaseResult>?
    fun findActiveRestriction(tenantId: String, subjectReference: String): AmlAccountRestriction?
    fun findAlert(tenantId: String, alertId: UUID): AmlAlertRecord?
    fun save(
        alert: AmlAlertRecord,
        result: AmlAlertCaseResult,
        tenantId: String,
        queryFingerprint: String,
        idempotencyKey: String,
        audit: AuditEvent,
        outbox: OutboxEvent,
        queueItem: AmlQueueItem,
    )
}

class AmlAlertCaseCreationService(
    private val policy: AdminRbacPolicy,
    private val sessions: AdminSessionDirectory,
    private val store: AmlAlertCaseStore,
    private val cache: EphemeralAmlRestrictionCache,
    private val clock: Clock = Clock.systemUTC(),
) {
    @Synchronized
    fun createAlertAndCase(command: CreateAmlAlertCommand): AmlAlertCaseResult {
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
            command.description.isBlank() ||
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
        val alertId = UUID.randomUUID()
        val resultId = UUID.randomUUID()
        val caseReference = "AML-CASE-${command.subjectReference}"

        // "Alert no case" prevented: Every AML alert atomically creates a review queue item
        val caseItem = AmlQueueItem(
            caseReference = caseReference,
            state = AmlReviewState.QUEUED,
            claimedBy = null,
            claimExpiresAt = null,
            serverVersion = 0L,
        )

        val alert = AmlAlertRecord(
            alertId = alertId,
            tenantId = command.tenantId,
            subjectReference = command.subjectReference,
            caseReference = caseReference,
            alertType = command.alertType,
            severity = command.severity,
            reason = command.reason,
            description = command.description,
            restriction = command.restrictionApplied,
            createdAt = now,
        )

        // Ephemeral cache write: Populated in cache, but durable store is source of truth
        if (command.restrictionApplied != AmlAccountRestriction.NONE) {
            cache.putRestriction(command.tenantId, command.subjectReference, command.restrictionApplied)
        }

        val result = AmlAlertCaseResult(
            resultId = resultId,
            alertId = alertId,
            tenantId = command.tenantId,
            subjectReference = command.subjectReference,
            caseReference = caseReference,
            alertType = command.alertType,
            severity = command.severity,
            restrictionApplied = command.restrictionApplied,
            caseItem = caseItem,
            financialAuthorityCreated = false, // Invariant: No financial authority created
            moneyMutated = false,             // Invariant: Cannot mutate money
            evidenceReference = "EVID-AML-ALERT-${command.subjectReference}",
            createdAt = now,
        )

        val audit = AuditEvent(
            eventId = UUID.randomUUID(),
            resultId = resultId,
            tenantId = command.tenantId,
            type = "AML_ALERT_CASE_CREATED",
            occurredAt = now,
            correlationId = command.correlationId,
            causationId = command.causationId,
        )

        val outbox = OutboxEvent(
            eventId = UUID.randomUUID(),
            resultId = resultId,
            tenantId = command.tenantId,
            type = "AML_ALERT_CASE_CREATED",
            createdAt = now,
        )

        store.save(alert, result, command.tenantId, fp, command.idempotencyKey, audit, outbox, caseItem)
        return result
    }

    private fun fingerprint(command: CreateAmlAlertCommand): String {
        val md = MessageDigest.getInstance("SHA-256")
        val raw = "${command.tenantId}:${command.subjectReference}:${command.alertType}:${command.severity}:${command.reason}:${command.description}:${command.restrictionApplied}:${command.expectedVersion}"
        return md.digest(raw.toByteArray(Charsets.UTF_8)).joinToString("") { "%02x".format(it) }
    }

    @Synchronized
    fun checkRestriction(tenantId: String, subjectReference: String): AmlAccountRestriction {
        // Check cache first
        val cached = cache.getRestriction(tenantId, subjectReference)
        if (cached != null) {
            return cached
        }
        // Ephemeral cache loss never erases restriction: fall back to durable store
        val durable = store.findActiveRestriction(tenantId, subjectReference) ?: AmlAccountRestriction.NONE
        cache.putRestriction(tenantId, subjectReference, durable)
        return durable
    }
}
