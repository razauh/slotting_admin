package com.slotting.admin.aml

import com.slotting.admin.auth.*
import java.security.MessageDigest
import java.time.Clock
import java.time.Instant
import java.util.UUID

enum class ScreeningCheckType {
    SANCTIONS,
    PEP,
    SANCTIONS_AND_PEP,
}

enum class SanctionsPepOutcome {
    CLEAR,
    SANCTION_HIT,
    PEP_MATCH,
    INDETERMINATE,
}

enum class ScreeningDecisionStatus {
    CLEARED,
    HOLD,
    REJECTED,
}

data class ApprovedThresholdConfig(
    val configVersion: Long = 1L,
    val sanctionsMatchThreshold: Double = 0.80,
    val pepMatchThreshold: Double = 0.85,
    val autoHoldOnHit: Boolean = true,
)

data class ScreeningSubject(
    val subjectReference: String,
    val fullName: String,
    val dateOfBirth: String? = null,
    val nationality: String? = null,
)

data class SanctionsPepScreeningCommand(
    val principal: AuthenticatedPrincipal?,
    val sessionId: String,
    val tenantId: String,
    val subject: ScreeningSubject,
    val checkType: ScreeningCheckType,
    val providerId: String,
    val idempotencyKey: String,
    val correlationId: String,
    val causationId: String,
    val expectedVersion: Long = 1L,
)

data class ScreeningDecisionProvenance(
    val providerId: String,
    val configVersion: Long,
    val appliedThreshold: Double,
    val observedScore: Double,
    val matchedLists: List<String>,
    val evaluatedAt: Instant,
)

data class SanctionsPepScreeningResult(
    val resultId: UUID,
    val tenantId: String,
    val subjectReference: String,
    val checkType: ScreeningCheckType,
    val outcome: SanctionsPepOutcome,
    val status: ScreeningDecisionStatus,
    val provenance: ScreeningDecisionProvenance,
    val amlCaseReference: String?,
    val financialAuthorityCreated: Boolean, // Invariant: No financial authority created
    val moneyMutated: Boolean,             // Invariant: Cannot mutate money
    val evidenceReference: String,
    val serverTime: Instant,
)

interface SanctionsPepVendorAdapter {
    val providerId: String
    fun screen(subject: ScreeningSubject, checkType: ScreeningCheckType): SanctionsPepVendorResponse
}

data class SanctionsPepVendorResponse(
    val matchScore: Double,
    val matchedLists: List<String>,
    val indeterminate: Boolean = false,
)

interface SanctionsPepScreeningStore {
    fun findByIdempotency(tenantId: String, idempotencyKey: String): Pair<String, SanctionsPepScreeningResult>?
    fun save(
        result: SanctionsPepScreeningResult,
        tenantId: String,
        queryFingerprint: String,
        idempotencyKey: String,
        audit: AuditEvent,
        outbox: OutboxEvent,
        queuedAmlItem: AmlQueueItem? = null,
    )
}

class SanctionsPepScreeningService(
    private val policy: AdminRbacPolicy,
    private val sessions: AdminSessionDirectory,
    private val store: SanctionsPepScreeningStore,
    private val thresholdConfig: ApprovedThresholdConfig = ApprovedThresholdConfig(),
    private val adapters: Map<String, SanctionsPepVendorAdapter>,
    private val clock: Clock = Clock.systemUTC(),
) {
    @Synchronized
    fun screenSubject(command: SanctionsPepScreeningCommand): SanctionsPepScreeningResult {
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

        if (command.subject.subjectReference.isBlank() ||
            command.subject.fullName.isBlank() ||
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

        val adapter = adapters[command.providerId]
            ?: throw AuthenticationFailure.Rejected(AuthErrorCode.FORBIDDEN)

        val vendorResponse = try {
            adapter.screen(command.subject, command.checkType)
        } catch (_: Exception) {
            throw AuthenticationFailure.Rejected(AuthErrorCode.DEPENDENCY_UNAVAILABLE)
        }

        val (outcome, status, appliedThreshold) = when {
            vendorResponse.indeterminate -> Triple(
                SanctionsPepOutcome.INDETERMINATE,
                ScreeningDecisionStatus.HOLD,
                thresholdConfig.sanctionsMatchThreshold,
            )
            vendorResponse.matchScore >= thresholdConfig.sanctionsMatchThreshold -> Triple(
                SanctionsPepOutcome.SANCTION_HIT,
                ScreeningDecisionStatus.HOLD,
                thresholdConfig.sanctionsMatchThreshold,
            )
            command.checkType != ScreeningCheckType.SANCTIONS && vendorResponse.matchScore >= thresholdConfig.pepMatchThreshold -> Triple(
                SanctionsPepOutcome.PEP_MATCH,
                ScreeningDecisionStatus.HOLD,
                thresholdConfig.pepMatchThreshold,
            )
            else -> Triple(
                SanctionsPepOutcome.CLEAR,
                ScreeningDecisionStatus.CLEARED,
                thresholdConfig.sanctionsMatchThreshold,
            )
        }

        val (amlCaseRef, queueItem) = if (status == ScreeningDecisionStatus.HOLD) {
            val caseRef = "AML-CASE-${command.subject.subjectReference}"
            val item = AmlQueueItem(
                caseReference = caseRef,
                state = AmlReviewState.QUEUED,
                claimedBy = null,
                claimExpiresAt = null,
                serverVersion = 0L,
            )
            caseRef to item
        } else {
            null to null
        }

        val resultId = UUID.randomUUID()
        val now = clock.instant()
        val provenance = ScreeningDecisionProvenance(
            providerId = command.providerId,
            configVersion = thresholdConfig.configVersion,
            appliedThreshold = appliedThreshold,
            observedScore = vendorResponse.matchScore,
            matchedLists = vendorResponse.matchedLists,
            evaluatedAt = now,
        )

        val result = SanctionsPepScreeningResult(
            resultId = resultId,
            tenantId = command.tenantId,
            subjectReference = command.subject.subjectReference,
            checkType = command.checkType,
            outcome = outcome,
            status = status,
            provenance = provenance,
            amlCaseReference = amlCaseRef,
            financialAuthorityCreated = false, // Invariant: No financial authority created
            moneyMutated = false,             // Invariant: Cannot mutate money
            evidenceReference = "EVID-AML-${command.subject.subjectReference}",
            serverTime = now,
        )

        val audit = AuditEvent(
            eventId = UUID.randomUUID(),
            resultId = resultId,
            tenantId = command.tenantId,
            type = "AML_SANCTIONS_PEP_SCREENING",
            occurredAt = now,
            correlationId = command.correlationId,
            causationId = command.causationId,
        )

        val outbox = OutboxEvent(
            eventId = UUID.randomUUID(),
            resultId = resultId,
            tenantId = command.tenantId,
            type = "AML_SANCTIONS_PEP_SCREENING",
            createdAt = now,
        )

        store.save(result, command.tenantId, fp, command.idempotencyKey, audit, outbox, queueItem)
        return result
    }

    private fun fingerprint(command: SanctionsPepScreeningCommand): String {
        val md = MessageDigest.getInstance("SHA-256")
        val raw = "${command.tenantId}:${command.subject.subjectReference}:${command.subject.fullName}:${command.checkType}:${command.providerId}:${command.expectedVersion}"
        return md.digest(raw.toByteArray(Charsets.UTF_8)).joinToString("") { "%02x".format(it) }
    }
}
