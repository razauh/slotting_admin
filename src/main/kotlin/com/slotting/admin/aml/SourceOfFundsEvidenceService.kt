package com.slotting.admin.aml

import com.slotting.admin.auth.*
import java.security.MessageDigest
import java.time.Clock
import java.time.Duration
import java.time.Instant
import java.util.UUID

enum class SofEvidenceType {
    PAYSLIP,
    BANK_STATEMENT,
    TAX_RETURN,
    PROPERTY_SALE,
    INHERITANCE,
    BUSINESS_DIVIDEND,
}

enum class SofReviewStatus {
    PENDING_REVIEW,
    APPROVED,
    REJECTED,
    SUPERSEDED,
}

enum class SofPayoutEligibility {
    ELIGIBLE,
    HELD_FOR_SOF_REVIEW,
    BLOCKED_REJECTED,
}

data class SofEvidenceDocument(
    val documentReference: String,
    val evidenceType: SofEvidenceType,
    val checksumSha256: String,
    val issuingInstitution: String,
    val verifiedAmountMinorUnits: Long,
    val currencyCode: String,
)

data class CollectSofEvidenceCommand(
    val principal: AuthenticatedPrincipal?,
    val sessionId: String,
    val tenantId: String,
    val subjectReference: String,
    val evidence: SofEvidenceDocument,
    val supersedesRecordId: UUID? = null,
    val idempotencyKey: String,
    val correlationId: String,
    val causationId: String,
    val expectedVersion: Long = 1L,
)

data class SofDecisionRecord(
    val recordId: UUID,
    val tenantId: String,
    val subjectReference: String,
    val evidence: SofEvidenceDocument,
    val status: SofReviewStatus,
    val amlCaseReference: String,
    val supersedesRecordId: UUID?,
    val reviewedBy: String?,
    val reviewedAt: Instant?,
    val retentionExpiresAt: Instant,
    val serverVersion: Long,
    val createdAt: Instant,
)

data class SofEvidenceCollectionResult(
    val resultId: UUID,
    val recordId: UUID,
    val tenantId: String,
    val subjectReference: String,
    val status: SofReviewStatus,
    val amlCaseReference: String,
    val supersedesRecordId: UUID?,
    val retentionExpiresAt: Instant,
    val queuedAmlItem: AmlQueueItem,
    val financialAuthorityCreated: Boolean, // Invariant: must be false
    val moneyMutated: Boolean,             // Invariant: must be false
    val evidenceReference: String,
    val serverTime: Instant,
)

data class VerifySofPayoutEligibilityCommand(
    val tenantId: String,
    val subjectReference: String,
    val requestedPayoutMinorUnits: Long,
)

data class SofPayoutEligibilityDecision(
    val canPayout: Boolean,
    val eligibility: SofPayoutEligibility,
    val currentSofStatus: SofReviewStatus?,
    val activeCaseReference: String?,
    val denialReason: String?,
    val evaluatedAt: Instant,
)

interface SourceOfFundsStore {
    fun findByIdempotency(tenantId: String, idempotencyKey: String): Pair<String, SofEvidenceCollectionResult>?
    fun findLatestRecord(tenantId: String, subjectReference: String): SofDecisionRecord?
    fun findRecordById(tenantId: String, recordId: UUID): SofDecisionRecord?
    fun save(
        record: SofDecisionRecord,
        result: SofEvidenceCollectionResult,
        tenantId: String,
        queryFingerprint: String,
        idempotencyKey: String,
        audit: AuditEvent,
        outbox: OutboxEvent,
        queueItem: AmlQueueItem,
        supersededRecord: SofDecisionRecord? = null,
    )
}

class SourceOfFundsEvidenceService(
    private val policy: AdminRbacPolicy,
    private val sessions: AdminSessionDirectory,
    private val store: SourceOfFundsStore,
    private val clock: Clock = Clock.systemUTC(),
    private val retentionDuration: Duration = Duration.ofDays(365 * 5), // 5 years minimal retention per approved policy
) {
    @Synchronized
    fun collectEvidence(command: CollectSofEvidenceCommand): SofEvidenceCollectionResult {
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
            command.evidence.documentReference.isBlank() ||
            command.evidence.checksumSha256.isBlank() ||
            command.sessionId.isBlank() ||
            command.correlationId.isBlank() ||
            command.causationId.isBlank() ||
            command.evidence.verifiedAmountMinorUnits <= 0L ||
            command.evidence.currencyCode.length != 3
        ) {
            throw AuthenticationFailure.Rejected(AuthErrorCode.INVALID)
        }

        if (command.expectedVersion != 1L) {
            throw AuthenticationFailure.Rejected(AuthErrorCode.STALE)
        }

        val supersededRecord = if (command.supersedesRecordId != null) {
            val old = store.findRecordById(command.tenantId, command.supersedesRecordId)
                ?: throw AuthenticationFailure.Rejected(AuthErrorCode.INVALID)
            // Decision immutable: previous record is preserved and superseding record created
            old.copy(status = SofReviewStatus.SUPERSEDED)
        } else {
            null
        }

        val fp = fingerprint(command)
        store.findByIdempotency(command.tenantId, command.idempotencyKey)?.let { (cachedFp, cachedResult) ->
            if (cachedFp != fp) throw AuthenticationFailure.Rejected(AuthErrorCode.CONFLICT)
            return cachedResult
        }

        val now = clock.instant()
        val resultId = UUID.randomUUID()
        val recordId = UUID.randomUUID()
        val caseReference = "SOF-CASE-${command.subjectReference}"

        val caseItem = AmlQueueItem(
            caseReference = caseReference,
            state = AmlReviewState.QUEUED,
            claimedBy = null,
            claimExpiresAt = null,
            serverVersion = 0L,
        )

        val serverVersion = if (supersededRecord != null) supersededRecord.serverVersion + 1L else 1L
        val retentionExpiresAt = now.plus(retentionDuration)

        val record = SofDecisionRecord(
            recordId = recordId,
            tenantId = command.tenantId,
            subjectReference = command.subjectReference,
            evidence = command.evidence,
            status = SofReviewStatus.PENDING_REVIEW,
            amlCaseReference = caseReference,
            supersedesRecordId = command.supersedesRecordId,
            reviewedBy = null,
            reviewedAt = null,
            retentionExpiresAt = retentionExpiresAt,
            serverVersion = serverVersion,
            createdAt = now,
        )

        val result = SofEvidenceCollectionResult(
            resultId = resultId,
            recordId = recordId,
            tenantId = command.tenantId,
            subjectReference = command.subjectReference,
            status = SofReviewStatus.PENDING_REVIEW,
            amlCaseReference = caseReference,
            supersedesRecordId = command.supersedesRecordId,
            retentionExpiresAt = retentionExpiresAt,
            queuedAmlItem = caseItem,
            financialAuthorityCreated = false, // Invariant: No financial authority created
            moneyMutated = false,             // Invariant: Cannot mutate money
            evidenceReference = "EVID-SOF-${command.subjectReference}",
            serverTime = now,
        )

        val audit = AuditEvent(
            eventId = UUID.randomUUID(),
            resultId = resultId,
            tenantId = command.tenantId,
            type = "AML_SOF_EVIDENCE_COLLECTED",
            occurredAt = now,
            correlationId = command.correlationId,
            causationId = command.causationId,
        )

        val outbox = OutboxEvent(
            eventId = UUID.randomUUID(),
            resultId = resultId,
            tenantId = command.tenantId,
            type = "AML_SOF_EVIDENCE_COLLECTED",
            createdAt = now,
        )

        store.save(record, result, command.tenantId, fp, command.idempotencyKey, audit, outbox, caseItem, supersededRecord)
        return result
    }

    @Synchronized
    fun verifyPayoutEligibility(command: VerifySofPayoutEligibilityCommand): SofPayoutEligibilityDecision {
        val latest = store.findLatestRecord(command.tenantId, command.subjectReference)
        val now = clock.instant()

        if (latest == null || latest.status == SofReviewStatus.PENDING_REVIEW) {
            return SofPayoutEligibilityDecision(
                canPayout = false,
                eligibility = SofPayoutEligibility.HELD_FOR_SOF_REVIEW,
                currentSofStatus = latest?.status ?: SofReviewStatus.PENDING_REVIEW,
                activeCaseReference = latest?.amlCaseReference ?: "SOF-CASE-${command.subjectReference}",
                denialReason = "Payout held: Source of funds review required before release",
                evaluatedAt = now,
            )
        }

        if (latest.status == SofReviewStatus.REJECTED) {
            return SofPayoutEligibilityDecision(
                canPayout = false,
                eligibility = SofPayoutEligibility.BLOCKED_REJECTED,
                currentSofStatus = SofReviewStatus.REJECTED,
                activeCaseReference = latest.amlCaseReference,
                denialReason = "Payout blocked: Source of funds evidence rejected",
                evaluatedAt = now,
            )
        }

        if (latest.retentionExpiresAt.isBefore(now)) {
            return SofPayoutEligibilityDecision(
                canPayout = false,
                eligibility = SofPayoutEligibility.HELD_FOR_SOF_REVIEW,
                currentSofStatus = SofReviewStatus.PENDING_REVIEW,
                activeCaseReference = latest.amlCaseReference,
                denialReason = "Payout held: Source of funds evidence expired per retention policy",
                evaluatedAt = now,
            )
        }

        return SofPayoutEligibilityDecision(
            canPayout = true,
            eligibility = SofPayoutEligibility.ELIGIBLE,
            currentSofStatus = SofReviewStatus.APPROVED,
            activeCaseReference = null,
            denialReason = null,
            evaluatedAt = now,
        )
    }

    private fun fingerprint(command: CollectSofEvidenceCommand): String {
        val md = MessageDigest.getInstance("SHA-256")
        val raw = "${command.tenantId}:${command.subjectReference}:${command.evidence.documentReference}:${command.evidence.checksumSha256}:${command.evidence.verifiedAmountMinorUnits}:${command.evidence.currencyCode}:${command.supersedesRecordId}:${command.expectedVersion}"
        return md.digest(raw.toByteArray(Charsets.UTF_8)).joinToString("") { "%02x".format(it) }
    }
}
