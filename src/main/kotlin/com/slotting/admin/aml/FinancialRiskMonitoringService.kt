package com.slotting.admin.aml

import com.slotting.admin.auth.*
import java.security.MessageDigest
import java.time.Clock
import java.time.Instant
import java.util.UUID

enum class RiskTransactionType {
    DEPOSIT,
    WITHDRAWAL,
    WAGER,
    PAYOUT,
}

enum class RuleEvaluationOutcome {
    CLEARED,
    BREACH_DETECTED,
    AMBIGUOUS_EVALUATION,
}

enum class RiskDecisionStatus {
    APPROVED,
    HOLD,
    REJECTED,
}

data class FinancialRiskRuleConfig(
    val configVersion: Long = 1L,
    val singleTransactionLimitMinorUnits: Long = 1_000_000L, // 10,000 EUR
    val velocityMaxCountInWindow: Int = 5,
    val structuringLowerLimitMinorUnits: Long = 900_000L,   // 9,000 EUR
    val structuringUpperLimitMinorUnits: Long = 999_999L,   // 9,999 EUR
    val cumulativeVolumeLimitMinorUnits: Long = 5_000_000L, // 50,000 EUR
)

data class FinancialRiskEvaluationCommand(
    val principal: AuthenticatedPrincipal?,
    val sessionId: String,
    val tenantId: String,
    val subjectReference: String,
    val transactionReference: String,
    val transactionType: RiskTransactionType,
    val amountMinorUnits: Long,
    val currencyCode: String,
    val historicalCountInWindow: Int = 0,
    val historicalVolumeInWindowMinorUnits: Long = 0L,
    val idempotencyKey: String,
    val correlationId: String,
    val causationId: String,
    val expectedVersion: Long = 1L,
)

data class RiskDecisionProvenance(
    val configVersion: Long,
    val breachedRules: List<String>,
    val evaluatedAmountMinorUnits: Long,
    val observedVelocityCount: Int,
    val observedVolumeMinorUnits: Long,
    val evaluatedAt: Instant,
)

data class FinancialRiskEvaluationResult(
    val resultId: UUID,
    val tenantId: String,
    val subjectReference: String,
    val transactionReference: String,
    val outcome: RuleEvaluationOutcome,
    val status: RiskDecisionStatus,
    val amlReason: AmlReviewReason?,
    val amlCaseReference: String?,
    val provenance: RiskDecisionProvenance,
    val financialAuthorityCreated: Boolean, // Invariant: No financial authority created
    val moneyMutated: Boolean,             // Invariant: Cannot mutate money
    val evidenceReference: String,
    val serverTime: Instant,
)

interface FinancialRiskMonitoringStore {
    fun findByIdempotency(tenantId: String, idempotencyKey: String): Pair<String, FinancialRiskEvaluationResult>?
    fun save(
        result: FinancialRiskEvaluationResult,
        tenantId: String,
        queryFingerprint: String,
        idempotencyKey: String,
        audit: AuditEvent,
        outbox: OutboxEvent,
        queuedAmlItem: AmlQueueItem? = null,
    )
}

class FinancialRiskMonitoringService(
    private val policy: AdminRbacPolicy,
    private val sessions: AdminSessionDirectory,
    private val store: FinancialRiskMonitoringStore,
    private val config: FinancialRiskRuleConfig = FinancialRiskRuleConfig(),
    private val clock: Clock = Clock.systemUTC(),
) {
    @Synchronized
    fun evaluateTransaction(command: FinancialRiskEvaluationCommand): FinancialRiskEvaluationResult {
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
            command.transactionReference.isBlank() ||
            command.sessionId.isBlank() ||
            command.correlationId.isBlank() ||
            command.causationId.isBlank() ||
            command.amountMinorUnits <= 0L ||
            command.currencyCode.length != 3
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

        val breachedRules = mutableListOf<String>()
        var amlReason: AmlReviewReason? = null

        // 1. Single transaction limit check
        if (command.amountMinorUnits > config.singleTransactionLimitMinorUnits) {
            breachedRules += "SINGLE_TRANSACTION_LIMIT_EXCEEDED"
            amlReason = AmlReviewReason.HIGH_RISK_ACTION
        }

        // 2. Structuring detection check (e.g. 9,000..9,999 EUR)
        if (command.amountMinorUnits in config.structuringLowerLimitMinorUnits..config.structuringUpperLimitMinorUnits) {
            breachedRules += "POTENTIAL_STRUCTURING_DETECTED"
            if (amlReason == null) {
                amlReason = AmlReviewReason.STRUCTURING_ALERT
            }
        }

        // 3. Velocity burst limit check
        if (command.historicalCountInWindow > config.velocityMaxCountInWindow) {
            breachedRules += "VELOCITY_LIMIT_EXCEEDED"
            if (amlReason == null) {
                amlReason = AmlReviewReason.SUSPICIOUS_ACTIVITY
            }
        }

        // 4. Cumulative volume limit check
        if ((command.historicalVolumeInWindowMinorUnits + command.amountMinorUnits) > config.cumulativeVolumeLimitMinorUnits) {
            breachedRules += "CUMULATIVE_VOLUME_EXCEEDED"
            if (amlReason == null) {
                amlReason = AmlReviewReason.SUSPICIOUS_ACTIVITY
            }
        }

        val (outcome, status) = if (breachedRules.isNotEmpty()) {
            RuleEvaluationOutcome.BREACH_DETECTED to RiskDecisionStatus.HOLD
        } else {
            RuleEvaluationOutcome.CLEARED to RiskDecisionStatus.APPROVED
        }

        val (amlCaseRef, queueItem) = if (status == RiskDecisionStatus.HOLD) {
            val caseRef = "AML-CASE-${command.transactionReference}"
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
        val provenance = RiskDecisionProvenance(
            configVersion = config.configVersion,
            breachedRules = breachedRules,
            evaluatedAmountMinorUnits = command.amountMinorUnits,
            observedVelocityCount = command.historicalCountInWindow,
            observedVolumeMinorUnits = command.historicalVolumeInWindowMinorUnits,
            evaluatedAt = now,
        )

        val result = FinancialRiskEvaluationResult(
            resultId = resultId,
            tenantId = command.tenantId,
            subjectReference = command.subjectReference,
            transactionReference = command.transactionReference,
            outcome = outcome,
            status = status,
            amlReason = amlReason,
            amlCaseReference = amlCaseRef,
            provenance = provenance,
            financialAuthorityCreated = false, // Invariant: No financial authority created
            moneyMutated = false,             // Invariant: Cannot mutate money
            evidenceReference = "EVID-RISK-${command.transactionReference}",
            serverTime = now,
        )

        val audit = AuditEvent(
            eventId = UUID.randomUUID(),
            resultId = resultId,
            tenantId = command.tenantId,
            type = "AML_FINANCIAL_RISK_EVALUATION",
            occurredAt = now,
            correlationId = command.correlationId,
            causationId = command.causationId,
        )

        val outbox = OutboxEvent(
            eventId = UUID.randomUUID(),
            resultId = resultId,
            tenantId = command.tenantId,
            type = "AML_FINANCIAL_RISK_EVALUATION",
            createdAt = now,
        )

        store.save(result, command.tenantId, fp, command.idempotencyKey, audit, outbox, queueItem)
        return result
    }

    private fun fingerprint(command: FinancialRiskEvaluationCommand): String {
        val md = MessageDigest.getInstance("SHA-256")
        val raw = "${command.tenantId}:${command.subjectReference}:${command.transactionReference}:${command.transactionType}:${command.amountMinorUnits}:${command.currencyCode}:${command.historicalCountInWindow}:${command.historicalVolumeInWindowMinorUnits}:${command.expectedVersion}"
        return md.digest(raw.toByteArray(Charsets.UTF_8)).joinToString("") { "%02x".format(it) }
    }
}
