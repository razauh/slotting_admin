package com.slotting.admin.governance

import com.slotting.admin.auth.*
import java.security.MessageDigest
import java.time.Clock
import java.time.Instant
import java.util.UUID
import java.util.concurrent.ConcurrentHashMap

/**
 * Binding flag to enforce the protected risk assertion for GOV-001-03:
 * "gate rejects missing approval"
 */
object TaxRegulatoryReportingBinding {
    @Volatile
    var isBound: Boolean = true

    fun checkBound() {
        if (!isBound) {
            throw AssertionError("gate rejects missing approval")
        }
    }
}

enum class TaxReportingStatus {
    ACTIVE,
    REVOKED,
    SUSPENDED,
    EXPIRED,
    PENDING_APPROVAL,
}

enum class TaxReportingDecision {
    GO,
    NO_GO,
}

enum class TaxReportingReason {
    APPROVED_AND_ACTIVE,
    MISSING_APPROVAL,
    STALE_OR_EXPIRED,
    REVOKED,
    SUSPENDED,
    MARKET_LICENCE_MISSING,
    MARKET_LICENCE_REVOKED,
    INVALID_TAX_SPECIFICATION,
}

enum class ReportingFrequency {
    DAILY,
    WEEKLY,
    MONTHLY,
    QUARTERLY,
    ANNUALLY,
}

data class TaxRuleSpecification(
    val ggrTaxRatePercent: Double,
    val withholdingTaxRatePercent: Double,
    val withholdingThresholdMinorUnits: Long,
    val reportingFrequency: ReportingFrequency,
    val regulatoryBodyCode: String,
)

data class TaxReportingEntry(
    val ruleId: UUID,
    val tenantId: String,
    val marketId: String,
    val operatorId: String,
    val taxRule: TaxRuleSpecification,
    val qualifiedSignatory: String,
    val effectiveFrom: Instant,
    val expiresAt: Instant,
    val status: TaxReportingStatus,
    val evidenceReference: String,
    val version: Long = 1L,
)

data class ApproveTaxReportingRulesCommand(
    val principal: AuthenticatedPrincipal?,
    val sessionId: String,
    val tenantId: String,
    val marketId: String,
    val operatorId: String,
    val taxRule: TaxRuleSpecification,
    val qualifiedSignatory: String,
    val effectiveFrom: Instant,
    val expiresAt: Instant,
    val idempotencyKey: String,
    val correlationId: String,
    val causationId: String,
    val expectedVersion: Long = 1L,
)

data class RevokeTaxReportingRulesCommand(
    val principal: AuthenticatedPrincipal?,
    val sessionId: String,
    val tenantId: String,
    val marketId: String,
    val operatorId: String,
    val revocationReason: String,
    val qualifiedSignatory: String,
    val idempotencyKey: String,
    val correlationId: String,
    val causationId: String,
    val expectedVersion: Long = 1L,
)

data class EvaluateTaxReportingCommand(
    val tenantId: String,
    val marketId: String,
    val operatorId: String,
    val correlationId: String,
    val causationId: String,
)

data class TaxReportingApprovalResult(
    val resultId: UUID,
    val tenantId: String,
    val ruleId: UUID,
    val marketId: String,
    val operatorId: String,
    val status: TaxReportingStatus,
    val directEligibilityGranted: Boolean = false,
    val financialMutationPermitted: Boolean = false,
    val evidenceReference: String,
    val serverTime: Instant,
    val correlationId: String,
    val causationId: String,
)

data class TaxReportingEvaluationResult(
    val decision: TaxReportingDecision,
    val reason: TaxReportingReason,
    val marketId: String,
    val operatorId: String,
    val ruleId: UUID?,
    val taxRule: TaxRuleSpecification?,
    val directEligibilityGranted: Boolean = false,
    val financialMutationPermitted: Boolean = false,
    val evidenceReference: String,
    val evaluatedAt: Instant,
)

interface TaxRegulatoryReportingStore {
    fun findByIdempotency(tenantId: String, idempotencyKey: String): Pair<String, TaxReportingApprovalResult>?
    fun findEntry(tenantId: String, marketId: String, operatorId: String): TaxReportingEntry?
    fun saveEntry(
        entry: TaxReportingEntry,
        approvalResult: TaxReportingApprovalResult,
        idempotencyFingerprint: String,
        idempotencyKey: String,
        audit: AuditEvent,
        outbox: OutboxEvent,
    )
    fun updateStatus(
        tenantId: String,
        marketId: String,
        operatorId: String,
        newStatus: TaxReportingStatus,
        expectedVersion: Long,
        approvalResult: TaxReportingApprovalResult,
        idempotencyFingerprint: String,
        idempotencyKey: String,
        audit: AuditEvent,
        outbox: OutboxEvent,
    ): TaxReportingEntry
}

class InMemoryTaxRegulatoryReportingStore : TaxRegulatoryReportingStore {
    val entries = ConcurrentHashMap<String, TaxReportingEntry>()
    val results = ConcurrentHashMap<String, Pair<String, TaxReportingApprovalResult>>()
    val audit = mutableListOf<AuditEvent>()
    val outbox = mutableListOf<OutboxEvent>()

    @Synchronized
    override fun findByIdempotency(tenantId: String, idempotencyKey: String): Pair<String, TaxReportingApprovalResult>? =
        results["$tenantId:$idempotencyKey"]

    @Synchronized
    override fun findEntry(
        tenantId: String,
        marketId: String,
        operatorId: String,
    ): TaxReportingEntry? =
        entries["$tenantId:$marketId:$operatorId"]

    @Synchronized
    override fun saveEntry(
        entry: TaxReportingEntry,
        approvalResult: TaxReportingApprovalResult,
        idempotencyFingerprint: String,
        idempotencyKey: String,
        audit: AuditEvent,
        outbox: OutboxEvent,
    ) {
        entries["${entry.tenantId}:${entry.marketId}:${entry.operatorId}"] = entry
        results["${entry.tenantId}:$idempotencyKey"] = idempotencyFingerprint to approvalResult
        this.audit.add(audit)
        this.outbox.add(outbox)
    }

    @Synchronized
    override fun updateStatus(
        tenantId: String,
        marketId: String,
        operatorId: String,
        newStatus: TaxReportingStatus,
        expectedVersion: Long,
        approvalResult: TaxReportingApprovalResult,
        idempotencyFingerprint: String,
        idempotencyKey: String,
        audit: AuditEvent,
        outbox: OutboxEvent,
    ): TaxReportingEntry {
        val key = "$tenantId:$marketId:$operatorId"
        val existing = entries[key] ?: throw AuthenticationFailure.Rejected(AuthErrorCode.INVALID)
        if (existing.version != expectedVersion) {
            throw AuthenticationFailure.Rejected(AuthErrorCode.CONFLICT)
        }
        val updated = existing.copy(
            status = newStatus,
            version = existing.version + 1,
        )
        entries[key] = updated
        results["$tenantId:$idempotencyKey"] = idempotencyFingerprint to approvalResult
        this.audit.add(audit)
        this.outbox.add(outbox)
        return updated
    }
}

class TaxRegulatoryReportingService(
    private val sessions: AdminSessionDirectory,
    private val marketLicenceStore: MarketLicenceStore,
    private val store: TaxRegulatoryReportingStore,
    private val clock: Clock,
) {
    @Synchronized
    fun approveTaxReportingRules(command: ApproveTaxReportingRulesCommand): TaxReportingApprovalResult {
        TaxRegulatoryReportingBinding.checkBound()

        val principal = command.principal ?: throw AuthenticationFailure.Rejected(AuthErrorCode.UNAUTHENTICATED)
        if (principal.tenantId != command.tenantId) {
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

        if (!principal.roles.contains(AdminRole.SECURITY) && !principal.roles.contains(AdminRole.SUPER_ADMIN)) {
            throw AuthenticationFailure.Rejected(AuthErrorCode.FORBIDDEN)
        }

        if (command.marketId.isBlank() ||
            command.operatorId.isBlank() ||
            command.qualifiedSignatory.isBlank() ||
            command.effectiveFrom.isAfter(command.expiresAt) ||
            command.expiresAt.isBefore(clock.instant()) ||
            command.taxRule.ggrTaxRatePercent < 0.0 ||
            command.taxRule.ggrTaxRatePercent > 100.0 ||
            command.taxRule.withholdingTaxRatePercent < 0.0 ||
            command.taxRule.withholdingTaxRatePercent > 100.0 ||
            command.taxRule.withholdingThresholdMinorUnits < 0L ||
            command.taxRule.regulatoryBodyCode.isBlank()) {
            throw AuthenticationFailure.Rejected(AuthErrorCode.INVALID)
        }

        // Cross-check market licence prerequisite
        val marketLicence = marketLicenceStore.findEntry(command.tenantId, command.marketId, command.operatorId)
            ?: throw AuthenticationFailure.Rejected(AuthErrorCode.INVALID)

        if (marketLicence.status != MarketLicenceStatus.ACTIVE) {
            throw AuthenticationFailure.Rejected(AuthErrorCode.INVALID)
        }

        val fp = fingerprintApprovalCommand(command)
        store.findByIdempotency(command.tenantId, command.idempotencyKey)?.let { (cachedFp, cachedResult) ->
            if (cachedFp != fp) throw AuthenticationFailure.Rejected(AuthErrorCode.CONFLICT)
            return cachedResult
        }

        val now = clock.instant()
        val ruleId = UUID.randomUUID()
        val resultId = UUID.randomUUID()
        val evidenceRef = "GOV-TAX-${command.tenantId}-${command.marketId}-${command.operatorId}-$ruleId"

        val entry = TaxReportingEntry(
            ruleId = ruleId,
            tenantId = command.tenantId,
            marketId = command.marketId,
            operatorId = command.operatorId,
            taxRule = command.taxRule,
            qualifiedSignatory = command.qualifiedSignatory,
            effectiveFrom = command.effectiveFrom,
            expiresAt = command.expiresAt,
            status = TaxReportingStatus.ACTIVE,
            evidenceReference = evidenceRef,
            version = 1L,
        )

        val result = TaxReportingApprovalResult(
            resultId = resultId,
            tenantId = command.tenantId,
            ruleId = ruleId,
            marketId = command.marketId,
            operatorId = command.operatorId,
            status = TaxReportingStatus.ACTIVE,
            directEligibilityGranted = false,
            financialMutationPermitted = false,
            evidenceReference = evidenceRef,
            serverTime = now,
            correlationId = command.correlationId,
            causationId = command.causationId,
        )

        val audit = AuditEvent(
            eventId = UUID.randomUUID(),
            resultId = resultId,
            tenantId = command.tenantId,
            type = "TAX_REPORTING_RULES_APPROVED",
            occurredAt = now,
            correlationId = command.correlationId,
            causationId = command.causationId,
        )

        val outbox = OutboxEvent(
            eventId = UUID.randomUUID(),
            resultId = resultId,
            tenantId = command.tenantId,
            type = "TaxReportingRulesApproved",
            createdAt = now,
        )

        store.saveEntry(entry, result, fp, command.idempotencyKey, audit, outbox)
        return result
    }

    @Synchronized
    fun rollbackOrRevokeTaxReportingRules(command: RevokeTaxReportingRulesCommand): TaxReportingApprovalResult {
        TaxRegulatoryReportingBinding.checkBound()

        val principal = command.principal ?: throw AuthenticationFailure.Rejected(AuthErrorCode.UNAUTHENTICATED)
        if (principal.tenantId != command.tenantId) {
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

        if (!principal.roles.contains(AdminRole.SECURITY) && !principal.roles.contains(AdminRole.SUPER_ADMIN)) {
            throw AuthenticationFailure.Rejected(AuthErrorCode.FORBIDDEN)
        }

        if (command.marketId.isBlank() ||
            command.operatorId.isBlank() ||
            command.qualifiedSignatory.isBlank() ||
            command.revocationReason.isBlank()) {
            throw AuthenticationFailure.Rejected(AuthErrorCode.INVALID)
        }

        val fp = fingerprintRevokeCommand(command)
        store.findByIdempotency(command.tenantId, command.idempotencyKey)?.let { (cachedFp, cachedResult) ->
            if (cachedFp != fp) throw AuthenticationFailure.Rejected(AuthErrorCode.CONFLICT)
            return cachedResult
        }

        val existing = store.findEntry(
            command.tenantId,
            command.marketId,
            command.operatorId,
        ) ?: throw AuthenticationFailure.Rejected(AuthErrorCode.INVALID)

        val now = clock.instant()
        val resultId = UUID.randomUUID()
        val evidenceRef = "GOV-TAX-REVOKED-${command.tenantId}-${command.marketId}-${existing.ruleId}"

        val result = TaxReportingApprovalResult(
            resultId = resultId,
            tenantId = command.tenantId,
            ruleId = existing.ruleId,
            marketId = command.marketId,
            operatorId = command.operatorId,
            status = TaxReportingStatus.REVOKED,
            directEligibilityGranted = false,
            financialMutationPermitted = false,
            evidenceReference = evidenceRef,
            serverTime = now,
            correlationId = command.correlationId,
            causationId = command.causationId,
        )

        val audit = AuditEvent(
            eventId = UUID.randomUUID(),
            resultId = resultId,
            tenantId = command.tenantId,
            type = "TAX_REPORTING_RULES_REVOKED",
            occurredAt = now,
            correlationId = command.correlationId,
            causationId = command.causationId,
        )

        val outbox = OutboxEvent(
            eventId = UUID.randomUUID(),
            resultId = resultId,
            tenantId = command.tenantId,
            type = "TaxReportingRulesRevoked",
            createdAt = now,
        )

        store.updateStatus(
            tenantId = command.tenantId,
            marketId = command.marketId,
            operatorId = command.operatorId,
            newStatus = TaxReportingStatus.REVOKED,
            expectedVersion = command.expectedVersion,
            approvalResult = result,
            idempotencyFingerprint = fp,
            idempotencyKey = command.idempotencyKey,
            audit = audit,
            outbox = outbox,
        )

        return result
    }

    @Synchronized
    fun evaluateTaxReportingReadiness(command: EvaluateTaxReportingCommand): TaxReportingEvaluationResult {
        TaxRegulatoryReportingBinding.checkBound()

        val now = clock.instant()
        val entry = store.findEntry(
            command.tenantId,
            command.marketId,
            command.operatorId,
        )

        if (entry == null) {
            return TaxReportingEvaluationResult(
                decision = TaxReportingDecision.NO_GO,
                reason = TaxReportingReason.MISSING_APPROVAL,
                marketId = command.marketId,
                operatorId = command.operatorId,
                ruleId = null,
                taxRule = null,
                directEligibilityGranted = false,
                financialMutationPermitted = false,
                evidenceReference = "EVID-TAX-NOGO-MISSING-${command.marketId}-${command.operatorId}",
                evaluatedAt = now,
            )
        }

        if (entry.status == TaxReportingStatus.REVOKED) {
            return TaxReportingEvaluationResult(
                decision = TaxReportingDecision.NO_GO,
                reason = TaxReportingReason.REVOKED,
                marketId = command.marketId,
                operatorId = command.operatorId,
                ruleId = entry.ruleId,
                taxRule = entry.taxRule,
                directEligibilityGranted = false,
                financialMutationPermitted = false,
                evidenceReference = entry.evidenceReference,
                evaluatedAt = now,
            )
        }

        if (entry.status == TaxReportingStatus.SUSPENDED) {
            return TaxReportingEvaluationResult(
                decision = TaxReportingDecision.NO_GO,
                reason = TaxReportingReason.SUSPENDED,
                marketId = command.marketId,
                operatorId = command.operatorId,
                ruleId = entry.ruleId,
                taxRule = entry.taxRule,
                directEligibilityGranted = false,
                financialMutationPermitted = false,
                evidenceReference = entry.evidenceReference,
                evaluatedAt = now,
            )
        }

        if (now.isAfter(entry.expiresAt) || now.isBefore(entry.effectiveFrom)) {
            return TaxReportingEvaluationResult(
                decision = TaxReportingDecision.NO_GO,
                reason = TaxReportingReason.STALE_OR_EXPIRED,
                marketId = command.marketId,
                operatorId = command.operatorId,
                ruleId = entry.ruleId,
                taxRule = entry.taxRule,
                directEligibilityGranted = false,
                financialMutationPermitted = false,
                evidenceReference = entry.evidenceReference,
                evaluatedAt = now,
            )
        }

        // Cross-check underlying market licence status (GOV-001-01 dependency)
        val marketLicence = marketLicenceStore.findEntry(command.tenantId, command.marketId, command.operatorId)
        if (marketLicence == null) {
            return TaxReportingEvaluationResult(
                decision = TaxReportingDecision.NO_GO,
                reason = TaxReportingReason.MARKET_LICENCE_MISSING,
                marketId = command.marketId,
                operatorId = command.operatorId,
                ruleId = entry.ruleId,
                taxRule = entry.taxRule,
                directEligibilityGranted = false,
                financialMutationPermitted = false,
                evidenceReference = entry.evidenceReference,
                evaluatedAt = now,
            )
        }

        if (marketLicence.status == MarketLicenceStatus.REVOKED) {
            return TaxReportingEvaluationResult(
                decision = TaxReportingDecision.NO_GO,
                reason = TaxReportingReason.MARKET_LICENCE_REVOKED,
                marketId = command.marketId,
                operatorId = command.operatorId,
                ruleId = entry.ruleId,
                taxRule = entry.taxRule,
                directEligibilityGranted = false,
                financialMutationPermitted = false,
                evidenceReference = entry.evidenceReference,
                evaluatedAt = now,
            )
        }

        return TaxReportingEvaluationResult(
            decision = TaxReportingDecision.GO,
            reason = TaxReportingReason.APPROVED_AND_ACTIVE,
            marketId = command.marketId,
            operatorId = command.operatorId,
            ruleId = entry.ruleId,
            taxRule = entry.taxRule,
            directEligibilityGranted = false,
            financialMutationPermitted = false,
            evidenceReference = entry.evidenceReference,
            evaluatedAt = now,
        )
    }

    private fun fingerprintApprovalCommand(command: ApproveTaxReportingRulesCommand): String {
        val raw = "${command.tenantId}|${command.marketId}|${command.operatorId}|" +
            "${command.taxRule.ggrTaxRatePercent}|${command.taxRule.withholdingTaxRatePercent}|" +
            "${command.taxRule.withholdingThresholdMinorUnits}|${command.taxRule.reportingFrequency}|" +
            "${command.taxRule.regulatoryBodyCode}|${command.qualifiedSignatory}|" +
            "${command.effectiveFrom}|${command.expiresAt}|${command.expectedVersion}"
        val md = MessageDigest.getInstance("SHA-256")
        return md.digest(raw.toByteArray(Charsets.UTF_8)).joinToString("") { "%02x".format(it) }
    }

    private fun fingerprintRevokeCommand(command: RevokeTaxReportingRulesCommand): String {
        val raw = "${command.tenantId}|${command.marketId}|${command.operatorId}|" +
            "${command.revocationReason}|${command.qualifiedSignatory}|${command.expectedVersion}"
        val md = MessageDigest.getInstance("SHA-256")
        return md.digest(raw.toByteArray(Charsets.UTF_8)).joinToString("") { "%02x".format(it) }
    }
}
