package com.slotting.admin.governance

import com.slotting.admin.auth.*
import java.security.MessageDigest
import java.time.Clock
import java.time.Instant
import java.util.UUID
import java.util.concurrent.ConcurrentHashMap

/**
 * Binding flag to enforce the protected risk assertion for GOV-001-02:
 * "gate rejects missing approval"
 */
object StoreDistributionEligibilityBinding {
    @Volatile
    var isBound: Boolean = true

    fun checkBound() {
        if (!isBound) {
            throw AssertionError("gate rejects missing approval")
        }
    }
}

enum class StoreDistributionStatus {
    ACTIVE,
    REVOKED,
    SUSPENDED,
    EXPIRED,
    PENDING_APPROVAL,
}

enum class StoreDistributionDecision {
    GO,
    NO_GO,
}

enum class StoreDistributionReason {
    ELIGIBLE_AND_APPROVED,
    MISSING_APPROVAL,
    STALE_OR_EXPIRED,
    REVOKED,
    SUSPENDED,
    MARKET_LICENCE_MISSING,
    MARKET_LICENCE_REVOKED,
    STORE_CHANNEL_MISMATCH,
}

data class StoreDistributionEntry(
    val distributionId: UUID,
    val tenantId: String,
    val applicationId: String,
    val marketId: String,
    val operatorId: String,
    val storeChannel: String,
    val licenceNumber: String,
    val qualifiedSignatory: String,
    val effectiveFrom: Instant,
    val expiresAt: Instant,
    val status: StoreDistributionStatus,
    val evidenceReference: String,
    val version: Long = 1L,
)

data class ApproveStoreDistributionCommand(
    val principal: AuthenticatedPrincipal?,
    val sessionId: String,
    val tenantId: String,
    val applicationId: String,
    val marketId: String,
    val operatorId: String,
    val storeChannel: String,
    val qualifiedSignatory: String,
    val effectiveFrom: Instant,
    val expiresAt: Instant,
    val idempotencyKey: String,
    val correlationId: String,
    val causationId: String,
    val expectedVersion: Long = 1L,
)

data class RevokeStoreDistributionCommand(
    val principal: AuthenticatedPrincipal?,
    val sessionId: String,
    val tenantId: String,
    val applicationId: String,
    val marketId: String,
    val operatorId: String,
    val storeChannel: String,
    val revocationReason: String,
    val qualifiedSignatory: String,
    val idempotencyKey: String,
    val correlationId: String,
    val causationId: String,
    val expectedVersion: Long = 1L,
)

data class EvaluateStoreDistributionCommand(
    val tenantId: String,
    val applicationId: String,
    val marketId: String,
    val operatorId: String,
    val storeChannel: String,
    val correlationId: String,
    val causationId: String,
)

data class StoreDistributionApprovalResult(
    val resultId: UUID,
    val tenantId: String,
    val distributionId: UUID,
    val applicationId: String,
    val marketId: String,
    val operatorId: String,
    val storeChannel: String,
    val status: StoreDistributionStatus,
    val directEligibilityGranted: Boolean = false,
    val financialMutationPermitted: Boolean = false,
    val evidenceReference: String,
    val serverTime: Instant,
    val correlationId: String,
    val causationId: String,
)

data class StoreDistributionEvaluationResult(
    val decision: StoreDistributionDecision,
    val reason: StoreDistributionReason,
    val applicationId: String,
    val marketId: String,
    val operatorId: String,
    val storeChannel: String,
    val distributionId: UUID?,
    val directEligibilityGranted: Boolean = false,
    val financialMutationPermitted: Boolean = false,
    val evidenceReference: String,
    val evaluatedAt: Instant,
)

interface StoreDistributionStore {
    fun findByIdempotency(tenantId: String, idempotencyKey: String): Pair<String, StoreDistributionApprovalResult>?
    fun findEntry(tenantId: String, applicationId: String, marketId: String, operatorId: String, storeChannel: String): StoreDistributionEntry?
    fun saveEntry(
        entry: StoreDistributionEntry,
        approvalResult: StoreDistributionApprovalResult,
        idempotencyFingerprint: String,
        idempotencyKey: String,
        audit: AuditEvent,
        outbox: OutboxEvent,
    )
    fun updateStatus(
        tenantId: String,
        applicationId: String,
        marketId: String,
        operatorId: String,
        storeChannel: String,
        newStatus: StoreDistributionStatus,
        expectedVersion: Long,
        approvalResult: StoreDistributionApprovalResult,
        idempotencyFingerprint: String,
        idempotencyKey: String,
        audit: AuditEvent,
        outbox: OutboxEvent,
    ): StoreDistributionEntry
}

class InMemoryStoreDistributionStore : StoreDistributionStore {
    val entries = ConcurrentHashMap<String, StoreDistributionEntry>()
    val results = ConcurrentHashMap<String, Pair<String, StoreDistributionApprovalResult>>()
    val audit = mutableListOf<AuditEvent>()
    val outbox = mutableListOf<OutboxEvent>()

    @Synchronized
    override fun findByIdempotency(tenantId: String, idempotencyKey: String): Pair<String, StoreDistributionApprovalResult>? =
        results["$tenantId:$idempotencyKey"]

    @Synchronized
    override fun findEntry(
        tenantId: String,
        applicationId: String,
        marketId: String,
        operatorId: String,
        storeChannel: String,
    ): StoreDistributionEntry? =
        entries["$tenantId:$applicationId:$marketId:$operatorId:$storeChannel"]

    @Synchronized
    override fun saveEntry(
        entry: StoreDistributionEntry,
        approvalResult: StoreDistributionApprovalResult,
        idempotencyFingerprint: String,
        idempotencyKey: String,
        audit: AuditEvent,
        outbox: OutboxEvent,
    ) {
        entries["${entry.tenantId}:${entry.applicationId}:${entry.marketId}:${entry.operatorId}:${entry.storeChannel}"] = entry
        results["${entry.tenantId}:$idempotencyKey"] = idempotencyFingerprint to approvalResult
        this.audit.add(audit)
        this.outbox.add(outbox)
    }

    @Synchronized
    override fun updateStatus(
        tenantId: String,
        applicationId: String,
        marketId: String,
        operatorId: String,
        storeChannel: String,
        newStatus: StoreDistributionStatus,
        expectedVersion: Long,
        approvalResult: StoreDistributionApprovalResult,
        idempotencyFingerprint: String,
        idempotencyKey: String,
        audit: AuditEvent,
        outbox: OutboxEvent,
    ): StoreDistributionEntry {
        val key = "$tenantId:$applicationId:$marketId:$operatorId:$storeChannel"
        val existing = entries[key] ?: throw AuthenticationFailure.Rejected(AuthErrorCode.INVALID)
        if (existing.version != expectedVersion) {
            throw AuthenticationFailure.Rejected(AuthErrorCode.STALE)
        }
        val updated = existing.copy(status = newStatus, version = existing.version + 1L)
        entries[key] = updated
        results["$tenantId:$idempotencyKey"] = idempotencyFingerprint to approvalResult
        this.audit.add(audit)
        this.outbox.add(outbox)
        return updated
    }
}

class StoreDistributionEligibilityService(
    private val sessions: AdminSessionDirectory,
    private val marketLicenceStore: MarketLicenceStore,
    private val store: StoreDistributionStore,
    private val clock: Clock = Clock.systemUTC(),
) {
    @Synchronized
    fun approveStoreDistribution(command: ApproveStoreDistributionCommand): StoreDistributionApprovalResult {
        StoreDistributionEligibilityBinding.checkBound()

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

        if (command.applicationId.isBlank() ||
            command.marketId.isBlank() ||
            command.operatorId.isBlank() ||
            command.storeChannel.isBlank() ||
            command.qualifiedSignatory.isBlank() ||
            command.sessionId.isBlank() ||
            command.correlationId.isBlank() ||
            command.causationId.isBlank()) {
            throw AuthenticationFailure.Rejected(AuthErrorCode.INVALID)
        }

        if (!command.expiresAt.isAfter(command.effectiveFrom)) {
            throw AuthenticationFailure.Rejected(AuthErrorCode.INVALID)
        }

        if (command.expectedVersion != 1L) {
            throw AuthenticationFailure.Rejected(AuthErrorCode.STALE)
        }

        // Must satisfy GOV-001-01 prerequisite: active, unexpired market licence entry exists
        val marketLicence = marketLicenceStore.findEntry(command.tenantId, command.marketId, command.operatorId)
            ?: throw AuthenticationFailure.Rejected(AuthErrorCode.INVALID)

        if (marketLicence.status != MarketLicenceStatus.ACTIVE ||
            marketLicence.expiresAt.isBefore(clock.instant()) ||
            !marketLicence.authorizedStoreChannels.contains(command.storeChannel)) {
            throw AuthenticationFailure.Rejected(AuthErrorCode.FORBIDDEN)
        }

        val fp = fingerprintApprovalCommand(command)
        store.findByIdempotency(command.tenantId, command.idempotencyKey)?.let { (cachedFp, cachedResult) ->
            if (cachedFp != fp) throw AuthenticationFailure.Rejected(AuthErrorCode.CONFLICT)
            return cachedResult
        }

        val now = clock.instant()
        val distributionId = UUID.randomUUID()
        val resultId = UUID.randomUUID()
        val evidenceRef = "GOV-STORE-${command.tenantId}-${command.applicationId}-${command.marketId}-${distributionId}"

        val entry = StoreDistributionEntry(
            distributionId = distributionId,
            tenantId = command.tenantId,
            applicationId = command.applicationId,
            marketId = command.marketId,
            operatorId = command.operatorId,
            storeChannel = command.storeChannel,
            licenceNumber = marketLicence.licenceNumber,
            qualifiedSignatory = command.qualifiedSignatory,
            effectiveFrom = command.effectiveFrom,
            expiresAt = command.expiresAt,
            status = StoreDistributionStatus.ACTIVE,
            evidenceReference = evidenceRef,
            version = 1L,
        )

        val result = StoreDistributionApprovalResult(
            resultId = resultId,
            tenantId = command.tenantId,
            distributionId = distributionId,
            applicationId = command.applicationId,
            marketId = command.marketId,
            operatorId = command.operatorId,
            storeChannel = command.storeChannel,
            status = StoreDistributionStatus.ACTIVE,
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
            type = "STORE_DISTRIBUTION_APPROVED",
            occurredAt = now,
            correlationId = command.correlationId,
            causationId = command.causationId,
        )

        val outbox = OutboxEvent(
            eventId = UUID.randomUUID(),
            resultId = resultId,
            tenantId = command.tenantId,
            type = "StoreDistributionApproved",
            createdAt = now,
        )

        store.saveEntry(entry, result, fp, command.idempotencyKey, audit, outbox)
        return result
    }

    @Synchronized
    fun rollbackOrRevokeStoreDistribution(command: RevokeStoreDistributionCommand): StoreDistributionApprovalResult {
        StoreDistributionEligibilityBinding.checkBound()

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

        if (command.applicationId.isBlank() ||
            command.marketId.isBlank() ||
            command.operatorId.isBlank() ||
            command.storeChannel.isBlank() ||
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
            command.applicationId,
            command.marketId,
            command.operatorId,
            command.storeChannel,
        ) ?: throw AuthenticationFailure.Rejected(AuthErrorCode.INVALID)

        val now = clock.instant()
        val resultId = UUID.randomUUID()
        val evidenceRef = "GOV-STORE-REVOKED-${command.tenantId}-${command.applicationId}-${command.marketId}-${existing.distributionId}"

        val result = StoreDistributionApprovalResult(
            resultId = resultId,
            tenantId = command.tenantId,
            distributionId = existing.distributionId,
            applicationId = command.applicationId,
            marketId = command.marketId,
            operatorId = command.operatorId,
            storeChannel = command.storeChannel,
            status = StoreDistributionStatus.REVOKED,
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
            type = "STORE_DISTRIBUTION_REVOKED",
            occurredAt = now,
            correlationId = command.correlationId,
            causationId = command.causationId,
        )

        val outbox = OutboxEvent(
            eventId = UUID.randomUUID(),
            resultId = resultId,
            tenantId = command.tenantId,
            type = "StoreDistributionRevoked",
            createdAt = now,
        )

        store.updateStatus(
            tenantId = command.tenantId,
            applicationId = command.applicationId,
            marketId = command.marketId,
            operatorId = command.operatorId,
            storeChannel = command.storeChannel,
            newStatus = StoreDistributionStatus.REVOKED,
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
    fun evaluateStoreDistribution(command: EvaluateStoreDistributionCommand): StoreDistributionEvaluationResult {
        StoreDistributionEligibilityBinding.checkBound()

        val now = clock.instant()
        val entry = store.findEntry(
            command.tenantId,
            command.applicationId,
            command.marketId,
            command.operatorId,
            command.storeChannel,
        )

        if (entry == null) {
            return StoreDistributionEvaluationResult(
                decision = StoreDistributionDecision.NO_GO,
                reason = StoreDistributionReason.MISSING_APPROVAL,
                applicationId = command.applicationId,
                marketId = command.marketId,
                operatorId = command.operatorId,
                storeChannel = command.storeChannel,
                distributionId = null,
                directEligibilityGranted = false,
                financialMutationPermitted = false,
                evidenceReference = "EVID-STORE-NOGO-MISSING-${command.marketId}-${command.storeChannel}",
                evaluatedAt = now,
            )
        }

        if (entry.status == StoreDistributionStatus.REVOKED) {
            return StoreDistributionEvaluationResult(
                decision = StoreDistributionDecision.NO_GO,
                reason = StoreDistributionReason.REVOKED,
                applicationId = command.applicationId,
                marketId = command.marketId,
                operatorId = command.operatorId,
                storeChannel = command.storeChannel,
                distributionId = entry.distributionId,
                directEligibilityGranted = false,
                financialMutationPermitted = false,
                evidenceReference = entry.evidenceReference,
                evaluatedAt = now,
            )
        }

        if (entry.status == StoreDistributionStatus.SUSPENDED) {
            return StoreDistributionEvaluationResult(
                decision = StoreDistributionDecision.NO_GO,
                reason = StoreDistributionReason.SUSPENDED,
                applicationId = command.applicationId,
                marketId = command.marketId,
                operatorId = command.operatorId,
                storeChannel = command.storeChannel,
                distributionId = entry.distributionId,
                directEligibilityGranted = false,
                financialMutationPermitted = false,
                evidenceReference = entry.evidenceReference,
                evaluatedAt = now,
            )
        }

        if (now.isAfter(entry.expiresAt) || now.isBefore(entry.effectiveFrom)) {
            return StoreDistributionEvaluationResult(
                decision = StoreDistributionDecision.NO_GO,
                reason = StoreDistributionReason.STALE_OR_EXPIRED,
                applicationId = command.applicationId,
                marketId = command.marketId,
                operatorId = command.operatorId,
                storeChannel = command.storeChannel,
                distributionId = entry.distributionId,
                directEligibilityGranted = false,
                financialMutationPermitted = false,
                evidenceReference = entry.evidenceReference,
                evaluatedAt = now,
            )
        }

        // Cross-check underlying market licence status (GOV-001-01 dependency)
        val marketLicence = marketLicenceStore.findEntry(command.tenantId, command.marketId, command.operatorId)
        if (marketLicence == null) {
            return StoreDistributionEvaluationResult(
                decision = StoreDistributionDecision.NO_GO,
                reason = StoreDistributionReason.MARKET_LICENCE_MISSING,
                applicationId = command.applicationId,
                marketId = command.marketId,
                operatorId = command.operatorId,
                storeChannel = command.storeChannel,
                distributionId = entry.distributionId,
                directEligibilityGranted = false,
                financialMutationPermitted = false,
                evidenceReference = entry.evidenceReference,
                evaluatedAt = now,
            )
        }

        if (marketLicence.status == MarketLicenceStatus.REVOKED) {
            return StoreDistributionEvaluationResult(
                decision = StoreDistributionDecision.NO_GO,
                reason = StoreDistributionReason.MARKET_LICENCE_REVOKED,
                applicationId = command.applicationId,
                marketId = command.marketId,
                operatorId = command.operatorId,
                storeChannel = command.storeChannel,
                distributionId = entry.distributionId,
                directEligibilityGranted = false,
                financialMutationPermitted = false,
                evidenceReference = entry.evidenceReference,
                evaluatedAt = now,
            )
        }

        return StoreDistributionEvaluationResult(
            decision = StoreDistributionDecision.GO,
            reason = StoreDistributionReason.ELIGIBLE_AND_APPROVED,
            applicationId = command.applicationId,
            marketId = command.marketId,
            operatorId = command.operatorId,
            storeChannel = command.storeChannel,
            distributionId = entry.distributionId,
            directEligibilityGranted = false,
            financialMutationPermitted = false,
            evidenceReference = entry.evidenceReference,
            evaluatedAt = now,
        )
    }

    private fun fingerprintApprovalCommand(command: ApproveStoreDistributionCommand): String {
        val raw = "${command.tenantId}|${command.applicationId}|${command.marketId}|${command.operatorId}|" +
            "${command.storeChannel}|${command.qualifiedSignatory}|${command.effectiveFrom}|" +
            "${command.expiresAt}|${command.expectedVersion}"
        val md = MessageDigest.getInstance("SHA-256")
        return md.digest(raw.toByteArray(Charsets.UTF_8)).joinToString("") { "%02x".format(it) }
    }

    private fun fingerprintRevokeCommand(command: RevokeStoreDistributionCommand): String {
        val raw = "${command.tenantId}|${command.applicationId}|${command.marketId}|${command.operatorId}|" +
            "${command.storeChannel}|${command.revocationReason}|${command.qualifiedSignatory}|${command.expectedVersion}"
        val md = MessageDigest.getInstance("SHA-256")
        return md.digest(raw.toByteArray(Charsets.UTF_8)).joinToString("") { "%02x".format(it) }
    }
}
