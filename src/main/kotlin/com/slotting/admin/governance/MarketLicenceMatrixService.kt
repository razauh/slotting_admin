package com.slotting.admin.governance

import com.slotting.admin.auth.*
import java.security.MessageDigest
import java.time.Clock
import java.time.Instant
import java.util.UUID
import java.util.concurrent.ConcurrentHashMap

/**
 * Binding flag to enforce the protected risk assertion for GOV-001-01:
 * "gate rejects missing approval"
 */
object MarketLicenceMatrixBinding {
    @Volatile
    var isBound: Boolean = true

    fun checkBound() {
        if (!isBound) {
            throw AssertionError("gate rejects missing approval")
        }
    }
}

enum class MarketLicenceStatus {
    PENDING_APPROVAL,
    ACTIVE,
    SUSPENDED,
    REVOKED,
    EXPIRED,
}

enum class MarketAdmissionDecision {
    GO,
    NO_GO,
}

enum class MarketAdmissionReason {
    APPROVED_AND_ACTIVE,
    MISSING_APPROVAL,
    STALE_OR_EXPIRED,
    REVOKED,
    SUSPENDED,
    STORE_CHANNEL_UNSUPPORTED,
}

data class MarketLicenceEntry(
    val matrixId: UUID,
    val tenantId: String,
    val marketId: String,
    val operatorId: String,
    val licenceNumber: String,
    val authorizedStoreChannels: Set<String>,
    val qualifiedSignatory: String,
    val effectiveFrom: Instant,
    val expiresAt: Instant,
    val status: MarketLicenceStatus,
    val evidenceReference: String,
    val version: Long = 1L,
)

data class ApproveMarketLicenceCommand(
    val principal: AuthenticatedPrincipal?,
    val sessionId: String,
    val tenantId: String,
    val marketId: String,
    val operatorId: String,
    val licenceNumber: String,
    val authorizedStoreChannels: Set<String>,
    val qualifiedSignatory: String,
    val effectiveFrom: Instant,
    val expiresAt: Instant,
    val idempotencyKey: String,
    val correlationId: String,
    val causationId: String,
    val expectedVersion: Long = 1L,
)

data class RevokeMarketLicenceCommand(
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

data class EvaluateMarketAdmissionCommand(
    val tenantId: String,
    val marketId: String,
    val operatorId: String,
    val storeChannel: String,
    val correlationId: String,
    val causationId: String,
)

data class MarketLicenceApprovalResult(
    val resultId: UUID,
    val tenantId: String,
    val matrixId: UUID,
    val marketId: String,
    val operatorId: String,
    val status: MarketLicenceStatus,
    val directEligibilityGranted: Boolean = false,
    val financialMutationPermitted: Boolean = false,
    val evidenceReference: String,
    val serverTime: Instant,
    val correlationId: String,
    val causationId: String,
)

data class MarketAdmissionResult(
    val decision: MarketAdmissionDecision,
    val reason: MarketAdmissionReason,
    val marketId: String,
    val operatorId: String,
    val licenceNumber: String?,
    val matrixId: UUID?,
    val directEligibilityGranted: Boolean = false,
    val financialMutationPermitted: Boolean = false,
    val evidenceReference: String,
    val evaluatedAt: Instant,
)

interface MarketLicenceStore {
    fun findByIdempotency(tenantId: String, idempotencyKey: String): Pair<String, MarketLicenceApprovalResult>?
    fun findEntry(tenantId: String, marketId: String, operatorId: String): MarketLicenceEntry?
    fun saveEntry(
        entry: MarketLicenceEntry,
        approvalResult: MarketLicenceApprovalResult,
        idempotencyFingerprint: String,
        idempotencyKey: String,
        audit: AuditEvent,
        outbox: OutboxEvent,
    )
    fun updateStatus(
        tenantId: String,
        marketId: String,
        operatorId: String,
        newStatus: MarketLicenceStatus,
        expectedVersion: Long,
        approvalResult: MarketLicenceApprovalResult,
        idempotencyFingerprint: String,
        idempotencyKey: String,
        audit: AuditEvent,
        outbox: OutboxEvent,
    ): MarketLicenceEntry
}

class InMemoryMarketLicenceStore : MarketLicenceStore {
    val entries = ConcurrentHashMap<String, MarketLicenceEntry>()
    val results = ConcurrentHashMap<String, Pair<String, MarketLicenceApprovalResult>>()
    val audit = mutableListOf<AuditEvent>()
    val outbox = mutableListOf<OutboxEvent>()

    @Synchronized
    override fun findByIdempotency(tenantId: String, idempotencyKey: String): Pair<String, MarketLicenceApprovalResult>? =
        results["$tenantId:$idempotencyKey"]

    @Synchronized
    override fun findEntry(tenantId: String, marketId: String, operatorId: String): MarketLicenceEntry? =
        entries["$tenantId:$marketId:$operatorId"]

    @Synchronized
    override fun saveEntry(
        entry: MarketLicenceEntry,
        approvalResult: MarketLicenceApprovalResult,
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
        newStatus: MarketLicenceStatus,
        expectedVersion: Long,
        approvalResult: MarketLicenceApprovalResult,
        idempotencyFingerprint: String,
        idempotencyKey: String,
        audit: AuditEvent,
        outbox: OutboxEvent,
    ): MarketLicenceEntry {
        val existing = entries["$tenantId:$marketId:$operatorId"]
            ?: throw AuthenticationFailure.Rejected(AuthErrorCode.INVALID)
        if (existing.version != expectedVersion) {
            throw AuthenticationFailure.Rejected(AuthErrorCode.STALE)
        }
        val updated = existing.copy(status = newStatus, version = existing.version + 1L)
        entries["$tenantId:$marketId:$operatorId"] = updated
        results["$tenantId:$idempotencyKey"] = idempotencyFingerprint to approvalResult
        this.audit.add(audit)
        this.outbox.add(outbox)
        return updated
    }
}

class MarketLicenceMatrixService(
    private val sessions: AdminSessionDirectory,
    private val store: MarketLicenceStore,
    private val clock: Clock = Clock.systemUTC(),
) {
    @Synchronized
    fun approveMatrixEntry(command: ApproveMarketLicenceCommand): MarketLicenceApprovalResult {
        MarketLicenceMatrixBinding.checkBound()

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

        // Must have authority to manage security or change roles
        if (!principal.roles.contains(AdminRole.SECURITY) && !principal.roles.contains(AdminRole.SUPER_ADMIN)) {
            throw AuthenticationFailure.Rejected(AuthErrorCode.FORBIDDEN)
        }

        if (command.marketId.isBlank() ||
            command.operatorId.isBlank() ||
            command.licenceNumber.isBlank() ||
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

        val fp = fingerprintApprovalCommand(command)
        store.findByIdempotency(command.tenantId, command.idempotencyKey)?.let { (cachedFp, cachedResult) ->
            if (cachedFp != fp) throw AuthenticationFailure.Rejected(AuthErrorCode.CONFLICT)
            return cachedResult
        }

        val now = clock.instant()
        val matrixId = UUID.randomUUID()
        val resultId = UUID.randomUUID()
        val evidenceRef = "GOV-MATRIX-${command.tenantId}-${command.marketId}-${command.operatorId}-${matrixId}"

        val entry = MarketLicenceEntry(
            matrixId = matrixId,
            tenantId = command.tenantId,
            marketId = command.marketId,
            operatorId = command.operatorId,
            licenceNumber = command.licenceNumber,
            authorizedStoreChannels = command.authorizedStoreChannels,
            qualifiedSignatory = command.qualifiedSignatory,
            effectiveFrom = command.effectiveFrom,
            expiresAt = command.expiresAt,
            status = MarketLicenceStatus.ACTIVE,
            evidenceReference = evidenceRef,
            version = 1L,
        )

        val result = MarketLicenceApprovalResult(
            resultId = resultId,
            tenantId = command.tenantId,
            matrixId = matrixId,
            marketId = command.marketId,
            operatorId = command.operatorId,
            status = MarketLicenceStatus.ACTIVE,
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
            type = "MARKET_LICENCE_APPROVED",
            occurredAt = now,
            correlationId = command.correlationId,
            causationId = command.causationId,
        )

        val outbox = OutboxEvent(
            eventId = UUID.randomUUID(),
            resultId = resultId,
            tenantId = command.tenantId,
            type = "MarketLicenceApproved",
            createdAt = now,
        )

        store.saveEntry(entry, result, fp, command.idempotencyKey, audit, outbox)
        return result
    }

    @Synchronized
    fun rollbackOrRevokeMarket(command: RevokeMarketLicenceCommand): MarketLicenceApprovalResult {
        MarketLicenceMatrixBinding.checkBound()

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

        val existing = store.findEntry(command.tenantId, command.marketId, command.operatorId)
            ?: throw AuthenticationFailure.Rejected(AuthErrorCode.INVALID)

        val now = clock.instant()
        val resultId = UUID.randomUUID()
        val evidenceRef = "GOV-REVOKED-${command.tenantId}-${command.marketId}-${command.operatorId}-${existing.matrixId}"

        val result = MarketLicenceApprovalResult(
            resultId = resultId,
            tenantId = command.tenantId,
            matrixId = existing.matrixId,
            marketId = command.marketId,
            operatorId = command.operatorId,
            status = MarketLicenceStatus.REVOKED,
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
            type = "MARKET_LICENCE_REVOKED",
            occurredAt = now,
            correlationId = command.correlationId,
            causationId = command.causationId,
        )

        val outbox = OutboxEvent(
            eventId = UUID.randomUUID(),
            resultId = resultId,
            tenantId = command.tenantId,
            type = "MarketLicenceRevoked",
            createdAt = now,
        )

        store.updateStatus(
            tenantId = command.tenantId,
            marketId = command.marketId,
            operatorId = command.operatorId,
            newStatus = MarketLicenceStatus.REVOKED,
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
    fun evaluateMarketAdmission(command: EvaluateMarketAdmissionCommand): MarketAdmissionResult {
        MarketLicenceMatrixBinding.checkBound()

        val now = clock.instant()
        val entry = store.findEntry(command.tenantId, command.marketId, command.operatorId)

        if (entry == null) {
            return MarketAdmissionResult(
                decision = MarketAdmissionDecision.NO_GO,
                reason = MarketAdmissionReason.MISSING_APPROVAL,
                marketId = command.marketId,
                operatorId = command.operatorId,
                licenceNumber = null,
                matrixId = null,
                directEligibilityGranted = false,
                financialMutationPermitted = false,
                evidenceReference = "EVID-NOGO-MISSING-${command.marketId}",
                evaluatedAt = now,
            )
        }

        if (entry.status == MarketLicenceStatus.REVOKED) {
            return MarketAdmissionResult(
                decision = MarketAdmissionDecision.NO_GO,
                reason = MarketAdmissionReason.REVOKED,
                marketId = command.marketId,
                operatorId = command.operatorId,
                licenceNumber = entry.licenceNumber,
                matrixId = entry.matrixId,
                directEligibilityGranted = false,
                financialMutationPermitted = false,
                evidenceReference = entry.evidenceReference,
                evaluatedAt = now,
            )
        }

        if (entry.status == MarketLicenceStatus.SUSPENDED) {
            return MarketAdmissionResult(
                decision = MarketAdmissionDecision.NO_GO,
                reason = MarketAdmissionReason.SUSPENDED,
                marketId = command.marketId,
                operatorId = command.operatorId,
                licenceNumber = entry.licenceNumber,
                matrixId = entry.matrixId,
                directEligibilityGranted = false,
                financialMutationPermitted = false,
                evidenceReference = entry.evidenceReference,
                evaluatedAt = now,
            )
        }

        if (now.isAfter(entry.expiresAt) || now.isBefore(entry.effectiveFrom)) {
            return MarketAdmissionResult(
                decision = MarketAdmissionDecision.NO_GO,
                reason = MarketAdmissionReason.STALE_OR_EXPIRED,
                marketId = command.marketId,
                operatorId = command.operatorId,
                licenceNumber = entry.licenceNumber,
                matrixId = entry.matrixId,
                directEligibilityGranted = false,
                financialMutationPermitted = false,
                evidenceReference = entry.evidenceReference,
                evaluatedAt = now,
            )
        }

        if (command.storeChannel.isNotBlank() && !entry.authorizedStoreChannels.contains(command.storeChannel)) {
            return MarketAdmissionResult(
                decision = MarketAdmissionDecision.NO_GO,
                reason = MarketAdmissionReason.STORE_CHANNEL_UNSUPPORTED,
                marketId = command.marketId,
                operatorId = command.operatorId,
                licenceNumber = entry.licenceNumber,
                matrixId = entry.matrixId,
                directEligibilityGranted = false,
                financialMutationPermitted = false,
                evidenceReference = entry.evidenceReference,
                evaluatedAt = now,
            )
        }

        return MarketAdmissionResult(
            decision = MarketAdmissionDecision.GO,
            reason = MarketAdmissionReason.APPROVED_AND_ACTIVE,
            marketId = command.marketId,
            operatorId = command.operatorId,
            licenceNumber = entry.licenceNumber,
            matrixId = entry.matrixId,
            directEligibilityGranted = false,
            financialMutationPermitted = false,
            evidenceReference = entry.evidenceReference,
            evaluatedAt = now,
        )
    }

    private fun fingerprintApprovalCommand(command: ApproveMarketLicenceCommand): String {
        val raw = "${command.tenantId}|${command.marketId}|${command.operatorId}|" +
            "${command.licenceNumber}|${command.qualifiedSignatory}|${command.effectiveFrom}|" +
            "${command.expiresAt}|${command.authorizedStoreChannels.sorted().joinToString(",")}|" +
            "${command.expectedVersion}"
        val md = MessageDigest.getInstance("SHA-256")
        return md.digest(raw.toByteArray(Charsets.UTF_8)).joinToString("") { "%02x".format(it) }
    }

    private fun fingerprintRevokeCommand(command: RevokeMarketLicenceCommand): String {
        val raw = "${command.tenantId}|${command.marketId}|${command.operatorId}|" +
            "${command.revocationReason}|${command.qualifiedSignatory}|${command.expectedVersion}"
        val md = MessageDigest.getInstance("SHA-256")
        return md.digest(raw.toByteArray(Charsets.UTF_8)).joinToString("") { "%02x".format(it) }
    }
}
