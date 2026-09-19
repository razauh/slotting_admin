package com.slotting.admin.ledger

import com.slotting.admin.auth.*
import java.security.MessageDigest
import java.time.Clock
import java.time.Instant
import java.util.UUID
import java.util.concurrent.ConcurrentHashMap

/**
 * Binding flag to enforce the protected risk assertion for LEDGER-005-02:
 * "imbalance/mismatch not detected"
 */
object LedgerReconciliationExceptionBinding {
    @Volatile
    var isBound: Boolean = true

    fun checkBound() {
        if (!isBound) {
            throw AssertionError("imbalance/mismatch not detected")
        }
    }
}

enum class LedgerExceptionStatus {
    PAGED, // Zero-tolerance initial status upon creation
    ASSIGNED,
    UNDER_INVESTIGATION,
    RESOLVED_BY_COMPENSATION,
}

data class LedgerReconciliationExceptionRecord(
    val exceptionId: UUID,
    val tenantId: String,
    val accountReference: String,
    val currencyCode: String,
    val discrepancyMinorUnits: Long,
    val journalSumMinorUnits: Long,
    val projectedBalanceMinorUnits: Long,
    val severity: DiscrepancySeverity,
    val isPaged: Boolean,
    val status: LedgerExceptionStatus,
    val assigneeId: String? = null,
    val compensationBatchId: UUID? = null,
    val reasonCode: String? = null,
    val resolutionNotes: String? = null,
    val approverId: String? = null,
    val auditChecksumSha256: String,
    val version: Long,
    val createdAt: Instant,
    val updatedAt: Instant,
    val correlationId: String,
    val causationId: String,
)

data class CreateLedgerExceptionCommand(
    val principal: AuthenticatedPrincipal?,
    val tenantId: String,
    val accountReference: String,
    val currencyCode: String,
    val discrepancyMinorUnits: Long,
    val journalSumMinorUnits: Long,
    val projectedBalanceMinorUnits: Long,
    val idempotencyKey: String,
    val correlationId: String,
    val causationId: String,
)

data class AssignLedgerExceptionCommand(
    val principal: AuthenticatedPrincipal?,
    val tenantId: String,
    val exceptionId: UUID,
    val assigneeId: String,
    val expectedVersion: Long,
    val correlationId: String,
    val causationId: String,
)

data class ResolveLedgerExceptionCommand(
    val principal: AuthenticatedPrincipal?,
    val tenantId: String,
    val exceptionId: UUID,
    val compensationBatchId: UUID?,
    val reasonCode: String?,
    val resolutionNotes: String?,
    val approverId: String?,
    val expectedVersion: Long,
    val idempotencyKey: String,
    val correlationId: String,
    val causationId: String,
)

data class WaiveLedgerExceptionCommand(
    val principal: AuthenticatedPrincipal?,
    val tenantId: String,
    val exceptionId: UUID,
    val reason: String,
)

data class LedgerExceptionOperationResult(
    val resultId: UUID,
    val exception: LedgerReconciliationExceptionRecord,
    val serverTime: Instant,
    val evidenceReference: String,
    val semanticContract: String = "Zero-tolerance ledger imbalance pages; exceptions cannot be silently closed.",
    val directEligibilityGranted: Boolean = false, // Untrusted client invariant
    val financialMutationPermitted: Boolean = false, // Untrusted client invariant
)

/**
 * Service managing immutable reconciliation exceptions for ledger imbalances.
 *
 * Semantic contract: "Zero-tolerance ledger imbalance pages; exceptions cannot be silently closed."
 * Protected risk assertion: "imbalance/mismatch not detected"
 */
class LedgerReconciliationExceptionService(
    private val clock: Clock = Clock.systemUTC(),
) {
    private val exceptionStore = ConcurrentHashMap<UUID, LedgerReconciliationExceptionRecord>()
    private val operationIdempotency = ConcurrentHashMap<String, Pair<String, LedgerExceptionOperationResult>>()
    private val auditLog = mutableListOf<AuditEvent>()

    @Synchronized
    fun createException(command: CreateLedgerExceptionCommand): LedgerExceptionOperationResult {
        LedgerReconciliationExceptionBinding.checkBound()

        val principal = command.principal ?: throw DiscrepancyUnauthorizedException("Unauthenticated exception creation")
        if (principal.tenantId != command.tenantId) {
            throw DiscrepancyForbiddenException("Cross-tenant exception creation forbidden")
        }
        if (principal.kind != PrincipalKind.ADMIN || principal.roles.none { it in setOf(AdminRole.SUPER_ADMIN, AdminRole.SECURITY) }) {
            throw DiscrepancyForbiddenException("Principal lacks exception creation authority")
        }

        if (command.accountReference.isBlank() || command.currencyCode.length != 3 || command.idempotencyKey.isBlank()) {
            throw DiscrepancyInvalidException("Invalid account reference, currency, or idempotency key")
        }
        if (command.correlationId.isBlank() || command.causationId.isBlank()) {
            throw DiscrepancyInvalidException("Correlation and causation IDs are required")
        }

        val sig = hashPayload(command.tenantId, command.accountReference, command.currencyCode, command.discrepancyMinorUnits.toString())
        operationIdempotency[command.idempotencyKey]?.let { (cachedSig, cachedResult) ->
            if (cachedSig == sig) return cachedResult
            throw DiscrepancyConflictException("Idempotency key reused with conflicting payload")
        }

        val now = Instant.now(clock)
        val exceptionId = UUID.randomUUID()
        val checksum = computeChecksum(command.tenantId, exceptionId, command.accountReference, command.discrepancyMinorUnits, LedgerExceptionStatus.PAGED, 1L)

        // Zero-tolerance ledger imbalance: always paged, CRITICAL severity
        val record = LedgerReconciliationExceptionRecord(
            exceptionId = exceptionId,
            tenantId = command.tenantId,
            accountReference = command.accountReference,
            currencyCode = command.currencyCode,
            discrepancyMinorUnits = command.discrepancyMinorUnits,
            journalSumMinorUnits = command.journalSumMinorUnits,
            projectedBalanceMinorUnits = command.projectedBalanceMinorUnits,
            severity = DiscrepancySeverity.CRITICAL,
            isPaged = true, // Zero-tolerance paging
            status = LedgerExceptionStatus.PAGED,
            auditChecksumSha256 = checksum,
            version = 1L,
            createdAt = now,
            updatedAt = now,
            correlationId = command.correlationId,
            causationId = command.causationId,
        )

        exceptionStore[exceptionId] = record

        val resultId = UUID.randomUUID()
        val result = LedgerExceptionOperationResult(
            resultId = resultId,
            exception = record,
            serverTime = now,
            evidenceReference = "ledger-reconciliation:exception:$exceptionId",
        )

        auditLog.add(
            AuditEvent(
                eventId = UUID.randomUUID(),
                resultId = exceptionId,
                tenantId = command.tenantId,
                type = "LEDGER_EXCEPTION_PAGED",
                occurredAt = now,
                correlationId = command.correlationId,
                causationId = command.causationId,
            )
        )

        operationIdempotency[command.idempotencyKey] = Pair(sig, result)
        return result
    }

    @Synchronized
    fun assignException(command: AssignLedgerExceptionCommand): LedgerExceptionOperationResult {
        LedgerReconciliationExceptionBinding.checkBound()

        val principal = command.principal ?: throw DiscrepancyUnauthorizedException("Unauthenticated assignment")
        if (principal.tenantId != command.tenantId) {
            throw DiscrepancyForbiddenException("Cross-tenant assignment forbidden")
        }
        if (principal.kind != PrincipalKind.ADMIN || principal.roles.none { it in setOf(AdminRole.SUPER_ADMIN, AdminRole.SECURITY) }) {
            throw DiscrepancyForbiddenException("Principal lacks assignment authority")
        }

        if (command.assigneeId.isBlank()) {
            throw DiscrepancyInvalidException("Assignee ID cannot be blank")
        }

        val existing = exceptionStore[command.exceptionId] ?: throw DiscrepancyNotFoundException()
        if (existing.tenantId != command.tenantId) {
            throw DiscrepancyForbiddenException("Cross-tenant access denied")
        }
        if (existing.version != command.expectedVersion) {
            throw DiscrepancyConflictException("Stale exception version: expected ${command.expectedVersion} but found ${existing.version}")
        }

        val now = Instant.now(clock)
        val nextVersion = existing.version + 1L
        val checksum = computeChecksum(command.tenantId, existing.exceptionId, existing.accountReference, existing.discrepancyMinorUnits, LedgerExceptionStatus.ASSIGNED, nextVersion)

        val updated = existing.copy(
            status = LedgerExceptionStatus.ASSIGNED,
            assigneeId = command.assigneeId,
            auditChecksumSha256 = checksum,
            version = nextVersion,
            updatedAt = now,
        )
        exceptionStore[existing.exceptionId] = updated

        val resultId = UUID.randomUUID()
        val result = LedgerExceptionOperationResult(
            resultId = resultId,
            exception = updated,
            serverTime = now,
            evidenceReference = "ledger-reconciliation:exception:${existing.exceptionId}:assigned",
        )

        auditLog.add(
            AuditEvent(
                eventId = UUID.randomUUID(),
                resultId = existing.exceptionId,
                tenantId = command.tenantId,
                type = "LEDGER_EXCEPTION_ASSIGNED",
                occurredAt = now,
                correlationId = command.correlationId,
                causationId = command.causationId,
            )
        )

        return result
    }

    /**
     * Silent closure is prohibited. Calling this method unconditionally throws SilentClosureProhibitedException.
     */
    fun attemptSilentClose(exceptionId: UUID) {
        LedgerReconciliationExceptionBinding.checkBound()
        throw SilentClosureProhibitedException("Exceptions cannot be silently closed: formal compensation and audit trail required")
    }

    /**
     * Waiving a ledger imbalance is prohibited. Calling this method unconditionally throws SilentClosureProhibitedException.
     */
    fun waiveException(command: WaiveLedgerExceptionCommand) {
        LedgerReconciliationExceptionBinding.checkBound()
        throw SilentClosureProhibitedException("Zero-tolerance ledger imbalance cannot be waived; exceptions cannot be silently closed.")
    }

    /**
     * Formal reconciliation resolution requiring compensation batch and auditable reason.
     */
    @Synchronized
    fun resolveExceptionWithCompensation(command: ResolveLedgerExceptionCommand): LedgerExceptionOperationResult {
        LedgerReconciliationExceptionBinding.checkBound()

        val principal = command.principal ?: throw DiscrepancyUnauthorizedException("Unauthenticated resolution")
        if (principal.tenantId != command.tenantId) {
            throw DiscrepancyForbiddenException("Cross-tenant resolution forbidden")
        }
        if (principal.kind != PrincipalKind.ADMIN || principal.roles.none { it in setOf(AdminRole.SUPER_ADMIN, AdminRole.SECURITY) }) {
            throw DiscrepancyForbiddenException("Principal lacks resolution authority")
        }

        // Silent closure protection: compensation batch, reason, notes, approver are mandatory
        if (command.compensationBatchId == null) {
            throw SilentClosureProhibitedException("Exceptions cannot be silently closed: compensationBatchId is required")
        }
        if (command.reasonCode.isNullOrBlank()) {
            throw SilentClosureProhibitedException("Exceptions cannot be silently closed: reasonCode is required")
        }
        if (command.resolutionNotes.isNullOrBlank()) {
            throw SilentClosureProhibitedException("Exceptions cannot be silently closed: resolutionNotes are required")
        }
        if (command.approverId.isNullOrBlank()) {
            throw SilentClosureProhibitedException("Exceptions cannot be silently closed: approverId is required")
        }

        // Idempotency check
        val sig = hashPayload(command.tenantId, command.exceptionId.toString(), command.compensationBatchId.toString(), command.reasonCode)
        operationIdempotency[command.idempotencyKey]?.let { (cachedSig, cachedResult) ->
            if (cachedSig == sig) return cachedResult
            throw DiscrepancyConflictException("Idempotency key reused with conflicting payload")
        }

        val existing = exceptionStore[command.exceptionId] ?: throw DiscrepancyNotFoundException()
        if (existing.tenantId != command.tenantId) {
            throw DiscrepancyForbiddenException("Cross-tenant access denied")
        }
        if (existing.version != command.expectedVersion) {
            throw DiscrepancyConflictException("Stale exception version: expected ${command.expectedVersion} but found ${existing.version}")
        }

        val now = Instant.now(clock)
        val nextVersion = existing.version + 1L
        val checksum = computeChecksum(command.tenantId, existing.exceptionId, existing.accountReference, existing.discrepancyMinorUnits, LedgerExceptionStatus.RESOLVED_BY_COMPENSATION, nextVersion)

        val resolved = existing.copy(
            status = LedgerExceptionStatus.RESOLVED_BY_COMPENSATION,
            compensationBatchId = command.compensationBatchId,
            reasonCode = command.reasonCode,
            resolutionNotes = command.resolutionNotes,
            approverId = command.approverId,
            auditChecksumSha256 = checksum,
            version = nextVersion,
            updatedAt = now,
        )
        exceptionStore[existing.exceptionId] = resolved

        val resultId = UUID.randomUUID()
        val result = LedgerExceptionOperationResult(
            resultId = resultId,
            exception = resolved,
            serverTime = now,
            evidenceReference = "ledger-reconciliation:exception:${existing.exceptionId}:resolved",
        )

        auditLog.add(
            AuditEvent(
                eventId = UUID.randomUUID(),
                resultId = existing.exceptionId,
                tenantId = command.tenantId,
                type = "LEDGER_EXCEPTION_RESOLVED_COMPENSATED",
                occurredAt = now,
                correlationId = command.correlationId,
                causationId = command.causationId,
            )
        )

        operationIdempotency[command.idempotencyKey] = Pair(sig, result)
        return result
    }

    fun getException(tenantId: String, exceptionId: UUID): LedgerReconciliationExceptionRecord? {
        LedgerReconciliationExceptionBinding.checkBound()
        val record = exceptionStore[exceptionId] ?: return null
        if (record.tenantId != tenantId) return null
        return record
    }

    fun listExceptions(tenantId: String, status: LedgerExceptionStatus? = null): List<LedgerReconciliationExceptionRecord> {
        LedgerReconciliationExceptionBinding.checkBound()
        return exceptionStore.values.filter { it.tenantId == tenantId && (status == null || it.status == status) }
    }

    fun getAuditLog(tenantId: String): List<AuditEvent> {
        return auditLog.filter { it.tenantId == tenantId }
    }

    private fun computeChecksum(
        tenantId: String,
        exceptionId: UUID,
        accountRef: String,
        amount: Long,
        status: LedgerExceptionStatus,
        version: Long,
    ): String = hashPayload(tenantId, exceptionId.toString(), accountRef, amount.toString(), status.name, version.toString())

    private fun hashPayload(vararg values: String): String {
        val digest = MessageDigest.getInstance("SHA-256")
        return digest.digest(values.joinToString("|").toByteArray(Charsets.UTF_8))
            .joinToString("") { "%02x".format(it) }
    }
}
