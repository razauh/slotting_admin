package com.slotting.admin.ledger

import com.slotting.admin.auth.*
import java.security.MessageDigest
import java.time.Clock
import java.time.Instant
import java.util.UUID
import java.util.concurrent.ConcurrentHashMap

/**
 * Binding flag to enforce the protected risk assertion for LEDGER-005-01:
 * "imbalance/mismatch not detected"
 */
object LedgerDiscrepancyDetectionBinding {
    @Volatile
    var isBound: Boolean = true

    fun checkBound() {
        if (!isBound) {
            throw AssertionError("imbalance/mismatch not detected")
        }
    }
}

enum class DiscrepancySeverity {
    CRITICAL, // Zero-tolerance ledger imbalance triggers immediate page
    HIGH,
    MEDIUM,
}

enum class DiscrepancyStatus {
    OPEN,
    PAGED,
    UNDER_INVESTIGATION,
    RESOLVED_BY_COMPENSATION,
}

open class DiscrepancyDetectionException(val errorCode: String, message: String) : RuntimeException(message)

class SilentClosureProhibitedException(
    message: String = "Exceptions cannot be silently closed: formal compensation and audit trail required",
) : DiscrepancyDetectionException("SILENT_CLOSURE_PROHIBITED", message)

class DiscrepancyUnauthorizedException(
    message: String = "Unauthenticated discrepancy detection attempt",
) : DiscrepancyDetectionException("UNAUTHORIZED", message)

class DiscrepancyForbiddenException(
    message: String = "Forbidden: insufficient permissions or cross-tenant access",
) : DiscrepancyDetectionException("FORBIDDEN", message)

class DiscrepancyInvalidException(
    message: String,
) : DiscrepancyDetectionException("INVALID", message)

class DiscrepancyConflictException(
    message: String,
) : DiscrepancyDetectionException("CONFLICT", message)

class DiscrepancyNotFoundException(
    message: String = "Discrepancy record not found",
) : DiscrepancyDetectionException("NOT_FOUND", message)

data class ReconciliationDiscrepancy(
    val discrepancyId: UUID,
    val tenantId: String,
    val accountReference: String,
    val currencyCode: String,
    val journalSumMinorUnits: Long,
    val projectedBalanceMinorUnits: Long,
    val differenceMinorUnits: Long,
    val severity: DiscrepancySeverity,
    val isPaged: Boolean,
    val status: DiscrepancyStatus,
    val detectedAt: Instant,
    val correlationId: String,
    val causationId: String,
)

data class RunDiscrepancyCheckCommand(
    val principal: AuthenticatedPrincipal?,
    val tenantId: String,
    val currencyCode: String? = null,
    val idempotencyKey: String,
    val correlationId: String,
    val causationId: String,
)

data class DiscrepancyCheckResult(
    val checkId: UUID,
    val tenantId: String,
    val totalAccountsScanned: Int,
    val discrepanciesFound: Int,
    val zeroToleranceImbalanceDetected: Boolean,
    val isPaged: Boolean,
    val discrepancies: List<ReconciliationDiscrepancy>,
    val serverTime: Instant,
    val evidenceReference: String,
    val semanticContract: String = "Zero-tolerance ledger imbalance pages; exceptions cannot be silently closed.",
    val directEligibilityGranted: Boolean = false, // Untrusted client invariant
    val financialMutationPermitted: Boolean = false, // Untrusted client invariant
)

data class CloseDiscrepancyCommand(
    val principal: AuthenticatedPrincipal?,
    val tenantId: String,
    val discrepancyId: UUID,
    val reason: String?,
    val compensationBatchId: UUID?,
)

/**
 * Authoritative discrepancy detection service enforcing zero-tolerance ledger imbalance paging,
 * reconciliation between journal entries and projections, and prohibition of silent exception closure.
 *
 * Semantic contract: "Zero-tolerance ledger imbalance pages; exceptions cannot be silently closed."
 * Protected risk assertion: "imbalance/mismatch not detected"
 */
class LedgerDiscrepancyDetectionService(
    private val clock: Clock = Clock.systemUTC(),
) {
    private val discrepancyStore = ConcurrentHashMap<UUID, ReconciliationDiscrepancy>()
    private val checkIdempotency = ConcurrentHashMap<String, Pair<String, DiscrepancyCheckResult>>()
    private val auditLogs = mutableListOf<AuditEvent>()

    /**
     * Run discrepancy detection comparing journal entries with projected account balances.
     * Any non-zero drift triggers immediate zero-tolerance paging (isPaged = true).
     */
    @Synchronized
    fun runDiscrepancyCheck(
        command: RunDiscrepancyCheckCommand,
        journalBatches: List<JournalBatchRecord>,
        liveProjections: List<AccountBalanceProjection>,
    ): DiscrepancyCheckResult {
        LedgerDiscrepancyDetectionBinding.checkBound()

        // 1. Auth & Permission checks
        val principal = command.principal ?: throw DiscrepancyUnauthorizedException("Unauthenticated discrepancy check")
        if (principal.tenantId != command.tenantId) {
            throw DiscrepancyForbiddenException("Cross-tenant discrepancy check forbidden")
        }
        if (principal.kind != PrincipalKind.ADMIN || principal.roles.none { it in setOf(AdminRole.SUPER_ADMIN, AdminRole.SECURITY) }) {
            throw DiscrepancyForbiddenException("Principal lacks reconciliation authority")
        }

        // 2. Input validation
        if (command.idempotencyKey.isBlank()) {
            throw DiscrepancyInvalidException("Idempotency key cannot be blank")
        }
        if (command.correlationId.isBlank() || command.causationId.isBlank()) {
            throw DiscrepancyInvalidException("Correlation and causation IDs are required")
        }

        // 3. Idempotency check
        val sig = hashPayload(command.tenantId, command.currencyCode ?: "ALL", command.idempotencyKey)
        checkIdempotency[command.idempotencyKey]?.let { (cachedSig, cachedResult) ->
            if (cachedSig == sig) return cachedResult
            throw DiscrepancyConflictException("Idempotency key reused with conflicting payload")
        }

        // 4. Calculate journal sums per account
        val journalSums = mutableMapOf<String, Long>()
        val accountCurrencies = mutableMapOf<String, String>()

        val relevantBatches = journalBatches.filter {
            it.tenantId == command.tenantId &&
                (it.status == JournalBatchStatus.POSTED || it.status == JournalBatchStatus.COMPENSATED) &&
                (command.currencyCode == null || it.currencyCode == command.currencyCode)
        }

        for (batch in relevantBatches) {
            for (entry in batch.entries) {
                val sign = if (entry.direction == JournalEntryDirection.CREDIT) 1L else -1L
                val delta = entry.amountMinorUnits * sign
                journalSums[entry.accountReference] = (journalSums[entry.accountReference] ?: 0L) + delta
                accountCurrencies[entry.accountReference] = entry.currencyCode
            }
        }

        // Map live projections by account
        val projectionsMap = liveProjections
            .filter { it.tenantId == command.tenantId && (command.currencyCode == null || it.currencyCode == command.currencyCode) }
            .associateBy { it.accountReference }

        val allAccountRefs = (journalSums.keys + projectionsMap.keys).toSet()
        val detectedDiscrepancies = mutableListOf<ReconciliationDiscrepancy>()
        val now = Instant.now(clock)
        var zeroTolerancePagingTriggered = false

        for (accRef in allAccountRefs) {
            val jSum = journalSums[accRef] ?: 0L
            val pBal = projectionsMap[accRef]?.balanceMinorUnits ?: 0L
            val diff = pBal - jSum

            if (diff != 0L) {
                // Zero-tolerance policy: ANY non-zero imbalance triggers immediate page
                zeroTolerancePagingTriggered = true
                val discId = UUID.randomUUID()
                val disc = ReconciliationDiscrepancy(
                    discrepancyId = discId,
                    tenantId = command.tenantId,
                    accountReference = accRef,
                    currencyCode = accountCurrencies[accRef] ?: projectionsMap[accRef]?.currencyCode ?: "USD",
                    journalSumMinorUnits = jSum,
                    projectedBalanceMinorUnits = pBal,
                    differenceMinorUnits = diff,
                    severity = DiscrepancySeverity.CRITICAL,
                    isPaged = true, // Zero-tolerance paging
                    status = DiscrepancyStatus.PAGED,
                    detectedAt = now,
                    correlationId = command.correlationId,
                    causationId = command.causationId,
                )
                discrepancyStore[discId] = disc
                detectedDiscrepancies.add(disc)

                auditLogs.add(
                    AuditEvent(
                        eventId = UUID.randomUUID(),
                        resultId = discId,
                        tenantId = command.tenantId,
                        type = "LEDGER_DISCREPANCY_PAGED",
                        occurredAt = now,
                        correlationId = command.correlationId,
                        causationId = command.causationId,
                    )
                )
            }
        }

        val checkId = UUID.randomUUID()
        val result = DiscrepancyCheckResult(
            checkId = checkId,
            tenantId = command.tenantId,
            totalAccountsScanned = allAccountRefs.size,
            discrepanciesFound = detectedDiscrepancies.size,
            zeroToleranceImbalanceDetected = zeroTolerancePagingTriggered,
            isPaged = zeroTolerancePagingTriggered,
            discrepancies = detectedDiscrepancies,
            serverTime = now,
            evidenceReference = "ledger-reconciliation:check:$checkId",
        )

        checkIdempotency[command.idempotencyKey] = Pair(sig, result)
        return result
    }

    /**
     * Exceptions CANNOT be silently closed without compensation and audit trail.
     * Attempting silent closure unconditionally throws SilentClosureProhibitedException.
     */
    fun attemptSilentClose(command: CloseDiscrepancyCommand) {
        LedgerDiscrepancyDetectionBinding.checkBound()
        throw SilentClosureProhibitedException("Exceptions cannot be silently closed: formal compensation and audit trail required")
    }

    /**
     * Formal reconciliation closure via compensation batch and explicit reason.
     */
    @Synchronized
    fun resolveWithCompensation(command: CloseDiscrepancyCommand): ReconciliationDiscrepancy {
        LedgerDiscrepancyDetectionBinding.checkBound()

        val principal = command.principal ?: throw DiscrepancyUnauthorizedException("Unauthenticated closure attempt")
        if (principal.tenantId != command.tenantId) {
            throw DiscrepancyForbiddenException("Cross-tenant closure forbidden")
        }
        if (principal.kind != PrincipalKind.ADMIN || principal.roles.none { it in setOf(AdminRole.SUPER_ADMIN, AdminRole.SECURITY) }) {
            throw DiscrepancyForbiddenException("Principal lacks reconciliation resolution authority")
        }

        if (command.reason.isNullOrBlank()) {
            throw SilentClosureProhibitedException("Exceptions cannot be silently closed: reason is mandatory")
        }
        if (command.compensationBatchId == null) {
            throw SilentClosureProhibitedException("Exceptions cannot be silently closed: compensationBatchId is mandatory")
        }

        val disc = discrepancyStore[command.discrepancyId] ?: throw DiscrepancyNotFoundException()
        if (disc.tenantId != command.tenantId) {
            throw DiscrepancyForbiddenException("Cross-tenant discrepancy access denied")
        }

        val resolved = disc.copy(
            status = DiscrepancyStatus.RESOLVED_BY_COMPENSATION,
        )
        discrepancyStore[disc.discrepancyId] = resolved

        val now = Instant.now(clock)
        auditLogs.add(
            AuditEvent(
                eventId = UUID.randomUUID(),
                resultId = disc.discrepancyId,
                tenantId = command.tenantId,
                type = "LEDGER_DISCREPANCY_RESOLVED",
                occurredAt = now,
                correlationId = disc.correlationId,
                causationId = disc.causationId,
            )
        )

        return resolved
    }

    fun getDiscrepancy(tenantId: String, discrepancyId: UUID): ReconciliationDiscrepancy? {
        LedgerDiscrepancyDetectionBinding.checkBound()
        val disc = discrepancyStore[discrepancyId] ?: return null
        if (disc.tenantId != tenantId) return null
        return disc
    }

    fun getAuditLogs(tenantId: String): List<AuditEvent> {
        return auditLogs.filter { it.tenantId == tenantId }
    }

    private fun hashPayload(vararg values: String): String {
        val digest = MessageDigest.getInstance("SHA-256")
        return digest.digest(values.joinToString("|").toByteArray(Charsets.UTF_8))
            .joinToString("") { "%02x".format(it) }
    }
}
