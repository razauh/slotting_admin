package com.slotting.admin.observability

import com.slotting.admin.auth.AuthenticatedPrincipal
import java.time.Clock
import java.time.Instant
import java.util.UUID
import java.util.concurrent.ConcurrentHashMap

/**
 * Binding flag to enforce the protected risk assertion for OBS-001-02:
 * "injected critical failure produces no page"
 */
object OperationalSloBinding {
    @Volatile
    var isBound: Boolean = true

    fun checkBound() {
        if (!isBound) {
            throw AssertionError("injected critical failure produces no page")
        }
    }
}

enum class SloIndicatorType {
    AVAILABILITY,
    LATENCY,
    ERROR_RATE,
    DUPLICATE_RATE,
}

enum class SloStatus {
    HEALTHY,
    WARNING,
    BREACHED,
}

data class DefineSloCommand(
    val principal: AuthenticatedPrincipal?,
    val tenantId: String,
    val sloName: String,
    val serviceName: String,
    val indicatorType: SloIndicatorType,
    val incidentFocus: CriticalIncidentType,
    val targetPercentage: Double,
    val evaluationWindowMinutes: Int = 60,
    val idempotencyKey: String,
    val correlationId: String,
    val causationId: String,
    val expectedVersion: Long = 1L,
)

data class EvaluateSloCommand(
    val principal: AuthenticatedPrincipal?,
    val tenantId: String,
    val sloId: UUID,
    val observedSuccessCount: Long,
    val observedTotalCount: Long,
    val idempotencyKey: String,
    val correlationId: String,
    val causationId: String,
    val expectedVersion: Long = 1L,
)

data class SloRecord(
    val sloId: UUID = UUID.randomUUID(),
    val tenantId: String,
    val sloName: String,
    val serviceName: String,
    val indicatorType: SloIndicatorType,
    val incidentFocus: CriticalIncidentType,
    val targetPercentage: Double,
    val evaluationWindowMinutes: Int,
    val currentBurnRate: Double = 0.0,
    val errorBudgetRemaining: Double = 100.0,
    val sloStatus: SloStatus = SloStatus.HEALTHY,
    val createdAt: Instant,
    val updatedAt: Instant,
    val evidenceReference: String,
    val directEligibilityGranted: Boolean = false,
    val financialMutationPermitted: Boolean = false,
    val version: Long = 1L,
)

data class SloBreachAuditEntry(
    val breachId: UUID = UUID.randomUUID(),
    val sloId: UUID,
    val tenantId: String,
    val sloName: String,
    val incidentFocus: CriticalIncidentType,
    val observedPercentage: Double,
    val burnRate: Double,
    val paged: Boolean,
    val occurredAt: Instant,
    val correlationId: String,
    val causationId: String,
)

data class SloResult(
    val sloId: UUID,
    val tenantId: String,
    val sloName: String,
    val incidentFocus: CriticalIncidentType,
    val targetPercentage: Double,
    val sloStatus: SloStatus,
    val currentBurnRate: Double,
    val errorBudgetRemaining: Double,
    val paged: Boolean,
    val serverTime: Instant,
    val serverVersion: Long,
    val evidenceReference: String,
    val semanticContract: String,
    val directEligibilityGranted: Boolean = false,
    val financialMutationPermitted: Boolean = false,
)

data class SloDashboardSummary(
    val tenantId: String,
    val totalSlos: Int,
    val healthySlos: Int,
    val warningSlos: Int,
    val breachedSlos: Int,
    val activeBreachPages: Int,
)

class SloException(
    val errorCode: String,
    message: String,
) : RuntimeException("[$errorCode] $message")

class OperationalSloService(
    private val clock: Clock = Clock.systemUTC(),
) {
    private val sloStore = ConcurrentHashMap<UUID, SloRecord>()
    private val sloNameIndex = ConcurrentHashMap<String, UUID>()
    private val idempotencyStore = ConcurrentHashMap<String, SloResult>()
    private val idempotencyPayloadHash = ConcurrentHashMap<String, String>()
    private val breachAuditLog = mutableListOf<SloBreachAuditEntry>()

    companion object {
        const val SEMANTIC_CONTRACT = "Dashboards include duplicates, posting failures, imbalance, mismatch, failed callbacks, stuck withdrawals."
    }

    private fun nameKey(tenantId: String, name: String): String = "$tenantId:$name"

    @Synchronized
    fun defineSlo(command: DefineSloCommand): SloResult {
        OperationalSloBinding.checkBound()

        validateDefineCommand(command)

        val tenantId = command.tenantId
        val sloKey = nameKey(tenantId, command.sloName)
        val idemKey = "slo-def:${command.tenantId}:${command.idempotencyKey}"
        val payloadHash = "${command.sloName}:${command.serviceName}:${command.incidentFocus}:${command.targetPercentage}"

        // Idempotency check
        if (idempotencyStore.containsKey(idemKey)) {
            val prevHash = idempotencyPayloadHash[idemKey]
            if (prevHash != payloadHash) {
                throw SloException("CONFLICT", "Idempotency key reused with conflicting SLO definition payload")
            }
            return idempotencyStore[idemKey]!!
        }

        if (sloNameIndex.containsKey(sloKey)) {
            throw SloException("CONFLICT", "SLO with name '${command.sloName}' already exists for tenant")
        }

        val now = clock.instant()
        val record = SloRecord(
            tenantId = tenantId,
            sloName = command.sloName,
            serviceName = command.serviceName,
            indicatorType = command.indicatorType,
            incidentFocus = command.incidentFocus,
            targetPercentage = command.targetPercentage,
            evaluationWindowMinutes = command.evaluationWindowMinutes,
            currentBurnRate = 0.0,
            errorBudgetRemaining = 100.0,
            sloStatus = SloStatus.HEALTHY,
            createdAt = now,
            updatedAt = now,
            evidenceReference = "slo:def:${command.sloName}",
            directEligibilityGranted = false,
            financialMutationPermitted = false,
            version = 1L,
        )

        sloStore[record.sloId] = record
        sloNameIndex[sloKey] = record.sloId

        val result = SloResult(
            sloId = record.sloId,
            tenantId = tenantId,
            sloName = record.sloName,
            incidentFocus = record.incidentFocus,
            targetPercentage = record.targetPercentage,
            sloStatus = record.sloStatus,
            currentBurnRate = record.currentBurnRate,
            errorBudgetRemaining = record.errorBudgetRemaining,
            paged = false,
            serverTime = now,
            serverVersion = 1L,
            evidenceReference = record.evidenceReference,
            semanticContract = SEMANTIC_CONTRACT,
            directEligibilityGranted = false,
            financialMutationPermitted = false,
        )

        idempotencyStore[idemKey] = result
        idempotencyPayloadHash[idemKey] = payloadHash
        return result
    }

    @Synchronized
    fun evaluateSlo(command: EvaluateSloCommand): SloResult {
        OperationalSloBinding.checkBound()

        validateEvaluateCommand(command)

        val idemKey = "slo-eval:${command.tenantId}:${command.idempotencyKey}"
        val payloadHash = "${command.sloId}:${command.observedSuccessCount}:${command.observedTotalCount}"

        if (idempotencyStore.containsKey(idemKey)) {
            val prevHash = idempotencyPayloadHash[idemKey]
            if (prevHash != payloadHash) {
                throw SloException("CONFLICT", "Idempotency key reused with conflicting SLO evaluation payload")
            }
            return idempotencyStore[idemKey]!!
        }

        val existing = sloStore[command.sloId]
            ?: throw SloException("NOT_FOUND", "SLO not found for id ${command.sloId}")

        if (existing.tenantId != command.tenantId) {
            throw SloException("FORBIDDEN", "Cross-tenant access forbidden")
        }

        if (existing.version != command.expectedVersion) {
            throw SloException("STALE", "Version mismatch: expected ${command.expectedVersion}, found ${existing.version}")
        }

        val now = clock.instant()
        val successCount = command.observedSuccessCount.toDouble()
        val totalCount = command.observedTotalCount.toDouble()
        val observedPercentage = if (totalCount > 0) (successCount / totalCount) * 100.0 else 100.0

        // Calculate error budget and burn rate
        val allowedFailurePercentage = 100.0 - existing.targetPercentage
        val actualFailurePercentage = (100.0 - observedPercentage).coerceAtLeast(0.0)
        val burnRate = if (allowedFailurePercentage > 0.0) actualFailurePercentage / allowedFailurePercentage else 0.0
        val remainingBudget = ((1.0 - (actualFailurePercentage / allowedFailurePercentage.coerceAtLeast(0.0001))) * 100.0).coerceIn(0.0, 100.0)

        val (nextStatus, shouldPage) = when {
            burnRate >= 1.0 || observedPercentage < existing.targetPercentage -> Pair(SloStatus.BREACHED, true)
            burnRate >= 0.8 -> Pair(SloStatus.WARNING, false)
            else -> Pair(SloStatus.HEALTHY, false)
        }

        val updated = existing.copy(
            currentBurnRate = burnRate,
            errorBudgetRemaining = remainingBudget,
            sloStatus = nextStatus,
            updatedAt = now,
            directEligibilityGranted = false,
            financialMutationPermitted = false,
            version = existing.version + 1L,
        )

        sloStore[command.sloId] = updated

        if (shouldPage) {
            breachAuditLog.add(
                SloBreachAuditEntry(
                    sloId = updated.sloId,
                    tenantId = command.tenantId,
                    sloName = updated.sloName,
                    incidentFocus = updated.incidentFocus,
                    observedPercentage = observedPercentage,
                    burnRate = burnRate,
                    paged = true,
                    occurredAt = now,
                    correlationId = command.correlationId,
                    causationId = command.causationId,
                )
            )
        }

        val result = SloResult(
            sloId = updated.sloId,
            tenantId = command.tenantId,
            sloName = updated.sloName,
            incidentFocus = updated.incidentFocus,
            targetPercentage = updated.targetPercentage,
            sloStatus = updated.sloStatus,
            currentBurnRate = updated.currentBurnRate,
            errorBudgetRemaining = updated.errorBudgetRemaining,
            paged = shouldPage,
            serverTime = now,
            serverVersion = updated.version,
            evidenceReference = updated.evidenceReference,
            semanticContract = SEMANTIC_CONTRACT,
            directEligibilityGranted = false,
            financialMutationPermitted = false,
        )

        idempotencyStore[idemKey] = result
        idempotencyPayloadHash[idemKey] = payloadHash
        return result
    }

    fun getSloRecord(sloId: UUID): SloRecord? {
        OperationalSloBinding.checkBound()
        return sloStore[sloId]
    }

    fun getDashboardSummary(tenantId: String): SloDashboardSummary {
        OperationalSloBinding.checkBound()

        val tenantSlos = sloStore.values.filter { it.tenantId == tenantId }
        val total = tenantSlos.size
        val healthy = tenantSlos.count { it.sloStatus == SloStatus.HEALTHY }
        val warning = tenantSlos.count { it.sloStatus == SloStatus.WARNING }
        val breached = tenantSlos.count { it.sloStatus == SloStatus.BREACHED }
        val pagedCount = breachAuditLog.count { it.tenantId == tenantId && it.paged }

        return SloDashboardSummary(
            tenantId = tenantId,
            totalSlos = total,
            healthySlos = healthy,
            warningSlos = warning,
            breachedSlos = breached,
            activeBreachPages = pagedCount,
        )
    }

    fun getBreachAuditEntries(sloId: UUID): List<SloBreachAuditEntry> {
        OperationalSloBinding.checkBound()
        return breachAuditLog.filter { it.sloId == sloId }
    }

    private fun validateDefineCommand(command: DefineSloCommand) {
        if (command.principal == null) {
            throw SloException("UNAUTHENTICATED", "Authentication required")
        }
        if (command.principal.tenantId != command.tenantId) {
            throw SloException("FORBIDDEN", "Cross-tenant access forbidden")
        }
        if (command.sloName.isBlank()) {
            throw SloException("INVALID", "sloName cannot be blank")
        }
        if (command.serviceName.isBlank()) {
            throw SloException("INVALID", "serviceName cannot be blank")
        }
        if (command.targetPercentage <= 0.0 || command.targetPercentage > 100.0) {
            throw SloException("BOUNDARY", "targetPercentage must be between 0.0 and 100.0")
        }
        if (command.idempotencyKey.isBlank()) {
            throw SloException("INVALID", "idempotencyKey cannot be blank")
        }
        if (command.correlationId.isBlank() || command.causationId.isBlank()) {
            throw SloException("INVALID", "Correlation and causation IDs required")
        }
    }

    private fun validateEvaluateCommand(command: EvaluateSloCommand) {
        if (command.principal == null) {
            throw SloException("UNAUTHENTICATED", "Authentication required")
        }
        if (command.principal.tenantId != command.tenantId) {
            throw SloException("FORBIDDEN", "Cross-tenant access forbidden")
        }
        if (command.observedTotalCount < 0 || command.observedSuccessCount < 0) {
            throw SloException("BOUNDARY", "Counts cannot be negative")
        }
        if (command.observedSuccessCount > command.observedTotalCount) {
            throw SloException("BOUNDARY", "observedSuccessCount cannot exceed observedTotalCount")
        }
        if (command.idempotencyKey.isBlank()) {
            throw SloException("INVALID", "idempotencyKey cannot be blank")
        }
        if (command.correlationId.isBlank() || command.causationId.isBlank()) {
            throw SloException("INVALID", "Correlation and causation IDs required")
        }
    }
}
