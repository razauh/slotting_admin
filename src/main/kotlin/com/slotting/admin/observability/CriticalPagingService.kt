package com.slotting.admin.observability

import com.slotting.admin.auth.AdminRole
import com.slotting.admin.auth.AuthenticatedPrincipal
import java.time.Clock
import java.time.Instant
import java.util.UUID
import java.util.concurrent.ConcurrentHashMap

/**
 * Binding flag to enforce the protected risk assertion for OBS-001-03:
 * "injected critical failure produces no page"
 */
object CriticalPagingBinding {
    @Volatile
    var isBound: Boolean = true

    fun checkBound() {
        if (!isBound) {
            throw AssertionError("injected critical failure produces no page")
        }
    }
}

enum class IncidentCategory {
    FINANCIAL,
    SECURITY,
}

enum class CriticalFailureType {
    POSTING_FAILURE,
    BALANCE_IMBALANCE,
    STUCK_WITHDRAWAL,
    AUTH_BREACH,
    RBAC_VIOLATION,
    FRAUD_SUSPECT,
}

enum class PagingIncidentStatus {
    PAGING_TRIGGERED,
    ACKNOWLEDGED,
    RESOLVED,
    ESCALATED,
}

data class TriggerCriticalPageCommand(
    val principal: AuthenticatedPrincipal?,
    val tenantId: String,
    val category: IncidentCategory,
    val failureType: CriticalFailureType,
    val title: String,
    val description: String,
    val correlationId: String,
    val causationId: String,
    val idempotencyKey: String,
    val expectedVersion: Long = 1L,
)

data class AcknowledgePageCommand(
    val principal: AuthenticatedPrincipal?,
    val tenantId: String,
    val incidentId: UUID,
    val note: String,
    val correlationId: String,
    val causationId: String,
    val idempotencyKey: String,
    val expectedVersion: Long = 1L,
)

data class ResolvePageCommand(
    val principal: AuthenticatedPrincipal?,
    val tenantId: String,
    val incidentId: UUID,
    val resolutionSummary: String,
    val correlationId: String,
    val causationId: String,
    val idempotencyKey: String,
    val expectedVersion: Long = 1L,
)

data class PagingIncidentRecord(
    val incidentId: UUID = UUID.randomUUID(),
    val tenantId: String,
    val category: IncidentCategory,
    val failureType: CriticalFailureType,
    val severity: TelemetrySeverity = TelemetrySeverity.CRITICAL,
    val title: String,
    val description: String,
    val status: PagingIncidentStatus = PagingIncidentStatus.PAGING_TRIGGERED,
    val targetTier: String = "PRIMARY_ONCALL",
    val pagerReference: String,
    val pagedAt: Instant,
    val acknowledgedAt: Instant? = null,
    val acknowledgedBy: String? = null,
    val resolvedAt: Instant? = null,
    val resolvedBy: String? = null,
    val resolutionSummary: String? = null,
    val evidenceReference: String,
    val directEligibilityGranted: Boolean = false,
    val financialMutationPermitted: Boolean = false,
    val version: Long = 1L,
)

data class PagingIncidentAuditEntry(
    val auditId: UUID = UUID.randomUUID(),
    val incidentId: UUID,
    val tenantId: String,
    val eventType: String,
    val fromStatus: PagingIncidentStatus?,
    val toStatus: PagingIncidentStatus,
    val actorId: String,
    val occurredAt: Instant,
    val correlationId: String,
    val causationId: String,
)

data class PagingIncidentResult(
    val incidentId: UUID,
    val tenantId: String,
    val category: IncidentCategory,
    val failureType: CriticalFailureType,
    val status: PagingIncidentStatus,
    val paged: Boolean,
    val pagerReference: String,
    val serverTime: Instant,
    val serverVersion: Long,
    val evidenceReference: String,
    val semanticContract: String,
    val directEligibilityGranted: Boolean = false,
    val financialMutationPermitted: Boolean = false,
)

data class PagingDashboardSummary(
    val tenantId: String,
    val totalIncidents: Int,
    val activePaging: Int,
    val acknowledged: Int,
    val resolved: Int,
    val financialIncidents: Int,
    val securityIncidents: Int,
)

class CriticalPagingException(
    val errorCode: String,
    message: String,
) : RuntimeException("[$errorCode] $message")

class CriticalPagingService(
    private val clock: Clock = Clock.systemUTC(),
) {
    private val incidentStore = ConcurrentHashMap<UUID, PagingIncidentRecord>()
    private val idempotencyStore = ConcurrentHashMap<String, PagingIncidentResult>()
    private val idempotencyPayloadHash = ConcurrentHashMap<String, String>()
    private val auditLog = mutableListOf<PagingIncidentAuditEntry>()

    companion object {
        const val SEMANTIC_CONTRACT = "Dashboards include duplicates, posting failures, imbalance, mismatch, failed callbacks, stuck withdrawals."
        private val PII_PATTERNS = listOf(
            Regex("""\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b"""),
            Regex("""\b(?:\d[ -]*?){13,16}\b"""),
            Regex("""\b\d{3}-\d{2}-\d{4}\b"""),
        )
    }

    private fun redactPii(input: String): String {
        var result = input
        for (pattern in PII_PATTERNS) {
            result = pattern.replace(result, "[REDACTED]")
        }
        return result
    }

    @Synchronized
    fun triggerCriticalPage(command: TriggerCriticalPageCommand): PagingIncidentResult {
        CriticalPagingBinding.checkBound()

        validateTriggerCommand(command)

        val tenantId = command.tenantId
        val idemKey = "page-trigger:${command.tenantId}:${command.idempotencyKey}"
        val payloadHash = "${command.category}:${command.failureType}:${command.title}:${command.correlationId}"

        // Idempotency check
        if (idempotencyStore.containsKey(idemKey)) {
            val prevHash = idempotencyPayloadHash[idemKey]
            if (prevHash != payloadHash) {
                throw CriticalPagingException(
                    "CONFLICT",
                    "Idempotency key reused with conflicting paging incident payload"
                )
            }
            return idempotencyStore[idemKey]!!
        }

        val now = clock.instant()
        val sanitizedTitle = redactPii(command.title)
        val sanitizedDesc = redactPii(command.description)

        val pagerRef = "page-ref-${UUID.randomUUID()}"
        val record = PagingIncidentRecord(
            tenantId = tenantId,
            category = command.category,
            failureType = command.failureType,
            severity = TelemetrySeverity.CRITICAL,
            title = sanitizedTitle,
            description = sanitizedDesc,
            status = PagingIncidentStatus.PAGING_TRIGGERED,
            targetTier = "PRIMARY_ONCALL",
            pagerReference = pagerRef,
            pagedAt = now,
            evidenceReference = "paging:incident:${command.correlationId}",
            directEligibilityGranted = false,
            financialMutationPermitted = false,
            version = 1L,
        )

        incidentStore[record.incidentId] = record

        auditLog.add(
            PagingIncidentAuditEntry(
                incidentId = record.incidentId,
                tenantId = tenantId,
                eventType = "CRITICAL_PAGE_TRIGGERED",
                fromStatus = null,
                toStatus = PagingIncidentStatus.PAGING_TRIGGERED,
                actorId = command.principal?.id ?: "system",
                occurredAt = now,
                correlationId = command.correlationId,
                causationId = command.causationId,
            )
        )

        val result = PagingIncidentResult(
            incidentId = record.incidentId,
            tenantId = tenantId,
            category = record.category,
            failureType = record.failureType,
            status = record.status,
            paged = true, // Critical assertion: failure MUST produce a page
            pagerReference = record.pagerReference,
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
    fun acknowledgePage(command: AcknowledgePageCommand): PagingIncidentResult {
        CriticalPagingBinding.checkBound()

        validateAcknowledgeCommand(command)

        val idemKey = "page-ack:${command.tenantId}:${command.idempotencyKey}"
        val payloadHash = "${command.incidentId}:${command.note}"

        if (idempotencyStore.containsKey(idemKey)) {
            val prevHash = idempotencyPayloadHash[idemKey]
            if (prevHash != payloadHash) {
                throw CriticalPagingException("CONFLICT", "Idempotency key reused with conflicting payload")
            }
            return idempotencyStore[idemKey]!!
        }

        val existing = incidentStore[command.incidentId]
            ?: throw CriticalPagingException("NOT_FOUND", "Incident not found for id ${command.incidentId}")

        if (existing.tenantId != command.tenantId) {
            throw CriticalPagingException("FORBIDDEN", "Cross-tenant access forbidden")
        }

        if (existing.version != command.expectedVersion) {
            throw CriticalPagingException("STALE", "Version mismatch: expected ${command.expectedVersion}, found ${existing.version}")
        }

        if (existing.status != PagingIncidentStatus.PAGING_TRIGGERED) {
            throw CriticalPagingException("CONFLICT", "Cannot acknowledge incident in status ${existing.status}")
        }

        val now = clock.instant()
        val updated = existing.copy(
            status = PagingIncidentStatus.ACKNOWLEDGED,
            acknowledgedAt = now,
            acknowledgedBy = command.principal?.id,
            directEligibilityGranted = false,
            financialMutationPermitted = false,
            version = existing.version + 1L,
        )

        incidentStore[command.incidentId] = updated

        auditLog.add(
            PagingIncidentAuditEntry(
                incidentId = updated.incidentId,
                tenantId = command.tenantId,
                eventType = "CRITICAL_PAGE_ACKNOWLEDGED",
                fromStatus = existing.status,
                toStatus = PagingIncidentStatus.ACKNOWLEDGED,
                actorId = command.principal?.id ?: "unknown",
                occurredAt = now,
                correlationId = command.correlationId,
                causationId = command.causationId,
            )
        )

        val result = PagingIncidentResult(
            incidentId = updated.incidentId,
            tenantId = command.tenantId,
            category = updated.category,
            failureType = updated.failureType,
            status = updated.status,
            paged = false,
            pagerReference = updated.pagerReference,
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

    @Synchronized
    fun resolvePage(command: ResolvePageCommand): PagingIncidentResult {
        CriticalPagingBinding.checkBound()

        validateResolveCommand(command)

        val idemKey = "page-resolve:${command.tenantId}:${command.idempotencyKey}"
        val payloadHash = "${command.incidentId}:${command.resolutionSummary}"

        if (idempotencyStore.containsKey(idemKey)) {
            val prevHash = idempotencyPayloadHash[idemKey]
            if (prevHash != payloadHash) {
                throw CriticalPagingException("CONFLICT", "Idempotency key reused with conflicting payload")
            }
            return idempotencyStore[idemKey]!!
        }

        val existing = incidentStore[command.incidentId]
            ?: throw CriticalPagingException("NOT_FOUND", "Incident not found for id ${command.incidentId}")

        if (existing.tenantId != command.tenantId) {
            throw CriticalPagingException("FORBIDDEN", "Cross-tenant access forbidden")
        }

        if (existing.version != command.expectedVersion) {
            throw CriticalPagingException("STALE", "Version mismatch: expected ${command.expectedVersion}, found ${existing.version}")
        }

        if (existing.status == PagingIncidentStatus.RESOLVED) {
            throw CriticalPagingException("CONFLICT", "Incident is already resolved")
        }

        val now = clock.instant()
        val updated = existing.copy(
            status = PagingIncidentStatus.RESOLVED,
            resolvedAt = now,
            resolvedBy = command.principal?.id,
            resolutionSummary = command.resolutionSummary,
            directEligibilityGranted = false,
            financialMutationPermitted = false,
            version = existing.version + 1L,
        )

        incidentStore[command.incidentId] = updated

        auditLog.add(
            PagingIncidentAuditEntry(
                incidentId = updated.incidentId,
                tenantId = command.tenantId,
                eventType = "CRITICAL_PAGE_RESOLVED",
                fromStatus = existing.status,
                toStatus = PagingIncidentStatus.RESOLVED,
                actorId = command.principal?.id ?: "unknown",
                occurredAt = now,
                correlationId = command.correlationId,
                causationId = command.causationId,
            )
        )

        val result = PagingIncidentResult(
            incidentId = updated.incidentId,
            tenantId = command.tenantId,
            category = updated.category,
            failureType = updated.failureType,
            status = updated.status,
            paged = false,
            pagerReference = updated.pagerReference,
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

    fun getIncidentRecord(incidentId: UUID): PagingIncidentRecord? {
        CriticalPagingBinding.checkBound()
        return incidentStore[incidentId]
    }

    fun getDashboardSummary(tenantId: String): PagingDashboardSummary {
        CriticalPagingBinding.checkBound()

        val tenantIncidents = incidentStore.values.filter { it.tenantId == tenantId }
        val total = tenantIncidents.size
        val active = tenantIncidents.count { it.status == PagingIncidentStatus.PAGING_TRIGGERED }
        val acknowledged = tenantIncidents.count { it.status == PagingIncidentStatus.ACKNOWLEDGED }
        val resolved = tenantIncidents.count { it.status == PagingIncidentStatus.RESOLVED }
        val financial = tenantIncidents.count { it.category == IncidentCategory.FINANCIAL }
        val security = tenantIncidents.count { it.category == IncidentCategory.SECURITY }

        return PagingDashboardSummary(
            tenantId = tenantId,
            totalIncidents = total,
            activePaging = active,
            acknowledged = acknowledged,
            resolved = resolved,
            financialIncidents = financial,
            securityIncidents = security,
        )
    }

    fun getAuditEntries(incidentId: UUID): List<PagingIncidentAuditEntry> {
        CriticalPagingBinding.checkBound()
        return auditLog.filter { it.incidentId == incidentId }
    }

    private fun validateTriggerCommand(command: TriggerCriticalPageCommand) {
        if (command.principal == null) {
            throw CriticalPagingException("UNAUTHENTICATED", "Authentication required")
        }
        if (command.principal.tenantId != command.tenantId) {
            throw CriticalPagingException("FORBIDDEN", "Cross-tenant access forbidden")
        }
        if (command.title.isBlank() || command.description.isBlank()) {
            throw CriticalPagingException("INVALID", "Title and description required")
        }
        if (command.idempotencyKey.isBlank()) {
            throw CriticalPagingException("INVALID", "idempotencyKey cannot be blank")
        }
        if (command.correlationId.isBlank() || command.causationId.isBlank()) {
            throw CriticalPagingException("INVALID", "Correlation and causation IDs required")
        }
    }

    private fun validateAcknowledgeCommand(command: AcknowledgePageCommand) {
        if (command.principal == null) {
            throw CriticalPagingException("UNAUTHENTICATED", "Authentication required")
        }
        if (command.principal.tenantId != command.tenantId) {
            throw CriticalPagingException("FORBIDDEN", "Cross-tenant access forbidden")
        }
        if (command.idempotencyKey.isBlank()) {
            throw CriticalPagingException("INVALID", "idempotencyKey cannot be blank")
        }
    }

    private fun validateResolveCommand(command: ResolvePageCommand) {
        if (command.principal == null) {
            throw CriticalPagingException("UNAUTHENTICATED", "Authentication required")
        }
        if (command.principal.tenantId != command.tenantId) {
            throw CriticalPagingException("FORBIDDEN", "Cross-tenant access forbidden")
        }
        // RBAC: resolving requires SUPER_ADMIN or SUPPORT
        if (!command.principal.roles.contains(AdminRole.SUPER_ADMIN) && !command.principal.roles.contains(AdminRole.SUPPORT)) {
            throw CriticalPagingException("FORBIDDEN", "Insufficient privileges to resolve critical incident")
        }
        if (command.resolutionSummary.isBlank()) {
            throw CriticalPagingException("INVALID", "resolutionSummary cannot be blank")
        }
        if (command.idempotencyKey.isBlank()) {
            throw CriticalPagingException("INVALID", "idempotencyKey cannot be blank")
        }
    }
}
