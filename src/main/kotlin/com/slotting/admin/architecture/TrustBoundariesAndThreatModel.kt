package com.slotting.admin.architecture

import com.slotting.admin.auth.AuditEvent
import com.slotting.admin.auth.AuthErrorCode
import com.slotting.admin.auth.AuthenticatedPrincipal
import com.slotting.admin.auth.AuthenticationFailure
import com.slotting.admin.auth.OutboxEvent
import com.slotting.admin.auth.PrincipalKind
import java.time.Clock
import java.time.Instant
import java.util.UUID
import java.util.concurrent.ConcurrentHashMap

/**
 * Traceability binding for ARCH-002: Trust boundaries and threat model.
 * Fail-closed assertion gate for RED/GREEN TDD verification.
 * Expected RED failure reason: "abuse cases demonstrate client authority".
 */
object TrustBoundariesBinding {
    @Volatile
    var isBound: Boolean = false

    fun checkBound() {
        if (!isBound) {
            throw AssertionError("abuse cases demonstrate client authority")
        }
    }
}

/**
 * The 4 core trust boundary domains governed by ARCH-002.
 * Contract: "Accept STRIDE/abuse review for money, callbacks, admin, Android; denied events observable."
 */
enum class TrustBoundaryDomain(val domainName: String) {
    MONEY("money"),
    CALLBACKS("callbacks"),
    ADMIN("admin"),
    ANDROID("android")
}

/**
 * Standard STRIDE threat classification categories.
 */
enum class StrideThreatCategory {
    SPOOFING,
    TAMPERING,
    REPUDIATION,
    INFORMATION_DISCLOSURE,
    DENIAL_OF_SERVICE,
    ELEVATION_OF_PRIVILEGE
}

/**
 * Evaluation record of a specific abuse test case.
 */
data class AbuseReviewCase(
    val caseId: String,
    val domain: TrustBoundaryDomain,
    val threatCategory: StrideThreatCategory,
    val abuseDescription: String,
    val isClientAuthorityClaimed: Boolean, // Must be blocked/denied
    val isDenied: Boolean,
    val isObservableInAudit: Boolean,
    val reasonCode: String,
    val evidenceArtifactRef: String,
    val passed: Boolean
)

/**
 * Threat model review and boundary status.
 */
enum class ThreatModelStatus {
    ACCEPTED,
    REJECTED
}

/**
 * Command to execute authoritative STRIDE/abuse threat model verification.
 */
data class ThreatModelReviewCommand(
    val principal: AuthenticatedPrincipal?,
    val sessionId: String,
    val tenantId: String,
    val idempotencyKey: String,
    val correlationId: String,
    val causationId: String,
    val expectedVersion: Long,
    val cases: List<AbuseReviewCase>
)

/**
 * Result of threat model review and trust boundary verification.
 */
data class ThreatModelReviewResult(
    val resultId: UUID,
    val status: ThreatModelStatus,
    val serverTime: Instant,
    val serverVersion: Long,
    val coveredDomains: Set<TrustBoundaryDomain>,
    val coveredThreatCategories: Set<StrideThreatCategory>,
    val deniedEventCount: Int,
    val evidenceReference: String,
    val auditEvent: AuditEvent,
    val outboxEvent: OutboxEvent
)

/**
 * Store interface for recording threat model audits and idempotency.
 */
interface ThreatModelStore {
    fun findByIdempotency(tenantId: String, key: String): Pair<ThreatModelReviewCommand, ThreatModelReviewResult>?
    fun save(
        tenantId: String,
        command: ThreatModelReviewCommand,
        result: ThreatModelReviewResult,
        deniedAuditEvents: List<AuditEvent>
    )
}

/**
 * In-memory test store for threat model evaluation.
 */
class InMemoryThreatModelStore : ThreatModelStore {
    val results = ConcurrentHashMap<String, Pair<ThreatModelReviewCommand, ThreatModelReviewResult>>()
    val audit = mutableListOf<AuditEvent>()
    val outbox = mutableListOf<OutboxEvent>()
    val deniedEvents = mutableListOf<AuditEvent>()

    override fun findByIdempotency(tenantId: String, key: String): Pair<ThreatModelReviewCommand, ThreatModelReviewResult>? {
        return results["$tenantId:$key"]
    }

    override fun save(
        tenantId: String,
        command: ThreatModelReviewCommand,
        result: ThreatModelReviewResult,
        deniedAuditEvents: List<AuditEvent>
    ) {
        results["$tenantId:${command.idempotencyKey}"] = Pair(command, result)
        audit.add(result.auditEvent)
        outbox.add(result.outboxEvent)
        deniedEvents.addAll(deniedAuditEvents)
    }
}

/**
 * Service enforcing trust boundaries and validating STRIDE threat models.
 */
class TrustBoundaryService(
    private val store: ThreatModelStore,
    private val clock: Clock = Clock.systemUTC()
) {
    fun review(command: ThreatModelReviewCommand): ThreatModelReviewResult = synchronized(store) {
        TrustBoundariesBinding.checkBound()

        // 1. Authentication check
        val principal = command.principal ?: throw AuthenticationFailure.Rejected(AuthErrorCode.UNAUTHENTICATED)
        if (principal.kind != PrincipalKind.ADMIN) {
            throw AuthenticationFailure.Rejected(AuthErrorCode.FORBIDDEN)
        }

        // 2. Authorization & Tenant check
        if (command.tenantId.isBlank() || command.tenantId != principal.tenantId) {
            throw AuthenticationFailure.Rejected(AuthErrorCode.FORBIDDEN)
        }

        // 3. Stale version check
        if (command.expectedVersion < 1L) {
            throw AuthenticationFailure.Rejected(AuthErrorCode.STALE)
        }

        // 4. Idempotency validation
        if (command.idempotencyKey.isBlank() || command.correlationId.isBlank() || command.causationId.isBlank()) {
            throw AuthenticationFailure.Rejected(AuthErrorCode.INVALID)
        }

        store.findByIdempotency(command.tenantId, command.idempotencyKey)?.let { (storedCommand, storedResult) ->
            if (storedCommand == command) {
                return storedResult
            } else {
                throw AuthenticationFailure.Rejected(AuthErrorCode.CONFLICT)
            }
        }

        // 5. Must have test cases
        if (command.cases.isEmpty()) {
            throw AuthenticationFailure.Rejected(AuthErrorCode.INVALID)
        }

        // 6. Verify full domain coverage (money, callbacks, admin, android)
        val representedDomains = command.cases.map { it.domain }.toSet()
        val missingDomains = TrustBoundaryDomain.entries.toSet() - representedDomains
        if (missingDomains.isNotEmpty()) {
            throw AuthenticationFailure.Rejected(AuthErrorCode.INVALID)
        }

        // 7. Verify all STRIDE threat categories are represented
        val representedThreats = command.cases.map { it.threatCategory }.toSet()
        val missingThreats = StrideThreatCategory.entries.toSet() - representedThreats
        if (missingThreats.isNotEmpty()) {
            throw AuthenticationFailure.Rejected(AuthErrorCode.INVALID)
        }

        // 8. Assert: No abuse case demonstrates client authority
        // If an abuse case claims client authority and was NOT denied, reject immediately
        val unmitigatedAbuse = command.cases.any { it.isClientAuthorityClaimed && !it.isDenied }
        if (unmitigatedAbuse) {
            throw AuthenticationFailure.Rejected(AuthErrorCode.INVALID)
        }

        // 9. Assert: Denied events observable
        val unobservableDenied = command.cases.any { it.isDenied && !it.isObservableInAudit }
        if (unobservableDenied) {
            throw AuthenticationFailure.Rejected(AuthErrorCode.INVALID)
        }

        val now = clock.instant()
        val resultId = UUID.randomUUID()

        // Generate observable audit events for each denied abuse attempt
        val deniedAuditEvents = command.cases.filter { it.isDenied }.map { case ->
            AuditEvent(
                eventId = UUID.randomUUID(),
                resultId = resultId,
                tenantId = command.tenantId,
                type = "STRIDE_ABUSE_DENIED_${case.domain.name}_${case.threatCategory.name}",
                occurredAt = now,
                correlationId = "${command.correlationId}:${case.caseId}",
                causationId = command.causationId
            )
        }

        val auditEvent = AuditEvent(
            eventId = UUID.randomUUID(),
            resultId = resultId,
            tenantId = command.tenantId,
            type = "STRIDE_THREAT_MODEL_ACCEPTED",
            occurredAt = now,
            correlationId = command.correlationId,
            causationId = command.causationId
        )

        val outboxEvent = OutboxEvent(
            eventId = UUID.randomUUID(),
            resultId = resultId,
            tenantId = command.tenantId,
            type = "STRIDE_THREAT_MODEL_ACCEPTED",
            createdAt = now
        )

        val result = ThreatModelReviewResult(
            resultId = resultId,
            status = ThreatModelStatus.ACCEPTED,
            serverTime = now,
            serverVersion = command.expectedVersion,
            coveredDomains = representedDomains,
            coveredThreatCategories = representedThreats,
            deniedEventCount = deniedAuditEvents.size,
            evidenceReference = "threat-model:${command.tenantId}:${resultId}",
            auditEvent = auditEvent,
            outboxEvent = outboxEvent
        )

        store.save(command.tenantId, command, result, deniedAuditEvents)
        return result
    }
}
