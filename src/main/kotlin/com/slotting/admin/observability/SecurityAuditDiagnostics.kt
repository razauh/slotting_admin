package com.slotting.admin.observability

import com.slotting.admin.auth.AuditEvent
import org.slf4j.LoggerFactory
import java.time.Clock
import java.util.UUID

enum class SecurityAuditOutcome {
    SUCCEEDED,
    FAILED,
    DENIED,
    EXPIRED,
    REVOKED,
}

data class SecurityAuditFacts(
    val eventType: String,
    val outcome: SecurityAuditOutcome,
    val actorType: String,
    val tenantId: String,
    val actorId: String?,
    val opaqueSessionId: String?,
    val correlationId: String,
    val causationId: String? = null,
    val safeMetadata: Map<String, String> = emptyMap(),
) {
    init {
        require(eventType.isNotBlank()) { "eventType must not be blank" }
        require(tenantId.isNotBlank()) { "tenantId must not be blank" }
        require(correlationId.isNotBlank()) { "correlationId must not be blank" }
        require(safeMetadata.keys.all { it in ALLOWED_METADATA_KEYS }) {
            "Security audit metadata key outside the explicit allowlist"
        }
        require(safeMetadata.values.all { it.length <= 256 }) {
            "Security audit metadata value exceeds the safe bound"
        }
    }

    companion object {
        val ALLOWED_METADATA_KEYS = setOf(
            "reasonCode",
            "requestedRole",
            "approverId",
            "targetActorId",
            "result",
            "action",
        )
    }
}

interface SecurityAuditDiagnosticProjector {
    fun project(facts: SecurityAuditFacts): DiagnosticEventEnvelope?
}

object NoOpSecurityAuditDiagnosticProjector : SecurityAuditDiagnosticProjector {
    override fun project(facts: SecurityAuditFacts): DiagnosticEventEnvelope? = null
}

class JdbcSecurityAuditDiagnosticProjector(
    private val diagnosticStore: JdbcDiagnosticEventStore,
    private val clock: Clock = Clock.systemUTC(),
) : SecurityAuditDiagnosticProjector {
    private val logger = LoggerFactory.getLogger(javaClass)

    override fun project(facts: SecurityAuditFacts): DiagnosticEventEnvelope? = try {
        val envelope = SecurityAuditProjections.envelope(facts, clock.instant())
        diagnosticStore.save(facts.tenantId, envelope)
        envelope
    } catch (conflict: DiagnosticEventConflictException) {
        logger.info("security_audit_deduplicated eventType={} correlationId={}", facts.eventType, facts.correlationId)
        null
    } catch (failure: Exception) {
        logger.warn(
            "security_audit_projection_failed eventType={} failureType={}",
            facts.eventType,
            failure::class.simpleName ?: "UNKNOWN",
        )
        null
    }
}

object SecurityAuditProjections {
    fun envelope(facts: SecurityAuditFacts, serverReceivedAt: java.time.Instant): DiagnosticEventEnvelope {
        val identity = listOfNotNull(
            facts.tenantId,
            facts.eventType,
            facts.outcome.name,
            facts.actorId,
            facts.opaqueSessionId,
            facts.correlationId,
        ).joinToString("|")
        val severity = when (facts.outcome) {
            SecurityAuditOutcome.SUCCEEDED -> DiagnosticEventSeverity.INFO
            SecurityAuditOutcome.FAILED, SecurityAuditOutcome.DENIED -> DiagnosticEventSeverity.WARN
            SecurityAuditOutcome.EXPIRED, SecurityAuditOutcome.REVOKED -> DiagnosticEventSeverity.WARN
        }
        return DiagnosticEventEnvelope(
            schemaVersion = DiagnosticEnvelopeParser.CURRENT_SCHEMA_VERSION,
            eventId = UUID.nameUUIDFromBytes(identity.toByteArray(Charsets.UTF_8)),
            occurredAt = serverReceivedAt,
            serverReceivedAt = serverReceivedAt,
            eventType = facts.eventType,
            severity = severity,
            sourceApp = "slotting_admin",
            component = "security",
            environment = "server",
            requestId = null,
            correlationId = facts.correlationId,
            causationId = facts.causationId,
            userId = if (facts.actorType == "PLAYER") facts.actorId else null,
            adminId = if (facts.actorType == "ADMIN") facts.actorId else null,
            sessionId = facts.opaqueSessionId,
            roundId = null,
            betId = null,
            paymentId = null,
            ledgerId = null,
            amountMinorUnits = null,
            currency = null,
            message = facts.eventType,
            context = facts.safeMetadata + mapOf("actorType" to facts.actorType),
            stackFrames = emptyList(),
        )
    }

    fun fromAuditEvent(
        audit: AuditEvent,
        outcome: SecurityAuditOutcome,
        actorType: String,
        actorId: String?,
        opaqueSessionId: String? = null,
        safeMetadata: Map<String, String> = emptyMap(),
    ): SecurityAuditFacts = SecurityAuditFacts(
        eventType = audit.type,
        outcome = outcome,
        actorType = actorType,
        tenantId = audit.tenantId,
        actorId = actorId,
        opaqueSessionId = opaqueSessionId,
        correlationId = audit.correlationId,
        causationId = audit.causationId,
        safeMetadata = safeMetadata,
    )
}
