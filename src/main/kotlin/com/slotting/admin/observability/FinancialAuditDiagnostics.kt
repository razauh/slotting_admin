package com.slotting.admin.observability

import org.slf4j.LoggerFactory
import org.springframework.stereotype.Component
import java.nio.charset.StandardCharsets
import java.time.Clock
import java.util.UUID

enum class FinancialAuditOutcome {
    INITIATED,
    PENDING,
    CONFIRMED,
    FAILED,
    REPLAYED,
    MISMATCH,
}

data class FinancialAuditEvent(
    val tenantId: String,
    val eventType: String,
    val outcome: FinancialAuditOutcome,
    val correlationId: String,
    val paymentId: String? = null,
    val operationId: String? = null,
    val providerReference: String? = null,
    val ledgerReference: String? = null,
    val amountMinorUnits: Long? = null,
    val currency: String? = null,
    val safeDetail: String? = null,
    val severity: DiagnosticEventSeverity = DiagnosticEventSeverity.INFO,
)

interface FinancialAuditProjector {
    fun project(event: FinancialAuditEvent): DiagnosticEventEnvelope?
}

object NoOpFinancialAuditProjector : FinancialAuditProjector {
    override fun project(event: FinancialAuditEvent): DiagnosticEventEnvelope? = null
}

@Component
class JdbcFinancialAuditProjector(
    private val diagnosticStore: JdbcDiagnosticEventStore,
    private val clock: Clock = Clock.systemUTC(),
) : FinancialAuditProjector {
    private val logger = LoggerFactory.getLogger(javaClass)

    override fun project(event: FinancialAuditEvent): DiagnosticEventEnvelope? {
        val identity = listOfNotNull(
            event.tenantId,
            event.eventType,
            event.outcome.name,
            event.paymentId,
            event.operationId,
            event.ledgerReference,
        ).joinToString("|")
        return try {
            val envelope = DiagnosticEventEnvelope(
                schemaVersion = DiagnosticEnvelopeParser.CURRENT_SCHEMA_VERSION,
                eventId = UUID.nameUUIDFromBytes(identity.toByteArray(StandardCharsets.UTF_8)),
                occurredAt = clock.instant(),
                serverReceivedAt = clock.instant(),
                eventType = event.eventType,
                severity = event.severity,
                sourceApp = "slotting_admin",
                component = "financial-audit",
                environment = "server",
                requestId = event.operationId,
                correlationId = event.correlationId,
                causationId = event.operationId,
                userId = null,
                adminId = null,
                sessionId = null,
                roundId = null,
                betId = null,
                paymentId = event.paymentId,
                ledgerId = event.ledgerReference,
                amountMinorUnits = event.amountMinorUnits,
                currency = event.currency,
                message = event.safeDetail,
                context = mapOf("action" to event.outcome.name),
                stackFrames = emptyList(),
            )
            diagnosticStore.save(event.tenantId, envelope)
            envelope
        } catch (conflict: DiagnosticEventConflictException) {
            logger.info("financial_audit_deduplicated eventType={} paymentId={}", event.eventType, event.paymentId)
            null
        } catch (failure: Exception) {
            logger.warn(
                "financial_audit_projection_failed eventType={} failureType={}",
                event.eventType,
                failure::class.simpleName ?: "UNKNOWN",
            )
            null
        }
    }
}
