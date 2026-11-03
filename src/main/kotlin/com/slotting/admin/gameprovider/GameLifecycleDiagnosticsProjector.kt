package com.slotting.admin.gameprovider

import com.slotting.admin.observability.DiagnosticEnvelopeParser
import com.slotting.admin.observability.DiagnosticEventStore
import com.slotting.admin.observability.DiagnosticEventConflictException
import com.slotting.admin.observability.DiagnosticEventEnvelope
import com.slotting.admin.observability.DiagnosticEventSeverity
import com.slotting.admin.observability.JdbcDiagnosticEventStore
import org.slf4j.LoggerFactory
import org.springframework.stereotype.Component
import java.nio.charset.StandardCharsets
import java.time.Clock
import java.util.UUID

enum class GameLifecycleOutcome {
    REQUESTED,
    ACCEPTED,
    REJECTED,
    REPLAYED,
    SETTLED,
    FAILED,
}

data class GameLifecycleDiagnosticEvent(
    val tenantId: String,
    val eventType: String,
    val outcome: GameLifecycleOutcome,
    val correlationId: String,
    val roundId: String? = null,
    val betId: String? = null,
    val commandId: String? = null,
    val causationId: String? = null,
    val authoritativeVersion: Long? = null,
    val ledgerReference: String? = null,
    val amountMinorUnits: Long? = null,
    val currency: String? = null,
    val safeReason: String? = null,
    val severity: DiagnosticEventSeverity = DiagnosticEventSeverity.INFO,
)

interface GameLifecycleDiagnosticProjector {
    fun project(event: GameLifecycleDiagnosticEvent)
}

object NoOpGameLifecycleDiagnosticProjector : GameLifecycleDiagnosticProjector {
    override fun project(event: GameLifecycleDiagnosticEvent) {}
}

@Component
class JdbcGameLifecycleDiagnosticProjector(
    private val diagnosticStore: DiagnosticEventStore,
    private val clock: Clock = Clock.systemUTC(),
) : GameLifecycleDiagnosticProjector {
    private val logger = LoggerFactory.getLogger(javaClass)

    override fun project(event: GameLifecycleDiagnosticEvent) {
        val identity = listOfNotNull(
            event.tenantId,
            event.eventType,
            event.outcome.name,
            event.roundId,
            event.betId,
            event.commandId,
            event.authoritativeVersion?.toString(),
        ).joinToString("|")
        val envelope = DiagnosticEventEnvelope(
            schemaVersion = DiagnosticEnvelopeParser.CURRENT_SCHEMA_VERSION,
            eventId = UUID.nameUUIDFromBytes(identity.toByteArray(StandardCharsets.UTF_8)),
            occurredAt = clock.instant(),
            serverReceivedAt = clock.instant(),
            eventType = event.eventType,
            severity = event.severity,
            sourceApp = "slotting_admin",
            component = "gameprovider",
            environment = "server",
            requestId = event.commandId,
            correlationId = event.correlationId,
            causationId = event.causationId,
            userId = null,
            adminId = null,
            sessionId = null,
            roundId = event.roundId,
            betId = event.betId,
            paymentId = null,
            ledgerId = event.ledgerReference,
            amountMinorUnits = event.amountMinorUnits,
            currency = event.currency,
            message = event.safeReason,
            context = mapOf("action" to event.outcome.name),
            stackFrames = emptyList(),
        )
        try {
            diagnosticStore.save(event.tenantId, envelope)
        } catch (conflict: DiagnosticEventConflictException) {
            logger.info(
                "lifecycle_diagnostic_deduplicated eventType={} commandId={}",
                event.eventType,
                event.commandId,
            )
        } catch (failure: Exception) {
            logger.warn(
                "lifecycle_diagnostic_projection_failed eventType={} failureType={}",
                event.eventType,
                failure::class.simpleName ?: "UNKNOWN",
            )
        }
    }
}
