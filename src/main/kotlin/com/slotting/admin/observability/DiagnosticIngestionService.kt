package com.slotting.admin.observability

import com.fasterxml.jackson.databind.JsonNode
import com.slotting.admin.auth.AdminRole
import com.slotting.admin.auth.AuthErrorCode
import com.slotting.admin.auth.AuthenticatedPrincipal
import com.slotting.admin.auth.AuthenticationFailure
import com.slotting.admin.auth.PrincipalKind
import org.springframework.stereotype.Service
import java.time.Clock
import java.time.Duration
import java.time.Instant
import java.util.concurrent.ConcurrentHashMap

enum class DiagnosticIngestionOutcome {
    ACCEPTED,
    DUPLICATE,
    REJECTED,
}

data class DiagnosticIngestionItemResult(
    val eventId: String?,
    val outcome: DiagnosticIngestionOutcome,
    val rejectionCode: String? = null,
    val safeReason: String? = null,
)

data class DiagnosticBatchIngestionResult(
    val tenantId: String,
    val receivedCount: Int,
    val acceptedCount: Int,
    val duplicateCount: Int,
    val rejectedCount: Int,
    val items: List<DiagnosticIngestionItemResult>,
)

class DiagnosticRateLimitExceededException(message: String) : IllegalStateException(message)

@Service
class DiagnosticIngestionService(
    private val store: DiagnosticEventStore,
    private val clock: Clock = Clock.systemUTC(),
    private val maxBatchSize: Int = 50,
    private val maxTotalPayloadCharacters: Int = 128_000,
    private val maxBatchesPerWindow: Int = 10,
    private val window: Duration = Duration.ofMinutes(1),
) {
    private data class WindowCounter(val windowStart: Instant, var count: Int)

    private val windows = ConcurrentHashMap<String, WindowCounter>()

    fun ingest(
        principal: AuthenticatedPrincipal?,
        tenantId: String,
        rawItems: List<JsonNode>,
    ): DiagnosticBatchIngestionResult {
        val authenticated = principal ?: throw AuthenticationFailure.Rejected(AuthErrorCode.UNAUTHENTICATED)
        if (authenticated.kind != PrincipalKind.PLAYER && authenticated.kind != PrincipalKind.ADMIN) {
            throw AuthenticationFailure.Rejected(AuthErrorCode.FORBIDDEN)
        }
        if (authenticated.tenantId != tenantId) {
            throw AuthenticationFailure.Rejected(AuthErrorCode.FORBIDDEN)
        }
        if (rawItems.size > maxBatchSize) {
            throw IllegalArgumentException("Diagnostic batch exceeds the maximum size of $maxBatchSize")
        }
        val totalCharacters = rawItems.sumOf { it.toString().length }
        if (totalCharacters > maxTotalPayloadCharacters) {
            throw IllegalArgumentException("Diagnostic batch exceeds the maximum payload size")
        }
        enforceRateLimit(tenantId, authenticated.id)

        val isAdmin = authenticated.kind == PrincipalKind.ADMIN && authenticated.roles.any {
            it in setOf(AdminRole.SUPER_ADMIN, AdminRole.SECURITY, AdminRole.AUDITOR)
        }
        val results = rawItems.map { item ->
            try {
                val envelope = DiagnosticEnvelopeParser.parse(
                    rawJson = item.toString(),
                    serverActorId = authenticated.id,
                    serverTenantId = authenticated.tenantId,
                    serverActorIsAdmin = isAdmin,
                    clock = clock,
                )
                val existing = store.find(tenantId, envelope.eventId)
                val stored = store.save(tenantId, envelope)
                DiagnosticIngestionItemResult(
                    eventId = stored.eventId.toString(),
                    outcome = if (existing == null) DiagnosticIngestionOutcome.ACCEPTED else DiagnosticIngestionOutcome.DUPLICATE,
                )
            } catch (rejection: DiagnosticEnvelopeRejection) {
                DiagnosticIngestionItemResult(
                    eventId = runCatching { item.get("eventId")?.asText() }.getOrNull(),
                    outcome = DiagnosticIngestionOutcome.REJECTED,
                    rejectionCode = rejection.code.name,
                    safeReason = rejection.message?.take(256),
                )
            } catch (conflict: DiagnosticEventConflictException) {
                DiagnosticIngestionItemResult(
                    eventId = runCatching { item.get("eventId")?.asText() }.getOrNull(),
                    outcome = DiagnosticIngestionOutcome.REJECTED,
                    rejectionCode = "CONFLICT",
                    safeReason = "Diagnostic event identity was reused with a conflicting payload",
                )
            }
        }
        return DiagnosticBatchIngestionResult(
            tenantId = tenantId,
            receivedCount = rawItems.size,
            acceptedCount = results.count { it.outcome == DiagnosticIngestionOutcome.ACCEPTED },
            duplicateCount = results.count { it.outcome == DiagnosticIngestionOutcome.DUPLICATE },
            rejectedCount = results.count { it.outcome == DiagnosticIngestionOutcome.REJECTED },
            items = results,
        )
    }

    private fun enforceRateLimit(tenantId: String, actorId: String) {
        val key = "$tenantId:$actorId"
        val now = clock.instant()
        val counter = windows.compute(key) { _, existing ->
            if (existing == null || Duration.between(existing.windowStart, now) >= window) {
                WindowCounter(now, 1)
            } else {
                existing.count += 1
                existing
            }
        } ?: WindowCounter(now, 1)
        if (counter.count > maxBatchesPerWindow) {
            throw DiagnosticRateLimitExceededException("Diagnostic upload rate limit exceeded")
        }
        if (windows.size > 10_000) {
            windows.entries.removeIf { Duration.between(it.value.windowStart, now) >= window }
        }
    }
}
