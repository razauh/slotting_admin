package com.slotting.admin.observability

import com.slotting.admin.auth.AdminPermission
import com.slotting.admin.auth.AdminRbacPolicy
import com.slotting.admin.auth.AdminSessionDirectory
import com.slotting.admin.auth.AuthErrorCode
import com.slotting.admin.auth.AuthenticatedPrincipal
import com.slotting.admin.auth.AuthenticationFailure
import com.slotting.admin.auth.PrincipalKind
import org.springframework.jdbc.core.JdbcTemplate
import org.springframework.stereotype.Service
import java.sql.Timestamp
import java.time.Clock
import java.time.Instant
import java.util.Base64
import java.util.UUID

data class DiagnosticSearchFilters(
    val from: Instant,
    val to: Instant,
    val severity: String? = null,
    val eventType: String? = null,
    val userId: String? = null,
    val correlationId: String? = null,
    val roundId: String? = null,
    val betId: String? = null,
    val paymentId: String? = null,
) {
    companion object {
        val SEVERITIES = DiagnosticEventSeverity.values().map { it.name }.toSet()
        val TEXT_FIELD_MAX = 256
    }

    init {
        require(!from.isAfter(to)) { "Search range must be chronological" }
        require(from.toEpochMilli() >= 0L) { "Search range must not be negative" }
        require(severity == null || severity.uppercase() in SEVERITIES) { "Unsupported severity filter" }
        fun bound(value: String?) = value == null || value.length <= TEXT_FIELD_MAX
        require(bound(eventType) && bound(userId) && bound(correlationId) && bound(roundId) && bound(betId) && bound(paymentId)) {
            "Filter values exceed the safe length bound"
        }
    }
}

data class DiagnosticSearchEntry(
    val eventId: UUID,
    val occurredAt: Instant,
    val eventType: String,
    val severity: String,
    val correlationId: String?,
    val roundId: String?,
    val betId: String?,
    val paymentId: String?,
    val deliveryState: String,
    val cursor: String,
)

data class DiagnosticSearchResult(
    val tenantId: String,
    val entries: List<DiagnosticSearchEntry>,
    val nextCursor: String?,
    val resultCompleteness: String,
    val serverTime: Instant,
)

data class DiagnosticEventDetail(
    val tenantId: String,
    val eventId: UUID,
    val eventType: String,
    val severity: String,
    val occurredAt: Instant,
    val correlationId: String?,
    val roundId: String?,
    val betId: String?,
    val paymentId: String?,
    val amountMinorUnits: Long?,
    val currency: String?,
    val message: String?,
    val context: Map<String, String>,
    val deliveryState: String,
    val relatedEvents: List<DiagnosticSearchEntry>,
    val missingLifecycleStages: List<String>,
)

class DiagnosticsDependencyUnavailableException(message: String) : IllegalStateException(message)

@Service
class AdminDiagnosticsQueryService(
    private val jdbc: JdbcTemplate,
    private val sessions: AdminSessionDirectory,
    private val policy: AdminRbacPolicy = AdminRbacPolicy(dualControlRequired = false),
    private val clock: Clock = Clock.systemUTC(),
) {
    fun search(
        principal: AuthenticatedPrincipal?,
        tenantId: String,
        sessionId: String?,
        filters: DiagnosticSearchFilters,
        cursor: String?,
        limit: Int,
    ): DiagnosticSearchResult {
        authorize(principal, tenantId, sessionId)
        require(limit in 1..200) { "Search limit must be between 1 and 200" }

        val cursorPosition = cursor?.let { decodeCursor(it) }
        val effectiveLimit = limit + 1
        val clauses = mutableListOf("tenant_id = ?", "occurred_at >= ?", "occurred_at <= ?")
        val args = mutableListOf<Any>(tenantId, Timestamp.from(filters.from), Timestamp.from(filters.to))
        filters.severity?.let { clauses += "severity = ?"; args += it.uppercase() }
        filters.eventType?.let { clauses += "event_type = ?"; args += it }
        filters.correlationId?.let { clauses += "correlation_id = ?"; args += it }
        filters.roundId?.let { clauses += "payload_json->>'roundId' = ?"; args += it }
        filters.betId?.let { clauses += "payload_json->>'betId' = ?"; args += it }
        filters.paymentId?.let { clauses += "payload_json->>'paymentId' = ?"; args += it }
        filters.userId?.let { clauses += "(payload_json->>'userId' = ? or payload_json->>'adminId' = ?)"; args += it; args += it }
        if (cursorPosition != null) {
            clauses += "(occurred_at < ? or (occurred_at = ? and event_id > ?))"
            args += Timestamp.from(cursorPosition.first)
            args += Timestamp.from(cursorPosition.first)
            args += cursorPosition.second
        }
        val rows = jdbc.query(
            """
            select event_id, occurred_at, event_type, severity, correlation_id,
                   payload_json->>'roundId' as round_id,
                   payload_json->>'betId' as bet_id,
                   payload_json->>'paymentId' as payment_id,
                   delivery_state
            from diagnostic_event
            where ${clauses.joinToString(" and ")}
            order by occurred_at desc, event_id asc
            limit $effectiveLimit
            """.trimIndent(),
            { rs, _ ->
                DiagnosticSearchEntry(
                    eventId = rs.getObject("event_id", UUID::class.java),
                    occurredAt = rs.getTimestamp("occurred_at").toInstant(),
                    eventType = rs.getString("event_type"),
                    severity = rs.getString("severity"),
                    correlationId = rs.getString("correlation_id"),
                    roundId = rs.getString("round_id"),
                    betId = rs.getString("bet_id"),
                    paymentId = rs.getString("payment_id"),
                    deliveryState = rs.getString("delivery_state"),
                    cursor = encodeCursor(rs.getTimestamp("occurred_at").toInstant(), rs.getObject("event_id", UUID::class.java)),
                )
            },
            *args.toTypedArray(),
        )
        val hasMore = rows.size > limit
        val page = rows.take(limit)
        return DiagnosticSearchResult(
            tenantId = tenantId,
            entries = page,
            nextCursor = if (hasMore) page.lastOrNull()?.cursor else null,
            resultCompleteness = "COMPLETE",
            serverTime = clock.instant(),
        )
    }

    fun detail(
        principal: AuthenticatedPrincipal?,
        tenantId: String,
        sessionId: String?,
        eventId: UUID,
    ): DiagnosticEventDetail {
        authorize(principal, tenantId, sessionId)
        val rows = jdbc.query(
            """
            select occurred_at, event_type, severity, correlation_id, delivery_state, payload_json
            from diagnostic_event
            where tenant_id = ? and event_id = ?
            """.trimIndent(),
            { rs, _ ->
                DetailRow(
                    occurredAt = rs.getTimestamp("occurred_at").toInstant(),
                    eventType = rs.getString("event_type"),
                    severity = rs.getString("severity"),
                    correlationId = rs.getString("correlation_id"),
                    deliveryState = rs.getString("delivery_state"),
                    payload = rs.getString("payload_json"),
                )
            },
            tenantId,
            eventId,
        )
        val row = rows.firstOrNull() ?: throw DiagnosticEventNotFoundException()

        fun field(name: String): String? {
            val matcher = Regex(""""$name":\s*"([^"]*)"""").find(row.payload) ?: return null
            return matcher.groupValues.takeIf { it[1].isNotBlank() }?.let { it[1] }
        }
        val roundId = field("roundId")
        val betId = field("betId")
        val paymentId = field("paymentId")

        val relatedConditions = mutableListOf<String>()
        val relatedArgs = mutableListOf<Any>(tenantId)
        if (roundId != null) {
            relatedConditions += "payload_json->>'roundId' = ?"
            relatedArgs += roundId
        }
        if (betId != null) {
            relatedConditions += "payload_json->>'betId' = ?"
            relatedArgs += betId
        }
        if (paymentId != null) {
            relatedConditions += "payload_json->>'paymentId' = ?"
            relatedArgs += paymentId
        }
        val related = if (relatedConditions.isEmpty()) {
            emptyList()
        } else {
            jdbc.query(
                """
                select event_id, occurred_at, event_type, severity, correlation_id,
                       payload_json->>'roundId' as round_id,
                       payload_json->>'betId' as bet_id,
                       payload_json->>'paymentId' as payment_id,
                       delivery_state
                from diagnostic_event
                where tenant_id = ? and (${relatedConditions.joinToString(" or ")}) and event_id <> ?
                order by occurred_at, event_id
                """.trimIndent(),
                { rs, _ ->
                    DiagnosticSearchEntry(
                        eventId = rs.getObject("event_id", UUID::class.java),
                        occurredAt = rs.getTimestamp("occurred_at").toInstant(),
                        eventType = rs.getString("event_type"),
                        severity = rs.getString("severity"),
                        correlationId = rs.getString("correlation_id"),
                        roundId = rs.getString("round_id"),
                        betId = rs.getString("bet_id"),
                        paymentId = rs.getString("payment_id"),
                        deliveryState = rs.getString("delivery_state"),
                        cursor = encodeCursor(rs.getTimestamp("occurred_at").toInstant(), rs.getObject("event_id", UUID::class.java)),
                    )
                },
                *relatedArgs.toTypedArray(),
                eventId,
            )
        }

        val presentTypes = related.map { it.eventType }.toSet()
        val expectedStages = buildList {
            if (betId != null) {
                add("GAME_BET_ACCEPTED")
                add("GAME_CASH_OUT_ACCEPTED")
                add("GAME_BET_SETTLED_CRASH")
            }
            if (paymentId != null) {
                add("DEPOSIT_INITIATED")
                add("DEPOSIT_CREDITED")
            }
        }
        val missing = expectedStages.filter { it !in presentTypes }

        return DiagnosticEventDetail(
            tenantId = tenantId,
            eventId = eventId,
            eventType = row.eventType,
            severity = row.severity,
            occurredAt = row.occurredAt,
            correlationId = row.correlationId,
            roundId = roundId,
            betId = betId,
            paymentId = paymentId,
            amountMinorUnits = field("amountMinorUnits")?.toLongOrNull(),
            currency = field("currency"),
            message = field("message"),
            context = Regex(""""([^"]+)":\s*"([^"]*)"""").findAll(field("context") ?: "{}")
                .associate { it.groupValues[1] to it.groupValues[2] },
            deliveryState = row.deliveryState,
            relatedEvents = related,
            missingLifecycleStages = missing,
        )
    }

    private data class DetailRow(
        val occurredAt: Instant,
        val eventType: String,
        val severity: String,
        val correlationId: String?,
        val deliveryState: String,
        val payload: String,
    )

    private fun authorize(principal: AuthenticatedPrincipal?, tenantId: String, sessionId: String?) {
        val authenticated = principal ?: throw AuthenticationFailure.Rejected(AuthErrorCode.UNAUTHENTICATED)
        if (authenticated.kind != PrincipalKind.ADMIN || authenticated.tenantId != tenantId) {
            throw AuthenticationFailure.Rejected(AuthErrorCode.FORBIDDEN)
        }
        val session = try {
            if (sessionId.isNullOrBlank()) null else sessions.find(tenantId, authenticated.id, sessionId)
        } catch (failure: Exception) {
            throw DiagnosticsDependencyUnavailableException("Diagnostics session lookup is unavailable")
        }
        if (sessionId.isNullOrBlank() || session == null || !session.active || !session.expiresAt.isAfter(clock.instant()) || !session.mfaVerified) {
            throw AuthenticationFailure.Rejected(AuthErrorCode.FORBIDDEN)
        }
        if (!policy.isPermitted(authenticated, AdminPermission.READ_AUDIT)) {
            throw AuthenticationFailure.Rejected(AuthErrorCode.FORBIDDEN)
        }
    }

    private fun encodeCursor(occurredAt: Instant, eventId: UUID): String =
        Base64.getUrlEncoder().encodeToString("$occurredAt|$eventId".toByteArray(Charsets.UTF_8))

    private fun decodeCursor(cursor: String): Pair<Instant, UUID> = runCatching {
        val decoded = String(Base64.getUrlDecoder().decode(cursor), Charsets.UTF_8)
        val parts = decoded.split('|')
        Pair(Instant.parse(parts[0]), UUID.fromString(parts[1]))
    }.getOrElse { throw IllegalArgumentException("Malformed diagnostics cursor") }
}

class DiagnosticEventNotFoundException : RuntimeException("Diagnostic event not found for tenant")
