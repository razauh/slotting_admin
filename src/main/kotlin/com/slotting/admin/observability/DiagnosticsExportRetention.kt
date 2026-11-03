package com.slotting.admin.observability

import com.slotting.admin.audit.JdbcAdminAuditStore
import com.slotting.admin.auth.AdminPermission
import com.slotting.admin.auth.AdminRbacPolicy
import com.slotting.admin.auth.AdminSessionDirectory
import com.slotting.admin.auth.AuthErrorCode
import com.slotting.admin.auth.AuthenticatedPrincipal
import com.slotting.admin.auth.AuthenticationFailure
import com.slotting.admin.auth.PrincipalKind
import org.springframework.jdbc.core.JdbcTemplate
import org.springframework.stereotype.Service
import java.nio.charset.StandardCharsets
import java.security.MessageDigest
import java.sql.Timestamp
import java.time.Clock
import java.time.Instant
import java.util.Base64
import java.util.UUID

data class DiagnosticsExportBatch(
    val tenantId: String,
    val schema: String,
    val filters: DiagnosticSearchFilters,
    val lines: List<String>,
    val lineCount: Int,
    val checksumSha256: String,
    val previousChecksumSha256: String?,
    val cumulativeLineCount: Long,
    val totalMatchingCount: Long,
    val rangeFrom: Instant?,
    val rangeTo: Instant?,
    val continuationCursor: String?,
    val complete: Boolean,
    val serverTime: Instant,
)

@Service
class DiagnosticsExportService(
    private val jdbc: JdbcTemplate,
    private val sessions: AdminSessionDirectory,
    private val policy: AdminRbacPolicy = AdminRbacPolicy(dualControlRequired = false),
    private val clock: Clock = Clock.systemUTC(),
    private val maxLinesPerBatch: Int = 1000,
) {
    fun export(
        principal: AuthenticatedPrincipal?,
        tenantId: String,
        sessionId: String?,
        filters: DiagnosticSearchFilters,
        cursor: String?,
        previousChecksumSha256: String? = null,
        previousCumulativeLineCount: Long = 0L,
    ): DiagnosticsExportBatch {
        authorize(principal, tenantId, sessionId)
        val cursorPosition = cursor?.let { decodeCursor(it) }
        if (cursor != null && previousChecksumSha256 == null) {
            throw IllegalArgumentException("Continued export batches require the previous page checksum")
        }

        val baseClauses = mutableListOf("tenant_id = ?", "occurred_at >= ?", "occurred_at <= ?")
        val baseArgs = mutableListOf<Any>(tenantId, Timestamp.from(filters.from), Timestamp.from(filters.to))
        filters.severity?.let { baseClauses += "severity = ?"; baseArgs += it.uppercase() }
        filters.eventType?.let { baseClauses += "event_type = ?"; baseArgs += it }
        filters.correlationId?.let { baseClauses += "correlation_id = ?"; baseArgs += it }
        filters.roundId?.let { baseClauses += "payload_json->>'roundId' = ?"; baseArgs += it }
        filters.betId?.let { baseClauses += "payload_json->>'betId' = ?"; baseArgs += it }
        filters.paymentId?.let { baseClauses += "payload_json->>'paymentId' = ?"; baseArgs += it }
        filters.userId?.let { baseClauses += "(payload_json->>'userId' = ? or payload_json->>'adminId' = ?)"; baseArgs += it; baseArgs += it }

        val clauses = baseClauses.toMutableList()
        val args = baseArgs.toMutableList()
        if (cursorPosition != null) {
            clauses += "(occurred_at < ? or (occurred_at = ? and event_id > ?))"
            args += Timestamp.from(cursorPosition.first)
            args += Timestamp.from(cursorPosition.first)
            args += cursorPosition.second
        }
        val rows = jdbc.query(
            """
            select event_id, occurred_at, payload_json::text as payload
            from diagnostic_event
            where ${clauses.joinToString(" and ")}
            order by occurred_at desc, event_id asc
            limit ${maxLinesPerBatch + 1}
            """.trimIndent(),
            { rs, _ ->
                Triple(
                    rs.getObject("event_id", UUID::class.java),
                    rs.getTimestamp("occurred_at").toInstant(),
                    rs.getString("payload"),
                )
            },
            *args.toTypedArray(),
        )

        val hasMore = rows.size > maxLinesPerBatch
        val page = rows.take(maxLinesPerBatch)
        val lines = page.map { (_, _, payload) -> redactExportLine(payload) }
        val chainedChecksum = sha256(
            (previousChecksumSha256?.let { "$it\n" } ?: "") + lines.joinToString("\n"),
        )
        val totalMatching = jdbc.queryForObject(
            "select count(*) from diagnostic_event where ${baseClauses.joinToString(" and ")}",
            Long::class.java,
            *baseArgs.toTypedArray(),
        ) ?: 0L
        recordExportAudit(tenantId, filters, lines.size, hasMore)

        return DiagnosticsExportBatch(
            tenantId = tenantId,
            schema = "slotting.diagnostics.export.v1",
            filters = filters,
            lines = lines,
            lineCount = lines.size,
            checksumSha256 = chainedChecksum,
            previousChecksumSha256 = previousChecksumSha256,
            cumulativeLineCount = previousCumulativeLineCount + lines.size,
            totalMatchingCount = totalMatching,
            rangeFrom = page.lastOrNull()?.second,
            rangeTo = page.firstOrNull()?.second,
            continuationCursor = page.lastOrNull()?.let { (eventId, occurredAt, _) -> encodeCursor(occurredAt, eventId) }
                ?.takeIf { hasMore },
            complete = !hasMore,
            serverTime = clock.instant(),
        )
    }

    private val secretFieldName = Regex(
        "(?i)\"([A-Za-z0-9_]*(?:accessToken|refreshToken|token|password|secret|otp|authorization|apiKey|api_key|signature)[A-Za-z0-9_]*)\"\\s*:\\s*\"([^\"]*)\"",
    )

    private fun redactExportLine(payload: String): String {
        var redacted = payload.replace(secretFieldName) { match ->
            "\"" + match.groupValues[1] + "\":\"[REDACTED]\""
        }
        redacted = redacted.replace(Regex("(?i)bearer\\s+[A-Za-z0-9_.\\-]+"), "[REDACTED]")
        return redacted
    }

    private fun recordExportAudit(tenantId: String, filters: DiagnosticSearchFilters, lineCount: Int, hasMore: Boolean) {
        val eventId = UUID.randomUUID()
        val payloadJson = """
            {"schemaVersion":2,"eventId":"$eventId","occurredAtMillis":${clock.instant().toEpochMilli()},
             "serverReceivedAtMillis":${clock.instant().toEpochMilli()},
             "eventType":"DIAGNOSTICS_EXPORTED","severity":"INFO","sourceApp":"slotting_admin",
             "component":"diagnostics-export","environment":"server",
             "correlationId":"export-$eventId","causationId":"export-$eventId",
             "message":"Exported $lineCount diagnostic records; continuation=${if (hasMore) "PENDING" else "COMPLETE"}",
             "context":{"action":"EXPORTED","result":"lineCount=$lineCount"},
             "stackFrames":[]}
        """.trimIndent().replace("\n", "")
        jdbc.update(
            """
            insert into diagnostic_event(tenant_id, event_id, payload_digest, schema_version, occurred_at, server_received_at,
                event_type, severity, source_app, component, environment, correlation_id, payload_json, delivery_state, attempt_count, created_at)
            values (?, ?, ?, 2, ?, ?, 'DIAGNOSTICS_EXPORTED', 'INFO', 'slotting_admin', 'diagnostics-export', 'server', ?, cast(? as jsonb), 'SENT', 0, ?)
            """.trimIndent(),
            tenantId,
            eventId,
            sha256(payloadJson),
            Timestamp.from(clock.instant()),
            Timestamp.from(clock.instant()),
            "export-$eventId",
            payloadJson,
            Timestamp.from(clock.instant()),
        )
    }

    private fun authorize(principal: AuthenticatedPrincipal?, tenantId: String, sessionId: String?) {
        val authenticated = principal ?: throw AuthenticationFailure.Rejected(AuthErrorCode.UNAUTHENTICATED)
        if (authenticated.kind != PrincipalKind.ADMIN || authenticated.tenantId != tenantId) {
            throw AuthenticationFailure.Rejected(AuthErrorCode.FORBIDDEN)
        }
        val session = if (sessionId.isNullOrBlank()) null else sessions.find(tenantId, authenticated.id, sessionId)
        if (sessionId.isNullOrBlank() || session == null || !session.active || !session.expiresAt.isAfter(clock.instant()) || !session.mfaVerified) {
            throw AuthenticationFailure.Rejected(AuthErrorCode.FORBIDDEN)
        }
        if (!policy.isPermitted(authenticated, AdminPermission.READ_AUDIT)) {
            throw AuthenticationFailure.Rejected(AuthErrorCode.FORBIDDEN)
        }
    }

    private fun encodeCursor(occurredAt: Instant, eventId: UUID): String =
        Base64.getUrlEncoder().encodeToString("$occurredAt|$eventId".toByteArray(StandardCharsets.UTF_8))

    private fun decodeCursor(cursor: String): Pair<Instant, UUID> = runCatching {
        val decoded = String(Base64.getUrlDecoder().decode(cursor), StandardCharsets.UTF_8)
        val parts = decoded.split('|')
        Pair(Instant.parse(parts[0]), UUID.fromString(parts[1]))
    }.getOrElse { throw IllegalArgumentException("Malformed export cursor") }

    private fun sha256(value: String): String =
        MessageDigest.getInstance("SHA-256")
            .digest(value.toByteArray(StandardCharsets.UTF_8))
            .joinToString("") { "%02x".format(it) }
}

data class DiagnosticRetentionPurgeResult(
    val purgedCount: Int,
    val scannedTenants: Int,
    val heldTenantsSkipped: Int,
    val batchComplete: Boolean,
    val oldestRemaining: Instant?,
)

@Service
class DiagnosticRetentionService(
    private val jdbc: JdbcTemplate,
    private val auditStore: JdbcAdminAuditStore,
    private val clock: Clock = Clock.systemUTC(),
) {
    fun purgeExpired(
        retentionDays: Long,
        batchLimit: Int = 500,
        customerPolicyAcknowledged: Boolean = false,
    ): DiagnosticRetentionPurgeResult {
        require(retentionDays > 0) { "Retention must be at least one day" }
        require(batchLimit in 1..10_000) { "Purge batch limit must be between 1 and 10000" }
        if (!customerPolicyAcknowledged) {
            throw IllegalStateException("Destructive diagnostics purge requires the customer retention policy acknowledgement")
        }

        val cutoff = clock.instant().minus(java.time.Duration.ofDays(retentionDays))
        val tenants = jdbc.queryForList(
            "select distinct tenant_id from diagnostic_event",
            String::class.java,
        )
        var purged = 0
        var heldSkipped = 0
        var batchComplete = true

        for (tenant in tenants) {
            if (purged >= batchLimit) {
                batchComplete = false
                break
            }
            if (auditStore.isLegalHoldActive(tenant)) {
                heldSkipped += 1
                continue
            }
            val remaining = batchLimit - purged
            purged += jdbc.update(
                """
                delete from diagnostic_event
                where event_id in (
                    select event_id from diagnostic_event
                    where tenant_id = ? and created_at < ?
                    order by created_at asc
                    limit $remaining
                )
                """.trimIndent(),
                tenant,
                Timestamp.from(cutoff),
            )
        }

        val oldestRemaining = jdbc.query(
            "select min(created_at) from diagnostic_event",
            { rs, _ -> rs.getTimestamp(1)?.toInstant() },
        ).firstOrNull()

        return DiagnosticRetentionPurgeResult(
            purgedCount = purged,
            scannedTenants = tenants.size,
            heldTenantsSkipped = heldSkipped,
            batchComplete = batchComplete,
            oldestRemaining = oldestRemaining,
        )
    }
}
