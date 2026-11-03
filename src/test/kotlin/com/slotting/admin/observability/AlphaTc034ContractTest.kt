package com.slotting.admin.observability

import com.slotting.admin.audit.JdbcAdminAuditStore
import com.slotting.admin.auth.AdminRole
import com.slotting.admin.auth.AdminRbacPolicy
import com.slotting.admin.auth.AdminSessionDirectory
import com.slotting.admin.auth.AdminSessionStatus
import com.slotting.admin.auth.AuthErrorCode
import com.slotting.admin.auth.AuthenticatedPrincipal
import com.slotting.admin.auth.AuthenticationFailure
import com.slotting.admin.auth.PrincipalKind
import com.slotting.admin.infra.PostgresIntegrationSupport
import java.sql.Timestamp
import java.time.Clock
import java.time.Instant
import java.time.ZoneOffset
import java.util.UUID
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertNotNull
import kotlin.test.assertTrue
import org.junit.jupiter.api.AfterAll
import org.junit.jupiter.api.Test
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.boot.test.context.SpringBootTest
import org.springframework.jdbc.core.JdbcTemplate
import org.springframework.test.context.DynamicPropertyRegistry
import org.springframework.test.context.DynamicPropertySource

@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.NONE)
class AlphaTc034ContractTest {
    companion object {
        private val databaseUrl = System.getenv("SLOTTING_ADMIN_DATABASE_URL")
            ?: "jdbc:postgresql://127.0.0.1:5432/slotting_admin_ci"
        private val isolatedSchema = PostgresIntegrationSupport.createIsolatedSchema(
            "tc04_${UUID.randomUUID().toString().replace("-", "").take(12)}",
        )

        @JvmStatic
        @DynamicPropertySource
        fun postgresProperties(registry: DynamicPropertyRegistry) {
            val separator = if (databaseUrl.contains('?')) '&' else '?'
            registry.add("spring.datasource.url") { "$databaseUrl${separator}currentSchema=${isolatedSchema.schemaName}" }
            registry.add("spring.datasource.username") { System.getenv("SLOTTING_ADMIN_DATABASE_USERNAME") ?: "ci_runner" }
            registry.add("spring.datasource.password") { System.getenv("SLOTTING_ADMIN_DATABASE_PASSWORD") ?: "ci_test_password_ephemeral" }
            registry.add("spring.flyway.enabled") { "true" }
        }

        @JvmStatic
        @AfterAll
        fun dropIsolatedSchema() {
            isolatedSchema.close()
        }

        private val sessions = object : AdminSessionDirectory {
            override fun find(tenantId: String, principalId: String, sessionId: String) =
                AdminSessionStatus(true, false, Instant.parse("2026-11-02T00:00:00Z"), true)
        }
    }

    @Autowired
    private lateinit var jdbc: JdbcTemplate

    private val now = Instant.parse("2026-10-31T16:00:00Z")
    private val clock = Clock.fixed(now, ZoneOffset.UTC)
    private val tenantId = "tenant-tc034"

    private fun admin() = AuthenticatedPrincipal(
        id = "admin-tc034",
        tenantId = tenantId,
        kind = PrincipalKind.ADMIN,
        roles = setOf(AdminRole.SECURITY),
    )

    private fun exportService(batchSize: Int = 1000) = DiagnosticsExportService(
        jdbc = jdbc,
        sessions = sessions,
        policy = AdminRbacPolicy(dualControlRequired = false),
        clock = clock,
        maxLinesPerBatch = batchSize,
    )

    private fun retentionService() = DiagnosticRetentionService(
        jdbc = jdbc,
        auditStore = JdbcAdminAuditStore(jdbc),
        clock = clock,
    )

    private fun seedDiagnostic(
        correlationId: String,
        eventType: String,
        createdAt: Instant = clock.instant(),
        payloadOverride: String? = null,
    ): UUID {
        val eventId = UUID.nameUUIDFromBytes("$correlationId|$eventType|${createdAt.toEpochMilli()}|${UUID.randomUUID()}".toByteArray())
        val payload = payloadOverride ?: """
            {"schemaVersion":2,"eventId":"$eventId","occurredAtMillis":${createdAt.toEpochMilli()},
             "serverReceivedAtMillis":${createdAt.toEpochMilli()},"eventType":"$eventType","severity":"INFO",
             "sourceApp":"slotting_admin","component":"seed","environment":"server",
             "correlationId":"$correlationId","message":"seeded","context":{"action":"SEEDED"},"stackFrames":[]}
        """.trimIndent().replace("\n", "")
        jdbc.update(
            """
            insert into diagnostic_event(tenant_id, event_id, payload_digest, schema_version, occurred_at, server_received_at,
                event_type, severity, source_app, component, environment, correlation_id, payload_json, delivery_state, attempt_count, created_at)
            values (?, ?, ?, 2, ?, ?, ?, 'INFO', 'slotting_admin', 'seed', 'server', ?, cast(? as jsonb), 'SENT', 0, ?)
            """.trimIndent(),
            tenantId,
            eventId,
            payload.hashCode().toString(16),
            Timestamp.from(createdAt),
            Timestamp.from(createdAt),
            eventType,
            correlationId,
            payload,
            Timestamp.from(createdAt),
        )
        return eventId
    }

    @Test
    fun `TC-034-R1 export of 1501 matching rows uses explicit continuation and never silently truncates`() {
        val correlation = "corr-export-${UUID.randomUUID()}"
        for (i in 1..1501) {
            seedDiagnostic(correlation, "EXPORT_EVENT")
        }
        val filters = DiagnosticSearchFilters(from = now.minusSeconds(3600), to = now, correlationId = correlation)

        val first = exportService().export(admin(), tenantId, "session-34", filters, cursor = null)
        assertEquals(1000, first.lineCount)
        assertTrue(!first.complete)
        assertNotNull(first.continuationCursor)
        assertNotNull(first.checksumSha256)
        assertNotNull(first.rangeFrom)
        assertNotNull(first.rangeTo)

        val second = exportService().export(
            admin(),
            tenantId,
            "session-34",
            filters,
            cursor = first.continuationCursor,
            previousChecksumSha256 = first.checksumSha256,
            previousCumulativeLineCount = first.lineCount.toLong(),
        )
        assertEquals(501, second.lineCount)
        assertTrue(second.complete)
        assertEquals(null, second.continuationCursor)

        val allLines = first.lines + second.lines
        assertEquals(1501, allLines.size)
        assertEquals(allLines.toSet().size, allLines.size)
        val sameFirst = exportService().export(admin(), tenantId, "session-34", filters, cursor = null)
        assertEquals(first.checksumSha256, sameFirst.checksumSha256)

        assertEquals(1501L, second.cumulativeLineCount)
        val lineSeparator = "\n"
        val expectedFinal = java.security.MessageDigest.getInstance("SHA-256")
            .digest((first.checksumSha256 + lineSeparator + second.lines.joinToString(lineSeparator)).toByteArray(Charsets.UTF_8))
            .joinToString("") { "%02x".format(it) }
        assertEquals(expectedFinal, second.checksumSha256)

        val tamperedChain = exportService().export(
            admin(),
            tenantId,
            "session-34",
            filters,
            cursor = first.continuationCursor,
            previousChecksumSha256 = "0".repeat(64),
            previousCumulativeLineCount = first.lineCount.toLong(),
        )
        assertTrue(tamperedChain.checksumSha256 != second.checksumSha256)

        val missingLastRow = second.lines.dropLast(1)
        val missingRowChecksum = java.security.MessageDigest.getInstance("SHA-256")
            .digest((first.checksumSha256 + lineSeparator + missingLastRow.joinToString(lineSeparator)).toByteArray(Charsets.UTF_8))
            .joinToString("") { "%02x".format(it) }
        assertTrue(missingRowChecksum != second.checksumSha256, "a missing row must change the final checksum")

        val reorderedRows = missingLastRow.asReversed()
        val reorderedChecksum = java.security.MessageDigest.getInstance("SHA-256")
            .digest((first.checksumSha256 + lineSeparator + reorderedRows.joinToString(lineSeparator)).toByteArray(Charsets.UTF_8))
            .joinToString("") { "%02x".format(it) }
        assertTrue(reorderedChecksum != second.checksumSha256, "reordered rows must change the final checksum")
        assertTrue(reorderedChecksum != missingRowChecksum, "reordering and deletion are distinct tamper outcomes")

        val noChain = assertFailsWith<IllegalArgumentException> {
            exportService().export(admin(), tenantId, "session-34", filters, cursor = first.continuationCursor)
        }
        assertTrue(noChain.message!!.contains("previous page checksum"))
        assertEquals(1501L, second.totalMatchingCount)
    }

    @Test
    fun `TC-034-R2 export is denied without authorization and its own audit contains no raw payload or secrets`() {
        val correlation = "corr-secret-${UUID.randomUUID()}"
        val secret = "super-secret-token-abc123"
        seedDiagnostic(
            correlationId = correlation,
            eventType = "SECRET_EVENT",
            payloadOverride = """
                {"schemaVersion":2,"eventId":"${UUID.randomUUID()}","eventType":"SECRET_EVENT","severity":"INFO",
                 "sourceApp":"slotting_admin","component":"seed","environment":"server",
                 "correlationId":"$correlation","message":"seeded",
                 "context":{"action":"SEEDED","result":"token=REDACTED-AT-INGESTION"},"stackFrames":[]}
            """.trimIndent().replace("\n", ""),
        )
        val filters = DiagnosticSearchFilters(from = now.minusSeconds(600), to = now, correlationId = correlation)

        val unauthenticated = assertFailsWith<AuthenticationFailure.Rejected> {
            exportService().export(null, tenantId, "session", filters, cursor = null)
        }
        assertEquals(AuthErrorCode.UNAUTHENTICATED, unauthenticated.code)

        val supportDenied = assertFailsWith<AuthenticationFailure.Rejected> {
            exportService().export(
                AuthenticatedPrincipal("s1", tenantId, PrincipalKind.ADMIN, setOf(AdminRole.SUPPORT)),
                tenantId,
                "session",
                filters,
                cursor = null,
            )
        }
        assertEquals(AuthErrorCode.FORBIDDEN, supportDenied.code)

        val legacySecret = "legacy-pat-token-abc123"
        val legacyPassword = "legacy-hunter2"
        seedDiagnostic(
            correlationId = correlation,
            eventType = "LEGACY_PAYLOAD_EVENT",
            payloadOverride = """
                {"schemaVersion":1,"eventId":"${UUID.randomUUID()}","eventType":"LEGACY_PAYLOAD_EVENT","severity":"INFO",
                 "sourceApp":"legacy","component":"legacy-exporter","environment":"server",
                 "correlationId":"$correlation","message":"legacy",
                 "accessToken":"$legacySecret","password":"$legacyPassword","refreshToken":"prt-legacy",
                 "context":{"action":"SEEDED"},"stackFrames":[]}
            """.trimIndent(),
        )

        val batch = exportService().export(admin(), tenantId, "session", filters, cursor = null)
        assertEquals(2, batch.lineCount)
        for (line in batch.lines) {
            assertTrue(!line.contains(secret))
            assertTrue(!line.contains(legacySecret))
            assertTrue(!line.contains(legacyPassword))
            assertTrue(!line.contains("prt-legacy"))
            if (line.contains("LEGACY_PAYLOAD_EVENT")) {
                assertTrue(line.contains("[REDACTED]"))
            }
        }

        val exportAudit = jdbc.queryForObject(
            "select payload_json::text from diagnostic_event where tenant_id = ? and event_type = 'DIAGNOSTICS_EXPORTED' order by created_at desc limit 1",
            String::class.java,
            tenantId,
        )
        assertTrue(exportAudit.contains("DIAGNOSTICS_EXPORTED"))
        assertTrue(!exportAudit.contains(secret))
        assertTrue(!exportAudit.contains("SECRET_EVENT"))
    }

    @Test
    fun `TC-034-R3 purge removes only expired diagnostics with legal holds and financial audit surviving`() {
        val retentionDays = 30L
        val cutoff = now.minus(java.time.Duration.ofDays(retentionDays))
        val expired = now.minus(java.time.Duration.ofDays(retentionDays + 5))
        val recent = now.minusSeconds(60)

        val expiredId = seedDiagnostic("corr-purge-expired", "PURGE_EXPIRED", createdAt = expired)
        val recentId = seedDiagnostic("corr-purge-recent", "PURGE_RECENT", createdAt = recent)

        val refused = assertFailsWith<IllegalStateException> {
            retentionService().purgeExpired(retentionDays, customerPolicyAcknowledged = false)
        }
        assertTrue(refused.message!!.contains("acknowledgement"))
        assertEquals(2, diagnosticCount(listOf(expiredId, recentId)))

        val purge = retentionService().purgeExpired(retentionDays, batchLimit = 500, customerPolicyAcknowledged = true)
        assertEquals(1, purge.purgedCount)
        assertEquals(0, diagnosticCount(listOf(expiredId)))
        assertEquals(1, diagnosticCount(listOf(recentId)))

        val financialAuditId = seedFinancialAudit(createdAt = expired)
        val financialExpired = now.minus(java.time.Duration.ofDays(retentionDays + 5))
        seedDiagnostic("corr-purge-financial", "FINANCIAL_SIDE_EVENT", createdAt = financialExpired)
        retentionService().purgeExpired(retentionDays, customerPolicyAcknowledged = true)
        assertEquals(1, financialAuditCount(financialAuditId))

        val interrupted = retentionService().purgeExpired(retentionDays, batchLimit = 1, customerPolicyAcknowledged = true)
        assertTrue(interrupted.purgedCount in 0..1)
        val resume = retentionService().purgeExpired(retentionDays, customerPolicyAcknowledged = true)
        assertEquals(0, resume.purgedCount)

        val heldTenant = "tenant-tc034-held-${UUID.randomUUID()}"
        JdbcAdminAuditStore(jdbc).saveHold(heldTenant, "HOLD-TC034", "litigation", "approver", true, 1L, now)
        val heldExpiredId = seedDiagnosticForTenant(heldTenant, "corr-held-purge", "HELD_EXPIRED", createdAt = expired)
        retentionService().purgeExpired(retentionDays, customerPolicyAcknowledged = true)
        assertEquals(1, diagnosticCount(listOf(heldExpiredId)), "a tenant under legal hold must never be purged")
        JdbcAdminAuditStore(jdbc).saveHold(heldTenant, "HOLD-TC034", "released", "approver", false, 2L, now)
        retentionService().purgeExpired(retentionDays, customerPolicyAcknowledged = true)
        assertEquals(0, diagnosticCount(listOf(heldExpiredId)), "after hold release the expired rows become purgeable")
    }

    private fun seedDiagnosticForTenant(
        tenantId: String,
        correlationId: String,
        eventType: String,
        createdAt: Instant,
    ): UUID {
        val eventId = UUID.nameUUIDFromBytes("$tenantId|$correlationId|$eventType|${createdAt.toEpochMilli()}".toByteArray())
        val payload = """
            {"schemaVersion":2,"eventId":"$eventId","eventType":"$eventType","severity":"INFO",
             "sourceApp":"slotting_admin","component":"seed","environment":"server",
             "correlationId":"$correlationId","message":"seeded","context":{"action":"SEEDED"},"stackFrames":[]}
        """.trimIndent()
        jdbc.update(
            """
            insert into diagnostic_event(tenant_id, event_id, payload_digest, schema_version, occurred_at, server_received_at,
                event_type, severity, source_app, component, environment, correlation_id, payload_json, delivery_state, attempt_count, created_at)
            values (?, ?, ?, 2, ?, ?, ?, 'INFO', 'slotting_admin', 'seed', 'server', ?, cast(? as jsonb), 'SENT', 0, ?)
            """.trimIndent(),
            tenantId,
            eventId,
            payload.hashCode().toString(16),
            Timestamp.from(createdAt),
            Timestamp.from(createdAt),
            eventType,
            correlationId,
            payload,
            Timestamp.from(createdAt),
        )
        return eventId
    }

    private fun diagnosticCount(eventIds: List<UUID>): Int {
        if (eventIds.isEmpty()) return 0
        val placeholders = eventIds.joinToString(",") { "?" }
        return jdbc.queryForObject(
            "select count(*) from diagnostic_event where event_id in ($placeholders)",
            Int::class.java,
            *eventIds.toTypedArray(),
        ) ?: 0
    }

    private fun seedFinancialAudit(createdAt: Instant): UUID {
        val eventId = UUID.randomUUID()
        val resultId = UUID.randomUUID()
        jdbc.update(
            "insert into admin_operation(result_id, tenant_id, operation_type, created_at) values (?, ?, ?, ?)",
            resultId, tenantId, "ADMIN_AUDIT", Timestamp.from(createdAt),
        )
        jdbc.update(
            """
            insert into admin_audit_event(event_id, result_id, tenant_id, event_type, occurred_at, correlation_id, causation_id, redacted_details)
            values (?, ?, ?, 'FINANCIAL_AUDIT_KEEP', ?, 'corr-fin', 'caus-fin', cast('{"keep":true}' as jsonb))
            """.trimIndent(),
            eventId, resultId, tenantId, Timestamp.from(createdAt),
        )
        return eventId
    }

    private fun financialAuditCount(eventId: UUID): Int = jdbc.queryForObject(
        "select count(*) from admin_audit_event where event_id = ?",
        Int::class.java,
        eventId,
    ) ?: 0
}
