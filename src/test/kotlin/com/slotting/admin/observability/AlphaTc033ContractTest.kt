package com.slotting.admin.observability

import com.slotting.admin.auth.AdminPermission
import com.slotting.admin.auth.AdminRole
import com.slotting.admin.auth.AdminRbacPolicy
import com.slotting.admin.auth.AdminSessionDirectory
import com.slotting.admin.auth.AdminSessionStatus
import com.slotting.admin.auth.AuthErrorCode
import com.slotting.admin.auth.AuthenticatedPrincipal
import com.slotting.admin.auth.AuthenticationFailure
import com.slotting.admin.auth.PrincipalKind
import com.slotting.admin.infra.PostgresIntegrationSupport
import java.time.Clock
import java.time.Instant
import java.time.ZoneOffset
import java.util.UUID
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertTrue
import org.junit.jupiter.api.AfterAll
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.boot.test.context.SpringBootTest
import org.springframework.jdbc.core.JdbcTemplate
import org.springframework.test.context.DynamicPropertyRegistry
import org.springframework.test.context.DynamicPropertySource

@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.NONE)
class AlphaTc033ContractTest {
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

        private val tenantSessions = object : AdminSessionDirectory {
            private val knownSessions = setOf("session-r1", "session-r3", "session-34", "session-33")

            override fun find(tenantId: String, principalId: String, sessionId: String): AdminSessionStatus? =
                if (tenantId.startsWith("tenant-tc033") && sessionId in knownSessions) {
                    AdminSessionStatus(true, false, Instant.parse("2026-11-01T00:00:00Z"), true)
                } else {
                    null
                }
        }

        private val noMfaSessions = object : AdminSessionDirectory {
            override fun find(tenantId: String, principalId: String, sessionId: String): AdminSessionStatus? =
                if (tenantId.startsWith("tenant-tc033")) {
                    AdminSessionStatus(true, false, Instant.parse("2026-11-01T00:00:00Z"), mfaVerified = false)
                } else {
                    null
                }
        }

        private val failingSessions = object : AdminSessionDirectory {
            override fun find(tenantId: String, principalId: String, sessionId: String): AdminSessionStatus =
                error("session dependency unavailable")
        }
    }

    @Autowired
    private lateinit var jdbc: JdbcTemplate

    private val now = Instant.parse("2026-10-31T15:00:00Z")
    private val clock = Clock.fixed(now, ZoneOffset.UTC)
    private val tenantId = "tenant-tc033"
    private val otherTenant = "tenant-tc033-other"

    private fun service(sessions: AdminSessionDirectory = tenantSessions) = AdminDiagnosticsQueryService(
        jdbc = jdbc,
        sessions = sessions,
        policy = AdminRbacPolicy(dualControlRequired = false),
        clock = clock,
    )

    private fun admin(roles: Set<AdminRole> = setOf(AdminRole.SECURITY)) = AuthenticatedPrincipal(
        id = "admin-tc033",
        tenantId = tenantId,
        kind = PrincipalKind.ADMIN,
        roles = roles,
    )

    private fun seedDiagnostic(
        tenant: String,
        correlationId: String,
        eventType: String,
        severity: DiagnosticEventSeverity = DiagnosticEventSeverity.INFO,
        roundId: String? = null,
        betId: String? = null,
        paymentId: String? = null,
        amountMinorUnits: Long? = null,
        currency: String? = null,
        message: String? = null,
    ): UUID {
        val store = JdbcDiagnosticEventStore(jdbc, clock)
        val identity = "seed|$tenant|$eventType|$correlationId|${roundId ?: ""}|${betId ?: ""}|${paymentId ?: ""}"
        val envelope = DiagnosticEventEnvelope(
            schemaVersion = 2,
            eventId = UUID.nameUUIDFromBytes(identity.toByteArray()),
            occurredAt = clock.instant(),
            serverReceivedAt = clock.instant(),
            eventType = eventType,
            severity = severity,
            sourceApp = "slotting_admin",
            component = "seed",
            environment = "server",
            requestId = null,
            correlationId = correlationId,
            causationId = null,
            userId = null,
            adminId = null,
            sessionId = null,
            roundId = roundId,
            betId = betId,
            paymentId = paymentId,
            ledgerId = null,
            amountMinorUnits = amountMinorUnits,
            currency = currency,
            message = message,
            context = mapOf("action" to "SEEDED"),
            stackFrames = emptyList(),
        )
        store.save(tenant, envelope)
        return envelope.eventId
    }

    @BeforeEach
    fun clearDiagnostics() {
        jdbc.update("delete from diagnostic_event where tenant_id like 'tenant-tc033%'")
    }

    @Test
    fun `TC-033-R1 correlation search shows only tenant events and detail exposes the missing settlement explicitly`() {
        val correlation = "corr-tc033-${UUID.randomUUID()}"
        val acceptedId = seedDiagnostic(
            tenant = tenantId,
            correlationId = correlation,
            eventType = "GAME_BET_ACCEPTED",
            roundId = "round-r1",
            betId = "bet-r1",
            amountMinorUnits = 2_500L,
            currency = "PKR",
        )
        seedDiagnostic(
            tenant = otherTenant,
            correlationId = correlation,
            eventType = "GAME_BET_ACCEPTED",
            roundId = "round-r1",
            betId = "bet-r1",
        )

        val result = service().search(
            principal = admin(),
            tenantId = tenantId,
            sessionId = "session-r1",
            filters = DiagnosticSearchFilters(from = now.minusSeconds(600), to = now, correlationId = correlation),
            cursor = null,
            limit = 50,
        )
        assertEquals(1, result.entries.size)
        assertEquals("GAME_BET_ACCEPTED", result.entries.single().eventType)
        assertEquals(tenantId, result.tenantId)

        val detail = service().detail(admin(), tenantId, "session-r1", acceptedId)
        assertEquals("bet-r1", detail.betId)
        assertTrue(detail.missingLifecycleStages.contains("GAME_CASH_OUT_ACCEPTED"))
        assertTrue(detail.missingLifecycleStages.contains("GAME_BET_SETTLED_CRASH"))

        val crossTenant = assertFailsWith<DiagnosticEventNotFoundException> {
            service().detail(admin(), tenantId, "session-r1", seedDiagnostic(otherTenant, "corr-other", "OTHER_EVENT"))
        }
        assertTrue(!crossTenant.message.orEmpty().contains(otherTenant))
    }

    @Test
    fun `TC-033-R2 unauthenticated unauthorized dependency failure and empty results are distinct states`() {
        val unauthenticated = assertFailsWith<AuthenticationFailure.Rejected> {
            service().search(null, tenantId, "session", DiagnosticSearchFilters(now, now), null, 50)
        }
        assertEquals(AuthErrorCode.UNAUTHENTICATED, unauthenticated.code)

        val player = AuthenticatedPrincipal("p1", tenantId, PrincipalKind.PLAYER, emptySet())
        val forbidden = assertFailsWith<AuthenticationFailure.Rejected> {
            service().search(player, tenantId, "session", DiagnosticSearchFilters(now, now), null, 50)
        }
        assertEquals(AuthErrorCode.FORBIDDEN, forbidden.code)

        val supportDenied = assertFailsWith<AuthenticationFailure.Rejected> {
            service().search(
                admin(roles = setOf(AdminRole.SUPPORT)),
                tenantId,
                "session",
                DiagnosticSearchFilters(now, now),
                null,
                50,
            )
        }
        assertEquals(AuthErrorCode.FORBIDDEN, supportDenied.code)

        val dependency = assertFailsWith<DiagnosticsDependencyUnavailableException> {
            service(failingSessions).search(admin(), tenantId, "session", DiagnosticSearchFilters(now, now), null, 50)
        }
        assertTrue(dependency.message.orEmpty().contains("unavailable"))

        val empty = service().search(
            admin(),
            tenantId,
            "session-33",
            DiagnosticSearchFilters(from = now.minusSeconds(60), to = now, eventType = "DOES_NOT_EXIST"),
            cursor = null,
            limit = 50,
        )
        assertTrue(empty.entries.isEmpty())
        assertEquals("COMPLETE", empty.resultCompleteness)
        assertTrue(!empty.resultCompleteness.equals("PARTIAL", ignoreCase = true))
    }

    @Test
    fun `TC-033-R2b sessions without MFA or with blank identifiers are denied before any query executes`() {
        val noMfa = assertFailsWith<AuthenticationFailure.Rejected> {
            AdminDiagnosticsQueryService(
                jdbc = jdbc,
                sessions = noMfaSessions,
                policy = AdminRbacPolicy(dualControlRequired = false),
                clock = clock,
            ).search(admin(), tenantId, "session-nomfa", DiagnosticSearchFilters(now, now), null, 50)
        }
        assertEquals(AuthErrorCode.FORBIDDEN, noMfa.code)

        val blankSession = assertFailsWith<AuthenticationFailure.Rejected> {
            service().search(admin(), tenantId, "  ", DiagnosticSearchFilters(now, now), null, 50)
        }
        assertEquals(AuthErrorCode.FORBIDDEN, blankSession.code)

        val unknownSession = assertFailsWith<AuthenticationFailure.Rejected> {
            service().search(admin(), tenantId, "session-unknown", DiagnosticSearchFilters(now, now), null, 50)
        }
        assertEquals(AuthErrorCode.FORBIDDEN, unknownSession.code)
    }

    @Test
    fun `TC-033-R3 cursor pagination is stable under concurrent insertion and malicious text stays escaped in the view`() {
        val correlation = "corr-paging-${UUID.randomUUID()}"
        val total = 75
        for (i in 1..total) {
            seedDiagnostic(tenantId, correlation, "PAGING_EVENT_$i")
        }
        val query = service()
        val firstPage = query.search(
            admin(),
            tenantId,
            "session-r3",
            DiagnosticSearchFilters(from = now.minusSeconds(600), to = now, correlationId = correlation),
            cursor = null,
            limit = 50,
        )
        assertEquals(50, firstPage.entries.size)
        assertTrue(firstPage.nextCursor != null)

        for (i in 1..5) {
            seedDiagnostic(tenantId, correlation, "PAGING_EVENT_LATE_$i")
        }

        val secondPage = query.search(
            admin(),
            tenantId,
            "session-r3",
            DiagnosticSearchFilters(from = now.minusSeconds(600), to = now, correlationId = correlation),
            cursor = checkNotNull(firstPage.nextCursor),
            limit = 50,
        )
        val firstIds = firstPage.entries.map { it.eventId }.toSet()
        val secondIds = secondPage.entries.map { it.eventId }.toSet()
        assertTrue(secondPage.entries.size in 25..30)
        assertEquals(0, firstIds.intersect(secondIds).size)
        assertTrue(secondPage.entries.all { it.occurredAt <= firstPage.entries.last().occurredAt })
        val originals = (1..total).map { "PAGING_EVENT_$it" }.toSet()
        val coveredTypes = (firstPage.entries + secondPage.entries).map { it.eventType }.toSet()
        assertTrue(originals.all { it in coveredTypes }, "keyset pagination must cover every original event exactly once")

        val malicious = "</script><img src=x onerror=alert(1)>"
        val seededId = seedDiagnostic(
            tenant = tenantId,
            correlationId = "corr-malicious",
            eventType = "MALICIOUS_PAYLOAD",
            message = malicious,
        )
        val detail = query.detail(admin(), tenantId, "session-r3", seededId)
        assertEquals(malicious, detail.message)

        val view = String(java.util.Objects.requireNonNull(
            javaClass.classLoader.getResourceAsStream("static/admin/diagnostics.html")?.readBytes() ?: throw IllegalStateException("admin view missing")
        ))
        assertTrue(view.contains("textContent"), "the admin view must assign event text through textContent")
        assertTrue(!view.contains("innerHTML"), "the admin view must not inject event HTML")
        assertTrue(!view.contains("localStorage"), "the admin view must not persist tokens in localStorage")
    }
}
