package com.slotting.admin.observability

import com.slotting.admin.auth.AdminMfaCommand
import com.slotting.admin.auth.AdminMfaAuthenticator
import com.slotting.admin.auth.AdminRole
import com.slotting.admin.auth.AlertSink
import com.slotting.admin.auth.AuditEvent
import com.slotting.admin.auth.AuthenticationFailure
import com.slotting.admin.auth.MfaVerifier
import com.slotting.admin.auth.PrincipalKind
import com.slotting.admin.auth.AuthenticatedPrincipal
import com.slotting.admin.identity.InMemoryPlayerRegistrationStore
import com.slotting.admin.identity.InMemoryPlayerSessionStore
import com.slotting.admin.identity.LoginPlayerCommand
import com.slotting.admin.identity.PlayerSessionService
import com.slotting.admin.identity.PlayerRegistrationService
import com.slotting.admin.identity.RegisterPlayerCommand
import com.slotting.admin.auth.UnpredictableChallengeService
import com.slotting.admin.identity.VerifyContactCommand
import com.slotting.admin.infra.PostgresIntegrationSupport
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
class AlphaTc037ContractTest {
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
    }

    @Autowired
    private lateinit var jdbc: JdbcTemplate

    private val now = Instant.parse("2026-10-31T12:00:00Z")
    private val clock = Clock.fixed(now, ZoneOffset.UTC)
    private val tenantId = "tenant-tc037"

    private class AlwaysAcceptVerifier : MfaVerifier {
        override fun verify(tenantId: String, principalId: String, sessionId: String, assertion: String) = true
    }

    private class RecordingAlertSink : AlertSink {
        val alerts = mutableListOf<AuditEvent>()
        override fun alert(event: AuditEvent) {
            alerts.add(event)
        }
    }

    @Test
    fun `TC-037-R1 login success exports no token or password and failure uses the same safe schema`() {
        val diagnosticStore = JdbcDiagnosticEventStore(jdbc, clock)
        val projector = JdbcSecurityAuditDiagnosticProjector(diagnosticStore, clock)
        val registrationStore = InMemoryPlayerRegistrationStore()
        val sessionStore = InMemoryPlayerSessionStore()
        val sessionService = PlayerSessionService(
            registrationStore = registrationStore,
            sessionStore = sessionStore,
            clock = clock,
            securityDiagnostics = projector,
        )
        registerVerifiedPlayer(registrationStore, sessionStore)
        val rawPassword = "SecretPass123!"

        val success = sessionService.login(
            LoginPlayerCommand(
                tenantId = tenantId,
                identifier = "player.tc037@example.com",
                rawPassword = rawPassword,
                idempotencyKey = "login-ok-${UUID.randomUUID()}",
                correlationId = "corr-login-ok",
                causationId = "caus-login-ok",
            )
        )
        assertNotNull(success.accessToken)

        val failureRejection = assertFailsWith<AuthenticationFailure.Rejected> {
            sessionService.login(
                LoginPlayerCommand(
                    tenantId = tenantId,
                    identifier = "player.tc037@example.com",
                    rawPassword = "wrong-password",
                    idempotencyKey = "login-bad-${UUID.randomUUID()}",
                    correlationId = "corr-login-bad",
                    causationId = "caus-login-bad",
                )
            )
        }
        assertEquals(com.slotting.admin.auth.AuthErrorCode.INVALID, failureRejection.code)

        val successEvents = querySecurityEvents(jdbc, "corr-login-ok")
        val failureEvents = querySecurityEvents(jdbc, "corr-login-bad")
        assertEquals(1, successEvents.count { it.second == "PLAYER_LOGIN_SUCCEEDED" })
        assertEquals(1, failureEvents.count { it.second == "PLAYER_LOGIN_FAILED_CREDENTIALS" })

        for ((_, _, payload) in successEvents + failureEvents) {
            assertTrue(!payload.contains(success.accessToken!!), "token must never appear in a projected event")
            assertTrue(!payload.contains(rawPassword), "password must never appear in a projected event")
            assertTrue(!payload.contains("pat_") && !payload.contains("prt_"), "token formats must never appear")
        }
        assertTrue(failureEvents.single { it.second == "PLAYER_LOGIN_FAILED_CREDENTIALS" }.third.contains("ANONYMOUS"))
    }

    @Test
    fun `TC-037-R2 admin denial is recorded before any disclosure and accepted sessions persist without secrets`() {
        val diagnosticStore = JdbcDiagnosticEventStore(jdbc, clock)
        val projector = JdbcSecurityAuditDiagnosticProjector(diagnosticStore, clock)
        val alerts = RecordingAlertSink()
        val authenticator = AdminMfaAuthenticator(
            verifier = AlwaysAcceptVerifier(),
            store = RecordingAuthenticationStore(),
            alerts = alerts,
            clock = clock,
            securityDiagnostics = projector,
        )
        val admin = AuthenticatedPrincipal(
            id = "admin-tc037",
            tenantId = tenantId,
            kind = PrincipalKind.ADMIN,
            roles = setOf(AdminRole.SECURITY),
        )

        val forbidden = assertFailsWith<AuthenticationFailure.Rejected> {
            authenticator.authenticate(
                AdminMfaCommand(
                    principal = AuthenticatedPrincipal(
                        id = "admin-tc037",
                        tenantId = tenantId,
                        kind = PrincipalKind.ADMIN,
                        roles = setOf(AdminRole.AUDITOR),
                    ),
                    requestedRole = AdminRole.SECURITY,
                    sessionId = "session-tc037",
                    idempotencyKey = "idem-denied-${UUID.randomUUID()}",
                    correlationId = "corr-denied",
                    causationId = "caus-denied",
                    expectedVersion = 1L,
                    mfaAssertion = "assertion",
                )
            )
        }
        assertEquals(com.slotting.admin.auth.AuthErrorCode.FORBIDDEN, forbidden.code)

        val accepted = authenticator.authenticate(
            AdminMfaCommand(
                principal = admin,
                requestedRole = AdminRole.SECURITY,
                sessionId = "session-tc037",
                idempotencyKey = "idem-ok-${UUID.randomUUID()}",
                correlationId = "corr-accepted",
                causationId = "caus-accepted",
                expectedVersion = 0L,
                mfaAssertion = "assertion",
            )
        )
        assertEquals(com.slotting.admin.auth.AuthenticationState.AUTHENTICATED, accepted.state)

        val deniedEvents = querySecurityEvents(jdbc, "corr-denied")
        assertEquals(1, deniedEvents.count { it.second == "ADMIN_MFA_DENIED" })
        val acceptedEvents = querySecurityEvents(jdbc, "corr-accepted")
        assertEquals(1, acceptedEvents.count { it.second == "ADMIN_MFA_ACCEPTED" })

        for ((_, _, payload) in deniedEvents + acceptedEvents) {
            assertTrue(!payload.contains("assertion"), "MFA assertion material must never appear")
            assertTrue(!payload.contains("password") || payload.contains("[REDACTED]"))
        }
    }

    @Test
    fun `TC-037-R3 authentication succeeds and rejects with a throwing diagnostic store and failures never enumerate accounts`() {
        val capturedFacts = mutableListOf<SecurityAuditFacts>()
        val capturedEnvelopes = mutableListOf<DiagnosticEventEnvelope>()
        val throwingProjector = object : SecurityAuditDiagnosticProjector {
            override fun project(facts: SecurityAuditFacts): DiagnosticEventEnvelope? {
                val envelope = SecurityAuditProjections.envelope(facts, now)
                capturedFacts.add(facts)
                capturedEnvelopes.add(envelope)
                error("diagnostics unavailable")
            }
        }
        val registrationStore = InMemoryPlayerRegistrationStore()
        val sessionStore = InMemoryPlayerSessionStore()
        val sessionService = PlayerSessionService(
            registrationStore = registrationStore,
            sessionStore = sessionStore,
            clock = clock,
            securityDiagnostics = throwingProjector,
        )
        registerVerifiedPlayer(registrationStore, sessionStore)

        val success = sessionService.login(
            LoginPlayerCommand(
                tenantId = tenantId,
                identifier = "player.tc037@example.com",
                rawPassword = "SecretPass123!",
                idempotencyKey = "login-throwing-ok-${UUID.randomUUID()}",
                correlationId = "corr-throwing-ok",
                causationId = "caus-throwing-ok",
            )
        )
        assertNotNull(success.accessToken)

        val wrongPassword = assertFailsWith<AuthenticationFailure.Rejected> {
            sessionService.login(
                LoginPlayerCommand(
                    tenantId = tenantId,
                    identifier = "player.tc037@example.com",
                    rawPassword = "wrong-password",
                    idempotencyKey = "login-throwing-bad-${UUID.randomUUID()}",
                    correlationId = "corr-throwing-bad",
                    causationId = "caus-throwing-bad",
                )
            )
        }
        assertEquals(com.slotting.admin.auth.AuthErrorCode.INVALID, wrongPassword.code)

        val nonexistent = assertFailsWith<AuthenticationFailure.Rejected> {
            sessionService.login(
                LoginPlayerCommand(
                    tenantId = tenantId,
                    identifier = "nobody.tc037@example.com",
                    rawPassword = "whatever",
                    idempotencyKey = "login-throwing-none-${UUID.randomUUID()}",
                    correlationId = "corr-throwing-none",
                    causationId = "caus-throwing-none",
                )
            )
        }
        assertEquals(com.slotting.admin.auth.AuthErrorCode.INVALID, nonexistent.code)
        assertEquals(wrongPassword.code, nonexistent.code)

        val failureFacts = capturedFacts.filter { it.eventType == "PLAYER_LOGIN_FAILED_CREDENTIALS" }
        assertEquals(2, failureFacts.size)
        val failureEnvelopes = capturedEnvelopes.filter { it.eventType == "PLAYER_LOGIN_FAILED_CREDENTIALS" }
        assertEquals(2, failureEnvelopes.size)
        val (wrongPasswordFacts, nonexistentFacts) = failureFacts
        val (wrongPasswordEnvelope, nonexistentEnvelope) = failureEnvelopes
        assertEquals(wrongPasswordFacts.eventType, nonexistentFacts.eventType)
        assertEquals(wrongPasswordFacts.actorType, nonexistentFacts.actorType)
        assertEquals("ANONYMOUS", nonexistentFacts.actorType)
        assertEquals(nonexistentFacts.actorId, wrongPasswordFacts.actorId)
        assertEquals(wrongPasswordFacts.safeMetadata.keys, nonexistentFacts.safeMetadata.keys)

        assertEquals(wrongPasswordEnvelope.eventType, nonexistentEnvelope.eventType)
        assertEquals(wrongPasswordEnvelope.severity, nonexistentEnvelope.severity)
        assertEquals(wrongPasswordEnvelope.sourceApp, nonexistentEnvelope.sourceApp)
        assertEquals(wrongPasswordEnvelope.component, nonexistentEnvelope.component)
        assertEquals(wrongPasswordEnvelope.environment, nonexistentEnvelope.environment)
        assertEquals(wrongPasswordEnvelope.userId, nonexistentEnvelope.userId)
        assertEquals(wrongPasswordEnvelope.adminId, nonexistentEnvelope.adminId)
        assertEquals(wrongPasswordEnvelope.sessionId, nonexistentEnvelope.sessionId)
        assertEquals(wrongPasswordEnvelope.amountMinorUnits, nonexistentEnvelope.amountMinorUnits)
        assertEquals(wrongPasswordEnvelope.currency, nonexistentEnvelope.currency)
        assertEquals(wrongPasswordEnvelope.message, nonexistentEnvelope.message)
        assertEquals(wrongPasswordEnvelope.context, nonexistentEnvelope.context)
        assertEquals(null, nonexistentEnvelope.userId)
        assertTrue(capturedFacts.none { it.actorId == "player.tc037@example.com" })
        assertTrue(capturedFacts.none { "SecretPass123!" in it.safeMetadata.values.joinToString() })
        assertTrue(capturedEnvelopes.none { it.message!!.contains("player.tc037") })
    }

    private fun querySecurityEvents(
        jdbc: JdbcTemplate,
        correlationId: String,
    ): List<Triple<String, String, String>> = jdbc.query(
        "select event_id, payload_json->>'eventType' as event_type, payload_json::text as payload from diagnostic_event where tenant_id = ? and payload_json->>'correlationId' = ? order by created_at",
        { rs, _ -> Triple(rs.getString("event_id"), rs.getString("event_type"), rs.getString("payload")) },
        tenantId,
        correlationId,
    )

    private fun registerVerifiedPlayer(
        registrationStore: InMemoryPlayerRegistrationStore,
        sessionStore: InMemoryPlayerSessionStore,
    ) {
        val registrationService = PlayerRegistrationService(
            store = registrationStore,
            clock = clock,
            challengeGenerator = { tenant, player, purpose, ttl, issuedAt ->
                val code = "123456"
                val salt = UUID.randomUUID().toString().replace("-", "")
                UnpredictableChallengeService.IssuedChallenge(
                    challengeId = UUID.randomUUID(),
                    tenantId = tenant,
                    playerId = player,
                    purpose = purpose,
                    plaintextCode = code,
                    codeHash = UnpredictableChallengeService.hashChallengeCode(code, salt),
                    salt = salt,
                    expiresAt = issuedAt.plus(ttl),
                    createdAt = issuedAt,
                )
            },
        )
        val registered = registrationService.register(
            RegisterPlayerCommand(
                tenantId = tenantId,
                email = "player.tc037@example.com",
                phone = "+15550101",
                jurisdiction = "DEFAULT",
                riskScore = 20.0,
                rawPassword = "SecretPass123!",
                idempotencyKey = "reg-${UUID.randomUUID()}",
                correlationId = "corr-reg",
                causationId = "caus-reg",
            )
        )
        registrationService.verifyContact(
            VerifyContactCommand(
                tenantId = tenantId,
                playerId = registered.playerId,
                channel = com.slotting.admin.identity.ContactVerificationChannel.EMAIL,
                verificationCode = "123456",
                idempotencyKey = "ver-${UUID.randomUUID()}",
                correlationId = "corr-ver",
                causationId = "caus-ver",
            )
        )
    }

    private class RecordingAuthenticationStore : com.slotting.admin.auth.AuthenticationStore {
        private val results = mutableMapOf<String, Pair<String, com.slotting.admin.auth.AuthenticationResult>>()
        private val versions = mutableMapOf<String, Long>()
        override fun findByIdempotency(tenantId: String, key: String) = synchronized(this) { results["$tenantId:$key"] }
        override fun currentVersion(tenantId: String, principalId: String): Long = synchronized(this) { versions["$tenantId:$principalId"] ?: 0L }
        override fun save(
            result: com.slotting.admin.auth.AuthenticationResult,
            tenantId: String,
            principalId: String,
            sessionId: String,
            roles: Set<AdminRole>,
            idempotencyKey: String,
            requestFingerprint: String,
            audit: AuditEvent,
            outbox: com.slotting.admin.auth.OutboxEvent,
        ) {
            synchronized(this) {
                results["$tenantId:$idempotencyKey"] = requestFingerprint to result
                versions["$tenantId:$principalId"] = result.serverVersion
            }
        }
    }
}
