package com.slotting.admin.observability

import com.slotting.admin.audit.AdminAuditStore
import com.slotting.admin.audit.AuditQueryAction
import com.slotting.admin.audit.AuditQueryCommand
import com.slotting.admin.audit.AuditQueryResult
import com.slotting.admin.audit.AuditRecord
import com.slotting.admin.audit.AdminAuditService
import com.slotting.admin.audit.JdbcAdminAuditStore
import com.slotting.admin.auth.AdminRole
import com.slotting.admin.auth.AdminSessionDirectory
import com.slotting.admin.auth.AdminSessionStatus
import com.slotting.admin.auth.AdminRbacPolicy
import com.slotting.admin.auth.AuthErrorCode
import com.slotting.admin.auth.AuthenticatedPrincipal
import com.slotting.admin.auth.AuthenticationFailure
import com.slotting.admin.auth.AuditEvent
import com.slotting.admin.auth.OutboxEvent
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
import org.junit.jupiter.api.Test
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.boot.test.context.SpringBootTest
import org.springframework.jdbc.core.JdbcTemplate
import org.springframework.test.context.DynamicPropertyRegistry
import org.springframework.test.context.DynamicPropertySource

@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.NONE)
class AlphaTc032ContractTest {
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

    private val now = Instant.parse("2026-10-31T10:00:00Z")
    private val clock = Clock.fixed(now, ZoneOffset.UTC)

    @Test
    fun `TC-032-R1 correlation filter is applied in the store before limit and returns the older target`() {
        val store = JdbcAdminAuditStore(jdbc)
        val tenantId = "tenant-tc032-r1-${UUID.randomUUID()}"
        val targetCorrelation = "corr-target-${UUID.randomUUID()}"
        for (i in 1..150) {
            val resultId = UUID.randomUUID()
            store.save(
                result = result(resultId),
                tenantId = tenantId,
                queryFingerprint = "fp-$i",
                idempotencyKey = "idem-r1-$i",
                audit = AuditEvent(
                    eventId = UUID.randomUUID(),
                    resultId = resultId,
                    tenantId = tenantId,
                    type = "UNRELATED_EVENT",
                    occurredAt = now.minusSeconds(i.toLong() * 10),
                    correlationId = "corr-unrelated-$i",
                    causationId = "cause-$i",
                ),
                outbox = OutboxEvent(UUID.randomUUID(), resultId, tenantId, "UNRELATED_EVENT", now),
            )
        }
        val targetResultId = UUID.randomUUID()
        store.save(
            result = result(targetResultId),
            tenantId = tenantId,
            queryFingerprint = "fp-target",
            idempotencyKey = "idem-r1-target",
            audit = AuditEvent(
                eventId = UUID.randomUUID(),
                resultId = targetResultId,
                tenantId = tenantId,
                type = "TARGET_EVENT",
                occurredAt = now.minusSeconds(5_000),
                correlationId = targetCorrelation,
                causationId = "cause-target",
            ),
            outbox = OutboxEvent(UUID.randomUUID(), targetResultId, tenantId, "TARGET_EVENT", now),
        )

        val found = store.queryEvents(
            tenantId = tenantId,
            eventType = null,
            from = now.minusSeconds(10_000),
            to = now,
            limit = 10,
            correlationId = targetCorrelation,
        )

        assertEquals(1, found.size)
        assertEquals("TARGET_EVENT", found.single().eventType)
        assertEquals(targetCorrelation, found.single().correlationId)
    }

    @Test
    fun `TC-032-R2 same correlation in two tenants is isolated and injection-like input is literal`() {
        val store = JdbcAdminAuditStore(jdbc)
        val tenantA = "tenant-tc032-a-${UUID.randomUUID()}"
        val tenantB = "tenant-tc032-b-${UUID.randomUUID()}"
        val sharedCorrelation = "corr-shared-${UUID.randomUUID()}"
        val injection = "x'; DROP TABLE admin_audit_event; --"
        for ((tenant, correlation) in listOf(tenantA to sharedCorrelation, tenantB to sharedCorrelation)) {
            val resultId = UUID.randomUUID()
            store.save(
                result = result(resultId),
                tenantId = tenant,
                queryFingerprint = "fp",
                idempotencyKey = "idem-${tenant.hashCode()}",
                audit = AuditEvent(
                    eventId = UUID.randomUUID(),
                    resultId = resultId,
                    tenantId = tenant,
                    type = "SHARED_CORRELATION_EVENT",
                    occurredAt = now,
                    correlationId = correlation,
                    causationId = "cause",
                ),
                outbox = OutboxEvent(UUID.randomUUID(), resultId, tenant, "SHARED_CORRELATION_EVENT", now),
            )
        }

        assertEquals(1, store.queryEvents(tenantA, null, now.minusSeconds(60), now, 100, sharedCorrelation).size)
        assertEquals(1, store.queryEvents(tenantB, null, now.minusSeconds(60), now, 100, sharedCorrelation).size)

        val injectionResultId = UUID.randomUUID()
        store.save(
            result = result(injectionResultId),
            tenantId = tenantA,
            queryFingerprint = "fp-inj",
            idempotencyKey = "idem-inj",
            audit = AuditEvent(
                eventId = UUID.randomUUID(),
                resultId = injectionResultId,
                tenantId = tenantA,
                type = "INJECTION_LIKE_EVENT",
                occurredAt = now,
                correlationId = injection,
                causationId = "cause",
            ),
            outbox = OutboxEvent(UUID.randomUUID(), injectionResultId, tenantA, "INJECTION_LIKE_EVENT", now),
        )
        val literal = store.queryEvents(tenantA, null, now.minusSeconds(60), now, 100, injection)
        assertEquals(1, literal.size)
        assertEquals("INJECTION_LIKE_EVENT", literal.single().eventType)
        assertEquals(0, store.queryEvents(tenantB, null, now.minusSeconds(60), now, 100, injection).size)
    }

    @Test
    fun `TC-032-R3 support roles may search but never mutate legal holds and replay after role removal is denied`() {
        val sessions = object : AdminSessionDirectory {
            override fun find(tenantId: String, principalId: String, sessionId: String) =
                AdminSessionStatus(true, false, now.plusSeconds(3_600), true)
        }
        val service = AdminAuditService(
            policy = AdminRbacPolicy(dualControlRequired = false),
            sessions = sessions,
            store = RecordingAuditStore(),
            clock = clock,
        )

        val supportSearch = service.operate(
            command(
                action = AuditQueryAction.SEARCH,
                principal = principal(roles = setOf(AdminRole.SUPPORT)),
            )
        )
        assertEquals(AuditQueryAction.SEARCH, supportSearch.action)

        val deniedMutations = listOf(AuditQueryAction.APPLY_LEGAL_HOLD, AuditQueryAction.RELEASE_LEGAL_HOLD)
        for (action in deniedMutations) {
            for (roles in listOf(setOf(AdminRole.SUPPORT), setOf(AdminRole.SUPPORT, AdminRole.AUDITOR))) {
                val rejection = assertFailsWith<AuthenticationFailure.Rejected> {
                    service.operate(
                        command(
                            action = action,
                            principal = principal(roles = roles),
                            legalHoldReference = "HOLD-1",
                            legalHoldReason = "reason",
                            approverId = "approver",
                        )
                    )
                }
                assertEquals(AuthErrorCode.FORBIDDEN, rejection.code)
            }
        }

        val securityPrincipal = principal(roles = setOf(AdminRole.SECURITY))
        val applied = service.operate(
            command(
                action = AuditQueryAction.APPLY_LEGAL_HOLD,
                principal = securityPrincipal,
                legalHoldReference = "HOLD-TC032",
                legalHoldReason = "regulatory",
                approverId = "approver-1",
            )
        )
        assertTrue(applied.legalHoldActive)

        val replayKey = "replay-after-role-removal"
        val first = service.operate(command(action = AuditQueryAction.SEARCH, principal = securityPrincipal, idempotencyKey = replayKey))
        val replay = service.operate(command(action = AuditQueryAction.SEARCH, principal = securityPrincipal, idempotencyKey = replayKey))
        assertEquals(first.resultId, replay.resultId)

        val replayDenied = assertFailsWith<AuthenticationFailure.Rejected> {
            service.operate(
                command(
                    action = AuditQueryAction.SEARCH,
                    principal = principal(roles = emptySet()),
                    idempotencyKey = replayKey,
                )
            )
        }
        assertEquals(AuthErrorCode.FORBIDDEN, replayDenied.code)
    }

    private fun result(resultId: UUID = UUID.randomUUID()) = AuditQueryResult(
        resultId = resultId,
        action = AuditQueryAction.SEARCH,
        records = emptyList(),
        exportChecksumSha256 = null,
        legalHoldActive = false,
        serverTime = now,
        serverVersion = 1L,
        evidenceReference = "evidence",
    )

    private fun principal(roles: Set<AdminRole>) = AuthenticatedPrincipal(
        id = "admin-${roles.hashCode()}",
        tenantId = "tenant-tc032-r3",
        kind = PrincipalKind.ADMIN,
        roles = roles,
    )

    private fun command(
        action: AuditQueryAction,
        principal: AuthenticatedPrincipal? = principal(roles = setOf(AdminRole.SUPER_ADMIN)),
        legalHoldReference: String? = null,
        legalHoldReason: String? = null,
        approverId: String? = null,
        idempotencyKey: String = "idem-${UUID.randomUUID()}",
    ) = AuditQueryCommand(
        principal = principal,
        sessionId = "session-1",
        tenantId = principal?.tenantId ?: "tenant-tc032-r3",
        action = action,
        from = now.minusSeconds(60),
        to = now,
        correlationId = null,
        legalHoldReference = legalHoldReference,
        legalHoldReason = legalHoldReason,
        approverId = approverId,
        limit = 10,
        idempotencyKey = idempotencyKey,
        commandCorrelationId = "corr-cmd",
        commandCausationId = "cause-cmd",
    )

    private class RecordingAuditStore : AdminAuditStore {
        private val results = mutableMapOf<String, Pair<String, AuditQueryResult>>()
        override fun findByIdempotency(tenantId: String, key: String): Pair<String, AuditQueryResult>? =
            synchronized(this) { results["$tenantId:$key"] }
        override fun queryEvents(
            tenantId: String,
            eventType: String?,
            from: Instant,
            to: Instant,
            limit: Int,
            correlationId: String?,
        ): List<AuditRecord> = emptyList()
        override fun isLegalHoldActive(tenantId: String): Boolean = false
        override fun findHoldVersion(tenantId: String, holdReference: String): Long? = null
        override fun saveHold(tenantId: String, holdReference: String, reason: String, approverId: String, active: Boolean, version: Long, now: Instant) {}
        override fun save(result: AuditQueryResult, tenantId: String, queryFingerprint: String, idempotencyKey: String, audit: AuditEvent, outbox: OutboxEvent) {
            synchronized(this) { results["$tenantId:$idempotencyKey"] = queryFingerprint to result }
        }
    }

}
