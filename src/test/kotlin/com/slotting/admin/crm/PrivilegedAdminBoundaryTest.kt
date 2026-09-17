package com.slotting.admin.crm

import com.slotting.admin.auth.*
import java.io.File
import java.time.Clock
import java.time.Instant
import java.time.ZoneOffset
import java.util.UUID
import java.util.concurrent.CountDownLatch
import java.util.concurrent.Executors
import kotlin.test.*
import org.junit.jupiter.api.Test

class PrivilegedAdminBoundaryTest {
    private val now = Instant.parse("2026-09-17T18:00:00Z")
    private val clock = Clock.fixed(now, ZoneOffset.UTC)

    @Test
    fun `ADR-007-01-T001 Define privileged admin integration boundary produces the required authoritative outcome`() {
        val store = PrivilegedAdminMemoryStore()
        val service = service(store)

        // 1. Execute canonical RECORD_SUPPORT_INTERACTION through privileged admin boundary
        val cmd = command(
            subjectReference = "player-crm-001",
            operation = PrivilegedAdminOperation.RECORD_SUPPORT_INTERACTION,
            details = mapOf("channel" to "CHAT", "summary" to "Player inquired about password reset"),
            idempotencyKey = "key-crm-001",
            correlationId = "corr-crm-1",
            causationId = "cause-crm-1",
        )
        val res = service.executePrivilegedOperation(cmd)

        // Assert: Finance authority never duplicated in CRM; privileged commands audited
        assertEquals(PrivilegedExecutionStatus.EXECUTED, res.status)
        assertEquals("player-crm-001", res.subjectReference)
        assertEquals("EVID-CRM-player-crm-001", res.evidenceReference)
        assertFalse(res.financialAuthorityDuplicated) // Invariant: Finance authority never duplicated in CRM
        assertFalse(res.moneyMutated)                 // Invariant: CRM changes money is prohibited

        // 2. Replay with identical idempotency key returns identical authoritative result
        val replay = service.executePrivilegedOperation(cmd)
        assertEquals(res.resultId, replay.resultId)
        assertEquals(res.evidenceReference, replay.evidenceReference)

        // Assert: Privileged commands audited with correlation/causation tracking and no secrets
        assertEquals(1, store.audit.size)
        assertEquals("PRIVILEGED_ADMIN_RECORD_SUPPORT_INTERACTION", store.audit[0].type)
        assertFalse(store.audit[0].type.contains("secret"))
        assertEquals("corr-crm-1", store.audit[0].correlationId)
        assertEquals("cause-crm-1", store.audit[0].causationId)
    }

    @Test
    fun `ADR-007-01-T002 Define privileged admin integration boundary rejects invalid, boundary, unauthorized, and stale input`() {
        val store = PrivilegedAdminMemoryStore()
        val service = service(store)

        // CRM changes money attempt 1: direct financial adjustment operation
        assertFailsWith<AuthenticationFailure.Rejected> {
            service.executePrivilegedOperation(
                command(
                    operation = PrivilegedAdminOperation.DIRECT_FINANCIAL_ADJUSTMENT,
                    requestedAmountMinorUnits = 5000L,
                    idempotencyKey = "key-illegal-fin-adj",
                )
            )
        }.also { assertEquals(AuthErrorCode.FORBIDDEN, it.code) }

        // CRM changes money attempt 2: direct balance mutation operation
        assertFailsWith<AuthenticationFailure.Rejected> {
            service.executePrivilegedOperation(
                command(
                    operation = PrivilegedAdminOperation.DIRECT_BALANCE_MUTATION,
                    idempotencyKey = "key-illegal-balance-mut",
                )
            )
        }.also { assertEquals(AuthErrorCode.FORBIDDEN, it.code) }

        // CRM changes money attempt 3: standard operation with financial amount attached
        assertFailsWith<AuthenticationFailure.Rejected> {
            service.executePrivilegedOperation(
                command(
                    operation = PrivilegedAdminOperation.RECORD_SUPPORT_INTERACTION,
                    requestedAmountMinorUnits = 1000L,
                    idempotencyKey = "key-illegal-amount",
                )
            )
        }.also { assertEquals(AuthErrorCode.FORBIDDEN, it.code) }

        // Unauthenticated
        assertFailsWith<AuthenticationFailure.Rejected> {
            service.executePrivilegedOperation(command(principal = null, idempotencyKey = "key-unauth"))
        }.also { assertEquals(AuthErrorCode.UNAUTHENTICATED, it.code) }

        // Non-admin player
        assertFailsWith<AuthenticationFailure.Rejected> {
            service.executePrivilegedOperation(command(principal = player(), idempotencyKey = "key-player"))
        }.also { assertEquals(AuthErrorCode.FORBIDDEN, it.code) }

        // Cross-tenant admin
        assertFailsWith<AuthenticationFailure.Rejected> {
            service.executePrivilegedOperation(command(principal = admin(tenantId = "other-tenant"), idempotencyKey = "key-cross-tenant"))
        }.also { assertEquals(AuthErrorCode.FORBIDDEN, it.code) }

        // Unauthorized role: Auditor has READ_SUPPORT and READ_AUDIT, lacks MANAGE_SUPPORT
        val auditorAdmin = AuthenticatedPrincipal("admin-auditor", "tenant-1", PrincipalKind.ADMIN, setOf(AdminRole.AUDITOR))
        assertFailsWith<AuthenticationFailure.Rejected> {
            service.executePrivilegedOperation(command(principal = auditorAdmin, idempotencyKey = "key-auditor-unauth"))
        }.also { assertEquals(AuthErrorCode.FORBIDDEN, it.code) }

        // Inactive / expired session
        val expiredSessionService = PrivilegedAdminBoundaryService(AdminRbacPolicy(true), TestCrmExpiredSessionDirectory(), store, clock)
        assertFailsWith<AuthenticationFailure.Rejected> {
            expiredSessionService.executePrivilegedOperation(command(idempotencyKey = "key-expired-sess"))
        }.also { assertEquals(AuthErrorCode.FORBIDDEN, it.code) }

        // Blank subject reference
        assertFailsWith<AuthenticationFailure.Rejected> {
            service.executePrivilegedOperation(command(subjectReference = "   ", idempotencyKey = "key-blank-subj"))
        }.also { assertEquals(AuthErrorCode.INVALID, it.code) }

        // Stale expected version
        assertFailsWith<AuthenticationFailure.Rejected> {
            service.executePrivilegedOperation(command(expectedVersion = 4L, idempotencyKey = "key-stale-ver"))
        }.also { assertEquals(AuthErrorCode.STALE, it.code) }

        // Conflicting replay with different payload
        service.executePrivilegedOperation(command(idempotencyKey = "key-conflict-crm"))
        assertFailsWith<AuthenticationFailure.Rejected> {
            service.executePrivilegedOperation(command(subjectReference = "different-crm-player", idempotencyKey = "key-conflict-crm"))
        }.also { assertEquals(AuthErrorCode.CONFLICT, it.code) }
    }

    @Test
    fun `ADR-007-01-T003 Define privileged admin integration boundary survives concurrency, duplicate delivery, and dependency failure`() {
        val store = PrivilegedAdminMemoryStore()
        val service = service(store)

        // 1. Concurrency: duplicate submissions race with identical idempotency key
        val gate = CountDownLatch(1)
        val pool = Executors.newFixedThreadPool(4)
        val cmd = command(idempotencyKey = "key-concurrent-crm-001")
        val calls = (1..4).map {
            pool.submit<PrivilegedAdminResult> {
                gate.await()
                service.executePrivilegedOperation(cmd)
            }
        }
        gate.countDown()
        val outcomes = calls.map { runCatching { it.get() } }

        assertEquals(4, outcomes.count { it.isSuccess })
        val distinctResultIds = outcomes.mapNotNull { it.getOrNull()?.resultId }.toSet()
        assertEquals(1, distinctResultIds.size)

        // 2. Dependency failure on session directory -> fails closed (DEPENDENCY_UNAVAILABLE)
        val failingSessionService = PrivilegedAdminBoundaryService(AdminRbacPolicy(true), TestCrmFailingSessionDirectory(), store, clock)
        assertFailsWith<AuthenticationFailure.Rejected> {
            failingSessionService.executePrivilegedOperation(command(idempotencyKey = "key-dep-fail"))
        }.also { assertEquals(AuthErrorCode.DEPENDENCY_UNAVAILABLE, it.code) }

        pool.shutdown()
    }

    @Test
    fun `ADR-007-01-T004 Define privileged admin integration boundary remains compatible, recoverable, observable, and lifecycle-safe`() {
        // Assert: no unapproved persistence or migration introduced
        val migrationDir = File("src/main/resources/db/migration")
        val sqlFiles = migrationDir.listFiles { _, name -> name.endsWith(".sql") } ?: emptyArray()
        assertTrue(sqlFiles.isNotEmpty())
        val migrationVersions = sqlFiles.map { it.name.substringBefore("__") }
        assertTrue(!migrationVersions.contains("V17"))

        // Assert: restart/recreation preserves consistency
        val store = PrivilegedAdminMemoryStore()
        val service = service(store)

        val cmd = command(
            subjectReference = "player-crm-reboot-001",
            idempotencyKey = "key-reboot-crm",
            correlationId = "corr-reboot-crm-1",
            causationId = "cause-reboot-crm-1",
        )
        val first = service.executePrivilegedOperation(cmd)

        val restartedService = service(store)
        val second = restartedService.executePrivilegedOperation(cmd)

        assertEquals(first.resultId, second.resultId)
        assertEquals(first.evidenceReference, second.evidenceReference)
        assertFalse(second.financialAuthorityDuplicated)
        assertFalse(second.moneyMutated)

        // Observability check
        assertEquals(1, store.audit.size)
        assertEquals("PRIVILEGED_ADMIN_RECORD_SUPPORT_INTERACTION", store.audit[0].type)
        assertEquals("corr-reboot-crm-1", store.audit[0].correlationId)
        assertEquals("cause-reboot-crm-1", store.audit[0].causationId)
        assertFalse(store.audit[0].type.contains("secret"))
    }

    private fun service(store: PrivilegedAdminBoundaryStore) =
        PrivilegedAdminBoundaryService(AdminRbacPolicy(true), TestCrmActiveSessionDirectory(), store, clock)

    private fun command(
        principal: AuthenticatedPrincipal? = admin(),
        subjectReference: String = "player-crm-001",
        operation: PrivilegedAdminOperation = PrivilegedAdminOperation.RECORD_SUPPORT_INTERACTION,
        details: Map<String, String> = emptyMap(),
        requestedAmountMinorUnits: Long? = null,
        idempotencyKey: String = "key-crm-cmd-001",
        correlationId: String = "corr-crm-default",
        causationId: String = "cause-crm-default",
        expectedVersion: Long = 1L,
    ) = PrivilegedAdminCommand(
        principal = principal,
        sessionId = "session-crm-1",
        tenantId = "tenant-1",
        subjectReference = subjectReference,
        operation = operation,
        details = details,
        requestedAmountMinorUnits = requestedAmountMinorUnits,
        idempotencyKey = idempotencyKey,
        correlationId = correlationId,
        causationId = causationId,
        expectedVersion = expectedVersion,
    )

    private fun admin(tenantId: String = "tenant-1") =
        AuthenticatedPrincipal("admin-crm-1", tenantId, PrincipalKind.ADMIN, setOf(AdminRole.SUPPORT))

    private fun player() =
        AuthenticatedPrincipal("player-crm-1", "tenant-1", PrincipalKind.PLAYER, emptySet())
}

private class TestCrmActiveSessionDirectory : AdminSessionDirectory {
    override fun find(tenantId: String, principalId: String, sessionId: String) =
        if (tenantId == "tenant-1" && sessionId == "session-crm-1")
            AdminSessionStatus(true, false, Instant.parse("2026-09-17T19:00:00Z"))
        else null
}

private class TestCrmExpiredSessionDirectory : AdminSessionDirectory {
    override fun find(tenantId: String, principalId: String, sessionId: String) =
        AdminSessionStatus(false, false, Instant.parse("2026-09-17T17:00:00Z"))
}

private class TestCrmFailingSessionDirectory : AdminSessionDirectory {
    override fun find(tenantId: String, principalId: String, sessionId: String): AdminSessionStatus =
        error("session directory failure")
}

private class PrivilegedAdminMemoryStore : PrivilegedAdminBoundaryStore {
    val results = mutableMapOf<String, Pair<String, PrivilegedAdminResult>>()
    val audit = mutableListOf<AuditEvent>()
    val outbox = mutableListOf<OutboxEvent>()

    override fun findByIdempotency(tenantId: String, idempotencyKey: String) =
        synchronized(this) { results["$tenantId:$idempotencyKey"] }

    override fun save(
        result: PrivilegedAdminResult,
        tenantId: String,
        queryFingerprint: String,
        idempotencyKey: String,
        audit: AuditEvent,
        outbox: OutboxEvent,
    ) = synchronized(this) {
        results["$tenantId:$idempotencyKey"] = queryFingerprint to result
        this.audit += audit
        this.outbox += outbox
    }
}
