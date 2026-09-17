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

class NonAuthoritativeCrmBoundaryTest {
    private val now = Instant.parse("2026-09-17T18:00:00Z")
    private val clock = Clock.fixed(now, ZoneOffset.UTC)

    @Test
    fun `ADR-007-02-T001 Define non-authoritative CRM integration boundary produces the required authoritative outcome`() {
        val store = NonAuthoritativeCrmMemoryStore()
        val service = service(store)

        // 1. Execute canonical SYNC_CUSTOMER_PROFILE through non-authoritative CRM integration boundary
        val cmd = command(
            subjectReference = "player-crm-sync-001",
            operation = CrmIntegrationOperation.SYNC_CUSTOMER_PROFILE,
            externalCrmId = "CRM-EXT-9912",
            payload = mapOf("preferredChannel" to "EMAIL", "marketingSegment" to "VIP_SILVER"),
            idempotencyKey = "key-crm-sync-001",
            correlationId = "corr-crm-sync-1",
            causationId = "cause-crm-sync-1",
        )
        val res = service.processCrmSync(cmd)

        // Assert: Finance authority never duplicated in CRM; privileged commands audited
        assertEquals(CrmSyncStatus.SYNCHRONIZED, res.status)
        assertEquals("player-crm-sync-001", res.subjectReference)
        assertEquals("CRM-EXT-9912", res.externalCrmId)
        assertEquals("EVID-CRM-SYNC-player-crm-sync-001", res.evidenceReference)
        assertFalse(res.isAuthoritative)              // Invariant: CRM is non-authoritative
        assertFalse(res.financialAuthorityDuplicated) // Invariant: Finance authority never duplicated in CRM
        assertFalse(res.moneyMutated)                 // Invariant: CRM changes money is prohibited

        // 2. Replay with identical idempotency key returns identical authoritative result
        val replay = service.processCrmSync(cmd)
        assertEquals(res.resultId, replay.resultId)
        assertEquals(res.evidenceReference, replay.evidenceReference)

        // Assert: Privileged commands audited with correlation/causation tracking and no secrets
        assertEquals(1, store.audit.size)
        assertEquals("CRM_NON_AUTHORITATIVE_SYNC_SYNC_CUSTOMER_PROFILE", store.audit[0].type)
        assertFalse(store.audit[0].type.contains("secret"))
        assertEquals("corr-crm-sync-1", store.audit[0].correlationId)
        assertEquals("cause-crm-sync-1", store.audit[0].causationId)
    }

    @Test
    fun `ADR-007-02-T002 Define non-authoritative CRM integration boundary rejects invalid, boundary, unauthorized, and stale input`() {
        val store = NonAuthoritativeCrmMemoryStore()
        val service = service(store)

        // CRM changes money attempt 1: direct financial sync operation
        assertFailsWith<AuthenticationFailure.Rejected> {
            service.processCrmSync(
                command(
                    operation = CrmIntegrationOperation.DIRECT_FINANCIAL_SYNC,
                    financialBalanceMinorUnits = 10000L,
                    idempotencyKey = "key-illegal-fin-sync",
                )
            )
        }.also { assertEquals(AuthErrorCode.FORBIDDEN, it.code) }

        // CRM changes money attempt 2: credit wallet adjustment operation
        assertFailsWith<AuthenticationFailure.Rejected> {
            service.processCrmSync(
                command(
                    operation = CrmIntegrationOperation.CREDIT_WALLET_ADJUSTMENT,
                    financialBalanceMinorUnits = 2500L,
                    idempotencyKey = "key-illegal-wallet-adj",
                )
            )
        }.also { assertEquals(AuthErrorCode.FORBIDDEN, it.code) }

        // CRM changes money attempt 3: standard operation with financial balance attached
        assertFailsWith<AuthenticationFailure.Rejected> {
            service.processCrmSync(
                command(
                    operation = CrmIntegrationOperation.SYNC_CUSTOMER_PROFILE,
                    financialBalanceMinorUnits = 5000L,
                    idempotencyKey = "key-illegal-balance-attached",
                )
            )
        }.also { assertEquals(AuthErrorCode.FORBIDDEN, it.code) }

        // Unauthenticated
        assertFailsWith<AuthenticationFailure.Rejected> {
            service.processCrmSync(command(principal = null, idempotencyKey = "key-unauth"))
        }.also { assertEquals(AuthErrorCode.UNAUTHENTICATED, it.code) }

        // Non-admin player
        assertFailsWith<AuthenticationFailure.Rejected> {
            service.processCrmSync(command(principal = player(), idempotencyKey = "key-player"))
        }.also { assertEquals(AuthErrorCode.FORBIDDEN, it.code) }

        // Cross-tenant admin
        assertFailsWith<AuthenticationFailure.Rejected> {
            service.processCrmSync(command(principal = admin(tenantId = "other-tenant"), idempotencyKey = "key-cross-tenant"))
        }.also { assertEquals(AuthErrorCode.FORBIDDEN, it.code) }

        // Inactive / expired session
        val expiredSessionService = NonAuthoritativeCrmBoundaryService(AdminRbacPolicy(true), TestNonAuthCrmExpiredSessionDirectory(), store, clock)
        assertFailsWith<AuthenticationFailure.Rejected> {
            expiredSessionService.processCrmSync(command(idempotencyKey = "key-expired-sess"))
        }.also { assertEquals(AuthErrorCode.FORBIDDEN, it.code) }

        // Blank subject reference
        assertFailsWith<AuthenticationFailure.Rejected> {
            service.processCrmSync(command(subjectReference = "   ", idempotencyKey = "key-blank-subj"))
        }.also { assertEquals(AuthErrorCode.INVALID, it.code) }

        // Blank external CRM ID
        assertFailsWith<AuthenticationFailure.Rejected> {
            service.processCrmSync(command(externalCrmId = "   ", idempotencyKey = "key-blank-crm-id"))
        }.also { assertEquals(AuthErrorCode.INVALID, it.code) }

        // Stale expected version
        assertFailsWith<AuthenticationFailure.Rejected> {
            service.processCrmSync(command(expectedVersion = 5L, idempotencyKey = "key-stale-ver"))
        }.also { assertEquals(AuthErrorCode.STALE, it.code) }

        // Conflicting replay with different payload
        service.processCrmSync(command(idempotencyKey = "key-conflict-sync"))
        assertFailsWith<AuthenticationFailure.Rejected> {
            service.processCrmSync(command(externalCrmId = "DIFFERENT-CRM-ID", idempotencyKey = "key-conflict-sync"))
        }.also { assertEquals(AuthErrorCode.CONFLICT, it.code) }
    }

    @Test
    fun `ADR-007-02-T003 Define non-authoritative CRM integration boundary survives concurrency, duplicate delivery, and dependency failure`() {
        val store = NonAuthoritativeCrmMemoryStore()
        val service = service(store)

        // 1. Concurrency: duplicate submissions race with identical idempotency key
        val gate = CountDownLatch(1)
        val pool = Executors.newFixedThreadPool(4)
        val cmd = command(idempotencyKey = "key-concurrent-sync-001")
        val calls = (1..4).map {
            pool.submit<CrmSyncResult> {
                gate.await()
                service.processCrmSync(cmd)
            }
        }
        gate.countDown()
        val outcomes = calls.map { runCatching { it.get() } }

        assertEquals(4, outcomes.count { it.isSuccess })
        val distinctResultIds = outcomes.mapNotNull { it.getOrNull()?.resultId }.toSet()
        assertEquals(1, distinctResultIds.size)

        // 2. Dependency failure on session directory -> fails closed (DEPENDENCY_UNAVAILABLE)
        val failingSessionService = NonAuthoritativeCrmBoundaryService(AdminRbacPolicy(true), TestNonAuthCrmFailingSessionDirectory(), store, clock)
        assertFailsWith<AuthenticationFailure.Rejected> {
            failingSessionService.processCrmSync(command(idempotencyKey = "key-dep-fail"))
        }.also { assertEquals(AuthErrorCode.DEPENDENCY_UNAVAILABLE, it.code) }

        pool.shutdown()
    }

    @Test
    fun `ADR-007-02-T004 Define non-authoritative CRM integration boundary remains compatible, recoverable, observable, and lifecycle-safe`() {
        // Assert: no unapproved persistence or migration introduced
        val migrationDir = File("src/main/resources/db/migration")
        val sqlFiles = migrationDir.listFiles { _, name -> name.endsWith(".sql") } ?: emptyArray()
        assertTrue(sqlFiles.isNotEmpty())
        val migrationVersions = sqlFiles.map { it.name.substringBefore("__") }
        assertTrue(!migrationVersions.contains("V17"))

        // Assert: restart/recreation preserves consistency
        val store = NonAuthoritativeCrmMemoryStore()
        val service = service(store)

        val cmd = command(
            subjectReference = "player-crm-reboot-sync-001",
            idempotencyKey = "key-reboot-sync",
            correlationId = "corr-reboot-sync-1",
            causationId = "cause-reboot-sync-1",
        )
        val first = service.processCrmSync(cmd)

        val restartedService = service(store)
        val second = restartedService.processCrmSync(cmd)

        assertEquals(first.resultId, second.resultId)
        assertEquals(first.evidenceReference, second.evidenceReference)
        assertFalse(second.isAuthoritative)
        assertFalse(second.financialAuthorityDuplicated)
        assertFalse(second.moneyMutated)

        // Observability check
        assertEquals(1, store.audit.size)
        assertEquals("CRM_NON_AUTHORITATIVE_SYNC_SYNC_CUSTOMER_PROFILE", store.audit[0].type)
        assertEquals("corr-reboot-sync-1", store.audit[0].correlationId)
        assertEquals("cause-reboot-sync-1", store.audit[0].causationId)
        assertFalse(store.audit[0].type.contains("secret"))
    }

    private fun service(store: NonAuthoritativeCrmStore) =
        NonAuthoritativeCrmBoundaryService(AdminRbacPolicy(true), TestNonAuthCrmActiveSessionDirectory(), store, clock)

    private fun command(
        principal: AuthenticatedPrincipal? = admin(),
        subjectReference: String = "player-crm-sync-001",
        operation: CrmIntegrationOperation = CrmIntegrationOperation.SYNC_CUSTOMER_PROFILE,
        externalCrmId: String = "CRM-EXT-9912",
        payload: Map<String, String> = emptyMap(),
        financialBalanceMinorUnits: Long? = null,
        idempotencyKey: String = "key-crm-sync-cmd-001",
        correlationId: String = "corr-crm-sync-default",
        causationId: String = "cause-crm-sync-default",
        expectedVersion: Long = 1L,
    ) = CrmSyncCommand(
        principal = principal,
        sessionId = "session-crm-sync-1",
        tenantId = "tenant-1",
        subjectReference = subjectReference,
        operation = operation,
        externalCrmId = externalCrmId,
        payload = payload,
        financialBalanceMinorUnits = financialBalanceMinorUnits,
        idempotencyKey = idempotencyKey,
        correlationId = correlationId,
        causationId = causationId,
        expectedVersion = expectedVersion,
    )

    private fun admin(tenantId: String = "tenant-1") =
        AuthenticatedPrincipal("admin-crm-sync-1", tenantId, PrincipalKind.ADMIN, setOf(AdminRole.SUPPORT))

    private fun player() =
        AuthenticatedPrincipal("player-crm-sync-1", "tenant-1", PrincipalKind.PLAYER, emptySet())
}

private class TestNonAuthCrmActiveSessionDirectory : AdminSessionDirectory {
    override fun find(tenantId: String, principalId: String, sessionId: String) =
        if (tenantId == "tenant-1" && sessionId == "session-crm-sync-1")
            AdminSessionStatus(true, false, Instant.parse("2026-09-17T19:00:00Z"))
        else null
}

private class TestNonAuthCrmExpiredSessionDirectory : AdminSessionDirectory {
    override fun find(tenantId: String, principalId: String, sessionId: String) =
        AdminSessionStatus(false, false, Instant.parse("2026-09-17T17:00:00Z"))
}

private class TestNonAuthCrmFailingSessionDirectory : AdminSessionDirectory {
    override fun find(tenantId: String, principalId: String, sessionId: String): AdminSessionStatus =
        error("session directory failure")
}

private class NonAuthoritativeCrmMemoryStore : NonAuthoritativeCrmStore {
    val results = mutableMapOf<String, Pair<String, CrmSyncResult>>()
    val audit = mutableListOf<AuditEvent>()
    val outbox = mutableListOf<OutboxEvent>()

    override fun findByIdempotency(tenantId: String, idempotencyKey: String) =
        synchronized(this) { results["$tenantId:$idempotencyKey"] }

    override fun save(
        result: CrmSyncResult,
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
