package com.slotting.admin.reconciliation

import com.slotting.admin.auth.*
import java.time.Clock
import java.time.Instant
import java.time.ZoneOffset
import java.util.concurrent.CountDownLatch
import java.util.concurrent.Executors
import kotlin.test.*
import org.junit.jupiter.api.Test

class ReconciliationExceptionTest {
    private val now = Instant.parse("2026-09-17T10:00:00Z")
    private val clock = Clock.fixed(now, ZoneOffset.UTC)

    @Test
    fun `ADMIN-006-02-T001 Assign and close reconciliation exceptions produces the required authoritative outcome`() {
        val store = ExceptionMemoryStore()
        val service = service(store)

        // 1. Create exception record
        val created = service.operate(
            command(
                action = ReconciliationExceptionAction.CREATE,
                exceptionReference = "EXC-2026-09-17-001",
                reportReference = "REC-2026-09-17-01",
                discrepancyMinorUnits = 50000L,
            )
        )
        assertEquals(ReconciliationExceptionState.OPEN, created.exception.state)
        assertEquals(50000L, created.exception.discrepancyMinorUnits)
        assertTrue(created.exception.exportChecksumSha256.isNotBlank())
        assertFalse(created.exception.exportChecksumSha256.contains("secret"))

        // 2. Assign exception to analyst
        val assigned = service.operate(
            command(
                action = ReconciliationExceptionAction.ASSIGN,
                exceptionReference = "EXC-2026-09-17-001",
                expectedVersion = created.exception.serverVersion,
                assigneeId = "analyst-42",
                idempotencyKey = "key-assign-exc",
            )
        )
        assertEquals(ReconciliationExceptionState.ASSIGNED, assigned.exception.state)
        assertEquals("analyst-42", assigned.exception.assigneeId)

        // 3. Ledger imbalance cannot be waived: attempting WAIVE fails
        assertFailsWith<AuthenticationFailure.Rejected> {
            service.operate(
                command(
                    action = ReconciliationExceptionAction.WAIVE,
                    exceptionReference = "EXC-2026-09-17-001",
                    expectedVersion = assigned.exception.serverVersion,
                    idempotencyKey = "key-waive-exc-fail",
                )
            )
        }.also { assertEquals(AuthErrorCode.FORBIDDEN, it.code) }

        // 4. Close exception with explicit reason, notes, and dual approver
        val closed = service.operate(
            command(
                action = ReconciliationExceptionAction.CLOSE,
                exceptionReference = "EXC-2026-09-17-001",
                expectedVersion = assigned.exception.serverVersion,
                reasonCode = "PROVIDER_SETTLEMENT_ADJUSTMENT",
                resolutionNotes = "Settlement difference credited by provider invoice INV-990",
                approverId = "admin-lead-5",
                idempotencyKey = "key-close-exc",
            )
        )
        assertEquals(ReconciliationExceptionState.CLOSED, closed.exception.state)
        assertEquals("PROVIDER_SETTLEMENT_ADJUSTMENT", closed.exception.reasonCode)
        assertEquals("admin-lead-5", closed.exception.approverId)

        // Verify audit and outbox
        assertEquals(3, store.audit.size)
        assertEquals(3, store.outbox.size)
        assertEquals("RECONCILIATION_EXCEPTION_CREATE", store.audit[0].type)
        assertEquals("RECONCILIATION_EXCEPTION_ASSIGN", store.audit[1].type)
        assertEquals("RECONCILIATION_EXCEPTION_CLOSE", store.audit[2].type)
        assertEquals("corr-exc-1", store.audit[0].correlationId)
        assertEquals("cause-exc-1", store.audit[0].causationId)
    }

    @Test
    fun `ADMIN-006-02-T002 Assign and close reconciliation exceptions rejects invalid, boundary, unauthorized, and stale input`() {
        val store = ExceptionMemoryStore()
        val service = service(store)

        // Unauthenticated
        assertFailsWith<AuthenticationFailure.Rejected> { service.operate(command(principal = null)) }
            .also { assertEquals(AuthErrorCode.UNAUTHENTICATED, it.code) }

        // Non-admin player
        assertFailsWith<AuthenticationFailure.Rejected> { service.operate(command(principal = player())) }
            .also { assertEquals(AuthErrorCode.FORBIDDEN, it.code) }

        // Cross-tenant
        assertFailsWith<AuthenticationFailure.Rejected> { service.operate(command(principal = admin(tenantId = "tenant-other"))) }
            .also { assertEquals(AuthErrorCode.FORBIDDEN, it.code) }

        val created = service.operate(command(action = ReconciliationExceptionAction.CREATE))

        // Mismatch close without reason
        assertFailsWith<AuthenticationFailure.Rejected> {
            service.operate(
                command(
                    action = ReconciliationExceptionAction.CLOSE,
                    exceptionReference = created.exception.exceptionReference,
                    expectedVersion = created.exception.serverVersion,
                    reasonCode = null, // missing reason
                    resolutionNotes = "some notes",
                    approverId = "admin-lead",
                    idempotencyKey = "key-close-no-reason",
                )
            )
        }.also { assertEquals(AuthErrorCode.INVALID, it.code) }

        assertFailsWith<AuthenticationFailure.Rejected> {
            service.operate(
                command(
                    action = ReconciliationExceptionAction.CLOSE,
                    exceptionReference = created.exception.exceptionReference,
                    expectedVersion = created.exception.serverVersion,
                    reasonCode = "REASON",
                    resolutionNotes = "   ", // blank notes
                    approverId = "admin-lead",
                    idempotencyKey = "key-close-blank-notes",
                )
            )
        }.also { assertEquals(AuthErrorCode.INVALID, it.code) }

        // Mismatch close without approver
        assertFailsWith<AuthenticationFailure.Rejected> {
            service.operate(
                command(
                    action = ReconciliationExceptionAction.CLOSE,
                    exceptionReference = created.exception.exceptionReference,
                    expectedVersion = created.exception.serverVersion,
                    reasonCode = "REASON",
                    resolutionNotes = "notes",
                    approverId = null, // missing approver
                    idempotencyKey = "key-close-no-approver",
                )
            )
        }.also { assertEquals(AuthErrorCode.INVALID, it.code) }

        // Assign without assigneeId
        assertFailsWith<AuthenticationFailure.Rejected> {
            service.operate(
                command(
                    action = ReconciliationExceptionAction.ASSIGN,
                    exceptionReference = created.exception.exceptionReference,
                    expectedVersion = created.exception.serverVersion,
                    assigneeId = "   ",
                    idempotencyKey = "key-assign-blank",
                )
            )
        }.also { assertEquals(AuthErrorCode.INVALID, it.code) }

        // Invalid boundaries
        assertFailsWith<AuthenticationFailure.Rejected> {
            service.operate(command(exceptionReference = "", idempotencyKey = "key-inv-ref"))
        }.also { assertEquals(AuthErrorCode.INVALID, it.code) }
        assertFailsWith<AuthenticationFailure.Rejected> {
            service.operate(command(currencyCode = "invalid", idempotencyKey = "key-inv-curr"))
        }.also { assertEquals(AuthErrorCode.INVALID, it.code) }
        assertFailsWith<AuthenticationFailure.Rejected> {
            service.operate(command(discrepancyMinorUnits = -1L, idempotencyKey = "key-inv-disc"))
        }.also { assertEquals(AuthErrorCode.INVALID, it.code) }

        // Stale expected version
        assertFailsWith<AuthenticationFailure.Rejected> {
            service.operate(
                command(
                    action = ReconciliationExceptionAction.CLOSE,
                    exceptionReference = created.exception.exceptionReference,
                    expectedVersion = 99,
                    reasonCode = "REASON",
                    resolutionNotes = "Notes",
                    approverId = "admin-2",
                    idempotencyKey = "stale-close-exc",
                )
            )
        }.also { assertEquals(AuthErrorCode.STALE, it.code) }
    }

    @Test
    fun `ADMIN-006-02-T003 Assign and close reconciliation exceptions survives concurrency, duplicate delivery, and dependency failure`() {
        val store = ExceptionMemoryStore()
        val service = service(store)
        val gate = CountDownLatch(1)
        val pool = Executors.newFixedThreadPool(2)
        val calls = (1..2).map {
            pool.submit<ReconciliationExceptionResult> {
                gate.await()
                service.operate(command(action = ReconciliationExceptionAction.CREATE, idempotencyKey = "race-create-exc"))
            }
        }
        gate.countDown()
        val outcomes = calls.map { runCatching { it.get() } }
        pool.shutdown()

        assertEquals(2, outcomes.count { it.isSuccess })
        assertEquals(1, outcomes.mapNotNull { it.getOrNull() }.distinctBy { it.resultId }.size)
        assertEquals(1, store.audit.size)
        assertEquals(1, store.outbox.size)

        // Conflicting replay with different payload
        assertFailsWith<AuthenticationFailure.Rejected> {
            service.operate(
                command(
                    action = ReconciliationExceptionAction.CREATE,
                    currencyCode = "USD",
                    idempotencyKey = "race-create-exc",
                )
            )
        }.also { assertEquals(AuthErrorCode.CONFLICT, it.code) }

        // Stale version rejected
        assertFailsWith<AuthenticationFailure.Rejected> {
            service.operate(
                command(
                    action = ReconciliationExceptionAction.CLOSE,
                    exceptionReference = "EXC-01",
                    expectedVersion = 0,
                    reasonCode = "REASON",
                    resolutionNotes = "Notes",
                    approverId = "approver-1",
                    idempotencyKey = "stale-close-exc-race",
                )
            )
        }.also { assertEquals(AuthErrorCode.FORBIDDEN, it.code) }

        // Dependency failure
        assertFailsWith<AuthenticationFailure.Rejected> {
            serviceWithDependencyFailure(store).operate(
                command(
                    action = ReconciliationExceptionAction.CREATE,
                    idempotencyKey = "dep-create-exc",
                )
            )
        }.also { assertEquals(AuthErrorCode.DEPENDENCY_UNAVAILABLE, it.code) }
    }

    @Test
    fun `ADMIN-006-02-T004 Assign and close reconciliation exceptions remains compatible, recoverable, observable, and lifecycle-safe`() {
        val migration = java.io.File("src/main/resources/db/migration/V15__reconciliation_exception.sql").readText()
        assertTrue(migration.contains("admin_reconciliation_exception"))
        assertTrue(migration.contains("admin_reconciliation_exception_result"))
        assertTrue(migration.contains("discrepancy_amount"))
        assertTrue(migration.contains("checksum_sha256"))
        assertTrue(migration.contains("foreign key"))
        assertTrue(!migration.contains("update admin_"))
    }

    private fun service(store: ExceptionMemoryStore) =
        ReconciliationExceptionService(AdminRbacPolicy(true), ActiveExceptionSessionDirectory(), store, clock)

    private fun serviceWithDependencyFailure(store: ExceptionMemoryStore) =
        ReconciliationExceptionService(AdminRbacPolicy(true), FailingExceptionSessionDirectory(), store, clock)

    private fun command(
        principal: AuthenticatedPrincipal? = admin(),
        exceptionReference: String = "EXC-2026-09-17-001",
        reportReference: String = "REC-2026-09-17-01",
        action: ReconciliationExceptionAction = ReconciliationExceptionAction.CREATE,
        currencyCode: String = "EUR",
        discrepancyMinorUnits: Long = 50000L,
        externalReference: String = "EXT-TXN-101",
        ledgerEntryReference: String = "LED-ENTRY-202",
        assigneeId: String? = null,
        reasonCode: String? = null,
        resolutionNotes: String? = null,
        approverId: String? = null,
        expectedVersion: Long = 0L,
        idempotencyKey: String = "key-exc-${action.name}",
        sessionId: String = "session-exc-1",
        correlationId: String = "corr-exc-1",
        causationId: String = "cause-exc-1",
    ) = ReconciliationExceptionCommand(
        principal,
        sessionId,
        "tenant-1",
        exceptionReference,
        reportReference,
        action,
        currencyCode,
        discrepancyMinorUnits,
        externalReference,
        ledgerEntryReference,
        assigneeId,
        reasonCode,
        resolutionNotes,
        approverId,
        idempotencyKey,
        correlationId,
        causationId,
        expectedVersion,
    )

    private fun admin(tenantId: String = "tenant-1") =
        AuthenticatedPrincipal("admin-1", tenantId, PrincipalKind.ADMIN, setOf(AdminRole.SUPER_ADMIN))

    private fun player() =
        AuthenticatedPrincipal("player-1", "tenant-1", PrincipalKind.PLAYER, emptySet())
}

private class ActiveExceptionSessionDirectory : AdminSessionDirectory {
    override fun find(tenantId: String, principalId: String, sessionId: String) =
        if (tenantId == "tenant-1" && principalId == "admin-1" && sessionId == "session-exc-1")
            AdminSessionStatus(true, false, Instant.parse("2026-09-17T18:00:00Z"))
        else null
}

private class FailingExceptionSessionDirectory : AdminSessionDirectory {
    override fun find(tenantId: String, principalId: String, sessionId: String): AdminSessionStatus =
        error("session dependency unavailable")
}

private class ExceptionMemoryStore : ReconciliationExceptionStore {
    val items = mutableMapOf<String, ReconciliationException>()
    val results = mutableMapOf<String, Pair<String, ReconciliationExceptionResult>>()
    val audit = mutableListOf<AuditEvent>()
    val outbox = mutableListOf<OutboxEvent>()

    override fun findByIdempotency(tenantId: String, key: String) = synchronized(this) { results["$tenantId:$key"] }
    override fun findException(tenantId: String, exceptionReference: String) = synchronized(this) { items["$tenantId:$exceptionReference"] }
    override fun save(
        result: ReconciliationExceptionResult,
        tenantId: String,
        queryFingerprint: String,
        idempotencyKey: String,
        audit: AuditEvent,
        outbox: OutboxEvent,
    ) = synchronized(this) {
        items["$tenantId:${result.exception.exceptionReference}"] = result.exception
        results["$tenantId:$idempotencyKey"] = queryFingerprint to result
        this.audit += audit
        this.outbox += outbox
    }
}
