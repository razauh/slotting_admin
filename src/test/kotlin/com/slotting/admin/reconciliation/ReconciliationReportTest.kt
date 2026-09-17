package com.slotting.admin.reconciliation

import com.slotting.admin.auth.*
import java.time.Clock
import java.time.Instant
import java.time.ZoneOffset
import java.util.concurrent.CountDownLatch
import java.util.concurrent.Executors
import kotlin.test.*
import org.junit.jupiter.api.Test

class ReconciliationReportTest {
    private val now = Instant.parse("2026-09-17T10:00:00Z")
    private val clock = Clock.fixed(now, ZoneOffset.UTC)

    @Test
    fun `ADMIN-006-01-T001 Publish reconciliation reports produces the required authoritative outcome`() {
        val store = ReconciliationMemoryStore()
        val service = service(store)

        // 1. Generate balanced report: ledger debits == credits, checksum calculated
        val balanced = service.operate(
            command(
                action = ReconciliationAction.GENERATE,
                reportReference = "REC-2026-09-17-01",
                totalLedgerDebits = 500000L,
                totalLedgerCredits = 500000L,
                totalExternalDebits = 500000L,
                totalExternalCredits = 500000L,
            )
        )
        assertEquals(ReconciliationStatus.BALANCED, balanced.report.status)
        assertEquals(0L, balanced.report.imbalanceAmount)
        assertTrue(balanced.report.exportChecksumSha256.isNotBlank())
        assertFalse(balanced.report.exportChecksumSha256.contains("secret"))

        // 2. Generate imbalanced report: ledger debits != credits
        val imbalanced = service.operate(
            command(
                action = ReconciliationAction.GENERATE,
                reportReference = "REC-2026-09-17-02",
                totalLedgerDebits = 500000L,
                totalLedgerCredits = 450000L,
                totalExternalDebits = 500000L,
                totalExternalCredits = 500000L,
                idempotencyKey = "key-gen-imbal",
            )
        )
        assertEquals(ReconciliationStatus.IMBALANCED, imbalanced.report.status)
        assertEquals(50000L, imbalanced.report.imbalanceAmount)

        // 3. Ledger imbalance cannot be waived: attempting WAIVE is rejected
        assertFailsWith<AuthenticationFailure.Rejected> {
            service.operate(
                command(
                    action = ReconciliationAction.WAIVE,
                    reportReference = "REC-2026-09-17-02",
                    expectedVersion = imbalanced.report.serverVersion,
                    idempotencyKey = "key-waive-fail",
                )
            )
        }.also { assertEquals(AuthErrorCode.FORBIDDEN, it.code) }

        // 4. Resolve / close mismatch with explicit reason, notes, and approver
        val resolved = service.operate(
            command(
                action = ReconciliationAction.CLOSE_MISMATCH,
                reportReference = "REC-2026-09-17-02",
                expectedVersion = imbalanced.report.serverVersion,
                reasonCode = "SETTLEMENT_TIMING_LAG",
                resolutionNotes = "Confirmed 500.00 EUR settlement batch posted in subsequent window",
                approverId = "admin-lead-2",
                idempotencyKey = "key-close-mismatch",
            )
        )
        assertEquals(ReconciliationStatus.RESOLVED, resolved.report.status)
        assertEquals("SETTLEMENT_TIMING_LAG", resolved.report.reasonCode)
        assertEquals("admin-lead-2", resolved.report.approverId)

        // Verify audit and outbox
        assertEquals(3, store.audit.size)
        assertEquals(3, store.outbox.size)
        assertEquals("RECONCILIATION_REPORT_GENERATE", store.audit[0].type)
        assertEquals("RECONCILIATION_REPORT_GENERATE", store.audit[1].type)
        assertEquals("RECONCILIATION_REPORT_CLOSE_MISMATCH", store.audit[2].type)
        assertEquals("corr-rec-1", store.audit[0].correlationId)
        assertEquals("cause-rec-1", store.audit[0].causationId)
    }

    @Test
    fun `ADMIN-006-01-T002 Publish reconciliation reports rejects invalid, boundary, unauthorized, and stale input`() {
        val store = ReconciliationMemoryStore()
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

        // Mismatch close without reason
        val imbalanced = service.operate(
            command(
                action = ReconciliationAction.GENERATE,
                reportReference = "REC-IMBAL-01",
                totalLedgerDebits = 2000L,
                totalLedgerCredits = 1000L,
                totalExternalDebits = 2000L,
                totalExternalCredits = 2000L,
                idempotencyKey = "key-gen-imb-2",
            )
        )
        assertFailsWith<AuthenticationFailure.Rejected> {
            service.operate(
                command(
                    action = ReconciliationAction.CLOSE_MISMATCH,
                    reportReference = "REC-IMBAL-01",
                    expectedVersion = imbalanced.report.serverVersion,
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
                    action = ReconciliationAction.CLOSE_MISMATCH,
                    reportReference = "REC-IMBAL-01",
                    expectedVersion = imbalanced.report.serverVersion,
                    reasonCode = "SETTLEMENT_LAG",
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
                    action = ReconciliationAction.CLOSE_MISMATCH,
                    reportReference = "REC-IMBAL-01",
                    expectedVersion = imbalanced.report.serverVersion,
                    reasonCode = "SETTLEMENT_LAG",
                    resolutionNotes = "Valid note",
                    approverId = null, // missing approver
                    idempotencyKey = "key-close-no-approver",
                )
            )
        }.also { assertEquals(AuthErrorCode.INVALID, it.code) }

        // Invalid boundaries
        assertFailsWith<AuthenticationFailure.Rejected> { service.operate(command(reportReference = "")) }
            .also { assertEquals(AuthErrorCode.INVALID, it.code) }
        assertFailsWith<AuthenticationFailure.Rejected> { service.operate(command(currencyCode = "invalid")) }
            .also { assertEquals(AuthErrorCode.INVALID, it.code) }
        assertFailsWith<AuthenticationFailure.Rejected> {
            service.operate(command(periodStart = now, periodEnd = now.minusSeconds(60)))
        }.also { assertEquals(AuthErrorCode.INVALID, it.code) }
        assertFailsWith<AuthenticationFailure.Rejected> { service.operate(command(totalLedgerDebits = -1L)) }
            .also { assertEquals(AuthErrorCode.INVALID, it.code) }

        // Stale expected version
        assertFailsWith<AuthenticationFailure.Rejected> {
            service.operate(
                command(
                    action = ReconciliationAction.CLOSE_MISMATCH,
                    reportReference = "REC-IMBAL-01",
                    expectedVersion = 99,
                    reasonCode = "REASON",
                    resolutionNotes = "Notes",
                    approverId = "admin-2",
                    idempotencyKey = "stale-close",
                )
            )
        }.also { assertEquals(AuthErrorCode.STALE, it.code) }
    }

    @Test
    fun `ADMIN-006-01-T003 Publish reconciliation reports survives concurrency, duplicate delivery, and dependency failure`() {
        val store = ReconciliationMemoryStore()
        val service = service(store)
        val gate = CountDownLatch(1)
        val pool = Executors.newFixedThreadPool(2)
        val calls = (1..2).map {
            pool.submit<ReconciliationReportResult> {
                gate.await()
                service.operate(command(action = ReconciliationAction.GENERATE, idempotencyKey = "race-gen-rec"))
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
                    action = ReconciliationAction.GENERATE,
                    currencyCode = "USD",
                    idempotencyKey = "race-gen-rec",
                )
            )
        }.also { assertEquals(AuthErrorCode.CONFLICT, it.code) }

        // Stale version rejected
        assertFailsWith<AuthenticationFailure.Rejected> {
            service.operate(
                command(
                    action = ReconciliationAction.CLOSE_MISMATCH,
                    reportReference = "REC-01",
                    expectedVersion = 0,
                    reasonCode = "REASON",
                    resolutionNotes = "Notes",
                    approverId = "approver-1",
                    idempotencyKey = "stale-close-rec",
                )
            )
        }.also { assertEquals(AuthErrorCode.FORBIDDEN, it.code) }

        // Dependency failure
        assertFailsWith<AuthenticationFailure.Rejected> {
            serviceWithDependencyFailure(store).operate(
                command(
                    action = ReconciliationAction.GENERATE,
                    idempotencyKey = "dep-gen-rec",
                )
            )
        }.also { assertEquals(AuthErrorCode.DEPENDENCY_UNAVAILABLE, it.code) }
    }

    @Test
    fun `ADMIN-006-01-T004 Publish reconciliation reports remains compatible, recoverable, observable, and lifecycle-safe`() {
        val migration = java.io.File("src/main/resources/db/migration/V14__reconciliation_report.sql").readText()
        assertTrue(migration.contains("admin_reconciliation_report"))
        assertTrue(migration.contains("admin_reconciliation_report_result"))
        assertTrue(migration.contains("imbalance_amount"))
        assertTrue(migration.contains("checksum_sha256"))
        assertTrue(migration.contains("foreign key"))
        assertTrue(!migration.contains("update admin_"))
    }

    private fun service(store: ReconciliationMemoryStore) =
        ReconciliationReportService(AdminRbacPolicy(true), ActiveReconciliationSessionDirectory(), store, clock)

    private fun serviceWithDependencyFailure(store: ReconciliationMemoryStore) =
        ReconciliationReportService(AdminRbacPolicy(true), FailingReconciliationSessionDirectory(), store, clock)

    private fun command(
        principal: AuthenticatedPrincipal? = admin(),
        reportReference: String = "REC-2026-09-17-01",
        action: ReconciliationAction = ReconciliationAction.GENERATE,
        currencyCode: String = "EUR",
        periodStart: Instant = now.minusSeconds(86400),
        periodEnd: Instant = now,
        totalLedgerDebits: Long = 100000L,
        totalLedgerCredits: Long = 100000L,
        totalExternalDebits: Long = 100000L,
        totalExternalCredits: Long = 100000L,
        reasonCode: String? = null,
        resolutionNotes: String? = null,
        approverId: String? = null,
        expectedVersion: Long = 0L,
        idempotencyKey: String = "key-rec-${action.name}",
        sessionId: String = "session-rec-1",
        correlationId: String = "corr-rec-1",
        causationId: String = "cause-rec-1",
    ) = ReconciliationReportCommand(
        principal,
        sessionId,
        "tenant-1",
        reportReference,
        action,
        currencyCode,
        periodStart,
        periodEnd,
        totalLedgerDebits,
        totalLedgerCredits,
        totalExternalDebits,
        totalExternalCredits,
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

private class ActiveReconciliationSessionDirectory : AdminSessionDirectory {
    override fun find(tenantId: String, principalId: String, sessionId: String) =
        if (tenantId == "tenant-1" && principalId == "admin-1" && sessionId == "session-rec-1")
            AdminSessionStatus(true, false, Instant.parse("2026-09-17T18:00:00Z"))
        else null
}

private class FailingReconciliationSessionDirectory : AdminSessionDirectory {
    override fun find(tenantId: String, principalId: String, sessionId: String): AdminSessionStatus =
        error("session dependency unavailable")
}

private class ReconciliationMemoryStore : ReconciliationReportStore {
    val items = mutableMapOf<String, ReconciliationReport>()
    val results = mutableMapOf<String, Pair<String, ReconciliationReportResult>>()
    val audit = mutableListOf<AuditEvent>()
    val outbox = mutableListOf<OutboxEvent>()

    override fun findByIdempotency(tenantId: String, key: String) = synchronized(this) { results["$tenantId:$key"] }
    override fun findReport(tenantId: String, reportReference: String) = synchronized(this) { items["$tenantId:$reportReference"] }
    override fun save(
        result: ReconciliationReportResult,
        tenantId: String,
        queryFingerprint: String,
        idempotencyKey: String,
        audit: AuditEvent,
        outbox: OutboxEvent,
    ) = synchronized(this) {
        items["$tenantId:${result.report.reportReference}"] = result.report
        results["$tenantId:$idempotencyKey"] = queryFingerprint to result
        this.audit += audit
        this.outbox += outbox
    }
}
