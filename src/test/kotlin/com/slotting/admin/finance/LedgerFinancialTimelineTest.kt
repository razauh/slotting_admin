package com.slotting.admin.finance

import com.slotting.admin.auth.AdminRbacPolicy
import com.slotting.admin.auth.AdminSessionDirectory
import com.slotting.admin.auth.AdminSessionStatus
import com.slotting.admin.auth.AuditEvent
import com.slotting.admin.auth.AuthErrorCode
import com.slotting.admin.auth.AuthenticatedPrincipal
import com.slotting.admin.auth.AuthenticationFailure
import com.slotting.admin.auth.OutboxEvent
import com.slotting.admin.auth.PrincipalKind
import com.slotting.admin.player.AccessReasonCode
import org.junit.jupiter.api.Test
import java.time.Clock
import java.time.Instant
import java.time.ZoneOffset
import java.util.concurrent.CountDownLatch
import java.util.concurrent.Executors
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertTrue

class LedgerFinancialTimelineTest {
    private val now = Instant.parse("2026-09-17T10:00:00Z")
    private val clock = Clock.fixed(now, ZoneOffset.UTC)
    private val from = now.minusSeconds(3600)
    private val to = now

    @Test
    fun `ADMIN-002-02-T001 Provide ledger-linked financial timeline produces authoritative outcome`() {
        val store = TimelineMemoryStore()
        val result = service(store).read(command())

        assertEquals(TimelineState.FOUND, result.state)
        assertEquals("ledger-entry-1", result.entries.single().ledgerEntryId)
        assertEquals(1250L, result.entries.single().value.minorUnits)
        assertEquals("USD", result.entries.single().value.currencyCode)
        assertEquals(7L, result.ledgerVersion)
        assertEquals(AccessReasonCode.SUPPORT_REQUEST, store.accessReasons.single())
        assertEquals(1, store.audit.size)
        assertEquals(1, store.outbox.size)
    }

    @Test
    fun `ADMIN-002-02-T002 Provide ledger-linked financial timeline rejects invalid boundary unauthorized and stale input`() {
        val store = TimelineMemoryStore()
        val service = service(store)
        assertFailsWith<AuthenticationFailure.Rejected> { service.read(command(principal = player())) }
            .also { assertEquals(AuthErrorCode.FORBIDDEN, it.code) }
        assertFailsWith<AuthenticationFailure.Rejected> { service.read(command(tenantId = "other-tenant")) }
            .also { assertEquals(AuthErrorCode.FORBIDDEN, it.code) }
        assertFailsWith<AuthenticationFailure.Rejected> { service.read(command(from = to, to = to)) }
            .also { assertEquals(AuthErrorCode.INVALID, it.code) }
        assertFailsWith<AuthenticationFailure.Rejected> { service.read(command(limit = 101)) }
            .also { assertEquals(AuthErrorCode.INVALID, it.code) }
        assertFailsWith<AuthenticationFailure.Rejected> { service.read(command(expectedVersion = 4)) }
            .also { assertEquals(AuthErrorCode.STALE, it.code) }
        assertFailsWith<AuthenticationFailure.Rejected> { service.read(command(sessionId = "expired-session")) }
            .also { assertEquals(AuthErrorCode.FORBIDDEN, it.code) }
        assertEquals(0, store.results.size)
    }

    @Test
    fun `ADMIN-002-02-T003 Provide ledger-linked financial timeline survives concurrency duplicate delivery and dependency failure`() {
        val store = TimelineMemoryStore()
        val service = service(store)
        val gate = CountDownLatch(1)
        val pool = Executors.newFixedThreadPool(2)
        val calls = (1..2).map { pool.submit<LedgerTimelineResult> { gate.await(); service.read(command()) } }
        gate.countDown()
        val results = calls.map { it.get() }
        pool.shutdown()
        assertEquals(1, results.distinctBy { it.resultId }.size)
        assertEquals(1, store.results.size)
        assertFailsWith<AuthenticationFailure.Rejected> {
            service.read(command(playerReference = "different-player"))
        }.also { assertEquals(AuthErrorCode.CONFLICT, it.code) }
        assertFailsWith<AuthenticationFailure.Rejected> {
            serviceWithFailure(store).read(command(idempotencyKey = "failure-key", expectedVersion = 1))
        }.also { assertEquals(AuthErrorCode.DEPENDENCY_UNAVAILABLE, it.code) }
    }

    @Test
    fun `ADMIN-002-02-T004 Provide ledger-linked financial timeline remains compatible recoverable observable and lifecycle-safe`() {
        val migration = java.io.File("src/main/resources/db/migration/V5__ledger_timeline_read.sql").readText()
        assertTrue(migration.contains("admin_ledger_timeline_read"))
        assertTrue(migration.contains("ledger_version"))
        assertTrue(migration.contains("access_reason"))
        assertTrue(!migration.contains("balance"))
        assertTrue(!migration.contains("update admin_"))
    }

    private fun service(store: TimelineMemoryStore) = LedgerFinancialTimeline(
        AdminRbacPolicy(true), ActiveLedgerSessionDirectory(), LedgerMemoryReader(), store, clock,
    )

    private fun serviceWithFailure(store: TimelineMemoryStore) = LedgerFinancialTimeline(
        AdminRbacPolicy(true), ActiveLedgerSessionDirectory(), FailingLedgerReader(), store, clock,
    )

    private fun command(
        principal: AuthenticatedPrincipal = admin(),
        tenantId: String = "tenant-1",
        playerReference: String = "player-1",
        from: Instant = this.from,
        to: Instant = this.to,
        limit: Int = 100,
        expectedVersion: Long = 0,
        sessionId: String = "session-1",
        idempotencyKey: String = "key-1",
    ) = LedgerTimelineCommand(principal, sessionId, tenantId, playerReference, from, to, AccessReasonCode.SUPPORT_REQUEST, idempotencyKey, "corr-1", "cause-1", expectedVersion, limit)

    private fun admin() = AuthenticatedPrincipal("admin-1", "tenant-1", PrincipalKind.ADMIN, setOf(com.slotting.admin.auth.AdminRole.SUPER_ADMIN))
    private fun player() = AuthenticatedPrincipal("player-1", "tenant-1", PrincipalKind.PLAYER, emptySet())
}

private class ActiveLedgerSessionDirectory : AdminSessionDirectory {
    override fun find(tenantId: String, principalId: String, sessionId: String) =
        if (tenantId == "tenant-1" && principalId == "admin-1" && sessionId == "session-1") AdminSessionStatus(true, false, Instant.parse("2026-09-17T18:00:00Z")) else null
}

private class LedgerMemoryReader : AuthoritativeLedgerReader {
    override fun read(tenantId: String, playerReference: String, from: Instant, to: Instant, limit: Int) = LedgerTimelinePage(
        listOf(LedgerEntry("ledger-entry-1", playerReference, Instant.parse("2026-09-17T09:30:00Z"), "CREDIT", LedgerMoney(1250, "USD"))),
        7,
    )
}

private class FailingLedgerReader : AuthoritativeLedgerReader {
    override fun read(tenantId: String, playerReference: String, from: Instant, to: Instant, limit: Int): LedgerTimelinePage = error("ledger unavailable")
}

private class TimelineMemoryStore : LedgerTimelineStore {
    val results = mutableMapOf<String, Pair<String, LedgerTimelineResult>>()
    val accessReasons = mutableListOf<AccessReasonCode>()
    val audit = mutableListOf<AuditEvent>()
    val outbox = mutableListOf<OutboxEvent>()
    override fun findByIdempotency(tenantId: String, key: String) = synchronized(this) { results["$tenantId:$key"] }
    override fun currentVersion(tenantId: String) = synchronized(this) { results.values.maxOfOrNull { it.second.serverVersion } ?: 0L }
    override fun save(result: LedgerTimelineResult, tenantId: String, idempotencyKey: String, queryFingerprint: String, accessReason: AccessReasonCode, audit: AuditEvent, outbox: OutboxEvent) = synchronized(this) {
        results["$tenantId:$idempotencyKey"] = queryFingerprint to result
        accessReasons += accessReason
        this.audit += audit
        this.outbox += outbox
    }
}
