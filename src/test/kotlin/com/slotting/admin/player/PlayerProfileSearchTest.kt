package com.slotting.admin.player

import com.slotting.admin.auth.AdminPermission
import com.slotting.admin.auth.AdminRbacPolicy
import com.slotting.admin.auth.AdminSessionDirectory
import com.slotting.admin.auth.AdminSessionStatus
import com.slotting.admin.auth.AuditEvent
import com.slotting.admin.auth.AuthErrorCode
import com.slotting.admin.auth.AuthenticatedPrincipal
import com.slotting.admin.auth.AuthenticationFailure
import com.slotting.admin.auth.OutboxEvent
import com.slotting.admin.auth.PrincipalKind
import org.junit.jupiter.api.Test
import java.time.Clock
import java.time.Instant
import java.time.ZoneOffset
import java.util.concurrent.CountDownLatch
import java.util.concurrent.Executors
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertTrue

class PlayerProfileSearchTest {
    private val now = Instant.parse("2026-09-17T10:00:00Z")
    private val clock = Clock.fixed(now, ZoneOffset.UTC)

    @Test
    fun `ADMIN-002-01-T001 Provide scoped player profile search produces authoritative outcome`() {
        val store = SearchMemoryStore()
        val result = service(store).search(command())

        assertEquals(ProfileSearchState.FOUND, result.state)
        assertEquals("ledger-player-1", result.profiles.single().ledgerLink.ledgerReference)
        assertEquals(AccessReasonCode.SUPPORT_REQUEST, store.accessReasons.single())
        assertEquals(1, store.audit.size)
        assertEquals(1, store.outbox.size)
        assertTrue(result.profiles.single().ledgerLink.asOf == now)
    }

    @Test
    fun `ADMIN-002-01-T002 Provide scoped player profile search rejects invalid boundary unauthorized and stale input`() {
        val store = SearchMemoryStore()
        val service = service(store)
        assertFailsWith<AuthenticationFailure.Rejected> { service.search(command(principal = player())) }
            .also { assertEquals(AuthErrorCode.FORBIDDEN, it.code) }
        assertFailsWith<AuthenticationFailure.Rejected> { service.search(command(tenantId = "other-tenant")) }
            .also { assertEquals(AuthErrorCode.FORBIDDEN, it.code) }
        assertFailsWith<AuthenticationFailure.Rejected> { service.search(command(exactTerm = "")) }
            .also { assertEquals(AuthErrorCode.INVALID, it.code) }
        assertFailsWith<AuthenticationFailure.Rejected> { service.search(command(limit = 21)) }
            .also { assertEquals(AuthErrorCode.INVALID, it.code) }
        assertFailsWith<AuthenticationFailure.Rejected> { service.search(command(expectedVersion = 2)) }
            .also { assertEquals(AuthErrorCode.STALE, it.code) }
        assertEquals(0, store.results.size)
    }

    @Test
    fun `ADMIN-002-01-T003 Provide scoped player profile search survives concurrency duplicate delivery and dependency failure`() {
        val store = SearchMemoryStore()
        val service = service(store)
        val gate = CountDownLatch(1)
        val pool = Executors.newFixedThreadPool(2)
        val calls = (1..2).map { pool.submit<ProfileSearchResult> { gate.await(); service.search(command()) } }
        gate.countDown()
        val results = calls.map { it.get() }
        pool.shutdown()
        assertEquals(1, results.distinctBy { it.resultId }.size)
        assertEquals(1, store.results.size)
        assertFailsWith<AuthenticationFailure.Rejected> {
            service.search(command(exactTerm = "different-player"))
        }.also { assertEquals(AuthErrorCode.CONFLICT, it.code) }
        assertFailsWith<AuthenticationFailure.Rejected> {
            serviceWithFailure(store).search(command(idempotencyKey = "key-failure", expectedVersion = 1))
        }.also { assertEquals(AuthErrorCode.DEPENDENCY_UNAVAILABLE, it.code) }
    }

    @Test
    fun `ADMIN-002-01-T004 Provide scoped player profile search remains compatible recoverable observable and lifecycle-safe`() {
        val migration = java.io.File("src/main/resources/db/migration/V3__scoped_player_profile_search.sql").readText()
        assertTrue(migration.contains("admin_player_profile_search"))
        assertTrue(migration.contains("access_reason"))
        assertTrue(migration.contains("idempotency_key"))
        assertTrue(!migration.contains("balance"))
        assertTrue(!migration.contains("update admin_"))
        val journalMigration = java.io.File("src/main/resources/db/migration/V4__shared_admin_operation_journal.sql").readText()
        assertTrue(journalMigration.contains("admin_operation"))
        assertTrue(journalMigration.contains("admin_audit_event_operation_fk"))
    }

    private fun service(store: SearchMemoryStore) = ScopedPlayerProfileSearch(
        AdminRbacPolicy(true), ActiveSearchSessionDirectory(), ProfileMemoryRepository(), store, clock,
    )

    private fun serviceWithFailure(store: SearchMemoryStore) = ScopedPlayerProfileSearch(
        AdminRbacPolicy(true), ActiveSearchSessionDirectory(), FailingProfileRepository(), store, clock,
    )

    private fun command(
        principal: AuthenticatedPrincipal = admin(),
        tenantId: String = "tenant-1",
        exactTerm: String = "player-1",
        limit: Int = 20,
        expectedVersion: Long = 0,
        idempotencyKey: String = "key-1",
    ) = PlayerProfileSearchCommand(principal, "session-1", tenantId, PlayerSearchField.PLAYER_REFERENCE, exactTerm, AccessReasonCode.SUPPORT_REQUEST, idempotencyKey, "corr-1", "cause-1", expectedVersion, limit)

    private fun admin() = AuthenticatedPrincipal("admin-1", "tenant-1", PrincipalKind.ADMIN, setOf(com.slotting.admin.auth.AdminRole.SUPER_ADMIN))
    private fun player() = AuthenticatedPrincipal("player-1", "tenant-1", PrincipalKind.PLAYER, emptySet())
}

private class ActiveSearchSessionDirectory : AdminSessionDirectory {
    override fun find(tenantId: String, principalId: String, sessionId: String) =
        if (tenantId == "tenant-1" && principalId == "admin-1" && sessionId == "session-1") AdminSessionStatus(true, false, Instant.parse("2026-09-17T18:00:00Z")) else null
}

private class ProfileMemoryRepository : PlayerProfileReadRepository {
    override fun search(tenantId: String, field: PlayerSearchField, exactTerm: String, limit: Int) = listOf(
        PlayerProfileReadModel("player-1", "Redacted Player", LedgerLink("player-1", "ledger-player-1", Instant.parse("2026-09-17T10:00:00Z"))),
    )
}

private class FailingProfileRepository : PlayerProfileReadRepository {
    override fun search(tenantId: String, field: PlayerSearchField, exactTerm: String, limit: Int): List<PlayerProfileReadModel> = error("dependency unavailable")
}

private class SearchMemoryStore : ProfileSearchStore {
    val results = mutableMapOf<String, Pair<String, ProfileSearchResult>>()
    val accessReasons = mutableListOf<AccessReasonCode>()
    val audit = mutableListOf<AuditEvent>()
    val outbox = mutableListOf<OutboxEvent>()
    override fun findByIdempotency(tenantId: String, key: String) = synchronized(this) { results["$tenantId:$key"] }
    override fun currentVersion(tenantId: String) = synchronized(this) { results.values.maxOfOrNull { it.second.serverVersion } ?: 0L }
    override fun save(result: ProfileSearchResult, tenantId: String, idempotencyKey: String, queryFingerprint: String, accessReason: AccessReasonCode, audit: AuditEvent, outbox: OutboxEvent) = synchronized(this) {
        results["$tenantId:$idempotencyKey"] = queryFingerprint to result
        accessReasons += accessReason
        this.audit += audit
        this.outbox += outbox
    }
}
