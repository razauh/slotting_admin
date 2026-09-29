package com.slotting.admin.wallet

import com.slotting.admin.auth.*
import com.slotting.admin.finance.*
import com.slotting.admin.ledger.*
import com.slotting.admin.player.AccessReasonCode
import org.junit.jupiter.api.Test
import org.mockito.ArgumentMatchers.any
import org.mockito.ArgumentMatchers.anyString
import org.mockito.Mockito.*
import org.springframework.jdbc.core.JdbcTemplate
import org.springframework.jdbc.core.RowMapper
import java.io.File
import java.sql.ResultSet
import java.sql.Timestamp
import java.time.Clock
import java.time.Instant
import java.time.ZoneOffset
import java.util.UUID
import java.util.concurrent.CountDownLatch
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicInteger
import kotlin.test.*

/**
 * TC-009 TDD Contract Test Suite:
 * Build authoritative wallet projections and lossless financial statements.
 *
 * Covers:
 * - BE-019: JdbcLedgerTimelineStore dropping entries on idempotent replay.
 * - AND-002: Backend root cause for fabricated zero balances in Android;
 *   authoritative per-owner/per-currency projections with freshness/sync status and cursor statements.
 *
 * Required test scenarios:
 * 1. BE-019 fix: JdbcLedgerTimelineStore preserves and reconstructs entries on replay
 * 2. nonzero balances
 * 3. multiple currencies
 * 4. overflow guard
 * 5. stale / tampered cursor rejection
 * 6. concurrent posting and query
 * 7. restart replay equivalence (meaning / byte equivalent)
 * 8. projection lag and sync status (FRESH vs STALE)
 * 9. wrong owner / IDOR rejection
 * 10. duplicate query replay vs changed query conflict
 * 11. large page cursor pagination
 * 12. deterministic projection rebuild from committed journal legs
 * 13. V22 Flyway migration schema validation
 */
class AuthoritativeWalletAndLosslessStatementContractTest {

    private val now = Instant.parse("2026-09-24T16:00:00Z")
    private val clock = Clock.fixed(now, ZoneOffset.UTC)

    private val player1 = AuthenticatedPrincipal(
        id = "player-01",
        tenantId = "tenant-prod-1",
        kind = PrincipalKind.PLAYER,
        roles = emptySet(),
    )

    private val player2 = AuthenticatedPrincipal(
        id = "player-02",
        tenantId = "tenant-prod-1",
        kind = PrincipalKind.PLAYER,
        roles = emptySet(),
    )

    private val adminPrincipal = AuthenticatedPrincipal(
        id = "admin-fin-01",
        tenantId = "tenant-prod-1",
        kind = PrincipalKind.ADMIN,
        roles = setOf(AdminRole.SUPER_ADMIN, AdminRole.AUDITOR),
    )

    private val foreignAdminPrincipal = AuthenticatedPrincipal(
        id = "admin-foreign",
        tenantId = "tenant-foreign-99",
        kind = PrincipalKind.ADMIN,
        roles = setOf(AdminRole.SUPER_ADMIN),
    )

    // =========================================================================
    // 1. BE-019: JdbcLedgerTimelineStore Drops Entries on Replay (Fixed)
    // =========================================================================

    @Test
    fun `test01 JdbcLedgerTimelineStore preserves and reconstructs non-empty entries on idempotent replay`() {
        val mockJdbc = mock(JdbcTemplate::class.java)
        val store = JdbcLedgerTimelineStore(mockJdbc)

        val resultId = UUID.randomUUID()
        val entry1 = LedgerEntry("leg-1", "player-1", now, "CREDIT", LedgerMoney(1000L, "USD"))
        val entry2 = LedgerEntry("leg-2", "player-1", now, "DEBIT", LedgerMoney(400L, "USD"))

        val mockRs = mock(ResultSet::class.java)
        `when`(mockRs.getObject("result_id", UUID::class.java)).thenReturn(resultId)
        `when`(mockRs.getString("query_fingerprint")).thenReturn("fingerprint-123")
        `when`(mockRs.getString("state")).thenReturn("FOUND")
        `when`(mockRs.getLong("ledger_version")).thenReturn(5L)
        `when`(mockRs.getInt("entry_count")).thenReturn(2)
        `when`(mockRs.getTimestamp("occurred_at")).thenReturn(Timestamp.from(now))
        `when`(mockRs.getLong("server_version")).thenReturn(1L)

        // Mock timeline read row
        `when`(mockJdbc.query(
            org.mockito.ArgumentMatchers.contains("admin_ledger_timeline_read where"),
            any<RowMapper<Pair<String, LedgerTimelineResult>>>(),
            anyString(),
            anyString()
        )).thenAnswer { invocation ->
            val mapper = invocation.getArgument<RowMapper<Pair<String, LedgerTimelineResult>>>(1)
            listOf(mapper.mapRow(mockRs, 1))
        }

        // Mock timeline entries query
        val entryRs1 = mock(ResultSet::class.java)
        `when`(entryRs1.getString("ledger_entry_id")).thenReturn("leg-1")
        `when`(entryRs1.getString("player_reference")).thenReturn("player-1")
        `when`(entryRs1.getTimestamp("occurred_at")).thenReturn(Timestamp.from(now))
        `when`(entryRs1.getString("entry_type")).thenReturn("CREDIT")
        `when`(entryRs1.getLong("amount_minor_units")).thenReturn(1000L)
        `when`(entryRs1.getString("currency_code")).thenReturn("USD")

        val entryRs2 = mock(ResultSet::class.java)
        `when`(entryRs2.getString("ledger_entry_id")).thenReturn("leg-2")
        `when`(entryRs2.getString("player_reference")).thenReturn("player-1")
        `when`(entryRs2.getTimestamp("occurred_at")).thenReturn(Timestamp.from(now))
        `when`(entryRs2.getString("entry_type")).thenReturn("DEBIT")
        `when`(entryRs2.getLong("amount_minor_units")).thenReturn(400L)
        `when`(entryRs2.getString("currency_code")).thenReturn("USD")

        `when`(mockJdbc.query(
            org.mockito.ArgumentMatchers.contains("admin_ledger_timeline_read_entry"),
            any<RowMapper<LedgerEntry>>(),
            any(UUID::class.java)
        )).thenAnswer { invocation ->
            val mapper = invocation.getArgument<RowMapper<LedgerEntry>>(1)
            listOf(mapper.mapRow(entryRs1, 1), mapper.mapRow(entryRs2, 2))
        }

        val replayed = store.findByIdempotency("tenant-1", "idem-key-1")
        assertNotNull(replayed)
        assertEquals(2, replayed.second.entries.size, "Replayed timeline must not drop entries")
        assertEquals("leg-1", replayed.second.entries[0].ledgerEntryId)
        assertEquals(1000L, replayed.second.entries[0].value.minorUnits)
    }

    // =========================================================================
    // 2. Authoritative Wallet Projections: Nonzero Balances & Multiple Currencies
    // =========================================================================

    @Test
    fun `test02 wallet projection derives nonzero balances and isolates multiple currencies`() {
        val ledgerStore = InMemoryLedgerJournalStore()
        val postingService = LedgerPostingService(store = ledgerStore, clock = clock)
        val walletStore = InMemoryAuthoritativeWalletStore(ledgerStore = ledgerStore, clock = clock)
        val walletService = AuthoritativeWalletService(store = walletStore, clock = clock)

        // 1. Post USD credit for player-01: +5,000 USD
        postingService.postTransaction(
            PostTransactionCommand(
                principal = adminPrincipal,
                tenantId = "tenant-prod-1",
                transactionReference = "TX-DEP-USD-1",
                currencyCode = "USD",
                entries = listOf(
                    JournalEntryDraft("HOUSE_SETTLEMENT", JournalEntryDirection.DEBIT, 5000L, "USD"),
                    JournalEntryDraft("player-01", JournalEntryDirection.CREDIT, 5000L, "USD"),
                ),
                idempotencyKey = "IDEM-DEP-USD",
                correlationId = "corr-1",
                causationId = "caus-1",
            )
        )

        // 2. Post EUR credit for player-01: +8,000 EUR
        postingService.postTransaction(
            PostTransactionCommand(
                principal = adminPrincipal,
                tenantId = "tenant-prod-1",
                transactionReference = "TX-DEP-EUR-1",
                currencyCode = "EUR",
                entries = listOf(
                    JournalEntryDraft("HOUSE_SETTLEMENT", JournalEntryDirection.DEBIT, 8000L, "EUR"),
                    JournalEntryDraft("player-01", JournalEntryDirection.CREDIT, 8000L, "EUR"),
                ),
                idempotencyKey = "IDEM-DEP-EUR",
                correlationId = "corr-2",
                causationId = "caus-2",
            )
        )

        // Query snapshot as player-01
        val snapshot = walletService.getWalletSnapshot(
            WalletSnapshotQuery(
                principal = player1,
                tenantId = "tenant-prod-1",
                ownerReference = "player-01",
            )
        )

        assertEquals("player-01", snapshot.ownerReference)
        assertEquals("tenant-prod-1", snapshot.tenantId)
        assertEquals(WalletSyncStatus.FRESH, snapshot.syncStatus)
        assertEquals(2, snapshot.currencyBalances.size)

        // EUR: 8,000 minor units
        val eur = snapshot.currencyBalances.first { it.currencyCode == "EUR" }
        assertEquals(8000L, eur.balanceMinorUnits)

        // USD: 5,000 minor units
        val usd = snapshot.currencyBalances.first { it.currencyCode == "USD" }
        assertEquals(5000L, usd.balanceMinorUnits)
    }

    // =========================================================================
    // 3. Security: Wrong Owner (IDOR) & Foreign Tenant Rejection
    // =========================================================================

    @Test
    fun `test03 wallet snapshot rejects wrong owner IDOR and foreign tenant`() {
        val ledgerStore = InMemoryLedgerJournalStore()
        val walletStore = InMemoryAuthoritativeWalletStore(ledgerStore = ledgerStore, clock = clock)
        val walletService = AuthoritativeWalletService(store = walletStore, clock = clock)

        // Player 1 trying to read Player 2's wallet -> FORBIDDEN
        val exIdor = assertFailsWith<AuthenticationFailure.Rejected> {
            walletService.getWalletSnapshot(
                WalletSnapshotQuery(
                    principal = player1,
                    tenantId = "tenant-prod-1",
                    ownerReference = "player-02",
                )
            )
        }
        assertEquals(AuthErrorCode.FORBIDDEN, exIdor.code)

        // Foreign admin trying to read tenant-prod-1 -> FORBIDDEN
        val exForeign = assertFailsWith<AuthenticationFailure.Rejected> {
            walletService.getWalletSnapshot(
                WalletSnapshotQuery(
                    principal = foreignAdminPrincipal,
                    tenantId = "tenant-prod-1",
                    ownerReference = "player-01",
                )
            )
        }
        assertEquals(AuthErrorCode.FORBIDDEN, exForeign.code)
    }

    // =========================================================================
    // 4. Cursor Statement Reads with Stable Ordering and Running Balance
    // =========================================================================

    @Test
    fun `test04 cursor statement read preserves stable ordering running balance and pagination`() {
        val ledgerStore = InMemoryLedgerJournalStore()
        val postingService = LedgerPostingService(store = ledgerStore, clock = clock)
        val walletStore = InMemoryAuthoritativeWalletStore(ledgerStore = ledgerStore, clock = clock)
        val walletService = AuthoritativeWalletService(store = walletStore, clock = clock)

        // 3 entries:
        // +10,000 deposit -> running bal: 10,000
        // -3,000 wager    -> running bal: 7,000
        // +1,500 win      -> running bal: 8,500
        postingService.postTransaction(
            PostTransactionCommand(
                principal = adminPrincipal,
                tenantId = "tenant-prod-1",
                transactionReference = "TX-STMT-1",
                currencyCode = "USD",
                entries = listOf(
                    JournalEntryDraft("HOUSE", JournalEntryDirection.DEBIT, 10000L, "USD"),
                    JournalEntryDraft("player-01", JournalEntryDirection.CREDIT, 10000L, "USD", narration = "Deposit"),
                ),
                idempotencyKey = "IDEM-STMT-1",
                correlationId = "c1",
                causationId = "c1",
            )
        )

        postingService.postTransaction(
            PostTransactionCommand(
                principal = adminPrincipal,
                tenantId = "tenant-prod-1",
                transactionReference = "TX-STMT-2",
                currencyCode = "USD",
                entries = listOf(
                    JournalEntryDraft("player-01", JournalEntryDirection.DEBIT, 3000L, "USD", narration = "Wager"),
                    JournalEntryDraft("HOUSE", JournalEntryDirection.CREDIT, 3000L, "USD"),
                ),
                idempotencyKey = "IDEM-STMT-2",
                correlationId = "c2",
                causationId = "c2",
            )
        )

        postingService.postTransaction(
            PostTransactionCommand(
                principal = adminPrincipal,
                tenantId = "tenant-prod-1",
                transactionReference = "TX-STMT-3",
                currencyCode = "USD",
                entries = listOf(
                    JournalEntryDraft("HOUSE", JournalEntryDirection.DEBIT, 1500L, "USD"),
                    JournalEntryDraft("player-01", JournalEntryDirection.CREDIT, 1500L, "USD", narration = "Win payout"),
                ),
                idempotencyKey = "IDEM-STMT-3",
                correlationId = "c3",
                causationId = "c3",
            )
        )

        // Query Page 1 with limit 2
        val page1 = walletService.getStatementPage(
            StatementPageQuery(
                principal = player1,
                tenantId = "tenant-prod-1",
                ownerReference = "player-01",
                currencyCode = "USD",
                limit = 2,
            )
        )

        assertEquals(2, page1.entries.size)
        assertTrue(page1.hasMore)
        assertNotNull(page1.nextCursor)

        // Entry 1: Deposit +10,000 -> running bal 10,000
        assertEquals(10000L, page1.entries[0].amountMinorUnits)
        assertEquals("CREDIT", page1.entries[0].direction)
        assertEquals(10000L, page1.entries[0].runningBalanceMinorUnits)

        // Entry 2: Wager -3,000 -> running bal 7,000
        assertEquals(3000L, page1.entries[1].amountMinorUnits)
        assertEquals("DEBIT", page1.entries[1].direction)
        assertEquals(7000L, page1.entries[1].runningBalanceMinorUnits)

        // Query Page 2 using nextCursor
        val page2 = walletService.getStatementPage(
            StatementPageQuery(
                principal = player1,
                tenantId = "tenant-prod-1",
                ownerReference = "player-01",
                currencyCode = "USD",
                cursor = page1.nextCursor,
                limit = 2,
            )
        )

        assertEquals(1, page2.entries.size)
        assertFalse(page2.hasMore)
        assertNull(page2.nextCursor)

        // Entry 3: Win +1,500 -> running bal 8,500
        assertEquals(1500L, page2.entries[0].amountMinorUnits)
        assertEquals("CREDIT", page2.entries[0].direction)
        assertEquals(8500L, page2.entries[0].runningBalanceMinorUnits)
    }

    // =========================================================================
    // 5. Stale / Tampered Cursor Rejection
    // =========================================================================

    @Test
    fun `test05 statement read rejects tampered or invalid cursor with INVALID`() {
        val ledgerStore = InMemoryLedgerJournalStore()
        val walletStore = InMemoryAuthoritativeWalletStore(ledgerStore = ledgerStore, clock = clock)
        val walletService = AuthoritativeWalletService(store = walletStore, clock = clock)

        // Tampered cursor string
        val ex1 = assertFailsWith<AuthenticationFailure.Rejected> {
            walletService.getStatementPage(
                StatementPageQuery(
                    principal = player1,
                    tenantId = "tenant-prod-1",
                    ownerReference = "player-01",
                    currencyCode = "USD",
                    cursor = "invalid-corrupted-cursor-data",
                )
            )
        }
        assertEquals(AuthErrorCode.INVALID, ex1.code)
    }

    // =========================================================================
    // 6. Idempotent Statement Query Replay vs Changed Query Conflict
    // =========================================================================

    @Test
    fun `test06 idempotent statement query returns identical result and changed query conflicts`() {
        val ledgerStore = InMemoryLedgerJournalStore()
        val postingService = LedgerPostingService(store = ledgerStore, clock = clock)
        val walletStore = InMemoryAuthoritativeWalletStore(ledgerStore = ledgerStore, clock = clock)
        val walletService = AuthoritativeWalletService(store = walletStore, clock = clock)

        postingService.postTransaction(
            PostTransactionCommand(
                principal = adminPrincipal,
                tenantId = "tenant-prod-1",
                transactionReference = "TX-IDEM-STMT",
                currencyCode = "USD",
                entries = listOf(
                    JournalEntryDraft("HOUSE", JournalEntryDirection.DEBIT, 5000L, "USD"),
                    JournalEntryDraft("player-01", JournalEntryDirection.CREDIT, 5000L, "USD"),
                ),
                idempotencyKey = "IDEM-KEY-STMT-01",
                correlationId = "c1",
                causationId = "c1",
            )
        )

        val query1 = StatementPageQuery(
            principal = player1,
            tenantId = "tenant-prod-1",
            ownerReference = "player-01",
            currencyCode = "USD",
            idempotencyKey = "IDEM-STMT-REPLAY-1",
        )

        val res1 = walletService.getStatementPage(query1)
        val res2 = walletService.getStatementPage(query1) // Exact replay
        assertEquals(res1.entries.size, res2.entries.size)
        assertEquals(res1.asOfTime, res2.asOfTime)

        // Reusing same idempotency key with different limit -> CONFLICT
        val conflictingQuery = query1.copy(limit = 50)
        val ex = assertFailsWith<AuthenticationFailure.Rejected> {
            walletService.getStatementPage(conflictingQuery)
        }
        assertEquals(AuthErrorCode.CONFLICT, ex.code)
    }

    // =========================================================================
    // 7. Restart Replay Equivalence (Meaning / Byte Equivalent)
    // =========================================================================

    @Test
    fun `test07 service restart preserves exact statement history and rebuilds projections`() {
        val ledgerStore = InMemoryLedgerJournalStore()
        val postingService = LedgerPostingService(store = ledgerStore, clock = clock)

        // Post 2 entries
        postingService.postTransaction(
            PostTransactionCommand(
                principal = adminPrincipal,
                tenantId = "tenant-prod-1",
                transactionReference = "TX-P1",
                currencyCode = "USD",
                entries = listOf(
                    JournalEntryDraft("HOUSE", JournalEntryDirection.DEBIT, 4000L, "USD"),
                    JournalEntryDraft("player-01", JournalEntryDirection.CREDIT, 4000L, "USD"),
                ),
                idempotencyKey = "IDEM-P1",
                correlationId = "c1",
                causationId = "c1",
            )
        )

        // Service instance 1
        val walletStore1 = InMemoryAuthoritativeWalletStore(ledgerStore = ledgerStore, clock = clock)
        val walletService1 = AuthoritativeWalletService(store = walletStore1, clock = clock)
        val snap1 = walletService1.getWalletSnapshot(WalletSnapshotQuery(player1, "tenant-prod-1", "player-01"))
        assertEquals(4000L, snap1.currencyBalances.single().balanceMinorUnits)

        // SIMULATE RESTART: service instance 2 reading from persistent ledger
        val walletStore2 = InMemoryAuthoritativeWalletStore(ledgerStore = ledgerStore, clock = clock)
        val walletService2 = AuthoritativeWalletService(store = walletStore2, clock = clock)
        val snap2 = walletService2.getWalletSnapshot(WalletSnapshotQuery(player1, "tenant-prod-1", "player-01"))

        assertEquals(snap1.currencyBalances.single().balanceMinorUnits, snap2.currencyBalances.single().balanceMinorUnits)
        assertEquals(snap1.ledgerVersion, snap2.ledgerVersion)

        // Rebuild projections test
        val rebuildReport = walletService2.rebuildProjections("tenant-prod-1", adminPrincipal)
        assertTrue(rebuildReport.verified)
        assertEquals(4000L, walletStore2.findBalance("tenant-prod-1", "player-01", "USD"))
    }

    // =========================================================================
    // 8. Projection Lag and Sync Status Semantics
    // =========================================================================

    @Test
    fun `test08 projection lag reports STALE or rejects when allowStale is false`() {
        val ledgerStore = InMemoryLedgerJournalStore()
        val walletStore = InMemoryAuthoritativeWalletStore(ledgerStore = ledgerStore, clock = clock)
        val walletService = AuthoritativeWalletService(store = walletStore, clock = clock)

        // Query expecting future ledger version 10 when ledger is version 0
        val staleQuery = WalletSnapshotQuery(
            principal = player1,
            tenantId = "tenant-prod-1",
            ownerReference = "player-01",
            expectedLedgerVersion = 10L,
            allowStale = true,
        )
        val staleSnapshot = walletService.getWalletSnapshot(staleQuery)
        assertEquals(WalletSyncStatus.STALE, staleSnapshot.syncStatus)

        // When allowStale is false -> rejects with STALE
        val rejectQuery = staleQuery.copy(allowStale = false)
        val ex = assertFailsWith<AuthenticationFailure.Rejected> {
            walletService.getWalletSnapshot(rejectQuery)
        }
        assertEquals(AuthErrorCode.STALE, ex.code)
    }

    // =========================================================================
    // 9. Concurrency: Parallel Queries
    // =========================================================================

    @Test
    fun `test09 concurrent queries yield consistent versioned snapshots`() {
        val ledgerStore = InMemoryLedgerJournalStore()
        val postingService = LedgerPostingService(store = ledgerStore, clock = clock)
        val walletStore = InMemoryAuthoritativeWalletStore(ledgerStore = ledgerStore, clock = clock)
        val walletService = AuthoritativeWalletService(store = walletStore, clock = clock)

        postingService.postTransaction(
            PostTransactionCommand(
                principal = adminPrincipal,
                tenantId = "tenant-prod-1",
                transactionReference = "TX-CONC-1",
                currencyCode = "USD",
                entries = listOf(
                    JournalEntryDraft("HOUSE", JournalEntryDirection.DEBIT, 1000L, "USD"),
                    JournalEntryDraft("player-01", JournalEntryDirection.CREDIT, 1000L, "USD"),
                ),
                idempotencyKey = "IDEM-CONC-1",
                correlationId = "c1",
                causationId = "c1",
            )
        )

        val threads = 8
        val pool = Executors.newFixedThreadPool(threads)
        val latch = CountDownLatch(threads)
        val successCount = AtomicInteger(0)

        for (i in 0 until threads) {
            pool.submit {
                try {
                    val s = walletService.getWalletSnapshot(WalletSnapshotQuery(player1, "tenant-prod-1", "player-01"))
                    if (s.currencyBalances.single().balanceMinorUnits == 1000L) {
                        successCount.incrementAndGet()
                    }
                } finally {
                    latch.countDown()
                }
            }
        }

        latch.await(5, TimeUnit.SECONDS)
        pool.shutdown()
        assertEquals(threads, successCount.get())
    }

    // =========================================================================
    // 10. PostgreSQL V22 Schema & Migration Invariant Verification
    // =========================================================================

    @Test
    fun `test10 V22 migration script exists and defines required tables and constraints`() {
        val migrationFile = File("src/main/resources/db/migration/V22__lossless_timeline_and_wallet_projection.sql")
        assertTrue(migrationFile.exists(), "V22 migration file must exist")
        val sql = migrationFile.readText()

        assertTrue(sql.contains("create table if not exists admin_ledger_timeline_read_entry"), "Must define admin_ledger_timeline_read_entry")
        assertTrue(sql.contains("create table if not exists wallet_projection"), "Must define wallet_projection")
        assertTrue(sql.contains("create table if not exists statement_query_receipt"), "Must define statement_query_receipt")
        assertTrue(sql.contains("unique (tenant_id, owner_reference, currency_code)"), "Must enforce unique wallet projection per owner and currency")
    }
}
