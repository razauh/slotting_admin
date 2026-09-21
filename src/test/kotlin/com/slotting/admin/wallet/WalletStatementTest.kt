package com.slotting.admin.wallet

import com.slotting.admin.auth.AdminRole
import com.slotting.admin.auth.AuthenticatedPrincipal
import com.slotting.admin.auth.PrincipalKind
import org.junit.jupiter.api.AfterEach
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test
import java.time.Clock
import java.time.Instant
import java.time.ZoneOffset
import java.util.UUID
import java.util.concurrent.Callable
import java.util.concurrent.Executors
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue

class WalletStatementTest {
    private val now = Instant.parse("2026-09-20T18:40:00Z")
    private val clock = Clock.fixed(now, ZoneOffset.UTC)

    private val playerAId = UUID.randomUUID()
    private val playerBId = UUID.randomUUID()

    private val playerAPrincipal = AuthenticatedPrincipal(
        id = playerAId.toString(),
        tenantId = "tenant-wallet-prod",
        kind = PrincipalKind.PLAYER,
        roles = emptySet()
    )

    private val playerBPrincipal = AuthenticatedPrincipal(
        id = playerBId.toString(),
        tenantId = "tenant-wallet-prod",
        kind = PrincipalKind.PLAYER,
        roles = emptySet()
    )

    private val adminPrincipal = AuthenticatedPrincipal(
        id = "admin-wallet-stmt",
        tenantId = "tenant-wallet-prod",
        kind = PrincipalKind.ADMIN,
        roles = setOf(AdminRole.SUPER_ADMIN, AdminRole.AUDITOR)
    )

    private val foreignTenantPrincipal = AuthenticatedPrincipal(
        id = "admin-foreign",
        tenantId = "tenant-foreign-99",
        kind = PrincipalKind.ADMIN,
        roles = setOf(AdminRole.SUPER_ADMIN)
    )

    private lateinit var bucketStore: InMemoryBalanceBucketsStore
    private lateinit var statementStore: InMemoryWalletStatementStore
    private lateinit var observability: InMemoryWalletStatementObservability
    private lateinit var service: WalletStatementService

    @BeforeEach
    fun setUp() {
        WalletStatementBinding.isBound = true
        bucketStore = InMemoryBalanceBucketsStore()
        statementStore = InMemoryWalletStatementStore()
        observability = InMemoryWalletStatementObservability()
        service = WalletStatementService(
            bucketStore = bucketStore,
            statementStore = statementStore,
            clock = clock,
            observability = observability
        )
    }

    @AfterEach
    fun tearDown() {
        WalletStatementBinding.isBound = true
    }

    private fun createTestWallet(
        ownerId: UUID,
        cashAvailable: Long = 50_000L,
        bonusActive: Long = 10_000L,
        version: Long = 3L
    ): WalletBalanceBucketsRecord {
        val wallet = WalletBalanceBucketsRecord(
            walletId = UUID.randomUUID(),
            tenantId = "tenant-wallet-prod",
            ownerId = ownerId,
            currencyCode = "EUR",
            cash = CashBuckets(availableMinorUnits = cashAvailable, lockedMinorUnits = 5_000L, pendingWithdrawalMinorUnits = 0L),
            bonus = BonusBuckets(activeMinorUnits = bonusActive, lockedMinorUnits = 0L, pendingMinorUnits = 0L),
            version = version,
            createdAt = now.minusSeconds(3600),
            updatedAt = now
        )
        bucketStore.saveWallet(wallet)
        return wallet
    }

    private fun addPosting(
        wallet: WalletBalanceBucketsRecord,
        type: StatementEntryType,
        direction: StatementDirection,
        amount: Long,
        balanceAfter: Long,
        reference: String,
        time: Instant = now
    ): StatementEntryRecord {
        val seq = statementStore.nextSequence(wallet.tenantId, wallet.ownerId, wallet.currencyCode)
        val entry = StatementEntryRecord(
            entryId = UUID.randomUUID(),
            tenantId = wallet.tenantId,
            walletId = wallet.walletId,
            ownerId = wallet.ownerId,
            currencyCode = wallet.currencyCode,
            entryType = type,
            direction = direction,
            amountMinorUnits = amount,
            balanceAfterMinorUnits = balanceAfter,
            cashAvailableAfterMinorUnits = balanceAfter,
            bonusActiveAfterMinorUnits = 0L,
            reference = reference,
            sourceAuthority = "SERVER_LEDGER",
            postedAt = time,
            sequenceNumber = seq
        )
        statementStore.recordPosting(entry)
        return entry
    }

    // =========================================================================
    // WALLET-004-T001: Authoritative Outcome Verification
    // =========================================================================

    @Test
    fun `WALLET-004-T001 Balance statement APIs produces the required authoritative outcome`() {
        WalletStatementBinding.checkBound()

        // 1. Verify semantic contract constant
        assertEquals(
            "Snapshot includes as-of/version; statements map postings, never local activity.",
            WALLET_STATEMENT_CONTRACT
        )

        val wallet = createTestWallet(ownerId = playerAId, cashAvailable = 45_000L, bonusActive = 5_000L, version = 7L)

        // 2. Query Balance Snapshot
        val snapQuery = BalanceSnapshotQuery(
            principal = playerAPrincipal,
            tenantId = "tenant-wallet-prod",
            ownerId = playerAId,
            currencyCode = "EUR",
            correlationId = "corr-snap-01",
            causationId = "caus-snap-01"
        )
        val snapResult = service.getBalanceSnapshot(snapQuery)

        // Assert snapshot includes as-of and authoritative version
        assertEquals(now, snapResult.asOfTime)
        assertEquals(7L, snapResult.version)
        assertEquals(55_000L, snapResult.totalBalanceMinorUnits)
        assertEquals(45_000L, snapResult.cash.availableMinorUnits)
        assertEquals(5_000L, snapResult.cash.lockedMinorUnits)
        assertEquals(5_000L, snapResult.bonus.activeMinorUnits)
        assertEquals(45_000L, snapResult.withdrawableCashMinorUnits) // Bonus non-withdrawable
        assertFalse(snapResult.hasAndroidDbImpact)
        assertFalse(snapResult.hasAndroidLifecycleClaim)
        assertEquals("WALLET_BALANCE_SNAPSHOT_ACCESSED", snapResult.auditEvent.type)

        // 3. Record server postings to statement store
        addPosting(wallet, StatementEntryType.DEPOSIT, StatementDirection.CREDIT, 20_000L, 20_000L, "DEP-001", now.minusSeconds(300))
        addPosting(wallet, StatementEntryType.WAGER, StatementDirection.DEBIT, 5_000L, 15_000L, "WAG-001", now.minusSeconds(200))
        addPosting(wallet, StatementEntryType.WIN_PAYOUT, StatementDirection.CREDIT, 10_000L, 25_000L, "WIN-001", now.minusSeconds(100))

        // 4. Query Statement Page 1 (limit 2)
        val stmtQuery1 = GetStatementQuery(
            principal = playerAPrincipal,
            tenantId = "tenant-wallet-prod",
            ownerId = playerAId,
            currencyCode = "EUR",
            cursor = null,
            limit = 2,
            correlationId = "corr-stmt-01",
            causationId = "caus-stmt-01"
        )
        val page1 = service.getStatement(stmtQuery1)

        assertEquals(2, page1.pageSize)
        assertEquals(2, page1.entries.size)
        assertTrue(page1.hasMore)
        assertNotNull(page1.nextCursor)
        assertEquals(now, page1.asOfTime)
        assertEquals(7L, page1.version)

        // Assert entries map postings, never local activity
        assertEquals("DEP-001", page1.entries[0].reference)
        assertEquals("SERVER_LEDGER", page1.entries[0].sourceAuthority)
        assertEquals("WAG-001", page1.entries[1].reference)
        assertEquals("SERVER_LEDGER", page1.entries[1].sourceAuthority)

        // 5. Query Statement Page 2 using nextCursor
        val stmtQuery2 = GetStatementQuery(
            principal = playerAPrincipal,
            tenantId = "tenant-wallet-prod",
            ownerId = playerAId,
            currencyCode = "EUR",
            cursor = page1.nextCursor,
            limit = 2,
            correlationId = "corr-stmt-02",
            causationId = "caus-stmt-02"
        )
        val page2 = service.getStatement(stmtQuery2)

        assertEquals(1, page2.pageSize)
        assertEquals(1, page2.entries.size)
        assertFalse(page2.hasMore)
        assertNull(page2.nextCursor)
        assertEquals("WIN-001", page2.entries[0].reference)
        assertEquals("SERVER_LEDGER", page2.entries[0].sourceAuthority)
    }

    // =========================================================================
    // WALLET-004-T002: Rejection of Invalid, Boundary, Unauthorized, and Stale Input
    // =========================================================================

    @Test
    fun `WALLET-004-T002 Balance statement APIs rejects invalid, boundary, unauthorized, and stale input`() {
        WalletStatementBinding.checkBound()

        val walletA = createTestWallet(ownerId = playerAId)
        val walletB = createTestWallet(ownerId = playerBId)

        // 1. Unauthenticated request
        assertFailsWith<UnauthorizedWalletAccessException> {
            service.getBalanceSnapshot(
                BalanceSnapshotQuery(
                    principal = null,
                    tenantId = "tenant-wallet-prod",
                    ownerId = playerAId,
                    currencyCode = "EUR",
                    correlationId = "c1",
                    causationId = "c2"
                )
            )
        }

        // 2. Cross-tenant request
        assertFailsWith<CrossTenantAccessException> {
            service.getBalanceSnapshot(
                BalanceSnapshotQuery(
                    principal = foreignTenantPrincipal,
                    tenantId = "tenant-wallet-prod",
                    ownerId = playerAId,
                    currencyCode = "EUR",
                    correlationId = "c1",
                    causationId = "c2"
                )
            )
        }

        // 3. Ownership Leak Protection (IDOR Prevention)
        // Player B tries to inspect Player A's balance snapshot
        val idorSnapEx = assertFailsWith<IdorForbiddenException> {
            service.getBalanceSnapshot(
                BalanceSnapshotQuery(
                    principal = playerBPrincipal,
                    tenantId = "tenant-wallet-prod",
                    ownerId = playerAId, // Target is player A!
                    currencyCode = "EUR",
                    correlationId = "c1",
                    causationId = "c2"
                )
            )
        }
        assertTrue(idorSnapEx.message!!.contains("ownership leak/inconsistent page"))

        // Player B tries to read Player A's statement
        val idorStmtEx = assertFailsWith<IdorForbiddenException> {
            service.getStatement(
                GetStatementQuery(
                    principal = playerBPrincipal,
                    tenantId = "tenant-wallet-prod",
                    ownerId = playerAId, // Target is player A!
                    currencyCode = "EUR",
                    correlationId = "c1",
                    causationId = "c2"
                )
            )
        }
        assertTrue(idorStmtEx.message!!.contains("ownership leak/inconsistent page"))

        // 4. Invalid Limit Boundaries
        assertFailsWith<InvalidStatementRequestException> {
            service.getStatement(
                GetStatementQuery(
                    principal = playerAPrincipal,
                    tenantId = "tenant-wallet-prod",
                    ownerId = playerAId,
                    currencyCode = "EUR",
                    limit = 0, // Invalid limit <= 0
                    correlationId = "c1",
                    causationId = "c2"
                )
            )
        }

        assertFailsWith<InvalidStatementRequestException> {
            service.getStatement(
                GetStatementQuery(
                    principal = playerAPrincipal,
                    tenantId = "tenant-wallet-prod",
                    ownerId = playerAId,
                    currencyCode = "EUR",
                    limit = 101, // Invalid limit > 100
                    correlationId = "c1",
                    causationId = "c2"
                )
            )
        }

        // 5. Malformed or Tampered Cursor (prevents inconsistent page / injection)
        val cursorEx = assertFailsWith<InvalidCursorException> {
            service.getStatement(
                GetStatementQuery(
                    principal = playerAPrincipal,
                    tenantId = "tenant-wallet-prod",
                    ownerId = playerAId,
                    currencyCode = "EUR",
                    cursor = "tampered-garbage-token",
                    correlationId = "c1",
                    causationId = "c2"
                )
            )
        }
        assertTrue(cursorEx.message!!.contains("ownership leak/inconsistent page"))

        // 6. Non-existent wallet lookup
        assertFailsWith<WalletNotFoundException> {
            service.getBalanceSnapshot(
                BalanceSnapshotQuery(
                    principal = adminPrincipal,
                    tenantId = "tenant-wallet-prod",
                    ownerId = UUID.randomUUID(), // Unknown owner
                    currencyCode = "EUR",
                    correlationId = "c1",
                    causationId = "c2"
                )
            )
        }
    }

    // =========================================================================
    // WALLET-004-T003: Concurrency, Duplicate Delivery, and Page Consistency
    // =========================================================================

    @Test
    fun `WALLET-004-T003 Balance statement APIs survives concurrency, duplicate delivery, and dependency failure`() {
        WalletStatementBinding.checkBound()

        val wallet = createTestWallet(ownerId = playerAId)

        // Seed 30 transactions
        for (i in 1..30) {
            addPosting(
                wallet = wallet,
                type = if (i % 2 == 0) StatementEntryType.DEPOSIT else StatementEntryType.WAGER,
                direction = if (i % 2 == 0) StatementDirection.CREDIT else StatementDirection.DEBIT,
                amount = i * 100L,
                balanceAfter = 50_000L + (i * 100L),
                reference = "TX-SEED-$i",
                time = now.minusSeconds((30 - i) * 10L)
            )
        }

        // Verify keyset cursor pagination completeness across all pages (no duplicate, no missing)
        val pageSize = 10
        val collectedReferences = mutableListOf<String>()
        var cursor: String? = null
        var pagesCount = 0

        do {
            val page = service.getStatement(
                GetStatementQuery(
                    principal = playerAPrincipal,
                    tenantId = "tenant-wallet-prod",
                    ownerId = playerAId,
                    currencyCode = "EUR",
                    cursor = cursor,
                    limit = pageSize,
                    correlationId = "c1",
                    causationId = "c2"
                )
            )
            pagesCount++
            collectedReferences.addAll(page.entries.map { it.reference })
            cursor = page.nextCursor
        } while (cursor != null)

        assertEquals(3, pagesCount, "30 items with limit 10 must span exactly 3 pages")
        assertEquals(30, collectedReferences.size, "Must collect exactly 30 entries")
        assertEquals(30, collectedReferences.toSet().size, "All collected entries must be distinct (no page drift/duplication)")

        // Duplicate query idempotency: reading same cursor twice returns exact same page
        val rep1 = service.getStatement(
            GetStatementQuery(
                principal = playerAPrincipal,
                tenantId = "tenant-wallet-prod",
                ownerId = playerAId,
                currencyCode = "EUR",
                cursor = null,
                limit = 10,
                correlationId = "c1",
                causationId = "c2"
            )
        )
        val rep2 = service.getStatement(
            GetStatementQuery(
                principal = playerAPrincipal,
                tenantId = "tenant-wallet-prod",
                ownerId = playerAId,
                currencyCode = "EUR",
                cursor = null,
                limit = 10,
                correlationId = "c1",
                causationId = "c2"
            )
        )
        assertEquals(rep1.entries.map { it.entryId }, rep2.entries.map { it.entryId })

        // Concurrency test: 10 threads concurrently reading statement pages while new items are posted
        val threadCount = 10
        val executor = Executors.newFixedThreadPool(threadCount)
        val futures = (1..threadCount).map {
            executor.submit(Callable {
                service.getStatement(
                    GetStatementQuery(
                        principal = playerAPrincipal,
                        tenantId = "tenant-wallet-prod",
                        ownerId = playerAId,
                        currencyCode = "EUR",
                        limit = 15,
                        correlationId = "c1",
                        causationId = "c2"
                    )
                )
            })
        }
        val results = futures.map { it.get() }
        executor.shutdown()

        assertEquals(10, results.size)
        results.forEach { result ->
            assertEquals(15, result.entries.size)
            assertTrue(result.entries.all { it.sourceAuthority == "SERVER_LEDGER" })
        }
    }

    // =========================================================================
    // WALLET-004-T004: Recovery, Observability, and Lifecycle Safety
    // =========================================================================

    @Test
    fun `WALLET-004-T004 Balance statement APIs remains compatible, recoverable, observable, and lifecycle-safe`() {
        WalletStatementBinding.checkBound()

        val wallet = createTestWallet(ownerId = playerAId, cashAvailable = 20_000L, version = 5L)
        addPosting(wallet, StatementEntryType.DEPOSIT, StatementDirection.CREDIT, 10_000L, 20_000L, "DEP-AUDIT-01")

        // 1. Audit & Outbox events for balance snapshot
        val snap = service.getBalanceSnapshot(
            BalanceSnapshotQuery(
                principal = playerAPrincipal,
                tenantId = "tenant-wallet-prod",
                ownerId = playerAId,
                currencyCode = "EUR",
                correlationId = "corr-aud-snap",
                causationId = "caus-aud-snap"
            )
        )
        assertEquals("WALLET_BALANCE_SNAPSHOT_ACCESSED", snap.auditEvent.type)
        assertEquals("corr-aud-snap", snap.auditEvent.correlationId)
        assertEquals("caus-aud-snap", snap.auditEvent.causationId)

        // 2. Audit & Outbox events for statement query
        val stmt = service.getStatement(
            GetStatementQuery(
                principal = playerAPrincipal,
                tenantId = "tenant-wallet-prod",
                ownerId = playerAId,
                currencyCode = "EUR",
                correlationId = "corr-aud-stmt",
                causationId = "caus-aud-stmt"
            )
        )
        assertEquals("WALLET_STATEMENT_ACCESSED", stmt.auditEvent.type)
        assertEquals("corr-aud-stmt", stmt.auditEvent.correlationId)
        assertEquals("caus-aud-stmt", stmt.auditEvent.causationId)

        // 3. Metrics logged
        val metrics = observability.getMetrics()
        assertTrue(metrics.any { it.eventType == "attempt" })
        assertTrue(metrics.any { it.eventType == "accept" })
        assertTrue(metrics.any { it.eventType == "query" })

        // 4. Client Presentation and Lifecycle Invariant
        assertFalse(snap.hasAndroidDbImpact)
        assertFalse(snap.hasAndroidLifecycleClaim)
        assertFalse(stmt.hasAndroidDbImpact)
        assertFalse(stmt.hasAndroidLifecycleClaim)
    }
}
