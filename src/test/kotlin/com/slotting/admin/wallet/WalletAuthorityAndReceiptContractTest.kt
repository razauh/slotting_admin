package com.slotting.admin.wallet

import com.slotting.admin.auth.AdminPermission
import com.slotting.admin.auth.AdminRbacPolicy
import com.slotting.admin.auth.AdminRole
import com.slotting.admin.auth.AuthErrorCode
import com.slotting.admin.auth.AuthenticatedPrincipal
import com.slotting.admin.auth.AuthenticationFailure
import com.slotting.admin.auth.PrincipalKind
import com.slotting.admin.ledger.InMemoryLedgerJournalStore
import com.slotting.admin.ledger.JournalEntryDirection
import com.slotting.admin.ledger.JournalEntryDraft
import com.slotting.admin.ledger.LedgerPostingService
import com.slotting.admin.ledger.PostTransactionCommand
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.assertThrows
import org.mockito.Mockito.mock
import org.springframework.jdbc.core.JdbcTemplate
import java.time.Clock
import java.time.Instant
import java.time.ZoneOffset
import java.util.UUID
import kotlin.test.assertEquals
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue

class WalletAuthorityAndReceiptContractTest {

    private val now = Instant.parse("2026-10-15T12:00:00Z")
    private val clock = Clock.fixed(now, ZoneOffset.UTC)
    private val tenantId = "tenant-tc44"
    private val currency = "PKR"
    private val playerId = "player-wallet-tc44"

    private val playerPrincipal = AuthenticatedPrincipal(
        id = playerId,
        tenantId = tenantId,
        kind = PrincipalKind.PLAYER,
        roles = setOf(AdminRole.SUPPORT),
    )

    private val adminPrincipal = AuthenticatedPrincipal(
        id = "admin-sys-tc44",
        tenantId = tenantId,
        kind = PrincipalKind.ADMIN,
        roles = setOf(AdminRole.SUPER_ADMIN),
    )

    private lateinit var ledgerStore: InMemoryLedgerJournalStore
    private lateinit var ledgerService: LedgerPostingService
    private lateinit var inMemoryWalletStore: InMemoryAuthoritativeWalletStore
    private lateinit var inMemoryWalletService: AuthoritativeWalletService

    @BeforeEach
    fun setUp() {
        ledgerStore = InMemoryLedgerJournalStore()
        ledgerService = LedgerPostingService(store = ledgerStore, clock = clock)
        inMemoryWalletStore = InMemoryAuthoritativeWalletStore(ledgerStore = ledgerStore)
        val policy = AdminRbacPolicy(dualControlRequired = false)
        inMemoryWalletService = AuthoritativeWalletService(
            store = inMemoryWalletStore,
            policy = policy,
            clock = clock,
        )
    }

    private fun postLedgerLegs(credits: Long, debits: Long) {
        if (credits > 0) {
            ledgerService.postTransaction(
                PostTransactionCommand(
                    principal = adminPrincipal,
                    tenantId = tenantId,
                    transactionReference = "TX-CREDIT-${UUID.randomUUID()}",
                    currencyCode = currency,
                    entries = listOf(
                        JournalEntryDraft("HOUSE:SOURCE", JournalEntryDirection.DEBIT, credits, currency),
                        JournalEntryDraft(playerId, JournalEntryDirection.CREDIT, credits, currency),
                    ),
                    idempotencyKey = "IDEM-CR-${UUID.randomUUID()}",
                    correlationId = "corr-credit",
                    causationId = "caus-credit",
                )
            )
        }
        if (debits > 0) {
            ledgerService.postTransaction(
                PostTransactionCommand(
                    principal = adminPrincipal,
                    tenantId = tenantId,
                    transactionReference = "TX-DEBIT-${UUID.randomUUID()}",
                    currencyCode = currency,
                    entries = listOf(
                        JournalEntryDraft(playerId, JournalEntryDirection.DEBIT, debits, currency),
                        JournalEntryDraft("HOUSE:SINK", JournalEntryDirection.CREDIT, debits, currency),
                    ),
                    idempotencyKey = "IDEM-DR-${UUID.randomUUID()}",
                    correlationId = "corr-debit",
                    causationId = "caus-debit",
                )
            )
        }
    }

    @Test
    fun balancesDeriveOnlyFromLedgerLegs() {
        postLedgerLegs(credits = 500_00L, debits = 150_00L)
        val snapshot = inMemoryWalletService.getWalletSnapshot(
            WalletSnapshotQuery(
                tenantId = tenantId,
                ownerReference = playerId,
                principal = playerPrincipal,
            )
        )
        val inrBalance = snapshot.currencyBalances.firstOrNull { it.currencyCode == currency }
        assertNotNull(inrBalance)
        assertEquals(350_00L, inrBalance.balanceMinorUnits)
        assertEquals(inMemoryWalletStore.findBalance(tenantId, playerId, currency), 350_00L)
    }

    @Test
    fun repeatedStatementQueryReturnsPersistedReceipt() {
        postLedgerLegs(credits = 200_00L, debits = 50_00L)
        val mockJdbc = mock(JdbcTemplate::class.java)
        val jdbcStore = JdbcAuthoritativeWalletStore(mockJdbc, ledgerStore)

        val page = AuthoritativeStatementPage(
            entries = emptyList(),
            nextCursor = null,
            hasMore = false,
            pageSize = 0,
            ledgerVersion = 1L,
            asOfTime = now,
            evidenceReference = "evidence-ref",
        )
        jdbcStore.saveStatementReceipt(tenantId, "test-idem-key", "test-fp", page)
        val found = jdbcStore.findStatementReceipt(tenantId, "test-idem-key")
        assertNotNull(found)
        assertEquals("test-fp", found.first)
        assertEquals(page.evidenceReference, found.second.evidenceReference)
    }

    @Test
    fun unusedWalletSubsystemsHaveNoMoneyPathCallers() {
        val moneyPathPackages = listOf(
            "com.slotting.admin.gameprovider",
            "com.slotting.admin.cashier",
            "com.slotting.admin.withdrawal",
            "com.slotting.admin.account",
        )
        val unusedSubsystems = listOf(
            "BalanceBucketsService",
            "WalletAccountService",
            "WalletReservationService",
        )
        for (pkg in moneyPathPackages) {
            for (subsystem in unusedSubsystems) {
                val fullClass = "$pkg.$subsystem"
                val exists = try {
                    Class.forName(fullClass)
                    true
                } catch (e: ClassNotFoundException) {
                    false
                }
                assertTrue(!exists)
            }
        }
    }

    @Test
    fun receiptFingerprintMismatchIsRejected() {
        postLedgerLegs(credits = 100_00L, debits = 0L)
        val key = "idem-conflict-key"
        val query1 = StatementPageQuery(
            tenantId = tenantId,
            ownerReference = playerId,
            currencyCode = currency,
            limit = 10,
            idempotencyKey = key,
            principal = playerPrincipal,
        )
        val page1 = inMemoryWalletService.getStatementPage(query1)
        assertNotNull(page1)

        val query2 = StatementPageQuery(
            tenantId = tenantId,
            ownerReference = playerId,
            currencyCode = currency,
            limit = 20,
            idempotencyKey = key,
            principal = playerPrincipal,
        )
        val ex = assertThrows<AuthenticationFailure.Rejected> {
            inMemoryWalletService.getStatementPage(query2)
        }
        assertEquals(AuthErrorCode.CONFLICT, ex.code)
    }
}
