package com.slotting.admin.wallet

import com.slotting.admin.auth.AdminRole
import com.slotting.admin.auth.AuthenticatedPrincipal
import com.slotting.admin.auth.PrincipalKind
import com.slotting.admin.ledger.InMemoryLedgerJournalStore
import com.slotting.admin.ledger.JournalEntryDirection
import com.slotting.admin.ledger.JournalEntryDraft
import com.slotting.admin.ledger.LedgerPostingService
import com.slotting.admin.ledger.PostTransactionCommand
import org.junit.jupiter.api.Test
import org.springframework.http.HttpStatus
import java.time.Clock
import java.time.Instant
import java.time.ZoneOffset
import java.util.UUID
import kotlin.test.assertEquals

class PlayerWalletControllerCanonicalAccountTest {
    private val now = Instant.parse("2026-11-12T12:00:00Z")
    private val clock = Clock.fixed(now, ZoneOffset.UTC)
    private val tenantId = "tenant-wallet-canonical"
    private val playerId = UUID.randomUUID().toString()
    private val player = AuthenticatedPrincipal(playerId, tenantId, PrincipalKind.PLAYER, emptySet())
    private val admin = AuthenticatedPrincipal("admin-wallet-canonical", tenantId, PrincipalKind.ADMIN, setOf(AdminRole.SUPER_ADMIN))

    @Test
    fun `snapshot default reads the canonical player account`() {
        val ledgerStore = InMemoryLedgerJournalStore()
        val ledgerService = LedgerPostingService(store = ledgerStore, clock = clock)
        ledgerService.postTransaction(
            PostTransactionCommand(
                principal = admin,
                tenantId = tenantId,
                transactionReference = "TX-WALLET-CANONICAL-1",
                currencyCode = "USD",
                entries = listOf(
                    JournalEntryDraft("HOUSE:FUNDING", JournalEntryDirection.DEBIT, 1000L, "USD"),
                    JournalEntryDraft("PLAYER:$playerId", JournalEntryDirection.CREDIT, 1000L, "USD"),
                ),
                idempotencyKey = "IDEM-WALLET-CANONICAL-1",
                correlationId = "corr-wallet-canonical",
                causationId = "caus-wallet-canonical",
            ),
        )
        val walletService = AuthoritativeWalletService(
            store = InMemoryAuthoritativeWalletStore(ledgerStore = ledgerStore, clock = clock),
            clock = clock,
        )
        val controller = PlayerWalletController(walletService)

        val response = controller.getSnapshot(
            tenantId = tenantId,
            ownerReference = null,
            expectedLedgerVersion = null,
            allowStale = true,
            sessionId = null,
            principalAttr = player,
        )

        assertEquals(HttpStatus.OK, response.statusCode)
        val snapshot = response.body as AuthoritativeWalletSnapshot
        assertEquals("PLAYER:$playerId", snapshot.ownerReference)
        assertEquals(1000L, snapshot.currencyBalances.single { it.currencyCode == "USD" }.balanceMinorUnits)
    }
}
