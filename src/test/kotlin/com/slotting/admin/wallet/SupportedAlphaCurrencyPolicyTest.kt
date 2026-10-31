package com.slotting.admin.wallet

import com.slotting.admin.auth.AdminRole
import com.slotting.admin.auth.AuthenticatedPrincipal
import com.slotting.admin.auth.PrincipalKind
import com.slotting.admin.ledger.InMemoryLedgerJournalStore
import com.slotting.admin.ledger.JournalEntryDirection
import com.slotting.admin.ledger.JournalEntryDraft
import com.slotting.admin.ledger.LedgerPostingService
import com.slotting.admin.ledger.PostTransactionCommand
import com.slotting.admin.ledger.LegacyIsoCurrencyPostingPolicy
import com.slotting.admin.ledger.PostingInvalidException
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test
import java.time.Clock
import java.time.Instant
import java.time.ZoneOffset
import java.util.UUID
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertTrue

class SupportedAlphaCurrencyPolicyTest {

    private val now = Instant.parse("2026-10-28T09:00:00Z")
    private val clock = Clock.fixed(now, ZoneOffset.UTC)

    private val adminPrincipal = AuthenticatedPrincipal(
        id = "admin-alpha-currency",
        tenantId = "tenant-alpha-currency",
        kind = PrincipalKind.ADMIN,
        roles = setOf(AdminRole.SUPER_ADMIN, AdminRole.SECURITY)
    )

    private lateinit var walletStore: InMemoryWalletAccountStore
    private lateinit var walletService: WalletAccountService
    private lateinit var ledgerStore: InMemoryLedgerJournalStore
    private lateinit var ledgerService: LedgerPostingService

    @BeforeEach
    fun setUp() {
        WalletAccountBinding.isBound = true
        walletStore = InMemoryWalletAccountStore()
        walletService = WalletAccountService(walletStore, clock)
        ledgerStore = InMemoryLedgerJournalStore()
        ledgerService = LedgerPostingService(ledgerStore, clock)
    }

    private fun createCommand(
        currencyCode: String,
        ownerId: UUID = UUID.randomUUID(),
        initialBalanceMinorUnits: Long = 0L
    ) = CreateWalletAccountCommand(
        principal = adminPrincipal,
        tenantId = "tenant-alpha-currency",
        ownerId = ownerId,
        currencyCode = currencyCode,
        accountType = WalletAccountType.CASH,
        initialBalanceMinorUnits = initialBalanceMinorUnits,
        idempotencyKey = "idem-create-$ownerId-$currencyCode-${initialBalanceMinorUnits}",
        correlationId = "corr-alpha-${UUID.randomUUID()}",
        causationId = "cause-alpha-${UUID.randomUUID()}"
    )

    private fun postingCommand(
        currencyCode: String,
        amount: Long,
        reference: String = "alpha-tx-${UUID.randomUUID()}"
    ) = PostTransactionCommand(
        principal = adminPrincipal,
        tenantId = "tenant-alpha-currency",
        transactionReference = reference,
        currencyCode = currencyCode,
        entries = listOf(
            JournalEntryDraft("ESCROW:alpha-house", JournalEntryDirection.DEBIT, amount, currencyCode, "house funding source"),
            JournalEntryDraft("PLAYER:alpha-player", JournalEntryDirection.CREDIT, amount, currencyCode, "player credit")
        ),
        idempotencyKey = "idem-post-$reference",
        correlationId = "corr-post-${UUID.randomUUID()}",
        causationId = "cause-post-${UUID.randomUUID()}"
    )

    @Test
    fun `TC-001-R1 PKR and USD are accepted with original currency and exact minor units`() {
        val pkrOwnerId = UUID.randomUUID()
        val pkrAccount = walletService.createAccount(
            createCommand("PKR", pkrOwnerId, initialBalanceMinorUnits = 10_001L)
        ).account
        assertEquals("PKR", pkrAccount.currencyCode)
        assertEquals(10_001L, pkrAccount.currentBalanceMinorUnits)
        assertEquals(10_001L, pkrAccount.availableBalanceMinorUnits)

        val usdOwnerId = UUID.randomUUID()
        val usdAccount = walletService.createAccount(
            createCommand("USD", usdOwnerId, initialBalanceMinorUnits = 10_001L)
        ).account
        assertEquals("USD", usdAccount.currencyCode)
        assertEquals(10_001L, usdAccount.availableBalanceMinorUnits)

        val posting = ledgerService.postTransaction(postingCommand("PKR", 10_001L))
        assertEquals("PKR", posting.currencyCode)
        assertEquals(10_001L, posting.totalDebitsMinorUnits)
        assertEquals(10_001L, posting.totalCreditsMinorUnits)
        assertEquals(true, posting.isBalanced)

        assertEquals(10_001L, ledgerStore.findBalance("tenant-alpha-currency", "PLAYER:alpha-player", "PKR"))
        assertEquals(-10_001L, ledgerStore.findBalance("tenant-alpha-currency", "ESCROW:alpha-house", "PKR"))
    }

    @Test
    fun `TC-001-R2 INR EUR empty and malformed currency are denied with zero journal writes`() {
        for (unsupported in listOf("INR", "EUR", "PK", "pkr")) {
            assertEquals(false, SupportedAlphaCurrencyPolicy.isSupported(unsupported))
            val ownerId = UUID.randomUUID()
            assertFailsWith<InvalidCurrencyException> {
                walletService.createAccount(createCommand(unsupported, ownerId))
            }
            assertTrue(walletStore.listAccountsByOwner("tenant-alpha-currency", ownerId).isEmpty())
        }

        for (blank in listOf("", "   ")) {
            assertFailsWith<InvalidCurrencyException> {
                SupportedAlphaCurrencyPolicy.validate(blank)
            }
            assertFailsWith<InvalidCurrencyException> {
                walletService.transferFunds(
                    TransferFundsCommand(
                        principal = adminPrincipal,
                        tenantId = "tenant-alpha-currency",
                        sourceAccountId = UUID.randomUUID(),
                        destinationAccountId = UUID.randomUUID(),
                        amountMinorUnits = 7_500L,
                        currencyCode = blank,
                        idempotencyKey = "idem-transfer-${UUID.randomUUID()}",
                        correlationId = "corr-transfer",
                        causationId = "cause-transfer"
                    )
                )
            }
        }

        assertEquals(0, ledgerStore.findAllLegsForTenant("tenant-alpha-currency").size)
        assertEquals(0, ledgerStore.findAllTransactionsForTenant("tenant-alpha-currency").size)
    }

    @Test
    fun `TC-001-R3 fractional minor units and overflow are rejected without rounding or wraparound`() {
        assertFailsWith<InvalidAmountException> {
            SupportedAlphaCurrencyPolicy.parseMajorUnitsText("1.001")
        }
        assertFailsWith<InvalidAmountException> {
            SupportedAlphaCurrencyPolicy.parseMajorUnitsText("${Long.MAX_VALUE}0")
        }
        assertEquals(10_001L, SupportedAlphaCurrencyPolicy.parseMajorUnitsText("100.01"))
        assertEquals(1_000_100L, SupportedAlphaCurrencyPolicy.parseMajorUnitsText("10001"))

        assertEquals(1L, SupportedAlphaCurrencyPolicy.parseMajorUnitsText("0.01"))

        assertFailsWith<PostingInvalidException> {
            ledgerService.postTransaction(
                PostTransactionCommand(
                    principal = adminPrincipal,
                    tenantId = "tenant-alpha-currency",
                    transactionReference = "overflow-tx-${UUID.randomUUID()}",
                    currencyCode = "PKR",
                    entries = listOf(
                        JournalEntryDraft("PLAYER:overflow-a", JournalEntryDirection.DEBIT, Long.MAX_VALUE, "PKR", "leg one"),
                        JournalEntryDraft("ESCROW:overflow-b", JournalEntryDirection.CREDIT, 5_001L, "PKR", "leg two")
                    ),
                    idempotencyKey = "idem-overflow-${UUID.randomUUID()}",
                    correlationId = "corr-overflow",
                    causationId = "cause-overflow"
                )
            )
        }
        assertEquals(0, ledgerStore.findAllLegsForTenant("tenant-alpha-currency").size)

        val overflowSource = walletService.createAccount(
            createCommand("USD", UUID.randomUUID(), initialBalanceMinorUnits = Long.MAX_VALUE)
        ).account
        val overflowDestination = walletService.createAccount(
            createCommand("USD", UUID.randomUUID(), initialBalanceMinorUnits = Long.MAX_VALUE)
        ).account
        assertFailsWith<InvalidAmountException> {
            walletService.transferFunds(
                TransferFundsCommand(
                    principal = adminPrincipal,
                    tenantId = "tenant-alpha-currency",
                    sourceAccountId = overflowSource.accountId,
                    destinationAccountId = overflowDestination.accountId,
                    amountMinorUnits = 1L,
                    currencyCode = "USD",
                    idempotencyKey = "idem-overflow-transfer-${UUID.randomUUID()}",
                    correlationId = "corr-overflow-transfer",
                    causationId = "cause-overflow-transfer",
                    expectedVersion = overflowSource.version
                )
            )
        }
    }

    @Test
    fun `TC-001-R4 absent creation currency defaults to PKR and explicit USD selection stays USD`() {
        val defaultOwnerId = UUID.randomUUID()
        val defaultedAccount = walletService.createAccount(
            createCommand("   ", defaultOwnerId)
        ).account
        assertEquals("PKR", defaultedAccount.currencyCode)

        val explicitOwnerId = UUID.randomUUID()
        val explicitAccount = walletService.createAccount(
            createCommand("USD", explicitOwnerId)
        ).account
        assertEquals("USD", explicitAccount.currencyCode)

        assertFailsWith<InvalidAmountException> {
            SupportedAlphaCurrencyPolicy.parseMajorUnitsText("")
        }
        assertFailsWith<InvalidAmountException> {
            SupportedAlphaCurrencyPolicy.parseMajorUnitsText("   ")
        }
        assertFailsWith<InvalidAmountException> {
            SupportedAlphaCurrencyPolicy.parseMajorUnitsText(null)
        }
        assertFailsWith<InvalidAmountException> {
            SupportedAlphaCurrencyPolicy.parseMajorUnitsText("abc")
        }
    }


    @Test
    fun `TC-001-R5 default posting boundary enforces the alpha policy and the legacy ISO route is an explicit opt-in`() {
        for (unsupported in listOf("INR", "EUR", "GBP", "", "PK")) {
            assertFailsWith<PostingInvalidException> {
                ledgerService.postTransaction(postingCommand(unsupported.ifBlank { "INR" }, 5_000L))
            }
        }

        assertEquals(0, ledgerStore.findAllLegsForTenant("tenant-alpha-currency").size)
        assertEquals(0, ledgerStore.findAllTransactionsForTenant("tenant-alpha-currency").size)

        val legacyService = LedgerPostingService(ledgerStore, clock, LegacyIsoCurrencyPostingPolicy)
        val legacyPosting = legacyService.postTransaction(postingCommand("INR", 2_500L))
        assertEquals("INR", legacyPosting.currencyCode)
        assertEquals(2_500L, legacyPosting.totalDebitsMinorUnits)
    }
}
