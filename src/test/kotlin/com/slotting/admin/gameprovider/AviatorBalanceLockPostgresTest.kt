package com.slotting.admin.gameprovider

import com.slotting.admin.auth.AdminRole
import com.slotting.admin.auth.AuthenticatedPrincipal
import com.slotting.admin.auth.PrincipalKind
import com.slotting.admin.infra.PostgresIntegrationSupport
import com.slotting.admin.ledger.AccountLockTimeoutException
import com.slotting.admin.ledger.InsufficientAccountBalanceException
import com.slotting.admin.ledger.JdbcLedgerJournalStore
import com.slotting.admin.ledger.JournalEntryDirection
import com.slotting.admin.ledger.JournalEntryDraft
import com.slotting.admin.ledger.LedgerJournalStore
import com.slotting.admin.ledger.LedgerPostingService
import com.slotting.admin.ledger.PostingResult
import com.slotting.admin.ledger.PostTransactionCommand
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.boot.test.context.SpringBootTest
import org.springframework.jdbc.core.JdbcTemplate
import org.springframework.test.context.DynamicPropertyRegistry
import org.springframework.test.context.DynamicPropertySource
import org.springframework.transaction.PlatformTransactionManager
import org.springframework.transaction.support.TransactionTemplate
import java.math.BigDecimal
import java.math.RoundingMode
import java.time.Clock
import java.time.Instant
import java.time.ZoneOffset
import java.util.UUID
import java.util.concurrent.ConcurrentLinkedQueue
import java.util.concurrent.CountDownLatch
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit
import kotlin.test.assertEquals
import kotlin.test.assertTrue

@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.NONE)
class AviatorBalanceLockPostgresTest {

    companion object {
        @JvmStatic
        @DynamicPropertySource
        fun postgresProperties(registry: DynamicPropertyRegistry) {
            PostgresIntegrationSupport.configureProperties(registry)
        }
    }

    @Autowired
    private lateinit var jdbc: JdbcTemplate

    @Autowired
    private lateinit var txManager: PlatformTransactionManager

    private val now = Instant.parse("2026-10-05T10:00:00Z")
    private val clock = Clock.fixed(now, ZoneOffset.UTC)
    private val tenantId = "tenant-tc007-balance"
    private val currency = "INR"
    private val playerId = "player-tc007"
    private val playerAccount = "PLAYER:$playerId"

    private val adminPrincipal = AuthenticatedPrincipal(
        id = "admin-sys-tc007",
        tenantId = tenantId,
        kind = PrincipalKind.ADMIN,
        roles = setOf(AdminRole.SUPER_ADMIN),
    )

    private lateinit var ledgerStore: JdbcLedgerJournalStore
    private lateinit var ledgerService: LedgerPostingService

    @BeforeEach
    fun setUp() {
        jdbc.update("delete from ledger_leg where tenant_id = ?", tenantId)
        jdbc.update("delete from ledger_idempotency_receipt where tenant_id = ?", tenantId)
        jdbc.update("delete from ledger_transaction where tenant_id = ?", tenantId)
        jdbc.update("delete from admin_outbox_event where tenant_id = ?", tenantId)
        jdbc.update("delete from admin_audit_event where tenant_id = ?", tenantId)
        jdbc.update("delete from admin_operation where tenant_id = ?", tenantId)
        jdbc.update("delete from ledger_account where tenant_id = ?", tenantId)
        jdbc.update("delete from ledger_version_tracker where tenant_id = ?", tenantId)

        ledgerStore = JdbcLedgerJournalStore(jdbc)
        ledgerService = LedgerPostingService(store = ledgerStore, clock = clock)
    }

    private fun seedFunds(amount: Long) {
        ledgerService.postTransaction(
            PostTransactionCommand(
                principal = adminPrincipal,
                tenantId = tenantId,
                transactionReference = "TX-TC007-SEED-${UUID.randomUUID()}",
                currencyCode = currency,
                entries = listOf(
                    JournalEntryDraft("HOUSE:SEED", JournalEntryDirection.DEBIT, amount, currency),
                    JournalEntryDraft(playerAccount, JournalEntryDirection.CREDIT, amount, currency),
                ),
                idempotencyKey = "IDEM-TC007-SEED-${UUID.randomUUID()}",
                correlationId = "corr-tc007-seed",
                causationId = "caus-tc007-seed",
            )
        )
    }

    private fun postWager(amount: Long, idempotencyKey: String): PostingResult =
        ledgerService.postTransaction(
            PostTransactionCommand(
                principal = adminPrincipal,
                tenantId = tenantId,
                transactionReference = "TX-TC007-WAGER-${UUID.randomUUID()}",
                currencyCode = currency,
                entries = listOf(
                    JournalEntryDraft(playerAccount, JournalEntryDirection.DEBIT, amount, currency),
                    JournalEntryDraft("HOUSE:GAME:AVIATOR", JournalEntryDirection.CREDIT, amount, currency),
                ),
                idempotencyKey = idempotencyKey,
                correlationId = "corr-tc007-wager",
                causationId = "caus-tc007-wager",
                requireNonNegativeAccounts = true,
            )
        )

    private fun ledgerTransactionCount(): Int =
        jdbc.queryForObject("select count(*) from ledger_transaction where tenant_id = ?", Int::class.java, tenantId) ?: 0

    private fun journalBalanced(): Boolean {
        val debits = jdbc.queryForObject(
            "select coalesce(sum(total_debits_minor_units), 0) from ledger_transaction where tenant_id = ?",
            Long::class.java,
            tenantId,
        ) ?: 0L
        val credits = jdbc.queryForObject(
            "select coalesce(sum(total_credits_minor_units), 0) from ledger_transaction where tenant_id = ?",
            Long::class.java,
            tenantId,
        ) ?: 0L
        return debits == credits
    }

    @Test
    fun `GivenBalance100_WhenTwentyWagersOf60Race_ThenAtMostOneDebit`() {
        seedFunds(100L)
        val txTemplate = TransactionTemplate(txManager)
        val pool = Executors.newFixedThreadPool(20)
        val successes = ConcurrentLinkedQueue<Long>()
        val insufficient = ConcurrentLinkedQueue<String>()
        val startLatch = CountDownLatch(1)
        val doneLatch = CountDownLatch(20)

        for (i in 0 until 20) {
            pool.submit {
                startLatch.await()
                try {
                    val result = txTemplate.execute<PostingResult> {
                        postWager(60L, "IDEM-TC007-RACE-$i")
                    }
                    successes.add(result?.totalDebitsMinorUnits ?: -1L)
                } catch (e: InsufficientAccountBalanceException) {
                    insufficient.add(e.errorCode)
                } catch (e: Exception) {
                    insufficient.add("UNEXPECTED:${e.javaClass.simpleName}")
                } finally {
                    doneLatch.countDown()
                }
            }
        }

        startLatch.countDown()
        assertTrue(doneLatch.await(60, TimeUnit.SECONDS), "racing wagers timed out")
        pool.shutdown()

        assertEquals(1, successes.size, "Exactly one wager must debit from balance 100")
        assertEquals(19, insufficient.size, "The other 19 must fail with an insufficient-funds error")
        assertTrue(insufficient.all { it == "INSUFFICIENT_FUNDS" }, "Unlocked check exposed: $insufficient")
        assertEquals(40L, ledgerStore.findBalance(tenantId, playerAccount, currency))
        assertTrue(ledgerStore.findBalance(tenantId, playerAccount, currency) >= 0L)
        assertTrue(journalBalanced())
    }

    @Test
    fun `GivenCreditsAndDebits_WhenSeededInterleavingsRun_ThenFundsAndJournalAgree`() {
        seedFunds(100L)
        val txTemplate = TransactionTemplate(txManager)
        val pool = Executors.newFixedThreadPool(20)
        val acceptedWagers = java.util.concurrent.atomic.AtomicLong(0)
        val creditsPosted = java.util.concurrent.atomic.AtomicLong(0)
        val startLatch = CountDownLatch(1)
        val doneLatch = CountDownLatch(20)

        for (i in 0 until 20) {
            pool.submit {
                startLatch.await()
                try {
                    txTemplate.execute<PostingResult> {
                        if (i % 2 == 0) {
                            ledgerService.postTransaction(
                                PostTransactionCommand(
                                    principal = adminPrincipal,
                                    tenantId = tenantId,
                                    transactionReference = "TX-TC007-CREDIT-${UUID.randomUUID()}",
                                    currencyCode = currency,
                                    entries = listOf(
                                        JournalEntryDraft("HOUSE:SEED", JournalEntryDirection.DEBIT, 60L, currency),
                                        JournalEntryDraft(playerAccount, JournalEntryDirection.CREDIT, 60L, currency),
                                    ),
                                    idempotencyKey = "IDEM-TC007-CREDIT-$i",
                                    correlationId = "corr-tc007-credit",
                                    causationId = "caus-tc007-credit",
                                )
                            ).also { creditsPosted.incrementAndGet() }
                        } else {
                            postWager(60L, "IDEM-TC007-MIX-$i").also { acceptedWagers.incrementAndGet() }
                        }
                    }
                } catch (e: InsufficientAccountBalanceException) {
                } catch (e: Exception) {
                } finally {
                    doneLatch.countDown()
                }
            }
        }

        startLatch.countDown()
        assertTrue(doneLatch.await(60, TimeUnit.SECONDS), "mixed interleavings timed out")
        pool.shutdown()

        val expected = 100L + creditsPosted.get() * 60L - acceptedWagers.get() * 60L
        val balance = ledgerStore.findBalance(tenantId, playerAccount, currency)
        assertTrue(balance >= 0L, "Player balance must never go negative: $balance")
        assertEquals(expected, balance, "Aggregate balance must equal accepted deltas")
        assertTrue(journalBalanced())
    }

    @Test
    fun `GivenAccountLockTimeout_WhenPostingAttempted_ThenNothingCommits`() {
        seedFunds(100L)
        val shortStore = JdbcLedgerJournalStore(jdbc, lockWaitMillis = 250L)
        val shortService = LedgerPostingService(store = shortStore, clock = clock)
        val txTemplate = TransactionTemplate(txManager)
        val lockKey = "$tenantId:$playerAccount:$currency"

        val held = CountDownLatch(1)
        val release = CountDownLatch(1)
        val pool = Executors.newFixedThreadPool(2)
        val holder = pool.submit {
            txTemplate.execute<Unit> {
                jdbc.query("select pg_advisory_xact_lock(hashtext(?))", { _, _ -> }, lockKey)
                held.countDown()
                release.await(10, TimeUnit.SECONDS)
            }
        }
        assertTrue(held.await(10, TimeUnit.SECONDS), "holder must acquire the account lock")

        val before = ledgerTransactionCount()
        val timedOut = try {
            txTemplate.execute<PostingResult> {
                shortService.postTransaction(
                    PostTransactionCommand(
                        principal = adminPrincipal,
                        tenantId = tenantId,
                        transactionReference = "TX-TC007-TIMEOUT-${UUID.randomUUID()}",
                        currencyCode = currency,
                        entries = listOf(
                            JournalEntryDraft(playerAccount, JournalEntryDirection.DEBIT, 60L, currency),
                            JournalEntryDraft("HOUSE:GAME:AVIATOR", JournalEntryDirection.CREDIT, 60L, currency),
                        ),
                        idempotencyKey = "IDEM-TC007-TIMEOUT",
                        correlationId = "corr-tc007-timeout",
                        causationId = "caus-tc007-timeout",
                        requireNonNegativeAccounts = true,
                    )
                )
            }
            false
        } catch (e: AccountLockTimeoutException) {
            true
        }
        assertTrue(timedOut, "Locked account must produce a typed retryable timeout")
        assertEquals(before, ledgerTransactionCount(), "No journal rows may commit on lock timeout")

        release.countDown()
        holder.get(10, TimeUnit.SECONDS)

        val retry = txTemplate.execute<PostingResult> {
            postWager(60L, "IDEM-TC007-RETRY")
        }
        assertTrue(retry != null)
        assertEquals(40L, ledgerStore.findBalance(tenantId, playerAccount, currency))
        pool.shutdown()
    }

    @Test
    fun `GivenWagerPosting_WhenLocksAreObserved_ThenOnlyPlayerAccountIsLockedBeforeInsert`() {
        seedFunds(100L)
        val events = java.util.Collections.synchronizedList(mutableListOf<String>())
        val tracingStore = object : LedgerJournalStore by ledgerStore {
            override fun lockAccount(tenantId: String, accountReference: String, currencyCode: String): Boolean {
                events.add("LOCK:$accountReference")
                return ledgerStore.lockAccount(tenantId, accountReference, currencyCode)
            }

            override fun save(
                result: PostingResult,
                legs: List<com.slotting.admin.ledger.JournalEntryRecord>,
                payloadDigest: String,
                audit: com.slotting.admin.auth.AuditEvent,
                outbox: com.slotting.admin.auth.OutboxEvent,
            ) {
                events.add("SAVE")
                ledgerStore.save(result, legs, payloadDigest, audit, outbox)
            }
        }
        val tracingService = LedgerPostingService(store = tracingStore, clock = clock)
        val txTemplate = TransactionTemplate(txManager)

        txTemplate.execute<PostingResult> {
            tracingService.postTransaction(
                PostTransactionCommand(
                    principal = adminPrincipal,
                    tenantId = tenantId,
                    transactionReference = "TX-TC007-TRACE-${UUID.randomUUID()}",
                    currencyCode = currency,
                    entries = listOf(
                        JournalEntryDraft(playerAccount, JournalEntryDirection.DEBIT, 60L, currency),
                        JournalEntryDraft("HOUSE:GAME:AVIATOR", JournalEntryDirection.CREDIT, 60L, currency),
                    ),
                    idempotencyKey = "IDEM-TC007-TRACE",
                    correlationId = "corr-tc007-trace",
                    causationId = "caus-tc007-trace",
                    requireNonNegativeAccounts = true,
                )
            )
        }

        val lockIndex = events.indexOfFirst { it == "LOCK:$playerAccount" }
        val saveIndex = events.indexOfFirst { it == "SAVE" }
        assertTrue(lockIndex >= 0, "The debited PLAYER account must be locked: $events")
        assertTrue(saveIndex > lockIndex, "The account lock must be acquired before the journal insert: $events")
        assertTrue(events.none { it.startsWith("LOCK:HOUSE") || it.startsWith("LOCK:ESCROW") }, "Only the debited PLAYER account may be locked: $events")
    }

    @Test
    fun `GivenHistoricalMoneyAndOutcomeVectors_WhenRefactoredPathRuns_ThenSemanticsStayUnchanged`() {
        val wagerMinor = 101L
        val multiplier = BigDecimal("1.2345")
        assertEquals(
            124L,
            BigDecimal.valueOf(wagerMinor).multiply(multiplier).setScale(0, RoundingMode.FLOOR).longValueExact(),
        )

        val startingBalance = 50000L
        seedFunds(startingBalance)
        val txTemplate = TransactionTemplate(txManager)

        txTemplate.execute<PostingResult> {
            ledgerService.postTransaction(
                PostTransactionCommand(
                    principal = adminPrincipal,
                    tenantId = tenantId,
                    transactionReference = "TX-TC007-GOLDEN-RESERVE-${UUID.randomUUID()}",
                    currencyCode = currency,
                    entries = listOf(
                        JournalEntryDraft(playerAccount, JournalEntryDirection.DEBIT, wagerMinor, currency),
                        JournalEntryDraft("ESCROW:GAME:AVIATOR", JournalEntryDirection.CREDIT, wagerMinor, currency),
                    ),
                    idempotencyKey = "IDEM-TC007-GOLDEN-RESERVE",
                    correlationId = "corr-tc007-golden-reserve",
                    causationId = "caus-tc007-golden-reserve",
                    requireNonNegativeAccounts = true,
                )
            )
        }
        assertEquals(startingBalance - wagerMinor, ledgerStore.findBalance(tenantId, playerAccount, currency))

        txTemplate.execute<PostingResult> {
            ledgerService.postTransaction(
                PostTransactionCommand(
                    principal = adminPrincipal,
                    tenantId = tenantId,
                    transactionReference = "TX-TC007-GOLDEN-REFUND-${UUID.randomUUID()}",
                    currencyCode = currency,
                    entries = listOf(
                        JournalEntryDraft("ESCROW:GAME:AVIATOR", JournalEntryDirection.DEBIT, wagerMinor, currency),
                        JournalEntryDraft(playerAccount, JournalEntryDirection.CREDIT, wagerMinor, currency),
                    ),
                    idempotencyKey = "IDEM-TC007-GOLDEN-REFUND",
                    correlationId = "corr-tc007-golden-refund",
                    causationId = "caus-tc007-golden-refund",
                )
            )
        }
        assertEquals(startingBalance, ledgerStore.findBalance(tenantId, playerAccount, currency))
        assertTrue(journalBalanced())
    }
}
