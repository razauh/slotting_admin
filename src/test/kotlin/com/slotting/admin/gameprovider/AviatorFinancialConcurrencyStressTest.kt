package com.slotting.admin.gameprovider

import com.slotting.admin.auth.AdminRole
import com.slotting.admin.auth.AuthenticatedPrincipal
import com.slotting.admin.auth.PrincipalKind
import com.slotting.admin.identity.AmlComplianceStatus
import com.slotting.admin.identity.InMemoryServerEligibilityStore
import com.slotting.admin.identity.JdbcPlayerRegistrationStore
import com.slotting.admin.identity.KycComplianceStatus
import com.slotting.admin.identity.PlayerComplianceProfile
import com.slotting.admin.identity.ResponsiblePlayProfile
import com.slotting.admin.infra.PostgresIntegrationSupport
import com.slotting.admin.ledger.JdbcLedgerJournalStore
import com.slotting.admin.ledger.JournalEntryDirection
import com.slotting.admin.ledger.JournalEntryDraft
import com.slotting.admin.ledger.InsufficientAccountBalanceException
import com.slotting.admin.ledger.LedgerPostingService
import com.slotting.admin.ledger.PostTransactionCommand
import org.junit.jupiter.api.Test
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.boot.test.context.SpringBootTest
import org.springframework.boot.test.mock.mockito.MockBean
import org.springframework.jdbc.core.JdbcTemplate
import org.springframework.test.context.DynamicPropertyRegistry
import org.springframework.test.context.DynamicPropertySource
import org.springframework.transaction.PlatformTransactionManager
import org.springframework.transaction.support.TransactionTemplate
import java.math.BigDecimal
import java.sql.Timestamp
import java.time.Clock
import java.time.Instant
import java.time.LocalDate
import java.time.ZoneOffset
import java.util.UUID
import java.util.concurrent.Callable
import java.util.concurrent.CountDownLatch
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicInteger
import kotlin.test.assertEquals
import kotlin.test.assertTrue

@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.NONE)
class AviatorFinancialConcurrencyStressTest {
    @MockBean
    private lateinit var snapshotAndEventService: AuthoritativeGameSnapshotAndEventService

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

    private val tenantId = "tenant-tc034-overdraft"
    private val gameId = "AVIATOR"
    private val currency = "INR"
    private val now = Instant.parse("2026-10-11T00:00:00Z")
    private val clock = Clock.fixed(now, ZoneOffset.UTC)

    @Test
    fun givenTwoOwnersWithOneHundredMinorUnits_whenFortySixtyMinorWagersRace_thenEachOwnerHasOneDebitAndNoNegativeBalance() {
        val runId = UUID.randomUUID().toString().take(8)
        val owners = listOf(UUID.randomUUID(), UUID.randomUUID())
        val admin = AuthenticatedPrincipal(
            id = "admin-tc034-stress",
            tenantId = tenantId,
            kind = PrincipalKind.ADMIN,
            roles = setOf(AdminRole.SUPER_ADMIN),
        )
        val gameStore = JdbcDurableGameWagerAndSettlementStore(jdbc)
        val ledgerStore = JdbcLedgerJournalStore(jdbc)
        val ledgerService = LedgerPostingService(ledgerStore, clock)
        val eligibilityStore = InMemoryServerEligibilityStore()
        val service = DurableGameWagerAndSettlementService(
            store = gameStore,
            ledgerService = ledgerService,
            registrationStore = JdbcPlayerRegistrationStore(jdbc),
            eligibilityStore = eligibilityStore,
            adminPrincipal = admin,
            clock = clock,
            txManager = txManager,
        )

        owners.forEachIndexed { index, owner ->
            val ownerId = owner.toString()
            jdbc.update(
                """
                insert into player_credential (
                    player_id, tenant_id, identifier, password_hash, password_algo,
                    password_salt, iterations, status, version, created_at, updated_at
                ) values (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """.trimIndent(),
                owner,
                tenantId,
                ownerId,
                "pbkdf2_sha256_hash",
                "pbkdf2_sha256",
                "salt",
                10000,
                "ACTIVE",
                1L,
                Timestamp.from(now.minusSeconds(86400)),
                Timestamp.from(now.minusSeconds(86400)),
            )
            eligibilityStore.saveComplianceProfile(
                PlayerComplianceProfile(
                    playerId = owner,
                    tenantId = tenantId,
                    dateOfBirth = LocalDate.of(1995, 5, 5),
                    kycStatus = KycComplianceStatus.VERIFIED,
                    amlStatus = AmlComplianceStatus.CLEARED,
                    jurisdiction = "DEFAULT",
                    responsiblePlay = ResponsiblePlayProfile(
                        playerId = owner,
                        selfExcluded = false,
                        singleWagerLimitMinor = 500L,
                        dailyWagerLimitMinor = 2000L,
                        currentDailyWagerMinor = 0L,
                    ),
                ),
            )
            ledgerService.postTransaction(
                PostTransactionCommand(
                    principal = admin,
                    tenantId = tenantId,
                    transactionReference = "TX-TC034-SEED-$runId-$index",
                    currencyCode = currency,
                    entries = listOf(
                        JournalEntryDraft("HOUSE:SEED", JournalEntryDirection.DEBIT, 100L, currency),
                        JournalEntryDraft("PLAYER:$ownerId", JournalEntryDirection.CREDIT, 100L, currency),
                    ),
                    idempotencyKey = "IDEM-TC034-SEED-$runId-$index",
                    correlationId = "corr-tc034-seed-$runId-$index",
                    causationId = "caus-tc034-seed-$runId-$index",
                ),
            )
        }

        val roundId = "rnd-tc034-overdraft-$runId"
        service.createOrUpdateRound(
            CreateOrUpdateRoundCommand(
                tenantId = tenantId,
                gameId = gameId,
                roundId = roundId,
                phase = GameRoundPhase.BET_COUNTDOWN,
                roundVersion = 1L,
                currentMultiplier = BigDecimal("1.0000"),
            ),
        )

        val contenders = owners.flatMapIndexed { ownerIndex, owner ->
            (0 until 20).map { contender ->
                val ownerId = owner.toString()
                val principal = AuthenticatedPrincipal(
                    id = ownerId,
                    tenantId = tenantId,
                    kind = PrincipalKind.PLAYER,
                    roles = setOf(AdminRole.SUPPORT),
                )
                AviatorRestCommand(
                    tenantId = tenantId,
                    principal = principal,
                    commandId = "cmd-tc034-$runId-$ownerIndex-$contender",
                    roundId = roundId,
                    handId = "hand-$ownerIndex-$contender",
                    action = "PLACE_BET",
                    wagerMinor = 60L,
                    currency = currency,
                    correlationId = "corr-tc034-$runId-$ownerIndex-$contender",
                )
            }
        }.shuffled(java.util.Random(34034L))

        val pool = Executors.newFixedThreadPool(40)
        val ready = CountDownLatch(contenders.size)
        val start = CountDownLatch(1)
        try {
            val results = contenders.map { command ->
                pool.submit(Callable {
                    ready.countDown()
                    check(start.await(30, TimeUnit.SECONDS))
                    service.processCommand(command)
                })
            }
            assertTrue(ready.await(30, TimeUnit.SECONDS), "all logical contenders must reach the shared start barrier")
            start.countDown()
            val acknowledgements = results.map { it.get(120, TimeUnit.SECONDS) }
            owners.forEach { owner ->
                val accepted = contenders.zip(acknowledgements).filter { (command, acknowledgement) ->
                    command.principal?.id == owner.toString() && acknowledgement.status == AviatorCommandAckStatus.ACCEPTED
                }
                assertEquals(1, accepted.size, "one 60-minor wager may be funded from a 100-minor owner balance")
                assertEquals(40L, ledgerStore.findBalance(tenantId, "PLAYER:$owner", currency))
            }
            assertEquals(
                0,
                jdbc.queryForObject(
                    "select count(*) from (select account_reference from ledger_leg where tenant_id = ? and account_reference like 'PLAYER:%' group by account_reference having sum(case when direction = 'CREDIT' then amount_minor_units else -amount_minor_units end) < 0) negative_accounts",
                    Int::class.java,
                    tenantId,
                ) ?: 0,
            )
            val debits = jdbc.queryForObject(
                "select count(*) from ledger_transaction where tenant_id = ? and idempotency_key like 'bet:$tenantId:$gameId:$roundId:%'",
                Int::class.java,
                tenantId,
            ) ?: 0
            assertEquals(2, debits, "each owner may have exactly one durable wager reservation")
            assertEquals(
                jdbc.queryForObject("select coalesce(sum(total_debits_minor_units), 0) from ledger_transaction where tenant_id = ?", Long::class.java, tenantId),
                jdbc.queryForObject("select coalesce(sum(total_credits_minor_units), 0) from ledger_transaction where tenant_id = ?", Long::class.java, tenantId),
                "tenant journal must reconcile after the concurrent run",
            )
        } finally {
            start.countDown()
            pool.shutdownNow()
            assertTrue(pool.awaitTermination(10, TimeUnit.SECONDS), "all contender workers must terminate")
        }
    }

    @Test
    fun givenSeededDebitRaces_whenOneThousandIterationsRun_thenExactlyOneDebitCommitsPerIteration() {
        val iterationTenant = "$tenantId-1000-${UUID.randomUUID().toString().take(8)}"
        val owner = UUID.randomUUID()
        val ownerId = owner.toString()
        val admin = AuthenticatedPrincipal(
            id = "admin-tc034-iterations",
            tenantId = iterationTenant,
            kind = PrincipalKind.ADMIN,
            roles = setOf(AdminRole.SUPER_ADMIN),
        )
        val store = JdbcLedgerJournalStore(jdbc)
        val postingService = LedgerPostingService(store, clock)
        val transaction = TransactionTemplate(txManager)
        val seed = PostTransactionCommand(
            principal = admin,
            tenantId = iterationTenant,
            transactionReference = "TX-TC034-1000-SEED",
            currencyCode = currency,
            entries = listOf(
                JournalEntryDraft("HOUSE:SEED", JournalEntryDirection.DEBIT, 100L, currency),
                JournalEntryDraft("PLAYER:$ownerId", JournalEntryDirection.CREDIT, 100L, currency),
            ),
            idempotencyKey = "IDEM-TC034-1000-SEED",
            correlationId = "corr-tc034-1000-seed",
            causationId = "caus-tc034-1000-seed",
        )
        transaction.execute { postingService.postTransaction(seed) }

        val pool = Executors.newFixedThreadPool(2)
        val random = java.util.Random(340340L)
        val committedDebits = AtomicInteger()
        try {
            repeat(1000) { iteration ->
                val ready = CountDownLatch(2)
                val start = CountDownLatch(1)
                val contenders = listOf(0, 1).shuffled(random).map { contender ->
                    pool.submit(Callable {
                        ready.countDown()
                        check(start.await(10, TimeUnit.SECONDS))
                        try {
                            transaction.execute {
                                postingService.postTransaction(
                                    PostTransactionCommand(
                                        principal = admin,
                                        tenantId = iterationTenant,
                                        transactionReference = "TX-TC034-1000-$iteration-$contender",
                                        currencyCode = currency,
                                        entries = listOf(
                                            JournalEntryDraft("PLAYER:$ownerId", JournalEntryDirection.DEBIT, 60L, currency),
                                            JournalEntryDraft("ESCROW:GAME:$gameId", JournalEntryDirection.CREDIT, 60L, currency),
                                        ),
                                        idempotencyKey = "IDEM-TC034-1000-$iteration-$contender",
                                        correlationId = "corr-tc034-1000-$iteration-$contender",
                                        causationId = "caus-tc034-1000-$iteration-$contender",
                                        requireNonNegativeAccounts = true,
                                    ),
                                )
                            }
                            true
                        } catch (_: InsufficientAccountBalanceException) {
                            false
                        }
                    })
                }
                assertTrue(ready.await(10, TimeUnit.SECONDS), "iteration $iteration contenders must reach the barrier")
                start.countDown()
                val outcomes = contenders.map { it.get(15, TimeUnit.SECONDS) }
                assertEquals(1, outcomes.count { it }, "iteration $iteration must commit exactly one debit")
                assertEquals(40L, store.findBalance(iterationTenant, "PLAYER:$ownerId", currency), "iteration $iteration balance")
                assertTrue(store.findBalance(iterationTenant, "PLAYER:$ownerId", currency) >= 0L, "iteration $iteration balance cannot be negative")
                committedDebits.incrementAndGet()
                transaction.execute {
                    postingService.postTransaction(
                        PostTransactionCommand(
                            principal = admin,
                            tenantId = iterationTenant,
                            transactionReference = "TX-TC034-1000-REFILL-$iteration",
                            currencyCode = currency,
                            entries = listOf(
                                JournalEntryDraft("HOUSE:SEED", JournalEntryDirection.DEBIT, 60L, currency),
                                JournalEntryDraft("PLAYER:$ownerId", JournalEntryDirection.CREDIT, 60L, currency),
                            ),
                            idempotencyKey = "IDEM-TC034-1000-REFILL-$iteration",
                            correlationId = "corr-tc034-1000-refill-$iteration",
                            causationId = "caus-tc034-1000-refill-$iteration",
                        ),
                    )
                }
            }
        } finally {
            pool.shutdownNow()
            assertTrue(pool.awaitTermination(10, TimeUnit.SECONDS), "debit workers must terminate")
        }

        assertEquals(1000, committedDebits.get())
        assertEquals(
            1000,
            jdbc.queryForObject(
                "select count(*) from ledger_transaction where tenant_id = ? and idempotency_key like 'IDEM-TC034-1000-%' and idempotency_key not like '%REFILL%' and idempotency_key not like '%SEED%'",
                Int::class.java,
                iterationTenant,
            ),
        )
        assertEquals(100L, store.findBalance(iterationTenant, "PLAYER:$ownerId", currency))
        assertEquals(
            jdbc.queryForObject("select coalesce(sum(total_debits_minor_units), 0) from ledger_transaction where tenant_id = ?", Long::class.java, iterationTenant),
            jdbc.queryForObject("select coalesce(sum(total_credits_minor_units), 0) from ledger_transaction where tenant_id = ?", Long::class.java, iterationTenant),
        )
    }
}
