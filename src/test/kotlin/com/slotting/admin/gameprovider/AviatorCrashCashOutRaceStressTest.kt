package com.slotting.admin.gameprovider

import com.slotting.admin.auth.AdminRole
import com.slotting.admin.auth.AuthenticatedPrincipal
import com.slotting.admin.auth.PrincipalKind
import com.slotting.admin.identity.AmlComplianceStatus
import com.slotting.admin.identity.JdbcPlayerRegistrationStore
import com.slotting.admin.identity.KycComplianceStatus
import com.slotting.admin.identity.PlayerComplianceProfile
import com.slotting.admin.identity.ResponsiblePlayProfile
import com.slotting.admin.identity.ServerEligibilityStore
import com.slotting.admin.infra.PostgresIntegrationSupport
import com.slotting.admin.ledger.JdbcLedgerJournalStore
import com.slotting.admin.ledger.JournalEntryDirection
import com.slotting.admin.ledger.JournalEntryDraft
import com.slotting.admin.ledger.LedgerPostingService
import com.slotting.admin.ledger.PostTransactionCommand
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.assertThrows
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.boot.test.context.SpringBootTest
import org.springframework.jdbc.core.JdbcTemplate
import org.springframework.test.context.DynamicPropertyRegistry
import org.springframework.test.context.DynamicPropertySource
import org.springframework.transaction.PlatformTransactionManager
import java.math.BigDecimal
import java.sql.Timestamp
import java.time.Clock
import java.time.Instant
import java.time.LocalDate
import java.time.ZoneOffset
import java.util.UUID
import java.util.concurrent.CountDownLatch
import java.util.concurrent.ExecutionException
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit
import kotlin.test.assertEquals
import kotlin.test.assertNotNull
import kotlin.test.assertTrue

@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.NONE)
class AviatorCrashCashOutRaceStressTest {

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

    private val now = Instant.parse("2026-10-07T11:00:00Z")
    private val clock = Clock.fixed(now, ZoneOffset.UTC)
    private val tenantId = "tenant-tc047-race"
    private val gameId = "AVIATOR"
    private val currency = "INR"
    private val playerUuids = (1..10).map { UUID.randomUUID() }

    private val adminPrincipal = AuthenticatedPrincipal(
        id = "admin-sys-tc047",
        tenantId = tenantId,
        kind = PrincipalKind.ADMIN,
        roles = setOf(AdminRole.SUPER_ADMIN),
    )

    private lateinit var gameStore: JdbcDurableGameWagerAndSettlementStore
    private lateinit var ledgerStore: JdbcLedgerJournalStore
    private lateinit var registrationStore: JdbcPlayerRegistrationStore
    private lateinit var eligibilityStore: ServerEligibilityStore
    private lateinit var ledgerService: LedgerPostingService
    private lateinit var gameService: DurableGameWagerAndSettlementService

    class PausingCrashStore(
        private val delegate: DurableGameWagerAndSettlementStore,
    ) : DurableGameWagerAndSettlementStore by delegate {
        @Volatile var pauseBeforeRoundLock: (() -> Unit)? = null
        @Volatile var pauseAfterRoundLock: (() -> Unit)? = null
        override fun findRoundForUpdate(tenantId: String, gameId: String, roundId: String): GameRoundRecord? {
            pauseBeforeRoundLock?.invoke()
            val round = delegate.findRoundForUpdate(tenantId, gameId, roundId)
            pauseAfterRoundLock?.invoke()
            return round
        }
    }

    @BeforeEach
    fun setUp() {
        clearTenantState()
        gameStore = JdbcDurableGameWagerAndSettlementStore(jdbc)
        ledgerStore = JdbcLedgerJournalStore(jdbc)
        registrationStore = JdbcPlayerRegistrationStore(jdbc)
        eligibilityStore = com.slotting.admin.identity.InMemoryServerEligibilityStore()
        ledgerService = LedgerPostingService(store = ledgerStore, clock = clock)
        gameService = DurableGameWagerAndSettlementService(
            store = gameStore,
            ledgerService = ledgerService,
            registrationStore = registrationStore,
            eligibilityStore = eligibilityStore,
            adminPrincipal = adminPrincipal,
            clock = clock,
            txManager = txManager,
        )
        for (uuid in playerUuids) {
            jdbc.update(
                """
                insert into player_credential (
                    player_id, tenant_id, identifier, password_hash, password_algo,
                    password_salt, iterations, status, version, created_at, updated_at
                ) values (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                on conflict (tenant_id, identifier) do nothing
                """.trimIndent(),
                uuid, tenantId, uuid.toString(), "pbkdf2_sha256_hash", "pbkdf2_sha256", "salt", 10000, "ACTIVE", 1L,
                Timestamp.from(now.minusSeconds(86400)), Timestamp.from(now.minusSeconds(86400))
            )
            eligibilityStore.saveComplianceProfile(
                PlayerComplianceProfile(
                    playerId = uuid,
                    tenantId = tenantId,
                    dateOfBirth = LocalDate.of(1995, 5, 5),
                    kycStatus = KycComplianceStatus.VERIFIED,
                    amlStatus = AmlComplianceStatus.CLEARED,
                    jurisdiction = "DEFAULT",
                    responsiblePlay = ResponsiblePlayProfile(
                        playerId = uuid,
                        selfExcluded = false,
                        singleWagerLimitMinor = 500000L,
                        dailyWagerLimitMinor = 2000000L,
                        currentDailyWagerMinor = 0L
                    )
                )
            )
        }
    }

    private fun clearTenantState() {
        jdbc.update("delete from game_bet_settlement where tenant_id = ?", tenantId)
        jdbc.update("delete from game_accepted_bet where tenant_id = ?", tenantId)
        jdbc.update("delete from game_command_receipt where tenant_id = ?", tenantId)
        jdbc.update("delete from game_cumulative_player_limit where tenant_id = ?", tenantId)
        jdbc.update("delete from game_authoritative_round where tenant_id = ?", tenantId)
        jdbc.update("delete from ledger_leg where tenant_id = ?", tenantId)
        jdbc.update("delete from ledger_idempotency_receipt where tenant_id = ?", tenantId)
        jdbc.update("delete from ledger_transaction where tenant_id = ?", tenantId)
        jdbc.update("delete from admin_outbox_event where tenant_id = ?", tenantId)
        jdbc.update("delete from admin_audit_event where tenant_id = ?", tenantId)
        jdbc.update("delete from admin_operation where tenant_id = ?", tenantId)
        jdbc.update("delete from ledger_account where tenant_id = ?", tenantId)
        jdbc.update("delete from game_command_sequence where tenant_id = ?", tenantId)
        jdbc.update("delete from ledger_version_tracker where tenant_id = ?", tenantId)
    }

    private fun playerPrincipal(uuid: UUID): AuthenticatedPrincipal =
        AuthenticatedPrincipal(id = uuid.toString(), tenantId = tenantId, kind = PrincipalKind.PLAYER, roles = setOf(AdminRole.SUPPORT))

    private fun seedFunds(uuid: UUID, amount: Long) {
        ledgerService.postTransaction(
            PostTransactionCommand(
                principal = adminPrincipal,
                tenantId = tenantId,
                transactionReference = "TX-TC047-SEED-${UUID.randomUUID()}",
                currencyCode = currency,
                entries = listOf(
                    JournalEntryDraft("HOUSE:SEED", JournalEntryDirection.DEBIT, amount, currency),
                    JournalEntryDraft("PLAYER:${uuid}", JournalEntryDirection.CREDIT, amount, currency),
                ),
                idempotencyKey = "IDEM-TC047-SEED-${UUID.randomUUID()}",
                correlationId = "corr-tc047-seed",
                causationId = "caus-tc047-seed",
            )
        )
    }

    private fun createRound(roundId: String) {
        gameService.createOrUpdateRound(
            CreateOrUpdateRoundCommand(
                tenantId = tenantId,
                gameId = gameId,
                roundId = roundId,
                phase = GameRoundPhase.BET_COUNTDOWN,
                roundVersion = 1L,
                currentMultiplier = BigDecimal("1.0000"),
            )
        )
    }

    private fun flyRound(roundId: String, multiplier: BigDecimal = BigDecimal("1.2345")) {
        gameService.createOrUpdateRound(
            CreateOrUpdateRoundCommand(
                tenantId = tenantId,
                gameId = gameId,
                roundId = roundId,
                phase = GameRoundPhase.FLYING,
                roundVersion = 2L,
                currentMultiplier = multiplier,
                crashMultiplier = BigDecimal("10.0000"),
            )
        )
    }

    private fun placeBet(roundId: String, commandId: String, uuid: UUID, wagerMinor: Long) {
        val ack = gameService.processCommand(
            AviatorRestCommand(
                tenantId = tenantId,
                principal = playerPrincipal(uuid),
                commandId = commandId,
                roundId = roundId,
                handId = "hand_primary",
                action = "PLACE_BET",
                wagerMinor = wagerMinor,
                currency = currency,
                correlationId = "corr-$commandId",
            )
        )
        assertEquals(AviatorCommandAckStatus.ACCEPTED, ack.status)
    }

    private fun cashOut(roundId: String, commandId: String, uuid: UUID): AviatorCommandAckResult =
        gameService.processCommand(
            AviatorRestCommand(
                tenantId = tenantId,
                principal = playerPrincipal(uuid),
                commandId = commandId,
                roundId = roundId,
                handId = "hand_primary",
                action = "CASH_OUT",
                currency = currency,
                correlationId = "corr-$commandId",
            )
        )

    private fun crash(roundId: String, multiplier: BigDecimal = BigDecimal("1.1000")): SettleRoundCrashResult =
        gameService.settleRoundCrash(SettleRoundCrashCommand(tenantId, gameId, roundId, multiplier))

    private fun settlementCountForBet(betId: UUID): Int =
        jdbc.queryForObject("select count(*) from game_bet_settlement where tenant_id = ? and bet_id = ?", Int::class.java, tenantId, betId) ?: 0

    private fun assertJournalBalanced() {
        val totalDebits = jdbc.queryForObject(
            "select coalesce(sum(total_debits_minor_units), 0) from ledger_transaction where tenant_id = ?",
            Long::class.java, tenantId
        ) ?: 0L
        val totalCredits = jdbc.queryForObject(
            "select coalesce(sum(total_credits_minor_units), 0) from ledger_transaction where tenant_id = ?",
            Long::class.java, tenantId
        ) ?: 0L
        assertEquals(totalDebits, totalCredits, "Double-entry journal must stay balanced")
    }

    private fun seedRound(roundId: String) {
        playerUuids.forEach { seedFunds(it, 50000L) }
        createRound(roundId)
        playerUuids.forEachIndexed { index, uuid -> placeBet(roundId, "cmd-$roundId-bet-$index", uuid, 101L) }
        flyRound(roundId)
    }

    @Test
    fun `GivenTenAcceptedBets_WhenCrashAndCashOutRaceForOneHundredIterations_ThenEachBetHasOneTerminalOutcome`() {
        val iterations = 100
        for (iteration in 0 until iterations) {
            clearTenantState()
            val roundId = "rnd-tc047-stress-$iteration"
            seedRound(roundId)

            val pool = Executors.newFixedThreadPool(playerUuids.size + 1)
            val startLatch = CountDownLatch(1)
            val futures = mutableListOf<java.util.concurrent.Future<*>>()

            futures.add(pool.submit {
                startLatch.await()
                crash(roundId)
            })
            playerUuids.forEachIndexed { index, uuid ->
                futures.add(pool.submit {
                    startLatch.await()
                    cashOut(roundId, "cmd-tc047-cashout-$iteration-$index", uuid)
                })
            }

            startLatch.countDown()
            futures.forEach { future ->
                try {
                    future.get(5, TimeUnit.SECONDS)
                } catch (e: ExecutionException) {
                    throw AssertionError("Iteration $iteration worker failed: ${e.cause}", e.cause)
                }
            }
            pool.shutdown()
            assertTrue(pool.awaitTermination(5, TimeUnit.SECONDS))

            val bets = gameStore.findBetsForRound(tenantId, gameId, roundId)
            assertEquals(10, bets.size, "Iteration $iteration must have 10 bets")
            assertTrue(
                bets.all { it.status == GameBetStatus.LOST || it.status == GameBetStatus.CASHED_OUT },
                "Iteration $iteration: every bet must be terminal, was ${bets.map { it.status }}",
            )
            bets.forEach { bet ->
                assertEquals(1, settlementCountForBet(bet.betId), "Iteration $iteration bet ${bet.betId} must have exactly one settlement")
            }
            assertEquals(0L, ledgerStore.findBalance(tenantId, "ESCROW:GAME:$gameId", currency), "Iteration $iteration escrow must net to zero")
            assertJournalBalanced()
        }
    }

    @Test
    fun `GivenCashOutCommitsFirst_WhenCrashContinues_ThenCashedOutBetIsPreserved`() {
        val roundId = "rnd-tc047-cashout-first"
        seedRound(roundId)
        val winner = playerUuids.first()

        val pausingStore = PausingCrashStore(gameStore)
        val crashService = DurableGameWagerAndSettlementService(
            store = pausingStore,
            ledgerService = ledgerService,
            registrationStore = registrationStore,
            eligibilityStore = eligibilityStore,
            adminPrincipal = adminPrincipal,
            clock = clock,
            txManager = txManager,
        )

        val crashMayProceed = CountDownLatch(1)
        val crashPaused = CountDownLatch(1)
        pausingStore.pauseBeforeRoundLock = {
            crashPaused.countDown()
            crashMayProceed.await(10, TimeUnit.SECONDS)
        }

        val pool = Executors.newFixedThreadPool(2)
        val crashFuture = pool.submit {
            crashService.settleRoundCrash(SettleRoundCrashCommand(tenantId, gameId, roundId, BigDecimal("1.1000")))
        }
        assertTrue(crashPaused.await(10, TimeUnit.SECONDS), "crash must pause before its exclusive round lock")

        val cashOutAck = cashOut(roundId, "cmd-tc047-cashout-first", winner)
        assertEquals(AviatorCommandAckStatus.ACCEPTED, cashOutAck.status)
        val payout = cashOutAck.result?.payoutMinor
        assertEquals(124L, payout)

        crashMayProceed.countDown()
        crashFuture.get(10, TimeUnit.SECONDS)
        pool.shutdown()

        val winnerBet = gameStore.findBet(tenantId, gameId, roundId, winner.toString(), "hand_primary")
        assertNotNull(winnerBet)
        assertEquals(GameBetStatus.CASHED_OUT, winnerBet.status, "cash-out committed first must be preserved")
        assertEquals(1, settlementCountForBet(winnerBet.betId))
        assertEquals(0L, ledgerStore.findBalance(tenantId, "ESCROW:GAME:$gameId", currency), "escrow must net to zero")

        val others = gameStore.findBetsForRound(tenantId, gameId, roundId).filter { it.betId != winnerBet.betId }
        assertTrue(others.all { it.status == GameBetStatus.LOST }, "remaining accepted bets must settle as losses")
        assertJournalBalanced()
    }

    @Test
    fun `GivenCrashOwnsRoundFirst_WhenCashOutContinues_ThenCashOutHasNoFinancialEffect`() {
        val roundId = "rnd-tc047-crash-first"
        seedRound(roundId)
        val target = playerUuids.first()

        val pausingStore = PausingCrashStore(gameStore)
        val crashService = DurableGameWagerAndSettlementService(
            store = pausingStore,
            ledgerService = ledgerService,
            registrationStore = registrationStore,
            eligibilityStore = eligibilityStore,
            adminPrincipal = adminPrincipal,
            clock = clock,
            txManager = txManager,
        )

        val crashHoldsLock = CountDownLatch(1)
        val crashMayProceed = CountDownLatch(1)
        pausingStore.pauseAfterRoundLock = {
            crashHoldsLock.countDown()
            crashMayProceed.await(10, TimeUnit.SECONDS)
        }

        val pool = Executors.newFixedThreadPool(2)
        val crashFuture = pool.submit {
            crashService.settleRoundCrash(SettleRoundCrashCommand(tenantId, gameId, roundId, BigDecimal("1.1000")))
        }
        assertTrue(crashHoldsLock.await(10, TimeUnit.SECONDS), "crash must hold the exclusive round lock")

        val cashOutFuture: java.util.concurrent.Future<AviatorCommandAckResult> =
            pool.submit(java.util.concurrent.Callable { cashOut(roundId, "cmd-tc047-crash-first", target) })
        Thread.sleep(500)

        crashMayProceed.countDown()
        crashFuture.get(10, TimeUnit.SECONDS)
        val cashOutAck = cashOutFuture.get(10, TimeUnit.SECONDS)
        pool.shutdown()

        assertEquals(AviatorCommandAckStatus.REJECTED, cashOutAck.status, "cash-out after crash must be rejected")
        assertTrue(
            cashOutAck.rejection?.code == AviatorCommandRejectionCode.ROUND_CLOSED || cashOutAck.rejection?.code == AviatorCommandRejectionCode.INVALID_PHASE,
            "cash-out rejection must be terminal-phase, was ${cashOutAck.rejection?.code}",
        )

        val bet = gameStore.findBet(tenantId, gameId, roundId, target.toString(), "hand_primary")
        assertNotNull(bet)
        assertEquals(GameBetStatus.LOST, bet.status)
        assertEquals(1, settlementCountForBet(bet.betId))
        assertJournalBalanced()
    }

    @Test
    fun `GivenAnyRaceWorkerFails_WhenCoordinatorCollectsFutures_ThenTestFails`() {
        val roundId = "rnd-tc047-worker-failure"
        seedRound(roundId)

        val failingStore = object : DurableGameWagerAndSettlementStore by gameStore {
            override fun findBetsForRoundForUpdate(tenantId: String, gameId: String, roundId: String): List<GameAcceptedBetRecord> {
                throw IllegalStateException("SIMULATED_WORKER_FAILURE")
            }
        }
        val failingService = DurableGameWagerAndSettlementService(
            store = failingStore,
            ledgerService = ledgerService,
            registrationStore = registrationStore,
            eligibilityStore = eligibilityStore,
            adminPrincipal = adminPrincipal,
            clock = clock,
            txManager = txManager,
        )

        val pool = Executors.newFixedThreadPool(2)
        val startLatch = CountDownLatch(1)
        val future = pool.submit {
            startLatch.await()
            failingService.settleRoundCrash(SettleRoundCrashCommand(tenantId, gameId, roundId, BigDecimal("1.1000")))
        }
        startLatch.countDown()

        val thrown = assertThrows<ExecutionException> { future.get(10, TimeUnit.SECONDS) }
        assertTrue(thrown.cause is IllegalStateException)
        pool.shutdown()
        assertTrue(pool.awaitTermination(5, TimeUnit.SECONDS))

        val bets = gameStore.findBetsForRound(tenantId, gameId, roundId)
        assertTrue(bets.all { it.status == GameBetStatus.ACCEPTED }, "failed crash must leave no partial state")
        assertEquals(0, jdbc.queryForObject("select count(*) from game_bet_settlement where tenant_id = ? and outcome = 'LOSS_CRASH'", Int::class.java, tenantId))
    }

    @Test
    fun `GivenHistoricalMoneyVectors_WhenRaceHarnessRuns_ThenAmountsRemainExact`() {
        val roundId = "rnd-tc047-golden"
        val uuid = playerUuids.first()
        seedFunds(uuid, 50000L)
        createRound(roundId)
        placeBet(roundId, "cmd-tc047-golden-bet", uuid, 101L)
        flyRound(roundId, BigDecimal("1.2345"))

        val cashOutAck = cashOut(roundId, "cmd-tc047-golden-cashout", uuid)
        assertEquals(AviatorCommandAckStatus.ACCEPTED, cashOutAck.status)
        assertEquals(124L, cashOutAck.result?.payoutMinor)
        assertEquals(50023L, ledgerStore.findBalance(tenantId, "PLAYER:$uuid", currency))
        assertEquals(0L, ledgerStore.findBalance(tenantId, "ESCROW:GAME:$gameId", currency))
        assertJournalBalanced()
    }
}
