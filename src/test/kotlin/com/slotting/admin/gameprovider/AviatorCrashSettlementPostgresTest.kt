package com.slotting.admin.gameprovider

import com.slotting.admin.auth.AdminRole
import com.slotting.admin.auth.AuditEvent
import com.slotting.admin.auth.AuthenticatedPrincipal
import com.slotting.admin.auth.OutboxEvent
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
import com.slotting.admin.ledger.JournalEntryRecord
import com.slotting.admin.ledger.LedgerJournalStore
import com.slotting.admin.ledger.LedgerPostingService
import com.slotting.admin.ledger.PostTransactionCommand
import com.slotting.admin.ledger.PostingResult
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.assertThrows
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.boot.test.context.SpringBootTest
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
import java.util.concurrent.ConcurrentLinkedQueue
import java.util.concurrent.CountDownLatch
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicInteger
import kotlin.test.assertEquals
import kotlin.test.assertNotNull
import kotlin.test.assertTrue

@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.NONE)
class AviatorCrashSettlementPostgresTest {

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

    private val now = Instant.parse("2026-10-07T10:00:00Z")
    private val clock = Clock.fixed(now, ZoneOffset.UTC)
    private val tenantId = "tenant-tc011-crash"
    private val gameId = "AVIATOR"
    private val currency = "INR"

    private val playerUuids = (1..10).map { UUID.randomUUID() }

    private val adminPrincipal = AuthenticatedPrincipal(
        id = "admin-sys-tc011",
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

    class SimulatedFailpointException(message: String) : RuntimeException(message)

    class FailOnNthSettlementStore(
        private val delegate: DurableGameWagerAndSettlementStore,
    ) : DurableGameWagerAndSettlementStore by delegate {
        var failOnNth: Int = 0
        private val settlementCalls = AtomicInteger(0)
        override fun saveSettlement(settlement: GameBetSettlementRecord) {
            delegate.saveSettlement(settlement)
            if (failOnNth > 0 && settlementCalls.incrementAndGet() == failOnNth) {
                throw SimulatedFailpointException("Triggered failpoint on settlement $failOnNth")
            }
        }
    }

    class CrashLockTracingStore(
        private val delegate: DurableGameWagerAndSettlementStore,
        val eventLog: MutableList<Pair<String, Int>> = mutableListOf(),
    ) : DurableGameWagerAndSettlementStore by delegate {
        override fun findRoundForUpdate(tenantId: String, gameId: String, roundId: String): GameRoundRecord? {
            eventLog.add("ROUND_EXCLUSIVE" to 2)
            return delegate.findRoundForUpdate(tenantId, gameId, roundId)
        }

        override fun findBetsForRoundForUpdate(tenantId: String, gameId: String, roundId: String): List<GameAcceptedBetRecord> {
            eventLog.add("BETS_FOR_UPDATE" to 3)
            return delegate.findBetsForRoundForUpdate(tenantId, gameId, roundId)
        }
    }

    class CrashLockTracingLedgerStore(
        private val delegate: LedgerJournalStore,
        private val eventLog: MutableList<Pair<String, Int>>,
    ) : LedgerJournalStore by delegate {
        override fun save(
            result: PostingResult,
            legs: List<JournalEntryRecord>,
            payloadDigest: String,
            audit: AuditEvent,
            outbox: OutboxEvent,
        ) {
            eventLog.add("LEDGER_ACCOUNT_WRITE" to 4)
            delegate.save(result, legs, payloadDigest, audit, outbox)
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
                transactionReference = "TX-TC011-SEED-${UUID.randomUUID()}",
                currencyCode = currency,
                entries = listOf(
                    JournalEntryDraft("HOUSE:SEED", JournalEntryDirection.DEBIT, amount, currency),
                    JournalEntryDraft("PLAYER:${uuid}", JournalEntryDirection.CREDIT, amount, currency),
                ),
                idempotencyKey = "IDEM-TC011-SEED-${UUID.randomUUID()}",
                correlationId = "corr-tc011-seed",
                causationId = "caus-tc011-seed",
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
                crashMultiplier = BigDecimal("1.1000"),
            )
        )
    }

    private fun placeBet(roundId: String, commandId: String, uuid: UUID, wagerMinor: Long): AviatorCommandAckResult {
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
        return ack
    }

    private fun crash(roundId: String, multiplier: BigDecimal = BigDecimal("1.1000")): SettleRoundCrashResult =
        gameService.settleRoundCrash(SettleRoundCrashCommand(tenantId, gameId, roundId, multiplier))

    private fun crashSettlementCount(): Int =
        jdbc.queryForObject(
            "select count(*) from game_bet_settlement where tenant_id = ? and outcome = 'LOSS_CRASH'",
            Int::class.java,
            tenantId,
        ) ?: 0

    private fun ledgerTransactionCount(): Int =
        jdbc.queryForObject("select count(*) from ledger_transaction where tenant_id = ?", Int::class.java, tenantId) ?: 0

    private fun assertJournalBalanced() {
        val totalDebits = jdbc.queryForObject(
            "select coalesce(sum(total_debits_minor_units), 0) from ledger_transaction where tenant_id = ?",
            Long::class.java,
            tenantId,
        ) ?: 0L
        val totalCredits = jdbc.queryForObject(
            "select coalesce(sum(total_credits_minor_units), 0) from ledger_transaction where tenant_id = ?",
            Long::class.java,
            tenantId,
        ) ?: 0L
        assertEquals(totalDebits, totalCredits, "Double-entry journal must stay balanced")
    }

    private fun seedTenBets(roundId: String) {
        playerUuids.forEach { uuid -> seedFunds(uuid, 50000L) }
        createRound(roundId)
        playerUuids.forEachIndexed { index, uuid -> placeBet(roundId, "cmd-tc011-bet-$index", uuid, 101L) }
        flyRound(roundId)
    }

    @Test
    fun `GivenTenAcceptedBets_WhenFifthLossWriteFails_ThenWholeCrashRollsBack`() {
        val roundId = "rnd-tc011-failpoint"
        seedTenBets(roundId)

        val decorated = FailOnNthSettlementStore(gameStore)
        val decoratedService = DurableGameWagerAndSettlementService(
            store = decorated,
            ledgerService = ledgerService,
            registrationStore = registrationStore,
            eligibilityStore = eligibilityStore,
            adminPrincipal = adminPrincipal,
            clock = clock,
            txManager = txManager,
        )
        decorated.failOnNth = 5

        val ledgerBefore = ledgerTransactionCount()
        assertThrows<SimulatedFailpointException> {
            decoratedService.settleRoundCrash(SettleRoundCrashCommand(tenantId, gameId, roundId, BigDecimal("1.1000")))
        }

        val round = gameStore.findRound(tenantId, gameId, roundId)
        assertNotNull(round)
        assertEquals(GameRoundPhase.FLYING, round.phase, "Round must remain FLYING after rollback")
        val bets = gameStore.findBetsForRound(tenantId, gameId, roundId)
        assertEquals(10, bets.size)
        assertTrue(bets.all { it.status == GameBetStatus.ACCEPTED }, "All ten bets must remain ACCEPTED after rollback")
        assertEquals(0, crashSettlementCount(), "No LOSS_CRASH settlement may persist")
        assertEquals(ledgerBefore, ledgerTransactionCount(), "No crash journal transaction may persist")

        decorated.failOnNth = 0
        val retry = gameService.settleRoundCrash(SettleRoundCrashCommand(tenantId, gameId, roundId, BigDecimal("1.1000")))
        assertEquals(10, retry.settledBetsCount)
        assertEquals(10, crashSettlementCount())
        assertTrue(gameStore.findBetsForRound(tenantId, gameId, roundId).all { it.status == GameBetStatus.LOST })
    }

    @Test
    fun `GivenCrashAndCashOut_WhenRaced_ThenOneTerminalOutcomePerBet`() {
        val roundId = "rnd-tc011-race"
        val uuid = playerUuids.first()
        seedFunds(uuid, 50000L)
        createRound(roundId)
        placeBet(roundId, "cmd-tc011-race-bet", uuid, 101L)
        flyRound(roundId)

        val pool = Executors.newFixedThreadPool(2)
        val results = ConcurrentLinkedQueue<Pair<String, String>>()
        val startLatch = CountDownLatch(1)
        val doneLatch = CountDownLatch(2)

        pool.submit {
            startLatch.await()
            try {
                val result = gameService.settleRoundCrash(SettleRoundCrashCommand(tenantId, gameId, roundId, BigDecimal("1.1000")))
                results.add("crash" to "settled:${result.settledBetsCount}")
            } catch (e: Exception) {
                results.add("crash" to "ERROR:${e.javaClass.simpleName}")
            } finally {
                doneLatch.countDown()
            }
        }
        pool.submit {
            startLatch.await()
            try {
                val ack = gameService.processCommand(
                    AviatorRestCommand(
                        tenantId = tenantId,
                        principal = playerPrincipal(uuid),
                        commandId = "cmd-tc011-race-cashout",
                        roundId = roundId,
                        handId = "hand_primary",
                        action = "CASH_OUT",
                        currency = currency,
                        correlationId = "corr-tc011-race-cashout",
                    )
                )
                results.add("cashout" to ack.status.name)
            } catch (e: Exception) {
                results.add("cashout" to "ERROR:${e.javaClass.simpleName}")
            } finally {
                doneLatch.countDown()
            }
        }

        startLatch.countDown()
        assertTrue(doneLatch.await(30, TimeUnit.SECONDS), "Crash/cash-out race timed out")
        pool.shutdown()

        val bet = gameStore.findBet(tenantId, gameId, roundId, uuid.toString(), "hand_primary")
        assertNotNull(bet)
        assertTrue(
            bet.status == GameBetStatus.LOST || bet.status == GameBetStatus.CASHED_OUT,
            "Bet must reach exactly one terminal state, was ${bet.status}",
        )
        val settlementRows = jdbc.queryForObject(
            "select count(*) from game_bet_settlement where tenant_id = ? and bet_id = ?",
            Int::class.java,
            tenantId,
            bet.betId,
        ) ?: 0
        assertEquals(1, settlementRows, "Exactly one settlement per bet")
        assertEquals(0L, ledgerStore.findBalance(tenantId, "ESCROW:GAME:$gameId", currency), "Escrow must net to zero")
        assertJournalBalanced()
    }

    @Test
    fun `GivenAlreadyCrashedRound_WhenCrashRetried_ThenNoAdditionalMovement`() {
        val roundId = "rnd-tc011-retry"
        val uuid = playerUuids.first()
        seedFunds(uuid, 50000L)
        createRound(roundId)
        placeBet(roundId, "cmd-tc011-retry-bet", uuid, 101L)
        flyRound(roundId)

        val first = crash(roundId)
        assertEquals(1, first.settledBetsCount)
        val roundAfter = assertNotNull(gameStore.findRound(tenantId, gameId, roundId))
        val ledgerAfter = ledgerTransactionCount()
        val settlementsAfter = crashSettlementCount()

        val retry = crash(roundId)
        assertEquals(0, retry.settledBetsCount, "Retry must settle no additional bets")
        val roundRetried = assertNotNull(gameStore.findRound(tenantId, gameId, roundId))
        assertEquals(roundAfter.roundVersion, roundRetried.roundVersion, "Retry must not change the round version")
        assertEquals(ledgerAfter, ledgerTransactionCount(), "Retry must not add ledger movement")
        assertEquals(settlementsAfter, crashSettlementCount(), "Retry must not add settlements")
    }

    @Test
    fun `GivenCrash_WhenLocksAreObserved_ThenGlobalOrderIsPreserved`() {
        val roundId = "rnd-tc011-lock-order"
        val uuid = playerUuids.first()
        seedFunds(uuid, 50000L)
        createRound(roundId)
        placeBet(roundId, "cmd-tc011-lock-bet", uuid, 101L)
        flyRound(roundId)

        val eventLog = mutableListOf<Pair<String, Int>>()
        val tracingStore = CrashLockTracingStore(gameStore, eventLog)
        val tracingLedgerStore = CrashLockTracingLedgerStore(ledgerStore, eventLog)
        val tracingService = DurableGameWagerAndSettlementService(
            store = tracingStore,
            ledgerService = LedgerPostingService(store = tracingLedgerStore, clock = clock),
            registrationStore = registrationStore,
            eligibilityStore = eligibilityStore,
            adminPrincipal = adminPrincipal,
            clock = clock,
            txManager = txManager,
        )

        val result = tracingService.settleRoundCrash(SettleRoundCrashCommand(tenantId, gameId, roundId, BigDecimal("1.1000")))
        assertEquals(1, result.settledBetsCount)

        var previousRank = 0
        for ((resource, rank) in eventLog) {
            assertTrue(rank >= previousRank, "Lock rank inversion at $resource ($rank) after $previousRank")
            previousRank = rank
        }
        assertTrue(eventLog.any { it.first == "ROUND_EXCLUSIVE" }, "Crash must take the exclusive round lock")
        assertTrue(eventLog.any { it.first == "BETS_FOR_UPDATE" }, "Crash must lock accepted bets by stable order")
        assertTrue(eventLog.any { it.first == "LEDGER_ACCOUNT_WRITE" })
    }

    @Test
    fun `GivenHistoricalMoneyAndOutcomeVectors_WhenCrashRuns_ThenLossPayoutIsZeroAndBalanced`() {
        val wagerMinor = 101L
        val roundId = "rnd-tc011-golden"
        val uuid = playerUuids.first()
        seedFunds(uuid, 50000L)
        createRound(roundId)
        placeBet(roundId, "cmd-tc011-golden-bet", uuid, wagerMinor)
        flyRound(roundId, BigDecimal("1.2345"))

        val result = crash(roundId, BigDecimal("1.2345"))
        assertEquals(1, result.settledBetsCount)

        val bet = gameStore.findBet(tenantId, gameId, roundId, uuid.toString(), "hand_primary")
        assertNotNull(bet)
        assertEquals(GameBetStatus.LOST, bet.status)

        val payout = jdbc.queryForObject(
            "select payout_minor_units from game_bet_settlement where tenant_id = ? and outcome = 'LOSS_CRASH'",
            Long::class.java,
            tenantId,
        )
        assertEquals(0L, payout, "Crash loss payout must be zero")
        assertEquals(0L, ledgerStore.findBalance(tenantId, "ESCROW:GAME:$gameId", currency), "Escrow must net to zero after crash")
        assertJournalBalanced()
    }

    @Test
    fun `GivenCrashAtOnePointOne_WhenRetriedWithNinePointZero_ThenStoredMultiplierIsReturned`() {
        val roundId = "rnd-tc049-retry"
        val uuid = playerUuids.first()
        seedFunds(uuid, 50000L)
        createRound(roundId)
        placeBet(roundId, "cmd-tc049-retry-bet", uuid, 101L)
        flyRound(roundId)

        val first = crash(roundId, BigDecimal("1.1000"))
        assertEquals(1, first.settledBetsCount)
        assertEquals(0, BigDecimal("1.1000").compareTo(first.crashMultiplier))

        val versionAfter = assertNotNull(gameStore.findRound(tenantId, gameId, roundId)).roundVersion
        val ledgerAfter = ledgerTransactionCount()
        val settlementsAfter = crashSettlementCount()

        val retry = crash(roundId, BigDecimal("9.0000"))
        assertEquals(0, retry.settledBetsCount)
        assertEquals(0, BigDecimal("1.1000").compareTo(retry.crashMultiplier), "Retry must return the persisted multiplier, not the command value")
        val roundRetried = assertNotNull(gameStore.findRound(tenantId, gameId, roundId))
        assertEquals(0, BigDecimal("1.1000").compareTo(roundRetried.crashMultiplier!!))
        assertEquals(versionAfter, roundRetried.roundVersion)
        assertEquals(ledgerAfter, ledgerTransactionCount())
        assertEquals(settlementsAfter, crashSettlementCount())
    }

    @Test
    fun `GivenCrashRetriedWithEquivalentScale_WhenCompleted_ThenCanonicalStoredValueIsReturned`() {
        val roundId = "rnd-tc049-scale"
        val uuid = playerUuids.first()
        seedFunds(uuid, 50000L)
        createRound(roundId)
        placeBet(roundId, "cmd-tc049-scale-bet", uuid, 101L)
        flyRound(roundId)

        crash(roundId, BigDecimal("1.1000"))
        val ledgerAfter = ledgerTransactionCount()
        val settlementsAfter = crashSettlementCount()

        val retry = crash(roundId, BigDecimal("1.10"))
        assertEquals(0, retry.settledBetsCount)
        assertEquals(0, BigDecimal("1.1000").compareTo(retry.crashMultiplier))
        assertEquals(ledgerAfter, ledgerTransactionCount())
        assertEquals(settlementsAfter, crashSettlementCount())
    }

    @Test
    fun `GivenConcurrentDifferentCrashMultipliers_WhenOneCommitsFirst_ThenBothSuccessfulResultsMatchWinner`() {
        val roundId = "rnd-tc049-concurrent"
        val uuid = playerUuids.first()
        seedFunds(uuid, 50000L)
        createRound(roundId)
        placeBet(roundId, "cmd-tc049-concurrent-bet", uuid, 101L)
        flyRound(roundId)

        val pool = Executors.newFixedThreadPool(2)
        val results = ConcurrentLinkedQueue<BigDecimal>()
        val startLatch = CountDownLatch(1)
        val doneLatch = CountDownLatch(2)

        listOf(BigDecimal("1.1000"), BigDecimal("9.0000")).forEach { multiplier ->
            pool.submit {
                startLatch.await()
                try {
                    results.add(crash(roundId, multiplier).crashMultiplier)
                } finally {
                    doneLatch.countDown()
                }
            }
        }

        startLatch.countDown()
        assertTrue(doneLatch.await(30, TimeUnit.SECONDS), "Concurrent crash retries timed out")
        pool.shutdown()

        val durable = assertNotNull(gameStore.findRound(tenantId, gameId, roundId)).crashMultiplier
        assertNotNull(durable)
        assertEquals(2, results.size)
        assertTrue(results.all { it.compareTo(durable) == 0 }, "Both successful results must match the durable winner: $results vs $durable")
        assertEquals(1, crashSettlementCount())
    }

    @Test
    fun `GivenCrashedRoundWithoutMultiplier_WhenRetried_ThenOperationFailsClosed`() {
        val roundId = "rnd-tc049-corrupt"
        jdbc.update(
            """
            insert into game_authoritative_round (
                tenant_id, game_id, round_id, phase, round_version, current_multiplier,
                crash_multiplier, started_at, crashed_at, server_time, created_at, updated_at
            ) values (?, ?, ?, 'CRASHED', 2, 1.0000, null, ?, ?, ?, ?, ?)
            """.trimIndent(),
            tenantId, gameId, roundId, Timestamp.from(now), Timestamp.from(now), Timestamp.from(now), Timestamp.from(now), Timestamp.from(now)
        )

        val ledgerBefore = ledgerTransactionCount()
        assertThrows<CrashStateIntegrityException> {
            crash(roundId, BigDecimal("1.1000"))
        }
        assertEquals(ledgerBefore, ledgerTransactionCount(), "No money may move for an invalid terminal round")
        assertEquals(0, crashSettlementCount())
    }

    @Test
    fun `GivenFirstCrash_WhenCompleted_ThenResultMatchesReloadedRound`() {
        val roundId = "rnd-tc049-first"
        val uuid = playerUuids.first()
        seedFunds(uuid, 50000L)
        createRound(roundId)
        placeBet(roundId, "cmd-tc049-first-bet", uuid, 101L)
        flyRound(roundId)

        val result = crash(roundId, BigDecimal("1.2345"))
        val round = assertNotNull(gameStore.findRound(tenantId, gameId, roundId))
        assertEquals(round.roundId, result.roundId)
        assertEquals(0, round.crashMultiplier!!.compareTo(result.crashMultiplier))
        assertEquals(1, result.settledBetsCount)
        assertEquals(1, crashSettlementCount())
    }
}
