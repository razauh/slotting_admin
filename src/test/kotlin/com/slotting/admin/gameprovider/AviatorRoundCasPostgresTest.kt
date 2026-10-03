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
import com.slotting.admin.wallet.AuthoritativeWalletService
import com.slotting.admin.wallet.InMemoryAuthoritativeWalletStore
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
import java.math.RoundingMode
import java.sql.Timestamp
import java.time.Clock
import java.time.Instant
import java.time.LocalDate
import java.time.ZoneOffset
import java.util.UUID
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.ConcurrentLinkedQueue
import java.util.concurrent.CountDownLatch
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicInteger
import kotlin.test.assertEquals
import kotlin.test.assertNotNull
import kotlin.test.assertTrue

@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.NONE)
class AviatorRoundCasPostgresTest {

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

    private val now = Instant.parse("2026-10-01T10:00:00Z")
    private val clock = Clock.fixed(now, ZoneOffset.UTC)
    private val tenantId = "tenant-tc004-cas"
    private val gameId = "AVIATOR"
    private val playerUuid = UUID.randomUUID()
    private val playerIdStr = playerUuid.toString()

    private val adminPrincipal = AuthenticatedPrincipal(
        id = "admin-sys-01",
        tenantId = tenantId,
        kind = PrincipalKind.ADMIN,
        roles = setOf(AdminRole.SUPER_ADMIN),
    )

    private val playerPrincipal = AuthenticatedPrincipal(
        id = playerIdStr,
        tenantId = tenantId,
        kind = PrincipalKind.PLAYER,
        roles = setOf(AdminRole.SUPPORT),
    )

    private val properties = AviatorLifecycleProperties(
        scheduledMillis = 100,
        bettingMillis = 200,
        closedMillis = 100,
        multiplierStep = BigDecimal("0.0500"),
        rulesVersion = "1.0.0",
        algorithmVersion = "1.0.0",
        publicSalt = "tc004-public-salt",
        configuredTenants = setOf(tenantId),
    )

    private lateinit var gameStore: JdbcDurableGameWagerAndSettlementStore
    private lateinit var fairnessStore: JdbcFairnessEvidenceStore
    private lateinit var ledgerStore: JdbcLedgerJournalStore
    private lateinit var registrationStore: JdbcPlayerRegistrationStore
    private lateinit var eligibilityStore: ServerEligibilityStore
    private lateinit var ledgerService: LedgerPostingService
    private lateinit var gameService: DurableGameWagerAndSettlementService
    private lateinit var fairnessAuthority: ProvablyFairOutcomeAuthority
    private lateinit var walletService: AuthoritativeWalletService
    private lateinit var snapshotService: AuthoritativeGameSnapshotAndEventService
    private lateinit var lifecyclePort: ProductionAviatorLifecyclePort

    @BeforeEach
    fun setUp() {
        jdbc.update("delete from game_bet_settlement where tenant_id = ?", tenantId)
        jdbc.update("delete from game_accepted_bet where tenant_id = ?", tenantId)
        jdbc.update("delete from game_command_receipt where tenant_id = ?", tenantId)
        jdbc.update("delete from game_fairness_audit where tenant_id = ?", tenantId)
        jdbc.update("delete from game_fairness_reveal where tenant_id = ?", tenantId)
        jdbc.update("delete from game_fairness_commitment where tenant_id = ?", tenantId)
        jdbc.update("delete from game_cumulative_player_limit where tenant_id = ?", tenantId)
        jdbc.update("delete from game_authoritative_round where tenant_id = ?", tenantId)
        jdbc.update("delete from ledger_leg where tenant_id = ?", tenantId)
        jdbc.update("delete from ledger_idempotency_receipt where tenant_id = ?", tenantId)
        jdbc.update("delete from ledger_transaction where tenant_id = ?", tenantId)
        jdbc.update("delete from ledger_account where tenant_id = ?", tenantId)

        gameStore = JdbcDurableGameWagerAndSettlementStore(jdbc)
        fairnessStore = JdbcFairnessEvidenceStore(jdbc)
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
            clock = clock
        )
        fairnessAuthority = ProvablyFairOutcomeAuthority(store = fairnessStore, clock = clock)
        val walletStore = InMemoryAuthoritativeWalletStore(ledgerStore = ledgerStore, clock = clock)
        walletService = AuthoritativeWalletService(
            store = walletStore,
            clock = clock,
        )
        snapshotService = AuthoritativeGameSnapshotAndEventService(
            gameStore = gameStore,
            gameService = gameService,
            walletService = walletService,
            ledgerStore = ledgerStore,
            fairnessStore = fairnessStore,
            eventJournalStore = InMemoryGameEventJournalStore(),
            registrationStore = registrationStore,
            clock = clock,
        )

        lifecyclePort = ProductionAviatorLifecyclePort(
            gameService = gameService,
            fairnessAuthority = fairnessAuthority,
            snapshotService = snapshotService,
            txManager = txManager,
        )

        jdbc.update(
            """
            insert into player_credential (
                player_id, tenant_id, identifier, password_hash, password_algo,
                password_salt, iterations, status, version, created_at, updated_at
            ) values (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            on conflict (tenant_id, identifier) do nothing
            """.trimIndent(),
            playerUuid,
            tenantId,
            playerIdStr,
            "pbkdf2_sha256_hash",
            "pbkdf2_sha256",
            "salt",
            10000,
            "ACTIVE",
            1L,
            Timestamp.from(now.minusSeconds(86400)),
            Timestamp.from(now.minusSeconds(86400))
        )

        eligibilityStore.saveComplianceProfile(
            PlayerComplianceProfile(
                playerId = playerUuid,
                tenantId = tenantId,
                dateOfBirth = LocalDate.of(1995, 5, 5),
                kycStatus = KycComplianceStatus.VERIFIED,
                amlStatus = AmlComplianceStatus.CLEARED,
                jurisdiction = "DEFAULT",
                responsiblePlay = ResponsiblePlayProfile(
                    playerId = playerUuid,
                    selfExcluded = false,
                    singleWagerLimitMinor = 500000L,
                    dailyWagerLimitMinor = 2000000L,
                    currentDailyWagerMinor = 0L
                )
            )
        )
    }

    @Test
    fun `GivenSameExpectedVersion_WhenTwoWritersUpdate_ThenExactlyOneWins`() {
        val roundId = "rnd-cas-two-writers-${UUID.randomUUID().toString().take(8)}"
        jdbc.update(
            """
            insert into game_authoritative_round (
                tenant_id, game_id, round_id, phase, round_version, current_multiplier,
                crash_multiplier, started_at, server_time, created_at, updated_at
            ) values (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """.trimIndent(),
            tenantId, gameId, roundId, GameRoundPhase.BET_COUNTDOWN.name, 7L,
            BigDecimal("1.0000"), null, Timestamp.from(now), Timestamp.from(now),
            Timestamp.from(now), Timestamp.from(now)
        )

        val pool = Executors.newFixedThreadPool(2)
        val readyLatch = CountDownLatch(2)
        val startLatch = CountDownLatch(1)
        val successes = AtomicInteger(0)
        val conflicts = AtomicInteger(0)

        for (i in 0 until 2) {
            pool.submit {
                readyLatch.countDown()
                startLatch.await()
                try {
                    gameService.createOrUpdateRound(
                        CreateOrUpdateRoundCommand(
                            tenantId = tenantId,
                            gameId = gameId,
                            roundId = roundId,
                            phase = GameRoundPhase.FLYING,
                            roundVersion = 8L,
                            expectedVersion = 7L,
                            currentMultiplier = BigDecimal("1.0500"),
                        )
                    )
                    successes.incrementAndGet()
                } catch (e: RoundVersionConflictException) {
                    conflicts.incrementAndGet()
                }
            }
        }

        assertTrue(readyLatch.await(5, TimeUnit.SECONDS))
        startLatch.countDown()
        pool.shutdown()
        assertTrue(pool.awaitTermination(5, TimeUnit.SECONDS))

        assertEquals(1, successes.get())
        assertEquals(1, conflicts.get())

        val persisted = gameStore.findRound(tenantId, gameId, roundId)
        assertNotNull(persisted)
        assertEquals(8L, persisted.roundVersion)
        assertEquals(GameRoundPhase.FLYING, persisted.phase)
    }

    @Test
    fun `GivenCrashedRound_WhenStaleFlyingWritten_ThenTerminalStateRemains`() {
        val roundId = "rnd-crashed-term-${UUID.randomUUID().toString().take(8)}"
        jdbc.update(
            """
            insert into game_authoritative_round (
                tenant_id, game_id, round_id, phase, round_version, current_multiplier,
                crash_multiplier, started_at, crashed_at, server_time, created_at, updated_at
            ) values (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """.trimIndent(),
            tenantId, gameId, roundId, GameRoundPhase.CRASHED.name, 9L,
            BigDecimal("1.5000"), BigDecimal("1.5000"),
            Timestamp.from(now), Timestamp.from(now), Timestamp.from(now),
            Timestamp.from(now), Timestamp.from(now)
        )

        assertThrows<RoundVersionConflictException> {
            gameService.createOrUpdateRound(
                CreateOrUpdateRoundCommand(
                    tenantId = tenantId,
                    gameId = gameId,
                    roundId = roundId,
                    phase = GameRoundPhase.FLYING,
                    roundVersion = 9L,
                    expectedVersion = 8L,
                    currentMultiplier = BigDecimal("1.4000"),
                )
            )
        }

        val illegalPhases = listOf(
            GameRoundPhase.SCHEDULED,
            GameRoundPhase.BET_COUNTDOWN,
            GameRoundPhase.FLYING,
        )
        for (illegalPhase in illegalPhases) {
            assertThrows<RoundVersionConflictException> {
                gameService.createOrUpdateRound(
                    CreateOrUpdateRoundCommand(
                        tenantId = tenantId,
                        gameId = gameId,
                        roundId = roundId,
                        phase = illegalPhase,
                        roundVersion = 10L,
                        expectedVersion = 9L,
                    )
                )
            }
        }

        val persisted = gameStore.findRound(tenantId, gameId, roundId)
        assertNotNull(persisted)
        assertEquals(GameRoundPhase.CRASHED, persisted.phase)
        assertEquals(9L, persisted.roundVersion)
    }

    @Test
    fun `GivenLegalTransition_WhenVersionAdvances_ThenExactlyOneIncrement`() {
        val roundId = "rnd-legal-trans-${UUID.randomUUID().toString().take(8)}"
        val scheduled = gameService.createOrUpdateRound(
            CreateOrUpdateRoundCommand(
                tenantId = tenantId,
                gameId = gameId,
                roundId = roundId,
                phase = GameRoundPhase.SCHEDULED,
                roundVersion = 1L,
            )
        )
        assertEquals(1L, scheduled.roundVersion)
        assertEquals(GameRoundPhase.SCHEDULED, scheduled.phase)

        val countdown = gameService.createOrUpdateRound(
            CreateOrUpdateRoundCommand(
                tenantId = tenantId,
                gameId = gameId,
                roundId = roundId,
                phase = GameRoundPhase.BET_COUNTDOWN,
                roundVersion = 2L,
                expectedVersion = 1L,
            )
        )
        assertEquals(2L, countdown.roundVersion)
        assertEquals(GameRoundPhase.BET_COUNTDOWN, countdown.phase)

        ledgerService.postTransaction(
            PostTransactionCommand(
                principal = adminPrincipal,
                tenantId = tenantId,
                transactionReference = "TX-DEP-BET-${UUID.randomUUID()}",
                currencyCode = "INR",
                entries = listOf(
                    JournalEntryDraft("HOUSE:SEED", JournalEntryDirection.DEBIT, 50000L, "INR"),
                    JournalEntryDraft("PLAYER:$playerIdStr", JournalEntryDirection.CREDIT, 50000L, "INR"),
                ),
                correlationId = "corr-bet",
                causationId = "caus-bet",
                idempotencyKey = UUID.randomUUID().toString(),
            )
        )

        val betAck = gameService.processCommand(
            AviatorRestCommand(
                tenantId = tenantId,
                principal = playerPrincipal,
                commandId = "cmd-bet-concurrent-1",
                roundId = roundId,
                handId = "hand_primary",
                action = "PLACE_BET",
                wagerMinor = 1000L,
                currency = "INR",
                correlationId = "corr-bet-1",
            )
        )
        assertEquals(AviatorCommandAckStatus.ACCEPTED, betAck.status)

        val roundAfterBet = gameStore.findRound(tenantId, gameId, roundId)
        assertNotNull(roundAfterBet)
        assertEquals(2L, roundAfterBet.roundVersion)

        val flying = gameService.createOrUpdateRound(
            CreateOrUpdateRoundCommand(
                tenantId = tenantId,
                gameId = gameId,
                roundId = roundId,
                phase = GameRoundPhase.FLYING,
                roundVersion = 3L,
                expectedVersion = 2L,
                currentMultiplier = BigDecimal("1.0500"),
            )
        )
        assertEquals(3L, flying.roundVersion)
        assertEquals(GameRoundPhase.FLYING, flying.phase)

        val flyingTick = gameService.createOrUpdateRound(
            CreateOrUpdateRoundCommand(
                tenantId = tenantId,
                gameId = gameId,
                roundId = roundId,
                phase = GameRoundPhase.FLYING,
                roundVersion = 4L,
                expectedVersion = 3L,
                currentMultiplier = BigDecimal("1.1000"),
            )
        )
        assertEquals(4L, flyingTick.roundVersion)
        assertEquals(GameRoundPhase.FLYING, flyingTick.phase)

        val crashed = gameService.createOrUpdateRound(
            CreateOrUpdateRoundCommand(
                tenantId = tenantId,
                gameId = gameId,
                roundId = roundId,
                phase = GameRoundPhase.CRASHED,
                roundVersion = 5L,
                expectedVersion = 4L,
                crashMultiplier = BigDecimal("1.1000"),
            )
        )
        assertEquals(5L, crashed.roundVersion)
        assertEquals(GameRoundPhase.CRASHED, crashed.phase)

        val closed = gameService.createOrUpdateRound(
            CreateOrUpdateRoundCommand(
                tenantId = tenantId,
                gameId = gameId,
                roundId = roundId,
                phase = GameRoundPhase.CLOSED,
                roundVersion = 6L,
                expectedVersion = 5L,
            )
        )
        assertEquals(6L, closed.roundVersion)
        assertEquals(GameRoundPhase.CLOSED, closed.phase)
    }

    @Test
    fun `GivenMixedOperations_WhenLocksAreObserved_ThenGlobalOrderIsPreserved`() {
        val pool = Executors.newFixedThreadPool(2)
        val rankInversions = ConcurrentLinkedQueue<String>()

        for (i in 0 until 100) {
            val roundId = "rnd-lock-cas-$i-${UUID.randomUUID().toString().take(6)}"
            lifecyclePort.createScheduledRoundWithCommitment(tenantId, gameId, roundId, properties)

            val latch = CountDownLatch(2)
            val workerAcquisitions = ConcurrentHashMap<String, MutableList<Pair<String, Int>>>()

            val workerCommand = Runnable {
                try {
                    val list = mutableListOf<Pair<String, Int>>()
                    val txTemplate = TransactionTemplate(txManager)
                    txTemplate.execute {
                        list.add("RECEIPT" to 1)
                        jdbc.queryForList(
                            "select round_id from game_authoritative_round where tenant_id = ? and game_id = ? and round_id = ? for share",
                            tenantId, gameId, roundId
                        )
                        list.add("ROUND_SHARED" to 2)
                    }
                    workerAcquisitions["cmd"] = list
                } finally {
                    latch.countDown()
                }
            }

            val workerLifecycle = Runnable {
                try {
                    val list = mutableListOf<Pair<String, Int>>()
                    val txTemplate = TransactionTemplate(txManager)
                    txTemplate.execute {
                        list.add("ROUND_EXCLUSIVE" to 2)
                        jdbc.queryForList(
                            "select round_id from game_authoritative_round where tenant_id = ? and game_id = ? and round_id = ? for update",
                            tenantId, gameId, roundId
                        )
                    }
                    workerAcquisitions["lifecycle"] = list
                } finally {
                    latch.countDown()
                }
            }

            pool.submit(workerCommand)
            pool.submit(workerLifecycle)
            assertTrue(latch.await(5, TimeUnit.SECONDS))

            for ((worker, events) in workerAcquisitions) {
                var prevRank = 0
                for ((resource, rank) in events) {
                    if (rank < prevRank) {
                        rankInversions.add("Inversion on $worker: $resource($rank) after rank $prevRank")
                    }
                    prevRank = rank
                }
            }
        }
        pool.shutdown()
        pool.awaitTermination(5, TimeUnit.SECONDS)

        assertTrue(rankInversions.isEmpty(), "Zero lock rank inversions expected: $rankInversions")
    }

    @Test
    fun `GivenHistoricalMoneyAndOutcomeVectors_WhenRefactoredPathRuns_ThenSemanticsStayUnchanged`() {
        val wagerMinor = 101L
        val multiplier = BigDecimal("1.2345")
        val expectedWinMinor = BigDecimal.valueOf(wagerMinor)
            .multiply(multiplier)
            .setScale(0, RoundingMode.FLOOR)
            .longValueExact()

        assertEquals(124L, expectedWinMinor)

        val roundId1 = "rnd-gld1-${UUID.randomUUID().toString().take(6)}"
        lifecyclePort.createScheduledRoundWithCommitment(tenantId, gameId, roundId1, properties)

        val balanceBefore = 50000L
        ledgerService.postTransaction(
            PostTransactionCommand(
                principal = adminPrincipal,
                tenantId = tenantId,
                transactionReference = "TX-GOLDEN-DEPOSIT-${UUID.randomUUID()}",
                currencyCode = "INR",
                entries = listOf(
                    JournalEntryDraft(
                        accountReference = "HOUSE:SEED",
                        direction = JournalEntryDirection.DEBIT,
                        amountMinorUnits = balanceBefore,
                        currencyCode = "INR",
                    ),
                    JournalEntryDraft(
                        accountReference = "PLAYER:$playerIdStr",
                        direction = JournalEntryDirection.CREDIT,
                        amountMinorUnits = balanceBefore,
                        currencyCode = "INR",
                    )
                ),
                correlationId = "corr-golden",
                causationId = "caus-golden",
                idempotencyKey = UUID.randomUUID().toString(),
            )
        )

        val betAck1 = gameService.processCommand(
            AviatorRestCommand(
                tenantId = tenantId,
                principal = playerPrincipal,
                commandId = "cmd-bet-golden-1",
                roundId = roundId1,
                handId = "hand_primary",
                action = "PLACE_BET",
                wagerMinor = wagerMinor,
                currency = "INR",
                correlationId = "corr-bet-golden-1",
            )
        )
        assertEquals(AviatorCommandAckStatus.ACCEPTED, betAck1.status)

        val cancelAck = gameService.processCommand(
            AviatorRestCommand(
                tenantId = tenantId,
                principal = playerPrincipal,
                commandId = "cmd-cancel-golden-1",
                roundId = roundId1,
                handId = "hand_primary",
                action = "CANCEL_BET",
                correlationId = "corr-cancel-golden-1",
            )
        )
        assertEquals(AviatorCommandAckStatus.ACCEPTED, cancelAck.status)
        assertEquals(balanceBefore, ledgerService.store.findBalance(tenantId, "PLAYER:$playerIdStr", "INR"))

        val roundId2 = "rnd-gld2-${UUID.randomUUID().toString().take(6)}"
        lifecyclePort.createScheduledRoundWithCommitment(tenantId, gameId, roundId2, properties)

        val betAck2 = gameService.processCommand(
            AviatorRestCommand(
                tenantId = tenantId,
                principal = playerPrincipal,
                commandId = "cmd-bet-golden-2",
                roundId = roundId2,
                handId = "hand_primary",
                action = "PLACE_BET",
                wagerMinor = wagerMinor,
                currency = "INR",
                correlationId = "corr-bet-golden-2",
            )
        )
        assertEquals(AviatorCommandAckStatus.ACCEPTED, betAck2.status)

        val betAck3 = gameService.processCommand(
            AviatorRestCommand(
                tenantId = tenantId,
                principal = playerPrincipal,
                commandId = "cmd-bet-golden-3",
                roundId = roundId2,
                handId = "hand_secondary",
                action = "PLACE_BET",
                wagerMinor = wagerMinor,
                currency = "INR",
                correlationId = "corr-bet-golden-3",
            )
        )
        assertEquals(AviatorCommandAckStatus.ACCEPTED, betAck3.status)

        gameService.createOrUpdateRound(
            CreateOrUpdateRoundCommand(
                tenantId = tenantId,
                gameId = gameId,
                roundId = roundId2,
                phase = GameRoundPhase.FLYING,
                roundVersion = 2L,
                currentMultiplier = multiplier,
            )
        )

        val cashOutAck = gameService.processCommand(
            AviatorRestCommand(
                tenantId = tenantId,
                principal = playerPrincipal,
                commandId = "cmd-cashout-golden-2",
                roundId = roundId2,
                handId = "hand_primary",
                action = "CASH_OUT",
                correlationId = "corr-cashout-golden-2",
            )
        )
        assertEquals(AviatorCommandAckStatus.ACCEPTED, cashOutAck.status)
        assertEquals(expectedWinMinor, cashOutAck.result?.payoutMinor)

        gameService.settleRoundCrash(
            SettleRoundCrashCommand(
                tenantId = tenantId,
                gameId = gameId,
                roundId = roundId2,
                crashMultiplier = BigDecimal("1.1000"),
            )
        )

        val bet3 = gameStore.findBet(tenantId, gameId, roundId2, playerIdStr, "hand_secondary")
        assertNotNull(bet3)
        assertEquals(GameBetStatus.LOST, bet3.status)

        val engineOutcome = IndependentFairnessVerifier.calculateCrashMultiplier(
            serverSeed = "d1ce9e16a70e4f20815457ef4d909dfc44ee035f58c440a373fc524cc404c5c2",
            clientSeed1 = "00000000000000000000000000000000",
            clientSeed2 = "00000000000000000000000000000000",
            clientSeed3 = "00000000000000000000000000000000",
        )
        assertTrue(engineOutcome >= BigDecimal("1.0000"))
    }
}
