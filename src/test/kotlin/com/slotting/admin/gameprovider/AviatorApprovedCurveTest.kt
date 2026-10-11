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
import com.slotting.admin.ledger.LedgerJournalStore
import com.slotting.admin.ledger.LedgerPostingService
import com.slotting.admin.ledger.PostTransactionCommand
import com.slotting.admin.wallet.AuthoritativeWalletService
import com.slotting.admin.wallet.InMemoryAuthoritativeWalletStore
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.boot.test.context.SpringBootTest
import org.springframework.jdbc.core.JdbcTemplate
import org.springframework.test.context.DynamicPropertyRegistry
import org.springframework.test.context.DynamicPropertySource
import org.springframework.transaction.PlatformTransactionManager
import java.math.BigDecimal
import java.math.RoundingMode
import java.sql.Timestamp
import java.time.Clock
import java.time.Duration
import java.time.Instant
import java.time.LocalDate
import java.time.ZoneId
import java.time.ZoneOffset
import java.util.UUID
import java.util.concurrent.ConcurrentLinkedQueue
import java.util.concurrent.CountDownLatch
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit
import kotlin.test.assertEquals
import kotlin.test.assertNotNull
import kotlin.test.assertTrue
import kotlin.test.assertFailsWith

@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.NONE)
class AviatorApprovedCurveTest {

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

    private val tenantId = "tenant-tc021-curve"
    private val gameId = "AVIATOR"
    private val currency = "INR"
    private val playerUuid = UUID.fromString("11111111-2222-3333-4444-555555555555")
    private val playerIdStr = playerUuid.toString()
    private val now = Instant.parse("2026-10-11T12:00:00Z")

    private val adminPrincipal = AuthenticatedPrincipal(
        id = "admin-tc021",
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

    private val propertiesV1 = AviatorLifecycleProperties(
        scheduledMillis = 10,
        bettingMillis = 10,
        closedMillis = 10,
        multiplierStep = BigDecimal("0.0500"),
        rulesVersion = "1.0.0",
        algorithmVersion = "1.0.0",
        publicSalt = "tc021-public-salt",
        configuredTenants = setOf(tenantId),
    )

    private val propertiesV2 = propertiesV1.copy(
        rulesVersion = "2.0.0"
    )

    private lateinit var clock: MutableClock
    private lateinit var gameStore: JdbcDurableGameWagerAndSettlementStore
    private lateinit var fairnessStore: JdbcFairnessEvidenceStore
    private lateinit var ledgerStore: JdbcLedgerJournalStore
    private lateinit var registrationStore: JdbcPlayerRegistrationStore
    private lateinit var eligibilityStore: ServerEligibilityStore
    private lateinit var ledgerService: LedgerPostingService
    private lateinit var fairnessAuthority: ProvablyFairOutcomeAuthority
    private lateinit var gameService: DurableGameWagerAndSettlementService
    private lateinit var leaseStore: JdbcGameLifecycleLeaseStore
    private lateinit var eventJournalStore: InMemoryGameEventJournalStore
    private lateinit var port: ProductionAviatorLifecyclePort

    @BeforeEach
    fun setUp() {
        clock = MutableClock(now)
        jdbc.update("delete from game_bet_settlement where tenant_id = ?", tenantId)
        jdbc.update("delete from game_accepted_bet where tenant_id = ?", tenantId)
        jdbc.update("delete from game_command_receipt where tenant_id = ?", tenantId)
        jdbc.update("delete from game_fairness_reveal where tenant_id = ?", tenantId)
        jdbc.update("delete from game_fairness_audit where tenant_id = ?", tenantId)
        jdbc.update("delete from game_fairness_commitment where tenant_id = ?", tenantId)
        jdbc.update("delete from game_cumulative_player_limit where tenant_id = ?", tenantId)
        jdbc.update("delete from game_authoritative_round where tenant_id = ?", tenantId)
        jdbc.update("delete from game_lifecycle_lease where tenant_id = ?", tenantId)
        jdbc.update("delete from ledger_leg where tenant_id = ?", tenantId)
        jdbc.update("delete from ledger_idempotency_receipt where tenant_id = ?", tenantId)
        jdbc.update("delete from ledger_transaction where tenant_id = ?", tenantId)
        jdbc.update("delete from ledger_account where tenant_id = ?", tenantId)
        jdbc.update("delete from game_command_sequence where tenant_id = ?", tenantId)
        jdbc.update("delete from ledger_version_tracker where tenant_id = ?", tenantId)

        gameStore = JdbcDurableGameWagerAndSettlementStore(jdbc)
        fairnessStore = JdbcFairnessEvidenceStore(jdbc)
        ledgerStore = JdbcLedgerJournalStore(jdbc)
        registrationStore = JdbcPlayerRegistrationStore(jdbc)
        eligibilityStore = com.slotting.admin.identity.InMemoryServerEligibilityStore()
        ledgerService = LedgerPostingService(store = ledgerStore, clock = clock)
        fairnessAuthority = ProvablyFairOutcomeAuthority(
            store = fairnessStore,
            clock = clock,
            envelope = FairnessSeedEnvelope.devDefault(),
            txManager = txManager,
        )
        gameService = DurableGameWagerAndSettlementService(
            store = gameStore,
            ledgerService = ledgerService,
            registrationStore = registrationStore,
            eligibilityStore = eligibilityStore,
            adminPrincipal = adminPrincipal,
            clock = clock,
            fairnessAuthority = fairnessAuthority,
            txManager = txManager,
        )
        val walletService = AuthoritativeWalletService(
            store = InMemoryAuthoritativeWalletStore(ledgerStore = ledgerStore, clock = clock),
            clock = clock,
        )
        eventJournalStore = InMemoryGameEventJournalStore()
        val snapshotService = AuthoritativeGameSnapshotAndEventService(
            gameStore = gameStore,
            gameService = gameService,
            walletService = walletService,
            ledgerStore = ledgerStore,
            fairnessStore = fairnessStore,
            eventJournalStore = eventJournalStore,
            registrationStore = registrationStore,
            clock = clock,
        )
        leaseStore = JdbcGameLifecycleLeaseStore(jdbc)
        port = ProductionAviatorLifecyclePort(
            gameService = gameService,
            fairnessAuthority = fairnessAuthority,
            snapshotService = snapshotService,
            txManager = txManager,
            leaseStore = leaseStore,
            clock = clock,
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
            Timestamp.from(now.minusSeconds(86400)),
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
                    singleWagerLimitMinor = 5_000_000L,
                    dailyWagerLimitMinor = 20_000_000L,
                    currentDailyWagerMinor = 0L,
                ),
            )
        )
    }

    private fun orchestrator(props: AviatorLifecycleProperties) =
        AviatorRoundLifecycleOrchestrator(port, props, clock, leaseStore, 5000L)

    private fun seedFunds(amount: Long) {
        ledgerService.postTransaction(
            PostTransactionCommand(
                principal = adminPrincipal,
                tenantId = tenantId,
                transactionReference = "TX-TC021-SEED-${UUID.randomUUID()}",
                currencyCode = currency,
                entries = listOf(
                    JournalEntryDraft("HOUSE:SEED", JournalEntryDirection.DEBIT, amount, currency),
                    JournalEntryDraft("PLAYER:$playerIdStr", JournalEntryDirection.CREDIT, amount, currency),
                ),
                idempotencyKey = "IDEM-TC021-SEED-${UUID.randomUUID()}",
                correlationId = "corr-tc021-seed",
                causationId = "caus-tc021-seed",
            )
        )
    }

    private fun placeBetCommand(roundId: String, commandId: String, wagerMinor: Long = 101L): AviatorRestCommand =
        AviatorRestCommand(
            tenantId = tenantId,
            principal = playerPrincipal,
            commandId = commandId,
            roundId = roundId,
            handId = "hand_primary",
            action = "PLACE_BET",
            wagerMinor = wagerMinor,
            currency = currency,
            correlationId = "corr-$commandId",
        )

    private fun cashOutCommand(roundId: String, commandId: String): AviatorRestCommand =
        AviatorRestCommand(
            tenantId = tenantId,
            principal = playerPrincipal,
            commandId = commandId,
            roundId = roundId,
            handId = "hand_primary",
            action = "CASH_OUT",
            currency = currency,
            correlationId = "corr-$commandId",
        )

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

    @Test
    fun GivenApprovedCurve_WhenSchedulerStallsThirtySeconds_ThenGoldenPointMatches() {
        val orch = orchestrator(propertiesV2)
        closeActiveRoundsFor(jdbc, tenantId, gameId)
        val initialRound = orch.tick(tenantId, gameId)
        val roundId = initialRound.roundId
        assertEquals(GameRoundPhase.SCHEDULED, initialRound.phase)

        clock.advanceMillis(15)
        orch.tick(tenantId, gameId)
        val countdownRound = gameStore.findRound(tenantId, gameId, roundId)
        assertNotNull(countdownRound)
        assertEquals(GameRoundPhase.BET_COUNTDOWN, countdownRound.phase)

        clock.advanceMillis(15)
        orch.tick(tenantId, gameId)
        val flyingRound = gameStore.findRound(tenantId, gameId, roundId)
        assertNotNull(flyingRound)
        assertEquals(GameRoundPhase.FLYING, flyingRound.phase)
        assertEquals(BigDecimal("1.0000"), flyingRound.currentMultiplier)

        clock.advanceMillis(30_000)
        orch.tick(tenantId, gameId)
        val sampledRound = gameStore.findRound(tenantId, gameId, roundId)
        assertNotNull(sampledRound)

        val expectedGolden = BigDecimal("6.0496")
        if (sampledRound.crashMultiplier != null && expectedGolden >= sampledRound.crashMultiplier!!) {
            assertEquals(GameRoundPhase.CRASHED, sampledRound.phase)
            assertEquals(sampledRound.crashMultiplier, sampledRound.currentMultiplier)
        } else {
            assertEquals(GameRoundPhase.FLYING, sampledRound.phase)
            assertEquals(expectedGolden, sampledRound.currentMultiplier)
        }
    }

    @Test
    fun GivenUnknownRulesVersion_WhenMultiplierResolved_ThenEvaluationFailsClosed() {
        val round = GameRoundRecord(
            tenantId = tenantId,
            gameId = gameId,
            roundId = "rnd-tc021-unknown-rules",
            phase = GameRoundPhase.FLYING,
            currentMultiplier = BigDecimal("1.5000"),
            crashMultiplier = BigDecimal("3.0000"),
            flyingAt = now,
            phaseStartedAt = now,
            phaseDeadlineAt = null,
            startedAt = now,
            serverTime = now,
            createdAt = now,
            updatedAt = now,
        )
        val failure = assertFailsWith<UnsupportedRulesVersionException> {
            FlightClock.resolveAuthoritativeMultiplier(round, "9.9.9", clock)
        }
        assertEquals("9.9.9", failure.rulesVersion)
    }

    @Test
    fun GivenCurveCashOut_WhenCrashBoundaryRaced_ThenLockedSampleIsClamped() {
        seedFunds(500_000L)
        val pool = Executors.newFixedThreadPool(2)

        try {
            for (instantOffsetSec in listOf(0L, 5L, 30L)) {
                val roundId = "rnd-tc021-cashout-race-$instantOffsetSec"
                closeActiveRoundsFor(jdbc, tenantId, gameId, keepRoundId = roundId)

                val crashPoint = BigDecimal("3.0000")
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
                fairnessAuthority.publishPreBetCommitment(
                    PublishCommitmentCommand(
                        tenantId = tenantId,
                        gameId = gameId,
                        roundId = roundId,
                        publicSalt = propertiesV2.publicSalt,
                        algorithmVersion = propertiesV2.algorithmVersion,
                        rulesVersion = propertiesV2.rulesVersion,
                    )
                )

                val betAck = gameService.processCommand(placeBetCommand(roundId, "cmd-tc021-bet-$instantOffsetSec", 101L))
                assertEquals(AviatorCommandAckStatus.ACCEPTED, betAck.status)

                val flightStart = clock.instant()
                gameService.createOrUpdateRound(
                    CreateOrUpdateRoundCommand(
                        tenantId = tenantId,
                        gameId = gameId,
                        roundId = roundId,
                        phase = GameRoundPhase.FLYING,
                        roundVersion = 2L,
                        currentMultiplier = BigDecimal("1.0000"),
                        crashMultiplier = crashPoint,
                        flyingAt = flightStart,
                        phaseStartedAt = flightStart,
                        expectedVersion = 1L,
                    )
                )

                clock.advanceMillis(instantOffsetSec * 1000)

                val startLatch = CountDownLatch(1)
                val doneLatch = CountDownLatch(2)
                val outcomes = ConcurrentLinkedQueue<Pair<String, String>>()

                pool.submit {
                    startLatch.await()
                    try {
                        val ack = gameService.processCommand(cashOutCommand(roundId, "cmd-tc021-cashout-$instantOffsetSec"))
                        outcomes.add("cashout" to ack.status.name)
                    } catch (e: Throwable) {
                        outcomes.add("cashout" to "ERR:${e.javaClass.simpleName}")
                    } finally {
                        doneLatch.countDown()
                    }
                }

                pool.submit {
                    startLatch.await()
                    try {
                        val res = gameService.settleRoundCrash(SettleRoundCrashCommand(tenantId, gameId, roundId, crashPoint))
                        outcomes.add("crash" to "settled:${res.settledBetsCount}")
                    } catch (e: Throwable) {
                        outcomes.add("crash" to "ERR:${e.javaClass.simpleName}")
                    } finally {
                        doneLatch.countDown()
                    }
                }

                startLatch.countDown()
                assertTrue(doneLatch.await(10, TimeUnit.SECONDS), "cashout/crash race must complete")

                val bet = gameStore.findBet(tenantId, gameId, roundId, playerIdStr, "hand_primary")
                assertNotNull(bet)
                assertTrue(
                    bet.status == GameBetStatus.CASHED_OUT || bet.status == GameBetStatus.LOST,
                    "Bet must reach exactly one terminal state, saw ${bet.status}"
                )

                val settlements = jdbc.queryForList(
                    "select outcome, multiplier, payout_minor_units from game_bet_settlement where tenant_id = ? and bet_id = ?",
                    tenantId,
                    bet.betId,
                )
                assertEquals(1, settlements.size, "Exactly one settlement record must be persisted")
                val settlement = settlements.first()
                val settlementOutcome = settlement["outcome"] as String
                val settlementMult = settlement["multiplier"] as BigDecimal
                val settlementPayout = (settlement["payout_minor_units"] as Number).toLong()

                if (settlementOutcome == "PAYOUT_CASH_OUT") {
                    val rawCurve = FlightClock.calculateCurveMultiplier(Duration.between(flightStart, clock.instant()).toMillis().coerceAtLeast(0) / 1000.0)
                    val expectedClamped = rawCurve.min(crashPoint)
                    assertEquals(expectedClamped, settlementMult, "cash-out multiplier must clamp to crash point")
                    val expectedPayout = BigDecimal(101L).multiply(expectedClamped).setScale(0, RoundingMode.FLOOR).toLong()
                    assertEquals(expectedPayout, settlementPayout, "payout must floor to minor units")
                } else {
                    assertEquals("LOSS_CRASH", settlementOutcome)
                    assertEquals(0L, settlementPayout)
                }
            }
        } finally {
            pool.shutdownNow()
        }
        assertJournalBalanced()
    }

    @Test
    fun GivenRules100_WhenNewCurveRegistered_ThenOldRoundsRemainStepped() {
        val orchV1 = orchestrator(propertiesV1)
        val orchV2 = orchestrator(propertiesV2)

        closeActiveRoundsFor(jdbc, tenantId, gameId)
        val v1Scheduled = orchV1.tick(tenantId, gameId)
        val roundOld = v1Scheduled.roundId
        clock.advanceMillis(15)
        orchV1.tick(tenantId, gameId)
        clock.advanceMillis(15)
        orchV1.tick(tenantId, gameId)

        val v1Flying = gameStore.findRound(tenantId, gameId, roundOld)
        assertNotNull(v1Flying)
        assertEquals(GameRoundPhase.FLYING, v1Flying.phase)

        clock.advanceMillis(2000)
        orchV1.tick(tenantId, gameId)
        val v1AfterTick = gameStore.findRound(tenantId, gameId, roundOld)
        assertNotNull(v1AfterTick)
        assertEquals(BigDecimal("1.0500"), v1AfterTick.currentMultiplier)

        val acquire1 = leaseStore.acquireOrRenew(tenantId, gameId, orchV1.ownerId, 10_000L)
        val token1 = LifecycleLeaseToken(orchV1.ownerId, acquire1.lease!!.epoch)
        port.settleCrash(tenantId, gameId, roundOld, v1Flying.crashMultiplier!!, token1)
        clock.advanceMillis(15)
        orchV1.tick(tenantId, gameId)
        clock.advanceMillis(propertiesV1.closedMillis + 15)
        orchV1.releaseLease(tenantId, gameId)

        val v2Scheduled = orchV2.tick(tenantId, gameId)
        val roundNew = v2Scheduled.roundId
        clock.advanceMillis(15)
        orchV2.tick(tenantId, gameId)
        clock.advanceMillis(15)
        orchV2.tick(tenantId, gameId)

        val v2Flying = gameStore.findRound(tenantId, gameId, roundNew)
        assertNotNull(v2Flying)
        assertEquals(GameRoundPhase.FLYING, v2Flying.phase)

        clock.advanceMillis(30_000)
        orchV2.tick(tenantId, gameId)
        val v2AfterStall = gameStore.findRound(tenantId, gameId, roundNew)
        assertNotNull(v2AfterStall)
        if (v2AfterStall.phase == GameRoundPhase.FLYING) {
            assertEquals(BigDecimal("6.0496"), v2AfterStall.currentMultiplier)
        } else {
            assertEquals(GameRoundPhase.CRASHED, v2AfterStall.phase)
        }
    }

    @Test
    fun GivenMixedOperations_WhenLocksAreObserved_ThenGlobalOrderIsPreserved() {
        seedFunds(5_000_000L)
        val trace = mutableListOf<Pair<String, Int>>()
        val commandStore = AviatorAlgorithmRegistryTest.LockRankTracingStore(gameStore, trace)
        val accountStore = AviatorAlgorithmRegistryTest.LedgerRankTracingStore(ledgerStore, trace)
        val commandLedgerService = LedgerPostingService(store = accountStore, clock = clock)
        val commandService = DurableGameWagerAndSettlementService(
            store = commandStore,
            ledgerService = commandLedgerService,
            registrationStore = registrationStore,
            eligibilityStore = eligibilityStore,
            adminPrincipal = adminPrincipal,
            clock = clock,
            fairnessAuthority = fairnessAuthority,
            txManager = txManager,
        )
        val lifecycleStore = AviatorAlgorithmRegistryTest.LockRankTracingStore(gameStore)
        val lifecycleService = DurableGameWagerAndSettlementService(
            store = lifecycleStore,
            ledgerService = ledgerService,
            registrationStore = registrationStore,
            eligibilityStore = eligibilityStore,
            adminPrincipal = adminPrincipal,
            clock = clock,
            fairnessAuthority = fairnessAuthority,
            txManager = txManager,
        )

        for (iteration in 0 until 100) {
            val roundId = "rnd-tc021-order-$iteration"
            closeActiveRoundsFor(jdbc, tenantId, gameId, keepRoundId = roundId)
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
            fairnessAuthority.publishPreBetCommitment(
                PublishCommitmentCommand(
                    tenantId = tenantId,
                    gameId = gameId,
                    roundId = roundId,
                    publicSalt = propertiesV2.publicSalt,
                    algorithmVersion = propertiesV2.algorithmVersion,
                    rulesVersion = propertiesV2.rulesVersion,
                )
            )

            trace.clear()
            lifecycleStore.eventLog.clear()

            val betAck = commandService.processCommand(placeBetCommand(roundId, "cmd-tc021-order-bet-$iteration", 101L))
            assertEquals(AviatorCommandAckStatus.ACCEPTED, betAck.status)
            assertTrue(trace.any { it.first == "RECEIPT" })
            assertTrue(trace.any { it.first == "ROUND_SHARED" })
            assertTrue(trace.any { it.first == "BET" })
            assertTrue(trace.any { it.first == "PLAYER_ACCOUNT" })
            assertTrue(trace.any { it.first == "SEQUENCE_COUNTER" })
            assertMonotonic(trace)

            val crash = lifecycleService.settleRoundCrash(SettleRoundCrashCommand(tenantId, gameId, roundId, BigDecimal("1.1000")))
            assertEquals(1, crash.settledBetsCount)
            assertTrue(lifecycleStore.eventLog.any { it.first == "ROUND_EXCLUSIVE" })
            assertTrue(lifecycleStore.eventLog.any { it.first == "BETS" })
            assertMonotonic(lifecycleStore.eventLog)
        }
        assertJournalBalanced()
        assertEquals(0L, ledgerStore.findBalance(tenantId, "ESCROW:GAME:$gameId", currency))
    }

    @Test
    fun GivenHistoricalMoneyAndOutcomeVectors_WhenRefactoredPathRuns_ThenSemanticsStayUnchanged() {
        val wagerMinor = 101L
        val multiplier = BigDecimal("1.2345")
        val expectedWinMinor = BigDecimal.valueOf(wagerMinor).multiply(multiplier).setScale(0, RoundingMode.FLOOR).longValueExact()
        assertEquals(124L, expectedWinMinor)

        val startingBalance = 50_000L
        seedFunds(startingBalance)

        val cashOutRound = "rnd-tc021-golden-cashout"
        closeActiveRoundsFor(jdbc, tenantId, gameId, keepRoundId = cashOutRound)
        gameService.createOrUpdateRound(
            CreateOrUpdateRoundCommand(
                tenantId = tenantId,
                gameId = gameId,
                roundId = cashOutRound,
                phase = GameRoundPhase.BET_COUNTDOWN,
                roundVersion = 1L,
                currentMultiplier = BigDecimal("1.0000"),
            )
        )
        fairnessAuthority.publishPreBetCommitment(
            PublishCommitmentCommand(
                tenantId = tenantId,
                gameId = gameId,
                roundId = cashOutRound,
                publicSalt = propertiesV1.publicSalt,
                algorithmVersion = propertiesV1.algorithmVersion,
                rulesVersion = propertiesV1.rulesVersion,
            )
        )

        assertEquals(AviatorCommandAckStatus.ACCEPTED, gameService.processCommand(placeBetCommand(cashOutRound, "cmd-tc021-golden-bet-1")).status)
        assertEquals(startingBalance - wagerMinor, ledgerStore.findBalance(tenantId, "PLAYER:$playerIdStr", currency))
        assertEquals(wagerMinor, ledgerStore.findBalance(tenantId, "ESCROW:GAME:$gameId", currency))

        gameService.createOrUpdateRound(
            CreateOrUpdateRoundCommand(
                tenantId = tenantId,
                gameId = gameId,
                roundId = cashOutRound,
                phase = GameRoundPhase.FLYING,
                roundVersion = 2L,
                currentMultiplier = multiplier,
                crashMultiplier = BigDecimal("10.0000"),
            )
        )
        val cashOutAck = gameService.processCommand(
            AviatorRestCommand(
                tenantId = tenantId,
                principal = playerPrincipal,
                commandId = "cmd-tc021-golden-cashout-1",
                roundId = cashOutRound,
                handId = "hand_primary",
                action = "CASH_OUT",
                currency = currency,
                correlationId = "corr-tc021-golden-cashout-1",
            )
        )
        assertEquals(AviatorCommandAckStatus.ACCEPTED, cashOutAck.status)
        assertEquals(expectedWinMinor, cashOutAck.result?.payoutMinor)
        assertEquals(startingBalance - wagerMinor + expectedWinMinor, ledgerStore.findBalance(tenantId, "PLAYER:$playerIdStr", currency))
        assertEquals(0L, ledgerStore.findBalance(tenantId, "ESCROW:GAME:$gameId", currency))

        val cancelRound = "rnd-tc021-golden-cancel"
        closeActiveRoundsFor(jdbc, tenantId, gameId, keepRoundId = cancelRound)
        gameService.createOrUpdateRound(
            CreateOrUpdateRoundCommand(
                tenantId = tenantId,
                gameId = gameId,
                roundId = cancelRound,
                phase = GameRoundPhase.BET_COUNTDOWN,
                roundVersion = 1L,
                currentMultiplier = BigDecimal("1.0000"),
            )
        )
        fairnessAuthority.publishPreBetCommitment(
            PublishCommitmentCommand(
                tenantId = tenantId,
                gameId = gameId,
                roundId = cancelRound,
                publicSalt = propertiesV1.publicSalt,
                algorithmVersion = propertiesV1.algorithmVersion,
                rulesVersion = propertiesV1.rulesVersion,
            )
        )
        assertEquals(AviatorCommandAckStatus.ACCEPTED, gameService.processCommand(placeBetCommand(cancelRound, "cmd-tc021-golden-bet-cancel")).status)
        assertEquals(startingBalance - 2 * wagerMinor + expectedWinMinor, ledgerStore.findBalance(tenantId, "PLAYER:$playerIdStr", currency))
        assertEquals(wagerMinor, ledgerStore.findBalance(tenantId, "ESCROW:GAME:$gameId", currency))
        val cancelAck = gameService.processCommand(
            AviatorRestCommand(
                tenantId = tenantId,
                principal = playerPrincipal,
                commandId = "cmd-tc021-golden-cancel-1",
                roundId = cancelRound,
                handId = "hand_primary",
                action = "CANCEL_BET",
                currency = currency,
                correlationId = "corr-tc021-golden-cancel-1",
            )
        )
        assertEquals(AviatorCommandAckStatus.ACCEPTED, cancelAck.status)
        assertEquals(startingBalance - wagerMinor + expectedWinMinor, ledgerStore.findBalance(tenantId, "PLAYER:$playerIdStr", currency))
        assertEquals(0L, ledgerStore.findBalance(tenantId, "ESCROW:GAME:$gameId", currency))

        val lossRound = "rnd-tc021-golden-loss"
        closeActiveRoundsFor(jdbc, tenantId, gameId, keepRoundId = lossRound)
        gameService.createOrUpdateRound(
            CreateOrUpdateRoundCommand(
                tenantId = tenantId,
                gameId = gameId,
                roundId = lossRound,
                phase = GameRoundPhase.BET_COUNTDOWN,
                roundVersion = 1L,
                currentMultiplier = BigDecimal("1.0000"),
            )
        )
        fairnessAuthority.publishPreBetCommitment(
            PublishCommitmentCommand(
                tenantId = tenantId,
                gameId = gameId,
                roundId = lossRound,
                publicSalt = propertiesV1.publicSalt,
                algorithmVersion = propertiesV1.algorithmVersion,
                rulesVersion = propertiesV1.rulesVersion,
            )
        )
        assertEquals(AviatorCommandAckStatus.ACCEPTED, gameService.processCommand(placeBetCommand(lossRound, "cmd-tc021-golden-bet-2")).status)
        val crashResult = gameService.settleRoundCrash(SettleRoundCrashCommand(tenantId, gameId, lossRound, BigDecimal("1.0000")))
        assertEquals(1, crashResult.settledBetsCount)
        assertEquals(0L, jdbc.queryForObject("select payout_minor_units from game_bet_settlement where tenant_id = ? and outcome = 'LOSS_CRASH'", Long::class.java, tenantId))
        assertEquals(0L, ledgerStore.findBalance(tenantId, "ESCROW:GAME:$gameId", currency))
        assertJournalBalanced()
    }

    private fun assertMonotonic(events: List<Pair<String, Int>>) {
        var previousRank = 0
        for ((resource, rank) in events) {
            if (resource == "RECEIPT_WRITE") continue
            assertTrue(rank >= previousRank, "Lock rank inversion at $resource ($rank) after $previousRank in $events")
            previousRank = rank
        }
    }

    class MutableClock(private var current: Instant) : Clock() {
        override fun getZone(): ZoneId = ZoneOffset.UTC
        override fun withZone(zone: ZoneId): Clock = this
        override fun instant(): Instant = current
        fun advanceMillis(millis: Long) {
            current = current.plusMillis(millis)
        }
    }
}
