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
            clock = clock,
            txManager = txManager,
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

    class LockOrderTracingStore(
        private val delegate: DurableGameWagerAndSettlementStore,
        val eventLog: MutableList<Pair<String, Int>> = mutableListOf(),
        val onRoundShared: (() -> Unit)? = null,
        val onBeforeRoundExclusive: (() -> Unit)? = null,
        val onAfterRoundExclusive: (() -> Unit)? = null,
    ) : DurableGameWagerAndSettlementStore by delegate {
        override fun findReceipt(tenantId: String, commandId: String): GameCommandReceiptRecord? {
            eventLog.add("RECEIPT" to 1)
            return delegate.findReceipt(tenantId, commandId)
        }

        override fun findRoundForShare(tenantId: String, gameId: String, roundId: String): GameRoundRecord? {
            val r = delegate.findRoundForShare(tenantId, gameId, roundId)
            eventLog.add("ROUND_SHARED" to 2)
            onRoundShared?.invoke()
            return r
        }

        override fun findRoundForUpdate(tenantId: String, gameId: String, roundId: String): GameRoundRecord? {
            eventLog.add("ROUND_EXCLUSIVE_ATTEMPT" to 2)
            onBeforeRoundExclusive?.invoke()
            val r = delegate.findRoundForUpdate(tenantId, gameId, roundId)
            eventLog.add("ROUND_EXCLUSIVE" to 2)
            onAfterRoundExclusive?.invoke()
            return r
        }

        override fun findBet(tenantId: String, gameId: String, roundId: String, ownerId: String, handId: String): GameAcceptedBetRecord? {
            eventLog.add("BET" to 3)
            return delegate.findBet(tenantId, gameId, roundId, ownerId, handId)
        }

        override fun nextSequenceId(tenantId: String): Long {
            eventLog.add("SEQUENCE_COUNTER" to 5)
            return delegate.nextSequenceId(tenantId)
        }

        override fun saveReceipt(receipt: GameCommandReceiptRecord) {
            eventLog.add("RECEIPT_WRITE" to 1)
            delegate.saveReceipt(receipt)
        }
    }

    @Test
    fun `GivenMixedOperations_WhenLocksAreObserved_ThenGlobalOrderIsPreserved`() {
        val pool = Executors.newFixedThreadPool(4)
        val rankInversions = ConcurrentLinkedQueue<String>()

        ledgerService.postTransaction(
            PostTransactionCommand(
                principal = adminPrincipal,
                tenantId = tenantId,
                transactionReference = "TX-SEED-LOCK-TEST-${UUID.randomUUID()}",
                currencyCode = "INR",
                entries = listOf(
                    JournalEntryDraft("HOUSE:SEED", JournalEntryDirection.DEBIT, 20_000_000L, "INR"),
                    JournalEntryDraft("PLAYER:$playerIdStr", JournalEntryDirection.CREDIT, 10_000_000L, "INR"),
                    JournalEntryDraft("HOUSE:GAME:$gameId", JournalEntryDirection.CREDIT, 10_000_000L, "INR"),
                ),
                idempotencyKey = "IDEM-SEED-LOCK-${UUID.randomUUID()}",
                correlationId = "corr-seed",
                causationId = "caus-seed",
            )
        )

        val actionTypes = listOf("PLACE_BET", "CANCEL_BET", "CASH_OUT")
        for ((idx, actionType) in actionTypes.withIndex()) {
            for (i in 0 until 5) {
                val roundId = "rnd-lock-cas-$idx-$i-${UUID.randomUUID().toString().take(6)}"
                gameService.createOrUpdateRound(
                    CreateOrUpdateRoundCommand(
                        tenantId = tenantId,
                        gameId = gameId,
                        roundId = roundId,
                        phase = GameRoundPhase.BET_COUNTDOWN,
                        roundVersion = 1L,
                    )
                )

                if (actionType == "CANCEL_BET") {
                    val placeAck = gameService.processCommand(
                        AviatorRestCommand(
                            tenantId = tenantId,
                            principal = playerPrincipal,
                            commandId = "cmd-pre-cancel-$idx-$i-${UUID.randomUUID().toString().take(4)}",
                            roundId = roundId,
                            handId = "hand_primary",
                            action = "PLACE_BET",
                            wagerMinor = 100L,
                            currency = "INR",
                            correlationId = "corr-pre-cancel-$idx-$i",
                        )
                    )
                    assertEquals(AviatorCommandAckStatus.ACCEPTED, placeAck.status)
                } else if (actionType == "CASH_OUT") {
                    val placeAck = gameService.processCommand(
                        AviatorRestCommand(
                            tenantId = tenantId,
                            principal = playerPrincipal,
                            commandId = "cmd-pre-cashout-$idx-$i-${UUID.randomUUID().toString().take(4)}",
                            roundId = roundId,
                            handId = "hand_primary",
                            action = "PLACE_BET",
                            wagerMinor = 100L,
                            currency = "INR",
                            correlationId = "corr-pre-cashout-$idx-$i",
                        )
                    )
                    assertEquals(AviatorCommandAckStatus.ACCEPTED, placeAck.status)
                    gameService.createOrUpdateRound(
                        CreateOrUpdateRoundCommand(
                            tenantId = tenantId,
                            gameId = gameId,
                            roundId = roundId,
                            phase = GameRoundPhase.FLYING,
                            roundVersion = 2L,
                            expectedVersion = 1L,
                            currentMultiplier = BigDecimal("1.2500"),
                        )
                    )
                }

                val cmdStore = LockOrderTracingStore(gameStore)
                val cmdService = DurableGameWagerAndSettlementService(
                    store = cmdStore,
                    ledgerService = ledgerService,
                    registrationStore = registrationStore,
                    eligibilityStore = eligibilityStore,
                    adminPrincipal = adminPrincipal,
                    clock = clock,
                    txManager = txManager,
                )

                val lifecycleStore = LockOrderTracingStore(gameStore)
                val lifecycleService = DurableGameWagerAndSettlementService(
                    store = lifecycleStore,
                    ledgerService = ledgerService,
                    registrationStore = registrationStore,
                    eligibilityStore = eligibilityStore,
                    adminPrincipal = adminPrincipal,
                    clock = clock,
                    txManager = txManager,
                )

                val latch = CountDownLatch(2)

                val workerCommand = Runnable {
                    try {
                        val ack = cmdService.processCommand(
                            AviatorRestCommand(
                                tenantId = tenantId,
                                principal = playerPrincipal,
                                commandId = "cmd-lock-$idx-$i-${UUID.randomUUID().toString().take(4)}",
                                roundId = roundId,
                                handId = "hand_primary",
                                action = actionType,
                                wagerMinor = if (actionType == "PLACE_BET") 100L else null,
                                currency = "INR",
                                correlationId = "corr-lock-$idx-$i",
                            )
                        )
                        assertEquals(AviatorCommandAckStatus.ACCEPTED, ack.status)
                    } finally {
                        latch.countDown()
                    }
                }

                val workerLifecycle = Runnable {
                    try {
                        if (actionType == "CASH_OUT") {
                            lifecycleService.createOrUpdateRound(
                                CreateOrUpdateRoundCommand(
                                    tenantId = tenantId,
                                    gameId = gameId,
                                    roundId = roundId,
                                    phase = GameRoundPhase.FLYING,
                                    roundVersion = 3L,
                                    expectedVersion = 2L,
                                    currentMultiplier = BigDecimal("1.3000"),
                                )
                            )
                        } else {
                            lifecycleService.createOrUpdateRound(
                                CreateOrUpdateRoundCommand(
                                    tenantId = tenantId,
                                    gameId = gameId,
                                    roundId = roundId,
                                    phase = GameRoundPhase.FLYING,
                                    roundVersion = 2L,
                                    expectedVersion = 1L,
                                    currentMultiplier = BigDecimal("1.0000"),
                                )
                            )
                        }
                    } catch (_: RoundVersionConflictException) {
                    } finally {
                        latch.countDown()
                    }
                }

                pool.submit(workerCommand)
                pool.submit(workerLifecycle)
                assertTrue(latch.await(5, TimeUnit.SECONDS))

                var prevRank = 0
                for ((resource, rank) in cmdStore.eventLog) {
                    if (resource != "RECEIPT_WRITE" && rank < prevRank) {
                        rankInversions.add("Inversion on command $actionType: $resource($rank) after rank $prevRank")
                    }
                    if (resource != "RECEIPT_WRITE") {
                        prevRank = rank
                    }
                }
                assertTrue(cmdStore.eventLog.any { it.first == "ROUND_SHARED" }, "Command $actionType must acquire shared round lock")
                assertTrue(lifecycleStore.eventLog.any { it.first == "ROUND_EXCLUSIVE" }, "Lifecycle must acquire exclusive round lock")
            }
        }

        assertTrue(rankInversions.isEmpty(), "Zero lock rank inversions expected: $rankInversions")

        for (actionType in listOf("PLACE_BET", "CANCEL_BET", "CASH_OUT")) {
            val testRoundId = "rnd-lock-share-hold-$actionType-${UUID.randomUUID().toString().take(6)}"
            gameService.createOrUpdateRound(
                CreateOrUpdateRoundCommand(
                    tenantId = tenantId,
                    gameId = gameId,
                    roundId = testRoundId,
                    phase = GameRoundPhase.BET_COUNTDOWN,
                    roundVersion = 1L,
                )
            )

            if (actionType == "CANCEL_BET") {
                val preBetAck = gameService.processCommand(
                    AviatorRestCommand(
                        tenantId = tenantId,
                        principal = playerPrincipal,
                        commandId = "cmd-pre-hold-cancel-${UUID.randomUUID().toString().take(4)}",
                        roundId = testRoundId,
                        handId = "hand_hold",
                        action = "PLACE_BET",
                        wagerMinor = 200L,
                        currency = "INR",
                        correlationId = "corr-pre-hold-cancel",
                    )
                )
                assertEquals(AviatorCommandAckStatus.ACCEPTED, preBetAck.status)
            } else if (actionType == "CASH_OUT") {
                val preBetAck = gameService.processCommand(
                    AviatorRestCommand(
                        tenantId = tenantId,
                        principal = playerPrincipal,
                        commandId = "cmd-pre-hold-cashout-${UUID.randomUUID().toString().take(4)}",
                        roundId = testRoundId,
                        handId = "hand_hold",
                        action = "PLACE_BET",
                        wagerMinor = 200L,
                        currency = "INR",
                        correlationId = "corr-pre-hold-cashout",
                    )
                )
                assertEquals(AviatorCommandAckStatus.ACCEPTED, preBetAck.status)
                gameService.createOrUpdateRound(
                    CreateOrUpdateRoundCommand(
                        tenantId = tenantId,
                        gameId = gameId,
                        roundId = testRoundId,
                        phase = GameRoundPhase.FLYING,
                        roundVersion = 2L,
                        expectedVersion = 1L,
                        currentMultiplier = BigDecimal("1.2500"),
                    )
                )
            }

            var cmdPid: Int? = null
            var lifecyclePid: Int? = null

            val roundLockedLatch = CountDownLatch(1)
            val releaseCommandLatch = CountDownLatch(1)

            val blockingStore = LockOrderTracingStore(
                gameStore,
                onRoundShared = {
                    cmdPid = jdbc.queryForObject("SELECT pg_backend_pid()", Int::class.java)
                    roundLockedLatch.countDown()
                    releaseCommandLatch.await(5, TimeUnit.SECONDS)
                }
            )
            val blockingService = DurableGameWagerAndSettlementService(
                store = blockingStore,
                ledgerService = ledgerService,
                registrationStore = registrationStore,
                eligibilityStore = eligibilityStore,
                adminPrincipal = adminPrincipal,
                clock = clock,
                txManager = txManager,
            )

            val lifecycleAttemptLatch = CountDownLatch(1)
            val lifecycleTracingStore = LockOrderTracingStore(
                gameStore,
                onBeforeRoundExclusive = {
                    lifecyclePid = jdbc.queryForObject("SELECT pg_backend_pid()", Int::class.java)
                    lifecycleAttemptLatch.countDown()
                }
            )
            val lifecycleTracingService = DurableGameWagerAndSettlementService(
                store = lifecycleTracingStore,
                ledgerService = ledgerService,
                registrationStore = registrationStore,
                eligibilityStore = eligibilityStore,
                adminPrincipal = adminPrincipal,
                clock = clock,
                txManager = txManager,
            )

            val cmdFuture = pool.submit<AviatorCommandAckResult> {
                blockingService.processCommand(
                    AviatorRestCommand(
                        tenantId = tenantId,
                        principal = playerPrincipal,
                        commandId = "cmd-holding-share-$actionType-${UUID.randomUUID().toString().take(6)}",
                        roundId = testRoundId,
                        handId = if (actionType == "PLACE_BET") "hand_new" else "hand_hold",
                        action = actionType,
                        wagerMinor = if (actionType == "PLACE_BET") 500L else null,
                        currency = "INR",
                        correlationId = "corr-share-hold-$actionType",
                    )
                )
            }

            assertTrue(roundLockedLatch.await(5, TimeUnit.SECONDS), "Command $actionType must acquire shared round lock")

            val lifecycleFuture = pool.submit<GameRoundRecord> {
                if (actionType == "CASH_OUT") {
                    lifecycleTracingService.createOrUpdateRound(
                        CreateOrUpdateRoundCommand(
                            tenantId = tenantId,
                            gameId = gameId,
                            roundId = testRoundId,
                            phase = GameRoundPhase.CRASHED,
                            roundVersion = 3L,
                            expectedVersion = 2L,
                            crashMultiplier = BigDecimal("1.2500"),
                        )
                    )
                } else {
                    lifecycleTracingService.createOrUpdateRound(
                        CreateOrUpdateRoundCommand(
                            tenantId = tenantId,
                            gameId = gameId,
                            roundId = testRoundId,
                            phase = GameRoundPhase.FLYING,
                            roundVersion = 2L,
                            expectedVersion = 1L,
                            currentMultiplier = BigDecimal("1.0000"),
                        )
                    )
                }
            }

            assertTrue(lifecycleAttemptLatch.await(5, TimeUnit.SECONDS), "Lifecycle must attempt exclusive round lock")

            var ungrantedCount = 0
            var blockedSpecifically = false
            for (attempt in 0 until 50) {
                val currentLifecyclePid = lifecyclePid
                val currentCmdPid = cmdPid
                if (currentLifecyclePid != null && currentCmdPid != null) {
                    ungrantedCount = jdbc.queryForObject(
                        "SELECT count(*) FROM pg_locks WHERE pid = ? AND NOT granted",
                        Int::class.java,
                        currentLifecyclePid,
                    ) ?: 0
                    val blockerMatches = jdbc.queryForObject(
                        """
                        SELECT count(*) FROM pg_stat_activity
                        WHERE pid = ?
                          AND wait_event_type = 'Lock'
                          AND query LIKE '%game_authoritative_round%for update%'
                          AND ? = ANY(pg_blocking_pids(pid))
                        """.trimIndent(),
                        Int::class.java,
                        currentLifecyclePid,
                        currentCmdPid,
                    ) ?: 0
                    val relationLockCount = jdbc.queryForObject(
                        "SELECT count(*) FROM pg_locks WHERE pid = ? AND relation = 'game_authoritative_round'::regclass::oid",
                        Int::class.java,
                        currentLifecyclePid,
                    ) ?: 0
                    if (ungrantedCount > 0 && blockerMatches > 0 && relationLockCount > 0) {
                        blockedSpecifically = true
                        break
                    }
                }
                Thread.sleep(20)
            }
            assertNotNull(lifecyclePid, "Lifecycle backend PID must be captured")
            assertNotNull(cmdPid, "Command backend PID must be captured")
            assertTrue(ungrantedCount > 0, "PostgreSQL must report ungranted lock for lifecycle PID $lifecyclePid while $actionType holds FOR SHARE")
            assertTrue(blockedSpecifically, "Lifecycle connection $lifecyclePid must be specifically blocked on game_authoritative_round FOR UPDATE by command connection $cmdPid")
            kotlin.test.assertFalse(lifecycleFuture.isDone, "Exclusive lifecycle write must be blocked in PostgreSQL while $actionType holds FOR SHARE")
            kotlin.test.assertFalse(lifecycleTracingStore.eventLog.any { it.first == "ROUND_EXCLUSIVE" }, "ROUND_EXCLUSIVE must not be granted yet")

            releaseCommandLatch.countDown()

            val ack = cmdFuture.get(5, TimeUnit.SECONDS)
            assertEquals(AviatorCommandAckStatus.ACCEPTED, ack.status)

            val updatedRound = lifecycleFuture.get(5, TimeUnit.SECONDS)
            assertNotNull(updatedRound)
            assertTrue(lifecycleTracingStore.eventLog.any { it.first == "ROUND_EXCLUSIVE" }, "Lifecycle must acquire ROUND_EXCLUSIVE after command releases")

            val remainingUngranted = jdbc.queryForObject(
                "SELECT count(*) FROM pg_locks WHERE pid = ? AND NOT granted",
                Int::class.java,
                lifecyclePid,
            ) ?: 0
            assertEquals(0, remainingUngranted, "PostgreSQL ungranted locks for lifecycle PID $lifecyclePid must be cleared after transaction commits")
        }

        pool.shutdown()
        pool.awaitTermination(5, TimeUnit.SECONDS)
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
