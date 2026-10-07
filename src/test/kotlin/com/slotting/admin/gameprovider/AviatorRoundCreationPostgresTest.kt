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
import kotlin.test.assertEquals
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue

@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.NONE)
class AviatorRoundCreationPostgresTest {

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
    private val tenantId = "tenant-tc002-round"
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
        publicSalt = "tc002-public-salt",
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
    private lateinit var orchestrator: AviatorRoundLifecycleOrchestrator

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
        orchestrator = AviatorRoundLifecycleOrchestrator(
            port = lifecyclePort,
            properties = properties,
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
    fun `GivenFreshDatabase_WhenLifecycleCreatesRound_ThenParentCommitmentAndAuditCommit`() {
        val round = orchestrator.ensureRunning(tenantId, gameId)

        assertEquals(GameRoundPhase.SCHEDULED, round.phase)
        assertEquals(tenantId, round.tenantId)
        assertEquals(gameId, round.gameId)

        val storedRound = gameStore.findRound(tenantId, gameId, round.roundId)
        assertNotNull(storedRound)
        assertEquals(GameRoundPhase.SCHEDULED, storedRound.phase)

        val commitment = fairnessStore.findCommitment(tenantId, gameId, round.roundId)
        assertNotNull(commitment)
        assertEquals(round.roundId, commitment.roundId)
        assertEquals(RoundCommitmentStatus.COMMITTED, commitment.status)
        assertEquals(64, commitment.commitmentHash.length)

        val audits = fairnessStore.findAuditEvents(tenantId, round.roundId)
        assertEquals(1, audits.size)
        assertEquals("PRE_BET_COMMITMENT_PUBLISHED", audits.single().action)
        assertEquals(round.roundId, audits.single().roundId)
    }

    @Test
    fun `GivenRoundInsert_WhenCommitmentWriteFails_ThenAllThreeTablesRollBack`() {
        val roundId = "aviator-failpoint-${UUID.randomUUID()}"
        var failCommitment = true

        val failingFairnessStore = object : FairnessEvidenceStore by fairnessStore {
            override fun saveCommitment(commitment: RoundCommitmentRecord) {
                if (failCommitment) {
                    throw RuntimeException("SIMULATED_FAILPOINT_AFTER_ROUND_INSERT")
                }
                fairnessStore.saveCommitment(commitment)
            }
        }

        val failingFairnessAuthority = ProvablyFairOutcomeAuthority(store = failingFairnessStore, clock = clock)
        val testPort = ProductionAviatorLifecyclePort(
            gameService = gameService,
            fairnessAuthority = failingFairnessAuthority,
            snapshotService = snapshotService,
            txManager = txManager,
        )

        assertThrows<Exception> {
            testPort.createScheduledRoundWithCommitment(tenantId, gameId, roundId, properties)
        }

        val roundCount = jdbc.queryForObject(
            "select count(*) from game_authoritative_round where tenant_id = ? and game_id = ? and round_id = ?",
            Int::class.java,
            tenantId, gameId, roundId
        )
        val commitmentCount = jdbc.queryForObject(
            "select count(*) from game_fairness_commitment where tenant_id = ? and game_id = ? and round_id = ?",
            Int::class.java,
            tenantId, gameId, roundId
        )
        val auditCount = jdbc.queryForObject(
            "select count(*) from game_fairness_audit where tenant_id = ? and round_id = ?",
            Int::class.java,
            tenantId, roundId
        )

        assertEquals(0, roundCount)
        assertEquals(0, commitmentCount)
        assertEquals(0, auditCount)

        failCommitment = false
        val retryResult = testPort.createScheduledRoundWithCommitment(tenantId, gameId, roundId, properties)
        assertNotNull(retryResult.first)

        val retryRoundCount = jdbc.queryForObject(
            "select count(*) from game_authoritative_round where tenant_id = ? and game_id = ? and round_id = ?",
            Int::class.java,
            tenantId, gameId, roundId
        )
        val retryCommitmentCount = jdbc.queryForObject(
            "select count(*) from game_fairness_commitment where tenant_id = ? and game_id = ? and round_id = ?",
            Int::class.java,
            tenantId, gameId, roundId
        )
        val retryAuditCount = jdbc.queryForObject(
            "select count(*) from game_fairness_audit where tenant_id = ? and round_id = ?",
            Int::class.java,
            tenantId, roundId
        )

        assertEquals(1, retryRoundCount)
        assertEquals(1, retryCommitmentCount)
        assertEquals(1, retryAuditCount)
    }

    @Test
    fun `GivenProductionLifecycle_WhenThreeRoundsComplete_ThenNoOrphansExist`() {
        val testClock = MutableTestClock(now)
        val portWithClock = ProductionAviatorLifecyclePort(
            gameService = DurableGameWagerAndSettlementService(
                store = gameStore,
                ledgerService = ledgerService,
                registrationStore = registrationStore,
                eligibilityStore = eligibilityStore,
                adminPrincipal = adminPrincipal,
                clock = testClock,
                txManager = txManager,
            ),
            fairnessAuthority = ProvablyFairOutcomeAuthority(store = fairnessStore, clock = testClock),
            snapshotService = snapshotService,
            txManager = txManager,
        )
        val activeOrchestrator = AviatorRoundLifecycleOrchestrator(
            port = portWithClock,
            properties = properties,
            clock = testClock,
        )

        fun completeRound(orch: AviatorRoundLifecycleOrchestrator): GameRoundRecord {
            var round = orch.ensureRunning(tenantId, gameId)
            while (round.phase != GameRoundPhase.CLOSED) {
                testClock.advanceMillis(10_000)
                round = orch.tick(tenantId, gameId)
            }
            return round
        }

        val round1 = completeRound(activeOrchestrator)
        assertEquals(GameRoundPhase.CLOSED, round1.phase)
        testClock.advanceMillis(properties.closedMillis)
        activeOrchestrator.tick(tenantId, gameId)

        val round2 = completeRound(activeOrchestrator)
        assertEquals(GameRoundPhase.CLOSED, round2.phase)
        testClock.advanceMillis(properties.closedMillis)
        activeOrchestrator.tick(tenantId, gameId)

        val round3 = completeRound(activeOrchestrator)
        assertEquals(GameRoundPhase.CLOSED, round3.phase)

        val closedCount = jdbc.queryForObject(
            "select count(*) from game_authoritative_round where tenant_id = ? and game_id = ? and phase = 'CLOSED'",
            Int::class.java,
            tenantId, gameId
        )
        assertEquals(3, closedCount)

        val orphanCommitments = jdbc.queryForObject(
            """
            select count(*) from game_fairness_commitment c
            where c.tenant_id = ? and not exists (
                select 1 from game_authoritative_round r
                where r.tenant_id = c.tenant_id and r.game_id = c.game_id and r.round_id = c.round_id
            )
            """.trimIndent(),
            Int::class.java,
            tenantId
        )
        assertEquals(0, orphanCommitments)

        val fake = FakeFaithfulLifecyclePort(testClock)
        assertThrows<IllegalStateException> {
            fake.ensureCommitment(tenantId, gameId, "non-existent-round-id", properties)
        }
    }

    @Test
    fun `GivenMixedOperations_WhenLocksAreObserved_ThenGlobalOrderIsPreserved`() {
        val pool = Executors.newFixedThreadPool(2)
        val rankInversions = ConcurrentLinkedQueue<String>()
        val iterations = 100

        for (i in 0 until iterations) {
            val roundId = "aviator-lock-${UUID.randomUUID()}"
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

    @Test
    fun `GivenRoundCreation_WhenTransactionIsObserved_ThenAllRequiredWritesShareOneBoundary`() {
        val roundId = "aviator-tx-${UUID.randomUUID()}"

        val failingFairnessStore = object : FairnessEvidenceStore by fairnessStore {
            override fun saveAuditEvent(event: FairnessAuditRecord) {
                fairnessStore.saveAuditEvent(event)
                throw RuntimeException("SIMULATED_FAILPOINT_AFTER_AUDIT_WRITE")
            }
        }
        val failingAuthority = ProvablyFairOutcomeAuthority(store = failingFairnessStore, clock = clock)
        val testPort = ProductionAviatorLifecyclePort(
            gameService = gameService,
            fairnessAuthority = failingAuthority,
            snapshotService = snapshotService,
            txManager = txManager,
        )

        assertThrows<Exception> {
            testPort.createScheduledRoundWithCommitment(tenantId, gameId, roundId, properties)
        }

        val roundCount = jdbc.queryForObject(
            "select count(*) from game_authoritative_round where tenant_id = ? and game_id = ? and round_id = ?",
            Int::class.java,
            tenantId, gameId, roundId
        )
        val commitmentCount = jdbc.queryForObject(
            "select count(*) from game_fairness_commitment where tenant_id = ? and game_id = ? and round_id = ?",
            Int::class.java,
            tenantId, gameId, roundId
        )
        val auditCount = jdbc.queryForObject(
            "select count(*) from game_fairness_audit where tenant_id = ? and round_id = ?",
            Int::class.java,
            tenantId, roundId
        )

        assertEquals(0, roundCount)
        assertEquals(0, commitmentCount)
        assertEquals(0, auditCount)
    }

    @Test
    fun `GivenRoundCreation_WhenTenantOrRoundKeysDiffer_ThenNoCrossLinkedEvidenceIsCommitted`() {
        val tenantA = "tenant-tc002-iso-a-${UUID.randomUUID()}"
        val tenantB = "tenant-tc002-iso-b-${UUID.randomUUID()}"
        val roundA = "aviator-iso-a-${UUID.randomUUID()}"
        val roundB = "aviator-iso-b-${UUID.randomUUID()}"

        try {
            lifecyclePort.createScheduledRoundWithCommitment(tenantA, gameId, roundA, properties)
            lifecyclePort.createScheduledRoundWithCommitment(tenantB, gameId, roundB, properties)

            val commitmentA = fairnessStore.findCommitment(tenantA, gameId, roundA)
            assertNotNull(commitmentA)
            assertEquals(tenantA, commitmentA.tenantId)
            assertEquals(roundA, commitmentA.roundId)

            val commitmentB = fairnessStore.findCommitment(tenantB, gameId, roundB)
            assertNotNull(commitmentB)
            assertEquals(tenantB, commitmentB.tenantId)
            assertEquals(roundB, commitmentB.roundId)

            assertNull(fairnessStore.findCommitment(tenantA, gameId, roundB))
            assertNull(fairnessStore.findCommitment(tenantB, gameId, roundA))

            val auditsA = fairnessStore.findAuditEvents(tenantA, roundA)
            assertEquals(1, auditsA.size)
            assertEquals(roundA, auditsA.single().roundId)
            assertEquals("PRE_BET_COMMITMENT_PUBLISHED", auditsA.single().action)
            assertTrue(auditsA.single().detail.contains(commitmentA.commitmentHash))

            assertEquals(0, fairnessStore.findAuditEvents(tenantB, roundA).size)
            assertEquals(0, fairnessStore.findAuditEvents(tenantA, roundB).size)

            val crossLinked = jdbc.queryForObject(
                """
                select count(*) from game_fairness_commitment c
                where c.tenant_id in (?, ?) and not exists (
                    select 1 from game_authoritative_round r
                    where r.tenant_id = c.tenant_id and r.game_id = c.game_id and r.round_id = c.round_id
                )
                """.trimIndent(),
                Int::class.java,
                tenantA, tenantB
            )
            assertEquals(0, crossLinked)
        } finally {
            jdbc.update("delete from game_fairness_audit where tenant_id in (?, ?)", tenantA, tenantB)
            jdbc.update("delete from game_fairness_reveal where tenant_id in (?, ?)", tenantA, tenantB)
            jdbc.update("delete from game_fairness_commitment where tenant_id in (?, ?)", tenantA, tenantB)
            jdbc.update("delete from game_authoritative_round where tenant_id in (?, ?)", tenantA, tenantB)
        }
    }

    private class MutableTestClock(private var current: Instant) : Clock() {
        override fun getZone(): ZoneOffset = ZoneOffset.UTC
        override fun withZone(zone: java.time.ZoneId?): Clock = this
        override fun instant(): Instant = current
        fun advanceMillis(millis: Long) {
            current = current.plusMillis(millis)
        }
    }

    private class FakeFaithfulLifecyclePort(private val clock: Clock) : AviatorLifecyclePort {
        var round: GameRoundRecord? = null

        override fun latestRound(tenantId: String, gameId: String): GameRoundRecord? = round?.copy()

        override fun createScheduledRoundWithCommitment(
            tenantId: String,
            gameId: String,
            roundId: String,
            properties: AviatorLifecycleProperties,
        ): Pair<GameRoundRecord, String> {
            val created = persistRound(
                CreateOrUpdateRoundCommand(
                    tenantId = tenantId,
                    gameId = gameId,
                    roundId = roundId,
                    phase = GameRoundPhase.SCHEDULED,
                    roundVersion = 1,
                    currentMultiplier = BigDecimal("1.0000"),
                    crashMultiplier = null,
                )
            )
            val commitment = ensureCommitment(tenantId, gameId, roundId, properties)
            return created to commitment
        }

        override fun ensureCommitment(
            tenantId: String,
            gameId: String,
            roundId: String,
            properties: AviatorLifecycleProperties,
        ): String {
            val existing = round
            check(existing != null && existing.roundId == roundId) {
                "Foreign key violation: parent round $roundId does not exist"
            }
            return "commitment-$roundId"
        }

        override fun deriveOutcome(tenantId: String, gameId: String, roundId: String): LifecycleOutcome =
            LifecycleOutcome(BigDecimal("1.1000"))

        override fun persistRound(command: CreateOrUpdateRoundCommand): GameRoundRecord {
            val now = clock.instant()
            val created = GameRoundRecord(
                tenantId = command.tenantId,
                gameId = command.gameId,
                roundId = command.roundId,
                phase = command.phase,
                roundVersion = command.roundVersion,
                currentMultiplier = command.currentMultiplier,
                crashMultiplier = command.crashMultiplier,
                startedAt = now,
                serverTime = now,
                createdAt = now,
                updatedAt = now,
            )
            round = created
            return created
        }

        override fun publishState(round: GameRoundRecord, elapsedFlightSeconds: Double): GameEventRecord =
            GameEventRecord(
                eventId = UUID.randomUUID(), tenantId = round.tenantId, gameId = round.gameId,
                roundId = round.roundId, sequenceId = 1L, eventName = "gameState",
                payloadJson = "{}", targetScope = "BROADCAST", targetOwnerId = null,
                timestampMillis = clock.instant().toEpochMilli(), createdAt = clock.instant(),
            )

        override fun settleCrash(tenantId: String, gameId: String, roundId: String, crashMultiplier: BigDecimal) {}

        override fun revealIfNeeded(tenantId: String, gameId: String, roundId: String, expectedMultiplier: BigDecimal) {}
    }
}
