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
import org.junit.jupiter.api.assertThrows
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.boot.test.context.SpringBootTest
import org.springframework.boot.test.mock.mockito.MockBean
import org.springframework.jdbc.core.JdbcTemplate
import org.springframework.test.context.DynamicPropertyRegistry
import org.springframework.test.context.DynamicPropertySource
import org.springframework.transaction.PlatformTransactionManager
import java.math.BigDecimal
import java.math.RoundingMode
import java.sql.Timestamp
import java.time.Clock
import java.time.Instant
import java.time.LocalDate
import java.time.ZoneId
import java.time.ZoneOffset
import java.util.UUID
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.ConcurrentLinkedQueue
import java.util.concurrent.CountDownLatch
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit
import kotlin.test.assertEquals
import kotlin.test.assertNotNull
import kotlin.test.assertTrue

@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.NONE)
class AviatorLifecycleFencingTest {
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

    private val now = Instant.parse("2026-10-01T10:00:00Z")
    private val tenantId = "tenant-tc019-fencing"
    private val gameId = "AVIATOR"
    private val currency = "INR"
    private val playerUuid = UUID.randomUUID()
    private val playerIdStr = playerUuid.toString()

    private val adminPrincipal = AuthenticatedPrincipal(
        id = "admin-sys-tc019",
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
        scheduledMillis = 10,
        bettingMillis = 10,
        closedMillis = 10,
        multiplierStep = BigDecimal("0.0500"),
        rulesVersion = "1.0.0",
        algorithmVersion = "1.0.0",
        publicSalt = "tc019-public-salt",
        configuredTenants = setOf(tenantId),
    )

    private lateinit var clock: MutableClock
    private lateinit var gameStore: JdbcDurableGameWagerAndSettlementStore
    private lateinit var fairnessStore: JdbcFairnessEvidenceStore
    private lateinit var ledgerStore: JdbcLedgerJournalStore
    private lateinit var registrationStore: JdbcPlayerRegistrationStore
    private lateinit var eligibilityStore: ServerEligibilityStore
    private lateinit var ledgerService: LedgerPostingService
    private lateinit var gameService: DurableGameWagerAndSettlementService
    private lateinit var fairnessAuthority: ProvablyFairOutcomeAuthority
    private lateinit var snapshotService: AuthoritativeGameSnapshotAndEventService
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
        jdbc.update("delete from game_lifecycle_lease where tenant_id like ?", "tenant-tc019%")
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
        snapshotService = AuthoritativeGameSnapshotAndEventService(
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

    private fun orchestrator(ttlMillis: Long = 5_000L, props: AviatorLifecycleProperties = properties) =
        AviatorRoundLifecycleOrchestrator(port, props, clock, leaseStore, ttlMillis)

    private fun sleepDatabase(millis: Long) {
        jdbc.execute("select pg_sleep(${millis / 1000.0})")
    }

    private fun activeRoundCount(tId: String = tenantId): Int =
        jdbc.queryForObject(
            "select count(*) from game_authoritative_round where tenant_id = ? and game_id = ? and phase <> 'CLOSED'",
            Int::class.java,
            tId,
            gameId,
        ) ?: 0

    private fun roundsCreated(tId: String = tenantId): Int =
        jdbc.queryForObject(
            "select count(*) from game_authoritative_round where tenant_id = ? and game_id = ?",
            Int::class.java,
            tId,
            gameId,
        ) ?: 0

    private fun settleCommand(roundId: String): SettleRoundCrashCommand =
        SettleRoundCrashCommand(tenantId, gameId, roundId, BigDecimal("1.1000"))

    @Test
    fun GivenTwoOrchestrators_WhenFiveHundredTicksRace_ThenOneRoundPerCycle() {
        val raceProps = properties.copy(multiplierStep = BigDecimal("5.0000"))
        val alpha = orchestrator(ttlMillis = 250L, props = raceProps)
        val beta = orchestrator(ttlMillis = 250L, props = raceProps)
        val pool = Executors.newFixedThreadPool(2)
        val failures = ConcurrentLinkedQueue<Throwable>()
        val versionsByRound = ConcurrentHashMap<String, Long>()

        try {
            for (iteration in 0 until 500) {
                clock.advanceMillis(50)
                val instance = if (iteration % 2 == 0) alpha else beta
                val latch = CountDownLatch(1)
                val future = pool.submit {
                    latch.await(5, TimeUnit.SECONDS)
                    try {
                        instance.tick(tenantId, gameId)
                    } catch (e: Throwable) {
                        failures.add(e)
                    }
                }
                latch.countDown()
                future.get(10, TimeUnit.SECONDS)

                assertTrue(
                    activeRoundCount() <= 1,
                    "iteration $iteration must never observe more than one active round",
                )

                val rounds = jdbc.queryForList(
                    "select round_id, round_version from game_authoritative_round where tenant_id = ? and game_id = ? order by round_id",
                    tenantId,
                    gameId,
                )
                for (row in rounds) {
                    val roundId = row["round_id"] as String
                    val version = (row["round_version"] as Number).toLong()
                    val previous = versionsByRound[roundId]
                    if (previous != null) {
                        assertTrue(version >= previous, "round $roundId version regressed from $previous to $version")
                    }
                    versionsByRound[roundId] = maxOf(previous ?: 0L, version)
                }
            }
        } finally {
            pool.shutdownNow()
        }

        clock.advanceMillis(50)
        val currentOwnerId = leaseStore.getLease(tenantId, gameId)?.ownerId
        val stabilizedRound = when (currentOwnerId) {
            alpha.ownerId -> alpha.tick(tenantId, gameId)
            beta.ownerId -> beta.tick(tenantId, gameId)
            else -> null
        }
        stabilizedRound?.let { versionsByRound[it.roundId] = maxOf(versionsByRound[it.roundId] ?: 0L, it.roundVersion) }

        assertTrue(failures.isEmpty(), "no orchestrator tick may fail the fencing contract: ${failures.map { it.message }}")
        assertTrue(roundsCreated() >= 3, "at least three full cycles must complete, saw ${roundsCreated()}")
        assertEquals(1, activeRoundCount(), "exactly one active round must remain for the tenant")
        assertEquals(0, versionsByRound.size - roundsCreated(), "version tracking must cover every created round")

        val diagnostics = alpha.diagnostics(tenantId)
        assertTrue(diagnostics.epoch != null && diagnostics.epoch!! >= 1L, "diagnostics must expose the current epoch")
        assertNotNull(diagnostics.ownerId, "diagnostics must expose the current owner")
        assertTrue(
            diagnostics.notOwnerOutcomes + beta.diagnostics(tenantId).notOwnerOutcomes > 0L,
            "at least one instance must observe a not-owner outcome while the other holds the lease",
        )

        val crashEvents = jdbc.queryForList(
            "select round_id from game_authoritative_round where tenant_id = ? and game_id = ?",
            tenantId,
            gameId,
        ).sumOf { row ->
            eventJournalStore.findEventsForRound(tenantId, gameId, row["round_id"] as String)
                .count { it.eventName == "gameState" && it.payloadJson.contains("CRASHED") }
        }
        assertTrue(
            crashEvents <= roundsCreated(),
            "each round may publish at most one crash transition, published=$crashEvents rounds=${roundsCreated()}",
        )
    }

    @Test
    fun GivenOwnerDiesMidTransition_WhenTtlExpires_ThenTakeoverFencesOldWrites() {
        val roundId = "rnd-tc019-fence-1"
        val acquireA = leaseStore.acquireOrRenew(tenantId, gameId, "node-A", 100L)
        assertEquals(LifecycleLeaseAcquireStatus.ACQUIRED, acquireA.status)
        val tokenA = LifecycleLeaseToken(acquireA.lease!!.ownerId, acquireA.lease!!.epoch)

        val created = port.createScheduledRoundWithCommitment(tenantId, gameId, roundId, properties, tokenA)
        assertEquals(GameRoundPhase.SCHEDULED, created.first.phase)

        sleepDatabase(200)

        val acquireB = leaseStore.acquireOrRenew(tenantId, gameId, "node-B", 200L)
        assertEquals(LifecycleLeaseAcquireStatus.ACQUIRED, acquireB.status)
        val tokenB = LifecycleLeaseToken(acquireB.lease!!.ownerId, acquireB.lease!!.epoch)
        assertTrue(tokenB.epoch > tokenA.epoch, "takeover must advance the epoch (${tokenA.epoch} -> ${tokenB.epoch})")

        val acquireCommand = CreateOrUpdateRoundCommand(
            tenantId = tenantId,
            gameId = gameId,
            roundId = roundId,
            phase = GameRoundPhase.BET_COUNTDOWN,
            roundVersion = 2L,
            currentMultiplier = BigDecimal("1.0000"),
            crashMultiplier = null,
            expectedVersion = 1L,
        )

        val eventsBeforeStaleWrites = eventJournalStore.findEventsForRound(tenantId, gameId, roundId).size

        val persistFailure = assertThrows<LifecycleNotOwnerException> {
            port.persistRound(acquireCommand, tokenA)
        }
        assertEquals(LifecycleNotOwnerReason.LEASE_EXPIRED_OR_SUPERSEDED, persistFailure.reason)
        assertThrows<LifecycleNotOwnerException> {
            port.settleCrash(tenantId, gameId, roundId, BigDecimal("1.1000"), tokenA)
        }
        assertThrows<LifecycleNotOwnerException> {
            port.publishState(created.first, 0.0, tokenA)
        }
        assertThrows<LifecycleNotOwnerException> {
            port.revealIfNeeded(tenantId, gameId, roundId, BigDecimal("1.1000"), tokenA)
        }
        assertThrows<LifecycleNotOwnerException> {
            port.createScheduledRoundWithCommitment(tenantId, gameId, "rnd-tc019-fence-stale", properties, tokenA)
        }
        assertThrows<LifecycleNotOwnerException> {
            port.deriveOutcome(tenantId, gameId, roundId, tokenA)
        }

        val afterStaleWrites = gameStore.findRound(tenantId, gameId, roundId)
        assertNotNull(afterStaleWrites)
        assertEquals(GameRoundPhase.SCHEDULED, afterStaleWrites.phase, "stale owner writes must affect zero rows")
        assertEquals(1L, afterStaleWrites.roundVersion, "stale owner writes must not advance the round version")
        assertEquals(1, roundsCreated(), "stale owner must not create additional rounds")
        assertEquals(
            eventsBeforeStaleWrites,
            eventJournalStore.findEventsForRound(tenantId, gameId, roundId).size,
            "stale owner must not publish events",
        )
        assertTrue(
            fairnessStore.findReveal(tenantId, gameId, roundId) == null,
            "stale owner must not reveal the fairness outcome",
        )
        val commitmentAfterStaleDerive = fairnessStore.findCommitment(tenantId, gameId, roundId)
        assertNotNull(commitmentAfterStaleDerive)
        assertTrue(
            commitmentAfterStaleDerive.clientSeed1 == null &&
                commitmentAfterStaleDerive.clientSeed2 == null &&
                commitmentAfterStaleDerive.clientSeed3 == null,
            "stale owner deriveOutcome must not persist client seeds through commitment CAS",
        )
        assertEquals(1L, commitmentAfterStaleDerive.serverVersion, "stale deriveOutcome must not mutate commitment server version")

        val resumed = port.persistRound(acquireCommand, tokenB)
        assertEquals(GameRoundPhase.BET_COUNTDOWN, resumed.phase, "takeover owner must resume durable state")
        assertEquals(2L, resumed.roundVersion)

        val settled = port.settleCrash(tenantId, gameId, roundId, BigDecimal("1.1000"), tokenB)
        assertEquals(GameRoundPhase.CRASHED, settled.phase)
        val crashEvents = eventJournalStore.findEventsForRound(tenantId, gameId, roundId)
            .count { it.eventName == "gameState" && it.payloadJson.contains("CRASHED") }

        sleepDatabase(250)
        val renewalLossOrchestrator = orchestrator(ttlMillis = 100L)
        val tokenBeforeLoss = leaseStore.acquireOrRenew(tenantId, gameId, renewalLossOrchestrator.ownerId, 100L)
        assertEquals(LifecycleLeaseAcquireStatus.ACQUIRED, tokenBeforeLoss.status)
        sleepDatabase(200)
        val takeover = leaseStore.acquireOrRenew(tenantId, gameId, "node-C", 60_000L)
        assertEquals(LifecycleLeaseAcquireStatus.ACQUIRED, takeover.status)
        val before = gameStore.findRound(tenantId, gameId, roundId)!!.roundVersion
        val blocked = renewalLossOrchestrator.tick(tenantId, gameId)
        assertEquals(before, blocked.roundVersion, "renewal loss must halt the stale owner immediately")
        assertTrue(
            renewalLossOrchestrator.diagnostics(tenantId).notOwnerOutcomes > 0L,
            "renewal loss must be recorded as a not-owner outcome",
        )

        val nodeCLease = leaseStore.getLease(tenantId, gameId)
        assertNotNull(nodeCLease)
        assertEquals("node-C", nodeCLease.ownerId, "takeover owner must retain the lease")
        assertTrue(crashEvents <= 1, "the crash transition must be published at most once, saw $crashEvents")

        val validDiagnostics = renewalLossOrchestrator.diagnostics(tenantId)
        assertEquals(false, validDiagnostics.holdsLease, "diagnostics must report holdsLease=false after takeover by another owner")

        val expiredTenant = "tenant-tc019-diag-expired"
        val expiredOwnerOrchestrator = orchestrator(ttlMillis = 100L)
        expiredOwnerOrchestrator.tick(expiredTenant, gameId)
        assertTrue(expiredOwnerOrchestrator.diagnostics(expiredTenant).holdsLease, "diagnostics must report holdsLease=true while lease is valid")
        sleepDatabase(200)
        assertEquals(
            false,
            expiredOwnerOrchestrator.diagnostics(expiredTenant).holdsLease,
            "diagnostics must not report holdsLease=true when lease has expired even if owner/epoch on row still match",
        )
        jdbc.update("delete from game_fairness_commitment where tenant_id = ?", expiredTenant)
        jdbc.update("delete from game_authoritative_round where tenant_id = ?", expiredTenant)
        jdbc.update("delete from game_lifecycle_lease where tenant_id = ?", expiredTenant)
    }

    @Test
    fun GivenSimultaneousCreation_WhenUniqueIndexArbitrates_ThenLoserIsNotOwner() {
        val alpha = orchestrator(ttlMillis = 60_000L)
        val beta = orchestrator(ttlMillis = 60_000L)
        val notOwnerReasons = ConcurrentLinkedQueue<String>()

        for (iteration in 0 until 100) {
            jdbc.update("delete from game_lifecycle_lease where tenant_id = ?", tenantId)
            jdbc.update("delete from game_fairness_reveal where tenant_id = ?", tenantId)
            jdbc.update("delete from game_fairness_audit where tenant_id = ?", tenantId)
            jdbc.update("delete from game_fairness_commitment where tenant_id = ?", tenantId)
            jdbc.update("delete from game_authoritative_round where tenant_id = ?", tenantId)

            val pool = Executors.newFixedThreadPool(2)
            val latch = CountDownLatch(1)
            val futures = listOf(alpha, beta).map { instance ->
                pool.submit {
                    latch.await(5, TimeUnit.SECONDS)
                    instance.tick(tenantId, gameId)
                }
            }
            latch.countDown()
            futures.forEach { it.get(20, TimeUnit.SECONDS) }
            pool.shutdown()
            pool.awaitTermination(5, TimeUnit.SECONDS)

            assertEquals(1, roundsCreated(), "iteration $iteration must create exactly one round")
            assertEquals(1, activeRoundCount(), "iteration $iteration must keep exactly one active round")

            val diagnostics = listOf(alpha, beta).map { it.diagnostics(tenantId) }
            val loser = diagnostics.firstOrNull { it.notOwnerOutcomes > 0L }
            assertNotNull(loser, "iteration $iteration: one instance must record a not-owner outcome")
            assertTrue(
                diagnostics.any { it.holdsLease && it.ownerId != null && it.epoch != null },
                "iteration $iteration: the winning instance must expose owner and epoch",
            )
            notOwnerReasons.add("iteration-$iteration")
        }

        assertTrue(notOwnerReasons.size == 100, "every iteration must produce a not-owner observation")
    }

    @Test
    fun GivenMixedOperations_WhenLockRanksObserved_ThenRankOrderIsPreserved() {
        val trace: MutableList<Pair<String, Int>> = mutableListOf()
        val tracingLeaseStore = object : GameLifecycleLeaseStore by leaseStore {
            override fun lockAndVerify(
                tenantId: String,
                gameId: String,
                ownerId: String,
                epoch: Long,
            ): GameLifecycleLeaseRecord? {
                trace.add("LEASE" to 0)
                return leaseStore.lockAndVerify(tenantId, gameId, ownerId, epoch)
            }

            override fun acquireOrRenew(
                tenantId: String,
                gameId: String,
                ownerId: String,
                ttlMillis: Long,
                expectedEpoch: Long?,
            ): LifecycleLeaseAcquireResult {
                trace.add("LEASE_ACQUIRE" to 0)
                return leaseStore.acquireOrRenew(tenantId, gameId, ownerId, ttlMillis, expectedEpoch)
            }
        }

        val tracingGameStore = LockRankTracingStore(gameStore, trace)
        val tracingLedgerStore = LedgerRankTracingStore(ledgerStore, trace)

        val tracingGameService = DurableGameWagerAndSettlementService(
            store = tracingGameStore,
            ledgerService = LedgerPostingService(store = tracingLedgerStore, clock = clock),
            registrationStore = registrationStore,
            eligibilityStore = eligibilityStore,
            adminPrincipal = adminPrincipal,
            clock = clock,
            txManager = txManager,
        )
        val tracingSnapshotService = AuthoritativeGameSnapshotAndEventService(
            gameStore = tracingGameStore,
            gameService = tracingGameService,
            walletService = AuthoritativeWalletService(
                store = InMemoryAuthoritativeWalletStore(ledgerStore = tracingLedgerStore, clock = clock),
                clock = clock,
            ),
            ledgerStore = tracingLedgerStore,
            fairnessStore = fairnessStore,
            eventJournalStore = eventJournalStore,
            registrationStore = registrationStore,
            clock = clock,
        )
        val tracingPort = ProductionAviatorLifecyclePort(
            gameService = tracingGameService,
            fairnessAuthority = fairnessAuthority,
            snapshotService = tracingSnapshotService,
            txManager = txManager,
            leaseStore = tracingLeaseStore,
            clock = clock,
        )
        val tracingOrchestrator = AviatorRoundLifecycleOrchestrator(
            tracingPort,
            properties,
            clock,
            tracingLeaseStore,
            60_000L,
        )

        seedFunds(500_000L)

        for (iteration in 0 until 100) {
            jdbc.update("delete from game_bet_settlement where tenant_id = ?", tenantId)
            jdbc.update("delete from game_accepted_bet where tenant_id = ?", tenantId)
            jdbc.update("delete from game_command_receipt where tenant_id = ?", tenantId)
            jdbc.update("delete from game_fairness_reveal where tenant_id = ?", tenantId)
            jdbc.update("delete from game_fairness_audit where tenant_id = ?", tenantId)
            jdbc.update("delete from game_fairness_commitment where tenant_id = ?", tenantId)
            jdbc.update("delete from game_authoritative_round where tenant_id = ?", tenantId)
            jdbc.update("delete from game_lifecycle_lease where tenant_id = ?", tenantId)
            jdbc.update("delete from game_command_sequence where tenant_id = ?", tenantId)

            trace.clear()

            val scheduled = tracingOrchestrator.ensureRunning(tenantId, gameId)
            clock.advanceMillis(20)
            tracingOrchestrator.tick(tenantId, gameId)
            val leaseEntriesAfterSetup = trace.count { it.first.startsWith("LEASE") }
            val commandTrace = mutableListOf<Pair<String, Int>>()
            val commandTracingGameStore = LockRankTracingStore(gameStore, commandTrace)
            val commandTracingLedgerStore = LedgerRankTracingStore(ledgerStore, commandTrace)
            val commandTracingGameService = DurableGameWagerAndSettlementService(
                store = commandTracingGameStore,
                ledgerService = LedgerPostingService(store = commandTracingLedgerStore, clock = clock),
                registrationStore = registrationStore,
                eligibilityStore = eligibilityStore,
                adminPrincipal = adminPrincipal,
                clock = clock,
                txManager = txManager,
            )
            val commandAck = commandTracingGameService.processCommand(
                AviatorRestCommand(
                    tenantId = tenantId,
                    principal = playerPrincipal,
                    commandId = "cmd-tc019-$iteration",
                    roundId = scheduled.roundId,
                    handId = "hand_primary",
                    action = "PLACE_BET",
                    wagerMinor = 101L,
                    currency = currency,
                    correlationId = "corr-tc019-$iteration",
                )
            )
            assertEquals(AviatorCommandAckStatus.ACCEPTED, commandAck.status, "iteration $iteration")

            assertTrue(trace.any { it.first == "LEASE_ACQUIRE" }, "iteration $iteration lifecycle must acquire the lease")
            assertTrue(trace.any { it.first == "LEASE" }, "iteration $iteration fenced write must verify the lease")
            assertTrue(commandTrace.any { it.first == "ROUND_EXCLUSIVE" || it.first == "ROUND_SHARED" }, "iteration $iteration round lock")
            assertTrue(commandTrace.any { it.first == "RECEIPT" }, "iteration $iteration command must claim the receipt")
            assertTrue(commandTrace.any { it.first == "BET" }, "iteration $iteration bet row must be locked")
            assertTrue(commandTrace.any { it.first == "PLAYER_ACCOUNT" }, "iteration $iteration player account must be locked")
            assertTrue(commandTrace.any { it.first == "SEQUENCE_COUNTER" }, "iteration $iteration sequence counter must be locked")

            val leaseRanks = trace.filter { it.first.startsWith("LEASE") }.map { it.second }
            assertTrue(leaseRanks.all { it == 0 }, "iteration $iteration lease must hold the outermost rank")

            val combinedTrace = trace + commandTrace
            assertTrue(
                combinedTrace.indexOfFirst { it.first.startsWith("LEASE") } <
                    combinedTrace.indexOfFirst { it.first == "ROUND_EXCLUSIVE" || it.first == "ROUND_SHARED" },
                "iteration $iteration lease verification must precede the round lock",
            )

            assertTrue(
                commandTrace.none { it.first.startsWith("LEASE") },
                "iteration $iteration bet commands must never take the lifecycle lease",
            )

            var previous = 0
            for ((resource, rank) in commandTrace) {
                assertTrue(rank >= previous, "iteration $iteration command lock rank inversion at $resource($rank) after $previous")
                previous = rank
            }
        }
    }

    @Test
    fun GivenHistoricalMoneyAndOutcomeVectors_WhenRefactoredPathRuns_ThenSemanticsStayUnchanged() {
        assertEquals(BigDecimal("2.66"), IndependentFairnessVerifier.calculateCrashMultiplier("0".repeat(64), "seed-a", "seed-b", "seed-c"))
        assertEquals(BigDecimal("2.90"), IndependentFairnessVerifier.calculateCrashMultiplier("a".repeat(64), "client-1", "client-2", "client-3"))
        assertEquals(BigDecimal("1.86"), IndependentFairnessVerifier.calculateCrashMultiplier("0123456789abcdef".repeat(4), "cs1", "cs2", "cs3"))

        val wagerMinor = 101L
        val multiplier = BigDecimal("1.2345")
        val expectedWinMinor = BigDecimal.valueOf(wagerMinor).multiply(multiplier).setScale(0, RoundingMode.FLOOR).longValueExact()
        assertEquals(124L, expectedWinMinor)

        val startingBalance = 50_000L
        seedFunds(startingBalance)

        val cashOutRound = "rnd-tc019-golden-cashout"
        insertRound(cashOutRound, "BET_COUNTDOWN")
        fairnessAuthority.publishPreBetCommitment(
            PublishCommitmentCommand(
                tenantId = tenantId,
                gameId = gameId,
                roundId = cashOutRound,
                publicSalt = "salt-$cashOutRound",
            ),
        )
        assertEquals(AviatorCommandAckStatus.ACCEPTED, gameService.processCommand(placeBetCommand(cashOutRound, "cmd-tc019-golden-bet-1")).status)
        assertEquals(startingBalance - wagerMinor, ledgerStore.findBalance(tenantId, "PLAYER:$playerIdStr", currency))
        assertEquals(wagerMinor, ledgerStore.findBalance(tenantId, "ESCROW:GAME:$gameId", currency))

        gameService.createOrUpdateRound(
            CreateOrUpdateRoundCommand(tenantId, gameId, cashOutRound, GameRoundPhase.FLYING, 2L, multiplier)
        )
        val cashOutAck = gameService.processCommand(
            AviatorRestCommand(
                tenantId = tenantId,
                principal = playerPrincipal,
                commandId = "cmd-tc019-golden-cashout-1",
                roundId = cashOutRound,
                handId = "hand_primary",
                action = "CASH_OUT",
                currency = currency,
                correlationId = "corr-tc019-golden-cashout-1",
            )
        )
        assertEquals(AviatorCommandAckStatus.ACCEPTED, cashOutAck.status)
        assertEquals(expectedWinMinor, cashOutAck.result?.payoutMinor)
        assertEquals(startingBalance - wagerMinor + expectedWinMinor, ledgerStore.findBalance(tenantId, "PLAYER:$playerIdStr", currency))
        assertEquals(0L, ledgerStore.findBalance(tenantId, "ESCROW:GAME:$gameId", currency))

        val lossRound = "rnd-tc019-golden-loss"
        closeActiveRoundsFor(jdbc, tenantId, gameId)
        insertRound(lossRound, "BET_COUNTDOWN")
        fairnessAuthority.publishPreBetCommitment(
            PublishCommitmentCommand(
                tenantId = tenantId,
                gameId = gameId,
                roundId = lossRound,
                publicSalt = "salt-$lossRound",
            ),
        )
        assertEquals(AviatorCommandAckStatus.ACCEPTED, gameService.processCommand(placeBetCommand(lossRound, "cmd-tc019-golden-bet-2")).status)
        val crashResult = gameService.settleRoundCrash(settleCommand(lossRound))
        assertEquals(1, crashResult.settledBetsCount)
        assertEquals(
            0L,
            jdbc.queryForObject(
                "select payout_minor_units from game_bet_settlement where tenant_id = ? and outcome = 'LOSS_CRASH'",
                Long::class.java,
                tenantId,
            ),
        )

        assertJournalBalanced()
        assertEquals(
            2,
            jdbc.queryForObject("select count(*) from game_bet_settlement where tenant_id = ?", Int::class.java, tenantId) ?: 0,
            "each bet must have exactly one terminal settlement",
        )
        assertEquals(0L, ledgerStore.findBalance(tenantId, "ESCROW:GAME:$gameId", currency))
    }

    private fun insertRound(roundId: String, phase: String = "SCHEDULED") {
        closeActiveRoundsFor(jdbc, tenantId, gameId, keepRoundId = roundId)
        jdbc.update(
            """
            insert into game_authoritative_round (
                round_id, tenant_id, game_id, phase, round_version,
                current_multiplier, started_at, server_time, created_at, updated_at
            ) values (?, ?, ?, ?, 1, 1.0000, ?, ?, ?, ?)
            on conflict (tenant_id, game_id, round_id) do nothing
            """.trimIndent(),
            roundId,
            tenantId,
            gameId,
            phase,
            Timestamp.from(now),
            Timestamp.from(now),
            Timestamp.from(now),
            Timestamp.from(now),
        )
    }

    private fun seedFunds(amount: Long) {
        ledgerService.postTransaction(
            PostTransactionCommand(
                principal = adminPrincipal,
                tenantId = tenantId,
                transactionReference = "TX-TC019-SEED-${UUID.randomUUID()}",
                currencyCode = currency,
                entries = listOf(
                    JournalEntryDraft("HOUSE:SEED", JournalEntryDirection.DEBIT, amount, currency),
                    JournalEntryDraft("PLAYER:$playerIdStr", JournalEntryDirection.CREDIT, amount, currency),
                ),
                idempotencyKey = "IDEM-TC019-SEED-${UUID.randomUUID()}",
                correlationId = "corr-tc019-seed",
                causationId = "caus-tc019-seed",
            )
        )
    }

    private fun placeBetCommand(roundId: String, commandId: String) = AviatorRestCommand(
        tenantId = tenantId,
        principal = playerPrincipal,
        commandId = commandId,
        roundId = roundId,
        handId = "hand_primary",
        action = "PLACE_BET",
        wagerMinor = 101L,
        currency = currency,
        correlationId = "corr-$commandId",
    )

    private fun assertJournalBalanced() {
        val debits = jdbc.queryForObject("select coalesce(sum(total_debits_minor_units), 0) from ledger_transaction where tenant_id = ?", Long::class.java, tenantId) ?: 0L
        val credits = jdbc.queryForObject("select coalesce(sum(total_credits_minor_units), 0) from ledger_transaction where tenant_id = ?", Long::class.java, tenantId) ?: 0L
        assertEquals(debits, credits, "Double-entry journal must stay balanced")
    }

    private class LockRankTracingStore(
        private val delegate: DurableGameWagerAndSettlementStore,
        val eventLog: MutableList<Pair<String, Int>>,
    ) : DurableGameWagerAndSettlementStore by delegate {
        override fun claimReceipt(claim: GameCommandReceiptClaim): CommandReceiptClaimResult {
            eventLog.add("RECEIPT" to 1)
            return delegate.claimReceipt(claim)
        }

        override fun findRoundForShare(tenantId: String, gameId: String, roundId: String): GameRoundRecord? {
            eventLog.add("ROUND_SHARED" to 2)
            return delegate.findRoundForShare(tenantId, gameId, roundId)
        }

        override fun findRoundForUpdate(tenantId: String, gameId: String, roundId: String): GameRoundRecord? {
            eventLog.add("ROUND_EXCLUSIVE" to 2)
            return delegate.findRoundForUpdate(tenantId, gameId, roundId)
        }

        override fun findBet(tenantId: String, gameId: String, roundId: String, ownerId: String, handId: String): GameAcceptedBetRecord? {
            eventLog.add("BET" to 3)
            return delegate.findBet(tenantId, gameId, roundId, ownerId, handId)
        }

        override fun findBetsForRoundForUpdate(tenantId: String, gameId: String, roundId: String): List<GameAcceptedBetRecord> {
            eventLog.add("BETS" to 3)
            return delegate.findBetsForRoundForUpdate(tenantId, gameId, roundId)
        }

        override fun nextSequenceId(tenantId: String): Long {
            val sequence = delegate.nextSequenceId(tenantId)
            eventLog.add("SEQUENCE_COUNTER" to 5)
            return sequence
        }
    }

    private class LedgerRankTracingStore(
        private val delegate: LedgerJournalStore,
        val eventLog: MutableList<Pair<String, Int>>,
    ) : LedgerJournalStore by delegate {
        override fun lockAccount(tenantId: String, accountReference: String, currencyCode: String): Boolean {
            eventLog.add("PLAYER_ACCOUNT" to 4)
            return delegate.lockAccount(tenantId, accountReference, currencyCode)
        }
    }

    private class MutableClock(private var now: Instant) : Clock() {
        override fun getZone(): ZoneId = ZoneOffset.UTC
        override fun withZone(zone: ZoneId): Clock = this
        override fun instant(): Instant = now
        fun advanceMillis(millis: Long) {
            now = now.plusMillis(millis)
        }
    }
}
