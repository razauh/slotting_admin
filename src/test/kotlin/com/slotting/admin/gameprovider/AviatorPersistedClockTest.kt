package com.slotting.admin.gameprovider

import com.fasterxml.jackson.databind.ObjectMapper
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
import org.flywaydb.core.Flyway
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
import java.time.Duration
import java.time.Instant
import java.time.LocalDate
import java.time.ZoneId
import java.util.UUID
import java.util.concurrent.ConcurrentLinkedQueue
import java.util.concurrent.CountDownLatch
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit
import kotlin.test.assertEquals
import kotlin.test.assertNotNull
import kotlin.test.assertTrue

@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.NONE)
class AviatorPersistedClockTest {

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
    private val tenantId = "tenant-tc020-clock"
    private val gameId = "AVIATOR"
    private val currency = "INR"

    private val adminPrincipal = AuthenticatedPrincipal(
        id = "admin-sys-tc020",
        tenantId = tenantId,
        kind = PrincipalKind.ADMIN,
        roles = setOf(AdminRole.SUPER_ADMIN),
    )

    private val playerUuid = UUID.randomUUID()
    private val playerIdStr = playerUuid.toString()
    private val playerPrincipal = AuthenticatedPrincipal(
        id = playerIdStr,
        tenantId = tenantId,
        kind = PrincipalKind.PLAYER,
        roles = setOf(AdminRole.SUPPORT),
    )

    private val properties = AviatorLifecycleProperties(
        scheduledMillis = 100_000,
        bettingMillis = 100_000,
        closedMillis = 100_000,
        multiplierStep = BigDecimal("0.0500"),
        rulesVersion = "1.0.0",
        algorithmVersion = "1.0.0",
        publicSalt = "tc020-public-salt",
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
    private lateinit var walletService: AuthoritativeWalletService
    private lateinit var snapshotService: AuthoritativeGameSnapshotAndEventService
    private lateinit var eventJournalStore: JdbcGameEventJournalStore

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
        jdbc.update("delete from game_lifecycle_lease where tenant_id like ?", "tenant-tc020%")
        jdbc.update("delete from ledger_leg where tenant_id = ?", tenantId)
        jdbc.update("delete from ledger_idempotency_receipt where tenant_id = ?", tenantId)
        jdbc.update("delete from ledger_transaction where tenant_id = ?", tenantId)
        jdbc.update("delete from ledger_account where tenant_id = ?", tenantId)
        jdbc.update("delete from game_command_sequence where tenant_id = ?", tenantId)
        jdbc.update("delete from ledger_version_tracker where tenant_id = ?", tenantId)
        jdbc.update("delete from player_credential where tenant_id = ?", tenantId)

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
        walletService = AuthoritativeWalletService(
            store = InMemoryAuthoritativeWalletStore(ledgerStore, clock),
            clock = clock,
        )
        fairnessAuthority = ProvablyFairOutcomeAuthority(
            store = fairnessStore,
            clock = clock,
            envelope = FairnessSeedEnvelope.devDefault(),
            txManager = txManager,
        )
        eventJournalStore = JdbcGameEventJournalStore(jdbc)
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

        seedFunds(100_000L)
    }

    private fun seedFunds(amount: Long) {
        ledgerService.postTransaction(
            PostTransactionCommand(
                principal = adminPrincipal,
                tenantId = tenantId,
                transactionReference = "TX-TC020-SEED-${UUID.randomUUID()}",
                currencyCode = currency,
                entries = listOf(
                    JournalEntryDraft("HOUSE:SEED", JournalEntryDirection.DEBIT, amount, currency),
                    JournalEntryDraft("PLAYER:$playerIdStr", JournalEntryDirection.CREDIT, amount, currency),
                ),
                idempotencyKey = "IDEM-TC020-SEED-${UUID.randomUUID()}",
                correlationId = "corr-tc020-seed",
                causationId = "caus-tc020-seed",
            )
        )
    }

    private fun closeActiveRound(roundId: String) {
        val round = gameStore.findRound(tenantId, gameId, roundId)
        if (round != null && round.phase != GameRoundPhase.CLOSED) {
            round.phase = GameRoundPhase.CLOSED
            round.closedAt = clock.instant()
            gameStore.saveRound(round)
        }
    }

    @Test
    fun GivenFlightStartedTenSecondsAgo_WhenSnapshotAndEventBuilt_ThenBothReportTen() {
        val roundId = "rnd-tc020-elapsed"
        val createCmd = CreateOrUpdateRoundCommand(
            tenantId = tenantId,
            gameId = gameId,
            roundId = roundId,
            phase = GameRoundPhase.FLYING,
            roundVersion = 1L,
            currentMultiplier = BigDecimal("1.2500"),
            crashMultiplier = BigDecimal("2.0000"),
            flyingAt = clock.instant(),
            phaseStartedAt = clock.instant(),
        )
        gameService.createOrUpdateRound(createCmd)

        clock.advance(Duration.ofSeconds(10))

        val snapshot = snapshotService.getAuthoritativeSnapshotForOwner(
            tenantId = tenantId,
            principal = adminPrincipal,
            targetOwnerId = adminPrincipal.id,
            gameId = gameId,
            roundId = roundId,
        )
        assertEquals(10.0, snapshot.elapsedFlightSeconds, 0.001, "snapshot elapsedFlightSeconds must be 10.0")

        val event = snapshotService.recordAndBroadcastGameState(
            tenantId = tenantId,
            gameId = gameId,
            roundId = roundId,
            phase = GameRoundPhase.FLYING,
            multiplier = BigDecimal("1.2500"),
            roundVersion = 1L,
            elapsedFlightSeconds = 0.0,
        )
        val payload = ObjectMapper().findAndRegisterModules().readTree(event.payloadJson)
        assertEquals(10.0, payload.path("elapsedFlightSeconds").asDouble(), 0.001, "event elapsedFlightSeconds must be 10.0")

        closeActiveRound(roundId)

        val scheduledRoundId = "rnd-tc020-sched"
        gameService.createOrUpdateRound(
            CreateOrUpdateRoundCommand(
                tenantId = tenantId,
                gameId = gameId,
                roundId = scheduledRoundId,
                phase = GameRoundPhase.SCHEDULED,
                roundVersion = 1L,
            )
        )
        val schedSnapshot = snapshotService.getAuthoritativeSnapshotForOwner(
            tenantId = tenantId,
            principal = adminPrincipal,
            targetOwnerId = adminPrincipal.id,
            gameId = gameId,
            roundId = scheduledRoundId,
        )
        assertEquals(0.0, schedSnapshot.elapsedFlightSeconds, 0.001, "outside FLYING elapsedFlightSeconds must be 0.0")
        closeActiveRound(scheduledRoundId)
    }

    @Test
    fun GivenCountdownDeadline_WhenBetUpdatesRound_ThenDeadlineDoesNotMove() {
        val roundId = "rnd-tc020-deadline"
        val deadline = clock.instant().plusMillis(properties.bettingMillis)
        gameService.createOrUpdateRound(
            CreateOrUpdateRoundCommand(
                tenantId = tenantId,
                gameId = gameId,
                roundId = roundId,
                phase = GameRoundPhase.BET_COUNTDOWN,
                roundVersion = 1L,
                phaseDeadlineAt = deadline,
            )
        )
        val initialRound = gameStore.findRound(tenantId, gameId, roundId)
        assertNotNull(initialRound)
        val initialDeadlineMillis = initialRound.phaseDeadlineAt?.toEpochMilli() ?: 0L

        val betResult = gameService.processCommand(
            AviatorRestCommand(
                tenantId = tenantId,
                principal = playerPrincipal,
                commandId = UUID.randomUUID().toString(),
                causationId = UUID.randomUUID().toString(),
                roundId = roundId,
                handId = "hand_primary",
                action = "PLACE_BET",
                wagerMinor = 100,
                currency = currency,
                correlationId = UUID.randomUUID().toString(),
                clientSeed = "seed-1",
            )
        )
        assertEquals(AviatorCommandAckStatus.ACCEPTED, betResult.status)

        val updatedRound = gameStore.findRound(tenantId, gameId, roundId)
        assertNotNull(updatedRound)
        val updatedDeadlineMillis = updatedRound.phaseDeadlineAt?.toEpochMilli() ?: 0L
        assertEquals(initialDeadlineMillis.toDouble(), updatedDeadlineMillis.toDouble(), 1000.0)
        closeActiveRound(roundId)
    }

    @Test
    fun GivenRestartDuringFlight_WhenStageAResumes_ThenClockChangesButStepRuleDoesNot() {
        val roundId = "rnd-tc020-restart"
        gameService.createOrUpdateRound(
            CreateOrUpdateRoundCommand(
                tenantId = tenantId,
                gameId = gameId,
                roundId = roundId,
                phase = GameRoundPhase.FLYING,
                roundVersion = 1L,
                currentMultiplier = BigDecimal("1.0000"),
                crashMultiplier = BigDecimal("3.0000"),
                flyingAt = clock.instant(),
            )
        )
        clock.advance(Duration.ofSeconds(5))
        val event = snapshotService.recordAndBroadcastGameState(
            tenantId = tenantId,
            gameId = gameId,
            roundId = roundId,
            phase = GameRoundPhase.FLYING,
            multiplier = BigDecimal("1.0000"),
            roundVersion = 1L,
            elapsedFlightSeconds = 0.0,
        )
        val payload = ObjectMapper().findAndRegisterModules().readTree(event.payloadJson)
        assertEquals(5.0, payload.path("elapsedFlightSeconds").asDouble(), 0.001)
        closeActiveRound(roundId)
    }

    @Test
    fun GivenLockRanks_WhenInspected_ThenGlobalOrderMatchesSpec() {
        val lockRanks = listOf("receipt" to 0, "round" to 2, "bet" to 3, "player_account" to 4, "sequence_counter" to 5)
        var lastRank = -1
        for (entry in lockRanks) {
            assertTrue(entry.second >= lastRank)
            lastRank = entry.second
        }
    }

    @Test
    fun GivenWager_WhenPlacedAndClosed_ThenLedgerAndEscrowBalancesAreCorrect() {
        val roundId = "rnd-tc020-golden"
        gameService.createOrUpdateRound(
            CreateOrUpdateRoundCommand(
                tenantId = tenantId,
                gameId = gameId,
                roundId = roundId,
                phase = GameRoundPhase.BET_COUNTDOWN,
                roundVersion = 1L,
            )
        )
        val betResult = gameService.processCommand(
            AviatorRestCommand(
                tenantId = tenantId,
                principal = playerPrincipal,
                commandId = UUID.randomUUID().toString(),
                causationId = UUID.randomUUID().toString(),
                roundId = roundId,
                handId = "hand_primary",
                action = "PLACE_BET",
                wagerMinor = 101,
                currency = currency,
                correlationId = UUID.randomUUID().toString(),
                clientSeed = "golden",
            )
        )
        assertEquals(AviatorCommandAckStatus.ACCEPTED, betResult.status)
        val playerBalance = ledgerStore.findBalance(tenantId, "PLAYER:$playerIdStr", currency)
        assertEquals(100_000L - 101L, playerBalance)
        val escrowBalance = ledgerStore.findBalance(tenantId, "ESCROW:GAME:$gameId", currency)
        assertEquals(101L, escrowBalance)
        closeActiveRound(roundId)
    }

    @Test
    fun GivenExactAndNearDeadlineBoundaries_WhenEvaluated_ThenPredicateAndAdvancementBehaveConsistently() {
        val roundId = "rnd-tc020-boundary"
        val deadline = clock.instant().plusMillis(5000)
        val round = GameRoundRecord(
            tenantId = tenantId,
            gameId = gameId,
            roundId = roundId,
            phase = GameRoundPhase.BET_COUNTDOWN,
            roundVersion = 1L,
            currentMultiplier = BigDecimal("1.0000"),
            crashMultiplier = null,
            startedAt = clock.instant(),
            serverTime = clock.instant(),
            createdAt = clock.instant(),
            updatedAt = clock.instant(),
            phaseStartedAt = clock.instant(),
            phaseDeadlineAt = deadline,
        )

        clock.advance(Duration.ofMillis(4999))
        assertEquals(false, FlightClock.isPhaseDeadlinePassed(round, clock))

        clock.advance(Duration.ofMillis(1))
        assertEquals(true, FlightClock.isPhaseDeadlinePassed(round, clock))

        clock.advance(Duration.ofMillis(1))
        assertEquals(true, FlightClock.isPhaseDeadlinePassed(round, clock))
    }

    @Test
    fun GivenCountdownRoundWithUnrelatedUpdate_WhenExamined_ThenDeadlinePersistsAndDiagnosticsReportIt() {
        val roundId = "rnd-tc020-diag"
        val initialStart = clock.instant()
        val initialDeadline = initialStart.plusMillis(properties.bettingMillis)
        gameService.createOrUpdateRound(
            CreateOrUpdateRoundCommand(
                tenantId = tenantId,
                gameId = gameId,
                roundId = roundId,
                phase = GameRoundPhase.BET_COUNTDOWN,
                roundVersion = 1L,
                phaseStartedAt = initialStart,
                phaseDeadlineAt = initialDeadline,
            )
        )

        clock.advance(Duration.ofSeconds(2))
        val betResult = gameService.processCommand(
            AviatorRestCommand(
                tenantId = tenantId,
                principal = playerPrincipal,
                commandId = UUID.randomUUID().toString(),
                causationId = UUID.randomUUID().toString(),
                roundId = roundId,
                handId = "hand_primary",
                action = "PLACE_BET",
                wagerMinor = 50,
                currency = currency,
                correlationId = UUID.randomUUID().toString(),
                clientSeed = "seed-diag",
            )
        )
        assertEquals(AviatorCommandAckStatus.ACCEPTED, betResult.status)

        val updatedRound = gameStore.findRound(tenantId, gameId, roundId)
        assertNotNull(updatedRound)
        assertEquals(initialStart.toEpochMilli(), updatedRound.phaseStartedAt?.toEpochMilli())
        assertEquals(initialDeadline.toEpochMilli(), updatedRound.phaseDeadlineAt?.toEpochMilli())

        val orchestrator = AviatorRoundLifecycleOrchestrator(
            port = ProductionAviatorLifecyclePort(
                gameService = gameService,
                fairnessAuthority = fairnessAuthority,
                snapshotService = snapshotService,
                txManager = txManager,
                leaseStore = null,
                clock = clock,
            ),
            properties = properties,
            clock = clock,
            leaseStore = null,
        )
        val diag = orchestrator.diagnostics(tenantId)
        assertEquals(initialDeadline.toEpochMilli(), diag.nextExpectedTransitionAt?.toEpochMilli())

        closeActiveRound(roundId)
    }

    @Test
    fun GivenV45SchemaWithRepresentativeData_WhenMigratedToV46_ThenBlockedOrSucceeds() {
        val schema = "tc020_mig_${UUID.randomUUID().toString().replace("-", "").take(12)}"
        jdbc.execute("create schema $schema")
        try {
            val flywayV45 = Flyway.configure()
                .dataSource(jdbc.dataSource!!)
                .locations("classpath:db/migration")
                .schemas(schema)
                .defaultSchema(schema)
                .cleanDisabled(true)
                .target("45")
                .load()
            val res45 = flywayV45.migrate()
            assertTrue(res45.success)

            jdbc.update("insert into $schema.game_authoritative_round (round_id, tenant_id, game_id, phase, round_version, current_multiplier, created_at, updated_at) values ('rnd-conflict', 'tenant-mig', 'AVIATOR', 'SCHEDULED', 1, 1.0000, now(), now())")

            val flywayV46 = Flyway.configure()
                .dataSource(jdbc.dataSource!!)
                .locations("classpath:db/migration")
                .schemas(schema)
                .defaultSchema(schema)
                .cleanDisabled(true)
                .target("46")
                .load()

            val exMissing = assertThrows<org.flywaydb.core.api.FlywayException> {
                flywayV46.migrate()
            }
            assertTrue(exMissing.message!!.contains("rnd-conflict"))

            jdbc.update("delete from $schema.game_authoritative_round where round_id = 'rnd-conflict'")

            jdbc.update("""
                insert into $schema.game_authoritative_round (
                    round_id, tenant_id, game_id, phase, round_version, current_multiplier, created_at, updated_at
                ) values (
                    'rnd-non-flying-flying-at', 'tenant-mig', 'AVIATOR', 'BET_COUNTDOWN', 1, 1.0000, now(), now()
                )
            """.trimIndent())
            jdbc.update("alter table $schema.game_authoritative_round add column if not exists flying_at timestamptz null, add column if not exists phase_started_at timestamptz null, add column if not exists phase_deadline_at timestamptz null")
            jdbc.update("update $schema.game_authoritative_round set flying_at = now(), phase_started_at = now(), phase_deadline_at = now() + interval '5 seconds' where round_id = 'rnd-non-flying-flying-at'")

            val exNonFlying = assertThrows<org.flywaydb.core.api.FlywayException> {
                flywayV46.migrate()
            }
            assertTrue(exNonFlying.message!!.contains("rnd-non-flying-flying-at"))

            jdbc.update("delete from $schema.game_authoritative_round where round_id = 'rnd-non-flying-flying-at'")

            jdbc.update("""
                insert into $schema.game_authoritative_round (
                    round_id, tenant_id, game_id, phase, round_version, current_multiplier, created_at, updated_at,
                    phase_started_at, phase_deadline_at
                ) values (
                    'rnd-deadline-before-start', 'tenant-mig', 'AVIATOR', 'BET_COUNTDOWN', 1, 1.0000, now(), now(),
                    now(), now() - interval '1 second'
                )
            """.trimIndent())

            val exDeadline = assertThrows<org.flywaydb.core.api.FlywayException> {
                flywayV46.migrate()
            }
            assertTrue(exDeadline.message!!.contains("rnd-deadline-before-start"))

            jdbc.update("delete from $schema.game_authoritative_round where round_id = 'rnd-deadline-before-start'")

            jdbc.update("""
                insert into $schema.game_authoritative_round (
                    round_id, tenant_id, game_id, phase, round_version, current_multiplier, created_at, updated_at,
                    phase_started_at, flying_at
                ) values (
                    'rnd-flying-before-start', 'tenant-mig', 'AVIATOR', 'FLYING', 1, 1.0000, now(), now(),
                    now(), now() - interval '2 seconds'
                )
            """.trimIndent())

            val exFlyingBefore = assertThrows<org.flywaydb.core.api.FlywayException> {
                flywayV46.migrate()
            }
            assertTrue(exFlyingBefore.message!!.contains("rnd-flying-before-start"))

            jdbc.update("update $schema.game_authoritative_round set phase = 'CLOSED' where round_id = 'rnd-flying-before-start'")
            val res46 = flywayV46.migrate()
            assertTrue(res46.success)
        } finally {
            jdbc.execute("drop schema if exists $schema cascade")
        }
    }

    private class MutableClock(private var currentInstant: Instant) : Clock() {
        override fun getZone(): ZoneId = ZoneId.of("UTC")
        override fun withZone(zone: ZoneId): Clock = this
        override fun instant(): Instant = currentInstant
        fun advance(duration: Duration) {
            currentInstant = currentInstant.plus(duration)
        }
    }
}
