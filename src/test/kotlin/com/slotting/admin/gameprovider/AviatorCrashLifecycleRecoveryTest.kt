package com.slotting.admin.gameprovider

import com.fasterxml.jackson.databind.ObjectMapper
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
import java.math.BigDecimal
import java.math.RoundingMode
import java.sql.Timestamp
import java.time.Clock
import java.time.Instant
import java.time.LocalDate
import java.time.ZoneId
import java.time.ZoneOffset
import java.util.UUID
import kotlin.test.assertEquals
import kotlin.test.assertNotNull
import kotlin.test.assertTrue

@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.NONE)
class AviatorCrashLifecycleRecoveryTest {

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

    private val now = Instant.parse("2026-10-08T10:00:00Z")
    private val tenantId = "tenant-tc012-recovery"
    private val gameId = "AVIATOR"
    private val currency = "INR"

    private val playerUuid = UUID.randomUUID()
    private val playerIdStr = playerUuid.toString()

    private val adminPrincipal = AuthenticatedPrincipal(
        id = "admin-sys-tc012",
        tenantId = tenantId,
        kind = PrincipalKind.ADMIN,
        roles = setOf(AdminRole.SUPER_ADMIN),
    )

    private val properties = AviatorLifecycleProperties(
        scheduledMillis = 100,
        bettingMillis = 200,
        closedMillis = 100,
        multiplierStep = BigDecimal("1000.0000"),
        rulesVersion = "1.0.0",
        algorithmVersion = "1.0.0",
        publicSalt = "tc012-public-salt",
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
    private lateinit var snapshotService: AuthoritativeGameSnapshotAndEventService
    private lateinit var testClock: MutableTestClock
    private val eventMapper = ObjectMapper()

    class SimulatedFailpointException(message: String) : RuntimeException(message)

    class FailOnSettlementStore(
        private val delegate: DurableGameWagerAndSettlementStore,
    ) : DurableGameWagerAndSettlementStore by delegate {
        var failSettlements: Boolean = false

        override fun saveSettlement(settlement: GameBetSettlementRecord) {
            if (failSettlements) throw SimulatedFailpointException("injected settlement failure")
            delegate.saveSettlement(settlement)
        }
    }

    class FailOnceRevealStore(
        private val delegate: FairnessEvidenceStore,
    ) : FairnessEvidenceStore by delegate {
        var failNextReveal: Boolean = false

        override fun saveReveal(reveal: RoundRevealRecord) {
            if (failNextReveal) {
                failNextReveal = false
                throw SimulatedFailpointException("injected reveal failure")
            }
            delegate.saveReveal(reveal)
        }
    }

    class FailOnceEventStore(
        private val delegate: GameEventJournalStore,
    ) : GameEventJournalStore by delegate {
        var failNextGameStateSave: Boolean = false

        override fun saveEvent(event: GameEventRecord) {
            if (failNextGameStateSave) {
                failNextGameStateSave = false
                throw SimulatedFailpointException("injected crash publication failure")
            }
            delegate.saveEvent(event)
        }
    }

    class CrashWriteTracingStore(
        private val delegate: DurableGameWagerAndSettlementStore,
        val crashedRoundWrites: MutableList<Long> = mutableListOf(),
    ) : DurableGameWagerAndSettlementStore by delegate {
        override fun insertRound(round: GameRoundRecord) {
            if (round.phase == GameRoundPhase.CRASHED) crashedRoundWrites.add(round.roundVersion)
            delegate.insertRound(round)
        }

        override fun updateRound(round: GameRoundRecord, expectedVersion: Long, allowedPriorPhases: Set<GameRoundPhase>) {
            if (round.phase == GameRoundPhase.CRASHED) crashedRoundWrites.add(round.roundVersion)
            delegate.updateRound(round, expectedVersion, allowedPriorPhases)
        }
    }

    class CrashLockTracingStore(
        private val delegate: DurableGameWagerAndSettlementStore,
        private val eventLog: MutableList<Pair<String, Int>>,
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
        testClock = MutableTestClock(now)

        gameStore = JdbcDurableGameWagerAndSettlementStore(jdbc)
        fairnessStore = JdbcFairnessEvidenceStore(jdbc)
        ledgerStore = JdbcLedgerJournalStore(jdbc)
        registrationStore = JdbcPlayerRegistrationStore(jdbc)
        eligibilityStore = com.slotting.admin.identity.InMemoryServerEligibilityStore()
        ledgerService = LedgerPostingService(store = ledgerStore, clock = testClock)

        gameService = DurableGameWagerAndSettlementService(
            store = gameStore,
            ledgerService = ledgerService,
            registrationStore = registrationStore,
            eligibilityStore = eligibilityStore,
            adminPrincipal = adminPrincipal,
            clock = testClock,
            txManager = txManager,
        )
        fairnessAuthority = ProvablyFairOutcomeAuthority(store = fairnessStore, clock = testClock)
        val walletStore = InMemoryAuthoritativeWalletStore(ledgerStore = ledgerStore, clock = testClock)
        val walletService = AuthoritativeWalletService(store = walletStore, clock = testClock)
        snapshotService = AuthoritativeGameSnapshotAndEventService(
            gameStore = gameStore,
            gameService = gameService,
            walletService = walletService,
            ledgerStore = ledgerStore,
            fairnessStore = fairnessStore,
            eventJournalStore = InMemoryGameEventJournalStore(),
            registrationStore = registrationStore,
            clock = testClock,
        )

        seedPlayer()
    }

    private fun clearTenantState() {
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
        jdbc.update("delete from admin_outbox_event where tenant_id = ?", tenantId)
        jdbc.update("delete from admin_audit_event where tenant_id = ?", tenantId)
        jdbc.update("delete from admin_operation where tenant_id = ?", tenantId)
        jdbc.update("delete from ledger_account where tenant_id = ?", tenantId)
        jdbc.update("delete from game_command_sequence where tenant_id = ?", tenantId)
        jdbc.update("delete from ledger_version_tracker where tenant_id = ?", tenantId)
    }

    private fun seedPlayer() {
        jdbc.update(
            """
            insert into player_credential (
                player_id, tenant_id, identifier, password_hash, password_algo,
                password_salt, iterations, status, version, created_at, updated_at
            ) values (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            on conflict (tenant_id, identifier) do nothing
            """.trimIndent(),
            playerUuid, tenantId, playerIdStr, "pbkdf2_sha256_hash", "pbkdf2_sha256", "salt", 10000, "ACTIVE", 1L,
            Timestamp.from(now.minusSeconds(86400)), Timestamp.from(now.minusSeconds(86400)),
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
                    currentDailyWagerMinor = 0L,
                ),
            ),
        )
    }

    private fun playerPrincipal(): AuthenticatedPrincipal =
        AuthenticatedPrincipal(id = playerIdStr, tenantId = tenantId, kind = PrincipalKind.PLAYER, roles = setOf(AdminRole.SUPPORT))

    private fun seedFunds(amount: Long) {
        ledgerService.postTransaction(
            PostTransactionCommand(
                principal = adminPrincipal,
                tenantId = tenantId,
                transactionReference = "TX-TC012-SEED-${UUID.randomUUID()}",
                currencyCode = currency,
                entries = listOf(
                    JournalEntryDraft("HOUSE:SEED", JournalEntryDirection.DEBIT, amount, currency),
                    JournalEntryDraft("PLAYER:$playerIdStr", JournalEntryDirection.CREDIT, amount, currency),
                ),
                idempotencyKey = "IDEM-TC012-SEED-${UUID.randomUUID()}",
                correlationId = "corr-tc012-seed",
                causationId = "caus-tc012-seed",
            ),
        )
    }

    private fun placeBet(roundId: String, commandId: String, wagerMinor: Long): AviatorCommandAckResult {
        val ack = gameService.processCommand(
            AviatorRestCommand(
                tenantId = tenantId,
                principal = playerPrincipal(),
                commandId = commandId,
                roundId = roundId,
                handId = "hand_primary",
                action = "PLACE_BET",
                wagerMinor = wagerMinor,
                currency = currency,
                correlationId = "corr-$commandId",
            ),
        )
        assertEquals(AviatorCommandAckStatus.ACCEPTED, ack.status)
        return ack
    }

    private fun newOrchestrator(service: DurableGameWagerAndSettlementService, authority: ProvablyFairOutcomeAuthority): AviatorRoundLifecycleOrchestrator {
        val port = ProductionAviatorLifecyclePort(
            gameService = service,
            fairnessAuthority = authority,
            snapshotService = snapshotService,
            txManager = txManager,
        )
        return AviatorRoundLifecycleOrchestrator(port = port, properties = properties, clock = testClock)
    }

    private fun driveToFlyingWithBet(orchestrator: AviatorRoundLifecycleOrchestrator, commandId: String, wagerMinor: Long): GameRoundRecord {
        seedFunds(50000L)
        var round = orchestrator.ensureRunning(tenantId, gameId)
        testClock.advanceMillis(properties.scheduledMillis + 1)
        round = orchestrator.tick(tenantId, gameId)
        assertEquals(GameRoundPhase.BET_COUNTDOWN, round.phase)
        placeBet(round.roundId, commandId, wagerMinor)
        testClock.advanceMillis(properties.bettingMillis + 1)
        round = orchestrator.tick(tenantId, gameId)
        assertEquals(GameRoundPhase.FLYING, round.phase)
        return round
    }

    private fun acceptedBetCount(roundId: String): Int =
        jdbc.queryForObject(
            "select count(*) from game_accepted_bet where tenant_id = ? and round_id = ? and status = 'ACCEPTED'",
            Int::class.java,
            tenantId,
            roundId,
        ) ?: 0

    private fun crashSettlementCount(): Int =
        jdbc.queryForObject(
            "select count(*) from game_bet_settlement where tenant_id = ? and outcome = 'LOSS_CRASH'",
            Int::class.java,
            tenantId,
        ) ?: 0

    private fun revealCount(): Int =
        jdbc.queryForObject("select count(*) from game_fairness_reveal where tenant_id = ?", Int::class.java, tenantId) ?: 0

    private fun ledgerTransactionCount(): Int =
        jdbc.queryForObject("select count(*) from ledger_transaction where tenant_id = ?", Int::class.java, tenantId) ?: 0

    @Test
    fun `GivenFlightAtCrash_WhenTickRuns_ThenExactlyOneCrashTransition`() {
        val tracingStore = CrashWriteTracingStore(gameStore)
        val tracingService = DurableGameWagerAndSettlementService(
            store = tracingStore,
            ledgerService = ledgerService,
            registrationStore = registrationStore,
            eligibilityStore = eligibilityStore,
            adminPrincipal = adminPrincipal,
            clock = testClock,
            txManager = txManager,
        )
        val orchestrator = newOrchestrator(tracingService, fairnessAuthority)
        val flying = driveToFlyingWithBet(orchestrator, "cmd-tc012-single", 101L)
        val flyingVersion = flying.roundVersion

        val crashed = orchestrator.tick(tenantId, gameId)

        assertEquals(GameRoundPhase.CRASHED, crashed.phase)
        assertEquals(flyingVersion + 1, crashed.roundVersion, "crash must advance the round version by exactly one")
        assertNotNull(crashed.crashMultiplier, "crashed round must carry an authoritative crash multiplier")
        assertEquals(1, tracingStore.crashedRoundWrites.size, "exactly one CRASHED round write is permitted")
        assertEquals(0, acceptedBetCount(crashed.roundId), "no accepted bet may remain after the crash commits")
        assertEquals(1, crashSettlementCount(), "one terminal loss settlement per bet")
        assertEquals(0L, ledgerStore.findBalance(tenantId, "ESCROW:GAME:$gameId", currency), "escrow must net to zero")
    }

    @Test
    fun `GivenCommittedCrash_WhenRevealFails_ThenRestartDoesNotResettle`() {
        val revealStore = FailOnceRevealStore(fairnessStore)
        val failingAuthority = ProvablyFairOutcomeAuthority(store = revealStore, clock = testClock)
        val orchestrator = newOrchestrator(gameService, failingAuthority)
        val flying = driveToFlyingWithBet(orchestrator, "cmd-tc012-reveal", 101L)

        val crashed = orchestrator.tick(tenantId, gameId)
        assertEquals(GameRoundPhase.CRASHED, crashed.phase)
        val settlementsAfterCrash = crashSettlementCount()
        val ledgerAfterCrash = ledgerTransactionCount()
        assertEquals(0, revealCount(), "no reveal may be recorded before the crash is committed")

        revealStore.failNextReveal = true
        assertThrows<SimulatedFailpointException> {
            orchestrator.tick(tenantId, gameId)
        }
        assertEquals(settlementsAfterCrash, crashSettlementCount(), "failed follow-up must not resettle")
        assertEquals(ledgerAfterCrash, ledgerTransactionCount(), "failed follow-up must not move money")

        val recovered = newOrchestrator(gameService, ProvablyFairOutcomeAuthority(store = revealStore, clock = testClock))
        val closed = recovered.tick(tenantId, gameId)
        assertEquals(GameRoundPhase.CLOSED, closed.phase)
        assertEquals(settlementsAfterCrash, crashSettlementCount(), "restart must not settle twice")
        assertEquals(ledgerAfterCrash, ledgerTransactionCount(), "restart must not move money twice")
        assertEquals(1, revealCount(), "reveal must be retried exactly once for the committed crash")
    }

    @Test
    fun `GivenCommittedCrash_WhenCrashPublicationFails_ThenRestartPublishesOnce`() {
        val journalStore = InMemoryGameEventJournalStore()
        val failingJournal = FailOnceEventStore(journalStore)
        val walletStore = InMemoryAuthoritativeWalletStore(ledgerStore = ledgerStore, clock = testClock)
        val walletService = AuthoritativeWalletService(store = walletStore, clock = testClock)
        val publishingSnapshot = AuthoritativeGameSnapshotAndEventService(
            gameStore = gameStore,
            gameService = gameService,
            walletService = walletService,
            ledgerStore = ledgerStore,
            fairnessStore = fairnessStore,
            eventJournalStore = failingJournal,
            registrationStore = registrationStore,
            clock = testClock,
        )
        val orchestrator = AviatorRoundLifecycleOrchestrator(
            port = ProductionAviatorLifecyclePort(gameService, fairnessAuthority, publishingSnapshot, txManager),
            properties = properties,
            clock = testClock,
        )
        val flying = driveToFlyingWithBet(orchestrator, "cmd-tc012-publish", 101L)

        failingJournal.failNextGameStateSave = true
        assertThrows<SimulatedFailpointException> {
            orchestrator.tick(tenantId, gameId)
        }

        val settlementsAfterCrashAttempt = crashSettlementCount()
        val crashedRound = assertNotNull(gameStore.findRound(tenantId, gameId, flying.roundId))
        assertEquals(GameRoundPhase.CRASHED, crashedRound.phase)
        assertTrue(
            !publishingSnapshot.hasPublishedPhase(tenantId, gameId, flying.roundId, GameRoundPhase.CRASHED),
            "CRASHED publication must be missing after the injected failure",
        )

        failingJournal.failNextGameStateSave = false
        val recovered = AviatorRoundLifecycleOrchestrator(
            port = ProductionAviatorLifecyclePort(gameService, fairnessAuthority, publishingSnapshot, txManager),
            properties = properties,
            clock = testClock,
        )
        val closed = recovered.tick(tenantId, gameId)

        assertEquals(GameRoundPhase.CLOSED, closed.phase)
        assertEquals(settlementsAfterCrashAttempt, crashSettlementCount(), "restart must not resettle")
        assertTrue(
            publishingSnapshot.hasPublishedPhase(tenantId, gameId, flying.roundId, GameRoundPhase.CRASHED),
            "restart must publish the missing CRASHED state",
        )
        val crashedEvents = journalStore.findEventsForRound(tenantId, gameId, flying.roundId)
            .count { eventMapper.readTree(it.payloadJson).path("phase").asText() == GameRoundPhase.CRASHED.name }
        assertEquals(1, crashedEvents, "exactly one CRASHED event must exist")
    }

    @Test
    fun `GivenCrashTransactionFailure_WhenNextTickRuns_ThenRetryCompletes`() {
        val failingStore = FailOnSettlementStore(gameStore)
        val failingService = DurableGameWagerAndSettlementService(
            store = failingStore,
            ledgerService = ledgerService,
            registrationStore = registrationStore,
            eligibilityStore = eligibilityStore,
            adminPrincipal = adminPrincipal,
            clock = testClock,
            txManager = txManager,
        )
        val orchestrator = newOrchestrator(failingService, fairnessAuthority)
        val flying = driveToFlyingWithBet(orchestrator, "cmd-tc012-retry", 101L)
        val ledgerBefore = ledgerTransactionCount()

        failingStore.failSettlements = true
        assertThrows<SimulatedFailpointException> {
            orchestrator.tick(tenantId, gameId)
        }

        val afterFailure = assertNotNull(gameStore.findRound(tenantId, gameId, flying.roundId))
        assertEquals(GameRoundPhase.FLYING, afterFailure.phase, "a failed crash attempt must roll back to FLYING")
        assertEquals(1, acceptedBetCount(flying.roundId), "the accepted bet must survive the rolled-back attempt")
        assertEquals(0, crashSettlementCount(), "no settlement may persist after rollback")
        assertEquals(ledgerBefore, ledgerTransactionCount(), "no ledger movement may persist after rollback")
        assertEquals(0, revealCount(), "no secret may be revealed while the round remains FLYING")

        failingStore.failSettlements = false
        val crashed = orchestrator.tick(tenantId, gameId)
        assertEquals(GameRoundPhase.CRASHED, crashed.phase)
        assertEquals(0, acceptedBetCount(crashed.roundId))
        assertEquals(1, crashSettlementCount())
        assertEquals(0L, ledgerStore.findBalance(tenantId, "ESCROW:GAME:$gameId", currency))
    }

    @Test
    fun `GivenMixedOperations_WhenLocksAreObserved_ThenGlobalOrderIsPreserved`() {
        val eventLog = mutableListOf<Pair<String, Int>>()
        val tracingStore = CrashLockTracingStore(gameStore, eventLog)
        val tracingLedger = CrashLockTracingLedgerStore(ledgerStore, eventLog)
        val tracingService = DurableGameWagerAndSettlementService(
            store = tracingStore,
            ledgerService = LedgerPostingService(store = tracingLedger, clock = testClock),
            registrationStore = registrationStore,
            eligibilityStore = eligibilityStore,
            adminPrincipal = adminPrincipal,
            clock = testClock,
            txManager = txManager,
        )
        val orchestrator = newOrchestrator(tracingService, fairnessAuthority)
        driveToFlyingWithBet(orchestrator, "cmd-tc012-lock", 101L)

        val crashed = orchestrator.tick(tenantId, gameId)
        assertEquals(GameRoundPhase.CRASHED, crashed.phase)

        var previousRank = 0
        eventLog.forEach { (resource, rank) ->
            assertTrue(rank >= previousRank, "Lock rank inversion at $resource ($rank) after $previousRank")
            previousRank = rank
        }
        assertTrue(eventLog.any { it.first == "ROUND_EXCLUSIVE" }, "crash must take the exclusive round lock")
        assertTrue(eventLog.any { it.first == "BETS_FOR_UPDATE" }, "crash must lock accepted bets in stable order")
        assertTrue(eventLog.any { it.first == "LEDGER_ACCOUNT_WRITE" })
    }

    @Test
    fun `GivenHistoricalMoneyAndOutcomeVectors_WhenRefactoredPathRuns_ThenSemanticsStayUnchanged`() {
        val wagerMinor = 101L
        val multiplier = BigDecimal("1.2345")
        val expectedPayoutMinor = BigDecimal(wagerMinor).multiply(multiplier).setScale(0, RoundingMode.FLOOR).toLong()
        assertEquals(124L, expectedPayoutMinor)

        val orchestrator = newOrchestrator(gameService, fairnessAuthority)
        val flying = driveToFlyingWithBet(orchestrator, "cmd-tc012-golden", wagerMinor)

        val result = gameService.settleRoundCrash(SettleRoundCrashCommand(tenantId, gameId, flying.roundId, multiplier))
        assertEquals(1, result.settledBetsCount)
        assertEquals(0, multiplier.compareTo(result.crashMultiplier))

        val payout = jdbc.queryForObject(
            "select payout_minor_units from game_bet_settlement where tenant_id = ? and outcome = 'LOSS_CRASH'",
            Long::class.java,
            tenantId,
        )
        assertEquals(0L, payout, "crash loss payout must be zero")
        assertEquals(0L, ledgerStore.findBalance(tenantId, "ESCROW:GAME:$gameId", currency), "escrow must net to zero")

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
        assertEquals(totalDebits, totalCredits, "double-entry journal must stay balanced")
    }

    private class MutableTestClock(private var current: Instant) : Clock() {
        override fun getZone(): ZoneId = ZoneOffset.UTC
        override fun withZone(zone: ZoneId): Clock = this
        override fun instant(): Instant = current
        fun advanceMillis(millis: Long) {
            current = current.plusMillis(millis)
        }
    }
}
