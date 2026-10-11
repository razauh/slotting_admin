package com.slotting.admin.gameprovider

import com.slotting.admin.auth.AdminRole
import com.slotting.admin.auth.AuthenticatedPrincipal
import com.slotting.admin.auth.PrincipalKind
import com.slotting.admin.identity.InMemoryPlayerRegistrationStore
import com.slotting.admin.identity.InMemoryServerEligibilityStore
import com.slotting.admin.ledger.InMemoryLedgerJournalStore
import com.slotting.admin.ledger.LedgerPostingService
import com.slotting.admin.wallet.AuthoritativeWalletService
import com.slotting.admin.wallet.InMemoryAuthoritativeWalletStore
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test
import org.springframework.transaction.support.TransactionSynchronizationManager
import java.math.BigDecimal
import java.time.Clock
import java.time.Instant
import java.time.ZoneOffset
import java.util.concurrent.Executors
import kotlin.test.assertEquals
import kotlin.test.assertTrue

class AviatorEventDeliveryRecoveryTest {
    private val now = Instant.parse("2026-10-11T00:00:00Z")
    private val clock = Clock.fixed(now, ZoneOffset.UTC)
    private val tenantId = "tenant-tc024"
    private val gameId = "AVIATOR"
    private lateinit var gameStore: CountingGameStore
    private lateinit var eventStore: InMemoryGameEventJournalStore
    private lateinit var service: AuthoritativeGameSnapshotAndEventService
    private lateinit var gameService: DurableGameWagerAndSettlementService
    private lateinit var ledgerStore: InMemoryLedgerJournalStore
    private lateinit var walletService: AuthoritativeWalletService
    private lateinit var registrationStore: InMemoryPlayerRegistrationStore

    @BeforeEach
    fun setUp() {
        ledgerStore = InMemoryLedgerJournalStore()
        val ledgerService = LedgerPostingService(ledgerStore, clock)
        walletService = AuthoritativeWalletService(
            store = InMemoryAuthoritativeWalletStore(ledgerStore, clock),
            clock = clock,
        )
        registrationStore = InMemoryPlayerRegistrationStore()
        gameStore = CountingGameStore()
        gameService = DurableGameWagerAndSettlementService(
            store = gameStore,
            ledgerService = ledgerService,
            registrationStore = registrationStore,
            eligibilityStore = InMemoryServerEligibilityStore(),
            adminPrincipal = AuthenticatedPrincipal(
                id = "admin-tc024",
                tenantId = tenantId,
                kind = PrincipalKind.ADMIN,
                roles = setOf(AdminRole.SUPER_ADMIN),
            ),
            clock = clock,
        )
        eventStore = InMemoryGameEventJournalStore()
        service = AuthoritativeGameSnapshotAndEventService(
            gameStore = gameStore,
            gameService = gameService,
            walletService = walletService,
            ledgerStore = ledgerStore,
            fairnessStore = InMemoryFairnessEvidenceStore(),
            eventJournalStore = eventStore,
            registrationStore = registrationStore,
            clock = clock,
        )
    }

    @Test
    fun givenRolledBackTransition_whenCallbackWouldBroadcast_thenNoSocketEvent() {
        val dispatched = mutableListOf<GameEventRecord>()
        val dispatchingService = serviceWithDispatcher { dispatched += it }
        TransactionSynchronizationManager.initSynchronization()
        dispatchingService.recordAndBroadcastGameState(
            tenantId, gameId, "round-tc024-rollback", GameRoundPhase.BET_COUNTDOWN,
            BigDecimal("1.0000"), 1L, 0.0,
        )
        assertTrue(TransactionSynchronizationManager.getSynchronizations().isNotEmpty())
        TransactionSynchronizationManager.clearSynchronization()
        assertTrue(dispatched.isEmpty())

        TransactionSynchronizationManager.initSynchronization()
        dispatchingService.recordAndBroadcastGameState(
            tenantId, gameId, "round-tc024-commit", GameRoundPhase.BET_COUNTDOWN,
            BigDecimal("1.0000"), 1L, 0.0,
        )
        TransactionSynchronizationManager.getSynchronizations().forEach { it.afterCommit() }
        TransactionSynchronizationManager.clearSynchronization()
        assertEquals(1, dispatched.size)
    }

    @Test
    fun givenBroadcastTimeout_whenClientReconnects_thenJournalRestoresState() {
        val dispatchingService = serviceWithDispatcher { error("socket unavailable") }
        val event = dispatchingService.recordAndBroadcastGameState(
            tenantId, gameId, "round-tc024-replay", GameRoundPhase.FLYING,
            BigDecimal("2.0000"), 1L, 3.0,
        )
        val resumed = service.resumeEvents(tenantId, gameId, 0L)
        assertEquals(event, (resumed as SocketResumeOutcome.EventsReplayed).events.single())
        assertEquals(1L, service.getAuthoritativeSnapshotForOwner(
            tenantId,
            AuthenticatedPrincipal("admin-tc024", tenantId, PrincipalKind.ADMIN, roles = setOf(AdminRole.SUPER_ADMIN)),
            "admin-tc024",
            gameId,
            "round-tc024-replay",
        ).sequenceId)
    }

    @Test
    fun givenMissingLatestEvent_whenStartupAndTakeoverRace_thenRepairOnce() {
        val recovery = AviatorEventDeliveryRecovery(gameStore, eventStore, service, clock = clock)
        val executor = Executors.newFixedThreadPool(8)
        repeat(100) { index ->
            val currentTenant = "$tenantId-$index"
            gameStore.insertRound(round(currentTenant, "round-$index"))
            val results = (0 until 2).map {
                executor.submit<GameEventRecord?> { recovery.repairLatest(currentTenant, gameId) }
            }.map { it.get() }
            assertEquals(1, eventStore.findEventsForRound(currentTenant, gameId, "round-$index").size)
            assertEquals(1, results.filterNotNull().distinctBy { it.eventId }.size)
        }
        executor.shutdown()
        assertEquals(0, gameStore.updateCount)
    }

    private fun serviceWithDispatcher(dispatcher: (GameEventRecord) -> Unit): AuthoritativeGameSnapshotAndEventService =
        AuthoritativeGameSnapshotAndEventService(
            gameStore = gameStore,
            gameService = gameService,
            walletService = walletService,
            ledgerStore = ledgerStore,
            fairnessStore = InMemoryFairnessEvidenceStore(),
            eventJournalStore = eventStore,
            registrationStore = InMemoryPlayerRegistrationStore(),
            clock = clock,
            eventDispatcher = GameEventDispatcher(dispatcher),
        )

    private fun round(tenant: String, roundId: String): GameRoundRecord = GameRoundRecord(
        tenantId = tenant,
        gameId = gameId,
        roundId = roundId,
        phase = GameRoundPhase.FLYING,
        roundVersion = 7L,
        currentMultiplier = BigDecimal("2.0000"),
        startedAt = now,
        flyingAt = now,
        phaseStartedAt = now,
        serverTime = now,
        createdAt = now,
        updatedAt = now,
    )

    private class CountingGameStore : InMemoryDurableGameWagerAndSettlementStore() {
        var updateCount: Int = 0

        override fun updateRound(round: GameRoundRecord, expectedVersion: Long, allowedPriorPhases: Set<GameRoundPhase>) {
            updateCount += 1
            super.updateRound(round, expectedVersion, allowedPriorPhases)
        }
    }
}
