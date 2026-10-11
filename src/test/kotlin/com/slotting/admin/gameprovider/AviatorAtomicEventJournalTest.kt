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
import java.math.BigDecimal
import java.time.Clock
import java.time.Instant
import java.time.ZoneOffset
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith

class AviatorAtomicEventJournalTest {

    private val now = Instant.parse("2026-10-11T00:00:00Z")
    private val clock = Clock.fixed(now, ZoneOffset.UTC)
    private val tenantId = "tenant-tc023"
    private val gameId = "AVIATOR"
    private val adminPrincipal = AuthenticatedPrincipal(
        id = "admin-tc023",
        tenantId = tenantId,
        kind = PrincipalKind.ADMIN,
        roles = setOf(AdminRole.SUPER_ADMIN),
    )

    private lateinit var gameStore: InMemoryDurableGameWagerAndSettlementStore
    private lateinit var eventStore: InMemoryGameEventJournalStore
    private lateinit var service: AuthoritativeGameSnapshotAndEventService

    @BeforeEach
    fun setUp() {
        val ledgerStore = InMemoryLedgerJournalStore()
        val ledgerService = LedgerPostingService(ledgerStore, clock)
        val walletService = AuthoritativeWalletService(
            store = InMemoryAuthoritativeWalletStore(ledgerStore, clock),
            clock = clock,
        )
        val registrationStore = InMemoryPlayerRegistrationStore()
        val eligibilityStore = InMemoryServerEligibilityStore()
        gameStore = InMemoryDurableGameWagerAndSettlementStore()
        val gameService = DurableGameWagerAndSettlementService(
            store = gameStore,
            ledgerService = ledgerService,
            registrationStore = registrationStore,
            eligibilityStore = eligibilityStore,
            adminPrincipal = adminPrincipal,
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
        gameService.createOrUpdateRound(
            CreateOrUpdateRoundCommand(
                tenantId = tenantId,
                gameId = gameId,
                roundId = "round-tc023",
                phase = GameRoundPhase.BET_COUNTDOWN,
                roundVersion = 1L,
            )
        )
    }

    @Test
    fun givenPersistedVersion_whenJournaledTwice_thenOneLogicalEvent() {
        val first = emit(BigDecimal("1.5000"), 2L)
        val replay = emit(BigDecimal("1.5000"), 2L)

        assertEquals(first.eventId, replay.eventId)
        assertEquals(first.sequenceId, replay.sequenceId)
        assertEquals(1, eventStore.findEventsForRound(tenantId, gameId, "round-tc023").size)
        assertEquals(2L, gameStore.findRound(tenantId, gameId, "round-tc023")?.roundVersion)

        assertFailsWith<GameEventIdentityConflictException> {
            emit(BigDecimal("1.6000"), 2L)
        }
        assertEquals(1, eventStore.findEventsForRound(tenantId, gameId, "round-tc023").size)
    }

    @Test
    fun givenEventBuild_whenPayloadCreated_thenRoundStateIsUsedWithoutInputMutation() {
        val event = emit(BigDecimal("1.7500"), 2L)
        val round = gameStore.findRound(tenantId, gameId, "round-tc023")

        assertEquals(2L, event.roundVersion)
        assertEquals(2L, round?.roundVersion)
        assertEquals(GameRoundPhase.FLYING, round?.phase)
        assertEquals(BigDecimal("1.7500"), round?.currentMultiplier)
    }

    private fun emit(multiplier: BigDecimal, version: Long): GameEventRecord =
        service.recordAndBroadcastGameState(
            tenantId = tenantId,
            gameId = gameId,
            roundId = "round-tc023",
            phase = GameRoundPhase.FLYING,
            multiplier = multiplier,
            roundVersion = version,
            elapsedFlightSeconds = 1.0,
        )
}
