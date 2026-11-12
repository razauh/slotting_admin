package com.slotting.admin.gameprovider

import com.slotting.admin.auth.AdminRole
import com.slotting.admin.auth.AuthenticatedPrincipal
import com.slotting.admin.auth.PrincipalKind
import com.slotting.admin.identity.InMemoryPlayerRegistrationStore
import com.slotting.admin.identity.InMemoryServerEligibilityStore
import com.slotting.admin.ledger.InMemoryLedgerJournalStore
import com.slotting.admin.ledger.LedgerPostingService
import com.slotting.admin.rails.DepositGate
import com.slotting.admin.rails.DepositSubmission
import com.slotting.admin.rails.DepositSubmissionRepository
import com.slotting.admin.rails.SubmissionStatus
import com.slotting.admin.wallet.AuthoritativeWalletService
import com.slotting.admin.wallet.InMemoryAuthoritativeWalletStore
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test
import org.springframework.http.HttpStatus
import java.math.BigDecimal
import java.time.Clock
import java.time.Instant
import java.time.ZoneOffset
import java.util.UUID
import kotlin.test.assertEquals
import kotlin.test.assertNotEquals

class GateBoundaryTest {
    private val now = Instant.parse("2026-11-12T08:00:00Z")
    private val clock = Clock.fixed(now, ZoneOffset.UTC)
    private val tenantId = "tenant-gate"
    private val playerId = UUID.randomUUID().toString()
    private lateinit var gameStore: InMemoryDurableGameWagerAndSettlementStore
    private lateinit var snapshot: AuthoritativeGameSnapshotAndEventService

    private class FakeRepo(private val approved: Boolean) : DepositSubmissionRepository {
        override fun find(id: String): DepositSubmission? = null
        override fun markApproved(id: String, rate: BigDecimal, usd: BigDecimal, by: String) = false
        override fun markRejected(id: String, reason: String, by: String) = false
        override fun hasApprovedDeposit(playerId: String) = approved
        override fun insert(submission: DepositSubmission, fundingAccountId: String, transferReference: String, transferredUtc: Instant, receiptObject: String) = Unit
        override fun listByStatus(tenantId: String, status: SubmissionStatus) = emptyList<DepositSubmission>()
        override fun listMine(tenantId: String, playerId: String) = emptyList<DepositSubmission>()
        override fun revertApproval(id: String) = false
    }

    private val player = AuthenticatedPrincipal(playerId, tenantId, PrincipalKind.PLAYER, emptySet())
    private val admin = AuthenticatedPrincipal("admin-sys", tenantId, PrincipalKind.ADMIN, setOf(AdminRole.SUPER_ADMIN))

    @BeforeEach
    fun setUp() {
        val ledgerStore = InMemoryLedgerJournalStore()
        val ledgerService = LedgerPostingService(store = ledgerStore, clock = clock)
        val walletStore = InMemoryAuthoritativeWalletStore(ledgerStore = ledgerStore, clock = clock)
        val walletService = AuthoritativeWalletService(store = walletStore, clock = clock)
        gameStore = InMemoryDurableGameWagerAndSettlementStore()
        val registrationStore = InMemoryPlayerRegistrationStore()
        val eligibilityStore = InMemoryServerEligibilityStore()
        val service = DurableGameWagerAndSettlementService(
            store = gameStore,
            ledgerService = ledgerService,
            registrationStore = registrationStore,
            eligibilityStore = eligibilityStore,
            adminPrincipal = admin,
            clock = clock,
        )
        snapshot = AuthoritativeGameSnapshotAndEventService(
            gameStore = gameStore,
            gameService = service,
            walletService = walletService,
            ledgerStore = ledgerStore,
            fairnessStore = com.slotting.admin.gameprovider.InMemoryFairnessEvidenceStore(),
            eventJournalStore = com.slotting.admin.gameprovider.InMemoryGameEventJournalStore(),
            registrationStore = registrationStore,
            clock = clock,
        )
        service.createOrUpdateRound(
            CreateOrUpdateRoundCommand(tenantId = tenantId, gameId = "AVIATOR", roundId = "round-gate-1", phase = GameRoundPhase.BET_COUNTDOWN),
        )
    }

    private fun gatedWithStore(approved: Boolean): Pair<AviatorGameRestController, InMemoryDurableGameWagerAndSettlementStore> {
        val ledgerStore = InMemoryLedgerJournalStore()
        val ledgerService = LedgerPostingService(store = ledgerStore, clock = clock)
        val walletService = AuthoritativeWalletService(InMemoryAuthoritativeWalletStore(ledgerStore = ledgerStore, clock = clock), clock = clock)
        val registrationStore = InMemoryPlayerRegistrationStore()
        val eligibilityStore = InMemoryServerEligibilityStore()
        val store = InMemoryDurableGameWagerAndSettlementStore()
        val service = DurableGameWagerAndSettlementService(
            store = store,
            ledgerService = ledgerService,
            registrationStore = registrationStore,
            eligibilityStore = eligibilityStore,
            adminPrincipal = admin,
            clock = clock,
            depositGate = DepositGate(FakeRepo(approved)),
        )
        service.createOrUpdateRound(
            CreateOrUpdateRoundCommand(tenantId = tenantId, gameId = "AVIATOR", roundId = "round-gate-1", phase = GameRoundPhase.BET_COUNTDOWN),
        )
        val snapshot = AuthoritativeGameSnapshotAndEventService(
            gameStore = store,
            gameService = service,
            walletService = walletService,
            ledgerStore = ledgerStore,
            fairnessStore = InMemoryFairnessEvidenceStore(),
            eventJournalStore = InMemoryGameEventJournalStore(),
            registrationStore = registrationStore,
            clock = clock,
        )
        return AviatorGameRestController(snapshotAndEventService = snapshot, gameService = service) to store
    }

    private fun gated(approved: Boolean): AviatorGameRestController = gatedWithStore(approved).first

    private fun request(action: String = "BET") = GameCommandRequest(
        commandId = "cmd-" + UUID.randomUUID(),
        gameId = "AVIATOR",
        roundId = "round-gate-1",
        handId = "hand_primary",
        action = action,
        wagerMinorUnits = 2500L,
        currencyCode = "PKR",
    )

    @Test
    fun `zero deposit bet is refused with typed 403 not 500`() {
        val response = gated(false).postCommand(tenantIdHeader = tenantId, request = request(), principalAttr = player)
        assertEquals(HttpStatus.FORBIDDEN, response.statusCode)
        assertNotEquals(HttpStatus.INTERNAL_SERVER_ERROR, response.statusCode)
        val body = response.body as Map<*, *>
        assertEquals("NO_VERIFIED_DEPOSIT", body["error"])
        assertEquals("a verified deposit is required before placing bets", body["message"])
    }

    @Test
    fun `approved deposit passes the gate`() {
        val response = gated(true).postCommand(tenantIdHeader = tenantId, request = request(), principalAttr = player)
        assertNotEquals(HttpStatus.FORBIDDEN, response.statusCode)
    }

    @Test
    fun `refused bet leaves the game store unchanged`() {
        val (controller, store) = gatedWithStore(false)
        val before = store.findBetsForRound(tenantId, "AVIATOR", "round-gate-1").size

        val response = controller.postCommand(tenantIdHeader = tenantId, request = request(), principalAttr = player)

        assertEquals(HttpStatus.FORBIDDEN, response.statusCode)
        assertEquals(before, store.findBetsForRound(tenantId, "AVIATOR", "round-gate-1").size)
    }

    @Test
    fun `cancel bet for a zero deposit player carries the typed shape`() {
        val response = gated(false).postCommand(tenantIdHeader = tenantId, request = request("CANCEL_BET"), principalAttr = player)
        assertEquals(HttpStatus.FORBIDDEN, response.statusCode)
        val body = response.body as Map<*, *>
        assertEquals("NO_VERIFIED_DEPOSIT", body["error"])
    }
}
