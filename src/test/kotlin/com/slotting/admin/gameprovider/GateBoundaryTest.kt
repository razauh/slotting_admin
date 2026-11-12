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
    private lateinit var gatedLedger: LedgerPostingService
    private lateinit var gatedRegistration: InMemoryPlayerRegistrationStore
    private lateinit var gatedEligibility: InMemoryServerEligibilityStore
    private lateinit var gatedWallet: AuthoritativeWalletService

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
        gatedLedger = ledgerService
        gatedRegistration = registrationStore
        gatedEligibility = eligibilityStore
        gatedWallet = walletService
        val playerUuid = UUID.fromString(playerId)
        registrationStore.players[playerUuid] = com.slotting.admin.identity.PlayerRegistrationRecord(
            playerId = playerUuid,
            tenantId = tenantId,
            emailHash = "email-hash-gate",
            phoneHash = "phone-hash-gate",
            maskedEmail = "gate@test.internal",
            maskedPhone = "+1***0000",
            jurisdiction = "DEFAULT",
            riskScore = 0.0,
            mfaRequired = false,
            status = com.slotting.admin.identity.PlayerAccountStatus.ACTIVE,
            createdAt = now.minusSeconds(86400),
            updatedAt = now.minusSeconds(86400),
        )
        eligibilityStore.saveComplianceProfile(
            com.slotting.admin.identity.PlayerComplianceProfile(
                playerId = playerUuid,
                tenantId = tenantId,
                dateOfBirth = java.time.LocalDate.of(1995, 1, 1),
                kycStatus = com.slotting.admin.identity.KycComplianceStatus.VERIFIED,
                amlStatus = com.slotting.admin.identity.AmlComplianceStatus.CLEARED,
                jurisdiction = "DEFAULT",
                responsiblePlay = com.slotting.admin.identity.ResponsiblePlayProfile(
                    playerId = playerUuid,
                    selfExcluded = false,
                    singleWagerLimitMinor = 50000L,
                    dailyWagerLimitMinor = 200000L,
                    currentDailyWagerMinor = 0L,
                ),
            ),
        )
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
    fun `control case - approved player bet mutates the store`() {
        val (controller, store) = gatedWithStore(true)
        gatedLedger.postTransaction(
            com.slotting.admin.ledger.PostTransactionCommand(
                principal = admin,
                tenantId = tenantId,
                transactionReference = "TX-GATE-DEP-1",
                currencyCode = "PKR",
                entries = listOf(
                    com.slotting.admin.ledger.JournalEntryDraft("SYSTEM:CASH", com.slotting.admin.ledger.JournalEntryDirection.DEBIT, 50000L, "PKR"),
                    com.slotting.admin.ledger.JournalEntryDraft("PLAYER:$playerId", com.slotting.admin.ledger.JournalEntryDirection.CREDIT, 50000L, "PKR"),
                ),
                idempotencyKey = "IDEM-GATE-DEP-1",
                correlationId = "corr-gate-dep-1",
                causationId = "caus-gate-dep-1",
            ),
        )
        val before = store.findBetsForRound(tenantId, "AVIATOR", "round-gate-1").size

        controller.postCommand(tenantIdHeader = tenantId, request = request(), principalAttr = player)

        val after = store.findBetsForRound(tenantId, "AVIATOR", "round-gate-1").size
        assertNotEquals(before, after)
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
