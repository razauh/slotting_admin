package com.slotting.admin.gameprovider

import com.fasterxml.jackson.databind.ObjectMapper
import com.slotting.admin.auth.*
import com.slotting.admin.identity.*
import com.slotting.admin.ledger.*
import com.slotting.admin.wallet.AuthoritativeWalletService
import com.slotting.admin.wallet.InMemoryAuthoritativeWalletStore
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test
import org.springframework.http.HttpStatus
import org.springframework.http.ResponseEntity
import java.math.BigDecimal
import java.time.Clock
import java.time.Instant
import java.time.ZoneOffset
import java.util.UUID
import kotlin.test.*

class AviatorGameRestControllerTest {

    private val now = Instant.parse("2026-09-25T15:00:00Z")
    private val clock = Clock.fixed(now, ZoneOffset.UTC)
    private val tenantId = "tenant-pilot-001"
    private val playerUuid = UUID.fromString("11111111-1111-1111-1111-111111111111")
    private val playerId = playerUuid.toString()

    private lateinit var ledgerStore: InMemoryLedgerJournalStore
    private lateinit var ledgerService: LedgerPostingService
    private lateinit var walletStore: InMemoryAuthoritativeWalletStore
    private lateinit var walletService: AuthoritativeWalletService
    private lateinit var registrationStore: InMemoryPlayerRegistrationStore
    private lateinit var eligibilityStore: InMemoryServerEligibilityStore
    private lateinit var gameStore: InMemoryDurableGameWagerAndSettlementStore
    private lateinit var gameService: DurableGameWagerAndSettlementService
    private lateinit var fairnessStore: InMemoryFairnessEvidenceStore
    private lateinit var fairnessAuthority: ProvablyFairOutcomeAuthority
    private lateinit var eventJournalStore: InMemoryGameEventJournalStore
    private lateinit var snapshotAndEventService: AuthoritativeGameSnapshotAndEventService
    private lateinit var controller: AviatorGameRestController

    private val adminPrincipal = AuthenticatedPrincipal(
        id = "admin-sys-01",
        tenantId = tenantId,
        kind = PrincipalKind.ADMIN,
        roles = setOf(AdminRole.SUPER_ADMIN)
    )

    private val playerPrincipal = AuthenticatedPrincipal(
        id = playerId,
        tenantId = tenantId,
        kind = PrincipalKind.PLAYER,
        roles = emptySet()
    )

    @BeforeEach
    fun setUp() {
        ledgerStore = InMemoryLedgerJournalStore()
        ledgerService = LedgerPostingService(store = ledgerStore, clock = clock)
        walletStore = InMemoryAuthoritativeWalletStore(ledgerStore = ledgerStore, clock = clock)
        walletService = AuthoritativeWalletService(store = walletStore, clock = clock)
        registrationStore = InMemoryPlayerRegistrationStore()
        eligibilityStore = InMemoryServerEligibilityStore()
        gameStore = InMemoryDurableGameWagerAndSettlementStore()

        registrationStore.players[playerUuid] = PlayerRegistrationRecord(
            playerId = playerUuid,
            tenantId = tenantId,
            emailHash = "email-hash-1",
            phoneHash = "phone-hash-1",
            maskedEmail = "player101@test.internal",
            maskedPhone = "+1***1111",
            jurisdiction = "DEFAULT",
            riskScore = 0.0,
            mfaRequired = false,
            status = PlayerAccountStatus.ACTIVE,
            createdAt = now.minusSeconds(86400),
            updatedAt = now.minusSeconds(86400)
        )

        eligibilityStore.saveComplianceProfile(
            PlayerComplianceProfile(
                playerId = playerUuid,
                tenantId = tenantId,
                dateOfBirth = java.time.LocalDate.of(1995, 1, 1),
                kycStatus = KycComplianceStatus.VERIFIED,
                amlStatus = AmlComplianceStatus.CLEARED,
                jurisdiction = "DEFAULT",
                responsiblePlay = ResponsiblePlayProfile(
                    playerId = playerUuid,
                    selfExcluded = false,
                    singleWagerLimitMinor = 50000L,
                    dailyWagerLimitMinor = 200000L,
                    currentDailyWagerMinor = 0L
                )
            )
        )

        gameService = DurableGameWagerAndSettlementService(
            store = gameStore,
            ledgerService = ledgerService,
            registrationStore = registrationStore,
            eligibilityStore = eligibilityStore,
            adminPrincipal = adminPrincipal,
            clock = clock
        )

        fairnessStore = InMemoryFairnessEvidenceStore()
        fairnessAuthority = ProvablyFairOutcomeAuthority(store = fairnessStore, clock = clock)
        eventJournalStore = InMemoryGameEventJournalStore()

        snapshotAndEventService = AuthoritativeGameSnapshotAndEventService(
            gameStore = gameStore,
            gameService = gameService,
            walletService = walletService,
            ledgerStore = ledgerStore,
            fairnessStore = fairnessStore,
            eventJournalStore = eventJournalStore,
            registrationStore = registrationStore,
            clock = clock,
        )

        controller = AviatorGameRestController(
            snapshotAndEventService = snapshotAndEventService,
            gameService = gameService
        )
    }

    @Test
    fun `GET bootstrap returns 200 with limits and game metadata`() {
        val response = controller.getBootstrap(
            tenantIdHeader = tenantId,
            gameId = "aviator",
            principalAttr = playerPrincipal
        )

        assertEquals(HttpStatus.OK, response.statusCode)
        val body = response.body as AviatorBootstrapResponse
        assertEquals("AVIATOR", body.gameId)
        assertEquals("1.2.0", body.protocolVersion)
        assertEquals(1000L, body.limits.minWagerMinor)
    }

    @Test
    fun `GET bet-limits returns 200 with crash bet limits`() {
        val response = controller.getBetLimits(tenantIdHeader = tenantId, gameId = "aviator")
        assertEquals(HttpStatus.OK, response.statusCode)
        val body = response.body as CrashBetLimits
        assertEquals(1000L, body.minWagerMinor)
        assertEquals(10000000L, body.maxWagerMinor)
    }

    @Test
    fun `GET my-info returns 401 when unauthenticated and 200 with balance when authenticated`() {
        // Unauthenticated
        val unauthResponse = controller.getMyInfo(
            tenantIdHeader = tenantId,
            sessionToken = null,
            authHeader = null,
            principalAttr = null
        )
        assertEquals(HttpStatus.UNAUTHORIZED, unauthResponse.statusCode)

        // Fund player
        ledgerService.postTransaction(
            PostTransactionCommand(
                principal = adminPrincipal,
                tenantId = tenantId,
                transactionReference = "TX-DEP-REST-01",
                currencyCode = "INR",
                entries = listOf(
                    JournalEntryDraft("SYSTEM:CASH", JournalEntryDirection.DEBIT, 50000L, "INR"),
                    JournalEntryDraft("PLAYER:$playerId", JournalEntryDirection.CREDIT, 50000L, "INR")
                ),
                idempotencyKey = "IDEM-DEP-REST-01",
                correlationId = "corr-dep-rest-01",
                causationId = "caus-dep-rest-01"
            )
        )

        // Authenticated
        val authResponse = controller.getMyInfo(
            tenantIdHeader = tenantId,
            principalAttr = playerPrincipal
        )
        assertEquals(HttpStatus.OK, authResponse.statusCode)
        val body = authResponse.body as SnapshotUser
        assertEquals(playerId, body.userId)
        assertEquals(50000L, body.balanceMinor)
    }

    @Test
    fun `GET snapshot returns full snapshot with balance and limits`() {
        val response = controller.getSnapshot(
            tenantIdHeader = tenantId,
            gameId = "aviator",
            roundId = null,
            principalAttr = playerPrincipal
        )
        assertEquals(HttpStatus.OK, response.statusCode)
        val body = response.body as FullSnapshot
        assertEquals(playerId, body.user.userId)
        assertEquals(0L, body.user.balanceMinor)
        assertFalse(body.primaryHand.betted)
    }

    @Test
    fun `POST command and GET command-result execute and recover ack`() {
        val roundId = "rnd-rest-cmd-01"
        gameService.createOrUpdateRound(
            CreateOrUpdateRoundCommand(
                tenantId = tenantId,
                gameId = "AVIATOR",
                roundId = roundId,
                phase = GameRoundPhase.BET_COUNTDOWN
            )
        )
        fairnessAuthority.publishPreBetCommitment(
            PublishCommitmentCommand(tenantId = tenantId, gameId = "AVIATOR", roundId = roundId, publicSalt = "salt-rest-01")
        )

        // Fund player
        ledgerService.postTransaction(
            PostTransactionCommand(
                principal = adminPrincipal,
                tenantId = tenantId,
                transactionReference = "TX-DEP-CMD-01",
                currencyCode = "INR",
                entries = listOf(
                    JournalEntryDraft("SYSTEM:CASH", JournalEntryDirection.DEBIT, 10000L, "INR"),
                    JournalEntryDraft("PLAYER:$playerId", JournalEntryDirection.CREDIT, 10000L, "INR")
                ),
                idempotencyKey = "IDEM-DEP-CMD-01",
                correlationId = "corr-dep-cmd-01",
                causationId = "caus-dep-cmd-01"
            )
        )

        val cmdRequest = GameCommandRequest(
            commandId = "cmd-rest-001",
            gameId = "AVIATOR",
            roundId = roundId,
            handId = "hand_primary",
            action = "BET",
            wagerMinorUnits = 2500L,
            currencyCode = "INR"
        )

        val cmdResponse = controller.postCommand(
            tenantIdHeader = tenantId,
            request = cmdRequest,
            principalAttr = playerPrincipal
        )
        assertEquals(HttpStatus.OK, cmdResponse.statusCode)
        val ack = cmdResponse.body as AviatorCommandAckResult
        assertEquals(AviatorCommandAckStatus.ACCEPTED, ack.status)
        assertEquals("cmd-rest-001", ack.commandId)

        // GET command-result
        val resultResponse = controller.getCommandResult(
            tenantIdHeader = tenantId,
            gameId = "AVIATOR",
            roundId = roundId,
            commandId = "cmd-rest-001",
            principalAttr = playerPrincipal
        )
        assertEquals(HttpStatus.OK, resultResponse.statusCode)
        val cachedAck = resultResponse.body as AviatorCommandAckResult
        assertEquals(AviatorCommandAckStatus.ACCEPTED, cachedAck.status)
        assertEquals("cmd-rest-001", cachedAck.commandId)
    }
}
