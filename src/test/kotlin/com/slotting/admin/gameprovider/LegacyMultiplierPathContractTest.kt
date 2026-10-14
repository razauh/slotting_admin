package com.slotting.admin.gameprovider

import com.slotting.admin.auth.AdminRole
import com.slotting.admin.auth.AuthenticatedPrincipal
import com.slotting.admin.auth.AuthenticationFailure
import com.slotting.admin.auth.AuthErrorCode
import com.slotting.admin.auth.PrincipalKind
import com.slotting.admin.identity.AmlComplianceStatus
import com.slotting.admin.identity.InMemoryPlayerRegistrationStore
import com.slotting.admin.identity.InMemoryServerEligibilityStore
import com.slotting.admin.identity.KycComplianceStatus
import com.slotting.admin.identity.PlayerAccountStatus
import com.slotting.admin.identity.PlayerComplianceProfile
import com.slotting.admin.identity.PlayerRegistrationRecord
import com.slotting.admin.identity.ResponsiblePlayProfile
import com.slotting.admin.ledger.InMemoryLedgerJournalStore
import com.slotting.admin.ledger.JournalEntryDirection
import com.slotting.admin.ledger.JournalEntryDraft
import com.slotting.admin.ledger.LedgerPostingService
import com.slotting.admin.ledger.PostTransactionCommand
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test
import java.io.File
import java.math.BigDecimal
import java.time.Clock
import java.time.Instant
import java.time.LocalDate
import java.time.ZoneOffset
import java.util.UUID
import kotlin.test.assertEquals
import kotlin.test.assertNotNull
import kotlin.test.assertTrue
import kotlin.test.assertFailsWith

class LegacyMultiplierPathContractTest {

    private val now = Instant.parse("2026-09-25T12:00:00Z")
    private val clock = Clock.fixed(now, ZoneOffset.UTC)
    private val tenantId = "tenant-pilot-001"
    private val gameId = "AVIATOR"
    private val currency = "INR"
    private val playerUuid = UUID.fromString("11111111-1111-1111-1111-111111111111")
    private val playerIdStr = playerUuid.toString()

    private val playerPrincipal = AuthenticatedPrincipal(
        id = playerIdStr,
        tenantId = tenantId,
        kind = PrincipalKind.PLAYER,
        roles = setOf(AdminRole.SUPPORT)
    )

    private val adminPrincipal = AuthenticatedPrincipal(
        id = "admin-sys-01",
        tenantId = tenantId,
        kind = PrincipalKind.ADMIN,
        roles = setOf(AdminRole.SUPER_ADMIN)
    )

    private lateinit var ledgerStore: InMemoryLedgerJournalStore
    private lateinit var ledgerService: LedgerPostingService
    private lateinit var registrationStore: InMemoryPlayerRegistrationStore
    private lateinit var eligibilityStore: InMemoryServerEligibilityStore
    private lateinit var gameStore: InMemoryDurableGameWagerAndSettlementStore
    private lateinit var fairnessStore: InMemoryFairnessEvidenceStore
    private lateinit var fairnessAuthority: ProvablyFairOutcomeAuthority
    private lateinit var service: DurableGameWagerAndSettlementService
    private lateinit var legacyStore: InMemoryAviatorCommandStore
    private lateinit var legacyService: AviatorRestCommandCompatibilityService

    @BeforeEach
    fun setUp() {
        ledgerStore = InMemoryLedgerJournalStore()
        ledgerService = LedgerPostingService(store = ledgerStore, clock = clock)
        registrationStore = InMemoryPlayerRegistrationStore()
        eligibilityStore = InMemoryServerEligibilityStore()
        gameStore = InMemoryDurableGameWagerAndSettlementStore()
        fairnessStore = InMemoryFairnessEvidenceStore()
        fairnessAuthority = ProvablyFairOutcomeAuthority(store = fairnessStore, clock = clock)
        service = DurableGameWagerAndSettlementService(
            store = gameStore,
            ledgerService = ledgerService,
            registrationStore = registrationStore,
            eligibilityStore = eligibilityStore,
            adminPrincipal = adminPrincipal,
            clock = clock,
            fairnessAuthority = fairnessAuthority,
        )
        legacyStore = InMemoryAviatorCommandStore()
        legacyService = AviatorRestCommandCompatibilityService(
            store = legacyStore,
            clock = clock,
        )

        registrationStore.players[playerUuid] = PlayerRegistrationRecord(
            playerId = playerUuid,
            tenantId = tenantId,
            emailHash = "email-hash-1",
            phoneHash = "phone-hash-1",
            maskedEmail = "p***@test.com",
            maskedPhone = "+1***1234",
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
                dateOfBirth = LocalDate.of(1995, 1, 1),
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

        ledgerService.postTransaction(
            PostTransactionCommand(
                principal = adminPrincipal,
                tenantId = tenantId,
                transactionReference = "TX-SEED-PLAYER-FUNDS",
                currencyCode = currency,
                entries = listOf(
                    JournalEntryDraft("HOUSE:SEED", JournalEntryDirection.DEBIT, 100000L, currency),
                    JournalEntryDraft("PLAYER:$playerIdStr", JournalEntryDirection.CREDIT, 100000L, currency)
                ),
                idempotencyKey = "IDEM-SEED-FUNDS-01",
                correlationId = "corr-seed",
                causationId = "caus-seed"
            )
        )
    }

    private fun seedRound(
        roundId: String,
        phase: GameRoundPhase = GameRoundPhase.BET_COUNTDOWN,
        roundVersion: Long = 1L,
        currentMultiplier: BigDecimal = BigDecimal("1.00"),
        crashMultiplier: BigDecimal? = null
    ) {
        fairnessAuthority.publishPreBetCommitment(
            PublishCommitmentCommand(
                tenantId = tenantId,
                gameId = gameId,
                roundId = roundId,
                publicSalt = "salt-$roundId",
            )
        )
        service.createOrUpdateRound(
            CreateOrUpdateRoundCommand(
                tenantId = tenantId,
                gameId = gameId,
                roundId = roundId,
                phase = phase,
                roundVersion = roundVersion,
                currentMultiplier = currentMultiplier,
                crashMultiplier = crashMultiplier
            )
        )
    }

    private fun placeBet(roundId: String, wagerMinor: Long): AviatorCommandAckResult {
        return service.processCommand(
            AviatorRestCommand(
                tenantId = tenantId,
                principal = playerPrincipal,
                commandId = "cmd-bet-$roundId",
                roundId = roundId,
                handId = "hand_primary",
                action = "PLACE_BET",
                wagerMinor = wagerMinor,
                currency = currency,
                correlationId = "corr-bet-$roundId"
            )
        )
    }

    @Test
    fun noRouteDelegatesToLegacyCompatibilityService() {
        val legacyClassName = "AviatorRestCommandCompatibilityService"
        val mainSourceRoot = File("src/main/kotlin")
        val controllerFiles = mainSourceRoot.walkTopDown()
            .filter { it.extension == "kt" && (it.name.contains("Controller") || it.name.contains("Resource") || it.name.contains("Route")) }
            .toList()
        for (file in controllerFiles) {
            assertTrue(!file.readText().contains(legacyClassName), "Controller ${file.name} must not reference $legacyClassName")
        }
    }

    @Test
    fun legacyClassAbsentFromProductionBeanGraph() {
        val mainSourceRoot = File("src/main/kotlin")
        val legacySimple = "AviatorRestCommandCompatibilityService"
        val occurrences = mainSourceRoot.walkTopDown()
            .filter { it.extension == "kt" }
            .count { it.readText().contains(legacySimple) && !it.name.contains("Compatibility") && !it.name.contains("AviatorRest") }
        assertEquals(0, occurrences, "No production source file outside the legacy harness should reference $legacySimple")
    }

    @Test
    fun inflatedClientMultiplierCannotMintMoney() {
        val roundId = "rnd-legacy-mint"
        seedRound(roundId)
        placeBet(roundId, 5000L)
        service.createOrUpdateRound(
            CreateOrUpdateRoundCommand(
                tenantId = tenantId,
                gameId = gameId,
                roundId = roundId,
                phase = GameRoundPhase.FLYING,
                roundVersion = 2L,
                currentMultiplier = BigDecimal("1.50"),
                crashMultiplier = BigDecimal("10.00")
            )
        )

        val inflatedCashOut = AviatorRestCommand(
            tenantId = tenantId,
            principal = playerPrincipal,
            commandId = "cmd-inflated-cashout",
            roundId = roundId,
            handId = "hand_primary",
            action = "CASH_OUT",
            cashOutMultiplier = 1_000_000.0,
            currency = currency,
            correlationId = "corr-inflated"
        )
        val ack = service.processCommand(inflatedCashOut)

        assertEquals(AviatorCommandAckStatus.ACCEPTED, ack.status)
        assertEquals(7500L, ack.result?.payoutMinor)
        assertNotNull(ack.result?.cashOutMultiplier)
        assertEquals(1.5, ack.result!!.cashOutMultiplier)

        val balance = ledgerStore.findBalance(tenantId, "PLAYER:$playerIdStr", currency)
        assertEquals(102500L, balance)

        val settlement = gameStore.findSettlement(tenantId, gameStore.findBet(tenantId, gameId, roundId, playerIdStr, "hand_primary")!!.betId)
        assertNotNull(settlement)
        assertEquals(0, BigDecimal("1.5").compareTo(settlement.multiplier))
        assertEquals(7500L, settlement.payoutMinorUnits)
    }

    @Test
    fun retainedPathUsesServerMultiplierAndLedgerOnly() {
        val roundId = "rnd-retained-guard"
        seedRound(roundId)
        placeBet(roundId, 5000L)
        service.createOrUpdateRound(
            CreateOrUpdateRoundCommand(
                tenantId = tenantId,
                gameId = gameId,
                roundId = roundId,
                phase = GameRoundPhase.FLYING,
                roundVersion = 2L,
                currentMultiplier = BigDecimal("2.00"),
                crashMultiplier = BigDecimal("5.00")
            )
        )

        val cashOutCmd = AviatorRestCommand(
            tenantId = tenantId,
            principal = playerPrincipal,
            commandId = "cmd-retained-cashout",
            roundId = roundId,
            handId = "hand_primary",
            action = "CASH_OUT",
            currency = currency,
            correlationId = "corr-retained"
        )
        val ack = service.processCommand(cashOutCmd)
        assertEquals(AviatorCommandAckStatus.ACCEPTED, ack.status)
        assertEquals(2.0, ack.result?.cashOutMultiplier)
        assertEquals(10000L, ack.result?.payoutMinor)

        val settlement = gameStore.findSettlement(
            tenantId,
            gameStore.findBet(tenantId, gameId, roundId, playerIdStr, "hand_primary")!!.betId
        )
        assertNotNull(settlement)
        assertNotNull(settlement.ledgerSettlementRef)
        assertTrue(settlement.ledgerSettlementRef.isNotBlank())

        val legacyCmd = AviatorRestCommand(
            tenantId = tenantId,
            principal = playerPrincipal,
            commandId = "cmd-legacy-cashout",
            roundId = "rnd-legacy",
            handId = "hand_primary",
            action = "CASH_OUT",
            cashOutMultiplier = 999.0,
            currency = currency,
            correlationId = "corr-legacy"
        )
        assertFailsWith<AuthenticationFailure.Rejected> {
            legacyService.processCommand(legacyCmd)
        }.also { assertEquals(AuthErrorCode.FORBIDDEN, it.code) }
    }
}
