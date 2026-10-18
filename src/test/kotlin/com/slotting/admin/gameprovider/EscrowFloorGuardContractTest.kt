package com.slotting.admin.gameprovider

import com.slotting.admin.auth.AdminRole
import com.slotting.admin.auth.AuthenticatedPrincipal
import com.slotting.admin.auth.PrincipalKind
import com.slotting.admin.identity.InMemoryPlayerRegistrationStore
import com.slotting.admin.identity.InMemoryServerEligibilityStore
import com.slotting.admin.identity.KycComplianceStatus
import com.slotting.admin.identity.AmlComplianceStatus
import com.slotting.admin.identity.PlayerAccountStatus
import com.slotting.admin.identity.PlayerComplianceProfile
import com.slotting.admin.identity.PlayerRegistrationRecord
import com.slotting.admin.identity.ResponsiblePlayProfile
import com.slotting.admin.ledger.InMemoryLedgerJournalStore
import com.slotting.admin.ledger.JournalEntryDirection
import com.slotting.admin.ledger.JournalEntryDraft
import com.slotting.admin.ledger.LedgerPostingService
import com.slotting.admin.ledger.PostTransactionCommand
import io.micrometer.core.instrument.simple.SimpleMeterRegistry
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test
import java.math.BigDecimal
import java.time.Clock
import java.time.Instant
import java.time.LocalDate
import java.time.ZoneOffset
import java.util.UUID
import kotlin.test.assertEquals
import kotlin.test.assertTrue

class EscrowFloorGuardContractTest {

    private val now = Instant.parse("2026-10-15T12:00:00Z")
    private val clock = Clock.fixed(now, ZoneOffset.UTC)
    private val tenantId = "tenant-tc43"
    private val gameId = "AVIATOR"
    private val currency = "INR"
    private val playerUuid = UUID.randomUUID()
    private val playerIdStr = playerUuid.toString()

    private val adminPrincipal = AuthenticatedPrincipal(
        id = "admin-sys-tc43",
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

    private lateinit var gameStore: InMemoryDurableGameWagerAndSettlementStore
    private lateinit var ledgerStore: InMemoryLedgerJournalStore
    private lateinit var registrationStore: InMemoryPlayerRegistrationStore
    private lateinit var eligibilityStore: InMemoryServerEligibilityStore
    private lateinit var fairnessStore: InMemoryFairnessEvidenceStore
    private lateinit var fairnessAuthority: ProvablyFairOutcomeAuthority
    private lateinit var ledgerService: LedgerPostingService
    private lateinit var meterRegistry: SimpleMeterRegistry
    private lateinit var gameService: DurableGameWagerAndSettlementService

    @BeforeEach
    fun setUp() {
        gameStore = InMemoryDurableGameWagerAndSettlementStore()
        ledgerStore = InMemoryLedgerJournalStore()
        registrationStore = InMemoryPlayerRegistrationStore()
        eligibilityStore = InMemoryServerEligibilityStore()
        fairnessStore = InMemoryFairnessEvidenceStore()
        fairnessAuthority = ProvablyFairOutcomeAuthority(
            store = fairnessStore,
            clock = clock,
            envelope = FairnessSeedEnvelope.devDefault(),
        )
        ledgerService = LedgerPostingService(store = ledgerStore, clock = clock)
        meterRegistry = SimpleMeterRegistry()
        gameService = DurableGameWagerAndSettlementService(
            store = gameStore,
            ledgerService = ledgerService,
            registrationStore = registrationStore,
            eligibilityStore = eligibilityStore,
            adminPrincipal = adminPrincipal,
            clock = clock,
            meterRegistry = meterRegistry,
            fairnessAuthority = fairnessAuthority,
        )

        val regRecord = PlayerRegistrationRecord(
            playerId = playerUuid,
            tenantId = tenantId,
            emailHash = "email-hash",
            phoneHash = "phone-hash",
            maskedEmail = "p***@example.com",
            maskedPhone = "+91******1234",
            jurisdiction = "DEFAULT",
            riskScore = 0.0,
            status = PlayerAccountStatus.ACTIVE,
            mfaRequired = false,
            createdAt = now.minusSeconds(86400),
            updatedAt = now.minusSeconds(86400),
        )
        registrationStore.players[playerUuid] = regRecord

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
                    singleWagerLimitMinor = Long.MAX_VALUE,
                    dailyWagerLimitMinor = Long.MAX_VALUE,
                    currentDailyWagerMinor = 0L,
                )
            )
        )

        ledgerService.postTransaction(
            PostTransactionCommand(
                principal = adminPrincipal,
                tenantId = tenantId,
                transactionReference = "TX-SEED-TC43-${UUID.randomUUID()}",
                currencyCode = currency,
                entries = listOf(
                    JournalEntryDraft("HOUSE:SEED", JournalEntryDirection.DEBIT, 1000_00L, currency),
                    JournalEntryDraft("PLAYER:$playerIdStr", JournalEntryDirection.CREDIT, 1000_00L, currency),
                ),
                idempotencyKey = "IDEM-SEED-TC43-${UUID.randomUUID()}",
                correlationId = "corr-seed",
                causationId = "caus-seed",
            )
        )
    }

    private fun createRound(roundId: String, phase: GameRoundPhase = GameRoundPhase.BET_COUNTDOWN, multiplier: BigDecimal = BigDecimal("1.0000")) {
        gameService.createOrUpdateRound(
            CreateOrUpdateRoundCommand(
                tenantId = tenantId,
                gameId = gameId,
                roundId = roundId,
                phase = phase,
                roundVersion = 1L,
                currentMultiplier = multiplier,
            )
        )
        fairnessAuthority.publishPreBetCommitment(
            PublishCommitmentCommand(
                tenantId = tenantId,
                gameId = gameId,
                roundId = roundId,
                publicSalt = "salt-$roundId",
            )
        )
    }

    private fun placeBet(roundId: String, handId: String, amount: Long): AviatorCommandAckResult {
        return gameService.processCommand(
            AviatorRestCommand(
                commandId = "cmd-bet-${UUID.randomUUID()}",
                tenantId = tenantId,
                roundId = roundId,
                handId = handId,
                action = AviatorCommandAction.PLACE_BET.name,
                wagerMinor = amount,
                currency = currency,
                principal = playerPrincipal,
                expectedRoundVersion = 1L,
                correlationId = "corr-place",
            )
        )
    }

    private fun drainEscrow(amount: Long) {
        ledgerService.postTransaction(
            PostTransactionCommand(
                principal = adminPrincipal,
                tenantId = tenantId,
                transactionReference = "TX-DRAIN-${UUID.randomUUID()}",
                currencyCode = currency,
                entries = listOf(
                    JournalEntryDraft("ESCROW:GAME:$gameId", JournalEntryDirection.DEBIT, amount, currency),
                    JournalEntryDraft("HOUSE:DRAIN", JournalEntryDirection.CREDIT, amount, currency),
                ),
                idempotencyKey = "IDEM-DRAIN-${UUID.randomUUID()}",
                correlationId = "corr-drain",
                causationId = "caus-drain",
                requireNonNegativeAccounts = false,
            )
        )
    }

    private fun getEscrowLegCount(): Int {
        return ledgerStore.findAllLegsForTenant(tenantId).count { it.accountReference == "ESCROW:GAME:$gameId" }
    }

    @Test
    fun crashSweepBeyondEscrowIsRejected() {
        val roundId = "round-crash-${UUID.randomUUID()}"
        createRound(roundId)
        val betAck = placeBet(roundId, "hand-1", 100_00L)
        assertEquals(AviatorCommandAckStatus.ACCEPTED, betAck.status)

        val escrowBalanceBefore = ledgerStore.findBalance(tenantId, "ESCROW:GAME:$gameId", currency)
        assertEquals(100_00L, escrowBalanceBefore)

        drainEscrow(100_00L)
        assertEquals(0L, ledgerStore.findBalance(tenantId, "ESCROW:GAME:$gameId", currency))

        val legCountBefore = getEscrowLegCount()

        gameService.createOrUpdateRound(
            CreateOrUpdateRoundCommand(
                tenantId = tenantId,
                gameId = gameId,
                roundId = roundId,
                phase = GameRoundPhase.FLYING,
                roundVersion = 2L,
                currentMultiplier = BigDecimal("1.5000"),
                expectedVersion = 1L,
            )
        )

        val result = gameService.settleRoundCrash(
            SettleRoundCrashCommand(
                tenantId = tenantId,
                gameId = gameId,
                roundId = roundId,
                crashMultiplier = BigDecimal("2.0000"),
            )
        )

        val escrowBalanceAfter = ledgerStore.findBalance(tenantId, "ESCROW:GAME:$gameId", currency)
        val legCountAfter = getEscrowLegCount()

        assertTrue(escrowBalanceAfter >= 0L)
        assertEquals(legCountBefore, legCountAfter)
        assertEquals(0, result.settledBetsCount)
        assertEquals(1.0, meterRegistry.get("ledger.escrow_floor_blocks_total").counter().count())
    }

    @Test
    fun cancelRefundBeyondEscrowIsRejected() {
        val roundId = "round-cancel-${UUID.randomUUID()}"
        createRound(roundId)
        val betAck = placeBet(roundId, "hand-1", 100_00L)
        assertEquals(AviatorCommandAckStatus.ACCEPTED, betAck.status)

        drainEscrow(100_00L)
        assertEquals(0L, ledgerStore.findBalance(tenantId, "ESCROW:GAME:$gameId", currency))

        val legCountBefore = getEscrowLegCount()

        val cancelAck = gameService.processCommand(
            AviatorRestCommand(
                commandId = "cmd-cancel-${UUID.randomUUID()}",
                tenantId = tenantId,
                roundId = roundId,
                handId = "hand-1",
                action = AviatorCommandAction.CANCEL_BET.name,
                currency = currency,
                principal = playerPrincipal,
                expectedRoundVersion = 1L,
                correlationId = "corr-cancel",
            )
        )

        val escrowBalanceAfter = ledgerStore.findBalance(tenantId, "ESCROW:GAME:$gameId", currency)
        val legCountAfter = getEscrowLegCount()

        assertTrue(escrowBalanceAfter >= 0L)
        assertEquals(legCountBefore, legCountAfter)
        assertEquals(AviatorCommandAckStatus.REJECTED, cancelAck.status)
        assertEquals(1.0, meterRegistry.get("ledger.escrow_floor_blocks_total").counter().count())
    }

    @Test
    fun cashoutSettlementBeyondEscrowIsRejected() {
        val roundId = "round-cashout-${UUID.randomUUID()}"
        createRound(roundId)
        val betAck = placeBet(roundId, "hand-1", 100_00L)
        assertEquals(AviatorCommandAckStatus.ACCEPTED, betAck.status)

        gameService.createOrUpdateRound(
            CreateOrUpdateRoundCommand(
                tenantId = tenantId,
                gameId = gameId,
                roundId = roundId,
                phase = GameRoundPhase.FLYING,
                roundVersion = 2L,
                currentMultiplier = BigDecimal("1.5000"),
                expectedVersion = 1L,
            )
        )

        drainEscrow(100_00L)
        assertEquals(0L, ledgerStore.findBalance(tenantId, "ESCROW:GAME:$gameId", currency))

        val legCountBefore = getEscrowLegCount()

        val cashOutAck = gameService.processCommand(
            AviatorRestCommand(
                commandId = "cmd-cashout-${UUID.randomUUID()}",
                tenantId = tenantId,
                roundId = roundId,
                handId = "hand-1",
                action = AviatorCommandAction.CASH_OUT.name,
                currency = currency,
                principal = playerPrincipal,
                expectedRoundVersion = 2L,
                correlationId = "corr-cashout",
            )
        )

        val escrowBalanceAfter = ledgerStore.findBalance(tenantId, "ESCROW:GAME:$gameId", currency)
        val legCountAfter = getEscrowLegCount()

        assertTrue(escrowBalanceAfter >= 0L)
        assertEquals(legCountBefore, legCountAfter)
        assertEquals(AviatorCommandAckStatus.REJECTED, cashOutAck.status)
        assertEquals(1.0, meterRegistry.get("ledger.escrow_floor_blocks_total").counter().count())
    }

    @Test
    fun replayedSettlementReturnsFirstResultWithoutSecondDebit() {
        val roundId = "round-replay-${UUID.randomUUID()}"
        createRound(roundId)
        val betAck = placeBet(roundId, "hand-1", 100_00L)
        assertEquals(AviatorCommandAckStatus.ACCEPTED, betAck.status)

        gameService.createOrUpdateRound(
            CreateOrUpdateRoundCommand(
                tenantId = tenantId,
                gameId = gameId,
                roundId = roundId,
                phase = GameRoundPhase.FLYING,
                roundVersion = 2L,
                currentMultiplier = BigDecimal("1.5000"),
                expectedVersion = 1L,
            )
        )

        val cmd = AviatorRestCommand(
            commandId = "cmd-cashout-replay",
            tenantId = tenantId,
            roundId = roundId,
            handId = "hand-1",
            action = AviatorCommandAction.CASH_OUT.name,
            currency = currency,
            principal = playerPrincipal,
            expectedRoundVersion = 2L,
            correlationId = "corr-replay",
        )

        val firstAck = gameService.processCommand(cmd)
        assertEquals(AviatorCommandAckStatus.ACCEPTED, firstAck.status)

        val legCountAfterFirst = getEscrowLegCount()

        val secondAck = gameService.processCommand(cmd)
        assertEquals(AviatorCommandAckStatus.ACCEPTED, secondAck.status)
        assertEquals(firstAck.commandId, secondAck.commandId)
        assertEquals(firstAck.evidenceReference, secondAck.evidenceReference)

        val legCountAfterSecond = getEscrowLegCount()
        assertEquals(legCountAfterFirst, legCountAfterSecond)
    }

    @Test
    fun normalSettlementsStillSucceed() {
        val roundId = "round-normal-${UUID.randomUUID()}"
        createRound(roundId)
        val betAck = placeBet(roundId, "hand-1", 100_00L)
        assertEquals(AviatorCommandAckStatus.ACCEPTED, betAck.status)

        gameService.createOrUpdateRound(
            CreateOrUpdateRoundCommand(
                tenantId = tenantId,
                gameId = gameId,
                roundId = roundId,
                phase = GameRoundPhase.FLYING,
                roundVersion = 2L,
                currentMultiplier = BigDecimal("2.0000"),
                expectedVersion = 1L,
            )
        )

        val cashOutAck = gameService.processCommand(
            AviatorRestCommand(
                commandId = "cmd-normal-cashout",
                tenantId = tenantId,
                roundId = roundId,
                handId = "hand-1",
                action = AviatorCommandAction.CASH_OUT.name,
                currency = currency,
                principal = playerPrincipal,
                expectedRoundVersion = 2L,
                correlationId = "corr-normal",
            )
        )
        assertEquals(AviatorCommandAckStatus.ACCEPTED, cashOutAck.status)
        assertEquals(200_00L, cashOutAck.result?.payoutMinor)
        assertEquals(1100_00L, cashOutAck.result?.accountMoneyAfterMinor)
        assertEquals(null, meterRegistry.find("ledger.escrow_floor_blocks_total").counter())
    }
}
