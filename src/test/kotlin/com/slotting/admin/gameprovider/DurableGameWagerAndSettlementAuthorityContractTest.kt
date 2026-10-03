package com.slotting.admin.gameprovider

import com.fasterxml.jackson.databind.ObjectMapper
import com.slotting.admin.auth.AdminRole
import com.slotting.admin.auth.AuthenticatedPrincipal
import com.slotting.admin.auth.PrincipalKind
import com.slotting.admin.identity.AmlComplianceStatus
import com.slotting.admin.identity.InMemoryPlayerRegistrationStore
import com.slotting.admin.identity.InMemoryServerEligibilityStore
import com.slotting.admin.identity.KycComplianceStatus
import com.slotting.admin.identity.PlayerRegistrationRecord
import com.slotting.admin.identity.PlayerAccountStatus
import com.slotting.admin.identity.PlayerComplianceProfile
import com.slotting.admin.identity.ResponsiblePlayProfile
import com.slotting.admin.ledger.InMemoryLedgerJournalStore
import com.slotting.admin.ledger.JournalEntryDraft
import com.slotting.admin.ledger.JournalEntryDirection
import com.slotting.admin.ledger.LedgerPostingException
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
import kotlin.test.*

/**
 * TC-021 Contract Test Suite:
 * Durable wager reservation and once-only game settlement authority.
 *
 * Covers:
 * - BE-004: Caller-selected refunds/payouts in Aviator, in-memory balance map, no ledger backing.
 * - BE-024: Missing compliance evidence / cumulative limit enforcement on wagers.
 *
 * 10 Required Scenarios:
 * 1. no prior bet
 * 2. duplicate bet
 * 3. cancel after settlement
 * 4. cash-out phase race
 * 5. round crash
 * 6. parallel hands
 * 7. insufficient funds
 * 8. eligibility changes
 * 9. restart
 * 10. ledger failure
 */
class DurableGameWagerAndSettlementAuthorityContractTest {

    private val now = Instant.parse("2026-09-25T12:00:00Z")
    private val clock = Clock.fixed(now, ZoneOffset.UTC)
    private val tenantId = "tenant-pilot-001"
    private val gameId = "AVIATOR"
    private val playerUuid = UUID.fromString("11111111-1111-1111-1111-111111111111")
    private val playerIdStr = playerUuid.toString()
    private val currency = "INR"

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
    private lateinit var service: DurableGameWagerAndSettlementService

    @BeforeEach
    fun setUp() {
        ledgerStore = InMemoryLedgerJournalStore()
        ledgerService = LedgerPostingService(store = ledgerStore, clock = clock)
        registrationStore = InMemoryPlayerRegistrationStore()
        eligibilityStore = InMemoryServerEligibilityStore()
        gameStore = InMemoryDurableGameWagerAndSettlementStore()

        service = DurableGameWagerAndSettlementService(
            store = gameStore,
            ledgerService = ledgerService,
            registrationStore = registrationStore,
            eligibilityStore = eligibilityStore,
            adminPrincipal = adminPrincipal,
            clock = clock
        )

        // Seed player registration as ACTIVE
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

        // Seed affirmative compliance profile (BE-024)
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
                    singleWagerLimitMinor = 50000L,
                    dailyWagerLimitMinor = 200000L,
                    currentDailyWagerMinor = 0L
                )
            )
        )

        // Fund player ledger balance with 100,000 INR minor units (1,000.00 INR)
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

    // =========================================================================
    // Scenario 1: no prior bet
    // =========================================================================

    @Test
    fun `scenario01 cancel or cash-out without accepted bet fails closed with no ledger credit`() {
        seedRound("rnd-001", phase = GameRoundPhase.BET_COUNTDOWN)

        // Attempt CANCEL_BET with no prior bet
        val cancelCmd = AviatorRestCommand(
            tenantId = tenantId,
            principal = playerPrincipal,
            commandId = "cmd-cancel-nobet",
            roundId = "rnd-001",
            handId = "hand_primary",
            action = "CANCEL_BET",
            correlationId = "corr-nobet-cancel"
        )
        val cancelAck = service.processCommand(cancelCmd)
        assertEquals(AviatorCommandAckStatus.REJECTED, cancelAck.status)
        assertEquals(AviatorCommandRejectionCode.INVALID_HAND_STATE, cancelAck.rejection?.code)

        // Advance round to FLYING to test CASH_OUT with no prior bet
        service.createOrUpdateRound(
            CreateOrUpdateRoundCommand(
                tenantId = tenantId,
                gameId = gameId,
                roundId = "rnd-001",
                phase = GameRoundPhase.FLYING,
                roundVersion = 2L,
                currentMultiplier = BigDecimal("1.50")
            )
        )

        // Attempt CASH_OUT with no prior bet
        val cashOutCmd = AviatorRestCommand(
            tenantId = tenantId,
            principal = playerPrincipal,
            commandId = "cmd-cashout-nobet",
            roundId = "rnd-001",
            handId = "hand_primary",
            action = "CASH_OUT",
            correlationId = "corr-nobet-cashout"
        )
        val cashOutAck = service.processCommand(cashOutCmd)
        assertEquals(AviatorCommandAckStatus.REJECTED, cashOutAck.status)
        assertEquals(AviatorCommandRejectionCode.INVALID_HAND_STATE, cashOutAck.rejection?.code)

        // Assert player ledger balance unchanged
        val balance = ledgerService.store.findBalance(tenantId, "PLAYER:$playerIdStr", currency)
        assertEquals(100000L, balance)
    }

    // =========================================================================
    // Scenario 2: duplicate bet
    // =========================================================================

    @Test
    fun `scenario02 duplicate bet command returns cached ACK and new command ID conflicts`() {
        seedRound("rnd-002", phase = GameRoundPhase.BET_COUNTDOWN)

        val placeCmd = AviatorRestCommand(
            tenantId = tenantId,
            principal = playerPrincipal,
            commandId = "cmd-bet-002",
            roundId = "rnd-002",
            handId = "hand_primary",
            action = "PLACE_BET",
            wagerMinor = 2000L,
            currency = currency,
            correlationId = "corr-002"
        )

        // 1. First submission succeeds
        val ack1 = service.processCommand(placeCmd)
        assertEquals(AviatorCommandAckStatus.ACCEPTED, ack1.status)
        assertEquals(98000L, ack1.result?.accountMoneyAfterMinor)

        val balanceAfter1 = ledgerService.store.findBalance(tenantId, "PLAYER:$playerIdStr", currency)
        assertEquals(98000L, balanceAfter1)

        // 2. Exact command ID replay returns cached ACK with status DUPLICATE or ACCEPTED and NO second debit
        val ackReplay = service.processCommand(placeCmd)
        assertEquals(ack1.commandId, ackReplay.commandId)
        assertEquals(ack1.sequenceId, ackReplay.sequenceId)
        assertEquals(98000L, ackReplay.result?.accountMoneyAfterMinor)

        val balanceAfterReplay = ledgerService.store.findBalance(tenantId, "PLAYER:$playerIdStr", currency)
        assertEquals(98000L, balanceAfterReplay, "Replay must NOT perform second debit")

        // 3. New command ID for already-betted hand for this round is rejected (CONFLICT / INVALID_HAND_STATE)
        val placeCmd2 = placeCmd.copy(commandId = "cmd-bet-002-dup")
        val ackNewCmd = service.processCommand(placeCmd2)
        assertEquals(AviatorCommandAckStatus.REJECTED, ackNewCmd.status)
        assertEquals(AviatorCommandRejectionCode.INVALID_HAND_STATE, ackNewCmd.rejection?.code)

        val balanceAfterNewCmd = ledgerService.store.findBalance(tenantId, "PLAYER:$playerIdStr", currency)
        assertEquals(98000L, balanceAfterNewCmd)
    }

    // =========================================================================
    // Scenario 3: cancel after settlement
    // =========================================================================

    @Test
    fun `scenario03 cancel on already cashed-out or settled bet is rejected`() {
        seedRound("rnd-003", phase = GameRoundPhase.BET_COUNTDOWN)

        // Place bet
        service.processCommand(
            AviatorRestCommand(
                tenantId = tenantId,
                principal = playerPrincipal,
                commandId = "cmd-bet-003",
                roundId = "rnd-003",
                handId = "hand_primary",
                action = "PLACE_BET",
                wagerMinor = 5000L,
                currency = currency,
                correlationId = "corr-003"
            )
        )

        // Advance round to FLYING with 1.50 multiplier
        service.createOrUpdateRound(
            CreateOrUpdateRoundCommand(
                tenantId = tenantId,
                gameId = gameId,
                roundId = "rnd-003",
                phase = GameRoundPhase.FLYING,
                roundVersion = 2L,
                currentMultiplier = BigDecimal("1.50")
            )
        )

        // Cash out at 1.50x: payout = 5000 * 1.50 = 7500
        val cashOutAck = service.processCommand(
            AviatorRestCommand(
                tenantId = tenantId,
                principal = playerPrincipal,
                commandId = "cmd-cashout-003",
                roundId = "rnd-003",
                handId = "hand_primary",
                action = "CASH_OUT",
                correlationId = "corr-003-co"
            )
        )
        assertEquals(AviatorCommandAckStatus.ACCEPTED, cashOutAck.status)
        assertEquals(7500L, cashOutAck.result?.payoutMinor)

        val balanceAfterWin = ledgerService.store.findBalance(tenantId, "PLAYER:$playerIdStr", currency)
        assertEquals(102500L, balanceAfterWin) // 100000 - 5000 + 7500 = 102500

        // Set round back to BET_COUNTDOWN to test cancellation attempt on settled bet
        val roundRecord = gameStore.findRound(tenantId, gameId, "rnd-003")!!
        gameStore.saveRound(roundRecord.copy(phase = GameRoundPhase.BET_COUNTDOWN, roundVersion = 3L))

        // Attempt CANCEL_BET on settled bet
        val cancelAck = service.processCommand(
            AviatorRestCommand(
                tenantId = tenantId,
                principal = playerPrincipal,
                commandId = "cmd-cancel-003",
                roundId = "rnd-003",
                handId = "hand_primary",
                action = "CANCEL_BET",
                correlationId = "corr-003-cancel"
            )
        )
        assertEquals(AviatorCommandAckStatus.REJECTED, cancelAck.status)
        assertEquals(AviatorCommandRejectionCode.INVALID_HAND_STATE, cancelAck.rejection?.code)

        // Ledger balance must remain 102500
        assertEquals(102500L, ledgerService.store.findBalance(tenantId, "PLAYER:$playerIdStr", currency))
    }

    // =========================================================================
    // Scenario 4: cash-out phase race
    // =========================================================================

    @Test
    fun `scenario04 cash-out after round has ended or crashed is rejected`() {
        seedRound("rnd-004", phase = GameRoundPhase.BET_COUNTDOWN)

        service.processCommand(
            AviatorRestCommand(
                tenantId = tenantId,
                principal = playerPrincipal,
                commandId = "cmd-bet-004",
                roundId = "rnd-004",
                handId = "hand_primary",
                action = "PLACE_BET",
                wagerMinor = 4000L,
                currency = currency,
                correlationId = "corr-004"
            )
        )

        // Round crashes at 1.10x
        service.settleRoundCrash(
            SettleRoundCrashCommand(
                tenantId = tenantId,
                gameId = gameId,
                roundId = "rnd-004",
                crashMultiplier = BigDecimal("1.10")
            )
        )

        // Attempt cash-out after crash
        val cashOutAck = service.processCommand(
            AviatorRestCommand(
                tenantId = tenantId,
                principal = playerPrincipal,
                commandId = "cmd-cashout-004-late",
                roundId = "rnd-004",
                handId = "hand_primary",
                action = "CASH_OUT",
                correlationId = "corr-004-late"
            )
        )
        assertEquals(AviatorCommandAckStatus.REJECTED, cashOutAck.status)
        assertTrue(
            cashOutAck.rejection?.code in listOf(
                AviatorCommandRejectionCode.INVALID_PHASE,
                AviatorCommandRejectionCode.ROUND_CLOSED,
                AviatorCommandRejectionCode.INVALID_HAND_STATE
            )
        )

        // Player balance is 100000 - 4000 = 96000 (no late payout)
        assertEquals(96000L, ledgerService.store.findBalance(tenantId, "PLAYER:$playerIdStr", currency))
    }

    // =========================================================================
    // Scenario 5: round crash
    // =========================================================================

    @Test
    fun `scenario05 round crash settles remaining accepted bets as LOST with escrow sweep to house`() {
        seedRound("rnd-005", phase = GameRoundPhase.BET_COUNTDOWN)

        service.processCommand(
            AviatorRestCommand(
                tenantId = tenantId,
                principal = playerPrincipal,
                commandId = "cmd-bet-005",
                roundId = "rnd-005",
                handId = "hand_primary",
                action = "PLACE_BET",
                wagerMinor = 10000L,
                currency = currency,
                correlationId = "corr-005"
            )
        )

        val escrowBalanceBefore = ledgerService.store.findBalance(tenantId, "ESCROW:GAME:AVIATOR", currency)
        assertEquals(10000L, escrowBalanceBefore)

        // Round crash triggers once-only settlement of pending bets
        val crashResult = service.settleRoundCrash(
            SettleRoundCrashCommand(
                tenantId = tenantId,
                gameId = gameId,
                roundId = "rnd-005",
                crashMultiplier = BigDecimal("1.25")
            )
        )
        assertEquals(1, crashResult.settledBetsCount)

        // Verify bet status is LOST
        val bet = gameStore.findBet(tenantId, gameId, "rnd-005", playerIdStr, "hand_primary")
        assertNotNull(bet)
        assertEquals(GameBetStatus.LOST, bet.status)

        // Escrow has been swept to house revenue
        val escrowBalanceAfter = ledgerService.store.findBalance(tenantId, "ESCROW:GAME:AVIATOR", currency)
        assertEquals(0L, escrowBalanceAfter)
        val houseBalance = ledgerService.store.findBalance(tenantId, "HOUSE:GAME:AVIATOR", currency)
        assertEquals(10000L, houseBalance)

        // Re-invoking settleRoundCrash is idempotent and settles 0 additional bets
        val crashReplay = service.settleRoundCrash(
            SettleRoundCrashCommand(
                tenantId = tenantId,
                gameId = gameId,
                roundId = "rnd-005",
                crashMultiplier = BigDecimal("1.25")
            )
        )
        assertEquals(0, crashReplay.settledBetsCount)
    }

    // =========================================================================
    // Scenario 6: parallel hands
    // =========================================================================

    @Test
    fun `scenario06 parallel hands can be independently placed and settled concurrently`() {
        seedRound("rnd-006", phase = GameRoundPhase.BET_COUNTDOWN)

        // Bet on hand_primary: 3000
        val ackPrimary = service.processCommand(
            AviatorRestCommand(
                tenantId = tenantId,
                principal = playerPrincipal,
                commandId = "cmd-bet-p",
                roundId = "rnd-006",
                handId = "hand_primary",
                action = "PLACE_BET",
                wagerMinor = 3000L,
                currency = currency,
                correlationId = "corr-p"
            )
        )
        assertEquals(AviatorCommandAckStatus.ACCEPTED, ackPrimary.status)

        // Bet on hand_secondary: 5000
        val ackSecondary = service.processCommand(
            AviatorRestCommand(
                tenantId = tenantId,
                principal = playerPrincipal,
                commandId = "cmd-bet-s",
                roundId = "rnd-006",
                handId = "hand_secondary",
                action = "PLACE_BET",
                wagerMinor = 5000L,
                currency = currency,
                correlationId = "corr-s"
            )
        )
        assertEquals(AviatorCommandAckStatus.ACCEPTED, ackSecondary.status)

        assertEquals(92000L, ledgerService.store.findBalance(tenantId, "PLAYER:$playerIdStr", currency))

        // Advance to FLYING at 2.00x
        service.createOrUpdateRound(
            CreateOrUpdateRoundCommand(
                tenantId = tenantId,
                gameId = gameId,
                roundId = "rnd-006",
                phase = GameRoundPhase.FLYING,
                roundVersion = 2L,
                currentMultiplier = BigDecimal("2.00")
            )
        )

        // Cash out hand_primary: payout = 3000 * 2.00 = 6000
        val coPrimary = service.processCommand(
            AviatorRestCommand(
                tenantId = tenantId,
                principal = playerPrincipal,
                commandId = "cmd-co-p",
                roundId = "rnd-006",
                handId = "hand_primary",
                action = "CASH_OUT",
                correlationId = "corr-co-p"
            )
        )
        assertEquals(AviatorCommandAckStatus.ACCEPTED, coPrimary.status)
        assertEquals(6000L, coPrimary.result?.payoutMinor)

        // hand_secondary crashes with round
        service.settleRoundCrash(
            SettleRoundCrashCommand(
                tenantId = tenantId,
                gameId = gameId,
                roundId = "rnd-006",
                crashMultiplier = BigDecimal("2.10")
            )
        )

        val betP = gameStore.findBet(tenantId, gameId, "rnd-006", playerIdStr, "hand_primary")
        val betS = gameStore.findBet(tenantId, gameId, "rnd-006", playerIdStr, "hand_secondary")
        assertEquals(GameBetStatus.CASHED_OUT, betP?.status)
        assertEquals(GameBetStatus.LOST, betS?.status)

        // Balance = 100000 - 3000 - 5000 + 6000 = 98000
        assertEquals(98000L, ledgerService.store.findBalance(tenantId, "PLAYER:$playerIdStr", currency))
    }

    // =========================================================================
    // Scenario 7: insufficient funds
    // =========================================================================

    @Test
    fun `scenario07 wager fails if ledger balance is below requested amount and creates no bet record`() {
        seedRound("rnd-007", phase = GameRoundPhase.BET_COUNTDOWN)

        val brokePlayerUuid = UUID.fromString("33333333-3333-3333-3333-333333333333")
        val brokePlayerIdStr = brokePlayerUuid.toString()
        val brokePrincipal = AuthenticatedPrincipal(
            id = brokePlayerIdStr,
            tenantId = tenantId,
            kind = PrincipalKind.PLAYER,
            roles = setOf(AdminRole.SUPPORT)
        )

        registrationStore.players[brokePlayerUuid] = PlayerRegistrationRecord(
            playerId = brokePlayerUuid,
            tenantId = tenantId,
            emailHash = "email-hash-3",
            phoneHash = "phone-hash-3",
            maskedEmail = "b***@test.com",
            maskedPhone = "+1***9999",
            jurisdiction = "DEFAULT",
            riskScore = 0.0,
            mfaRequired = false,
            status = PlayerAccountStatus.ACTIVE,
            createdAt = now.minusSeconds(86400),
            updatedAt = now.minusSeconds(86400)
        )

        eligibilityStore.saveComplianceProfile(
            PlayerComplianceProfile(
                playerId = brokePlayerUuid,
                tenantId = tenantId,
                dateOfBirth = LocalDate.of(1995, 1, 1),
                kycStatus = KycComplianceStatus.VERIFIED,
                amlStatus = AmlComplianceStatus.CLEARED,
                jurisdiction = "DEFAULT",
                responsiblePlay = ResponsiblePlayProfile(
                    playerId = brokePlayerUuid,
                    selfExcluded = false,
                    singleWagerLimitMinor = 50000L,
                    dailyWagerLimitMinor = 200000L,
                    currentDailyWagerMinor = 0L
                )
            )
        )

        // Fund broke player with only 5,000 minor units
        ledgerService.postTransaction(
            PostTransactionCommand(
                principal = adminPrincipal,
                tenantId = tenantId,
                transactionReference = "TX-SEED-BROKE-FUNDS",
                currencyCode = currency,
                entries = listOf(
                    JournalEntryDraft("HOUSE:SEED", JournalEntryDirection.DEBIT, 5000L, currency),
                    JournalEntryDraft("PLAYER:$brokePlayerIdStr", JournalEntryDirection.CREDIT, 5000L, currency)
                ),
                idempotencyKey = "IDEM-SEED-BROKE-01",
                correlationId = "corr-broke",
                causationId = "caus-broke"
            )
        )

        // Request 20,000 minor units (within 50,000 single limit, but exceeds 5,000 balance)
        val placeCmd = AviatorRestCommand(
            tenantId = tenantId,
            principal = brokePrincipal,
            commandId = "cmd-bet-insufficient",
            roundId = "rnd-007",
            handId = "hand_primary",
            action = "PLACE_BET",
            wagerMinor = 20000L,
            currency = currency,
            correlationId = "corr-insufficient"
        )

        val ack = service.processCommand(placeCmd)
        assertEquals(AviatorCommandAckStatus.REJECTED, ack.status)
        assertEquals(AviatorCommandRejectionCode.INSUFFICIENT_BALANCE, ack.rejection?.code)

        // No bet record should exist
        val bet = gameStore.findBet(tenantId, gameId, "rnd-007", brokePlayerIdStr, "hand_primary")
        assertNull(bet)

        // Balance unchanged
        assertEquals(5000L, ledgerService.store.findBalance(tenantId, "PLAYER:$brokePlayerIdStr", currency))
    }

    // =========================================================================
    // Scenario 8: eligibility changes
    // =========================================================================

    @Test
    fun `scenario08 missing or restricted compliance evidence denies wager and enforces cumulative limits`() {
        seedRound("rnd-008", phase = GameRoundPhase.BET_COUNTDOWN)

        val otherPlayerId = UUID.fromString("22222222-2222-2222-2222-222222222222")
        val otherPrincipal = AuthenticatedPrincipal(
            id = otherPlayerId.toString(),
            tenantId = tenantId,
            kind = PrincipalKind.PLAYER,
            roles = setOf(AdminRole.SUPPORT)
        )

        registrationStore.players[otherPlayerId] = PlayerRegistrationRecord(
            playerId = otherPlayerId,
            tenantId = tenantId,
            emailHash = "email-hash-2",
            phoneHash = "phone-hash-2",
            maskedEmail = "o***@test.com",
            maskedPhone = "+1***5678",
            jurisdiction = "DEFAULT",
            riskScore = 0.0,
            mfaRequired = false,
            status = PlayerAccountStatus.ACTIVE,
            createdAt = now.minusSeconds(86400),
            updatedAt = now.minusSeconds(86400)
        )

        // 1. Missing compliance profile (BE-024) -> Rejection
        val noComplianceAck = service.processCommand(
            AviatorRestCommand(
                tenantId = tenantId,
                principal = otherPrincipal,
                commandId = "cmd-no-comp",
                roundId = "rnd-008",
                handId = "hand_primary",
                action = "PLACE_BET",
                wagerMinor = 1000L,
                currency = currency,
                correlationId = "c-no-comp"
            )
        )
        assertEquals(AviatorCommandAckStatus.REJECTED, noComplianceAck.status)
        assertEquals(AviatorCommandRejectionCode.INELIGIBLE, noComplianceAck.rejection?.code)

        // 2. Self-excluded player -> Rejection
        eligibilityStore.saveComplianceProfile(
            PlayerComplianceProfile(
                playerId = otherPlayerId,
                tenantId = tenantId,
                dateOfBirth = LocalDate.of(1990, 5, 5),
                responsiblePlay = ResponsiblePlayProfile(
                    playerId = otherPlayerId,
                    selfExcluded = true
                )
            )
        )
        val selfExcludedAck = service.processCommand(
            AviatorRestCommand(
                tenantId = tenantId,
                principal = otherPrincipal,
                commandId = "cmd-self-ex",
                roundId = "rnd-008",
                handId = "hand_primary",
                action = "PLACE_BET",
                wagerMinor = 1000L,
                currency = currency,
                correlationId = "c-self-ex"
            )
        )
        assertEquals(AviatorCommandAckStatus.REJECTED, selfExcludedAck.status)
        assertEquals(AviatorCommandRejectionCode.INELIGIBLE, selfExcludedAck.rejection?.code)

        // 3. Single wager limit exceeded
        val overSingleLimitAck = service.processCommand(
            AviatorRestCommand(
                tenantId = tenantId,
                principal = playerPrincipal,
                commandId = "cmd-over-single",
                roundId = "rnd-008",
                handId = "hand_primary",
                action = "PLACE_BET",
                wagerMinor = 60000L, // Limit is 50,000L
                currency = currency,
                correlationId = "c-over-single"
            )
        )
        assertEquals(AviatorCommandAckStatus.REJECTED, overSingleLimitAck.status)
        assertEquals(AviatorCommandRejectionCode.OUT_OF_LIMITS, overSingleLimitAck.rejection?.code)

        // 4. Daily cumulative limit enforced atomically
        // Player places 40,000 (accumulated = 40,000; daily limit = 200,000)
        val validBetAck = service.processCommand(
            AviatorRestCommand(
                tenantId = tenantId,
                principal = playerPrincipal,
                commandId = "cmd-valid-daily-1",
                roundId = "rnd-008",
                handId = "hand_primary",
                action = "PLACE_BET",
                wagerMinor = 40000L,
                currency = currency,
                correlationId = "c-valid-1"
            )
        )
        assertEquals(AviatorCommandAckStatus.ACCEPTED, validBetAck.status)

        // Check cumulative wager accumulated
        val usage = gameStore.findDailyAccumulatedWager(tenantId, playerIdStr, currency, "2026-09-25")
        assertEquals(40000L, usage)
    }

    // =========================================================================
    // Scenario 9: restart
    // =========================================================================

    @Test
    fun `scenario09 persistent state and command results survive service restart`() {
        seedRound("rnd-009", phase = GameRoundPhase.BET_COUNTDOWN)

        val betCmd = AviatorRestCommand(
            tenantId = tenantId,
            principal = playerPrincipal,
            commandId = "cmd-bet-009",
            roundId = "rnd-009",
            handId = "hand_primary",
            action = "PLACE_BET",
            wagerMinor = 1500L,
            currency = currency,
            correlationId = "corr-009"
        )
        val originalAck = service.processCommand(betCmd)
        assertEquals(AviatorCommandAckStatus.ACCEPTED, originalAck.status)

        // Simulate restart: construct new service instance with same persistent stores
        val restartedService = DurableGameWagerAndSettlementService(
            store = gameStore,
            ledgerService = ledgerService,
            registrationStore = registrationStore,
            eligibilityStore = eligibilityStore,
            adminPrincipal = adminPrincipal,
            clock = clock
        )

        // Exact command result lookup by roundId and commandId
        val recoveredAck = restartedService.getCommandResult(
            tenantId = tenantId,
            principal = playerPrincipal,
            roundId = "rnd-009",
            commandId = "cmd-bet-009"
        )
        assertNotNull(recoveredAck)
        assertEquals(originalAck.commandId, recoveredAck.commandId)
        assertEquals(originalAck.sequenceId, recoveredAck.sequenceId)
        assertEquals(originalAck.result?.accountMoneyAfterMinor, recoveredAck.result?.accountMoneyAfterMinor)
        assertEquals(originalAck.evidenceReference, recoveredAck.evidenceReference)

        // Replaying command on restarted service returns same result
        val replayedAck = restartedService.processCommand(betCmd)
        assertEquals(originalAck.commandId, replayedAck.commandId)
        assertEquals(originalAck.sequenceId, replayedAck.sequenceId)
    }

    // =========================================================================
    // Scenario 10: ledger failure
    // =========================================================================

    @Test
    fun `scenario10 ledger posting failure rolls back wager reservation transactionally`() {
        seedRound("rnd-010", phase = GameRoundPhase.BET_COUNTDOWN)

        // A mock/faulty ledger service that fails on postTransaction
        val failingLedgerService = object : LedgerPostingService(store = ledgerStore, clock = clock) {
            override fun postTransaction(command: PostTransactionCommand): com.slotting.admin.ledger.PostingResult {
                throw LedgerPostingException("SIMULATED_FAILURE", "Simulated ledger storage down")
            }
        }

        val serviceWithFailingLedger = DurableGameWagerAndSettlementService(
            store = gameStore,
            ledgerService = failingLedgerService,
            registrationStore = registrationStore,
            eligibilityStore = eligibilityStore,
            adminPrincipal = adminPrincipal,
            clock = clock
        )

        val betCmd = AviatorRestCommand(
            tenantId = tenantId,
            principal = playerPrincipal,
            commandId = "cmd-bet-010",
            roundId = "rnd-010",
            handId = "hand_primary",
            action = "PLACE_BET",
            wagerMinor = 2500L,
            currency = currency,
            correlationId = "corr-010"
        )

        val ack = serviceWithFailingLedger.processCommand(betCmd)
        assertEquals(AviatorCommandAckStatus.REJECTED, ack.status)

        // Verify no accepted bet persisted in store
        val bet = gameStore.findBet(tenantId, gameId, "rnd-010", playerIdStr, "hand_primary")
        assertNull(bet, "Bet record must NOT exist if ledger posting fails")

        // Verify no cumulative usage tracked
        val usage = gameStore.findDailyAccumulatedWager(tenantId, playerIdStr, currency, "2026-09-25")
        assertEquals(0L, usage)
    }

    // =========================================================================
    // Scenario 11: Schema Migration & Constraint Validation
    // =========================================================================

    @Test
    fun `scenario11 V28 migration script exists and specifies all authoritative constraints`() {
        val migrationFile = File("src/main/resources/db/migration/V28__durable_game_wager_and_settlement_authority.sql")
        assertTrue(migrationFile.exists(), "V28 migration file must exist")

        val sql = migrationFile.readText()
        assertTrue(sql.contains("create table if not exists game_authoritative_round"), "Must create game_authoritative_round")
        assertTrue(sql.contains("create table if not exists game_accepted_bet"), "Must create game_accepted_bet")
        assertTrue(sql.contains("create table if not exists game_bet_settlement"), "Must create game_bet_settlement")
        assertTrue(sql.contains("create table if not exists game_command_receipt"), "Must create game_command_receipt")
        assertTrue(sql.contains("unique (tenant_id, game_id, round_id, owner_id, hand_id)"), "Must enforce one bet per hand per round")
        assertTrue(sql.contains("unique (tenant_id, bet_id)"), "Must enforce once-only settlement")
        assertTrue(sql.contains("unique (tenant_id, command_id)"), "Must enforce command idempotency")
    }
}
