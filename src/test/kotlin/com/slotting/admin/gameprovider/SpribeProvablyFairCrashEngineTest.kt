package com.slotting.admin.gameprovider

import com.slotting.admin.auth.AdminRole
import com.slotting.admin.auth.AuthenticatedPrincipal
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
import java.math.BigDecimal
import java.math.RoundingMode
import java.time.Clock
import java.time.Instant
import java.time.LocalDate
import java.time.ZoneOffset
import java.util.UUID
import kotlin.test.*

class SpribeProvablyFairCrashEngineTest {

    private val now = Instant.parse("2026-10-01T12:00:00Z")
    private val clock = Clock.fixed(now, ZoneOffset.UTC)
    private val tenantId = "tenant-spribe-01"
    private val gameId = "AVIATOR"

    private val adminPrincipal = AuthenticatedPrincipal(
        id = "admin-sys",
        tenantId = tenantId,
        kind = PrincipalKind.ADMIN,
        roles = setOf(AdminRole.SUPER_ADMIN),
    )

    private lateinit var fairnessStore: InMemoryFairnessEvidenceStore
    private lateinit var fairnessAuthority: ProvablyFairOutcomeAuthority
    private lateinit var gameStore: InMemoryDurableGameWagerAndSettlementStore
    private lateinit var ledgerStore: InMemoryLedgerJournalStore
    private lateinit var ledgerService: LedgerPostingService
    private lateinit var registrationStore: InMemoryPlayerRegistrationStore
    private lateinit var eligibilityStore: InMemoryServerEligibilityStore
    private lateinit var gameService: DurableGameWagerAndSettlementService

    private val player1 = UUID.fromString("11111111-1111-1111-1111-111111111111")
    private val player2 = UUID.fromString("22222222-2222-2222-2222-222222222222")
    private val player3 = UUID.fromString("33333333-3333-3333-3333-333333333333")
    private val player4 = UUID.fromString("44444444-4444-4444-4444-444444444444")

    @BeforeEach
    fun setUp() {
        fairnessStore = InMemoryFairnessEvidenceStore()
        fairnessAuthority = ProvablyFairOutcomeAuthority(store = fairnessStore, clock = clock)

        gameStore = InMemoryDurableGameWagerAndSettlementStore()
        ledgerStore = InMemoryLedgerJournalStore()
        ledgerService = LedgerPostingService(store = ledgerStore, clock = clock)
        registrationStore = InMemoryPlayerRegistrationStore()
        eligibilityStore = InMemoryServerEligibilityStore()

        gameService = DurableGameWagerAndSettlementService(
            store = gameStore,
            ledgerService = ledgerService,
            registrationStore = registrationStore,
            eligibilityStore = eligibilityStore,
            adminPrincipal = adminPrincipal,
            clock = clock,
            fairnessAuthority = fairnessAuthority,
            houseMaxRoundExposure = 50_000_000L, // 500,000 INR
        )

        listOf(player1, player2, player3, player4).forEach { pid ->
            registrationStore.players[pid] = PlayerRegistrationRecord(
                playerId = pid,
                tenantId = tenantId,
                emailHash = "hash-$pid",
                phoneHash = "phone-$pid",
                maskedEmail = "u***@test.com",
                maskedPhone = "+1***0000",
                jurisdiction = "DEFAULT",
                riskScore = 0.0,
                mfaRequired = false,
                status = PlayerAccountStatus.ACTIVE,
                createdAt = now.minusSeconds(86400),
                updatedAt = now.minusSeconds(86400),
            )

            eligibilityStore.saveComplianceProfile(
                PlayerComplianceProfile(
                    playerId = pid,
                    tenantId = tenantId,
                    dateOfBirth = LocalDate.of(1990, 1, 1),
                    kycStatus = KycComplianceStatus.VERIFIED,
                    amlStatus = AmlComplianceStatus.CLEARED,
                    jurisdiction = "DEFAULT",
                    responsiblePlay = ResponsiblePlayProfile(
                        playerId = pid,
                        selfExcluded = false,
                        singleWagerLimitMinor = 1_000_000L,
                        dailyWagerLimitMinor = 5_000_000L,
                        currentDailyWagerMinor = 0L,
                    ),
                )
            )

            ledgerService.postTransaction(
                PostTransactionCommand(
                    principal = adminPrincipal,
                    tenantId = tenantId,
                    transactionReference = "TX-SEED-$pid",
                    currencyCode = "INR",
                    entries = listOf(
                        JournalEntryDraft("HOUSE:SEED", JournalEntryDirection.DEBIT, 1_000_000L, "INR"),
                        JournalEntryDraft("PLAYER:$pid", JournalEntryDirection.CREDIT, 1_000_000L, "INR"),
                    ),
                    idempotencyKey = "IDEM-SEED-$pid",
                    correlationId = "corr-seed-$pid",
                    causationId = "caus-seed-$pid",
                )
            )
        }
    }

    // =========================================================================
    // 1. Cryptographic Protocol: 3-Client Seed Consensus & Standalone Verifier
    // =========================================================================

    @Test
    fun `standalone verifier reproduces multiplier deterministically without dependencies`() {
        val serverSeed = "d4e2a1b5c8f7e6d5c4b3a2f1e0d9c8b7a6f5e4d3c2b1a0f9e8d7c6b5a4f3e2d1"
        val cs1 = "client_seed_alpha_001"
        val cs2 = "client_seed_beta_002"
        val cs3 = "client_seed_gamma_003"

        // Dependency-free calculation
        val multiplier1 = IndependentFairnessVerifier.calculateCrashMultiplier(serverSeed, cs1, cs2, cs3)
        val verifier = IndependentFairnessVerifier()
        val multiplier2 = verifier.verify(serverSeed, cs1, cs2, cs3)
        val multiplier3 = verifier.verifyOutcome(serverSeed, cs1, cs2, cs3)

        assertEquals(multiplier1, multiplier2)
        assertEquals(multiplier1, multiplier3)
        assertTrue(multiplier1 >= BigDecimal("1.00"))
        assertEquals(2, multiplier1.scale())
    }

    @Test
    fun `instant bust condition produces exactly 1_00x multiplier`() {
        // Find or synthesize a combined hash where h % 100 < 3
        // h in [0, e - 1]. If h % 100 == 0, 1, or 2 -> instant crash 1.00x
        var foundBust = false
        var testSeed = 0
        while (!foundBust && testSeed < 10_000) {
            val serverSeed = "test_server_seed_$testSeed"
            val m = IndependentFairnessVerifier.calculateCrashMultiplier(serverSeed, "cs1", "cs2", "cs3")
            if (m.compareTo(BigDecimal("1.00")) == 0) {
                foundBust = true
                assertEquals(BigDecimal("1.00"), m)
            }
            testSeed++
        }
        assertTrue(foundBust, "Should encounter 3% instant bust within 10,000 iterations")
    }

    @Test
    fun `three distinct human players provide client seeds for round`() {
        val roundId = "rnd-spribe-001"
        fairnessAuthority.publishPreBetCommitment(
            PublishCommitmentCommand(
                tenantId = tenantId,
                gameId = gameId,
                roundId = roundId,
                publicSalt = "salt-$roundId",
            )
        )
        gameService.createOrUpdateRound(
            CreateOrUpdateRoundCommand(
                tenantId = tenantId,
                gameId = gameId,
                roundId = roundId,
                phase = GameRoundPhase.BET_COUNTDOWN,
            )
        )

        // Player 1 bets with seed1
        gameService.processCommand(
            AviatorRestCommand(
                tenantId = tenantId,
                principal = AuthenticatedPrincipal(player1.toString(), tenantId, PrincipalKind.PLAYER, emptySet()),
                commandId = "cmd-1",
                roundId = roundId,
                handId = "hand_primary",
                action = "PLACE_BET",
                wagerMinor = 1000L,
                correlationId = "corr-1",
                clientSeed = "seed-p1",
            )
        )

        // Player 2 bets with seed2
        gameService.processCommand(
            AviatorRestCommand(
                tenantId = tenantId,
                principal = AuthenticatedPrincipal(player2.toString(), tenantId, PrincipalKind.PLAYER, emptySet()),
                commandId = "cmd-2",
                roundId = roundId,
                handId = "hand_primary",
                action = "PLACE_BET",
                wagerMinor = 2000L,
                correlationId = "corr-2",
                clientSeed = "seed-p2",
            )
        )

        // Player 3 bets with seed3
        gameService.processCommand(
            AviatorRestCommand(
                tenantId = tenantId,
                principal = AuthenticatedPrincipal(player3.toString(), tenantId, PrincipalKind.PLAYER, emptySet()),
                commandId = "cmd-3",
                roundId = roundId,
                handId = "hand_primary",
                action = "PLACE_BET",
                wagerMinor = 3000L,
                correlationId = "corr-3",
                clientSeed = "seed-p3",
            )
        )

        // Player 4 bets (beyond the first 3) -> should not overwrite client seeds
        gameService.processCommand(
            AviatorRestCommand(
                tenantId = tenantId,
                principal = AuthenticatedPrincipal(player4.toString(), tenantId, PrincipalKind.PLAYER, emptySet()),
                commandId = "cmd-4",
                roundId = roundId,
                handId = "hand_primary",
                action = "PLACE_BET",
                wagerMinor = 4000L,
                correlationId = "corr-4",
                clientSeed = "seed-p4",
            )
        )

        val outcome = fairnessAuthority.deriveAuthoritativeOutcome(tenantId, gameId, roundId)
        assertEquals("seed-p1", outcome.clientSeed1)
        assertEquals("seed-p2", outcome.clientSeed2)
        assertEquals("seed-p3", outcome.clientSeed3)

        // Verify with standalone verifier
        val expectedMultiplier = IndependentFairnessVerifier.calculateCrashMultiplier(
            outcome.secretSeed, "seed-p1", "seed-p2", "seed-p3"
        )
        assertEquals(expectedMultiplier, outcome.multiplier)
    }

    @Test
    fun `fewer than 3 players deterministically fill fallback seeds`() {
        val roundId = "rnd-spribe-002"
        val commitment = fairnessAuthority.publishPreBetCommitment(
            PublishCommitmentCommand(
                tenantId = tenantId,
                gameId = gameId,
                roundId = roundId,
                publicSalt = "salt-$roundId",
            )
        )
        gameService.createOrUpdateRound(
            CreateOrUpdateRoundCommand(
                tenantId = tenantId,
                gameId = gameId,
                roundId = roundId,
                phase = GameRoundPhase.BET_COUNTDOWN,
            )
        )

        // Only Player 1 bets
        gameService.processCommand(
            AviatorRestCommand(
                tenantId = tenantId,
                principal = AuthenticatedPrincipal(player1.toString(), tenantId, PrincipalKind.PLAYER, emptySet()),
                commandId = "cmd-p1-only",
                roundId = roundId,
                handId = "hand_primary",
                action = "PLACE_BET",
                wagerMinor = 1000L,
                correlationId = "corr-p1",
                clientSeed = "p1-seed-custom",
            )
        )

        val outcome = fairnessAuthority.deriveAuthoritativeOutcome(tenantId, gameId, roundId)
        assertEquals("p1-seed-custom", outcome.clientSeed1)

        val expectedFallback2 = ProvablyFairOutcomeAuthority.sha256("${commitment.commitmentHash}:fallback:2:$roundId")
        val expectedFallback3 = ProvablyFairOutcomeAuthority.sha256("${commitment.commitmentHash}:fallback:3:$roundId")

        assertEquals(expectedFallback2, outcome.clientSeed2)
        assertEquals(expectedFallback3, outcome.clientSeed3)

        val expectedMultiplier = IndependentFairnessVerifier.calculateCrashMultiplier(
            outcome.secretSeed, "p1-seed-custom", expectedFallback2, expectedFallback3
        )
        assertEquals(expectedMultiplier, outcome.multiplier)
    }

    // =========================================================================
    // 2. House Risk & Exposure Guardrails
    // =========================================================================

    @Test
    fun `wager exceeding aggregate round liability cap is rejected with ROUND_CAPACITY_REACHED`() {
        val roundId = "rnd-exposure-001"
        fairnessAuthority.publishPreBetCommitment(
            PublishCommitmentCommand(tenantId = tenantId, gameId = gameId, roundId = roundId, publicSalt = "salt")
        )
        gameService.createOrUpdateRound(
            CreateOrUpdateRoundCommand(tenantId = tenantId, gameId = gameId, roundId = roundId, phase = GameRoundPhase.BET_COUNTDOWN)
        )

        // houseMaxRoundExposure is 50_000_000L (500,000 INR)
        // MAX_MULTIPLIER is 100.00
        // A wager of 600,000 minor units has liability 600,000 * 100 = 60,000,000 > 50,000,000
        val ack = gameService.processCommand(
            AviatorRestCommand(
                tenantId = tenantId,
                principal = AuthenticatedPrincipal(player1.toString(), tenantId, PrincipalKind.PLAYER, emptySet()),
                commandId = "cmd-heavy-bet",
                roundId = roundId,
                handId = "hand_primary",
                action = "PLACE_BET",
                wagerMinor = 600_000L,
                correlationId = "corr-heavy",
            )
        )

        assertEquals(AviatorCommandAckStatus.REJECTED, ack.status)
        assertEquals(AviatorCommandRejectionCode.ROUND_CAPACITY_REACHED, ack.rejection?.code)
    }

    @Test
    fun `cashout payout is capped at MAX_PAYOUT_PER_BET`() {
        val roundId = "rnd-maxwin-001"
        fairnessAuthority.publishPreBetCommitment(
            PublishCommitmentCommand(tenantId = tenantId, gameId = gameId, roundId = roundId, publicSalt = "salt")
        )
        gameService.createOrUpdateRound(
            CreateOrUpdateRoundCommand(
                tenantId = tenantId,
                gameId = gameId,
                roundId = roundId,
                phase = GameRoundPhase.BET_COUNTDOWN,
            )
        )

        // Place bet of 1000 minor units
        gameService.processCommand(
            AviatorRestCommand(
                tenantId = tenantId,
                principal = AuthenticatedPrincipal(player1.toString(), tenantId, PrincipalKind.PLAYER, emptySet()),
                commandId = "cmd-bet-maxwin",
                roundId = roundId,
                handId = "hand_primary",
                action = "PLACE_BET",
                wagerMinor = 1000L,
                correlationId = "corr-maxwin",
            )
        )

        // Transition to FLYING with a high currentMultiplier of 150.00x
        // MAX_PAYOUT_PER_BET is 100.00x, so payout should be capped at 1000 * 100 = 100,000
        gameService.createOrUpdateRound(
            CreateOrUpdateRoundCommand(
                tenantId = tenantId,
                gameId = gameId,
                roundId = roundId,
                phase = GameRoundPhase.FLYING,
                currentMultiplier = BigDecimal("150.0000"),
                crashMultiplier = BigDecimal("200.0000"),
            )
        )

        val cashOutAck = gameService.processCommand(
            AviatorRestCommand(
                tenantId = tenantId,
                principal = AuthenticatedPrincipal(player1.toString(), tenantId, PrincipalKind.PLAYER, emptySet()),
                commandId = "cmd-cashout-maxwin",
                roundId = roundId,
                handId = "hand_primary",
                action = "CASH_OUT",
                correlationId = "corr-cashout",
            )
        )

        assertEquals(AviatorCommandAckStatus.ACCEPTED, cashOutAck.status)
        assertEquals(100_000L, cashOutAck.result?.payoutMinor)
    }

    @Test
    fun `server tick authority rejects cashout if round crashed or current multiplier exceeds crash multiplier`() {
        val roundId = "rnd-tick-001"
        fairnessAuthority.publishPreBetCommitment(
            PublishCommitmentCommand(tenantId = tenantId, gameId = gameId, roundId = roundId, publicSalt = "salt")
        )
        gameService.createOrUpdateRound(
            CreateOrUpdateRoundCommand(
                tenantId = tenantId,
                gameId = gameId,
                roundId = roundId,
                phase = GameRoundPhase.BET_COUNTDOWN,
            )
        )

        gameService.processCommand(
            AviatorRestCommand(
                tenantId = tenantId,
                principal = AuthenticatedPrincipal(player1.toString(), tenantId, PrincipalKind.PLAYER, emptySet()),
                commandId = "cmd-bet-tick",
                roundId = roundId,
                handId = "hand_primary",
                action = "PLACE_BET",
                wagerMinor = 1000L,
                correlationId = "corr-tick",
            )
        )

        // Round has crash multiplier 2.00x but currentMultiplier has exceeded to 2.05x (race condition)
        gameService.createOrUpdateRound(
            CreateOrUpdateRoundCommand(
                tenantId = tenantId,
                gameId = gameId,
                roundId = roundId,
                phase = GameRoundPhase.FLYING,
                currentMultiplier = BigDecimal("2.0500"),
                crashMultiplier = BigDecimal("2.0000"),
            )
        )

        // Attempting to cash out must be rejected as round crashed
        val ack = gameService.processCommand(
            AviatorRestCommand(
                tenantId = tenantId,
                principal = AuthenticatedPrincipal(player1.toString(), tenantId, PrincipalKind.PLAYER, emptySet()),
                commandId = "cmd-cashout-late",
                roundId = roundId,
                handId = "hand_primary",
                action = "CASH_OUT",
                correlationId = "corr-late",
                cashOutMultiplier = 1.50, // Client attempts to supply its own multiplier
            )
        )

        assertEquals(AviatorCommandAckStatus.REJECTED, ack.status)
        assertEquals(AviatorCommandRejectionCode.ROUND_CLOSED, ack.rejection?.code)
    }
}
