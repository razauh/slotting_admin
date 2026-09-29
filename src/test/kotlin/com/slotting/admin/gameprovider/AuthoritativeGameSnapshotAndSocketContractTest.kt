package com.slotting.admin.gameprovider

import com.fasterxml.jackson.databind.ObjectMapper
import com.slotting.admin.auth.*
import com.slotting.admin.identity.*
import com.slotting.admin.ledger.*
import com.slotting.admin.wallet.*
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test
import java.io.File
import java.math.BigDecimal
import java.time.Clock
import java.time.Duration
import java.time.Instant
import java.time.LocalDate
import java.time.ZoneOffset
import java.util.UUID
import kotlin.test.*

/**
 * TC-023 Contract Test Suite:
 * Authoritative snapshots, command results, bounded history, and ordered socket events.
 *
 * Covers:
 * - BE-005: Snapshots fabricate independent financial/game state and independent sequence counters.
 * - XREP-001 / XREP-003: Consistent REST and socket read boundaries without divergent stores.
 *
 * 10 Required Test Scenarios:
 * 1. initial connect
 * 2. round advance
 * 3. lost ACK
 * 4. server restart
 * 5. event gap
 * 6. expired token
 * 7. different user
 * 8. no active round
 * 9. history bound
 * 10. fairness missing
 * 11. V30 schema validation
 */
class AuthoritativeGameSnapshotAndSocketContractTest {

    private val now = Instant.parse("2026-09-25T15:00:00Z")
    private val clock = Clock.fixed(now, ZoneOffset.UTC)
    private val tenantId = "tenant-pilot-001"
    private val gameId = "AVIATOR"
    private val player1Uuid = UUID.fromString("11111111-1111-1111-1111-111111111111")
    private val player1IdStr = player1Uuid.toString()
    private val player2Uuid = UUID.fromString("22222222-2222-2222-2222-222222222222")
    private val player2IdStr = player2Uuid.toString()
    private val currency = "INR"

    private val player1Principal = AuthenticatedPrincipal(
        id = player1IdStr,
        tenantId = tenantId,
        kind = PrincipalKind.PLAYER,
        roles = setOf(AdminRole.SUPPORT)
    )

    private val player2Principal = AuthenticatedPrincipal(
        id = player2IdStr,
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

    @BeforeEach
    fun setUp() {
        ledgerStore = InMemoryLedgerJournalStore()
        ledgerService = LedgerPostingService(store = ledgerStore, clock = clock)
        walletStore = InMemoryAuthoritativeWalletStore(ledgerStore = ledgerStore, clock = clock)
        walletService = AuthoritativeWalletService(store = walletStore, clock = clock)
        registrationStore = InMemoryPlayerRegistrationStore()
        eligibilityStore = InMemoryServerEligibilityStore()
        gameStore = InMemoryDurableGameWagerAndSettlementStore()

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
            clock = clock
        )

        // Seed player 1 registration
        registrationStore.players[player1Uuid] = PlayerRegistrationRecord(
            playerId = player1Uuid,
            tenantId = tenantId,
            emailHash = "email-hash-1",
            phoneHash = "phone-hash-1",
            maskedEmail = "p1***@test.com",
            maskedPhone = "+1***1111",
            jurisdiction = "DEFAULT",
            riskScore = 0.0,
            mfaRequired = false,
            status = PlayerAccountStatus.ACTIVE,
            createdAt = now.minusSeconds(86400),
            updatedAt = now.minusSeconds(86400)
        )

        // Seed player 2 registration
        registrationStore.players[player2Uuid] = PlayerRegistrationRecord(
            playerId = player2Uuid,
            tenantId = tenantId,
            emailHash = "email-hash-2",
            phoneHash = "phone-hash-2",
            maskedEmail = "p2***@test.com",
            maskedPhone = "+1***2222",
            jurisdiction = "DEFAULT",
            riskScore = 0.0,
            mfaRequired = false,
            status = PlayerAccountStatus.ACTIVE,
            createdAt = now.minusSeconds(86400),
            updatedAt = now.minusSeconds(86400)
        )

        // Seed compliance profile for player 1
        eligibilityStore.saveComplianceProfile(
            PlayerComplianceProfile(
                playerId = player1Uuid,
                tenantId = tenantId,
                dateOfBirth = LocalDate.of(1995, 1, 1),
                kycStatus = KycComplianceStatus.VERIFIED,
                amlStatus = AmlComplianceStatus.CLEARED,
                jurisdiction = "DEFAULT",
                responsiblePlay = ResponsiblePlayProfile(
                    playerId = player1Uuid,
                    selfExcluded = false,
                    singleWagerLimitMinor = 50000L,
                    dailyWagerLimitMinor = 200000L,
                    currentDailyWagerMinor = 0L
                )
            )
        )

        // Fund player 1 ledger balance with 75,000 INR minor units
        ledgerService.postTransaction(
            PostTransactionCommand(
                principal = adminPrincipal,
                tenantId = tenantId,
                transactionReference = "TX-SEED-P1-FUNDS",
                currencyCode = currency,
                entries = listOf(
                    JournalEntryDraft("HOUSE:SEED", JournalEntryDirection.DEBIT, 75000L, currency),
                    JournalEntryDraft("PLAYER:$player1IdStr", JournalEntryDirection.CREDIT, 75000L, currency)
                ),
                idempotencyKey = "IDEM-SEED-P1",
                correlationId = "corr-seed-p1",
                causationId = "caus-seed-p1"
            )
        )
    }

    // =========================================================================
    // Scenario 1: initial connect
    // =========================================================================

    @Test
    fun `scenario01 initial connect returns authoritative snapshot matching durable state and 0 for unfunded user`() {
        // Create active round with fairness commitment
        val roundId = "rnd-snap-001"
        gameService.createOrUpdateRound(
            CreateOrUpdateRoundCommand(
                tenantId = tenantId,
                gameId = gameId,
                roundId = roundId,
                phase = GameRoundPhase.BET_COUNTDOWN,
                roundVersion = 1L
            )
        )
        val commitment = fairnessAuthority.publishPreBetCommitment(
            PublishCommitmentCommand(
                tenantId = tenantId,
                gameId = gameId,
                roundId = roundId,
                publicSalt = "salt-001"
            )
        )

        // Player 1 connects: has 75,000 minor units
        val snapshotP1 = snapshotAndEventService.getAuthoritativeSnapshot(
            tenantId = tenantId,
            principal = player1Principal,
            gameId = gameId,
            roundId = roundId
        )
        assertEquals(roundId, snapshotP1.roundId)
        assertEquals("BET_COUNTDOWN", snapshotP1.phase)
        assertEquals(75000L, snapshotP1.user.balanceMinor)
        assertEquals(commitment.commitmentHash, snapshotP1.serverSeedHash)
        assertFalse(snapshotP1.primaryHand.betted)
        assertFalse(snapshotP1.secondaryHand.betted)

        // Player 2 connects: has 0 minor units (BE-005: never 500,000!)
        val snapshotP2 = snapshotAndEventService.getAuthoritativeSnapshot(
            tenantId = tenantId,
            principal = player2Principal,
            gameId = gameId,
            roundId = roundId
        )
        assertEquals(0L, snapshotP2.user.balanceMinor, "Unfunded player must have 0 balance, never fabricated 500,000")
        assertEquals(emptyList(), snapshotP2.history, "History must be empty when no rounds have completed")
    }

    // =========================================================================
    // Scenario 2: round advance
    // =========================================================================

    @Test
    fun `scenario02 round advance emits ordered socket events with monotonic sequences and updates snapshot`() {
        val roundId = "rnd-snap-002"
        gameService.createOrUpdateRound(
            CreateOrUpdateRoundCommand(
                tenantId = tenantId,
                gameId = gameId,
                roundId = roundId,
                phase = GameRoundPhase.BET_COUNTDOWN,
                roundVersion = 1L
            )
        )
        fairnessAuthority.publishPreBetCommitment(
            PublishCommitmentCommand(tenantId = tenantId, gameId = gameId, roundId = roundId, publicSalt = "salt-002")
        )

        // Advance to FLYING at 1.50x
        val event1 = snapshotAndEventService.recordAndBroadcastGameState(
            tenantId = tenantId,
            gameId = gameId,
            roundId = roundId,
            phase = GameRoundPhase.FLYING,
            multiplier = BigDecimal("1.50"),
            roundVersion = 2L,
            elapsedFlightSeconds = 2.0
        )
        assertEquals(1L, event1.sequenceId)
        assertEquals("gameState", event1.eventName)

        // Advance to FLYING at 2.10x
        val event2 = snapshotAndEventService.recordAndBroadcastGameState(
            tenantId = tenantId,
            gameId = gameId,
            roundId = roundId,
            phase = GameRoundPhase.FLYING,
            multiplier = BigDecimal("2.10"),
            roundVersion = 3L,
            elapsedFlightSeconds = 4.0
        )
        assertEquals(2L, event2.sequenceId)
        assertTrue(event2.sequenceId > event1.sequenceId, "Sequence IDs must be strictly monotonic")

        // Snapshot reflects latest phase and multiplier
        val snapshot = snapshotAndEventService.getAuthoritativeSnapshot(
            tenantId = tenantId,
            principal = player1Principal,
            gameId = gameId,
            roundId = roundId
        )
        assertEquals("FLYING", snapshot.phase)
        assertEquals(2.10, snapshot.multiplier)
        assertEquals(2L, snapshot.sequenceId)
        assertEquals(3L, snapshot.roundVersion)
    }

    // =========================================================================
    // Scenario 3: lost ACK
    // =========================================================================

    @Test
    fun `scenario03 lost ACK recovery returns exact cached result from durable receipt`() {
        val roundId = "rnd-snap-003"
        gameService.createOrUpdateRound(
            CreateOrUpdateRoundCommand(tenantId = tenantId, gameId = gameId, roundId = roundId, phase = GameRoundPhase.BET_COUNTDOWN)
        )
        fairnessAuthority.publishPreBetCommitment(
            PublishCommitmentCommand(tenantId = tenantId, gameId = gameId, roundId = roundId, publicSalt = "salt-003")
        )

        val betCmd = AviatorRestCommand(
            tenantId = tenantId,
            principal = player1Principal,
            commandId = "cmd-lost-ack-01",
            roundId = roundId,
            handId = "hand_primary",
            action = "PLACE_BET",
            wagerMinor = 5000L,
            currency = currency,
            correlationId = "corr-lost-ack"
        )

        // Command processed on server
        val originalAck = gameService.processCommand(betCmd)
        assertEquals(AviatorCommandAckStatus.ACCEPTED, originalAck.status)

        // Client lost the response and queries exact command result endpoint
        val recoveredAck = snapshotAndEventService.getCommandResult(
            tenantId = tenantId,
            principal = player1Principal,
            gameId = gameId,
            roundId = roundId,
            commandId = "cmd-lost-ack-01"
        )

        assertNotNull(recoveredAck)
        assertEquals(originalAck.commandId, recoveredAck.commandId)
        assertEquals(originalAck.sequenceId, recoveredAck.sequenceId)
        assertEquals(originalAck.status, recoveredAck.status)
        assertEquals(originalAck.result?.accountMoneyAfterMinor, recoveredAck.result?.accountMoneyAfterMinor)
    }

    // =========================================================================
    // Scenario 4: server restart
    // =========================================================================

    @Test
    fun `scenario04 persistent state survives service restart with consistent sequence checkpoints`() {
        val roundId = "rnd-snap-004"
        gameService.createOrUpdateRound(
            CreateOrUpdateRoundCommand(tenantId = tenantId, gameId = gameId, roundId = roundId, phase = GameRoundPhase.BET_COUNTDOWN)
        )
        fairnessAuthority.publishPreBetCommitment(
            PublishCommitmentCommand(tenantId = tenantId, gameId = gameId, roundId = roundId, publicSalt = "salt-004")
        )

        snapshotAndEventService.recordAndBroadcastGameState(
            tenantId = tenantId,
            gameId = gameId,
            roundId = roundId,
            phase = GameRoundPhase.FLYING,
            multiplier = BigDecimal("1.75"),
            roundVersion = 2L,
            elapsedFlightSeconds = 3.0
        )

        // Simulate server restart: create fresh service instance backed by same stores
        val restartedService = AuthoritativeGameSnapshotAndEventService(
            gameStore = gameStore,
            gameService = gameService,
            walletService = walletService,
            ledgerStore = ledgerStore,
            fairnessStore = fairnessStore,
            eventJournalStore = eventJournalStore,
            registrationStore = registrationStore,
            clock = clock
        )

        val snapshot = restartedService.getAuthoritativeSnapshot(
            tenantId = tenantId,
            principal = player1Principal,
            gameId = gameId,
            roundId = roundId
        )

        assertEquals(roundId, snapshot.roundId)
        assertEquals("FLYING", snapshot.phase)
        assertEquals(1.75, snapshot.multiplier)
        assertEquals(1L, snapshot.sequenceId)
    }

    // =========================================================================
    // Scenario 5: event gap
    // =========================================================================

    @Test
    fun `scenario05 event gap returns missed frames or forces resnapshot if gap exceeds retention`() {
        val roundId = "rnd-snap-005"
        gameService.createOrUpdateRound(
            CreateOrUpdateRoundCommand(tenantId = tenantId, gameId = gameId, roundId = roundId, phase = GameRoundPhase.FLYING)
        )

        // Emit events with sequence 1..5
        for (i in 1..5) {
            snapshotAndEventService.recordAndBroadcastGameState(
                tenantId = tenantId,
                gameId = gameId,
                roundId = roundId,
                phase = GameRoundPhase.FLYING,
                multiplier = BigDecimal("1.00").add(BigDecimal("0.10").multiply(BigDecimal(i))),
                roundVersion = i.toLong(),
                elapsedFlightSeconds = i.toDouble()
            )
        }

        // Client reconnects having missed sequences 3..5 (last seen = 2)
        val resumeResult = snapshotAndEventService.resumeEvents(
            tenantId = tenantId,
            gameId = gameId,
            lastSeenSequenceId = 2L,
            maxGapLimit = 10
        )
        assertTrue(resumeResult is SocketResumeOutcome.EventsReplayed)
        assertEquals(3, (resumeResult as SocketResumeOutcome.EventsReplayed).events.size)
        assertEquals(listOf(3L, 4L, 5L), resumeResult.events.map { it.sequenceId })

        // Client reconnects with ancient sequence exceeding gap limit
        val exceededResult = snapshotAndEventService.resumeEvents(
            tenantId = tenantId,
            gameId = gameId,
            lastSeenSequenceId = 0L,
            maxGapLimit = 2 // Buffer limit is 2, but gap is 5
        )
        assertTrue(exceededResult is SocketResumeOutcome.ResnapshotRequired)
    }

    // =========================================================================
    // Scenario 6: expired token
    // =========================================================================

    @Test
    fun `scenario06 expired or invalid session token fails closed`() {
        val ex = assertFailsWith<AuthenticationFailure.Rejected> {
            snapshotAndEventService.authenticateSession(
                tenantId = tenantId,
                rawSessionToken = "expired-token-12345"
            )
        }
        assertEquals(AuthErrorCode.UNAUTHENTICATED, ex.code)
    }

    // =========================================================================
    // Scenario 7: different user
    // =========================================================================

    @Test
    fun `scenario07 cross-owner access is denied and private events are partitioned`() {
        val roundId = "rnd-snap-007"
        gameService.createOrUpdateRound(
            CreateOrUpdateRoundCommand(tenantId = tenantId, gameId = gameId, roundId = roundId, phase = GameRoundPhase.BET_COUNTDOWN)
        )

        // Player 1 attempts to query snapshot for Player 2
        val ex = assertFailsWith<AuthenticationFailure.Rejected> {
            snapshotAndEventService.getAuthoritativeSnapshotForOwner(
                tenantId = tenantId,
                principal = player1Principal,
                targetOwnerId = player2IdStr,
                gameId = gameId,
                roundId = roundId
            )
        }
        assertEquals(AuthErrorCode.FORBIDDEN, ex.code)

        // Verify room partitioning: private events for player 1 are not visible in player 2's subscription
        val roomP1 = snapshotAndEventService.getPrivatePlayerRoom(tenantId, player1IdStr)
        val roomP2 = snapshotAndEventService.getPrivatePlayerRoom(tenantId, player2IdStr)
        assertNotEquals(roomP1, roomP2)
    }

    // =========================================================================
    // Scenario 8: no active round
    // =========================================================================

    @Test
    fun `scenario08 bootstrap and snapshot without active round return null and never synthesize fake state`() {
        // No round created in database
        val bootstrap = snapshotAndEventService.getBootstrap(tenantId = tenantId, gameId = gameId)
        assertNull(bootstrap.activeRoundId, "Must be null when no active round exists")
        assertNull(bootstrap.phase, "Must be null when no active round exists")

        val snapshot = snapshotAndEventService.getAuthoritativeSnapshot(
            tenantId = tenantId,
            principal = player1Principal,
            gameId = gameId,
            roundId = null
        )
        assertNull(snapshot.roundId)
        assertEquals("NONE", snapshot.phase)
        assertEquals(1.00, snapshot.multiplier)
        assertFalse(snapshot.primaryHand.betted)
        assertFalse(snapshot.secondaryHand.betted)
    }

    // =========================================================================
    // Scenario 9: history bound
    // =========================================================================

    @Test
    fun `scenario09 round history returns bounded results from durable crashed rounds in reverse chronological order`() {
        // Seed 3 completed crashed rounds
        for (i in 1..3) {
            val rId = "rnd-hist-$i"
            gameService.createOrUpdateRound(
                CreateOrUpdateRoundCommand(
                    tenantId = tenantId,
                    gameId = gameId,
                    roundId = rId,
                    phase = GameRoundPhase.CRASHED,
                    crashMultiplier = BigDecimal("1.$i" + "0")
                )
            )
        }

        val history = snapshotAndEventService.getRoundHistory(tenantId = tenantId, gameId = gameId, limit = 2)
        assertEquals(2, history.size, "Must respect requested limit")
        assertEquals("rnd-hist-3", history[0].roundId)
        assertEquals(1.30, history[0].crashMultiplier)
        assertEquals("rnd-hist-2", history[1].roundId)
        assertEquals(1.20, history[1].crashMultiplier)
    }

    // =========================================================================
    // Scenario 10: fairness missing
    // =========================================================================

    @Test
    fun `scenario10 round without fairness commitment returns empty serverSeedHash and never synthesizes a hash`() {
        val roundId = "rnd-nofair-010"
        gameService.createOrUpdateRound(
            CreateOrUpdateRoundCommand(
                tenantId = tenantId,
                gameId = gameId,
                roundId = roundId,
                phase = GameRoundPhase.BET_COUNTDOWN
            )
        )
        // No commitment published!

        val snapshot = snapshotAndEventService.getAuthoritativeSnapshot(
            tenantId = tenantId,
            principal = player1Principal,
            gameId = gameId,
            roundId = roundId
        )

        assertEquals("", snapshot.serverSeedHash, "Must not synthesize fake hash like sha256('seed:roundId')")
    }

    // =========================================================================
    // Scenario 11: Schema Migration & Constraints Validation
    // =========================================================================

    @Test
    fun `scenario11 V30 migration script exists and specifies event checkpoint constraints`() {
        val migrationFile = File("src/main/resources/db/migration/V30__authoritative_game_snapshot_and_event_checkpoint.sql")
        assertTrue(migrationFile.exists(), "V30 migration file must exist")

        val sql = migrationFile.readText()
        assertTrue(sql.contains("create table if not exists game_socket_sequence_checkpoint"), "Must create game_socket_sequence_checkpoint")
        assertTrue(sql.contains("create table if not exists game_event_journal"), "Must create game_event_journal")
        assertTrue(sql.contains("unique (tenant_id, game_id, sequence_id)"), "Must enforce sequence uniqueness")
    }
}
