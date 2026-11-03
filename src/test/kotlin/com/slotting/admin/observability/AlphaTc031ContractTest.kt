package com.slotting.admin.observability

import com.slotting.admin.gameprovider.AviatorCommandAckResult
import com.slotting.admin.gameprovider.AviatorCommandAckStatus
import com.slotting.admin.gameprovider.AviatorRestCommand
import com.slotting.admin.gameprovider.CommandReceiptClaimResult
import com.slotting.admin.gameprovider.CreateOrUpdateRoundCommand
import com.slotting.admin.gameprovider.DurableGameWagerAndSettlementService
import com.slotting.admin.gameprovider.DurableGameWagerAndSettlementStore
import com.slotting.admin.gameprovider.FairnessSeedEnvelope
import com.slotting.admin.gameprovider.GameAcceptedBetRecord
import com.slotting.admin.gameprovider.JdbcFairnessEvidenceStore
import com.slotting.admin.gameprovider.ProvablyFairOutcomeAuthority
import com.slotting.admin.gameprovider.PublishCommitmentCommand
import com.slotting.admin.gameprovider.GameLifecycleOutcome
import com.slotting.admin.gameprovider.JdbcDurableGameWagerAndSettlementStore
import com.slotting.admin.gameprovider.JdbcGameLifecycleDiagnosticProjector
import com.slotting.admin.gameprovider.GameRoundPhase
import com.slotting.admin.gameprovider.SettleRoundCrashCommand
import com.slotting.admin.auth.AdminRole
import com.slotting.admin.auth.AuthenticatedPrincipal
import com.slotting.admin.auth.PrincipalKind
import com.slotting.admin.infra.PostgresIntegrationSupport
import com.slotting.admin.ledger.JdbcLedgerJournalStore
import com.slotting.admin.ledger.LedgerPostingService
import com.slotting.admin.identity.InMemoryServerEligibilityStore
import com.slotting.admin.identity.JdbcPlayerRegistrationStore
import java.math.BigDecimal
import java.sql.Timestamp
import java.time.Clock
import java.time.Instant
import java.time.LocalDate
import java.time.ZoneOffset
import java.util.UUID
import kotlin.test.assertEquals
import kotlin.test.assertNotNull
import kotlin.test.assertTrue
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.boot.test.context.SpringBootTest
import org.springframework.jdbc.core.JdbcTemplate
import org.springframework.test.context.DynamicPropertyRegistry
import org.springframework.test.context.DynamicPropertySource

@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.NONE)
class AlphaTc031ContractTest {
    companion object {
        @JvmStatic
        @DynamicPropertySource
        fun postgresProperties(registry: DynamicPropertyRegistry) {
            PostgresIntegrationSupport.configureProperties(registry)
        }
    }

    @Autowired
    private lateinit var jdbc: JdbcTemplate

    @Autowired
    private lateinit var txManager: org.springframework.transaction.PlatformTransactionManager

    private val now = Instant.parse("2026-10-31T10:00:00Z")
    private val clock = Clock.fixed(now, ZoneOffset.UTC)
    private val tenantId = "tenant-tc031"
    private val gameId = "AVIATOR"
    private val currency = "PKR"

    private lateinit var gameStore: JdbcDurableGameWagerAndSettlementStore
    private lateinit var ledgerService: LedgerPostingService
    private lateinit var projector: JdbcGameLifecycleDiagnosticProjector
    private lateinit var gameService: DurableGameWagerAndSettlementService
    private val eligibilityStore = InMemoryServerEligibilityStore()
    private lateinit var fairnessAuthority: ProvablyFairOutcomeAuthority

    class SimulatedFailpointException(message: String) : RuntimeException(message)

    class FailOnSaveBetStore(
        private val delegate: DurableGameWagerAndSettlementStore,
    ) : DurableGameWagerAndSettlementStore by delegate {
        var failSaveBet: Boolean = false
        override fun saveBet(bet: GameAcceptedBetRecord) {
            delegate.saveBet(bet)
            if (failSaveBet) throw SimulatedFailpointException("planned failpoint after reservation")
        }
    }

    private val failStore = lazy { FailOnSaveBetStore(JdbcDurableGameWagerAndSettlementStore(jdbc)) }

    private val adminPrincipal = AuthenticatedPrincipal(
        id = "admin-sys-tc031",
        tenantId = tenantId,
        kind = PrincipalKind.ADMIN,
        roles = setOf(AdminRole.SUPER_ADMIN),
    )

    @BeforeEach
    fun setUp() {
        clearTenantState()
        gameStore = JdbcDurableGameWagerAndSettlementStore(jdbc)
        ledgerService = LedgerPostingService(store = JdbcLedgerJournalStore(jdbc), clock = clock)
        projector = JdbcGameLifecycleDiagnosticProjector(JdbcDiagnosticEventStore(jdbc, clock), clock)
        fairnessAuthority = ProvablyFairOutcomeAuthority(
            store = JdbcFairnessEvidenceStore(jdbc),
            clock = clock,
            envelope = FairnessSeedEnvelope.devDefault(),
        )
        gameService = DurableGameWagerAndSettlementService(
            store = gameStore,
            ledgerService = ledgerService,
            registrationStore = JdbcPlayerRegistrationStore(jdbc),
            eligibilityStore = eligibilityStore,
            adminPrincipal = adminPrincipal,
            clock = clock,
            fairnessAuthority = fairnessAuthority,
            txManager = txManager,
            lifecycleDiagnostics = projector,
        )
    }

    @Test
    fun `TC-031-R4 a failing diagnostic store never breaks the financial flow`() {
        val throwingStore = object : DiagnosticEventStore {
            override fun save(tenantId: String, envelope: DiagnosticEventEnvelope): StoredDiagnosticEvent =
                error("diagnostic store unavailable")
            override fun find(tenantId: String, eventId: UUID): StoredDiagnosticEvent? = null
        }
        val failingProjector = JdbcGameLifecycleDiagnosticProjector(throwingStore, clock)
        val playerId = UUID.randomUUID()
        seedPlayer(playerId)
        seedFunds(playerId, 10_000L)
        val roundId = "round-tc031-r4"
        createRound(roundId)
        val failingService = DurableGameWagerAndSettlementService(
            store = gameStore,
            ledgerService = ledgerService,
            registrationStore = JdbcPlayerRegistrationStore(jdbc),
            eligibilityStore = eligibilityStore,
            adminPrincipal = adminPrincipal,
            clock = clock,
            fairnessAuthority = fairnessAuthority,
            txManager = txManager,
            lifecycleDiagnostics = failingProjector,
        )

        val ack = failingService.processCommand(
            AviatorRestCommand(
                tenantId = tenantId,
                principal = playerPrincipal(playerId),
                commandId = "cmd-r4-${UUID.randomUUID()}",
                roundId = roundId,
                handId = "hand_primary",
                action = "PLACE_BET",
                wagerMinor = 2_500L,
                currency = currency,
                correlationId = "corr-r4",
            )
        )
        assertEquals(AviatorCommandAckStatus.ACCEPTED, ack.status)
        flyRound(roundId)
        val settlement = failingService.settleRoundCrash(
            SettleRoundCrashCommand(tenantId, gameId, roundId, BigDecimal("1.5000"))
        )
        assertEquals(1, settlement.settledBetsCount)
        assertEquals(1, jdbc.queryForObject(
            "select count(*) from game_accepted_bet where tenant_id = ? and round_id = ?",
            Int::class.java,
            tenantId,
            roundId,
        ))
        assertEquals(1, jdbc.queryForObject(
            "select count(*) from ledger_leg where tenant_id = ? and account_reference = ? and amount_minor_units = 2500 and direction = 'CREDIT'",
            Int::class.java,
            tenantId,
            "ESCROW:GAME:$gameId",
        ))
        val settlementLedgerRef = jdbc.queryForObject(
            "select ledger_settlement_ref from game_bet_settlement where tenant_id = ? and round_id = ?",
            String::class.java,
            tenantId,
            roundId,
        )
        assertNotNull(settlementLedgerRef)
        assertEquals(1, jdbc.queryForObject(
            "select count(*) from ledger_transaction where tenant_id = ? and transaction_reference = ?",
            Int::class.java,
            tenantId,
            settlementLedgerRef,
        ))
    }

    @Test
    fun `TC-031-R1 accepted bet then crash settlement links request accept and settle with same identities`() {
        val playerId = UUID.randomUUID()
        seedPlayer(playerId)
        seedFunds(playerId, 10_000L)
        val roundId = "round-tc031-r1"
        createRound(roundId)

        val correlation = "corr-bet-r1-${UUID.randomUUID()}"
        val ack = gameService.processCommand(
            AviatorRestCommand(
                tenantId = tenantId,
                principal = playerPrincipal(playerId),
                commandId = "cmd-r1-${UUID.randomUUID()}",
                roundId = roundId,
                handId = "hand_primary",
                action = "PLACE_BET",
                wagerMinor = 2_500L,
                currency = currency,
                correlationId = correlation,
            )
        )
        assertEquals(AviatorCommandAckStatus.ACCEPTED, ack.status)
        flyRound(roundId)

        val settlement = gameService.settleRoundCrash(
            SettleRoundCrashCommand(
                tenantId = tenantId,
                gameId = gameId,
                roundId = roundId,
                crashMultiplier = BigDecimal("1.5000"),
            )
        )
        assertEquals(1, settlement.settledBetsCount)

        val accepted = queryEvents(correlation)
        assertEquals(1, accepted.count { it.second == "GAME_BET_ACCEPTED" })
        val acceptedRow = accepted.single { it.second == "GAME_BET_ACCEPTED" }
        assertEquals(roundId, acceptedRow.fourth)
        assertNotNull(acceptedRow.fifth)
        assertEquals(2_500L, acceptedRow.seventh)
        assertEquals(currency, acceptedRow.eighth)

        val crashEvents = queryEvents("corr-crash-$roundId")
        assertTrue(crashEvents.any { it.second == "GAME_ROUND_CRASHED" })
        val settled = crashEvents.single { it.second == "GAME_BET_SETTLED_CRASH" }
        assertEquals(roundId, settled.fourth)
        assertEquals(acceptedRow.fifth, settled.fifth)
        assertNotNull(settled.sixth)
        assertEquals(2_500L, settled.seventh)
        assertEquals(currency, settled.eighth)

        val bet = gameStore.findBetsForRoundForUpdate(tenantId, gameId, roundId).single()
        assertEquals(acceptedRow.fifth, bet.betId.toString())
        val settlementRecord = jdbc.queryForObject(
            "select ledger_settlement_ref from game_bet_settlement where tenant_id = ? and bet_id = ?",
            String::class.java,
            tenantId,
            bet.betId,
        )
        assertEquals(settled.sixth, settlementRecord)
    }

    @Test
    fun `TC-031-R2 rollback after planned reservation leaves no accepted event and records a safe failure`() {
        val playerId = UUID.randomUUID()
        seedPlayer(playerId)
        seedFunds(playerId, 10_000L)
        val roundId = "round-tc031-r2"
        createRound(roundId)

        val failingService = DurableGameWagerAndSettlementService(
            store = failStore.value,
            ledgerService = ledgerService,
            registrationStore = JdbcPlayerRegistrationStore(jdbc),
            eligibilityStore = eligibilityStore,
            adminPrincipal = adminPrincipal,
            clock = clock,
            txManager = txManager,
            lifecycleDiagnostics = projector,
        )
        failStore.value.failSaveBet = true
        val correlation = "corr-bet-r2-${UUID.randomUUID()}"
        val ack = failingService.processCommand(
            AviatorRestCommand(
                tenantId = tenantId,
                principal = playerPrincipal(playerId),
                commandId = "cmd-r2-${UUID.randomUUID()}",
                roundId = roundId,
                handId = "hand_primary",
                action = "PLACE_BET",
                wagerMinor = 2_500L,
                currency = currency,
                correlationId = correlation,
            )
        )
        assertEquals(AviatorCommandAckStatus.REJECTED, ack.status)
        failStore.value.failSaveBet = false

        assertEquals(0, queryEvents(correlation).count { it.second == "GAME_BET_ACCEPTED" })
        val failure = queryEvents(correlation).single { it.second == "GAME_PLACE_BET_FAILED" }
        assertEquals(GameLifecycleOutcome.FAILED.name, failure.third)
        assertTrue(!failure.ninth.contains("password", ignoreCase = true))
        assertEquals(0, jdbc.queryForObject(
            "select count(*) from game_accepted_bet where tenant_id = ? and round_id = ?",
            Int::class.java,
            tenantId,
            roundId,
        ))
        assertEquals(
            0L,
            jdbc.queryForObject(
                "select coalesce(sum(case when account_reference like 'ESCROW%' then amount_minor_units else 0 end), 0) from ledger_leg where tenant_id = ?",
                Long::class.java,
                tenantId,
            ),
        )
    }

    @Test
    fun `TC-031-R3 duplicate cash-out yields one success with replay evidence and late crash rejection is explicit`() {
        val playerOne = UUID.randomUUID()
        val playerTwo = UUID.randomUUID()
        seedPlayer(playerOne)
        seedPlayer(playerTwo)
        seedFunds(playerOne, 10_000L)
        seedFunds(playerTwo, 10_000L)
        val roundId = "round-tc031-r3"
        createRound(roundId)

        val commandId = "cmd-r3-cashout-${UUID.randomUUID()}"
        val betCorrelation = "corr-cashout-r3"
        val placeAck = gameService.processCommand(
            AviatorRestCommand(
                tenantId = tenantId,
                principal = playerPrincipal(playerOne),
                commandId = "cmd-place-r3-${UUID.randomUUID()}",
                roundId = roundId,
                handId = "hand_primary",
                action = "PLACE_BET",
                wagerMinor = 2_500L,
                currency = currency,
                correlationId = "corr-place-r3",
            )
        )
        assertEquals(AviatorCommandAckStatus.ACCEPTED, placeAck.status)
        val secondPlaceAck = gameService.processCommand(
            AviatorRestCommand(
                tenantId = tenantId,
                principal = playerPrincipal(playerTwo),
                commandId = "cmd-place2-r3-${UUID.randomUUID()}",
                roundId = roundId,
                handId = "hand_primary",
                action = "PLACE_BET",
                wagerMinor = 1_000L,
                currency = currency,
                correlationId = "corr-place2-r3",
            )
        )
        assertEquals(AviatorCommandAckStatus.ACCEPTED, secondPlaceAck.status)
        flyRound(roundId)

        val cashOutCommand = AviatorRestCommand(
            tenantId = tenantId,
            principal = playerPrincipal(playerOne),
            commandId = commandId,
            roundId = roundId,
            handId = "hand_primary",
            action = "CASH_OUT",
            currency = currency,
            correlationId = betCorrelation,
        )
        val cashOutAck = gameService.processCommand(cashOutCommand)
        assertEquals(AviatorCommandAckStatus.ACCEPTED, cashOutAck.status)
        val replayAck = gameService.processCommand(cashOutCommand)
        assertEquals(cashOutAck.commandId, replayAck.commandId)

        val events = queryEvents(betCorrelation)
        assertEquals(1, events.count { it.second == "GAME_CASH_OUT_ACCEPTED" })
        assertEquals(1, events.count { it.second == "GAME_CASH_OUT_REPLAYED" })
        assertEquals(
            1,
            jdbc.queryForObject(
                "select count(*) from game_bet_settlement where tenant_id = ? and round_id = ? and outcome = 'PAYOUT_CASH_OUT'",
                Int::class.java,
                tenantId,
                roundId,
            ),
        )

        gameService.settleRoundCrash(
            SettleRoundCrashCommand(
                tenantId = tenantId,
                gameId = gameId,
                roundId = roundId,
                crashMultiplier = BigDecimal("2.0000"),
            )
        )
        val lateCashOut = gameService.processCommand(
            AviatorRestCommand(
                tenantId = tenantId,
                principal = playerPrincipal(playerTwo),
                commandId = "cmd-late-r3-${UUID.randomUUID()}",
                roundId = roundId,
                handId = "hand_primary",
                action = "CASH_OUT",
                currency = currency,
                correlationId = "corr-late-r3",
            )
        )
        assertEquals(AviatorCommandAckStatus.REJECTED, lateCashOut.status)
        val rejectionEvents = queryEvents("corr-late-r3")
        assertEquals(1, rejectionEvents.count { it.second == "GAME_CASH_OUT_REJECTED" })
        assertEquals(
            1,
            jdbc.queryForObject(
                "select count(*) from game_bet_settlement where tenant_id = ? and round_id = ? and outcome = 'PAYOUT_CASH_OUT'",
                Int::class.java,
                tenantId,
                roundId,
            ),
        )
    }

    private fun queryEvents(correlationId: String): List<Septuple<String, String, String, String, String?, String?, Long, String, String>> {
        return jdbc.query(
            """
            select event_id,
                   event_type,
                   coalesce(payload_json->'context'->>'action', '') as outcome,
                   payload_json->>'roundId' as round_id,
                   payload_json->>'betId' as bet_id,
                   payload_json->>'ledgerId' as ledger_id,
                   coalesce((payload_json->>'amountMinorUnits')::bigint, 0) as amount_minor_units,
                   coalesce(payload_json->>'currency', '') as currency,
                   coalesce(payload_json->>'message', '') as message
            from diagnostic_event
            where tenant_id = ? and correlation_id = ?
            order by occurred_at, event_id
            """.trimIndent(),
            { rs, _ ->
                Septuple(
                    rs.getString("event_id"),
                    rs.getString("event_type"),
                    rs.getString("outcome"),
                    rs.getString("round_id"),
                    rs.getString("bet_id"),
                    rs.getString("ledger_id"),
                    rs.getLong("amount_minor_units"),
                    rs.getString("currency"),
                    rs.getString("message"),
                )
            },
            tenantId,
            correlationId,
        )
    }

    data class Septuple<A, B, C, D, E, F, G, H, I>(
        val first: A,
        val second: B,
        val third: C,
        val fourth: D,
        val fifth: E,
        val sixth: F,
        val seventh: G,
        val eighth: H,
        val ninth: I,
    )

    private fun clearTenantState() {
        jdbc.update("delete from game_fairness_audit where tenant_id = ?", tenantId)
        jdbc.update("delete from game_fairness_reveal where tenant_id = ?", tenantId)
        jdbc.update("delete from game_fairness_commitment where tenant_id = ?", tenantId)
        jdbc.update("delete from diagnostic_event where tenant_id = ?", tenantId)
        jdbc.update("delete from game_bet_settlement where tenant_id = ?", tenantId)
        jdbc.update("delete from game_accepted_bet where tenant_id = ?", tenantId)
        jdbc.update("delete from game_command_receipt where tenant_id = ?", tenantId)
        jdbc.update("delete from game_cumulative_player_limit where tenant_id = ?", tenantId)
        jdbc.update("delete from game_authoritative_round where tenant_id = ?", tenantId)
        jdbc.update("delete from ledger_leg where tenant_id = ?", tenantId)
        jdbc.update("delete from ledger_idempotency_receipt where tenant_id = ?", tenantId)
        jdbc.update("delete from ledger_transaction where tenant_id = ?", tenantId)
        jdbc.update("delete from admin_outbox_event where tenant_id = ?", tenantId)
        jdbc.update("delete from admin_audit_event where tenant_id = ?", tenantId)
        jdbc.update("delete from admin_operation where tenant_id = ?", tenantId)
        jdbc.update("delete from ledger_account where tenant_id = ?", tenantId)
        jdbc.update("delete from game_command_sequence where tenant_id = ?", tenantId)
        jdbc.update("delete from ledger_version_tracker where tenant_id = ?", tenantId)
    }

    private fun playerPrincipal(uuid: UUID) = AuthenticatedPrincipal(
        id = uuid.toString(),
        tenantId = tenantId,
        kind = PrincipalKind.PLAYER,
        roles = setOf(AdminRole.SUPPORT),
    )

    private fun seedPlayer(uuid: UUID) {
        jdbc.update(
            """
            insert into player_credential (
                player_id, tenant_id, identifier, password_hash, password_algo,
                password_salt, iterations, status, version, created_at, updated_at
            ) values (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            on conflict (tenant_id, identifier) do nothing
            """.trimIndent(),
            uuid, tenantId, uuid.toString(), "pbkdf2_sha256_hash", "pbkdf2_sha256", "salt", 10000, "ACTIVE", 1L,
            Timestamp.from(now.minusSeconds(86400)), Timestamp.from(now.minusSeconds(86400)),
        )
        eligibilityStore.saveComplianceProfile(
            com.slotting.admin.identity.PlayerComplianceProfile(
                playerId = uuid,
                tenantId = tenantId,
                dateOfBirth = LocalDate.of(1995, 5, 5),
                kycStatus = com.slotting.admin.identity.KycComplianceStatus.VERIFIED,
                amlStatus = com.slotting.admin.identity.AmlComplianceStatus.CLEARED,
                jurisdiction = "DEFAULT",
                responsiblePlay = com.slotting.admin.identity.ResponsiblePlayProfile(
                    playerId = uuid,
                    selfExcluded = false,
                    singleWagerLimitMinor = 500_000L,
                    dailyWagerLimitMinor = 2_000_000L,
                    currentDailyWagerMinor = 0L,
                ),
            )
        )
    }

    private fun seedFunds(uuid: UUID, amount: Long) {
        ledgerService.postTransaction(
            com.slotting.admin.ledger.PostTransactionCommand(
                principal = adminPrincipal,
                tenantId = tenantId,
                transactionReference = "TX-TC031-SEED-${UUID.randomUUID()}",
                currencyCode = currency,
                entries = listOf(
                    com.slotting.admin.ledger.JournalEntryDraft("HOUSE:SEED", com.slotting.admin.ledger.JournalEntryDirection.DEBIT, amount, currency),
                    com.slotting.admin.ledger.JournalEntryDraft("PLAYER:$uuid", com.slotting.admin.ledger.JournalEntryDirection.CREDIT, amount, currency),
                ),
                idempotencyKey = "IDEM-TC031-SEED-${UUID.randomUUID()}",
                correlationId = "corr-tc031-seed",
                causationId = "caus-tc031-seed",
            )
        )
    }

    private fun createRound(roundId: String) {
        gameService.createOrUpdateRound(
            CreateOrUpdateRoundCommand(
                tenantId = tenantId,
                gameId = gameId,
                roundId = roundId,
                phase = GameRoundPhase.BET_COUNTDOWN,
                roundVersion = 1L,
                currentMultiplier = BigDecimal("1.0000"),
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

    private fun flyRound(roundId: String) {
        gameService.createOrUpdateRound(
            CreateOrUpdateRoundCommand(
                tenantId = tenantId,
                gameId = gameId,
                roundId = roundId,
                phase = GameRoundPhase.FLYING,
                roundVersion = 2L,
                currentMultiplier = BigDecimal("1.2345"),
                crashMultiplier = BigDecimal("10.0000"),
            )
        )
    }
}
