package com.slotting.admin.gameprovider

import com.slotting.admin.auth.AdminRole
import com.slotting.admin.auth.AuthenticatedPrincipal
import com.slotting.admin.auth.PrincipalKind
import com.slotting.admin.identity.AmlComplianceStatus
import com.slotting.admin.identity.JdbcPlayerRegistrationStore
import com.slotting.admin.identity.KycComplianceStatus
import com.slotting.admin.identity.PlayerComplianceProfile
import com.slotting.admin.identity.ResponsiblePlayProfile
import com.slotting.admin.identity.ServerEligibilityStore
import com.slotting.admin.infra.PostgresIntegrationSupport
import com.slotting.admin.ledger.JdbcLedgerJournalStore
import com.slotting.admin.ledger.JournalEntryDirection
import com.slotting.admin.ledger.JournalEntryDraft
import com.slotting.admin.ledger.LedgerPostingService
import com.slotting.admin.ledger.PostTransactionCommand
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.boot.test.context.SpringBootTest
import org.springframework.jdbc.core.JdbcTemplate
import org.springframework.test.context.DynamicPropertyRegistry
import org.springframework.test.context.DynamicPropertySource
import org.springframework.transaction.PlatformTransactionManager
import java.math.BigDecimal
import java.math.RoundingMode
import java.sql.Timestamp
import java.time.Clock
import java.time.Instant
import java.time.LocalDate
import java.time.ZoneOffset
import java.util.UUID
import kotlin.test.assertEquals

@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.NONE)
class Tc006BaselineRedReproductionTest {

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
    private lateinit var txManager: PlatformTransactionManager

    private val now = Instant.parse("2026-10-05T10:00:00Z")
    private val clock = Clock.fixed(now, ZoneOffset.UTC)
    private val tenantId = "tenant-tc006-baseline-red"
    private val gameId = "AVIATOR"
    private val playerUuid = UUID.randomUUID()
    private val playerIdStr = playerUuid.toString()

    private val adminPrincipal = AuthenticatedPrincipal(
        id = "admin-sys-tc006",
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

    private lateinit var gameStore: JdbcDurableGameWagerAndSettlementStore
    private lateinit var ledgerStore: JdbcLedgerJournalStore
    private lateinit var registrationStore: JdbcPlayerRegistrationStore
    private lateinit var eligibilityStore: ServerEligibilityStore
    private lateinit var ledgerService: LedgerPostingService
    private lateinit var gameService: DurableGameWagerAndSettlementService

    @BeforeEach
    fun setUp() {
        jdbc.update("delete from game_bet_settlement where tenant_id = ?", tenantId)
        jdbc.update("delete from game_accepted_bet where tenant_id = ?", tenantId)
        jdbc.update("delete from game_command_receipt where tenant_id = ?", tenantId)
        jdbc.update("delete from game_cumulative_player_limit where tenant_id = ?", tenantId)
        jdbc.update("delete from game_authoritative_round where tenant_id = ?", tenantId)
        jdbc.update("delete from ledger_leg where tenant_id = ?", tenantId)
        jdbc.update("delete from ledger_idempotency_receipt where tenant_id = ?", tenantId)
        jdbc.update("delete from ledger_transaction where tenant_id = ?", tenantId)
        jdbc.update("delete from ledger_account where tenant_id = ?", tenantId)
        jdbc.update("delete from ledger_version_tracker where tenant_id = ?", tenantId)

        gameStore = JdbcDurableGameWagerAndSettlementStore(jdbc)
        ledgerStore = JdbcLedgerJournalStore(jdbc)
        registrationStore = JdbcPlayerRegistrationStore(jdbc)
        eligibilityStore = com.slotting.admin.identity.InMemoryServerEligibilityStore()
        ledgerService = LedgerPostingService(store = ledgerStore, clock = clock)
        gameService = DurableGameWagerAndSettlementService(
            store = gameStore,
            ledgerService = ledgerService,
            registrationStore = registrationStore,
            eligibilityStore = eligibilityStore,
            adminPrincipal = adminPrincipal,
            clock = clock,
            txManager = txManager,
        )

        jdbc.update(
            """
            insert into player_credential (
                player_id, tenant_id, identifier, password_hash, password_algo,
                password_salt, iterations, status, version, created_at, updated_at
            ) values (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            on conflict (tenant_id, identifier) do nothing
            """.trimIndent(),
            playerUuid,
            tenantId,
            playerIdStr,
            "pbkdf2_sha256_hash",
            "pbkdf2_sha256",
            "salt",
            10000,
            "ACTIVE",
            1L,
            Timestamp.from(now.minusSeconds(86400)),
            Timestamp.from(now.minusSeconds(86400))
        )

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
                    singleWagerLimitMinor = 500000L,
                    dailyWagerLimitMinor = 2000000L,
                    currentDailyWagerMinor = 0L
                )
            )
        )
    }

    private fun seedFunds(amount: Long) {
        ledgerService.postTransaction(
            PostTransactionCommand(
                principal = adminPrincipal,
                tenantId = tenantId,
                transactionReference = "TX-RED-SEED-${UUID.randomUUID()}",
                currencyCode = "INR",
                entries = listOf(
                    JournalEntryDraft("HOUSE:SEED", JournalEntryDirection.DEBIT, amount, "INR"),
                    JournalEntryDraft("PLAYER:$playerIdStr", JournalEntryDirection.CREDIT, amount, "INR"),
                ),
                idempotencyKey = "IDEM-RED-SEED-${UUID.randomUUID()}",
                correlationId = "corr-red-seed",
                causationId = "caus-red-seed",
            )
        )
    }

    private fun createRound(
        roundId: String,
        phase: GameRoundPhase = GameRoundPhase.BET_COUNTDOWN,
        version: Long = 1L,
        multiplier: BigDecimal = BigDecimal("1.0000"),
    ) {
        gameService.createOrUpdateRound(
            CreateOrUpdateRoundCommand(
                tenantId = tenantId,
                gameId = gameId,
                roundId = roundId,
                phase = phase,
                roundVersion = version,
                currentMultiplier = multiplier,
            )
        )
    }

    class LockOrderTracingStore(
        private val delegate: DurableGameWagerAndSettlementStore,
        val events: MutableList<Pair<String, Int>> = mutableListOf(),
    ) : DurableGameWagerAndSettlementStore by delegate {
        override fun findReceipt(tenantId: String, commandId: String): GameCommandReceiptRecord? {
            events.add("RECEIPT_READ" to 1)
            return delegate.findReceipt(tenantId, commandId)
        }

        override fun saveReceipt(receipt: GameCommandReceiptRecord) {
            events.add("RECEIPT_WRITE" to 1)
            delegate.saveReceipt(receipt)
        }

        override fun findRoundForShare(tenantId: String, gameId: String, roundId: String): GameRoundRecord? {
            events.add("ROUND_SHARED" to 2)
            return delegate.findRoundForShare(tenantId, gameId, roundId)
        }

        override fun findBet(tenantId: String, gameId: String, roundId: String, ownerId: String, handId: String): GameAcceptedBetRecord? {
            events.add("BET" to 3)
            return delegate.findBet(tenantId, gameId, roundId, ownerId, handId)
        }

        override fun nextSequenceId(tenantId: String): Long {
            val seq = delegate.nextSequenceId(tenantId)
            events.add("SEQUENCE_COUNTER" to 5)
            return seq
        }
    }

    @Test
    fun `RED baseline place bet emits a random idempotency key instead of the deterministic command key`() {
        seedFunds(50000L)
        val roundId = "rnd-red-deterministic-key"
        createRound(roundId)

        val ack = gameService.processCommand(
            AviatorRestCommand(
                tenantId = tenantId,
                principal = playerPrincipal,
                commandId = "cmd-red-deterministic-key",
                roundId = roundId,
                handId = "hand_primary",
                action = "PLACE_BET",
                wagerMinor = 60L,
                currency = "INR",
                correlationId = "corr-red-deterministic-key",
            )
        )
        assertEquals(AviatorCommandAckStatus.ACCEPTED, ack.status)

        val storedIdempotencyKey = jdbc.queryForObject(
            "select idempotency_key from ledger_transaction where tenant_id = ? and transaction_reference like 'TX-WAGER-%'",
            String::class.java,
            tenantId,
        )
        val expectedDeterministicKey = "bet:$tenantId:$gameId:$roundId:$playerIdStr:hand_primary"
        assertEquals(
            expectedDeterministicKey,
            storedIdempotencyKey,
            "TC-006 requires the place-bet ledger idempotency key to be the stable deterministic command key",
        )
    }

    @Test
    fun `RED baseline place bet claims the receipt after round and bet locks instead of receipt first`() {
        seedFunds(50000L)
        val roundId = "rnd-red-lock-order"
        createRound(roundId)

        val tracing = LockOrderTracingStore(gameStore)
        val tracingService = DurableGameWagerAndSettlementService(
            store = tracing,
            ledgerService = ledgerService,
            registrationStore = registrationStore,
            eligibilityStore = eligibilityStore,
            adminPrincipal = adminPrincipal,
            clock = clock,
            txManager = txManager,
        )

        val ack = tracingService.processCommand(
            AviatorRestCommand(
                tenantId = tenantId,
                principal = playerPrincipal,
                commandId = "cmd-red-lock-order",
                roundId = roundId,
                handId = "hand_primary",
                action = "PLACE_BET",
                wagerMinor = 60L,
                currency = "INR",
                correlationId = "corr-red-lock-order",
            )
        )
        assertEquals(AviatorCommandAckStatus.ACCEPTED, ack.status)

        val lockEvents = tracing.events.filter {
            it.first == "RECEIPT_WRITE" || it.first == "ROUND_SHARED" || it.first == "BET" || it.first == "SEQUENCE_COUNTER"
        }
        assertEquals(
            "RECEIPT_WRITE",
            lockEvents.firstOrNull()?.first,
            "TC-006 requires receipt -> round -> bet -> sequence lock order; baseline claims the receipt last: ${tracing.events}",
        )
    }

    @Test
    fun `RED baseline schema cannot represent a transaction private pending claim`() {
        val commandId = "cmd-red-pending"
        val receiptId = UUID.randomUUID()
        jdbc.update(
            """
            insert into game_command_receipt (
                receipt_id, tenant_id, owner_id, game_id, command_id, round_id, hand_id,
                action, status, fingerprint, response_json, causation_id, correlation_id,
                server_sequence_id, round_version, created_at
            ) values (?, ?, ?, ?, ?, ?, ?, ?, 'PENDING', ?, null, ?, ?, null, ?, ?)
            """.trimIndent(),
            receiptId,
            tenantId,
            playerIdStr,
            gameId,
            commandId,
            "rnd-red-pending",
            "hand_primary",
            "PLACE_BET",
            "fp-red-pending",
            "caus-red-pending",
            "corr-red-pending",
            1L,
            Timestamp.from(now),
        )

        val pendingCount = jdbc.queryForObject(
            "select count(*) from game_command_receipt where tenant_id = ? and command_id = ? and status = 'PENDING'",
            Int::class.java,
            tenantId,
            commandId,
        )
        assertEquals(1, pendingCount, "TC-006 requires a transaction-private PENDING claim representation")
    }

    @Test
    fun `GREEN baseline golden money vectors remain unchanged before and after TC-006`() {
        val wagerMinor = 101L
        val multiplier = BigDecimal("1.2345")
        val expectedWinMinor = BigDecimal.valueOf(wagerMinor)
            .multiply(multiplier)
            .setScale(0, RoundingMode.FLOOR)
            .longValueExact()
        assertEquals(124L, expectedWinMinor)

        val startingBalance = 50000L
        seedFunds(startingBalance)

        val cashOutRound = "rnd-red-golden-cashout"
        createRound(cashOutRound)
        val placeAck = gameService.processCommand(
            AviatorRestCommand(
                tenantId = tenantId,
                principal = playerPrincipal,
                commandId = "cmd-red-golden-bet-1",
                roundId = cashOutRound,
                handId = "hand_primary",
                action = "PLACE_BET",
                wagerMinor = wagerMinor,
                currency = "INR",
                correlationId = "corr-red-golden-bet-1",
            )
        )
        assertEquals(AviatorCommandAckStatus.ACCEPTED, placeAck.status)

        createRound(cashOutRound, phase = GameRoundPhase.FLYING, version = 2L, multiplier = multiplier)
        val cashOutAck = gameService.processCommand(
            AviatorRestCommand(
                tenantId = tenantId,
                principal = playerPrincipal,
                commandId = "cmd-red-golden-cashout-1",
                roundId = cashOutRound,
                handId = "hand_primary",
                action = "CASH_OUT",
                correlationId = "corr-red-golden-cashout-1",
            )
        )
        assertEquals(AviatorCommandAckStatus.ACCEPTED, cashOutAck.status)
        assertEquals(expectedWinMinor, cashOutAck.result?.payoutMinor)
        assertEquals(
            startingBalance - wagerMinor + expectedWinMinor,
            ledgerStore.findBalance(tenantId, "PLAYER:$playerIdStr", "INR"),
        )
    }
}
