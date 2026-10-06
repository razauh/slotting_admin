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
import org.junit.jupiter.api.assertThrows
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.boot.test.context.SpringBootTest
import org.springframework.jdbc.core.JdbcTemplate
import org.springframework.test.context.DynamicPropertyRegistry
import org.springframework.test.context.DynamicPropertySource
import org.springframework.transaction.PlatformTransactionManager
import org.springframework.transaction.support.TransactionTemplate
import java.math.BigDecimal
import java.sql.Timestamp
import java.time.Clock
import java.time.Instant
import java.time.LocalDate
import java.time.ZoneOffset
import java.util.UUID
import java.util.concurrent.ConcurrentLinkedQueue
import java.util.concurrent.CountDownLatch
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit
import kotlin.test.assertEquals
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue

@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.NONE)
class AviatorCancelTransactionTest {

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
    private val tenantId = "tenant-tc009-cancel"
    private val gameId = "AVIATOR"
    private val currency = "INR"
    private val playerUuid = UUID.randomUUID()
    private val playerIdStr = playerUuid.toString()

    private val foreignUuid = UUID.randomUUID()
    private val foreignIdStr = foreignUuid.toString()

    private val adminPrincipal = AuthenticatedPrincipal(
        id = "admin-sys-tc009",
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

    private val foreignPrincipal = AuthenticatedPrincipal(
        id = foreignIdStr,
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

    class SimulatedFailpointException(message: String) : RuntimeException(message)

    class FailAfterSettlementStore(
        private val delegate: DurableGameWagerAndSettlementStore,
    ) : DurableGameWagerAndSettlementStore by delegate {
        var throwAfterSaveSettlement = false
        override fun saveSettlement(settlement: GameBetSettlementRecord) {
            delegate.saveSettlement(settlement)
            if (throwAfterSaveSettlement) {
                throw SimulatedFailpointException("Triggered failpoint after settlement insert")
            }
        }
    }

    class CancelLockTracingStore(
        private val delegate: DurableGameWagerAndSettlementStore,
        val eventLog: MutableList<Pair<String, Int>> = mutableListOf(),
    ) : DurableGameWagerAndSettlementStore by delegate {
        override fun claimReceipt(claim: GameCommandReceiptClaim): CommandReceiptClaimResult {
            eventLog.add("RECEIPT" to 1)
            return delegate.claimReceipt(claim)
        }

        override fun completeReceipt(tenantId: String, commandId: String, status: String, responseJson: String, serverSequenceId: Long, roundVersion: Long) {
            eventLog.add("RECEIPT_WRITE" to 1)
            delegate.completeReceipt(tenantId, commandId, status, responseJson, serverSequenceId, roundVersion)
        }

        override fun findRoundForShare(tenantId: String, gameId: String, roundId: String): GameRoundRecord? {
            eventLog.add("ROUND_SHARED" to 2)
            return delegate.findRoundForShare(tenantId, gameId, roundId)
        }

        override fun findBetForUpdate(tenantId: String, gameId: String, roundId: String, ownerId: String, handId: String): GameAcceptedBetRecord? {
            eventLog.add("BET" to 3)
            return delegate.findBetForUpdate(tenantId, gameId, roundId, ownerId, handId)
        }

        override fun nextSequenceId(tenantId: String): Long {
            val seq = delegate.nextSequenceId(tenantId)
            eventLog.add("SEQUENCE_COUNTER" to 5)
            return seq
        }
    }

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
        jdbc.update("delete from admin_outbox_event where tenant_id = ?", tenantId)
        jdbc.update("delete from admin_audit_event where tenant_id = ?", tenantId)
        jdbc.update("delete from admin_operation where tenant_id = ?", tenantId)
        jdbc.update("delete from ledger_account where tenant_id = ?", tenantId)
        jdbc.update("delete from game_command_sequence where tenant_id = ?", tenantId)
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

        for ((uuid, identifier) in listOf(playerUuid to playerIdStr, foreignUuid to foreignIdStr)) {
            jdbc.update(
                """
                insert into player_credential (
                    player_id, tenant_id, identifier, password_hash, password_algo,
                    password_salt, iterations, status, version, created_at, updated_at
                ) values (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                on conflict (tenant_id, identifier) do nothing
                """.trimIndent(),
                uuid,
                tenantId,
                identifier,
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
                    playerId = uuid,
                    tenantId = tenantId,
                    dateOfBirth = LocalDate.of(1995, 5, 5),
                    kycStatus = KycComplianceStatus.VERIFIED,
                    amlStatus = AmlComplianceStatus.CLEARED,
                    jurisdiction = "DEFAULT",
                    responsiblePlay = ResponsiblePlayProfile(
                        playerId = uuid,
                        selfExcluded = false,
                        singleWagerLimitMinor = 500000L,
                        dailyWagerLimitMinor = 2000000L,
                        currentDailyWagerMinor = 0L
                    )
                )
            )
        }
    }

    private fun seedFunds(amount: Long) {
        ledgerService.postTransaction(
            PostTransactionCommand(
                principal = adminPrincipal,
                tenantId = tenantId,
                transactionReference = "TX-TC009-SEED-${UUID.randomUUID()}",
                currencyCode = currency,
                entries = listOf(
                    JournalEntryDraft("HOUSE:SEED", JournalEntryDirection.DEBIT, amount, currency),
                    JournalEntryDraft("PLAYER:$playerIdStr", JournalEntryDirection.CREDIT, amount, currency),
                ),
                idempotencyKey = "IDEM-TC009-SEED-${UUID.randomUUID()}",
                correlationId = "corr-tc009-seed",
                causationId = "caus-tc009-seed",
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
    }

    private fun placeBet(roundId: String, commandId: String, wagerMinor: Long, handId: String = "hand_primary"): AviatorCommandAckResult {
        val ack = gameService.processCommand(
            AviatorRestCommand(
                tenantId = tenantId,
                principal = playerPrincipal,
                commandId = commandId,
                roundId = roundId,
                handId = handId,
                action = "PLACE_BET",
                wagerMinor = wagerMinor,
                currency = currency,
                correlationId = "corr-$commandId",
            )
        )
        assertEquals(AviatorCommandAckStatus.ACCEPTED, ack.status)
        return ack
    }

    private fun cancelCommand(roundId: String, commandId: String, handId: String = "hand_primary"): AviatorRestCommand =
        AviatorRestCommand(
            tenantId = tenantId,
            principal = playerPrincipal,
            commandId = commandId,
            roundId = roundId,
            handId = handId,
            action = "CANCEL_BET",
            currency = currency,
            correlationId = "corr-$commandId",
        )

    private fun settlementCount(outcome: GameSettlementOutcome): Int =
        jdbc.queryForObject(
            "select count(*) from game_bet_settlement where tenant_id = ? and outcome = ?",
            Int::class.java,
            tenantId,
            outcome.name,
        ) ?: 0

    @Test
    fun `GivenRefundPosted_WhenBetSettlementWriteFails_ThenCancellationRollsBack`() {
        val startingBalance = 50000L
        seedFunds(startingBalance)
        val roundId = "rnd-tc009-failpoint"
        createRound(roundId)
        placeBet(roundId, "cmd-tc009-fp-bet", 60L)

        val decorated = FailAfterSettlementStore(gameStore)
        val decoratedService = DurableGameWagerAndSettlementService(
            store = decorated,
            ledgerService = ledgerService,
            registrationStore = registrationStore,
            eligibilityStore = eligibilityStore,
            adminPrincipal = adminPrincipal,
            clock = clock,
        )
        decorated.throwAfterSaveSettlement = true
        val txTemplate = TransactionTemplate(txManager)

        assertThrows<SimulatedFailpointException> {
            txTemplate.execute<Unit> {
                decoratedService.processCommand(cancelCommand(roundId, "cmd-tc009-failpoint"))
            }
        }

        val bet = gameStore.findBet(tenantId, gameId, roundId, playerIdStr, "hand_primary")
        assertNotNull(bet)
        assertEquals(GameBetStatus.ACCEPTED, bet.status, "Cancelled transition must roll back with the failed settlement")
        assertEquals(0, settlementCount(GameSettlementOutcome.REFUND_CANCEL), "No terminal settlement may persist")
        assertEquals(startingBalance - 60L, ledgerStore.findBalance(tenantId, "PLAYER:$playerIdStr", currency))
        assertNull(gameStore.findReceipt(tenantId, "cmd-tc009-failpoint"), "No accepted cancel receipt may persist")
    }

    @Test
    fun `GivenAcceptedBet_WhenTwoCancelsRace_ThenOneRefund`() {
        seedFunds(50000L)
        val roundId = "rnd-tc009-race"
        createRound(roundId)
        placeBet(roundId, "cmd-tc009-race-bet", 60L)

        val pool = Executors.newFixedThreadPool(2)
        val results = ConcurrentLinkedQueue<Pair<String, String>>()
        val startLatch = CountDownLatch(1)
        val doneLatch = CountDownLatch(2)

        val commands = listOf(cancelCommand(roundId, "cmd-tc009-race-a"), cancelCommand(roundId, "cmd-tc009-race-b"))
        for (command in commands) {
            pool.submit {
                startLatch.await()
                try {
                    val ack = gameService.processCommand(command)
                    results.add(command.commandId to ack.status.name)
                } catch (e: Exception) {
                    results.add(command.commandId to "ERROR:${e.javaClass.simpleName}")
                } finally {
                    doneLatch.countDown()
                }
            }
        }

        startLatch.countDown()
        assertTrue(doneLatch.await(30, TimeUnit.SECONDS), "Concurrent cancels timed out")
        pool.shutdown()

        val outcomes = results.toMap()
        assertEquals(2, outcomes.size)
        assertTrue(outcomes.values.contains("ACCEPTED"), "One cancel must win: $outcomes")
        assertTrue(outcomes.values.none { it.startsWith("ERROR") }, "Losing cancel must be a clean rejection, not an error: $outcomes")
        assertEquals(1, settlementCount(GameSettlementOutcome.REFUND_CANCEL), "Exactly one REFUND_CANCEL settlement")
        val refundCount = jdbc.queryForObject(
            "select count(*) from ledger_transaction where tenant_id = ? and idempotency_key like 'settle:%'",
            Int::class.java,
            tenantId,
        ) ?: 0
        assertEquals(1, refundCount, "Exactly one refund journal movement")
        val cancelledCount = jdbc.queryForObject(
            "select count(*) from game_accepted_bet where tenant_id = ? and status = 'CANCELLED'",
            Int::class.java,
            tenantId,
        ) ?: 0
        assertEquals(1, cancelledCount, "Exactly one CANCELLED transition")

        val winningId = outcomes.filterValues { it == "ACCEPTED" }.keys.single()
        val winnerCommand = commands.first { it.commandId == winningId }
        val winnerReplay = gameService.processCommand(winnerCommand)
        assertEquals(AviatorCommandAckStatus.ACCEPTED, winnerReplay.status)
        assertEquals(1, settlementCount(GameSettlementOutcome.REFUND_CANCEL))
    }

    @Test
    fun `GivenForeignOwner_WhenCancelRequested_ThenNoEffects`() {
        val startingBalance = 50000L
        seedFunds(startingBalance)
        val roundId = "rnd-tc009-owner"
        createRound(roundId)
        placeBet(roundId, "cmd-tc009-owner-bet", 60L)

        val foreignCancel = AviatorRestCommand(
            tenantId = tenantId,
            principal = foreignPrincipal,
            commandId = "cmd-tc009-foreign",
            roundId = roundId,
            handId = "hand_primary",
            action = "CANCEL_BET",
            currency = currency,
            correlationId = "corr-tc009-foreign",
        )
        val foreignAck = gameService.processCommand(foreignCancel)
        assertEquals(AviatorCommandAckStatus.REJECTED, foreignAck.status)
        assertEquals(AviatorCommandRejectionCode.INVALID_HAND_STATE, foreignAck.rejection?.code)

        val bet = gameStore.findBet(tenantId, gameId, roundId, playerIdStr, "hand_primary")
        assertNotNull(bet)
        assertEquals(GameBetStatus.ACCEPTED, bet.status)
        assertEquals(startingBalance - 60L, ledgerStore.findBalance(tenantId, "PLAYER:$playerIdStr", currency))
        assertEquals(0, settlementCount(GameSettlementOutcome.REFUND_CANCEL))
    }

    @Test
    fun `GivenSuccessfulCancelWithLostResponse_WhenReplayed_ThenRefundAndSequencePreserved`() {
        val startingBalance = 50000L
        seedFunds(startingBalance)
        val roundId = "rnd-tc009-replay"
        createRound(roundId)
        placeBet(roundId, "cmd-tc009-replay-bet", 60L)

        val command = cancelCommand(roundId, "cmd-tc009-replay")
        val ack = gameService.processCommand(command)
        assertEquals(AviatorCommandAckStatus.ACCEPTED, ack.status)
        assertEquals(50000L, ack.result?.accountMoneyAfterMinor)

        val replay = gameService.processCommand(command)
        assertEquals(ack.sequenceId, replay.sequenceId, "Replay must preserve the original sequence")
        assertEquals(ack.result?.accountMoneyAfterMinor, replay.result?.accountMoneyAfterMinor)
        assertEquals(1, settlementCount(GameSettlementOutcome.REFUND_CANCEL))
        assertEquals(50000L, ledgerStore.findBalance(tenantId, "PLAYER:$playerIdStr", currency))
    }

    @Test
    fun `GivenCancel_WhenLocksAreObserved_ThenGlobalOrderIsPreserved`() {
        seedFunds(50000L)
        val roundId = "rnd-tc009-lock-order"
        createRound(roundId)
        placeBet(roundId, "cmd-tc009-lock-bet", 60L)

        val tracing = CancelLockTracingStore(gameStore)
        val tracingService = DurableGameWagerAndSettlementService(
            store = tracing,
            ledgerService = ledgerService,
            registrationStore = registrationStore,
            eligibilityStore = eligibilityStore,
            adminPrincipal = adminPrincipal,
            clock = clock,
            txManager = txManager,
        )

        val ack = tracingService.processCommand(cancelCommand(roundId, "cmd-tc009-lock-order"))
        assertEquals(AviatorCommandAckStatus.ACCEPTED, ack.status)

        var previousRank = 0
        for ((resource, rank) in tracing.eventLog) {
            if (resource == "RECEIPT_WRITE") {
                continue
            }
            assertTrue(rank >= previousRank, "Lock rank inversion at $resource ($rank) after $previousRank")
            previousRank = rank
        }
        assertTrue(tracing.eventLog.any { it.first == "RECEIPT" }, "Early claim must be first")
        assertTrue(tracing.eventLog.any { it.first == "ROUND_SHARED" })
        assertTrue(tracing.eventLog.any { it.first == "BET" }, "Cancel must lock the bet row")
        assertTrue(tracing.eventLog.any { it.first == "SEQUENCE_COUNTER" })
    }

    @Test
    fun `GivenHistoricalMoneyAndOutcomeVectors_WhenCancelRuns_ThenRefundEqualsReservation`() {
        val wagerMinor = 101L
        val startingBalance = 50000L
        seedFunds(startingBalance)
        val roundId = "rnd-tc009-golden"
        createRound(roundId)
        placeBet(roundId, "cmd-tc009-golden-bet", wagerMinor)

        assertEquals(startingBalance - wagerMinor, ledgerStore.findBalance(tenantId, "PLAYER:$playerIdStr", currency))

        val ack = gameService.processCommand(cancelCommand(roundId, "cmd-tc009-golden-cancel"))
        assertEquals(AviatorCommandAckStatus.ACCEPTED, ack.status)
        assertEquals(wagerMinor, ack.result?.wagerMinor)
        assertEquals(startingBalance, ledgerStore.findBalance(tenantId, "PLAYER:$playerIdStr", currency))

        val settlement = jdbc.queryForObject(
            "select payout_minor_units from game_bet_settlement where tenant_id = ? and outcome = 'REFUND_CANCEL'",
            Long::class.java,
            tenantId,
        )
        assertEquals(wagerMinor, settlement)

        val totalDebits = jdbc.queryForObject(
            "select coalesce(sum(total_debits_minor_units), 0) from ledger_transaction where tenant_id = ?",
            Long::class.java,
            tenantId,
        ) ?: 0L
        val totalCredits = jdbc.queryForObject(
            "select coalesce(sum(total_credits_minor_units), 0) from ledger_transaction where tenant_id = ?",
            Long::class.java,
            tenantId,
        ) ?: 0L
        assertEquals(totalDebits, totalCredits, "Double-entry journal must stay balanced")
    }
}
