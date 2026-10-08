package com.slotting.admin.gameprovider

import com.slotting.admin.auth.AdminRole
import com.slotting.admin.auth.AuditEvent
import com.slotting.admin.auth.AuthenticatedPrincipal
import com.slotting.admin.auth.OutboxEvent
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
import com.slotting.admin.ledger.JournalEntryRecord
import com.slotting.admin.ledger.LedgerJournalStore
import com.slotting.admin.ledger.LedgerPostingService
import com.slotting.admin.ledger.PostTransactionCommand
import com.slotting.admin.ledger.PostingResult
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
class AviatorCashOutTransactionTest {

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

    @Autowired
    private lateinit var dataSource: javax.sql.DataSource

    private val now = Instant.parse("2026-10-06T10:00:00Z")
    private val clock = Clock.fixed(now, ZoneOffset.UTC)
    private val tenantId = "tenant-tc010-cashout"
    private val gameId = "AVIATOR"
    private val currency = "INR"
    private val playerUuid = UUID.randomUUID()
    private val playerIdStr = playerUuid.toString()

    private val foreignUuid = UUID.randomUUID()
    private val foreignIdStr = foreignUuid.toString()

    private val adminPrincipal = AuthenticatedPrincipal(
        id = "admin-sys-tc010",
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

    class CashOutLockTracingStore(
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

    class CashOutLockTracingLedgerStore(
        private val delegate: LedgerJournalStore,
        private val eventLog: MutableList<Pair<String, Int>>,
    ) : LedgerJournalStore by delegate {
        override fun lockAccount(tenantId: String, accountReference: String, currencyCode: String): Boolean {
            val locked = delegate.lockAccount(tenantId, accountReference, currencyCode)
            if (accountReference.startsWith("PLAYER:")) {
                eventLog.add("PLAYER_ACCOUNT_LOCK" to 4)
            }
            return locked
        }

        override fun save(
            result: PostingResult,
            legs: List<JournalEntryRecord>,
            payloadDigest: String,
            audit: AuditEvent,
            outbox: OutboxEvent,
        ) {
            eventLog.add("LEDGER_ACCOUNT_WRITE" to 4)
            delegate.save(result, legs, payloadDigest, audit, outbox)
        }
    }

    class ConfigurableFailpointStore(
        private val delegate: DurableGameWagerAndSettlementStore,
    ) : DurableGameWagerAndSettlementStore by delegate {
        var failAfter: String? = null

        override fun transitionBetStatus(betId: UUID, tenantId: String, from: GameBetStatus, to: GameBetStatus, updatedAt: Instant): Boolean {
            val result = delegate.transitionBetStatus(betId, tenantId, from, to, updatedAt)
            if (failAfter == "BET_TRANSITION") throw SimulatedFailpointException("Triggered failpoint after bet transition")
            return result
        }

        override fun saveSettlement(settlement: GameBetSettlementRecord) {
            delegate.saveSettlement(settlement)
            if (failAfter == "SETTLEMENT") throw SimulatedFailpointException("Triggered failpoint after settlement insert")
        }

        override fun nextSequenceId(tenantId: String): Long {
            val seq = delegate.nextSequenceId(tenantId)
            if (failAfter == "SEQUENCE") throw SimulatedFailpointException("Triggered failpoint after sequence allocation")
            return seq
        }

        override fun completeReceipt(tenantId: String, commandId: String, status: String, responseJson: String, serverSequenceId: Long, roundVersion: Long) {
            delegate.completeReceipt(tenantId, commandId, status, responseJson, serverSequenceId, roundVersion)
            if (failAfter == "RECEIPT") throw SimulatedFailpointException("Triggered failpoint after receipt completion")
        }
    }

    class ConfigurableFailpointLedgerStore(
        private val delegate: LedgerJournalStore,
    ) : LedgerJournalStore by delegate {
        var failAfterSave = false

        override fun save(
            result: PostingResult,
            legs: List<JournalEntryRecord>,
            payloadDigest: String,
            audit: AuditEvent,
            outbox: OutboxEvent,
        ) {
            delegate.save(result, legs, payloadDigest, audit, outbox)
            if (failAfterSave) throw SimulatedFailpointException("Triggered failpoint after ledger posting")
        }
    }

    class ConnectionTracingStore(
        private val delegate: DurableGameWagerAndSettlementStore,
        private val dataSource: javax.sql.DataSource,
    ) : DurableGameWagerAndSettlementStore by delegate {
        val shareConnectionIds = java.util.Collections.synchronizedList(mutableListOf<Int>())
        val updateConnectionIds = java.util.Collections.synchronizedList(mutableListOf<Int>())
        @Volatile var onFindRoundForUpdateEntered: (() -> Unit)? = null

        override fun findRoundForShare(tenantId: String, gameId: String, roundId: String): GameRoundRecord? {
            shareConnectionIds.add(currentConnectionId())
            return delegate.findRoundForShare(tenantId, gameId, roundId)
        }

        override fun findRoundForUpdate(tenantId: String, gameId: String, roundId: String): GameRoundRecord? {
            updateConnectionIds.add(currentConnectionId())
            onFindRoundForUpdateEntered?.invoke()
            return delegate.findRoundForUpdate(tenantId, gameId, roundId)
        }

        private fun currentConnectionId(): Int {
            val connection = org.springframework.jdbc.datasource.DataSourceUtils.getConnection(dataSource)
            val id = System.identityHashCode(connection)
            org.springframework.jdbc.datasource.DataSourceUtils.releaseConnection(connection, dataSource)
            return id
        }
    }

    private fun clearTenantState() {
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

    @BeforeEach
    fun setUp() {
        clearTenantState()

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
                transactionReference = "TX-TC010-SEED-${UUID.randomUUID()}",
                currencyCode = currency,
                entries = listOf(
                    JournalEntryDraft("HOUSE:SEED", JournalEntryDirection.DEBIT, amount, currency),
                    JournalEntryDraft("PLAYER:$playerIdStr", JournalEntryDirection.CREDIT, amount, currency),
                ),
                idempotencyKey = "IDEM-TC010-SEED-${UUID.randomUUID()}",
                correlationId = "corr-tc010-seed",
                causationId = "caus-tc010-seed",
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

    private fun flyRound(roundId: String, multiplier: BigDecimal = BigDecimal("1.2345")) {
        gameService.createOrUpdateRound(
            CreateOrUpdateRoundCommand(
                tenantId = tenantId,
                gameId = gameId,
                roundId = roundId,
                phase = GameRoundPhase.FLYING,
                roundVersion = 2L,
                currentMultiplier = multiplier,
                crashMultiplier = BigDecimal("10.0000"),
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

    private fun cashOutCommand(roundId: String, commandId: String, handId: String = "hand_primary"): AviatorRestCommand =
        AviatorRestCommand(
            tenantId = tenantId,
            principal = playerPrincipal,
            commandId = commandId,
            roundId = roundId,
            handId = handId,
            action = "CASH_OUT",
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

    private fun lastSequenceId(): Long =
        jdbc.queryForObject(
            "select coalesce(max(last_sequence_id), 0) from game_command_sequence where tenant_id = ?",
            Long::class.java,
            tenantId,
        ) ?: 0L

    private fun ledgerTransactionCount(): Int =
        jdbc.queryForObject(
            "select count(*) from ledger_transaction where tenant_id = ?",
            Int::class.java,
            tenantId,
        ) ?: 0

    private fun ledgerLegCount(): Int =
        jdbc.queryForObject(
            "select count(*) from ledger_leg where tenant_id = ?",
            Int::class.java,
            tenantId,
        ) ?: 0

    private fun roundVersion(roundId: String): Long =
        jdbc.queryForObject(
            "select round_version from game_authoritative_round where tenant_id = ? and game_id = ? and round_id = ?",
            Long::class.java,
            tenantId,
            gameId,
            roundId,
        ) ?: 0L

    private fun assertJournalBalanced() {
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

    @Test
    fun `GivenCashOutStepFails_WhenCommandRollsBack_ThenNoPartialMoneyStateRemains`() {
        val startingBalance = 50000L
        seedFunds(startingBalance)
        val roundId = "rnd-tc010-failpoint"
        createRound(roundId)
        placeBet(roundId, "cmd-tc010-fp-bet", 101L)
        flyRound(roundId)

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
                decoratedService.processCommand(cashOutCommand(roundId, "cmd-tc010-failpoint"))
            }
        }

        val bet = gameStore.findBet(tenantId, gameId, roundId, playerIdStr, "hand_primary")
        assertNotNull(bet)
        assertEquals(GameBetStatus.ACCEPTED, bet.status, "Cash-out transition must roll back with the failed settlement")
        assertEquals(0, settlementCount(GameSettlementOutcome.PAYOUT_CASH_OUT), "No terminal settlement may persist")
        assertEquals(startingBalance - 101L, ledgerStore.findBalance(tenantId, "PLAYER:$playerIdStr", currency))
        assertNull(gameStore.findReceipt(tenantId, "cmd-tc010-failpoint"), "No accepted cash-out receipt may persist")
    }

    @Test
    fun `GivenDuplicateCashOut_WhenCommandsRace_ThenOneTerminalSettlement`() {
        seedFunds(50000L)
        val roundId = "rnd-tc010-race"
        createRound(roundId)
        placeBet(roundId, "cmd-tc010-race-bet", 101L)
        flyRound(roundId)

        val pool = Executors.newFixedThreadPool(2)
        val results = ConcurrentLinkedQueue<Pair<String, String>>()
        val startLatch = CountDownLatch(1)
        val doneLatch = CountDownLatch(2)

        val commands = listOf(cashOutCommand(roundId, "cmd-tc010-race-a"), cashOutCommand(roundId, "cmd-tc010-race-b"))
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
        assertTrue(doneLatch.await(30, TimeUnit.SECONDS), "Concurrent cash-outs timed out")
        pool.shutdown()

        val outcomes = results.toMap()
        assertEquals(2, outcomes.size)
        assertTrue(outcomes.values.contains("ACCEPTED"), "One cash-out must win: $outcomes")
        assertTrue(outcomes.values.none { it.startsWith("ERROR") }, "Losing cash-out must be a clean rejection, not an error: $outcomes")
        assertEquals(1, settlementCount(GameSettlementOutcome.PAYOUT_CASH_OUT), "Exactly one PAYOUT_CASH_OUT settlement")
        val payoutCount = jdbc.queryForObject(
            "select count(*) from ledger_transaction where tenant_id = ? and idempotency_key like 'settle:%'",
            Int::class.java,
            tenantId,
        ) ?: 0
        assertEquals(1, payoutCount, "Exactly one payout journal movement")
        val cashedOutCount = jdbc.queryForObject(
            "select count(*) from game_accepted_bet where tenant_id = ? and status = 'CASHED_OUT'",
            Int::class.java,
            tenantId,
        ) ?: 0
        assertEquals(1, cashedOutCount, "Exactly one CASHED_OUT transition")

        val losingId = outcomes.filterValues { it == "REJECTED" }.keys.single()
        val loserCommand = commands.first { it.commandId == losingId }
        val loserReplay = gameService.processCommand(loserCommand)
        assertEquals(AviatorCommandAckStatus.REJECTED, loserReplay.status)
        assertEquals(1, settlementCount(GameSettlementOutcome.PAYOUT_CASH_OUT))
    }

    @Test
    fun `GivenForeignOwner_WhenCashOutRequested_ThenNoEffects`() {
        val startingBalance = 50000L
        seedFunds(startingBalance)
        val roundId = "rnd-tc010-owner"
        createRound(roundId)
        placeBet(roundId, "cmd-tc010-owner-bet", 101L)
        flyRound(roundId)

        val foreignCashOut = AviatorRestCommand(
            tenantId = tenantId,
            principal = foreignPrincipal,
            commandId = "cmd-tc010-foreign",
            roundId = roundId,
            handId = "hand_primary",
            action = "CASH_OUT",
            currency = currency,
            correlationId = "corr-tc010-foreign",
        )
        val foreignAck = gameService.processCommand(foreignCashOut)
        assertEquals(AviatorCommandAckStatus.REJECTED, foreignAck.status)
        assertEquals(AviatorCommandRejectionCode.INVALID_HAND_STATE, foreignAck.rejection?.code)

        val bet = gameStore.findBet(tenantId, gameId, roundId, playerIdStr, "hand_primary")
        assertNotNull(bet)
        assertEquals(GameBetStatus.ACCEPTED, bet.status)
        assertEquals(startingBalance - 101L, ledgerStore.findBalance(tenantId, "PLAYER:$playerIdStr", currency))
        assertEquals(0, settlementCount(GameSettlementOutcome.PAYOUT_CASH_OUT))
    }

    @Test
    fun `GivenSuccessfulCashOutWithLostResponse_WhenReplayed_ThenPayoutAndSequencePreserved`() {
        val startingBalance = 50000L
        seedFunds(startingBalance)
        val roundId = "rnd-tc010-replay"
        createRound(roundId)
        placeBet(roundId, "cmd-tc010-replay-bet", 101L)
        flyRound(roundId)

        val command = cashOutCommand(roundId, "cmd-tc010-replay")
        val ack = gameService.processCommand(command)
        assertEquals(AviatorCommandAckStatus.ACCEPTED, ack.status)
        assertEquals(124L, ack.result?.payoutMinor)

        val replay = gameService.processCommand(command)
        assertEquals(ack.sequenceId, replay.sequenceId, "Replay must preserve the original sequence")
        assertEquals(ack.result?.payoutMinor, replay.result?.payoutMinor)
        assertEquals(1, settlementCount(GameSettlementOutcome.PAYOUT_CASH_OUT))
    }

    @Test
    fun `GivenRoundCrashedBeforeCashOut_WhenCashOutRequested_ThenRejectedWithoutMoneyMovement`() {
        val startingBalance = 50000L
        seedFunds(startingBalance)
        val roundId = "rnd-tc010-crashed-first"
        createRound(roundId)
        placeBet(roundId, "cmd-tc010-crashed-bet", 101L)
        flyRound(roundId, BigDecimal("1.2345"))

        gameService.createOrUpdateRound(
            CreateOrUpdateRoundCommand(
                tenantId = tenantId,
                gameId = gameId,
                roundId = roundId,
                phase = GameRoundPhase.CRASHED,
                roundVersion = 3L,
                currentMultiplier = BigDecimal("10.0000"),
                crashMultiplier = BigDecimal("10.0000"),
            )
        )

        val ack = gameService.processCommand(cashOutCommand(roundId, "cmd-tc010-crashed-cashout"))
        assertEquals(AviatorCommandAckStatus.REJECTED, ack.status)
        assertEquals(AviatorCommandRejectionCode.ROUND_CLOSED, ack.rejection?.code)

        val bet = gameStore.findBet(tenantId, gameId, roundId, playerIdStr, "hand_primary")
        assertNotNull(bet)
        assertEquals(GameBetStatus.ACCEPTED, bet.status, "Lifecycle win must leave the bet un-cashed")
        assertEquals(startingBalance - 101L, ledgerStore.findBalance(tenantId, "PLAYER:$playerIdStr", currency))
        assertEquals(0, settlementCount(GameSettlementOutcome.PAYOUT_CASH_OUT))
    }

    @Test
    fun `GivenCashOut_WhenLocksAreObserved_ThenGlobalOrderIsPreserved`() {
        seedFunds(50000L)
        val roundId = "rnd-tc010-lock-order"
        createRound(roundId)
        placeBet(roundId, "cmd-tc010-lock-bet", 101L)
        flyRound(roundId)

        val eventLog = mutableListOf<Pair<String, Int>>()
        val tracingStore = CashOutLockTracingStore(gameStore, eventLog)
        val tracingLedgerStore = CashOutLockTracingLedgerStore(ledgerStore, eventLog)
        val tracingLedgerService = LedgerPostingService(store = tracingLedgerStore, clock = clock)
        val tracingService = DurableGameWagerAndSettlementService(
            store = tracingStore,
            ledgerService = tracingLedgerService,
            registrationStore = registrationStore,
            eligibilityStore = eligibilityStore,
            adminPrincipal = adminPrincipal,
            clock = clock,
            txManager = txManager,
        )

        val ack = tracingService.processCommand(cashOutCommand(roundId, "cmd-tc010-lock-order"))
        assertEquals(AviatorCommandAckStatus.ACCEPTED, ack.status)

        var previousRank = 0
        for ((resource, rank) in eventLog) {
            if (resource == "RECEIPT_WRITE") {
                continue
            }
            assertTrue(rank >= previousRank, "Lock rank inversion at $resource ($rank) after $previousRank")
            previousRank = rank
        }
        assertTrue(eventLog.any { it.first == "RECEIPT" }, "Early claim must be first")
        assertTrue(eventLog.any { it.first == "ROUND_SHARED" })
        assertTrue(eventLog.any { it.first == "BET" }, "Cash-out must lock the bet row")
        assertTrue(eventLog.any { it.first == "LEDGER_ACCOUNT_WRITE" }, "Cash-out must write the player account during the ledger posting")
        assertTrue(eventLog.any { it.first == "SEQUENCE_COUNTER" })
    }

    @Test
    fun `GivenHistoricalMoneyAndOutcomeVectors_WhenCashOutCompletes_ThenSemanticsStayUnchanged`() {
        val wagerMinor = 101L
        val startingBalance = 50000L
        seedFunds(startingBalance)
        val roundId = "rnd-tc010-golden"
        createRound(roundId)
        placeBet(roundId, "cmd-tc010-golden-bet", wagerMinor)
        flyRound(roundId, BigDecimal("1.2345"))

        val ack = gameService.processCommand(cashOutCommand(roundId, "cmd-tc010-golden-cashout"))
        assertEquals(AviatorCommandAckStatus.ACCEPTED, ack.status)
        assertEquals(124L, ack.result?.payoutMinor)
        assertEquals(startingBalance - wagerMinor + 124L, ledgerStore.findBalance(tenantId, "PLAYER:$playerIdStr", currency))

        val settlement = jdbc.queryForObject(
            "select payout_minor_units from game_bet_settlement where tenant_id = ? and outcome = 'PAYOUT_CASH_OUT'",
            Long::class.java,
            tenantId,
        )
        assertEquals(124L, settlement)

        assertJournalBalanced()
    }

    @Test
    fun `GivenCashOutFailsAtEachPersistenceBoundary_ThenFullRollback`() {
        val startingBalance = 50000L
        val boundaries = listOf("BET_TRANSITION", "LEDGER_POST", "SETTLEMENT", "SEQUENCE", "RECEIPT")

        for (boundary in boundaries) {
            clearTenantState()
            seedFunds(startingBalance)
            val suffix = boundary.lowercase()
            val roundId = "rnd-tc010-fp-$suffix"
            val commandId = "cmd-tc010-fp-$suffix"
            createRound(roundId)
            placeBet(roundId, "cmd-tc010-fp-bet-$suffix", 101L)
            flyRound(roundId)

            val fpGameStore = ConfigurableFailpointStore(gameStore)
            val fpLedgerStore = ConfigurableFailpointLedgerStore(ledgerStore)
            val fpLedgerService = LedgerPostingService(store = fpLedgerStore, clock = clock)
            val fpService = DurableGameWagerAndSettlementService(
                store = fpGameStore,
                ledgerService = fpLedgerService,
                registrationStore = registrationStore,
                eligibilityStore = eligibilityStore,
                adminPrincipal = adminPrincipal,
                clock = clock,
            )
            if (boundary == "LEDGER_POST") {
                fpLedgerStore.failAfterSave = true
            } else {
                fpGameStore.failAfter = boundary
            }

            val sequenceBefore = lastSequenceId()
            val ledgerTransactionsBefore = ledgerTransactionCount()
            val ledgerLegsBefore = ledgerLegCount()
            val roundVersionBefore = roundVersion(roundId)
            val betUpdatedAtBefore = assertNotNull(gameStore.findBet(tenantId, gameId, roundId, playerIdStr, "hand_primary")).updatedAt

            val txTemplate = TransactionTemplate(txManager)
            assertThrows<SimulatedFailpointException> {
                txTemplate.execute<Unit> {
                    fpService.processCommand(cashOutCommand(roundId, commandId))
                }
            }

            val bet = gameStore.findBet(tenantId, gameId, roundId, playerIdStr, "hand_primary")
            assertNotNull(bet)
            assertEquals(GameBetStatus.ACCEPTED, bet.status, "Boundary $boundary must roll back the bet status")
            assertEquals(betUpdatedAtBefore, bet.updatedAt, "Boundary $boundary must not change the bet updatedAt")
            assertEquals(0, settlementCount(GameSettlementOutcome.PAYOUT_CASH_OUT), "Boundary $boundary must leave no settlement")
            assertEquals(startingBalance - 101L, ledgerStore.findBalance(tenantId, "PLAYER:$playerIdStr", currency), "Boundary $boundary must restore the balance")
            assertNull(gameStore.findReceipt(tenantId, commandId), "Boundary $boundary must leave no receipt")
            assertEquals(sequenceBefore, lastSequenceId(), "Boundary $boundary must not commit a sequence allocation")
            assertEquals(ledgerTransactionsBefore, ledgerTransactionCount(), "Boundary $boundary must not commit a ledger transaction")
            assertEquals(ledgerLegsBefore, ledgerLegCount(), "Boundary $boundary must not commit ledger legs")
            assertEquals(roundVersionBefore, roundVersion(roundId), "Boundary $boundary must not change the round version")
        }
    }

    @Test
    fun `GivenCashOutHoldsSharedRoundLock_WhenLifecycleRequestsExclusive_ThenLifecycleBlocksAndCashOutSettles`() {
        seedFunds(50000L)
        val roundId = "rnd-tc010-forced-interleave"
        createRound(roundId)
        placeBet(roundId, "cmd-tc010-forced-bet", 101L)
        flyRound(roundId, BigDecimal("1.2345"))

        val tracingStore = ConnectionTracingStore(gameStore, dataSource)
        val sharedHeld = CountDownLatch(1)
        val release = CountDownLatch(1)
        val blockingStore = object : DurableGameWagerAndSettlementStore by tracingStore {
            override fun findRoundForShare(tenantId: String, gameId: String, roundId: String): GameRoundRecord? {
                val round = tracingStore.findRoundForShare(tenantId, gameId, roundId)
                sharedHeld.countDown()
                release.await(10, TimeUnit.SECONDS)
                return round
            }
        }
        val cashOutService = DurableGameWagerAndSettlementService(
            store = blockingStore,
            ledgerService = ledgerService,
            registrationStore = registrationStore,
            eligibilityStore = eligibilityStore,
            adminPrincipal = adminPrincipal,
            clock = clock,
            txManager = txManager,
        )
        val lifecycleService = DurableGameWagerAndSettlementService(
            store = tracingStore,
            ledgerService = ledgerService,
            registrationStore = registrationStore,
            eligibilityStore = eligibilityStore,
            adminPrincipal = adminPrincipal,
            clock = clock,
            txManager = txManager,
        )

        val pool = Executors.newFixedThreadPool(2)
        val cashOutOutcome = java.util.concurrent.atomic.AtomicReference<String>()
        val lifecycleEntered = CountDownLatch(1)
        val lifecycleAcquired = CountDownLatch(1)
        tracingStore.onFindRoundForUpdateEntered = { lifecycleEntered.countDown() }

        val cashOutFuture = pool.submit {
            try {
                val ack = cashOutService.processCommand(cashOutCommand(roundId, "cmd-tc010-forced-cashout"))
                cashOutOutcome.set(ack.status.name)
            } catch (e: Exception) {
                cashOutOutcome.set("ERROR:${e.javaClass.simpleName}")
            }
        }
        assertTrue(sharedHeld.await(10, TimeUnit.SECONDS), "cash-out must acquire the shared round lock")

        val lifecycleFuture = pool.submit {
            lifecycleService.createOrUpdateRound(
                CreateOrUpdateRoundCommand(
                    tenantId = tenantId,
                    gameId = gameId,
                    roundId = roundId,
                    phase = GameRoundPhase.CRASHED,
                    roundVersion = 3L,
                    currentMultiplier = BigDecimal("10.0000"),
                    crashMultiplier = BigDecimal("10.0000"),
                )
            )
            lifecycleAcquired.countDown()
        }
        assertTrue(lifecycleEntered.await(5, TimeUnit.SECONDS), "lifecycle worker must enter findRoundForUpdate")
        assertTrue(!lifecycleAcquired.await(1, TimeUnit.SECONDS), "lifecycle exclusive lock must block while cash-out holds the shared round lock")

        release.countDown()
        cashOutFuture.get(20, TimeUnit.SECONDS)
        lifecycleFuture.get(20, TimeUnit.SECONDS)
        pool.shutdown()

        assertEquals("ACCEPTED", cashOutOutcome.get(), "cash-out that won the shared lock must settle")
        assertEquals(1, settlementCount(GameSettlementOutcome.PAYOUT_CASH_OUT))
        val payout = jdbc.queryForObject(
            "select payout_minor_units from game_bet_settlement where tenant_id = ? and outcome = 'PAYOUT_CASH_OUT'",
            Long::class.java,
            tenantId,
        )
        assertEquals(124L, payout, "cash-out must settle at the shared-lock multiplier")

        assertTrue(tracingStore.shareConnectionIds.isNotEmpty(), "cash-out connection must be observed")
        assertTrue(tracingStore.updateConnectionIds.isNotEmpty(), "lifecycle connection must be observed")
        assertTrue(
            tracingStore.shareConnectionIds.toSet().intersect(tracingStore.updateConnectionIds.toSet()).isEmpty(),
            "cash-out and lifecycle must run on distinct transaction-bound connections",
        )

        val round = gameStore.findRound(tenantId, gameId, roundId)
        assertNotNull(round)
        assertEquals(GameRoundPhase.CRASHED, round.phase, "lifecycle must crash the round after cash-out commits")
        assertJournalBalanced()
    }
}
