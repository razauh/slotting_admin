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
import com.slotting.admin.ledger.JournalEntryRecord
import com.slotting.admin.ledger.LedgerJournalStore
import com.slotting.admin.ledger.LedgerPostingException
import com.slotting.admin.ledger.LedgerPostingService
import com.slotting.admin.ledger.PostingResult
import com.slotting.admin.ledger.PostTransactionCommand
import com.slotting.admin.auth.AuditEvent
import com.slotting.admin.auth.OutboxEvent
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
import java.math.RoundingMode
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
import java.util.concurrent.atomic.AtomicBoolean
import kotlin.test.assertEquals
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue

@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.NONE)
class AviatorPlaceBetTransactionTest {

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
    private val tenantId = "tenant-tc008-place"
    private val gameId = "AVIATOR"
    private val currency = "INR"
    private val playerUuid = UUID.randomUUID()
    private val playerIdStr = playerUuid.toString()

    private val adminPrincipal = AuthenticatedPrincipal(
        id = "admin-sys-tc008",
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
    private lateinit var fairnessStore: JdbcFairnessEvidenceStore
    private lateinit var fairnessAuthority: ProvablyFairOutcomeAuthority
    private lateinit var gameService: DurableGameWagerAndSettlementService

    class SimulatedFailpointException(message: String) : RuntimeException(message)

    class FailAfterLedgerBetStore(
        private val delegate: DurableGameWagerAndSettlementStore,
    ) : DurableGameWagerAndSettlementStore by delegate {
        var throwAfterSaveBet = false
        override fun saveBet(bet: GameAcceptedBetRecord) {
            delegate.saveBet(bet)
            if (throwAfterSaveBet) {
                throw SimulatedFailpointException("Triggered failpoint after bet insert")
            }
        }
    }

    class FailpointConfiguredStore(
        private val delegate: DurableGameWagerAndSettlementStore,
    ) : DurableGameWagerAndSettlementStore by delegate {
        var failOn: String? = null
        var failBefore = false

        private fun before(name: String) {
            if (failOn == name && failBefore) throw SimulatedFailpointException("before $name")
        }

        private fun after(name: String) {
            if (failOn == name && !failBefore) throw SimulatedFailpointException("after $name")
        }

        override fun claimReceipt(claim: GameCommandReceiptClaim): CommandReceiptClaimResult {
            before("claimReceipt")
            val outcome = delegate.claimReceipt(claim)
            after("claimReceipt")
            return outcome
        }

        override fun findRoundForShare(tenantId: String, gameId: String, roundId: String): GameRoundRecord? {
            before("findRoundForShare")
            val round = delegate.findRoundForShare(tenantId, gameId, roundId)
            after("findRoundForShare")
            return round
        }

        override fun saveBet(bet: GameAcceptedBetRecord) {
            before("saveBet")
            delegate.saveBet(bet)
            after("saveBet")
        }

        override fun saveSettlement(settlement: GameBetSettlementRecord) {
            before("saveSettlement")
            delegate.saveSettlement(settlement)
            after("saveSettlement")
        }

        override fun addDailyAccumulatedWager(tenantId: String, playerId: String, currencyCode: String, dailyDate: String, amountMinor: Long) {
            before("addDailyAccumulatedWager")
            delegate.addDailyAccumulatedWager(tenantId, playerId, currencyCode, dailyDate, amountMinor)
            after("addDailyAccumulatedWager")
        }

        override fun nextSequenceId(tenantId: String): Long {
            before("nextSequenceId")
            val seq = delegate.nextSequenceId(tenantId)
            after("nextSequenceId")
            return seq
        }

        override fun completeReceipt(tenantId: String, commandId: String, status: String, responseJson: String, serverSequenceId: Long, roundVersion: Long) {
            before("completeReceipt")
            delegate.completeReceipt(tenantId, commandId, status, responseJson, serverSequenceId, roundVersion)
            after("completeReceipt")
        }
    }

    class FailpointLedgerStore(
        private val delegate: LedgerJournalStore,
    ) : LedgerJournalStore by delegate {
        var failOn: String? = null
        var failBefore = false

        private fun before(name: String) {
            if (failOn == name && failBefore) throw SimulatedFailpointException("before $name")
        }

        private fun after(name: String) {
            if (failOn == name && !failBefore) throw SimulatedFailpointException("after $name")
        }

        override fun lockAccount(tenantId: String, accountReference: String, currencyCode: String): Boolean {
            before("lockAccount")
            val acquired = delegate.lockAccount(tenantId, accountReference, currencyCode)
            after("lockAccount")
            return acquired
        }

        override fun findBalance(tenantId: String, accountReference: String, currencyCode: String): Long {
            before("findBalance")
            val balance = delegate.findBalance(tenantId, accountReference, currencyCode)
            after("findBalance")
            return balance
        }

        override fun save(
            result: PostingResult,
            legs: List<JournalEntryRecord>,
            payloadDigest: String,
            audit: AuditEvent,
            outbox: OutboxEvent,
        ) {
            before("ledgerSave")
            delegate.save(result, legs, payloadDigest, audit, outbox)
            after("ledgerSave")
        }
    }

    class FailpointFairnessStore(
        private val delegate: FairnessEvidenceStore,
    ) : FairnessEvidenceStore by delegate {
        var failOn: String? = null
        var failBefore = false

        private fun before(name: String) {
            if (failOn == name && failBefore) throw SimulatedFailpointException("before $name")
        }

        private fun after(name: String) {
            if (failOn == name && !failBefore) throw SimulatedFailpointException("after $name")
        }

        override fun updateCommitment(commitment: RoundCommitmentRecord) {
            before("fairnessUpdate")
            delegate.updateCommitment(commitment)
            after("fairnessUpdate")
        }
    }

    class LockRankTracingStore(
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

        override fun findBet(tenantId: String, gameId: String, roundId: String, ownerId: String, handId: String): GameAcceptedBetRecord? {
            eventLog.add("BET" to 3)
            return delegate.findBet(tenantId, gameId, roundId, ownerId, handId)
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
        jdbc.update("delete from game_fairness_audit where tenant_id = ?", tenantId)
        jdbc.update("delete from game_fairness_reveal where tenant_id = ?", tenantId)
        jdbc.update("delete from game_fairness_commitment where tenant_id = ?", tenantId)
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
        fairnessStore = JdbcFairnessEvidenceStore(jdbc)
        fairnessAuthority = ProvablyFairOutcomeAuthority(store = fairnessStore, clock = clock)
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
                transactionReference = "TX-TC008-SEED-${UUID.randomUUID()}",
                currencyCode = currency,
                entries = listOf(
                    JournalEntryDraft("HOUSE:SEED", JournalEntryDirection.DEBIT, amount, currency),
                    JournalEntryDraft("PLAYER:$playerIdStr", JournalEntryDirection.CREDIT, amount, currency),
                ),
                idempotencyKey = "IDEM-TC008-SEED-${UUID.randomUUID()}",
                correlationId = "corr-tc008-seed",
                causationId = "caus-tc008-seed",
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

    private fun seedCommitment(roundId: String) {
        fairnessAuthority.publishPreBetCommitment(
            PublishCommitmentCommand(
                tenantId = tenantId,
                gameId = gameId,
                roundId = roundId,
                publicSalt = "salt-$roundId",
            )
        )
    }

    private fun ledgerTransactionCountForKey(idempotencyKey: String): Int =
        jdbc.queryForObject(
            "select count(*) from ledger_transaction where tenant_id = ? and idempotency_key = ?",
            Int::class.java,
            tenantId,
            idempotencyKey,
        ) ?: 0

    private fun rootMessage(throwable: Throwable): String {
        val builder = StringBuilder()
        var cause: Throwable? = throwable
        while (cause != null) {
            builder.append(cause.message).append(' ')
            cause = cause.cause
        }
        return builder.toString()
    }

    @Test
    fun `GivenLedgerPostSucceeds_WhenBetWriteFails_ThenNoPartialBet`() {
        val startingBalance = 50000L
        seedFunds(startingBalance)
        val roundId = "rnd-tc008-failpoint"
        createRound(roundId)

        val decorated = FailAfterLedgerBetStore(gameStore)
        val decoratedService = DurableGameWagerAndSettlementService(
            store = decorated,
            ledgerService = ledgerService,
            registrationStore = registrationStore,
            eligibilityStore = eligibilityStore,
            adminPrincipal = adminPrincipal,
            clock = clock,
        )
        decorated.throwAfterSaveBet = true
        val txTemplate = TransactionTemplate(txManager)

        assertThrows<SimulatedFailpointException> {
            txTemplate.execute<Unit> {
                decoratedService.processCommand(
                    AviatorRestCommand(
                        tenantId = tenantId,
                        principal = playerPrincipal,
                        commandId = "cmd-tc008-failpoint",
                        roundId = roundId,
                        handId = "hand_primary",
                        action = "PLACE_BET",
                        wagerMinor = 60L,
                        currency = currency,
                        correlationId = "corr-tc008-failpoint",
                    )
                )
            }
        }

        val placeBetKey = AviatorCommandKeys.placeBetKey(tenantId, gameId, roundId, playerIdStr, "hand_primary")
        assertNull(gameStore.findBet(tenantId, gameId, roundId, playerIdStr, "hand_primary"), "No bet may persist after rollback")
        assertNull(gameStore.findReceipt(tenantId, "cmd-tc008-failpoint"), "No receipt may persist after rollback")
        assertEquals(0, ledgerTransactionCountForKey(placeBetKey), "No ledger movement may persist after rollback")
        assertEquals(startingBalance, ledgerStore.findBalance(tenantId, "PLAYER:$playerIdStr", currency))
        val sequenceRow = jdbc.queryForObject(
            "select count(*) from game_command_sequence where tenant_id = ?",
            Int::class.java,
            tenantId,
        )
        assertEquals(0, sequenceRow, "Sequence counter must roll back with the aborted place-bet")
    }

    @Test
    fun `GivenDuplicateCommand_WhenOneHundredRequestsRace_ThenOneBetAndDebit`() {
        seedFunds(2_000_000L)
        val pool = Executors.newFixedThreadPool(32)

        for (iteration in 0 until 100) {
            val roundId = "rnd-tc008-race-$iteration"
            createRound(roundId)
            val commandId = "cmd-tc008-race-$iteration"
            val command = AviatorRestCommand(
                tenantId = tenantId,
                principal = playerPrincipal,
                commandId = commandId,
                roundId = roundId,
                handId = "hand_primary",
                action = "PLACE_BET",
                wagerMinor = 60L,
                currency = currency,
                correlationId = "corr-tc008-race-$iteration",
            )

            val results = ConcurrentLinkedQueue<String>()
            val startLatch = CountDownLatch(1)
            val doneLatch = CountDownLatch(100)
            repeat(100) {
                pool.submit {
                    startLatch.await()
                    try {
                        val ack = gameService.processCommand(command)
                        results.add("${ack.status}:${ack.sequenceId}:${ack.result?.accountMoneyAfterMinor}")
                    } catch (e: Exception) {
                        results.add("ERROR:${e.javaClass.simpleName}:${e.message}")
                    } finally {
                        doneLatch.countDown()
                    }
                }
            }

            startLatch.countDown()
            assertTrue(doneLatch.await(120, TimeUnit.SECONDS), "iteration $iteration racing place-bet commands timed out")
            assertEquals(100, results.size)
            val distinct = results.toSet()
            assertEquals(1, distinct.size, "iteration $iteration must observe one identical stored result: $distinct")
            assertTrue(distinct.first().startsWith("ACCEPTED"), "iteration $iteration winner must be the accepted stored response")

            val placeBetKey = AviatorCommandKeys.placeBetKey(tenantId, gameId, roundId, playerIdStr, "hand_primary")
            assertEquals(1, ledgerTransactionCountForKey(placeBetKey), "iteration $iteration must post exactly one reservation debit")
            val betCount = jdbc.queryForObject(
                "select count(*) from game_accepted_bet where tenant_id = ? and round_id = ?",
                Int::class.java,
                tenantId,
                roundId,
            )
            assertEquals(1, betCount, "iteration $iteration must persist exactly one bet")
        }
        pool.shutdown()
    }

    @Test
    fun `GivenCommittedBet_WhenTransportResponseLost_ThenLookupAndRetryReturnOriginal`() {
        seedFunds(100000L)
        val roundId = "rnd-tc008-lost-response"
        createRound(roundId)

        val commandId = "cmd-tc008-lost"
        val command = AviatorRestCommand(
            tenantId = tenantId,
            principal = playerPrincipal,
            commandId = commandId,
            roundId = roundId,
            handId = "hand_primary",
            action = "PLACE_BET",
            wagerMinor = 60L,
            currency = currency,
            correlationId = "corr-tc008-lost",
        )

        val ack = gameService.processCommand(command)
        assertEquals(AviatorCommandAckStatus.ACCEPTED, ack.status)
        assertEquals(99940L, ack.result?.accountMoneyAfterMinor)

        val lookedUp = gameService.getCommandResult(tenantId, playerPrincipal, roundId, commandId)
        assertNotNull(lookedUp)
        assertEquals(ack.sequenceId, lookedUp.sequenceId)
        assertEquals(99940L, lookedUp.result?.accountMoneyAfterMinor)

        val replay = gameService.processCommand(command)
        assertEquals(ack.sequenceId, replay.sequenceId)
        assertEquals(99940L, replay.result?.accountMoneyAfterMinor)

        assertThrows<com.slotting.admin.auth.AuthenticationFailure.Rejected> {
            gameService.processCommand(command.copy(wagerMinor = 61L))
        }

        val placeBetKey = AviatorCommandKeys.placeBetKey(tenantId, gameId, roundId, playerIdStr, "hand_primary")
        assertEquals(1, ledgerTransactionCountForKey(placeBetKey), "Changed payload must not post a second debit")
        assertEquals(99940L, ledgerStore.findBalance(tenantId, "PLAYER:$playerIdStr", currency))
    }

    @Test
    fun `GivenPlaceBet_WhenLocksAreObserved_ThenGlobalOrderIsPreserved`() {
        seedFunds(100000L)
        val roundId = "rnd-tc008-lock-order"
        createRound(roundId)

        val tracing = LockRankTracingStore(gameStore)
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
                commandId = "cmd-tc008-lock-order",
                roundId = roundId,
                handId = "hand_primary",
                action = "PLACE_BET",
                wagerMinor = 60L,
                currency = currency,
                correlationId = "corr-tc008-lock-order",
            )
        )
        assertEquals(AviatorCommandAckStatus.ACCEPTED, ack.status)

        var previousRank = 0
        for ((resource, rank) in tracing.eventLog) {
            if (resource == "RECEIPT_WRITE") {
                continue
            }
            assertTrue(rank >= previousRank, "Lock rank inversion at $resource ($rank) after $previousRank")
            previousRank = rank
        }
        assertTrue(tracing.eventLog.any { it.first == "RECEIPT" }, "Early claim must be the first lock")
        assertTrue(tracing.eventLog.any { it.first == "ROUND_SHARED" })
        assertTrue(tracing.eventLog.any { it.first == "BET" })
        assertTrue(tracing.eventLog.any { it.first == "SEQUENCE_COUNTER" })
    }

    @Test
    fun `GivenHistoricalMoneyAndOutcomeVectors_WhenRefactoredPathRuns_ThenSemanticsStayUnchanged`() {
        val wagerMinor = 101L
        val multiplier = BigDecimal("1.2345")
        val expectedWinMinor = BigDecimal.valueOf(wagerMinor)
            .multiply(multiplier)
            .setScale(0, RoundingMode.FLOOR)
            .longValueExact()
        assertEquals(124L, expectedWinMinor)

        val startingBalance = 50000L
        seedFunds(startingBalance)

        val cashOutRound = "rnd-tc008-golden-cashout"
        createRound(cashOutRound)
        val placeAck = gameService.processCommand(
            AviatorRestCommand(
                tenantId = tenantId,
                principal = playerPrincipal,
                commandId = "cmd-tc008-golden-bet-1",
                roundId = cashOutRound,
                handId = "hand_primary",
                action = "PLACE_BET",
                wagerMinor = wagerMinor,
                currency = currency,
                correlationId = "corr-tc008-golden-bet-1",
            )
        )
        assertEquals(AviatorCommandAckStatus.ACCEPTED, placeAck.status)

        createRound(cashOutRound, phase = GameRoundPhase.FLYING, version = 2L, multiplier = multiplier)
        val cashOutAck = gameService.processCommand(
            AviatorRestCommand(
                tenantId = tenantId,
                principal = playerPrincipal,
                commandId = "cmd-tc008-golden-cashout-1",
                roundId = cashOutRound,
                handId = "hand_primary",
                action = "CASH_OUT",
                correlationId = "corr-tc008-golden-cashout-1",
            )
        )
        assertEquals(AviatorCommandAckStatus.ACCEPTED, cashOutAck.status)
        assertEquals(expectedWinMinor, cashOutAck.result?.payoutMinor)
        assertEquals(
            startingBalance - wagerMinor + expectedWinMinor,
            ledgerStore.findBalance(tenantId, "PLAYER:$playerIdStr", currency),
        )

        val lossRound = "rnd-tc008-golden-loss"
        createRound(lossRound)
        val lossBet = gameService.processCommand(
            AviatorRestCommand(
                tenantId = tenantId,
                principal = playerPrincipal,
                commandId = "cmd-tc008-golden-bet-2",
                roundId = lossRound,
                handId = "hand_primary",
                action = "PLACE_BET",
                wagerMinor = wagerMinor,
                currency = currency,
                correlationId = "corr-tc008-golden-bet-2",
            )
        )
        assertEquals(AviatorCommandAckStatus.ACCEPTED, lossBet.status)

        val crashResult = gameService.settleRoundCrash(
            SettleRoundCrashCommand(
                tenantId = tenantId,
                gameId = gameId,
                roundId = lossRound,
                crashMultiplier = BigDecimal("1.0000"),
            )
        )
        assertEquals(1, crashResult.settledBetsCount)
        assertEquals(0L, jdbc.queryForObject(
            "select payout_minor_units from game_bet_settlement where tenant_id = ? and outcome = 'LOSS_CRASH'",
            Long::class.java,
            tenantId,
        ))

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

        val terminalCount = jdbc.queryForObject(
            "select count(*) from game_bet_settlement where tenant_id = ?",
            Int::class.java,
            tenantId,
        ) ?: 0
        assertEquals(2, terminalCount, "Each bet must have exactly one terminal settlement")
    }

    @Test
    fun `GivenDistinctIdsSameHand_WhenRequestsRace_ThenOneBetAndDebit`() {
        seedFunds(2_000_000L)
        val pool = Executors.newFixedThreadPool(32)

        for (iteration in 0 until 100) {
            val roundId = "rnd-tc008-distinct-hand-$iteration"
            createRound(roundId)

            val results = ConcurrentLinkedQueue<String>()
            val startLatch = CountDownLatch(1)
            val doneLatch = CountDownLatch(100)
            repeat(100) { request ->
                pool.submit {
                    startLatch.await()
                    try {
                        val ack = gameService.processCommand(
                            AviatorRestCommand(
                                tenantId = tenantId,
                                principal = playerPrincipal,
                                commandId = "cmd-tc008-distinct-$iteration-$request",
                                roundId = roundId,
                                handId = "hand_primary",
                                action = "PLACE_BET",
                                wagerMinor = 60L,
                                currency = currency,
                                correlationId = "corr-tc008-distinct-$iteration-$request",
                            )
                        )
                        results.add("ACK:${ack.status}")
                    } catch (e: Exception) {
                        results.add("ERROR:${e.javaClass.simpleName}")
                    } finally {
                        doneLatch.countDown()
                    }
                }
            }

            startLatch.countDown()
            assertTrue(doneLatch.await(120, TimeUnit.SECONDS), "iteration $iteration distinct-id same-hand race timed out")

            val placeBetKey = AviatorCommandKeys.placeBetKey(tenantId, gameId, roundId, playerIdStr, "hand_primary")
            assertEquals(1, ledgerTransactionCountForKey(placeBetKey), "iteration $iteration must post exactly one reservation debit for the hand")
            val betCount = jdbc.queryForObject(
                "select count(*) from game_accepted_bet where tenant_id = ? and round_id = ?",
                Int::class.java,
                tenantId,
                roundId,
            ) ?: 0
            assertEquals(1, betCount, "iteration $iteration must persist exactly one bet for the hand")
            assertTrue(results.any { it == "ACK:ACCEPTED" }, "iteration $iteration must accept exactly one command: $results")
        }
        pool.shutdown()
    }

    @Test
    fun `GivenFailpointsCoveringEachCommandStep_WhenBeforeOrAfterFails_ThenFullRollback`() {
        val startingBalance = 50000L
        seedFunds(startingBalance)
        val roundId = "rnd-tc008-failpoint-matrix"
        createRound(roundId)
        seedCommitment(roundId)
        val today = now.atZone(ZoneOffset.UTC).toLocalDate().toString()
        val txTemplate = TransactionTemplate(txManager)

        val failpoints = listOf(
            "GAME:claimReceipt:before",
            "GAME:claimReceipt:after",
            "GAME:findRoundForShare:before",
            "GAME:findRoundForShare:after",
            "GAME:saveBet:before",
            "GAME:saveBet:after",
            "LEDGER:lockAccount:before",
            "LEDGER:lockAccount:after",
            "LEDGER:findBalance:before",
            "LEDGER:findBalance:after",
            "LEDGER:ledgerSave:before",
            "LEDGER:ledgerSave:after",
            "FAIRNESS:fairnessUpdate:before",
            "FAIRNESS:fairnessUpdate:after",
            "GAME:addDailyAccumulatedWager:before",
            "GAME:addDailyAccumulatedWager:after",
            "GAME:nextSequenceId:before",
            "GAME:nextSequenceId:after",
            "GAME:completeReceipt:before",
            "GAME:completeReceipt:after",
        )

        for ((index, spec) in failpoints.withIndex()) {
            val target = spec.substringBefore(':')
            val method = spec.substringAfter(':').substringBefore(':')
            val before = spec.endsWith(":before")

            val gameFailpoint = FailpointConfiguredStore(gameStore)
            val ledgerFailpoint = FailpointLedgerStore(ledgerStore)
            val fairnessFailpoint = FailpointFairnessStore(fairnessStore)
            when (target) {
                "GAME" -> {
                    gameFailpoint.failOn = method
                    gameFailpoint.failBefore = before
                }
                "LEDGER" -> {
                    ledgerFailpoint.failOn = method
                    ledgerFailpoint.failBefore = before
                }
                "FAIRNESS" -> {
                    fairnessFailpoint.failOn = method
                    fairnessFailpoint.failBefore = before
                }
            }

            val ledgerSvc = LedgerPostingService(store = ledgerFailpoint, clock = clock)
            val fairnessAuth = ProvablyFairOutcomeAuthority(store = fairnessFailpoint, clock = clock)
            val service = DurableGameWagerAndSettlementService(
                store = gameFailpoint,
                ledgerService = ledgerSvc,
                registrationStore = registrationStore,
                eligibilityStore = eligibilityStore,
                adminPrincipal = adminPrincipal,
                clock = clock,
                fairnessAuthority = fairnessAuth,
            )
            val commandId = "cmd-tc008-fp-$index"
            val ledgerPostSpecs = setOf(
                "LEDGER:lockAccount:before",
                "LEDGER:lockAccount:after",
                "LEDGER:ledgerSave:before",
            )

            var thrown: SimulatedFailpointException? = null
            val ack = try {
                txTemplate.execute<AviatorCommandAckResult> {
                    service.processCommand(
                        AviatorRestCommand(
                            tenantId = tenantId,
                            principal = playerPrincipal,
                            commandId = commandId,
                            roundId = roundId,
                            handId = "hand_primary",
                            action = "PLACE_BET",
                            wagerMinor = 60L,
                            currency = currency,
                            correlationId = "corr-$commandId",
                        )
                    )
                }
            } catch (e: SimulatedFailpointException) {
                thrown = e
                null
            }

            if (spec in ledgerPostSpecs) {
                val rejection = assertNotNull(ack, "ledger post failure must produce a rejection at $spec")
                assertEquals(AviatorCommandAckStatus.REJECTED, rejection.status, "expected rejection at $spec")
            } else {
                assertTrue(thrown != null, "expected rollback exception at $spec")
                assertNull(gameStore.findReceipt(tenantId, commandId), "receipt persisted at $spec")
            }

            assertNull(gameStore.findBet(tenantId, gameId, roundId, playerIdStr, "hand_primary"), "bet persisted at $spec")
            assertEquals(startingBalance, ledgerStore.findBalance(tenantId, "PLAYER:$playerIdStr", currency), "balance changed at $spec")
            assertEquals(0L, gameStore.findDailyAccumulatedWager(tenantId, playerIdStr, currency, today), "limit changed at $spec")
            assertEquals(0, ledgerTransactionCountForKey(AviatorCommandKeys.placeBetKey(tenantId, gameId, roundId, playerIdStr, "hand_primary")), "journal persisted at $spec")
            val round = gameStore.findRound(tenantId, gameId, roundId)
            assertNotNull(round)
            assertEquals(GameRoundPhase.BET_COUNTDOWN, round.phase, "round phase changed at $spec")
            assertEquals(1L, round.roundVersion, "round version changed at $spec")
            val commitment = fairnessStore.findCommitment(tenantId, gameId, roundId)
            assertNotNull(commitment)
            assertEquals(RoundCommitmentStatus.COMMITTED, commitment.status, "fairness status changed at $spec")
            assertEquals(1L, commitment.serverVersion, "fairness version changed at $spec")
            assertNull(commitment.firstBetAcceptedAt, "fairness first-bet marker changed at $spec")
        }
        assertEquals(20, failpoints.size, "Each command step must have a before and after failpoint")
    }

    @Test
    fun `GivenLedgerFailure_WhenReservationRejected_ThenNoBetAndNoLimitChange`() {
        val startingBalance = 50000L
        seedFunds(startingBalance)
        val roundId = "rnd-tc008-ledger-fail"
        createRound(roundId)
        val today = now.atZone(ZoneOffset.UTC).toLocalDate().toString()

        val failingLedger = object : LedgerPostingService(store = ledgerStore, clock = clock) {
            override fun postTransaction(command: PostTransactionCommand): PostingResult {
                throw LedgerPostingException("SIMULATED_FAILURE", "Simulated ledger storage down")
            }
        }
        val service = DurableGameWagerAndSettlementService(
            store = gameStore,
            ledgerService = failingLedger,
            registrationStore = registrationStore,
            eligibilityStore = eligibilityStore,
            adminPrincipal = adminPrincipal,
            clock = clock,
            txManager = txManager,
        )
        val ack = service.processCommand(
            AviatorRestCommand(
                tenantId = tenantId,
                principal = playerPrincipal,
                commandId = "cmd-tc008-ledger-fail",
                roundId = roundId,
                handId = "hand_primary",
                action = "PLACE_BET",
                wagerMinor = 60L,
                currency = currency,
                correlationId = "corr-tc008-ledger-fail",
            )
        )
        assertEquals(AviatorCommandAckStatus.REJECTED, ack.status)
        assertNull(gameStore.findBet(tenantId, gameId, roundId, playerIdStr, "hand_primary"))
        assertEquals(startingBalance, ledgerStore.findBalance(tenantId, "PLAYER:$playerIdStr", currency))
        assertEquals(0L, gameStore.findDailyAccumulatedWager(tenantId, playerIdStr, currency, today))
    }

    @Test
    fun `GivenOpposingLifecycleWriter_WhenPlaceBetHoldsSharedRoundLock_ThenLifecycleIsExclusive`() {
        seedFunds(100000L)
        val roundId = "rnd-tc008-opposing"
        createRound(roundId)
        val txTemplate = TransactionTemplate(txManager)
        val pool = Executors.newFixedThreadPool(3)
        val sharedHeld = CountDownLatch(1)
        val release = CountDownLatch(1)
        val exclusiveAcquired = CountDownLatch(1)

        val holder = pool.submit {
            txTemplate.execute<Unit> {
                gameStore.findRoundForShare(tenantId, gameId, roundId)
                sharedHeld.countDown()
                release.await(10, TimeUnit.SECONDS)
            }
        }
        assertTrue(sharedHeld.await(5, TimeUnit.SECONDS), "command must hold the shared round lock")

        val lifecycle = pool.submit {
            txTemplate.execute<Unit> {
                gameStore.findRoundForUpdate(tenantId, gameId, roundId)
                exclusiveAcquired.countDown()
            }
        }
        assertTrue(!exclusiveAcquired.await(1, TimeUnit.SECONDS), "lifecycle exclusive lock must be blocked by the shared command lock")
        release.countDown()
        holder.get(10, TimeUnit.SECONDS)
        lifecycle.get(10, TimeUnit.SECONDS)

        val inversionRoundId = "rnd-tc008-inversion"
        createRound(inversionRoundId)
        val deadlockDetected = AtomicBoolean(false)
        val ready = CountDownLatch(2)

        val forward = pool.submit {
            try {
                txTemplate.execute<Unit> {
                    jdbc.execute("SET LOCAL deadlock_timeout = '100ms'")
                    gameStore.findRoundForUpdate(tenantId, gameId, inversionRoundId)
                    ready.countDown()
                    ready.await(5, TimeUnit.SECONDS)
                    Thread.sleep(50)
                    gameStore.nextSequenceId(tenantId)
                }
            } catch (e: Exception) {
                if (rootMessage(e).contains("deadlock detected")) deadlockDetected.set(true)
            }
        }
        val inverted = pool.submit {
            try {
                txTemplate.execute<Unit> {
                    jdbc.execute("SET LOCAL deadlock_timeout = '100ms'")
                    gameStore.nextSequenceId(tenantId)
                    ready.countDown()
                    ready.await(5, TimeUnit.SECONDS)
                    Thread.sleep(50)
                    gameStore.findRoundForUpdate(tenantId, gameId, inversionRoundId)
                }
            } catch (e: Exception) {
                if (rootMessage(e).contains("deadlock detected")) deadlockDetected.set(true)
            }
        }
        forward.get(10, TimeUnit.SECONDS)
        inverted.get(10, TimeUnit.SECONDS)
        assertTrue(deadlockDetected.get(), "PostgreSQL must detect the inverted round/sequence acquisition order")
        pool.shutdown()
    }

    @Test
    fun `GivenMixedOperations_WhenLocksAreObservedForOneHundredIterations_ThenGlobalOrderIsPreserved`() {
        seedFunds(2_000_000L)
        val pool = Executors.newFixedThreadPool(2)

        for (iteration in 0 until 100) {
            val roundId = "rnd-tc008-trace-$iteration"
            createRound(roundId)

            val commandStore = LockRankTracingStore(gameStore)
            val commandService = DurableGameWagerAndSettlementService(
                store = commandStore,
                ledgerService = ledgerService,
                registrationStore = registrationStore,
                eligibilityStore = eligibilityStore,
                adminPrincipal = adminPrincipal,
                clock = clock,
                txManager = txManager,
            )

            val lifecycleEvents = java.util.Collections.synchronizedList(mutableListOf<Pair<String, Int>>())
            val lifecycleStore = object : DurableGameWagerAndSettlementStore by gameStore {
                override fun findRoundForUpdate(tenantId: String, gameId: String, roundId: String): GameRoundRecord? {
                    lifecycleEvents.add("ROUND_EXCLUSIVE" to 2)
                    return gameStore.findRoundForUpdate(tenantId, gameId, roundId)
                }
            }
            val lifecycleService = DurableGameWagerAndSettlementService(
                store = lifecycleStore,
                ledgerService = ledgerService,
                registrationStore = registrationStore,
                eligibilityStore = eligibilityStore,
                adminPrincipal = adminPrincipal,
                clock = clock,
                txManager = txManager,
            )

            val latch = CountDownLatch(2)
            val commandWorker = pool.submit {
                try {
                    commandService.processCommand(
                        AviatorRestCommand(
                            tenantId = tenantId,
                            principal = playerPrincipal,
                            commandId = "cmd-tc008-trace-$iteration",
                            roundId = roundId,
                            handId = "hand_primary",
                            action = "PLACE_BET",
                            wagerMinor = 60L,
                            currency = currency,
                            correlationId = "corr-tc008-trace-$iteration",
                        )
                    )
                } catch (e: Exception) {
                    if (rootMessage(e).contains("deadlock detected")) {
                        throw e
                    }
                } finally {
                    latch.countDown()
                }
            }
            val lifecycleWorker = pool.submit {
                try {
                    lifecycleService.createOrUpdateRound(
                        CreateOrUpdateRoundCommand(
                            tenantId = tenantId,
                            gameId = gameId,
                            roundId = roundId,
                            phase = GameRoundPhase.FLYING,
                            roundVersion = 2L,
                            expectedVersion = 1L,
                            currentMultiplier = BigDecimal("1.0000"),
                        )
                    )
                } catch (e: RoundVersionConflictException) {
                } finally {
                    latch.countDown()
                }
            }

            assertTrue(latch.await(30, TimeUnit.SECONDS), "iteration $iteration workers timed out")
            commandWorker.get(30, TimeUnit.SECONDS)
            lifecycleWorker.get(30, TimeUnit.SECONDS)

            var previousRank = 0
            for ((resource, rank) in commandStore.eventLog) {
                if (resource == "RECEIPT_WRITE") {
                    continue
                }
                assertTrue(rank >= previousRank, "iteration $iteration rank inversion at $resource ($rank) after $previousRank")
                previousRank = rank
            }
            assertTrue(commandStore.eventLog.any { it.first == "ROUND_SHARED" }, "iteration $iteration command must acquire the shared round lock")
            assertTrue(lifecycleEvents.any { it.first == "ROUND_EXCLUSIVE" }, "iteration $iteration lifecycle must acquire the exclusive round lock")
        }
        pool.shutdown()
    }
}
