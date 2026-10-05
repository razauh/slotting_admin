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
import com.slotting.admin.ledger.IdempotencyConflictException
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
import kotlin.test.assertTrue

@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.NONE)
class AviatorCommandClaimPostgresTest {

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
    private val tenantId = "tenant-tc006-claim"
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
                transactionReference = "TX-CLAIM-SEED-${UUID.randomUUID()}",
                currencyCode = "INR",
                entries = listOf(
                    JournalEntryDraft("HOUSE:SEED", JournalEntryDirection.DEBIT, amount, "INR"),
                    JournalEntryDraft("PLAYER:$playerIdStr", JournalEntryDirection.CREDIT, amount, "INR"),
                ),
                idempotencyKey = "IDEM-CLAIM-SEED-${UUID.randomUUID()}",
                correlationId = "corr-claim-seed",
                causationId = "caus-claim-seed",
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

    private fun claim(
        commandId: String,
        fingerprint: String,
        roundId: String,
        action: String = "PLACE_BET",
        handId: String = "hand_primary",
    ): GameCommandReceiptClaim = GameCommandReceiptClaim(
        receiptId = UUID.randomUUID(),
        tenantId = tenantId,
        ownerId = playerIdStr,
        gameId = gameId,
        commandId = commandId,
        roundId = roundId,
        handId = handId,
        action = action,
        fingerprint = fingerprint,
        causationId = "caus-$commandId",
        correlationId = "corr-$commandId",
        roundVersion = 1L,
        createdAt = now,
    )

    private fun ledgerTransactionCount(): Int =
        jdbc.queryForObject("select count(*) from ledger_transaction where tenant_id = ?", Int::class.java, tenantId) ?: 0

    private fun ledgerTransactionCountForKey(idempotencyKey: String): Int =
        jdbc.queryForObject(
            "select count(*) from ledger_transaction where tenant_id = ? and idempotency_key = ?",
            Int::class.java,
            tenantId,
            idempotencyKey,
        ) ?: 0

    private fun ledgerLegCountForKey(idempotencyKey: String): Int =
        jdbc.queryForObject(
            """
            select count(*) from ledger_leg l
            join ledger_transaction t on l.transaction_id = t.transaction_id
            where t.tenant_id = ? and t.idempotency_key = ?
            """.trimIndent(),
            Int::class.java,
            tenantId,
            idempotencyKey,
        ) ?: 0

    @Test
    fun `GivenSameOperation_WhenKeyBuiltTwice_ThenKeysAreStableAndDomainSeparated`() {
        val betId = UUID.fromString("00000000-0000-0000-0000-0000000000b1")
        val first = AviatorCommandKeys.placeBetKey("t1", "game", "r1", "p1", "hand")
        val second = AviatorCommandKeys.placeBetKey("t1", "game", "r1", "p1", "hand")
        assertEquals("bet:t1:game:r1:p1:hand", first)
        assertEquals(first, second)
        assertEquals("settle:$betId", AviatorCommandKeys.settlementKey(betId))
        val changedHand = AviatorCommandKeys.placeBetKey("t1", "game", "r1", "p1", "hand2")
        assertTrue(first != changedHand, "Changed hand must yield a different place key")
        assertEquals(
            AviatorCommandKeys.ledgerTransactionReference("WAGER", first),
            AviatorCommandKeys.ledgerTransactionReference("WAGER", second),
        )

        seedFunds(50000L)
        val roundId = "rnd-key-stable"
        createRound(roundId)

        val ack = gameService.processCommand(
            AviatorRestCommand(
                tenantId = tenantId,
                principal = playerPrincipal,
                commandId = "cmd-key-stable-1",
                roundId = roundId,
                handId = "hand_primary",
                action = "PLACE_BET",
                wagerMinor = 60L,
                currency = "INR",
                correlationId = "corr-key-stable-1",
            )
        )
        assertEquals(AviatorCommandAckStatus.ACCEPTED, ack.status)

        val placeBetKey = AviatorCommandKeys.placeBetKey(tenantId, gameId, roundId, playerIdStr, "hand_primary")
        val storedIdempotencyKey = jdbc.queryForObject(
            "select idempotency_key from ledger_transaction where tenant_id = ? and transaction_reference = ?",
            String::class.java,
            tenantId,
            AviatorCommandKeys.ledgerTransactionReference("WAGER", placeBetKey),
        )
        assertEquals(placeBetKey, storedIdempotencyKey)
    }

    @Test
    fun `GivenSameClaim_WhenOneHundredTransactionsRace_ThenOneOwnerAndSameResult`() {
        seedFunds(100000L)
        val roundId = "rnd-claim-race"
        createRound(roundId)

        val commandId = "cmd-claim-race"
        val fingerprint = "fp-claim-race"
        val placeBetKey = AviatorCommandKeys.placeBetKey(tenantId, gameId, roundId, playerIdStr, "hand_primary")
        val txRef = AviatorCommandKeys.ledgerTransactionReference("WAGER", placeBetKey)
        val txTemplate = TransactionTemplate(txManager)
        val pool = Executors.newFixedThreadPool(20)
        val results = ConcurrentLinkedQueue<String>()
        val startLatch = CountDownLatch(1)
        val doneLatch = CountDownLatch(100)

        for (i in 0 until 100) {
            pool.submit {
                startLatch.await()
                try {
                    val result = txTemplate.execute<String> {
                        when (val outcome = gameStore.claimReceipt(claim(commandId, fingerprint, roundId))) {
                            is CommandReceiptClaimResult.Claimed -> {
                                ledgerService.postTransaction(
                                    PostTransactionCommand(
                                        principal = adminPrincipal,
                                        tenantId = tenantId,
                                        transactionReference = txRef,
                                        currencyCode = "INR",
                                        entries = listOf(
                                            JournalEntryDraft("PLAYER:$playerIdStr", JournalEntryDirection.DEBIT, 60L, "INR"),
                                            JournalEntryDraft("ESCROW:GAME:$gameId", JournalEntryDirection.CREDIT, 60L, "INR"),
                                        ),
                                        idempotencyKey = placeBetKey,
                                        correlationId = "corr-claim-race",
                                        causationId = "caus-claim-race",
                                    )
                                )
                                val seq = gameStore.nextSequenceId(tenantId)
                                val json = "{\"status\":\"ACCEPTED\",\"sequenceId\":$seq}"
                                gameStore.completeReceipt(tenantId, commandId, "ACCEPTED", json, seq, 1L)
                                json
                            }
                            is CommandReceiptClaimResult.AlreadyClaimed -> outcome.receipt.responseJson
                        }
                    }
                    if (result != null) {
                        results.add(result)
                    }
                } catch (e: Exception) {
                    results.add("ERROR:${e.javaClass.simpleName}:${e.message}")
                } finally {
                    doneLatch.countDown()
                }
            }
        }

        startLatch.countDown()
        assertTrue(doneLatch.await(60, TimeUnit.SECONDS), "100 racing claims timed out")
        pool.shutdown()

        assertEquals(100, results.size)
        val distinct = results.toSet()
        assertEquals(1, distinct.size, "All racing claims must observe one identical stored result: $distinct")
        assertTrue(distinct.first().startsWith("{\"status\":\"ACCEPTED\""), "Winner result must be the stored response")
        assertEquals(1, ledgerTransactionCountForKey(placeBetKey), "Exactly one ledger movement must be posted for the claim")
        assertEquals(2, ledgerLegCountForKey(placeBetKey), "Exactly one debit and one credit leg")
    }

    @Test
    fun `GivenReusedCommandOrLedgerKey_WhenPayloadDiffers_ThenConflict`() {
        seedFunds(50000L)
        val roundId = "rnd-claim-conflict"
        createRound(roundId)

        val commandId = "cmd-claim-conflict"
        val fingerprint = "fp-original-60"
        val placeBetKey = AviatorCommandKeys.placeBetKey(tenantId, gameId, roundId, playerIdStr, "hand_primary")
        val txRef = AviatorCommandKeys.ledgerTransactionReference("WAGER", placeBetKey)
        val txTemplate = TransactionTemplate(txManager)

        txTemplate.execute<Unit> {
            val outcome = gameStore.claimReceipt(claim(commandId, fingerprint, roundId))
            assertTrue(outcome is CommandReceiptClaimResult.Claimed)
            ledgerService.postTransaction(
                PostTransactionCommand(
                    principal = adminPrincipal,
                    tenantId = tenantId,
                    transactionReference = txRef,
                    currencyCode = "INR",
                    entries = listOf(
                        JournalEntryDraft("PLAYER:$playerIdStr", JournalEntryDirection.DEBIT, 60L, "INR"),
                        JournalEntryDraft("ESCROW:GAME:$gameId", JournalEntryDirection.CREDIT, 60L, "INR"),
                    ),
                    idempotencyKey = placeBetKey,
                    correlationId = "corr-conflict",
                    causationId = "caus-conflict",
                )
            )
            gameStore.completeReceipt(tenantId, commandId, "ACCEPTED", "{\"status\":\"ACCEPTED\"}", 1L, 1L)
        }

        assertThrows<CommandClaimConflictException> {
            txTemplate.execute<Unit> {
                gameStore.claimReceipt(claim(commandId, "fp-reused-61", roundId))
            }
        }

        assertThrows<IdempotencyConflictException> {
            txTemplate.execute<Unit> {
                ledgerService.postTransaction(
                    PostTransactionCommand(
                        principal = adminPrincipal,
                        tenantId = tenantId,
                        transactionReference = txRef,
                        currencyCode = "INR",
                        entries = listOf(
                            JournalEntryDraft("PLAYER:$playerIdStr", JournalEntryDirection.DEBIT, 61L, "INR"),
                            JournalEntryDraft("ESCROW:GAME:$gameId", JournalEntryDirection.CREDIT, 61L, "INR"),
                        ),
                        idempotencyKey = placeBetKey,
                        correlationId = "corr-conflict",
                        causationId = "caus-conflict",
                    )
                )
            }
        }
        assertEquals(1, ledgerTransactionCountForKey(placeBetKey), "No second movement may be posted for a conflicting payload")

        val legacyCommandId = "cmd-legacy-sentinel"
        gameStore.saveReceipt(
            GameCommandReceiptRecord(
                receiptId = UUID.randomUUID(),
                tenantId = tenantId,
                ownerId = playerIdStr,
                gameId = gameId,
                commandId = legacyCommandId,
                roundId = roundId,
                handId = "hand_primary",
                action = "PLACE_BET",
                status = "ACCEPTED",
                fingerprint = "legacy-sentinel",
                responseJson = "{\"status\":\"ACCEPTED\"}",
                causationId = "caus-legacy",
                correlationId = "corr-legacy",
                serverSequenceId = 900L,
                roundVersion = 1L,
                createdAt = now,
            )
        )
        assertThrows<CommandClaimConflictException> {
            txTemplate.execute<Unit> {
                gameStore.claimReceipt(claim(legacyCommandId, "modern-fingerprint", roundId))
            }
        }
        val legacyReplay = txTemplate.execute<CommandReceiptClaimResult> {
            gameStore.claimReceipt(claim(legacyCommandId, "legacy-sentinel", roundId))
        }
        assertTrue(legacyReplay is CommandReceiptClaimResult.AlreadyClaimed)

        val retryCommandId = "cmd-rollback-retry"
        assertThrows<RuntimeException> {
            txTemplate.execute<Unit> {
                gameStore.claimReceipt(claim(retryCommandId, "fp-rollback", roundId))
                throw RuntimeException("simulated owner failure")
            }
        }
        val countAfterRollback = jdbc.queryForObject(
            "select count(*) from game_command_receipt where tenant_id = ? and command_id = ?",
            Int::class.java,
            tenantId,
            retryCommandId,
        )
        assertEquals(0, countAfterRollback, "Rolled-back claim must leave no durable receipt")
        val retryOutcome = txTemplate.execute<CommandReceiptClaimResult> {
            val outcome = gameStore.claimReceipt(claim(retryCommandId, "fp-rollback", roundId))
            if (outcome is CommandReceiptClaimResult.Claimed) {
                gameStore.completeReceipt(tenantId, retryCommandId, "ACCEPTED", "{\"status\":\"ACCEPTED\"}", 2L, 1L)
            }
            outcome
        }
        assertTrue(retryOutcome is CommandReceiptClaimResult.Claimed, "Rollback must permit retry ownership")
    }

    @Test
    fun `GivenUncompletedEarlyClaim_WhenTransactionCommits_ThenCommitIsRejected`() {
        val txTemplate = TransactionTemplate(txManager)
        val commandId = "cmd-incomplete-claim"

        assertThrows<Exception> {
            txTemplate.execute<Unit> {
                val outcome = gameStore.claimReceipt(claim(commandId, "fp-incomplete", "rnd-incomplete"))
                assertTrue(outcome is CommandReceiptClaimResult.Claimed)
                gameStore.nextSequenceId(tenantId)
            }
        }

        val receiptCount = jdbc.queryForObject(
            "select count(*) from game_command_receipt where tenant_id = ? and command_id = ?",
            Int::class.java,
            tenantId,
            commandId,
        )
        assertEquals(0, receiptCount, "No pending receipt may be durable after commit rejection")
        assertEquals(0, ledgerTransactionCount(), "No money movement may occur for an incomplete claim")
        val counter = jdbc.queryForObject(
            "select count(*) from game_command_sequence where tenant_id = ? and last_sequence_id > 0",
            Int::class.java,
            tenantId,
        )
        assertEquals(0, counter, "Sequence counter must roll back with the aborted claim")

        val recovered = txTemplate.execute<CommandReceiptClaimResult> {
            val outcome = gameStore.claimReceipt(claim(commandId, "fp-incomplete", "rnd-incomplete"))
            if (outcome is CommandReceiptClaimResult.Claimed) {
                gameStore.completeReceipt(tenantId, commandId, "ACCEPTED", "{\"status\":\"ACCEPTED\"}", 1L, 1L)
            }
            outcome
        }
        assertTrue(recovered is CommandReceiptClaimResult.Claimed, "Retry after abort must succeed")
    }

    class RankTracingStore(
        private val delegate: DurableGameWagerAndSettlementStore,
        val events: MutableList<Pair<String, Int>> = mutableListOf(),
    ) : DurableGameWagerAndSettlementStore by delegate {
        override fun claimReceipt(claim: GameCommandReceiptClaim): CommandReceiptClaimResult {
            events.add("RECEIPT" to 1)
            return delegate.claimReceipt(claim)
        }

        override fun completeReceipt(tenantId: String, commandId: String, status: String, responseJson: String, serverSequenceId: Long, roundVersion: Long) {
            events.add("RECEIPT_WRITE" to 1)
            delegate.completeReceipt(tenantId, commandId, status, responseJson, serverSequenceId, roundVersion)
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
    fun `GivenMixedOperations_WhenLocksAreObserved_ThenGlobalOrderIsPreserved`() {
        seedFunds(100000L)
        val roundId = "rnd-lock-order-tc006"
        createRound(roundId)
        val txTemplate = TransactionTemplate(txManager)
        val tracing = RankTracingStore(gameStore)

        txTemplate.execute<Unit> {
            val outcome = tracing.claimReceipt(claim("cmd-lock-forward", "fp-lock-forward", roundId))
            assertTrue(outcome is CommandReceiptClaimResult.Claimed)
            assertNotNull(tracing.findRoundForShare(tenantId, gameId, roundId))
            tracing.findBet(tenantId, gameId, roundId, playerIdStr, "hand_primary")
            tracing.nextSequenceId(tenantId)
            tracing.completeReceipt(tenantId, "cmd-lock-forward", "ACCEPTED", "{\"status\":\"ACCEPTED\"}", 1L, 1L)
        }

        var previousRank = 0
        for ((resource, rank) in tracing.events) {
            if (resource == "RECEIPT_WRITE") {
                continue
            }
            assertTrue(rank >= previousRank, "Lock rank inversion at $resource ($rank) after $previousRank")
            previousRank = rank
        }
        assertTrue(tracing.events.any { it.first == "RECEIPT" })
        assertTrue(tracing.events.any { it.first == "ROUND_SHARED" })
        assertTrue(tracing.events.any { it.first == "BET" })
        assertTrue(tracing.events.any { it.first == "SEQUENCE_COUNTER" })

        val pool = Executors.newFixedThreadPool(2)
        val aHeld = CountDownLatch(1)
        val bHeld = CountDownLatch(1)
        val bothReady = CountDownLatch(2)
        val deadlockDetected = AtomicBoolean(false)
        val inversionCommandId = "cmd-lock-inversion"

        val workerA = pool.submit {
            try {
                txTemplate.execute<Unit> {
                    jdbc.execute("SET LOCAL deadlock_timeout = '100ms'")
                    gameStore.claimReceipt(claim(inversionCommandId, "fp-lock-inversion", roundId))
                    aHeld.countDown()
                    bothReady.countDown()
                    bothReady.await(5, TimeUnit.SECONDS)
                    Thread.sleep(50)
                    gameStore.findRoundForUpdate(tenantId, gameId, roundId)
                }
            } catch (e: Exception) {
                var cause: Throwable? = e
                while (cause != null) {
                    if (cause.message?.contains("deadlock detected") == true) {
                        deadlockDetected.set(true)
                    }
                    cause = cause.cause
                }
            }
        }

        val workerB = pool.submit {
            try {
                txTemplate.execute<Unit> {
                    jdbc.execute("SET LOCAL deadlock_timeout = '100ms'")
                    gameStore.findRoundForUpdate(tenantId, gameId, roundId)
                    bHeld.countDown()
                    bothReady.countDown()
                    bothReady.await(5, TimeUnit.SECONDS)
                    Thread.sleep(50)
                    gameStore.claimReceipt(claim(inversionCommandId, "fp-lock-inversion", roundId))
                }
            } catch (e: Exception) {
                var cause: Throwable? = e
                while (cause != null) {
                    if (cause.message?.contains("deadlock detected") == true) {
                        deadlockDetected.set(true)
                    }
                    cause = cause.cause
                }
            }
        }

        assertTrue(aHeld.await(5, TimeUnit.SECONDS), "Worker A must hold the receipt claim")
        assertTrue(bHeld.await(5, TimeUnit.SECONDS), "Worker B must hold the round exclusive lock")
        workerA.get(10, TimeUnit.SECONDS)
        workerB.get(10, TimeUnit.SECONDS)
        pool.shutdown()

        assertTrue(deadlockDetected.get(), "PostgreSQL must detect an inverted receipt/round acquisition order")
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

        val cashOutRound = "rnd-tc006-golden-cashout"
        createRound(cashOutRound)
        val placeAck = gameService.processCommand(
            AviatorRestCommand(
                tenantId = tenantId,
                principal = playerPrincipal,
                commandId = "cmd-tc006-golden-bet-1",
                roundId = cashOutRound,
                handId = "hand_primary",
                action = "PLACE_BET",
                wagerMinor = wagerMinor,
                currency = "INR",
                correlationId = "corr-tc006-golden-bet-1",
            )
        )
        assertEquals(AviatorCommandAckStatus.ACCEPTED, placeAck.status)

        createRound(cashOutRound, phase = GameRoundPhase.FLYING, version = 2L, multiplier = multiplier)
        val cashOutAck = gameService.processCommand(
            AviatorRestCommand(
                tenantId = tenantId,
                principal = playerPrincipal,
                commandId = "cmd-tc006-golden-cashout-1",
                roundId = cashOutRound,
                handId = "hand_primary",
                action = "CASH_OUT",
                correlationId = "corr-tc006-golden-cashout-1",
            )
        )
        assertEquals(AviatorCommandAckStatus.ACCEPTED, cashOutAck.status)
        assertEquals(expectedWinMinor, cashOutAck.result?.payoutMinor)
        assertEquals(
            startingBalance - wagerMinor + expectedWinMinor,
            ledgerStore.findBalance(tenantId, "PLAYER:$playerIdStr", "INR"),
        )

        val lossRound = "rnd-tc006-golden-loss"
        createRound(lossRound)
        val lossBet = gameService.processCommand(
            AviatorRestCommand(
                tenantId = tenantId,
                principal = playerPrincipal,
                commandId = "cmd-tc006-golden-bet-2",
                roundId = lossRound,
                handId = "hand_primary",
                action = "PLACE_BET",
                wagerMinor = wagerMinor,
                currency = "INR",
                correlationId = "corr-tc006-golden-bet-2",
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
}
