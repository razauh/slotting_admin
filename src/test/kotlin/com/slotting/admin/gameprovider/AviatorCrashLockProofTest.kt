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
import org.springframework.dao.DeadlockLoserDataAccessException
import org.springframework.jdbc.core.JdbcTemplate
import org.springframework.test.context.DynamicPropertyRegistry
import org.springframework.test.context.DynamicPropertySource
import org.springframework.transaction.PlatformTransactionManager
import org.springframework.transaction.support.TransactionTemplate
import java.math.BigDecimal
import java.sql.SQLException
import java.sql.Timestamp
import java.time.Clock
import java.time.Instant
import java.time.LocalDate
import java.time.ZoneOffset
import java.util.UUID
import java.util.concurrent.Callable
import java.util.concurrent.ConcurrentLinkedQueue
import java.util.concurrent.CountDownLatch
import java.util.concurrent.Executors
import java.util.concurrent.Future
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicInteger
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertNotNull
import kotlin.test.assertTrue

@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.NONE)
class AviatorCrashLockProofTest {

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

    private val now = Instant.parse("2026-10-07T12:00:00Z")
    private val clock = Clock.fixed(now, ZoneOffset.UTC)
    private val tenantId = "tenant-tc048-locks"
    private val gameId = "AVIATOR"
    private val currency = "INR"
    private val playerUuids = (1..5).map { UUID.randomUUID() }

    private val adminPrincipal = AuthenticatedPrincipal(
        id = "admin-sys-tc048",
        tenantId = tenantId,
        kind = PrincipalKind.ADMIN,
        roles = setOf(AdminRole.SUPER_ADMIN),
    )

    private lateinit var gameStore: JdbcDurableGameWagerAndSettlementStore
    private lateinit var ledgerStore: JdbcLedgerJournalStore
    private lateinit var registrationStore: JdbcPlayerRegistrationStore
    private lateinit var eligibilityStore: ServerEligibilityStore
    private lateinit var ledgerService: LedgerPostingService

    @BeforeEach
    fun setUp() {
        clearTenantState()
        gameStore = JdbcDurableGameWagerAndSettlementStore(jdbc)
        ledgerStore = JdbcLedgerJournalStore(jdbc)
        registrationStore = JdbcPlayerRegistrationStore(jdbc)
        eligibilityStore = com.slotting.admin.identity.InMemoryServerEligibilityStore()
        ledgerService = LedgerPostingService(store = ledgerStore, clock = clock)
        for (uuid in playerUuids) {
            jdbc.update(
                """
                insert into player_credential (
                    player_id, tenant_id, identifier, password_hash, password_algo,
                    password_salt, iterations, status, version, created_at, updated_at
                ) values (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                on conflict (tenant_id, identifier) do nothing
                """.trimIndent(),
                uuid, tenantId, uuid.toString(), "pbkdf2_sha256_hash", "pbkdf2_sha256", "salt", 10000, "ACTIVE", 1L,
                Timestamp.from(now.minusSeconds(86400)), Timestamp.from(now.minusSeconds(86400))
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

    private fun clearTenantState() {
        jdbc.update("delete from game_bet_settlement where tenant_id = ?", tenantId)
        jdbc.update("delete from game_accepted_bet where tenant_id = ?", tenantId)
        jdbc.update("delete from game_fairness_audit where tenant_id = ?", tenantId)
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

    private fun playerPrincipal(uuid: UUID): AuthenticatedPrincipal =
        AuthenticatedPrincipal(id = uuid.toString(), tenantId = tenantId, kind = PrincipalKind.PLAYER, roles = setOf(AdminRole.SUPPORT))

    private fun seedFunds(uuid: UUID, amount: Long) {
        ledgerService.postTransaction(
            PostTransactionCommand(
                principal = adminPrincipal,
                tenantId = tenantId,
                transactionReference = "TX-TC048-SEED-${UUID.randomUUID()}",
                currencyCode = currency,
                entries = listOf(
                    JournalEntryDraft("HOUSE:SEED", JournalEntryDirection.DEBIT, amount, currency),
                    JournalEntryDraft("PLAYER:${uuid}", JournalEntryDirection.CREDIT, amount, currency),
                ),
                idempotencyKey = "IDEM-TC048-SEED-${UUID.randomUUID()}",
                correlationId = "corr-tc048-seed",
                causationId = "caus-tc048-seed",
            )
        )
    }

    private fun defaultService(store: DurableGameWagerAndSettlementStore = gameStore): DurableGameWagerAndSettlementService =
        DurableGameWagerAndSettlementService(
            store = store, ledgerService = ledgerService, registrationStore = registrationStore,
            eligibilityStore = eligibilityStore, adminPrincipal = adminPrincipal, clock = clock, txManager = txManager,
        )

    private fun seedRound(roundId: String) {
        playerUuids.forEach { seedFunds(it, 50000L) }
        val service = defaultService()
        service.createOrUpdateRound(
            CreateOrUpdateRoundCommand(tenantId = tenantId, gameId = gameId, roundId = roundId, phase = GameRoundPhase.BET_COUNTDOWN, roundVersion = 1L, currentMultiplier = BigDecimal("1.0000"))
        )
        playerUuids.forEachIndexed { index, uuid ->
            val ack = service.processCommand(
                AviatorRestCommand(
                    tenantId = tenantId, principal = playerPrincipal(uuid), commandId = "cmd-$roundId-bet-$index",
                    roundId = roundId, handId = "hand_primary", action = "PLACE_BET", wagerMinor = 101L,
                    currency = currency, correlationId = "corr-$roundId-bet-$index",
                )
            )
            assertEquals(AviatorCommandAckStatus.ACCEPTED, ack.status)
        }
        service.createOrUpdateRound(
            CreateOrUpdateRoundCommand(tenantId = tenantId, gameId = gameId, roundId = roundId, phase = GameRoundPhase.FLYING, roundVersion = 2L, currentMultiplier = BigDecimal("1.2345"), crashMultiplier = BigDecimal("10.0000"))
        )
    }

    private fun cashOutCommand(roundId: String, commandId: String, uuid: UUID): AviatorRestCommand =
        AviatorRestCommand(
            tenantId = tenantId, principal = playerPrincipal(uuid), commandId = commandId, roundId = roundId,
            handId = "hand_primary", action = "CASH_OUT", currency = currency, correlationId = "corr-$commandId",
        )

    private fun settlementCountForBet(betId: UUID): Int =
        jdbc.queryForObject("select count(*) from game_bet_settlement where tenant_id = ? and bet_id = ?", Int::class.java, tenantId, betId) ?: 0

    private fun assertJournalBalanced() {
        val totalDebits = jdbc.queryForObject("select coalesce(sum(total_debits_minor_units), 0) from ledger_transaction where tenant_id = ?", Long::class.java, tenantId) ?: 0L
        val totalCredits = jdbc.queryForObject("select coalesce(sum(total_credits_minor_units), 0) from ledger_transaction where tenant_id = ?", Long::class.java, tenantId) ?: 0L
        assertEquals(totalDebits, totalCredits, "Double-entry journal must stay balanced")
    }

    private inner class ProductionContentionProbe {
        fun backendPid(): Int = jdbc.queryForObject("select pg_backend_pid()", Int::class.java)!!

        fun blockingPids(waitingPid: Int): List<Int> {
            val text = jdbc.queryForObject("select pg_blocking_pids(?)::text", String::class.java, waitingPid) ?: "{}"
            return text.trim('{', '}').split(',').mapNotNull { it.trim().toIntOrNull() }
        }

        fun awaitBlocking(waitingPid: Int, expectedBlockerPid: Int, timeoutSeconds: Int) {
            val deadline = System.currentTimeMillis() + timeoutSeconds * 1000L
            while (System.currentTimeMillis() < deadline) {
                if (blockingPids(waitingPid).contains(expectedBlockerPid)) return
                Thread.sleep(50)
            }
            val waiting = jdbc.queryForList("select pid, wait_event_type, wait_event, state, query from pg_stat_activity where pid = ?", waitingPid)
            val locks = jdbc.queryForList("select locktype, mode, granted, relation::regclass::text as relation from pg_locks where pid = ?", waitingPid)
            throw AssertionError("Expected PostgreSQL blocker $expectedBlockerPid not observed for waiting PID $waitingPid within ${timeoutSeconds}s. waiting=$waiting locks=$locks")
        }
    }

    private inner class ProductionCrashStore(
        private val delegate: DurableGameWagerAndSettlementStore,
    ) : DurableGameWagerAndSettlementStore by delegate {
        val crashPid = AtomicInteger(0)
        val roundLockRequested = CountDownLatch(1)
        val rankTrace = java.util.Collections.synchronizedList(mutableListOf<Pair<String, Int>>())
        val betOrder = java.util.Collections.synchronizedList(mutableListOf<UUID>())
        @Volatile var pauseAfterRoundLock: (() -> Unit)? = null

        override fun findRoundForUpdate(tenantId: String, gameId: String, roundId: String): GameRoundRecord? {
            crashPid.set(jdbc.queryForObject("select pg_backend_pid()", Int::class.java)!!)
            rankTrace.add("ROUND_EXCLUSIVE" to 2)
            roundLockRequested.countDown()
            val round = delegate.findRoundForUpdate(tenantId, gameId, roundId)
            pauseAfterRoundLock?.invoke()
            return round
        }

        override fun findBetsForRoundForUpdate(tenantId: String, gameId: String, roundId: String): List<GameAcceptedBetRecord> {
            rankTrace.add("BETS" to 3)
            val bets = delegate.findBetsForRoundForUpdate(tenantId, gameId, roundId)
            betOrder.addAll(bets.map { it.betId })
            return bets
        }
    }

    private inner class ProductionCashOutStore(
        private val delegate: DurableGameWagerAndSettlementStore,
    ) : DurableGameWagerAndSettlementStore by delegate {
        val cashOutPid = AtomicInteger(0)
        val roundLockRequested = CountDownLatch(1)
        @Volatile var pauseAfterRoundShare: (() -> Unit)? = null

        override fun findRoundForShare(tenantId: String, gameId: String, roundId: String): GameRoundRecord? {
            cashOutPid.set(jdbc.queryForObject("select pg_backend_pid()", Int::class.java)!!)
            roundLockRequested.countDown()
            val round = delegate.findRoundForShare(tenantId, gameId, roundId)
            pauseAfterRoundShare?.invoke()
            return round
        }
    }

    private fun isDeadlock(t: Throwable?): Boolean {
        var current = t
        while (current != null) {
            if (current is DeadlockLoserDataAccessException) return true
            if (current is SQLException && current.sqlState == "40P01") return true
            current = current.cause
        }
        return false
    }

    @Test
    fun `GivenProductionCrashHoldsExclusiveRoundLock_WhenProductionCashOutRequestsSharedLock_ThenPostgresReportsBlocking`() {
        val roundId = "rnd-tc048-prod-blocking"
        seedRound(roundId)
        val target = playerUuids.first()

        val probe = ProductionContentionProbe()
        val crashStore = ProductionCrashStore(gameStore)
        val crashService = defaultService(crashStore)
        val cashOutStore = ProductionCashOutStore(gameStore)
        val cashOutService = defaultService(cashOutStore)

        val crashHolds = CountDownLatch(1)
        val releaseCrash = CountDownLatch(1)
        crashStore.pauseAfterRoundLock = {
            crashHolds.countDown()
            releaseCrash.await(10, TimeUnit.SECONDS)
        }

        val pool = Executors.newFixedThreadPool(2)
        val crashFuture: Future<*> = pool.submit(Callable { crashService.settleRoundCrash(SettleRoundCrashCommand(tenantId, gameId, roundId, BigDecimal("1.1000"))) })
        assertTrue(crashHolds.await(10, TimeUnit.SECONDS), "production crash must hold the exclusive round lock")

        val cashOutFuture: Future<AviatorCommandAckResult> = pool.submit(Callable { cashOutService.processCommand(cashOutCommand(roundId, "cmd-tc048-prod", target)) })
        assertTrue(cashOutStore.roundLockRequested.await(10, TimeUnit.SECONDS), "production cash-out must request the shared round lock")
        probe.awaitBlocking(cashOutStore.cashOutPid.get(), crashStore.crashPid.get(), 5)

        releaseCrash.countDown()
        crashFuture.get(15, TimeUnit.SECONDS)
        val cashOutAck = cashOutFuture.get(15, TimeUnit.SECONDS)
        pool.shutdown()

        assertEquals(AviatorCommandAckStatus.REJECTED, cashOutAck.status, "cash-out after the crash must be rejected")
        val bet = gameStore.findBet(tenantId, gameId, roundId, target.toString(), "hand_primary")
        assertNotNull(bet)
        assertEquals(GameBetStatus.LOST, bet.status)
        assertEquals(1, settlementCountForBet(bet.betId), "exactly one settlement for the bet")
        assertEquals(0L, ledgerStore.findBalance(tenantId, "ESCROW:GAME:$gameId", currency), "escrow must net to zero")
        assertJournalBalanced()

        val ranks = crashStore.rankTrace.map { it.second }
        assertEquals(ranks, ranks.sorted(), "production crash rank trace must be monotonic: ${crashStore.rankTrace}")
    }

    @Test
    fun `GivenProductionCrash_WhenLocksAreObserved_ThenAcceptedBetsLockInStableOrder`() {
        val roundId = "rnd-tc048-order"
        seedRound(roundId)

        val crashStore = ProductionCrashStore(gameStore)
        val service = defaultService(crashStore)
        val result = service.settleRoundCrash(SettleRoundCrashCommand(tenantId, gameId, roundId, BigDecimal("1.1000")))
        assertEquals(5, result.settledBetsCount)
        assertTrue(crashStore.rankTrace.contains("ROUND_EXCLUSIVE" to 2), "crash must lock the round first")
        assertTrue(crashStore.rankTrace.contains("BETS" to 3), "crash must lock accepted bets after the round")

        val dbOrder = jdbc.queryForList(
            "select bet_id from game_accepted_bet where tenant_id = ? and game_id = ? and round_id = ? order by bet_id",
            UUID::class.java, tenantId, gameId, roundId,
        )
        assertEquals(dbOrder, crashStore.betOrder.toList(), "production crash must lock accepted bets in ascending bet_id order")
    }

    @Test
    fun `GivenProductionContention_WhenOneHundredSeededIterationsRun_ThenBlockingObservedAndNoPartialEffects`() {
        val random = java.util.Random(20261007L)
        val probe = ProductionContentionProbe()
        for (iteration in 0 until 100) {
            clearTenantState()
            val roundId = "rnd-tc048-iter-$iteration"
            seedRound(roundId)
            val target = playerUuids.first()
            val cashOutFirst = random.nextBoolean()

            val crashStore = ProductionCrashStore(gameStore)
            val crashService = defaultService(crashStore)
            val cashOutStore = ProductionCashOutStore(gameStore)
            val cashOutService = defaultService(cashOutStore)
            val pool = Executors.newFixedThreadPool(2)

            if (cashOutFirst) {
                val cashOutHolds = CountDownLatch(1)
                val releaseCashOut = CountDownLatch(1)
                cashOutStore.pauseAfterRoundShare = {
                    cashOutHolds.countDown()
                    releaseCashOut.await(10, TimeUnit.SECONDS)
                }
                val cashOutFuture = pool.submit(Callable { cashOutService.processCommand(cashOutCommand(roundId, "cmd-tc048-iter-$iteration-cashout", target)) })
                assertTrue(cashOutHolds.await(10, TimeUnit.SECONDS), "iteration $iteration cash-out must hold the shared round lock")
                val crashFuture: Future<*> = pool.submit(Callable { crashService.settleRoundCrash(SettleRoundCrashCommand(tenantId, gameId, roundId, BigDecimal("1.1000"))) })
                assertTrue(crashStore.roundLockRequested.await(10, TimeUnit.SECONDS), "iteration $iteration crash must request the exclusive round lock")
                probe.awaitBlocking(crashStore.crashPid.get(), cashOutStore.cashOutPid.get(), 5)
                releaseCashOut.countDown()
                cashOutFuture.get(15, TimeUnit.SECONDS)
                crashFuture.get(15, TimeUnit.SECONDS)
            } else {
                val crashHolds = CountDownLatch(1)
                val releaseCrash = CountDownLatch(1)
                crashStore.pauseAfterRoundLock = {
                    crashHolds.countDown()
                    releaseCrash.await(10, TimeUnit.SECONDS)
                }
                val crashFuture: Future<*> = pool.submit(Callable { crashService.settleRoundCrash(SettleRoundCrashCommand(tenantId, gameId, roundId, BigDecimal("1.1000"))) })
                assertTrue(crashHolds.await(10, TimeUnit.SECONDS), "iteration $iteration crash must hold the exclusive round lock")
                val cashOutFuture = pool.submit(Callable { cashOutService.processCommand(cashOutCommand(roundId, "cmd-tc048-iter-$iteration-cashout", target)) })
                assertTrue(cashOutStore.roundLockRequested.await(10, TimeUnit.SECONDS), "iteration $iteration cash-out must request the shared round lock")
                probe.awaitBlocking(cashOutStore.cashOutPid.get(), crashStore.crashPid.get(), 5)
                releaseCrash.countDown()
                crashFuture.get(15, TimeUnit.SECONDS)
                cashOutFuture.get(15, TimeUnit.SECONDS)
            }
            pool.shutdown()
            assertTrue(pool.awaitTermination(5, TimeUnit.SECONDS))

            val bets = gameStore.findBetsForRound(tenantId, gameId, roundId)
            assertEquals(5, bets.size, "iteration $iteration")
            assertTrue(
                bets.all { it.status == GameBetStatus.LOST || it.status == GameBetStatus.CASHED_OUT },
                "iteration $iteration no bet may remain ACCEPTED: ${bets.map { it.status }}",
            )
            bets.forEach { bet -> assertEquals(1, settlementCountForBet(bet.betId), "iteration $iteration bet ${bet.betId}") }
            assertEquals(0L, ledgerStore.findBalance(tenantId, "ESCROW:GAME:$gameId", currency), "iteration $iteration escrow")
            assertJournalBalanced()

            val ranks = crashStore.rankTrace.map { it.second }
            assertEquals(ranks, ranks.sorted(), "iteration $iteration crash rank inversion: ${crashStore.rankTrace}")
        }
    }

    @Test
    fun `GivenBetThenRoundInversion_WhenControlRuns_ThenPostgresDetectsDeadlockAndRollsBackLoser`() {
        val roundId = "rnd-tc048-inversion"
        seedRound(roundId)
        val betId = gameStore.findBetsForRound(tenantId, gameId, roundId).first().betId

        val ledgerBefore = jdbc.queryForObject("select count(*) from ledger_transaction where tenant_id = ?", Int::class.java, tenantId)
        val settlementsBefore = jdbc.queryForObject("select count(*) from game_bet_settlement where tenant_id = ?", Int::class.java, tenantId)
        val versionBefore = jdbc.queryForObject("select round_version from game_authoritative_round where tenant_id = ? and game_id = ? and round_id = ?", Long::class.java, tenantId, gameId, roundId)

        val txTemplate = TransactionTemplate(txManager)
        val pool = Executors.newFixedThreadPool(2)
        val forwardHoldsRound = CountDownLatch(1)
        val inversionHoldsBet = CountDownLatch(1)
        val outcomes = ConcurrentLinkedQueue<Pair<String, Throwable?>>()

        val forward = pool.submit(Callable {
            try {
                txTemplate.execute<Unit> {
                    jdbc.queryForList("select round_id from game_authoritative_round where tenant_id = ? and game_id = ? and round_id = ? for update", tenantId, gameId, roundId)
                    jdbc.update(
                        "insert into game_fairness_audit (audit_id, tenant_id, round_id, action, actor, detail, occurred_at) values (?, ?, ?, 'TC048_FORWARD', 'TEST', 'forward-write', ?)",
                        UUID.randomUUID(), tenantId, roundId, Timestamp.from(now),
                    )
                    forwardHoldsRound.countDown()
                    inversionHoldsBet.await(10, TimeUnit.SECONDS)
                    jdbc.queryForList("select bet_id from game_accepted_bet where bet_id = ? for update", betId)
                }
                outcomes.add("forward" to null)
            } catch (e: Exception) {
                outcomes.add("forward" to e)
            }
        })
        assertTrue(forwardHoldsRound.await(10, TimeUnit.SECONDS))

        val inversion = pool.submit(Callable {
            try {
                txTemplate.execute<Unit> {
                    jdbc.queryForList("select bet_id from game_accepted_bet where bet_id = ? for update", betId)
                    jdbc.update(
                        "insert into game_fairness_audit (audit_id, tenant_id, round_id, action, actor, detail, occurred_at) values (?, ?, ?, 'TC048_INVERSION', 'TEST', 'inversion-write', ?)",
                        UUID.randomUUID(), tenantId, roundId, Timestamp.from(now),
                    )
                    inversionHoldsBet.countDown()
                    jdbc.queryForList("select round_id from game_authoritative_round where tenant_id = ? and game_id = ? and round_id = ? for update", tenantId, gameId, roundId)
                }
                outcomes.add("inversion" to null)
            } catch (e: Exception) {
                outcomes.add("inversion" to e)
            }
        })

        forward.get(15, TimeUnit.SECONDS)
        inversion.get(15, TimeUnit.SECONDS)
        pool.shutdown()

        val forwardAborted = outcomes.first { it.first == "forward" }.second != null
        val inversionAborted = outcomes.first { it.first == "inversion" }.second != null
        assertTrue(forwardAborted != inversionAborted, "exactly one transaction must abort: $outcomes")
        val aborted = outcomes.first { it.second != null }
        assertTrue(isDeadlock(aborted.second), "the aborted transaction must be a PostgreSQL deadlock (SQLSTATE 40P01): ${aborted.second}")

        val forwardMarkers = jdbc.queryForObject("select count(*) from game_fairness_audit where tenant_id = ? and action = 'TC048_FORWARD'", Int::class.java, tenantId) ?: 0
        val inversionMarkers = jdbc.queryForObject("select count(*) from game_fairness_audit where tenant_id = ? and action = 'TC048_INVERSION'", Int::class.java, tenantId) ?: 0
        assertEquals(if (forwardAborted) 0 else 1, forwardMarkers, "the forward transaction's write must roll back iff it was aborted")
        assertEquals(if (inversionAborted) 0 else 1, inversionMarkers, "the inversion transaction's write must roll back iff it was aborted")

        assertEquals(ledgerBefore, jdbc.queryForObject("select count(*) from ledger_transaction where tenant_id = ?", Int::class.java, tenantId), "aborted loser must leave no ledger effects")
        assertEquals(settlementsBefore, jdbc.queryForObject("select count(*) from game_bet_settlement where tenant_id = ?", Int::class.java, tenantId), "aborted loser must leave no settlement effects")
        assertEquals(versionBefore, jdbc.queryForObject("select round_version from game_authoritative_round where tenant_id = ? and game_id = ? and round_id = ?", Long::class.java, tenantId, gameId, roundId), "aborted loser must leave no round effects")
    }

    @Test
    fun `GivenLockProbeCannotObserveContention_WhenTestRuns_ThenTestFailsClosedWithDiagnostics`() {
        val probe = ProductionContentionProbe()
        val selfPid = probe.backendPid()
        val error = assertFailsWith<AssertionError> {
            probe.awaitBlocking(selfPid, selfPid + 1, 1)
        }
        val message = error.message ?: ""
        assertTrue(message.contains("blocker", ignoreCase = true), "diagnostic must name the expected blocker: $message")
        assertTrue(message.contains(selfPid.toString()), "diagnostic must include the waiting PID: $message")
    }
}
