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
import com.slotting.admin.wallet.AuthoritativeWalletService
import com.slotting.admin.wallet.InMemoryAuthoritativeWalletStore
import org.flywaydb.core.Flyway
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
import java.util.Random
import java.util.UUID
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.ConcurrentLinkedQueue
import java.util.concurrent.CountDownLatch
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicInteger
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNotNull
import kotlin.test.assertTrue

@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.NONE)
class AviatorCommandSequencePostgresTest {

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
    private val tenantId = "tenant-tc005-seq"
    private val tenantId2 = "tenant-tc005-other"
    private val gameId = "AVIATOR"
    private val playerUuid = UUID.randomUUID()
    private val playerIdStr = playerUuid.toString()

    private val adminPrincipal = AuthenticatedPrincipal(
        id = "admin-sys-tc005",
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

    private val properties = AviatorLifecycleProperties(
        scheduledMillis = 100,
        bettingMillis = 200,
        closedMillis = 100,
        multiplierStep = BigDecimal("0.0500"),
        rulesVersion = "1.0.0",
        algorithmVersion = "1.0.0",
        publicSalt = "tc005-public-salt",
        configuredTenants = setOf(tenantId),
    )

    private lateinit var gameStore: JdbcDurableGameWagerAndSettlementStore
    private lateinit var fairnessStore: JdbcFairnessEvidenceStore
    private lateinit var ledgerStore: JdbcLedgerJournalStore
    private lateinit var registrationStore: JdbcPlayerRegistrationStore
    private lateinit var eligibilityStore: ServerEligibilityStore
    private lateinit var ledgerService: LedgerPostingService
    private lateinit var gameService: DurableGameWagerAndSettlementService
    private lateinit var fairnessAuthority: ProvablyFairOutcomeAuthority
    private lateinit var walletService: AuthoritativeWalletService
    private lateinit var snapshotService: AuthoritativeGameSnapshotAndEventService
    private lateinit var lifecyclePort: ProductionAviatorLifecyclePort

    @BeforeEach
    fun setUp() {
        jdbc.update("delete from game_bet_settlement where tenant_id in (?, ?)", tenantId, tenantId2)
        jdbc.update("delete from game_accepted_bet where tenant_id in (?, ?)", tenantId, tenantId2)
        jdbc.update("delete from game_command_receipt where tenant_id in (?, ?)", tenantId, tenantId2)
        jdbc.update("delete from game_fairness_audit where tenant_id in (?, ?)", tenantId, tenantId2)
        jdbc.update("delete from game_fairness_reveal where tenant_id in (?, ?)", tenantId, tenantId2)
        jdbc.update("delete from game_fairness_commitment where tenant_id in (?, ?)", tenantId, tenantId2)
        jdbc.update("delete from game_cumulative_player_limit where tenant_id in (?, ?)", tenantId, tenantId2)
        jdbc.update("delete from game_authoritative_round where tenant_id in (?, ?)", tenantId, tenantId2)
        jdbc.update("delete from ledger_leg where tenant_id in (?, ?)", tenantId, tenantId2)
        jdbc.update("delete from ledger_idempotency_receipt where tenant_id in (?, ?)", tenantId, tenantId2)
        jdbc.update("delete from ledger_transaction where tenant_id in (?, ?)", tenantId, tenantId2)
        jdbc.update("delete from ledger_account where tenant_id in (?, ?)", tenantId, tenantId2)

        val tableExists = jdbc.queryForObject(
            "select count(*) from information_schema.tables where table_name = 'game_command_sequence'",
            Int::class.java
        ) ?: 0
        if (tableExists > 0) {
            jdbc.update("delete from game_command_sequence where tenant_id in (?, ?)", tenantId, tenantId2)
        }

        gameStore = JdbcDurableGameWagerAndSettlementStore(jdbc)
        fairnessStore = JdbcFairnessEvidenceStore(jdbc)
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
        fairnessAuthority = ProvablyFairOutcomeAuthority(store = fairnessStore, clock = clock)
        val walletStore = InMemoryAuthoritativeWalletStore(ledgerStore = ledgerStore, clock = clock)
        walletService = AuthoritativeWalletService(
            store = walletStore,
            clock = clock,
        )
        snapshotService = AuthoritativeGameSnapshotAndEventService(
            gameStore = gameStore,
            gameService = gameService,
            walletService = walletService,
            ledgerStore = ledgerStore,
            fairnessStore = fairnessStore,
            eventJournalStore = InMemoryGameEventJournalStore(),
            registrationStore = registrationStore,
            clock = clock,
        )
        lifecyclePort = ProductionAviatorLifecyclePort(
            gameService = gameService,
            fairnessAuthority = fairnessAuthority,
            snapshotService = snapshotService,
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

    private fun createReceipt(
        tenantId: String,
        commandId: String,
        serverSequenceId: Long,
        roundId: String = "rnd-seq-test",
    ): GameCommandReceiptRecord {
        return GameCommandReceiptRecord(
            receiptId = UUID.randomUUID(),
            tenantId = tenantId,
            ownerId = playerIdStr,
            gameId = gameId,
            commandId = commandId,
            roundId = roundId,
            handId = "hand_primary",
            action = "PLACE_BET",
            status = "ACCEPTED",
            fingerprint = "fp-$commandId",
            responseJson = "{}",
            causationId = "caus-$commandId",
            correlationId = "corr-$commandId",
            serverSequenceId = serverSequenceId,
            roundVersion = 1L,
            createdAt = now,
        )
    }

    @Test
    fun `GivenConcurrentReceipts_WhenAllocated_ThenFiftyDistinctConsecutiveSequences`() {
        val pool = Executors.newFixedThreadPool(50)
        val txTemplate = TransactionTemplate(txManager)

        val firstBatchResults = ConcurrentLinkedQueue<Long>()
        val startLatch = CountDownLatch(1)
        val doneLatch = CountDownLatch(50)

        for (i in 0 until 50) {
            pool.submit {
                startLatch.await()
                try {
                    val allocatedSeq = txTemplate.execute {
                        val seq = gameStore.nextSequenceId(tenantId)
                        gameStore.saveReceipt(
                            createReceipt(
                                tenantId = tenantId,
                                commandId = "cmd-batch0-$i-${UUID.randomUUID()}",
                                serverSequenceId = seq,
                            )
                        )
                        seq
                    }
                    if (allocatedSeq != null) {
                        firstBatchResults.add(allocatedSeq)
                    }
                } finally {
                    doneLatch.countDown()
                }
            }
        }

        startLatch.countDown()
        assertTrue(doneLatch.await(30, TimeUnit.SECONDS), "First batch of 50 concurrent allocations timed out")

        val sortedBatch0 = firstBatchResults.toList().sorted()
        assertEquals(50, sortedBatch0.size)
        val expectedFirst50 = (1L..50L).toList()
        assertEquals(expectedFirst50, sortedBatch0)

        for (batch in 1..100) {
            val batchResults = ConcurrentLinkedQueue<Long>()
            val batchSize = 5
            val batchStart = CountDownLatch(1)
            val batchDone = CountDownLatch(batchSize)

            for (i in 0 until batchSize) {
                pool.submit {
                    batchStart.await()
                    try {
                        val allocatedSeq = txTemplate.execute {
                            val seq = gameStore.nextSequenceId(tenantId)
                            gameStore.saveReceipt(
                                createReceipt(
                                    tenantId = tenantId,
                                    commandId = "cmd-batch$batch-$i-${UUID.randomUUID()}",
                                    serverSequenceId = seq,
                                )
                            )
                            seq
                        }
                        if (allocatedSeq != null) {
                            batchResults.add(allocatedSeq)
                        }
                    } finally {
                        batchDone.countDown()
                    }
                }
            }

            batchStart.countDown()
            assertTrue(batchDone.await(10, TimeUnit.SECONDS), "Batch $batch timed out")

            val uniqueCount = batchResults.toSet().size
            assertEquals(batchSize, uniqueCount, "Duplicate sequence found in batch $batch: $batchResults")
        }

        pool.shutdown()
        pool.awaitTermination(5, TimeUnit.SECONDS)
    }

    @Test
    fun `GivenDuplicateLegacySequences_WhenMigrationRuns_ThenDiagnosticAbort`() {
        val legacyTenant = tenantId
        val seqToDuplicate = 7L
        val r1 = createReceipt(legacyTenant, "cmd-legacy-dup-1", seqToDuplicate)
        val r2 = createReceipt(legacyTenant, "cmd-legacy-dup-2", seqToDuplicate)

        val flyway = Flyway.configure()
            .dataSource(jdbc.dataSource!!)
            .locations("classpath:db/migration")
            .cleanDisabled(true)
            .load()

        jdbc.update("delete from flyway_schema_history where version in ('39', '40')")
        jdbc.update("drop table if exists game_command_sequence cascade")
        jdbc.update("drop index if exists ix_game_command_receipt_tenant_seq")

        try {
            jdbc.update(
                """
                insert into game_command_receipt (
                    receipt_id, tenant_id, owner_id, game_id, command_id, round_id, hand_id,
                    action, status, fingerprint, response_json, causation_id, correlation_id,
                    server_sequence_id, round_version, created_at
                ) values (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """.trimIndent(),
                r1.receiptId, r1.tenantId, r1.ownerId, r1.gameId, r1.commandId, r1.roundId, r1.handId,
                r1.action, r1.status, r1.fingerprint, r1.responseJson, r1.causationId, r1.correlationId,
                r1.serverSequenceId, r1.roundVersion, Timestamp.from(r1.createdAt)
            )

            jdbc.update(
                """
                insert into game_command_receipt (
                    receipt_id, tenant_id, owner_id, game_id, command_id, round_id, hand_id,
                    action, status, fingerprint, response_json, causation_id, correlation_id,
                    server_sequence_id, round_version, created_at
                ) values (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """.trimIndent(),
                r2.receiptId, r2.tenantId, r2.ownerId, r2.gameId, r2.commandId, r2.roundId, r2.handId,
                r2.action, r2.status, r2.fingerprint, r2.responseJson, r2.causationId, r2.correlationId,
                r2.serverSequenceId, r2.roundVersion, Timestamp.from(r2.createdAt)
            )

            val duplicates = CommandSequenceDiagnostics.detectDuplicateReceiptSequences(jdbc)
            assertTrue(duplicates.isNotEmpty(), "Duplicate sequences must be detected by diagnostic query")
            val match = duplicates.firstOrNull { it.tenantId == legacyTenant && it.sequenceId == seqToDuplicate }
            assertNotNull(match, "Diagnostic must identify tenant=$legacyTenant sequence=$seqToDuplicate")
            assertEquals(2L, match.count, "Diagnostic must report row count 2")

            val flywayException = assertThrows<Exception> {
                flyway.migrate()
            }
            var rootCause: Throwable? = flywayException
            val allMessages = StringBuilder()
            while (rootCause != null) {
                allMessages.append(" ").append(rootCause.message)
                rootCause = rootCause.cause
            }
            val msg = allMessages.toString()
            assertTrue(msg.contains(legacyTenant), "Diagnostic abort message must contain tenantId: $msg")
            assertTrue(msg.contains("7"), "Diagnostic abort message must contain sequence 7: $msg")
            assertTrue(msg.contains("2"), "Diagnostic abort message must contain count 2: $msg")

            val countAfter = jdbc.queryForObject(
                "select count(*) from game_command_receipt where tenant_id = ? and server_sequence_id = ?",
                Int::class.java,
                legacyTenant,
                seqToDuplicate
            )
            assertEquals(2, countAfter, "No rows must be deleted or renumbered during diagnostic abort")
        } finally {
            jdbc.update("delete from game_command_receipt where tenant_id = ?", legacyTenant)
            jdbc.update("delete from flyway_schema_history where version in ('39', '40')")
            flyway.repair()
            flyway.migrate()
        }
    }

    @Test
    fun `GivenAllocatedSequence_WhenTransactionFails_ThenCounterUnchanged`() {
        val txTemplate = TransactionTemplate(txManager)

        txTemplate.execute {
            for (i in 1..10) {
                val seq = gameStore.nextSequenceId(tenantId)
                gameStore.saveReceipt(createReceipt(tenantId, "cmd-seed-$i", seq))
            }
        }

        val counterTableExists = jdbc.queryForObject(
            "select count(*) from information_schema.tables where table_name = 'game_command_sequence'",
            Int::class.java
        ) ?: 0
        assertTrue(counterTableExists > 0, "game_command_sequence table must exist")

        val counterBefore = jdbc.queryForObject(
            "select last_sequence_id from game_command_sequence where tenant_id = ?",
            Long::class.java,
            tenantId
        )
        assertEquals(10L, counterBefore)

        assertThrows<RuntimeException> {
            txTemplate.execute {
                val next = gameStore.nextSequenceId(tenantId)
                assertEquals(11L, next)
                throw RuntimeException("Simulated failure after allocation")
            }
        }

        val counterAfterRollback = jdbc.queryForObject(
            "select last_sequence_id from game_command_sequence where tenant_id = ?",
            Long::class.java,
            tenantId
        )
        assertEquals(10L, counterAfterRollback, "Counter must stay at 10 after rollback")

        val retrySeq = txTemplate.execute {
            val next = gameStore.nextSequenceId(tenantId)
            gameStore.saveReceipt(createReceipt(tenantId, "cmd-retry-11", next))
            next
        }
        assertEquals(11L, retrySeq, "Retry after rollback must receive 11")

        val otherTenantSeq = txTemplate.execute {
            val next = gameStore.nextSequenceId(tenantId2)
            gameStore.saveReceipt(createReceipt(tenantId2, "cmd-other-1", next))
            next
        }
        assertEquals(1L, otherTenantSeq, "Independent tenant must start at 1")
    }

    class LockOrderTracingStore(
        private val delegate: DurableGameWagerAndSettlementStore,
        val eventLog: MutableList<Pair<String, Int>> = mutableListOf(),
        val onRoundShared: (() -> Unit)? = null,
        val onRoundExclusive: (() -> Unit)? = null,
        val onBeforeSequenceCounter: (() -> Unit)? = null,
        val onAfterSequenceCounter: (() -> Unit)? = null,
    ) : DurableGameWagerAndSettlementStore by delegate {
        override fun findReceipt(tenantId: String, commandId: String): GameCommandReceiptRecord? {
            eventLog.add("RECEIPT" to 1)
            return delegate.findReceipt(tenantId, commandId)
        }

        override fun findRoundForShare(tenantId: String, gameId: String, roundId: String): GameRoundRecord? {
            val r = delegate.findRoundForShare(tenantId, gameId, roundId)
            eventLog.add("ROUND_SHARED" to 2)
            onRoundShared?.invoke()
            return r
        }

        override fun findRoundForUpdate(tenantId: String, gameId: String, roundId: String): GameRoundRecord? {
            onRoundExclusive?.invoke()
            val r = delegate.findRoundForUpdate(tenantId, gameId, roundId)
            eventLog.add("ROUND_EXCLUSIVE" to 2)
            return r
        }

        override fun findBet(tenantId: String, gameId: String, roundId: String, ownerId: String, handId: String): GameAcceptedBetRecord? {
            eventLog.add("BET" to 3)
            return delegate.findBet(tenantId, gameId, roundId, ownerId, handId)
        }

        override fun nextSequenceId(tenantId: String): Long {
            onBeforeSequenceCounter?.invoke()
            val seq = delegate.nextSequenceId(tenantId)
            eventLog.add("SEQUENCE_COUNTER" to 5)
            onAfterSequenceCounter?.invoke()
            return seq
        }

        override fun saveReceipt(receipt: GameCommandReceiptRecord) {
            eventLog.add("RECEIPT_WRITE" to 1)
            delegate.saveReceipt(receipt)
        }
    }

    @Test
    fun `GivenMixedOperations_WhenLocksAreObserved_ThenGlobalOrderIsPreserved`() {
        val pool = Executors.newFixedThreadPool(8)
        val rankInversions = ConcurrentLinkedQueue<String>()

        ledgerService.postTransaction(
            PostTransactionCommand(
                principal = adminPrincipal,
                tenantId = tenantId,
                transactionReference = "TX-SEED-LOCK-TEST-${UUID.randomUUID()}",
                currencyCode = "INR",
                entries = listOf(
                    JournalEntryDraft("HOUSE:SEED", JournalEntryDirection.DEBIT, 50_000_000L, "INR"),
                    JournalEntryDraft("PLAYER:$playerIdStr", JournalEntryDirection.CREDIT, 25_000_000L, "INR"),
                    JournalEntryDraft("HOUSE:GAME:$gameId", JournalEntryDirection.CREDIT, 25_000_000L, "INR"),
                ),
                idempotencyKey = "IDEM-SEED-LOCK-${UUID.randomUUID()}",
                correlationId = "corr-seed",
                causationId = "caus-seed",
            )
        )

        val testRoundHoldingId = "rnd-lock-earlier-later-${UUID.randomUUID().toString().take(6)}"
        gameService.createOrUpdateRound(
            CreateOrUpdateRoundCommand(
                tenantId = tenantId,
                gameId = gameId,
                roundId = testRoundHoldingId,
                phase = GameRoundPhase.BET_COUNTDOWN,
                roundVersion = 1L,
            )
        )

        var cmdPid: Int? = null
        var lifecyclePid: Int? = null
        val roundHeldLatch = CountDownLatch(1)
        val lifecycleAttemptLatch = CountDownLatch(1)
        val releaseEarlierLockLatch = CountDownLatch(1)

        val holdingEarlierStore = LockOrderTracingStore(
            gameStore,
            onRoundShared = {
                cmdPid = jdbc.queryForObject("SELECT pg_backend_pid()", Int::class.java)
                roundHeldLatch.countDown()
                releaseEarlierLockLatch.await(5, TimeUnit.SECONDS)
            }
        )
        val holdingEarlierService = DurableGameWagerAndSettlementService(
            store = holdingEarlierStore,
            ledgerService = ledgerService,
            registrationStore = registrationStore,
            eligibilityStore = eligibilityStore,
            adminPrincipal = adminPrincipal,
            clock = clock,
            txManager = txManager,
        )

        val lifecycleStore = LockOrderTracingStore(
            gameStore,
            onRoundExclusive = {
                lifecyclePid = jdbc.queryForObject("SELECT pg_backend_pid()", Int::class.java)
                lifecycleAttemptLatch.countDown()
            }
        )
        val lifecycleService = DurableGameWagerAndSettlementService(
            store = lifecycleStore,
            ledgerService = ledgerService,
            registrationStore = registrationStore,
            eligibilityStore = eligibilityStore,
            adminPrincipal = adminPrincipal,
            clock = clock,
            txManager = txManager,
        )

        val workerEarlierToLater = pool.submit<AviatorCommandAckResult> {
            holdingEarlierService.processCommand(
                AviatorRestCommand(
                    tenantId = tenantId,
                    principal = playerPrincipal,
                    commandId = "cmd-hold-earlier-req-later-${UUID.randomUUID()}",
                    roundId = testRoundHoldingId,
                    handId = "hand_primary",
                    action = "PLACE_BET",
                    wagerMinor = 100L,
                    currency = "INR",
                    correlationId = "corr-hold-earlier",
                )
            )
        }

        assertTrue(roundHeldLatch.await(5, TimeUnit.SECONDS), "Worker 1 must acquire earlier lock (Round FOR SHARE)")

        val workerOpposingLifecycle = pool.submit<GameRoundRecord> {
            lifecycleService.createOrUpdateRound(
                CreateOrUpdateRoundCommand(
                    tenantId = tenantId,
                    gameId = gameId,
                    roundId = testRoundHoldingId,
                    phase = GameRoundPhase.FLYING,
                    roundVersion = 2L,
                    expectedVersion = 1L,
                    currentMultiplier = BigDecimal("1.0000"),
                )
            )
        }

        assertTrue(lifecycleAttemptLatch.await(5, TimeUnit.SECONDS), "Worker 2 must attempt exclusive lock on Round")

        var ungrantedCount = 0
        var blockedSpecifically = false
        for (attempt in 0 until 50) {
            val curLifecyclePid = lifecyclePid
            val curCmdPid = cmdPid
            if (curLifecyclePid != null && curCmdPid != null) {
                ungrantedCount = jdbc.queryForObject(
                    "SELECT count(*) FROM pg_locks WHERE pid = ? AND NOT granted",
                    Int::class.java,
                    curLifecyclePid,
                ) ?: 0
                val blockerMatches = jdbc.queryForObject(
                    """
                    SELECT count(*) FROM pg_stat_activity
                    WHERE pid = ?
                      AND wait_event_type = 'Lock'
                      AND ? = ANY(pg_blocking_pids(pid))
                    """.trimIndent(),
                    Int::class.java,
                    curLifecyclePid,
                    curCmdPid,
                ) ?: 0
                if (ungrantedCount > 0 && blockerMatches > 0) {
                    blockedSpecifically = true
                    break
                }
            }
            Thread.sleep(20)
        }
        assertTrue(ungrantedCount > 0, "Opposing worker must be blocked in PostgreSQL by earlier lock holder")
        assertTrue(blockedSpecifically, "Opposing worker PID $lifecyclePid must be specifically blocked by earlier lock holder PID $cmdPid")

        releaseEarlierLockLatch.countDown()

        val ack1 = workerEarlierToLater.get(5, TimeUnit.SECONDS)
        assertEquals(AviatorCommandAckStatus.ACCEPTED, ack1.status)

        val updatedRound = workerOpposingLifecycle.get(5, TimeUnit.SECONDS)
        assertNotNull(updatedRound)
        assertEquals(GameRoundPhase.FLYING, updatedRound.phase)

        var prevRankEarlier = 0
        for ((resource, rank) in holdingEarlierStore.eventLog) {
            if (resource != "RECEIPT_WRITE" && rank < prevRankEarlier) {
                rankInversions.add("Inversion in earlier-to-later holding test: $resource($rank) after rank $prevRankEarlier")
            }
            if (resource != "RECEIPT_WRITE") {
                prevRankEarlier = rank
            }
        }
        assertTrue(holdingEarlierStore.eventLog.any { it.first == "ROUND_SHARED" })
        assertTrue(holdingEarlierStore.eventLog.any { it.first == "SEQUENCE_COUNTER" })

        val txTemplate = TransactionTemplate(txManager)
        val roundContentionId = "rnd-seq-contention-${UUID.randomUUID().toString().take(6)}"
        gameService.createOrUpdateRound(
            CreateOrUpdateRoundCommand(
                tenantId = tenantId,
                gameId = gameId,
                roundId = roundContentionId,
                phase = GameRoundPhase.BET_COUNTDOWN,
                roundVersion = 1L,
            )
        )

        var conn1Pid: Int? = null
        var conn2Pid: Int? = null
        val workerAHeldCounterLatch = CountDownLatch(1)
        val workerBRequestedCounterLatch = CountDownLatch(1)
        val releaseWorkerALatch = CountDownLatch(1)

        val workerA = pool.submit<Long> {
            txTemplate.execute {
                conn1Pid = jdbc.queryForObject("SELECT pg_backend_pid()", Int::class.java)
                gameStore.findRoundForShare(tenantId, gameId, roundContentionId)
                val seq = gameStore.nextSequenceId(tenantId)
                workerAHeldCounterLatch.countDown()
                releaseWorkerALatch.await(5, TimeUnit.SECONDS)
                seq
            }
        }

        assertTrue(workerAHeldCounterLatch.await(5, TimeUnit.SECONDS))

        val workerB = pool.submit<Long> {
            txTemplate.execute {
                conn2Pid = jdbc.queryForObject("SELECT pg_backend_pid()", Int::class.java)
                gameStore.findRoundForShare(tenantId, gameId, roundContentionId)
                workerBRequestedCounterLatch.countDown()
                gameStore.nextSequenceId(tenantId)
            }
        }

        assertTrue(workerBRequestedCounterLatch.await(5, TimeUnit.SECONDS))

        var seqCounterBlocked = false
        for (attempt in 0 until 100) {
            val c1Pid = conn1Pid
            val c2Pid = conn2Pid
            if (c1Pid != null && c2Pid != null) {
                val ungranted = jdbc.queryForObject(
                    "SELECT count(*) FROM pg_locks WHERE pid = ? AND NOT granted",
                    Int::class.java,
                    c2Pid,
                ) ?: 0
                val blockedByC1 = jdbc.queryForObject(
                    "SELECT count(*) FROM pg_stat_activity WHERE pid = ? AND ? = ANY(pg_blocking_pids(pid))",
                    Int::class.java,
                    c2Pid,
                    c1Pid,
                ) ?: 0
                if (ungranted > 0 || blockedByC1 > 0) {
                    seqCounterBlocked = true
                    break
                }
            }
            Thread.sleep(50)
        }
        assertTrue(seqCounterBlocked, "Worker B must be blocked in PostgreSQL on game_command_sequence row held by Worker A")

        releaseWorkerALatch.countDown()

        val seqA = workerA.get(5, TimeUnit.SECONDS)
        val seqB = workerB.get(5, TimeUnit.SECONDS)
        assertNotNull(seqA)
        assertNotNull(seqB)
        assertEquals(seqA + 1L, seqB, "Worker B must receive consecutive sequence immediately after Worker A commits")

        val roundInvertId = "rnd-invert-deadlock-${UUID.randomUUID().toString().take(6)}"
        gameService.createOrUpdateRound(
            CreateOrUpdateRoundCommand(
                tenantId = tenantId,
                gameId = gameId,
                roundId = roundInvertId,
                phase = GameRoundPhase.BET_COUNTDOWN,
                roundVersion = 1L,
            )
        )

        val forwardHeldRoundLatch = CountDownLatch(1)
        val invertedHeldCounterLatch = CountDownLatch(1)
        val deadlockDetected = AtomicBoolean(false)
        val bothReadyToInvertLatch = CountDownLatch(2)

        val workerForward = pool.submit {
            try {
                txTemplate.execute {
                    jdbc.execute("SET LOCAL deadlock_timeout = '100ms'")
                    gameStore.findRoundForUpdate(tenantId, gameId, roundInvertId)
                    forwardHeldRoundLatch.countDown()
                    bothReadyToInvertLatch.countDown()
                    bothReadyToInvertLatch.await(5, TimeUnit.SECONDS)
                    Thread.sleep(50)
                    gameStore.nextSequenceId(tenantId)
                }
            } catch (e: Exception) {
                var c: Throwable? = e
                while (c != null) {
                    if (c.message?.contains("deadlock detected") == true) {
                        deadlockDetected.set(true)
                    }
                    c = c.cause
                }
            }
        }

        val workerInverted = pool.submit {
            try {
                txTemplate.execute {
                    jdbc.execute("SET LOCAL deadlock_timeout = '100ms'")
                    gameStore.nextSequenceId(tenantId)
                    invertedHeldCounterLatch.countDown()
                    bothReadyToInvertLatch.countDown()
                    bothReadyToInvertLatch.await(5, TimeUnit.SECONDS)
                    Thread.sleep(50)
                    gameStore.findRoundForUpdate(tenantId, gameId, roundInvertId)
                }
            } catch (e: Exception) {
                var c: Throwable? = e
                while (c != null) {
                    if (c.message?.contains("deadlock detected") == true) {
                        deadlockDetected.set(true)
                    }
                    c = c.cause
                }
            }
        }

        assertTrue(forwardHeldRoundLatch.await(5, TimeUnit.SECONDS))
        assertTrue(invertedHeldCounterLatch.await(5, TimeUnit.SECONDS))

        workerForward.get(5, TimeUnit.SECONDS)
        workerInverted.get(5, TimeUnit.SECONDS)
        assertTrue(deadlockDetected.get(), "PostgreSQL must detect deadlock when a worker inverts the global lock order")

        val actionTypes = listOf("PLACE_BET", "CANCEL_BET", "CASH_OUT")
        val rng = Random(1337)
        for (i in 0 until 100) {
            val actionType = actionTypes[rng.nextInt(actionTypes.size)]
            val roundId = "rnd-seeded-100-$i-${UUID.randomUUID().toString().take(6)}"
            gameService.createOrUpdateRound(
                CreateOrUpdateRoundCommand(
                    tenantId = tenantId,
                    gameId = gameId,
                    roundId = roundId,
                    phase = GameRoundPhase.BET_COUNTDOWN,
                    roundVersion = 1L,
                )
            )

            if (actionType == "CANCEL_BET" || actionType == "CASH_OUT") {
                val prePlace = gameService.processCommand(
                    AviatorRestCommand(
                        tenantId = tenantId,
                        principal = playerPrincipal,
                        commandId = "cmd-pre-100-$i-${UUID.randomUUID().toString().take(4)}",
                        roundId = roundId,
                        handId = "hand_primary",
                        action = "PLACE_BET",
                        wagerMinor = 100L,
                        currency = "INR",
                        correlationId = "corr-pre-100-$i",
                    )
                )
                assertEquals(AviatorCommandAckStatus.ACCEPTED, prePlace.status)
                if (actionType == "CASH_OUT") {
                    gameService.createOrUpdateRound(
                        CreateOrUpdateRoundCommand(
                            tenantId = tenantId,
                            gameId = gameId,
                            roundId = roundId,
                            phase = GameRoundPhase.FLYING,
                            roundVersion = 2L,
                            expectedVersion = 1L,
                            currentMultiplier = BigDecimal("1.2000"),
                        )
                    )
                }
            }

            var cmdPid: Int? = null
            var lifecyclePid: Int? = null
            val roundHeldLatch = CountDownLatch(1)
            val worker1ProceedLatch = CountDownLatch(1)

            val cmdStore = LockOrderTracingStore(
                gameStore,
                onRoundShared = {
                    cmdPid = jdbc.queryForObject("SELECT pg_backend_pid()", Int::class.java)
                    roundHeldLatch.countDown()
                    worker1ProceedLatch.await(5, TimeUnit.SECONDS)
                }
            )
            val cmdSvc = DurableGameWagerAndSettlementService(
                store = cmdStore,
                ledgerService = ledgerService,
                registrationStore = registrationStore,
                eligibilityStore = eligibilityStore,
                adminPrincipal = adminPrincipal,
                clock = clock,
                txManager = txManager,
            )

            val lifeStore = LockOrderTracingStore(
                gameStore,
                onRoundExclusive = {
                    lifecyclePid = jdbc.queryForObject("SELECT pg_backend_pid()", Int::class.java)
                }
            )
            val lifeSvc = DurableGameWagerAndSettlementService(
                store = lifeStore,
                ledgerService = ledgerService,
                registrationStore = registrationStore,
                eligibilityStore = eligibilityStore,
                adminPrincipal = adminPrincipal,
                clock = clock,
                txManager = txManager,
            )

            val cmdFuture = pool.submit<AviatorCommandAckResult> {
                cmdSvc.processCommand(
                    AviatorRestCommand(
                        tenantId = tenantId,
                        principal = playerPrincipal,
                        commandId = "cmd-seeded-$i-${UUID.randomUUID().toString().take(4)}",
                        roundId = roundId,
                        handId = "hand_primary",
                        action = actionType,
                        wagerMinor = if (actionType == "PLACE_BET") 100L else null,
                        currency = "INR",
                        correlationId = "corr-seeded-$i",
                    )
                )
            }

            val lifeFuture = pool.submit<GameRoundRecord> {
                assertTrue(roundHeldLatch.await(5, TimeUnit.SECONDS), "Worker 2 timed out waiting for Worker 1 to hold round lock")
                if (actionType == "CASH_OUT") {
                    lifeSvc.createOrUpdateRound(
                        CreateOrUpdateRoundCommand(
                            tenantId = tenantId,
                            gameId = gameId,
                            roundId = roundId,
                            phase = GameRoundPhase.FLYING,
                            roundVersion = 3L,
                            expectedVersion = 2L,
                            currentMultiplier = BigDecimal("1.2500"),
                        )
                    )
                } else {
                    lifeSvc.createOrUpdateRound(
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
                }
            }

            var blockedInPg = false
            for (attempt in 0 until 100) {
                val curLifecyclePid = lifecyclePid
                val curCmdPid = cmdPid
                if (curLifecyclePid != null && curCmdPid != null) {
                    val ungranted = jdbc.queryForObject(
                        "SELECT count(*) FROM pg_locks WHERE pid = ? AND NOT granted",
                        Int::class.java,
                        curLifecyclePid,
                    ) ?: 0
                    val blockerMatches = jdbc.queryForObject(
                        """
                        SELECT count(*) FROM pg_stat_activity
                        WHERE pid = ?
                          AND wait_event_type = 'Lock'
                          AND ? = ANY(pg_blocking_pids(pid))
                        """.trimIndent(),
                        Int::class.java,
                        curLifecyclePid,
                        curCmdPid,
                    ) ?: 0
                    if (ungranted > 0 && blockerMatches > 0) {
                        blockedInPg = true
                        break
                    }
                }
                Thread.sleep(5)
            }
            assertTrue(blockedInPg, "Iteration $i: Worker 2 must be actively blocked in PostgreSQL by Worker 1 on round lock")

            worker1ProceedLatch.countDown()

            val cmdAck = cmdFuture.get(5, TimeUnit.SECONDS)
            assertNotNull(cmdAck)
            assertEquals(AviatorCommandAckStatus.ACCEPTED, cmdAck.status)
            assertTrue(cmdAck.sequenceId > 0L)

            val lifeRound = lifeFuture.get(5, TimeUnit.SECONDS)
            assertNotNull(lifeRound)
            assertEquals(GameRoundPhase.FLYING, lifeRound.phase)

            var prevRankCmd = 0
            for ((resource, rank) in cmdStore.eventLog) {
                if (resource != "RECEIPT_WRITE" && rank < prevRankCmd) {
                    rankInversions.add("Cmd store inversion at iteration $i for $actionType: $resource($rank) after rank $prevRankCmd")
                }
                if (resource != "RECEIPT_WRITE") {
                    prevRankCmd = rank
                }
            }
            assertTrue(cmdStore.eventLog.any { it.first == "ROUND_SHARED" }, "Cmd worker must acquire ROUND_SHARED")
            assertTrue(cmdStore.eventLog.any { it.first == "SEQUENCE_COUNTER" }, "Cmd worker must acquire SEQUENCE_COUNTER")

            var prevRankLife = 0
            for ((resource, rank) in lifeStore.eventLog) {
                if (resource != "RECEIPT_WRITE" && rank < prevRankLife) {
                    rankInversions.add("Life store inversion at iteration $i for $actionType: $resource($rank) after rank $prevRankLife")
                }
                if (resource != "RECEIPT_WRITE") {
                    prevRankLife = rank
                }
            }
            assertTrue(lifeStore.eventLog.any { it.first == "ROUND_EXCLUSIVE" }, "Lifecycle worker must acquire ROUND_EXCLUSIVE")
        }

        assertTrue(rankInversions.isEmpty(), "Zero lock rank inversions expected across 100 iterations: $rankInversions")

        pool.shutdown()
        pool.awaitTermination(5, TimeUnit.SECONDS)
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

        val roundId1 = "rnd-seq-gld1-${UUID.randomUUID().toString().take(6)}"
        lifecyclePort.createScheduledRoundWithCommitment(tenantId, gameId, roundId1, properties)

        val balanceBefore = 50000L
        ledgerService.postTransaction(
            PostTransactionCommand(
                principal = adminPrincipal,
                tenantId = tenantId,
                transactionReference = "TX-GOLDEN-SEQ-DEPOSIT-${UUID.randomUUID()}",
                currencyCode = "INR",
                entries = listOf(
                    JournalEntryDraft(
                        accountReference = "HOUSE:SEED",
                        direction = JournalEntryDirection.DEBIT,
                        amountMinorUnits = balanceBefore,
                        currencyCode = "INR",
                    ),
                    JournalEntryDraft(
                        accountReference = "PLAYER:$playerIdStr",
                        direction = JournalEntryDirection.CREDIT,
                        amountMinorUnits = balanceBefore,
                        currencyCode = "INR",
                    )
                ),
                correlationId = "corr-golden",
                causationId = "caus-golden",
                idempotencyKey = UUID.randomUUID().toString(),
            )
        )

        val betAck1 = gameService.processCommand(
            AviatorRestCommand(
                tenantId = tenantId,
                principal = playerPrincipal,
                commandId = "cmd-bet-seq-golden-1",
                roundId = roundId1,
                handId = "hand_primary",
                action = "PLACE_BET",
                wagerMinor = wagerMinor,
                currency = "INR",
                correlationId = "corr-bet-seq-golden-1",
            )
        )
        assertEquals(AviatorCommandAckStatus.ACCEPTED, betAck1.status)

        val cancelAck = gameService.processCommand(
            AviatorRestCommand(
                tenantId = tenantId,
                principal = playerPrincipal,
                commandId = "cmd-cancel-seq-golden-1",
                roundId = roundId1,
                handId = "hand_primary",
                action = "CANCEL_BET",
                correlationId = "corr-cancel-seq-golden-1",
            )
        )
        assertEquals(AviatorCommandAckStatus.ACCEPTED, cancelAck.status)
        assertEquals(balanceBefore, ledgerService.store.findBalance(tenantId, "PLAYER:$playerIdStr", "INR"))

        val roundId2 = "rnd-seq-gld2-${UUID.randomUUID().toString().take(6)}"
        lifecyclePort.createScheduledRoundWithCommitment(tenantId, gameId, roundId2, properties)

        val betAck2 = gameService.processCommand(
            AviatorRestCommand(
                tenantId = tenantId,
                principal = playerPrincipal,
                commandId = "cmd-bet-seq-golden-2",
                roundId = roundId2,
                handId = "hand_primary",
                action = "PLACE_BET",
                wagerMinor = wagerMinor,
                currency = "INR",
                correlationId = "corr-bet-seq-golden-2",
            )
        )
        assertEquals(AviatorCommandAckStatus.ACCEPTED, betAck2.status)

        gameService.createOrUpdateRound(
            CreateOrUpdateRoundCommand(
                tenantId = tenantId,
                gameId = gameId,
                roundId = roundId2,
                phase = GameRoundPhase.FLYING,
                roundVersion = 2L,
                expectedVersion = 1L,
                currentMultiplier = multiplier,
            )
        )

        val cashOutAck = gameService.processCommand(
            AviatorRestCommand(
                tenantId = tenantId,
                principal = playerPrincipal,
                commandId = "cmd-cashout-seq-golden-2",
                roundId = roundId2,
                handId = "hand_primary",
                action = "CASH_OUT",
                correlationId = "corr-cashout-seq-golden-2",
            )
        )
        assertEquals(AviatorCommandAckStatus.ACCEPTED, cashOutAck.status)
        assertEquals(124L, cashOutAck.result?.payoutMinor)

        val expectedBalance = balanceBefore - wagerMinor + 124L
        assertEquals(expectedBalance, ledgerService.store.findBalance(tenantId, "PLAYER:$playerIdStr", "INR"))

        val roundId3 = "rnd-seq-gld3-${UUID.randomUUID().toString().take(6)}"
        lifecyclePort.createScheduledRoundWithCommitment(tenantId, gameId, roundId3, properties)

        val betAck3 = gameService.processCommand(
            AviatorRestCommand(
                tenantId = tenantId,
                principal = playerPrincipal,
                commandId = "cmd-bet-seq-golden-3",
                roundId = roundId3,
                handId = "hand_primary",
                action = "PLACE_BET",
                wagerMinor = wagerMinor,
                currency = "INR",
                correlationId = "corr-bet-seq-golden-3",
            )
        )
        assertEquals(AviatorCommandAckStatus.ACCEPTED, betAck3.status)

        val crashResult = gameService.settleRoundCrash(
            SettleRoundCrashCommand(
                tenantId = tenantId,
                gameId = gameId,
                roundId = roundId3,
                crashMultiplier = BigDecimal("1.0000"),
            )
        )
        assertEquals(1, crashResult.settledBetsCount)

        val finalBalance = ledgerService.store.findBalance(tenantId, "PLAYER:$playerIdStr", "INR")
        assertEquals(expectedBalance - wagerMinor, finalBalance)
    }
}
