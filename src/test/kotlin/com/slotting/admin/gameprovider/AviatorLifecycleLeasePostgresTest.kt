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
import com.slotting.admin.ledger.LedgerJournalStore
import com.slotting.admin.ledger.LedgerPostingService
import com.slotting.admin.ledger.PostTransactionCommand
import org.flywaydb.core.Flyway
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.assertThrows
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.boot.test.context.SpringBootTest
import org.springframework.boot.test.mock.mockito.MockBean
import org.springframework.dao.DataIntegrityViolationException
import org.springframework.jdbc.core.JdbcTemplate
import org.springframework.test.context.DynamicPropertyRegistry
import org.springframework.test.context.DynamicPropertySource
import org.springframework.transaction.PlatformTransactionManager
import org.springframework.transaction.support.TransactionTemplate
import java.math.BigDecimal
import java.math.RoundingMode
import java.sql.SQLException
import java.sql.Timestamp
import java.time.Clock
import java.time.Instant
import java.time.LocalDate
import java.time.ZoneOffset
import java.util.UUID
import java.util.concurrent.Callable
import java.util.concurrent.Executors
import java.util.concurrent.Future
import java.util.concurrent.TimeUnit
import kotlin.random.Random
import kotlin.test.assertEquals
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue

@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.NONE)
class AviatorLifecycleLeasePostgresTest {
    @MockBean
    private lateinit var snapshotAndEventService: AuthoritativeGameSnapshotAndEventService


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

    private val now = Instant.parse("2026-10-01T10:00:00Z")
    private val clock = Clock.fixed(now, ZoneOffset.UTC)
    private val tenantId = "tenant-tc018-lease"
    private val gameId = "AVIATOR"
    private val currency = "INR"
    private val playerUuid = UUID.randomUUID()
    private val playerIdStr = playerUuid.toString()

    private val adminPrincipal = AuthenticatedPrincipal(
        id = "admin-sys-tc018",
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
    private lateinit var leaseStore: JdbcGameLifecycleLeaseStore
    private lateinit var fairnessAuthority: ProvablyFairOutcomeAuthority

    @BeforeEach
    fun setUp() {
        jdbc.update("delete from game_bet_settlement where tenant_id = ?", tenantId)
        jdbc.update("delete from game_accepted_bet where tenant_id = ?", tenantId)
        jdbc.update("delete from game_command_receipt where tenant_id = ?", tenantId)
        jdbc.update("delete from game_fairness_audit where tenant_id = ?", tenantId)
        jdbc.update("delete from game_fairness_reveal where tenant_id = ?", tenantId)
        jdbc.update("delete from game_fairness_commitment where tenant_id = ?", tenantId)
        jdbc.update("delete from game_cumulative_player_limit where tenant_id = ?", tenantId)
        jdbc.update("delete from game_authoritative_round where tenant_id = ?", tenantId)
        jdbc.update("delete from ledger_leg where tenant_id = ?", tenantId)
        jdbc.update("delete from ledger_idempotency_receipt where tenant_id = ?", tenantId)
        jdbc.update("delete from ledger_transaction where tenant_id = ?", tenantId)
        jdbc.update("delete from ledger_account where tenant_id = ?", tenantId)
        jdbc.update("delete from game_command_sequence where tenant_id = ?", tenantId)
        jdbc.update("delete from ledger_version_tracker where tenant_id = ?", tenantId)
        if (leaseTableExists()) {
            jdbc.update("delete from game_lifecycle_lease where tenant_id = ? or tenant_id like ?", tenantId, "tenant-tc018%")
        }

        gameStore = JdbcDurableGameWagerAndSettlementStore(jdbc)
        ledgerStore = JdbcLedgerJournalStore(jdbc)
        registrationStore = JdbcPlayerRegistrationStore(jdbc)
        eligibilityStore = com.slotting.admin.identity.InMemoryServerEligibilityStore()
        ledgerService = LedgerPostingService(store = ledgerStore, clock = clock)
        fairnessAuthority = ProvablyFairOutcomeAuthority(JdbcFairnessEvidenceStore(jdbc), clock)
        leaseStore = JdbcGameLifecycleLeaseStore(jdbc)

        gameService = DurableGameWagerAndSettlementService(
            store = gameStore,
            ledgerService = ledgerService,
            registrationStore = registrationStore,
            eligibilityStore = eligibilityStore,
            adminPrincipal = adminPrincipal,
            clock = clock,
            fairnessAuthority = fairnessAuthority,
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
                    singleWagerLimitMinor = 5_000_000L,
                    dailyWagerLimitMinor = 20_000_000L,
                    currentDailyWagerMinor = 0L,
                ),
            )
        )
    }

    private fun leaseTableExists(): Boolean =
        (jdbc.queryForObject(
            "select count(*) from information_schema.tables where table_name = 'game_lifecycle_lease'",
            Int::class.java,
        ) ?: 0) > 0

    private fun closeActiveRounds(tId: String = tenantId, gId: String = gameId) {
        jdbc.update(
            "update game_authoritative_round set phase = 'CLOSED', closed_at = now(), updated_at = now() where tenant_id = ? and game_id = ? and phase <> 'CLOSED'",
            tId,
            gId,
        )
    }

    private fun insertRound(roundId: String, phase: String = "SCHEDULED", tId: String = tenantId, gId: String = gameId) {
        jdbc.update(
            """
            insert into game_authoritative_round (
                round_id, tenant_id, game_id, phase, round_version,
                current_multiplier, started_at, server_time, created_at, updated_at
            ) values (?, ?, ?, ?, 1, 1.0000, ?, ?, ?, ?)
            on conflict (tenant_id, game_id, round_id) do nothing
            """.trimIndent(),
            roundId,
            tId,
            gId,
            phase,
            Timestamp.from(now),
            Timestamp.from(now),
            Timestamp.from(now),
            Timestamp.from(now),
        )
    }

    private fun seedFunds(amount: Long) {
        ledgerService.postTransaction(
            PostTransactionCommand(
                principal = adminPrincipal,
                tenantId = tenantId,
                transactionReference = "TX-TC018-SEED-${UUID.randomUUID()}",
                currencyCode = currency,
                entries = listOf(
                    JournalEntryDraft("HOUSE:SEED", JournalEntryDirection.DEBIT, amount, currency),
                    JournalEntryDraft("PLAYER:$playerIdStr", JournalEntryDirection.CREDIT, amount, currency),
                ),
                idempotencyKey = "IDEM-TC018-SEED-${UUID.randomUUID()}",
                correlationId = "corr-tc018-seed",
                causationId = "caus-tc018-seed",
            )
        )
    }

    private fun placeBetCommand(roundId: String, commandId: String) = AviatorRestCommand(
        tenantId = tenantId,
        principal = playerPrincipal,
        commandId = commandId,
        roundId = roundId,
        handId = "hand_primary",
        action = "PLACE_BET",
        wagerMinor = 101L,
        autoCashOutMultiplier = null,
        currency = currency,
        correlationId = "corr-$commandId",
    )

    private fun assertJournalBalanced() {
        val debits = jdbc.queryForObject("select coalesce(sum(total_debits_minor_units), 0) from ledger_transaction where tenant_id = ?", Long::class.java, tenantId) ?: 0L
        val credits = jdbc.queryForObject("select coalesce(sum(total_credits_minor_units), 0) from ledger_transaction where tenant_id = ?", Long::class.java, tenantId) ?: 0L
        assertEquals(debits, credits, "Double-entry journal must stay balanced")
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

        override fun findRoundForUpdate(tenantId: String, gameId: String, roundId: String): GameRoundRecord? {
            eventLog.add("ROUND_EXCLUSIVE" to 2)
            return delegate.findRoundForUpdate(tenantId, gameId, roundId)
        }

        override fun findBet(tenantId: String, gameId: String, roundId: String, ownerId: String, handId: String): GameAcceptedBetRecord? {
            eventLog.add("BET" to 3)
            return delegate.findBet(tenantId, gameId, roundId, ownerId, handId)
        }

        override fun findBetsForRoundForUpdate(tenantId: String, gameId: String, roundId: String): List<GameAcceptedBetRecord> {
            eventLog.add("BETS" to 3)
            return delegate.findBetsForRoundForUpdate(tenantId, gameId, roundId)
        }

        override fun nextSequenceId(tenantId: String): Long {
            val sequence = delegate.nextSequenceId(tenantId)
            eventLog.add("SEQUENCE_COUNTER" to 5)
            return sequence
        }
    }

    class LedgerRankTracingStore(
        private val delegate: LedgerJournalStore,
        val eventLog: MutableList<Pair<String, Int>> = mutableListOf(),
    ) : LedgerJournalStore by delegate {
        override fun lockAccount(tenantId: String, accountReference: String, currencyCode: String): Boolean {
            eventLog.add("PLAYER_ACCOUNT" to 4)
            return delegate.lockAccount(tenantId, accountReference, currencyCode)
        }
    }

    private fun assertMonotonic(events: List<Pair<String, Int>>) {
        var previousRank = 0
        for ((resource, rank) in events) {
            if (resource == "RECEIPT_WRITE") continue
            assertTrue(rank >= previousRank, "Lock rank inversion at $resource ($rank) after $previousRank in $events")
            previousRank = rank
        }
    }

    @Test
    fun GivenTwoActiveRounds_WhenConstraintAdded_ThenDiagnosticAborts() {
        val schema = "tc018_diag_${UUID.randomUUID().toString().replace("-", "").take(12)}"
        val testTenant = "tenant-tc018-diag-${UUID.randomUUID()}"
        val roundA = "rnd-diag-a"
        val roundB = "rnd-diag-b"

        jdbc.execute("create schema $schema")

        try {
            val toBaseline = Flyway.configure()
                .dataSource(jdbc.dataSource!!)
                .locations("classpath:db/migration")
                .schemas(schema)
                .defaultSchema(schema)
                .cleanDisabled(true)
                .target("44")
                .load()
            toBaseline.migrate()

            insertIsolatedRound(schema, roundA, "SCHEDULED", testTenant)
            insertIsolatedRound(schema, roundB, "FLYING", testTenant)

            val reusableDiagnostic = TransactionTemplate(txManager).execute {
                jdbc.execute("set local search_path to $schema, public")
                AviatorActiveRoundDiagnostics.detectDuplicateActiveRounds(jdbc)
            }
            val reusableMatch = reusableDiagnostic?.firstOrNull { it.tenantId == testTenant && it.gameId == gameId }
            assertNotNull(reusableMatch, "Reusable diagnostic must report the duplicate group for $testTenant/$gameId")
            assertEquals(2L, reusableMatch.count, "Reusable diagnostic must report count 2")
            assertEquals(
                setOf(roundA, roundB),
                reusableMatch.roundIds.toSet(),
                "Reusable diagnostic must report both conflicting round IDs",
            )

            val toLatest = Flyway.configure()
                .dataSource(jdbc.dataSource!!)
                .locations("classpath:db/migration")
                .schemas(schema)
                .defaultSchema(schema)
                .cleanDisabled(true)
                .load()

            val flywayException = assertThrows<Exception> {
                toLatest.migrate()
            }
            var rootCause: Throwable? = flywayException
            val allMessages = StringBuilder()
            while (rootCause != null) {
                allMessages.append(" ").append(rootCause.message)
                rootCause = rootCause.cause
            }
            val msg = allMessages.toString()
            assertTrue(msg.contains(testTenant), "Diagnostic abort message must contain tenantId: $msg")
            assertTrue(msg.contains(gameId), "Diagnostic abort message must contain gameId: $msg")
            assertTrue(msg.contains("count=2"), "Diagnostic abort message must contain count=2: $msg")
            assertTrue(msg.contains(roundA), "Diagnostic abort message must contain roundA: $msg")
            assertTrue(msg.contains(roundB), "Diagnostic abort message must contain roundB: $msg")

            val phasesAfter = isolatedActiveRoundPhases(schema, testTenant)
            assertEquals(
                setOf(roundA to "SCHEDULED", roundB to "FLYING"),
                phasesAfter,
                "Diagnostic abort must not close, delete or otherwise change conflicting rounds",
            )

            assertEquals(
                0,
                jdbc.queryForObject(
                    "select count(*) from information_schema.tables where table_schema = ? and table_name = 'game_lifecycle_lease'",
                    Int::class.java,
                    schema,
                ),
                "Migration must fail closed before creating the lease table",
            )
        } finally {
            jdbc.execute("drop schema if exists $schema cascade")
        }
    }

    @Test
    fun GivenCleanSchema_WhenSecondActiveRoundInserted_ThenUniqueViolation() {
        val cleanTenant = "tenant-tc018-clean-${UUID.randomUUID()}"
        try {
            insertRound("rnd-clean-1", "SCHEDULED", cleanTenant, gameId)
            assertUniqueViolation("Clean schema must reject second active round with 23505 unique violation") {
                insertRound("rnd-clean-2", "FLYING", cleanTenant, gameId)
            }
        } finally {
            jdbc.update("delete from game_authoritative_round where tenant_id = ?", cleanTenant)
        }
    }

    @Test
    fun GivenCleanIsolatedSchema_WhenMigratedThroughV45_ThenLeaseAndSingleActiveConstraintsExist() {
        val schema = "tc018_clean_${UUID.randomUUID().toString().replace("-", "").take(12)}"

        jdbc.execute("create schema $schema")

        try {
            val flyway = Flyway.configure()
                .dataSource(jdbc.dataSource!!)
                .locations("classpath:db/migration")
                .schemas(schema)
                .defaultSchema(schema)
                .cleanDisabled(true)
                .target("45")
                .load()
            val result = flyway.migrate()
            assertTrue(result.success, "a clean fresh schema must migrate through V45 successfully")

            assertEquals(
                "45",
                jdbc.queryForObject(
                    "select version from $schema.flyway_schema_history where version is not null order by installed_rank desc limit 1",
                    String::class.java,
                ),
                "the clean schema must end at schema version 45",
            )

            assertEquals(
                1,
                jdbc.queryForObject(
                    "select count(*) from information_schema.tables where table_schema = ? and table_name = 'game_lifecycle_lease'",
                    Int::class.java,
                    schema,
                ),
                "V45 must create the lease table in a clean schema",
            )

            val leaseColumns = jdbc.query(
                "select column_name from information_schema.columns where table_schema = ? and table_name = 'game_lifecycle_lease'",
                { rs, _ -> rs.getString("column_name") },
                schema,
            ).toSet()
            assertTrue(
                leaseColumns.containsAll(setOf("tenant_id", "game_id", "owner_id", "epoch", "lease_expires_at")),
                "lease table must carry the tenant/game/owner/epoch/expiry contract, saw $leaseColumns",
            )

            val activeIndex = jdbc.queryForObject(
                "select indexdef from pg_indexes where schemaname = ? and indexname = 'ux_game_authoritative_round_active'",
                String::class.java,
                schema,
            )
            assertNotNull(activeIndex, "V45 must create the partial unique active-round index")
            assertTrue(activeIndex.contains("UNIQUE"), "active-round index must be unique: $activeIndex")
            assertTrue(
                activeIndex.contains("phase") && activeIndex.contains("CLOSED"),
                "active-round index must be partial on phase <> 'CLOSED': $activeIndex",
            )

            val constraintTenant = "tenant-tc018-clean-schema-${UUID.randomUUID()}"
            insertIsolatedRound(schema, "rnd-clean-schema-1", "SCHEDULED", constraintTenant)
            assertUniqueViolation("a clean V45 schema must reject a second active round") {
                insertIsolatedRound(schema, "rnd-clean-schema-2", "FLYING", constraintTenant)
            }

            insertIsolatedRound(schema, "rnd-clean-schema-3", "CLOSED", constraintTenant)
            assertEquals(
                1,
                jdbc.queryForObject(
                    "select count(*) from $schema.game_authoritative_round where tenant_id = ? and phase <> 'CLOSED'",
                    Int::class.java,
                    constraintTenant,
                ),
                "CLOSED rounds must not count as active",
            )
        } finally {
            jdbc.execute("drop schema if exists $schema cascade")
        }
    }

    private fun assertUniqueViolation(message: String, block: () -> Unit) {
        val ex = assertThrows<Exception>(message) { block() }
        var current: Throwable? = ex
        var hasSqlState23505 = false
        while (current != null) {
            if (current is SQLException && current.sqlState == "23505") hasSqlState23505 = true
            current = current.cause
        }
        assertTrue(
            hasSqlState23505 || ex is DataIntegrityViolationException,
            "$message: $ex",
        )
    }

    private fun insertIsolatedRound(schema: String, roundId: String, phase: String, tId: String) {
        jdbc.update(
            """
            insert into $schema.game_authoritative_round (
                round_id, tenant_id, game_id, phase, round_version,
                current_multiplier, started_at, server_time, created_at, updated_at
            ) values (?, ?, ?, ?, 1, 1.0000, now(), now(), now(), now())
            """.trimIndent(),
            roundId,
            tId,
            gameId,
            phase,
        )
    }

    private fun isolatedActiveRoundPhases(schema: String, tId: String): Set<Pair<String, String>> =
        jdbc.query(
            "select round_id, phase from $schema.game_authoritative_round where tenant_id = ? and phase <> 'CLOSED'",
            { rs, _ -> rs.getString("round_id") to rs.getString("phase") },
            tId,
        ).toSet()

    @Test
    fun GivenTwoOwners_WhenLeaseAcquired_ThenOneEpochOwner() {
        val owner1 = "node-alpha"
        val owner2 = "node-beta"
        val foreignTenant = "tenant-tc018-foreign"

        val foreignAcquire = leaseStore.acquireOrRenew(foreignTenant, gameId, "node-foreign", 60_000L)
        assertEquals(LifecycleLeaseAcquireStatus.ACQUIRED, foreignAcquire.status)

        val executor = Executors.newFixedThreadPool(2)
        val attempts = 500
        val submitted = mutableListOf<Pair<String, Future<LifecycleLeaseAcquireResult>>>()

        for (i in 0 until attempts) {
            val owner = if (i % 2 == 0) owner1 else owner2
            submitted.add(owner to executor.submit(Callable {
                leaseStore.acquireOrRenew(tenantId, gameId, owner, 150L)
            }))
        }
        executor.shutdown()
        assertTrue(executor.awaitTermination(60, TimeUnit.SECONDS), "all lease attempts must complete within the bound")

        val outcomes = submitted.map { (owner, future) -> owner to future.get(10, TimeUnit.SECONDS) }
        assertEquals(attempts, outcomes.size, "every submitted attempt must be observed")

        val acquiredByEpoch = mutableMapOf<Long, MutableSet<String>>()
        var acquiredCount = 0
        for ((owner, result) in outcomes) {
            assertTrue(
                result.status == LifecycleLeaseAcquireStatus.ACQUIRED ||
                    result.status == LifecycleLeaseAcquireStatus.REJECTED_ACTIVE_LEASE,
                "an uncontended acquire with no expected epoch must be ACQUIRED or REJECTED_ACTIVE_LEASE, got ${result.status}",
            )
            val lease = result.lease
            assertNotNull(lease, "a lease outcome must carry the durable lease row")
            assertEquals(tenantId, lease.tenantId)
            assertEquals(gameId, lease.gameId)
            assertTrue(lease.epoch >= 1, "epoch must be at least 1")
            if (result.status == LifecycleLeaseAcquireStatus.ACQUIRED) {
                acquiredCount++
                assertEquals(owner, lease.ownerId, "an acquired lease must be owned by the requesting owner")
                acquiredByEpoch.getOrPut(lease.epoch) { mutableSetOf() }.add(owner)
            }
        }

        assertTrue(acquiredCount >= 1, "at least one attempt must acquire the lease")
        acquiredByEpoch.forEach { (epoch, owners) ->
            assertEquals(1, owners.size, "epoch $epoch must be held by exactly one owner, saw $owners")
        }
        val epochs = acquiredByEpoch.keys.sorted()
        assertEquals(
            (1L..epochs.last()).toList(),
            epochs,
            "epochs must be contiguous from 1 and strictly increase on takeover, saw $epochs",
        )

        val currentLease = leaseStore.getLease(tenantId, gameId)
        assertNotNull(currentLease)
        assertTrue(currentLease.ownerId == owner1 || currentLease.ownerId == owner2)
        assertEquals(epochs.last(), currentLease.epoch, "durable lease must reflect the highest acquired epoch")
        assertEquals(
            acquiredByEpoch.getValue(currentLease.epoch),
            setOf(currentLease.ownerId),
            "durable lease owner must match the owner that acquired the highest epoch",
        )
        assertTrue(
            leaseOwnerRowCount(tenantId, gameId) == 1,
            "exactly one durable lease row must exist per tenant/game",
        )

        val foreignLease = leaseStore.getLease(foreignTenant, gameId)
        assertNotNull(foreignLease)
        assertEquals("node-foreign", foreignLease.ownerId)
        assertEquals(1L, foreignLease.epoch, "foreign tenant lease must be completely independent")

        jdbc.update("delete from game_lifecycle_lease where tenant_id = ?", foreignTenant)
    }

    private fun leaseOwnerRowCount(tId: String, gId: String): Int =
        jdbc.queryForObject(
            "select count(*) from game_lifecycle_lease where tenant_id = ? and game_id = ?",
            Int::class.java,
            tId,
            gId,
        ) ?: 0

    @Test
    fun GivenExpiredLease_WhenStaleOwnerRenews_ThenRenewalFails() {
        val ownerA = "worker-stale-A"
        val ownerB = "worker-takeover-B"

        val acquireA = leaseStore.acquireOrRenew(tenantId, gameId, ownerA, 50L)
        assertEquals(LifecycleLeaseAcquireStatus.ACQUIRED, acquireA.status)
        val epochA = acquireA.lease!!.epoch

        Thread.sleep(80)

        val acquireB = leaseStore.acquireOrRenew(tenantId, gameId, ownerB, 60_000L)
        assertEquals(LifecycleLeaseAcquireStatus.ACQUIRED, acquireB.status)
        val epochB = acquireB.lease!!.epoch
        assertTrue(epochB > epochA, "takeover must strictly increment epoch ($epochB > $epochA)")
        assertEquals(ownerB, acquireB.lease!!.ownerId)

        val staleRenew = leaseStore.acquireOrRenew(tenantId, gameId, ownerA, 60_000L, expectedEpoch = epochA)
        assertTrue(staleRenew.status != LifecycleLeaseAcquireStatus.ACQUIRED, "stale owner A renew must fail")

        val staleRelease = leaseStore.release(tenantId, gameId, ownerA, epoch = epochA)
        assertTrue(!staleRelease, "stale owner A release with old epoch must affect 0 rows")

        val currentLease = leaseStore.getLease(tenantId, gameId)
        assertNotNull(currentLease)
        assertEquals(ownerB, currentLease.ownerId, "B lease must remain intact")
        assertEquals(epochB, currentLease.epoch, "B epoch must remain intact")
    }

    @Test
    fun GivenMixedOperations_WhenLocksAreObserved_ThenGlobalOrderIsPreserved() {
        seedFunds(100_000L)
        val trace = mutableListOf<Pair<String, Int>>()
        val commandStore = LockRankTracingStore(gameStore, trace)
        val accountStore = LedgerRankTracingStore(ledgerStore, trace)
        val commandLedgerService = LedgerPostingService(store = accountStore, clock = clock)
        val commandService = DurableGameWagerAndSettlementService(
            store = commandStore,
            ledgerService = commandLedgerService,
            registrationStore = registrationStore,
            eligibilityStore = eligibilityStore,
            adminPrincipal = adminPrincipal,
            clock = clock,
            txManager = txManager,
        )

        val lifecycleStore = LockRankTracingStore(gameStore)
        val lifecycleService = DurableGameWagerAndSettlementService(
            store = lifecycleStore,
            ledgerService = ledgerService,
            registrationStore = registrationStore,
            eligibilityStore = eligibilityStore,
            adminPrincipal = adminPrincipal,
            clock = clock,
            txManager = txManager,
        )

        for (iteration in 0 until 100) {
            val roundId = "rnd-tc018-order-$iteration"
            closeActiveRounds()
            insertRound(roundId, "BET_COUNTDOWN")

            trace.clear()
            lifecycleStore.eventLog.clear()

            val ack = commandService.processCommand(placeBetCommand(roundId, "cmd-tc018-$iteration"))
            assertEquals(AviatorCommandAckStatus.ACCEPTED, ack.status, "iteration $iteration")

            assertTrue(trace.any { it.first == "RECEIPT" }, "iteration $iteration claim first")
            assertTrue(trace.any { it.first == "ROUND_SHARED" }, "iteration $iteration command shared round")
            assertTrue(trace.any { it.first == "BET" }, "iteration $iteration bet locked")
            assertTrue(trace.any { it.first == "PLAYER_ACCOUNT" }, "iteration $iteration player account locked")
            assertTrue(trace.any { it.first == "SEQUENCE_COUNTER" }, "iteration $iteration sequence counter locked")
            assertMonotonic(trace)

            val crash = lifecycleService.settleRoundCrash(
                SettleRoundCrashCommand(tenantId, gameId, roundId, BigDecimal("1.1000"))
            )
            assertEquals(1, crash.settledBetsCount, "iteration $iteration")
            assertTrue(lifecycleStore.eventLog.any { it.first == "ROUND_EXCLUSIVE" }, "iteration $iteration lifecycle exclusive round")
            assertTrue(lifecycleStore.eventLog.any { it.first == "BETS" }, "iteration $iteration lifecycle locks bets")
            assertMonotonic(lifecycleStore.eventLog)
        }
        assertJournalBalanced()
        assertEquals(0L, ledgerStore.findBalance(tenantId, "ESCROW:GAME:$gameId", currency))
    }

    @Test
    fun GivenHistoricalMoneyAndOutcomeVectors_WhenRefactoredPathRuns_ThenSemanticsStayUnchanged() {
        assertEquals(BigDecimal("2.66"), IndependentFairnessVerifier.calculateCrashMultiplier("0".repeat(64), "seed-a", "seed-b", "seed-c"))
        assertEquals(BigDecimal("2.90"), IndependentFairnessVerifier.calculateCrashMultiplier("a".repeat(64), "client-1", "client-2", "client-3"))
        assertEquals(BigDecimal("1.86"), IndependentFairnessVerifier.calculateCrashMultiplier("0123456789abcdef".repeat(4), "cs1", "cs2", "cs3"))

        val wagerMinor = 101L
        val multiplier = BigDecimal("1.2345")
        val expectedWinMinor = BigDecimal.valueOf(wagerMinor).multiply(multiplier).setScale(0, RoundingMode.FLOOR).longValueExact()
        assertEquals(124L, expectedWinMinor)

        val startingBalance = 50_000L
        seedFunds(startingBalance)

        val cashOutRound = "rnd-tc018-golden-cashout"
        insertRound(cashOutRound, "BET_COUNTDOWN")
        fairnessAuthority.publishPreBetCommitment(
            PublishCommitmentCommand(
                tenantId = tenantId,
                gameId = gameId,
                roundId = cashOutRound,
                publicSalt = "salt-$cashOutRound",
            ),
        )
        assertEquals(AviatorCommandAckStatus.ACCEPTED, gameService.processCommand(placeBetCommand(cashOutRound, "cmd-tc018-golden-bet-1")).status)
        gameService.createOrUpdateRound(
            CreateOrUpdateRoundCommand(tenantId, gameId, cashOutRound, GameRoundPhase.FLYING, 2L, multiplier)
        )
        val cashOutAck = gameService.processCommand(
            AviatorRestCommand(
                tenantId = tenantId,
                principal = playerPrincipal,
                commandId = "cmd-tc018-golden-cashout-1",
                roundId = cashOutRound,
                handId = "hand_primary",
                action = "CASH_OUT",
                currency = currency,
                correlationId = "corr-tc018-golden-cashout-1",
            )
        )
        assertEquals(AviatorCommandAckStatus.ACCEPTED, cashOutAck.status)
        assertEquals(expectedWinMinor, cashOutAck.result?.payoutMinor)
        assertEquals(startingBalance - wagerMinor + expectedWinMinor, ledgerStore.findBalance(tenantId, "PLAYER:$playerIdStr", currency))

        val lossRound = "rnd-tc018-golden-loss"
        closeActiveRounds()
        insertRound(lossRound, "BET_COUNTDOWN")
        fairnessAuthority.publishPreBetCommitment(
            PublishCommitmentCommand(
                tenantId = tenantId,
                gameId = gameId,
                roundId = lossRound,
                publicSalt = "salt-$lossRound",
            ),
        )
        assertEquals(AviatorCommandAckStatus.ACCEPTED, gameService.processCommand(placeBetCommand(lossRound, "cmd-tc018-golden-bet-2")).status)
        val crashResult = gameService.settleRoundCrash(SettleRoundCrashCommand(tenantId, gameId, lossRound, BigDecimal("1.0000")))
        assertEquals(1, crashResult.settledBetsCount)
        assertEquals(
            0L,
            jdbc.queryForObject("select payout_minor_units from game_bet_settlement where tenant_id = ? and outcome = 'LOSS_CRASH'", Long::class.java, tenantId),
        )

        assertJournalBalanced()
        assertEquals(
            2,
            jdbc.queryForObject("select count(*) from game_bet_settlement where tenant_id = ?", Int::class.java, tenantId) ?: 0,
            "each bet must have exactly one terminal settlement",
        )
        assertEquals(0L, ledgerStore.findBalance(tenantId, "ESCROW:GAME:$gameId", currency))
    }
}
