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
import com.slotting.admin.wallet.AuthoritativeWalletService
import com.slotting.admin.wallet.InMemoryAuthoritativeWalletStore
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.assertThrows
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
import kotlin.test.assertNotNull
import kotlin.test.assertTrue

@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.NONE)
class AviatorCommitmentReuseTest {

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
    private val tenantId = "tenant-tc017-commitment"
    private val gameId = "AVIATOR"
    private val currency = "INR"
    private val playerUuid = UUID.randomUUID()
    private val playerIdStr = playerUuid.toString()

    private val adminPrincipal = AuthenticatedPrincipal(
        id = "admin-sys-tc017",
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
        publicSalt = "tc017-public-salt",
        configuredTenants = setOf(tenantId),
    )

    private lateinit var gameStore: JdbcDurableGameWagerAndSettlementStore
    private lateinit var fairnessStore: JdbcFairnessEvidenceStore
    private lateinit var ledgerStore: JdbcLedgerJournalStore
    private lateinit var registrationStore: JdbcPlayerRegistrationStore
    private lateinit var eligibilityStore: ServerEligibilityStore
    private lateinit var ledgerService: LedgerPostingService
    private lateinit var gameService: DurableGameWagerAndSettlementService
    private lateinit var fairnessEnvelope: FairnessSeedEnvelope
    private lateinit var fairnessAuthority: ProvablyFairOutcomeAuthority
    private lateinit var walletService: AuthoritativeWalletService
    private lateinit var snapshotService: AuthoritativeGameSnapshotAndEventService
    private lateinit var lifecyclePort: ProductionAviatorLifecyclePort
    private lateinit var orchestrator: AviatorRoundLifecycleOrchestrator

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

        fairnessEnvelope = FairnessSeedEnvelope.devDefault()
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
        fairnessAuthority = ProvablyFairOutcomeAuthority(store = fairnessStore, clock = clock, envelope = fairnessEnvelope, txManager = txManager)
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
        orchestrator = AviatorRoundLifecycleOrchestrator(
            port = lifecyclePort,
            properties = properties,
            clock = clock,
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

    private fun insertRound(roundId: String, phase: String = "SCHEDULED") {
        closeActiveRoundsFor(jdbc, tenantId, gameId, keepRoundId = roundId)
        jdbc.update(
            """
            insert into game_authoritative_round (
                round_id, tenant_id, game_id, phase, round_version,
                current_multiplier, started_at, server_time, created_at, updated_at
            ) values (?, ?, ?, ?, 1, 1.0000, ?, ?, ?, ?)
            on conflict (tenant_id, game_id, round_id) do nothing
            """.trimIndent(),
            roundId,
            tenantId,
            gameId,
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
                transactionReference = "TX-TC017-SEED-${UUID.randomUUID()}",
                currencyCode = currency,
                entries = listOf(
                    JournalEntryDraft("HOUSE:SEED", JournalEntryDirection.DEBIT, amount, currency),
                    JournalEntryDraft("PLAYER:$playerIdStr", JournalEntryDirection.CREDIT, amount, currency),
                ),
                idempotencyKey = "IDEM-TC017-SEED-${UUID.randomUUID()}",
                correlationId = "corr-tc017-seed",
                causationId = "caus-tc017-seed",
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
    fun GivenMismatchedCommitment_WhenReused_ThenTypedConflictAndNoAdvance() {
        data class TestCase(
            val label: String,
            val expectedReason: String,
            val setup: (String) -> Unit,
        )

        val testCases = listOf(
            TestCase("status_revealed", "INVALID_STATUS") { rId: String ->
                fairnessAuthority.publishPreBetCommitment(
                    PublishCommitmentCommand(tenantId, gameId, rId, properties.publicSalt, properties.algorithmVersion, properties.rulesVersion)
                )
                jdbc.update("update game_fairness_commitment set status = 'REVEALED' where round_id = ?", rId)
            },
            TestCase("status_invalidated", "INVALID_STATUS") { rId: String ->
                fairnessAuthority.publishPreBetCommitment(
                    PublishCommitmentCommand(tenantId, gameId, rId, properties.publicSalt, properties.algorithmVersion, properties.rulesVersion)
                )
                jdbc.update("update game_fairness_commitment set status = 'INVALIDATED' where round_id = ?", rId)
            },
            TestCase("status_betting_active", "INVALID_STATUS") { rId: String ->
                fairnessAuthority.publishPreBetCommitment(
                    PublishCommitmentCommand(tenantId, gameId, rId, properties.publicSalt, properties.algorithmVersion, properties.rulesVersion)
                )
                jdbc.update("update game_fairness_commitment set status = 'BETTING_ACTIVE' where round_id = ?", rId)
            },
            TestCase("first_bet_accepted_set", "FIRST_BET_ACCEPTED") { rId: String ->
                fairnessAuthority.publishPreBetCommitment(
                    PublishCommitmentCommand(tenantId, gameId, rId, properties.publicSalt, properties.algorithmVersion, properties.rulesVersion)
                )
                jdbc.update("update game_fairness_commitment set first_bet_accepted_at = ? where round_id = ?", Timestamp.from(now), rId)
            },
            TestCase("mismatched_rules_version", "RULES_VERSION_MISMATCH") { rId: String ->
                fairnessAuthority.publishPreBetCommitment(
                    PublishCommitmentCommand(tenantId, gameId, rId, properties.publicSalt, properties.algorithmVersion, properties.rulesVersion)
                )
                jdbc.update("update game_fairness_commitment set rules_version = '2.0.0' where round_id = ?", rId)
            },
            TestCase("mismatched_algorithm_version", "ALGORITHM_VERSION_MISMATCH") { rId: String ->
                fairnessAuthority.publishPreBetCommitment(
                    PublishCommitmentCommand(tenantId, gameId, rId, properties.publicSalt, properties.algorithmVersion, properties.rulesVersion)
                )
                jdbc.update("update game_fairness_commitment set algorithm_version = '9.9.9' where round_id = ?", rId)
            },
            TestCase("mismatched_public_salt", "PUBLIC_SALT_MISMATCH") { rId: String ->
                fairnessAuthority.publishPreBetCommitment(
                    PublishCommitmentCommand(tenantId, gameId, rId, properties.publicSalt, properties.algorithmVersion, properties.rulesVersion)
                )
                jdbc.update("update game_fairness_commitment set public_salt = 'tampered-salt' where round_id = ?", rId)
            },
            TestCase("mismatched_authority_type", "AUTHORITY_TYPE_MISMATCH") { rId: String ->
                fairnessAuthority.publishPreBetCommitment(
                    PublishCommitmentCommand(tenantId, gameId, rId, properties.publicSalt, properties.algorithmVersion, properties.rulesVersion)
                )
                jdbc.update("update game_fairness_commitment set authority_type = 'EXTERNAL_CERTIFIED_PROVIDER' where round_id = ?", rId)
            },
            TestCase("undecryptable_envelope", "UNDECRYPTABLE_ENVELOPE") { rId: String ->
                fairnessAuthority.publishPreBetCommitment(
                    PublishCommitmentCommand(tenantId, gameId, rId, properties.publicSalt, properties.algorithmVersion, properties.rulesVersion)
                )
                jdbc.update("update game_fairness_commitment set encrypted_secret_seed = 'corrupted-ciphertext' where round_id = ?", rId)
            },
            TestCase("tampered_commitment_hash", "COMMITMENT_HASH_MISMATCH") { rId: String ->
                fairnessAuthority.publishPreBetCommitment(
                    PublishCommitmentCommand(tenantId, gameId, rId, properties.publicSalt, properties.algorithmVersion, properties.rulesVersion)
                )
                jdbc.update("update game_fairness_commitment set commitment_hash = ? where round_id = ?", "f".repeat(64), rId)
            },
        )

        for ((label, expectedReason, setup) in testCases) {
            val roundId = "rnd-reuse-$label"
            insertRound(roundId)
            setup(roundId)

            val initialCommitment = fairnessStore.findCommitment(tenantId, gameId, roundId)
            assertNotNull(initialCommitment, "initial commitment for $label must exist")
            val initialHash = initialCommitment.commitmentHash
            val initialCommitmentCount = jdbc.queryForObject(
                "select count(*) from game_fairness_commitment where tenant_id = ? and round_id = ?",
                Int::class.java,
                tenantId,
                roundId
            ) ?: 0

            val conflict = assertThrows<CommitmentStateConflictException>("Expected CommitmentStateConflictException for $label") {
                lifecyclePort.ensureCommitment(tenantId, gameId, roundId, properties)
            }
            assertEquals("COMMITMENT_STATE_CONFLICT", conflict.errorCode)
            assertEquals(expectedReason, conflict.reason, "expected specific mismatch reason for $label")

            val message = conflict.message ?: ""
            assertTrue(
                !message.contains("corrupted-ciphertext") && !message.contains("f".repeat(64)),
                "exception message must not disclose secret data for $label: $message"
            )

            val currentCommitment = fairnessStore.findCommitment(tenantId, gameId, roundId)
            assertNotNull(currentCommitment)
            assertEquals(initialHash, currentCommitment.commitmentHash, "no new hash or replacement commitment for $label")
            val currentCommitmentCount = jdbc.queryForObject(
                "select count(*) from game_fairness_commitment where tenant_id = ? and round_id = ?",
                Int::class.java,
                tenantId,
                roundId
            ) ?: 0
            assertEquals(initialCommitmentCount, currentCommitmentCount, "commitment count must remain unchanged for $label")

            val round = gameStore.findRound(tenantId, gameId, roundId)
            assertEquals(GameRoundPhase.SCHEDULED, round?.phase, "round must not advance for $label")
            assertEquals(1L, round?.roundVersion, "round version must not advance for $label")

            val auditLogs = fairnessStore.findAuditEvents(tenantId, roundId)
            for (audit in auditLogs) {
                assertTrue(!audit.detail.contains("corrupted-ciphertext"), "audit detail must not log secrets for $label")
            }
        }
    }

    @Test
    fun GivenMatchingCommittedRecord_WhenRetried_ThenOriginalHashReused() {
        val roundId = "rnd-reuse-matching"
        insertRound(roundId)

        val published = fairnessAuthority.publishPreBetCommitment(
            PublishCommitmentCommand(tenantId, gameId, roundId, properties.publicSalt, properties.algorithmVersion, properties.rulesVersion)
        )
        val originalHash = published.commitmentHash
        val originalCommitmentId = published.commitmentId

        for (retry in 1..3) {
            val returnedHash = lifecyclePort.ensureCommitment(tenantId, gameId, roundId, properties)
            assertEquals(originalHash, returnedHash, "retry $retry returned same hash")
        }

        val restartedPort = ProductionAviatorLifecyclePort(
            gameService = gameService,
            fairnessAuthority = fairnessAuthority,
            snapshotService = snapshotService,
            txManager = txManager,
        )
        val hashAfterRestart = restartedPort.ensureCommitment(tenantId, gameId, roundId, properties)
        assertEquals(originalHash, hashAfterRestart, "after port restart returned same hash")

        val storedCommitment = fairnessStore.findCommitment(tenantId, gameId, roundId)
        assertNotNull(storedCommitment)
        assertEquals(originalCommitmentId, storedCommitment.commitmentId)
        assertEquals(1L, storedCommitment.serverVersion, "no version mutation on retry")

        val count = jdbc.queryForObject(
            "select count(*) from game_fairness_commitment where tenant_id = ? and round_id = ?",
            Int::class.java,
            tenantId,
            roundId
        ) ?: 0
        assertEquals(1, count, "row count must be 1")
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
            val roundId = "rnd-tc017-order-$iteration"
            insertRound(roundId)

            trace.clear()
            lifecycleStore.eventLog.clear()

            val ack = commandService.processCommand(placeBetCommand(roundId, "cmd-tc017-$iteration"))
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

        val cashOutRound = "rnd-tc017-golden-cashout"
        insertRound(cashOutRound)
        assertEquals(AviatorCommandAckStatus.ACCEPTED, gameService.processCommand(placeBetCommand(cashOutRound, "cmd-tc017-golden-bet-1")).status)
        gameService.createOrUpdateRound(
            CreateOrUpdateRoundCommand(tenantId, gameId, cashOutRound, GameRoundPhase.FLYING, 2L, multiplier)
        )
        val cashOutAck = gameService.processCommand(
            AviatorRestCommand(
                tenantId = tenantId,
                principal = playerPrincipal,
                commandId = "cmd-tc017-golden-cashout-1",
                roundId = cashOutRound,
                handId = "hand_primary",
                action = "CASH_OUT",
                currency = currency,
                correlationId = "corr-tc017-golden-cashout-1",
            )
        )
        assertEquals(AviatorCommandAckStatus.ACCEPTED, cashOutAck.status)
        assertEquals(expectedWinMinor, cashOutAck.result?.payoutMinor)
        assertEquals(startingBalance - wagerMinor + expectedWinMinor, ledgerStore.findBalance(tenantId, "PLAYER:$playerIdStr", currency))

        val lossRound = "rnd-tc017-golden-loss"
        insertRound(lossRound)
        assertEquals(AviatorCommandAckStatus.ACCEPTED, gameService.processCommand(placeBetCommand(lossRound, "cmd-tc017-golden-bet-2")).status)
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
