package com.slotting.admin.gameprovider

import com.slotting.admin.auth.AdminRole
import com.slotting.admin.auth.AuthenticatedPrincipal
import com.slotting.admin.auth.PrincipalKind
import com.slotting.admin.config.EnvironmentMasterKeyProvider
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
import com.slotting.admin.secret.AesGcmEnvelopeEncryptor
import com.slotting.admin.secret.DecryptionTamperException
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
import java.math.RoundingMode
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
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicInteger
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertNotEquals
import kotlin.test.assertTrue

@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.NONE)
class FairnessSecretMigrationTest {

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

    private val now = Instant.parse("2026-10-08T12:00:00Z")
    private val clock = Clock.fixed(now, ZoneOffset.UTC)
    private val tenantId = "tenant-tc014-migration"
    private val gameId = "AVIATOR"
    private val currency = "INR"

    private val keyV1 = ByteArray(32) { (it + 1).toByte() }
    private val keyV2 = ByteArray(32) { (it + 91).toByte() }
    private val keyV9 = ByteArray(32) { (it + 200).toByte() }
    private val playerUuid = UUID.randomUUID()
    private val playerIdStr = playerUuid.toString()

    private val adminPrincipal = AuthenticatedPrincipal("admin-sys-tc014", tenantId, PrincipalKind.ADMIN, setOf(AdminRole.SUPER_ADMIN))
    private val playerPrincipal = AuthenticatedPrincipal(playerIdStr, tenantId, PrincipalKind.PLAYER, setOf(AdminRole.SUPPORT))

    private lateinit var gameStore: JdbcDurableGameWagerAndSettlementStore
    private lateinit var ledgerStore: JdbcLedgerJournalStore
    private lateinit var registrationStore: JdbcPlayerRegistrationStore
    private lateinit var eligibilityStore: ServerEligibilityStore
    private lateinit var ledgerService: LedgerPostingService
    private lateinit var fairnessStore: JdbcFairnessEvidenceStore
    private lateinit var gameService: DurableGameWagerAndSettlementService

    private fun envelope(keyId: String, version: Int, ring: Map<Int, ByteArray>): FairnessSeedEnvelope =
        FairnessSeedEnvelope(
            encryptor = AesGcmEnvelopeEncryptor(EnvironmentMasterKeyProvider(ring), environment = "TEST"),
            keyId = keyId,
            keyVersion = version,
        )

    private fun activeEnvelope(): FairnessSeedEnvelope = envelope("tc014-key", 2, mapOf(1 to keyV1, 2 to keyV2))

    private fun authority(envelope: FairnessSeedEnvelope): ProvablyFairOutcomeAuthority =
        ProvablyFairOutcomeAuthority(store = fairnessStore, clock = clock, envelope = envelope)

    private fun job(envelope: FairnessSeedEnvelope, beforeReplace: (RoundCommitmentRecord) -> Unit = {}): FairnessSecretMigrationJob =
        FairnessSecretMigrationJob(jdbc, fairnessStore, envelope, clock, beforeReplace)

    @BeforeEach
    fun setUp() {
        jdbc.update("delete from game_fairness_reveal where tenant_id = ?", tenantId)
        jdbc.update("delete from game_fairness_audit where tenant_id = ?", tenantId)
        jdbc.update("delete from game_fairness_commitment where tenant_id = ?", tenantId)
        jdbc.update("delete from fairness_secret_migration_run where tenant_id = ?", tenantId)
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
        fairnessStore = JdbcFairnessEvidenceStore(jdbc)
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
            playerUuid, tenantId, playerIdStr, "pbkdf2_sha256_hash", "pbkdf2_sha256", "salt", 10000, "ACTIVE", 1L,
            Timestamp.from(now.minusSeconds(86400)), Timestamp.from(now.minusSeconds(86400)),
        )
        eligibilityStore.saveComplianceProfile(
            PlayerComplianceProfile(
                playerId = playerUuid, tenantId = tenantId, dateOfBirth = LocalDate.of(1995, 5, 5),
                kycStatus = KycComplianceStatus.VERIFIED, amlStatus = AmlComplianceStatus.CLEARED,
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
        jdbc.update(
            """
            insert into game_authoritative_round (
                tenant_id, game_id, round_id, phase, round_version, current_multiplier, server_time, created_at, updated_at
            ) values (?, ?, ?, ?, 1, 1.0000, ?, ?, ?)
            """.trimIndent(),
            tenantId, gameId, roundId, phase, Timestamp.from(now), Timestamp.from(now), Timestamp.from(now),
        )
    }

    private fun insertLegacyCommitment(roundId: String, status: RoundCommitmentStatus = RoundCommitmentStatus.COMMITTED): String {
        insertRound(roundId, if (status == RoundCommitmentStatus.REVEALED) "CLOSED" else "SCHEDULED")
        val canonical = (java.util.UUID.randomUUID().toString().replace("-", "") + java.util.UUID.randomUUID().toString().replace("-", "")).take(64)
        val hash = ProvablyFairOutcomeAuthority.sha256(canonical)
        jdbc.update(
            """
            insert into game_fairness_commitment (
                commitment_id, tenant_id, game_id, round_id, authority_type, algorithm_version,
                rules_version, commitment_hash, public_salt, encrypted_secret_seed, committed_at,
                status, server_version, created_at, updated_at
            ) values (?, ?, ?, ?, 'INTERNAL_HMAC_SHA256', '1.0.0', '1.0.0', ?, ?, ?, ?, ?, 1, ?, ?)
            """.trimIndent(),
            UUID.randomUUID(), tenantId, gameId, roundId, hash, "salt-$roundId", canonical,
            Timestamp.from(now), status.name, Timestamp.from(now), Timestamp.from(now),
        )
        return canonical
    }

    private fun migratedSeed(roundId: String, env: FairnessSeedEnvelope): String = authority(env).openCommittedSecret(tenantId, gameId, roundId)

    private fun commitmentRow(roundId: String) =
        fairnessStore.findCommitment(tenantId, gameId, roundId)!!

    @Test
    fun GivenLegacyRows_WhenMigrationInterrupted_ThenRetryEncryptsEachExactlyOnce() {
        val unrevealed = (1..3).map { "rnd-tc014-unrev-$it" }
        val revealed = listOf("rnd-tc014-rev-A", "rnd-tc014-rev-B")
        val seeds = mutableMapOf<String, String>()
        unrevealed.forEach { seeds[it] = insertLegacyCommitment(it, RoundCommitmentStatus.BETTING_ACTIVE) }
        revealed.forEach { seeds[it] = insertLegacyCommitment(it, RoundCommitmentStatus.REVEALED) }
        val totalRows = jdbc.queryForObject("select count(*) from game_fairness_commitment where tenant_id = ?", Int::class.java, tenantId)!!

        val observedOrder = mutableListOf<String>()
        val attempts = AtomicInteger(0)
        val interrupting = job(activeEnvelope()) { record ->
            observedOrder.add(record.roundId)
            if (attempts.incrementAndGet() >= 3) throw RuntimeException("injected interruption after row 2 verification")
        }

        assertFailsWith<RuntimeException> { interrupting.migrate(tenantId) }

        val failedRunStatus = jdbc.queryForObject(
            "select status from fairness_secret_migration_run where tenant_id = ? order by started_at desc limit 1",
            String::class.java, tenantId,
        )
        assertEquals("FAILED", failedRunStatus)
        assertEquals(totalRows, jdbc.queryForObject("select count(*) from game_fairness_commitment where tenant_id = ?", Int::class.java, tenantId)!!, "no rows deleted during interruption")

        val resumeOrder = mutableListOf<String>()
        val resumed = job(activeEnvelope()) { record -> resumeOrder.add(record.roundId) }.migrate(tenantId)
        assertTrue(resumed.completed, "resumed migration must complete; failures=${resumed.failures}")
        assertEquals(0, resumed.remainingCount)

        seeds.forEach { (roundId, seed) ->
            assertEquals(seed, migratedSeed(roundId, activeEnvelope()), "each row must decrypt to its original seed")
            assertEquals(ProvablyFairOutcomeAuthority.sha256(seed), commitmentRow(roundId).commitmentHash)
            assertTrue(commitmentRow(roundId).secretNonce != null, "no unverified plaintext may remain")
        }

        val secondRun = job(activeEnvelope()).migrate(tenantId)
        assertEquals(0, secondRun.processedCount, "second full run must change 0 rows")
        assertEquals(0, secondRun.encryptedCount)
        assertEquals(0, secondRun.remainingCount)
        assertTrue(secondRun.completed)

        val revealedReplacedAfter = resumeOrder.indexOfFirst { it.startsWith("rnd-tc014-rev") }
        val lastUnrevealedBefore = resumeOrder.indexOfLast { it.startsWith("rnd-tc014-unrev") }
        assertTrue(revealedReplacedAfter != -1, "resume must observe a revealed-row replacement; order=$resumeOrder")
        assertTrue(lastUnrevealedBefore != -1 && lastUnrevealedBefore < revealedReplacedAfter, "unrevealed rows must be replaced before any revealed row; order=$resumeOrder")
    }

    @Test
    fun GivenOldKey_WhenRotatedDuringReveal_ThenVersionConflictCannotCorruptSecret() {
        val oldEnvelope = envelope("rot-key", 1, mapOf(1 to keyV1))
        val newEnvelope = envelope("rot-key", 2, mapOf(1 to keyV1, 2 to keyV2))

        repeat(100) { iteration ->
            val roundId = "rnd-tc014-rot-$iteration"
            insertRound(roundId)
            val authorityOld = authority(oldEnvelope)
            val commitment = authorityOld.publishPreBetCommitment(
                PublishCommitmentCommand(tenantId, gameId, roundId, "salt-$roundId")
            )
            assertEquals(1, commitment.secretKeyVersion)
            val originalSeed = authorityOld.openCommittedSecret(tenantId, gameId, roundId)

            val rotationService = authority(newEnvelope)
            assertFalse(job(newEnvelope).canRetireKey(tenantId, 1), "old key must not retire while referenced")

            val start = CountDownLatch(1)
            val pool = Executors.newFixedThreadPool(2)
            val rotate = pool.submit(Callable {
                start.await()
                job(newEnvelope).migrate(tenantId)
            })
            val reveal = pool.submit(Callable {
                start.await()
                rotationService.revealAndVerifyOutcome(RevealOutcomeCommand(tenantId, gameId, roundId))
            })
            start.countDown()
            val migrationResult = rotate.get(20, TimeUnit.SECONDS)
            val revealRecord = reveal.get(20, TimeUnit.SECONDS)
            pool.shutdown()
            assertTrue(migrationResult.completed, "iteration $iteration rotation must complete: ${migrationResult.failures}")

            val rotated = commitmentRow(roundId)
            assertEquals(2, rotated.secretKeyVersion, "iteration $iteration envelope rotated to active version")
            assertEquals(RoundCommitmentStatus.REVEALED, rotated.status, "iteration $iteration reveal committed")
            assertEquals(originalSeed, migratedSeed(roundId, newEnvelope), "iteration $iteration reveal secret unchanged after rotation")
            assertEquals(commitment.commitmentHash, ProvablyFairOutcomeAuthority.sha256(revealRecord.revealedSecretSeed))
            assertEquals(commitment.commitmentHash, ProvablyFairOutcomeAuthority.sha256(migratedSeed(roundId, newEnvelope)))
            assertEquals(0, job(newEnvelope).remainingKeyReferences(tenantId, 1), "iteration $iteration no old-key references remain")
            assertTrue(job(newEnvelope).canRetireKey(tenantId, 1), "iteration $iteration old key now retirable")
            jdbc.update("delete from game_fairness_reveal where tenant_id = ? and round_id = ?", tenantId, roundId)
            jdbc.update("delete from game_fairness_commitment where tenant_id = ? and round_id = ?", tenantId, roundId)
        }
    }

    @Test
    fun GivenWrongKeyOrCorruptRow_WhenBackfillRuns_ThenDiagnosticAndResume() {
        val goodA = "rnd-tc014-good-a"
        val goodB = "rnd-tc014-good-b"
        val orphan = "rnd-tc014-orphan"
        insertLegacyCommitment(goodA)
        insertLegacyCommitment(goodB)

        val orphanEnvelope = envelope("tc014-key", 9, mapOf(9 to keyV9))
        insertRound(orphan)
        val orphanAuthority = authority(orphanEnvelope)
        orphanAuthority.publishPreBetCommitment(PublishCommitmentCommand(tenantId, gameId, orphan, "salt-orphan"))
        val orphanSeed = orphanAuthority.openCommittedSecret(tenantId, gameId, orphan)
        val orphanBeforeCiphertext = commitmentRow(orphan).encryptedSecretSeed

        val firstRun = job(activeEnvelope()).migrate(tenantId)
        assertFalse(firstRun.completed, "wrong-key row must prevent a false complete report")
        assertTrue(firstRun.remainingCount >= 1)
        val orphanFailure = firstRun.failures.first { it.roundId == orphan }
        assertEquals(commitmentRow(orphan).commitmentId, orphanFailure.commitmentId)
        assertTrue(orphanFailure.reason.contains("key", ignoreCase = true), "diagnostic must name the key problem: ${orphanFailure.reason}")
        assertFalse(orphanFailure.reason.contains(orphanSeed), "diagnostic must not leak the seed")
        assertEquals(orphanBeforeCiphertext, commitmentRow(orphan).encryptedSecretSeed, "corrupt/wrong-key row must be preserved")
        assertNotEquals(orphanSeed, commitmentRow(orphan).encryptedSecretSeed)

        val corrected = envelope("tc014-key", 2, mapOf(1 to keyV1, 2 to keyV2, 9 to keyV9))
        val resumeRun = job(corrected).migrate(tenantId)
        assertTrue(resumeRun.completed, "resume with corrected provider must complete; failures=${resumeRun.failures}")
        assertEquals(0, resumeRun.remainingCount)
        assertEquals(orphanSeed, migratedSeed(orphan, corrected))
        assertEquals(2, commitmentRow(orphan).secretKeyVersion)
    }

    @Test
    fun GivenIncompleteEnvelopeMetadata_WhenBackfillRuns_ThenRowFailureReportedWithoutAbort() {
        val roundId = "rnd-tc014-partial"
        insertRound(roundId)
        val seed = "a".repeat(64)
        val hash = ProvablyFairOutcomeAuthority.sha256(seed)
        jdbc.update(
            """
            insert into game_fairness_commitment (
                commitment_id, tenant_id, game_id, round_id, authority_type, algorithm_version,
                rules_version, commitment_hash, public_salt, encrypted_secret_seed, committed_at,
                status, server_version, created_at, updated_at, secret_nonce
            ) values (?, ?, ?, ?, 'INTERNAL_HMAC_SHA256', '1.0.0', '1.0.0', ?, ?, ?, ?, 'COMMITTED', 1, ?, ?, 'AAAA')
            """.trimIndent(),
            UUID.randomUUID(), tenantId, gameId, roundId, hash, "salt-$roundId", "not-base64-envelope",
            Timestamp.from(now), Timestamp.from(now), Timestamp.from(now),
        )
        val beforeCiphertext = commitmentRow(roundId).encryptedSecretSeed

        val result = job(activeEnvelope()).migrate(tenantId)
        assertFalse(result.completed, "incomplete metadata must not report a false completion")
        val failure = result.failures.first { it.roundId == roundId }
        assertTrue(failure.reason.contains("incomplete", ignoreCase = true), "must classify incomplete metadata: ${failure.reason}")
        assertFalse(failure.reason.contains(seed), "diagnostic must not leak the seed")
        assertEquals(beforeCiphertext, commitmentRow(roundId).encryptedSecretSeed, "row must be preserved")
        val runStatus = jdbc.queryForObject(
            "select status from fairness_secret_migration_run where tenant_id = ? order by started_at desc limit 1",
            String::class.java, tenantId,
        )
        assertEquals("FAILED", runStatus)
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
            val seq = delegate.nextSequenceId(tenantId)
            eventLog.add("SEQUENCE_COUNTER" to 5)
            return seq
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

    private fun isDeadlock(t: Throwable?): Boolean {
        var current = t
        while (current != null) {
            if (current is DeadlockLoserDataAccessException) return true
            if (current is SQLException && current.sqlState == "40P01") return true
            current = current.cause
        }
        return false
    }

    private fun seedFunds(amount: Long) {
        ledgerService.postTransaction(
            PostTransactionCommand(
                principal = adminPrincipal, tenantId = tenantId,
                transactionReference = "TX-TC014-SEED-${UUID.randomUUID()}", currencyCode = currency,
                entries = listOf(
                    JournalEntryDraft("HOUSE:SEED", JournalEntryDirection.DEBIT, amount, currency),
                    JournalEntryDraft("PLAYER:$playerIdStr", JournalEntryDirection.CREDIT, amount, currency),
                ),
                idempotencyKey = "IDEM-TC014-SEED-${UUID.randomUUID()}", correlationId = "corr-tc014-seed", causationId = "caus-tc014-seed",
            )
        )
    }

    private fun createRound(roundId: String) {
        gameService.createOrUpdateRound(
            CreateOrUpdateRoundCommand(tenantId, gameId, roundId, GameRoundPhase.BET_COUNTDOWN, 1L, BigDecimal("1.0000"))
        )
    }

    private fun placeBetCommand(roundId: String, commandId: String) = AviatorRestCommand(
        tenantId = tenantId, principal = playerPrincipal, commandId = commandId, roundId = roundId,
        handId = "hand_primary", action = "PLACE_BET", wagerMinor = 101L, currency = currency, correlationId = "corr-$commandId",
    )

    private fun assertJournalBalanced() {
        val debits = jdbc.queryForObject("select coalesce(sum(total_debits_minor_units), 0) from ledger_transaction where tenant_id = ?", Long::class.java, tenantId) ?: 0L
        val credits = jdbc.queryForObject("select coalesce(sum(total_credits_minor_units), 0) from ledger_transaction where tenant_id = ?", Long::class.java, tenantId) ?: 0L
        assertEquals(debits, credits, "Double-entry journal must stay balanced")
    }

    @Test
    fun GivenMixedOperations_WhenLocksAreObserved_ThenGlobalOrderIsPreserved() {
        seedFunds(5_000_000L)
        val trace = mutableListOf<Pair<String, Int>>()
        val commandStore = LockRankTracingStore(gameStore, trace)
        val accountStore = LedgerRankTracingStore(ledgerStore, trace)
        val commandLedgerService = LedgerPostingService(store = accountStore, clock = clock)
        val commandService = DurableGameWagerAndSettlementService(
            store = commandStore, ledgerService = commandLedgerService, registrationStore = registrationStore,
            eligibilityStore = eligibilityStore, adminPrincipal = adminPrincipal, clock = clock, txManager = txManager,
        )
        val lifecycleStore = LockRankTracingStore(gameStore)
        val lifecycleService = DurableGameWagerAndSettlementService(
            store = lifecycleStore, ledgerService = ledgerService, registrationStore = registrationStore,
            eligibilityStore = eligibilityStore, adminPrincipal = adminPrincipal, clock = clock, txManager = txManager,
        )

        for (iteration in 0 until 100) {
            val roundId = "rnd-tc014-order-$iteration"
            createRound(roundId)
            trace.clear()
            lifecycleStore.eventLog.clear()

            val ack = commandService.processCommand(placeBetCommand(roundId, "cmd-tc014-$iteration"))
            assertEquals(AviatorCommandAckStatus.ACCEPTED, ack.status, "iteration $iteration")
            assertTrue(trace.any { it.first == "RECEIPT" }, "iteration $iteration claim must be first")
            assertTrue(trace.any { it.first == "ROUND_SHARED" }, "iteration $iteration command holds round shared")
            assertTrue(trace.any { it.first == "BET" }, "iteration $iteration bet locked")
            assertTrue(trace.any { it.first == "PLAYER_ACCOUNT" }, "iteration $iteration player account locked")
            assertTrue(trace.any { it.first == "SEQUENCE_COUNTER" }, "iteration $iteration sequence counter locked")
            assertMonotonic(trace)

            val crash = lifecycleService.settleRoundCrash(SettleRoundCrashCommand(tenantId, gameId, roundId, BigDecimal("1.1000")))
            assertEquals(1, crash.settledBetsCount, "iteration $iteration")
            assertTrue(lifecycleStore.eventLog.any { it.first == "ROUND_EXCLUSIVE" }, "iteration $iteration lifecycle holds round exclusive")
            assertTrue(lifecycleStore.eventLog.any { it.first == "BETS" }, "iteration $iteration lifecycle locks bets")
            assertMonotonic(lifecycleStore.eventLog)

            assertEquals(GameBetStatus.LOST, gameStore.findBet(tenantId, gameId, roundId, playerIdStr, "hand_primary")?.status, "iteration $iteration terminal")
        }
        assertJournalBalanced()
        assertEquals(0L, ledgerStore.findBalance(tenantId, "ESCROW:GAME:$gameId", currency))
    }

    @Test
    fun GivenBetThenRoundInversion_WhenControlRuns_ThenDeadlockDetectedAndRolledBack() {
        val roundId = "rnd-tc014-inversion"
        val betId = UUID.randomUUID()
        insertRound(roundId, phase = "FLYING")
        jdbc.update(
            """
            insert into game_accepted_bet (
                bet_id, tenant_id, owner_id, game_id, round_id, hand_id, wager_minor_units,
                currency_code, reservation_id, ledger_reservation_ref, status, created_at, updated_at
            ) values (?, ?, ?, ?, ?, 'hand_primary', 101, 'INR', ?, 'lref', 'ACCEPTED', ?, ?)
            """.trimIndent(),
            betId, tenantId, playerIdStr, gameId, roundId, UUID.randomUUID(), Timestamp.from(now), Timestamp.from(now),
        )
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
                        "insert into game_fairness_audit (audit_id, tenant_id, round_id, action, actor, detail, occurred_at) values (?, ?, ?, 'TC014_FORWARD', 'TEST', 'forward', ?)",
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
                        "insert into game_fairness_audit (audit_id, tenant_id, round_id, action, actor, detail, occurred_at) values (?, ?, ?, 'TC014_INVERSION', 'TEST', 'inversion', ?)",
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
        assertTrue(forwardAborted != inversionAborted, "exactly one worker must abort: $outcomes")
        val aborted = outcomes.first { it.second != null }
        assertTrue(isDeadlock(aborted.second), "aborted worker must be a PostgreSQL deadlock (40P01): ${aborted.second}")
        val forwardMarkers = jdbc.queryForObject("select count(*) from game_fairness_audit where tenant_id = ? and action = 'TC014_FORWARD'", Int::class.java, tenantId) ?: 0
        val inversionMarkers = jdbc.queryForObject("select count(*) from game_fairness_audit where tenant_id = ? and action = 'TC014_INVERSION'", Int::class.java, tenantId) ?: 0
        assertEquals(if (forwardAborted) 0 else 1, forwardMarkers)
        assertEquals(if (inversionAborted) 0 else 1, inversionMarkers)
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

        val cashOutRound = "rnd-tc014-golden-cashout"
        createRound(cashOutRound)
        assertEquals(AviatorCommandAckStatus.ACCEPTED, gameService.processCommand(placeBetCommand(cashOutRound, "cmd-tc014-golden-bet-1")).status)
        gameService.createOrUpdateRound(CreateOrUpdateRoundCommand(tenantId, gameId, cashOutRound, GameRoundPhase.FLYING, 2L, multiplier))
        val cashOutAck = gameService.processCommand(
            AviatorRestCommand(
                tenantId = tenantId, principal = playerPrincipal, commandId = "cmd-tc014-golden-cashout-1",
                roundId = cashOutRound, handId = "hand_primary", action = "CASH_OUT", currency = currency, correlationId = "corr-tc014-golden-cashout-1",
            )
        )
        assertEquals(AviatorCommandAckStatus.ACCEPTED, cashOutAck.status)
        assertEquals(expectedWinMinor, cashOutAck.result?.payoutMinor)
        assertEquals(startingBalance - wagerMinor + expectedWinMinor, ledgerStore.findBalance(tenantId, "PLAYER:$playerIdStr", currency))

        val lossRound = "rnd-tc014-golden-loss"
        createRound(lossRound)
        assertEquals(AviatorCommandAckStatus.ACCEPTED, gameService.processCommand(placeBetCommand(lossRound, "cmd-tc014-golden-bet-2")).status)
        val crashResult = gameService.settleRoundCrash(SettleRoundCrashCommand(tenantId, gameId, lossRound, BigDecimal("1.0000")))
        assertEquals(1, crashResult.settledBetsCount)
        assertEquals(0L, jdbc.queryForObject("select payout_minor_units from game_bet_settlement where tenant_id = ? and outcome = 'LOSS_CRASH'", Long::class.java, tenantId))
        assertJournalBalanced()
        assertEquals(2, jdbc.queryForObject("select count(*) from game_bet_settlement where tenant_id = ?", Int::class.java, tenantId) ?: 0)
        assertEquals(0L, ledgerStore.findBalance(tenantId, "ESCROW:GAME:$gameId", currency))
    }
}
