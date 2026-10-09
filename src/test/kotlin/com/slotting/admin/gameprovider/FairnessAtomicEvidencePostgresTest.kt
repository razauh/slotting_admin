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
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue
import kotlin.test.assertFalse

@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.NONE)
class FairnessAtomicEvidencePostgresTest {

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
    private lateinit var outcomeFinalizationPort: OutcomeFinalizationPort

    @Autowired
    private lateinit var springAuthority: ProvablyFairOutcomeAuthority

    private val now = Instant.parse("2026-10-08T14:00:00Z")
    private val clock = Clock.fixed(now, ZoneOffset.UTC)
    private val tenantId = "tenant-tc015-atomic"
    private val gameId = "AVIATOR"
    private val currency = "INR"

    private val playerUuid = UUID.randomUUID()
    private val playerIdStr = playerUuid.toString()

    private val adminPrincipal = AuthenticatedPrincipal("admin-sys-tc015", tenantId, PrincipalKind.ADMIN, setOf(AdminRole.SUPER_ADMIN))
    private val playerPrincipal = AuthenticatedPrincipal(playerIdStr, tenantId, PrincipalKind.PLAYER, setOf(AdminRole.SUPPORT))

    private lateinit var gameStore: JdbcDurableGameWagerAndSettlementStore
    private lateinit var ledgerStore: JdbcLedgerJournalStore
    private lateinit var registrationStore: JdbcPlayerRegistrationStore
    private lateinit var eligibilityStore: ServerEligibilityStore
    private lateinit var ledgerService: LedgerPostingService
    private lateinit var fairnessStore: JdbcFairnessEvidenceStore
    private lateinit var gameService: DurableGameWagerAndSettlementService

    class SimulatedFailpoint(message: String) : RuntimeException(message)

    class FailpointFairnessStore(
        val delegate: FairnessEvidenceStore,
    ) : FairnessEvidenceStore by delegate {
        var failAfterSaveAudit = false
        var failAfterSaveReveal = false
        var failAfterCommitment = false
        var failAfterCas = false

        override fun saveCommitment(commitment: RoundCommitmentRecord) {
            delegate.saveCommitment(commitment)
            if (failAfterCommitment) throw SimulatedFailpoint("after commitment write")
        }

        override fun saveReveal(reveal: RoundRevealRecord) {
            delegate.saveReveal(reveal)
            if (failAfterSaveReveal) throw SimulatedFailpoint("after reveal write")
        }

        override fun saveAuditEvent(event: FairnessAuditRecord) {
            delegate.saveAuditEvent(event)
            if (failAfterSaveAudit) throw SimulatedFailpoint("after audit write")
        }

        override fun compareAndSetCommitment(
            commitment: RoundCommitmentRecord,
            expectedServerVersion: Long,
            expectedStatuses: Set<RoundCommitmentStatus>,
        ): Boolean {
            val applied = delegate.compareAndSetCommitment(commitment, expectedServerVersion, expectedStatuses)
            if (applied && failAfterCas) throw SimulatedFailpoint("after commitment CAS")
            return applied
        }
    }

    class BarrierFairnessStore(
        private val delegate: FairnessEvidenceStore,
        private val barrier: java.util.concurrent.CyclicBarrier,
    ) : FairnessEvidenceStore by delegate {
        private val reads = ThreadLocal.withInitial { java.util.concurrent.atomic.AtomicInteger(0) }

        override fun findCommitment(tenantId: String, gameId: String, roundId: String): RoundCommitmentRecord? {
            val record = delegate.findCommitment(tenantId, gameId, roundId)
            if (reads.get().getAndIncrement() == 0) {
                barrier.await(15, java.util.concurrent.TimeUnit.SECONDS)
            }
            return record
        }
    }

    @BeforeEach
    fun setUp() {
        jdbc.update("delete from game_fairness_reveal where tenant_id = ?", tenantId)
        jdbc.update("delete from game_fairness_audit where tenant_id = ?", tenantId)
        jdbc.update("delete from game_fairness_commitment where tenant_id = ?", tenantId)
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
            store = gameStore, ledgerService = ledgerService, registrationStore = registrationStore,
            eligibilityStore = eligibilityStore, adminPrincipal = adminPrincipal, clock = clock, txManager = txManager,
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
                    playerId = playerUuid, selfExcluded = false,
                    singleWagerLimitMinor = 5_000_000L, dailyWagerLimitMinor = 20_000_000L, currentDailyWagerMinor = 0L,
                ),
            )
        )
    }

    private fun authority(store: FairnessEvidenceStore) =
        ProvablyFairOutcomeAuthority(store = store, clock = clock, txManager = txManager)

    private fun authorityWithFinalization(store: FairnessEvidenceStore, finalization: OutcomeFinalizationPort) =
        ProvablyFairOutcomeAuthority(store = store, clock = clock, txManager = txManager, outcomeFinalization = finalization)

    private fun insertRound(roundId: String, phase: String = "SCHEDULED", game: String = gameId) {
        jdbc.update(
            """
            insert into game_authoritative_round (
                tenant_id, game_id, round_id, phase, round_version, current_multiplier, server_time, created_at, updated_at
            ) values (?, ?, ?, ?, 1, 1.0000, ?, ?, ?)
            """.trimIndent(),
            tenantId, game, roundId, phase, Timestamp.from(now), Timestamp.from(now), Timestamp.from(now),
        )
    }

    private fun count(table: String, roundId: String, extra: String = "", vararg args: Any): Int {
        val sql = "select count(*) from $table where tenant_id = ? and round_id = ? $extra"
        return (jdbc.queryForObject(sql, Int::class.java, *arrayOf(tenantId, roundId, *args)) ?: 0)
    }

    @Test
    fun GivenFairnessWriteSucceeds_WhenNextEvidenceWriteFails_ThenWholeFlowRollsBack() {
        val failpoint = FailpointFairnessStore(fairnessStore)
        val failing = authority(failpoint)

        failpoint.failAfterSaveAudit = true
        val commitRound = "rnd-tc015-atomic-commit"
        insertRound(commitRound)
        assertFailsWith<SimulatedFailpoint> {
            failing.publishPreBetCommitment(PublishCommitmentCommand(tenantId, gameId, commitRound, "salt-commit"))
        }
        assertEquals(0, count("game_fairness_commitment", commitRound), "commitment must roll back with audit")
        assertEquals(0, count("game_fairness_audit", commitRound), "audit must roll back with commitment")

        failpoint.failAfterSaveAudit = false
        val revealRound = "rnd-tc015-atomic-reveal"
        insertRound(revealRound)
        val published = failing.publishPreBetCommitment(PublishCommitmentCommand(tenantId, gameId, revealRound, "salt-reveal"))
        assertEquals(1, count("game_fairness_commitment", revealRound))

        failpoint.failAfterSaveReveal = true
        assertFailsWith<SimulatedFailpoint> {
            failing.revealAndVerifyOutcome(RevealOutcomeCommand(tenantId, gameId, revealRound))
        }
        assertEquals(0, count("game_fairness_reveal", revealRound), "reveal row must roll back atomically")
        assertEquals(0, count("game_fairness_audit", revealRound, "and event_key = ?", ProvablyFairOutcomeAuthority.REVEAL_EVENT_KEY), "verified audit must roll back atomically")
        assertEquals(RoundCommitmentStatus.COMMITTED, fairnessStore.findCommitment(tenantId, gameId, revealRound)?.status, "status must not regress")
        assertEquals(published.commitmentHash, fairnessStore.findCommitment(tenantId, gameId, revealRound)?.commitmentHash)
    }

    @Test
    fun GivenSameCommitmentVersion_WhenTwoFirstBetsRace_ThenOneWinsAndOneConflicts() {
        val pool = Executors.newFixedThreadPool(2)
        var conflicts = 0
        repeat(1000) { iteration ->
            val roundId = "rnd-tc015-cas-$iteration"
            insertRound(roundId)
            authority(fairnessStore).publishPreBetCommitment(PublishCommitmentCommand(tenantId, gameId, roundId, "salt-$roundId"))
            assertEquals(1L, fairnessStore.findCommitment(tenantId, gameId, roundId)!!.serverVersion)

            val barrier = java.util.concurrent.CyclicBarrier(2)
            val raceAuth = authority(BarrierFairnessStore(fairnessStore, barrier))
            val successes = AtomicInteger(0)
            val conflictCount = AtomicInteger(0)
            val done = CountDownLatch(2)

            repeat(2) {
                pool.submit {
                    try {
                        raceAuth.notifyBetAccepted(tenantId, gameId, roundId, "race-player-$it", null)
                        successes.incrementAndGet()
                    } catch (e: FairnessAuthorityException) {
                        if (e.errorCode == "COMMIT_VERSION_CONFLICT") conflictCount.incrementAndGet() else throw e
                    } finally {
                        done.countDown()
                    }
                }
            }
            assertTrue(done.await(20, TimeUnit.SECONDS), "iteration $iteration")

            assertEquals(1, successes.get(), "iteration $iteration one first-bet wins")
            assertEquals(1, conflictCount.get(), "iteration $iteration one typed conflict")
            conflicts += conflictCount.get()
            val after = fairnessStore.findCommitment(tenantId, gameId, roundId)!!
            assertEquals(RoundCommitmentStatus.BETTING_ACTIVE, after.status, "iteration $iteration")
            assertEquals(2L, after.serverVersion, "iteration $iteration no version regression")
            val firstTimestamp = after.firstBetAcceptedAt

            authority(fairnessStore).notifyBetAccepted(tenantId, gameId, roundId, "second-bet-player", "seed-two")
            val afterSecond = fairnessStore.findCommitment(tenantId, gameId, roundId)!!
            assertEquals(RoundCommitmentStatus.BETTING_ACTIVE, afterSecond.status, "iteration $iteration second bet idempotent")
            assertEquals(firstTimestamp, afterSecond.firstBetAcceptedAt, "iteration $iteration first timestamp unchanged")
        }
        pool.shutdown()
        assertEquals(1000, conflicts)
    }

    @Test
    fun GivenLegacyRevealedPartial_WhenRevealRetried_ThenMissingEvidenceRepairsOnce() {
        val fairAuth = authority(fairnessStore)
        val roundId = "rnd-tc015-repair"
        insertRound(roundId)
        val commitment = fairAuth.publishPreBetCommitment(PublishCommitmentCommand(tenantId, gameId, roundId, "salt-repair"))
        val seed = fairAuth.openCommittedSecret(tenantId, gameId, roundId)

        val firstReveal = fairAuth.revealAndVerifyOutcome(RevealOutcomeCommand(tenantId, gameId, roundId))
        assertEquals(FairnessVerificationStatus.VERIFIED, firstReveal.verificationStatus)

        jdbc.update("delete from game_fairness_reveal where tenant_id = ? and round_id = ?", tenantId, roundId)
        jdbc.update("delete from game_fairness_audit where tenant_id = ? and round_id = ? and event_key = ?", tenantId, roundId, ProvablyFairOutcomeAuthority.REVEAL_EVENT_KEY)
        assertEquals(0, count("game_fairness_reveal", roundId), "no premature secret before repair")

        fairAuth.revealAndVerifyOutcome(RevealOutcomeCommand(tenantId, gameId, roundId))
        val secondReveal = fairAuth.revealAndVerifyOutcome(RevealOutcomeCommand(tenantId, gameId, roundId))

        assertEquals(1, count("game_fairness_reveal", roundId), "exactly one reveal after idempotent repair")
        assertEquals(1, count("game_fairness_audit", roundId, "and event_key = ?", ProvablyFairOutcomeAuthority.REVEAL_EVENT_KEY), "exactly one verified audit after idempotent repair")
        assertEquals(commitment.commitmentHash, ProvablyFairOutcomeAuthority.sha256(secondReveal.revealedSecretSeed))
        assertEquals(RoundCommitmentStatus.REVEALED, fairnessStore.findCommitment(tenantId, gameId, roundId)?.status)
        assertEquals(seed, secondReveal.revealedSecretSeed)
    }

    @Test
    fun GivenPartialOrDuplicateEvidence_WhenPrecheckRuns_ThenReportsIdentityWithoutDeleting() {
        val fairAuth = authority(fairnessStore)
        val partial = "rnd-tc015-partial"
        insertRound(partial)
        fairAuth.publishPreBetCommitment(PublishCommitmentCommand(tenantId, gameId, partial, "salt-partial"))
        jdbc.update("update game_fairness_commitment set status = 'REVEALED' where tenant_id = ? and round_id = ?", tenantId, partial)

        val diagnostic = FairnessEvidenceRepairDiagnostic(jdbc)
        val partials = diagnostic.conflicts(tenantId).filter { it.kind == FairnessEvidenceConflictKind.PARTIAL_REVEAL }
        assertTrue(partials.any { it.roundId == partial }, "pre-check must report the partial reveal")
        assertEquals(partial, partials.first { it.roundId == partial }.roundId)

        diagnostic.assertReconcilable(tenantId)
        assertEquals(1, count("game_fairness_commitment", partial), "read-only diagnostic must not delete rows")
    }

    @Test
    fun GivenFirstBetCas_WhenLaterCommandStepFails_ThenWholePlaceBetRollsBack() {
        val startingBalance = 50_000L
        seedFunds(startingBalance)
        val roundId = "rnd-tc015-firstbet-failpoint"
        createRound(roundId)
        val failpoint = FailpointFairnessStore(fairnessStore)
        val fairAuth = authority(failpoint)
        fairAuth.publishPreBetCommitment(PublishCommitmentCommand(tenantId, gameId, roundId, "salt-firstbet"))

        val service = DurableGameWagerAndSettlementService(
            store = gameStore, ledgerService = ledgerService, registrationStore = registrationStore,
            eligibilityStore = eligibilityStore, adminPrincipal = adminPrincipal, clock = clock,
            fairnessAuthority = fairAuth, txManager = txManager,
        )
        failpoint.failAfterCas = true
        val txTemplate = TransactionTemplate(txManager)
        assertFailsWith<SimulatedFailpoint> {
            txTemplate.execute<Unit> { service.processCommand(placeBetCommand(roundId, "cmd-tc015-firstbet")) }
        }

        assertNull(gameStore.findBet(tenantId, gameId, roundId, playerIdStr, "hand_primary"), "no bet may persist")
        assertNull(gameStore.findReceipt(tenantId, "cmd-tc015-firstbet"), "no receipt may persist")
        assertEquals(startingBalance, ledgerStore.findBalance(tenantId, "PLAYER:$playerIdStr", currency), "no ledger movement may persist")
        val commitment = fairnessStore.findCommitment(tenantId, gameId, roundId)!!
        assertEquals(RoundCommitmentStatus.COMMITTED, commitment.status, "first-bet status must roll back")
        assertEquals(1L, commitment.serverVersion)
        assertNull(commitment.firstBetAcceptedAt)
        assertEquals(0, count("game_fairness_audit", roundId, "and event_key = ?", ProvablyFairOutcomeAuthority.REVEAL_EVENT_KEY))
    }

    @Test
    fun GivenRevealExistsButVerifiedAuditMissing_WhenRetried_ThenOneAuditRestored() {
        val fairAuth = authority(fairnessStore)
        val roundId = "rnd-tc015-audit-only"
        insertRound(roundId)
        val commitment = fairAuth.publishPreBetCommitment(PublishCommitmentCommand(tenantId, gameId, roundId, "salt-audit"))
        val reveal = fairAuth.revealAndVerifyOutcome(RevealOutcomeCommand(tenantId, gameId, roundId))

        jdbc.update("delete from game_fairness_audit where tenant_id = ? and round_id = ? and event_key = ?", tenantId, roundId, ProvablyFairOutcomeAuthority.REVEAL_EVENT_KEY)
        val repaired = fairAuth.revealAndVerifyOutcome(RevealOutcomeCommand(tenantId, gameId, roundId))

        assertEquals(reveal.revealId, repaired.revealId, "reveal must not change")
        assertEquals(1, count("game_fairness_reveal", roundId))
        assertEquals(1, count("game_fairness_audit", roundId, "and event_key = ?", ProvablyFairOutcomeAuthority.REVEAL_EVENT_KEY))
        val after = fairnessStore.findCommitment(tenantId, gameId, roundId)!!
        assertEquals(RoundCommitmentStatus.REVEALED, after.status)
        assertEquals(commitment.commitmentHash, ProvablyFairOutcomeAuthority.sha256(repaired.revealedSecretSeed))
    }

    @Test
    fun GivenConcurrentRevealRepair_WhenBothRetry_ThenSingleRevealAndAudit() {
        val fairAuth = authority(fairnessStore)
        val roundId = "rnd-tc015-concurrent-repair"
        insertRound(roundId)
        fairAuth.publishPreBetCommitment(PublishCommitmentCommand(tenantId, gameId, roundId, "salt-concurrent"))
        fairAuth.revealAndVerifyOutcome(RevealOutcomeCommand(tenantId, gameId, roundId))
        jdbc.update("delete from game_fairness_reveal where tenant_id = ? and round_id = ?", tenantId, roundId)
        jdbc.update("delete from game_fairness_audit where tenant_id = ? and round_id = ? and event_key = ?", tenantId, roundId, ProvablyFairOutcomeAuthority.REVEAL_EVENT_KEY)

        val pool = Executors.newFixedThreadPool(2)
        val done = CountDownLatch(2)
        repeat(2) {
            pool.submit {
                try {
                    fairAuth.revealAndVerifyOutcome(RevealOutcomeCommand(tenantId, gameId, roundId))
                } finally {
                    done.countDown()
                }
            }
        }
        assertTrue(done.await(20, TimeUnit.SECONDS))
        pool.shutdown()

        assertEquals(1, count("game_fairness_reveal", roundId), "exactly one reveal under concurrent repair")
        assertEquals(1, count("game_fairness_audit", roundId, "and event_key = ?", ProvablyFairOutcomeAuthority.REVEAL_EVENT_KEY), "exactly one verified audit under concurrent repair")
        assertEquals(RoundCommitmentStatus.REVEALED, fairnessStore.findCommitment(tenantId, gameId, roundId)?.status)
    }

    @Test
    fun GivenPrematureReveal_WhenOutcomeNotFinalized_ThenRejectedWithoutPersistence() {
        val finalization = JdbcOutcomeFinalizationPort(jdbc)
        val gated = authorityWithFinalization(fairnessStore, finalization)
        val roundId = "rnd-tc015-premature"
        insertRound(roundId, phase = "SCHEDULED")
        gated.publishPreBetCommitment(PublishCommitmentCommand(tenantId, gameId, roundId, "salt-premature"))

        val failure = assertFailsWith<FairnessAuthorityException> {
            gated.revealAndVerifyOutcome(RevealOutcomeCommand(tenantId, gameId, roundId))
        }
        assertEquals("OUTCOME_NOT_FINALIZED", failure.errorCode)
        assertEquals(0, count("game_fairness_reveal", roundId), "premature reveal must write no reveal row")
        assertEquals(0, count("game_fairness_audit", roundId, "and event_key = ?", ProvablyFairOutcomeAuthority.REVEAL_EVENT_KEY), "premature reveal must write no verified audit")
        assertEquals(RoundCommitmentStatus.COMMITTED, fairnessStore.findCommitment(tenantId, gameId, roundId)?.status)

        jdbc.update("update game_authoritative_round set phase = 'CRASHED', crash_multiplier = 1.1000 where tenant_id = ? and game_id = ? and round_id = ?", tenantId, gameId, roundId)
        val reveal = gated.revealAndVerifyOutcome(RevealOutcomeCommand(tenantId, gameId, roundId))
        assertEquals(FairnessVerificationStatus.VERIFIED, reveal.verificationStatus)
        assertEquals(1, count("game_fairness_reveal", roundId))
    }

    @Test
    fun GivenLegacyRevealedStatus_WhenRepairRuns_ThenAllowedWithoutFinalization() {
        val permissive = authority(fairnessStore)
        val roundId = "rnd-tc015-legacy-finalization"
        insertRound(roundId, phase = "SCHEDULED")
        permissive.publishPreBetCommitment(PublishCommitmentCommand(tenantId, gameId, roundId, "salt-legacy"))
        permissive.revealAndVerifyOutcome(RevealOutcomeCommand(tenantId, gameId, roundId))
        jdbc.update("delete from game_fairness_reveal where tenant_id = ? and round_id = ?", tenantId, roundId)
        jdbc.update("delete from game_fairness_audit where tenant_id = ? and round_id = ? and event_key = ?", tenantId, roundId, ProvablyFairOutcomeAuthority.REVEAL_EVENT_KEY)

        val gated = authorityWithFinalization(fairnessStore, JdbcOutcomeFinalizationPort(jdbc))
        val repaired = gated.revealAndVerifyOutcome(RevealOutcomeCommand(tenantId, gameId, roundId))
        assertEquals(FairnessVerificationStatus.VERIFIED, repaired.verificationStatus, "legacy REVEALED repair must not be blocked by the finalization gate")
        assertEquals(1, count("game_fairness_reveal", roundId))
    }

    @Test
    fun GivenTwoGamesShareRoundId_WhenRevealRecorded_ThenIdentityIsolated() {
        val roundId = "rnd-tc015-shared"
        val otherGame = "AVIATOR-B"
        insertRound(roundId, game = gameId)
        insertRound(roundId, game = otherGame)
        val fairAuth = authority(fairnessStore)
        val c1 = fairAuth.publishPreBetCommitment(PublishCommitmentCommand(tenantId, gameId, roundId, "salt-a"))
        val c2 = fairAuth.publishPreBetCommitment(PublishCommitmentCommand(tenantId, otherGame, roundId, "salt-b"))
        fairAuth.revealAndVerifyOutcome(RevealOutcomeCommand(tenantId, gameId, roundId))
        fairAuth.revealAndVerifyOutcome(RevealOutcomeCommand(tenantId, otherGame, roundId))

        assertEquals(1, countGame("game_fairness_reveal", roundId, gameId), "game A reveal isolated")
        assertEquals(1, countGame("game_fairness_reveal", roundId, otherGame), "game B reveal isolated")
        assertTrue(fairnessStore.existsAuditEvent(tenantId, c1.commitmentId, ProvablyFairOutcomeAuthority.REVEAL_EVENT_KEY))
        assertTrue(fairnessStore.existsAuditEvent(tenantId, c2.commitmentId, ProvablyFairOutcomeAuthority.REVEAL_EVENT_KEY))
    }

    @Test
    fun GivenDuplicateLegacyEvidence_WhenPrecheckRuns_ThenReportsIdentitiesAndCanonicalIndexEnforced() {
        val fairAuth = authority(fairnessStore)
        val roundId = "rnd-tc015-legacy-dup"
        insertRound(roundId)
        val commitment = fairAuth.publishPreBetCommitment(PublishCommitmentCommand(tenantId, gameId, roundId, "salt-legacy-dup"))
        repeat(2) {
            jdbc.update(
                """
                insert into game_fairness_audit (audit_id, tenant_id, round_id, action, actor, detail, occurred_at)
                values (?, ?, ?, ?, 'TEST', 'legacy verified audit', ?)
                """.trimIndent(),
                UUID.randomUUID(), tenantId, roundId, ProvablyFairOutcomeAuthority.REVEAL_EVENT_KEY, Timestamp.from(now),
            )
        }

        val diagnostic = FairnessEvidenceRepairDiagnostic(jdbc)
        val legacy = diagnostic.conflicts(tenantId).filter { it.kind == FairnessEvidenceConflictKind.DUPLICATE_LEGACY_AUDIT }
        assertTrue(legacy.any { it.roundId == roundId }, "pre-check must report duplicate legacy reveal audits")
        val failure = assertFailsWith<FairnessEvidenceReconcileException> { diagnostic.assertReconcilable(tenantId) }
        assertTrue(failure.conflicts.any { it.kind == FairnessEvidenceConflictKind.DUPLICATE_LEGACY_AUDIT && it.roundId == roundId })
        assertEquals(2, count("game_fairness_audit", roundId, "and action = ?", ProvablyFairOutcomeAuthority.REVEAL_EVENT_KEY), "diagnostic must not delete duplicate evidence")

        assertFailsWith<org.springframework.dao.DataIntegrityViolationException> {
            repeat(2) {
                jdbc.update(
                    """
                    insert into game_fairness_audit (audit_id, tenant_id, round_id, action, actor, detail, occurred_at, game_id, commitment_id, event_key)
                    values (?, ?, ?, ?, 'TEST', 'canonical', ?, ?, ?, ?)
                    """.trimIndent(),
                    UUID.randomUUID(), tenantId, roundId, ProvablyFairOutcomeAuthority.REVEAL_EVENT_KEY, Timestamp.from(now),
                    gameId, commitment.commitmentId, ProvablyFairOutcomeAuthority.REVEAL_EVENT_KEY,
                )
            }
        }
    }

    @Test
    fun GivenProductionProperty_WhenSpringContextLoads_ThenFinalizationGateIsInstalledAndPrematureRevealRejected() {
        assertTrue(outcomeFinalizationPort is JdbcOutcomeFinalizationPort, "spring context must install the JDBC finalization gate")
        val roundId = "rnd-tc015-gate-wired"
        insertRound(roundId, phase = "SCHEDULED")
        springAuthority.publishPreBetCommitment(PublishCommitmentCommand(tenantId, gameId, roundId, "salt-gate"))

        val failure = assertFailsWith<FairnessAuthorityException> {
            springAuthority.revealAndVerifyOutcome(RevealOutcomeCommand(tenantId, gameId, roundId))
        }
        assertEquals("OUTCOME_NOT_FINALIZED", failure.errorCode)
        assertEquals(0, count("game_fairness_reveal", roundId), "gated reveal must write nothing")
        assertEquals(0, count("game_fairness_audit", roundId, "and event_key = ?", ProvablyFairOutcomeAuthority.REVEAL_EVENT_KEY))
        assertEquals(RoundCommitmentStatus.COMMITTED, fairnessStore.findCommitment(tenantId, gameId, roundId)?.status)
    }

    @Test
    fun GivenSafeLegacyRevealAudit_WhenBackfillExecutes_ThenCanonicalIdentitySeenAndNoSemanticDuplicate() {
        val diagnostic = FairnessEvidenceRepairDiagnostic(jdbc)
        val backfill = FairnessAuditIdentityBackfill(jdbc, diagnostic)
        val roundId = "rnd-tc015-backfill"
        insertRound(roundId)
        val fairAuth = authority(fairnessStore)
        val commitment = fairAuth.publishPreBetCommitment(PublishCommitmentCommand(tenantId, gameId, roundId, "salt-backfill"))
        fairAuth.revealAndVerifyOutcome(RevealOutcomeCommand(tenantId, gameId, roundId))

        jdbc.update(
            "update game_fairness_audit set game_id = null, commitment_id = null, event_key = null where tenant_id = ? and round_id = ? and action = ?",
            tenantId, roundId, ProvablyFairOutcomeAuthority.REVEAL_EVENT_KEY,
        )
        assertFalse(fairnessStore.existsAuditEvent(tenantId, commitment.commitmentId, ProvablyFairOutcomeAuthority.REVEAL_EVENT_KEY), "legacy row must be invisible to canonical lookup")

        val plan = backfill.plan(tenantId)
        assertTrue(plan.blocked.isEmpty(), "unambiguous legacy audit must not be blocked: ${plan.blocked}")
        assertTrue(plan.eligible.any { it.roundId == roundId }, "unambiguous legacy audit must be eligible")

        val result = backfill.execute(tenantId)
        assertEquals(1, result.updatedRows)
        assertEquals(result.beforeCanonical + 1, result.afterCanonical, "canonical count must grow by exactly the backfilled row")
        assertTrue(fairnessStore.existsAuditEvent(tenantId, commitment.commitmentId, ProvablyFairOutcomeAuthority.REVEAL_EVENT_KEY), "canonical lookup must see the backfilled row")

        val repaired = fairAuth.revealAndVerifyOutcome(RevealOutcomeCommand(tenantId, gameId, roundId))
        assertEquals(FairnessVerificationStatus.VERIFIED, repaired.verificationStatus)
        assertEquals(1, count("game_fairness_audit", roundId, "and action = ?", ProvablyFairOutcomeAuthority.REVEAL_EVENT_KEY), "repair must not add a semantic duplicate after backfill")
        assertEquals(1, count("game_fairness_reveal", roundId))
    }

    @Test
    fun GivenOrphanLegacyRevealAudit_WhenPrecheckRuns_ThenReportsIdentityAndBackfillRefuses() {
        val orphanRound = "rnd-tc015-orphan-audit"
        insertRound(orphanRound)
        jdbc.update(
            """
            insert into game_fairness_audit (audit_id, tenant_id, round_id, action, actor, detail, occurred_at)
            values (?, ?, ?, ?, 'TEST', 'legacy verified audit with no commitment', ?)
            """.trimIndent(),
            UUID.randomUUID(), tenantId, orphanRound, ProvablyFairOutcomeAuthority.REVEAL_EVENT_KEY, Timestamp.from(now),
        )

        val diagnostic = FairnessEvidenceRepairDiagnostic(jdbc)
        val orphans = diagnostic.conflicts(tenantId).filter { it.kind == FairnessEvidenceConflictKind.AMBIGUOUS_AUDIT_MAPPING }
        assertTrue(orphans.any { it.roundId == orphanRound && it.detail.contains("no commitment") }, "pre-check must report zero-match orphan rows: $orphans")

        val blocked = assertFailsWith<FairnessEvidenceReconcileException> { diagnostic.assertReconcilable(tenantId) }
        assertTrue(blocked.conflicts.any { it.roundId == orphanRound }, "assertReconcilable must block the orphan identity")

        val backfill = FairnessAuditIdentityBackfill(jdbc, diagnostic)
        assertFailsWith<FairnessEvidenceReconcileException> { backfill.execute(tenantId) }
        assertEquals(1, count("game_fairness_audit", orphanRound, "and action = ?", ProvablyFairOutcomeAuthority.REVEAL_EVENT_KEY), "backfill must never delete orphan evidence")
    }

    @Test
    fun GivenLegacyAndCanonicalAudit_WhenBackfillRuns_ThenRefusedWithoutDeletion() {
        val dupRound = "rnd-tc015-semantic-dup"
        insertRound(dupRound)
        val fairAuth = authority(fairnessStore)
        val commitment = fairAuth.publishPreBetCommitment(PublishCommitmentCommand(tenantId, gameId, dupRound, "salt-dup"))
        fairAuth.revealAndVerifyOutcome(RevealOutcomeCommand(tenantId, gameId, dupRound))
        jdbc.update(
            """
            insert into game_fairness_audit (audit_id, tenant_id, round_id, action, actor, detail, occurred_at)
            values (?, ?, ?, ?, 'TEST', 'legacy duplicate of canonical reveal audit', ?)
            """.trimIndent(),
            UUID.randomUUID(), tenantId, dupRound, ProvablyFairOutcomeAuthority.REVEAL_EVENT_KEY, Timestamp.from(now),
        )

        val diagnostic = FairnessEvidenceRepairDiagnostic(jdbc)
        val duplicates = diagnostic.conflicts(tenantId).filter { it.kind == FairnessEvidenceConflictKind.DUPLICATE_LEGACY_AUDIT && it.roundId == dupRound }
        assertTrue(duplicates.isNotEmpty(), "pre-check must report legacy/canonical duplicate")
        assertEquals(commitment.commitmentId, duplicates.first().commitmentId, "conflict must carry the commitment identity")

        assertFailsWith<FairnessEvidenceReconcileException> { diagnostic.assertReconcilable(tenantId) }

        val backfill = FairnessAuditIdentityBackfill(jdbc, diagnostic)
        assertFailsWith<FairnessEvidenceReconcileException> { backfill.execute(tenantId) }
        assertEquals(2, count("game_fairness_audit", dupRound, "and action = ?", ProvablyFairOutcomeAuthority.REVEAL_EVENT_KEY), "neither evidence row may be deleted")
    }

    private fun countGame(table: String, roundId: String, game: String): Int =
        jdbc.queryForObject(
            "select count(*) from $table where tenant_id = ? and round_id = ? and game_id = ?",
            Int::class.java, tenantId, roundId, game,
        ) ?: 0

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
                transactionReference = "TX-TC015-SEED-${UUID.randomUUID()}", currencyCode = currency,
                entries = listOf(
                    JournalEntryDraft("HOUSE:SEED", JournalEntryDirection.DEBIT, amount, currency),
                    JournalEntryDraft("PLAYER:$playerIdStr", JournalEntryDirection.CREDIT, amount, currency),
                ),
                idempotencyKey = "IDEM-TC015-SEED-${UUID.randomUUID()}", correlationId = "corr-tc015-seed", causationId = "caus-tc015-seed",
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
            val roundId = "rnd-tc015-order-$iteration"
            createRound(roundId)
            trace.clear()
            lifecycleStore.eventLog.clear()

            val ack = commandService.processCommand(placeBetCommand(roundId, "cmd-tc015-$iteration"))
            assertEquals(AviatorCommandAckStatus.ACCEPTED, ack.status, "iteration $iteration")
            assertTrue(trace.any { it.first == "RECEIPT" }, "iteration $iteration claim first")
            assertTrue(trace.any { it.first == "ROUND_SHARED" }, "iteration $iteration command shared round")
            assertTrue(trace.any { it.first == "BET" }, "iteration $iteration bet locked")
            assertTrue(trace.any { it.first == "PLAYER_ACCOUNT" }, "iteration $iteration player account locked")
            assertTrue(trace.any { it.first == "SEQUENCE_COUNTER" }, "iteration $iteration sequence counter locked")
            assertMonotonic(trace)

            val crash = lifecycleService.settleRoundCrash(SettleRoundCrashCommand(tenantId, gameId, roundId, BigDecimal("1.1000")))
            assertEquals(1, crash.settledBetsCount, "iteration $iteration")
            assertTrue(lifecycleStore.eventLog.any { it.first == "ROUND_EXCLUSIVE" }, "iteration $iteration lifecycle exclusive round")
            assertTrue(lifecycleStore.eventLog.any { it.first == "BETS" }, "iteration $iteration lifecycle locks bets")
            assertMonotonic(lifecycleStore.eventLog)

            assertEquals(GameBetStatus.LOST, gameStore.findBet(tenantId, gameId, roundId, playerIdStr, "hand_primary")?.status, "iteration $iteration terminal")
        }
        assertJournalBalanced()
        assertEquals(0L, ledgerStore.findBalance(tenantId, "ESCROW:GAME:$gameId", currency))
    }

    @Test
    fun GivenBetThenRoundInversion_WhenControlRuns_ThenDeadlockDetectedAndRolledBack() {
        val roundId = "rnd-tc015-inversion"
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
                        "insert into game_fairness_audit (audit_id, tenant_id, round_id, action, actor, detail, occurred_at) values (?, ?, ?, 'TC015_FORWARD', 'TEST', 'forward', ?)",
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
                        "insert into game_fairness_audit (audit_id, tenant_id, round_id, action, actor, detail, occurred_at) values (?, ?, ?, 'TC015_INVERSION', 'TEST', 'inversion', ?)",
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
        val forwardMarkers = jdbc.queryForObject("select count(*) from game_fairness_audit where tenant_id = ? and action = 'TC015_FORWARD'", Int::class.java, tenantId) ?: 0
        val inversionMarkers = jdbc.queryForObject("select count(*) from game_fairness_audit where tenant_id = ? and action = 'TC015_INVERSION'", Int::class.java, tenantId) ?: 0
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

        val cashOutRound = "rnd-tc015-golden-cashout"
        createRound(cashOutRound)
        assertEquals(AviatorCommandAckStatus.ACCEPTED, gameService.processCommand(placeBetCommand(cashOutRound, "cmd-tc015-golden-bet-1")).status)
        gameService.createOrUpdateRound(CreateOrUpdateRoundCommand(tenantId, gameId, cashOutRound, GameRoundPhase.FLYING, 2L, multiplier))
        val cashOutAck = gameService.processCommand(
            AviatorRestCommand(
                tenantId = tenantId, principal = playerPrincipal, commandId = "cmd-tc015-golden-cashout-1",
                roundId = cashOutRound, handId = "hand_primary", action = "CASH_OUT", currency = currency, correlationId = "corr-tc015-golden-cashout-1",
            )
        )
        assertEquals(AviatorCommandAckStatus.ACCEPTED, cashOutAck.status)
        assertEquals(expectedWinMinor, cashOutAck.result?.payoutMinor)
        assertEquals(startingBalance - wagerMinor + expectedWinMinor, ledgerStore.findBalance(tenantId, "PLAYER:$playerIdStr", currency))

        val lossRound = "rnd-tc015-golden-loss"
        createRound(lossRound)
        assertEquals(AviatorCommandAckStatus.ACCEPTED, gameService.processCommand(placeBetCommand(lossRound, "cmd-tc015-golden-bet-2")).status)
        val crashResult = gameService.settleRoundCrash(SettleRoundCrashCommand(tenantId, gameId, lossRound, BigDecimal("1.0000")))
        assertEquals(1, crashResult.settledBetsCount)
        assertEquals(0L, jdbc.queryForObject("select payout_minor_units from game_bet_settlement where tenant_id = ? and outcome = 'LOSS_CRASH'", Long::class.java, tenantId))
        assertJournalBalanced()
        assertEquals(2, jdbc.queryForObject("select count(*) from game_bet_settlement where tenant_id = ?", Int::class.java, tenantId) ?: 0)
        assertEquals(0L, ledgerStore.findBalance(tenantId, "ESCROW:GAME:$gameId", currency))
    }
}
