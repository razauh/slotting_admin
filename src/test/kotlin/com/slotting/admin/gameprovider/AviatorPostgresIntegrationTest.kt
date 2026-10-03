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
import org.springframework.dao.DataIntegrityViolationException
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
import kotlin.test.assertEquals
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue

@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.NONE)
class AviatorPostgresIntegrationTest {

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
    private val tenantId = "tenant-ci-pg"
    private val gameId = "AVIATOR"
    private val playerUuid = UUID.fromString("22222222-2222-2222-2222-222222222222")
    private val playerIdStr = playerUuid.toString()
    private val currency = "INR"

    private val adminPrincipal = AuthenticatedPrincipal(
        id = "admin-ci-01",
        tenantId = tenantId,
        kind = PrincipalKind.ADMIN,
        roles = setOf(AdminRole.SUPER_ADMIN)
    )

    private val playerPrincipal = AuthenticatedPrincipal(
        id = playerIdStr,
        tenantId = tenantId,
        kind = PrincipalKind.PLAYER,
        roles = setOf(AdminRole.SUPPORT)
    )

    private lateinit var gameStore: JdbcDurableGameWagerAndSettlementStore
    private lateinit var fairnessStore: JdbcFairnessEvidenceStore
    private lateinit var ledgerStore: JdbcLedgerJournalStore
    private lateinit var registrationStore: JdbcPlayerRegistrationStore
    private lateinit var eligibilityStore: ServerEligibilityStore
    private lateinit var ledgerService: LedgerPostingService
    private lateinit var service: DurableGameWagerAndSettlementService

    enum class FailpointLocation {
        NONE,
        BEFORE_CALL,
        AFTER_CALL
    }

    class SimulatedFailpointException(message: String) : RuntimeException(message)

    class FailpointDecoratedGameWagerStore(
        private val delegate: DurableGameWagerAndSettlementStore
    ) : DurableGameWagerAndSettlementStore by delegate {
        var failpointAction: String? = null
        var failpointLocation: FailpointLocation = FailpointLocation.NONE

        override fun saveBet(bet: GameAcceptedBetRecord) {
            if (failpointAction == "saveBet" && failpointLocation == FailpointLocation.BEFORE_CALL) {
                throw SimulatedFailpointException("Triggered BEFORE_CALL failpoint on saveBet")
            }
            delegate.saveBet(bet)
            if (failpointAction == "saveBet" && failpointLocation == FailpointLocation.AFTER_CALL) {
                throw SimulatedFailpointException("Triggered AFTER_CALL failpoint on saveBet")
            }
        }

        override fun updateBet(bet: GameAcceptedBetRecord) {
            if (failpointAction == "updateBet" && failpointLocation == FailpointLocation.BEFORE_CALL) {
                throw SimulatedFailpointException("Triggered BEFORE_CALL failpoint on updateBet")
            }
            delegate.updateBet(bet)
            if (failpointAction == "updateBet" && failpointLocation == FailpointLocation.AFTER_CALL) {
                throw SimulatedFailpointException("Triggered AFTER_CALL failpoint on updateBet")
            }
        }
    }

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
        jdbc.update("delete from admin_outbox_event where tenant_id = ?", tenantId)
        jdbc.update("delete from admin_audit_event where tenant_id = ?", tenantId)
        jdbc.update("delete from admin_operation where tenant_id = ?", tenantId)

        gameStore = JdbcDurableGameWagerAndSettlementStore(jdbc)
        fairnessStore = JdbcFairnessEvidenceStore(jdbc)
        ledgerStore = JdbcLedgerJournalStore(jdbc)
        registrationStore = JdbcPlayerRegistrationStore(jdbc)
        eligibilityStore = com.slotting.admin.identity.InMemoryServerEligibilityStore()
        ledgerService = LedgerPostingService(store = ledgerStore, clock = clock)

        service = DurableGameWagerAndSettlementService(
            store = gameStore,
            ledgerService = ledgerService,
            registrationStore = registrationStore,
            eligibilityStore = eligibilityStore,
            adminPrincipal = adminPrincipal,
            clock = clock
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
            "pg-email-hash-1",
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

    @Test
    fun `database schema contains all operational aviator and ledger tables`() {
        val tables = listOf(
            "game_authoritative_round",
            "game_accepted_bet",
            "game_bet_settlement",
            "game_command_receipt",
            "game_fairness_commitment",
            "game_fairness_reveal",
            "game_fairness_audit",
            "ledger_transaction",
            "ledger_leg",
            "ledger_idempotency_receipt",
            "ledger_version_tracker"
        )
        for (table in tables) {
            val count = jdbc.queryForObject(
                "select count(*) from information_schema.tables where table_name = ?",
                Int::class.java,
                table
            )
            assertEquals(1, count, "Table $table must exist in PostgreSQL")
        }
    }

    @Test
    fun `commitment foreign key constraint rejects commitments for non existent rounds in postgres`() {
        val nonExistentRoundId = "ROUND-DOES-NOT-EXIST-${UUID.randomUUID()}"
        val commitmentId = UUID.randomUUID()

        assertThrows<DataIntegrityViolationException> {
            jdbc.update(
                """
                insert into game_fairness_commitment (
                    commitment_id, tenant_id, game_id, round_id, authority_type,
                    algorithm_version, rules_version, commitment_hash, public_salt,
                    encrypted_secret_seed, status
                ) values (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """.trimIndent(),
                commitmentId,
                tenantId,
                gameId,
                nonExistentRoundId,
                "INTERNAL_HMAC_SHA256",
                "1.0.0",
                "1.0.0",
                "a".repeat(64),
                "salt-001",
                "encrypted-seed-data",
                "COMMITTED"
            )
        }

        val validRoundId = "ROUND-FK-VALID-${UUID.randomUUID()}"
        service.createOrUpdateRound(
            CreateOrUpdateRoundCommand(
                tenantId = tenantId,
                gameId = gameId,
                roundId = validRoundId,
                phase = GameRoundPhase.SCHEDULED,
                roundVersion = 1L,
                currentMultiplier = BigDecimal.ONE
            )
        )

        val inserted = jdbc.update(
            """
            insert into game_fairness_commitment (
                commitment_id, tenant_id, game_id, round_id, authority_type,
                algorithm_version, rules_version, commitment_hash, public_salt,
                encrypted_secret_seed, status
            ) values (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """.trimIndent(),
            commitmentId,
            tenantId,
            gameId,
            validRoundId,
            "INTERNAL_HMAC_SHA256",
            "1.0.0",
            "1.0.0",
            "b".repeat(64),
            "salt-002",
            "encrypted-seed-data",
            "COMMITTED"
        )
        assertEquals(1, inserted)

        val rowCount = jdbc.queryForObject(
            "select count(*) from game_fairness_commitment where commitment_id = ?",
            Int::class.java,
            commitmentId
        )
        assertEquals(1, rowCount)
    }

    @Test
    fun `transaction boundary with configurable failpoint decorator rolls back ledger and bet atomically`() {
        val txTemplate = TransactionTemplate(txManager)
        val initialRef = "TX-PG-FAILPOINT-INIT-${UUID.randomUUID()}"
        ledgerService.postTransaction(
            PostTransactionCommand(
                principal = adminPrincipal,
                tenantId = tenantId,
                transactionReference = initialRef,
                currencyCode = currency,
                entries = listOf(
                    JournalEntryDraft("HOUSE:SEED", JournalEntryDirection.DEBIT, 100000L, currency),
                    JournalEntryDraft("PLAYER:$playerIdStr", JournalEntryDirection.CREDIT, 100000L, currency)
                ),
                idempotencyKey = "IDEM-$initialRef",
                correlationId = "corr-$initialRef",
                causationId = "caus-$initialRef"
            )
        )
        val balanceBefore = ledgerStore.findBalance(tenantId, "PLAYER:$playerIdStr", currency)
        assertEquals(100000L, balanceBefore)

        val roundId = "RND-PG-FP-${UUID.randomUUID()}"
        service.createOrUpdateRound(
            CreateOrUpdateRoundCommand(
                tenantId = tenantId,
                gameId = gameId,
                roundId = roundId,
                phase = GameRoundPhase.BET_COUNTDOWN,
                roundVersion = 1L,
                currentMultiplier = BigDecimal.ONE,
                crashMultiplier = BigDecimal("2.00")
            )
        )

        val decoratedStore = FailpointDecoratedGameWagerStore(gameStore)
        val failpointService = DurableGameWagerAndSettlementService(
            store = decoratedStore,
            ledgerService = ledgerService,
            registrationStore = registrationStore,
            eligibilityStore = eligibilityStore,
            adminPrincipal = adminPrincipal,
            clock = clock
        )

        decoratedStore.failpointAction = "saveBet"
        decoratedStore.failpointLocation = FailpointLocation.BEFORE_CALL
        assertThrows<SimulatedFailpointException> {
            txTemplate.execute {
                failpointService.processCommand(
                    AviatorRestCommand(
                        tenantId = tenantId,
                        principal = playerPrincipal,
                        commandId = "cmd-fp-before",
                        roundId = roundId,
                        handId = "hand_primary",
                        action = "PLACE_BET",
                        wagerMinor = 10000L,
                        currency = currency,
                        correlationId = "corr-fp-before"
                    )
                )
            }
        }
        val betBefore = gameStore.findBet(tenantId, gameId, roundId, playerIdStr, "hand_primary")
        assertNull(betBefore)
        assertEquals(100000L, ledgerStore.findBalance(tenantId, "PLAYER:$playerIdStr", currency))

        decoratedStore.failpointAction = "saveBet"
        decoratedStore.failpointLocation = FailpointLocation.AFTER_CALL
        assertThrows<SimulatedFailpointException> {
            txTemplate.execute {
                failpointService.processCommand(
                    AviatorRestCommand(
                        tenantId = tenantId,
                        principal = playerPrincipal,
                        commandId = "cmd-fp-after",
                        roundId = roundId,
                        handId = "hand_primary",
                        action = "PLACE_BET",
                        wagerMinor = 10000L,
                        currency = currency,
                        correlationId = "corr-fp-after"
                    )
                )
            }
        }

        val betAfter = gameStore.findBet(tenantId, gameId, roundId, playerIdStr, "hand_primary")
        assertNull(betAfter, "Transaction rollback must remove inserted bet record")

        val txCount = jdbc.queryForObject(
            "select count(*) from ledger_transaction where idempotency_key = ?",
            Int::class.java,
            "cmd-fp-after"
        )
        assertEquals(0, txCount, "Transaction rollback must remove inserted ledger transaction")

        val balanceAfterRollback = ledgerStore.findBalance(tenantId, "PLAYER:$playerIdStr", currency)
        assertEquals(100000L, balanceAfterRollback, "Transaction rollback must preserve exact initial ledger balance")

        decoratedStore.failpointLocation = FailpointLocation.NONE
        val cleanAck = txTemplate.execute {
            failpointService.processCommand(
                AviatorRestCommand(
                    tenantId = tenantId,
                    principal = playerPrincipal,
                    commandId = "cmd-fp-committed",
                    roundId = roundId,
                    handId = "hand_primary",
                    action = "PLACE_BET",
                    wagerMinor = 10000L,
                    currency = currency,
                    correlationId = "corr-fp-committed"
                )
            )
        }
        assertNotNull(cleanAck)
        assertEquals(AviatorCommandAckStatus.ACCEPTED, cleanAck.status)

        val committedBet = gameStore.findBet(tenantId, gameId, roundId, playerIdStr, "hand_primary")
        assertNotNull(committedBet)
        assertEquals(GameBetStatus.ACCEPTED, committedBet.status)
        assertEquals(90000L, ledgerStore.findBalance(tenantId, "PLAYER:$playerIdStr", currency))
    }

    @Test
    fun `round trips through fairness jdbc adapter verify commitment and reveal lifecycle`() {
        val roundId = "RND-FAIRNESS-RT-${UUID.randomUUID()}"
        service.createOrUpdateRound(
            CreateOrUpdateRoundCommand(
                tenantId = tenantId,
                gameId = gameId,
                roundId = roundId,
                phase = GameRoundPhase.SCHEDULED,
                roundVersion = 1L,
                currentMultiplier = BigDecimal.ONE
            )
        )

        val commitmentId = UUID.randomUUID()
        val commitment = RoundCommitmentRecord(
            commitmentId = commitmentId,
            tenantId = tenantId,
            gameId = gameId,
            roundId = roundId,
            authorityType = FairnessAuthorityType.INTERNAL_HMAC_SHA256,
            algorithmVersion = "1.0.0",
            rulesVersion = "1.0.0",
            commitmentHash = "c".repeat(64),
            publicSalt = "salt-rt-001",
            encryptedSecretSeed = "enc-seed-001",
            committedAt = now,
            status = RoundCommitmentStatus.COMMITTED,
            serverVersion = 1L,
            createdAt = now,
            updatedAt = now
        )
        fairnessStore.saveCommitment(commitment)

        val fetchedCommitment = fairnessStore.findCommitment(tenantId, gameId, roundId)
        assertNotNull(fetchedCommitment)
        assertEquals(commitmentId, fetchedCommitment.commitmentId)
        assertEquals("c".repeat(64), fetchedCommitment.commitmentHash)
        assertEquals(RoundCommitmentStatus.COMMITTED, fetchedCommitment.status)

        fetchedCommitment.status = RoundCommitmentStatus.LOCKED
        fetchedCommitment.clientSeed1 = "seed1"
        fetchedCommitment.clientSeed2 = "seed2"
        fetchedCommitment.clientSeed3 = "seed3"
        fetchedCommitment.updatedAt = now.plusSeconds(30)
        fairnessStore.updateCommitment(fetchedCommitment)

        val updatedCommitment = fairnessStore.findCommitment(tenantId, gameId, roundId)
        assertNotNull(updatedCommitment)
        assertEquals(RoundCommitmentStatus.LOCKED, updatedCommitment.status)
        assertEquals(2L, updatedCommitment.serverVersion)
        assertEquals("seed1", updatedCommitment.clientSeed1)

        val revealId = UUID.randomUUID()
        val reveal = RoundRevealRecord(
            revealId = revealId,
            commitmentId = commitmentId,
            tenantId = tenantId,
            gameId = gameId,
            roundId = roundId,
            revealedSecretSeed = "d".repeat(64),
            derivedMultiplier = BigDecimal("2.7500"),
            revealedAt = now.plusSeconds(60),
            verificationStatus = FairnessVerificationStatus.VERIFIED,
            verificationError = null,
            evidenceReference = "evidence-rt-001"
        )
        fairnessStore.saveReveal(reveal)

        val fetchedReveal = fairnessStore.findReveal(tenantId, gameId, roundId)
        assertNotNull(fetchedReveal)
        assertEquals(revealId, fetchedReveal.revealId)
        assertEquals("d".repeat(64), fetchedReveal.revealedSecretSeed)
        assertEquals(BigDecimal("2.7500"), fetchedReveal.derivedMultiplier)
        assertEquals(FairnessVerificationStatus.VERIFIED, fetchedReveal.verificationStatus)

        val audit = FairnessAuditRecord(
            auditId = UUID.randomUUID(),
            tenantId = tenantId,
            roundId = roundId,
            action = "AUDIT_REVEAL_VERIFIED",
            actor = "sys-fairness",
            detail = "Verification passed with zero deviation",
            occurredAt = now.plusSeconds(65)
        )
        fairnessStore.saveAuditEvent(audit)

        val auditEvents = fairnessStore.findAuditEvents(tenantId, roundId)
        assertEquals(1, auditEvents.size)
        assertEquals("AUDIT_REVEAL_VERIFIED", auditEvents.first().action)
    }

    @Test
    fun `round trips through round lifecycle jdbc adapter verify round progression and state persistence`() {
        val testTenant = "tenant-lifecycle-${UUID.randomUUID()}"
        val roundId = "RND-LIFECYCLE-RT-${UUID.randomUUID()}"
        val initialRound = GameRoundRecord(
            tenantId = testTenant,
            gameId = gameId,
            roundId = roundId,
            phase = GameRoundPhase.BET_COUNTDOWN,
            roundVersion = 1L,
            currentMultiplier = BigDecimal.ONE,
            crashMultiplier = BigDecimal("3.00"),
            startedAt = now,
            serverTime = now,
            createdAt = now,
            updatedAt = now
        )
        gameStore.saveRound(initialRound)

        val round1 = gameStore.findRound(testTenant, gameId, roundId)
        assertNotNull(round1)
        assertEquals(GameRoundPhase.BET_COUNTDOWN, round1.phase)

        val latest = gameStore.findLatestRound(testTenant, gameId)
        assertNotNull(latest)
        assertEquals(roundId, latest.roundId)

        round1.phase = GameRoundPhase.FLYING
        round1.roundVersion = 2L
        round1.currentMultiplier = BigDecimal("2.10")
        round1.updatedAt = now.plusSeconds(10)
        gameStore.saveRound(round1)

        val round2 = gameStore.findRound(testTenant, gameId, roundId)
        assertNotNull(round2)
        assertEquals(GameRoundPhase.FLYING, round2.phase)
        assertEquals(BigDecimal("2.1000"), round2.currentMultiplier)

        round2.phase = GameRoundPhase.CRASHED
        round2.roundVersion = 3L
        round2.crashedAt = now.plusSeconds(20)
        round2.closedAt = now.plusSeconds(25)
        round2.updatedAt = now.plusSeconds(25)
        gameStore.saveRound(round2)

        val round3 = gameStore.findRound(testTenant, gameId, roundId)
        assertNotNull(round3)
        assertEquals(GameRoundPhase.CRASHED, round3.phase)
        assertNotNull(round3.crashedAt)

        val finished = gameStore.findFinishedRounds(testTenant, gameId, 10)
        assertTrue(finished.any { it.roundId == roundId })
    }

    @Test
    fun `end to end aviator wager placement cashout and round settlement against real postgres`() {
        val seedRef = "TX-PG-SEED-${UUID.randomUUID()}"
        ledgerService.postTransaction(
            PostTransactionCommand(
                principal = adminPrincipal,
                tenantId = tenantId,
                transactionReference = seedRef,
                currencyCode = currency,
                entries = listOf(
                    JournalEntryDraft("HOUSE:SEED", JournalEntryDirection.DEBIT, 100000L, currency),
                    JournalEntryDraft("PLAYER:$playerIdStr", JournalEntryDirection.CREDIT, 100000L, currency)
                ),
                idempotencyKey = "IDEM-$seedRef",
                correlationId = "corr-$seedRef",
                causationId = "caus-$seedRef"
            )
        )
        val initialBalance = ledgerStore.findBalance(tenantId, "PLAYER:$playerIdStr", currency)
        assertEquals(100000L, initialBalance)

        val roundId = "RND-PG-${UUID.randomUUID()}"
        service.createOrUpdateRound(
            CreateOrUpdateRoundCommand(
                tenantId = tenantId,
                gameId = gameId,
                roundId = roundId,
                phase = GameRoundPhase.BET_COUNTDOWN,
                roundVersion = 1L,
                currentMultiplier = BigDecimal.ONE,
                crashMultiplier = BigDecimal("2.50")
            )
        )

        val roundFromDb = gameStore.findRound(tenantId, gameId, roundId)
        assertNotNull(roundFromDb)
        assertEquals(GameRoundPhase.BET_COUNTDOWN, roundFromDb.phase)

        val betCmd = AviatorRestCommand(
            tenantId = tenantId,
            principal = playerPrincipal,
            commandId = "cmd-bet-pg-001",
            roundId = roundId,
            handId = "hand_primary",
            action = "PLACE_BET",
            wagerMinor = 10000L,
            currency = currency,
            correlationId = "corr-bet-pg-001"
        )
        val betAck = service.processCommand(betCmd)
        assertEquals(AviatorCommandAckStatus.ACCEPTED, betAck.status)

        val betFromDb = gameStore.findBet(tenantId, gameId, roundId, playerIdStr, "hand_primary")
        assertNotNull(betFromDb)
        assertEquals(GameBetStatus.ACCEPTED, betFromDb.status)
        assertEquals(10000L, betFromDb.wagerMinorUnits)

        val balanceAfterBet = ledgerStore.findBalance(tenantId, "PLAYER:$playerIdStr", currency)
        assertEquals(90000L, balanceAfterBet)

        val dupAck = service.processCommand(betCmd)
        assertEquals(AviatorCommandAckStatus.ACCEPTED, dupAck.status)
        val balanceAfterDup = ledgerStore.findBalance(tenantId, "PLAYER:$playerIdStr", currency)
        assertEquals(90000L, balanceAfterDup)

        service.createOrUpdateRound(
            CreateOrUpdateRoundCommand(
                tenantId = tenantId,
                gameId = gameId,
                roundId = roundId,
                phase = GameRoundPhase.FLYING,
                roundVersion = 2L,
                currentMultiplier = BigDecimal("2.00")
            )
        )

        val cashOutCmd = AviatorRestCommand(
            tenantId = tenantId,
            principal = playerPrincipal,
            commandId = "cmd-cashout-pg-001",
            roundId = roundId,
            handId = "hand_primary",
            action = "CASH_OUT",
            correlationId = "corr-cashout-pg-001"
        )
        val cashOutAck = service.processCommand(cashOutCmd)
        assertEquals(AviatorCommandAckStatus.ACCEPTED, cashOutAck.status)
        assertEquals(20000L, cashOutAck.result?.payoutMinor)

        val betAfterCashOut = gameStore.findBet(tenantId, gameId, roundId, playerIdStr, "hand_primary")
        assertNotNull(betAfterCashOut)
        assertEquals(GameBetStatus.CASHED_OUT, betAfterCashOut.status)

        val settlementFromDb = gameStore.findSettlement(tenantId, betAfterCashOut.betId)
        assertNotNull(settlementFromDb)
        assertEquals(GameSettlementOutcome.PAYOUT_CASH_OUT, settlementFromDb.outcome)
        assertEquals(20000L, settlementFromDb.payoutMinorUnits)

        val balanceAfterCashOut = ledgerStore.findBalance(tenantId, "PLAYER:$playerIdStr", currency)
        assertEquals(110000L, balanceAfterCashOut)

        val freshStore = JdbcDurableGameWagerAndSettlementStore(jdbc)
        val reloadedRound = freshStore.findRound(tenantId, gameId, roundId)
        assertNotNull(reloadedRound)
        assertEquals(GameRoundPhase.FLYING, reloadedRound.phase)
        val reloadedBet = freshStore.findBet(tenantId, gameId, roundId, playerIdStr, "hand_primary")
        assertNotNull(reloadedBet)
        assertEquals(GameBetStatus.CASHED_OUT, reloadedBet.status)
    }

    @Test
    fun `round crash settles uncashed bets as lost and sweeps escrow in postgres`() {
        val seedRef = "TX-PG-SEED2-${UUID.randomUUID()}"
        ledgerService.postTransaction(
            PostTransactionCommand(
                principal = adminPrincipal,
                tenantId = tenantId,
                transactionReference = seedRef,
                currencyCode = currency,
                entries = listOf(
                    JournalEntryDraft("HOUSE:SEED", JournalEntryDirection.DEBIT, 50000L, currency),
                    JournalEntryDraft("PLAYER:$playerIdStr", JournalEntryDirection.CREDIT, 50000L, currency)
                ),
                idempotencyKey = "IDEM-$seedRef",
                correlationId = "corr-$seedRef",
                causationId = "caus-$seedRef"
            )
        )

        val roundId = "RND-C-${UUID.randomUUID().toString().take(12)}"
        service.createOrUpdateRound(
            CreateOrUpdateRoundCommand(
                tenantId = tenantId,
                gameId = gameId,
                roundId = roundId,
                phase = GameRoundPhase.BET_COUNTDOWN,
                roundVersion = 1L,
                currentMultiplier = BigDecimal.ONE,
                crashMultiplier = BigDecimal("1.50")
            )
        )

        val betCmd = AviatorRestCommand(
            tenantId = tenantId,
            principal = playerPrincipal,
            commandId = "cmd-bet-crash-001",
            roundId = roundId,
            handId = "hand_primary",
            action = "PLACE_BET",
            wagerMinor = 5000L,
            currency = currency,
            correlationId = "corr-bet-crash-001"
        )
        val betAck = service.processCommand(betCmd)
        assertEquals(AviatorCommandAckStatus.ACCEPTED, betAck.status)

        val crashResult = service.settleRoundCrash(
            SettleRoundCrashCommand(
                tenantId = tenantId,
                gameId = gameId,
                roundId = roundId,
                crashMultiplier = BigDecimal("1.50")
            )
        )
        assertEquals(1, crashResult.settledBetsCount)

        val betAfterCrash = gameStore.findBet(tenantId, gameId, roundId, playerIdStr, "hand_primary")
        assertNotNull(betAfterCrash)
        assertEquals(GameBetStatus.LOST, betAfterCrash.status)

        val settlement = gameStore.findSettlement(tenantId, betAfterCrash.betId)
        assertNotNull(settlement)
        assertEquals(GameSettlementOutcome.LOSS_CRASH, settlement.outcome)
        assertEquals(0L, settlement.payoutMinorUnits)
    }
}
