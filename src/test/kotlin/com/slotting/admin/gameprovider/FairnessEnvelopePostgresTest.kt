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
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertNotEquals
import kotlin.test.assertNull
import kotlin.test.assertTrue

@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.NONE)
class FairnessEnvelopePostgresTest {

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

    private val now = Instant.parse("2026-10-08T10:00:00Z")
    private val clock = Clock.fixed(now, ZoneOffset.UTC)
    private val tenantId = "tenant-tc013-envelope"
    private val gameId = "AVIATOR"
    private val currency = "INR"
    private val keyBytes = ByteArray(32) { (it + 1).toByte() }
    private val rotatedKeyBytes = ByteArray(32) { (it + 101).toByte() }

    private val playerUuid = UUID.randomUUID()
    private val playerIdStr = playerUuid.toString()

    private val adminPrincipal = AuthenticatedPrincipal(
        id = "admin-sys-tc013",
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

    private fun testEnvelope(
        keyId: String = "tc013-key",
        keyVersion: Int = 1,
        supportedVersion: Int = keyVersion,
    ): FairnessSeedEnvelope = FairnessSeedEnvelope(
        encryptor = AesGcmEnvelopeEncryptor(
            EnvironmentMasterKeyProvider(mapOf(supportedVersion to keyBytes)),
            environment = "TEST",
        ),
        keyId = keyId,
        keyVersion = keyVersion,
    )

    private fun newAuthority(
        store: FairnessEvidenceStore,
        envelope: FairnessSeedEnvelope = testEnvelope(),
    ): ProvablyFairOutcomeAuthority = ProvablyFairOutcomeAuthority(store = store, clock = clock, envelope = envelope)

    @BeforeEach
    fun setUp() {
        jdbc.update("delete from game_bet_settlement where tenant_id = ?", tenantId)
        jdbc.update("delete from game_accepted_bet where tenant_id = ?", tenantId)
        jdbc.update("delete from game_command_receipt where tenant_id = ?", tenantId)
        jdbc.update("delete from game_cumulative_player_limit where tenant_id = ?", tenantId)
        jdbc.update("delete from game_fairness_reveal where tenant_id = ?", tenantId)
        jdbc.update("delete from game_fairness_audit where tenant_id = ?", tenantId)
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
        fairnessAuthority = newAuthority(fairnessStore)
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
        jdbc.update(
            """
            insert into game_authoritative_round (
                tenant_id, game_id, round_id, phase, round_version, current_multiplier, server_time, created_at, updated_at
            ) values (?, ?, ?, ?, 1, 1.0000, ?, ?, ?)
            """.trimIndent(),
            tenantId, gameId, roundId, phase, Timestamp.from(now), Timestamp.from(now), Timestamp.from(now),
        )
    }

    private fun createRound(roundId: String, phase: GameRoundPhase = GameRoundPhase.BET_COUNTDOWN) {
        gameService.createOrUpdateRound(
            CreateOrUpdateRoundCommand(
                tenantId = tenantId,
                gameId = gameId,
                roundId = roundId,
                phase = phase,
                roundVersion = 1L,
                currentMultiplier = BigDecimal("1.0000"),
            )
        )
    }

    private fun seedFunds(amount: Long) {
        ledgerService.postTransaction(
            PostTransactionCommand(
                principal = adminPrincipal,
                tenantId = tenantId,
                transactionReference = "TX-TC013-SEED-${UUID.randomUUID()}",
                currencyCode = currency,
                entries = listOf(
                    JournalEntryDraft("HOUSE:SEED", JournalEntryDirection.DEBIT, amount, currency),
                    JournalEntryDraft("PLAYER:$playerIdStr", JournalEntryDirection.CREDIT, amount, currency),
                ),
                idempotencyKey = "IDEM-TC013-SEED-${UUID.randomUUID()}",
                correlationId = "corr-tc013-seed",
                causationId = "caus-tc013-seed",
            )
        )
    }

    private fun publish(authority: ProvablyFairOutcomeAuthority, roundId: String): RoundCommitmentRecord {
        insertRound(roundId)
        return authority.publishPreBetCommitment(
            PublishCommitmentCommand(
                tenantId = tenantId,
                gameId = gameId,
                roundId = roundId,
                publicSalt = "salt-$roundId",
            )
        )
    }

    private fun placeBetCommand(roundId: String, commandId: String): AviatorRestCommand =
        AviatorRestCommand(
            tenantId = tenantId,
            principal = playerPrincipal,
            commandId = commandId,
            roundId = roundId,
            handId = "hand_primary",
            action = "PLACE_BET",
            wagerMinor = 101L,
            currency = currency,
            correlationId = "corr-$commandId",
        )

    private fun assertJournalBalanced() {
        val debits = jdbc.queryForObject(
            "select coalesce(sum(total_debits_minor_units), 0) from ledger_transaction where tenant_id = ?",
            Long::class.java, tenantId,
        ) ?: 0L
        val credits = jdbc.queryForObject(
            "select coalesce(sum(total_credits_minor_units), 0) from ledger_transaction where tenant_id = ?",
            Long::class.java, tenantId,
        ) ?: 0L
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

    @Test
    fun GivenUnrevealedSeed_WhenStoredAndSerialized_ThenNoPlaintextEscapes() {
        val store = JdbcFairnessEvidenceStore(jdbc)
        val authority = newAuthority(store)
        val roundId = "rnd-tc013-t01"
        val commitment = publish(authority, roundId)

        val row = jdbc.queryForMap(
            "select encrypted_secret_seed, secret_nonce, secret_key_id, secret_key_version, secret_format_version from game_fairness_commitment where tenant_id = ? and game_id = ? and round_id = ?",
            tenantId, gameId, roundId,
        )
        val storedCiphertext = row["encrypted_secret_seed"] as String
        assertNotEquals(commitment.commitmentHash, storedCiphertext)
        assertTrue((row["secret_nonce"] as String).isNotBlank())
        assertEquals("tc013-key", row["secret_key_id"])
        assertEquals(1, (row["secret_key_version"] as Number).toInt())
        assertEquals(1, (row["secret_format_version"] as Number).toInt())

        val outcome = authority.deriveAuthoritativeOutcome(tenantId, gameId, roundId)
        val plaintextSeed = authority.openCommittedSecret(tenantId, gameId, roundId)

        assertFalse(storedCiphertext.contains(plaintextSeed))
        assertFalse(outcome.toString().contains(plaintextSeed))
        assertFalse(commitment.toString().contains(plaintextSeed))
        val auditDetails = jdbc.queryForList(
            "select detail from game_fairness_audit where tenant_id = ? and round_id = ?",
            String::class.java, tenantId, roundId,
        )
        assertTrue(auditDetails.none { it.contains(plaintextSeed) })

        val reveal = authority.revealAndVerifyOutcome(RevealOutcomeCommand(tenantId, gameId, roundId))
        assertEquals(FairnessVerificationStatus.VERIFIED, reveal.verificationStatus)
        assertEquals(commitment.commitmentHash, ProvablyFairOutcomeAuthority.sha256(reveal.revealedSecretSeed))
    }

    @Test
    fun GivenTamperedEnvelope_WhenDecrypted_ThenAuthenticationFails() {
        val store = JdbcFairnessEvidenceStore(jdbc)
        val envelope = testEnvelope()
        val authority = newAuthority(store, envelope)
        val roundId = "rnd-tc013-t02"
        val commitment = publish(authority, roundId)

        val stored = SealedFairnessSeed(
            ciphertextBase64 = commitment.encryptedSecretSeed,
            nonceBase64 = commitment.secretNonce!!,
            keyId = commitment.secretKeyId!!,
            keyVersion = commitment.secretKeyVersion!!,
            formatVersion = commitment.secretFormatVersion!!,
        )
        val commitmentId = commitment.commitmentId.toString()

        assertFailsWith<DecryptionTamperException> {
            envelope.open(tenantId, gameId, roundId, commitmentId, stored.copy(ciphertextBase64 = stored.ciphertextBase64.dropLast(4) + "AAAA"))
        }
        assertFailsWith<DecryptionTamperException> {
            envelope.open(tenantId, gameId, roundId, commitmentId, stored.copy(nonceBase64 = "AAAAAAAAAAAAAAAA"))
        }
        assertFailsWith<DecryptionTamperException> {
            envelope.open(tenantId, gameId, roundId, commitmentId, stored.copy(keyId = "attacker-key"))
        }
        val versionFailure = assertFailsWith<RuntimeException> {
            envelope.open(tenantId, gameId, roundId, commitmentId, stored.copy(keyVersion = stored.keyVersion + 7))
        }
        assertTrue(
            versionFailure is DecryptionTamperException || versionFailure is IllegalStateException,
            "tampered key version must fail closed, was $versionFailure",
        )
        assertFailsWith<DecryptionTamperException> {
            envelope.open(tenantId, gameId, "different-round", commitmentId, stored)
        }
        assertFailsWith<DecryptionTamperException> {
            envelope.open(tenantId, gameId, roundId, UUID.randomUUID().toString(), stored)
        }
        assertFailsWith<DecryptionTamperException> {
            envelope.open("different-tenant", gameId, roundId, commitmentId, stored)
        }
        assertFailsWith<DecryptionTamperException> {
            testEnvelope(keyId = "different-configured-key").open(tenantId, gameId, roundId, commitmentId, stored)
        }
        assertFailsWith<IllegalStateException> {
            testEnvelope(keyVersion = 1, supportedVersion = 2).open(tenantId, gameId, roundId, commitmentId, stored)
        }

        val beforeReveal = store.findCommitment(tenantId, gameId, roundId)
        assertEquals(RoundCommitmentStatus.COMMITTED, beforeReveal?.status)
        assertNull(store.findReveal(tenantId, gameId, roundId))

        jdbc.update(
            "update game_fairness_commitment set encrypted_secret_seed = ? where commitment_id = ?",
            "AAAA" + commitment.encryptedSecretSeed.drop(4), commitment.commitmentId,
        )
        assertFailsWith<DecryptionTamperException> {
            authority.revealAndVerifyOutcome(RevealOutcomeCommand(tenantId, gameId, roundId))
        }
        assertEquals(RoundCommitmentStatus.COMMITTED, store.findCommitment(tenantId, gameId, roundId)?.status)
        assertNull(store.findReveal(tenantId, gameId, roundId))
    }

    @Test
    fun GivenTenThousandEncryptions_WhenNonceCollected_ThenAllUnique() {
        val envelope = testEnvelope()
        val plaintext = "a".repeat(64)

        val nonces = HashSet<String>()
        repeat(10_000) {
            val sealed = envelope.seal(tenantId, gameId, "rnd", UUID.randomUUID().toString(), plaintext)
            assertTrue(nonces.add(sealed.nonceBase64), "nonce must be unique")
        }
        assertEquals(10_000, nonces.size)

        val roundTripId = UUID.randomUUID().toString()
        val sealed = envelope.seal(tenantId, gameId, "rnd", roundTripId, plaintext)
        assertEquals(plaintext, envelope.open(tenantId, gameId, "rnd", roundTripId, sealed))

        val productionConfig = com.slotting.admin.config.FairnessEnvelopeConfiguration()
        assertFailsWith<IllegalArgumentException> { productionConfig.fairnessSeedEnvelope("PRODUCTION", "", 1, "") }
        assertFailsWith<IllegalArgumentException> { productionConfig.fairnessSeedEnvelope("PRODUCTION", "key-id", 1, "") }

        val store = JdbcFairnessEvidenceStore(jdbc)
        val authority = newAuthority(store)
        val roundId = "rnd-tc013-t03"
        val commitment = publish(authority, roundId)
        val seed = authority.openCommittedSecret(tenantId, gameId, roundId)
        assertEquals(commitment.commitmentHash, ProvablyFairOutcomeAuthority.sha256(seed))
        val m1 = authority.deriveAuthoritativeOutcome(tenantId, gameId, roundId).multiplier
        val m2 = authority.deriveAuthoritativeOutcome(tenantId, gameId, roundId).multiplier
        assertEquals(m1, m2)
    }

    @Test
    fun GivenKeyRotation_WhenOlderEnvelopeIsOpened_ThenKeyRingResolvesOldVersion() {
        val v1 = FairnessSeedEnvelope(
            encryptor = AesGcmEnvelopeEncryptor(EnvironmentMasterKeyProvider(mapOf(1 to keyBytes)), environment = "TEST"),
            keyId = "ring-key",
            keyVersion = 1,
        )
        val plaintext = "c".repeat(64)
        val commitmentId = UUID.randomUUID().toString()
        val sealedV1 = v1.seal(tenantId, gameId, "rnd-rot", commitmentId, plaintext)

        val ring = FairnessSeedEnvelope(
            encryptor = AesGcmEnvelopeEncryptor(
                EnvironmentMasterKeyProvider(mapOf(1 to keyBytes, 2 to rotatedKeyBytes)),
                environment = "TEST",
            ),
            keyId = "ring-key",
            keyVersion = 2,
        )
        assertEquals(plaintext, ring.open(tenantId, gameId, "rnd-rot", commitmentId, sealedV1))
        val sealedV2 = ring.seal(tenantId, gameId, "rnd-rot", commitmentId, plaintext)
        assertEquals(2, sealedV2.keyVersion)
        assertEquals(plaintext, ring.open(tenantId, gameId, "rnd-rot", commitmentId, sealedV2))
    }

    @Test
    fun GivenLegacyPlaintextRows_WhenMigrationPrecheckRuns_ThenIdentitiesReported() {
        val roundId = "rnd-tc013-legacy"
        insertRound(roundId)
        val legacyId = UUID.randomUUID()
        jdbc.update(
            """
            insert into game_fairness_commitment (
                commitment_id, tenant_id, game_id, round_id, authority_type, algorithm_version,
                rules_version, commitment_hash, public_salt, encrypted_secret_seed, committed_at,
                status, server_version, created_at, updated_at
            ) values (?, ?, ?, ?, 'INTERNAL_HMAC_SHA256', '1.0.0', '1.0.0', ?, 'salt-legacy', ?, ?, 'COMMITTED', 1, ?, ?)
            """.trimIndent(),
            legacyId, tenantId, gameId, roundId, "a".repeat(64), "b".repeat(64),
            Timestamp.from(now), Timestamp.from(now), Timestamp.from(now),
        )

        val diagnostic = FairnessEnvelopeMigrationDiagnostic(jdbc)
        val inventory = diagnostic.inventory()
        val legacyRow = inventory.first { it.roundId == roundId }
        assertEquals(FairnessEnvelopeClassification.LEGACY_PLAINTEXT, legacyRow.classification)
        assertEquals(legacyId, legacyRow.commitmentId)

        val failure = assertFailsWith<FairnessEnvelopeMigrationException> { diagnostic.assertSafeToProceed() }
        assertTrue(failure.affectedIdentities.any { it.contains(roundId) }, "affected identities must name the legacy row")

        jdbc.update("delete from game_fairness_commitment where commitment_id = ?", legacyId)
        val encryptedRound = "rnd-tc013-legacy-encrypted"
        publish(newAuthority(JdbcFairnessEvidenceStore(jdbc)), encryptedRound)
        val encryptedRow = diagnostic.inventory().first { it.roundId == encryptedRound }
        assertEquals(FairnessEnvelopeClassification.ENCRYPTED, encryptedRow.classification)
        diagnostic.assertSafeToProceed()
    }

    @Test
    fun GivenMixedOperations_WhenLocksAreObserved_ThenGlobalOrderIsPreserved() {
        seedFunds(5_000_000L)

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
            val roundId = "rnd-tc013-order-$iteration"
            createRound(roundId)

            trace.clear()
            lifecycleStore.eventLog.clear()

            val ack = commandService.processCommand(placeBetCommand(roundId, "cmd-tc013-$iteration"))
            assertEquals(AviatorCommandAckStatus.ACCEPTED, ack.status, "iteration $iteration")

            assertTrue(trace.any { it.first == "RECEIPT" }, "iteration $iteration early claim must be the first lock")
            assertTrue(trace.any { it.first == "ROUND_SHARED" }, "iteration $iteration command must take the shared round lock")
            assertTrue(trace.any { it.first == "BET" }, "iteration $iteration bet row must be locked")
            assertTrue(trace.any { it.first == "PLAYER_ACCOUNT" }, "iteration $iteration player account must be locked")
            assertTrue(trace.any { it.first == "SEQUENCE_COUNTER" }, "iteration $iteration sequence counter must be locked last")
            assertMonotonic(trace)

            val crash = lifecycleService.settleRoundCrash(
                SettleRoundCrashCommand(tenantId, gameId, roundId, BigDecimal("1.1000"))
            )
            assertEquals(1, crash.settledBetsCount, "iteration $iteration")
            assertTrue(lifecycleStore.eventLog.any { it.first == "ROUND_EXCLUSIVE" }, "iteration $iteration lifecycle must take the exclusive round lock")
            assertTrue(lifecycleStore.eventLog.any { it.first == "BETS" }, "iteration $iteration lifecycle must lock accepted bets")
            assertMonotonic(lifecycleStore.eventLog)

            val bet = gameStore.findBet(tenantId, gameId, roundId, playerIdStr, "hand_primary")
            assertEquals(GameBetStatus.LOST, bet?.status, "iteration $iteration bet must be terminal")
            assertEquals(
                1,
                jdbc.queryForObject("select count(*) from game_bet_settlement where tenant_id = ? and round_id = ?", Int::class.java, tenantId, roundId) ?: 0,
                "iteration $iteration exactly one settlement",
            )
        }

        assertJournalBalanced()
        assertEquals(0L, ledgerStore.findBalance(tenantId, "ESCROW:GAME:$gameId", currency))
    }

    @Test
    fun GivenBetThenRoundInversion_WhenControlRuns_ThenDeadlockDetectedAndRolledBack() {
        val roundId = "rnd-tc013-inversion"
        val betId = UUID.randomUUID()
        insertRound(roundId, phase = "FLYING")
        jdbc.update(
            """
            insert into game_accepted_bet (
                bet_id, tenant_id, owner_id, game_id, round_id, hand_id, wager_minor_units,
                currency_code, reservation_id, ledger_reservation_ref, status, created_at, updated_at
            ) values (?, ?, ?, ?, ?, 'hand_primary', 101, 'INR', ?, 'lref', 'ACCEPTED', ?, ?)
            """.trimIndent(),
            betId, tenantId, playerIdStr, gameId, roundId, UUID.randomUUID(),
            Timestamp.from(now), Timestamp.from(now),
        )

        val txTemplate = TransactionTemplate(txManager)
        val pool = Executors.newFixedThreadPool(2)
        val forwardHoldsRound = CountDownLatch(1)
        val inversionHoldsBet = CountDownLatch(1)
        val outcomes = ConcurrentLinkedQueue<Pair<String, Throwable?>>()

        val forward = pool.submit(Callable {
            try {
                txTemplate.execute<Unit> {
                    jdbc.queryForList(
                        "select round_id from game_authoritative_round where tenant_id = ? and game_id = ? and round_id = ? for update",
                        tenantId, gameId, roundId,
                    )
                    jdbc.update(
                        "insert into game_fairness_audit (audit_id, tenant_id, round_id, action, actor, detail, occurred_at) values (?, ?, ?, 'TC013_FORWARD', 'TEST', 'forward', ?)",
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
        assertTrue(forwardHoldsRound.await(10, TimeUnit.SECONDS), "forward worker must hold the round lock")

        val inversion = pool.submit(Callable {
            try {
                txTemplate.execute<Unit> {
                    jdbc.queryForList("select bet_id from game_accepted_bet where bet_id = ? for update", betId)
                    jdbc.update(
                        "insert into game_fairness_audit (audit_id, tenant_id, round_id, action, actor, detail, occurred_at) values (?, ?, ?, 'TC013_INVERSION', 'TEST', 'inversion', ?)",
                        UUID.randomUUID(), tenantId, roundId, Timestamp.from(now),
                    )
                    inversionHoldsBet.countDown()
                    jdbc.queryForList(
                        "select round_id from game_authoritative_round where tenant_id = ? and game_id = ? and round_id = ? for update",
                        tenantId, gameId, roundId,
                    )
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

        val forwardMarkers = jdbc.queryForObject("select count(*) from game_fairness_audit where tenant_id = ? and action = 'TC013_FORWARD'", Int::class.java, tenantId) ?: 0
        val inversionMarkers = jdbc.queryForObject("select count(*) from game_fairness_audit where tenant_id = ? and action = 'TC013_INVERSION'", Int::class.java, tenantId) ?: 0
        assertEquals(if (forwardAborted) 0 else 1, forwardMarkers, "aborted forward attempt must leave no effects")
        assertEquals(if (inversionAborted) 0 else 1, inversionMarkers, "aborted inversion attempt must leave no effects")
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

        val cashOutRound = "rnd-tc013-golden-cashout"
        createRound(cashOutRound)
        assertEquals(AviatorCommandAckStatus.ACCEPTED, gameService.processCommand(placeBetCommand(cashOutRound, "cmd-tc013-golden-bet-1")).status)
        gameService.createOrUpdateRound(
            CreateOrUpdateRoundCommand(tenantId, gameId, cashOutRound, GameRoundPhase.FLYING, 2L, multiplier)
        )
        val cashOutAck = gameService.processCommand(
            AviatorRestCommand(
                tenantId = tenantId,
                principal = playerPrincipal,
                commandId = "cmd-tc013-golden-cashout-1",
                roundId = cashOutRound,
                handId = "hand_primary",
                action = "CASH_OUT",
                currency = currency,
                correlationId = "corr-tc013-golden-cashout-1",
            )
        )
        assertEquals(AviatorCommandAckStatus.ACCEPTED, cashOutAck.status)
        assertEquals(expectedWinMinor, cashOutAck.result?.payoutMinor)
        assertEquals(startingBalance - wagerMinor + expectedWinMinor, ledgerStore.findBalance(tenantId, "PLAYER:$playerIdStr", currency))

        val lossRound = "rnd-tc013-golden-loss"
        createRound(lossRound)
        assertEquals(AviatorCommandAckStatus.ACCEPTED, gameService.processCommand(placeBetCommand(lossRound, "cmd-tc013-golden-bet-2")).status)
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
