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
import java.io.File
import java.math.BigDecimal
import java.math.RoundingMode
import java.nio.charset.StandardCharsets
import java.security.MessageDigest
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
import kotlin.test.assertFalse
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue

@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.NONE)
class AviatorAlgorithmRegistryTest {

    companion object {
        @JvmStatic
        @DynamicPropertySource
        fun postgresProperties(registry: DynamicPropertyRegistry) {
            PostgresIntegrationSupport.configureProperties(registry)
        }

        const val UNSUPPORTED_VERSION_CODE = "UNSUPPORTED_ALGORITHM_VERSION"
        const val UNKNOWN_VERSION = "9.9.9"
        const val REGISTRY_SOURCE_PATH = "src/main/kotlin/com/slotting/admin/gameprovider/AviatorAlgorithmRegistry.kt"
    }

    @Autowired
    private lateinit var jdbc: JdbcTemplate

    @Autowired
    private lateinit var txManager: PlatformTransactionManager

    private val now = Instant.parse("2026-10-09T12:00:00Z")
    private val clock = Clock.fixed(now, ZoneOffset.UTC)
    private val tenantId = "tenant-tc016-registry"
    private val gameId = "AVIATOR"
    private val currency = "INR"

    private val playerUuid = UUID.randomUUID()
    private val playerIdStr = playerUuid.toString()

    private val adminPrincipal = AuthenticatedPrincipal("admin-sys-tc016", tenantId, PrincipalKind.ADMIN, setOf(AdminRole.SUPER_ADMIN))
    private val playerPrincipal = AuthenticatedPrincipal(playerIdStr, tenantId, PrincipalKind.PLAYER, setOf(AdminRole.SUPPORT))

    private lateinit var gameStore: JdbcDurableGameWagerAndSettlementStore
    private lateinit var ledgerStore: JdbcLedgerJournalStore
    private lateinit var registrationStore: JdbcPlayerRegistrationStore
    private lateinit var eligibilityStore: ServerEligibilityStore
    private lateinit var ledgerService: LedgerPostingService
    private lateinit var fairnessStore: JdbcFairnessEvidenceStore
    private lateinit var gameService: DurableGameWagerAndSettlementService

    private data class FrozenOutcome(
        val combinedString: String,
        val combinedHash: String,
        val hexPrefix: String,
        val modulusBucket: Long,
        val instantCrash: Boolean,
        val value: BigDecimal,
    )

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
                jurisdiction = "DEFAULT", responsiblePlay = ResponsiblePlayProfile(
                    playerId = playerUuid, selfExcluded = false,
                    singleWagerLimitMinor = 5_000_000L, dailyWagerLimitMinor = 20_000_000L, currentDailyWagerMinor = 0L,
                ),
            )
        )
    }

    private fun unitAuthority(): Pair<ProvablyFairOutcomeAuthority, InMemoryFairnessEvidenceStore> {
        val store = InMemoryFairnessEvidenceStore()
        return ProvablyFairOutcomeAuthority(store = store, clock = clock) to store
    }

    private fun authority() = ProvablyFairOutcomeAuthority(store = fairnessStore, clock = clock, txManager = txManager)

    private fun lifecycleProperties(algorithmVersion: String) =
        AviatorLifecycleConfiguration().aviatorLifecycleProperties(
            scheduledMillis = 1_000L,
            bettingMillis = 5_000L,
            closedMillis = 1_000L,
            multiplierStep = BigDecimal("0.0500"),
            rulesVersion = "1.0.0",
            algorithmVersion = algorithmVersion,
            publicSalt = "aviator-public",
            tenants = listOf("default"),
        )

    @Test
    fun GivenUnknownStoredVersion_WhenDerivingOrVerifying_ThenUnsupportedVersion() {
        val (authorityUnderTest, unitStore) = unitAuthority()
        val deriveRound = "rnd-tc016-unknown-derive"
        authorityUnderTest.publishPreBetCommitment(
            PublishCommitmentCommand(
                tenantId = tenantId,
                gameId = gameId,
                roundId = deriveRound,
                publicSalt = "salt-tc016-derive",
                algorithmVersion = UNKNOWN_VERSION,
                rulesVersion = "1.0.0",
            )
        )

        val deriveAttempt = runCatching { authorityUnderTest.deriveAuthoritativeOutcome(tenantId, gameId, deriveRound) }
        val deriveFailure = deriveAttempt.exceptionOrNull()
        assertTrue(deriveAttempt.isFailure, "derive must reject an unregistered stored algorithm version")
        val typedDeriveFailure = deriveFailure as? FairnessAuthorityException
        assertNotNull(typedDeriveFailure, "derive rejection must be a typed fairness authority failure, was $deriveFailure")
        assertEquals(UNSUPPORTED_VERSION_CODE, typedDeriveFailure?.errorCode)
        assertNull(deriveAttempt.getOrNull(), "no computed multiplier may be returned for an unregistered version")
        assertNull(unitStore.findReveal(tenantId, gameId, deriveRound), "no reveal evidence may exist for a rejected derive")

        val supportedRound = "rnd-tc016-supported-derive"
        authorityUnderTest.publishPreBetCommitment(
            PublishCommitmentCommand(
                tenantId = tenantId,
                gameId = gameId,
                roundId = supportedRound,
                publicSalt = "salt-tc016-supported",
                algorithmVersion = "1.0.0",
                rulesVersion = "1.0.0",
            )
        )
        val supportedOutcome = authorityUnderTest.deriveAuthoritativeOutcome(tenantId, gameId, supportedRound)
        assertEquals("1.0.0", supportedOutcome.algorithmVersion)
        assertEquals(2, supportedOutcome.multiplier.scale())
        assertTrue(supportedOutcome.multiplier >= BigDecimal("1.00"))

        val verifyRound = "rnd-tc016-unknown-verify"
        val secretSeed = "ab".repeat(32)
        val storedCommitment = RoundCommitmentRecord(
            commitmentId = UUID.randomUUID(),
            tenantId = tenantId,
            gameId = gameId,
            roundId = verifyRound,
            authorityType = FairnessAuthorityType.INTERNAL_HMAC_SHA256,
            algorithmVersion = UNKNOWN_VERSION,
            rulesVersion = "1.0.0",
            commitmentHash = ProvablyFairOutcomeAuthority.sha256(secretSeed),
            publicSalt = "salt-tc016-verify",
            encryptedSecretSeed = "ciphertext-placeholder",
            committedAt = now,
            status = RoundCommitmentStatus.REVEALED,
            createdAt = now,
            updatedAt = now,
            clientSeed1 = "client-seed-1",
            clientSeed2 = "client-seed-2",
            clientSeed3 = "client-seed-3",
        )
        unitStore.saveCommitment(storedCommitment)
        unitStore.saveReveal(
            RoundRevealRecord(
                revealId = UUID.randomUUID(),
                commitmentId = storedCommitment.commitmentId,
                tenantId = tenantId,
                gameId = gameId,
                roundId = verifyRound,
                revealedSecretSeed = secretSeed,
                derivedMultiplier = BigDecimal("2.50"),
                revealedAt = now,
                verificationStatus = FairnessVerificationStatus.VERIFIED,
                evidenceReference = "evidence-tc016-unknown",
            )
        )

        val verification = IndependentFairnessVerifier(unitStore).verifyHistoricalRound(
            VerifyHistoricalRoundQuery(tenantId = tenantId, gameId = gameId, roundId = verifyRound)
        )
        assertFalse(verification.isVerified, "historical verification must not accept an unregistered stored version")
        assertEquals(UNSUPPORTED_VERSION_CODE, verification.failureCode)
        assertNull(verification.derivedMultiplier, "no computed multiplier may be reported for an unregistered version")
        assertEquals(UNKNOWN_VERSION, verification.algorithmVersion)

        assertEquals("1.0.0", lifecycleProperties("1.0.0").algorithmVersion)

        val startupAttempt = runCatching { lifecycleProperties(UNKNOWN_VERSION) }
        val startupFailure = startupAttempt.exceptionOrNull()
        assertTrue(startupAttempt.isFailure, "startup configuration must reject an unregistered algorithm version")
        val typedStartupFailure = startupFailure as? FairnessAuthorityException
        assertNotNull(typedStartupFailure, "startup rejection must be typed, was $startupFailure")
        assertEquals(UNSUPPORTED_VERSION_CODE, typedStartupFailure?.errorCode)
    }

    @Test
    fun GivenVersion100_WhenRegistryComputes_ThenHistoricalCorpusIsIdentical() {
        assertEquals(BigDecimal("2.66"), frozenMultiplier("0".repeat(64), "seed-a", "seed-b", "seed-c"))
        assertEquals(BigDecimal("2.90"), frozenMultiplier("a".repeat(64), "client-1", "client-2", "client-3"))
        assertEquals(BigDecimal("1.86"), frozenMultiplier("0123456789abcdef".repeat(4), "cs1", "cs2", "cs3"))
        assertEquals(BigDecimal("2.66"), AviatorAlgorithmRegistry.compute("1.0.0", "0".repeat(64), "seed-a", "seed-b", "seed-c"))
        assertEquals(BigDecimal("2.90"), AviatorAlgorithmRegistry.compute("1.0.0", "a".repeat(64), "client-1", "client-2", "client-3"))
        assertEquals(BigDecimal("1.86"), AviatorAlgorithmRegistry.compute("1.0.0", "0123456789abcdef".repeat(4), "cs1", "cs2", "cs3"))

        var instantCrashCount = 0
        for (index in 0 until 10_000) {
            val (serverSeed, clientSeed1, clientSeed2, clientSeed3) = corpusVector(index)
            val expected = frozenMultiplier(serverSeed, clientSeed1, clientSeed2, clientSeed3)
            val implemented = IndependentFairnessVerifier.calculateCrashMultiplier(serverSeed, clientSeed1, clientSeed2, clientSeed3)
            val entryPoint = ProvablyFairOutcomeAuthority.computeMultiplier(serverSeed, clientSeed1, clientSeed2, clientSeed3)
            val dispatched = AviatorAlgorithmRegistry.compute("1.0.0", serverSeed, clientSeed1, clientSeed2, clientSeed3)
            assertEquals(expected, implemented, "vector $index multiplier")
            assertEquals(expected, entryPoint, "vector $index entry point")
            assertEquals(expected, dispatched, "vector $index registry dispatch")
            assertEquals(2, implemented.scale(), "vector $index scale")
            assertEquals(0, expected.compareTo(implemented), "vector $index comparison")
            assertTrue(implemented >= BigDecimal("1.00"), "vector $index lower bound")
            if (implemented.compareTo(BigDecimal("1.00")) == 0) instantCrashCount++
        }
        assertTrue(instantCrashCount in 150..450, "instant-crash modulus outcomes were $instantCrashCount of 10000")

        assertTrue(AviatorAlgorithmRegistry.supportedVersions.contains("1.0.0"), "registry must register version 1.0.0")
        assertFalse(AviatorAlgorithmRegistry.isSupported(UNKNOWN_VERSION), "registry must not register an unregistered version")
        val unsupportedDispatch = runCatching { AviatorAlgorithmRegistry.compute(UNKNOWN_VERSION, "seed", "client-1", "client-2", "client-3") }
        assertTrue(unsupportedDispatch.isFailure, "registry dispatch must reject an unregistered version")
        assertEquals(UNSUPPORTED_VERSION_CODE, (unsupportedDispatch.exceptionOrNull() as? FairnessAuthorityException)?.errorCode)
        assertNull(unsupportedDispatch.getOrNull(), "registry dispatch must not return a computed multiplier")

        val unicodeServerSeed = "секрет-日本語-π-🙂"
        val unicodeSeed1 = "клиент-1-α"
        val unicodeSeed2 = "クライアント-2"
        val unicodeSeed3 = "client-seed-3-🚀"
        val unicodeTrace = frozenTrace(unicodeServerSeed, unicodeSeed1, unicodeSeed2, unicodeSeed3)
        assertEquals(unicodeServerSeed + unicodeSeed1 + unicodeSeed2 + unicodeSeed3, unicodeTrace.combinedString)
        assertEquals(13, unicodeTrace.hexPrefix.length)
        assertTrue(unicodeTrace.hexPrefix.all { it in "0123456789abcdef" })
        assertTrue(unicodeTrace.modulusBucket in 0L..99L)
        val utf8Digest = MessageDigest.getInstance("SHA-512")
            .digest(unicodeTrace.combinedString.toByteArray(StandardCharsets.UTF_8))
            .joinToString("") { "%02x".format(it) }
        assertEquals(utf8Digest, unicodeTrace.combinedHash)
        assertEquals(2, unicodeTrace.value.scale())
        assertEquals(
            unicodeTrace.value,
            IndependentFairnessVerifier.calculateCrashMultiplier(unicodeServerSeed, unicodeSeed1, unicodeSeed2, unicodeSeed3),
        )

        var instantServerSeed: String? = null
        var searchIndex = 0
        while (instantServerSeed == null && searchIndex < 20_000) {
            val candidate = "tc016-instant-bust-$searchIndex"
            if (frozenMultiplier(candidate, "cs1", "cs2", "cs3").compareTo(BigDecimal("1.00")) == 0) {
                instantServerSeed = candidate
            }
            searchIndex++
        }
        assertNotNull(instantServerSeed, "boundary fixture must locate an instant-crash vector")
        val locatedInstantSeed = instantServerSeed ?: throw AssertionError("boundary fixture must locate an instant-crash vector")
        val instantTrace = frozenTrace(locatedInstantSeed, "cs1", "cs2", "cs3")
        assertTrue(instantTrace.instantCrash)
        assertTrue(instantTrace.modulusBucket < 3L)
        assertEquals(BigDecimal("1.00"), instantTrace.value)
        assertEquals(
            instantTrace.value,
            IndependentFairnessVerifier.calculateCrashMultiplier(locatedInstantSeed, "cs1", "cs2", "cs3"),
        )

        val nearMissTrace = frozenTrace("tc016-boundary-hash", "cs1", "cs2", "cs3")
        assertEquals(13, nearMissTrace.hexPrefix.length)
        assertEquals(nearMissTrace.hexPrefix, nearMissTrace.combinedHash.substring(0, 13))
    }

    @Test
    fun GivenStoredVersion_WhenConfigurationDiffers_ThenHistoricalVersionWins() {
        val storedRound = "rnd-tc016-stored-100"
        createRound(storedRound)
        val storedAuthority = authority()
        storedAuthority.publishPreBetCommitment(
            PublishCommitmentCommand(
                tenantId = tenantId,
                gameId = gameId,
                roundId = storedRound,
                publicSalt = "salt-tc016-stored",
                algorithmVersion = "1.0.0",
                rulesVersion = "1.0.0",
            )
        )
        val derived = storedAuthority.deriveAuthoritativeOutcome(tenantId, gameId, storedRound)
        assertEquals("1.0.0", derived.algorithmVersion)
        val reveal = storedAuthority.revealAndVerifyOutcome(RevealOutcomeCommand(tenantId, gameId, storedRound))
        assertEquals(FairnessVerificationStatus.VERIFIED, reveal.verificationStatus)

        val unknownConfiguration = runCatching { lifecycleProperties(UNKNOWN_VERSION) }

        val verification = IndependentFairnessVerifier(fairnessStore).verifyHistoricalRound(
            VerifyHistoricalRoundQuery(tenantId = tenantId, gameId = gameId, roundId = storedRound)
        )
        assertTrue(verification.isVerified, "historical verification must dispatch on the stored 1.0.0 version")
        val verifiedMultiplier = assertNotNull(verification.derivedMultiplier, "verified round must report a multiplier")
        assertEquals(0, derived.multiplier.compareTo(verifiedMultiplier), "stored version outcome must reproduce exactly")
        assertEquals("1.0.0", verification.algorithmVersion)

        val unknownRound = "rnd-tc016-stored-unknown"
        createRound(unknownRound)
        storedAuthority.publishPreBetCommitment(
            PublishCommitmentCommand(
                tenantId = tenantId,
                gameId = gameId,
                roundId = unknownRound,
                publicSalt = "salt-tc016-unknown-stored",
                algorithmVersion = "1.0.0",
                rulesVersion = "1.0.0",
            )
        )
        jdbc.update(
            "update game_fairness_commitment set algorithm_version = ? where tenant_id = ? and game_id = ? and round_id = ?",
            UNKNOWN_VERSION, tenantId, gameId, unknownRound,
        )
        val unknownDerive = runCatching { storedAuthority.deriveAuthoritativeOutcome(tenantId, gameId, unknownRound) }
        assertTrue(unknownDerive.isFailure, "derive must reject an unregistered stored version")
        assertEquals(UNSUPPORTED_VERSION_CODE, (unknownDerive.exceptionOrNull() as? FairnessAuthorityException)?.errorCode)
        assertNull(unknownDerive.getOrNull(), "no computed multiplier may exist for an unregistered stored version")

        val configurationFailure = unknownConfiguration.exceptionOrNull()
        assertNotNull(configurationFailure, "unknown configuration must be rejected while stored 1.0.0 stays authoritative")
        assertEquals(UNSUPPORTED_VERSION_CODE, (configurationFailure as? FairnessAuthorityException)?.errorCode)

        val registrySource = File(REGISTRY_SOURCE_PATH)
        assertTrue(registrySource.exists(), "immutable algorithm-version registry must exist at $REGISTRY_SOURCE_PATH")

        val offenders = mutableListOf<Triple<File, Int, String>>()
        File("src/main/kotlin/com/slotting/admin")
            .walkTopDown()
            .filter { it.isFile && it.extension == "kt" }
            .forEach { sourceFile ->
                sourceFile.readLines().forEachIndexed { index, text ->
                    if ("calculateCrashMultiplier" in text && sourceFile.name != "IndependentFairnessVerifier.kt" && sourceFile.name != "AviatorAlgorithmRegistry.kt") {
                        offenders.add(Triple(sourceFile, index + 1, text))
                    }
                }
            }
        assertTrue(offenders.isEmpty(), "outcome computation may only be reached through the registry, found $offenders")

        val verifierOccurrences = File("src/main/kotlin/com/slotting/admin/gameprovider/IndependentFairnessVerifier.kt")
            .readLines()
            .count { "calculateCrashMultiplier" in it }
        assertEquals(1, verifierOccurrences, "IndependentFairnessVerifier.kt may only retain the declaration")
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
            val roundId = "rnd-tc016-order-$iteration"
            createRound(roundId)
            trace.clear()
            lifecycleStore.eventLog.clear()

            val ack = commandService.processCommand(placeBetCommand(roundId, "cmd-tc016-$iteration"))
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
        val roundId = "rnd-tc016-inversion"
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
                        "insert into game_fairness_audit (audit_id, tenant_id, round_id, action, actor, detail, occurred_at) values (?, ?, ?, 'TC016_FORWARD', 'TEST', 'forward', ?)",
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
                        "insert into game_fairness_audit (audit_id, tenant_id, round_id, action, actor, detail, occurred_at) values (?, ?, ?, 'TC016_INVERSION', 'TEST', 'inversion', ?)",
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
        val forwardMarkers = jdbc.queryForObject("select count(*) from game_fairness_audit where tenant_id = ? and action = 'TC016_FORWARD'", Int::class.java, tenantId) ?: 0
        val inversionMarkers = jdbc.queryForObject("select count(*) from game_fairness_audit where tenant_id = ? and action = 'TC016_INVERSION'", Int::class.java, tenantId) ?: 0
        assertEquals(if (forwardAborted) 0 else 1, forwardMarkers)
        assertEquals(if (inversionAborted) 0 else 1, inversionMarkers)
    }

    @Test
    fun GivenHistoricalMoneyAndOutcomeVectors_WhenRefactoredPathRuns_ThenSemanticsStayUnchanged() {
        assertEquals(BigDecimal("2.66"), IndependentFairnessVerifier.calculateCrashMultiplier("0".repeat(64), "seed-a", "seed-b", "seed-c"))
        assertEquals(BigDecimal("2.90"), IndependentFairnessVerifier.calculateCrashMultiplier("a".repeat(64), "client-1", "client-2", "client-3"))
        assertEquals(BigDecimal("1.86"), IndependentFairnessVerifier.calculateCrashMultiplier("0123456789abcdef".repeat(4), "cs1", "cs2", "cs3"))
        assertEquals(BigDecimal("2.66"), ProvablyFairOutcomeAuthority.computeMultiplier("0".repeat(64), "seed-a", "seed-b", "seed-c"))
        assertEquals(BigDecimal("2.90"), ProvablyFairOutcomeAuthority.computeMultiplier("a".repeat(64), "client-1", "client-2", "client-3"))
        assertEquals(BigDecimal("1.86"), ProvablyFairOutcomeAuthority.computeMultiplier("0123456789abcdef".repeat(4), "cs1", "cs2", "cs3"))
        assertEquals(BigDecimal("2.66"), frozenMultiplier("0".repeat(64), "seed-a", "seed-b", "seed-c"))
        assertEquals(BigDecimal("2.90"), frozenMultiplier("a".repeat(64), "client-1", "client-2", "client-3"))
        assertEquals(BigDecimal("1.86"), frozenMultiplier("0123456789abcdef".repeat(4), "cs1", "cs2", "cs3"))

        val wagerMinor = 101L
        val multiplier = BigDecimal("1.2345")
        val expectedWinMinor = BigDecimal.valueOf(wagerMinor).multiply(multiplier).setScale(0, RoundingMode.FLOOR).longValueExact()
        assertEquals(124L, expectedWinMinor)

        val startingBalance = 50_000L
        seedFunds(startingBalance)

        val cashOutRound = "rnd-tc016-golden-cashout"
        createRound(cashOutRound)
        assertEquals(AviatorCommandAckStatus.ACCEPTED, gameService.processCommand(placeBetCommand(cashOutRound, "cmd-tc016-golden-bet-1")).status)
        assertEquals(startingBalance - wagerMinor, ledgerStore.findBalance(tenantId, "PLAYER:$playerIdStr", currency))
        assertEquals(wagerMinor, ledgerStore.findBalance(tenantId, "ESCROW:GAME:$gameId", currency))

        val cancelRound = "rnd-tc016-golden-cancel"
        createRound(cancelRound)
        assertEquals(AviatorCommandAckStatus.ACCEPTED, gameService.processCommand(placeBetCommand(cancelRound, "cmd-tc016-golden-bet-cancel")).status)
        assertEquals(startingBalance - 2 * wagerMinor, ledgerStore.findBalance(tenantId, "PLAYER:$playerIdStr", currency))
        assertEquals(2 * wagerMinor, ledgerStore.findBalance(tenantId, "ESCROW:GAME:$gameId", currency))
        val cancelAck = gameService.processCommand(
            AviatorRestCommand(
                tenantId = tenantId, principal = playerPrincipal, commandId = "cmd-tc016-golden-cancel-1",
                roundId = cancelRound, handId = "hand_primary", action = "CANCEL_BET", currency = currency, correlationId = "corr-tc016-golden-cancel-1",
            )
        )
        assertEquals(AviatorCommandAckStatus.ACCEPTED, cancelAck.status)
        assertEquals(startingBalance - wagerMinor, ledgerStore.findBalance(tenantId, "PLAYER:$playerIdStr", currency))
        assertEquals(wagerMinor, ledgerStore.findBalance(tenantId, "ESCROW:GAME:$gameId", currency))

        gameService.createOrUpdateRound(CreateOrUpdateRoundCommand(tenantId, gameId, cashOutRound, GameRoundPhase.FLYING, 2L, multiplier))
        val cashOutAck = gameService.processCommand(
            AviatorRestCommand(
                tenantId = tenantId, principal = playerPrincipal, commandId = "cmd-tc016-golden-cashout-1",
                roundId = cashOutRound, handId = "hand_primary", action = "CASH_OUT", currency = currency, correlationId = "corr-tc016-golden-cashout-1",
            )
        )
        assertEquals(AviatorCommandAckStatus.ACCEPTED, cashOutAck.status)
        assertEquals(expectedWinMinor, cashOutAck.result?.payoutMinor)
        assertEquals(startingBalance - wagerMinor + expectedWinMinor, ledgerStore.findBalance(tenantId, "PLAYER:$playerIdStr", currency))
        assertEquals(0L, ledgerStore.findBalance(tenantId, "ESCROW:GAME:$gameId", currency))

        val lossRound = "rnd-tc016-golden-loss"
        createRound(lossRound)
        assertEquals(AviatorCommandAckStatus.ACCEPTED, gameService.processCommand(placeBetCommand(lossRound, "cmd-tc016-golden-bet-2")).status)
        val crashResult = gameService.settleRoundCrash(SettleRoundCrashCommand(tenantId, gameId, lossRound, BigDecimal("1.0000")))
        assertEquals(1, crashResult.settledBetsCount)
        assertEquals(0L, jdbc.queryForObject("select payout_minor_units from game_bet_settlement where tenant_id = ? and outcome = 'LOSS_CRASH'", Long::class.java, tenantId))
        assertEquals(0L, ledgerStore.findBalance(tenantId, "ESCROW:GAME:$gameId", currency))
        assertJournalBalanced()

        val releaseRound = "rnd-tc016-golden-release"
        createRound(releaseRound)
        assertEquals(AviatorCommandAckStatus.ACCEPTED, gameService.processCommand(placeBetCommand(releaseRound, "cmd-tc016-golden-bet-3")).status)
        val releaseAck = gameService.processCommand(
            AviatorRestCommand(
                tenantId = tenantId, principal = playerPrincipal, commandId = "cmd-tc016-golden-release-1",
                roundId = releaseRound, handId = "hand_primary", action = "CANCEL_BET", currency = currency, correlationId = "corr-tc016-golden-release-1",
            )
        )
        assertEquals(AviatorCommandAckStatus.ACCEPTED, releaseAck.status)
        assertEquals(startingBalance - 2 * wagerMinor + expectedWinMinor, ledgerStore.findBalance(tenantId, "PLAYER:$playerIdStr", currency))
        assertEquals(0L, ledgerStore.findBalance(tenantId, "ESCROW:GAME:$gameId", currency))
        val playerEntries = jdbc.queryForObject(
            "select count(*) from ledger_leg where tenant_id = ? and account_reference = ?",
            Int::class.java, tenantId, "PLAYER:$playerIdStr",
        ) ?: 0
        assertTrue(playerEntries >= 4, "PLAYER ledger entries must be preserved, found $playerEntries")
        assertJournalBalanced()
    }

    private fun frozenTrace(serverSeed: String, clientSeed1: String, clientSeed2: String, clientSeed3: String): FrozenOutcome {
        val combinedString = serverSeed + clientSeed1 + clientSeed2 + clientSeed3
        val combinedHash = MessageDigest.getInstance("SHA-512")
            .digest(combinedString.toByteArray(StandardCharsets.UTF_8))
            .joinToString("") { "%02x".format(it) }
        val hexPrefix = combinedHash.substring(0, 13)
        val h = hexPrefix.toLong(16)
        val e = 4503599627370496.0
        val modulusBucket = h % 100L
        val instantCrash = modulusBucket < 3L
        val value = if (instantCrash) {
            BigDecimal.valueOf(1.00).setScale(2, RoundingMode.FLOOR)
        } else {
            val mRaw = e / (e - h.toDouble())
            val truncated = Math.floor(mRaw * 100.0) / 100.0
            BigDecimal.valueOf(Math.max(1.01, truncated)).setScale(2, RoundingMode.FLOOR)
        }
        return FrozenOutcome(combinedString, combinedHash, hexPrefix, modulusBucket, instantCrash, value)
    }

    private fun frozenMultiplier(serverSeed: String, clientSeed1: String, clientSeed2: String, clientSeed3: String): BigDecimal =
        frozenTrace(serverSeed, clientSeed1, clientSeed2, clientSeed3).value

    private fun corpusVector(index: Int): List<String> {
        val serverSeed = if (index % 97 == 0) {
            "种子-$index-π-🙂-${ProvablyFairOutcomeAuthority.sha256("tc016-server-$index")}"
        } else {
            ProvablyFairOutcomeAuthority.sha256("tc016-server-$index")
        }
        val clientSeed1 = if (index % 89 == 0) "клиент-1-$index" else "client-seed-1-$index"
        val clientSeed2 = if (index % 83 == 0) "クライアント-2-$index" else "client-seed-2-$index"
        val clientSeed3 = if (index % 79 == 0) "client-seed-3-🙂-$index" else "client-seed-3-$index"
        return listOf(serverSeed, clientSeed1, clientSeed2, clientSeed3)
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
                transactionReference = "TX-TC016-SEED-${UUID.randomUUID()}", currencyCode = currency,
                entries = listOf(
                    JournalEntryDraft("HOUSE:SEED", JournalEntryDirection.DEBIT, amount, currency),
                    JournalEntryDraft("PLAYER:$playerIdStr", JournalEntryDirection.CREDIT, amount, currency),
                ),
                idempotencyKey = "IDEM-TC016-SEED-${UUID.randomUUID()}", correlationId = "corr-tc016-seed", causationId = "caus-tc016-seed",
            )
        )
    }

    private fun createRound(roundId: String) {
        gameService.createOrUpdateRound(
            CreateOrUpdateRoundCommand(tenantId, gameId, roundId, GameRoundPhase.BET_COUNTDOWN, 1L, BigDecimal("1.0000"))
        )
    }

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

    private fun placeBetCommand(roundId: String, commandId: String) = AviatorRestCommand(
        tenantId = tenantId, principal = playerPrincipal, commandId = commandId, roundId = roundId,
        handId = "hand_primary", action = "PLACE_BET", wagerMinor = 101L, currency = currency, correlationId = "corr-$commandId",
    )

    private fun assertJournalBalanced() {
        val debits = jdbc.queryForObject("select coalesce(sum(total_debits_minor_units), 0) from ledger_transaction where tenant_id = ?", Long::class.java, tenantId) ?: 0L
        val credits = jdbc.queryForObject("select coalesce(sum(total_credits_minor_units), 0) from ledger_transaction where tenant_id = ?", Long::class.java, tenantId) ?: 0L
        assertEquals(debits, credits, "Double-entry journal must stay balanced")
    }
}
