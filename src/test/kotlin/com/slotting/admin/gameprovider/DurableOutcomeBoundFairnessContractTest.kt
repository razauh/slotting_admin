package com.slotting.admin.gameprovider

import com.slotting.admin.auth.AdminRole
import com.slotting.admin.auth.AuthenticatedPrincipal
import com.slotting.admin.auth.PrincipalKind
import com.slotting.admin.identity.AmlComplianceStatus
import com.slotting.admin.identity.InMemoryPlayerRegistrationStore
import com.slotting.admin.identity.InMemoryServerEligibilityStore
import com.slotting.admin.identity.KycComplianceStatus
import com.slotting.admin.identity.PlayerAccountStatus
import com.slotting.admin.identity.PlayerComplianceProfile
import com.slotting.admin.identity.PlayerRegistrationRecord
import com.slotting.admin.identity.ResponsiblePlayProfile
import com.slotting.admin.ledger.InMemoryLedgerJournalStore
import com.slotting.admin.ledger.JournalEntryDraft
import com.slotting.admin.ledger.JournalEntryDirection
import com.slotting.admin.ledger.LedgerPostingService
import com.slotting.admin.ledger.PostTransactionCommand
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test
import java.io.File
import java.math.BigDecimal
import java.time.Clock
import java.time.Instant
import java.time.LocalDate
import java.time.ZoneOffset
import java.util.UUID
import kotlin.test.*

/**
 * TC-022 Contract Test Suite:
 * Outcome-bound fairness evidence and independent historical verification.
 *
 * Covers:
 * - BE-006: Missing outcome-bound commitment/reveal provably-fair system.
 *
 * 10 Required Test Scenarios:
 * 1. commit after bet attempt
 * 2. changed seed
 * 3. changed rules
 * 4. duplicate round
 * 5. provider timeout
 * 6. missing reveal
 * 7. restart
 * 8. key rotation
 * 9. historical verification
 * 10. invalid evidence
 * 11. V29 schema migration and constraints validation
 */
class DurableOutcomeBoundFairnessContractTest {

    private val now = Instant.parse("2026-09-25T14:00:00Z")
    private val clock = Clock.fixed(now, ZoneOffset.UTC)
    private val tenantId = "tenant-pilot-001"
    private val gameId = "AVIATOR"
    private val playerUuid = UUID.fromString("11111111-1111-1111-1111-111111111111")
    private val playerIdStr = playerUuid.toString()
    private val currency = "INR"

    private val adminPrincipal = AuthenticatedPrincipal(
        id = "admin-sys-01",
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

    private lateinit var fairnessStore: InMemoryFairnessEvidenceStore
    private lateinit var fairnessAuthority: ProvablyFairOutcomeAuthority
    private lateinit var gameStore: InMemoryDurableGameWagerAndSettlementStore
    private lateinit var ledgerStore: InMemoryLedgerJournalStore
    private lateinit var ledgerService: LedgerPostingService
    private lateinit var registrationStore: InMemoryPlayerRegistrationStore
    private lateinit var eligibilityStore: InMemoryServerEligibilityStore
    private lateinit var gameService: DurableGameWagerAndSettlementService

    @BeforeEach
    fun setUp() {
        fairnessStore = InMemoryFairnessEvidenceStore()
        fairnessAuthority = ProvablyFairOutcomeAuthority(
            store = fairnessStore,
            clock = clock
        )

        gameStore = InMemoryDurableGameWagerAndSettlementStore()
        ledgerStore = InMemoryLedgerJournalStore()
        ledgerService = LedgerPostingService(store = ledgerStore, clock = clock)
        registrationStore = InMemoryPlayerRegistrationStore()
        eligibilityStore = InMemoryServerEligibilityStore()

        gameService = DurableGameWagerAndSettlementService(
            store = gameStore,
            ledgerService = ledgerService,
            registrationStore = registrationStore,
            eligibilityStore = eligibilityStore,
            adminPrincipal = adminPrincipal,
            clock = clock
        )

        // Seed player registration as ACTIVE
        registrationStore.players[playerUuid] = PlayerRegistrationRecord(
            playerId = playerUuid,
            tenantId = tenantId,
            emailHash = "email-hash-1",
            phoneHash = "phone-hash-1",
            maskedEmail = "p***@test.com",
            maskedPhone = "+1***1234",
            jurisdiction = "DEFAULT",
            riskScore = 0.0,
            mfaRequired = false,
            status = PlayerAccountStatus.ACTIVE,
            createdAt = now.minusSeconds(86400),
            updatedAt = now.minusSeconds(86400)
        )

        // Seed compliance profile
        eligibilityStore.saveComplianceProfile(
            PlayerComplianceProfile(
                playerId = playerUuid,
                tenantId = tenantId,
                dateOfBirth = LocalDate.of(1995, 1, 1),
                kycStatus = KycComplianceStatus.VERIFIED,
                amlStatus = AmlComplianceStatus.CLEARED,
                jurisdiction = "DEFAULT",
                responsiblePlay = ResponsiblePlayProfile(
                    playerId = playerUuid,
                    selfExcluded = false,
                    singleWagerLimitMinor = 50000L,
                    dailyWagerLimitMinor = 200000L,
                    currentDailyWagerMinor = 0L
                )
            )
        )

        // Fund player ledger balance with 100,000 INR minor units
        ledgerService.postTransaction(
            PostTransactionCommand(
                principal = adminPrincipal,
                tenantId = tenantId,
                transactionReference = "TX-SEED-PLAYER-FAIRNESS",
                currencyCode = currency,
                entries = listOf(
                    JournalEntryDraft("HOUSE:SEED", JournalEntryDirection.DEBIT, 100000L, currency),
                    JournalEntryDraft("PLAYER:$playerIdStr", JournalEntryDirection.CREDIT, 100000L, currency)
                ),
                idempotencyKey = "IDEM-SEED-FAIRNESS-01",
                correlationId = "corr-seed",
                causationId = "caus-seed"
            )
        )
    }

    private fun seedRoundWithFairness(
        roundId: String,
        phase: GameRoundPhase = GameRoundPhase.BET_COUNTDOWN
    ): RoundCommitmentRecord {
        gameService.createOrUpdateRound(
            CreateOrUpdateRoundCommand(
                tenantId = tenantId,
                gameId = gameId,
                roundId = roundId,
                phase = phase,
                roundVersion = 1L
            )
        )
        return fairnessAuthority.publishPreBetCommitment(
            PublishCommitmentCommand(
                tenantId = tenantId,
                gameId = gameId,
                roundId = roundId,
                publicSalt = "salt-$roundId",
                algorithmVersion = "1.0.0",
                rulesVersion = "1.0.0"
            )
        )
    }

    // =========================================================================
    // Scenario 1: commit after bet attempt
    // =========================================================================

    @Test
    fun `scenario01 committing or modifying commitment after bet has been placed fails closed`() {
        val roundId = "rnd-fair-001"
        seedRoundWithFairness(roundId, phase = GameRoundPhase.BET_COUNTDOWN)

        // Player places a bet
        val betAck = gameService.processCommand(
            AviatorRestCommand(
                tenantId = tenantId,
                principal = playerPrincipal,
                commandId = "cmd-bet-fair-001",
                roundId = roundId,
                handId = "hand_primary",
                action = "PLACE_BET",
                wagerMinor = 2000L,
                currency = currency,
                correlationId = "corr-fair-001"
            )
        )
        assertEquals(AviatorCommandAckStatus.ACCEPTED, betAck.status)

        // Mark betting active on fairness authority
        fairnessAuthority.notifyBetAccepted(tenantId, gameId, roundId)

        // Attempting to publish a new commitment or replace commitment after bet accepted fails
        val ex = assertFailsWith<FairnessAuthorityException> {
            fairnessAuthority.publishPreBetCommitment(
                PublishCommitmentCommand(
                    tenantId = tenantId,
                    gameId = gameId,
                    roundId = roundId,
                    publicSalt = "salt-malicious-replacement",
                    algorithmVersion = "1.0.0",
                    rulesVersion = "1.0.0"
                )
            )
        }
        assertEquals("BETTING_ACTIVE_CANNOT_COMMIT", ex.errorCode)
    }

    // =========================================================================
    // Scenario 2: changed seed
    // =========================================================================

    @Test
    fun `scenario02 changed secret seed fails hash verification and raises alert`() {
        val roundId = "rnd-fair-002"
        val commitment = seedRoundWithFairness(roundId)

        // Settle round and reveal with tampered seed (e.g. attacker swapped secret seed)
        val tamperedSeed = "f".repeat(64) // Different 64-char hex seed

        val ex = assertFailsWith<FairnessVerificationException> {
            fairnessAuthority.revealAndVerifyOutcome(
                RevealOutcomeCommand(
                    tenantId = tenantId,
                    gameId = gameId,
                    roundId = roundId,
                    revealedSecretSeed = tamperedSeed
                )
            )
        }
        assertEquals("COMMITMENT_HASH_MISMATCH", ex.errorCode)

        val auditLogs = fairnessStore.findAuditEvents(tenantId, roundId)
        assertTrue(auditLogs.any { it.action == "FAIRNESS_VERIFICATION_FAILED" && it.detail.contains("tampered seed") })
    }

    // =========================================================================
    // Scenario 3: changed rules
    // =========================================================================

    @Test
    fun `scenario03 changed algorithm or rules version fails verification`() {
        val roundId = "rnd-fair-003"
        seedRoundWithFairness(roundId)

        val outcome = fairnessAuthority.deriveAuthoritativeOutcome(tenantId, gameId, roundId)
        val revealResult = fairnessAuthority.revealAndVerifyOutcome(
            RevealOutcomeCommand(
                tenantId = tenantId,
                gameId = gameId,
                roundId = roundId,
                revealedSecretSeed = outcome.secretSeed
            )
        )
        assertEquals(FairnessVerificationStatus.VERIFIED, revealResult.verificationStatus)

        // Independent historical verifier with modified rules version fails
        val verifier = IndependentFairnessVerifier(fairnessStore)
        val verifyWithWrongRules = verifier.verifyHistoricalRound(
            VerifyHistoricalRoundQuery(
                tenantId = tenantId,
                gameId = gameId,
                roundId = roundId,
                expectedAlgorithmVersion = "1.0.0",
                expectedRulesVersion = "2.0.0-unapproved" // Expected version differs!
            )
        )
        assertFalse(verifyWithWrongRules.isVerified)
        assertEquals("RULES_VERSION_MISMATCH", verifyWithWrongRules.failureCode)
    }

    // =========================================================================
    // Scenario 4: duplicate round
    // =========================================================================

    @Test
    fun `scenario04 duplicate commitment for same round is rejected`() {
        val roundId = "rnd-fair-004"
        seedRoundWithFairness(roundId)

        val ex = assertFailsWith<FairnessAuthorityException> {
            fairnessAuthority.publishPreBetCommitment(
                PublishCommitmentCommand(
                    tenantId = tenantId,
                    gameId = gameId,
                    roundId = roundId,
                    publicSalt = "salt-duplicate",
                    algorithmVersion = "1.0.0",
                    rulesVersion = "1.0.0"
                )
            )
        }
        assertEquals("DUPLICATE_ROUND_COMMITMENT", ex.errorCode)
    }

    // =========================================================================
    // Scenario 5: provider timeout
    // =========================================================================

    @Test
    fun `scenario05 provider timeout holds settlement and marks round in pending reconciliation`() {
        val roundId = "rnd-fair-005"
        seedRoundWithFairness(roundId)

        // Create delegated authority with simulated timeout
        val timeoutAuthority = object : ExternalFairnessProviderPort {
            override fun fetchOutcome(tenantId: String, gameId: String, roundId: String): ExternalOutcomeResult {
                throw ExternalFairnessProviderTimeoutException("External RNG provider timed out after 3000ms")
            }
        }

        val settlementResult = fairnessAuthority.executeProviderFairnessReconciliation(
            tenantId = tenantId,
            gameId = gameId,
            roundId = roundId,
            providerPort = timeoutAuthority
        )

        assertEquals(FairnessReconciliationStatus.HELD_PENDING_RECONCILIATION, settlementResult.status)
        assertTrue(settlementResult.safeMessage.contains("timed out", ignoreCase = true))

        val commitment = fairnessStore.findCommitment(tenantId, gameId, roundId)
        assertNotNull(commitment)
        assertEquals(RoundCommitmentStatus.LOCKED, commitment.status)
    }

    // =========================================================================
    // Scenario 6: missing reveal
    // =========================================================================

    @Test
    fun `scenario06 verification of unrevealed round returns pending reveal status without leaking secret`() {
        val roundId = "rnd-fair-006"
        seedRoundWithFairness(roundId)

        val verifier = IndependentFairnessVerifier(fairnessStore)
        val result = verifier.verifyHistoricalRound(
            VerifyHistoricalRoundQuery(
                tenantId = tenantId,
                gameId = gameId,
                roundId = roundId,
                expectedAlgorithmVersion = "1.0.0",
                expectedRulesVersion = "1.0.0"
            )
        )

        assertFalse(result.isVerified)
        assertEquals("ROUND_NOT_YET_REVEALED", result.failureCode)
        assertNull(result.revealedSecretSeed, "Unrevealed secret must NOT be leaked")
    }

    // =========================================================================
    // Scenario 7: restart
    // =========================================================================

    @Test
    fun `scenario07 persistent fairness records survive service restart`() {
        val roundId = "rnd-fair-007"
        val commitment = seedRoundWithFairness(roundId)
        val outcome = fairnessAuthority.deriveAuthoritativeOutcome(tenantId, gameId, roundId)
        fairnessAuthority.revealAndVerifyOutcome(
            RevealOutcomeCommand(
                tenantId = tenantId,
                gameId = gameId,
                roundId = roundId,
                revealedSecretSeed = outcome.secretSeed
            )
        )

        // Simulate restart: construct new instances reading from the persistent store
        val restartedAuthority = ProvablyFairOutcomeAuthority(store = fairnessStore, clock = clock)
        val restartedVerifier = IndependentFairnessVerifier(store = fairnessStore)

        val verifyAfterRestart = restartedVerifier.verifyHistoricalRound(
            VerifyHistoricalRoundQuery(
                tenantId = tenantId,
                gameId = gameId,
                roundId = roundId,
                expectedAlgorithmVersion = "1.0.0",
                expectedRulesVersion = "1.0.0"
            )
        )

        assertTrue(verifyAfterRestart.isVerified)
        assertEquals(commitment.commitmentHash, verifyAfterRestart.commitmentHash)
        assertEquals(outcome.multiplier, verifyAfterRestart.derivedMultiplier)
    }

    // =========================================================================
    // Scenario 8: key rotation
    // =========================================================================

    @Test
    fun `scenario08 key rotation produces distinct cryptographically unguessable seeds across rounds`() {
        val c1 = seedRoundWithFairness("rnd-rot-01")
        val c2 = seedRoundWithFairness("rnd-rot-02")
        val c3 = seedRoundWithFairness("rnd-rot-03")

        assertNotEquals(c1.commitmentHash, c2.commitmentHash)
        assertNotEquals(c2.commitmentHash, c3.commitmentHash)
        assertNotEquals(c1.commitmentHash, c3.commitmentHash)

        // Derive outcomes and check secret seeds are distinct 256-bit hex strings
        val o1 = fairnessAuthority.deriveAuthoritativeOutcome(tenantId, gameId, "rnd-rot-01")
        val o2 = fairnessAuthority.deriveAuthoritativeOutcome(tenantId, gameId, "rnd-rot-02")
        val o3 = fairnessAuthority.deriveAuthoritativeOutcome(tenantId, gameId, "rnd-rot-03")

        assertEquals(64, o1.secretSeed.length)
        assertEquals(64, o2.secretSeed.length)
        assertEquals(64, o3.secretSeed.length)

        assertNotEquals(o1.secretSeed, o2.secretSeed)
        assertNotEquals(o2.secretSeed, o3.secretSeed)
    }

    // =========================================================================
    // Scenario 9: historical verification
    // =========================================================================

    @Test
    fun `scenario09 independent verifier reproduces exact outcome from revealed seed and public salt`() {
        val roundId = "rnd-fair-009"
        val commitment = seedRoundWithFairness(roundId)

        val outcome = fairnessAuthority.deriveAuthoritativeOutcome(tenantId, gameId, roundId)
        val reveal = fairnessAuthority.revealAndVerifyOutcome(
            RevealOutcomeCommand(
                tenantId = tenantId,
                gameId = gameId,
                roundId = roundId,
                revealedSecretSeed = outcome.secretSeed
            )
        )

        val verifier = IndependentFairnessVerifier(fairnessStore)
        val verification = verifier.verifyHistoricalRound(
            VerifyHistoricalRoundQuery(
                tenantId = tenantId,
                gameId = gameId,
                roundId = roundId,
                expectedAlgorithmVersion = "1.0.0",
                expectedRulesVersion = "1.0.0"
            )
        )

        assertTrue(verification.isVerified)
        assertEquals(commitment.commitmentHash, verification.commitmentHash)
        assertEquals(outcome.multiplier, verification.derivedMultiplier)
        assertNotNull(verification.derivedMultiplier)
        assertTrue(verification.derivedMultiplier!! >= BigDecimal("1.0000"))
    }

    // =========================================================================
    // Scenario 10: invalid evidence
    // =========================================================================

    @Test
    fun `scenario10 tampered multiplier evidence is detected and fails verification`() {
        val roundId = "rnd-fair-010"
        val commitment = seedRoundWithFairness(roundId)
        val outcome = fairnessAuthority.deriveAuthoritativeOutcome(tenantId, gameId, roundId)

        // Store reveal with tampered multiplier (e.g. database altered to claim 100.00x instead of actual derived outcome)
        fairnessStore.saveReveal(
            RoundRevealRecord(
                revealId = UUID.randomUUID(),
                commitmentId = commitment.commitmentId,
                tenantId = tenantId,
                gameId = gameId,
                roundId = roundId,
                revealedSecretSeed = outcome.secretSeed,
                derivedMultiplier = BigDecimal("999.9900"), // Tampered! Actual was outcome.multiplier
                revealedAt = now,
                verificationStatus = FairnessVerificationStatus.VERIFIED,
                verificationError = null,
                evidenceReference = "ev-tampered"
            )
        )

        val verifier = IndependentFairnessVerifier(fairnessStore)
        val result = verifier.verifyHistoricalRound(
            VerifyHistoricalRoundQuery(
                tenantId = tenantId,
                gameId = gameId,
                roundId = roundId,
                expectedAlgorithmVersion = "1.0.0",
                expectedRulesVersion = "1.0.0"
            )
        )

        assertFalse(result.isVerified)
        assertEquals("OUTCOME_MULTIPLIER_TAMPERED", result.failureCode)
    }

    // =========================================================================
    // Scenario 11: Schema Migration & Constraints Validation
    // =========================================================================

    @Test
    fun `scenario11 V29 migration script exists and specifies all fairness invariants`() {
        val migrationFile = File("src/main/resources/db/migration/V29__outcome_bound_fairness_authority.sql")
        assertTrue(migrationFile.exists(), "V29 migration file must exist")

        val sql = migrationFile.readText()
        assertTrue(sql.contains("create table if not exists game_fairness_commitment"), "Must create game_fairness_commitment")
        assertTrue(sql.contains("create table if not exists game_fairness_reveal"), "Must create game_fairness_reveal")
        assertTrue(sql.contains("create table if not exists game_fairness_audit"), "Must create game_fairness_audit")
        assertTrue(sql.contains("unique (tenant_id, game_id, round_id)"), "Must enforce one commitment per round")
        assertTrue(sql.contains("foreign key (tenant_id, game_id, round_id) references game_authoritative_round"), "Must reference round")
    }
}
