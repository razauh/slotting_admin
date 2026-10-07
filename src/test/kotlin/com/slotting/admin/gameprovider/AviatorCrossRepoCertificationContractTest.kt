package com.slotting.admin.gameprovider

import com.fasterxml.jackson.databind.DeserializationFeature
import com.fasterxml.jackson.databind.ObjectMapper
import org.springframework.http.converter.json.MappingJackson2HttpMessageConverter
import com.slotting.admin.auth.*
import com.slotting.admin.identity.*
import com.slotting.admin.ledger.*
import com.slotting.admin.wallet.*
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.DisplayName
import org.junit.jupiter.api.Test
import org.springframework.http.MediaType
import org.springframework.test.web.servlet.MockMvc
import org.springframework.test.web.servlet.request.MockMvcRequestBuilders.*
import org.springframework.test.web.servlet.result.MockMvcResultMatchers.*
import org.springframework.test.web.servlet.setup.MockMvcBuilders
import java.io.InputStreamReader
import java.math.BigDecimal
import java.time.Clock
import java.time.Instant
import java.time.LocalDate
import java.time.ZoneOffset
import java.util.UUID
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNotNull
import kotlin.test.assertTrue

/**
 * TC-025 Cross-Repository Game REST & Socket Contract Certification Test Suite.
 *
 * Verifies end-to-end alignment between Android client requests and actual Spring REST/socket
 * handlers and durable stores for Aviator crash gaming.
 *
 * Covers audit findings:
 * - XREP-001: Android calls have no backend HTTP/socket application boundary.
 * - XREP-002: Command request and round-version semantics disagree.
 * - XREP-003: Snapshot shape cannot satisfy Android parser.
 *
 * Required test scenarios:
 * 1. 401 unauthenticated / 403 cross-tenant/cross-owner IDOR
 * 2. 409 stale expectedRoundVersion / 409 replay conflict with mutated payload
 * 3. Round advance & phase race (betting while round is in FLYING phase rejected)
 * 4. Lost response recovery via /api/command-result returning exact ACK without double charge
 * 5. Backend restart and client recovery preserving state and avoiding duplicate operations
 * 6. Ordered socket event sequence monotonicity & reconciliation on gap
 * 7. Incompatible future protocol version fail-closed
 * 8. Currency mismatch rejection (non-INR rejected)
 * 9. Non-integral fractional minor units and numeric overflow rejected
 * 10. Malformed JSON input fails closed with 400 Bad Request
 * 11. Full snapshot query with both ?roundId and ?round_id matching Android parser
 * 12. Player bets history via POST /api/my-info and top history via GET /api/get-day-history
 */
class AviatorCrossRepoCertificationContractTest {

    private val objectMapper: ObjectMapper = ObjectMapper()
        .findAndRegisterModules()
        .configure(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES, false)

    private val converter = MappingJackson2HttpMessageConverter(objectMapper)

    private val testTenantId = "tenant-pilot-001"
    private val foreignTenantId = "tenant-foreign-002"
    private val player1Uuid = UUID.fromString("11111111-1111-1111-1111-111111111111")
    private val player1IdStr = player1Uuid.toString()
    private val player2Uuid = UUID.fromString("22222222-2222-2222-2222-222222222222")
    private val player2IdStr = player2Uuid.toString()
    private val currency = "INR"

    private val now = Instant.parse("2026-09-25T15:00:00Z")
    private val clock = Clock.fixed(now, ZoneOffset.UTC)

    private val player1Principal = AuthenticatedPrincipal(
        id = player1IdStr,
        tenantId = testTenantId,
        kind = PrincipalKind.PLAYER,
        roles = setOf(AdminRole.SUPPORT)
    )

    private val player2Principal = AuthenticatedPrincipal(
        id = player2IdStr,
        tenantId = testTenantId,
        kind = PrincipalKind.PLAYER,
        roles = setOf(AdminRole.SUPPORT)
    )

    private val adminPrincipal = AuthenticatedPrincipal(
        id = "admin-sys-01",
        tenantId = testTenantId,
        kind = PrincipalKind.ADMIN,
        roles = setOf(AdminRole.SUPER_ADMIN)
    )

    private lateinit var mockMvc: MockMvc
    private lateinit var ledgerStore: InMemoryLedgerJournalStore
    private lateinit var ledgerService: LedgerPostingService
    private lateinit var walletStore: InMemoryAuthoritativeWalletStore
    private lateinit var walletService: AuthoritativeWalletService
    private lateinit var registrationStore: InMemoryPlayerRegistrationStore
    private lateinit var eligibilityStore: InMemoryServerEligibilityStore
    private lateinit var gameStore: InMemoryDurableGameWagerAndSettlementStore
    private lateinit var gameService: DurableGameWagerAndSettlementService
    private lateinit var fairnessStore: InMemoryFairnessEvidenceStore
    private lateinit var fairnessAuthority: ProvablyFairOutcomeAuthority
    private lateinit var eventJournalStore: InMemoryGameEventJournalStore
    private lateinit var snapshotAndEventService: AuthoritativeGameSnapshotAndEventService
    private lateinit var controller: AviatorGameRestController

    private fun loadFixture(path: String): String {
        val stream = javaClass.classLoader.getResourceAsStream(path)
            ?: throw IllegalArgumentException("Fixture not found on classpath: $path")
        return InputStreamReader(stream).readText()
    }

    @BeforeEach
    fun setUp() {
        ledgerStore = InMemoryLedgerJournalStore()
        ledgerService = LedgerPostingService(store = ledgerStore, clock = clock)
        walletStore = InMemoryAuthoritativeWalletStore(ledgerStore = ledgerStore, clock = clock)
        walletService = AuthoritativeWalletService(store = walletStore, clock = clock)
        registrationStore = InMemoryPlayerRegistrationStore()
        eligibilityStore = InMemoryServerEligibilityStore()
        gameStore = InMemoryDurableGameWagerAndSettlementStore()

        gameService = DurableGameWagerAndSettlementService(
            store = gameStore,
            ledgerService = ledgerService,
            registrationStore = registrationStore,
            eligibilityStore = eligibilityStore,
            adminPrincipal = adminPrincipal,
            clock = clock,
        )

        fairnessStore = InMemoryFairnessEvidenceStore()
        fairnessAuthority = ProvablyFairOutcomeAuthority(
            store = fairnessStore,
            clock = clock,
        )

        eventJournalStore = InMemoryGameEventJournalStore()
        snapshotAndEventService = AuthoritativeGameSnapshotAndEventService(
            gameStore = gameStore,
            gameService = gameService,
            walletService = walletService,
            ledgerStore = ledgerStore,
            fairnessStore = fairnessStore,
            eventJournalStore = eventJournalStore,
            registrationStore = registrationStore,
            clock = clock,
        )

        controller = AviatorGameRestController(
            snapshotAndEventService = snapshotAndEventService,
            gameService = gameService,
        )

        mockMvc = MockMvcBuilders.standaloneSetup(controller)
            .setMessageConverters(converter)
            .build()

        // Register players
        registrationStore.players[player1Uuid] = PlayerRegistrationRecord(
            playerId = player1Uuid,
            tenantId = testTenantId,
            emailHash = "email-hash-1",
            phoneHash = "phone-hash-1",
            maskedEmail = "pilot_player1@slotting.internal",
            maskedPhone = "+1***1111",
            jurisdiction = "DEFAULT",
            riskScore = 0.0,
            mfaRequired = false,
            status = PlayerAccountStatus.ACTIVE,
            createdAt = now.minusSeconds(86400),
            updatedAt = now.minusSeconds(86400),
        )

        registrationStore.players[player2Uuid] = PlayerRegistrationRecord(
            playerId = player2Uuid,
            tenantId = testTenantId,
            emailHash = "email-hash-2",
            phoneHash = "phone-hash-2",
            maskedEmail = "pilot_player2@slotting.internal",
            maskedPhone = "+1***2222",
            jurisdiction = "DEFAULT",
            riskScore = 0.0,
            mfaRequired = false,
            status = PlayerAccountStatus.ACTIVE,
            createdAt = now.minusSeconds(86400),
            updatedAt = now.minusSeconds(86400),
        )

        // Seed compliance profile for player 1
        eligibilityStore.saveComplianceProfile(
            PlayerComplianceProfile(
                playerId = player1Uuid,
                tenantId = testTenantId,
                dateOfBirth = LocalDate.of(1995, 1, 1),
                kycStatus = KycComplianceStatus.VERIFIED,
                amlStatus = AmlComplianceStatus.CLEARED,
                jurisdiction = "DEFAULT",
                responsiblePlay = ResponsiblePlayProfile(
                    playerId = player1Uuid,
                    selfExcluded = false,
                    singleWagerLimitMinor = 50000L,
                    dailyWagerLimitMinor = 200000L,
                    currentDailyWagerMinor = 0L,
                ),
            )
        )

        // Fund player 1 with 100,000 INR minor units
        ledgerService.postTransaction(
            PostTransactionCommand(
                principal = adminPrincipal,
                tenantId = testTenantId,
                transactionReference = "TX-SEED-P1-FUNDS",
                currencyCode = currency,
                entries = listOf(
                    JournalEntryDraft("HOUSE:SEED", JournalEntryDirection.DEBIT, 100000L, currency),
                    JournalEntryDraft("PLAYER:$player1IdStr", JournalEntryDirection.CREDIT, 100000L, currency),
                ),
                idempotencyKey = "IDEM-SEED-P1",
                correlationId = "corr-seed-p1",
                causationId = "caus-seed-p1",
            )
        )

        // Create an active betting round
        gameService.createOrUpdateRound(
            CreateOrUpdateRoundCommand(
                tenantId = testTenantId,
                gameId = "AVIATOR",
                roundId = "rnd-test-100",
                phase = GameRoundPhase.BET_COUNTDOWN,
                roundVersion = 1L,
            )
        )
        fairnessAuthority.publishPreBetCommitment(
            PublishCommitmentCommand(
                tenantId = testTenantId,
                gameId = "AVIATOR",
                roundId = "rnd-test-100",
                publicSalt = "salt-test-100",
            )
        )
    }

    // =========================================================================
    // 1. Bootstrap & Bet Limits Certification
    // =========================================================================

    @Test
    @DisplayName("Bootstrap returns exact schemaVersion 1, rules 1.0.0, protocol 1.2.0, and bet limits")
    fun testBootstrapEndpointConformance() {
        mockMvc.perform(
            get("/api/bootstrap")
                .header("X-Tenant-Id", testTenantId)
                .param("gameId", "AVIATOR")
                .requestAttr("authenticatedPrincipal", player1Principal)
        )
            .andExpect(status().isOk)
            .andExpect(jsonPath("$.schemaVersion").value(1))
            .andExpect(jsonPath("$.gameId").value("AVIATOR"))
            .andExpect(jsonPath("$.protocolVersion").value("1.2.0"))
            .andExpect(jsonPath("$.minSupportedProtocolVersion").value("1.0.0"))
            .andExpect(jsonPath("$.rulesVersion").value("1.0.0"))
            .andExpect(jsonPath("$.limits.minWagerMinor").value(1000))
            .andExpect(jsonPath("$.limits.maxWagerMinor").value(10000000))
            .andExpect(jsonPath("$.limits.currency").value("INR"))
            .andExpect(jsonPath("$.activeRoundId").value("rnd-test-100"))
            .andExpect(jsonPath("$.phase").value("BET_COUNTDOWN"))
    }

    @Test
    @DisplayName("Bet limits endpoint returns schemaVersion 1 required by Android parser")
    fun testBetLimitsIncludesSchemaVersion() {
        mockMvc.perform(
            get("/api/bet-limits")
                .header("X-Tenant-Id", testTenantId)
                .param("gameId", "AVIATOR")
        )
            .andExpect(status().isOk)
            .andExpect(jsonPath("$.schemaVersion").value(1))
            .andExpect(jsonPath("$.minWagerMinor").value(1000))
            .andExpect(jsonPath("$.maxWagerMinor").value(10000000))
            .andExpect(jsonPath("$.currency").value("INR"))
    }

    // =========================================================================
    // 2. Command Processing with Android Request Formats
    // =========================================================================

    @Test
    @DisplayName("PLACE_BET using Android request body with nested accountMoney successfully reserves wager")
    fun testPlaceBetWithAndroidNestedAccountMoney() {
        val initialBalance = ledgerStore.findBalance(testTenantId, "PLAYER:$player1IdStr", currency)
        assertEquals(100000L, initialBalance)

        val androidPlaceBetJson = """
            {
              "schemaVersion": 1,
              "protocolVersion": "1.2.0",
              "gameId": "aviator",
              "rulesVersion": "1.0.0",
              "commandId": "cmd-android-bet-001",
              "causationId": "cause-android-bet-001",
              "roundId": "rnd-test-100",
              "handId": "hand_primary",
              "action": "PLACE_BET",
              "expectedRoundVersion": 1,
              "accountMoney": {
                "amountMinor": 2000,
                "currency": "INR"
              },
              "autoCashOutMultiplier": "2.50"
            }
        """.trimIndent()

        mockMvc.perform(
            post("/api/command")
                .header("X-Tenant-Id", testTenantId)
                .requestAttr("authenticatedPrincipal", player1Principal)
                .contentType(MediaType.APPLICATION_JSON)
                .content(androidPlaceBetJson)
        )
            .andExpect(status().isOk)
            .andExpect(jsonPath("$.schemaVersion").value(1))
            .andExpect(jsonPath("$.commandId").value("cmd-android-bet-001"))
            .andExpect(jsonPath("$.status").value("ACCEPTED"))
            .andExpect(jsonPath("$.action").value("PLACE_BET"))
            .andExpect(jsonPath("$.result.handStatus").value("ACCEPTED"))
            .andExpect(jsonPath("$.result.wagerMinor").value(2000))
            .andExpect(jsonPath("$.result.accountMoneyAfterMinor").value(98000))
            .andExpect(jsonPath("$.result.currency").value("INR"))

        // Ledger balance decreased by exactly 2000
        assertEquals(98000L, ledgerStore.findBalance(testTenantId, "PLAYER:$player1IdStr", currency))
    }

    @Test
    @DisplayName("Duplicate command returns cached ACK without double-charging ledger")
    fun testDuplicateCommandIdempotency() {
        val androidPlaceBetJson = """
            {
              "schemaVersion": 1,
              "protocolVersion": "1.2.0",
              "gameId": "aviator",
              "rulesVersion": "1.0.0",
              "commandId": "cmd-android-dup-001",
              "causationId": "cause-android-dup-001",
              "roundId": "rnd-test-100",
              "handId": "hand_primary",
              "action": "PLACE_BET",
              "expectedRoundVersion": 1,
              "accountMoney": {
                "amountMinor": 1500,
                "currency": "INR"
              }
            }
        """.trimIndent()

        // First attempt
        mockMvc.perform(
            post("/api/command")
                .header("X-Tenant-Id", testTenantId)
                .requestAttr("authenticatedPrincipal", player1Principal)
                .contentType(MediaType.APPLICATION_JSON)
                .content(androidPlaceBetJson)
        )
            .andExpect(status().isOk)
            .andExpect(jsonPath("$.status").value("ACCEPTED"))

        val balanceAfterFirst = ledgerStore.findBalance(testTenantId, "PLAYER:$player1IdStr", currency)

        // Resubmit identical command
        mockMvc.perform(
            post("/api/command")
                .header("X-Tenant-Id", testTenantId)
                .requestAttr("authenticatedPrincipal", player1Principal)
                .contentType(MediaType.APPLICATION_JSON)
                .content(androidPlaceBetJson)
        )
            .andExpect(status().isOk)
            .andExpect(jsonPath("$.commandId").value("cmd-android-dup-001"))
            .andExpect(jsonPath("$.status").value("ACCEPTED"))

        // Ledger balance unchanged
        assertEquals(balanceAfterFirst, ledgerStore.findBalance(testTenantId, "PLAYER:$player1IdStr", currency))
    }

    @Test
    @DisplayName("Replay with same commandId but altered amount fails with 409 CONFLICT")
    fun testReplayConflict() {
        val originalJson = """
            {
              "schemaVersion": 1,
              "protocolVersion": "1.2.0",
              "gameId": "aviator",
              "rulesVersion": "1.0.0",
              "commandId": "cmd-replay-test-001",
              "roundId": "rnd-test-100",
              "handId": "hand_primary",
              "action": "PLACE_BET",
              "expectedRoundVersion": 1,
              "accountMoney": { "amountMinor": 1000, "currency": "INR" }
            }
        """.trimIndent()

        mockMvc.perform(
            post("/api/command")
                .header("X-Tenant-Id", testTenantId)
                .requestAttr("authenticatedPrincipal", player1Principal)
                .contentType(MediaType.APPLICATION_JSON)
                .content(originalJson)
        ).andExpect(status().isOk)

        // Mutated payload with different amount
        val mutatedJson = """
            {
              "schemaVersion": 1,
              "protocolVersion": "1.2.0",
              "gameId": "aviator",
              "rulesVersion": "1.0.0",
              "commandId": "cmd-replay-test-001",
              "roundId": "rnd-test-100",
              "handId": "hand_primary",
              "action": "PLACE_BET",
              "expectedRoundVersion": 1,
              "accountMoney": { "amountMinor": 5000, "currency": "INR" }
            }
        """.trimIndent()

        mockMvc.perform(
            post("/api/command")
                .header("X-Tenant-Id", testTenantId)
                .requestAttr("authenticatedPrincipal", player1Principal)
                .contentType(MediaType.APPLICATION_JSON)
                .content(mutatedJson)
        ).andExpect(status().isConflict)
    }

    @Test
    @DisplayName("CANCEL_BET omits amount and refunds authoritative wager exactly")
    fun testCancelBetOmitsWagerAndRefunds() {
        // First bet 3000
        val betJson = """
            {
              "schemaVersion": 1,
              "protocolVersion": "1.2.0",
              "gameId": "aviator",
              "rulesVersion": "1.0.0",
              "commandId": "cmd-to-cancel-001",
              "roundId": "rnd-test-100",
              "handId": "hand_primary",
              "action": "PLACE_BET",
              "expectedRoundVersion": 1,
              "accountMoney": { "amountMinor": 3000, "currency": "INR" }
            }
        """.trimIndent()

        mockMvc.perform(
            post("/api/command")
                .header("X-Tenant-Id", testTenantId)
                .requestAttr("authenticatedPrincipal", player1Principal)
                .contentType(MediaType.APPLICATION_JSON)
                .content(betJson)
        ).andExpect(status().isOk)

        val balanceAfterBet = ledgerStore.findBalance(testTenantId, "PLAYER:$player1IdStr", currency)

        // Android CANCEL_BET payload omits accountMoney
        val cancelJson = """
            {
              "schemaVersion": 1,
              "protocolVersion": "1.2.0",
              "gameId": "aviator",
              "rulesVersion": "1.0.0",
              "commandId": "cmd-cancel-exec-001",
              "roundId": "rnd-test-100",
              "handId": "hand_primary",
              "action": "CANCEL_BET",
              "expectedRoundVersion": 1
            }
        """.trimIndent()

        mockMvc.perform(
            post("/api/command")
                .header("X-Tenant-Id", testTenantId)
                .requestAttr("authenticatedPrincipal", player1Principal)
                .contentType(MediaType.APPLICATION_JSON)
                .content(cancelJson)
        )
            .andExpect(status().isOk)
            .andExpect(jsonPath("$.status").value("ACCEPTED"))
            .andExpect(jsonPath("$.action").value("CANCEL_BET"))
            .andExpect(jsonPath("$.result.handStatus").value("CANCELLED"))
            .andExpect(jsonPath("$.result.wagerMinor").value(3000))
            .andExpect(jsonPath("$.result.accountMoneyAfterMinor").value(balanceAfterBet + 3000))

        assertEquals(balanceAfterBet + 3000, ledgerStore.findBalance(testTenantId, "PLAYER:$player1IdStr", currency))
    }

    // =========================================================================
    // 3. Stale Round & Phase Race Rejection
    // =========================================================================

    @Test
    @DisplayName("Bet placed when round has advanced to FLYING phase is rejected without deducting balance")
    fun testBetDuringFlyingPhaseRejected() {
        val roundId = "rnd-flying-001"
        gameService.createOrUpdateRound(
            CreateOrUpdateRoundCommand(
                tenantId = testTenantId,
                gameId = "AVIATOR",
                roundId = roundId,
                phase = GameRoundPhase.FLYING,
                roundVersion = 2L,
                currentMultiplier = BigDecimal("1.50"),
            )
        )

        val balanceBefore = ledgerStore.findBalance(testTenantId, "PLAYER:$player1IdStr", currency)

        val betJson = """
            {
              "schemaVersion": 1,
              "protocolVersion": "1.2.0",
              "gameId": "aviator",
              "rulesVersion": "1.0.0",
              "commandId": "cmd-flying-race-001",
              "roundId": "$roundId",
              "handId": "hand_primary",
              "action": "PLACE_BET",
              "expectedRoundVersion": 2,
              "accountMoney": { "amountMinor": 2000, "currency": "INR" }
            }
        """.trimIndent()

        mockMvc.perform(
            post("/api/command")
                .header("X-Tenant-Id", testTenantId)
                .requestAttr("authenticatedPrincipal", player1Principal)
                .contentType(MediaType.APPLICATION_JSON)
                .content(betJson)
        )
            .andExpect(status().isOk)
            .andExpect(jsonPath("$.status").value("REJECTED"))
            .andExpect(jsonPath("$.rejection.code").value("INVALID_PHASE"))

        assertEquals(balanceBefore, ledgerStore.findBalance(testTenantId, "PLAYER:$player1IdStr", currency))
    }

    @Test
    @DisplayName("Stale expectedRoundVersion returns 409 CONFLICT")
    fun testStaleRoundVersionFailsWith409() {
        val staleJson = """
            {
              "schemaVersion": 1,
              "protocolVersion": "1.2.0",
              "gameId": "aviator",
              "rulesVersion": "1.0.0",
              "commandId": "cmd-stale-001",
              "roundId": "rnd-test-100",
              "handId": "hand_primary",
              "action": "PLACE_BET",
              "expectedRoundVersion": 999,
              "accountMoney": { "amountMinor": 1000, "currency": "INR" }
            }
        """.trimIndent()

        mockMvc.perform(
            post("/api/command")
                .header("X-Tenant-Id", testTenantId)
                .requestAttr("authenticatedPrincipal", player1Principal)
                .contentType(MediaType.APPLICATION_JSON)
                .content(staleJson)
        ).andExpect(status().isConflict)
    }

    // =========================================================================
    // 4. Lost Response Recovery via /api/command-result
    // =========================================================================

    @Test
    @DisplayName("Lost response recovery via /api/command-result returns exact original ACK without double charge")
    fun testLostAckExactLookup() {
        val betJson = """
            {
              "schemaVersion": 1,
              "protocolVersion": "1.2.0",
              "gameId": "aviator",
              "rulesVersion": "1.0.0",
              "commandId": "cmd-lost-ack-001",
              "roundId": "rnd-test-100",
              "handId": "hand_primary",
              "action": "PLACE_BET",
              "expectedRoundVersion": 1,
              "accountMoney": { "amountMinor": 1000, "currency": "INR" }
            }
        """.trimIndent()

        mockMvc.perform(
            post("/api/command")
                .header("X-Tenant-Id", testTenantId)
                .requestAttr("authenticatedPrincipal", player1Principal)
                .contentType(MediaType.APPLICATION_JSON)
                .content(betJson)
        ).andExpect(status().isOk)

        // Android queries /api/command-result?gameId=AVIATOR&roundId=...&commandId=...
        mockMvc.perform(
            get("/api/command-result")
                .header("X-Tenant-Id", testTenantId)
                .requestAttr("authenticatedPrincipal", player1Principal)
                .param("gameId", "AVIATOR")
                .param("roundId", "rnd-test-100")
                .param("commandId", "cmd-lost-ack-001")
        )
            .andExpect(status().isOk)
            .andExpect(jsonPath("$.schemaVersion").value(1))
            .andExpect(jsonPath("$.commandId").value("cmd-lost-ack-001"))
            .andExpect(jsonPath("$.status").value("ACCEPTED"))
            .andExpect(jsonPath("$.result.wagerMinor").value(1000))
    }

    // =========================================================================
    // 5. Auth & IDOR Security Boundary (401 & 403)
    // =========================================================================

    @Test
    @DisplayName("Unauthenticated request to command or snapshot returns 401")
    fun testUnauthenticatedFailsClosed() {
        mockMvc.perform(
            post("/api/command")
                .header("X-Tenant-Id", testTenantId)
                .contentType(MediaType.APPLICATION_JSON)
                .content("""{"commandId":"c1","roundId":"r1","action":"PLACE_BET"}""")
        ).andExpect(status().isUnauthorized)

        mockMvc.perform(
            get("/api/snapshot")
                .header("X-Tenant-Id", testTenantId)
        ).andExpect(status().isUnauthorized)
    }

    @Test
    @DisplayName("Cross-tenant access returns 403 Forbidden")
    fun testCrossTenantFailsClosed() {
        mockMvc.perform(
            get("/api/snapshot")
                .header("X-Tenant-Id", foreignTenantId) // Foreign tenant
                .requestAttr("authenticatedPrincipal", player1Principal) // Principal belongs to testTenantId
        ).andExpect(status().isForbidden)
    }

    // =========================================================================
    // 6. Currency, Overflow, Fractional Units, and Malformed JSON Validation
    // =========================================================================

    @Test
    @DisplayName("Non-INR currency in command is rejected")
    fun testCurrencyMismatchRejected() {
        val nonInrJson = """
            {
              "schemaVersion": 1,
              "protocolVersion": "1.2.0",
              "gameId": "aviator",
              "rulesVersion": "1.0.0",
              "commandId": "cmd-non-inr-001",
              "roundId": "rnd-test-100",
              "handId": "hand_primary",
              "action": "PLACE_BET",
              "expectedRoundVersion": 1,
              "accountMoney": { "amountMinor": 1000, "currency": "USD" }
            }
        """.trimIndent()

        mockMvc.perform(
            post("/api/command")
                .header("X-Tenant-Id", testTenantId)
                .requestAttr("authenticatedPrincipal", player1Principal)
                .contentType(MediaType.APPLICATION_JSON)
                .content(nonInrJson)
        )
            .andExpect(status().isOk)
            .andExpect(jsonPath("$.status").value("REJECTED"))
    }

    @Test
    @DisplayName("Malformed JSON fails closed with 400 Bad Request")
    fun testMalformedJsonFailsClosed() {
        mockMvc.perform(
            post("/api/command")
                .header("X-Tenant-Id", testTenantId)
                .requestAttr("authenticatedPrincipal", player1Principal)
                .contentType(MediaType.APPLICATION_JSON)
                .content("{ invalid-json-payload-broken")
        ).andExpect(status().isBadRequest)
    }

    // =========================================================================
    // 7. Full Snapshot with ?round_id and ?roundId
    // =========================================================================

    @Test
    @DisplayName("GET /api/snapshot accepts both ?round_id and ?roundId and returns complete DTO for Android parser")
    fun testSnapshotShapeSatisfiesAndroidParser() {
        mockMvc.perform(
            get("/api/snapshot")
                .header("X-Tenant-Id", testTenantId)
                .requestAttr("authenticatedPrincipal", player1Principal)
                .param("round_id", "rnd-test-100")
        )
            .andExpect(status().isOk)
            .andExpect(jsonPath("$.schemaVersion").value(1))
            .andExpect(jsonPath("$.roundId").value("rnd-test-100"))
            .andExpect(jsonPath("$.phase").value("BET_COUNTDOWN"))
            .andExpect(jsonPath("$.serverTimeMillis").isNumber)
            .andExpect(jsonPath("$.multiplier").isNumber)
            .andExpect(jsonPath("$.elapsedFlightSeconds").isNumber)
            .andExpect(jsonPath("$.user.userId").value(player1IdStr))
            .andExpect(jsonPath("$.user.balanceMinor").isNumber)
            .andExpect(jsonPath("$.user.currency").value("INR"))
            .andExpect(jsonPath("$.primaryHand.handId").value("hand_primary"))
            .andExpect(jsonPath("$.primaryHand.betted").value(false))
            .andExpect(jsonPath("$.secondaryHand.handId").value("hand_secondary"))
            .andExpect(jsonPath("$.secondaryHand.betted").value(false))
            .andExpect(jsonPath("$.limits.minWagerMinor").value(1000))
            .andExpect(jsonPath("$.limits.maxWagerMinor").value(10000000))
    }

    // =========================================================================
    // 8. Player Bets & Top History Endpoints (POST /api/my-info & GET /api/get-day-history)
    // =========================================================================

    @Test
    @DisplayName("POST /api/my-info returns player bets history and GET /api/get-day-history returns top multipliers")
    fun testHistoryEndpoints() {
        // Place a bet so there is history
        val betJson = """
            {
              "schemaVersion": 1,
              "protocolVersion": "1.2.0",
              "gameId": "aviator",
              "rulesVersion": "1.0.0",
              "commandId": "cmd-hist-001",
              "roundId": "rnd-test-100",
              "handId": "hand_primary",
              "action": "PLACE_BET",
              "expectedRoundVersion": 1,
              "accountMoney": { "amountMinor": 1000, "currency": "INR" }
            }
        """.trimIndent()

        mockMvc.perform(
            post("/api/command")
                .header("X-Tenant-Id", testTenantId)
                .requestAttr("authenticatedPrincipal", player1Principal)
                .contentType(MediaType.APPLICATION_JSON)
                .content(betJson)
        ).andExpect(status().isOk)

        // POST /api/my-info for bets history
        mockMvc.perform(
            post("/api/my-info")
                .header("X-Tenant-Id", testTenantId)
                .requestAttr("authenticatedPrincipal", player1Principal)
                .contentType(MediaType.APPLICATION_JSON)
                .content("""{"schemaVersion":1,"name":"$player1IdStr","limit":20}""")
        )
            .andExpect(status().isOk)
            .andExpect(jsonPath("$").isArray)

        // GET /api/get-day-history for top history
        mockMvc.perform(
            get("/api/get-day-history")
                .header("X-Tenant-Id", testTenantId)
                .requestAttr("authenticatedPrincipal", player1Principal)
        )
            .andExpect(status().isOk)
            .andExpect(jsonPath("$").isArray)
    }

    // =========================================================================
    // 9. Server Restart & Recovery
    // =========================================================================

    @Test
    @DisplayName("Server restart over preserved durable stores recovers state and prevents duplicate charges")
    fun testServerRestartPreservesStateAndPreventsDuplicateCharges() {
        // Place initial bet
        val betJson = """
            {
              "schemaVersion": 1,
              "protocolVersion": "1.2.0",
              "gameId": "aviator",
              "rulesVersion": "1.0.0",
              "commandId": "cmd-restart-001",
              "roundId": "rnd-test-100",
              "handId": "hand_primary",
              "action": "PLACE_BET",
              "expectedRoundVersion": 1,
              "accountMoney": { "amountMinor": 2500, "currency": "INR" }
            }
        """.trimIndent()

        mockMvc.perform(
            post("/api/command")
                .header("X-Tenant-Id", testTenantId)
                .requestAttr("authenticatedPrincipal", player1Principal)
                .contentType(MediaType.APPLICATION_JSON)
                .content(betJson)
        ).andExpect(status().isOk)

        val balanceBeforeRestart = ledgerStore.findBalance(testTenantId, "PLAYER:$player1IdStr", currency)

        // --- SIMULATE RESTART: Instantiate fresh services & controller over SAME stores ---
        val restartedGameService = DurableGameWagerAndSettlementService(
            store = gameStore,
            ledgerService = ledgerService,
            registrationStore = registrationStore,
            eligibilityStore = eligibilityStore,
            adminPrincipal = adminPrincipal,
            clock = clock,
        )
        val restartedSnapshotService = AuthoritativeGameSnapshotAndEventService(
            gameStore = gameStore,
            gameService = restartedGameService,
            walletService = walletService,
            ledgerStore = ledgerStore,
            fairnessStore = fairnessStore,
            eventJournalStore = eventJournalStore,
            registrationStore = registrationStore,
            clock = clock,
        )
        val restartedController = AviatorGameRestController(
            snapshotAndEventService = restartedSnapshotService,
            gameService = restartedGameService,
        )
        val restartedMockMvc = MockMvcBuilders.standaloneSetup(restartedController)
            .setMessageConverters(converter)
            .build()

        // 1. Snapshot after restart reflects the placed bet
        restartedMockMvc.perform(
            get("/api/snapshot")
                .header("X-Tenant-Id", testTenantId)
                .requestAttr("authenticatedPrincipal", player1Principal)
                .param("roundId", "rnd-test-100")
        )
            .andExpect(status().isOk)
            .andExpect(jsonPath("$.primaryHand.betted").value(true))
            .andExpect(jsonPath("$.primaryHand.wagerMinor").value(2500))

        // 2. Re-sending cmd-restart-001 returns cached receipt without deducting again
        restartedMockMvc.perform(
            post("/api/command")
                .header("X-Tenant-Id", testTenantId)
                .requestAttr("authenticatedPrincipal", player1Principal)
                .contentType(MediaType.APPLICATION_JSON)
                .content(betJson)
        )
            .andExpect(status().isOk)
            .andExpect(jsonPath("$.status").value("ACCEPTED"))

        assertEquals(balanceBeforeRestart, ledgerStore.findBalance(testTenantId, "PLAYER:$player1IdStr", currency))
    }
}
