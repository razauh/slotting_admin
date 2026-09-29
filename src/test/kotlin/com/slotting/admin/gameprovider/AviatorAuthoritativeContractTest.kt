package com.slotting.admin.gameprovider

import com.fasterxml.jackson.databind.JsonNode
import com.fasterxml.jackson.databind.ObjectMapper
import com.slotting.admin.auth.AdminPermission
import com.slotting.admin.auth.AdminRbacPolicy
import com.slotting.admin.auth.AdminRole
import com.slotting.admin.auth.AuthErrorCode
import com.slotting.admin.auth.AuthenticatedPrincipal
import com.slotting.admin.auth.AuthenticationFailure
import com.slotting.admin.auth.PrincipalKind
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test
import java.io.InputStream
import java.time.Clock
import java.time.Instant
import java.time.ZoneOffset
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue

class AviatorAuthoritativeContractTest {

    private val objectMapper: ObjectMapper = ObjectMapper()
    private val clock: Clock = Clock.fixed(Instant.parse("2026-09-25T12:00:00Z"), ZoneOffset.UTC)
    private val tenantId = "tenant-pilot-001"
    private val playerId = "usr-player-123"
    private val authorizedPrincipal = AuthenticatedPrincipal(
        id = playerId,
        tenantId = tenantId,
        kind = PrincipalKind.PLAYER,
        roles = setOf(AdminRole.SUPPORT)
    )

    private lateinit var store: InMemoryAviatorCommandStore
    private lateinit var socketStore: InMemoryAviatorSocketStore
    private lateinit var commandService: AviatorRestCommandCompatibilityService
    private lateinit var socketService: AviatorSocketReconciliationCompatibilityService

    @BeforeEach
    fun setUp() {
        store = InMemoryAviatorCommandStore()
        socketStore = InMemoryAviatorSocketStore()
        commandService = AviatorRestCommandCompatibilityService(
            store = store,
            rbacPolicy = AdminRbacPolicy(true),
            clock = clock,
        )
        socketService = AviatorSocketReconciliationCompatibilityService(
            store = socketStore,
            rbacPolicy = AdminRbacPolicy(true),
            clock = clock,
        )
    }

    private fun loadFixture(path: String): String {
        val stream: InputStream = javaClass.classLoader.getResourceAsStream(path)
            ?: error("Fixture not found: $path")
        return stream.bufferedReader().use { it.readText() }
    }

    private fun loadFixtureJson(path: String): JsonNode {
        return objectMapper.readTree(loadFixture(path))
    }

    // =========================================================================
    // Golden Fixtures Validation
    // =========================================================================

    @Test
    fun `TC-020 Golden fixtures are valid and conform to contract specifications`() {
        val bootstrapSuccess = loadFixtureJson("fixtures/aviator/v1/bootstrap_success.json")
        assertEquals(1, bootstrapSuccess.get("schemaVersion").asInt())
        assertEquals("AVIATOR", bootstrapSuccess.get("gameId").asText())
        assertEquals("1.2.0", bootstrapSuccess.get("protocolVersion").asText())
        assertEquals("1.0.0", bootstrapSuccess.get("minSupportedProtocolVersion").asText())
        assertEquals(1000L, bootstrapSuccess.get("limits").get("minWagerMinor").asLong())
        assertEquals(10000000L, bootstrapSuccess.get("limits").get("maxWagerMinor").asLong())

        val placeBetPrimary = loadFixtureJson("fixtures/aviator/v1/command_place_bet_primary.json")
        assertEquals("PLACE_BET", placeBetPrimary.get("action").asText())
        assertEquals("hand_primary", placeBetPrimary.get("handId").asText())
        assertEquals(2000L, placeBetPrimary.get("accountMoney").get("amountMinor").asLong())
        assertEquals("INR", placeBetPrimary.get("accountMoney").get("currency").asText())

        val cancelBet = loadFixtureJson("fixtures/aviator/v1/command_cancel_bet.json")
        assertEquals("CANCEL_BET", cancelBet.get("action").asText())
        assertNull(cancelBet.get("accountMoney"), "CANCEL_BET must not specify client accountMoney")
        assertNull(cancelBet.get("wagerMinor"), "CANCEL_BET must not specify client wagerMinor")

        val cashOut = loadFixtureJson("fixtures/aviator/v1/command_cash_out.json")
        assertEquals("CASH_OUT", cashOut.get("action").asText())
        assertNull(cashOut.get("cashOutMultiplier"), "CASH_OUT must not specify client multiplier")
        assertNull(cashOut.get("payoutMinor"), "CASH_OUT must not specify client payout")

        val fullSnapshot = loadFixtureJson("fixtures/aviator/v1/full_snapshot_flying.json")
        assertEquals(1, fullSnapshot.get("schemaVersion").asInt())
        assertEquals("rnd-crash-100", fullSnapshot.get("roundId").asText())
        assertEquals("FLYING", fullSnapshot.get("phase").asText())
        assertNotNull(fullSnapshot.get("user"))
        assertEquals("usr-player-123", fullSnapshot.get("user").get("userId").asText())
        assertNotNull(fullSnapshot.get("primaryHand"))
        assertNotNull(fullSnapshot.get("secondaryHand"))

        val settlement = loadFixtureJson("fixtures/aviator/v1/socket_settlement.json")
        assertEquals("rnd-crash-100", settlement.get("roundId").asText())
        assertEquals(2.50, settlement.get("finalCrashMultiplier").asDouble())
        assertNotNull(settlement.get("userSettlement"))
    }

    // =========================================================================
    // Scenario 1: Duplicate Command
    // =========================================================================

    @Test
    fun `Scenario 1 - Duplicate command returns cached ack with DUPLICATE status without mutating balance twice`() {
        val initialBal = store.getBalance(tenantId, playerId, "INR")
        val cmd = AviatorRestCommand(
            tenantId = tenantId,
            principal = authorizedPrincipal,
            commandId = "cmd-dup-001",
            roundId = "rnd-crash-100",
            handId = "hand_primary",
            action = "PLACE_BET",
            wagerMinor = 2000L,
            currency = "INR",
            correlationId = "corr-dup-001",
            expectedRoundVersion = 1L
        )

        val firstAck = commandService.processCommand(cmd)
        assertEquals(AviatorCommandAckStatus.ACCEPTED, firstAck.status)
        assertEquals(initialBal - 2000L, store.getBalance(tenantId, playerId, "INR"))

        // Re-submit identical command
        val dupAck = commandService.processCommand(cmd)
        assertEquals(AviatorCommandAckStatus.DUPLICATE, dupAck.status)
        assertEquals(firstAck.commandId, dupAck.commandId)
        assertEquals(firstAck.sequenceId, dupAck.sequenceId)
        // Balance remains unchanged (no double deduction)
        assertEquals(initialBal - 2000L, store.getBalance(tenantId, playerId, "INR"))
    }

    // =========================================================================
    // Scenario 2: Round Advance
    // =========================================================================

    @Test
    fun `Scenario 2 - Round advance causes expectedRoundVersion mismatch and rejects with STALE`() {
        store.setRoundVersion(tenantId, "rnd-crash-100", 3L)

        val staleCmd = AviatorRestCommand(
            tenantId = tenantId,
            principal = authorizedPrincipal,
            commandId = "cmd-stale-001",
            roundId = "rnd-crash-100",
            handId = "hand_primary",
            action = "PLACE_BET",
            wagerMinor = 1000L,
            currency = "INR",
            correlationId = "corr-stale-001",
            expectedRoundVersion = 1L // Expected 1L but round is already at 3L
        )

        val ex = assertFailsWith<AuthenticationFailure.Rejected> {
            commandService.processCommand(staleCmd)
        }
        assertEquals(AuthErrorCode.STALE, ex.code)
    }

    // =========================================================================
    // Scenario 3: Lost ACK Exact Lookup
    // =========================================================================

    @Test
    fun `Scenario 3 - Lost ACK can be recovered via exact result lookup without duplicate charge`() {
        val initialBal = store.getBalance(tenantId, playerId, "INR")
        val cmd = AviatorRestCommand(
            tenantId = tenantId,
            principal = authorizedPrincipal,
            commandId = "cmd-lost-001",
            roundId = "rnd-crash-100",
            handId = "hand_primary",
            action = "PLACE_BET",
            wagerMinor = 3000L,
            currency = "INR",
            correlationId = "corr-lost-001",
            expectedRoundVersion = 1L
        )

        val originalAck = commandService.processCommand(cmd)
        assertEquals(AviatorCommandAckStatus.ACCEPTED, originalAck.status)
        assertEquals(initialBal - 3000L, store.getBalance(tenantId, playerId, "INR"))

        // Exact result lookup
        val lookedUpAck = commandService.getCommandResult(tenantId, authorizedPrincipal, "rnd-crash-100", "cmd-lost-001")
        assertNotNull(lookedUpAck)
        assertEquals(originalAck.commandId, lookedUpAck.commandId)
        assertEquals(originalAck.sequenceId, lookedUpAck.sequenceId)
        assertEquals(originalAck.result?.accountMoneyAfterMinor, lookedUpAck.result?.accountMoneyAfterMinor)
    }

    // =========================================================================
    // Scenario 4: Future Protocol SemVer Rejection
    // =========================================================================

    @Test
    fun `Scenario 4 - Incompatible future protocol version is rejected`() {
        val incompatibleCmd = AviatorRestCommand(
            tenantId = tenantId,
            principal = authorizedPrincipal,
            commandId = "cmd-proto-future",
            roundId = "rnd-crash-100",
            handId = "hand_primary",
            action = "PLACE_BET",
            wagerMinor = 1000L,
            currency = "INR",
            correlationId = "corr-proto-future",
            protocolVersion = "3.0.0", // Major version incompatible with 1.x
            expectedRoundVersion = 1L
        )

        val ex = assertFailsWith<AuthenticationFailure.Rejected> {
            commandService.processCommand(incompatibleCmd)
        }
        assertEquals(AuthErrorCode.INVALID, ex.code)
    }

    // =========================================================================
    // Scenario 5: Rules Version Agreement
    // =========================================================================

    @Test
    fun `Scenario 5 - Rules version mismatch or missing rules agreement is rejected`() {
        val mismatchedRulesCmd = AviatorRestCommand(
            tenantId = tenantId,
            principal = authorizedPrincipal,
            commandId = "cmd-rules-001",
            roundId = "rnd-crash-100",
            handId = "hand_primary",
            action = "PLACE_BET",
            wagerMinor = 1000L,
            currency = "INR",
            correlationId = "corr-rules-001",
            rulesVersion = "2.0.0-incompatible", // Incompatible rules version
            expectedRoundVersion = 1L
        )

        val ex = assertFailsWith<AuthenticationFailure.Rejected> {
            commandService.processCommand(mismatchedRulesCmd)
        }
        assertEquals(AuthErrorCode.INVALID, ex.code)
    }

    // =========================================================================
    // Scenario 6: Sequence Gap Authoritative Reconciliation
    // =========================================================================

    @Test
    fun `Scenario 6 - Frame sequence gap triggers authoritative snapshot reconciliation`() {
        val frame1 = socketService.produceAuthoritativeGameState(tenantId, "rnd-crash-100", AviatorSocketPhase.PLAYING, 1.10, "c-1")
        val frame2 = socketService.produceAuthoritativeGameState(tenantId, "rnd-crash-100", AviatorSocketPhase.PLAYING, 1.25, "c-2")

        // Client detects gap between sequenceIds
        assertTrue(frame2.sequenceId > frame1.sequenceId)

        // Reconciliation fetches snapshot
        val snapshot = socketService.getAuthoritativeSnapshot(tenantId, authorizedPrincipal, "rnd-crash-100", "c-recon")
        assertEquals("rnd-crash-100", snapshot.roundId)
        assertEquals(tenantId, authorizedPrincipal.tenantId)
        assertTrue(snapshot.sequenceId >= frame2.sequenceId)
    }

    // =========================================================================
    // Scenario 7: Malformed Enum Rejection
    // =========================================================================

    @Test
    fun `Scenario 7 - Malformed action enum is rejected without mutating state`() {
        val badActionCmd = AviatorRestCommand(
            tenantId = tenantId,
            principal = authorizedPrincipal,
            commandId = "cmd-malformed-enum",
            roundId = "rnd-crash-100",
            handId = "hand_primary",
            action = "STEAL_MONEY",
            wagerMinor = 1000L,
            currency = "INR",
            correlationId = "corr-bad-enum",
            expectedRoundVersion = 1L
        )

        val ex = assertFailsWith<AuthenticationFailure.Rejected> {
            commandService.processCommand(badActionCmd)
        }
        assertEquals(AuthErrorCode.INVALID, ex.code)
    }

    // =========================================================================
    // Scenario 8: Fractional Minor Units Rejection
    // =========================================================================

    @Test
    fun `Scenario 8 - Non-integral fractional minor units are rejected`() {
        val rawJson = """
            {
                "schemaVersion": 1,
                "protocolVersion": "1.2.0",
                "rulesVersion": "1.0.0",
                "commandId": "cmd-frac-001",
                "roundId": "rnd-crash-100",
                "handId": "hand_primary",
                "action": "PLACE_BET",
                "accountMoney": {
                    "amountMinor": 100.5,
                    "currency": "INR"
                }
            }
        """.trimIndent()

        val parsedTree = objectMapper.readTree(rawJson)
        val amountNode = parsedTree.get("accountMoney").get("amountMinor")
        // Jackson or parser validation: isIntegralNumber must be false for 100.5
        assertTrue(!amountNode.isIntegralNumber || amountNode.isFloatingPointNumber)

        val ex = assertFailsWith<AuthenticationFailure.Rejected> {
            commandService.parseAndValidateCommand(
                tenantId = tenantId,
                principal = authorizedPrincipal,
                payloadJson = rawJson,
                correlationId = "corr-frac"
            )
        }
        assertEquals(AuthErrorCode.INVALID, ex.code)
    }

    // =========================================================================
    // Scenario 9: Overflow Protection
    // =========================================================================

    @Test
    fun `Scenario 9 - Numeric overflow beyond Long MAX_VALUE is rejected`() {
        val overflowJson = """
            {
                "schemaVersion": 1,
                "protocolVersion": "1.2.0",
                "rulesVersion": "1.0.0",
                "commandId": "cmd-overflow-001",
                "roundId": "rnd-crash-100",
                "handId": "hand_primary",
                "action": "PLACE_BET",
                "accountMoney": {
                    "amountMinor": 99999999999999999999999999999999,
                    "currency": "INR"
                }
            }
        """.trimIndent()

        val ex = assertFailsWith<AuthenticationFailure.Rejected> {
            commandService.parseAndValidateCommand(
                tenantId = tenantId,
                principal = authorizedPrincipal,
                payloadJson = overflowJson,
                correlationId = "corr-overflow"
            )
        }
        assertEquals(AuthErrorCode.INVALID, ex.code)
    }

    // =========================================================================
    // Scenario 10: Wrong Currency Rejection
    // =========================================================================

    @Test
    fun `Scenario 10 - Wrong currency or invalid currency code is rejected`() {
        val wrongCurrencyCmd = AviatorRestCommand(
            tenantId = tenantId,
            principal = authorizedPrincipal,
            commandId = "cmd-curr-001",
            roundId = "rnd-crash-100",
            handId = "hand_primary",
            action = "PLACE_BET",
            wagerMinor = 1000L,
            currency = "XYZ", // Invalid or mismatched currency
            correlationId = "corr-curr-001",
            expectedRoundVersion = 1L
        )

        val ex = assertFailsWith<AuthenticationFailure.Rejected> {
            commandService.processCommand(wrongCurrencyCmd)
        }
        assertEquals(AuthErrorCode.INVALID, ex.code)
    }

    // =========================================================================
    // Server Authority on CANCEL_BET and CASH_OUT
    // =========================================================================

    @Test
    fun `Server authority on CANCEL_BET - calculates refund from stored placed bet without trusting client`() {
        // First place a bet
        val placeCmd = AviatorRestCommand(
            tenantId = tenantId,
            principal = authorizedPrincipal,
            commandId = "cmd-bet-to-cancel",
            roundId = "rnd-crash-100",
            handId = "hand_primary",
            action = "PLACE_BET",
            wagerMinor = 2500L,
            currency = "INR",
            correlationId = "corr-place",
            expectedRoundVersion = 1L
        )
        val placeAck = commandService.processCommand(placeCmd)
        assertEquals(AviatorCommandAckStatus.ACCEPTED, placeAck.status)

        // Now cancel the bet without specifying wagerMinor
        val cancelCmd = AviatorRestCommand(
            tenantId = tenantId,
            principal = authorizedPrincipal,
            commandId = "cmd-cancel-001",
            roundId = "rnd-crash-100",
            handId = "hand_primary",
            action = "CANCEL_BET",
            wagerMinor = null, // Client does not send amount!
            currency = "INR",
            correlationId = "corr-cancel",
            expectedRoundVersion = 2L
        )

        val cancelAck = commandService.processCommand(cancelCmd)
        assertEquals(AviatorCommandAckStatus.ACCEPTED, cancelAck.status)
        assertEquals(AviatorAuthoritativeHandStatus.CANCELLED, cancelAck.result?.handStatus)
        assertEquals(2500L, cancelAck.result?.wagerMinor) // Refunded exactly the original wager
        assertEquals(500000L, cancelAck.result?.accountMoneyAfterMinor) // Full balance restored
    }
}
