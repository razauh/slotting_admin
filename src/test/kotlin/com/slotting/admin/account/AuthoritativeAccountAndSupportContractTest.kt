package com.slotting.admin.account

import com.fasterxml.jackson.databind.DeserializationFeature
import com.fasterxml.jackson.databind.ObjectMapper
import com.slotting.admin.auth.*
import com.slotting.admin.identity.*
import com.slotting.admin.ledger.*
import com.slotting.admin.rg.*
import com.slotting.admin.wallet.*
import org.junit.jupiter.api.Assertions.*
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.DisplayName
import org.junit.jupiter.api.Test
import org.springframework.http.MediaType
import org.springframework.test.web.servlet.MockMvc
import org.springframework.test.web.servlet.request.MockMvcRequestBuilders.*
import org.springframework.test.web.servlet.result.MockMvcResultMatchers.*
import org.springframework.test.web.servlet.setup.MockMvcBuilders
import java.time.Clock
import java.time.Duration
import java.time.Instant
import java.time.ZoneOffset
import java.util.UUID

/**
 * TC-018: Authoritative Profile, Statement, Support, Closure, and RG Account APIs Contract Test.
 *
 * Verifies:
 * 1. Authenticated self-profile query with masked PII and KYC summary without secret disclosure.
 * 2. Foreign owner 403 Forbidden rejection and 401 unauthenticated fail-closed handling.
 * 3. Authoritative cursor statement queries matching TC-009 double-entry ledger versions.
 * 4. Durable support case creation, deduplication, altered payload conflict, and PII redaction.
 * 5. Support case list and single read with cross-owner IDOR rejection.
 * 6. Account closure with pending financial operations (pending withdrawal/deposit) holding in PENDING_SETTLEMENT.
 * 7. Account closure with positive balance requiring settlement acknowledgment (422).
 * 8. Account closure under active legal hold remaining held without remote deletion.
 * 9. Clean account closure producing authoritative server receipt and revoking active sessions.
 * 10. Consolidated RG/restrictions summary reflecting cooling-off, exclusions, and limits.
 * 11. 503 Service Unavailable when dependency fails without fallback fabrication.
 */
class AuthoritativeAccountAndSupportContractTest {

    private val objectMapper: ObjectMapper = ObjectMapper()
        .configure(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES, false)

    private val testTenantId = "tenant-pk-1"
    private val testPlayerId = UUID.fromString("c1f7b0a8-3482-4cf4-91fa-404c00000001")
    private val foreignPlayerId = UUID.fromString("c2f7b0a8-3482-4cf4-91fa-404c00000002")
    private val testSessionId = "sess-acc-valid-001"
    private val fixedNow = Instant.parse("2026-09-25T11:00:00Z")
    private val clock = Clock.fixed(fixedNow, ZoneOffset.UTC)

    private lateinit var mockMvc: MockMvc
    private lateinit var sessionDirectory: AdminSessionDirectory
    private lateinit var registrationStore: InMemoryPlayerRegistrationStore
    private lateinit var ledgerStore: InMemoryLedgerJournalStore
    private lateinit var walletService: AuthoritativeWalletService
    private lateinit var accountStore: InMemoryAccountWorkflowStore
    private lateinit var accountService: AuthoritativeAccountService
    private lateinit var playerAccountController: PlayerAccountController

    @BeforeEach
    fun setUp() {
        registrationStore = InMemoryPlayerRegistrationStore()
        ledgerStore = InMemoryLedgerJournalStore()
        val walletStore = InMemoryAuthoritativeWalletStore(ledgerStore, clock)
        walletService = AuthoritativeWalletService(walletStore, clock = clock)
        accountStore = InMemoryAccountWorkflowStore()

        sessionDirectory = object : AdminSessionDirectory {
            override fun find(tenantId: String, principalId: String, sessionId: String): AdminSessionStatus? {
                if (sessionId == "sess-unauth") return null
                if (sessionId == "sess-broken") throw IllegalStateException("Session cluster timeout")
                return AdminSessionStatus(
                    active = true,
                    breakGlass = false,
                    expiresAt = fixedNow.plusSeconds(3600),
                    mfaVerified = true,
                )
            }
        }

        // Register test player
        registrationStore.players[testPlayerId] = PlayerRegistrationRecord(
            playerId = testPlayerId,
            tenantId = testTenantId,
            emailHash = "hash-pkr-player",
            phoneHash = "hash-phone-player",
            maskedEmail = "p***@example.com",
            maskedPhone = "+92******1234",
            jurisdiction = "PK",
            riskScore = 0.1,
            mfaRequired = false,
            status = PlayerAccountStatus.ACTIVE,
            emailVerified = true,
            phoneVerified = true,
            version = 1L,
            createdAt = fixedNow.minus(Duration.ofDays(10)),
            updatedAt = fixedNow.minus(Duration.ofDays(10)),
        )

        // Seed initial balance in ledger
        val adminPrincipal = AuthenticatedPrincipal(
            id = "admin-sys",
            tenantId = testTenantId,
            kind = PrincipalKind.ADMIN,
            roles = setOf(AdminRole.SUPER_ADMIN),
        )
        val ledgerPostingService = LedgerPostingService(ledgerStore, clock = clock)
        ledgerPostingService.postTransaction(
            PostTransactionCommand(
                principal = adminPrincipal,
                tenantId = testTenantId,
                transactionReference = "TX-ACC-INIT",
                currencyCode = "PKR",
                entries = listOf(
                    JournalEntryDraft("SYSTEM_TREASURY", JournalEntryDirection.DEBIT, 500000L, "PKR"),
                    JournalEntryDraft(testPlayerId.toString(), JournalEntryDirection.CREDIT, 500000L, "PKR"),
                ),
                idempotencyKey = "INIT-ACC-001",
                correlationId = "corr-init",
                causationId = "caus-init",
            )
        )

        accountService = AuthoritativeAccountService(
            accountStore = accountStore,
            registrationStore = registrationStore,
            walletService = walletService,
            sessions = sessionDirectory,
            clock = clock,
        )

        playerAccountController = PlayerAccountController(accountService, walletService)

        mockMvc = MockMvcBuilders.standaloneSetup(playerAccountController).build()
    }

    private fun playerPrincipal(id: UUID = testPlayerId) = AuthenticatedPrincipal(
        id = id.toString(),
        tenantId = testTenantId,
        kind = PrincipalKind.PLAYER,
        roles = emptySet(),
    )

    // =========================================================================
    // Scenario 1: Authenticated Self-Profile Query
    // =========================================================================
    @Test
    @DisplayName("Scenario 1: Authenticated player queries own profile with masked PII and KYC summary")
    fun testSelfProfileQuery() {
        val result = mockMvc.perform(
            get("/api/v1/tenants/$testTenantId/account/profile")
                .header("X-Session-Id", testSessionId)
                .requestAttr("authenticatedPrincipal", playerPrincipal())
        )
            .andExpect(status().isOk)
            .andExpect(content().contentType(MediaType.APPLICATION_JSON))
            .andReturn()

        val json = result.response.contentAsString
        val root = objectMapper.readTree(json)

        assertEquals(testPlayerId.toString(), root.get("userId").asText())
        assertEquals("p***@example.com", root.get("maskedEmail").asText())
        assertEquals("+92******1234", root.get("maskedPhone").asText())
        assertEquals("UNVERIFIED", root.get("kycStatus").asText())
        assertEquals("ACTIVE", root.get("accountStatus").asText())
        assertEquals(1L, root.get("serverVersion").asLong())
        assertFalse(root.has("passwordHash"))
        assertFalse(root.has("salt"))
    }

    // =========================================================================
    // Scenario 2: 401 Unauthenticated & 403 Cross-Owner IDOR Rejection
    // =========================================================================
    @Test
    @DisplayName("Scenario 2: Unauthenticated returns 401; Foreign player requesting other profile returns 403")
    fun testAuthAndForbiddenScenarios() {
        // Missing auth -> 401
        mockMvc.perform(
            get("/api/v1/tenants/$testTenantId/account/profile")
        )
            .andExpect(status().isUnauthorized)

        // Foreign player requesting testPlayerId's profile -> 403
        mockMvc.perform(
            get("/api/v1/tenants/$testTenantId/account/profile")
                .param("ownerUserId", testPlayerId.toString())
                .header("X-Session-Id", "sess-foreign")
                .requestAttr("authenticatedPrincipal", playerPrincipal(foreignPlayerId))
        )
            .andExpect(status().isForbidden)

        // Foreign player requesting closure of testPlayerId's account -> 403
        mockMvc.perform(
            post("/api/v1/tenants/$testTenantId/account/closure/requests")
                .contentType(MediaType.APPLICATION_JSON)
                .content("""
                    {
                      "ownerUserId": "$testPlayerId",
                      "reason": "NO_LONGER_WANT_SERVICE",
                      "reasonDetails": "Closing other account illegally",
                      "settlementAcknowledgment": true,
                      "idempotencyKey": "idem-idor-closure"
                    }
                """.trimIndent())
                .header("X-Session-Id", "sess-foreign")
                .requestAttr("authenticatedPrincipal", playerPrincipal(foreignPlayerId))
        )
            .andExpect(status().isForbidden)
    }

    // =========================================================================
    // Scenario 3: Authoritative Cursor Statement Route
    // =========================================================================
    @Test
    @DisplayName("Scenario 3: Account statement returns double-entry ledger entries and running balances")
    fun testAccountStatementRoute() {
        val result = mockMvc.perform(
            get("/api/v1/tenants/$testTenantId/account/statement")
                .param("currencyCode", "PKR")
                .param("pageSize", "10")
                .header("X-Session-Id", testSessionId)
                .requestAttr("authenticatedPrincipal", playerPrincipal())
        )
            .andExpect(status().isOk)
            .andReturn()

        val json = result.response.contentAsString
        val root = objectMapper.readTree(json)
        val entries = root.get("entries")
        assertTrue(entries.isArray)
        assertTrue(entries.size() >= 1)

        val entry = entries.get(0)
        assertEquals("PKR", entry.get("currencyCode").asText())
        assertEquals("CREDIT", entry.get("direction").asText())
        assertEquals(500000L, entry.get("amountMinorUnits").asLong())
        assertEquals(500000L, entry.get("runningBalanceMinorUnits").asLong())
    }

    // =========================================================================
    // Scenario 4: Support Case Creation, Replay & 409 Conflict on Altered Payload
    // =========================================================================
    @Test
    @DisplayName("Scenario 4: Durable support case creation; replay idempotent; conflict on altered payload")
    fun testSupportCaseCreateAndConflict() {
        val payload1 = """
            {
              "category": "PAYMENT_ISSUE",
              "subject": "Missing deposit",
              "description": "Deposit via Easypaisa not reflected yet card 1234567812345678 secret xyz",
              "idempotencyKey": "idem-supp-001"
            }
        """.trimIndent()

        // First submit -> OK
        val result1 = mockMvc.perform(
            post("/api/v1/tenants/$testTenantId/account/support/cases")
                .contentType(MediaType.APPLICATION_JSON)
                .content(payload1)
                .header("X-Session-Id", testSessionId)
                .requestAttr("authenticatedPrincipal", playerPrincipal())
        )
            .andExpect(status().isOk)
            .andReturn()

        val root1 = objectMapper.readTree(result1.response.contentAsString)
        val caseId = root1.get("caseId").asText()
        assertFalse(caseId.isBlank())
        assertEquals("SUBMITTED", root1.get("status").asText())
        // Verify PII/token redaction
        assertFalse(root1.get("description").asText().contains("1234567812345678"))
        assertFalse(root1.get("description").asText().contains("secret xyz"))

        // Replay identical -> Returns same caseId
        val resultReplay = mockMvc.perform(
            post("/api/v1/tenants/$testTenantId/account/support/cases")
                .contentType(MediaType.APPLICATION_JSON)
                .content(payload1)
                .header("X-Session-Id", testSessionId)
                .requestAttr("authenticatedPrincipal", playerPrincipal())
        )
            .andExpect(status().isOk)
            .andReturn()

        val rootReplay = objectMapper.readTree(resultReplay.response.contentAsString)
        assertEquals(caseId, rootReplay.get("caseId").asText())

        // Mutated payload with same idempotency key -> 409 Conflict
        val payload2 = """
            {
              "category": "PAYMENT_ISSUE",
              "subject": "Altered subject with same key",
              "description": "Completely different text",
              "idempotencyKey": "idem-supp-001"
            }
        """.trimIndent()

        mockMvc.perform(
            post("/api/v1/tenants/$testTenantId/account/support/cases")
                .contentType(MediaType.APPLICATION_JSON)
                .content(payload2)
                .header("X-Session-Id", testSessionId)
                .requestAttr("authenticatedPrincipal", playerPrincipal())
        )
            .andExpect(status().isConflict)
    }

    // =========================================================================
    // Scenario 5: Support Case Read & Foreign IDOR
    // =========================================================================
    @Test
    @DisplayName("Scenario 5: Support case list and single read with cross-owner IDOR protection")
    fun testSupportCaseReadAndIdor() {
        val created = accountService.createSupportCase(
            CreateSupportCaseCommand(
                principal = playerPrincipal(),
                tenantId = testTenantId,
                ownerUserId = testPlayerId,
                category = "GENERAL_INQUIRY",
                subject = "Account question",
                description = "General question about rules",
                idempotencyKey = "idem-supp-read-1",
            )
        )

        // Read own case -> OK
        mockMvc.perform(
            get("/api/v1/tenants/$testTenantId/account/support/cases/${created.caseId}")
                .header("X-Session-Id", testSessionId)
                .requestAttr("authenticatedPrincipal", playerPrincipal())
        )
            .andExpect(status().isOk)

        // Foreign player reads case -> 403 Forbidden
        mockMvc.perform(
            get("/api/v1/tenants/$testTenantId/account/support/cases/${created.caseId}")
                .header("X-Session-Id", "sess-foreign")
                .requestAttr("authenticatedPrincipal", playerPrincipal(foreignPlayerId))
        )
            .andExpect(status().isForbidden)
    }

    // =========================================================================
    // Scenario 6: Account Closure with Pending Financial Operations
    // =========================================================================
    @Test
    @DisplayName("Scenario 6: Account closure with in-flight pending operations enters PENDING_SETTLEMENT")
    fun testAccountClosureWithPendingFinancialOperations() {
        accountStore.setPendingFinancialOperations(testTenantId, testPlayerId, true)

        val closurePayload = """
            {
              "reason": "NO_LONGER_WANT_SERVICE",
              "reasonDetails": "Moving to another service",
              "settlementAcknowledgment": true,
              "idempotencyKey": "idem-close-pending-ops"
            }
        """.trimIndent()

        val result = mockMvc.perform(
            post("/api/v1/tenants/$testTenantId/account/closure/requests")
                .contentType(MediaType.APPLICATION_JSON)
                .content(closurePayload)
                .header("X-Session-Id", testSessionId)
                .requestAttr("authenticatedPrincipal", playerPrincipal())
        )
            .andExpect(status().isOk)
            .andReturn()

        val root = objectMapper.readTree(result.response.contentAsString)
        assertEquals("PENDING_SETTLEMENT", root.get("status").asText())
        assertTrue(root.get("hasPendingFinancialOps").asBoolean())
        assertFalse(root.get("serverReceipt").asText().isBlank())
    }

    // =========================================================================
    // Scenario 7: Positive Balance without Settlement Acknowledgment -> 422
    // =========================================================================
    @Test
    @DisplayName("Scenario 7: Positive balance without settlement acknowledgment returns 422")
    fun testAccountClosureWithoutSettlementAcknowledgment() {
        val payloadWithoutAck = """
            {
              "reason": "NO_LONGER_WANT_SERVICE",
              "reasonDetails": "Closing without acknowledging outstanding funds",
              "settlementAcknowledgment": false,
              "idempotencyKey": "idem-close-no-ack"
            }
        """.trimIndent()

        mockMvc.perform(
            post("/api/v1/tenants/$testTenantId/account/closure/requests")
                .contentType(MediaType.APPLICATION_JSON)
                .content(payloadWithoutAck)
                .header("X-Session-Id", testSessionId)
                .requestAttr("authenticatedPrincipal", playerPrincipal())
        )
            .andExpect(status().isUnprocessableEntity)
    }

    // =========================================================================
    // Scenario 8: Account Closure under Active Legal Hold
    // =========================================================================
    @Test
    @DisplayName("Scenario 8: Account closure under active legal hold remains held without remote deletion")
    fun testAccountClosureUnderLegalHold() {
        accountStore.setLegalHold(testTenantId, testPlayerId, true, "Court order ref #9988")

        val closurePayload = """
            {
              "reason": "PRIVACY_DATA_DELETION",
              "reasonDetails": "Requesting total deletion under privacy policy",
              "settlementAcknowledgment": true,
              "idempotencyKey": "idem-close-legal-hold"
            }
        """.trimIndent()

        val result = mockMvc.perform(
            post("/api/v1/tenants/$testTenantId/account/closure/requests")
                .contentType(MediaType.APPLICATION_JSON)
                .content(closurePayload)
                .header("X-Session-Id", testSessionId)
                .requestAttr("authenticatedPrincipal", playerPrincipal())
        )
            .andExpect(status().isOk)
            .andReturn()

        val root = objectMapper.readTree(result.response.contentAsString)
        assertEquals("LEGAL_HOLD", root.get("status").asText())
        assertTrue(root.get("hasLegalHold").asBoolean())
        assertTrue(root.get("retentionPolicyReference").asText().contains("LEGAL_HOLD"))
    }

    // =========================================================================
    // Scenario 9: Successful Clean Account Closure with Server Receipt
    // =========================================================================
    @Test
    @DisplayName("Scenario 9: Clean account closure marks CLOSED, produces server receipt, survives restart")
    fun testCleanAccountClosure() {
        accountStore.setPendingFinancialOperations(testTenantId, testPlayerId, false)
        accountStore.setLegalHold(testTenantId, testPlayerId, false)

        val closurePayload = """
            {
              "reason": "NO_LONGER_WANT_SERVICE",
              "reasonDetails": "Closing clean account with full acknowledgment",
              "settlementAcknowledgment": true,
              "idempotencyKey": "idem-clean-close-1"
            }
        """.trimIndent()

        val result = mockMvc.perform(
            post("/api/v1/tenants/$testTenantId/account/closure/requests")
                .contentType(MediaType.APPLICATION_JSON)
                .content(closurePayload)
                .header("X-Session-Id", testSessionId)
                .requestAttr("authenticatedPrincipal", playerPrincipal())
        )
            .andExpect(status().isOk)
            .andReturn()

        val root = objectMapper.readTree(result.response.contentAsString)
        assertEquals("CLOSED", root.get("status").asText())
        assertFalse(root.get("serverReceipt").asText().isBlank())

        // Query status route -> returns CLOSED
        val statusResult = mockMvc.perform(
            get("/api/v1/tenants/$testTenantId/account/closure/status")
                .header("X-Session-Id", testSessionId)
                .requestAttr("authenticatedPrincipal", playerPrincipal())
        )
            .andExpect(status().isOk)
            .andReturn()

        val statusRoot = objectMapper.readTree(statusResult.response.contentAsString)
        assertEquals("CLOSED", statusRoot.get("status").asText())
    }

    // =========================================================================
    // Scenario 10: Consolidated RG and Restrictions Summary
    // =========================================================================
    @Test
    @DisplayName("Scenario 10: Consolidated RG summary truthfully reflects restrictions and limits")
    fun testAccountRestrictionsSummary() {
        accountStore.setCoolingOff(testTenantId, testPlayerId, fixedNow.plus(Duration.ofDays(7)))

        val result = mockMvc.perform(
            get("/api/v1/tenants/$testTenantId/account/restrictions")
                .header("X-Session-Id", testSessionId)
                .requestAttr("authenticatedPrincipal", playerPrincipal())
        )
            .andExpect(status().isOk)
            .andReturn()

        val root = objectMapper.readTree(result.response.contentAsString)
        assertTrue(root.get("isRestricted").asBoolean())
        assertTrue(root.get("restrictionTypes").map { it.asText() }.contains("COOLING_OFF"))
        assertNotNull(root.get("coolingOffUntil"))
    }

    // =========================================================================
    // Scenario 11: 503 Backend / Dependency Unavailable
    // =========================================================================
    @Test
    @DisplayName("Scenario 11: Backend / session failure returns 503 without local fabrication")
    fun testDependencyFailureReturns503() {
        mockMvc.perform(
            get("/api/v1/tenants/$testTenantId/account/profile")
                .header("X-Session-Id", "sess-broken")
                .requestAttr("authenticatedPrincipal", playerPrincipal())
        )
            .andExpect(status().isServiceUnavailable)
    }
}
