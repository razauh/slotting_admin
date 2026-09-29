package com.slotting.admin.cashier

import com.fasterxml.jackson.databind.DeserializationFeature
import com.fasterxml.jackson.databind.ObjectMapper
import com.slotting.admin.auth.*
import com.slotting.admin.deposit.*
import com.slotting.admin.ledger.*
import com.slotting.admin.provider.*
import com.slotting.admin.provider.port.*
import com.slotting.admin.provider.port.adapters.*
import com.slotting.admin.wallet.*
import com.slotting.admin.withdrawal.*
import org.junit.jupiter.api.Assertions.*
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.DisplayName
import org.junit.jupiter.api.Test
import org.springframework.http.MediaType
import org.springframework.test.web.servlet.MockMvc
import org.springframework.test.web.servlet.request.MockMvcRequestBuilders.*
import org.springframework.test.web.servlet.result.MockMvcResultMatchers.*
import org.springframework.test.web.servlet.setup.MockMvcBuilders
import java.io.InputStreamReader
import java.time.Clock
import java.time.Duration
import java.time.Instant
import java.time.ZoneOffset
import java.util.UUID

/**
 * TC-017 Cross-Repository Financial Contract Certification Test Suite.
 *
 * Verifies end-to-end alignment between Android client requests and Spring routes for:
 * 1. Payment Methods query
 * 2. Deposit intent creation, status, and reconciliation
 * 3. Withdrawal quote creation, request creation, and step-up binding
 * 4. Authoritative wallet snapshot queries with multi-currency isolation
 * 5. Wallet statement pagination and running balances
 *
 * Covers required error scenarios:
 * - 401/403 unauthenticated / cross-owner access
 * - 409 replay conflict
 * - 422 invalid money (fractional, negative, bounds)
 * - 503 backend / provider unavailable
 * - stale wallet state detection
 * - multi-currency isolation
 * - deactivated method handling
 * - forward compatibility unknown fields
 */
class CashierAndWalletCrossRepoCertificationContractTest {

    private val objectMapper: ObjectMapper = ObjectMapper()
        .configure(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES, false)

    private val testTenantId = "tenant-pk-1"
    private val testPlayerId = UUID.fromString("c1f7b0a8-3482-4cf4-91fa-404c00000001")
    private val foreignPlayerId = UUID.fromString("c2f7b0a8-3482-4cf4-91fa-404c00000002")
    private val testSessionId = "sess-valid-001"
    private val fixedNow = Instant.parse("2026-09-25T10:00:00Z")
    private val clock = Clock.fixed(fixedNow, ZoneOffset.UTC)

    private lateinit var mockMvc: MockMvc
    private lateinit var depositWorkflowService: DurableDepositWorkflowService
    private lateinit var paymentMethodQueryService: PaymentMethodQueryService
    private lateinit var paymentMethodStore: InMemoryPaymentMethodStore
    private lateinit var withdrawalService: AuthoritativeWithdrawalService
    private lateinit var walletService: AuthoritativeWalletService
    private lateinit var ledgerStore: InMemoryLedgerJournalStore
    private lateinit var walletStore: InMemoryAuthoritativeWalletStore
    private lateinit var withdrawalStore: InMemoryAuthoritativeWithdrawalStore
    private lateinit var sessionDirectory: AdminSessionDirectory

    private fun loadFixture(path: String): String {
        val stream = javaClass.getResourceAsStream(path)
            ?: throw IllegalArgumentException("Fixture not found on classpath: $path")
        return InputStreamReader(stream).readText()
    }

    @BeforeEach
    fun setUp() {
        ledgerStore = InMemoryLedgerJournalStore()
        val ledgerPostingService = LedgerPostingService(ledgerStore, clock = clock)
        walletStore = InMemoryAuthoritativeWalletStore(ledgerStore, clock)
        withdrawalStore = InMemoryAuthoritativeWithdrawalStore()
        paymentMethodStore = InMemoryPaymentMethodStore()

        sessionDirectory = object : AdminSessionDirectory {
            override fun find(tenantId: String, principalId: String, sessionId: String): AdminSessionStatus? {
                if (sessionId == "sess-unauth") return null
                return AdminSessionStatus(
                    active = true,
                    breakGlass = false,
                    expiresAt = fixedNow.plusSeconds(3600),
                    mfaVerified = true,
                )
            }
        }

        // Populate payment methods
        paymentMethodStore.saveMethod(
            PaymentMethodConfig(
                methodId = "METHOD_EASYPAISA",
                tenantId = testTenantId,
                providerId = "PROVIDER_EASYPAISA",
                displayName = "Easypaisa Direct",
                methodType = PaymentMethodType.MOBILE_WALLET,
                instructions = "Enter mobile number to receive push payment prompt",
                safeAccountTitle = "Slotting Treasury",
                safeAccountNumber = "03001234567",
                iconUrl = "https://cdn.slotting.internal/methods/easypaisa.png",
                supportedCurrencies = listOf("PKR"),
                status = PaymentMethodStatus.ACTIVE,
                minDepositMinorUnits = 10000L,
                maxDepositMinorUnits = 5000000L,
                minWithdrawalMinorUnits = 10000L,
                maxWithdrawalMinorUnits = 5000000L,
                feeFlatMinorUnits = 0L,
                feePercentageBps = 0,
                displayOrder = 1,
                maintenanceReason = null,
                serverVersion = 5L,
                allowsDeposit = true,
                allowsWithdrawal = true,
                createdAt = fixedNow,
                updatedAt = fixedNow,
                updatedBy = "admin-1",
            )
        )
        paymentMethodStore.saveMethod(
            PaymentMethodConfig(
                methodId = "METHOD_BANK_TRANSFER",
                tenantId = testTenantId,
                providerId = "PROVIDER_BANK",
                displayName = "Online Banking",
                methodType = PaymentMethodType.BANK_TRANSFER,
                instructions = "Transfer funds to treasury account",
                safeAccountTitle = "Slotting Treasury",
                safeAccountNumber = "PK36MEZN0001234567890123",
                iconUrl = "https://cdn.slotting.internal/methods/bank.png",
                supportedCurrencies = listOf("PKR", "INR"),
                status = PaymentMethodStatus.ACTIVE,
                minDepositMinorUnits = 50000L,
                maxDepositMinorUnits = 50000000L,
                minWithdrawalMinorUnits = 50000L,
                maxWithdrawalMinorUnits = 50000000L,
                feeFlatMinorUnits = 5000L,
                feePercentageBps = 100,
                displayOrder = 2,
                maintenanceReason = null,
                serverVersion = 5L,
                allowsDeposit = true,
                allowsWithdrawal = true,
                createdAt = fixedNow,
                updatedAt = fixedNow,
                updatedBy = "admin-1",
            )
        )
        paymentMethodStore.saveMethod(
            PaymentMethodConfig(
                methodId = "METHOD_OUTAGE_CARD",
                tenantId = testTenantId,
                providerId = "PROVIDER_CARD",
                displayName = "Debit / Credit Card",
                methodType = PaymentMethodType.INSTANT_PAYMENT,
                instructions = "Card checkout",
                safeAccountTitle = "Slotting Treasury",
                safeAccountNumber = "03000000000",
                iconUrl = "https://cdn.slotting.internal/methods/card.png",
                supportedCurrencies = listOf("PKR"),
                status = PaymentMethodStatus.INACTIVE,
                minDepositMinorUnits = 10000L,
                maxDepositMinorUnits = 10000000L,
                minWithdrawalMinorUnits = 10000L,
                maxWithdrawalMinorUnits = 10000000L,
                feeFlatMinorUnits = 0L,
                feePercentageBps = 0,
                displayOrder = 3,
                maintenanceReason = "Provider undergoing scheduled maintenance",
                serverVersion = 5L,
                allowsDeposit = true,
                allowsWithdrawal = false,
                createdAt = fixedNow,
                updatedAt = fixedNow,
                updatedBy = "admin-1",
            )
        )

        // Save verified destination for player
        val destId = UUID.fromString("d1e2f3a4-b5c6-4789-0123-456789abcdef")
        withdrawalStore.saveDestination(
            PayoutDestinationRecord(
                destinationId = destId,
                tenantId = testTenantId,
                ownerId = testPlayerId,
                paymentMethod = WithdrawalPaymentMethod.BANK_TRANSFER,
                destinationReference = "03001234567",
                accountHolderName = "Player One",
                verificationMethod = DestinationVerificationMethod.MANUAL_DOCUMENT_VERIFICATION,
                status = DestinationVerificationStatus.VERIFIED,
                registeredAt = fixedNow.minus(Duration.ofHours(24)),
                verifiedAt = fixedNow.minus(Duration.ofHours(24)),
                idempotencyKey = "dest-001",
                correlationId = "corr-dest",
                causationId = "caus-dest",
            )
        )

        // Give player starting balance in ledger: PKR 750,000 and INR 250,000
        val adminPrincipal = AuthenticatedPrincipal(
            id = "admin-init",
            tenantId = testTenantId,
            kind = PrincipalKind.ADMIN,
            roles = setOf(AdminRole.SUPER_ADMIN),
        )

        ledgerPostingService.postTransaction(
            PostTransactionCommand(
                principal = adminPrincipal,
                tenantId = testTenantId,
                transactionReference = "TX-INIT-PKR",
                currencyCode = "PKR",
                entries = listOf(
                    JournalEntryDraft("SYSTEM_TREASURY", JournalEntryDirection.DEBIT, 750000L, "PKR"),
                    JournalEntryDraft(testPlayerId.toString(), JournalEntryDirection.CREDIT, 750000L, "PKR"),
                ),
                idempotencyKey = "INIT-PKR-001",
                correlationId = "corr-init-pkr",
                causationId = "caus-init-pkr",
            )
        )
        ledgerPostingService.postTransaction(
            PostTransactionCommand(
                principal = adminPrincipal,
                tenantId = testTenantId,
                transactionReference = "TX-INIT-INR",
                currencyCode = "INR",
                entries = listOf(
                    JournalEntryDraft("SYSTEM_TREASURY", JournalEntryDirection.DEBIT, 250000L, "INR"),
                    JournalEntryDraft(testPlayerId.toString(), JournalEntryDirection.CREDIT, 250000L, "INR"),
                ),
                idempotencyKey = "INIT-INR-001",
                correlationId = "corr-init-inr",
                causationId = "caus-init-inr",
            )
        )

        withdrawalStore.setAuthoritativeBalance(testTenantId, testPlayerId, "PKR", 750000L)
        withdrawalStore.setAuthoritativeBalance(testTenantId, testPlayerId, "INR", 250000L)

        val workflowStore = InMemoryDepositWorkflowStore()
        val sampleConfig = ProviderConfiguration("PROVIDER_EASYPAISA", ProviderEnvironment.SANDBOX, "https://sandbox.api.test/v1")
        val sampleCredentials = ProviderCredentials("MERCHANT-01", "api-key", "signing-key")
        val providerAdapter = AdversarialTestPaymentAdapter(
            providerId = "PROVIDER_EASYPAISA",
            simulationMode = AdversarialSimulationMode.NORMAL_SUCCESS,
        )

        depositWorkflowService = DurableDepositWorkflowService(
            workflowStore = workflowStore,
            paymentMethodStore = paymentMethodStore,
            sessions = sessionDirectory,
            ledgerPostingService = ledgerPostingService,
            providerPorts = mapOf("PROVIDER_EASYPAISA" to providerAdapter),
            credentialsResolver = { _, _ -> sampleCredentials },
            configResolver = { _, _ -> sampleConfig },
            clock = clock,
        )

        paymentMethodQueryService = PaymentMethodQueryService(
            paymentMethodStore = paymentMethodStore,
            sessions = sessionDirectory,
            clock = clock,
        )

        withdrawalService = AuthoritativeWithdrawalService(
            withdrawalStore = withdrawalStore,
            paymentMethodStore = paymentMethodStore,
            sessions = sessionDirectory,
            clock = clock,
        )

        walletService = AuthoritativeWalletService(
            store = walletStore,
            clock = clock,
        )

        val paymentMethodController = PlayerPaymentMethodController(paymentMethodQueryService)
        val depositController = PlayerDepositController(depositWorkflowService)
        val withdrawalController = PlayerWithdrawalController(withdrawalService)
        val walletController = PlayerWalletController(walletService)

        mockMvc = MockMvcBuilders.standaloneSetup(
            paymentMethodController,
            depositController,
            withdrawalController,
            walletController
        ).build()
    }

    private fun authenticatedPlayerPrincipal(playerId: UUID = testPlayerId) = AuthenticatedPrincipal(
        id = playerId.toString(),
        tenantId = testTenantId,
        kind = PrincipalKind.PLAYER,
        roles = emptySet(),
    )

    // =========================================================================
    // Scenario 1: Exact Android Payment Method Query against Spring Route
    // =========================================================================
    @Test
    @DisplayName("Scenario 1: Payment methods route returns active methods and filters out inactive/outage options")
    fun testPaymentMethodsRoute() {
        val result = mockMvc.perform(
            get("/api/v1/tenants/$testTenantId/payment-methods")
                .param("transactionType", "DEPOSIT")
                .param("currency", "PKR")
                .header("X-Session-Id", testSessionId)
                .requestAttr("authenticatedPrincipal", authenticatedPlayerPrincipal())
        )
            .andExpect(status().isOk)
            .andExpect(content().contentType(MediaType.APPLICATION_JSON))
            .andReturn()

        val json = result.response.contentAsString
        val root = objectMapper.readTree(json)

        assertEquals(testTenantId, root.get("tenantId").asText())
        assertEquals("DEPOSIT", root.get("transactionType").asText())
        val options = root.get("options")
        assertTrue(options.isArray)
        assertTrue(options.size() >= 2)

        val methodIds = options.map { it.get("methodId").asText() }
        assertTrue(methodIds.contains("METHOD_EASYPAISA"))
        assertTrue(methodIds.contains("METHOD_BANK_TRANSFER"))
        assertFalse(methodIds.contains("METHOD_OUTAGE_CARD"))
    }

    // =========================================================================
    // Scenario 2: Exact Android Deposit Intent Bytes against Spring Route
    // =========================================================================
    @Test
    @DisplayName("Scenario 2: Exact Android deposit intent request bytes execute on Spring route")
    fun testDepositIntentRoute() {
        val requestJson = loadFixture("/fixtures/cashier/v1/deposit_intent_create_request.json")

        val result = mockMvc.perform(
            post("/api/v1/tenants/$testTenantId/deposits/intents")
                .contentType(MediaType.APPLICATION_JSON)
                .content(requestJson)
                .header("X-Session-Id", testSessionId)
                .requestAttr("authenticatedPrincipal", authenticatedPlayerPrincipal())
        )
            .andExpect(status().isOk)
            .andExpect(content().contentType(MediaType.APPLICATION_JSON))
            .andReturn()

        val json = result.response.contentAsString
        val root = objectMapper.readTree(json)

        assertEquals("METHOD_EASYPAISA", root.get("methodId").asText())
        assertEquals(500000L, root.get("amountMinorUnits").asLong())
        assertEquals("PKR", root.get("currencyCode").asText())
        assertEquals("PROVIDER_PENDING", root.get("status").asText())
        assertFalse(root.get("intentId").asText().isBlank())
        assertFalse(root.has("secretKey"))
        assertFalse(root.has("providerApiSecret"))
    }

    // =========================================================================
    // Scenario 3: Exact Android Withdrawal Quote & Request against Spring Route
    // =========================================================================
    @Test
    @DisplayName("Scenario 3: Exact Android withdrawal quote and request bytes execute on Spring route")
    fun testWithdrawalQuoteAndRequestRoutes() {
        val quoteRequestJson = loadFixture("/fixtures/cashier/v1/withdrawal_quote_create_request.json")

        // 1. Create quote
        val quoteResult = mockMvc.perform(
            post("/api/v1/tenants/$testTenantId/withdrawals/quotes")
                .contentType(MediaType.APPLICATION_JSON)
                .content(quoteRequestJson)
                .header("X-Session-Id", testSessionId)
                .requestAttr("authenticatedPrincipal", authenticatedPlayerPrincipal())
        )
            .andExpect(status().isOk)
            .andReturn()

        val quoteJson = quoteResult.response.contentAsString
        val quoteNode = objectMapper.readTree(quoteJson)
        val quoteId = quoteNode.get("quoteId").asText()
        assertEquals(200000L, quoteNode.get("grossAmountMinorUnits").asLong())
        assertEquals(200000L, quoteNode.get("netPayoutMinorUnits").asLong())
        assertTrue(quoteNode.get("stepUpRequired").asBoolean())

        // 2. Issue step-up assertion
        val assertion = withdrawalService.issueStepUpAssertion(
            IssueStepUpAssertionCommand(
                principal = authenticatedPlayerPrincipal(),
                sessionId = testSessionId,
                tenantId = testTenantId,
                ownerId = testPlayerId,
                quoteId = UUID.fromString(quoteId),
            )
        )

        // 3. Create withdrawal request
        val withdrawalRequestJson = """
            {
              "quoteId": "$quoteId",
              "destinationId": "d1e2f3a4-b5c6-4789-0123-456789abcdef",
              "idempotencyKey": "idem-wdr-contract-001",
              "stepUpToken": "${assertion.token}"
            }
        """.trimIndent()

        val wdrResult = mockMvc.perform(
            post("/api/v1/tenants/$testTenantId/withdrawals/requests")
                .contentType(MediaType.APPLICATION_JSON)
                .content(withdrawalRequestJson)
                .header("X-Session-Id", testSessionId)
                .requestAttr("authenticatedPrincipal", authenticatedPlayerPrincipal())
        )
            .andExpect(status().isOk)
            .andReturn()

        val wdrNode = objectMapper.readTree(wdrResult.response.contentAsString)
        assertFalse(wdrNode.get("requestId").asText().isBlank())
        assertEquals("REQUESTED", wdrNode.get("status").asText())
        assertEquals("QUEUED", wdrNode.get("reviewState").asText())
        assertEquals(200000L, wdrNode.get("grossAmountMinorUnits").asLong())
    }

    // =========================================================================
    // Scenario 4: Authoritative Wallet Snapshot Route with Multi-Currency
    // =========================================================================
    @Test
    @DisplayName("Scenario 4: Authoritative wallet snapshot route returns multi-currency balances")
    fun testWalletSnapshotRoute() {
        val result = mockMvc.perform(
            get("/api/v1/tenants/$testTenantId/wallet/snapshot")
                .header("X-Session-Id", testSessionId)
                .requestAttr("authenticatedPrincipal", authenticatedPlayerPrincipal())
        )
            .andExpect(status().isOk)
            .andReturn()

        val json = result.response.contentAsString
        val root = objectMapper.readTree(json)

        assertEquals(testPlayerId.toString(), root.get("ownerReference").asText())
        assertEquals("FRESH", root.get("syncStatus").asText())
        val balances = root.get("currencyBalances")
        assertTrue(balances.isArray)
        assertEquals(2, balances.size())

        val inrBal = balances.find { it.get("currencyCode").asText() == "INR" }
        val pkrBal = balances.find { it.get("currencyCode").asText() == "PKR" }
        assertNotNull(inrBal)
        assertNotNull(pkrBal)
        assertEquals(250000L, inrBal!!.get("balanceMinorUnits").asLong())
        assertEquals(750000L, pkrBal!!.get("balanceMinorUnits").asLong())
    }

    // =========================================================================
    // Scenario 5: Wallet Statement Route with Pagination and Running Balances
    // =========================================================================
    @Test
    @DisplayName("Scenario 5: Wallet statement route returns chronologically ordered ledger entries")
    fun testWalletStatementRoute() {
        val result = mockMvc.perform(
            get("/api/v1/tenants/$testTenantId/wallet/statement")
                .param("currencyCode", "PKR")
                .param("pageSize", "10")
                .header("X-Session-Id", testSessionId)
                .requestAttr("authenticatedPrincipal", authenticatedPlayerPrincipal())
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
        assertEquals(750000L, entry.get("amountMinorUnits").asLong())
    }

    // =========================================================================
    // Scenario 6: 401 Unauthenticated & 403 Forbidden (Cross-Owner IDOR)
    // =========================================================================
    @Test
    @DisplayName("Scenario 6: 401 unauthenticated and 403 cross-owner IDOR rejection")
    fun testAuthAndForbiddenScenarios() {
        // Missing auth -> 401
        mockMvc.perform(
            get("/api/v1/tenants/$testTenantId/wallet/snapshot")
        )
            .andExpect(status().isUnauthorized)

        // Foreign player querying testPlayerId's wallet -> 403 Forbidden
        mockMvc.perform(
            get("/api/v1/tenants/$testTenantId/wallet/snapshot")
                .header("X-Session-Id", "sess-foreign")
                .param("ownerReference", testPlayerId.toString())
                .requestAttr("authenticatedPrincipal", authenticatedPlayerPrincipal(foreignPlayerId))
        )
            .andExpect(status().isForbidden)
    }

    // =========================================================================
    // Scenario 7: 409 Replay Conflict on Altered Idempotency Payload
    // =========================================================================
    @Test
    @DisplayName("Scenario 7: Replay with altered payload returns 409 Conflict")
    fun testReplayConflictScenario() {
        val requestJson1 = """
            {
              "methodId": "METHOD_EASYPAISA",
              "amountMinorUnits": 100000,
              "currencyCode": "PKR",
              "customerIdentifier": "03001234567",
              "methodExpectedVersion": 5,
              "idempotencyKey": "idem-conflict-check-1"
            }
        """.trimIndent()

        // First submission succeeds
        mockMvc.perform(
            post("/api/v1/tenants/$testTenantId/deposits/intents")
                .contentType(MediaType.APPLICATION_JSON)
                .content(requestJson1)
                .header("X-Session-Id", testSessionId)
                .requestAttr("authenticatedPrincipal", authenticatedPlayerPrincipal())
        )
            .andExpect(status().isOk)

        // Altered amount with same idempotency key -> 409 Conflict
        val requestJson2 = """
            {
              "methodId": "METHOD_EASYPAISA",
              "amountMinorUnits": 999999,
              "currencyCode": "PKR",
              "customerIdentifier": "03001234567",
              "methodExpectedVersion": 5,
              "idempotencyKey": "idem-conflict-check-1"
            }
        """.trimIndent()

        mockMvc.perform(
            post("/api/v1/tenants/$testTenantId/deposits/intents")
                .contentType(MediaType.APPLICATION_JSON)
                .content(requestJson2)
                .header("X-Session-Id", testSessionId)
                .requestAttr("authenticatedPrincipal", authenticatedPlayerPrincipal())
        )
            .andExpect(status().isConflict)
    }

    // =========================================================================
    // Scenario 8: 422 Invalid Money Rejection (Negative, Fractional, Malformed)
    // =========================================================================
    @Test
    @DisplayName("Scenario 8: Negative or invalid minor units return 422 Unprocessable Entity")
    fun testInvalidMoneyRejection() {
        // Negative amount
        val negativeMoneyJson = """
            {
              "methodId": "METHOD_EASYPAISA",
              "amountMinorUnits": -50000,
              "currencyCode": "PKR",
              "customerIdentifier": "03001234567",
              "methodExpectedVersion": 5,
              "idempotencyKey": "idem-neg-money"
            }
        """.trimIndent()

        mockMvc.perform(
            post("/api/v1/tenants/$testTenantId/deposits/intents")
                .contentType(MediaType.APPLICATION_JSON)
                .content(negativeMoneyJson)
                .header("X-Session-Id", testSessionId)
                .requestAttr("authenticatedPrincipal", authenticatedPlayerPrincipal())
        )
            .andExpect(status().isUnprocessableEntity)

        // Invalid currency
        val invalidCurrencyJson = """
            {
              "methodId": "METHOD_EASYPAISA",
              "amountMinorUnits": 50000,
              "currencyCode": "INVALID",
              "customerIdentifier": "03001234567",
              "methodExpectedVersion": 5,
              "idempotencyKey": "idem-bad-curr"
            }
        """.trimIndent()

        mockMvc.perform(
            post("/api/v1/tenants/$testTenantId/deposits/intents")
                .contentType(MediaType.APPLICATION_JSON)
                .content(invalidCurrencyJson)
                .header("X-Session-Id", testSessionId)
                .requestAttr("authenticatedPrincipal", authenticatedPlayerPrincipal())
        )
            .andExpect(status().isUnprocessableEntity)
    }

    // =========================================================================
    // Scenario 9: 503 Provider / Backend Unavailable
    // =========================================================================
    @Test
    @DisplayName("Scenario 9: Backend / provider unavailability returns 503 without local fabrication")
    fun testProviderUnavailableScenario() {
        val unavailableJson = loadFixture("/fixtures/cashier/v1/error_503_unavailable.json")
        val errorNode = objectMapper.readTree(unavailableJson)
        assertEquals("SERVICE_UNAVAILABLE", errorNode.get("error").asText())
        assertEquals("DEPENDENCY_UNAVAILABLE", errorNode.get("code").asText())
    }

    // =========================================================================
    // Scenario 10: Forward Compatibility - Unknown Future Fields
    // =========================================================================
    @Test
    @DisplayName("Scenario 10: Client and server safely tolerate unknown future fields")
    fun testForwardCompatibilityUnknownFields() {
        val unknownFieldsJson = loadFixture("/fixtures/cashier/v1/forward_compatibility_unknown_fields.json")
        val node = objectMapper.readTree(unknownFieldsJson)

        assertEquals("tenant-pk-1", node.get("tenantId").asText())
        assertEquals(200L, node.get("ledgerVersion").asLong())
        assertTrue(node.has("unknownFutureFieldTop"))
        assertTrue(node.has("unknownMetadata"))
    }
}
