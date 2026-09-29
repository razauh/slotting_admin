package com.slotting.admin.provider

import com.slotting.admin.auth.*
import com.slotting.admin.circuitbreaker.*
import org.junit.jupiter.api.Test
import java.time.Clock
import java.time.Duration
import java.time.Instant
import java.time.ZoneOffset
import java.util.UUID
import kotlin.test.*

/**
 * TC-011 TDD Contract Test Suite:
 * Expose server-approved active payment-method query.
 */
class PaymentMethodQueryContractTest {

    private val now = Instant.parse("2026-09-24T20:00:00Z")
    private val clock = Clock.fixed(now, ZoneOffset.UTC)

    private val playerPrincipal = AuthenticatedPrincipal(
        id = "player-pk-001",
        tenantId = "tenant-pk-1",
        kind = PrincipalKind.PLAYER,
        roles = emptySet(),
    )

    private val foreignPlayerPrincipal = AuthenticatedPrincipal(
        id = "player-other-002",
        tenantId = "tenant-pk-2",
        kind = PrincipalKind.PLAYER,
        roles = emptySet(),
    )

    private val sessionDir = object : AdminSessionDirectory {
        override fun find(tenantId: String, principalId: String, sessionId: String): AdminSessionStatus? {
            return when (sessionId) {
                "sess-valid" -> AdminSessionStatus(active = true, breakGlass = false, expiresAt = now.plus(Duration.ofHours(2)), mfaVerified = true)
                "sess-expired" -> AdminSessionStatus(active = true, breakGlass = false, expiresAt = now.minus(Duration.ofSeconds(30)), mfaVerified = true)
                "sess-inactive" -> AdminSessionStatus(active = false, breakGlass = false, expiresAt = now.plus(Duration.ofHours(2)), mfaVerified = true)
                "sess-crash" -> throw RuntimeException("Database timeout")
                else -> AdminSessionStatus(active = true, breakGlass = false, expiresAt = now.plus(Duration.ofHours(2)), mfaVerified = true)
            }
        }
    }

    private fun sampleMethod(
        methodId: String = "EASYPAISA",
        providerId: String = "provider-ep-1",
        displayName: String = "Easypaisa Mobile Account",
        methodType: PaymentMethodType = PaymentMethodType.MOBILE_WALLET,
        supportedCurrencies: List<String> = listOf("PKR"),
        allowsDeposit: Boolean = true,
        allowsWithdrawal: Boolean = true,
        minDeposit: Long = 10_000L, // 100 PKR
        maxDeposit: Long = 5_000_000L, // 50,000 PKR
        minWithdrawal: Long = 10_000L,
        maxWithdrawal: Long = 2_500_000L,
        feeFlat: Long = 500L,
        feeBps: Int = 150,
        status: PaymentMethodStatus = PaymentMethodStatus.ACTIVE,
        maintenanceReason: String? = null,
        serverVersion: Long = 1L,
        displayOrder: Int = 1,
        tenantId: String = "tenant-pk-1",
    ) = PaymentMethodConfig(
        tenantId = tenantId,
        methodId = methodId,
        providerId = providerId,
        methodType = methodType,
        displayName = displayName,
        instructions = "Transfer to mobile account and enter transaction ID.",
        safeAccountTitle = "Official Merchant Wallet",
        safeAccountNumber = "03001234567",
        iconUrl = "https://cdn.example.com/easypaisa.png",
        supportedCurrencies = supportedCurrencies,
        allowsDeposit = allowsDeposit,
        allowsWithdrawal = allowsWithdrawal,
        minDepositMinorUnits = minDeposit,
        maxDepositMinorUnits = maxDeposit,
        minWithdrawalMinorUnits = minWithdrawal,
        maxWithdrawalMinorUnits = maxWithdrawal,
        feeFlatMinorUnits = feeFlat,
        feePercentageBps = feeBps,
        displayOrder = displayOrder,
        status = status,
        maintenanceReason = maintenanceReason,
        serverVersion = serverVersion,
        createdAt = now,
        updatedAt = now,
        updatedBy = "admin-1",
    )

    private fun createStoreWithMethods(vararg methods: PaymentMethodConfig): InMemoryPaymentMethodStore {
        val store = InMemoryPaymentMethodStore()
        for (m in methods) {
            val result = PaymentMethodResult(
                resultId = UUID.randomUUID(),
                method = m,
                serverTime = now,
                evidenceReference = "ev-${m.methodId}",
            )
            val audit = AuditEvent(UUID.randomUUID(), result.resultId, m.tenantId, "INIT", now, "c-1", "ca-1")
            val outbox = OutboxEvent(UUID.randomUUID(), result.resultId, m.tenantId, "INIT", now)
            store.save(result, "fp-${m.methodId}", "idem-${m.methodId}", PaymentMethodAction.REGISTER, "init", "admin", audit, outbox)
        }
        return store
    }

    // =========================================================================
    // 1. Authentication, Tenant, and Session Validation
    // =========================================================================

    @Test
    fun `test01 query rejects unauthenticated, expired, or foreign tenant sessions`() {
        val store = createStoreWithMethods(sampleMethod())
        val service = PaymentMethodQueryService(
            paymentMethodStore = store,
            sessions = sessionDir,
            clock = clock,
        )

        // 1. Unauthenticated
        assertFailsWith<AuthenticationFailure.Rejected> {
            service.query(PaymentMethodQuery(
                principal = null,
                sessionId = "sess-valid",
                tenantId = "tenant-pk-1",
                transactionType = TransactionType.DEPOSIT,
            ))
        }.also { assertEquals(AuthErrorCode.UNAUTHENTICATED, it.code) }

        // 2. Foreign tenant
        assertFailsWith<AuthenticationFailure.Rejected> {
            service.query(PaymentMethodQuery(
                principal = foreignPlayerPrincipal,
                sessionId = "sess-valid",
                tenantId = "tenant-pk-1",
                transactionType = TransactionType.DEPOSIT,
            ))
        }.also { assertEquals(AuthErrorCode.FORBIDDEN, it.code) }

        // 3. Expired session
        assertFailsWith<AuthenticationFailure.Rejected> {
            service.query(PaymentMethodQuery(
                principal = playerPrincipal,
                sessionId = "sess-expired",
                tenantId = "tenant-pk-1",
                transactionType = TransactionType.DEPOSIT,
            ))
        }.also { assertEquals(AuthErrorCode.FORBIDDEN, it.code) }

        // 4. Inactive session
        assertFailsWith<AuthenticationFailure.Rejected> {
            service.query(PaymentMethodQuery(
                principal = playerPrincipal,
                sessionId = "sess-inactive",
                tenantId = "tenant-pk-1",
                transactionType = TransactionType.DEPOSIT,
            ))
        }.also { assertEquals(AuthErrorCode.FORBIDDEN, it.code) }

        // 5. Dependency failure / database crash
        assertFailsWith<AuthenticationFailure.Rejected> {
            service.query(PaymentMethodQuery(
                principal = playerPrincipal,
                sessionId = "sess-crash",
                tenantId = "tenant-pk-1",
                transactionType = TransactionType.DEPOSIT,
            ))
        }.also { assertEquals(AuthErrorCode.DEPENDENCY_UNAVAILABLE, it.code) }
    }

    // =========================================================================
    // 2. Active vs Inactive / Maintenance Methods & Safe Explanation
    // =========================================================================

    @Test
    fun `test02 query returns only active permitted methods and excludes inactive or maintenance methods by default`() {
        val activeEp = sampleMethod("EASYPAISA", status = PaymentMethodStatus.ACTIVE, displayOrder = 1)
        val inactiveJc = sampleMethod("JAZZCASH", status = PaymentMethodStatus.INACTIVE, displayOrder = 2)
        val maintenanceBt = sampleMethod(
            "BANK_TRANSFER",
            status = PaymentMethodStatus.MAINTENANCE,
            maintenanceReason = "Bank 1link maintenance",
            displayOrder = 3,
        )

        val store = createStoreWithMethods(activeEp, inactiveJc, maintenanceBt)
        val service = PaymentMethodQueryService(store, sessions = sessionDir, clock = clock)

        // Default query: returns only selectable active methods
        val response = service.query(PaymentMethodQuery(
            principal = playerPrincipal,
            sessionId = "sess-valid",
            tenantId = "tenant-pk-1",
            transactionType = TransactionType.DEPOSIT,
        ))

        assertEquals(1, response.options.size)
        assertEquals("EASYPAISA", response.options[0].methodId)
        assertTrue(response.options[0].isSelectable)
        assertEquals(MethodAvailabilityCode.AVAILABLE, response.options[0].availabilityCode)
        assertEquals(1, response.eligibleCount)
        assertEquals(2, response.filteredCount)

        // When includeUnavailable is true: returns all methods with safe explanation
        val explainedResponse = service.query(PaymentMethodQuery(
            principal = playerPrincipal,
            sessionId = "sess-valid",
            tenantId = "tenant-pk-1",
            transactionType = TransactionType.DEPOSIT,
            includeUnavailable = true,
        ))

        assertEquals(3, explainedResponse.options.size)
        val jc = explainedResponse.options.first { it.methodId == "JAZZCASH" }
        assertFalse(jc.isSelectable)
        assertEquals(MethodAvailabilityCode.INACTIVE, jc.availabilityCode)

        val bt = explainedResponse.options.first { it.methodId == "BANK_TRANSFER" }
        assertFalse(bt.isSelectable)
        assertEquals(MethodAvailabilityCode.MAINTENANCE, bt.availabilityCode)
        assertEquals("Bank 1link maintenance", bt.availabilityReason)
    }

    // =========================================================================
    // 3. Deposit vs Withdrawal Capability Filtering
    // =========================================================================

    @Test
    fun `test03 query filters by transaction type deposit versus withdrawal`() {
        val depositOnly = sampleMethod("DEPOSIT_ONLY", allowsDeposit = true, allowsWithdrawal = false)
        val withdrawOnly = sampleMethod("WITHDRAW_ONLY", allowsDeposit = false, allowsWithdrawal = true)
        val biDirectional = sampleMethod("BIDIRECTIONAL", allowsDeposit = true, allowsWithdrawal = true)

        val store = createStoreWithMethods(depositOnly, withdrawOnly, biDirectional)
        val service = PaymentMethodQueryService(store, sessions = sessionDir, clock = clock)

        // Deposit query
        val depositResponse = service.query(PaymentMethodQuery(
            principal = playerPrincipal,
            sessionId = "sess-valid",
            tenantId = "tenant-pk-1",
            transactionType = TransactionType.DEPOSIT,
        ))
        assertEquals(setOf("DEPOSIT_ONLY", "BIDIRECTIONAL"), depositResponse.options.map { it.methodId }.toSet())

        // Withdrawal query
        val withdrawalResponse = service.query(PaymentMethodQuery(
            principal = playerPrincipal,
            sessionId = "sess-valid",
            tenantId = "tenant-pk-1",
            transactionType = TransactionType.WITHDRAWAL,
        ))
        assertEquals(setOf("WITHDRAW_ONLY", "BIDIRECTIONAL"), withdrawalResponse.options.map { it.methodId }.toSet())
    }

    // =========================================================================
    // 4. Currency Filtering and Unsupported Currencies
    // =========================================================================

    @Test
    fun `test04 query filters by currency and rejects malformed currency format`() {
        val pkrMethod = sampleMethod("EASYPAISA", supportedCurrencies = listOf("PKR"))
        val usdMethod = sampleMethod("CRYPTO_USD", supportedCurrencies = listOf("USD"))

        val store = createStoreWithMethods(pkrMethod, usdMethod)
        val service = PaymentMethodQueryService(store, sessions = sessionDir, clock = clock)

        // Filter by PKR
        val pkrResponse = service.query(PaymentMethodQuery(
            principal = playerPrincipal,
            sessionId = "sess-valid",
            tenantId = "tenant-pk-1",
            transactionType = TransactionType.DEPOSIT,
            currency = "PKR",
        ))
        assertEquals(listOf("EASYPAISA"), pkrResponse.options.map { it.methodId })

        // Filter by USD
        val usdResponse = service.query(PaymentMethodQuery(
            principal = playerPrincipal,
            sessionId = "sess-valid",
            tenantId = "tenant-pk-1",
            transactionType = TransactionType.DEPOSIT,
            currency = "USD",
        ))
        assertEquals(listOf("CRYPTO_USD"), usdResponse.options.map { it.methodId })

        // Malformed currency
        assertFailsWith<AuthenticationFailure.Rejected> {
            service.query(PaymentMethodQuery(
                principal = playerPrincipal,
                sessionId = "sess-valid",
                tenantId = "tenant-pk-1",
                transactionType = TransactionType.DEPOSIT,
                currency = "pkr1",
            ))
        }.also { assertEquals(AuthErrorCode.INVALID, it.code) }
    }

    // =========================================================================
    // 5. Amount Bounds and Fee Rules Calculation
    // =========================================================================

    @Test
    fun `test05 query validates amount bounds, calculates fees, and handles negative or overflow amounts`() {
        val method = sampleMethod(
            methodId = "EASYPAISA",
            minDeposit = 10_000L, // 100.00 PKR
            maxDeposit = 5_000_000L, // 50,000.00 PKR
            feeFlat = 500L, // 5.00 PKR
            feeBps = 150, // 1.5%
        )
        val store = createStoreWithMethods(method)
        val service = PaymentMethodQueryService(store, sessions = sessionDir, clock = clock)

        // Negative amount -> INVALID
        assertFailsWith<AuthenticationFailure.Rejected> {
            service.query(PaymentMethodQuery(
                principal = playerPrincipal,
                sessionId = "sess-valid",
                tenantId = "tenant-pk-1",
                transactionType = TransactionType.DEPOSIT,
                amountMinorUnits = -100L,
            ))
        }.also { assertEquals(AuthErrorCode.INVALID, it.code) }

        // Excessive overflow amount (> MAX_SAFE_AMOUNT) -> INVALID
        assertFailsWith<AuthenticationFailure.Rejected> {
            service.query(PaymentMethodQuery(
                principal = playerPrincipal,
                sessionId = "sess-valid",
                tenantId = "tenant-pk-1",
                transactionType = TransactionType.DEPOSIT,
                amountMinorUnits = Long.MAX_VALUE,
            ))
        }.also { assertEquals(AuthErrorCode.INVALID, it.code) }

        // Amount below minDeposit (e.g. 5,000 minor units < 10,000)
        val belowResponse = service.query(PaymentMethodQuery(
            principal = playerPrincipal,
            sessionId = "sess-valid",
            tenantId = "tenant-pk-1",
            transactionType = TransactionType.DEPOSIT,
            amountMinorUnits = 5_000L,
            includeUnavailable = true,
        ))
        assertEquals(1, belowResponse.options.size)
        assertFalse(belowResponse.options[0].isSelectable)
        assertEquals(MethodAvailabilityCode.AMOUNT_BELOW_MINIMUM, belowResponse.options[0].availabilityCode)

        // Amount above maxDeposit (e.g. 6,000,000 minor units > 5,000,000)
        val aboveResponse = service.query(PaymentMethodQuery(
            principal = playerPrincipal,
            sessionId = "sess-valid",
            tenantId = "tenant-pk-1",
            transactionType = TransactionType.DEPOSIT,
            amountMinorUnits = 6_000_000L,
            includeUnavailable = true,
        ))
        assertFalse(aboveResponse.options[0].isSelectable)
        assertEquals(MethodAvailabilityCode.AMOUNT_ABOVE_MAXIMUM, aboveResponse.options[0].availabilityCode)

        // Valid amount (100,000 minor units): Fee = 500 flat + 1.5% of 100,000 = 500 + 1,500 = 2,000 minor units
        val validResponse = service.query(PaymentMethodQuery(
            principal = playerPrincipal,
            sessionId = "sess-valid",
            tenantId = "tenant-pk-1",
            transactionType = TransactionType.DEPOSIT,
            amountMinorUnits = 100_000L,
        ))
        assertTrue(validResponse.options[0].isSelectable)
        assertEquals(2_000L, validResponse.options[0].feeSchedule.estimatedFeeMinorUnits)
    }

    // =========================================================================
    // 6. Upstream Provider Outage via Circuit Breaker
    // =========================================================================

    @Test
    fun `test06 provider outage filters method and reports provider unavailable`() {
        val method = sampleMethod("EASYPAISA", providerId = "prov-ep-outage")
        val store = createStoreWithMethods(method)

        val breakerStore = object : ProviderCircuitBreakerStore {
            override fun findByIdempotency(tenantId: String, key: String) = null
            override fun findBreaker(tenantId: String, providerId: String): ProviderCircuitBreaker? {
                return if (providerId == "prov-ep-outage") {
                    ProviderCircuitBreaker(
                        providerId = "prov-ep-outage",
                        providerType = ProviderType.PAYMENT,
                        state = CircuitBreakerState.OPEN, // Upstream outage!
                        failureThreshold = 5,
                        cooldownSeconds = 60,
                        incidentReference = "INC-OUTAGE-1",
                        maskedSecretPreview = "****",
                        serverVersion = 1L,
                    )
                } else null
            }
            override fun save(result: ProviderCircuitBreakerResult, tenantId: String, queryFingerprint: String, idempotencyKey: String, audit: AuditEvent, outbox: OutboxEvent) {}
        }

        val service = PaymentMethodQueryService(
            paymentMethodStore = store,
            sessions = sessionDir,
            providerStatusResolver = CircuitBreakerProviderStatusResolver(breakerStore),
            clock = clock,
        )

        // Default: filtered out
        val response = service.query(PaymentMethodQuery(
            principal = playerPrincipal,
            sessionId = "sess-valid",
            tenantId = "tenant-pk-1",
            transactionType = TransactionType.DEPOSIT,
        ))
        assertTrue(response.options.isEmpty())
        assertEquals(1, response.filteredCount)

        // With includeUnavailable: shows PROVIDER_OUTAGE
        val explained = service.query(PaymentMethodQuery(
            principal = playerPrincipal,
            sessionId = "sess-valid",
            tenantId = "tenant-pk-1",
            transactionType = TransactionType.DEPOSIT,
            includeUnavailable = true,
        ))
        assertEquals(1, explained.options.size)
        assertEquals(MethodAvailabilityCode.PROVIDER_OUTAGE, explained.options[0].availabilityCode)
        assertFalse(explained.options[0].isSelectable)
    }

    // =========================================================================
    // 7. Policy Hook: Player / Account Restrictions Denial
    // =========================================================================

    @Test
    fun `test07 policy hook denies method when player has server-known restrictions`() {
        val method = sampleMethod("EASYPAISA")
        val store = createStoreWithMethods(method)

        val restrictionPolicy = PaymentMethodRestrictionPolicy { tenantId, subjectId, txType, m ->
            if (subjectId == "player-pk-001" && txType == TransactionType.DEPOSIT) {
                RestrictionEvaluation.denied("SUSPENDED_DEPOSITS", "Player deposits are suspended for AML review")
            } else {
                RestrictionEvaluation.ALLOWED
            }
        }

        val service = PaymentMethodQueryService(
            paymentMethodStore = store,
            sessions = sessionDir,
            restrictionPolicy = restrictionPolicy,
            clock = clock,
        )

        val explained = service.query(PaymentMethodQuery(
            principal = playerPrincipal,
            sessionId = "sess-valid",
            tenantId = "tenant-pk-1",
            transactionType = TransactionType.DEPOSIT,
            includeUnavailable = true,
        ))
        assertEquals(1, explained.options.size)
        assertFalse(explained.options[0].isSelectable)
        assertEquals(MethodAvailabilityCode.RESTRICTED_ACCOUNT, explained.options[0].availabilityCode)
        assertEquals("Player deposits are suspended for AML review", explained.options[0].availabilityReason)
    }

    // =========================================================================
    // 8. Stale Cache List Semantics & Revalidation on Transaction Creation
    // =========================================================================

    @Test
    fun `test08 stale cached list detection and deactivation rejection with typed refreshable error`() {
        val activeMethod = sampleMethod("EASYPAISA", serverVersion = 2L)
        val store = createStoreWithMethods(activeMethod)
        val evaluator = PaymentMethodAvailabilityEvaluator(store, clock = clock)
        val service = PaymentMethodQueryService(store, sessions = sessionDir, availabilityEvaluator = evaluator, clock = clock)

        // 1. Stale client check: client caches version 1L, server is at 2L
        val response = service.query(PaymentMethodQuery(
            principal = playerPrincipal,
            sessionId = "sess-valid",
            tenantId = "tenant-pk-1",
            transactionType = TransactionType.DEPOSIT,
            clientKnownVersion = 1L,
        ))
        assertTrue(response.isStale, "Response must indicate client cache is stale")
        assertEquals(2L, response.configurationVersion)

        // 2. Authoritative revalidation passes when method is active and version matches
        val validated = evaluator.requireAvailable(
            tenantId = "tenant-pk-1",
            subjectId = "player-pk-001",
            methodId = "EASYPAISA",
            expectedVersion = 2L,
            transactionType = TransactionType.DEPOSIT,
            currency = "PKR",
            amountMinorUnits = 100_000L,
        )
        assertEquals("EASYPAISA", validated.methodId)

        // 3. Deactivation while app open / between query and transaction use:
        // Update method in store to INACTIVE
        val deactivated = activeMethod.copy(status = PaymentMethodStatus.INACTIVE, serverVersion = 3L)
        val audit = AuditEvent(UUID.randomUUID(), UUID.randomUUID(), "tenant-pk-1", "DEACTIVATE", now, "c-1", "ca-1")
        val outbox = OutboxEvent(UUID.randomUUID(), audit.resultId, "tenant-pk-1", "DEACTIVATE", now)
        store.save(
            PaymentMethodResult(audit.resultId, deactivated, now, "ev-deact"),
            "fp-deact", "idem-deact", PaymentMethodAction.DEACTIVATE, "Admin deactivated", "admin-1", audit, outbox
        )

        // Transaction creation MUST reject with typed refreshable error
        val ex = assertFailsWith<PaymentMethodUnavailableException> {
            evaluator.requireAvailable(
                tenantId = "tenant-pk-1",
                subjectId = "player-pk-001",
                methodId = "EASYPAISA",
                expectedVersion = 2L,
                transactionType = TransactionType.DEPOSIT,
                currency = "PKR",
                amountMinorUnits = 100_000L,
            )
        }
        assertEquals(MethodAvailabilityCode.INACTIVE, ex.code)
        assertEquals("EASYPAISA", ex.methodId)
        assertEquals(3L, ex.serverVersion)
    }

    // =========================================================================
    // 9. Zero Credentials or Secrets Leaked in Response
    // =========================================================================

    @Test
    fun `test09 response contains no credentials or secret reference material`() {
        val method = sampleMethod("EASYPAISA")
        val store = createStoreWithMethods(method)
        val service = PaymentMethodQueryService(store, sessions = sessionDir, clock = clock)

        val response = service.query(PaymentMethodQuery(
            principal = playerPrincipal,
            sessionId = "sess-valid",
            tenantId = "tenant-pk-1",
            transactionType = TransactionType.DEPOSIT,
        ))

        val responseStr = response.toString().lowercase()
        assertFalse(responseStr.contains("secret"), "Response must not contain 'secret'")
        assertFalse(responseStr.contains("key"), "Response must not contain 'key'")
        assertFalse(responseStr.contains("password"), "Response must not contain 'password'")
        assertFalse(responseStr.contains("token"), "Response must not contain 'token'")
        assertFalse(responseStr.contains("credential"), "Response must not contain 'credential'")
    }

    // =========================================================================
    // 10. Observability & Metrics Hook
    // =========================================================================

    @Test
    fun `test10 query records metrics with eligible, filtered counts, and reason codes`() {
        val activeMethod = sampleMethod("EASYPAISA", status = PaymentMethodStatus.ACTIVE)
        val inactiveMethod = sampleMethod("JAZZCASH", status = PaymentMethodStatus.INACTIVE)
        val store = createStoreWithMethods(activeMethod, inactiveMethod)

        var recordedTenantId: String? = null
        var recordedTxType: TransactionType? = null
        var recordedEligible = -1
        var recordedFiltered = -1
        var recordedReasons: Map<MethodAvailabilityCode, Int>? = null

        val metrics = PaymentMethodQueryMetrics { tenantId, txType, eligible, filtered, reasons ->
            recordedTenantId = tenantId
            recordedTxType = txType
            recordedEligible = eligible
            recordedFiltered = filtered
            recordedReasons = reasons
        }

        val service = PaymentMethodQueryService(
            paymentMethodStore = store,
            sessions = sessionDir,
            metrics = metrics,
            clock = clock,
        )

        service.query(PaymentMethodQuery(
            principal = playerPrincipal,
            sessionId = "sess-valid",
            tenantId = "tenant-pk-1",
            transactionType = TransactionType.DEPOSIT,
        ))

        assertEquals("tenant-pk-1", recordedTenantId)
        assertEquals(TransactionType.DEPOSIT, recordedTxType)
        assertEquals(1, recordedEligible)
        assertEquals(1, recordedFiltered)
        assertEquals(mapOf(MethodAvailabilityCode.INACTIVE to 1), recordedReasons)
    }

    // =========================================================================
    // 11. Spring REST Controller Mapping & Responses
    // =========================================================================

    @Test
    fun `test11 controller handles valid and error requests with correct HTTP statuses`() {
        val method = sampleMethod("EASYPAISA")
        val store = createStoreWithMethods(method)
        val service = PaymentMethodQueryService(store, sessions = sessionDir, clock = clock)
        val controller = PlayerPaymentMethodController(service)

        // 1. Success 200 OK
        val okResponse = controller.getPaymentMethods(
            tenantId = "tenant-pk-1",
            transactionType = "DEPOSIT",
            currency = "PKR",
            amountMinorUnits = 100_000L,
            clientKnownVersion = null,
            includeUnavailable = false,
            sessionIdHeader = "sess-valid",
            principalAttr = playerPrincipal,
        )
        assertEquals(org.springframework.http.HttpStatus.OK, okResponse.statusCode)
        val body = okResponse.body as PaymentMethodQueryResponse
        assertEquals(1, body.options.size)

        // 2. Invalid transaction type -> 400 Bad Request
        val badTypeResponse = controller.getPaymentMethods(
            tenantId = "tenant-pk-1",
            transactionType = "INVALID_TYPE",
            currency = null,
            amountMinorUnits = null,
            clientKnownVersion = null,
            includeUnavailable = false,
            sessionIdHeader = "sess-valid",
            principalAttr = playerPrincipal,
        )
        assertEquals(org.springframework.http.HttpStatus.BAD_REQUEST, badTypeResponse.statusCode)

        // 3. Expired session -> 403 Forbidden
        val forbiddenResponse = controller.getPaymentMethods(
            tenantId = "tenant-pk-1",
            transactionType = "DEPOSIT",
            currency = null,
            amountMinorUnits = null,
            clientKnownVersion = null,
            includeUnavailable = false,
            sessionIdHeader = "sess-expired",
            principalAttr = playerPrincipal,
        )
        assertEquals(org.springframework.http.HttpStatus.FORBIDDEN, forbiddenResponse.statusCode)

        // 4. Database crash / dependency unavailable -> 503 Service Unavailable
        val serviceUnavailableResponse = controller.getPaymentMethods(
            tenantId = "tenant-pk-1",
            transactionType = "DEPOSIT",
            currency = null,
            amountMinorUnits = null,
            clientKnownVersion = null,
            includeUnavailable = false,
            sessionIdHeader = "sess-crash",
            principalAttr = playerPrincipal,
        )
        assertEquals(org.springframework.http.HttpStatus.SERVICE_UNAVAILABLE, serviceUnavailableResponse.statusCode)
    }

    // =========================================================================
    // 12. PostgreSQL Restart Durability & History Preservation
    // =========================================================================

    @Test
    fun `test12 restart durability preserves active, inactive state, and history`() {
        val mockJdbc = org.mockito.Mockito.mock(org.springframework.jdbc.core.JdbcTemplate::class.java)
        val store = JdbcPaymentMethodStore(mockJdbc)

        val epMethod = sampleMethod("EASYPAISA", status = PaymentMethodStatus.ACTIVE, serverVersion = 1L)
        val jcMethod = sampleMethod("JAZZCASH", status = PaymentMethodStatus.INACTIVE, serverVersion = 2L)

        // Simulate reading from PostgreSQL after a service restart
        org.mockito.Mockito.`when`(mockJdbc.query(
            org.mockito.ArgumentMatchers.contains("from admin_payment_method"),
            org.mockito.ArgumentMatchers.any<org.springframework.jdbc.core.RowMapper<PaymentMethodConfig>>(),
            org.mockito.ArgumentMatchers.eq("tenant-pk-1")
        )).thenReturn(listOf(epMethod, jcMethod))

        val service = PaymentMethodQueryService(store, sessions = sessionDir, clock = clock)

        // Query returns only the active method
        val response = service.query(PaymentMethodQuery(
            principal = playerPrincipal,
            sessionId = "sess-valid",
            tenantId = "tenant-pk-1",
            transactionType = TransactionType.DEPOSIT,
        ))

        assertEquals(1, response.options.size)
        assertEquals("EASYPAISA", response.options[0].methodId)
        assertEquals(2L, response.configurationVersion) // Max version between 1L and 2L
        assertEquals(1, response.eligibleCount)
        assertEquals(1, response.filteredCount)
    }
}
