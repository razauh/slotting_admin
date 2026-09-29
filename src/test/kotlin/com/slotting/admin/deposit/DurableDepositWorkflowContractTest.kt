package com.slotting.admin.deposit

import com.slotting.admin.auth.*
import com.slotting.admin.ledger.*
import com.slotting.admin.provider.*
import com.slotting.admin.provider.port.*
import com.slotting.admin.provider.port.adapters.*
import org.junit.jupiter.api.Test
import java.time.Clock
import java.time.Duration
import java.time.Instant
import java.time.ZoneOffset
import java.util.UUID
import java.util.concurrent.CountDownLatch
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit
import kotlin.test.*

/**
 * TC-013 TDD Contract Test Suite:
 * Durable deposit intent, callback, credit, and reconciliation workflow.
 */
class DurableDepositWorkflowContractTest {

    private val now = Instant.parse("2026-09-25T11:00:00Z")
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

    private val adminPrincipal = AuthenticatedPrincipal(
        id = "admin-001",
        tenantId = "tenant-pk-1",
        kind = PrincipalKind.ADMIN,
        roles = setOf(AdminRole.SUPER_ADMIN),
    )

    private val sessionDir = object : AdminSessionDirectory {
        override fun find(tenantId: String, principalId: String, sessionId: String): AdminSessionStatus? {
            return when (sessionId) {
                "sess-valid" -> AdminSessionStatus(active = true, breakGlass = false, expiresAt = now.plus(Duration.ofHours(2)), mfaVerified = true)
                "sess-expired" -> AdminSessionStatus(active = true, breakGlass = false, expiresAt = now.minus(Duration.ofSeconds(30)), mfaVerified = true)
                else -> AdminSessionStatus(active = true, breakGlass = false, expiresAt = now.plus(Duration.ofHours(2)), mfaVerified = true)
            }
        }
    }

    private val sampleMethod = PaymentMethodConfig(
        tenantId = "tenant-pk-1",
        methodId = "EASYPAISA",
        providerId = "ADVERSARIAL_TEST",
        methodType = PaymentMethodType.MOBILE_WALLET,
        displayName = "Easypaisa Mobile Account",
        instructions = "Send payment to mobile wallet",
        safeAccountTitle = "Merchant Wallet",
        safeAccountNumber = "03001234567",
        iconUrl = "https://cdn.example.com/easypaisa.png",
        supportedCurrencies = listOf("PKR"),
        allowsDeposit = true,
        allowsWithdrawal = true,
        minDepositMinorUnits = 10_000L, // 100 PKR
        maxDepositMinorUnits = 5_000_000L, // 50,000 PKR
        minWithdrawalMinorUnits = 10_000L,
        maxWithdrawalMinorUnits = 2_500_000L,
        feeFlatMinorUnits = 500L,
        feePercentageBps = 150,
        displayOrder = 1,
        status = PaymentMethodStatus.ACTIVE,
        maintenanceReason = null,
        serverVersion = 1L,
        createdAt = now,
        updatedAt = now,
        updatedBy = "admin-1",
    )

    private val sampleConfig = ProviderConfiguration(
        providerId = "ADVERSARIAL_TEST",
        environment = ProviderEnvironment.SANDBOX,
        baseUrl = "https://sandbox.api.test/v1",
    )

    private val sampleCredentials = ProviderCredentials(
        merchantId = "MERCHANT-01",
        apiKey = "api-key-test",
        signingSecretOrKey = "signing-secret-123",
    )

    private fun sampleCreateCommand(
        opId: UUID = UUID.randomUUID(),
        amount: Long = 50_000L, // 500 PKR
        currency: String = "PKR",
        methodId: String = "EASYPAISA",
        idempotencyKey: String = "IDEM-${UUID.randomUUID()}",
        principal: AuthenticatedPrincipal? = playerPrincipal,
        sessionId: String = "sess-valid",
        tenantId: String = "tenant-pk-1",
        methodExpectedVersion: Long = 1L,
    ) = CreateDepositIntentCommand(
        principal = principal,
        sessionId = sessionId,
        tenantId = tenantId,
        playerId = UUID.fromString("00000000-0000-0000-0000-000000000001"),
        methodId = methodId,
        amountMinorUnits = amount,
        currencyCode = currency,
        customerIdentifier = "03001234567",
        methodExpectedVersion = methodExpectedVersion,
        idempotencyKey = idempotencyKey,
        correlationId = "corr-1",
        causationId = "caus-1",
    )

    // =========================================================================
    // 1. Create Intent & Method Revalidation
    // =========================================================================

    @Test
    fun `test01 create intent persists intent, revalidates method, and dispatches to provider`() {
        val methodStore = InMemoryPaymentMethodStore()
        val audit = AuditEvent(UUID.randomUUID(), UUID.randomUUID(), "tenant-pk-1", "INIT", now, "c", "ca")
        val outbox = OutboxEvent(UUID.randomUUID(), audit.resultId, "tenant-pk-1", "INIT", now)
        methodStore.save(PaymentMethodResult(audit.resultId, sampleMethod, now, "ev"), "fp", "idem-m", PaymentMethodAction.REGISTER, "init", "admin", audit, outbox)

        val workflowStore = InMemoryDepositWorkflowStore()
        val ledgerStore = InMemoryLedgerJournalStore()
        val ledgerService = LedgerPostingService(ledgerStore, clock = clock)
        val providerAdapter = AdversarialTestPaymentAdapter(
            providerId = "ADVERSARIAL_TEST",
            simulationMode = AdversarialSimulationMode.NORMAL_SUCCESS,
        )

        val service = DurableDepositWorkflowService(
            workflowStore = workflowStore,
            paymentMethodStore = methodStore,
            sessions = sessionDir,
            ledgerPostingService = ledgerService,
            providerPorts = mapOf("ADVERSARIAL_TEST" to providerAdapter),
            credentialsResolver = { _, _ -> sampleCredentials },
            configResolver = { _, _ -> sampleConfig },
            clock = clock,
        )

        val cmd = sampleCreateCommand()
        val result = service.createIntent(cmd)

        assertEquals(DepositIntentStatus.PROVIDER_PENDING, result.status)
        assertNotNull(result.intentId)
        assertNotNull(result.providerReference)
        assertEquals(50_000L, result.amountMinorUnits)
        assertEquals("PKR", result.currencyCode)
        assertTrue(result.expiresAt.isAfter(now))

        // Check persistent store
        val stored = workflowStore.findIntent("tenant-pk-1", result.intentId)
        assertNotNull(stored)
        assertEquals(DepositIntentStatus.PROVIDER_PENDING, stored.status)
    }

    @Test
    fun `test02 create intent rejects unauthenticated, foreign tenant, inactive method, or amount bounds violation`() {
        val methodStore = InMemoryPaymentMethodStore()
        val audit = AuditEvent(UUID.randomUUID(), UUID.randomUUID(), "tenant-pk-1", "INIT", now, "c", "ca")
        val outbox = OutboxEvent(UUID.randomUUID(), audit.resultId, "tenant-pk-1", "INIT", now)
        methodStore.save(PaymentMethodResult(audit.resultId, sampleMethod, now, "ev"), "fp", "idem-m", PaymentMethodAction.REGISTER, "init", "admin", audit, outbox)

        val workflowStore = InMemoryDepositWorkflowStore()
        val ledgerService = LedgerPostingService(InMemoryLedgerJournalStore(), clock = clock)
        val service = DurableDepositWorkflowService(
            workflowStore = workflowStore,
            paymentMethodStore = methodStore,
            sessions = sessionDir,
            ledgerPostingService = ledgerService,
            providerPorts = mapOf("ADVERSARIAL_TEST" to AdversarialTestPaymentAdapter("ADVERSARIAL_TEST")),
            credentialsResolver = { _, _ -> sampleCredentials },
            configResolver = { _, _ -> sampleConfig },
            clock = clock,
        )

        // 1. Unauthenticated
        assertFailsWith<AuthenticationFailure.Rejected> {
            service.createIntent(sampleCreateCommand(principal = null))
        }.also { assertEquals(AuthErrorCode.UNAUTHENTICATED, it.code) }

        // 2. Foreign tenant
        assertFailsWith<AuthenticationFailure.Rejected> {
            service.createIntent(sampleCreateCommand(principal = foreignPlayerPrincipal))
        }.also { assertEquals(AuthErrorCode.FORBIDDEN, it.code) }

        // 3. Amount below minimum (5,000 minor units < 10,000 minDeposit)
        assertFailsWith<PaymentMethodUnavailableException> {
            service.createIntent(sampleCreateCommand(amount = 5_000L))
        }.also { assertEquals(MethodAvailabilityCode.AMOUNT_BELOW_MINIMUM, it.code) }

        // 4. Stale method version
        assertFailsWith<PaymentMethodUnavailableException> {
            service.createIntent(sampleCreateCommand(methodExpectedVersion = 999L))
        }
    }

    // =========================================================================
    // 2. Idempotency Replay
    // =========================================================================

    @Test
    fun `test03 duplicate intent returns cached result with same fingerprint or CONFLICT on altered payload`() {
        val methodStore = InMemoryPaymentMethodStore()
        val audit = AuditEvent(UUID.randomUUID(), UUID.randomUUID(), "tenant-pk-1", "INIT", now, "c", "ca")
        val outbox = OutboxEvent(UUID.randomUUID(), audit.resultId, "tenant-pk-1", "INIT", now)
        methodStore.save(PaymentMethodResult(audit.resultId, sampleMethod, now, "ev"), "fp", "idem-m", PaymentMethodAction.REGISTER, "init", "admin", audit, outbox)

        val workflowStore = InMemoryDepositWorkflowStore()
        val ledgerService = LedgerPostingService(InMemoryLedgerJournalStore(), clock = clock)
        val service = DurableDepositWorkflowService(
            workflowStore = workflowStore,
            paymentMethodStore = methodStore,
            sessions = sessionDir,
            ledgerPostingService = ledgerService,
            providerPorts = mapOf("ADVERSARIAL_TEST" to AdversarialTestPaymentAdapter("ADVERSARIAL_TEST")),
            credentialsResolver = { _, _ -> sampleCredentials },
            configResolver = { _, _ -> sampleConfig },
            clock = clock,
        )

        val fixedKey = "IDEM-FIXED-INTENT-1"
        val cmd = sampleCreateCommand(idempotencyKey = fixedKey)
        val res1 = service.createIntent(cmd)
        val res2 = service.createIntent(cmd)

        assertEquals(res1.intentId, res2.intentId)
        assertEquals(res1.providerReference, res2.providerReference)

        // Altered payload with same idempotency key -> CONFLICT
        val altered = cmd.copy(amountMinorUnits = 70_000L)
        assertFailsWith<AuthenticationFailure.Rejected> {
            service.createIntent(altered)
        }.also { assertEquals(AuthErrorCode.CONFLICT, it.code) }
    }

    // =========================================================================
    // 3. Ambiguity Invariant: Timeout during dispatch
    // =========================================================================

    @Test
    fun `test04 provider timeout during dispatch transitions intent to AMBIGUOUS_RECONCILING without failing prematurely`() {
        val methodStore = InMemoryPaymentMethodStore()
        val audit = AuditEvent(UUID.randomUUID(), UUID.randomUUID(), "tenant-pk-1", "INIT", now, "c", "ca")
        val outbox = OutboxEvent(UUID.randomUUID(), audit.resultId, "tenant-pk-1", "INIT", now)
        methodStore.save(PaymentMethodResult(audit.resultId, sampleMethod, now, "ev"), "fp", "idem-m", PaymentMethodAction.REGISTER, "init", "admin", audit, outbox)

        val workflowStore = InMemoryDepositWorkflowStore()
        val ledgerService = LedgerPostingService(InMemoryLedgerJournalStore(), clock = clock)
        val adapter = AdversarialTestPaymentAdapter(
            providerId = "ADVERSARIAL_TEST",
            simulationMode = AdversarialSimulationMode.TIMEOUT_AFTER_DISPATCH,
        )

        val service = DurableDepositWorkflowService(
            workflowStore = workflowStore,
            paymentMethodStore = methodStore,
            sessions = sessionDir,
            ledgerPostingService = ledgerService,
            providerPorts = mapOf("ADVERSARIAL_TEST" to adapter),
            credentialsResolver = { _, _ -> sampleCredentials },
            configResolver = { _, _ -> sampleConfig },
            clock = clock,
        )

        val res = service.createIntent(sampleCreateCommand())
        assertEquals(DepositIntentStatus.AMBIGUOUS_RECONCILING, res.status)

        val stored = workflowStore.findIntent("tenant-pk-1", res.intentId)
        assertNotNull(stored)
        assertEquals(DepositIntentStatus.AMBIGUOUS_RECONCILING, stored.status)
    }

    // =========================================================================
    // 4. Authenticated Callback & Exactly-Once Ledger Credit
    // =========================================================================

    @Test
    fun `test05 authenticated callback with valid signature credits ledger exactly once and transitions intent to SETTLED`() {
        val safepayMethod = sampleMethod.copy(
            methodId = "SAFEPAY",
            providerId = "SAFEPAY_RAAST",
        )
        val methodStore = InMemoryPaymentMethodStore()
        val audit = AuditEvent(UUID.randomUUID(), UUID.randomUUID(), "tenant-pk-1", "INIT", now, "c", "ca")
        val outbox = OutboxEvent(UUID.randomUUID(), audit.resultId, "tenant-pk-1", "INIT", now)
        methodStore.save(PaymentMethodResult(audit.resultId, safepayMethod, now, "ev"), "fp", "idem-sp", PaymentMethodAction.REGISTER, "init", "admin", audit, outbox)

        val workflowStore = InMemoryDepositWorkflowStore()
        val ledgerStore = InMemoryLedgerJournalStore()
        val ledgerService = LedgerPostingService(ledgerStore, clock = clock)
        val safepayAdapter = SafepayRaastAdapter()

        val service = DurableDepositWorkflowService(
            workflowStore = workflowStore,
            paymentMethodStore = methodStore,
            sessions = sessionDir,
            ledgerPostingService = ledgerService,
            providerPorts = mapOf("SAFEPAY_RAAST" to safepayAdapter),
            credentialsResolver = { _, _ -> sampleCredentials },
            configResolver = { _, _ -> sampleConfig },
            clock = clock,
        )

        // 1. Create deposit intent
        val createResult = service.createIntent(sampleCreateCommand(methodId = "SAFEPAY"))
        assertEquals(DepositIntentStatus.PROVIDER_PENDING, createResult.status)

        // 2. Construct authentic callback
        val tracker = createResult.providerReference!!
        val callbackBody = """{"data":{"token":"token_123","amount":50000,"currency":"PKR","status":"paid","tracker":"$tracker"}}"""
        val validSig = safepayAdapter.calculateHmacSha256(callbackBody, sampleCredentials.signingSecretOrKey!!)

        val callbackCmd = DepositCallbackCommand(
            tenantId = "tenant-pk-1",
            providerId = "SAFEPAY_RAAST",
            providerEventId = "evt-sp-001",
            rawBody = callbackBody,
            headers = mapOf("x-sfpy-signature" to validSig),
        )

        // 3. Process callback
        val callbackResult = service.processCallback(callbackCmd)
        assertEquals(DepositIntentStatus.SETTLED, callbackResult.status)
        assertNotNull(callbackResult.ledgerTransactionReference)

        // Verify ledger was credited exactly once
        val storedIntent = workflowStore.findIntent("tenant-pk-1", createResult.intentId)
        assertEquals(DepositIntentStatus.SETTLED, storedIntent?.status)
        assertNotNull(storedIntent?.settledAt)
        assertNotNull(storedIntent?.ledgerTransactionReference)

        // 4. Duplicate / replayed callback MUST NOT double-credit ledger
        val duplicateResult = service.processCallback(callbackCmd)
        assertEquals(DepositIntentStatus.SETTLED, duplicateResult.status)
        assertEquals(callbackResult.ledgerTransactionReference, duplicateResult.ledgerTransactionReference)
    }

    @Test
    fun `test06 invalid callback signature or tampered payload is rejected and does not credit ledger`() {
        val safepayMethod = sampleMethod.copy(methodId = "SAFEPAY", providerId = "SAFEPAY_RAAST")
        val methodStore = InMemoryPaymentMethodStore()
        val audit = AuditEvent(UUID.randomUUID(), UUID.randomUUID(), "tenant-pk-1", "INIT", now, "c", "ca")
        val outbox = OutboxEvent(UUID.randomUUID(), audit.resultId, "tenant-pk-1", "INIT", now)
        methodStore.save(PaymentMethodResult(audit.resultId, safepayMethod, now, "ev"), "fp", "idem-sp", PaymentMethodAction.REGISTER, "init", "admin", audit, outbox)

        val workflowStore = InMemoryDepositWorkflowStore()
        val ledgerStore = InMemoryLedgerJournalStore()
        val ledgerService = LedgerPostingService(ledgerStore, clock = clock)

        val service = DurableDepositWorkflowService(
            workflowStore = workflowStore,
            paymentMethodStore = methodStore,
            sessions = sessionDir,
            ledgerPostingService = ledgerService,
            providerPorts = mapOf("SAFEPAY_RAAST" to SafepayRaastAdapter()),
            credentialsResolver = { _, _ -> sampleCredentials },
            configResolver = { _, _ -> sampleConfig },
            clock = clock,
        )

        val createResult = service.createIntent(sampleCreateCommand(methodId = "SAFEPAY"))

        // Tampered signature
        val callbackCmd = DepositCallbackCommand(
            tenantId = "tenant-pk-1",
            providerId = "SAFEPAY_RAAST",
            providerEventId = "evt-tampered-1",
            rawBody = """{"data":{"status":"paid","tracker":"${createResult.providerReference}"}}""",
            headers = mapOf("x-sfpy-signature" to "invalid-tampered-sig"),
        )

        assertFailsWith<AuthenticationFailure.Rejected> {
            service.processCallback(callbackCmd)
        }.also { assertEquals(AuthErrorCode.FORBIDDEN, it.code) }

        // Intent remains PROVIDER_PENDING
        val intent = workflowStore.findIntent("tenant-pk-1", createResult.intentId)
        assertEquals(DepositIntentStatus.PROVIDER_PENDING, intent?.status)
    }

    // =========================================================================
    // 5. Client Return URL Rejection (Android / browser return never settles)
    // =========================================================================

    @Test
    fun `test07 client return URL alone is rejected and never credits ledger or settles intent`() {
        val workflowStore = InMemoryDepositWorkflowStore()
        val ledgerService = LedgerPostingService(InMemoryLedgerJournalStore(), clock = clock)
        val service = DurableDepositWorkflowService(
            workflowStore = workflowStore,
            paymentMethodStore = InMemoryPaymentMethodStore(),
            sessions = sessionDir,
            ledgerPostingService = ledgerService,
            providerPorts = emptyMap(),
            credentialsResolver = { _, _ -> null },
            configResolver = { _, _ -> null },
            clock = clock,
        )

        // Attempting to settle or credit via return URL parameter
        assertFailsWith<AuthenticationFailure.Rejected> {
            service.handleClientReturn(
                tenantId = "tenant-pk-1",
                intentId = UUID.randomUUID(),
                returnUrlParams = mapOf("status" to "SUCCESS", "claimed" to "true"),
                principal = playerPrincipal,
            )
        }.also { assertEquals(AuthErrorCode.FORBIDDEN, it.code) }
    }

    // =========================================================================
    // 6. Reconciliation of Ambiguous Intents
    // =========================================================================

    @Test
    fun `test08 reconciliation resolves ambiguous intent and posts ledger credit exactly once`() {
        val methodStore = InMemoryPaymentMethodStore()
        val audit = AuditEvent(UUID.randomUUID(), UUID.randomUUID(), "tenant-pk-1", "INIT", now, "c", "ca")
        val outbox = OutboxEvent(UUID.randomUUID(), audit.resultId, "tenant-pk-1", "INIT", now)
        methodStore.save(PaymentMethodResult(audit.resultId, sampleMethod, now, "ev"), "fp", "idem-m", PaymentMethodAction.REGISTER, "init", "admin", audit, outbox)

        val workflowStore = InMemoryDepositWorkflowStore()
        val ledgerStore = InMemoryLedgerJournalStore()
        val ledgerService = LedgerPostingService(ledgerStore, clock = clock)
        val adapter = AdversarialTestPaymentAdapter("ADVERSARIAL_TEST")

        val service = DurableDepositWorkflowService(
            workflowStore = workflowStore,
            paymentMethodStore = methodStore,
            sessions = sessionDir,
            ledgerPostingService = ledgerService,
            providerPorts = mapOf("ADVERSARIAL_TEST" to adapter),
            credentialsResolver = { _, _ -> sampleCredentials },
            configResolver = { _, _ -> sampleConfig },
            clock = clock,
        )

        // 1. Timeout during dispatch -> intent is AMBIGUOUS_RECONCILING
        adapter.simulationMode = AdversarialSimulationMode.TIMEOUT_AFTER_DISPATCH
        val created = service.createIntent(sampleCreateCommand())
        assertEquals(DepositIntentStatus.AMBIGUOUS_RECONCILING, created.status)

        // 2. Provider recovers and reports success during status inquiry
        adapter.simulationMode = AdversarialSimulationMode.NORMAL_SUCCESS
        val reconcileCmd = DepositReconciliationCommand(
            tenantId = "tenant-pk-1",
            intentId = created.intentId,
            principal = adminPrincipal,
            sessionId = "sess-valid",
        )

        val reconcileResult = service.reconcile(reconcileCmd)
        assertEquals(DepositIntentStatus.SETTLED, reconcileResult.status)
        assertNotNull(reconcileResult.ledgerTransactionReference)

        // Stored intent is now SETTLED
        val stored = workflowStore.findIntent("tenant-pk-1", created.intentId)
        assertEquals(DepositIntentStatus.SETTLED, stored?.status)

        // Reconciling again does not duplicate ledger credit
        val secondReconcile = service.reconcile(reconcileCmd)
        assertEquals(DepositIntentStatus.SETTLED, secondReconcile.status)
        assertEquals(reconcileResult.ledgerTransactionReference, secondReconcile.ledgerTransactionReference)
    }

    // =========================================================================
    // 7. Concurrent Callback Handling
    // =========================================================================

    @Test
    fun `test09 concurrent callbacks allow exactly one ledger credit and reject duplicate credit`() {
        val safepayMethod = sampleMethod.copy(methodId = "SAFEPAY", providerId = "SAFEPAY_RAAST")
        val methodStore = InMemoryPaymentMethodStore()
        val audit = AuditEvent(UUID.randomUUID(), UUID.randomUUID(), "tenant-pk-1", "INIT", now, "c", "ca")
        val outbox = OutboxEvent(UUID.randomUUID(), audit.resultId, "tenant-pk-1", "INIT", now)
        methodStore.save(PaymentMethodResult(audit.resultId, safepayMethod, now, "ev"), "fp", "idem-sp", PaymentMethodAction.REGISTER, "init", "admin", audit, outbox)

        val workflowStore = InMemoryDepositWorkflowStore()
        val ledgerStore = InMemoryLedgerJournalStore()
        val ledgerService = LedgerPostingService(ledgerStore, clock = clock)
        val safepayAdapter = SafepayRaastAdapter()

        val service = DurableDepositWorkflowService(
            workflowStore = workflowStore,
            paymentMethodStore = methodStore,
            sessions = sessionDir,
            ledgerPostingService = ledgerService,
            providerPorts = mapOf("SAFEPAY_RAAST" to safepayAdapter),
            credentialsResolver = { _, _ -> sampleCredentials },
            configResolver = { _, _ -> sampleConfig },
            clock = clock,
        )

        val createResult = service.createIntent(sampleCreateCommand(methodId = "SAFEPAY"))
        val tracker = createResult.providerReference!!
        val callbackBody = """{"data":{"token":"token_123","amount":50000,"currency":"PKR","status":"paid","tracker":"$tracker"}}"""
        val validSig = safepayAdapter.calculateHmacSha256(callbackBody, sampleCredentials.signingSecretOrKey!!)

        val threadCount = 6
        val executor = Executors.newFixedThreadPool(threadCount)
        val latch = CountDownLatch(1)

        val tasks = (1..threadCount).map { i ->
            {
                latch.await()
                try {
                    service.processCallback(
                        DepositCallbackCommand(
                            tenantId = "tenant-pk-1",
                            providerId = "SAFEPAY_RAAST",
                            providerEventId = "evt-sp-$i",
                            rawBody = callbackBody,
                            headers = mapOf("x-sfpy-signature" to validSig),
                        )
                    )
                } catch (e: Exception) {
                    e
                }
            }
        }

        val futures = tasks.map { executor.submit(it) }
        latch.countDown()
        val results = futures.map { it.get() }
        executor.shutdown()
        executor.awaitTermination(5, TimeUnit.SECONDS)

        val settledResults = results.filterIsInstance<DepositCallbackResult>()
        assertTrue(settledResults.isNotEmpty())
        val txRefs = settledResults.mapNotNull { it.ledgerTransactionReference }.distinct()
        assertEquals(1, txRefs.size, "Exactly one unique ledger transaction reference produced across concurrent callbacks")
    }

    // =========================================================================
    // 8. Zero Credentials in Intent Response
    // =========================================================================

    @Test
    fun `test10 zero credentials or secrets exposed in intent response or launch data`() {
        val methodStore = InMemoryPaymentMethodStore()
        val audit = AuditEvent(UUID.randomUUID(), UUID.randomUUID(), "tenant-pk-1", "INIT", now, "c", "ca")
        val outbox = OutboxEvent(UUID.randomUUID(), audit.resultId, "tenant-pk-1", "INIT", now)
        methodStore.save(PaymentMethodResult(audit.resultId, sampleMethod, now, "ev"), "fp", "idem-m", PaymentMethodAction.REGISTER, "init", "admin", audit, outbox)

        val workflowStore = InMemoryDepositWorkflowStore()
        val ledgerService = LedgerPostingService(InMemoryLedgerJournalStore(), clock = clock)
        val service = DurableDepositWorkflowService(
            workflowStore = workflowStore,
            paymentMethodStore = methodStore,
            sessions = sessionDir,
            ledgerPostingService = ledgerService,
            providerPorts = mapOf("ADVERSARIAL_TEST" to AdversarialTestPaymentAdapter("ADVERSARIAL_TEST")),
            credentialsResolver = { _, _ -> sampleCredentials },
            configResolver = { _, _ -> sampleConfig },
            clock = clock,
        )

        val result = service.createIntent(sampleCreateCommand())
        val str = result.toString().lowercase()
        assertFalse(str.contains("secret"), "No secret in create intent response")
        assertFalse(str.contains("api-key"), "No api-key in create intent response")
        assertFalse(str.contains("password"), "No password in create intent response")
    }
}
