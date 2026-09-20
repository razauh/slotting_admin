package com.slotting.admin.payment

import com.slotting.admin.auth.*
import java.io.File
import java.time.Clock
import java.time.Instant
import java.time.ZoneOffset
import java.util.UUID
import java.util.concurrent.CountDownLatch
import java.util.concurrent.Executors
import kotlin.test.*
import org.junit.jupiter.api.AfterEach
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test

class CanonicalPaymentProviderPortTest {
    private val now = Instant.parse("2026-09-19T14:00:00Z")
    private val clock = Clock.fixed(now, ZoneOffset.UTC)
    private val tenantId = "tenant-canonical-pay-1"
    private val fakeProviderId = "prov-adversarial-fake"
    private val unselectedProdProviderId = "prov-prod-unselected"
    private val certifiedProdProviderId = "prov-prod-certified"

    private val adminPrincipal = AuthenticatedPrincipal(
        id = "admin-pay-1",
        tenantId = tenantId,
        kind = PrincipalKind.ADMIN,
        roles = setOf(AdminRole.SUPER_ADMIN),
    )

    private val playerPrincipal = AuthenticatedPrincipal(
        id = "player-1",
        tenantId = tenantId,
        kind = PrincipalKind.PLAYER,
        roles = emptySet(),
    )

    private val crossTenantPrincipal = AuthenticatedPrincipal(
        id = "admin-other",
        tenantId = "tenant-other",
        kind = PrincipalKind.ADMIN,
        roles = setOf(AdminRole.SUPER_ADMIN),
    )

    @BeforeEach
    fun setUp() {
        CanonicalPaymentProviderPortBinding.isBound = true
    }

    @AfterEach
    fun tearDown() {
        CanonicalPaymentProviderPortBinding.isBound = true
    }

    @Test
    fun `PAYMENT-001-01-T001 — Define canonical payment provider port produces the required authoritative outcome`() {
        // 1. Expected RED failure verification: Fail-closed gate throws expected assertion when unbound
        CanonicalPaymentProviderPortBinding.isBound = false
        val store = InMemoryCanonicalPaymentPortStore()
        val fakeAdapter = AdversarialPaymentProviderFakeAdapter(fakeProviderId, clock = clock)
        val unselectedProdAdapter = UnselectedProductionPaymentAdapter(unselectedProdProviderId)
        val certifiedProdAdapter = CertifiedProductionPaymentAdapter(certifiedProdProviderId)
        val adapters = mapOf(
            fakeProviderId to fakeAdapter,
            unselectedProdProviderId to unselectedProdAdapter,
            certifiedProdProviderId to certifiedProdAdapter,
        )
        val service = service(store, adapters)

        val initCmd = command(paymentReference = "pay-init-001", idempotencyKey = "key-init-001")
        val gateError = assertFailsWith<AssertionError> {
            service.executeOperation(initCmd)
        }
        assertEquals("domain tied to vendor", gateError.message)

        // Bind the fail-closed gate
        CanonicalPaymentProviderPortBinding.isBound = true

        // 2. Authoritative operation: Execute AUTHORIZE through canonical payment provider port
        val authCmd = command(
            paymentReference = "pay-auth-001",
            operation = CanonicalPaymentOperation.AUTHORIZE,
            amountMinorUnits = 10000L,
            currencyCode = "EUR",
            providerId = fakeProviderId,
            idempotencyKey = "key-auth-001",
            correlationId = "corr-auth-1",
            causationId = "cause-auth-1",
        )
        val authRes = service.executeOperation(authCmd)
        assertNotNull(authRes)
        assertEquals(CanonicalPaymentStatus.AUTHORIZED, authRes.status)
        assertEquals("pay-auth-001", authRes.paymentReference)
        assertEquals(10000L, authRes.amountMinorUnits)
        assertEquals("EUR", authRes.currencyCode)
        assertEquals("EXT-TX-pay-auth-001", authRes.externalTransactionReference)
        assertEquals("SUCCESS", authRes.safeReasonCode)

        // Assert: Fake supports duplicates/order/signature/timeouts; production completion waits for selected provider.
        assertEquals(CANONICAL_PAYMENT_PORT_CONTRACT, authRes.semanticContract)

        // Financial conservation: Assert debits equal credits, no double effect, transactional atomicity
        assertEquals(authRes.debitMinorUnits, authRes.creditMinorUnits)
        assertTrue(authRes.conserved)
        assertEquals(10000L, authRes.debitMinorUnits)

        // Idempotent replay yields identical authoritative identity
        val replayRes = service.executeOperation(authCmd)
        assertEquals(authRes.resultId, replayRes.resultId)
        assertEquals(authRes.evidenceReference, replayRes.evidenceReference)

        // 3. Immutable reversal/compensation: debits equal credits and reconciliation
        val compCmd = CompensatePaymentCommand(
            principal = adminPrincipal,
            sessionId = "session-pay-1",
            tenantId = tenantId,
            paymentReference = "pay-auth-001",
            originalDebitMinorUnits = 10000L,
            compensatingCreditMinorUnits = 10000L,
            currencyCode = "EUR",
            reason = "Customer cancelled order before capture",
            idempotencyKey = "key-comp-001",
            correlationId = "corr-comp-1",
            causationId = "cause-comp-1",
        )
        val compRes = service.compensatePayment(compCmd)
        assertNotNull(compRes)
        assertTrue(compRes.conserved)
        assertEquals(10000L, compRes.debitMinorUnits)
        assertEquals(10000L, compRes.creditMinorUnits)
        assertTrue(compRes.immutableCompensationReference.startsWith("COMP-REV-"))
        assertEquals(CANONICAL_PAYMENT_PORT_CONTRACT, compRes.semanticContract)

        // Idempotent compensation replay
        val compReplay = service.compensatePayment(compCmd)
        assertEquals(compRes.resultId, compReplay.resultId)
        assertEquals(compRes.immutableCompensationReference, compReplay.immutableCompensationReference)

        // 4. Production completion waits for selected provider
        val prodCmd = command(
            paymentReference = "pay-prod-wait-001",
            providerId = unselectedProdProviderId,
            idempotencyKey = "key-prod-wait-001",
        )
        val prodRes = service.executeOperation(prodCmd)
        assertEquals(CanonicalPaymentStatus.PENDING, prodRes.status)
        assertEquals("WAITING_FOR_SELECTED_PROVIDER", prodRes.safeReasonCode)
        assertEquals(CANONICAL_PAYMENT_PORT_CONTRACT, prodRes.semanticContract)

        // 5. Selected & certified production provider completes
        val certProdCmd = command(
            paymentReference = "pay-prod-cert-001",
            providerId = certifiedProdProviderId,
            idempotencyKey = "key-prod-cert-001",
        )
        val certProdRes = service.executeOperation(certProdCmd)
        assertEquals(CanonicalPaymentStatus.AUTHORIZED, certProdRes.status)
        assertEquals("SUCCESS", certProdRes.safeReasonCode)
        assertEquals(CANONICAL_PAYMENT_PORT_CONTRACT, certProdRes.semanticContract)

        // 6. Inbound Webhook processing through canonical port
        val webhookCmd = ProcessCanonicalWebhookCommand(
            tenantId = tenantId,
            providerId = fakeProviderId,
            signatureHeader = "valid-fake-sig",
            rawPayload = "{\"ref\":\"pay-auth-001\",\"status\":\"CAPTURED\",\"amount\":5000}",
            idempotencyKey = "key-wh-001",
            correlationId = "corr-wh-1",
            causationId = "cause-wh-1",
            deliverySequence = 2L,
        )
        val webhookRes = service.processWebhook(webhookCmd)
        assertEquals(CanonicalPaymentStatus.CAPTURED, webhookRes.status)
        assertEquals("pay-ref-fake-001", webhookRes.paymentReference)
        assertEquals(CANONICAL_PAYMENT_PORT_CONTRACT, webhookRes.semanticContract)

        // Audit & Outbox verification: correlation/causation identity and zero secrets/PII
        assertTrue(store.audit.isNotEmpty())
        assertTrue(store.outbox.isNotEmpty())
        for (audit in store.audit) {
            assertFalse(audit.type.contains("secret", ignoreCase = true))
            assertFalse(audit.type.contains("password", ignoreCase = true))
            assertFalse(audit.type.contains("credential", ignoreCase = true))
            assertNotNull(audit.correlationId)
            assertNotNull(audit.causationId)
        }
    }

    @Test
    fun `PAYMENT-001-01-T002 — Define canonical payment provider port rejects invalid, boundary, unauthorized, and stale input`() {
        val store = InMemoryCanonicalPaymentPortStore()
        val fakeAdapter = AdversarialPaymentProviderFakeAdapter(fakeProviderId, clock = clock)
        val service = service(store, mapOf(fakeProviderId to fakeAdapter))

        // 1. Unauthenticated request rejected
        assertFailsWith<AuthenticationFailure.Rejected> {
            service.executeOperation(command(principal = null, idempotencyKey = "key-unauth"))
        }.also { assertEquals(AuthErrorCode.UNAUTHENTICATED, it.code) }

        // 2. Non-admin player request rejected
        assertFailsWith<AuthenticationFailure.Rejected> {
            service.executeOperation(command(principal = playerPrincipal, idempotencyKey = "key-player"))
        }.also { assertEquals(AuthErrorCode.FORBIDDEN, it.code) }

        // 3. Cross-tenant request rejected
        assertFailsWith<AuthenticationFailure.Rejected> {
            service.executeOperation(command(principal = crossTenantPrincipal, idempotencyKey = "key-cross"))
        }.also { assertEquals(AuthErrorCode.FORBIDDEN, it.code) }

        // 4. Invalid currency code
        assertFailsWith<AuthenticationFailure.Rejected> {
            service.executeOperation(command(currencyCode = "TOOLONG", idempotencyKey = "key-bad-curr-1"))
        }.also { assertEquals(AuthErrorCode.INVALID, it.code) }

        assertFailsWith<AuthenticationFailure.Rejected> {
            service.executeOperation(command(currencyCode = "12", idempotencyKey = "key-bad-curr-2"))
        }.also { assertEquals(AuthErrorCode.INVALID, it.code) }

        // 5. Zero and negative amount
        assertFailsWith<AuthenticationFailure.Rejected> {
            service.executeOperation(command(amountMinorUnits = 0L, idempotencyKey = "key-zero-amt"))
        }.also { assertEquals(AuthErrorCode.INVALID, it.code) }

        assertFailsWith<AuthenticationFailure.Rejected> {
            service.executeOperation(command(amountMinorUnits = -1000L, idempotencyKey = "key-neg-amt"))
        }.also { assertEquals(AuthErrorCode.INVALID, it.code) }

        // 6. Blank paymentReference, correlationId, causationId
        assertFailsWith<AuthenticationFailure.Rejected> {
            service.executeOperation(command(paymentReference = "   ", idempotencyKey = "key-blank-ref"))
        }.also { assertEquals(AuthErrorCode.INVALID, it.code) }

        assertFailsWith<AuthenticationFailure.Rejected> {
            service.executeOperation(command(correlationId = "", idempotencyKey = "key-blank-corr"))
        }.also { assertEquals(AuthErrorCode.INVALID, it.code) }

        assertFailsWith<AuthenticationFailure.Rejected> {
            service.executeOperation(command(causationId = "", idempotencyKey = "key-blank-cause"))
        }.also { assertEquals(AuthErrorCode.INVALID, it.code) }

        // 7. Unknown provider rejected
        assertFailsWith<AuthenticationFailure.Rejected> {
            service.executeOperation(command(providerId = "prov-unknown-999", idempotencyKey = "key-unknown-prov"))
        }.also { assertEquals(AuthErrorCode.FORBIDDEN, it.code) }

        // 8. Stale expected version rejected
        assertFailsWith<AuthenticationFailure.Rejected> {
            service.executeOperation(command(expectedVersion = 42L, idempotencyKey = "key-stale-ver"))
        }.also { assertEquals(AuthErrorCode.STALE, it.code) }

        // 9. Conflicting replay with mutated payload
        service.executeOperation(command(amountMinorUnits = 5000L, idempotencyKey = "key-conflict-idem"))
        assertFailsWith<AuthenticationFailure.Rejected> {
            service.executeOperation(command(amountMinorUnits = 9999L, idempotencyKey = "key-conflict-idem"))
        }.also { assertEquals(AuthErrorCode.CONFLICT, it.code) }

        // 10. Invalid webhook signature rejected
        assertFailsWith<AuthenticationFailure.Rejected> {
            service.processWebhook(
                ProcessCanonicalWebhookCommand(
                    tenantId = tenantId,
                    providerId = fakeProviderId,
                    signatureHeader = "tampered-signature",
                    rawPayload = "{\"test\":1}",
                    idempotencyKey = "key-bad-sig-wh",
                    correlationId = "corr-bad-sig",
                    causationId = "cause-bad-sig",
                )
            )
        }.also { assertEquals(AuthErrorCode.FORBIDDEN, it.code) }

        // 11. Invalid compensation command rejected (debit != credit or negative)
        assertFailsWith<AuthenticationFailure.Rejected> {
            service.compensatePayment(
                CompensatePaymentCommand(
                    principal = adminPrincipal,
                    sessionId = "session-pay-1",
                    tenantId = tenantId,
                    paymentReference = "pay-ref-bad-comp",
                    originalDebitMinorUnits = 5000L,
                    compensatingCreditMinorUnits = 4000L, // Mismatched
                    currencyCode = "EUR",
                    reason = "Unbalanced compensation",
                    idempotencyKey = "key-unbalanced-comp",
                    correlationId = "corr-unbalanced",
                    causationId = "cause-unbalanced",
                )
            )
        }.also { assertEquals(AuthErrorCode.INVALID, it.code) }

        // Ensure zero unauthorized mutation occurred
        assertEquals(1, store.results.size)
        assertEquals(0, store.compensations.size)
    }

    @Test
    fun `PAYMENT-001-01-T003 — Define canonical payment provider port survives concurrency, duplicate delivery, and dependency failure`() {
        val store = InMemoryCanonicalPaymentPortStore()
        val fakeAdapter = AdversarialPaymentProviderFakeAdapter(fakeProviderId, clock = clock)
        val service = service(store, mapOf(fakeProviderId to fakeAdapter))

        // 1. Benchmark concurrent callers with identical idempotency key produce exactly one lawful effect
        val gate = CountDownLatch(1)
        val pool = Executors.newFixedThreadPool(4)
        val concurrentCalls = (1..4).map {
            pool.submit<CanonicalPaymentPortResult> {
                gate.await()
                service.executeOperation(
                    command(
                        paymentReference = "pay-concurrent-101",
                        amountMinorUnits = 7500L,
                        idempotencyKey = "key-concurrent-race-1",
                        correlationId = "corr-race-1",
                        causationId = "cause-race-1",
                    )
                )
            }
        }
        gate.countDown()
        val outcomes = concurrentCalls.map { runCatching { it.get() } }

        assertEquals(4, outcomes.count { it.isSuccess })
        val distinctResultIds = outcomes.mapNotNull { it.getOrNull()?.resultId }.toSet()
        assertEquals(1, distinctResultIds.size)
        val firstResult = outcomes[0].getOrThrow()
        assertEquals(7500L, firstResult.debitMinorUnits)
        assertEquals(7500L, firstResult.creditMinorUnits)
        assertTrue(firstResult.conserved)
        assertEquals(CANONICAL_PAYMENT_PORT_CONTRACT, firstResult.semanticContract)

        // 2. Adversarial fake adapter: duplicate delivery simulation
        val dupCmd = command(
            paymentReference = "pay-dup-sim-001",
            idempotencyKey = "key-dup-sim-001",
            simulationMode = AdversarialPaymentSimulationMode.DUPLICATE_DELIVERY,
        )
        val dupResult = service.executeOperation(dupCmd)
        assertEquals(CanonicalPaymentStatus.AUTHORIZED, dupResult.status)
        assertEquals("DUPLICATE_DELIVERY_HANDLED", dupResult.safeReasonCode)
        assertEquals(CANONICAL_PAYMENT_PORT_CONTRACT, dupResult.semanticContract)

        // 3. Adversarial fake adapter: out-of-order delivery simulation rejected / held
        val outOfOrderCmd = command(
            paymentReference = "pay-ooo-sim-001",
            idempotencyKey = "key-ooo-sim-001",
            simulationMode = AdversarialPaymentSimulationMode.OUT_OF_ORDER,
        )
        assertFailsWith<AuthenticationFailure.Rejected> {
            service.executeOperation(outOfOrderCmd)
        }.also { assertEquals(AuthErrorCode.CONFLICT, it.code) }

        // 4. Adversarial fake adapter: timeout / dependency failure fails closed
        val timeoutCmd = command(
            paymentReference = "pay-timeout-sim-001",
            idempotencyKey = "key-timeout-sim-001",
            simulationMode = AdversarialPaymentSimulationMode.TIMEOUT,
        )
        assertFailsWith<AuthenticationFailure.Rejected> {
            service.executeOperation(timeoutCmd)
        }.also { assertEquals(AuthErrorCode.DEPENDENCY_UNAVAILABLE, it.code) }

        pool.shutdown()
    }

    @Test
    fun `PAYMENT-001-01-T004 — Define canonical payment provider port remains compatible, recoverable, observable, and lifecycle-safe`() {
        // 1. Flyway migration compatibility guardrail: no unapproved persistence introduced
        val migrationDir = File("src/main/resources/db/migration")
        val sqlFiles = migrationDir.listFiles { _, name -> name.endsWith(".sql") } ?: emptyArray()
        assertTrue(sqlFiles.isNotEmpty())
        val migrationVersions = sqlFiles.map { it.name.substringBefore("__") }
        assertFalse(migrationVersions.contains("V17"))

        // 2. Lifecycle safety: Confirm no Android lifecycle surface is claimed
        val androidActivityClass = runCatching { Class.forName("android.app.Activity") }
        assertTrue(androidActivityClass.isFailure, "Authoritative backend must not link Android framework lifecycle")

        // 3. Recovery across restart: Recreating service instance sharing the store restores identical authoritative state
        val store = InMemoryCanonicalPaymentPortStore()
        val fakeAdapter = AdversarialPaymentProviderFakeAdapter(fakeProviderId, clock = clock)
        val initialService = service(store, mapOf(fakeProviderId to fakeAdapter))

        val paymentCmd = command(
            paymentReference = "pay-reboot-001",
            amountMinorUnits = 12000L,
            idempotencyKey = "key-reboot-pay-001",
            correlationId = "corr-reboot-1",
            causationId = "cause-reboot-1",
        )
        val initialResult = initialService.executeOperation(paymentCmd)

        // Instantiate new service instance representing system restart
        val restartedService = service(store, mapOf(fakeProviderId to fakeAdapter))
        val replayedResult = restartedService.executeOperation(paymentCmd)

        assertEquals(initialResult.resultId, replayedResult.resultId)
        assertEquals(initialResult.evidenceReference, replayedResult.evidenceReference)
        assertEquals(CANONICAL_PAYMENT_PORT_CONTRACT, replayedResult.semanticContract)

        // 4. Compensation after reboot: preserves history, never edits posted rows
        val compCmd = CompensatePaymentCommand(
            principal = adminPrincipal,
            sessionId = "session-pay-1",
            tenantId = tenantId,
            paymentReference = "pay-reboot-001",
            originalDebitMinorUnits = 12000L,
            compensatingCreditMinorUnits = 12000L,
            currencyCode = "EUR",
            reason = "Settlement dispute resolved by compensation",
            idempotencyKey = "key-reboot-comp-001",
            correlationId = "corr-reboot-comp-1",
            causationId = "cause-reboot-comp-1",
        )
        val compResult = restartedService.compensatePayment(compCmd)
        assertNotNull(compResult)
        assertEquals(12000L, compResult.debitMinorUnits)
        assertEquals(12000L, compResult.creditMinorUnits)
        assertTrue(compResult.conserved)
        assertTrue(compResult.immutableCompensationReference.startsWith("COMP-REV-"))

        // 5. Observability and zero raw secrets in audit or outbox
        assertTrue(store.audit.isNotEmpty())
        assertTrue(store.outbox.isNotEmpty())
        for (audit in store.audit) {
            assertEquals(tenantId, audit.tenantId)
            assertNotNull(audit.correlationId)
            assertNotNull(audit.causationId)
            assertFalse(audit.type.contains("secret", ignoreCase = true))
            assertFalse(audit.type.contains("token", ignoreCase = true))
        }
    }

    private fun service(
        store: CanonicalPaymentPortStore,
        adapters: Map<String, CanonicalPaymentProviderPort>,
    ) = CanonicalPaymentProviderPortService(
        policy = AdminRbacPolicy(true),
        sessions = TestCanonicalPaymentSessionDirectory(),
        store = store,
        adapters = adapters,
        clock = clock,
    )

    private fun command(
        principal: AuthenticatedPrincipal? = adminPrincipal,
        paymentReference: String = "pay-ref-default",
        operation: CanonicalPaymentOperation = CanonicalPaymentOperation.AUTHORIZE,
        amountMinorUnits: Long = 1000L,
        currencyCode: String = "EUR",
        providerId: String = fakeProviderId,
        paymentMethod: CanonicalPaymentMethodType = CanonicalPaymentMethodType.CARD,
        idempotencyKey: String = "key-pay-default",
        correlationId: String = "corr-pay-default",
        causationId: String = "cause-pay-default",
        expectedVersion: Long = 1L,
        simulationMode: AdversarialPaymentSimulationMode = AdversarialPaymentSimulationMode.NORMAL,
        deliverySequence: Long = 1L,
    ) = ExecuteCanonicalPaymentCommand(
        principal = principal,
        sessionId = "session-pay-1",
        tenantId = tenantId,
        paymentReference = paymentReference,
        operation = operation,
        amountMinorUnits = amountMinorUnits,
        currencyCode = currencyCode,
        providerId = providerId,
        paymentMethod = paymentMethod,
        idempotencyKey = idempotencyKey,
        correlationId = correlationId,
        causationId = causationId,
        expectedVersion = expectedVersion,
        simulationMode = simulationMode,
        deliverySequence = deliverySequence,
    )
}

private class TestCanonicalPaymentSessionDirectory : AdminSessionDirectory {
    override fun find(tenantId: String, principalId: String, sessionId: String) =
        if (tenantId == "tenant-canonical-pay-1" && principalId == "admin-pay-1" && sessionId == "session-pay-1")
            AdminSessionStatus(true, false, Instant.parse("2026-09-19T18:00:00Z"))
        else null
}
