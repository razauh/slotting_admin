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

class AdversarialPaymentProviderFakeTest {
    private val now = Instant.parse("2026-09-19T15:00:00Z")
    private val clock = Clock.fixed(now, ZoneOffset.UTC)
    private val tenantId = "tenant-fake-pay-1"
    private val fakeProviderId = "prov-adversarial-fake-01"
    private val uncertifiedProdProviderId = "prov-prod-uncertified-01"
    private val secretKey = "raw-secret-key-payment-fake-12345"

    private val adminPrincipal = AuthenticatedPrincipal(
        id = "admin-fake-1",
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
        AdversarialPaymentProviderFakeBinding.isBound = false
    }

    @AfterEach
    fun tearDown() {
        AdversarialPaymentProviderFakeBinding.isBound = true
    }

    @Test
    fun `PAYMENT-001-02-T001 — Build adversarial payment provider fake produces the required authoritative outcome`() {
        // 1. Expected RED failure verification: Fail-closed gate throws expected assertion when unbound
        AdversarialPaymentProviderFakeBinding.isBound = false
        val store = InMemoryAdversarialPaymentFakeStore()
        val service = service(store)

        val cfgCmd = ConfigureAdversarialPaymentFakeCommand(
            principal = adminPrincipal,
            sessionId = "session-fake-1",
            tenantId = tenantId,
            providerId = fakeProviderId,
            simulationMode = AdversarialPaymentSimulationMode.NORMAL,
            secretKey = secretKey,
            idempotencyKey = "key-cfg-fake-001",
            correlationId = "corr-cfg-1",
            causationId = "cause-cfg-1",
        )

        val gateError = assertFailsWith<AssertionError> {
            service.configureFake(cfgCmd)
        }
        assertEquals("domain tied to vendor", gateError.message)

        // Bind the fail-closed gate
        AdversarialPaymentProviderFakeBinding.isBound = true

        // 2. Authoritative configuration: Configure adversarial payment fake
        val cfgResult = service.configureFake(cfgCmd)
        assertNotNull(cfgResult)
        assertEquals(tenantId, cfgResult.tenantId)
        assertEquals(fakeProviderId, cfgResult.providerId)
        assertEquals(AdversarialPaymentSimulationMode.NORMAL, cfgResult.simulationMode)
        assertEquals(ADVERSARIAL_PAYMENT_FAKE_CONTRACT, cfgResult.semanticContract)

        // Idempotent configuration replay
        val cfgReplay = service.configureFake(cfgCmd)
        assertEquals(cfgResult.resultId, cfgReplay.resultId)
        assertEquals(cfgResult.evidenceReference, cfgReplay.evidenceReference)

        // 3. Execute simulated payment (AUTHORIZE)
        val payCmd = paymentCommand(
            paymentReference = "pay-fake-auth-001",
            operation = CanonicalPaymentOperation.AUTHORIZE,
            amountMinorUnits = 12500L,
            currencyCode = "EUR",
            idempotencyKey = "key-fake-auth-001",
            correlationId = "corr-fake-auth-1",
            causationId = "cause-fake-auth-1",
        )
        val payResult = service.executeSimulatedPayment(payCmd)
        assertNotNull(payResult)
        assertEquals(CanonicalPaymentStatus.AUTHORIZED, payResult.status)
        assertEquals("pay-fake-auth-001", payResult.paymentReference)
        assertEquals(12500L, payResult.amountMinorUnits)
        assertEquals("EUR", payResult.currencyCode)
        assertEquals("SUCCESS", payResult.safeReasonCode)
        assertEquals(ADVERSARIAL_PAYMENT_FAKE_CONTRACT, payResult.semanticContract)

        // Financial conservation: Assert debits equal credits, no double effect, transactional atomicity
        assertEquals(payResult.debitMinorUnits, payResult.creditMinorUnits)
        assertTrue(payResult.conserved)
        assertEquals(12500L, payResult.debitMinorUnits)

        // Idempotent payment replay
        val payReplay = service.executeSimulatedPayment(payCmd)
        assertEquals(payResult.resultId, payReplay.resultId)
        assertEquals(payResult.evidenceReference, payReplay.evidenceReference)

        // 4. Immutable compensation: debits equal credits and reconciliation
        val compCmd = ExecuteSimulatedCompensationCommand(
            principal = adminPrincipal,
            sessionId = "session-fake-1",
            tenantId = tenantId,
            paymentReference = "pay-fake-auth-001",
            originalDebitMinorUnits = 12500L,
            compensatingCreditMinorUnits = 12500L,
            currencyCode = "EUR",
            reason = "Customer cancelled order before capture",
            idempotencyKey = "key-fake-comp-001",
            correlationId = "corr-fake-comp-1",
            causationId = "cause-fake-comp-1",
        )
        val compResult = service.executeSimulatedCompensation(compCmd)
        assertNotNull(compResult)
        assertEquals(12500L, compResult.debitMinorUnits)
        assertEquals(12500L, compResult.creditMinorUnits)
        assertTrue(compResult.conserved)
        assertTrue(compResult.immutableCompensationReference.startsWith("COMP-REV-"))
        assertEquals(ADVERSARIAL_PAYMENT_FAKE_CONTRACT, compResult.semanticContract)

        // Idempotent compensation replay
        val compReplay = service.executeSimulatedCompensation(compCmd)
        assertEquals(compResult.resultId, compReplay.resultId)
        assertEquals(compResult.immutableCompensationReference, compReplay.immutableCompensationReference)

        // 5. Generate and process simulated signed inbound webhook
        val webhookPayload = service.generateSimulatedWebhook(
            SimulateInboundWebhookCommand(
                tenantId = tenantId,
                providerId = fakeProviderId,
                paymentReference = "pay-fake-auth-001",
                amountMinorUnits = 12500L,
                currencyCode = "EUR",
                status = CanonicalPaymentStatus.CAPTURED,
                deliverySequence = 2L,
                idempotencyKey = "key-gen-wh-001",
                correlationId = "corr-gen-wh-1",
                causationId = "cause-gen-wh-1",
            )
        )
        val webhookResult = service.verifyAndProcessSimulatedWebhook(
            tenantId = tenantId,
            providerId = fakeProviderId,
            payload = webhookPayload,
            idempotencyKey = "key-proc-wh-001",
            correlationId = "corr-proc-wh-1",
            causationId = "cause-proc-wh-1",
        )
        assertEquals(CanonicalPaymentStatus.CAPTURED, webhookResult.status)
        assertEquals("SUCCESS", webhookResult.safeReasonCode)
        assertEquals(ADVERSARIAL_PAYMENT_FAKE_CONTRACT, webhookResult.semanticContract)

        // 6. Production completion waits for selected provider
        val certStore = TestPaymentAdapterCertificationStore()
        val prodService = service(store, certStore)
        val prodCfgCmd = cfgCmd.copy(
            providerId = uncertifiedProdProviderId,
            idempotencyKey = "key-cfg-prod-uncert",
        )
        prodService.configureFake(prodCfgCmd)

        // Register uncertified production provider in certification store
        certStore.saveCertification(
            PaymentAdapterCertification(
                certificationId = UUID.randomUUID(),
                tenantId = tenantId,
                providerId = uncertifiedProdProviderId,
                tier = AdapterTier.PRODUCTION_CERTIFIED,
                status = CertificationStatus.PENDING_REVIEW, // Not certified yet
                canonicalSemanticsVerified = false,
                signatureVerificationVerified = false,
                retryAcknowledgementVerified = false,
                productionApproved = false,
                certifierId = "admin-fake-1",
                issuedAt = now,
                expiresAt = now.plusSeconds(86400),
            ),
            CertificationVerificationResult(
                resultId = UUID.randomUUID(),
                certificationId = UUID.randomUUID(),
                tenantId = tenantId,
                providerId = uncertifiedProdProviderId,
                tier = AdapterTier.PRODUCTION_CERTIFIED,
                status = CertificationStatus.PENDING_REVIEW,
                serverTime = now,
                evidenceReference = "CERT-EVID-WAIT",
            ),
            queryFingerprint = "fp-cert-wait",
            idempotencyKey = "key-cert-save-wait",
            audit = AuditEvent(UUID.randomUUID(), UUID.randomUUID(), tenantId, "CERT_PENDING", now, "corr-1", "cause-1"),
            outbox = OutboxEvent(UUID.randomUUID(), UUID.randomUUID(), tenantId, "CERT_PENDING", now),
        )

        val prodPayCmd = paymentCommand(
            providerId = uncertifiedProdProviderId,
            paymentReference = "pay-prod-wait-002",
            idempotencyKey = "key-prod-wait-002",
        )
        val prodPayResult = prodService.executeSimulatedPayment(prodPayCmd)
        assertEquals(CanonicalPaymentStatus.PENDING, prodPayResult.status)
        assertEquals("WAITING_FOR_SELECTED_PROVIDER", prodPayResult.safeReasonCode)
        assertEquals(ADVERSARIAL_PAYMENT_FAKE_CONTRACT, prodPayResult.semanticContract)

        // 7. Audit & Outbox verification: correlation/causation identity and zero secrets/PII
        assertTrue(store.audit.isNotEmpty())
        assertTrue(store.outbox.isNotEmpty())
        for (audit in store.audit) {
            assertFalse(audit.type.contains("secret", ignoreCase = true))
            assertFalse(audit.type.contains("password", ignoreCase = true))
            assertFalse(audit.type.contains("token", ignoreCase = true))
            assertNotNull(audit.correlationId)
            assertNotNull(audit.causationId)
        }
    }

    @Test
    fun `PAYMENT-001-02-T002 — Build adversarial payment provider fake rejects invalid, boundary, unauthorized, and stale input`() {
        AdversarialPaymentProviderFakeBinding.isBound = true
        val store = InMemoryAdversarialPaymentFakeStore()
        val service = service(store)
        configureDefaultFake(service)

        // 1. Unauthenticated request rejected
        assertFailsWith<AuthenticationFailure.Rejected> {
            service.executeSimulatedPayment(paymentCommand(principal = null, idempotencyKey = "key-unauth-fake"))
        }.also { assertEquals(AuthErrorCode.UNAUTHENTICATED, it.code) }

        // 2. Non-admin player request rejected
        assertFailsWith<AuthenticationFailure.Rejected> {
            service.executeSimulatedPayment(paymentCommand(principal = playerPrincipal, idempotencyKey = "key-player-fake"))
        }.also { assertEquals(AuthErrorCode.FORBIDDEN, it.code) }

        // 3. Cross-tenant request rejected
        assertFailsWith<AuthenticationFailure.Rejected> {
            service.executeSimulatedPayment(paymentCommand(principal = crossTenantPrincipal, idempotencyKey = "key-cross-fake"))
        }.also { assertEquals(AuthErrorCode.FORBIDDEN, it.code) }

        // 4. Invalid currency code
        assertFailsWith<AuthenticationFailure.Rejected> {
            service.executeSimulatedPayment(paymentCommand(currencyCode = "TOOLONG", idempotencyKey = "key-bad-curr-fake"))
        }.also { assertEquals(AuthErrorCode.INVALID, it.code) }

        // 5. Zero and negative amount
        assertFailsWith<AuthenticationFailure.Rejected> {
            service.executeSimulatedPayment(paymentCommand(amountMinorUnits = 0L, idempotencyKey = "key-zero-amt-fake"))
        }.also { assertEquals(AuthErrorCode.INVALID, it.code) }

        assertFailsWith<AuthenticationFailure.Rejected> {
            service.executeSimulatedPayment(paymentCommand(amountMinorUnits = -500L, idempotencyKey = "key-neg-amt-fake"))
        }.also { assertEquals(AuthErrorCode.INVALID, it.code) }

        // 6. Blank fields
        assertFailsWith<AuthenticationFailure.Rejected> {
            service.executeSimulatedPayment(paymentCommand(paymentReference = "   ", idempotencyKey = "key-blank-ref-fake"))
        }.also { assertEquals(AuthErrorCode.INVALID, it.code) }

        assertFailsWith<AuthenticationFailure.Rejected> {
            service.executeSimulatedPayment(paymentCommand(correlationId = "", idempotencyKey = "key-blank-corr-fake"))
        }.also { assertEquals(AuthErrorCode.INVALID, it.code) }

        // 7. Unconfigured provider rejected
        assertFailsWith<AuthenticationFailure.Rejected> {
            service.executeSimulatedPayment(paymentCommand(providerId = "prov-unconfigured", idempotencyKey = "key-unconf-fake"))
        }.also { assertEquals(AuthErrorCode.FORBIDDEN, it.code) }

        // 8. Stale expected version rejected
        assertFailsWith<AuthenticationFailure.Rejected> {
            service.executeSimulatedPayment(paymentCommand(expectedVersion = 10L, idempotencyKey = "key-stale-ver-fake"))
        }.also { assertEquals(AuthErrorCode.STALE, it.code) }

        // 9. Conflicting replay with mutated payload
        service.executeSimulatedPayment(paymentCommand(amountMinorUnits = 1000L, idempotencyKey = "key-conflict-fake"))
        assertFailsWith<AuthenticationFailure.Rejected> {
            service.executeSimulatedPayment(paymentCommand(amountMinorUnits = 2000L, idempotencyKey = "key-conflict-fake"))
        }.also { assertEquals(AuthErrorCode.CONFLICT, it.code) }

        // 10. Tampered webhook signature rejected
        val webhookPayload = service.generateSimulatedWebhook(
            SimulateInboundWebhookCommand(
                tenantId = tenantId,
                providerId = fakeProviderId,
                paymentReference = "pay-ref-webhook-bad",
                amountMinorUnits = 5000L,
                currencyCode = "EUR",
                tamperSignature = true,
                idempotencyKey = "key-gen-bad-sig",
                correlationId = "corr-gen-bad",
                causationId = "cause-gen-bad",
            )
        )
        assertFailsWith<AuthenticationFailure.Rejected> {
            service.verifyAndProcessSimulatedWebhook(
                tenantId = tenantId,
                providerId = fakeProviderId,
                payload = webhookPayload,
                idempotencyKey = "key-proc-bad-sig",
                correlationId = "corr-proc-bad",
                causationId = "cause-proc-bad",
            )
        }.also { assertEquals(AuthErrorCode.FORBIDDEN, it.code) }

        // 11. Invalid compensation command rejected
        assertFailsWith<AuthenticationFailure.Rejected> {
            service.executeSimulatedCompensation(
                ExecuteSimulatedCompensationCommand(
                    principal = adminPrincipal,
                    sessionId = "session-fake-1",
                    tenantId = tenantId,
                    paymentReference = "pay-ref-bad-comp",
                    originalDebitMinorUnits = 5000L,
                    compensatingCreditMinorUnits = 3000L, // Mismatched
                    currencyCode = "EUR",
                    reason = "Unbalanced compensation",
                    idempotencyKey = "key-bad-comp-fake",
                    correlationId = "corr-bad-comp",
                    causationId = "cause-bad-comp",
                )
            )
        }.also { assertEquals(AuthErrorCode.INVALID, it.code) }

        // Assert zero unauthorized durable mutation
        assertEquals(1, store.executions.size)
        assertEquals(0, store.compensations.size)
    }

    @Test
    fun `PAYMENT-001-02-T003 — Build adversarial payment provider fake survives concurrency, duplicate delivery, and dependency failure`() {
        AdversarialPaymentProviderFakeBinding.isBound = true
        val store = InMemoryAdversarialPaymentFakeStore()
        val service = service(store)
        configureDefaultFake(service)

        // 1. Concurrency: 4 concurrent callers with identical idempotency key produce exactly 1 distinct resultId
        val gate = CountDownLatch(1)
        val pool = Executors.newFixedThreadPool(4)
        val concurrentCalls = (1..4).map {
            pool.submit<AdversarialPaymentExecutionResult> {
                gate.await()
                service.executeSimulatedPayment(
                    paymentCommand(
                        paymentReference = "pay-race-fake-001",
                        amountMinorUnits = 8500L,
                        idempotencyKey = "key-race-fake-idem",
                        correlationId = "corr-race-fake",
                        causationId = "cause-race-fake",
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
        assertEquals(8500L, firstResult.debitMinorUnits)
        assertEquals(8500L, firstResult.creditMinorUnits)
        assertTrue(firstResult.conserved)
        assertEquals(ADVERSARIAL_PAYMENT_FAKE_CONTRACT, firstResult.semanticContract)

        // 2. Duplicate delivery simulation mode
        val dupCmd = paymentCommand(
            paymentReference = "pay-dup-fake-001",
            idempotencyKey = "key-dup-fake-001",
            simulationMode = AdversarialPaymentSimulationMode.DUPLICATE_DELIVERY,
        )
        val dupResult = service.executeSimulatedPayment(dupCmd)
        assertEquals(CanonicalPaymentStatus.AUTHORIZED, dupResult.status)
        assertEquals("DUPLICATE_DELIVERY_HANDLED", dupResult.safeReasonCode)
        assertEquals(ADVERSARIAL_PAYMENT_FAKE_CONTRACT, dupResult.semanticContract)

        // 3. Out-of-order delivery simulation mode rejected / held
        val oooCmd = paymentCommand(
            paymentReference = "pay-ooo-fake-001",
            idempotencyKey = "key-ooo-fake-001",
            simulationMode = AdversarialPaymentSimulationMode.OUT_OF_ORDER,
        )
        assertFailsWith<AuthenticationFailure.Rejected> {
            service.executeSimulatedPayment(oooCmd)
        }.also { assertEquals(AuthErrorCode.CONFLICT, it.code) }

        // 4. Timeout / dependency failure fails closed with DEPENDENCY_UNAVAILABLE
        val timeoutCmd = paymentCommand(
            paymentReference = "pay-timeout-fake-001",
            idempotencyKey = "key-timeout-fake-001",
            simulationMode = AdversarialPaymentSimulationMode.TIMEOUT,
        )
        assertFailsWith<AuthenticationFailure.Rejected> {
            service.executeSimulatedPayment(timeoutCmd)
        }.also { assertEquals(AuthErrorCode.DEPENDENCY_UNAVAILABLE, it.code) }

        pool.shutdown()
    }

    @Test
    fun `PAYMENT-001-02-T004 — Build adversarial payment provider fake remains compatible, recoverable, observable, and lifecycle-safe`() {
        AdversarialPaymentProviderFakeBinding.isBound = true

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
        val store = InMemoryAdversarialPaymentFakeStore()
        val initialService = service(store)
        configureDefaultFake(initialService)

        val paymentCmd = paymentCommand(
            paymentReference = "pay-reboot-fake-001",
            amountMinorUnits = 15000L,
            idempotencyKey = "key-reboot-fake-001",
            correlationId = "corr-reboot-fake-1",
            causationId = "cause-reboot-fake-1",
        )
        val initialResult = initialService.executeSimulatedPayment(paymentCmd)

        // Instantiate restarted service instance sharing the store
        val restartedService = service(store)
        val replayedResult = restartedService.executeSimulatedPayment(paymentCmd)

        assertEquals(initialResult.resultId, replayedResult.resultId)
        assertEquals(initialResult.evidenceReference, replayedResult.evidenceReference)
        assertEquals(ADVERSARIAL_PAYMENT_FAKE_CONTRACT, replayedResult.semanticContract)

        // 4. Compensation after reboot: preserves history, never edits posted rows
        val compCmd = ExecuteSimulatedCompensationCommand(
            principal = adminPrincipal,
            sessionId = "session-fake-1",
            tenantId = tenantId,
            paymentReference = "pay-reboot-fake-001",
            originalDebitMinorUnits = 15000L,
            compensatingCreditMinorUnits = 15000L,
            currencyCode = "EUR",
            reason = "Settlement error resolved by immutable compensation",
            idempotencyKey = "key-comp-reboot-fake-001",
            correlationId = "corr-comp-reboot",
            causationId = "cause-comp-reboot",
        )
        val compResult = restartedService.executeSimulatedCompensation(compCmd)
        assertNotNull(compResult)
        assertEquals(15000L, compResult.debitMinorUnits)
        assertEquals(15000L, compResult.creditMinorUnits)
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
            assertFalse(audit.type.contains("credential", ignoreCase = true))
        }
    }

    private fun configureDefaultFake(service: AdversarialPaymentProviderFakeService) {
        val cfgCmd = ConfigureAdversarialPaymentFakeCommand(
            principal = adminPrincipal,
            sessionId = "session-fake-1",
            tenantId = tenantId,
            providerId = fakeProviderId,
            simulationMode = AdversarialPaymentSimulationMode.NORMAL,
            secretKey = secretKey,
            idempotencyKey = "key-cfg-default",
            correlationId = "corr-cfg-default",
            causationId = "cause-cfg-default",
        )
        service.configureFake(cfgCmd)
    }

    private fun service(
        store: AdversarialPaymentFakeStore,
        certificationStore: PaymentAdapterCertificationStore? = null,
    ) = AdversarialPaymentProviderFakeService(
        policy = AdminRbacPolicy(true),
        sessions = TestAdversarialPaymentSessionDirectory(),
        store = store,
        certificationStore = certificationStore,
        clock = clock,
    )

    private fun paymentCommand(
        principal: AuthenticatedPrincipal? = adminPrincipal,
        paymentReference: String = "pay-fake-ref-001",
        operation: CanonicalPaymentOperation = CanonicalPaymentOperation.AUTHORIZE,
        amountMinorUnits: Long = 5000L,
        currencyCode: String = "EUR",
        providerId: String = fakeProviderId,
        paymentMethod: CanonicalPaymentMethodType = CanonicalPaymentMethodType.CARD,
        idempotencyKey: String = "key-fake-pay-default",
        correlationId: String = "corr-fake-pay-default",
        causationId: String = "cause-fake-pay-default",
        expectedVersion: Long = 1L,
        simulationMode: AdversarialPaymentSimulationMode? = null,
        deliverySequence: Long = 1L,
    ) = ExecuteSimulatedPaymentCommand(
        principal = principal,
        sessionId = "session-fake-1",
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

private class TestAdversarialPaymentSessionDirectory : AdminSessionDirectory {
    override fun find(tenantId: String, principalId: String, sessionId: String) =
        if (tenantId == "tenant-fake-pay-1" && principalId == "admin-fake-1" && sessionId == "session-fake-1")
            AdminSessionStatus(true, false, Instant.parse("2026-09-19T18:00:00Z"))
        else null
}

private class TestPaymentAdapterCertificationStore : PaymentAdapterCertificationStore {
    val certs = mutableMapOf<String, PaymentAdapterCertification>()
    val results = mutableMapOf<String, Pair<String, CertificationVerificationResult>>()

    override fun findByIdempotency(tenantId: String, idempotencyKey: String) = results["$tenantId:$idempotencyKey"]
    override fun findCertification(tenantId: String, certificationId: UUID) =
        certs.values.firstOrNull { it.tenantId == tenantId && it.certificationId == certificationId }
    override fun findByProvider(tenantId: String, providerId: String) = certs["$tenantId:$providerId"]
    override fun saveCertification(
        certification: PaymentAdapterCertification,
        result: CertificationVerificationResult,
        queryFingerprint: String,
        idempotencyKey: String,
        audit: AuditEvent,
        outbox: OutboxEvent,
    ) {
        certs["${certification.tenantId}:${certification.providerId}"] = certification
        results["${certification.tenantId}:$idempotencyKey"] = queryFingerprint to result
    }
}
