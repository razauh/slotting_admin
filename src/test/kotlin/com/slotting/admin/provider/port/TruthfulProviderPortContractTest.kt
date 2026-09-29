package com.slotting.admin.provider.port

import com.slotting.admin.provider.port.adapters.*
import org.junit.jupiter.api.Test
import java.time.Instant
import java.util.UUID
import kotlin.test.*

/**
 * TC-012 TDD Contract Test Suite:
 * Truthful payment and payout provider ports, outcome semantics, capability discovery,
 * fail-closed production protections, and concrete adapter contracts.
 */
class TruthfulProviderPortContractTest {

    private val now = Instant.parse("2026-09-25T10:00:00Z")

    private val sampleConfig = ProviderConfiguration(
        providerId = "prov-test",
        environment = ProviderEnvironment.SANDBOX,
        baseUrl = "https://sandbox.api.provider.test/v1",
        timeoutMs = 3000L,
    )

    private val sampleCredentials = ProviderCredentials(
        merchantId = "MERCHANT-001",
        apiKey = "api-key-test-123",
        clientSecret = "secret-test-456",
        signingSecretOrKey = "signing-secret-789",
    )

    private fun sampleDeposit(
        opId: UUID = UUID.randomUUID(),
        amount: Long = 50_000L, // 500.00 PKR
        currency: String = "PKR",
        idempotencyKey: String = "idem-${UUID.randomUUID()}",
        providerId: String = "prov-test",
    ) = ProviderDepositCommand(
        tenantId = "tenant-pk-1",
        operationId = opId,
        idempotencyKey = idempotencyKey,
        providerId = providerId,
        methodId = "EASYPAISA",
        amountMinorUnits = amount,
        currency = currency,
        customerIdentifier = "03001234567",
        callbackUrl = "https://slotting.example.com/api/v1/callbacks/$providerId",
        correlationId = "corr-1",
    )

    private fun samplePayout(
        opId: UUID = UUID.randomUUID(),
        amount: Long = 100_000L, // 1000.00 PKR
        currency: String = "PKR",
        idempotencyKey: String = "idem-${UUID.randomUUID()}",
        providerId: String = "prov-test",
    ) = ProviderPayoutCommand(
        tenantId = "tenant-pk-1",
        operationId = opId,
        idempotencyKey = idempotencyKey,
        providerId = providerId,
        methodId = "BANK_TRANSFER",
        amountMinorUnits = amount,
        currency = currency,
        destinationAccount = "PK36MEZN0001234567890101",
        destinationTitle = "John Doe",
        correlationId = "corr-1",
    )

    // =========================================================================
    // 1. Ambiguity Invariant: Timeouts, Drops, 5xx, and Lost Responses
    // =========================================================================

    @Test
    fun `test01 timeout or lost response after dispatch resolves strictly to UNKNOWN_AMBIGUOUS`() {
        val adapter = AdversarialTestPaymentAdapter(
            providerId = "prov-adv-1",
            simulationMode = AdversarialSimulationMode.TIMEOUT_AFTER_DISPATCH,
        )

        val cmd = sampleDeposit(providerId = "prov-adv-1")
        val outcome = adapter.deposit(cmd, sampleConfig, sampleCredentials)

        // Local timeout must NEVER be inferred as FAILED or ACCEPTED; it must be UNKNOWN_AMBIGUOUS
        assertEquals(ProviderOutcomeStatus.UNKNOWN_AMBIGUOUS, outcome.status)
        assertTrue(outcome.isAmbiguous)
        assertTrue(outcome.retryable)
        assertNull(outcome.providerReference, "No fake provider reference allowed on ambiguous timeout")
        assertEquals(cmd.operationId, outcome.operationId)
    }

    @Test
    fun `test02 connection reset or HTTP 5xx resolves strictly to UNKNOWN_AMBIGUOUS`() {
        val adapter = AdversarialTestPaymentAdapter(
            providerId = "prov-adv-1",
            simulationMode = AdversarialSimulationMode.HTTP_500_INTERNAL_ERROR,
        )

        val cmd = sampleDeposit(providerId = "prov-adv-1")
        val outcome = adapter.deposit(cmd, sampleConfig, sampleCredentials)

        assertEquals(ProviderOutcomeStatus.UNKNOWN_AMBIGUOUS, outcome.status)
        assertTrue(outcome.isAmbiguous)
        assertEquals("HTTP_500", outcome.rawResponseCode)
    }

    @Test
    fun `test03 malformed provider response resolves to UNKNOWN_AMBIGUOUS`() {
        val adapter = AdversarialTestPaymentAdapter(
            providerId = "prov-adv-1",
            simulationMode = AdversarialSimulationMode.MALFORMED_RESPONSE_PAYLOAD,
        )

        val cmd = sampleDeposit(providerId = "prov-adv-1")
        val outcome = adapter.deposit(cmd, sampleConfig, sampleCredentials)

        assertEquals(ProviderOutcomeStatus.UNKNOWN_AMBIGUOUS, outcome.status)
        assertTrue(outcome.isAmbiguous)
    }

    // =========================================================================
    // 2. Truthful Outcomes: Acceptance, Decline, and No Fabricated IDs
    // =========================================================================

    @Test
    fun `test04 successful acceptance returns truthful provider reference and never fabricates one on failure`() {
        val adapter = AdversarialTestPaymentAdapter(
            providerId = "prov-adv-1",
            simulationMode = AdversarialSimulationMode.NORMAL_SUCCESS,
        )

        val cmd = sampleDeposit(providerId = "prov-adv-1")
        val success = adapter.deposit(cmd, sampleConfig, sampleCredentials)

        assertEquals(ProviderOutcomeStatus.ACCEPTED, success.status)
        assertFalse(success.isAmbiguous)
        assertNotNull(success.providerReference)
        assertEquals(cmd.operationId, success.operationId)

        // On explicit decline
        val declineAdapter = AdversarialTestPaymentAdapter(
            providerId = "prov-adv-1",
            simulationMode = AdversarialSimulationMode.EXPLICIT_DECLINE,
        )
        val declined = declineAdapter.deposit(cmd, sampleConfig, sampleCredentials)

        assertEquals(ProviderOutcomeStatus.DECLINED, declined.status)
        assertFalse(declined.isAmbiguous)
        assertNull(declined.providerReference, "Production outcome must not fabricate reference on decline")
    }

    // =========================================================================
    // 3. Immutable Operation Identity & Retries
    // =========================================================================

    @Test
    fun `test05 retry preserves immutable operation identity and idempotency key`() {
        val adapter = AdversarialTestPaymentAdapter(
            providerId = "prov-adv-1",
            simulationMode = AdversarialSimulationMode.NORMAL_SUCCESS,
        )

        val fixedOpId = UUID.randomUUID()
        val fixedIdempotencyKey = "IDEM-IMMUTABLE-1"
        val cmd1 = sampleDeposit(opId = fixedOpId, idempotencyKey = fixedIdempotencyKey, providerId = "prov-adv-1")

        val res1 = adapter.deposit(cmd1, sampleConfig, sampleCredentials)
        val res2 = adapter.deposit(cmd1, sampleConfig, sampleCredentials)

        assertEquals(res1.operationId, res2.operationId)
        assertEquals(res1.providerReference, res2.providerReference)
        assertEquals(1, adapter.recordedDispatches(fixedIdempotencyKey))
    }

    // =========================================================================
    // 4. Missing Credentials & Fail-Closed Transport
    // =========================================================================

    @Test
    fun `test06 missing or invalid credentials fails closed with UNAVAILABLE`() {
        val adapter = OneLinkRaastAdapter()

        val cmd = sampleDeposit(providerId = adapter.providerId)
        // Missing credentials (null)
        val outcome = adapter.deposit(cmd, sampleConfig, credentials = null)

        assertEquals(ProviderOutcomeStatus.UNAVAILABLE, outcome.status)
        assertEquals("CREDENTIALS_UNAVAILABLE", outcome.rawResponseCode)
        assertFalse(outcome.isAmbiguous)
    }

    @Test
    fun `test07 production environment rejects insecure HTTP and private IP base URLs`() {
        val prodConfigInsecure = ProviderConfiguration(
            providerId = "prov-test",
            environment = ProviderEnvironment.PRODUCTION,
            baseUrl = "http://api.provider.test/v1", // Insecure HTTP!
        )
        assertFailsWith<IllegalArgumentException> {
            prodConfigInsecure.validateNetworkSafety()
        }

        val prodConfigPrivateIp = ProviderConfiguration(
            providerId = "prov-test",
            environment = ProviderEnvironment.PRODUCTION,
            baseUrl = "https://127.0.0.1:8443/v1", // Private loopback IP in production!
        )
        assertFailsWith<IllegalArgumentException> {
            prodConfigPrivateIp.validateNetworkSafety()
        }
    }

    // =========================================================================
    // 5. Production Profile Guardrail: Fakes Prohibited in Production
    // =========================================================================

    @Test
    fun `test08 production profile guardrail fails closed if test or fake adapter is configured`() {
        val fakeAdapter = AdversarialTestPaymentAdapter("fake-1")

        assertFailsWith<IllegalStateException> {
            ProductionProviderGuard.assertProductionReady(fakeAdapter, profile = "production")
        }.also { assertTrue(it.message!!.contains("cannot be composed in production")) }

        // Allowed in test profile
        ProductionProviderGuard.assertProductionReady(fakeAdapter, profile = "test")
    }

    // =========================================================================
    // 6. Capability Discovery & Unsupported Operation Enforcement
    // =========================================================================

    @Test
    fun `test09 capability discovery accurately reflects documented capabilities and denies unestablished ones`() {
        val jazzCash = JazzCashAdapter()
        assertTrue(jazzCash.capabilities.supportsDeposit, "JazzCash supports pay-in")
        assertTrue(jazzCash.capabilities.supportsStatusLookup, "JazzCash supports inquiry")
        assertTrue(jazzCash.capabilities.supportsRefund, "JazzCash supports refund")
        assertFalse(jazzCash.capabilities.supportsPayout, "JazzCash payout must NOT be inferred without documented contract")

        // Attempting payout on JazzCash must return FAILED / DECLINED with UNSUPPORTED_OPERATION
        val payoutCmd = samplePayout(providerId = jazzCash.providerId)
        val payoutOutcome = jazzCash.payout(payoutCmd, sampleConfig, sampleCredentials)
        assertEquals(ProviderOutcomeStatus.DECLINED, payoutOutcome.status)
        assertEquals("UNSUPPORTED_OPERATION", payoutOutcome.rawResponseCode)

        val easypaisa = EasypaisaAdapter()
        assertTrue(easypaisa.capabilities.supportsDeposit, "Easypaisa supports mobile and OTC pay-in")
        assertTrue(easypaisa.capabilities.supportsStatusLookup, "Easypaisa supports inquiry")
        assertFalse(easypaisa.capabilities.supportsPayout, "Easypaisa payout must NOT be inferred")
        assertFalse(easypaisa.capabilities.supportsCancellation, "Easypaisa cancellation not established")

        val oneLinkRaast = OneLinkRaastAdapter()
        assertTrue(oneLinkRaast.capabilities.supportsRequestToPay, "OneLink Raast supports RTP")
        assertTrue(oneLinkRaast.capabilities.supportsCancellation, "OneLink Raast supports RTP cancellation")
        assertTrue(oneLinkRaast.capabilities.supportsStatusLookup, "OneLink Raast supports status inquiry")
        assertTrue(oneLinkRaast.capabilities.supportsAliasInquiry, "OneLink Raast supports alias inquiry")
        assertTrue(oneLinkRaast.capabilities.supportsTitleFetch, "OneLink Raast supports title fetch")
        assertFalse(oneLinkRaast.capabilities.supportsPayout, "OneLink Raast P2M does not execute IBFT payout")

        val oneLinkIbft = OneLinkIbftAdapter()
        assertTrue(oneLinkIbft.capabilities.supportsPayout, "OneLink IBFT executes payout transfer")
        assertTrue(oneLinkIbft.capabilities.supportsTitleFetch, "OneLink IBFT supports title fetch")
        assertTrue(oneLinkIbft.capabilities.supportsStatusLookup, "OneLink IBFT supports status lookup")
        assertFalse(oneLinkIbft.capabilities.supportsDeposit, "OneLink IBFT does not execute deposit")
    }

    // =========================================================================
    // 7. Currency Mismatch & Amount Validation
    // =========================================================================

    @Test
    fun `test10 currency mismatch rejects unsupported currency with typed DECLINED outcome`() {
        val adapter = SafepayRaastAdapter()

        val usdDeposit = sampleDeposit(currency = "USD", providerId = adapter.providerId)
        val outcome = adapter.deposit(usdDeposit, sampleConfig, sampleCredentials)

        assertEquals(ProviderOutcomeStatus.DECLINED, outcome.status)
        assertEquals("CURRENCY_MISMATCH", outcome.rawResponseCode)
        assertFalse(outcome.isAmbiguous)
    }

    // =========================================================================
    // 8. Webhook Callback Verification & Signature Validation
    // =========================================================================

    @Test
    fun `test11 webhook callback verification rejects invalid signature and accepts authentic payload`() {
        val safepay = SafepayRaastAdapter()

        val validBody = """{"data":{"token":"pay_12345","amount":50000,"currency":"PKR","status":"paid","tracker":"track_abc123"}}"""
        val validSig = safepay.calculateHmacSha256(validBody, sampleCredentials.signingSecretOrKey!!)

        // Valid webhook
        val validCallback = ProviderCallbackPayload(
            providerId = safepay.providerId,
            rawBody = validBody,
            headers = mapOf("x-sfpy-signature" to validSig),
        )
        val validResult = safepay.verifyCallback(validCallback, sampleConfig, sampleCredentials)
        assertTrue(validResult.isValid)
        assertNotNull(validResult.outcome)
        assertEquals(ProviderOutcomeStatus.ACCEPTED, validResult.outcome!!.status)
        assertEquals("track_abc123", validResult.providerReference)

        // Invalid signature
        val tamperedCallback = ProviderCallbackPayload(
            providerId = safepay.providerId,
            rawBody = validBody,
            headers = mapOf("x-sfpy-signature" to "invalid-tampered-signature"),
        )
        val invalidResult = safepay.verifyCallback(tamperedCallback, sampleConfig, sampleCredentials)
        assertFalse(invalidResult.isValid)
        assertEquals("INVALID_SIGNATURE", invalidResult.rejectionReason)
    }

    // =========================================================================
    // 9. Provider Status Inquiry / Reconciliation
    // =========================================================================

    @Test
    fun `test12 status lookup resolves unknown ambiguous transaction to final truthful outcome`() {
        val adapter = AdversarialTestPaymentAdapter(
            providerId = "prov-adv-1",
            simulationMode = AdversarialSimulationMode.NORMAL_SUCCESS,
        )

        val query = ProviderStatusQuery(
            tenantId = "tenant-pk-1",
            operationId = UUID.randomUUID(),
            providerId = "prov-adv-1",
            providerReference = "prov-ref-known-999",
            idempotencyKey = "idem-inq-1",
        )

        val statusOutcome = adapter.queryStatus(query, sampleConfig, sampleCredentials)
        assertEquals(ProviderOutcomeStatus.ACCEPTED, statusOutcome.status)
        assertEquals("prov-ref-known-999", statusOutcome.providerReference)

        // Querying non-existent reference returns UNKNOWN_AMBIGUOUS or FAILED without inventing outcome
        val unknownQuery = query.copy(providerReference = "prov-ref-non-existent")
        val unknownOutcome = adapter.queryStatus(unknownQuery, sampleConfig, sampleCredentials)
        assertEquals(ProviderOutcomeStatus.UNKNOWN_AMBIGUOUS, unknownOutcome.status)
        assertEquals("UNKNOWN_REFERENCE", unknownOutcome.rawResponseCode)
    }

    // =========================================================================
    // 10. Duplicate Callbacks, Rate Limiting, Credential Rotation, and Refunds
    // =========================================================================

    @Test
    fun `test13 duplicate or replayed callback processing preserves idempotency`() {
        val safepay = SafepayRaastAdapter()
        val validBody = """{"data":{"token":"pay_replay","amount":25000,"currency":"PKR","status":"paid","tracker":"track_replay_1"}}"""
        val validSig = safepay.calculateHmacSha256(validBody, sampleCredentials.signingSecretOrKey!!)

        val callback = ProviderCallbackPayload(
            providerId = safepay.providerId,
            rawBody = validBody,
            headers = mapOf("x-sfpy-signature" to validSig),
        )

        val firstVerification = safepay.verifyCallback(callback, sampleConfig, sampleCredentials)
        val secondVerification = safepay.verifyCallback(callback, sampleConfig, sampleCredentials)

        assertTrue(firstVerification.isValid)
        assertTrue(secondVerification.isValid)
        assertEquals(firstVerification.providerReference, secondVerification.providerReference)
    }

    @Test
    fun `test14 rate limiting returns unavailable with retryable indication`() {
        val adapter = AdversarialTestPaymentAdapter(
            providerId = "prov-adv-1",
            simulationMode = AdversarialSimulationMode.RATE_LIMITED,
        )

        val cmd = sampleDeposit(providerId = "prov-adv-1")
        val outcome = adapter.deposit(cmd, sampleConfig, sampleCredentials)

        assertEquals(ProviderOutcomeStatus.UNAVAILABLE, outcome.status)
        assertEquals("RATE_LIMITED", outcome.rawResponseCode)
        assertTrue(outcome.retryable)
        assertFalse(outcome.isAmbiguous)
    }

    @Test
    fun `test15 credential rotation preserves immutable operation identity`() {
        val adapter = AdversarialTestPaymentAdapter(
            providerId = "prov-adv-1",
            simulationMode = AdversarialSimulationMode.NORMAL_SUCCESS,
        )

        val opId = UUID.randomUUID()
        val cmd = sampleDeposit(opId = opId, idempotencyKey = "IDEM-ROT-1", providerId = "prov-adv-1")

        // First attempt with old credentials
        val initialResult = adapter.deposit(cmd, sampleConfig, sampleCredentials)

        // Rotate credentials (e.g. new API key and secret)
        val rotatedCredentials = sampleCredentials.copy(
            apiKey = "new-rotated-api-key-999",
            clientSecret = "new-rotated-secret-888",
        )

        val retryResult = adapter.deposit(cmd, sampleConfig, rotatedCredentials)

        assertEquals(initialResult.operationId, retryResult.operationId)
        assertEquals(initialResult.providerReference, retryResult.providerReference)
        assertEquals(opId, retryResult.operationId)
    }

    @Test
    fun `test16 refund duplication reuses original refund reference without creating second refund`() {
        val adapter = AdversarialTestPaymentAdapter(
            providerId = "prov-adv-1",
            simulationMode = AdversarialSimulationMode.NORMAL_SUCCESS,
        )

        val refundCmd = ProviderRefundCommand(
            tenantId = "tenant-pk-1",
            operationId = UUID.randomUUID(),
            originalOperationId = UUID.randomUUID(),
            providerReference = "prov-ref-orig-1",
            amountMinorUnits = 10_000L,
            currency = "PKR",
            idempotencyKey = "IDEM-RFND-1",
            reason = "Customer refund",
        )

        val refund1 = adapter.refund(refundCmd, sampleConfig, sampleCredentials)
        val refund2 = adapter.refund(refundCmd, sampleConfig, sampleCredentials)

        assertEquals(refund1.providerReference, refund2.providerReference)
        assertEquals(refund1.operationId, refund2.operationId)
    }

    @Test
    fun `test17 cancellation returns accepted when supported and declined when unsupported`() {
        val oneLink = OneLinkRaastAdapter()
        val cancelCmd = ProviderCancelCommand(
            tenantId = "tenant-pk-1",
            operationId = UUID.randomUUID(),
            providerId = oneLink.providerId,
            providerReference = "RTP-12345",
            idempotencyKey = "IDEM-CANCEL-1",
            reason = "Expired timeout",
        )

        val supportedCancel = oneLink.cancel(cancelCmd, sampleConfig, sampleCredentials)
        assertEquals(ProviderOutcomeStatus.ACCEPTED, supportedCancel.status)

        val easypaisa = EasypaisaAdapter()
        val unsupportedCancel = easypaisa.cancel(cancelCmd.copy(providerId = easypaisa.providerId), sampleConfig, sampleCredentials)
        assertEquals(ProviderOutcomeStatus.DECLINED, unsupportedCancel.status)
        assertEquals("UNSUPPORTED_OPERATION", unsupportedCancel.rawResponseCode)
    }
}

