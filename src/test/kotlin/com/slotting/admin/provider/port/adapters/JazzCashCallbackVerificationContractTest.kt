package com.slotting.admin.provider.port.adapters

import com.slotting.admin.auth.AdminSessionDirectory
import com.slotting.admin.auth.AdminSessionStatus
import com.slotting.admin.deposit.DepositIntentRecord
import com.slotting.admin.deposit.DepositIntentStatus
import com.slotting.admin.deposit.DurableDepositWorkflowService
import com.slotting.admin.deposit.InMemoryDepositWorkflowStore
import com.slotting.admin.ledger.InMemoryLedgerJournalStore
import com.slotting.admin.ledger.LedgerPostingService
import com.slotting.admin.provider.InMemoryPaymentMethodStore
import com.slotting.admin.provider.port.ProviderCallbackPayload
import com.slotting.admin.provider.port.ProviderConfiguration
import com.slotting.admin.provider.port.ProviderCredentials
import com.slotting.admin.provider.port.ProviderEnvironment
import java.time.Clock
import java.time.Duration
import java.time.Instant
import java.time.ZoneOffset
import java.util.UUID
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue
import org.junit.jupiter.api.Test

class JazzCashCallbackVerificationContractTest {
    private val adapter = JazzCashAdapter()
    private val secret = "test-jazzcash-shared-secret"
    private val now = Instant.parse("2026-10-12T10:00:00Z")
    private val clock = Clock.fixed(now, ZoneOffset.UTC)
    private val tenantId = "tenant-jazzcash-${UUID.randomUUID()}"
    private val intentId = UUID.randomUUID()
    private val providerReference = "JC-TXN-$intentId"

    @Test
    fun arbitraryPresentHashWithoutHmacIsRejected() {
        val fields = fields()
        val result = adapter.verifyCallback(
            ProviderCallbackPayload("JAZZCASH", "", mapOf("pp_SecureHash" to "anything"), fields),
            config(),
            credentials(),
        )
        assertFalse(result.isValid)
        assertEquals("SIGNATURE_MISMATCH", result.rejectionReason)
    }

    @Test
    fun officialKnownAnswerAndValidCallbackAreAccepted() {
        assertEquals(
            "c7689cda7474eb1adcd343fd0c0b676bad0ba66361cc46db589bdb0da4c1c867",
            adapter.calculateSecureHash(
                mapOf("pp_Amount" to "2995", "pp_MerchantID" to "MER123", "pp_OrderInfo" to "A48cvE28"),
                "0F5DD14AE2",
            ),
        )
        val fields = signedFields()
        val result = adapter.verifyCallback(
            ProviderCallbackPayload("JAZZCASH", "", emptyMap(), fields),
            config(),
            credentials(),
        )
        assertTrue(result.isValid, result.rejectionReason.orEmpty())
        assertEquals(providerReference, result.providerReference)
        assertEquals("50000", result.outcome?.evidence?.get("amountMinorUnits"))
        assertEquals("PKR", result.outcome?.evidence?.get("currency"))
    }

    @Test
    fun mutatedAmountAndMissingHashAreRejectedWithDistinctReasons() {
        val original = signedFields()
        val mutated = original + ("pp_Amount" to "50001")
        val badAmount = adapter.verifyCallback(
            ProviderCallbackPayload("JAZZCASH", "", emptyMap(), mutated),
            config(),
            credentials(),
        )
        val missing = adapter.verifyCallback(
            ProviderCallbackPayload("JAZZCASH", "", emptyMap(), fields()),
            config(),
            credentials(),
        )
        assertEquals("SIGNATURE_MISMATCH", badAmount.rejectionReason)
        assertEquals("MISSING_SIGNATURE", missing.rejectionReason)
    }

    @Test
    fun definitiveFailureResponseIsReturnedForQuarantineAndMissingSecretIsRejected() {
        val failedPayment = signedFields(responseCode = "124")
        val failedResult = adapter.verifyCallback(
            ProviderCallbackPayload("JAZZCASH", "", emptyMap(), failedPayment),
            config(),
            credentials(),
        )
        val missingSecret = adapter.verifyCallback(
            ProviderCallbackPayload("JAZZCASH", "", emptyMap(), signedFields()),
            config(),
            ProviderCredentials(signingSecretOrKey = null),
        )
        assertTrue(failedResult.isValid)
        assertEquals("124", failedResult.outcome?.evidence?.get("responseCode"))
        assertEquals("SIGNING_KEY_UNAVAILABLE", missingSecret.rejectionReason)
    }

    @Test
    fun verifiedAmountAndCurrencyMustMatchIntentAndReplayCreditsOnlyOnce() {
        val (amountService, amountWorkflowStore, amountLedgerStore) = serviceFixture()
        val mismatchedAmount = signedFields().toMutableMap().apply {
            this["pp_Amount"] = "50001"
            this["pp_SecureHash"] = adapter.calculateSecureHash(this, secret)
        }
        val invalidAmount = runCatching {
            amountService.processCallback(command(mismatchedAmount, "evt-bad-amount"))
        }
        assertEquals(DepositIntentStatus.QUARANTINED, invalidAmount.getOrThrow().status)
        assertEquals(0, amountLedgerStore.findAllLegsForTenant(tenantId).size)
        assertEquals(DepositIntentStatus.QUARANTINED, amountWorkflowStore.findIntent(tenantId, intentId)?.status)

        val (currencyService, _, currencyLedgerStore) = serviceFixture()
        val mismatchedCurrency = signedFields().toMutableMap().apply {
            this["pp_TxnCurrency"] = "USD"
            this["pp_SecureHash"] = adapter.calculateSecureHash(this, secret)
        }
        val invalidCurrency = runCatching {
            currencyService.processCallback(command(mismatchedCurrency, "evt-bad-currency"))
        }
        assertEquals(DepositIntentStatus.QUARANTINED, invalidCurrency.getOrThrow().status)
        assertEquals(0, currencyLedgerStore.findAllLegsForTenant(tenantId).size)

        val (service, _, ledgerStore) = serviceFixture()
        val signed = signedFields()
        val first = service.processCallback(command(signed, "evt-valid"))
        val replay = service.processCallback(command(signed, "evt-valid"))
        assertEquals(DepositIntentStatus.SETTLED, first.status)
        assertFalse(first.alreadyProcessed)
        assertTrue(replay.alreadyProcessed)
        assertEquals(first.ledgerTransactionReference, replay.ledgerTransactionReference)
        assertEquals(2, ledgerStore.findAllLegsForTenant(tenantId).size)
        assertEquals(50_000L, ledgerStore.findBalance(tenantId, "player:wallet:${UUID.nameUUIDFromBytes("player".toByteArray())}", "PKR"))
    }

    private fun serviceFixture(): Triple<DurableDepositWorkflowService, InMemoryDepositWorkflowStore, InMemoryLedgerJournalStore> {
        val workflowStore = InMemoryDepositWorkflowStore()
        workflowStore.saveIntent(
            DepositIntentRecord(
                intentId = intentId,
                tenantId = tenantId,
                playerId = UUID.nameUUIDFromBytes("player".toByteArray()),
                methodId = "JAZZCASH",
                providerId = "JAZZCASH",
                amountMinorUnits = 50_000L,
                currencyCode = "PKR",
                status = DepositIntentStatus.PROVIDER_PENDING,
                idempotencyKey = "intent-$intentId",
                requestFingerprint = "fingerprint",
                providerReference = providerReference,
                expiresAt = now.plus(Duration.ofMinutes(15)),
                createdAt = now,
                updatedAt = now,
            ),
        )
        val ledgerStore = InMemoryLedgerJournalStore()
        val sessionDirectory = object : AdminSessionDirectory {
            override fun find(tenantId: String, principalId: String, sessionId: String) =
                AdminSessionStatus(true, false, now.plus(Duration.ofHours(1)), true)
        }
        val service = DurableDepositWorkflowService(
            workflowStore = workflowStore,
            paymentMethodStore = InMemoryPaymentMethodStore(),
            sessions = sessionDirectory,
            ledgerPostingService = LedgerPostingService(ledgerStore, clock = clock),
            providerPorts = mapOf("JAZZCASH" to adapter),
            credentialsResolver = { _, _ -> credentials() },
            configResolver = { _, providerId -> config(providerId) },
            clock = clock,
        )
        return Triple(service, workflowStore, ledgerStore)
    }

    private fun command(fields: Map<String, String>, eventId: String) =
        com.slotting.admin.deposit.DepositCallbackCommand(
            tenantId = tenantId,
            providerId = "JAZZCASH",
            providerEventId = eventId,
            rawBody = fields.toSortedMap().toString(),
            queryParams = fields,
        )

    private fun signedFields(responseCode: String = "000"): Map<String, String> {
        val fields = fields(responseCode)
        return fields + ("pp_SecureHash" to adapter.calculateSecureHash(fields, secret))
    }

    private fun fields(responseCode: String = "000") = mapOf(
        "pp_Amount" to "50000",
        "pp_MerchantID" to "MERCHANT-01",
        "pp_ResponseCode" to responseCode,
        "pp_TxnCurrency" to "PKR",
        "pp_TxnRefNo" to providerReference,
    )

    private fun credentials() = ProviderCredentials(merchantId = "MERCHANT-01", signingSecretOrKey = secret)

    private fun config(providerId: String = "JAZZCASH") = ProviderConfiguration(
        providerId = providerId,
        environment = ProviderEnvironment.SANDBOX,
        baseUrl = "https://sandbox.jazzcash.example",
    )
}
