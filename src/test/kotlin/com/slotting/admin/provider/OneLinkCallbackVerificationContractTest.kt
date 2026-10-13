package com.slotting.admin.provider

import com.slotting.admin.auth.AdminSessionDirectory
import com.slotting.admin.auth.AdminSessionStatus
import com.slotting.admin.deposit.DepositCallbackCommand
import com.slotting.admin.deposit.DepositIntentRecord
import com.slotting.admin.deposit.DepositIntentStatus
import com.slotting.admin.deposit.DurableDepositWorkflowService
import com.slotting.admin.deposit.InMemoryDepositWorkflowStore
import com.slotting.admin.ledger.InMemoryLedgerJournalStore
import com.slotting.admin.ledger.LedgerPostingService
import com.slotting.admin.provider.port.ProviderCallbackPayload
import com.slotting.admin.provider.port.ProviderConfiguration
import com.slotting.admin.provider.port.ProviderCredentials
import com.slotting.admin.provider.port.ProviderEnvironment
import com.slotting.admin.provider.port.adapters.OneLinkRaastAdapter
import java.time.Clock
import java.time.Duration
import java.time.Instant
import java.time.ZoneOffset
import java.util.UUID
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue
import org.junit.jupiter.api.Test

class OneLinkCallbackVerificationContractTest {
    private val adapter = OneLinkRaastAdapter()
    private val signingSecret = "test-only-onelink-callback-secret"
    private val now = Instant.parse("2026-10-12T10:00:00Z")
    private val clock = Clock.fixed(now, ZoneOffset.UTC)
    private val tenantId = "tenant-onelink-${UUID.randomUUID()}"
    private val intentId = UUID.randomUUID()
    private val providerReference = "RTP-$intentId"

    @Test
    fun arbitraryPresentSignatureWithoutVerificationIsRejected() {
        val callback = payload("anything")
        val result = adapter.verifyCallback(callback, config(), credentials())
        assertFalse(result.isValid)
        assertEquals("SIGNATURE_MISMATCH", result.rejectionReason)
    }

    @Test
    fun validSignatureAcceptsOnlyAuthenticatedReferenceAmountAndSettledStatus() {
        assertEquals(
            "f7bc83f430538424b13298e6aa6fb143ef4d59a14946175997479dbc2d1a3cd8",
            adapter.calculateHmacSha256("The quick brown fox jumps over the lazy dog", "key"),
        )
        val fixture = signedFixture()
        val result = adapter.verifyCallback(
            WebhookSignatureFixtures.oneLinkCallback(fixture),
            config(),
            credentials(),
        )
        assertTrue(result.isValid, result.rejectionReason.orEmpty())
        assertEquals("RTP_SETTLED", result.eventType)
        assertEquals(providerReference, result.providerReference)
        assertEquals("50000", result.outcome?.evidence?.get("amountMinorUnits"))
        assertTrue(result.operationId != null)
    }

    @Test
    fun mutatedPayloadAndMissingSignatureAreRejected() {
        val fixture = signedFixture()
        val tampered = WebhookSignatureFixtures.tamperedAmount(fixture)
        val invalid = adapter.verifyCallback(
            WebhookSignatureFixtures.oneLinkCallback(tampered),
            config(),
            credentials(),
        )
        val missing = adapter.verifyCallback(
            payload(null),
            config(),
            credentials(),
        )
        assertEquals("SIGNATURE_MISMATCH", invalid.rejectionReason)
        assertEquals("MISSING_SIGNATURE", missing.rejectionReason)
    }

    @Test
    fun alternateHeaderWorksAndConflictingHeadersFailClosed() {
        val fixture = signedFixture()
        val callback = WebhookSignatureFixtures.oneLinkCallback(fixture)
        val alternate = callback.copy(
            headers = mapOf("SIGNATURE" to fixture.signature),
        )
        val conflict = callback.copy(
            headers = callback.headers + ("signature" to "0".repeat(64)),
        )
        assertTrue(adapter.verifyCallback(alternate, config(), credentials()).isValid)
        assertEquals("SIGNATURE_CONFLICT", adapter.verifyCallback(conflict, config(), credentials()).rejectionReason)
        assertEquals(
            "SIGNATURE_MISMATCH",
            adapter.verifyCallback(callback.copy(headers = mapOf("signature" to " ${fixture.signature}")), config(), credentials()).rejectionReason,
        )
    }

    @Test
    fun signedUnsettledStatusIsReturnedForQuarantineAndMissingReferenceIsRejected() {
        val unsettled = signedFixture(body(status = "RTP_PENDING"))
        val missingReference = signedFixture(body(reference = ""))
        val result = adapter.verifyCallback(WebhookSignatureFixtures.oneLinkCallback(unsettled), config(), credentials())
        assertTrue(result.isValid)
        assertEquals("RTP_PENDING", result.outcome?.evidence?.get("status"))
        assertEquals(
            "MISSING_REFERENCE",
            adapter.verifyCallback(WebhookSignatureFixtures.oneLinkCallback(missingReference), config(), credentials()).rejectionReason,
        )
    }

    @Test
    fun validCallbackReplaysOnceAndMismatchedAmountCannotCredit() {
        val (service, store, ledger) = serviceFixture()
        val fixture = signedFixture()
        val cmd = command(fixture, "event-valid")
        val first = service.processCallback(cmd)
        val replay = service.processCallback(cmd)
        assertEquals(DepositIntentStatus.SETTLED, first.status)
        assertFalse(first.alreadyProcessed)
        assertTrue(replay.alreadyProcessed)
        assertEquals(first.ledgerTransactionReference, replay.ledgerTransactionReference)
        assertEquals(2, ledger.findAllLegsForTenant(tenantId).size)
        assertEquals(50_000L, ledger.findBalance(tenantId, "player:wallet:${playerId()}", "PKR"))

        val (mismatchService, mismatchStore, mismatchLedger) = serviceFixture(intentAmount = 50_001L)
        val mismatch = runCatching {
            mismatchService.processCallback(command(signedFixture(), "event-amount-mismatch"))
        }
        assertEquals(DepositIntentStatus.QUARANTINED, mismatch.getOrThrow().status)
        assertEquals(DepositIntentStatus.QUARANTINED, mismatchStore.findIntent(tenantId, intentId)?.status)
        assertEquals(0, mismatchLedger.findAllLegsForTenant(tenantId).size)
        assertEquals(DepositIntentStatus.SETTLED, store.findIntent(tenantId, intentId)?.status)
    }

    private fun serviceFixture(intentAmount: Long = 50_000L): Triple<DurableDepositWorkflowService, InMemoryDepositWorkflowStore, InMemoryLedgerJournalStore> {
        val workflowStore = InMemoryDepositWorkflowStore()
        workflowStore.saveIntent(
            DepositIntentRecord(
                intentId = intentId,
                tenantId = tenantId,
                playerId = playerId(),
                methodId = "ONELINK_RAAST",
                providerId = "ONELINK_RAAST",
                amountMinorUnits = intentAmount,
                currencyCode = "PKR",
                status = DepositIntentStatus.PROVIDER_PENDING,
                idempotencyKey = "intent-$intentId-$intentAmount",
                requestFingerprint = "fingerprint-$intentAmount",
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
            providerPorts = mapOf("ONELINK_RAAST" to adapter),
            credentialsResolver = { _, _ -> credentials() },
            configResolver = { _, providerId -> config(providerId) },
            clock = clock,
        )
        return Triple(service, workflowStore, ledgerStore)
    }

    private fun signedFixture(rawBody: String = body()) = WebhookSignatureFixtures.signedCallback(
        providerId = WebhookSignatureFixtures.ONELINK_RAAST,
        tenantId = tenantId,
        eventId = "event-${UUID.randomUUID()}",
        rawPayload = rawBody,
        secret = signingSecret,
    )

    private fun body(
        reference: String = providerReference,
        amount: Long = 50_000L,
        status: String = "RTP_SETTLED",
    ) = """{"reference":"$reference","amountMinorUnits":$amount,"currency":"PKR","status":"$status"}"""

    private fun payload(signature: String?) = ProviderCallbackPayload(
        providerId = "ONELINK_RAAST",
        rawBody = body(),
        headers = signature?.let { mapOf("x-raast-signature" to it) }.orEmpty(),
        queryParams = mapOf("reference" to "unsigned-reference"),
    )

    private fun command(fixture: WebhookSignatureFixture, eventId: String) = DepositCallbackCommand(
        tenantId = tenantId,
        providerId = "ONELINK_RAAST",
        providerEventId = eventId,
        rawBody = fixture.rawPayload,
        headers = mapOf("x-raast-signature" to fixture.signature),
    )

    private fun credentials() = ProviderCredentials(signingSecretOrKey = signingSecret)

    private fun config(providerId: String = "ONELINK_RAAST") = ProviderConfiguration(
        providerId = providerId,
        environment = ProviderEnvironment.SANDBOX,
        baseUrl = "https://sandbox.onelink.example",
    )

    private fun playerId() = UUID.nameUUIDFromBytes("player-onelink".toByteArray())
}
