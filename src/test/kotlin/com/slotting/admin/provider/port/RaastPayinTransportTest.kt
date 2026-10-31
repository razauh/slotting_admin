package com.slotting.admin.provider.port

import com.slotting.admin.provider.port.adapters.OneLinkRaastAdapter
import com.slotting.admin.provider.port.adapters.SafepayRaastAdapter
import java.net.http.HttpTimeoutException
import java.util.UUID
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNotEquals
import kotlin.test.assertTrue
import org.junit.jupiter.api.Test

class RaastPayinTransportTest {
    private val config = ProviderConfiguration(
        providerId = "SAFEPAY_RAAST",
        environment = ProviderEnvironment.SANDBOX,
        baseUrl = "https://sandbox.safepay.example",
    )
    private val credentials = ProviderCredentials(apiKey = "test-api-key")

    @Test
    fun `TC-019-RED-1 approved provider reference is used and no synthetic tracker is produced`() {
        val transport = RecordingTransport { httpResponse(200, """{"data":{"tracker":"R1","status":"PENDING"}}""") }
        val adapter = SafepayRaastAdapter(ProviderHttpClient(transport.transport()))
        val operationId = UUID.randomUUID()

        val result = adapter.deposit(command(operationId), config, credentials)

        assertEquals(ProviderOutcomeStatus.PENDING, result.status)
        assertEquals("R1", result.providerReference)
        assertNotEquals("track_$operationId", result.providerReference)
        assertEquals(operationId, result.operationId)
        assertEquals(1, transport.requests.size)
        assertEquals("raast-idem-$operationId", transport.requests.single().headers().firstValue("Idempotency-Key").orElse(null))
    }

    @Test
    fun `TC-019-RED-2 transport timeout keeps original identity and malformed or unauthorized responses never succeed`() {
        val operationId = UUID.randomUUID()
        val timeout = RecordingTransport { throw HttpTimeoutException("timeout") }
        val timedOut = SafepayRaastAdapter(ProviderHttpClient(timeout.transport()))
            .deposit(command(operationId), config, credentials)

        assertEquals(ProviderOutcomeStatus.UNKNOWN_AMBIGUOUS, timedOut.status)
        assertEquals(operationId, timedOut.operationId)
        assertTrue(timedOut.isAmbiguous)
        assertTrue(timedOut.providerReference == null)

        val malformed = SafepayRaastAdapter(
            ProviderHttpClient(RecordingTransport { httpResponse(200, "not-json") }.transport())
        ).deposit(command(operationId), config, credentials)
        assertEquals(ProviderOutcomeStatus.FAILED, malformed.status)
        assertFalse(malformed.status == ProviderOutcomeStatus.ACCEPTED)

        val unauthorized = SafepayRaastAdapter(
            ProviderHttpClient(RecordingTransport { httpResponse(401, """{"error":"denied"}""") }.transport())
        ).deposit(command(operationId), config, credentials)
        assertEquals(ProviderOutcomeStatus.DECLINED, unauthorized.status)
        assertFalse(unauthorized.status == ProviderOutcomeStatus.ACCEPTED)
    }

    @Test
    fun `TC-019-RED-3 unsupported currency and non-positive amount make zero network calls`() {
        val transport = RecordingTransport { httpResponse(200, """{"tracker":"never"}""") }
        val adapter = SafepayRaastAdapter(ProviderHttpClient(transport.transport()))
        val operationId = UUID.randomUUID()

        val usd = adapter.deposit(command(operationId, currency = "USD"), config, credentials)
        val inr = adapter.deposit(command(operationId, currency = "INR"), config, credentials)
        val zero = adapter.deposit(command(operationId, amount = 0L), config, credentials)
        val negative = adapter.deposit(command(operationId, amount = -1L), config, credentials)

        assertEquals(ProviderOutcomeStatus.DECLINED, usd.status)
        assertEquals(ProviderOutcomeStatus.DECLINED, inr.status)
        assertEquals(ProviderOutcomeStatus.DECLINED, zero.status)
        assertEquals(ProviderOutcomeStatus.DECLINED, negative.status)
        assertEquals(0, transport.requests.size)
    }

    @Test
    fun `unselected OneLink Raast pay-in is explicitly unavailable without network access`() {
        val adapter = OneLinkRaastAdapter()

        val result = adapter.deposit(command(UUID.randomUUID()), config.copy(providerId = "ONELINK_RAAST"), ProviderCredentials(clientId = "client"))

        assertEquals(ProviderOutcomeStatus.DECLINED, result.status)
        assertEquals("UNSUPPORTED_OPERATION", result.rawResponseCode)
        assertFalse(adapter.capabilities.supportsDeposit)
    }

    private fun command(
        operationId: UUID,
        amount: Long = 2500L,
        currency: String = "PKR",
    ) = ProviderDepositCommand(
        tenantId = "tenant-raast",
        operationId = operationId,
        idempotencyKey = "raast-idem-$operationId",
        providerId = "SAFEPAY_RAAST",
        methodId = "RAAST",
        amountMinorUnits = amount,
        currency = currency,
        customerIdentifier = "03001234567",
        callbackUrl = "https://merchant.example/callback",
        correlationId = "corr-$operationId",
    )
}
