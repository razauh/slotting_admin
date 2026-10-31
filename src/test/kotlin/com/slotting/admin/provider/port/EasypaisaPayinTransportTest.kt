package com.slotting.admin.provider.port

import com.slotting.admin.provider.port.adapters.EasypaisaAdapter
import java.net.http.HttpTimeoutException
import java.util.UUID
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue
import org.junit.jupiter.api.Test

class EasypaisaPayinTransportTest {
    private val config = ProviderConfiguration(
        providerId = "EASYPAISA",
        environment = ProviderEnvironment.SANDBOX,
        baseUrl = "https://sandbox.easypaisa.example",
    )
    private val credentials = ProviderCredentials(merchantId = "MERCHANT-EP", apiKey = "test-api-key")

    @Test
    fun `TC-021-RED-1 provider reference is pending and initiation never credits a wallet`() {
        val transport = RecordingTransport { httpResponse(200, """{"transactionId":"EP1","status":"PENDING"}""") }
        val adapter = EasypaisaAdapter(ProviderHttpClient(transport.transport()))
        val operationId = UUID.randomUUID()

        val result = adapter.deposit(command(operationId), config, credentials)

        assertEquals(ProviderOutcomeStatus.PENDING, result.status)
        assertEquals("EP1", result.providerReference)
        assertEquals(operationId, result.operationId)
        assertEquals("2500", result.evidence["amountMinorUnits"])
        assertFalse(result.status == ProviderOutcomeStatus.ACCEPTED)
    }

    @Test
    fun `TC-021-RED-2 unsigned redirect claims success are not accepted as callbacks`() {
        val adapter = EasypaisaAdapter()
        val result = adapter.verifyCallback(
            ProviderCallbackPayload(
                providerId = "EASYPAISA",
                rawBody = """{"status":"SUCCESS"}""",
                headers = emptyMap(),
                queryParams = mapOf("status" to "SUCCESS"),
            ),
            config,
            credentials,
        )
        assertFalse(result.isValid)
        assertEquals("CALLBACK_UNSUPPORTED_IN_HISTORICAL_CONTRACT", result.rejectionReason)
    }

    @Test
    fun `TC-021-RED-3 timeout malformed body USD and missing credentials return explicit safe results`() {
        val operationId = UUID.randomUUID()
        val timeout = EasypaisaAdapter(ProviderHttpClient(RecordingTransport { throw HttpTimeoutException("timeout") }.transport()))
            .deposit(command(operationId), config, credentials)
        val malformed = EasypaisaAdapter(ProviderHttpClient(RecordingTransport { httpResponse(200, "not-json") }.transport()))
            .deposit(command(operationId), config, credentials)
        val noCallTransport = RecordingTransport { httpResponse(200, """{"transactionId":"never"}""") }
        val adapter = EasypaisaAdapter(ProviderHttpClient(noCallTransport.transport()))
        val usd = adapter.deposit(command(operationId, currency = "USD"), config, credentials)
        val missing = adapter.deposit(command(operationId), config, ProviderCredentials())

        assertEquals(ProviderOutcomeStatus.UNKNOWN_AMBIGUOUS, timeout.status)
        assertEquals(ProviderOutcomeStatus.FAILED, malformed.status)
        assertEquals(ProviderOutcomeStatus.DECLINED, usd.status)
        assertEquals(ProviderOutcomeStatus.UNAVAILABLE, missing.status)
        assertEquals(0, noCallTransport.requests.size)
    }

    private fun command(
        operationId: UUID,
        amount: Long = 2500L,
        currency: String = "PKR",
    ) = ProviderDepositCommand(
        tenantId = "tenant-easypaisa",
        operationId = operationId,
        idempotencyKey = "ep-idem-$operationId",
        providerId = "EASYPAISA",
        methodId = "MA",
        amountMinorUnits = amount,
        currency = currency,
        customerIdentifier = "03001234567",
        callbackUrl = "https://merchant.example/callback",
        correlationId = "corr-$operationId",
    )
}
