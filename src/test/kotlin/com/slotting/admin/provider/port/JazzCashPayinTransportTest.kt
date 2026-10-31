package com.slotting.admin.provider.port

import com.slotting.admin.provider.port.adapters.JazzCashAdapter
import java.net.http.HttpTimeoutException
import java.util.UUID
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue
import org.junit.jupiter.api.Test

class JazzCashPayinTransportTest {
    private val config = ProviderConfiguration(
        providerId = "JAZZCASH",
        environment = ProviderEnvironment.SANDBOX,
        baseUrl = "https://sandbox.jazzcash.example",
    )
    private val credentials = ProviderCredentials(
        merchantId = "MERCHANT-01",
        apiKey = "test-api-key",
        signingSecretOrKey = "test-signing-secret",
    )

    @Test
    fun `TC-020-RED-1 provider reference and exact PKR amount are preserved`() {
        val transport = RecordingTransport { httpResponse(200, """{"pp_TxnRefNo":"JC1","status":"PENDING"}""") }
        val adapter = JazzCashAdapter(ProviderHttpClient(transport.transport()))
        val operationId = UUID.randomUUID()

        val result = adapter.deposit(command(operationId, amount = 12345L), config, credentials)

        assertEquals(ProviderOutcomeStatus.PENDING, result.status)
        assertEquals("JC1", result.providerReference)
        assertEquals(operationId, result.operationId)
        assertEquals("12345", result.evidence["amountMinorUnits"])
        assertEquals("PKR", result.evidence["currency"])
        assertEquals("jc-idem-$operationId", transport.requests.single().headers().firstValue("Idempotency-Key").orElse(null))
    }

    @Test
    fun `TC-020-RED-2 missing credentials and unsupported currency make no call and tampered callbacks are rejected`() {
        val transport = RecordingTransport { httpResponse(200, """{"pp_TxnRefNo":"never"}""") }
        val adapter = JazzCashAdapter(ProviderHttpClient(transport.transport()))
        val operationId = UUID.randomUUID()

        val missing = adapter.deposit(command(operationId), config, ProviderCredentials())
        val usd = adapter.deposit(command(operationId, currency = "USD"), config, credentials)
        assertEquals(ProviderOutcomeStatus.UNAVAILABLE, missing.status)
        assertEquals(ProviderOutcomeStatus.DECLINED, usd.status)
        assertEquals(0, transport.requests.size)

        val unsigned = adapter.verifyCallback(
            ProviderCallbackPayload(
                providerId = "JAZZCASH",
                rawBody = "",
                headers = mapOf("pp_SecureHash" to "0".repeat(64)),
                queryParams = mapOf("pp_TxnRefNo" to "JC1", "pp_Amount" to "12345", "pp_TxnCurrency" to "PKR"),
            ),
            config,
            credentials,
        )
        assertFalse(unsigned.isValid)
        assertEquals("SIGNATURE_MISMATCH", unsigned.rejectionReason)
    }

    @Test
    fun `TC-020-RED-3 timeout retains identity and a duplicate retry never changes the transaction identity`() {
        var attempt = 0
        val transport = RecordingTransport {
            attempt += 1
            if (attempt == 1) throw HttpTimeoutException("timeout")
            httpResponse(200, """{"pp_TxnRefNo":"JC1"}""")
        }
        val adapter = JazzCashAdapter(ProviderHttpClient(transport.transport()))
        val operationId = UUID.randomUUID()
        val command = command(operationId)

        val first = adapter.deposit(command, config, credentials)
        val second = adapter.deposit(command, config, credentials)

        assertEquals(ProviderOutcomeStatus.UNKNOWN_AMBIGUOUS, first.status)
        assertEquals(operationId, first.operationId)
        assertEquals(ProviderOutcomeStatus.PENDING, second.status)
        assertEquals(operationId, second.operationId)
        assertEquals(2, transport.requests.size)
        assertEquals(transport.requests[0].headers().firstValue("Idempotency-Key").orElse(null), transport.requests[1].headers().firstValue("Idempotency-Key").orElse(null))
    }

    private fun command(
        operationId: UUID,
        amount: Long = 12345L,
        currency: String = "PKR",
    ) = ProviderDepositCommand(
        tenantId = "tenant-jazzcash",
        operationId = operationId,
        idempotencyKey = "jc-idem-$operationId",
        providerId = "JAZZCASH",
        methodId = "MWALLET",
        amountMinorUnits = amount,
        currency = currency,
        customerIdentifier = "03001234567",
        callbackUrl = "https://merchant.example/callback",
        correlationId = "corr-$operationId",
    )
}
