package com.slotting.admin.provider.port

import com.slotting.admin.provider.port.adapters.EasypaisaAdapter
import com.slotting.admin.provider.port.adapters.JazzCashAdapter
import com.slotting.admin.provider.port.adapters.OneLinkIbftAdapter
import com.slotting.admin.provider.port.adapters.SafepayRaastAdapter
import java.net.http.HttpTimeoutException
import java.util.UUID
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue
import org.junit.jupiter.api.Test

class ProviderPayoutTransportTest {
    private val ibftConfig = ProviderConfiguration(
        providerId = "ONELINK_IBFT",
        environment = ProviderEnvironment.SANDBOX,
        baseUrl = "https://sandbox.ibft.example",
    )
    private val ibftCredentials = ProviderCredentials(clientId = "client-1", apiKey = "test-api-key")
    private val safepayConfig = ProviderConfiguration(
        providerId = "SAFEPAY_RAAST",
        environment = ProviderEnvironment.SANDBOX,
        baseUrl = "https://sandbox.safepay.example",
    )
    private val safepayCredentials = ProviderCredentials(apiKey = "test-api-key")

    @Test
    fun `TC-023-RED-1 accepted payout stays pending until authenticated inquiry proves settlement`() {
        var call = 0
        val transport = RecordingTransport {
            call += 1
            when (call) {
                1 -> httpResponse(200, """{"transferId":"IB1","status":"PENDING"}""")
                else -> httpResponse(200, """{"transferId":"IB1","status":"PAID","amountMinorUnits":47500,"currency":"PKR"}""")
            }
        }
        val adapter = OneLinkIbftAdapter(ProviderHttpClient(transport.transport()))
        val operationId = UUID.randomUUID()
        val command = payout(operationId, 47500L)

        val accepted = adapter.payout(command, ibftConfig, ibftCredentials)
        assertEquals(ProviderOutcomeStatus.ACCEPTED, accepted.status)
        assertEquals("IB1", accepted.providerReference)
        assertTrue(accepted.verifiedStatus == null)

        val settled = adapter.queryStatus(
            ProviderStatusQuery(
                tenantId = "tenant-payout",
                operationId = operationId,
                providerId = "ONELINK_IBFT",
                providerReference = "IB1",
                idempotencyKey = "query-$operationId",
                expectedAmountMinorUnits = 47500L,
                expectedCurrency = "PKR",
            ),
            ibftConfig,
            ibftCredentials,
        )
        assertEquals(ProviderOutcomeStatus.ACCEPTED, settled.status)
        assertEquals(47500L, settled.verifiedStatus?.amountMinorUnits)
        assertEquals("PKR", settled.verifiedStatus?.currency)
        assertTrue(settled.verifiedStatus?.signatureVerified == true)
    }

    @Test
    fun `TC-023-RED-2 definitive rejection is terminal while timeout remains ambiguous`() {
        val transport = RecordingTransport {
            httpResponse(200, """{"transferId":"IB2","status":"REJECTED"}""")
        }
        val adapter = OneLinkIbftAdapter(ProviderHttpClient(transport.transport()))
        val operationId = UUID.randomUUID()
        val query = ProviderStatusQuery(
            tenantId = "tenant-payout",
            operationId = operationId,
            providerId = "ONELINK_IBFT",
            providerReference = "IB2",
            idempotencyKey = "query-$operationId",
            expectedAmountMinorUnits = 47500L,
            expectedCurrency = "PKR",
        )
        val rejected = adapter.queryStatus(query, ibftConfig, ibftCredentials)
        assertEquals(ProviderOutcomeStatus.FAILED, rejected.status)

        val timeoutAdapter = OneLinkIbftAdapter(ProviderHttpClient(RecordingTransport { throw HttpTimeoutException("timeout") }.transport()))
        val timedOut = timeoutAdapter.payout(payout(operationId, 47500L), ibftConfig, ibftCredentials)
        assertEquals(ProviderOutcomeStatus.UNKNOWN_AMBIGUOUS, timedOut.status)
        assertEquals(operationId, timedOut.operationId)
        assertTrue(timedOut.providerReference == null)
    }

    @Test
    fun `TC-023-RED-3 wrong amount or reference inquiry is quarantined and never finalized`() {
        val wrongAmount = OneLinkIbftAdapter(
            ProviderHttpClient(
                RecordingTransport {
                    httpResponse(200, """{"transferId":"IB3","status":"PAID","amountMinorUnits":1,"currency":"PKR"}""")
                }.transport()
            )
        ).queryStatus(
            ProviderStatusQuery(
                tenantId = "tenant-payout",
                operationId = UUID.randomUUID(),
                providerId = "ONELINK_IBFT",
                providerReference = "IB3",
                idempotencyKey = "query-3",
                expectedAmountMinorUnits = 47500L,
                expectedCurrency = "PKR",
            ),
            ibftConfig,
            ibftCredentials,
        )
        assertEquals(ProviderOutcomeStatus.DECLINED, wrongAmount.status)
        assertTrue(wrongAmount.verifiedStatus == null)

        val wrongReference = OneLinkIbftAdapter(
            ProviderHttpClient(
                RecordingTransport {
                    httpResponse(200, """{"transferId":"OTHER","status":"PAID","amountMinorUnits":47500,"currency":"PKR"}""")
                }.transport()
            )
        ).queryStatus(
            ProviderStatusQuery(
                tenantId = "tenant-payout",
                operationId = UUID.randomUUID(),
                providerId = "ONELINK_IBFT",
                providerReference = "IB3",
                idempotencyKey = "query-4",
                expectedAmountMinorUnits = 47500L,
                expectedCurrency = "PKR",
            ),
            ibftConfig,
            ibftCredentials,
        )
        assertEquals(ProviderOutcomeStatus.DECLINED, wrongReference.status)
        assertTrue(wrongReference.verifiedStatus == null)
    }

    @Test
    fun `Safepay payout transport and inquiry map authenticated settlement`() {
        var call = 0
        val adapter = SafepayRaastAdapter(
            ProviderHttpClient(
                RecordingTransport {
                    call += 1
                    if (call == 1) {
                        httpResponse(200, """{"tracker":"SP1","status":"PENDING"}""")
                    } else {
                        httpResponse(200, """{"tracker":"SP1","status":"SETTLED","amountMinorUnits":2500,"currency":"PKR"}""")
                    }
                }.transport()
            )
        )
        val operationId = UUID.randomUUID()
        val command = ProviderPayoutCommand(
            tenantId = "tenant-payout",
            operationId = operationId,
            idempotencyKey = "sp-idem-$operationId",
            providerId = "SAFEPAY_RAAST",
            methodId = "RAAST",
            amountMinorUnits = 2500L,
            currency = "PKR",
            destinationAccount = "PK36SCBL0000001123456701",
            correlationId = "corr-$operationId",
        )
        val accepted = adapter.payout(command, safepayConfig, safepayCredentials)
        assertEquals(ProviderOutcomeStatus.ACCEPTED, accepted.status)
        assertEquals("SP1", accepted.providerReference)

        val settled = adapter.queryStatus(
            ProviderStatusQuery(
                tenantId = "tenant-payout",
                operationId = operationId,
                providerId = "SAFEPAY_RAAST",
                providerReference = "SP1",
                idempotencyKey = "sp-query-$operationId",
                expectedAmountMinorUnits = 2500L,
                expectedCurrency = "PKR",
            ),
            safepayConfig,
            safepayCredentials,
        )
        assertEquals(ProviderOutcomeStatus.ACCEPTED, settled.status)
        assertTrue(settled.verifiedStatus?.signatureVerified == true)
    }

    @Test
    fun `providers without payout capability remain explicitly unsupported`() {
        val command = ProviderPayoutCommand(
            tenantId = "tenant-payout",
            operationId = UUID.randomUUID(),
            idempotencyKey = "unsupported",
            providerId = "JAZZCASH",
            methodId = "MWALLET",
            amountMinorUnits = 2500L,
            currency = "PKR",
            destinationAccount = "03001234567",
            correlationId = "corr",
        )
        val jazz = JazzCashAdapter().payout(command, ibftConfig.copy(providerId = "JAZZCASH"), ProviderCredentials())
        val easy = EasypaisaAdapter().payout(command, ibftConfig.copy(providerId = "EASYPAISA"), ProviderCredentials())
        assertEquals(ProviderOutcomeStatus.DECLINED, jazz.status)
        assertEquals(ProviderOutcomeStatus.DECLINED, easy.status)
        assertFalse(jazz.rawResponseCode == "ACCEPTED")
    }

    private fun payout(operationId: UUID, amount: Long) = ProviderPayoutCommand(
        tenantId = "tenant-payout",
        operationId = operationId,
        idempotencyKey = "payout-idem-$operationId",
        providerId = "ONELINK_IBFT",
        methodId = "IBFT",
        amountMinorUnits = amount,
        currency = "PKR",
        destinationAccount = "PK36SCBL0000001123456701",
        destinationTitle = "Test Beneficiary",
        destinationBankCode = "SCBL",
        correlationId = "corr-$operationId",
    )
}
