package com.slotting.admin.provider.port

import com.slotting.admin.auth.AdminSessionDirectory
import com.slotting.admin.auth.AdminSessionStatus
import com.slotting.admin.deposit.DepositCallbackCommand
import com.slotting.admin.deposit.DepositIntentRecord
import com.slotting.admin.deposit.DepositIntentStatus
import com.slotting.admin.deposit.DurableDepositWorkflowService
import com.slotting.admin.deposit.InMemoryDepositWorkflowStore
import com.slotting.admin.ledger.InMemoryLedgerJournalStore
import com.slotting.admin.ledger.LedgerPostingService
import com.slotting.admin.provider.InMemoryPaymentMethodStore
import com.slotting.admin.provider.port.adapters.JazzCashAdapter
import com.slotting.admin.provider.port.adapters.OneLinkRaastAdapter
import java.time.Clock
import java.time.Duration
import java.time.Instant
import java.time.ZoneOffset
import java.util.UUID
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertTrue
import org.junit.jupiter.api.Test

class ProviderAlphaCertificationTest {
    private val now = Instant.parse("2026-10-31T10:00:00Z")
    private val clock = Clock.fixed(now, ZoneOffset.UTC)
    private val secret = "certification-test-secret"
    private val adapter = JazzCashAdapter()
    private val tenantId = "tenant-cert-${UUID.randomUUID()}"
    private val intentId = UUID.randomUUID()
    private val providerReference = "JC-TXN-$intentId"

    @Test
    fun `TC-024-RED-1 full fake journey yields one balanced credit and matching immutable currency reference`() {
        val workflowStore = InMemoryDepositWorkflowStore()
        workflowStore.saveIntent(
            DepositIntentRecord(
                intentId = intentId,
                tenantId = tenantId,
                playerId = UUID.nameUUIDFromBytes("player".toByteArray()),
                methodId = "JAZZCASH",
                providerId = "JAZZCASH",
                amountMinorUnits = 250_000L,
                currencyCode = "PKR",
                status = DepositIntentStatus.PROVIDER_PENDING,
                idempotencyKey = "intent-$intentId",
                requestFingerprint = "fingerprint",
                providerReference = providerReference,
                expiresAt = now.plus(Duration.ofMinutes(15)),
                createdAt = now,
                updatedAt = now,
            )
        )
        val ledgerStore = InMemoryLedgerJournalStore()
        val service = DurableDepositWorkflowService(
            workflowStore = workflowStore,
            paymentMethodStore = InMemoryPaymentMethodStore(),
            sessions = object : AdminSessionDirectory {
                override fun find(tenantId: String, principalId: String, sessionId: String) =
                    AdminSessionStatus(true, false, now.plus(Duration.ofHours(1)), true)
            },
            ledgerPostingService = LedgerPostingService(ledgerStore, clock = clock),
            providerPorts = mapOf("JAZZCASH" to adapter),
            credentialsResolver = { _, _ -> ProviderCredentials(merchantId = "MERCHANT-01", signingSecretOrKey = secret) },
            configResolver = { _, providerId ->
                ProviderConfiguration(providerId, ProviderEnvironment.SANDBOX, "https://sandbox.jazzcash.example")
            },
            clock = clock,
        )

        val fields = signedFields()
        val result = service.processCallback(
            DepositCallbackCommand(
                tenantId = tenantId,
                providerId = "JAZZCASH",
                providerEventId = "cert-event-1",
                rawBody = fields.toSortedMap().toString(),
                queryParams = fields,
            )
        )

        assertEquals(DepositIntentStatus.SETTLED, result.status)
        assertEquals(2, ledgerStore.findAllLegsForTenant(tenantId).size)
        assertEquals(250_000L, ledgerStore.findBalance(tenantId, "PLAYER:${UUID.nameUUIDFromBytes("player".toByteArray())}", "PKR"))
        assertEquals(-250_000L, ledgerStore.findBalance(tenantId, "gateway:clearing:JAZZCASH", "PKR"))
        val stored = workflowStore.findIntent(tenantId, intentId)
        assertEquals(providerReference, stored?.providerReference)
        assertEquals("PKR", stored?.currencyCode)
    }

    @Test
    fun `TC-024-RED-2 missing sandbox evidence is blocked and never reported as pass`() {
        val service = ProviderRouteCertificationService()
        val blocked = service.externalEvidence(sandboxCredentialsPresent = false, sandboxRouteAuthorized = false)
        assertEquals(ProviderRouteCertificationStatus.EXTERNALLY_BLOCKED, blocked.status)
        assertTrue(blocked.reason.contains("not PASS"))

        val matrix = service.routeMatrix()
        assertEquals(5, matrix.size)
        assertEquals(
            setOf("SAFEPAY_RAAST", "ONELINK_RAAST", "JAZZCASH", "EASYPAISA", "ONELINK_IBFT"),
            matrix.map { it.providerId }.toSet(),
        )
        assertTrue(matrix.any { it.status == ProviderRouteCertificationStatus.SIMULATED_PASS })
        assertTrue(matrix.any { it.status == ProviderRouteCertificationStatus.DISABLED_UNSUPPORTED })
    }

    @Test
    fun `TC-024-RED-3 production host is refused before network and disabled route returns unsupported`() {
        val service = ProviderRouteCertificationService()
        assertFailsWith<IllegalStateException> {
            service.requireNonProductionEndpoint(
                ProviderConfiguration("SAFEPAY_RAAST", ProviderEnvironment.PRODUCTION, "https://live.safepay.example")
            )
        }

        val disabled = OneLinkRaastAdapter().deposit(
            ProviderDepositCommand(
                tenantId = tenantId,
                operationId = UUID.randomUUID(),
                idempotencyKey = "disabled",
                providerId = "ONELINK_RAAST",
                methodId = "RAAST",
                amountMinorUnits = 2500L,
                currency = "PKR",
                customerIdentifier = "03001234567",
                correlationId = "corr",
            ),
            ProviderConfiguration("ONELINK_RAAST", ProviderEnvironment.SANDBOX, "https://sandbox.onelink.example"),
            ProviderCredentials(clientId = "client"),
        )
        assertEquals(ProviderOutcomeStatus.DECLINED, disabled.status)
        assertEquals("UNSUPPORTED_OPERATION", disabled.rawResponseCode)
    }

    private fun signedFields(): Map<String, String> {
        val fields = mapOf(
            "pp_Amount" to "250000",
            "pp_MerchantID" to "MERCHANT-01",
            "pp_ResponseCode" to "000",
            "pp_TxnCurrency" to "PKR",
            "pp_TxnRefNo" to providerReference,
        )
        return fields + ("pp_SecureHash" to adapter.calculateSecureHash(fields, secret))
    }
}
