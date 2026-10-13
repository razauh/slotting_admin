package com.slotting.admin.deposit

import com.fasterxml.jackson.databind.ObjectMapper
import com.slotting.admin.auth.AdminRole
import com.slotting.admin.auth.AdminSessionDirectory
import com.slotting.admin.auth.AdminSessionStatus
import com.slotting.admin.auth.AuthenticatedPrincipal
import com.slotting.admin.auth.OutboxEvent
import com.slotting.admin.auth.PrincipalKind
import com.slotting.admin.ledger.InMemoryLedgerJournalStore
import com.slotting.admin.ledger.LedgerPostingService
import com.slotting.admin.provider.InMemoryPaymentMethodStore
import com.slotting.admin.provider.PaymentMethodAction
import com.slotting.admin.provider.PaymentMethodConfig
import com.slotting.admin.provider.PaymentMethodResult
import com.slotting.admin.provider.PaymentMethodStatus
import com.slotting.admin.provider.PaymentMethodType
import com.slotting.admin.provider.WebhookSignatureFixtures
import com.slotting.admin.provider.port.ProviderConfiguration
import com.slotting.admin.provider.port.ProviderCredentials
import com.slotting.admin.provider.port.ProviderEnvironment
import com.slotting.admin.provider.port.adapters.SafepayRaastAdapter
import org.junit.jupiter.api.Test
import org.springframework.http.MediaType
import org.springframework.test.web.servlet.MockMvc
import org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post
import org.springframework.test.web.servlet.setup.MockMvcBuilders
import java.time.Clock
import java.time.Duration
import java.time.Instant
import java.time.ZoneOffset
import java.util.UUID
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue

class PlayerDepositControllerWebhookContractTest {
    private val now = Instant.parse("2026-10-12T10:00:00Z")
    private val clock = Clock.fixed(now, ZoneOffset.UTC)
    private val tenantId = "tenant-mockmvc-" + UUID.randomUUID()
    private val playerId = UUID.randomUUID()
    private val providerId = "SAFEPAY_RAAST"
    private val signingSecret = "test-only-callback-signing-secret"

    @Test
    fun callbackRouteAcceptsAndReplaysIdenticalEventOnceAndRejectsConflicts() {
        val methodStore = InMemoryPaymentMethodStore()
        val methodConfig = PaymentMethodConfig(
            tenantId = tenantId,
            methodId = "SAFEPAY",
            providerId = providerId,
            methodType = PaymentMethodType.BANK_TRANSFER,
            displayName = "Safepay test method",
            instructions = "Test deposit",
            safeAccountTitle = "Safepay test account",
            safeAccountNumber = "test-account",
            iconUrl = "https://example.test/safepay.png",
            supportedCurrencies = listOf("PKR"),
            allowsDeposit = true,
            allowsWithdrawal = false,
            minDepositMinorUnits = 1L,
            maxDepositMinorUnits = 100_000L,
            minWithdrawalMinorUnits = 0L,
            maxWithdrawalMinorUnits = 0L,
            feeFlatMinorUnits = 0L,
            feePercentageBps = 0,
            displayOrder = 1,
            status = PaymentMethodStatus.ACTIVE,
            maintenanceReason = null,
            serverVersion = 1L,
            createdAt = now,
            updatedAt = now,
            updatedBy = "test",
        )
        val methodAudit = com.slotting.admin.auth.AuditEvent(
            eventId = UUID.randomUUID(),
            resultId = UUID.randomUUID(),
            tenantId = tenantId,
            type = "TEST_METHOD_REGISTERED",
            occurredAt = now,
            correlationId = "corr-method",
            causationId = "cause-method",
        )
        methodStore.save(
            PaymentMethodResult(methodAudit.resultId, methodConfig, now, "test-evidence"),
            "method-fingerprint",
            "method-idempotency",
            PaymentMethodAction.REGISTER,
            "test-registration",
            "test-admin",
            methodAudit,
            OutboxEvent(
                eventId = UUID.randomUUID(),
                resultId = methodAudit.resultId,
                tenantId = tenantId,
                type = "TEST_METHOD_REGISTERED",
                createdAt = now,
            ),
        )

        val workflowStore = InMemoryDepositWorkflowStore()
        val ledgerStore = InMemoryLedgerJournalStore()
        val adapter = SafepayRaastAdapter()
        val sessionDirectory = object : AdminSessionDirectory {
            override fun find(tenantId: String, principalId: String, sessionId: String) =
                AdminSessionStatus(
                    active = true,
                    breakGlass = false,
                    expiresAt = now.plus(Duration.ofHours(1)),
                    mfaVerified = true,
                )
        }
        val service = DurableDepositWorkflowService(
            workflowStore = workflowStore,
            paymentMethodStore = methodStore,
            sessions = sessionDirectory,
            ledgerPostingService = LedgerPostingService(ledgerStore, clock = clock),
            providerPorts = mapOf(providerId to adapter),
            credentialsResolver = { _, _ ->
                ProviderCredentials(apiKey = "test-only-api-key", signingSecretOrKey = signingSecret)
            },
            configResolver = { _, selectedProvider ->
                ProviderConfiguration(
                    providerId = selectedProvider,
                    environment = ProviderEnvironment.SANDBOX,
                    baseUrl = "https://sandbox.safepay.example",
                )
            },
            clock = clock,
        )
        val principal = AuthenticatedPrincipal(
            id = playerId.toString(),
            tenantId = tenantId,
            kind = PrincipalKind.PLAYER,
            roles = emptySet(),
        )
        val intent = service.createIntent(
            CreateDepositIntentCommand(
                principal = principal,
                sessionId = "test-session",
                tenantId = tenantId,
                playerId = playerId,
                methodId = "SAFEPAY",
                amountMinorUnits = 50_000L,
                currencyCode = "PKR",
                customerIdentifier = "test-customer",
                methodExpectedVersion = 1L,
                idempotencyKey = "deposit-" + UUID.randomUUID(),
                correlationId = "corr-deposit",
                causationId = "cause-deposit",
            ),
        )
        val eventId = "evt-" + UUID.randomUUID()
        val rawBody = """{"data":{"token":"token-test","amount":50000,"currency":"PKR","status":"paid","tracker":"${intent.providerReference}"}}"""
        assertEquals(
            intent.providerReference,
            workflowStore.findIntentByProviderReference(tenantId, intent.providerReference!!)?.providerReference,
        )
        val signedFixture = WebhookSignatureFixtures.signedCallback(
            providerId = WebhookSignatureFixtures.SAFEPAY_RAAST,
            tenantId = tenantId,
            eventId = eventId,
            rawPayload = rawBody,
            secret = signingSecret,
        )
        val mockMvc: MockMvc = MockMvcBuilders.standaloneSetup(PlayerDepositController(service)).build()
        val route = "/api/v1/tenants/$tenantId/deposits/callback/$providerId"
        val mapper = ObjectMapper()

        fun deliver(
            body: String,
            signature: String? = signedFixture.signature,
            eventHeader: String? = eventId,
        ) = mockMvc.perform(
            post(route)
                .contentType(MediaType.APPLICATION_JSON)
                .apply {
                    if (eventHeader != null) header("x-provider-event-id", eventHeader)
                    if (signature != null) header("x-sfpy-signature", signature)
                }
                .content(body),
        ).andReturn().response

        val firstResponse = deliver(rawBody)
        assertEquals(200, firstResponse.status, firstResponse.contentAsString)
        val firstJson = mapper.readTree(firstResponse.contentAsString)
        assertEquals("SETTLED", firstJson.get("status").asText())
        assertFalse(firstJson.get("alreadyProcessed").asBoolean())
        val firstLedgerReference = firstJson.get("ledgerTransactionReference").asText()

        val replayResponse = deliver(rawBody)
        assertEquals(200, replayResponse.status)
        val replayJson = mapper.readTree(replayResponse.contentAsString)
        assertTrue(replayJson.get("alreadyProcessed").asBoolean())
        assertEquals(firstLedgerReference, replayJson.get("ledgerTransactionReference").asText())

        val tamperedBody = WebhookSignatureFixtures.tamperedAmount(signedFixture).rawPayload
        assertEquals(403, deliver(tamperedBody).status)
        assertEquals(403, deliver(rawBody, signature = null).status)

        val newlySignedConflict = WebhookSignatureFixtures.signedCallback(
            providerId = WebhookSignatureFixtures.SAFEPAY_RAAST,
            tenantId = tenantId,
            eventId = eventId,
            rawPayload = tamperedBody,
            secret = signingSecret,
        )
        val conflictResponse = deliver(tamperedBody, newlySignedConflict.signature)
        assertEquals(409, conflictResponse.status)
        assertTrue(conflictResponse.contentAsString.contains("CALLBACK_EVENT_CONFLICT"))

        assertEquals(400, deliver(rawBody, eventHeader = null).status)
        assertEquals(400, deliver(rawBody, signature = null, eventHeader = null).status)
        assertEquals(400, deliver(rawBody, eventHeader = "   ").status)
        assertEquals(400, deliver(rawBody, eventHeader = "e".repeat(129)).status)

        assertEquals(1, ledgerStore.findAllTransactionsForTenant(tenantId).size)
        assertEquals(
            50_000L,
            ledgerStore.findBalance(tenantId, "player:wallet:$playerId", "PKR"),
        )
        val inboxEvent = workflowStore.findInboxEvent(tenantId, providerId, eventId)
        assertEquals("PROCESSED", inboxEvent?.status)
    }
}
