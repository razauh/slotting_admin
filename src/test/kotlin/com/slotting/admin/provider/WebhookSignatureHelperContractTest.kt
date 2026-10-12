package com.slotting.admin.provider

import com.slotting.admin.auth.AuthErrorCode
import com.slotting.admin.auth.AuthenticationFailure
import com.slotting.admin.payment.AuthenticateDepositWebhookCommand
import com.slotting.admin.payment.DepositWebhookAuthenticationBinding
import com.slotting.admin.payment.DepositWebhookAuthenticationService
import com.slotting.admin.payment.InMemoryDepositWebhookAlertSink
import com.slotting.admin.payment.InMemoryDepositWebhookSecretResolver
import com.slotting.admin.payment.InMemoryDepositWebhookStore
import com.slotting.admin.payment.WebhookAuthStatus
import com.slotting.admin.provider.port.ProviderConfiguration
import com.slotting.admin.provider.port.ProviderCredentials
import com.slotting.admin.provider.port.ProviderEnvironment
import com.slotting.admin.provider.port.adapters.SafepayRaastAdapter
import org.junit.jupiter.api.AfterEach
import org.junit.jupiter.api.Test
import java.time.Clock
import java.time.Instant
import java.time.ZoneOffset
import java.util.UUID
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertTrue

class WebhookSignatureHelperContractTest {
    private val now = Instant.parse("2026-10-12T10:00:00Z")
    private val clock = Clock.fixed(now, ZoneOffset.UTC)
    private val safepaySecret = "test-only-safepay-signing-key"
    private val adapter = SafepayRaastAdapter()
    private val config = ProviderConfiguration(
        providerId = adapter.providerId,
        environment = ProviderEnvironment.SANDBOX,
        baseUrl = "https://sandbox.safepay.example",
    )

    @AfterEach
    fun restoreWebhookBinding() {
        DepositWebhookAuthenticationBinding.isBound = true
    }

    @Test
    fun validSignatureVerifiesForEachProviderProtocol() {
        val knownAnswer = WebhookSignatureFixtures.signedCallback(
            providerId = WebhookSignatureFixtures.SAFEPAY_RAAST,
            tenantId = "tenant-known-answer",
            eventId = "event-known-answer",
            rawPayload = "The quick brown fox jumps over the lazy dog",
            secret = "key",
        )
        assertEquals(
            "f7bc83f430538424b13298e6aa6fb143ef4d59a14946175997479dbc2d1a3cd8",
            knownAnswer.signature,
        )
        assertEquals(
            WebhookSignatureVerification.VALID,
            WebhookSignatureFixtures.verify(
                WebhookSignatureFixtures.SAFEPAY_RAAST,
                "",
                null,
                WebhookSignatureFixtures.signedCallback(
                    WebhookSignatureFixtures.SAFEPAY_RAAST,
                    "tenant-empty",
                    "event-empty",
                    "",
                    "empty-payload-secret",
                ).signature,
                "empty-payload-secret",
            ),
        )
        val safepayFixture = WebhookSignatureFixtures.signedCallback(
            providerId = WebhookSignatureFixtures.SAFEPAY_RAAST,
            tenantId = "tenant-" + UUID.randomUUID(),
            eventId = UUID.randomUUID().toString(),
            rawPayload = "{\"amount\":5000,\"tracker\":\"track-known-answer\"}",
            secret = safepaySecret,
        )
        assertEquals(
            WebhookSignatureVerification.VALID,
            WebhookSignatureFixtures.verify(
                safepayFixture.providerId,
                safepayFixture.rawPayload,
                safepayFixture.timestamp,
                safepayFixture.signature,
                safepaySecret,
            ),
        )
        val safepayResult = adapter.verifyCallback(
            WebhookSignatureFixtures.safepayCallback(safepayFixture),
            config,
            ProviderCredentials(signingSecretOrKey = safepaySecret),
        )
        assertTrue(safepayResult.isValid)
        assertEquals("track-known-answer", safepayResult.providerReference)

        val timestampedFixture = WebhookSignatureFixtures.signedCallback(
            providerId = WebhookSignatureFixtures.TIMESTAMPED_DEPOSIT,
            tenantId = "tenant-" + UUID.randomUUID(),
            eventId = UUID.randomUUID().toString(),
            rawPayload = "{\"amount\":5000}",
            secret = "test-only-deposit-signing-key",
            timestamp = now.epochSecond.toString(),
        )
        assertEquals(
            WebhookSignatureVerification.VALID,
            WebhookSignatureFixtures.verify(
                timestampedFixture.providerId,
                timestampedFixture.rawPayload,
                timestampedFixture.timestamp,
                timestampedFixture.signature,
                "test-only-deposit-signing-key",
            ),
        )
    }

    @Test
    fun wrongSecretIsRejectedWithDistinctReason() {
        val fixture = safepayFixture()
        assertEquals(
            WebhookSignatureVerification.INVALID_SIGNATURE,
            WebhookSignatureFixtures.verify(
                fixture.providerId,
                fixture.rawPayload,
                fixture.timestamp,
                fixture.signature,
                "wrong-test-secret",
            ),
        )
        val result = adapter.verifyCallback(
            WebhookSignatureFixtures.safepayCallback(fixture),
            config,
            ProviderCredentials(signingSecretOrKey = "wrong-test-secret"),
        )
        assertFalse(result.isValid)
        assertEquals("INVALID_SIGNATURE", result.rejectionReason)
        assertEquals(
            WebhookSignatureVerification.INVALID_SIGNATURE,
            WebhookSignatureFixtures.verify(
                fixture.providerId,
                fixture.rawPayload,
                fixture.timestamp,
                fixture.signature.uppercase(),
                safepaySecret,
            ),
        )
        assertEquals(
            WebhookSignatureVerification.INVALID_SIGNATURE,
            WebhookSignatureFixtures.verify(
                fixture.providerId,
                fixture.rawPayload,
                fixture.timestamp,
                " ${fixture.signature} ",
                safepaySecret,
            ),
        )
    }

    @Test
    fun mutatedAmountIsRejectedWithDistinctReason() {
        val fixture = safepayFixture()
        val tampered = WebhookSignatureFixtures.tamperedAmount(fixture)
        assertEquals(
            WebhookSignatureVerification.INVALID_SIGNATURE,
            WebhookSignatureFixtures.verify(
                tampered.providerId,
                tampered.rawPayload,
                tampered.timestamp,
                tampered.signature,
                safepaySecret,
            ),
        )
        val result = adapter.verifyCallback(
            WebhookSignatureFixtures.safepayCallback(tampered),
            config,
            ProviderCredentials(signingSecretOrKey = safepaySecret),
        )
        assertFalse(result.isValid)
        assertEquals("INVALID_SIGNATURE", result.rejectionReason)
    }

    @Test
    fun missingHashAndSecretFailClosedWithDistinctReasons() {
        val fixture = safepayFixture()
        val missingHash = WebhookSignatureFixtures.withoutHash(fixture)
        assertEquals(
            WebhookSignatureVerification.MISSING_HASH,
            WebhookSignatureFixtures.verify(
                missingHash.providerId,
                missingHash.rawPayload,
                missingHash.timestamp,
                missingHash.signature,
                safepaySecret,
            ),
        )
        val result = adapter.verifyCallback(
            WebhookSignatureFixtures.safepayCallback(missingHash),
            config,
            ProviderCredentials(signingSecretOrKey = safepaySecret),
        )
        assertFalse(result.isValid)
        assertEquals("MISSING_SIGNATURE", result.rejectionReason)
        assertEquals(
            WebhookSignatureVerification.MISSING_SECRET,
            WebhookSignatureFixtures.verify(
                fixture.providerId,
                fixture.rawPayload,
                fixture.timestamp,
                fixture.signature,
                null,
            ),
        )
        assertEquals(
            WebhookSignatureVerification.UNKNOWN_PROVIDER,
            WebhookSignatureFixtures.verify("UNKNOWN", fixture.rawPayload, null, fixture.signature, safepaySecret),
        )
    }

    @Test
    fun duplicateEventIdIsRejectedByServiceAndScopedByTenant() {
        DepositWebhookAuthenticationBinding.isBound = true
        val tenantId = "tenant-" + UUID.randomUUID()
        val providerId = "test-deposit-provider"
        val secret = "test-only-deposit-signing-key"
        val eventId = UUID.randomUUID().toString()
        val timestamp = now.epochSecond.toString()
        val fixture = WebhookSignatureFixtures.signedCallback(
            providerId = WebhookSignatureFixtures.TIMESTAMPED_DEPOSIT,
            tenantId = tenantId,
            eventId = eventId,
            rawPayload = "{\"eventId\":\"$eventId\",\"paymentReference\":\"pay-$eventId\",\"amount\":5000,\"currency\":\"PKR\",\"status\":\"CAPTURED\"}",
            secret = secret,
            timestamp = timestamp,
        )
        val resolver = InMemoryDepositWebhookSecretResolver().apply { setSecret(tenantId, providerId, secret) }
        val store = InMemoryDepositWebhookStore()
        val service = DepositWebhookAuthenticationService(
            resolver,
            store,
            InMemoryDepositWebhookAlertSink(),
            clock = clock,
        )
        val command = AuthenticateDepositWebhookCommand(
            tenantId = tenantId,
            providerId = providerId,
            signatureHeader = fixture.signature,
            timestampHeader = timestamp,
            rawPayload = fixture.rawPayload,
            idempotencyKey = "event-$eventId",
            correlationId = "corr-$eventId",
            causationId = "cause-$eventId",
        )
        val accepted = service.authenticateWebhook(command)
        assertEquals(WebhookAuthStatus.AUTHENTICATED, accepted.status)
        assertEquals(accepted.resultId, service.authenticateWebhook(command).resultId)
        val replay = assertFailsWith<AuthenticationFailure.Rejected> {
            service.authenticateWebhook(command.copy(idempotencyKey = "replay-$eventId"))
        }
        assertEquals(AuthErrorCode.CONFLICT, replay.code)
        assertEquals(1, store.getAuditEvents().size)

        val replayRegistry = WebhookReplayEventRegistry()
        assertTrue(replayRegistry.markIfNew(tenantId, eventId))
        assertFalse(replayRegistry.markIfNew(tenantId, eventId))
        assertTrue(replayRegistry.markIfNew("another-tenant", eventId))
    }

    private fun safepayFixture() = WebhookSignatureFixtures.signedCallback(
        providerId = WebhookSignatureFixtures.SAFEPAY_RAAST,
        tenantId = "tenant-" + UUID.randomUUID(),
        eventId = UUID.randomUUID().toString(),
        rawPayload = "{\"amount\":5000,\"tracker\":\"track-fixture\"}",
        secret = safepaySecret,
    )
}
