package com.slotting.admin.settings

import com.slotting.admin.auth.AdminPermission
import com.slotting.admin.auth.AdminRbacPolicy
import com.slotting.admin.auth.AdminRole
import com.slotting.admin.auth.AdminSessionDirectory
import com.slotting.admin.auth.AdminSessionStatus
import com.slotting.admin.auth.AuthErrorCode
import com.slotting.admin.auth.AuthenticatedPrincipal
import com.slotting.admin.auth.AuthenticationFailure
import com.slotting.admin.auth.PrincipalKind
import com.slotting.admin.notification.CallbackEventType
import com.slotting.admin.notification.EmailTransport
import com.slotting.admin.notification.NotificationChannel
import com.slotting.admin.notification.NotificationClassification
import com.slotting.admin.notification.NotificationDispatchRequest
import com.slotting.admin.notification.NotificationSuppressionService
import com.slotting.admin.notification.ProviderDeliveryCallback
import com.slotting.admin.notification.PushTransport
import com.slotting.admin.notification.SmsTransport
import com.slotting.admin.notification.TransportSubmitResult
import com.slotting.admin.notification.TruthfulDeliveryState
import com.slotting.admin.notification.TruthfulNotificationService
import com.slotting.admin.secret.AesGcmEnvelopeEncryptor
import com.slotting.admin.secret.DecryptionTamperException
import com.slotting.admin.secret.EncryptedSecretPayload
import com.slotting.admin.secret.ExternalKmsMasterKeyProvider
import com.slotting.admin.secret.LocalDevMasterKeyProvider
import com.slotting.admin.secret.ProductionSecurityException
import org.junit.jupiter.api.Assertions.*
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test
import java.time.Clock
import java.time.Duration
import java.time.Instant
import java.time.ZoneOffset
import java.util.Base64
import java.util.UUID

class TruthfulNotificationAndKmsIntegrationContractTest {

    private lateinit var settingsStore: InMemoryIntegrationSettingsStore
    private lateinit var sessionDirectory: FakeAdminSessionDirectory
    private lateinit var rbacPolicy: AdminRbacPolicy
    private lateinit var devEncryptor: AesGcmEnvelopeEncryptor
    private lateinit var settingsService: IntegrationSettingsService
    private lateinit var notificationService: TruthfulNotificationService
    private lateinit var mockSmsTransportTwilio: TestSmsTransport
    private lateinit var mockSmsTransportAwsSns: TestSmsTransport

    private val tenantId = "tenant-settings-1"
    private val foreignTenantId = "tenant-foreign-2"
    private val fixedNow = Instant.parse("2026-09-26T12:00:00Z")
    private val clock = Clock.fixed(fixedNow, ZoneOffset.UTC)
    private val validSessionId = "session-settings-valid"

    private val superAdmin = AuthenticatedPrincipal(
        id = "admin-super",
        tenantId = tenantId,
        kind = PrincipalKind.ADMIN,
        roles = setOf(AdminRole.SUPER_ADMIN),
    )

    private val securityAdmin = AuthenticatedPrincipal(
        id = "admin-sec",
        tenantId = tenantId,
        kind = PrincipalKind.ADMIN,
        roles = setOf(AdminRole.SECURITY),
    )

    private val supportAdmin = AuthenticatedPrincipal(
        id = "admin-sup",
        tenantId = tenantId,
        kind = PrincipalKind.ADMIN,
        roles = setOf(AdminRole.SUPPORT), // Lacks integration settings permissions
    )

    @BeforeEach
    fun setUp() {
        settingsStore = InMemoryIntegrationSettingsStore()
        sessionDirectory = FakeAdminSessionDirectory()
        sessionDirectory.registerSession(
            tenantId = tenantId,
            principalId = superAdmin.id,
            sessionId = validSessionId,
            status = AdminSessionStatus(active = true, breakGlass = false, expiresAt = fixedNow.plus(Duration.ofHours(2)), mfaVerified = true)
        )
        sessionDirectory.registerSession(
            tenantId = tenantId,
            principalId = securityAdmin.id,
            sessionId = validSessionId,
            status = AdminSessionStatus(active = true, breakGlass = false, expiresAt = fixedNow.plus(Duration.ofHours(2)), mfaVerified = true)
        )
        sessionDirectory.registerSession(
            tenantId = tenantId,
            principalId = supportAdmin.id,
            sessionId = validSessionId,
            status = AdminSessionStatus(active = true, breakGlass = false, expiresAt = fixedNow.plus(Duration.ofHours(2)), mfaVerified = true)
        )

        rbacPolicy = AdminRbacPolicy(dualControlRequired = false)
        devEncryptor = AesGcmEnvelopeEncryptor(LocalDevMasterKeyProvider(), environment = "TEST")

        settingsService = IntegrationSettingsService(
            store = settingsStore,
            sessions = sessionDirectory,
            rbacPolicy = rbacPolicy,
            encryptor = devEncryptor,
            clock = clock,
            environment = "TEST",
        )

        mockSmsTransportTwilio = TestSmsTransport("twilio-ref")
        mockSmsTransportAwsSns = TestSmsTransport("sns-ref")

        notificationService = TruthfulNotificationService(
            settingsStore = settingsStore,
            smsTransports = mapOf(
                SmsProviderType.TWILIO to mockSmsTransportTwilio,
                SmsProviderType.AWS_SNS to mockSmsTransportAwsSns,
            ),
            emailTransports = emptyMap(),
            pushTransports = emptyMap(),
            clock = clock,
            environment = "TEST",
        )
    }

    // =========================================================================
    // Scenario 1: Accepted but NOT Delivered (Truthful Initial State)
    // =========================================================================
    @Test
    fun `Scenario 1 - notification submit returns ACCEPTED never DELIVERED`() {
        // Configure SMS via Settings
        settingsService.updateSmsSettings(
            UpdateSmsIntegrationCommand(
                principal = superAdmin,
                sessionId = validSessionId,
                tenantId = tenantId,
                providerType = SmsProviderType.TWILIO,
                enabled = true,
                accountId = "AC123456789",
                senderId = "SLOTTING",
                replaceAuthToken = "secret-token-value-123",
                expectedVersion = 1L,
            )
        )

        val request = NotificationDispatchRequest(
            principal = superAdmin,
            tenantId = tenantId,
            notificationId = UUID.randomUUID(),
            recipientUserId = "user-1",
            classification = NotificationClassification.TRANSACTIONAL,
            channel = NotificationChannel.SMS,
            templateId = "AUTH_OTP",
            templateParameters = mapOf("code" to "123456"),
            recipientDestination = "+1234567890",
            idempotencyKey = "idem-notif-1",
            correlationId = "corr-1",
            causationId = "cause-1",
        )

        val result = notificationService.dispatch(request)
        assertEquals(TruthfulDeliveryState.ACCEPTED, result.deliveryState, "Submission must result in ACCEPTED, never synthetic DELIVERED")
        assertNotNull(result.providerReference)
    }

    // =========================================================================
    // Scenario 2: Verified Delivery Callback
    // =========================================================================
    @Test
    fun `Scenario 2 - verified delivery callback transitions state to DELIVERED`() {
        val callback = ProviderDeliveryCallback(
            tenantId = tenantId,
            channel = NotificationChannel.SMS,
            providerReference = "twilio-ref-123",
            eventType = CallbackEventType.DELIVERED,
            signature = "valid-sig",
            timestamp = fixedNow,
        )

        val res = notificationService.handleDeliveryCallback(callback)
        assertEquals(TruthfulDeliveryState.DELIVERED, res.resultingState)
        assertFalse(res.isDuplicate)
    }

    // =========================================================================
    // Scenario 3: Duplicate Callback Idempotency
    // =========================================================================
    @Test
    fun `Scenario 3 - duplicate callback is acknowledged idempotently without error`() {
        val callback = ProviderDeliveryCallback(
            tenantId = tenantId,
            channel = NotificationChannel.SMS,
            providerReference = "twilio-ref-dup",
            eventType = CallbackEventType.DELIVERED,
            signature = "valid-sig",
            timestamp = fixedNow,
        )

        val firstRes = notificationService.handleDeliveryCallback(callback)
        assertEquals(TruthfulDeliveryState.DELIVERED, firstRes.resultingState)

        val secondRes = notificationService.handleDeliveryCallback(callback)
        assertEquals(TruthfulDeliveryState.DELIVERED, secondRes.resultingState)
        assertTrue(secondRes.isDuplicate, "Second callback must be marked as duplicate")
    }

    // =========================================================================
    // Scenario 4: Suppressed Player (Marketing vs Transactional)
    // =========================================================================
    @Test
    fun `Scenario 4 - marketing suppressed player is blocked across provider switch`() {
        // Setup suppression service with opted-out player
        val suppressionService = NotificationSuppressionService()
        suppressionService.addSuppression(
            principal = superAdmin,
            tenantId = tenantId,
            userId = "user-optout",
            channel = null,
            reason = com.slotting.admin.notification.SuppressionReason.MARKETING_OPT_OUT,
            evidenceReference = "ev-optout",
        )

        val suppressedNotifService = TruthfulNotificationService(
            settingsStore = settingsStore,
            smsTransports = mapOf(
                SmsProviderType.TWILIO to mockSmsTransportTwilio,
                SmsProviderType.AWS_SNS to mockSmsTransportAwsSns,
            ),
            emailTransports = emptyMap(),
            pushTransports = emptyMap(),
            suppressionService = suppressionService,
            clock = clock,
        )

        settingsService.updateSmsSettings(
            UpdateSmsIntegrationCommand(
                principal = superAdmin,
                sessionId = validSessionId,
                tenantId = tenantId,
                providerType = SmsProviderType.TWILIO,
                enabled = true,
                replaceAuthToken = "tok-1",
                expectedVersion = 1L,
            )
        )

        val marketingReq = NotificationDispatchRequest(
            principal = superAdmin,
            tenantId = tenantId,
            notificationId = UUID.randomUUID(),
            recipientUserId = "user-optout",
            classification = NotificationClassification.MARKETING,
            channel = NotificationChannel.SMS,
            templateId = "PROMO_DISCOUNT",
            templateParameters = emptyMap(),
            recipientDestination = "+1000000000",
            idempotencyKey = "idem-mkt-1",
            correlationId = "corr-mkt",
            causationId = "cause-mkt",
        )

        val resTwilio = suppressedNotifService.dispatch(marketingReq)
        assertEquals(TruthfulDeliveryState.SUPPRESSED, resTwilio.deliveryState)

        // Switch to AWS_SNS - suppression must still apply!
        settingsService.updateSmsSettings(
            UpdateSmsIntegrationCommand(
                principal = superAdmin,
                sessionId = validSessionId,
                tenantId = tenantId,
                providerType = SmsProviderType.AWS_SNS,
                enabled = true,
                replaceAuthToken = "tok-2",
                expectedVersion = 2L,
            )
        )

        val resSns = suppressedNotifService.dispatch(marketingReq.copy(idempotencyKey = "idem-mkt-2"))
        assertEquals(TruthfulDeliveryState.SUPPRESSED, resSns.deliveryState, "Switching provider must not bypass suppression")
    }

    // =========================================================================
    // Scenario 5: Secret Write-Only from Settings Read View
    // =========================================================================
    @Test
    fun `Scenario 5 - stored secret credentials are write-only and never returned to UI or API`() {
        val rawSecret = "super-sensitive-twilio-auth-token-999"

        settingsService.updateSmsSettings(
            UpdateSmsIntegrationCommand(
                principal = superAdmin,
                sessionId = validSessionId,
                tenantId = tenantId,
                providerType = SmsProviderType.TWILIO,
                enabled = true,
                accountId = "AC_SECRET_TEST",
                replaceAuthToken = rawSecret,
                expectedVersion = 1L,
            )
        )

        val view = settingsService.getSmsSettings(superAdmin, tenantId, validSessionId)

        // Verify write-only semantics
        assertTrue(view.tokenStatus.configured, "Secret should be marked configured")
        val viewStr = view.toString()
        assertFalse(viewStr.contains(rawSecret), "Plaintext secret must never appear in view or toString representation")

        // Direct store inspection: verify encrypted payload at rest
        val stored = settingsStore.getSmsConfig(tenantId)
        assertNotNull(stored?.encryptedAuthToken)
        assertNotEquals(rawSecret, stored?.encryptedAuthToken?.ciphertextBase64, "Database must store encrypted ciphertext, not plaintext")
    }

    // =========================================================================
    // Scenario 6: Secret Replaced Without Source Code Change
    // =========================================================================
    @Test
    fun `Scenario 6 - credential rotation replaces secret at runtime and preserves omitted secret`() {
        // 1. Initial save with authToken and webhookSecret
        settingsService.updateSmsSettings(
            UpdateSmsIntegrationCommand(
                principal = superAdmin,
                sessionId = validSessionId,
                tenantId = tenantId,
                providerType = SmsProviderType.TWILIO,
                enabled = true,
                replaceAuthToken = "token-v1",
                replaceWebhookSecret = "webhook-v1",
                expectedVersion = 1L,
            )
        )

        val v1 = settingsService.getSmsSettings(superAdmin, tenantId, validSessionId)
        assertEquals(1L, v1.configVersion)
        assertTrue(v1.tokenStatus.configured)
        assertTrue(v1.webhookSecretStatus.configured)

        // 2. Rotate webhookSecret only, leaving authToken omitted (replaceAuthToken = null)
        settingsService.updateSmsSettings(
            UpdateSmsIntegrationCommand(
                principal = superAdmin,
                sessionId = validSessionId,
                tenantId = tenantId,
                providerType = SmsProviderType.TWILIO,
                enabled = true,
                replaceAuthToken = null, // OMITTED: must keep existing token!
                replaceWebhookSecret = "webhook-v2", // REPLACED!
                expectedVersion = 2L,
            )
        )

        val v2 = settingsService.getSmsSettings(superAdmin, tenantId, validSessionId)
        assertEquals(2L, v2.configVersion)
        assertTrue(v2.tokenStatus.configured, "Omitted secret must remain configured")
        assertTrue(v2.webhookSecretStatus.configured)

        // Verify decrypted value of preserved authToken is still token-v1
        val stored = settingsStore.getSmsConfig(tenantId)!!
        val decryptedToken = devEncryptor.decryptString(tenantId, "SMS_AUTH_TOKEN", stored.encryptedAuthToken!!)
        val decryptedWebhook = devEncryptor.decryptString(tenantId, "SMS_WEBHOOK_SECRET", stored.encryptedWebhookSecret!!)
        assertEquals("token-v1", decryptedToken, "Omitted secret must retain its original value")
        assertEquals("webhook-v2", decryptedWebhook, "Replaced secret must have updated value")
    }

    // =========================================================================
    // Scenario 7: Active Provider Switched Dynamically
    // =========================================================================
    @Test
    fun `Scenario 7 - active provider switch changes runtime routing without recompilation`() {
        // Active = TWILIO
        settingsService.updateSmsSettings(
            UpdateSmsIntegrationCommand(
                principal = superAdmin,
                sessionId = validSessionId,
                tenantId = tenantId,
                providerType = SmsProviderType.TWILIO,
                enabled = true,
                replaceAuthToken = "twilio-tok",
                expectedVersion = 1L,
            )
        )

        val req1 = NotificationDispatchRequest(
            principal = superAdmin,
            tenantId = tenantId,
            notificationId = UUID.randomUUID(),
            recipientUserId = "u1",
            classification = NotificationClassification.TRANSACTIONAL,
            channel = NotificationChannel.SMS,
            templateId = "T1",
            templateParameters = emptyMap(),
            recipientDestination = "+12345",
            idempotencyKey = "i-1",
            correlationId = "c-1",
            causationId = "c-1",
        )

        val res1 = notificationService.dispatch(req1)
        assertEquals("twilio-ref", res1.providerReference)

        // Switch Active Provider to AWS_SNS
        settingsService.updateSmsSettings(
            UpdateSmsIntegrationCommand(
                principal = superAdmin,
                sessionId = validSessionId,
                tenantId = tenantId,
                providerType = SmsProviderType.AWS_SNS,
                enabled = true,
                replaceAuthToken = "sns-tok",
                expectedVersion = 2L,
            )
        )

        val req2 = req1.copy(idempotencyKey = "i-2")
        val res2 = notificationService.dispatch(req2)
        assertEquals("sns-ref", res2.providerReference, "Active provider switch must route immediately to AWS_SNS")
    }

    // =========================================================================
    // Scenario 8: Unauthorized Admin Rejected
    // =========================================================================
    @Test
    fun `Scenario 8 - unauthorized admin is rejected with FORBIDDEN when attempting settings changes`() {
        val ex = assertThrows(AuthenticationFailure.Rejected::class.java) {
            settingsService.updateSmsSettings(
                UpdateSmsIntegrationCommand(
                    principal = supportAdmin, // Support lacks EDIT_INTEGRATION_SETTINGS
                    sessionId = validSessionId,
                    tenantId = tenantId,
                    providerType = SmsProviderType.TWILIO,
                    enabled = true,
                    expectedVersion = 1L,
                )
            )
        }
        assertEquals(AuthErrorCode.FORBIDDEN, ex.code)
    }

    // =========================================================================
    // Scenario 9: Authenticated AES-256-GCM Encryption, Wrong Tenant, and Tamper Detection
    // =========================================================================
    @Test
    fun `Scenario 9 - AES-GCM envelope encryption fails on wrong tenant AAD or ciphertext tampering`() {
        val plaintext = "my-secret-signing-key-12345"
        val context = "SMS_WEBHOOK_SECRET"

        // Encrypt with tenantId
        val payload = devEncryptor.encryptString(tenantId, context, plaintext)

        // Decrypt with same tenant and context succeeds
        val decrypted = devEncryptor.decryptString(tenantId, context, payload)
        assertEquals(plaintext, decrypted)

        // 1. Wrong Tenant AAD mismatch must fail
        val wrongTenantEx = assertThrows(DecryptionTamperException::class.java) {
            devEncryptor.decryptString(foreignTenantId, context, payload)
        }
        assertTrue(wrongTenantEx.message!!.contains("tamper", ignoreCase = true) || wrongTenantEx.message!!.contains("tag", ignoreCase = true))

        // 2. Tampered ciphertext must fail
        val rawBytes = Base64.getDecoder().decode(payload.ciphertextBase64)
        rawBytes[0] = (rawBytes[0].toInt() xor 0xFF).toByte() // Flip bit!
        val tamperedPayload = payload.copy(ciphertextBase64 = Base64.getEncoder().encodeToString(rawBytes))

        assertThrows(DecryptionTamperException::class.java) {
            devEncryptor.decryptString(tenantId, context, tamperedPayload)
        }
    }

    // =========================================================================
    // Scenario 10: Production Rejection of Test Master Key Provider
    // =========================================================================
    @Test
    fun `Scenario 10 - production environment rejects local dev master key provider`() {
        val prodEncryptor = AesGcmEnvelopeEncryptor(
            masterKeyProvider = LocalDevMasterKeyProvider(),
            environment = "PRODUCTION" // Production!
        )

        assertThrows(ProductionSecurityException::class.java) {
            prodEncryptor.encryptString(tenantId, "CTX", "secret-payload")
        }
    }

    // =========================================================================
    // Scenario 11: IV Uniqueness and Nonce Randomness
    // =========================================================================
    @Test
    fun `Scenario 11 - IV uniqueness generates distinct ciphertexts for identical plaintext`() {
        val plaintext = "identical-secret-payload"
        val payload1 = devEncryptor.encryptString(tenantId, "CTX", plaintext)
        val payload2 = devEncryptor.encryptString(tenantId, "CTX", plaintext)

        assertNotEquals(payload1.ivBase64, payload2.ivBase64, "Consecutive encryptions must use fresh distinct random IVs")
        assertNotEquals(payload1.ciphertextBase64, payload2.ciphertextBase64, "Identical plaintext under fresh IVs must yield distinct ciphertexts")

        assertEquals(plaintext, devEncryptor.decryptString(tenantId, "CTX", payload1))
        assertEquals(plaintext, devEncryptor.decryptString(tenantId, "CTX", payload2))
    }

    // =========================================================================
    // Scenario 12: Synthetic Adapter Rejected in Production Environment
    // =========================================================================
    @Test
    fun `Scenario 12 - synthetic adapter is rejected when environment is PRODUCTION`() {
        class SyntheticSmsTransport : SmsTransport {
            override fun submit(request: NotificationDispatchRequest, authToken: String?): TransportSubmitResult =
                TransportSubmitResult("synth", true)
            override fun isSynthetic(): Boolean = true
        }

        val prodSettingsStore = InMemoryIntegrationSettingsStore()
        prodSettingsStore.saveSmsConfig(
            SmsIntegrationConfig(
                tenantId = tenantId,
                providerType = SmsProviderType.TWILIO,
                enabled = true,
                updatedAt = fixedNow,
            )
        )

        val prodNotifService = TruthfulNotificationService(
            settingsStore = prodSettingsStore,
            smsTransports = mapOf(SmsProviderType.TWILIO to SyntheticSmsTransport()),
            clock = clock,
            environment = "PRODUCTION",
        )

        val req = NotificationDispatchRequest(
            principal = superAdmin,
            tenantId = tenantId,
            notificationId = UUID.randomUUID(),
            recipientUserId = "u1",
            classification = NotificationClassification.TRANSACTIONAL,
            channel = NotificationChannel.SMS,
            templateId = "T1",
            templateParameters = emptyMap(),
            recipientDestination = "+123",
            idempotencyKey = "i-synth",
            correlationId = "c-1",
            causationId = "c-1",
        )

        assertThrows(ProductionSecurityException::class.java) {
            prodNotifService.dispatch(req)
        }
    }

    // =========================================================================
    // Scenario 13: Test Integration Action Validates Configuration Contract
    // =========================================================================
    @Test
    fun `Scenario 13 - test integration action validates configuration completeness without fake external claim`() {
        // Unconfigured channel test returns false
        val unconfiguredResult = settingsService.testIntegration(securityAdmin, tenantId, validSessionId, IntegrationChannel.SMS)
        assertFalse(unconfiguredResult.success)

        // Configured channel with valid encrypted token returns true
        settingsService.updateSmsSettings(
            UpdateSmsIntegrationCommand(
                principal = superAdmin,
                sessionId = validSessionId,
                tenantId = tenantId,
                providerType = SmsProviderType.TWILIO,
                enabled = true,
                replaceAuthToken = "valid-token-for-test",
                expectedVersion = 1L,
            )
        )

        val configuredResult = settingsService.testIntegration(securityAdmin, tenantId, validSessionId, IntegrationChannel.SMS)
        assertTrue(configuredResult.success)
        assertTrue(configuredResult.message.contains("valid", ignoreCase = true))
    }

    // =========================================================================
    // Scenario 14: Disabled Provider Rejects Dispatch Attempt
    // =========================================================================
    @Test
    fun `Scenario 14 - disabled provider rejects dispatch attempt`() {
        settingsService.updateSmsSettings(
            UpdateSmsIntegrationCommand(
                principal = superAdmin,
                sessionId = validSessionId,
                tenantId = tenantId,
                providerType = SmsProviderType.TWILIO,
                enabled = false, // Disabled!
                expectedVersion = 1L,
            )
        )

        val req = NotificationDispatchRequest(
            principal = superAdmin,
            tenantId = tenantId,
            notificationId = UUID.randomUUID(),
            recipientUserId = "u1",
            classification = NotificationClassification.TRANSACTIONAL,
            channel = NotificationChannel.SMS,
            templateId = "T1",
            templateParameters = emptyMap(),
            recipientDestination = "+123",
            idempotencyKey = "i-dis",
            correlationId = "c-1",
            causationId = "c-1",
        )

        val ex = assertThrows(IllegalStateException::class.java) {
            notificationService.dispatch(req)
        }
        assertTrue(ex.message!!.contains("disabled", ignoreCase = true))
    }

    // =========================================================================
    // Scenario 15: Delivery Failure Callback Transitions State to FAILED
    // =========================================================================
    @Test
    fun `Scenario 15 - delivery failure callback transitions state to FAILED`() {
        val callback = ProviderDeliveryCallback(
            tenantId = tenantId,
            channel = NotificationChannel.SMS,
            providerReference = "twilio-ref-fail",
            eventType = CallbackEventType.BOUNCED,
            signature = "sig-bounce",
            timestamp = fixedNow,
        )

        val res = notificationService.handleDeliveryCallback(callback)
        assertEquals(TruthfulDeliveryState.FAILED, res.resultingState)
    }

    // =========================================================================
    // Scenario 16: Missing KMS Master Key Fails Closed
    // =========================================================================
    @Test
    fun `Scenario 16 - missing KMS master key fails closed`() {
        val emptyKms = ExternalKmsMasterKeyProvider(emptyMap())
        val encryptor = AesGcmEnvelopeEncryptor(emptyKms, environment = "TEST")

        assertThrows(IllegalStateException::class.java) {
            encryptor.encryptString(tenantId, "CTX", "secret-data")
        }
    }

    // =========================================================================
    // Test Fakes
    // =========================================================================
    private class TestSmsTransport(private val refPrefix: String) : SmsTransport {
        override fun submit(request: NotificationDispatchRequest, authToken: String?): TransportSubmitResult {
            return TransportSubmitResult(
                providerReference = refPrefix,
                accepted = true,
                initialDeliveryState = TruthfulDeliveryState.ACCEPTED,
            )
        }
    }

    private class FakeAdminSessionDirectory : AdminSessionDirectory {
        private val sessions = mutableMapOf<String, AdminSessionStatus>()

        fun registerSession(tenantId: String, principalId: String, sessionId: String, status: AdminSessionStatus) {
            sessions["$tenantId:$principalId:$sessionId"] = status
        }

        override fun find(tenantId: String, principalId: String, sessionId: String): AdminSessionStatus? {
            return sessions["$tenantId:$principalId:$sessionId"]
        }
    }
}
