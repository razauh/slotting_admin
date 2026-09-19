package com.slotting.admin.notification

import com.slotting.admin.auth.AdminRole
import com.slotting.admin.auth.AuthenticatedPrincipal
import com.slotting.admin.auth.PrincipalKind
import org.junit.jupiter.api.Assertions.*
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.DisplayName
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.assertThrows
import java.time.Clock
import java.time.Instant
import java.time.ZoneOffset
import java.util.UUID

class FakeNotificationAdapterTest {

    private val tenantId = "tenant-notify-01"
    private val clock = Clock.fixed(Instant.parse("2026-09-19T18:00:00Z"), ZoneOffset.UTC)
    private lateinit var adapter: FakeNotificationAdapterService

    private val validPrincipal = AuthenticatedPrincipal(
        id = "service-actor-01",
        tenantId = tenantId,
        roles = setOf(AdminRole.SUPPORT),
        kind = PrincipalKind.ADMIN,
    )

    private val crossTenantPrincipal = AuthenticatedPrincipal(
        id = "service-actor-other",
        tenantId = "tenant-other",
        roles = setOf(AdminRole.SUPPORT),
        kind = PrincipalKind.ADMIN,
    )

    @BeforeEach
    fun setup() {
        adapter = FakeNotificationAdapterService(clock = clock)
    }

    private fun createValidEmailRequest(
        notificationId: UUID = UUID.randomUUID(),
        idempotencyKey: String = "idem-fake-001",
        recipientUserId: String = "user-01",
        recipientDestination: String = "user01@slotting.com",
        templateId: String = "TEMPLATE_SECURITY_ALERT",
        classification: NotificationClassification = NotificationClassification.TRANSACTIONAL,
        channel: NotificationChannel = NotificationChannel.EMAIL,
        parameters: Map<String, String> = mapOf("event" to "password_reset", "device" to "Pixel 8"),
        principal: AuthenticatedPrincipal? = validPrincipal,
        tenant: String = tenantId,
        expectedVersion: Long = 1L,
    ) = NotificationDispatchRequest(
        principal = principal,
        tenantId = tenant,
        notificationId = notificationId,
        recipientUserId = recipientUserId,
        classification = classification,
        channel = channel,
        templateId = templateId,
        templateParameters = parameters,
        recipientDestination = recipientDestination,
        idempotencyKey = idempotencyKey,
        correlationId = "corr-${UUID.randomUUID()}",
        causationId = "cause-${UUID.randomUUID()}",
        expectedVersion = expectedVersion,
    )

    @Test
    @DisplayName("NOTIFY-001-02-T001: Fake adapter normal dispatch produces authoritative receipt, audit log, idempotent replay, and zero financial mutation")
    fun testNormalDispatchAndIdempotency() {
        val request = createValidEmailRequest()
        val result = adapter.dispatch(request)

        assertNotNull(result)
        assertEquals(request.notificationId, result.notificationId)
        assertEquals(tenantId, result.tenantId)
        assertEquals("user-01", result.recipientUserId)
        assertEquals(NotificationClassification.TRANSACTIONAL, result.classification)
        assertEquals(NotificationChannel.EMAIL, result.channel)
        assertEquals(NotificationDeliveryState.DELIVERED, result.deliveryState)
        assertEquals(1L, result.serverVersion)
        assertEquals("Transactional vs marketing classified; sensitive details behind authenticated app.", result.semanticContract)
        assertFalse(result.directEligibilityGranted, "Adapter must NEVER grant eligibility")
        assertFalse(result.financialMutationPermitted, "Adapter must NEVER mutate financial authority")
        assertTrue(result.providerReference.startsWith("fake-provider-ref:"))
        assertTrue(result.evidenceReference.startsWith("notification:dispatch:"))

        // Verify Journal and Audit logs
        val journal = adapter.getDispatchedJournal(tenantId)
        assertEquals(1, journal.size)
        assertEquals(result.dispatchId, journal[0].dispatchId)

        val auditLogs = adapter.getAuditLogs(tenantId)
        assertEquals(1, auditLogs.size)
        assertEquals("NOTIFICATION_DISPATCHED_FAKE_ADAPTER", auditLogs[0].type)
        assertEquals(result.dispatchId, auditLogs[0].dispatchId)

        // Verify Idempotent replay
        val replayResult = adapter.dispatch(request)
        assertEquals(result.dispatchId, replayResult.dispatchId)
        assertEquals(1, adapter.getDispatchedJournal(tenantId).size)

        // Verify Idempotency conflict on payload mutation
        val conflictingRequest = request.copy(templateId = "TEMPLATE_MFA_CHALLENGE")
        assertThrows<NotificationDispatchException.Conflict> {
            adapter.dispatch(conflictingRequest)
        }
    }

    @Test
    @DisplayName("NOTIFY-001-02-T002: Fake adapter adversarial simulation modes trigger retryable timeout, transient failure, provider down, and rate limited errors")
    fun testAdversarialSimulationModes() {
        val request = createValidEmailRequest()

        // 1. Timeout
        adapter.simulationMode = NotificationSimulationMode.SIMULATE_TIMEOUT
        val timeoutEx = assertThrows<NotificationDispatchException.Timeout> {
            adapter.dispatch(request)
        }
        assertTrue(timeoutEx.isRetryable)
        assertTrue(timeoutEx.message!!.contains("timeout", ignoreCase = true))

        // 2. Transient Failure
        adapter.simulationMode = NotificationSimulationMode.SIMULATE_TRANSIENT_FAILURE
        val transientEx = assertThrows<NotificationDispatchException.TransientFailure> {
            adapter.dispatch(request)
        }
        assertTrue(transientEx.isRetryable)
        assertTrue(transientEx.message!!.contains("transient", ignoreCase = true))

        // 3. Provider Unavailable
        adapter.simulationMode = NotificationSimulationMode.SIMULATE_PROVIDER_DOWN
        val downEx = assertThrows<NotificationDispatchException.ProviderUnavailable> {
            adapter.dispatch(request)
        }
        assertTrue(downEx.isRetryable)
        assertTrue(downEx.message!!.contains("outage", ignoreCase = true))

        // 4. Rate Limited
        adapter.simulationMode = NotificationSimulationMode.SIMULATE_RATE_LIMITED
        val rateLimitEx = assertThrows<NotificationDispatchException.RateLimited> {
            adapter.dispatch(request)
        }
        assertTrue(rateLimitEx.isRetryable)
        assertTrue(rateLimitEx.message!!.contains("rate limit", ignoreCase = true))

        // 5. Restore Normal
        adapter.simulationMode = NotificationSimulationMode.NORMAL
        val successResult = adapter.dispatch(request)
        assertEquals(NotificationDeliveryState.DELIVERED, successResult.deliveryState)
    }

    @Test
    @DisplayName("NOTIFY-001-02-T003: Fake adapter rejects insecure payloads containing credentials/PAN and rejects template injection attempts or unapproved templates")
    fun testInsecurePayloadAndTemplateInjectionRejections() {
        // Insecure payload: password key
        val pwRequest = createValidEmailRequest(
            idempotencyKey = "idem-insecure-pw",
            parameters = mapOf("raw_password" to "SuperSecret123!")
        )
        val pwEx = assertThrows<NotificationDispatchException.Invalid> {
            adapter.dispatch(pwRequest)
        }
        assertTrue(pwEx.message!!.contains("Insecure payload", ignoreCase = true))

        // Insecure payload: credit card raw PAN
        val panRequest = createValidEmailRequest(
            idempotencyKey = "idem-insecure-pan",
            parameters = mapOf("card_details" to "4111111111111111")
        )
        val panEx = assertThrows<NotificationDispatchException.Invalid> {
            adapter.dispatch(panRequest)
        }
        assertTrue(panEx.message!!.contains("raw card PAN", ignoreCase = true))

        // Template injection: mustache / interpolation in value
        val injectionRequest1 = createValidEmailRequest(
            idempotencyKey = "idem-injection-1",
            parameters = mapOf("user_greeting" to "{{system.leakCredentials()}}")
        )
        val injEx1 = assertThrows<NotificationDispatchException.Invalid> {
            adapter.dispatch(injectionRequest1)
        }
        assertTrue(injEx1.message!!.contains("Template injection", ignoreCase = true))

        // Template injection: script tag in key
        val injectionRequest2 = createValidEmailRequest(
            idempotencyKey = "idem-injection-2",
            parameters = mapOf("<script>alert(1)</script>" to "innocent_val")
        )
        val injEx2 = assertThrows<NotificationDispatchException.Invalid> {
            adapter.dispatch(injectionRequest2)
        }
        assertTrue(injEx2.message!!.contains("Template injection", ignoreCase = true))

        // Unapproved template ID
        val unapprovedRequest = createValidEmailRequest(
            idempotencyKey = "idem-unapproved-tmpl",
            templateId = "TEMPLATE_UNKNOWN_HACK"
        )
        val unapprovedEx = assertThrows<NotificationDispatchException.Invalid> {
            adapter.dispatch(unapprovedRequest)
        }
        assertTrue(unapprovedEx.message!!.contains("Unapproved template", ignoreCase = true))

        // Classification mismatch
        val mismatchRequest = createValidEmailRequest(
            idempotencyKey = "idem-mismatch-tmpl",
            templateId = "TEMPLATE_MARKETING_PROMO",
            classification = NotificationClassification.TRANSACTIONAL
        )
        val mismatchEx = assertThrows<NotificationDispatchException.Invalid> {
            adapter.dispatch(mismatchRequest)
        }
        assertTrue(mismatchEx.message!!.contains("Classification mismatch", ignoreCase = true))
    }

    @Test
    @DisplayName("NOTIFY-001-02-T004: Fake adapter validates recipient address format and rejects unauthorized cross-tenant or mismatched user destinations")
    fun testRecipientValidationAndTenantIsolation() {
        // Cross-tenant principal access rejected
        val crossTenantRequest = createValidEmailRequest(
            idempotencyKey = "idem-cross-tenant",
            principal = crossTenantPrincipal,
            tenant = tenantId
        )
        val forbiddenEx = assertThrows<NotificationDispatchException.Forbidden> {
            adapter.dispatch(crossTenantRequest)
        }
        assertTrue(forbiddenEx.message!!.contains("Cross-tenant access forbidden", ignoreCase = true))

        // Unauthenticated principal rejected
        val unauthRequest = createValidEmailRequest(
            idempotencyKey = "idem-unauth",
            principal = null
        )
        assertThrows<NotificationDispatchException.Unauthorized> {
            adapter.dispatch(unauthRequest)
        }

        // Malformed Email format
        val malformedEmailReq = createValidEmailRequest(
            idempotencyKey = "idem-bad-email",
            recipientDestination = "not-an-email"
        )
        val malformedEmailEx = assertThrows<NotificationDispatchException.Invalid> {
            adapter.dispatch(malformedEmailReq)
        }
        assertTrue(malformedEmailEx.message!!.contains("Invalid email recipient format", ignoreCase = true))

        // Malformed SMS format
        val malformedSmsReq = createValidEmailRequest(
            idempotencyKey = "idem-bad-sms",
            channel = NotificationChannel.SMS,
            recipientDestination = "123456" // not E.164
        )
        val malformedSmsEx = assertThrows<NotificationDispatchException.Invalid> {
            adapter.dispatch(malformedSmsReq)
        }
        assertTrue(malformedSmsEx.message!!.contains("must be E.164", ignoreCase = true))

        // Wrong recipient (unregistered user in tenant)
        val unregisteredReq = createValidEmailRequest(
            idempotencyKey = "idem-unreg-user",
            recipientUserId = "user-unknown",
            recipientDestination = "user-unknown@slotting.com"
        )
        val unregEx = assertThrows<NotificationDispatchException.Forbidden> {
            adapter.dispatch(unregisteredReq)
        }
        assertTrue(unregEx.message!!.contains("Wrong recipient: user", ignoreCase = true))

        // Mismatched destination for valid user
        val mismatchedDestReq = createValidEmailRequest(
            idempotencyKey = "idem-mismatched-dest",
            recipientUserId = "user-01",
            recipientDestination = "user01-attacker@slotting.com"
        )
        val mismatchEx = assertThrows<NotificationDispatchException.Invalid> {
            adapter.dispatch(mismatchedDestReq)
        }
        assertTrue(mismatchEx.message!!.contains("Wrong recipient destination", ignoreCase = true))

        // Valid SMS user dispatch
        val validSmsReq = createValidEmailRequest(
            idempotencyKey = "idem-valid-sms",
            recipientUserId = "user-02",
            recipientDestination = "+15551234567",
            channel = NotificationChannel.SMS,
            templateId = "TEMPLATE_MFA_CHALLENGE",
            parameters = mapOf("code" to "987654")
        )
        val smsResult = adapter.dispatch(validSmsReq)
        assertEquals(NotificationChannel.SMS, smsResult.channel)
        assertEquals(NotificationDeliveryState.DELIVERED, smsResult.deliveryState)

        // Valid PUSH user dispatch
        val validPushReq = createValidEmailRequest(
            idempotencyKey = "idem-valid-push",
            recipientUserId = "user-03",
            recipientDestination = "push_token_alphanumeric_1234567890",
            channel = NotificationChannel.PUSH,
            templateId = "TEMPLATE_SECURITY_ALERT"
        )
        val pushResult = adapter.dispatch(validPushReq)
        assertEquals(NotificationChannel.PUSH, pushResult.channel)
        assertEquals(NotificationDeliveryState.DELIVERED, pushResult.deliveryState)
    }
}
