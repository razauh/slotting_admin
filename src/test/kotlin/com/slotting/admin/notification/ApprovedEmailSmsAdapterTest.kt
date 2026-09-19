package com.slotting.admin.notification

import com.slotting.admin.auth.AdminRole
import com.slotting.admin.auth.AuthenticatedPrincipal
import com.slotting.admin.auth.PrincipalKind
import org.junit.jupiter.api.Assertions.*
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.DisplayName
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.assertThrows
import java.nio.charset.StandardCharsets
import java.time.Clock
import java.time.Instant
import java.time.ZoneOffset
import java.util.Base64
import java.util.UUID
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit
import javax.crypto.Mac
import javax.crypto.spec.SecretKeySpec

class ApprovedEmailSmsAdapterTest {

    private val tenantId = "tenant-notify-01"
    private val clock = Clock.fixed(Instant.parse("2026-09-19T19:00:00Z"), ZoneOffset.UTC)
    private lateinit var service: ApprovedEmailSmsAdapterService

    private val validPrincipal = AuthenticatedPrincipal(
        id = "service-actor-01",
        tenantId = tenantId,
        roles = setOf(AdminRole.SUPPORT),
        kind = PrincipalKind.ADMIN,
    )

    private val otherTenantPrincipal = AuthenticatedPrincipal(
        id = "service-actor-other",
        tenantId = "tenant-other",
        roles = setOf(AdminRole.SUPPORT),
        kind = PrincipalKind.ADMIN,
    )

    @BeforeEach
    fun setup() {
        val emailAdapter = ApprovedEmailAdapter(clock = clock)
        val smsAdapter = ApprovedSmsAdapter(clock = clock)
        service = ApprovedEmailSmsAdapterService(emailAdapter = emailAdapter, smsAdapter = smsAdapter)
    }

    private fun createEmailRequest(
        idempotencyKey: String = "idem-email-001",
        recipientUserId: String = "user-01",
        recipientDestination: String = "user01@slotting.com",
        templateId: String = "TEMPLATE_SECURITY_ALERT",
        classification: NotificationClassification = NotificationClassification.TRANSACTIONAL,
        parameters: Map<String, String> = mapOf("event" to "password_reset", "device" to "Pixel 8"),
        principal: AuthenticatedPrincipal? = validPrincipal,
        tenant: String = tenantId,
        expectedVersion: Long = 1L,
    ) = NotificationDispatchRequest(
        principal = principal,
        tenantId = tenant,
        notificationId = UUID.randomUUID(),
        recipientUserId = recipientUserId,
        classification = classification,
        channel = NotificationChannel.EMAIL,
        templateId = templateId,
        templateParameters = parameters,
        recipientDestination = recipientDestination,
        idempotencyKey = idempotencyKey,
        correlationId = "corr-${UUID.randomUUID()}",
        causationId = "cause-${UUID.randomUUID()}",
        expectedVersion = expectedVersion,
    )

    private fun createSmsRequest(
        idempotencyKey: String = "idem-sms-001",
        recipientUserId: String = "user-02",
        recipientDestination: String = "+15551234567",
        templateId: String = "TEMPLATE_MFA_CHALLENGE",
        classification: NotificationClassification = NotificationClassification.TRANSACTIONAL,
        parameters: Map<String, String> = mapOf("code" to "123456"),
        principal: AuthenticatedPrincipal? = validPrincipal,
        tenant: String = tenantId,
        expectedVersion: Long = 1L,
    ) = NotificationDispatchRequest(
        principal = principal,
        tenantId = tenant,
        notificationId = UUID.randomUUID(),
        recipientUserId = recipientUserId,
        classification = classification,
        channel = NotificationChannel.SMS,
        templateId = templateId,
        templateParameters = parameters,
        recipientDestination = recipientDestination,
        idempotencyKey = idempotencyKey,
        correlationId = "corr-${UUID.randomUUID()}",
        causationId = "cause-${UUID.randomUUID()}",
        expectedVersion = expectedVersion,
    )

    @Test
    @DisplayName("NOTIFY-001-03-T001: Integrate approved email and SMS adapters produces the required authoritative outcome")
    fun testT001_AuthoritativeOutcome() {
        // 1. Email Dispatch
        val emailReq = createEmailRequest()
        val emailResult = service.dispatch(emailReq)

        assertNotNull(emailResult)
        assertEquals(tenantId, emailResult.tenantId)
        assertEquals("user-01", emailResult.recipientUserId)
        assertEquals(NotificationChannel.EMAIL, emailResult.channel)
        assertEquals(NotificationClassification.TRANSACTIONAL, emailResult.classification)
        assertEquals(NotificationDeliveryState.DELIVERED, emailResult.deliveryState)
        assertEquals("Transactional vs marketing classified; sensitive details behind authenticated app.", emailResult.semanticContract)
        assertFalse(emailResult.directEligibilityGranted, "Approved email adapter cannot grant eligibility")
        assertFalse(emailResult.financialMutationPermitted, "Approved email adapter cannot mutate money")
        assertTrue(emailResult.providerReference.startsWith("aws_ses:email:"))
        assertTrue(emailResult.evidenceReference.startsWith("notification:dispatch:email:"))

        val emailJournal = service.emailAdapter.getDispatchedJournal(tenantId)
        assertEquals(1, emailJournal.size)
        assertEquals(emailResult.dispatchId, emailJournal[0].dispatchId)

        val emailAudit = service.emailAdapter.getAuditLogs(tenantId)
        assertEquals(1, emailAudit.size)
        assertEquals("NOTIFICATION_EMAIL_DISPATCHED_APPROVED_ADAPTER", emailAudit[0].type)

        // 2. SMS Dispatch
        val smsReq = createSmsRequest()
        val smsResult = service.dispatch(smsReq)

        assertNotNull(smsResult)
        assertEquals(tenantId, smsResult.tenantId)
        assertEquals("user-02", smsResult.recipientUserId)
        assertEquals(NotificationChannel.SMS, smsResult.channel)
        assertEquals(NotificationClassification.TRANSACTIONAL, smsResult.classification)
        assertEquals(NotificationDeliveryState.DELIVERED, smsResult.deliveryState)
        assertEquals("Transactional vs marketing classified; sensitive details behind authenticated app.", smsResult.semanticContract)
        assertFalse(smsResult.directEligibilityGranted, "Approved SMS adapter cannot grant eligibility")
        assertFalse(smsResult.financialMutationPermitted, "Approved SMS adapter cannot mutate money")
        assertTrue(smsResult.providerReference.startsWith("twilio_sms:sms:"))
        assertTrue(smsResult.evidenceReference.startsWith("notification:dispatch:sms:"))

        val smsJournal = service.smsAdapter.getDispatchedJournal(tenantId)
        assertEquals(1, smsJournal.size)
        assertEquals(smsResult.dispatchId, smsJournal[0].dispatchId)

        val smsAudit = service.smsAdapter.getAuditLogs(tenantId)
        assertEquals(1, smsAudit.size)
        assertEquals("NOTIFICATION_SMS_DISPATCHED_APPROVED_ADAPTER", smsAudit[0].type)
    }

    @Test
    @DisplayName("NOTIFY-001-03-T002: Integrate approved email and SMS adapters rejects invalid, boundary, unauthorized, and stale input")
    fun testT002_RejectsInvalidBoundaryUnauthorizedStale() {
        // 1. Unauthenticated principal
        val unauthReq = createEmailRequest(principal = null)
        assertThrows<NotificationDispatchException.Unauthorized> {
            service.dispatch(unauthReq)
        }

        // 2. Cross-tenant principal
        val crossTenantReq = createEmailRequest(principal = otherTenantPrincipal, tenant = tenantId)
        val crossTenantEx = assertThrows<NotificationDispatchException.Forbidden> {
            service.dispatch(crossTenantReq)
        }
        assertTrue(crossTenantEx.message!!.contains("Cross-tenant access forbidden"))

        // 3. Stale / invalid expected version
        val staleReq = createEmailRequest(expectedVersion = 0L)
        assertThrows<NotificationDispatchException.Invalid> {
            service.dispatch(staleReq)
        }

        // 4. Insecure payload: password in parameters
        val pwReq = createEmailRequest(parameters = mapOf("password" to "secret123"))
        val pwEx = assertThrows<NotificationDispatchException.Invalid> {
            service.dispatch(pwReq)
        }
        assertTrue(pwEx.message!!.contains("Insecure payload"))

        // 5. Insecure payload: raw credit card PAN
        val panReq = createEmailRequest(parameters = mapOf("pan" to "4111222233334444"))
        val panEx = assertThrows<NotificationDispatchException.Invalid> {
            service.dispatch(panReq)
        }
        assertTrue(panEx.message!!.contains("raw card PAN"))

        // 6. Template injection attempt
        val injectionReq = createEmailRequest(parameters = mapOf("var" to "{{malicious_call()}}"))
        val injEx = assertThrows<NotificationDispatchException.Invalid> {
            service.dispatch(injectionReq)
        }
        assertTrue(injEx.message!!.contains("Template injection attempt"))

        // 7. Unapproved template
        val unapprovedReq = createEmailRequest(templateId = "UNKNOWN_PROMO")
        assertThrows<NotificationDispatchException.Invalid> {
            service.dispatch(unapprovedReq)
        }

        // 8. Classification mismatch
        val mismatchReq = createEmailRequest(
            templateId = "TEMPLATE_MARKETING_PROMO",
            classification = NotificationClassification.TRANSACTIONAL
        )
        assertThrows<NotificationDispatchException.Invalid> {
            service.dispatch(mismatchReq)
        }

        // 9. Malformed Email address
        val badEmailReq = createEmailRequest(recipientDestination = "invalid-email-address")
        assertThrows<NotificationDispatchException.Invalid> {
            service.dispatch(badEmailReq)
        }

        // 10. Malformed SMS phone number (not E.164)
        val badSmsReq = createSmsRequest(recipientDestination = "555-1234")
        assertThrows<NotificationDispatchException.Invalid> {
            service.dispatch(badSmsReq)
        }

        // 11. Wrong recipient user destination mismatch
        val wrongDestReq = createEmailRequest(recipientDestination = "wronguser@slotting.com")
        assertThrows<NotificationDispatchException.Invalid> {
            service.dispatch(wrongDestReq)
        }

        // 12. Unsupported channel (e.g. PUSH delegated to NOTIFY-001-04)
        val pushReq = createEmailRequest().copy(channel = NotificationChannel.PUSH)
        val pushEx = assertThrows<NotificationDispatchException.Invalid> {
            service.dispatch(pushReq)
        }
        assertTrue(pushEx.message!!.contains("Unsupported channel"))
    }

    @Test
    @DisplayName("NOTIFY-001-03-T003: Integrate approved email and SMS adapters survives concurrency, duplicate delivery, and dependency failure")
    fun testT003_ConcurrencyDuplicateFailureRecovery() {
        val request = createEmailRequest(idempotencyKey = "idem-email-concurrent")

        // Concurrency: Multiple threads executing identical request
        val threads = 6
        val executor = Executors.newFixedThreadPool(threads)
        val results = mutableListOf<NotificationDispatchResult>()

        for (i in 0 until threads) {
            executor.submit {
                val res = service.dispatch(request)
                synchronized(results) { results.add(res) }
            }
        }
        executor.shutdown()
        assertTrue(executor.awaitTermination(5, TimeUnit.SECONDS))

        // Exactly one unique dispatch created, subsequent replays return identical dispatchId
        assertEquals(threads, results.size)
        val firstDispatchId = results[0].dispatchId
        assertTrue(results.all { it.dispatchId == firstDispatchId })
        assertEquals(1, service.emailAdapter.getDispatchedJournal(tenantId).size)

        // Duplicate delivery with changed payload triggers conflict
        val conflictReq = request.copy(templateId = "TEMPLATE_MFA_CHALLENGE")
        assertThrows<NotificationDispatchException.Conflict> {
            service.dispatch(conflictReq)
        }

        // Disabled provider config fails closed with ProviderUnavailable
        val disabledEmailAdapter = ApprovedEmailAdapter(
            emailConfigs = mapOf(tenantId to EmailProviderConfig(tenantId = tenantId, isActive = false)),
            clock = clock
        )
        val disabledService = ApprovedEmailSmsAdapterService(emailAdapter = disabledEmailAdapter)
        val unavailableEx = assertThrows<NotificationDispatchException.ProviderUnavailable> {
            disabledService.dispatch(createEmailRequest(idempotencyKey = "idem-disabled"))
        }
        assertTrue(unavailableEx.isRetryable)
    }

    @Test
    @DisplayName("NOTIFY-001-03-T004: Integrate approved email and SMS adapters remains compatible, recoverable, observable, and lifecycle-safe")
    fun testT004_CompatibilityObservabilityLifecycleSafe() {
        // Verify provider tier is PRODUCTION_CERTIFIED
        assertEquals(NotificationAdapterTier.PRODUCTION_CERTIFIED, service.tier)
        assertEquals(NotificationAdapterTier.PRODUCTION_CERTIFIED, service.emailAdapter.tier)
        assertEquals(NotificationAdapterTier.PRODUCTION_CERTIFIED, service.smsAdapter.tier)

        // Webhook signature verification
        val payload = """{"event":"delivery","notification_id":"123","status":"DELIVERED"}"""
        val secret = "aws-ses-webhook-secret-key"
        val mac = Mac.getInstance("HmacSHA256")
        mac.init(SecretKeySpec(secret.toByteArray(StandardCharsets.UTF_8), "HmacSHA256"))
        val validSig = Base64.getEncoder().encodeToString(mac.doFinal(payload.toByteArray(StandardCharsets.UTF_8)))

        val isEmailSigValid = service.verifyProviderWebhookSignature(
            NotificationChannel.EMAIL,
            tenantId,
            payload,
            validSig
        )
        assertTrue(isEmailSigValid)

        val isFakeSigValid = service.verifyProviderWebhookSignature(
            NotificationChannel.EMAIL,
            tenantId,
            payload,
            "invalid-tampered-signature"
        )
        assertFalse(isFakeSigValid)

        // Non-financial authority remains immutable
        val emailReq = createEmailRequest(idempotencyKey = "idem-lifecycle-01")
        val result = service.dispatch(emailReq)
        assertFalse(result.directEligibilityGranted)
        assertFalse(result.financialMutationPermitted)
        assertEquals("Transactional vs marketing classified; sensitive details behind authenticated app.", result.semanticContract)
    }
}
