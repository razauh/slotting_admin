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

class ApprovedPushAdapterTest {

    private val tenantId = "tenant-notify-01"
    private val clock = Clock.fixed(Instant.parse("2026-09-19T20:00:00Z"), ZoneOffset.UTC)
    private lateinit var adapter: ApprovedPushAdapterService

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
        adapter = ApprovedPushAdapterService(clock = clock)
    }

    private fun createPushRequest(
        idempotencyKey: String = "idem-push-001",
        recipientUserId: String = "user-01",
        recipientDestination: String = "fcm_token_device_user_01_alpha_numeric_12345",
        templateId: String = "TEMPLATE_SECURITY_ALERT",
        classification: NotificationClassification = NotificationClassification.TRANSACTIONAL,
        parameters: Map<String, String> = mapOf("device" to "Pixel 8"),
        principal: AuthenticatedPrincipal? = validPrincipal,
        tenant: String = tenantId,
        expectedVersion: Long = 1L,
    ) = NotificationDispatchRequest(
        principal = principal,
        tenantId = tenant,
        notificationId = UUID.randomUUID(),
        recipientUserId = recipientUserId,
        classification = classification,
        channel = NotificationChannel.PUSH,
        templateId = templateId,
        templateParameters = parameters,
        recipientDestination = recipientDestination,
        idempotencyKey = idempotencyKey,
        correlationId = "corr-${UUID.randomUUID()}",
        causationId = "cause-${UUID.randomUUID()}",
        expectedVersion = expectedVersion,
    )

    @Test
    @DisplayName("NOTIFY-001-04-T001: Integrate approved push adapter and templates produces the required authoritative outcome")
    fun testT001_AuthoritativeOutcome() {
        val request = createPushRequest()
        val result = adapter.dispatch(request)

        assertNotNull(result)
        assertEquals(tenantId, result.tenantId)
        assertEquals("user-01", result.recipientUserId)
        assertEquals(NotificationChannel.PUSH, result.channel)
        assertEquals(NotificationClassification.TRANSACTIONAL, result.classification)
        assertEquals(NotificationDeliveryState.DELIVERED, result.deliveryState)
        assertEquals("Transactional vs marketing classified; sensitive details behind authenticated app.", result.semanticContract)
        assertFalse(result.directEligibilityGranted, "Push adapter cannot grant eligibility")
        assertFalse(result.financialMutationPermitted, "Push adapter cannot mutate money")
        assertTrue(result.providerReference.startsWith("fcm:push:"))
        assertTrue(result.evidenceReference.startsWith("notification:dispatch:push:"))

        val journal = adapter.getDispatchedJournal(tenantId)
        assertEquals(1, journal.size)
        assertEquals(result.dispatchId, journal[0].dispatchId)

        val audit = adapter.getAuditLogs(tenantId)
        assertEquals(1, audit.size)
        assertEquals("NOTIFICATION_PUSH_DISPATCHED_APPROVED_ADAPTER", audit[0].type)
        assertEquals(result.dispatchId, audit[0].dispatchId)

        // Marketing push dispatch
        val marketingReq = createPushRequest(
            idempotencyKey = "idem-push-marketing",
            recipientUserId = "user-02",
            recipientDestination = "fcm_token_device_user_02_alpha_numeric_67890",
            templateId = "TEMPLATE_MARKETING_PROMO",
            classification = NotificationClassification.MARKETING,
            parameters = mapOf("promo_code" to "GOLD2026")
        )
        val marketingResult = adapter.dispatch(marketingReq)
        assertEquals(NotificationClassification.MARKETING, marketingResult.classification)
        assertEquals(NotificationDeliveryState.DELIVERED, marketingResult.deliveryState)
    }

    @Test
    @DisplayName("NOTIFY-001-04-T002: Integrate approved push adapter and templates rejects invalid, boundary, unauthorized, and stale input")
    fun testT002_RejectsInvalidBoundaryUnauthorizedStale() {
        // 1. Unauthenticated principal
        val unauthReq = createPushRequest(principal = null)
        assertThrows<NotificationDispatchException.Unauthorized> {
            adapter.dispatch(unauthReq)
        }

        // 2. Cross-tenant principal
        val crossTenantReq = createPushRequest(principal = otherTenantPrincipal, tenant = tenantId)
        val crossTenantEx = assertThrows<NotificationDispatchException.Forbidden> {
            adapter.dispatch(crossTenantReq)
        }
        assertTrue(crossTenantEx.message!!.contains("Cross-tenant access forbidden"))

        // 3. Stale / invalid version
        val staleReq = createPushRequest(expectedVersion = 0L)
        assertThrows<NotificationDispatchException.Invalid> {
            adapter.dispatch(staleReq)
        }

        // 4. Insecure payload: password
        val pwReq = createPushRequest(parameters = mapOf("password" to "cleartext123"))
        val pwEx = assertThrows<NotificationDispatchException.Invalid> {
            adapter.dispatch(pwReq)
        }
        assertTrue(pwEx.message!!.contains("Insecure payload"))

        // 5. Insecure payload: raw credit card PAN
        val panReq = createPushRequest(parameters = mapOf("card_pan" to "4111222233334444"))
        val panEx = assertThrows<NotificationDispatchException.Invalid> {
            adapter.dispatch(panReq)
        }
        assertTrue(panEx.message!!.contains("raw card PAN"))

        // 6. Template injection attempt
        val injectionReq = createPushRequest(parameters = mapOf("device" to "{{hackSystem()}}"))
        val injEx = assertThrows<NotificationDispatchException.Invalid> {
            adapter.dispatch(injectionReq)
        }
        assertTrue(injEx.message!!.contains("Template injection attempt"))

        // 7. Unapproved template
        val unapprovedReq = createPushRequest(templateId = "UNKNOWN_PUSH_TEMPLATE")
        assertThrows<NotificationDispatchException.Invalid> {
            adapter.dispatch(unapprovedReq)
        }

        // 8. Classification mismatch
        val mismatchReq = createPushRequest(
            templateId = "TEMPLATE_MARKETING_PROMO",
            classification = NotificationClassification.TRANSACTIONAL
        )
        assertThrows<NotificationDispatchException.Invalid> {
            adapter.dispatch(mismatchReq)
        }

        // 9. Malformed push token
        val malformedTokenReq = createPushRequest(recipientDestination = "short_token")
        assertThrows<NotificationDispatchException.Invalid> {
            adapter.dispatch(malformedTokenReq)
        }

        // 10. Wrong recipient / token mismatch
        val wrongTokenReq = createPushRequest(recipientDestination = "fcm_token_device_user_02_alpha_numeric_67890")
        assertThrows<NotificationDispatchException.Invalid> {
            adapter.dispatch(wrongTokenReq)
        }

        // 11. Wrong channel (e.g. EMAIL sent to push adapter)
        val wrongChannelReq = createPushRequest().copy(channel = NotificationChannel.EMAIL)
        assertThrows<NotificationDispatchException.Invalid> {
            adapter.dispatch(wrongChannelReq)
        }
    }

    @Test
    @DisplayName("NOTIFY-001-04-T003: Integrate approved push adapter and templates survives concurrency, duplicate delivery, and dependency failure")
    fun testT003_ConcurrencyDuplicateFailureRecovery() {
        val request = createPushRequest(idempotencyKey = "idem-push-concurrent")

        val threads = 6
        val executor = Executors.newFixedThreadPool(threads)
        val results = mutableListOf<NotificationDispatchResult>()

        for (i in 0 until threads) {
            executor.submit {
                val res = adapter.dispatch(request)
                synchronized(results) { results.add(res) }
            }
        }
        executor.shutdown()
        assertTrue(executor.awaitTermination(5, TimeUnit.SECONDS))

        // Replay returns identical result
        assertEquals(threads, results.size)
        val firstDispatchId = results[0].dispatchId
        assertTrue(results.all { it.dispatchId == firstDispatchId })
        assertEquals(1, adapter.getDispatchedJournal(tenantId).size)

        // Duplicate with mutated payload conflicts
        val conflictReq = request.copy(templateId = "TEMPLATE_LOGIN_APPROVAL")
        assertThrows<NotificationDispatchException.Conflict> {
            adapter.dispatch(conflictReq)
        }

        // Disabled provider config fails closed
        val disabledAdapter = ApprovedPushAdapterService(
            pushConfigs = mapOf(tenantId to PushProviderConfig(tenantId = tenantId, isActive = false)),
            clock = clock
        )
        val unavailableEx = assertThrows<NotificationDispatchException.ProviderUnavailable> {
            disabledAdapter.dispatch(createPushRequest(idempotencyKey = "idem-push-disabled"))
        }
        assertTrue(unavailableEx.isRetryable)
    }

    @Test
    @DisplayName("NOTIFY-001-04-T004: Integrate approved push adapter and templates remains compatible, recoverable, observable, and lifecycle-safe")
    fun testT004_CompatibilityObservabilityLifecycleSafe() {
        assertEquals(NotificationAdapterTier.PRODUCTION_CERTIFIED, adapter.tier)

        // Webhook signature verification
        val payload = """{"message_id":"fcm-123","status":"DELIVERED","timestamp":1700000000}"""
        val secret = "fcm-webhook-signing-secret"
        val mac = Mac.getInstance("HmacSHA256")
        mac.init(SecretKeySpec(secret.toByteArray(StandardCharsets.UTF_8), "HmacSHA256"))
        val validSig = Base64.getEncoder().encodeToString(mac.doFinal(payload.toByteArray(StandardCharsets.UTF_8)))

        val isSigValid = adapter.verifyPushWebhookSignature(tenantId, payload, validSig)
        assertTrue(isSigValid)

        val isTamperedSigValid = adapter.verifyPushWebhookSignature(tenantId, payload, "tampered-sig")
        assertFalse(isTamperedSigValid)

        // Safe template rendering verification
        val tmpl = ApprovedPushAdapterService.DEFAULT_APPROVED_PUSH_TEMPLATES["TEMPLATE_SECURITY_ALERT"]!!
        val rendered = adapter.renderPushMessage(tmpl, mapOf("device" to "Pixel 8 Pro"))
        assertEquals("Security Alert", rendered.title)
        assertEquals("Security event detected on Pixel 8 Pro", rendered.body)
        assertEquals(PushPriority.HIGH, rendered.priority)
        assertEquals("sec_alert", rendered.collapseKey)

        // Invariant: Non-financial authority remains immutable
        val result = adapter.dispatch(createPushRequest(idempotencyKey = "idem-lifecycle-push"))
        assertFalse(result.directEligibilityGranted)
        assertFalse(result.financialMutationPermitted)
        assertEquals("Transactional vs marketing classified; sensitive details behind authenticated app.", result.semanticContract)
    }
}
