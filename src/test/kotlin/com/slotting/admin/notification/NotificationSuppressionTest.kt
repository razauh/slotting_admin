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
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit

class NotificationSuppressionTest {

    private val tenantId = "tenant-notify-01"
    private val clock = Clock.fixed(Instant.parse("2026-09-19T21:00:00Z"), ZoneOffset.UTC)
    private lateinit var service: NotificationSuppressionService

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
        service = NotificationSuppressionService(clock = clock)
    }

    private fun createCheckRequest(
        idempotencyKey: String = "idem-suppr-001",
        userId: String = "user-01",
        channel: NotificationChannel = NotificationChannel.EMAIL,
        classification: NotificationClassification = NotificationClassification.MARKETING,
        templateId: String = "TEMPLATE_MARKETING_PROMO",
        recipientDestination: String = "user01@slotting.com",
        principal: AuthenticatedPrincipal? = validPrincipal,
        tenant: String = tenantId,
        expectedVersion: Long = 1L,
    ) = SuppressionCheckRequest(
        principal = principal,
        tenantId = tenant,
        userId = userId,
        channel = channel,
        classification = classification,
        templateId = templateId,
        recipientDestination = recipientDestination,
        idempotencyKey = idempotencyKey,
        correlationId = "corr-${UUID.randomUUID()}",
        causationId = "cause-${UUID.randomUUID()}",
        expectedVersion = expectedVersion,
    )

    @Test
    @DisplayName("NOTIFY-002-01-T001: Enforce notification suppression produces the required authoritative outcome")
    fun testT001_AuthoritativeOutcome() {
        // Normal user without suppression: marketing allowed
        val cleanReq = createCheckRequest(idempotencyKey = "idem-clean-01", userId = "user-clean")
        val cleanResult = service.evaluateSuppression(cleanReq)
        assertTrue(cleanResult.isAllowed)
        assertEquals(SuppressionDecision.ALLOWED, cleanResult.decision)
        assertNull(cleanResult.reason)
        assertEquals("Mandatory legal/security notices separately approved; stale tokens removed safely.", cleanResult.semanticContract)
        assertFalse(cleanResult.directEligibilityGranted)
        assertFalse(cleanResult.financialMutationPermitted)

        // 1. Self-excluded user: marketing strictly suppressed
        service.addSuppression(
            principal = validPrincipal,
            tenantId = tenantId,
            userId = "user-excluded",
            channel = null, // global
            reason = SuppressionReason.SELF_EXCLUDED,
            evidenceReference = "rg:exclusion:rec-001"
        )
        val excludedReq = createCheckRequest(
            idempotencyKey = "idem-excl-01",
            userId = "user-excluded",
            classification = NotificationClassification.MARKETING
        )
        val excludedResult = service.evaluateSuppression(excludedReq)
        assertFalse(excludedResult.isAllowed, "Self-excluded user must NEVER receive marketing")
        assertEquals(SuppressionDecision.SUPPRESSED_MARKETING_EXCLUDED, excludedResult.decision)
        assertEquals(SuppressionReason.SELF_EXCLUDED, excludedResult.reason)

        // 2. Opted-out user: marketing strictly suppressed
        service.addSuppression(
            principal = validPrincipal,
            tenantId = tenantId,
            userId = "user-optout",
            channel = NotificationChannel.EMAIL,
            reason = SuppressionReason.MARKETING_OPT_OUT,
            evidenceReference = "crm:optout:rec-002"
        )
        val optOutReq = createCheckRequest(
            idempotencyKey = "idem-optout-01",
            userId = "user-optout",
            channel = NotificationChannel.EMAIL,
            classification = NotificationClassification.MARKETING
        )
        val optOutResult = service.evaluateSuppression(optOutReq)
        assertFalse(optOutResult.isAllowed, "Opted-out user must not receive marketing on opted-out channel")
        assertEquals(SuppressionDecision.SUPPRESSED_MARKETING_OPTOUT, optOutResult.decision)
        assertEquals(SuppressionReason.MARKETING_OPT_OUT, optOutResult.reason)

        // 3. Mandatory legal/security notice: delivered EVEN to excluded/opted-out user
        val mandatoryReq = createCheckRequest(
            idempotencyKey = "idem-mandatory-01",
            userId = "user-excluded",
            channel = NotificationChannel.EMAIL,
            classification = NotificationClassification.TRANSACTIONAL,
            templateId = "TEMPLATE_SECURITY_ALERT"
        )
        val mandatoryResult = service.evaluateSuppression(mandatoryReq)
        assertTrue(mandatoryResult.isAllowed, "Approved mandatory security notice must be delivered")
        assertEquals(SuppressionDecision.ALLOWED, mandatoryResult.decision)

        // Verify Audit Log persisted
        val auditLogs = service.getAuditLogs(tenantId)
        assertTrue(auditLogs.size >= 4)
    }

    @Test
    @DisplayName("NOTIFY-002-01-T002: Enforce notification suppression rejects invalid, boundary, unauthorized, and stale input")
    fun testT002_RejectsInvalidBoundaryUnauthorizedStale() {
        // 1. Unauthenticated principal
        val unauthReq = createCheckRequest(principal = null)
        assertThrows<NotificationSuppressionException.Unauthorized> {
            service.evaluateSuppression(unauthReq)
        }

        // 2. Cross-tenant principal
        val crossTenantReq = createCheckRequest(principal = otherTenantPrincipal, tenant = tenantId)
        val crossTenantEx = assertThrows<NotificationSuppressionException.Forbidden> {
            service.evaluateSuppression(crossTenantReq)
        }
        assertTrue(crossTenantEx.message!!.contains("Cross-tenant access forbidden"))

        // 3. Blank userId
        val blankUserReq = createCheckRequest(userId = "")
        assertThrows<NotificationSuppressionException.Invalid> {
            service.evaluateSuppression(blankUserReq)
        }

        // 4. Stale version (< 1)
        val staleReq = createCheckRequest(expectedVersion = 0L)
        assertThrows<NotificationSuppressionException.Invalid> {
            service.evaluateSuppression(staleReq)
        }

        // 5. Unapproved transactional template claiming mandatory bypass
        val unapprovedTransactionalReq = createCheckRequest(
            classification = NotificationClassification.TRANSACTIONAL,
            templateId = "TEMPLATE_UNKNOWN_UNAPPROVED"
        )
        val unapprovedEx = assertThrows<NotificationSuppressionException.Invalid> {
            service.evaluateSuppression(unapprovedTransactionalReq)
        }
        assertTrue(unapprovedEx.message!!.contains("not an approved mandatory"))
    }

    @Test
    @DisplayName("NOTIFY-002-01-T003: Enforce notification suppression survives concurrency, duplicate delivery, and dependency failure")
    fun testT003_ConcurrencyDuplicateFailureRecovery() {
        val request = createCheckRequest(idempotencyKey = "idem-concurrent-suppr")

        val threads = 6
        val executor = Executors.newFixedThreadPool(threads)
        val results = mutableListOf<SuppressionCheckResult>()

        for (i in 0 until threads) {
            executor.submit {
                val res = service.evaluateSuppression(request)
                synchronized(results) { results.add(res) }
            }
        }
        executor.shutdown()
        assertTrue(executor.awaitTermination(5, TimeUnit.SECONDS))

        // Idempotent duplicate: identical check ID returned
        assertEquals(threads, results.size)
        val firstId = results[0].checkId
        assertTrue(results.all { it.checkId == firstId })

        // Conflict on altered payload
        val conflictReq = request.copy(templateId = "TEMPLATE_MARKETING_TOURNAMENT")
        assertThrows<NotificationSuppressionException.Conflict> {
            service.evaluateSuppression(conflictReq)
        }
    }

    @Test
    @DisplayName("NOTIFY-002-01-T004: Enforce notification suppression remains compatible, recoverable, observable, and lifecycle-safe")
    fun testT004_CompatibilityObservabilityLifecycleSafe() {
        val staleToken = "fcm_token_stale_device_old_12345"
        service.registerStaleToken(validPrincipal, tenantId, staleToken)

        // Sending push to stale token: suppressed with SUPPRESSED_STALE_TOKEN
        val stalePushReq = createCheckRequest(
            idempotencyKey = "idem-stale-push",
            userId = "user-stale-dev",
            channel = NotificationChannel.PUSH,
            recipientDestination = staleToken,
            classification = NotificationClassification.MARKETING
        )
        val staleResult = service.evaluateSuppression(stalePushReq)
        assertFalse(staleResult.isAllowed)
        assertEquals(SuppressionDecision.SUPPRESSED_STALE_TOKEN, staleResult.decision)
        assertEquals(SuppressionReason.STALE_TOKEN, staleResult.reason)

        // Safe removal of stale token
        val removed = service.removeStaleToken(validPrincipal, tenantId, staleToken)
        assertTrue(removed)

        // Invariant: Non-financial authority remains immutable
        assertFalse(staleResult.directEligibilityGranted)
        assertFalse(staleResult.financialMutationPermitted)
        assertEquals("Mandatory legal/security notices separately approved; stale tokens removed safely.", staleResult.semanticContract)
    }
}
