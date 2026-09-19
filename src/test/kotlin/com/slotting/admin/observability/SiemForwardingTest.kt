package com.slotting.admin.observability

import com.slotting.admin.auth.AdminRole
import com.slotting.admin.auth.AuthenticatedPrincipal
import com.slotting.admin.auth.PrincipalKind
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertNotNull
import org.junit.jupiter.api.Assertions.assertNull
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test
import java.time.Clock
import java.time.Instant
import java.time.ZoneOffset
import java.util.UUID

class SiemForwardingTest {

    private lateinit var clock: Clock
    private lateinit var service: SiemForwardingService

    private val adminPrincipal = AuthenticatedPrincipal(
        id = "admin-sec-01",
        tenantId = "tenant-01",
        roles = setOf(AdminRole.SUPER_ADMIN),
        kind = PrincipalKind.ADMIN,
    )

    private val supportPrincipal = AuthenticatedPrincipal(
        id = "support-01",
        tenantId = "tenant-01",
        roles = setOf(AdminRole.SUPPORT),
        kind = PrincipalKind.ADMIN,
    )

    @BeforeEach
    fun setUp() {
        clock = Clock.fixed(Instant.parse("2026-09-19T23:00:00Z"), ZoneOffset.UTC)
        service = SiemForwardingService(clock = clock, maxRetries = 3)
    }

    @Test
    fun testOBS_001_04_T001_AuthoritativeOutcomeAndContract() {
        val command = ForwardSiemEventCommand(
            principal = adminPrincipal,
            tenantId = "tenant-01",
            category = SiemEventCategory.AUTH_FAILURE,
            severity = SiemEventSeverity.HIGH,
            action = "LOGIN_FAILED",
            targetResource = "/api/v1/admin/auth/login",
            sourceIp = "192.168.1.50",
            userAgent = "Mozilla/5.0 (SecurityScanner)",
            rawPayload = mapOf(
                "attemptedUser" to "target@example.com",
                "password" to "SuperSecretP@ssword123",
                "apiKey" to "sk_live_1234567890",
            ),
            destination = SiemDeliveryTarget.ENTERPRISE_SIEM,
            correlationId = "corr-siem-001",
            causationId = "cause-siem-001",
            idempotencyKey = "idem-siem-001",
        )

        val result = service.forwardSecurityEvent(command)

        assertTrue(result.success)
        assertEquals(
            "Dashboards include duplicates, posting failures, imbalance, mismatch, failed callbacks, stuck withdrawals.",
            result.semanticContract
        )
        assertFalse(result.directEligibilityGranted)
        assertFalse(result.financialMutationPermitted)

        val event = result.event
        assertNotNull(event)
        assertEquals("tenant-01", event!!.tenantId)
        assertEquals(SiemEventCategory.AUTH_FAILURE, event.category)
        assertEquals(SiemEventSeverity.HIGH, event.severity)
        assertEquals("admin-sec-01", event.actorPrincipal)
        assertEquals("LOGIN_FAILED", event.action)
        assertEquals(SiemForwardStatus.FORWARDED, event.forwardStatus)
        assertEquals("ENTERPRISE_SIEM", event.destination)
        assertNotNull(event.siemReceiptId)
        assertTrue(event.evidenceReference.startsWith("siem:forward:"))
        assertFalse(event.directEligibilityGranted)
        assertFalse(event.financialMutationPermitted)

        // Verify sensitive data is redacted
        assertFalse(event.redactedPayload.contains("SuperSecretP@ssword123"))
        assertFalse(event.redactedPayload.contains("sk_live_1234567890"))
        assertTrue(event.redactedPayload.contains("[REDACTED_SECRET]"))
        assertTrue(event.redactedPayload.contains("[REDACTED_EMAIL]"))
    }

    @Test
    fun testOBS_001_04_T002_RejectInvalidBoundaryUnauthorizedStale() {
        // 1. Unauthenticated principal
        val unauthCmd = ForwardSiemEventCommand(
            principal = null,
            tenantId = "tenant-01",
            category = SiemEventCategory.RBAC_VIOLATION,
            action = "UNAUTHORIZED_RESOURCE_ACCESS",
            targetResource = "/api/v1/finance/ledger",
            sourceIp = "10.0.0.1",
            correlationId = "corr-unauth",
            causationId = "cause-unauth",
            idempotencyKey = "idem-unauth",
        )
        val unauthResult = service.forwardSecurityEvent(unauthCmd)
        assertFalse(unauthResult.success)
        assertEquals("UNAUTHENTICATED", unauthResult.reasonCode)
        assertNull(unauthResult.event)

        // 2. Blank tenant ID
        val blankTenantCmd = ForwardSiemEventCommand(
            principal = adminPrincipal,
            tenantId = "   ",
            category = SiemEventCategory.POLICY_DENIED,
            action = "WAF_BLOCKED",
            targetResource = "/api/v1/auth",
            sourceIp = "10.0.0.2",
            correlationId = "corr-blank-tenant",
            causationId = "cause-blank-tenant",
            idempotencyKey = "idem-blank-tenant",
        )
        val blankTenantResult = service.forwardSecurityEvent(blankTenantCmd)
        assertFalse(blankTenantResult.success)
        assertEquals("INVALID_TENANT", blankTenantResult.reasonCode)

        // 3. Invalid payload (blank action)
        val invalidPayloadCmd = ForwardSiemEventCommand(
            principal = adminPrincipal,
            tenantId = "tenant-01",
            category = SiemEventCategory.INTEGRITY_BREACH,
            action = "",
            targetResource = "/api/v1/config",
            sourceIp = "10.0.0.3",
            correlationId = "corr-invalid-payload",
            causationId = "cause-invalid-payload",
            idempotencyKey = "idem-invalid-payload",
        )
        val invalidPayloadResult = service.forwardSecurityEvent(invalidPayloadCmd)
        assertFalse(invalidPayloadResult.success)
        assertEquals("INVALID_PAYLOAD", invalidPayloadResult.reasonCode)

        // 4. Stale version and cross-tenant retry
        val seedCmd = ForwardSiemEventCommand(
            principal = adminPrincipal,
            tenantId = "tenant-01",
            category = SiemEventCategory.PRIVILEGE_ESCALATION,
            action = "ROLE_MODIFIED",
            targetResource = "/api/v1/admin/users",
            sourceIp = "10.0.0.4",
            correlationId = "corr-seed",
            causationId = "cause-seed",
            idempotencyKey = "idem-seed",
        )
        val seedResult = service.forwardSecurityEvent(seedCmd)
        assertTrue(seedResult.success)
        val seededEventId = seedResult.event!!.eventId

        // Cross-tenant retry rejection
        val crossTenantRetry = RetrySiemForwardCommand(
            principal = adminPrincipal,
            tenantId = "other-tenant",
            eventId = seededEventId,
            correlationId = "corr-cross",
            causationId = "cause-cross",
            idempotencyKey = "idem-cross",
        )
        val crossTenantResult = service.retrySiemForward(crossTenantRetry)
        assertFalse(crossTenantResult.success)
        assertEquals("FORBIDDEN_CROSS_TENANT", crossTenantResult.reasonCode)

        // Stale version retry rejection
        val staleRetry = RetrySiemForwardCommand(
            principal = adminPrincipal,
            tenantId = "tenant-01",
            eventId = seededEventId,
            correlationId = "corr-stale",
            causationId = "cause-stale",
            idempotencyKey = "idem-stale",
            expectedVersion = 999L,
        )
        val staleResult = service.retrySiemForward(staleRetry)
        assertFalse(staleResult.success)
        assertEquals("STALE_VERSION", staleResult.reasonCode)
    }

    @Test
    fun testOBS_001_04_T003_ConcurrencyDuplicateDeliveryAndDependencyFailure() {
        val baseCmd = ForwardSiemEventCommand(
            principal = adminPrincipal,
            tenantId = "tenant-01",
            category = SiemEventCategory.FRAUD_SUSPECT,
            severity = SiemEventSeverity.CRITICAL,
            action = "SUSPICIOUS_TRANSFER_PATTERN",
            targetResource = "/api/v1/transfers",
            sourceIp = "203.0.113.195",
            rawPayload = mapOf("riskScore" to 95, "user" to "player-441"),
            correlationId = "corr-fraud-01",
            causationId = "cause-fraud-01",
            idempotencyKey = "idem-fraud-dedup-01",
        )

        // 1. First execution
        val firstResult = service.forwardSecurityEvent(baseCmd)
        assertTrue(firstResult.success)
        val eventId = firstResult.event!!.eventId

        // 2. Replay with identical idempotency key and identical payload -> returns cached result
        val replayResult = service.forwardSecurityEvent(baseCmd)
        assertTrue(replayResult.success)
        assertEquals(eventId, replayResult.event!!.eventId)

        // 3. Replay with changed payload -> CONFLICT
        val conflictingCmd = baseCmd.copy(action = "DIFFERENT_ACTION_ON_SAME_KEY")
        val conflictResult = service.forwardSecurityEvent(conflictingCmd)
        assertFalse(conflictResult.success)
        assertEquals("CONFLICT_IDEMPOTENCY_KEY_REUSED", conflictResult.reasonCode)

        // 4. Bounded retry to QUARANTINED state
        // Max retries is 3. Retries 1, 2, 3 succeed; retry 4 exceeds bounds -> QUARANTINED.
        var currentVersion = 1L
        for (i in 1..3) {
            val retryCmd = RetrySiemForwardCommand(
                principal = adminPrincipal,
                tenantId = "tenant-01",
                eventId = eventId,
                correlationId = "corr-retry-$i",
                causationId = "cause-retry-$i",
                idempotencyKey = "idem-retry-$i",
                expectedVersion = currentVersion,
            )
            val retryResult = service.retrySiemForward(retryCmd)
            assertTrue(retryResult.success)
            assertEquals(SiemForwardStatus.FORWARDED, retryResult.event!!.forwardStatus)
            assertEquals(i, retryResult.event!!.retryCount)
            currentVersion = retryResult.event!!.version
        }

        // Retry 4: exceeds maxRetries (3) -> QUARANTINED
        val quarantineCmd = RetrySiemForwardCommand(
            principal = adminPrincipal,
            tenantId = "tenant-01",
            eventId = eventId,
            correlationId = "corr-retry-quarantine",
            causationId = "cause-retry-quarantine",
            idempotencyKey = "idem-retry-quarantine",
            expectedVersion = currentVersion,
        )
        val quarantineResult = service.retrySiemForward(quarantineCmd)
        assertFalse(quarantineResult.success)
        assertEquals("MAX_RETRIES_EXCEEDED", quarantineResult.reasonCode)
        assertEquals(SiemForwardStatus.QUARANTINED, quarantineResult.event!!.forwardStatus)
    }

    @Test
    fun testOBS_001_04_T004_CompatibilityRecoverableObservableAndLifecycleSafe() {
        val command = ForwardSiemEventCommand(
            principal = supportPrincipal,
            tenantId = "tenant-01",
            category = SiemEventCategory.SECRET_ACCESSED,
            severity = SiemEventSeverity.MEDIUM,
            action = "CONFIG_CREDENTIAL_READ",
            targetResource = "/api/v1/config/credentials",
            sourceIp = "10.10.10.10",
            rawPayload = mapOf(
                "operatorEmail" to "support_agent@operator.com",
                "ssn" to "123-45-6789",
                "creditCard" to "4111111111111111",
            ),
            correlationId = "corr-audit-check",
            causationId = "cause-audit-check",
            idempotencyKey = "idem-audit-check",
        )

        val result = service.forwardSecurityEvent(command)
        assertTrue(result.success)
        val eventId = result.event!!.eventId

        // Verify audit log presence
        val auditTrail = service.getAuditTrail(eventId)
        assertEquals(1, auditTrail.size)
        val audit = auditTrail[0]
        assertEquals(eventId, audit.eventId)
        assertEquals("tenant-01", audit.tenantId)
        assertEquals("SECURITY_EVENT_FORWARDED", audit.actionType)
        assertEquals(SiemForwardStatus.FORWARDED, audit.toStatus)
        assertEquals("support-01", audit.actorId)
        assertEquals("corr-audit-check", audit.correlationId)
        assertEquals("cause-audit-check", audit.causationId)

        // Verify evidence reference format
        assertEquals("siem:forward:$eventId", result.event!!.evidenceReference)

        // Verify PII redaction
        val payload = result.event!!.redactedPayload
        assertFalse(payload.contains("123-45-6789"))
        assertFalse(payload.contains("4111111111111111"))
        assertTrue(payload.contains("[REDACTED_SSN]"))
        assertTrue(payload.contains("[REDACTED_PAN]"))
        assertTrue(payload.contains("[REDACTED_EMAIL]"))

        // Re-read event directly
        val fetched = service.getEvent("tenant-01", eventId)
        assertNotNull(fetched)
        assertEquals(eventId, fetched!!.eventId)
        assertEquals(result.semanticContract, "Dashboards include duplicates, posting failures, imbalance, mismatch, failed callbacks, stuck withdrawals.")
        assertFalse(fetched.directEligibilityGranted)
        assertFalse(fetched.financialMutationPermitted)
    }
}
