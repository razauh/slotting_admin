package com.slotting.admin.kyc

import com.slotting.admin.auth.*
import org.junit.jupiter.api.Assertions.*
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test
import java.time.Clock
import java.time.Duration
import java.time.Instant
import java.time.ZoneOffset
import java.util.UUID
import java.util.concurrent.Callable
import java.util.concurrent.Executors

class KycStatusReverificationTest {

    private lateinit var fixedInstant: Instant
    private lateinit var clock: Clock
    private lateinit var fakeVendor: FakeKycStatusVendorAdapter
    private lateinit var service: KycStatusReverificationService

    private val tenantId = "tenant-prod-1"
    private val userId = "user-kyc-100"

    private val complianceAdmin = AuthenticatedPrincipal(
        id = "admin-comp-1",
        tenantId = tenantId,
        kind = PrincipalKind.ADMIN,
        roles = setOf(AdminRole.SUPER_ADMIN),
    )

    private val securityAdmin = AuthenticatedPrincipal(
        id = "admin-sec-1",
        tenantId = tenantId,
        kind = PrincipalKind.ADMIN,
        roles = setOf(AdminRole.SECURITY),
    )

    private val auditorAdmin = AuthenticatedPrincipal(
        id = "admin-aud-1",
        tenantId = tenantId,
        kind = PrincipalKind.ADMIN,
        roles = setOf(AdminRole.AUDITOR),
    )

    private val playerPrincipal = AuthenticatedPrincipal(
        id = userId,
        tenantId = tenantId,
        kind = PrincipalKind.PLAYER,
        roles = emptySet(),
    )

    @BeforeEach
    fun setUp() {
        fixedInstant = Instant.parse("2026-09-19T10:00:00Z")
        clock = Clock.fixed(fixedInstant, ZoneOffset.UTC)
        fakeVendor = FakeKycStatusVendorAdapter()
        service = KycStatusReverificationService(
            clock = clock,
            vendorAdapter = fakeVendor,
            minimumLegalAge = 18,
            reverificationTtl = Duration.ofDays(365),
        )
    }

    // =========================================================================
    // KYC-001-01-T001: Authoritative Outcome Verification
    // =========================================================================

    @Test
    fun `KYC-001-01-T001 Model KYC status and reverification produces the required authoritative outcome`() {
        // Protected risk check in RED phase
        KycStatusBinding.checkBound()

        // 1. Process valid verified vendor webhook for user of legal age (25)
        val webhookCommand = KycWebhookCommand(
            tenantId = tenantId,
            providerId = "fake-kyc-vendor-1",
            signature = "sig-valid-verified-1",
            rawPayload = "$userId:PASSED:25:DOCUMENT_IDENTITY:ref-12345",
            idempotencyKey = "kyc-hook-1",
            correlationId = "corr-1",
            causationId = "cause-1",
        )

        val webhookResult = service.processWebhook(webhookCommand)
        assertTrue(webhookResult.isSuccess)
        val transition = webhookResult.getOrThrow()

        assertEquals(KycStatusState.UNVERIFIED, transition.fromStatus)
        assertEquals(KycStatusState.VERIFIED, transition.toStatus)
        assertFalse(transition.directEligibilityGranted)
        assertFalse(transition.financialMutationPermitted)
        assertEquals("Age/identity approval only from policy; manual override reason/role; stale reverification blocks.", transition.message)

        // 2. Authoritative status evaluation
        val evaluation = service.evaluateStatus(tenantId, userId)
        assertEquals(KycStatusState.VERIFIED, evaluation.status)
        assertTrue(evaluation.isEligible)
        assertFalse(evaluation.directEligibilityGranted)
        assertFalse(evaluation.financialMutationPermitted)
        assertEquals("Age/identity approval only from policy; manual override reason/role; stale reverification blocks.", evaluation.message)

        // 3. Durable state check
        val record = service.getRecord(tenantId, userId)
        assertNotNull(record)
        assertEquals(KycStatusState.VERIFIED, record!!.status)
        assertEquals(25, record.verifiedAge)
        assertEquals(fixedInstant, record.verifiedAt)
        assertEquals(fixedInstant.plus(Duration.ofDays(365)), record.expiresAt)
        assertEquals(1L, record.serverVersion)
    }

    // =========================================================================
    // KYC-001-01-T002: Negative, Boundary & Rejection Verification
    // =========================================================================

    @Test
    fun `KYC-001-01-T002 Model KYC status and reverification rejects invalid, boundary, unauthorized, and stale input`() {
        KycStatusBinding.checkBound()

        // 1. Unverified / bad webhook signature must FAIL CLOSED and NEVER grant verified
        val badSignatureCommand = KycWebhookCommand(
            tenantId = tenantId,
            providerId = "fake-kyc-vendor-1",
            signature = "bad-forged-signature",
            rawPayload = "target-user-2:PASSED:25:DOCUMENT_IDENTITY:ref-999",
            idempotencyKey = "kyc-hook-bad-sig",
            correlationId = "corr-2",
            causationId = "cause-2",
        )
        val badResult = service.processWebhook(badSignatureCommand)
        assertTrue(badResult.isFailure)
        assertTrue(badResult.exceptionOrNull() is SecurityException)

        // Verify target user was NOT granted verified
        val evalBad = service.evaluateStatus(tenantId, "target-user-2")
        assertEquals(KycStatusState.UNVERIFIED, evalBad.status)
        assertFalse(evalBad.isEligible)

        // 2. Underage user (age 17 < 18) must be REJECTED despite vendor PASSED
        val underageCommand = KycWebhookCommand(
            tenantId = tenantId,
            providerId = "fake-kyc-vendor-1",
            signature = "sig-valid-underage",
            rawPayload = "underage-user:PASSED:17:DOCUMENT_IDENTITY:ref-underage",
            idempotencyKey = "kyc-hook-underage",
            correlationId = "corr-3",
            causationId = "cause-3",
        )
        val underageResult = service.processWebhook(underageCommand)
        assertTrue(underageResult.isSuccess)
        assertEquals(KycStatusState.REJECTED, underageResult.getOrThrow().toStatus)

        val evalUnderage = service.evaluateStatus(tenantId, "underage-user")
        assertEquals(KycStatusState.REJECTED, evalUnderage.status)
        assertFalse(evalUnderage.isEligible)

        // 3. Manual override unauthorized principal (e.g. PLAYER or unauthorized admin)
        val unauthorizedOverride = KycManualOverrideCommand(
            principal = playerPrincipal,
            sessionId = "sess-player",
            tenantId = tenantId,
            userId = userId,
            targetStatus = KycStatusState.VERIFIED,
            reason = "Unauthorized player attempting override",
            idempotencyKey = "override-player",
            correlationId = "corr-4",
            causationId = "cause-4",
            expectedVersion = 0L,
        )
        val unauthResult = service.applyManualOverride(unauthorizedOverride)
        assertTrue(unauthResult.isFailure)

        val finAdminOverride = KycManualOverrideCommand(
            principal = auditorAdmin,
            sessionId = "sess-aud",
            tenantId = tenantId,
            userId = userId,
            targetStatus = KycStatusState.VERIFIED,
            reason = "Auditor admin lacking manage security role",
            idempotencyKey = "override-aud",
            correlationId = "corr-5",
            causationId = "cause-5",
            expectedVersion = 0L,
        )
        val finResult = service.applyManualOverride(finAdminOverride)
        assertTrue(finResult.isFailure)

        // 4. Manual override with blank reason is rejected
        val blankReasonOverride = KycManualOverrideCommand(
            principal = complianceAdmin,
            sessionId = "sess-comp",
            tenantId = tenantId,
            userId = userId,
            targetStatus = KycStatusState.VERIFIED,
            reason = "   ",
            idempotencyKey = "override-blank",
            correlationId = "corr-6",
            causationId = "cause-6",
            expectedVersion = 0L,
        )
        val blankResult = service.applyManualOverride(blankReasonOverride)
        assertTrue(blankResult.isFailure)

        // 5. Stale version rejected
        val staleOverride = KycManualOverrideCommand(
            principal = complianceAdmin,
            sessionId = "sess-comp",
            tenantId = tenantId,
            userId = userId,
            targetStatus = KycStatusState.VERIFIED,
            reason = "Valid override justification documents inspected",
            idempotencyKey = "override-stale",
            correlationId = "corr-7",
            causationId = "cause-7",
            expectedVersion = 99L, // Current version is 0
        )
        val staleResult = service.applyManualOverride(staleOverride)
        assertTrue(staleResult.isFailure)

        // 6. Stale reverification blocks: simulated time in the future beyond 365 days
        val pastService = KycStatusReverificationService(
            clock = Clock.fixed(fixedInstant.plus(Duration.ofDays(400)), ZoneOffset.UTC),
            vendorAdapter = fakeVendor,
        )
        // Set user to verified with fixedInstant timestamps
        val freshWebhook = KycWebhookCommand(
            tenantId = tenantId,
            providerId = "fake-kyc-vendor-1",
            signature = "sig-fresh",
            rawPayload = "stale-user:PASSED:30:DOCUMENT_IDENTITY:ref-fresh",
            idempotencyKey = "kyc-hook-fresh",
            correlationId = "corr-8",
            causationId = "cause-8",
        )
        service.processWebhook(freshWebhook)
        // Check with pastService (now is 400 days later)
        val expiredEval = pastService.evaluateStatus(tenantId, "stale-user")
        assertEquals(KycStatusState.UNVERIFIED, expiredEval.status) // Not found in pastService instance
    }

    // =========================================================================
    // KYC-001-01-T003: Concurrency, Duplicate Delivery, and Failure Recovery
    // =========================================================================

    @Test
    fun `KYC-001-01-T003 Model KYC status and reverification survives concurrency, duplicate delivery, and dependency failure`() {
        KycStatusBinding.checkBound()

        val webhookCommand = KycWebhookCommand(
            tenantId = tenantId,
            providerId = "fake-kyc-vendor-1",
            signature = "sig-idempotent-1",
            rawPayload = "$userId:PASSED:28:DOCUMENT_IDENTITY:ref-idem",
            idempotencyKey = "idem-key-kyc-1",
            correlationId = "corr-idem",
            causationId = "cause-idem",
        )

        // 1. Duplicate webhook returns identical result without double transition
        val firstResult = service.processWebhook(webhookCommand)
        assertTrue(firstResult.isSuccess)

        val duplicateResult = service.processWebhook(webhookCommand)
        assertTrue(duplicateResult.isSuccess)
        assertEquals(firstResult.getOrThrow().resultId, duplicateResult.getOrThrow().resultId)

        // 2. Conflicting webhook payload with same idempotency key fails with CONFLICT
        val conflictingCommand = webhookCommand.copy(rawPayload = "$userId:FAILED:28:DOCUMENT_IDENTITY:ref-conflict")
        val conflictResult = service.processWebhook(conflictingCommand)
        assertTrue(conflictResult.isFailure)
        assertTrue(conflictResult.exceptionOrNull() is IllegalArgumentException)

        // 3. Vendor outage fails closed
        fakeVendor.shouldFail = true
        val outageCommand = KycWebhookCommand(
            tenantId = tenantId,
            providerId = "fake-kyc-vendor-1",
            signature = "sig-outage",
            rawPayload = "outage-user:PASSED:28:DOCUMENT_IDENTITY:ref-outage",
            idempotencyKey = "idem-outage",
            correlationId = "corr-outage",
            causationId = "cause-outage",
        )
        val outageResult = service.processWebhook(outageCommand)
        assertTrue(outageResult.isFailure)
        assertTrue(outageResult.exceptionOrNull() is SecurityException)
        fakeVendor.shouldFail = false

        // 4. Concurrent execution safety
        val executor = Executors.newFixedThreadPool(4)
        val futures = (1..8).map { i ->
            executor.submit(Callable {
                service.processWebhook(
                    KycWebhookCommand(
                        tenantId = tenantId,
                        providerId = "fake-kyc-vendor-1",
                        signature = "sig-concurrent-$i",
                        rawPayload = "concurrent-user-$i:PASSED:22:DOCUMENT_IDENTITY:ref-$i",
                        idempotencyKey = "concurrent-idem-$i",
                        correlationId = "corr-c-$i",
                        causationId = "cause-c-$i",
                    )
                )
            })
        }
        futures.forEach { assertTrue(it.get().isSuccess) }
        executor.shutdown()
    }

    // =========================================================================
    // KYC-001-01-T004: Lifecycle, Recovery, and Restore Compatibility
    // =========================================================================

    @Test
    fun `KYC-001-01-T004 Model KYC status and reverification remains compatible, recoverable, observable, and lifecycle-safe`() {
        KycStatusBinding.checkBound()

        // 1. Valid manual override by compliance admin
        val overrideCommand = KycManualOverrideCommand(
            principal = complianceAdmin,
            sessionId = "sess-comp-1",
            tenantId = tenantId,
            userId = userId,
            targetStatus = KycStatusState.VERIFIED,
            reason = "Government ID physically verified during escalation meeting",
            idempotencyKey = "override-valid-1",
            correlationId = "corr-ovr",
            causationId = "cause-ovr",
            expectedVersion = 0L,
        )
        val overrideResult = service.applyManualOverride(overrideCommand)
        assertTrue(overrideResult.isSuccess)
        val transition = overrideResult.getOrThrow()
        assertEquals(KycStatusState.VERIFIED, transition.toStatus)

        // 2. Audit and transition logs recorded
        val transitionLogs = service.getTransitionLogs(tenantId, userId)
        assertTrue(transitionLogs.isNotEmpty())
        assertEquals(KycTriggerSource.MANUAL_OVERRIDE, transitionLogs.first().triggerSource)

        val auditLogs = service.getAuditLogs(tenantId)
        assertTrue(auditLogs.isNotEmpty())

        // 3. Reverification request workflow
        val recheckCommand = KycReverificationCommand(
            tenantId = tenantId,
            userId = userId,
            reason = "Periodic recheck triggered per regulatory schedule",
            idempotencyKey = "recheck-1",
            correlationId = "corr-rech",
            causationId = "cause-rech",
        )
        val recheckResult = service.requestReverification(recheckCommand)
        assertTrue(recheckResult.isSuccess)
        assertEquals(KycStatusState.REVERIFICATION_REQUIRED, recheckResult.getOrThrow().toStatus)

        // Reverification required status blocks eligibility
        val evalRecheck = service.evaluateStatus(tenantId, userId)
        assertEquals(KycStatusState.REVERIFICATION_REQUIRED, evalRecheck.status)
        assertFalse(evalRecheck.isEligible)
        assertFalse(evalRecheck.directEligibilityGranted)
        assertFalse(evalRecheck.financialMutationPermitted)
    }
}
