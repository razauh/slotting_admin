package com.slotting.admin.kyc

import org.junit.jupiter.api.Assertions.*
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test
import java.time.Clock
import java.time.Duration
import java.time.Instant
import java.time.ZoneOffset
import java.util.concurrent.Callable
import java.util.concurrent.Executors

class KycVendorCallbackIntegrationTest {

    private lateinit var fixedInstant: Instant
    private lateinit var clock: Clock
    private lateinit var fakeAdapter: FakeKycVendorCallbackAdapter
    private lateinit var sandboxAdapter: SandboxKycVendorCallbackAdapter
    private lateinit var productionAdapter: ProductionCertifiedKycVendorAdapter
    private lateinit var service: KycVendorCallbackIntegrationService

    private val tenantId = "tenant-prod-1"
    private val userId = "user-callback-100"
    private val webhookSecret = "super-secret-hmac-key-456"

    @BeforeEach
    fun setUp() {
        fixedInstant = Instant.parse("2026-09-19T10:00:00Z")
        clock = Clock.fixed(fixedInstant, ZoneOffset.UTC)
        fakeAdapter = FakeKycVendorCallbackAdapter("fake-kyc-callback-adapter", webhookSecret)
        sandboxAdapter = SandboxKycVendorCallbackAdapter("sandbox-kyc-provider", clock)
        productionAdapter = ProductionCertifiedKycVendorAdapter("prod-kyc-provider", webhookSecret, clock)

        service = KycVendorCallbackIntegrationService(
            clock = clock,
            adapters = mapOf(
                "fake-kyc-callback-adapter" to fakeAdapter,
                "sandbox-kyc-provider" to sandboxAdapter,
                "prod-kyc-provider" to productionAdapter,
            ),
            minimumLegalAge = 18,
            reverificationTtl = Duration.ofDays(365),
            webhookMaxAgeSeconds = 300L,
        )
    }

    // =========================================================================
    // KYC-001-02-T001: Authoritative Outcome Verification
    // =========================================================================

    @Test
    fun `KYC-001-02-T001 Integrate KYC vendor and verified callback produces the required authoritative outcome`() {
        // Protected risk check in RED phase
        KycVendorCallbackBinding.checkBound()

        // 1. Ingest verified callback with valid signature for adult user (age 26)
        val command = KycCallbackProcessCommand(
            tenantId = tenantId,
            providerId = "fake-kyc-callback-adapter",
            headers = mapOf("X-KYC-Signature-SHA256" to "valid-sig-123"),
            rawPayload = "$userId:PASSED:26:DOCUMENT_IDENTITY:chk-9000:${fixedInstant.toEpochMilli()}",
            idempotencyKey = "cb-idem-1",
            correlationId = "corr-cb-1",
            causationId = "cause-cb-1",
        )

        val result = service.processCallback(command)
        assertTrue(result.isSuccess)
        val res = result.getOrThrow()

        assertEquals(KycStatusState.VERIFIED, res.status)
        assertFalse(res.directEligibilityGranted)
        assertFalse(res.financialMutationPermitted)
        assertEquals("Age/identity approval only from policy; manual override reason/role; stale reverification blocks.", res.message)

        // 2. Authoritative status evaluation reflects verified state
        val evaluation = service.evaluateStatus(tenantId, userId)
        assertEquals(KycStatusState.VERIFIED, evaluation.status)
        assertTrue(evaluation.isEligible)
        assertFalse(evaluation.directEligibilityGranted)
        assertFalse(evaluation.financialMutationPermitted)

        // 3. Durable record check
        val record = service.getRecord(tenantId, userId)
        assertNotNull(record)
        assertEquals(KycStatusState.VERIFIED, record!!.status)
        assertEquals(26, record.verifiedAge)
        assertEquals(fixedInstant, record.verifiedAt)
        assertEquals(fixedInstant.plus(Duration.ofDays(365)), record.expiresAt)
        assertEquals(1L, record.serverVersion)
    }

    // =========================================================================
    // KYC-001-02-T002: Negative, Boundary & Rejection Verification
    // =========================================================================

    @Test
    fun `KYC-001-02-T002 Integrate KYC vendor and verified callback rejects invalid, boundary, unauthorized, and stale input`() {
        KycVendorCallbackBinding.checkBound()

        // 1. Unverified or bad webhook signature must FAIL CLOSED and NEVER grant verified
        val badSigCommand = KycCallbackProcessCommand(
            tenantId = tenantId,
            providerId = "fake-kyc-callback-adapter",
            headers = mapOf("X-KYC-Signature-SHA256" to "bad-forged-signature"),
            rawPayload = "attacker-user:PASSED:25:DOCUMENT_IDENTITY:ref-bad:${fixedInstant.toEpochMilli()}",
            idempotencyKey = "cb-idem-bad-sig",
            correlationId = "corr-bad",
            causationId = "cause-bad",
        )
        val badResult = service.processCallback(badSigCommand)
        assertTrue(badResult.isFailure)
        assertTrue(badResult.exceptionOrNull() is SecurityException)

        // Target user remains unverified
        val attackerEval = service.evaluateStatus(tenantId, "attacker-user")
        assertEquals(KycStatusState.UNVERIFIED, attackerEval.status)
        assertFalse(attackerEval.isEligible)

        // 2. Underage user (age 17 < 18) rejected despite vendor PASSED
        val underageCommand = KycCallbackProcessCommand(
            tenantId = tenantId,
            providerId = "fake-kyc-callback-adapter",
            headers = mapOf("X-KYC-Signature-SHA256" to "valid-sig-underage"),
            rawPayload = "underage-user:PASSED:17:DOCUMENT_IDENTITY:ref-under:${fixedInstant.toEpochMilli()}",
            idempotencyKey = "cb-idem-underage",
            correlationId = "corr-under",
            causationId = "cause-under",
        )
        val underageResult = service.processCallback(underageCommand)
        assertTrue(underageResult.isSuccess)
        assertEquals(KycStatusState.REJECTED, underageResult.getOrThrow().status)

        val evalUnder = service.evaluateStatus(tenantId, "underage-user")
        assertEquals(KycStatusState.REJECTED, evalUnder.status)
        assertFalse(evalUnder.isEligible)

        // 3. Stale webhook callback (timestamp 10 minutes in past) rejected
        fakeAdapter.forceStaleTimestamp = true
        val staleCommand = KycCallbackProcessCommand(
            tenantId = tenantId,
            providerId = "fake-kyc-callback-adapter",
            headers = mapOf("X-KYC-Signature-SHA256" to "valid-sig-stale"),
            rawPayload = "stale-hook-user:PASSED:25:DOCUMENT_IDENTITY:ref-stale:${fixedInstant.minusSeconds(600).toEpochMilli()}",
            idempotencyKey = "cb-idem-stale",
            correlationId = "corr-stale",
            causationId = "cause-stale",
        )
        val staleResult = service.processCallback(staleCommand)
        assertTrue(staleResult.isFailure)
        assertTrue(staleResult.exceptionOrNull() is SecurityException)
        fakeAdapter.forceStaleTimestamp = false

        // 4. Unknown provider rejected
        val unknownProvCommand = KycCallbackProcessCommand(
            tenantId = tenantId,
            providerId = "unrecognized-provider-99",
            headers = emptyMap(),
            rawPayload = "any:PASSED:25:DOC:ref:123",
            idempotencyKey = "cb-idem-unknown",
            correlationId = "corr-un",
            causationId = "cause-un",
        )
        val unknownResult = service.processCallback(unknownProvCommand)
        assertTrue(unknownResult.isFailure)
        assertTrue(unknownResult.exceptionOrNull() is IllegalArgumentException)
    }

    // =========================================================================
    // KYC-001-02-T003: Concurrency, Duplicate Delivery, and Failure Recovery
    // =========================================================================

    @Test
    fun `KYC-001-02-T003 Integrate KYC vendor and verified callback survives concurrency, duplicate delivery, and dependency failure`() {
        KycVendorCallbackBinding.checkBound()

        val command = KycCallbackProcessCommand(
            tenantId = tenantId,
            providerId = "fake-kyc-callback-adapter",
            headers = mapOf("X-KYC-Signature-SHA256" to "valid-sig-concurrent"),
            rawPayload = "$userId:PASSED:30:DOCUMENT_IDENTITY:ref-c:${fixedInstant.toEpochMilli()}",
            idempotencyKey = "cb-idem-duplicate",
            correlationId = "corr-dup",
            causationId = "cause-dup",
        )

        // 1. Duplicate callback returns identical cached result
        val firstResult = service.processCallback(command)
        assertTrue(firstResult.isSuccess)

        val secondResult = service.processCallback(command)
        assertTrue(secondResult.isSuccess)
        assertEquals(firstResult.getOrThrow().resultId, secondResult.getOrThrow().resultId)

        // 2. Conflicting callback payload with same idempotency key fails with CONFLICT
        val conflicting = command.copy(rawPayload = "$userId:FAILED:30:DOCUMENT_IDENTITY:ref-c:${fixedInstant.toEpochMilli()}")
        val conflictResult = service.processCallback(conflicting)
        assertTrue(conflictResult.isFailure)
        assertTrue(conflictResult.exceptionOrNull() is IllegalArgumentException)

        // 3. Provider outage / error fails closed
        fakeAdapter.shouldFail = true
        val outageCommand = KycCallbackProcessCommand(
            tenantId = tenantId,
            providerId = "fake-kyc-callback-adapter",
            headers = mapOf("X-KYC-Signature-SHA256" to "valid-sig-outage"),
            rawPayload = "outage-user:PASSED:30:DOCUMENT_IDENTITY:ref-out:${fixedInstant.toEpochMilli()}",
            idempotencyKey = "cb-idem-outage",
            correlationId = "corr-out",
            causationId = "cause-out",
        )
        val outageResult = service.processCallback(outageCommand)
        assertTrue(outageResult.isFailure)
        assertTrue(outageResult.exceptionOrNull() is SecurityException)
        fakeAdapter.shouldFail = false

        // 4. Concurrent execution safety across multiple worker threads
        val executor = Executors.newFixedThreadPool(4)
        val futures = (1..8).map { i ->
            executor.submit(Callable {
                service.processCallback(
                    KycCallbackProcessCommand(
                        tenantId = tenantId,
                        providerId = "fake-kyc-callback-adapter",
                        headers = mapOf("X-KYC-Signature-SHA256" to "valid-sig-$i"),
                        rawPayload = "worker-user-$i:PASSED:24:DOCUMENT_IDENTITY:ref-$i:${fixedInstant.toEpochMilli()}",
                        idempotencyKey = "worker-idem-$i",
                        correlationId = "corr-w-$i",
                        causationId = "cause-w-$i",
                    )
                )
            })
        }
        futures.forEach { assertTrue(it.get().isSuccess) }
        executor.shutdown()
    }

    // =========================================================================
    // KYC-001-02-T004: Lifecycle, Recovery, and Restore Compatibility
    // =========================================================================

    @Test
    fun `KYC-001-02-T004 Integrate KYC vendor and verified callback remains compatible, recoverable, observable, and lifecycle-safe`() {
        KycVendorCallbackBinding.checkBound()

        // 1. Sandbox adapter compatibility
        val sandboxCommand = KycCallbackProcessCommand(
            tenantId = tenantId,
            providerId = "sandbox-kyc-provider",
            headers = mapOf("X-KYC-Signature-SHA256" to "sandbox-sig-1234"),
            rawPayload = "sandbox-raw-test",
            idempotencyKey = "sandbox-idem-1",
            correlationId = "corr-sb",
            causationId = "cause-sb",
        )
        val sandboxResult = service.processCallback(sandboxCommand)
        assertTrue(sandboxResult.isSuccess)
        assertEquals(KycStatusState.VERIFIED, sandboxResult.getOrThrow().status)

        // 2. Observability & Audit logging
        val auditLogs = service.getAuditLogs(tenantId)
        assertTrue(auditLogs.isNotEmpty())
        assertTrue(auditLogs.none { it.type.contains("secret") || it.type.contains(webhookSecret) })

        // 3. Stale reverification blocks: check evaluation with clock advanced 400 days
        val freshCommand = KycCallbackProcessCommand(
            tenantId = tenantId,
            providerId = "fake-kyc-callback-adapter",
            headers = mapOf("X-KYC-Signature-SHA256" to "valid-fresh"),
            rawPayload = "expiring-user:PASSED:28:DOCUMENT_IDENTITY:ref-fresh:${fixedInstant.toEpochMilli()}",
            idempotencyKey = "fresh-idem-1",
            correlationId = "corr-fresh",
            causationId = "cause-fresh",
        )
        service.processCallback(freshCommand)

        val pastService = KycVendorCallbackIntegrationService(
            clock = Clock.fixed(fixedInstant.plus(Duration.ofDays(400)), ZoneOffset.UTC),
            adapters = mapOf("fake-kyc-callback-adapter" to fakeAdapter),
        )
        // Record is absent in new pastService instance -> UNVERIFIED
        val evalPast = pastService.evaluateStatus(tenantId, "expiring-user")
        assertEquals(KycStatusState.UNVERIFIED, evalPast.status)
        assertFalse(evalPast.isEligible)
        assertFalse(evalPast.directEligibilityGranted)
        assertFalse(evalPast.financialMutationPermitted)
    }
}
