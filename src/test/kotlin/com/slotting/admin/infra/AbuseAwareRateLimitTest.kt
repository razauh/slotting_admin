package com.slotting.admin.infra

import com.slotting.admin.auth.AdminRole
import com.slotting.admin.auth.AuthenticatedPrincipal
import com.slotting.admin.auth.PrincipalKind
import org.junit.jupiter.api.Assertions.*
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test
import java.time.Clock
import java.time.Instant
import java.time.ZoneOffset
import java.util.concurrent.Callable
import java.util.concurrent.Executors

class AbuseAwareRateLimitTest {

    private lateinit var fixedInstant: Instant
    private lateinit var clock: Clock
    private lateinit var fakeProvider: FakeRateLimitProviderAdapter
    private lateinit var service: AbuseAwareRateLimitService

    private val tenantId = "tenant-prod-1"

    private val securityAdmin = AuthenticatedPrincipal(
        id = "admin-sec-1",
        tenantId = tenantId,
        kind = PrincipalKind.ADMIN,
        roles = setOf(AdminRole.SECURITY),
    )

    private val superAdmin = AuthenticatedPrincipal(
        id = "admin-super-1",
        tenantId = tenantId,
        kind = PrincipalKind.ADMIN,
        roles = setOf(AdminRole.SUPER_ADMIN),
    )

    private val auditor = AuthenticatedPrincipal(
        id = "admin-audit-1",
        tenantId = tenantId,
        kind = PrincipalKind.ADMIN,
        roles = setOf(AdminRole.AUDITOR),
    )

    private val defaultPolicies = mapOf(
        RateLimitCategory.AUTH to RateLimitPolicy(
            category = RateLimitCategory.AUTH,
            maxRequestsPerMinute = 5,
            burstCapacity = 2,
            abuseThresholdPerMinute = 3,
        ),
        RateLimitCategory.GAMEPLAY to RateLimitPolicy(
            category = RateLimitCategory.GAMEPLAY,
            maxRequestsPerMinute = 60,
            burstCapacity = 20,
            abuseThresholdPerMinute = 10,
        ),
        RateLimitCategory.CASHIER to RateLimitPolicy(
            category = RateLimitCategory.CASHIER,
            maxRequestsPerMinute = 10,
            burstCapacity = 3,
            abuseThresholdPerMinute = 4,
        ),
        RateLimitCategory.GENERAL to RateLimitPolicy(
            category = RateLimitCategory.GENERAL,
            maxRequestsPerMinute = 120,
            burstCapacity = 30,
            abuseThresholdPerMinute = 20,
        ),
    )

    @BeforeEach
    fun setUp() {
        fixedInstant = Instant.parse("2026-09-19T10:00:00Z")
        clock = Clock.fixed(fixedInstant, ZoneOffset.UTC)
        fakeProvider = FakeRateLimitProviderAdapter(clock)
        service = AbuseAwareRateLimitService(clock = clock, provider = fakeProvider)
    }

    // =========================================================================
    // INFRA-003-03-T001: Authoritative Outcome Verification
    // =========================================================================

    @Test
    fun `INFRA-003-03-T001 Enforce abuse-aware rate limits produces the required authoritative outcome`() {
        // Must fail with AssertionError("rotation/abuse/bypass scenarios") in RED phase
        AbuseAwareRateLimitBinding.checkBound()

        // 1. Configure rate limit tiers
        val tierResult = service.configureTiers(
            tenantId = tenantId,
            policies = defaultPolicies,
            principal = securityAdmin,
            idempotencyKey = "tier-config-1",
        )
        assertTrue(tierResult.isSuccess)
        val tier = tierResult.getOrThrow()
        assertEquals(1L, tier.version)
        assertEquals(4, tier.policies.size)

        // 2. Allow requests within limit
        val req1 = RateLimitEvaluationRequest(
            tenantId = tenantId,
            clientIp = "192.168.1.100",
            userId = "user-1",
            category = RateLimitCategory.AUTH,
        )
        val resp1 = service.checkRateLimit(req1)
        assertEquals(RateLimitDecisionState.ALLOWED, resp1.state)
        assertEquals(4, resp1.remainingRequests)
        assertFalse(resp1.abuseDetected)
        assertFalse(resp1.directEligibilityGranted)
        assertFalse(resp1.financialMutationPermitted)

        // 3. Exhaust limit -> Throttled
        repeat(4) { service.checkRateLimit(req1) }
        val throttledResp = service.checkRateLimit(req1)
        assertEquals(RateLimitDecisionState.THROTTLED, throttledResp.state)
        assertEquals(0, throttledResp.remainingRequests)
        assertTrue(throttledResp.retryAfterSeconds > 0)
        assertFalse(throttledResp.directEligibilityGranted)
        assertFalse(throttledResp.financialMutationPermitted)

        // 4. Record abuse violations -> Abuse Quarantine
        repeat(3) {
            service.recordAbuseViolation(tenantId, "192.168.1.100:${RateLimitCategory.AUTH}")
        }
        val abuseResp = service.checkRateLimit(req1)
        assertEquals(RateLimitDecisionState.BLOCKED_ABUSE, abuseResp.state)
        assertTrue(abuseResp.abuseDetected)
        assertEquals(300L, abuseResp.retryAfterSeconds)
        assertFalse(abuseResp.directEligibilityGranted)
        assertFalse(abuseResp.financialMutationPermitted)

        // 5. Test emergency procedure
        val emergResult = service.recordEmergencyProcedure(
            tenantId = tenantId,
            emergencyType = RateLimitEmergencyType.EMERGENCY_ABUSE_QUARANTINE,
            success = true,
            verificationEvidence = "Emergency abuse quarantine verified under load",
            principal = superAdmin,
            idempotencyKey = "emerg-rl-1",
        )
        assertTrue(emergResult.isSuccess)

        // 6. Readiness evaluation
        val evaluation = service.evaluateRateLimitReadiness(tenantId, securityAdmin)
        assertEquals(AbuseRateLimitDecision.GO, evaluation.status)
        assertEquals(AbuseRateLimitReason.RATE_LIMITS_ACTIVE_AND_EMERGENCY_TESTED, evaluation.reason)
        assertEquals(4, evaluation.activeTiersCount)
        assertTrue(evaluation.emergencyProceduresTested)
        assertFalse(evaluation.directEligibilityGranted)
        assertFalse(evaluation.financialMutationPermitted)
        assertEquals("Rate limits never become financial authority; emergency procedures tested.", evaluation.message)
        assertTrue(evaluation.evidenceReference.isNotBlank())
    }

    // =========================================================================
    // INFRA-003-03-T002: Negative, Boundary & Rejection Verification
    // =========================================================================

    @Test
    fun `INFRA-003-03-T002 Enforce abuse-aware rate limits rejects invalid, boundary, unauthorized, and stale input`() {
        AbuseAwareRateLimitBinding.checkBound()

        // Unauthorized principal cannot configure tiers
        val unauthResult = service.configureTiers(
            tenantId = tenantId,
            policies = defaultPolicies,
            principal = auditor,
            idempotencyKey = "unauth-tier-1",
        )
        assertTrue(unauthResult.isFailure)
        assertTrue(unauthResult.exceptionOrNull() is SecurityException)

        // Cross-tenant configuration forbidden
        val crossTenantPrincipal = AuthenticatedPrincipal(
            id = "cross-admin",
            tenantId = "other-tenant",
            kind = PrincipalKind.ADMIN,
            roles = setOf(AdminRole.SECURITY),
        )
        val crossTenantResult = service.configureTiers(
            tenantId = tenantId,
            policies = defaultPolicies,
            principal = crossTenantPrincipal,
            idempotencyKey = "cross-tier-1",
        )
        assertTrue(crossTenantResult.isFailure)
        assertTrue(crossTenantResult.exceptionOrNull() is SecurityException)

        // Empty policies map rejected
        val emptyResult = service.configureTiers(
            tenantId = tenantId,
            policies = emptyMap(),
            principal = securityAdmin,
            idempotencyKey = "empty-tier-1",
        )
        assertTrue(emptyResult.isFailure)
        assertTrue(emptyResult.exceptionOrNull() is IllegalArgumentException)

        // Stale expected version conflict
        service.configureTiers(
            tenantId = tenantId,
            policies = defaultPolicies,
            principal = securityAdmin,
            idempotencyKey = "tier-v1",
            expectedVersion = 1L,
        ).getOrThrow()

        val staleResult = service.configureTiers(
            tenantId = tenantId,
            policies = defaultPolicies,
            principal = securityAdmin,
            idempotencyKey = "tier-stale",
            expectedVersion = 999L,
        )
        assertTrue(staleResult.isFailure)
        assertTrue(staleResult.exceptionOrNull() is IllegalStateException)

        // Readiness evaluation with untested emergency procedures returns NO_GO
        val evalUntested = service.evaluateRateLimitReadiness(tenantId, securityAdmin)
        assertEquals(AbuseRateLimitDecision.NO_GO, evalUntested.status)
        assertEquals(AbuseRateLimitReason.EMERGENCY_PROCEDURES_UNTESTED, evalUntested.reason)

        // Unconfigured tenant fails closed on check
        val unconfiguredCheck = service.checkRateLimit(
            RateLimitEvaluationRequest(
                tenantId = "tenant-unconfigured",
                clientIp = "10.0.0.1",
                userId = null,
                category = RateLimitCategory.GENERAL,
            )
        )
        assertEquals(RateLimitDecisionState.THROTTLED, unconfiguredCheck.state)
        assertTrue(unconfiguredCheck.reasonCode.contains("FAIL_CLOSED"))

        // Audit log records failures
        val audits = service.getAuditLog(tenantId)
        assertTrue(audits.any { !it.success })
    }

    // =========================================================================
    // INFRA-003-03-T003: Concurrency, Duplicate Delivery, and Failure Recovery
    // =========================================================================

    @Test
    fun `INFRA-003-03-T003 Enforce abuse-aware rate limits survives concurrency, duplicate delivery, and dependency failure`() {
        AbuseAwareRateLimitBinding.checkBound()

        // Idempotent duplicate update
        val update1 = service.configureTiers(
            tenantId = tenantId,
            policies = defaultPolicies,
            principal = securityAdmin,
            idempotencyKey = "idem-tier-1",
        ).getOrThrow()

        val update2 = service.configureTiers(
            tenantId = tenantId,
            policies = defaultPolicies,
            principal = securityAdmin,
            idempotencyKey = "idem-tier-1",
        ).getOrThrow()

        assertEquals(update1.tierId, update2.tierId)
        assertEquals(update1.version, update2.version)

        // Conflict on payload reuse
        val conflictResult = service.configureTiers(
            tenantId = tenantId,
            policies = mapOf(RateLimitCategory.AUTH to defaultPolicies.getValue(RateLimitCategory.AUTH)),
            principal = securityAdmin,
            idempotencyKey = "idem-tier-1",
        )
        assertTrue(conflictResult.isFailure)
        assertTrue(conflictResult.exceptionOrNull() is IllegalArgumentException)

        // Provider failure handling (fail-closed)
        fakeProvider.shouldFail = true
        val failedCheck = service.checkRateLimit(
            RateLimitEvaluationRequest(
                tenantId = tenantId,
                clientIp = "192.168.1.5",
                userId = "user-1",
                category = RateLimitCategory.GAMEPLAY,
            )
        )
        assertEquals(RateLimitDecisionState.THROTTLED, failedCheck.state)
        assertTrue(failedCheck.reasonCode.contains("FAIL_CLOSED_PROVIDER_FAILURE"))
        assertFalse(failedCheck.directEligibilityGranted)
        assertFalse(failedCheck.financialMutationPermitted)

        // Provider recovery
        fakeProvider.shouldFail = false
        val recoveredCheck = service.checkRateLimit(
            RateLimitEvaluationRequest(
                tenantId = tenantId,
                clientIp = "192.168.1.5",
                userId = "user-1",
                category = RateLimitCategory.GAMEPLAY,
            )
        )
        assertEquals(RateLimitDecisionState.ALLOWED, recoveredCheck.state)

        // Concurrent emergency registrations
        val pool = Executors.newFixedThreadPool(4)
        val futures = (1..6).map { i ->
            pool.submit(Callable {
                service.recordEmergencyProcedure(
                    tenantId = tenantId,
                    emergencyType = RateLimitEmergencyType.EMERGENCY_TRAFFIC_SHEDDING,
                    success = true,
                    verificationEvidence = "Evidence test $i",
                    principal = superAdmin,
                    idempotencyKey = "concurrent-emerg-$i",
                )
            })
        }
        val results = futures.map { it.get() }
        pool.shutdown()

        assertTrue(results.all { it.isSuccess })
    }

    // =========================================================================
    // INFRA-003-03-T004: Lifecycle, Recovery, and Restore Compatibility
    // =========================================================================

    @Test
    fun `INFRA-003-03-T004 Enforce abuse-aware rate limits remains compatible, recoverable, observable, and lifecycle-safe`() {
        AbuseAwareRateLimitBinding.checkBound()

        // Sandbox adapter compatibility
        val sandboxAdapter = SandboxRateLimitProviderAdapter()
        val sandboxService = AbuseAwareRateLimitService(clock = clock, provider = sandboxAdapter)

        val sandboxResult = sandboxService.configureTiers(
            tenantId = tenantId,
            policies = defaultPolicies,
            principal = securityAdmin,
            idempotencyKey = "sandbox-tier-1",
        )
        assertTrue(sandboxResult.isSuccess)

        // Configure and verify emergency procedures
        service.configureTiers(
            tenantId = tenantId,
            policies = defaultPolicies,
            principal = securityAdmin,
            idempotencyKey = "setup-tier",
        )
        service.recordEmergencyProcedure(
            tenantId = tenantId,
            emergencyType = RateLimitEmergencyType.EMERGENCY_RATE_LIMIT_ROLLBACK,
            success = true,
            verificationEvidence = "Rate limit rollback rehearsal complete",
            principal = superAdmin,
            idempotencyKey = "emerg-rollback-1",
        )

        val evaluation = service.evaluateRateLimitReadiness(tenantId, securityAdmin)
        assertEquals(AbuseRateLimitDecision.GO, evaluation.status)
        assertEquals("Rate limits never become financial authority; emergency procedures tested.", evaluation.message)
        assertFalse(evaluation.directEligibilityGranted)
        assertFalse(evaluation.financialMutationPermitted)

        // Audit observability
        val audits = service.getAuditLog(tenantId)
        assertTrue(audits.isNotEmpty())
        assertTrue(audits.all { it.detailsRedacted.isNotBlank() })
    }
}
