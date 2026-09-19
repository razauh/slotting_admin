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

class EnforceWafPolicyTest {

    private lateinit var fixedInstant: Instant
    private lateinit var clock: Clock
    private lateinit var fakeWaf: FakeWafProviderAdapter
    private lateinit var service: EnforceWafPolicyService

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

    private val sampleRules = listOf(
        WafRule(
            ruleId = "rule-sqli",
            ruleType = WafRuleType.SQLI_PROTECTION,
            action = WafAction.BLOCK,
            priority = 1,
            enabled = true,
        ),
        WafRule(
            ruleId = "rule-xss",
            ruleType = WafRuleType.XSS_PROTECTION,
            action = WafAction.BLOCK,
            priority = 2,
            enabled = true,
        ),
        WafRule(
            ruleId = "rule-rce",
            ruleType = WafRuleType.RCE_PROTECTION,
            action = WafAction.BLOCK,
            priority = 3,
            enabled = true,
        ),
    )

    @BeforeEach
    fun setUp() {
        fixedInstant = Instant.parse("2026-09-19T10:00:00Z")
        clock = Clock.fixed(fixedInstant, ZoneOffset.UTC)
        fakeWaf = FakeWafProviderAdapter()
        service = EnforceWafPolicyService(clock = clock, wafProvider = fakeWaf)
    }

    // =========================================================================
    // INFRA-003-02-T001: Authoritative Outcome Verification
    // =========================================================================

    @Test
    fun `INFRA-003-02-T001 Enforce WAF policy produces the required authoritative outcome`() {
        // RED phase failure expectation: AssertionError("rotation/abuse/bypass scenarios")
        EnforceWafPolicyBinding.checkBound()

        // 1. Configure WAF ruleset
        val rulesetResult = service.updateRuleset(
            tenantId = tenantId,
            rules = sampleRules,
            principal = securityAdmin,
            idempotencyKey = "ruleset-v1",
        )
        assertTrue(rulesetResult.isSuccess)
        val ruleset = rulesetResult.getOrThrow()
        assertEquals(1L, ruleset.version)
        assertEquals(3, ruleset.rules.size)

        // 2. Perform inspection: legitimate request allowed
        val legitimateReq = WafInspectionRequest(
            tenantId = tenantId,
            clientIp = "192.168.1.50",
            uri = "/api/v1/games/catalog",
            method = "GET",
            headers = mapOf("User-Agent" to "Android-Client/1.0"),
        )
        val allowedResult = service.inspectRequest(legitimateReq)
        assertTrue(allowedResult.isAllowed)
        assertEquals(WafAction.ALLOW, allowedResult.action)

        // 3. Perform inspection: SQLi attack blocked
        val sqliReq = WafInspectionRequest(
            tenantId = tenantId,
            clientIp = "192.168.1.50",
            uri = "/api/v1/games?filter=1'--",
            method = "GET",
            headers = mapOf("User-Agent" to "curl/7.68.0"),
            bodySnippet = "SELECT * FROM users union select null, password from secrets",
        )
        val blockedResult = service.inspectRequest(sqliReq)
        assertFalse(blockedResult.isAllowed)
        assertEquals(WafAction.BLOCK, blockedResult.action)
        assertEquals("rule-sqli-owasp", blockedResult.matchedRuleId)

        // 4. Test emergency procedure
        val emergResult = service.recordEmergencyProcedure(
            tenantId = tenantId,
            actionType = WafEmergencyActionType.EMERGENCY_UNDER_ATTACK_MODE,
            success = true,
            verificationEvidence = "WAF under attack mode tested under load",
            principal = superAdmin,
            idempotencyKey = "emerg-waf-1",
        )
        assertTrue(emergResult.isSuccess)

        // 5. Authoritative readiness evaluation
        val evaluation = service.evaluateWafPolicyReadiness(tenantId, securityAdmin)
        assertEquals(WafDecision.GO, evaluation.status)
        assertEquals(WafReason.WAF_POLICY_ACTIVE_AND_EMERGENCY_TESTED, evaluation.reason)
        assertEquals(3, evaluation.activeRulesCount)
        assertTrue(evaluation.emergencyProceduresTested)

        // Financial & Semantic Contract assertions
        assertFalse(evaluation.directEligibilityGranted)
        assertFalse(evaluation.financialMutationPermitted)
        assertEquals("Rate limits never become financial authority; emergency procedures tested.", evaluation.message)
        assertTrue(evaluation.evidenceReference.isNotBlank())
    }

    // =========================================================================
    // INFRA-003-02-T002: Negative, Boundary & Rejection Verification
    // =========================================================================

    @Test
    fun `INFRA-003-02-T002 Enforce WAF policy rejects invalid, boundary, unauthorized, and stale input`() {
        EnforceWafPolicyBinding.checkBound()

        // Unauthorized principal lacks permissions to update WAF
        val unauthResult = service.updateRuleset(
            tenantId = tenantId,
            rules = sampleRules,
            principal = auditor,
            idempotencyKey = "unauth-ruleset-1",
        )
        assertTrue(unauthResult.isFailure)
        assertTrue(unauthResult.exceptionOrNull() is SecurityException)

        // Cross-tenant update rejected
        val crossTenantPrincipal = AuthenticatedPrincipal(
            id = "cross-admin",
            tenantId = "other-tenant",
            kind = PrincipalKind.ADMIN,
            roles = setOf(AdminRole.SECURITY),
        )
        val crossTenantResult = service.updateRuleset(
            tenantId = tenantId,
            rules = sampleRules,
            principal = crossTenantPrincipal,
            idempotencyKey = "cross-ruleset-1",
        )
        assertTrue(crossTenantResult.isFailure)
        assertTrue(crossTenantResult.exceptionOrNull() is SecurityException)

        // Empty ruleset rejected
        val emptyResult = service.updateRuleset(
            tenantId = tenantId,
            rules = emptyList(),
            principal = securityAdmin,
            idempotencyKey = "empty-ruleset-1",
        )
        assertTrue(emptyResult.isFailure)
        assertTrue(emptyResult.exceptionOrNull() is IllegalArgumentException)

        // All rules disabled rejected
        val disabledResult = service.updateRuleset(
            tenantId = tenantId,
            rules = listOf(sampleRules.first().copy(enabled = false)),
            principal = securityAdmin,
            idempotencyKey = "disabled-ruleset-1",
        )
        assertTrue(disabledResult.isFailure)
        assertTrue(disabledResult.exceptionOrNull() is IllegalArgumentException)

        // Stale expected version conflict
        service.updateRuleset(
            tenantId = tenantId,
            rules = sampleRules,
            principal = securityAdmin,
            idempotencyKey = "ruleset-v1",
            expectedVersion = 1L,
        ).getOrThrow()

        val staleResult = service.updateRuleset(
            tenantId = tenantId,
            rules = sampleRules,
            principal = securityAdmin,
            idempotencyKey = "ruleset-v-stale",
            expectedVersion = 999L,
        )
        assertTrue(staleResult.isFailure)
        assertTrue(staleResult.exceptionOrNull() is IllegalStateException)

        // Readiness evaluation with untested emergencies yields NO_GO
        val evalUntested = service.evaluateWafPolicyReadiness(tenantId, securityAdmin)
        assertEquals(WafDecision.NO_GO, evalUntested.status)
        assertEquals(WafReason.EMERGENCY_PROCEDURES_UNTESTED, evalUntested.reason)

        // Inspection on unconfigured tenant fails closed
        val unconfiguredTenantReq = WafInspectionRequest(
            tenantId = "tenant-unconfigured",
            clientIp = "10.0.0.1",
            uri = "/api/test",
            method = "GET",
            headers = emptyMap(),
        )
        val blockedUnconfigured = service.inspectRequest(unconfiguredTenantReq)
        assertFalse(blockedUnconfigured.isAllowed)
        assertEquals(WafAction.BLOCK, blockedUnconfigured.action)

        // Audit records rejections
        val audits = service.getAuditLog(tenantId)
        assertTrue(audits.any { !it.success })
    }

    // =========================================================================
    // INFRA-003-02-T003: Concurrency, Duplicate Delivery, and Failure Recovery
    // =========================================================================

    @Test
    fun `INFRA-003-02-T003 Enforce WAF policy survives concurrency, duplicate delivery, and dependency failure`() {
        EnforceWafPolicyBinding.checkBound()

        // Idempotent duplicate update returns cached result
        val update1 = service.updateRuleset(
            tenantId = tenantId,
            rules = sampleRules,
            principal = securityAdmin,
            idempotencyKey = "idem-ruleset-1",
        ).getOrThrow()

        val update2 = service.updateRuleset(
            tenantId = tenantId,
            rules = sampleRules,
            principal = securityAdmin,
            idempotencyKey = "idem-ruleset-1",
        ).getOrThrow()

        assertEquals(update1.rulesetId, update2.rulesetId)
        assertEquals(update1.version, update2.version)

        // Conflict on payload reuse
        val conflictResult = service.updateRuleset(
            tenantId = tenantId,
            rules = listOf(sampleRules[0]),
            principal = securityAdmin,
            idempotencyKey = "idem-ruleset-1",
        )
        assertTrue(conflictResult.isFailure)
        assertTrue(conflictResult.exceptionOrNull() is IllegalArgumentException)

        // Provider failure handling (fail-closed)
        fakeWaf.shouldFail = true
        val failedInspection = service.inspectRequest(
            WafInspectionRequest(
                tenantId = tenantId,
                clientIp = "192.168.1.1",
                uri = "/api/test",
                method = "GET",
                headers = emptyMap(),
            )
        )
        assertFalse(failedInspection.isAllowed)
        assertEquals(WafAction.BLOCK, failedInspection.action)
        assertTrue(failedInspection.blockReason?.contains("FAIL_CLOSED") == true)

        // Recover provider
        fakeWaf.shouldFail = false
        val recoveredInspection = service.inspectRequest(
            WafInspectionRequest(
                tenantId = tenantId,
                clientIp = "192.168.1.1",
                uri = "/api/test",
                method = "GET",
                headers = emptyMap(),
            )
        )
        assertTrue(recoveredInspection.isAllowed)

        // Concurrent emergency procedure registrations
        val pool = Executors.newFixedThreadPool(4)
        val futures = (1..6).map { i ->
            pool.submit(Callable {
                service.recordEmergencyProcedure(
                    tenantId = tenantId,
                    actionType = WafEmergencyActionType.EMERGENCY_IP_BLOCK,
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
    // INFRA-003-02-T004: Lifecycle, Recovery, and Restore Compatibility
    // =========================================================================

    @Test
    fun `INFRA-003-02-T004 Enforce WAF policy remains compatible, recoverable, observable, and lifecycle-safe`() {
        EnforceWafPolicyBinding.checkBound()

        // Sandbox adapter compatibility
        val sandboxAdapter = SandboxWafProviderAdapter()
        val sandboxService = EnforceWafPolicyService(clock = clock, wafProvider = sandboxAdapter)

        val sandboxResult = sandboxService.updateRuleset(
            tenantId = tenantId,
            rules = sampleRules,
            principal = securityAdmin,
            idempotencyKey = "sandbox-waf-1",
        )
        assertTrue(sandboxResult.isSuccess)

        // Verify attack vector coverage: XSS, RCE, IP blocking
        service.updateRuleset(
            tenantId = tenantId,
            rules = sampleRules,
            principal = securityAdmin,
            idempotencyKey = "setup-ruleset",
        )

        // XSS blocked
        val xssResult = service.inspectRequest(
            WafInspectionRequest(
                tenantId = tenantId,
                clientIp = "192.168.1.2",
                uri = "/search?q=<script>alert(1)</script>",
                method = "GET",
                headers = emptyMap(),
            )
        )
        assertFalse(xssResult.isAllowed)
        assertEquals("rule-xss-owasp", xssResult.matchedRuleId)

        // RCE blocked
        val rceResult = service.inspectRequest(
            WafInspectionRequest(
                tenantId = tenantId,
                clientIp = "192.168.1.3",
                uri = "/upload",
                method = "POST",
                headers = emptyMap(),
                bodySnippet = "param=test; rm -rf /",
            )
        )
        assertFalse(rceResult.isAllowed)
        assertEquals("rule-rce-owasp", rceResult.matchedRuleId)

        // Emergency IP blocking
        fakeWaf.blockIp("192.168.1.99")
        val blockedIpResult = service.inspectRequest(
            WafInspectionRequest(
                tenantId = tenantId,
                clientIp = "192.168.1.99",
                uri = "/api/v1/games",
                method = "GET",
                headers = emptyMap(),
            )
        )
        assertFalse(blockedIpResult.isAllowed)
        assertEquals("rule-ip-block", blockedIpResult.matchedRuleId)

        // Emergency tested & full readiness
        service.recordEmergencyProcedure(
            tenantId = tenantId,
            actionType = WafEmergencyActionType.EMERGENCY_RULESET_ROLLBACK,
            success = true,
            verificationEvidence = "WAF ruleset rollback tested successfully",
            principal = superAdmin,
            idempotencyKey = "emerg-rollback-1",
        )

        val evaluation = service.evaluateWafPolicyReadiness(tenantId, securityAdmin)
        assertEquals(WafDecision.GO, evaluation.status)
        assertEquals("Rate limits never become financial authority; emergency procedures tested.", evaluation.message)
        assertFalse(evaluation.directEligibilityGranted)
        assertFalse(evaluation.financialMutationPermitted)

        // Audit observability
        val audits = service.getAuditLog(tenantId)
        assertTrue(audits.isNotEmpty())
        assertTrue(audits.all { it.detailsRedacted.isNotBlank() })
    }
}
