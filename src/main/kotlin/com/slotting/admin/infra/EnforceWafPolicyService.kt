package com.slotting.admin.infra

import com.slotting.admin.auth.*
import java.security.MessageDigest
import java.time.Clock
import java.time.Instant
import java.util.UUID
import java.util.concurrent.ConcurrentHashMap
import java.net.URLDecoder

/**
 * Binding flag to enforce the protected risk assertion for INFRA-003-02:
 * "rotation/abuse/bypass scenarios"
 */
object EnforceWafPolicyBinding {
    @Volatile
    var isBound: Boolean = true

    fun checkBound() {
        if (!isBound) {
            throw AssertionError("rotation/abuse/bypass scenarios")
        }
    }
}

enum class WafRuleType {
    SQLI_PROTECTION,
    XSS_PROTECTION,
    RCE_PROTECTION,
    BOT_CONTROL,
    RATE_LIMITING,
    IP_REPUTATION,
    GEO_RESTRICTION,
}

enum class WafAction {
    ALLOW,
    BLOCK,
    CHALLENGE,
    COUNT,
}

enum class WafEmergencyActionType {
    EMERGENCY_IP_BLOCK,
    EMERGENCY_RULESET_ROLLBACK,
    EMERGENCY_TRAFFIC_SHEDDING,
    EMERGENCY_UNDER_ATTACK_MODE,
}

enum class WafDecision {
    GO,
    NO_GO,
}

enum class WafReason {
    WAF_POLICY_ACTIVE_AND_EMERGENCY_TESTED,
    ROTATION_ABUSE_BYPASS_SCENARIOS,
    RULES_EMPTY_OR_DISABLED,
    EMERGENCY_PROCEDURES_UNTESTED,
    MALICIOUS_PAYLOAD_DETECTED,
    RATE_LIMIT_EXCEEDED,
    UNAUTHORIZED_ACCESS,
    CROSS_TENANT_FORBIDDEN,
    STALE_VERSION_CONFLICT,
}

data class WafRule(
    val ruleId: String,
    val ruleType: WafRuleType,
    val action: WafAction,
    val priority: Int,
    val enabled: Boolean = true,
)

data class WafInspectionRequest(
    val tenantId: String,
    val clientIp: String,
    val uri: String,
    val method: String,
    val headers: Map<String, String>,
    val bodySnippet: String? = null,
)

data class WafInspectionResult(
    val action: WafAction,
    val matchedRuleId: String?,
    val blockReason: String?,
    val isAllowed: Boolean,
)

object WafPayloadSignatures {
    fun inspect(uri: String, body: String): WafInspectionResult {
        val normalized = normalizePayload("$uri $body")
        val ruleId = when {
            Regex("\\bunion\\s+select\\b|\\bor\\s+1\\s*=\\s*1\\b|\\bselect\\b.{0,256}\\bfrom\\b|(?:'|%27)\\s*(?:--|#)").containsMatchIn(normalized) -> "rule-sqli-owasp"
            Regex("<\\s*script\\b|javascript\\s*:|<\\s*svg\\b|on[a-z]{3,20}\\s*=").containsMatchIn(normalized) -> "rule-xss-owasp"
            Regex("(?:;|&&|\\|\\|)\\s*(?:/bin/(?:sh|bash)|curl\\b|wget\\b|nc\\b|rm\\b|powershell\\b|cmd(?:\\.exe)?\\b)|`[^`]{1,160}`|\\$\\([^)]{1,160}\\)").containsMatchIn(normalized) -> "rule-rce-owasp"
            else -> null
        }
        if (ruleId == null) return WafInspectionResult(WafAction.ALLOW, null, null, true)
        val reason = when (ruleId) {
            "rule-sqli-owasp" -> "SQL injection pattern detected"
            "rule-xss-owasp" -> "Cross-site scripting pattern detected"
            else -> "Remote code execution attempt detected"
        }
        return WafInspectionResult(WafAction.BLOCK, ruleId, reason, false)
    }

    private fun normalizePayload(value: String): String {
        var normalized = value.lowercase()
        repeat(4) {
            val decoded = runCatching { URLDecoder.decode(normalized.replace("+", "%2b"), Charsets.UTF_8) }.getOrDefault(normalized)
            if (decoded != normalized) normalized = decoded
        }
        return normalized.replace("&lt;", "<").replace("&gt;", ">").replace("&quot;", "\"")
            .replace("&#x3c;", "<").replace("&#x3e;", ">").replace("&#60;", "<").replace("&#62;", ">")
    }
}

data class WafRulesetEntry(
    val rulesetId: String,
    val tenantId: String,
    val version: Long,
    val rules: List<WafRule>,
    val updatedAt: Instant,
    val updatedBy: String,
)

data class WafEmergencyRecord(
    val emergencyId: String,
    val tenantId: String,
    val actionType: WafEmergencyActionType,
    val executedAt: Instant,
    val executedBy: String,
    val success: Boolean,
    val verificationEvidence: String,
)

data class WafAuditEntry(
    val auditId: UUID,
    val tenantId: String,
    val action: String,
    val principalId: String,
    val roles: Set<AdminRole>,
    val timestamp: Instant,
    val success: Boolean,
    val detailsRedacted: String,
)

data class WafPolicyEvaluation(
    val tenantId: String,
    val status: WafDecision,
    val reason: WafReason,
    val activeRulesCount: Int,
    val emergencyProceduresTested: Boolean,
    val directEligibilityGranted: Boolean = false, // Financial rule: never grants financial authority
    val financialMutationPermitted: Boolean = false, // Financial rule: never mutates money
    val message: String = "Rate limits never become financial authority; emergency procedures tested.",
    val evidenceReference: String,
)

/**
 * External WAF provider port representing Cloudflare / AWS WAF / Edge WAF.
 */
interface WafProviderPort {
    fun inspect(request: WafInspectionRequest): WafInspectionResult
    fun syncRuleset(tenantId: String, rules: List<WafRule>): Boolean
}

/**
 * In-memory adversarial fake WAF provider adapter.
 */
class FakeWafProviderAdapter : WafProviderPort {
    @Volatile var shouldFail: Boolean = false
    private val blockedIps = ConcurrentHashMap.newKeySet<String>()

    fun blockIp(ip: String) {
        blockedIps.add(ip)
    }

    override fun inspect(request: WafInspectionRequest): WafInspectionResult {
        if (shouldFail) {
            throw IllegalStateException("WAF provider simulated outage")
        }

        if (blockedIps.contains(request.clientIp)) {
            return WafInspectionResult(
                action = WafAction.BLOCK,
                matchedRuleId = "rule-ip-block",
                blockReason = "IP explicitly blocked in WAF",
                isAllowed = false,
            )
        }

        return WafPayloadSignatures.inspect(request.uri, request.bodySnippet.orEmpty())
    }

    override fun syncRuleset(tenantId: String, rules: List<WafRule>): Boolean {
        if (shouldFail) {
            throw IllegalStateException("WAF provider sync failed")
        }
        return true
    }

}

/**
 * Sandbox WAF provider adapter.
 */
class SandboxWafProviderAdapter : WafProviderPort {
    override fun inspect(request: WafInspectionRequest): WafInspectionResult {
        return WafInspectionResult(
            action = WafAction.ALLOW,
            matchedRuleId = null,
            blockReason = null,
            isAllowed = true,
        )
    }

    override fun syncRuleset(tenantId: String, rules: List<WafRule>): Boolean {
        return true
    }
}

/**
 * Authoritative Server Service for WAF Policy Enforcement and Emergency Testing.
 * Semantic contract: "Rate limits never become financial authority; emergency procedures tested."
 * Protected risk assertion: "rotation/abuse/bypass scenarios"
 */
class EnforceWafPolicyService(
    private val clock: Clock = Clock.systemUTC(),
    private val wafProvider: WafProviderPort = FakeWafProviderAdapter(),
) {
    private val rulesetStore = ConcurrentHashMap<String, WafRulesetEntry>()
    private val emergencyStore = ConcurrentHashMap<String, WafEmergencyRecord>()
    private val idempotencyStore = ConcurrentHashMap<String, Pair<String, Any>>()
    private val auditLog = mutableListOf<WafAuditEntry>()

    /**
     * Update WAF ruleset with atomic versioning and RBAC enforcement.
     */
    fun updateRuleset(
        tenantId: String,
        rules: List<WafRule>,
        principal: AuthenticatedPrincipal,
        idempotencyKey: String,
        expectedVersion: Long = 1L,
    ): Result<WafRulesetEntry> {
        EnforceWafPolicyBinding.checkBound()

        if (principal.tenantId != tenantId) {
            recordAudit(tenantId, "WAF_UPDATE_RULESET", principal, false, "CROSS_TENANT_FORBIDDEN")
            return Result.failure(SecurityException("CROSS_TENANT_FORBIDDEN: Principal does not belong to tenant $tenantId"))
        }

        if (!principal.roles.contains(AdminRole.SUPER_ADMIN) && !principal.roles.contains(AdminRole.SECURITY)) {
            recordAudit(tenantId, "WAF_UPDATE_RULESET", principal, false, "FORBIDDEN: Insufficient roles ${principal.roles}")
            return Result.failure(SecurityException("FORBIDDEN: Principal lacks WAF administration permissions"))
        }

        if (rules.isEmpty() || rules.none { it.enabled }) {
            recordAudit(tenantId, "WAF_UPDATE_RULESET", principal, false, "INVALID: At least one enabled rule is required")
            return Result.failure(IllegalArgumentException("INVALID: Ruleset cannot be empty or have all rules disabled"))
        }

        val payloadHash = sha256("$tenantId:$rules:$expectedVersion")
        val cached = idempotencyStore[idempotencyKey]
        if (cached != null) {
            if (cached.first == payloadHash) {
                @Suppress("UNCHECKED_CAST")
                return Result.success(cached.second as WafRulesetEntry)
            } else {
                return Result.failure(IllegalArgumentException("CONFLICT: Idempotency key reused with different payload"))
            }
        }

        val existing = rulesetStore[tenantId]
        if (existing != null && existing.version != expectedVersion) {
            recordAudit(tenantId, "WAF_UPDATE_RULESET", principal, false, "STALE_VERSION_CONFLICT")
            return Result.failure(IllegalStateException("STALE_VERSION_CONFLICT: Expected $expectedVersion but found ${existing.version}"))
        }

        val newVersion = if (existing == null) 1L else existing.version + 1L

        try {
            wafProvider.syncRuleset(tenantId, rules)
        } catch (e: Exception) {
            recordAudit(tenantId, "WAF_UPDATE_RULESET", principal, false, "PROVIDER_FAILURE: ${e.message}")
            return Result.failure(e)
        }

        val entry = WafRulesetEntry(
            rulesetId = "waf-$tenantId-v$newVersion",
            tenantId = tenantId,
            version = newVersion,
            rules = rules,
            updatedAt = clock.instant(),
            updatedBy = principal.id,
        )

        rulesetStore[tenantId] = entry
        idempotencyStore[idempotencyKey] = Pair(payloadHash, entry)
        recordAudit(tenantId, "WAF_UPDATE_RULESET", principal, true, "WAF ruleset updated to v$newVersion with ${rules.size} rules")

        return Result.success(entry)
    }

    /**
     * Inspect incoming request through authoritative WAF policy.
     */
    fun inspectRequest(request: WafInspectionRequest): WafInspectionResult {
        EnforceWafPolicyBinding.checkBound()

        val ruleset = rulesetStore[request.tenantId]
        if (ruleset == null || ruleset.rules.none { it.enabled }) {
            // Fail closed if no ruleset configured for tenant
            return WafInspectionResult(
                action = WafAction.BLOCK,
                matchedRuleId = "fail-closed-no-ruleset",
                blockReason = "FAIL_CLOSED: No active WAF ruleset found for tenant",
                isAllowed = false,
            )
        }

        return try {
            wafProvider.inspect(request)
        } catch (e: Exception) {
            // Fail closed on provider outage
            WafInspectionResult(
                action = WafAction.BLOCK,
                matchedRuleId = "fail-closed-provider-outage",
                blockReason = "FAIL_CLOSED: WAF provider error ${e.message}",
                isAllowed = false,
            )
        }
    }

    /**
     * Test and record emergency WAF procedures (e.g. emergency ruleset rollback, under-attack mode).
     */
    fun recordEmergencyProcedure(
        tenantId: String,
        actionType: WafEmergencyActionType,
        success: Boolean,
        verificationEvidence: String,
        principal: AuthenticatedPrincipal,
        idempotencyKey: String,
    ): Result<WafEmergencyRecord> {
        EnforceWafPolicyBinding.checkBound()

        if (principal.tenantId != tenantId) {
            recordAudit(tenantId, "WAF_EMERGENCY", principal, false, "CROSS_TENANT_FORBIDDEN")
            return Result.failure(SecurityException("CROSS_TENANT_FORBIDDEN: Principal does not belong to tenant $tenantId"))
        }

        if (!principal.roles.contains(AdminRole.SUPER_ADMIN) && !principal.roles.contains(AdminRole.SECURITY)) {
            recordAudit(tenantId, "WAF_EMERGENCY", principal, false, "FORBIDDEN")
            return Result.failure(SecurityException("FORBIDDEN: Insufficient permissions for WAF emergency procedures"))
        }

        val payloadHash = sha256("$tenantId:$actionType:$success:$verificationEvidence")
        val cached = idempotencyStore[idempotencyKey]
        if (cached != null) {
            if (cached.first == payloadHash) {
                @Suppress("UNCHECKED_CAST")
                return Result.success(cached.second as WafEmergencyRecord)
            } else {
                return Result.failure(IllegalArgumentException("CONFLICT: Idempotency key reused with different payload"))
            }
        }

        val record = WafEmergencyRecord(
            emergencyId = "waf-emerg-${UUID.randomUUID()}",
            tenantId = tenantId,
            actionType = actionType,
            executedAt = clock.instant(),
            executedBy = principal.id,
            success = success,
            verificationEvidence = verificationEvidence,
        )

        emergencyStore[record.emergencyId] = record
        idempotencyStore[idempotencyKey] = Pair(payloadHash, record)
        recordAudit(tenantId, "WAF_EMERGENCY", principal, success, "WAF Emergency procedure ${record.emergencyId} type $actionType success=$success")

        return Result.success(record)
    }

    /**
     * Authoritative readiness evaluation for WAF policy enforcement.
     * Evaluates that:
     * 1. Enabled ruleset exists.
     * 2. Emergency procedures have been successfully tested.
     * Semantic contract: "Rate limits never become financial authority; emergency procedures tested."
     */
    fun evaluateWafPolicyReadiness(
        tenantId: String,
        principal: AuthenticatedPrincipal,
    ): WafPolicyEvaluation {
        EnforceWafPolicyBinding.checkBound()

        val ruleset = rulesetStore[tenantId]
        val activeRules = ruleset?.rules?.filter { it.enabled } ?: emptyList()
        val testedEmergencies = emergencyStore.values.filter { it.tenantId == tenantId && it.success }

        val hasTestedEmergencyProcedures = testedEmergencies.isNotEmpty()

        val decision: WafDecision
        val reason: WafReason

        if (ruleset == null || activeRules.isEmpty()) {
            decision = WafDecision.NO_GO
            reason = WafReason.ROTATION_ABUSE_BYPASS_SCENARIOS
        } else if (!hasTestedEmergencyProcedures) {
            decision = WafDecision.NO_GO
            reason = WafReason.EMERGENCY_PROCEDURES_UNTESTED
        } else {
            decision = WafDecision.GO
            reason = WafReason.WAF_POLICY_ACTIVE_AND_EMERGENCY_TESTED
        }

        val evidenceRef = sha256("$tenantId:${activeRules.size}:$hasTestedEmergencyProcedures:$decision")

        return WafPolicyEvaluation(
            tenantId = tenantId,
            status = decision,
            reason = reason,
            activeRulesCount = activeRules.size,
            emergencyProceduresTested = hasTestedEmergencyProcedures,
            directEligibilityGranted = false, // Financial rule: never grants financial authority
            financialMutationPermitted = false, // Financial rule: never mutates money
            message = "Rate limits never become financial authority; emergency procedures tested.",
            evidenceReference = evidenceRef,
        )
    }

    @Synchronized
    private fun recordAudit(tenantId: String, action: String, principal: AuthenticatedPrincipal, success: Boolean, details: String) {
        val entry = WafAuditEntry(
            auditId = UUID.randomUUID(),
            tenantId = tenantId,
            action = action,
            principalId = principal.id,
            roles = principal.roles,
            timestamp = clock.instant(),
            success = success,
            detailsRedacted = details,
        )
        auditLog.add(entry)
    }

    fun getAuditLog(tenantId: String): List<WafAuditEntry> {
        return synchronized(this) {
            auditLog.filter { it.tenantId == tenantId }
        }
    }

    private fun sha256(input: String): String {
        val digest = MessageDigest.getInstance("SHA-256")
        return digest.digest(input.toByteArray(Charsets.UTF_8))
            .joinToString("") { "%02x".format(it) }
    }
}
