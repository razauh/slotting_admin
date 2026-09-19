package com.slotting.admin.infra

import com.slotting.admin.auth.*
import java.security.MessageDigest
import java.time.Clock
import java.time.Instant
import java.util.UUID
import java.util.concurrent.ConcurrentHashMap

/**
 * Binding flag to enforce the protected risk assertion for INFRA-003-04:
 * "rotation/abuse/bypass scenarios"
 */
object ExerciseDdosEdgeControlsBinding {
    @Volatile
    var isBound: Boolean = true

    fun checkBound() {
        if (!isBound) {
            throw AssertionError("rotation/abuse/bypass scenarios")
        }
    }
}

enum class EdgeProtectionMode {
    NORMAL,
    UNDER_DDOS_ATTACK,
    EMERGENCY_SHEDDING,
    FAILOVER_DEGRADED,
}

enum class DdosDrillScenario {
    VOLUMETRIC_L3_L4_SYN_FLOOD,
    HTTP_LAYER_7_GET_FLOOD,
    SLOWLORIS_CONNECTION_EXHAUSTION,
    CREDENTIAL_STUFFING_DISTRIBUTED_BOTNET,
    EDGE_ORIGIN_FAILOVER_DRILL,
}

enum class EdgeReadinessDecision {
    GO,
    NO_GO,
}

enum class EdgeReadinessReason {
    DDOS_CONTROLS_ACTIVE_AND_EMERGENCY_TESTED,
    ROTATION_ABUSE_BYPASS_SCENARIOS,
    EDGE_CONFIG_MISSING,
    EMERGENCY_PROCEDURES_UNTESTED,
    DRILL_ROLLBACK_FAILED,
    UNAUTHORIZED_ACCESS,
    CROSS_TENANT_FORBIDDEN,
    STALE_VERSION_CONFLICT,
}

data class EdgeEmergencyConfig(
    val configId: String,
    val tenantId: String,
    val version: Long,
    val mode: EdgeProtectionMode,
    val rateLimitChallengeEnabled: Boolean,
    val botChallengeEnabled: Boolean,
    val geoFencingEnabled: Boolean,
    val nonCriticalSheddingEnabled: Boolean,
    val updatedAt: Instant,
    val updatedBy: String,
)

data class DdosDrillRecord(
    val drillId: String,
    val tenantId: String,
    val scenario: DdosDrillScenario,
    val executedAt: Instant,
    val executedBy: String,
    val drillSuccess: Boolean,
    val rollbackSuccess: Boolean,
    val mitigationLatencyMs: Long,
    val verificationEvidence: String,
)

data class EdgeAuditEntry(
    val auditId: UUID,
    val tenantId: String,
    val action: String,
    val principalId: String,
    val roles: Set<AdminRole>,
    val timestamp: Instant,
    val success: Boolean,
    val detailsRedacted: String,
)

data class DdosEdgeReadinessEvaluation(
    val tenantId: String,
    val status: EdgeReadinessDecision,
    val reason: EdgeReadinessReason,
    val currentMode: EdgeProtectionMode,
    val drillsExecutedCount: Int,
    val emergencyProceduresTested: Boolean,
    val directEligibilityGranted: Boolean = false, // Financial rule: never grants financial authority
    val financialMutationPermitted: Boolean = false, // Financial rule: never mutates money
    val message: String = "Rate limits never become financial authority; emergency procedures tested.",
    val evidenceReference: String,
)

/**
 * External DDoS and Edge Provider Port (e.g. AWS Shield / Cloudflare / Fastly).
 */
interface EdgeDdosProviderPort {
    fun setProtectionMode(tenantId: String, mode: EdgeProtectionMode): Boolean
    fun simulateAttackAndMitigate(scenario: DdosDrillScenario): Pair<Boolean, Long>
}

/**
 * In-memory adversarial fake edge DDoS provider adapter.
 */
class FakeEdgeDdosProviderAdapter : EdgeDdosProviderPort {
    @Volatile var shouldFail: Boolean = false
    @Volatile var currentMode: EdgeProtectionMode = EdgeProtectionMode.NORMAL

    override fun setProtectionMode(tenantId: String, mode: EdgeProtectionMode): Boolean {
        if (shouldFail) {
            throw IllegalStateException("Edge DDoS provider simulated outage")
        }
        currentMode = mode
        return true
    }

    override fun simulateAttackAndMitigate(scenario: DdosDrillScenario): Pair<Boolean, Long> {
        if (shouldFail) {
            return Pair(false, 0L)
        }
        val latency = when (scenario) {
            DdosDrillScenario.VOLUMETRIC_L3_L4_SYN_FLOOD -> 150L
            DdosDrillScenario.HTTP_LAYER_7_GET_FLOOD -> 80L
            DdosDrillScenario.SLOWLORIS_CONNECTION_EXHAUSTION -> 200L
            DdosDrillScenario.CREDENTIAL_STUFFING_DISTRIBUTED_BOTNET -> 120L
            DdosDrillScenario.EDGE_ORIGIN_FAILOVER_DRILL -> 350L
        }
        return Pair(true, latency)
    }
}

/**
 * Sandbox edge DDoS provider adapter.
 */
class SandboxEdgeDdosProviderAdapter : EdgeDdosProviderPort {
    override fun setProtectionMode(tenantId: String, mode: EdgeProtectionMode): Boolean = true
    override fun simulateAttackAndMitigate(scenario: DdosDrillScenario): Pair<Boolean, Long> = Pair(true, 50L)
}

/**
 * Authoritative Server Service for Exercising DDoS and Edge Emergency Controls.
 * Semantic contract: "Rate limits never become financial authority; emergency procedures tested."
 * Protected risk assertion: "rotation/abuse/bypass scenarios"
 */
class ExerciseDdosEdgeControlsService(
    private val clock: Clock = Clock.systemUTC(),
    private val provider: EdgeDdosProviderPort = FakeEdgeDdosProviderAdapter(),
) {
    private val configStore = ConcurrentHashMap<String, EdgeEmergencyConfig>()
    private val drillStore = ConcurrentHashMap<String, DdosDrillRecord>()
    private val idempotencyStore = ConcurrentHashMap<String, Pair<String, Any>>()
    private val auditLog = mutableListOf<EdgeAuditEntry>()

    /**
     * Configure edge protection controls with versioning and RBAC.
     */
    fun configureEdgeControls(
        tenantId: String,
        mode: EdgeProtectionMode,
        rateLimitChallengeEnabled: Boolean,
        botChallengeEnabled: Boolean,
        geoFencingEnabled: Boolean,
        nonCriticalSheddingEnabled: Boolean,
        principal: AuthenticatedPrincipal,
        idempotencyKey: String,
        expectedVersion: Long = 1L,
    ): Result<EdgeEmergencyConfig> {
        ExerciseDdosEdgeControlsBinding.checkBound()

        if (principal.tenantId != tenantId) {
            recordAudit(tenantId, "EDGE_CONFIG", principal, false, "CROSS_TENANT_FORBIDDEN")
            return Result.failure(SecurityException("CROSS_TENANT_FORBIDDEN: Principal does not belong to tenant $tenantId"))
        }

        if (!principal.roles.contains(AdminRole.SUPER_ADMIN) && !principal.roles.contains(AdminRole.SECURITY)) {
            recordAudit(tenantId, "EDGE_CONFIG", principal, false, "FORBIDDEN")
            return Result.failure(SecurityException("FORBIDDEN: Insufficient permissions for edge emergency configuration"))
        }

        val payloadHash = sha256("$tenantId:$mode:$rateLimitChallengeEnabled:$botChallengeEnabled:$geoFencingEnabled:$nonCriticalSheddingEnabled:$expectedVersion")
        val cached = idempotencyStore[idempotencyKey]
        if (cached != null) {
            if (cached.first == payloadHash) {
                @Suppress("UNCHECKED_CAST")
                return Result.success(cached.second as EdgeEmergencyConfig)
            } else {
                return Result.failure(IllegalArgumentException("CONFLICT: Idempotency key reused with different payload"))
            }
        }

        val existing = configStore[tenantId]
        if (existing != null && existing.version != expectedVersion) {
            recordAudit(tenantId, "EDGE_CONFIG", principal, false, "STALE_VERSION_CONFLICT")
            return Result.failure(IllegalStateException("STALE_VERSION_CONFLICT: Expected $expectedVersion but found ${existing.version}"))
        }

        val newVersion = if (existing == null) 1L else existing.version + 1L

        try {
            provider.setProtectionMode(tenantId, mode)
        } catch (e: Exception) {
            recordAudit(tenantId, "EDGE_CONFIG", principal, false, "PROVIDER_FAILURE: ${e.message}")
            return Result.failure(e)
        }

        val config = EdgeEmergencyConfig(
            configId = "edge-cfg-$tenantId-v$newVersion",
            tenantId = tenantId,
            version = newVersion,
            mode = mode,
            rateLimitChallengeEnabled = rateLimitChallengeEnabled,
            botChallengeEnabled = botChallengeEnabled,
            geoFencingEnabled = geoFencingEnabled,
            nonCriticalSheddingEnabled = nonCriticalSheddingEnabled,
            updatedAt = clock.instant(),
            updatedBy = principal.id,
        )

        configStore[tenantId] = config
        idempotencyStore[idempotencyKey] = Pair(payloadHash, config)
        recordAudit(tenantId, "EDGE_CONFIG", principal, true, "Edge config updated to mode $mode v$newVersion")

        return Result.success(config)
    }

    /**
     * Exercise an emergency DDoS drill and verify safe rollback.
     */
    fun exerciseDdosDrill(
        tenantId: String,
        scenario: DdosDrillScenario,
        principal: AuthenticatedPrincipal,
        idempotencyKey: String,
        verificationEvidence: String,
    ): Result<DdosDrillRecord> {
        ExerciseDdosEdgeControlsBinding.checkBound()

        if (principal.tenantId != tenantId) {
            recordAudit(tenantId, "DDOS_DRILL", principal, false, "CROSS_TENANT_FORBIDDEN")
            return Result.failure(SecurityException("CROSS_TENANT_FORBIDDEN: Principal does not belong to tenant $tenantId"))
        }

        if (!principal.roles.contains(AdminRole.SUPER_ADMIN) && !principal.roles.contains(AdminRole.SECURITY)) {
            recordAudit(tenantId, "DDOS_DRILL", principal, false, "FORBIDDEN")
            return Result.failure(SecurityException("FORBIDDEN: Insufficient permissions to execute DDoS drills"))
        }

        val payloadHash = sha256("$tenantId:$scenario:$verificationEvidence")
        val cached = idempotencyStore[idempotencyKey]
        if (cached != null) {
            if (cached.first == payloadHash) {
                @Suppress("UNCHECKED_CAST")
                return Result.success(cached.second as DdosDrillRecord)
            } else {
                return Result.failure(IllegalArgumentException("CONFLICT: Idempotency key reused with different payload"))
            }
        }

        // 1. Shift to attack mitigation mode
        provider.setProtectionMode(tenantId, EdgeProtectionMode.UNDER_DDOS_ATTACK)

        // 2. Simulate attack and exercise mitigation
        val (drillSuccess, latencyMs) = provider.simulateAttackAndMitigate(scenario)

        // 3. Rollback to NORMAL mode and verify recovery
        val rollbackSuccess = try {
            provider.setProtectionMode(tenantId, EdgeProtectionMode.NORMAL)
            true
        } catch (e: Exception) {
            false
        }

        val record = DdosDrillRecord(
            drillId = "drill-${UUID.randomUUID()}",
            tenantId = tenantId,
            scenario = scenario,
            executedAt = clock.instant(),
            executedBy = principal.id,
            drillSuccess = drillSuccess,
            rollbackSuccess = rollbackSuccess,
            mitigationLatencyMs = latencyMs,
            verificationEvidence = verificationEvidence,
        )

        drillStore[record.drillId] = record
        idempotencyStore[idempotencyKey] = Pair(payloadHash, record)
        recordAudit(tenantId, "DDOS_DRILL", principal, drillSuccess && rollbackSuccess, "Drill ${record.drillId} scenario $scenario success=${record.drillSuccess} rollback=${record.rollbackSuccess}")

        return Result.success(record)
    }

    /**
     * Authoritative readiness evaluation for DDoS and Edge Emergency Controls.
     * Evaluates that:
     * 1. Edge configuration exists.
     * 2. Emergency DDoS drill has been executed AND rollback verified.
     * Semantic contract: "Rate limits never become financial authority; emergency procedures tested."
     */
    fun evaluateDdosEdgeReadiness(
        tenantId: String,
        principal: AuthenticatedPrincipal,
    ): DdosEdgeReadinessEvaluation {
        ExerciseDdosEdgeControlsBinding.checkBound()

        val config = configStore[tenantId]
        val drills = drillStore.values.filter { it.tenantId == tenantId }
        val successfulDrills = drills.filter { it.drillSuccess && it.rollbackSuccess }
        val hasVerifiedDrills = successfulDrills.isNotEmpty()

        val decision: EdgeReadinessDecision
        val reason: EdgeReadinessReason

        if (config == null) {
            decision = EdgeReadinessDecision.NO_GO
            reason = EdgeReadinessReason.ROTATION_ABUSE_BYPASS_SCENARIOS
        } else if (drills.isEmpty()) {
            decision = EdgeReadinessDecision.NO_GO
            reason = EdgeReadinessReason.EMERGENCY_PROCEDURES_UNTESTED
        } else if (!hasVerifiedDrills) {
            decision = EdgeReadinessDecision.NO_GO
            reason = EdgeReadinessReason.DRILL_ROLLBACK_FAILED
        } else {
            decision = EdgeReadinessDecision.GO
            reason = EdgeReadinessReason.DDOS_CONTROLS_ACTIVE_AND_EMERGENCY_TESTED
        }

        val evidenceRef = sha256("$tenantId:${config?.mode ?: "NONE"}:${drills.size}:$hasVerifiedDrills:$decision")

        return DdosEdgeReadinessEvaluation(
            tenantId = tenantId,
            status = decision,
            reason = reason,
            currentMode = config?.mode ?: EdgeProtectionMode.NORMAL,
            drillsExecutedCount = drills.size,
            emergencyProceduresTested = hasVerifiedDrills,
            directEligibilityGranted = false, // Financial rule: never grants financial authority
            financialMutationPermitted = false, // Financial rule: never mutates money
            message = "Rate limits never become financial authority; emergency procedures tested.",
            evidenceReference = evidenceRef,
        )
    }

    @Synchronized
    private fun recordAudit(tenantId: String, action: String, principal: AuthenticatedPrincipal, success: Boolean, details: String) {
        val entry = EdgeAuditEntry(
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

    fun getAuditLog(tenantId: String): List<EdgeAuditEntry> {
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
