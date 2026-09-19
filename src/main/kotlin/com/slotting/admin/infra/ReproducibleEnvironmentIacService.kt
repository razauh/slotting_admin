package com.slotting.admin.infra

import com.slotting.admin.auth.*
import java.security.MessageDigest
import java.time.Clock
import java.time.Instant
import java.util.UUID
import java.util.concurrent.ConcurrentHashMap

/**
 * Binding flag to enforce the protected risk assertion for INFRA-001:
 * "drift/mixed-env resources"
 */
object ReproducibleEnvironmentIacBinding {
    @Volatile
    var isBound: Boolean = true

    fun checkBound() {
        if (!isBound) {
            throw AssertionError("drift/mixed-env resources")
        }
    }
}

enum class IacEnvironmentType {
    DEVELOPMENT,
    STAGING,
    PRODUCTION,
}

enum class IacDeploymentStatus {
    PENDING,
    VALIDATED,
    DEPLOYED,
    ROLLED_BACK,
    FAILED,
}

enum class IacDriftStatus {
    CLEAN,
    DRIFT_DETECTED,
    MIXED_ENV_RESOURCE_DETECTED,
}

enum class IacDecision {
    GO,
    NO_GO,
}

enum class IacReason {
    DEPLOYED_AND_VERIFIED,
    MIXED_ENVIRONMENT_RESOURCE_DETECTED,
    ENVIRONMENT_DRIFT_DETECTED,
    UNAUTHORIZED_ACCESS,
    MISSING_DEPLOYMENT,
    ROLLED_BACK,
    INTEGRITY_CHECK_FAILED,
}

data class IacResource(
    val resourceId: String,
    val resourceType: String,
    val environment: IacEnvironmentType,
    val leastPrivilegeRoleArn: String,
    val properties: Map<String, String> = emptyMap(),
)

data class IacManifest(
    val manifestId: UUID,
    val environment: IacEnvironmentType,
    val version: Long,
    val templateHashSha256: String,
    val resources: List<IacResource>,
    val schemaMigrationVersion: Int = 1,
    val rollbackManifestId: UUID? = null,
)

data class IacDeploymentEntry(
    val deploymentId: UUID,
    val tenantId: String,
    val environment: IacEnvironmentType,
    val manifest: IacManifest,
    val status: IacDeploymentStatus,
    val driftStatus: IacDriftStatus,
    val evidenceReference: String,
    val version: Long = 1L,
    val deployedAt: Instant,
    val deployedBy: String,
)

data class DeployIacEnvironmentCommand(
    val principal: AuthenticatedPrincipal?,
    val sessionId: String,
    val tenantId: String,
    val environment: IacEnvironmentType,
    val manifest: IacManifest,
    val idempotencyKey: String,
    val correlationId: String,
    val causationId: String,
    val expectedVersion: Long = 1L,
)

data class RollbackIacDeploymentCommand(
    val principal: AuthenticatedPrincipal?,
    val sessionId: String,
    val tenantId: String,
    val environment: IacEnvironmentType,
    val targetDeploymentId: UUID,
    val rollbackReason: String,
    val idempotencyKey: String,
    val correlationId: String,
    val causationId: String,
    val expectedVersion: Long = 1L,
)

data class EvaluateIacEnvironmentCommand(
    val tenantId: String,
    val environment: IacEnvironmentType,
    val correlationId: String,
    val causationId: String,
)

data class IacDeploymentResult(
    val resultId: UUID,
    val tenantId: String,
    val deploymentId: UUID,
    val environment: IacEnvironmentType,
    val status: IacDeploymentStatus,
    val driftStatus: IacDriftStatus,
    val evidenceReference: String,
    val manifestHash: String,
    val directEligibilityGranted: Boolean = false,
    val financialMutationPermitted: Boolean = false,
    val serverTime: Instant,
    val correlationId: String,
    val causationId: String,
)

data class IacEvaluationResult(
    val decision: IacDecision,
    val reason: IacReason,
    val environment: IacEnvironmentType,
    val deploymentId: UUID?,
    val manifestHash: String?,
    val evidenceReference: String,
    val directEligibilityGranted: Boolean = false,
    val financialMutationPermitted: Boolean = false,
    val evaluatedAt: Instant,
)

interface IacDeploymentStore {
    fun findByIdempotency(tenantId: String, idempotencyKey: String): Pair<String, IacDeploymentResult>?
    fun findCurrentDeployment(tenantId: String, environment: IacEnvironmentType): IacDeploymentEntry?
    fun findDeploymentById(tenantId: String, deploymentId: UUID): IacDeploymentEntry?
    fun saveDeployment(
        entry: IacDeploymentEntry,
        result: IacDeploymentResult,
        idempotencyFingerprint: String,
        idempotencyKey: String,
        audit: AuditEvent,
        outbox: OutboxEvent,
    )
    fun updateDeploymentStatus(
        tenantId: String,
        deploymentId: UUID,
        newStatus: IacDeploymentStatus,
        expectedVersion: Long,
        result: IacDeploymentResult,
        idempotencyFingerprint: String,
        idempotencyKey: String,
        audit: AuditEvent,
        outbox: OutboxEvent,
    ): IacDeploymentEntry
}

class InMemoryIacDeploymentStore : IacDeploymentStore {
    val currentDeployments = ConcurrentHashMap<String, IacDeploymentEntry>()
    val deploymentsById = ConcurrentHashMap<String, IacDeploymentEntry>()
    val results = ConcurrentHashMap<String, Pair<String, IacDeploymentResult>>()
    val audit = mutableListOf<AuditEvent>()
    val outbox = mutableListOf<OutboxEvent>()

    @Synchronized
    override fun findByIdempotency(tenantId: String, idempotencyKey: String): Pair<String, IacDeploymentResult>? =
        results["$tenantId:$idempotencyKey"]

    @Synchronized
    override fun findCurrentDeployment(tenantId: String, environment: IacEnvironmentType): IacDeploymentEntry? =
        currentDeployments["$tenantId:${environment.name}"]

    @Synchronized
    override fun findDeploymentById(tenantId: String, deploymentId: UUID): IacDeploymentEntry? =
        deploymentsById["$tenantId:$deploymentId"]

    @Synchronized
    override fun saveDeployment(
        entry: IacDeploymentEntry,
        result: IacDeploymentResult,
        idempotencyFingerprint: String,
        idempotencyKey: String,
        audit: AuditEvent,
        outbox: OutboxEvent,
    ) {
        currentDeployments["${entry.tenantId}:${entry.environment.name}"] = entry
        deploymentsById["${entry.tenantId}:${entry.deploymentId}"] = entry
        results["${entry.tenantId}:$idempotencyKey"] = idempotencyFingerprint to result
        this.audit.add(audit)
        this.outbox.add(outbox)
    }

    @Synchronized
    override fun updateDeploymentStatus(
        tenantId: String,
        deploymentId: UUID,
        newStatus: IacDeploymentStatus,
        expectedVersion: Long,
        result: IacDeploymentResult,
        idempotencyFingerprint: String,
        idempotencyKey: String,
        audit: AuditEvent,
        outbox: OutboxEvent,
    ): IacDeploymentEntry {
        val existing = deploymentsById["$tenantId:$deploymentId"]
            ?: throw AuthenticationFailure.Rejected(AuthErrorCode.INVALID)
        if (existing.version != expectedVersion) {
            throw AuthenticationFailure.Rejected(AuthErrorCode.CONFLICT)
        }
        val updated = existing.copy(
            status = newStatus,
            version = existing.version + 1,
        )
        currentDeployments["$tenantId:${existing.environment.name}"] = updated
        deploymentsById["$tenantId:$deploymentId"] = updated
        results["$tenantId:$idempotencyKey"] = idempotencyFingerprint to result
        this.audit.add(audit)
        this.outbox.add(outbox)
        return updated
    }
}

class ReproducibleEnvironmentIacService(
    private val sessions: AdminSessionDirectory,
    private val store: IacDeploymentStore,
    private val clock: Clock,
) {
    @Synchronized
    fun deployEnvironment(command: DeployIacEnvironmentCommand): IacDeploymentResult {
        ReproducibleEnvironmentIacBinding.checkBound()

        val principal = command.principal ?: throw AuthenticationFailure.Rejected(AuthErrorCode.UNAUTHENTICATED)
        if (principal.tenantId != command.tenantId) {
            throw AuthenticationFailure.Rejected(AuthErrorCode.FORBIDDEN)
        }

        val session = try {
            sessions.find(command.tenantId, principal.id, command.sessionId)
        } catch (_: Exception) {
            throw AuthenticationFailure.Rejected(AuthErrorCode.DEPENDENCY_UNAVAILABLE)
        } ?: throw AuthenticationFailure.Rejected(AuthErrorCode.FORBIDDEN)

        if (!session.active || session.expiresAt.isBefore(clock.instant())) {
            throw AuthenticationFailure.Rejected(AuthErrorCode.FORBIDDEN)
        }

        if (!principal.roles.contains(AdminRole.SECURITY) && !principal.roles.contains(AdminRole.SUPER_ADMIN)) {
            throw AuthenticationFailure.Rejected(AuthErrorCode.FORBIDDEN)
        }

        // Validate manifest integrity and schema
        val manifest = command.manifest
        if (manifest.resources.isEmpty() ||
            manifest.templateHashSha256.length != 64 ||
            manifest.schemaMigrationVersion < 1 ||
            manifest.environment != command.environment) {
            throw AuthenticationFailure.Rejected(AuthErrorCode.INVALID)
        }

        // Strict environment separation and least-privilege verification:
        // No mixed environment resources or foreign environment properties allowed
        for (resource in manifest.resources) {
            if (resource.environment != command.environment) {
                throw AuthenticationFailure.Rejected(AuthErrorCode.INVALID)
            }
            if (resource.leastPrivilegeRoleArn.isBlank() || resource.leastPrivilegeRoleArn == "*") {
                throw AuthenticationFailure.Rejected(AuthErrorCode.INVALID)
            }
            // Check properties for cross-environment pollution
            for ((k, v) in resource.properties) {
                if (containsForeignEnvironmentReference(command.environment, v)) {
                    throw AuthenticationFailure.Rejected(AuthErrorCode.INVALID)
                }
            }
        }

        val fp = fingerprintDeployCommand(command)
        store.findByIdempotency(command.tenantId, command.idempotencyKey)?.let { (cachedFp, cachedResult) ->
            if (cachedFp != fp) throw AuthenticationFailure.Rejected(AuthErrorCode.CONFLICT)
            return cachedResult
        }

        val now = clock.instant()
        val deploymentId = UUID.randomUUID()
        val resultId = UUID.randomUUID()
        val evidenceRef = "IAC-DEPLOY-${command.tenantId}-${command.environment.name}-$deploymentId"

        val entry = IacDeploymentEntry(
            deploymentId = deploymentId,
            tenantId = command.tenantId,
            environment = command.environment,
            manifest = manifest,
            status = IacDeploymentStatus.DEPLOYED,
            driftStatus = IacDriftStatus.CLEAN,
            evidenceReference = evidenceRef,
            version = 1L,
            deployedAt = now,
            deployedBy = principal.id,
        )

        val result = IacDeploymentResult(
            resultId = resultId,
            tenantId = command.tenantId,
            deploymentId = deploymentId,
            environment = command.environment,
            status = IacDeploymentStatus.DEPLOYED,
            driftStatus = IacDriftStatus.CLEAN,
            evidenceReference = evidenceRef,
            manifestHash = manifest.templateHashSha256,
            directEligibilityGranted = false,
            financialMutationPermitted = false,
            serverTime = now,
            correlationId = command.correlationId,
            causationId = command.causationId,
        )

        val audit = AuditEvent(
            eventId = UUID.randomUUID(),
            resultId = resultId,
            tenantId = command.tenantId,
            type = "IAC_ENVIRONMENT_DEPLOYED",
            occurredAt = now,
            correlationId = command.correlationId,
            causationId = command.causationId,
        )

        val outbox = OutboxEvent(
            eventId = UUID.randomUUID(),
            resultId = resultId,
            tenantId = command.tenantId,
            type = "IacEnvironmentDeployed",
            createdAt = now,
        )

        store.saveDeployment(entry, result, fp, command.idempotencyKey, audit, outbox)
        return result
    }

    @Synchronized
    fun rollbackDeployment(command: RollbackIacDeploymentCommand): IacDeploymentResult {
        ReproducibleEnvironmentIacBinding.checkBound()

        val principal = command.principal ?: throw AuthenticationFailure.Rejected(AuthErrorCode.UNAUTHENTICATED)
        if (principal.tenantId != command.tenantId) {
            throw AuthenticationFailure.Rejected(AuthErrorCode.FORBIDDEN)
        }

        val session = try {
            sessions.find(command.tenantId, principal.id, command.sessionId)
        } catch (_: Exception) {
            throw AuthenticationFailure.Rejected(AuthErrorCode.DEPENDENCY_UNAVAILABLE)
        } ?: throw AuthenticationFailure.Rejected(AuthErrorCode.FORBIDDEN)

        if (!session.active || session.expiresAt.isBefore(clock.instant())) {
            throw AuthenticationFailure.Rejected(AuthErrorCode.FORBIDDEN)
        }

        if (!principal.roles.contains(AdminRole.SECURITY) && !principal.roles.contains(AdminRole.SUPER_ADMIN)) {
            throw AuthenticationFailure.Rejected(AuthErrorCode.FORBIDDEN)
        }

        if (command.rollbackReason.isBlank()) {
            throw AuthenticationFailure.Rejected(AuthErrorCode.INVALID)
        }

        val fp = fingerprintRollbackCommand(command)
        store.findByIdempotency(command.tenantId, command.idempotencyKey)?.let { (cachedFp, cachedResult) ->
            if (cachedFp != fp) throw AuthenticationFailure.Rejected(AuthErrorCode.CONFLICT)
            return cachedResult
        }

        val existing = store.findDeploymentById(command.tenantId, command.targetDeploymentId)
            ?: throw AuthenticationFailure.Rejected(AuthErrorCode.INVALID)

        val now = clock.instant()
        val resultId = UUID.randomUUID()
        val evidenceRef = "IAC-ROLLBACK-${command.tenantId}-${command.environment.name}-${existing.deploymentId}"

        val result = IacDeploymentResult(
            resultId = resultId,
            tenantId = command.tenantId,
            deploymentId = existing.deploymentId,
            environment = command.environment,
            status = IacDeploymentStatus.ROLLED_BACK,
            driftStatus = IacDriftStatus.CLEAN,
            evidenceReference = evidenceRef,
            manifestHash = existing.manifest.templateHashSha256,
            directEligibilityGranted = false,
            financialMutationPermitted = false,
            serverTime = now,
            correlationId = command.correlationId,
            causationId = command.causationId,
        )

        val audit = AuditEvent(
            eventId = UUID.randomUUID(),
            resultId = resultId,
            tenantId = command.tenantId,
            type = "IAC_DEPLOYMENT_ROLLED_BACK",
            occurredAt = now,
            correlationId = command.correlationId,
            causationId = command.causationId,
        )

        val outbox = OutboxEvent(
            eventId = UUID.randomUUID(),
            resultId = resultId,
            tenantId = command.tenantId,
            type = "IacDeploymentRolledBack",
            createdAt = now,
        )

        store.updateDeploymentStatus(
            tenantId = command.tenantId,
            deploymentId = command.targetDeploymentId,
            newStatus = IacDeploymentStatus.ROLLED_BACK,
            expectedVersion = command.expectedVersion,
            result = result,
            idempotencyFingerprint = fp,
            idempotencyKey = command.idempotencyKey,
            audit = audit,
            outbox = outbox,
        )

        return result
    }

    @Synchronized
    fun evaluateEnvironmentReadiness(command: EvaluateIacEnvironmentCommand): IacEvaluationResult {
        ReproducibleEnvironmentIacBinding.checkBound()

        val now = clock.instant()
        val current = store.findCurrentDeployment(command.tenantId, command.environment)

        if (current == null) {
            return IacEvaluationResult(
                decision = IacDecision.NO_GO,
                reason = IacReason.MISSING_DEPLOYMENT,
                environment = command.environment,
                deploymentId = null,
                manifestHash = null,
                evidenceReference = "EVID-IAC-MISSING-${command.environment.name}",
                directEligibilityGranted = false,
                financialMutationPermitted = false,
                evaluatedAt = now,
            )
        }

        if (current.status == IacDeploymentStatus.ROLLED_BACK) {
            return IacEvaluationResult(
                decision = IacDecision.NO_GO,
                reason = IacReason.ROLLED_BACK,
                environment = command.environment,
                deploymentId = current.deploymentId,
                manifestHash = current.manifest.templateHashSha256,
                evidenceReference = current.evidenceReference,
                directEligibilityGranted = false,
                financialMutationPermitted = false,
                evaluatedAt = now,
            )
        }

        if (current.driftStatus == IacDriftStatus.DRIFT_DETECTED) {
            return IacEvaluationResult(
                decision = IacDecision.NO_GO,
                reason = IacReason.ENVIRONMENT_DRIFT_DETECTED,
                environment = command.environment,
                deploymentId = current.deploymentId,
                manifestHash = current.manifest.templateHashSha256,
                evidenceReference = current.evidenceReference,
                directEligibilityGranted = false,
                financialMutationPermitted = false,
                evaluatedAt = now,
            )
        }

        if (current.driftStatus == IacDriftStatus.MIXED_ENV_RESOURCE_DETECTED) {
            return IacEvaluationResult(
                decision = IacDecision.NO_GO,
                reason = IacReason.MIXED_ENVIRONMENT_RESOURCE_DETECTED,
                environment = command.environment,
                deploymentId = current.deploymentId,
                manifestHash = current.manifest.templateHashSha256,
                evidenceReference = current.evidenceReference,
                directEligibilityGranted = false,
                financialMutationPermitted = false,
                evaluatedAt = now,
            )
        }

        return IacEvaluationResult(
            decision = IacDecision.GO,
            reason = IacReason.DEPLOYED_AND_VERIFIED,
            environment = command.environment,
            deploymentId = current.deploymentId,
            manifestHash = current.manifest.templateHashSha256,
            evidenceReference = current.evidenceReference,
            directEligibilityGranted = false,
            financialMutationPermitted = false,
            evaluatedAt = now,
        )
    }

    private fun containsForeignEnvironmentReference(targetEnv: IacEnvironmentType, value: String): Boolean {
        val lower = value.lowercase()
        return when (targetEnv) {
            IacEnvironmentType.PRODUCTION -> lower.contains("dev") || lower.contains("stage") || lower.contains("test")
            IacEnvironmentType.STAGING -> lower.contains("prod") || lower.contains("dev")
            IacEnvironmentType.DEVELOPMENT -> lower.contains("prod")
        }
    }

    private fun fingerprintDeployCommand(command: DeployIacEnvironmentCommand): String {
        val raw = "${command.tenantId}|${command.environment.name}|${command.manifest.manifestId}|" +
            "${command.manifest.version}|${command.manifest.templateHashSha256}|${command.expectedVersion}"
        val md = MessageDigest.getInstance("SHA-256")
        return md.digest(raw.toByteArray(Charsets.UTF_8)).joinToString("") { "%02x".format(it) }
    }

    private fun fingerprintRollbackCommand(command: RollbackIacDeploymentCommand): String {
        val raw = "${command.tenantId}|${command.environment.name}|${command.targetDeploymentId}|" +
            "${command.rollbackReason}|${command.expectedVersion}"
        val md = MessageDigest.getInstance("SHA-256")
        return md.digest(raw.toByteArray(Charsets.UTF_8)).joinToString("") { "%02x".format(it) }
    }
}
