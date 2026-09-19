package com.slotting.admin.infra

import com.slotting.admin.auth.*
import java.security.MessageDigest
import java.time.Clock
import java.time.Instant
import java.util.UUID
import java.util.concurrent.ConcurrentHashMap

/**
 * Binding flag to enforce the protected risk assertion for INFRA-002-03:
 * "failover/restore/migration partial"
 */
object AutomateCompatibleFlywayBinding {
    @Volatile
    var isBound: Boolean = true

    fun checkBound() {
        if (!isBound) {
            throw AssertionError("failover/restore/migration partial")
        }
    }
}

enum class FlywayMigrationState {
    PENDING,
    APPLIED,
    FAILED,
    PARTIAL,
    COMPENSATED,
}

enum class FlywayDeployDecision {
    GO,
    NO_GO,
}

enum class FlywayDeployReason {
    MIGRATION_SUCCESS_AND_RECONCILED,
    FAILOVER_RESTORE_MIGRATION_PARTIAL,
    CHECKSUM_MISMATCH,
    VERSION_OUT_OF_ORDER,
    MISSING_PRE_MIGRATION_BACKUP,
    MIGRATION_FAILED,
    UNAUTHORIZED_ACCESS,
}

data class FlywayScriptDescriptor(
    val version: Int,
    val description: String,
    val scriptName: String,
    val checksumSha256: String,
    val isTransactional: Boolean = true,
)

data class FlywayMigrationEntry(
    val deploymentId: UUID,
    val tenantId: String,
    val environment: IacEnvironmentType,
    val preMigrationBackupId: UUID,
    val currentVersion: Int,
    val targetVersion: Int,
    val appliedScripts: List<FlywayScriptDescriptor>,
    val state: FlywayMigrationState,
    val reconciliation: ReconciliationEvidence,
    val evidenceReference: String,
    val version: Long = 1L,
    val deployedAt: Instant,
    val deployedBy: String,
)

data class DeployFlywayMigrationCommand(
    val principal: AuthenticatedPrincipal?,
    val sessionId: String,
    val tenantId: String,
    val environment: IacEnvironmentType,
    val preMigrationBackupId: UUID,
    val scriptsToApply: List<FlywayScriptDescriptor>,
    val reconciliation: ReconciliationEvidence,
    val idempotencyKey: String,
    val correlationId: String,
    val causationId: String,
    val expectedVersion: Long = 1L,
)

data class EvaluateFlywayDeploymentCommand(
    val tenantId: String,
    val deploymentId: UUID,
    val correlationId: String,
    val causationId: String,
)

data class FlywayDeployResult(
    val resultId: UUID,
    val tenantId: String,
    val deploymentId: UUID,
    val currentVersion: Int,
    val state: FlywayMigrationState,
    val reconciliationStatus: ReconciliationStatus,
    val directEligibilityGranted: Boolean = false,
    val financialMutationPermitted: Boolean = false,
    val evidenceReference: String,
    val serverTime: Instant,
    val correlationId: String,
    val causationId: String,
)

data class FlywayEvaluationResult(
    val decision: FlywayDeployDecision,
    val reason: FlywayDeployReason,
    val deploymentId: UUID,
    val currentVersion: Int,
    val state: FlywayMigrationState,
    val directEligibilityGranted: Boolean = false,
    val financialMutationPermitted: Boolean = false,
    val evidenceReference: String,
    val evaluatedAt: Instant,
)

interface FlywayDeploymentStore {
    fun findByIdempotency(tenantId: String, idempotencyKey: String): Pair<String, FlywayDeployResult>?
    fun findDeployment(tenantId: String, deploymentId: UUID): FlywayMigrationEntry?
    fun findCurrentDeploymentByEnvironment(tenantId: String, environment: IacEnvironmentType): FlywayMigrationEntry?
    fun saveDeployment(
        entry: FlywayMigrationEntry,
        result: FlywayDeployResult,
        idempotencyFingerprint: String,
        idempotencyKey: String,
        audit: AuditEvent,
        outbox: OutboxEvent,
    )
    fun updateDeployment(
        entry: FlywayMigrationEntry,
        result: FlywayDeployResult,
        idempotencyFingerprint: String,
        idempotencyKey: String,
        audit: AuditEvent,
        outbox: OutboxEvent,
    ): FlywayMigrationEntry
}

class InMemoryFlywayDeploymentStore : FlywayDeploymentStore {
    val deployments = ConcurrentHashMap<String, FlywayMigrationEntry>()
    val deploymentsByEnv = ConcurrentHashMap<String, FlywayMigrationEntry>()
    val results = ConcurrentHashMap<String, Pair<String, FlywayDeployResult>>()
    val audit = mutableListOf<AuditEvent>()
    val outbox = mutableListOf<OutboxEvent>()

    @Synchronized
    override fun findByIdempotency(tenantId: String, idempotencyKey: String): Pair<String, FlywayDeployResult>? =
        results["$tenantId:$idempotencyKey"]

    @Synchronized
    override fun findDeployment(tenantId: String, deploymentId: UUID): FlywayMigrationEntry? =
        deployments["$tenantId:$deploymentId"]

    @Synchronized
    override fun findCurrentDeploymentByEnvironment(tenantId: String, environment: IacEnvironmentType): FlywayMigrationEntry? =
        deploymentsByEnv["$tenantId:${environment.name}"]

    @Synchronized
    override fun saveDeployment(
        entry: FlywayMigrationEntry,
        result: FlywayDeployResult,
        idempotencyFingerprint: String,
        idempotencyKey: String,
        audit: AuditEvent,
        outbox: OutboxEvent,
    ) {
        deployments["${entry.tenantId}:${entry.deploymentId}"] = entry
        deploymentsByEnv["${entry.tenantId}:${entry.environment.name}"] = entry
        results["${entry.tenantId}:$idempotencyKey"] = idempotencyFingerprint to result
        this.audit.add(audit)
        this.outbox.add(outbox)
    }

    @Synchronized
    override fun updateDeployment(
        entry: FlywayMigrationEntry,
        result: FlywayDeployResult,
        idempotencyFingerprint: String,
        idempotencyKey: String,
        audit: AuditEvent,
        outbox: OutboxEvent,
    ): FlywayMigrationEntry {
        val existing = deployments["${entry.tenantId}:${entry.deploymentId}"]
            ?: throw AuthenticationFailure.Rejected(AuthErrorCode.INVALID)
        if (existing.version != entry.version - 1) {
            throw AuthenticationFailure.Rejected(AuthErrorCode.CONFLICT)
        }
        deployments["${entry.tenantId}:${entry.deploymentId}"] = entry
        deploymentsByEnv["${entry.tenantId}:${entry.environment.name}"] = entry
        results["${entry.tenantId}:$idempotencyKey"] = idempotencyFingerprint to result
        this.audit.add(audit)
        this.outbox.add(outbox)
        return entry
    }
}

class AutomateCompatibleFlywayService(
    private val sessions: AdminSessionDirectory,
    private val pitrBackupStore: EncryptedPitrBackupStore,
    private val store: FlywayDeploymentStore,
    private val clock: Clock,
) {
    @Synchronized
    fun deployMigration(command: DeployFlywayMigrationCommand): FlywayDeployResult {
        AutomateCompatibleFlywayBinding.checkBound()

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

        // Validate prerequisite: PITR backup must exist before schema migration
        val backup = pitrBackupStore.findBackup(command.tenantId, command.preMigrationBackupId)
            ?: throw AuthenticationFailure.Rejected(AuthErrorCode.INVALID)

        if (backup.status != BackupStatus.COMPLETED) {
            throw AuthenticationFailure.Rejected(AuthErrorCode.INVALID)
        }

        // Validate script list not empty
        if (command.scriptsToApply.isEmpty()) {
            throw AuthenticationFailure.Rejected(AuthErrorCode.INVALID)
        }

        // Validate versions are strictly ascending and checksums are 64-char hex
        var previousVersion = 0
        for (script in command.scriptsToApply) {
            if (script.version <= previousVersion) {
                throw AuthenticationFailure.Rejected(AuthErrorCode.INVALID)
            }
            if (script.checksumSha256.length != 64 || script.scriptName.isBlank()) {
                throw AuthenticationFailure.Rejected(AuthErrorCode.INVALID)
            }
            previousVersion = script.version
        }

        val fp = fingerprintDeployCommand(command)
        store.findByIdempotency(command.tenantId, command.idempotencyKey)?.let { (cachedFp, cachedResult) ->
            if (cachedFp != fp) throw AuthenticationFailure.Rejected(AuthErrorCode.CONFLICT)
            return cachedResult
        }

        val now = clock.instant()
        val deploymentId = UUID.randomUUID()
        val resultId = UUID.randomUUID()
        val evidenceRef = "FLYWAY-DEPLOY-${command.tenantId}-${command.environment.name}-$deploymentId"

        val migrationState = when {
            command.reconciliation.isFullyReconciled -> FlywayMigrationState.APPLIED
            command.reconciliation.isPartial -> FlywayMigrationState.PARTIAL
            else -> FlywayMigrationState.FAILED
        }

        val targetVersion = command.scriptsToApply.last().version

        val entry = FlywayMigrationEntry(
            deploymentId = deploymentId,
            tenantId = command.tenantId,
            environment = command.environment,
            preMigrationBackupId = command.preMigrationBackupId,
            currentVersion = targetVersion,
            targetVersion = targetVersion,
            appliedScripts = command.scriptsToApply,
            state = migrationState,
            reconciliation = command.reconciliation,
            evidenceReference = evidenceRef,
            version = 1L,
            deployedAt = now,
            deployedBy = principal.id,
        )

        val reconciliationStatus = when (migrationState) {
            FlywayMigrationState.APPLIED -> ReconciliationStatus.RECONCILED
            FlywayMigrationState.PARTIAL -> ReconciliationStatus.PARTIAL
            else -> ReconciliationStatus.UNRECONCILED
        }

        val result = FlywayDeployResult(
            resultId = resultId,
            tenantId = command.tenantId,
            deploymentId = deploymentId,
            currentVersion = targetVersion,
            state = migrationState,
            reconciliationStatus = reconciliationStatus,
            directEligibilityGranted = false,
            financialMutationPermitted = false,
            evidenceReference = evidenceRef,
            serverTime = now,
            correlationId = command.correlationId,
            causationId = command.causationId,
        )

        val audit = AuditEvent(
            eventId = UUID.randomUUID(),
            resultId = resultId,
            tenantId = command.tenantId,
            type = if (migrationState == FlywayMigrationState.APPLIED) "FLYWAY_MIGRATION_DEPLOYED" else "FLYWAY_MIGRATION_PARTIAL",
            occurredAt = now,
            correlationId = command.correlationId,
            causationId = command.causationId,
        )

        val outbox = OutboxEvent(
            eventId = UUID.randomUUID(),
            resultId = resultId,
            tenantId = command.tenantId,
            type = if (migrationState == FlywayMigrationState.APPLIED) "FlywayMigrationDeployed" else "FlywayMigrationPartial",
            createdAt = now,
        )

        store.saveDeployment(entry, result, fp, command.idempotencyKey, audit, outbox)
        return result
    }

    @Synchronized
    fun evaluateFlywayDeployment(command: EvaluateFlywayDeploymentCommand): FlywayEvaluationResult {
        AutomateCompatibleFlywayBinding.checkBound()

        val now = clock.instant()
        val entry = store.findDeployment(command.tenantId, command.deploymentId)

        if (entry == null) {
            return FlywayEvaluationResult(
                decision = FlywayDeployDecision.NO_GO,
                reason = FlywayDeployReason.MIGRATION_FAILED,
                deploymentId = command.deploymentId,
                currentVersion = 0,
                state = FlywayMigrationState.FAILED,
                directEligibilityGranted = false,
                financialMutationPermitted = false,
                evidenceReference = "EVID-FLYWAY-MISSING-${command.deploymentId}",
                evaluatedAt = now,
            )
        }

        if (entry.state != FlywayMigrationState.APPLIED || !entry.reconciliation.isFullyReconciled) {
            return FlywayEvaluationResult(
                decision = FlywayDeployDecision.NO_GO,
                reason = FlywayDeployReason.FAILOVER_RESTORE_MIGRATION_PARTIAL,
                deploymentId = entry.deploymentId,
                currentVersion = entry.currentVersion,
                state = entry.state,
                directEligibilityGranted = false,
                financialMutationPermitted = false,
                evidenceReference = entry.evidenceReference,
                evaluatedAt = now,
            )
        }

        return FlywayEvaluationResult(
            decision = FlywayDeployDecision.GO,
            reason = FlywayDeployReason.MIGRATION_SUCCESS_AND_RECONCILED,
            deploymentId = entry.deploymentId,
            currentVersion = entry.currentVersion,
            state = entry.state,
            directEligibilityGranted = false,
            financialMutationPermitted = false,
            evidenceReference = entry.evidenceReference,
            evaluatedAt = now,
        )
    }

    private fun fingerprintDeployCommand(command: DeployFlywayMigrationCommand): String {
        val raw = "${command.tenantId}|${command.environment.name}|${command.preMigrationBackupId}|" +
            "${command.scriptsToApply.size}|${command.reconciliation.journalReconciled}|" +
            "${command.reconciliation.projectionsReconciled}|${command.reconciliation.outboxReconciled}|" +
            "${command.expectedVersion}"
        val md = MessageDigest.getInstance("SHA-256")
        return md.digest(raw.toByteArray(Charsets.UTF_8)).joinToString("") { "%02x".format(it) }
    }
}
