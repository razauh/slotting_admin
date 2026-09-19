package com.slotting.admin.infra

import com.slotting.admin.auth.*
import java.security.MessageDigest
import java.time.Clock
import java.time.Instant
import java.util.UUID
import java.util.concurrent.ConcurrentHashMap

/**
 * Binding flag to enforce the protected risk assertion for INFRA-002-01:
 * "failover/restore/migration partial"
 */
object PostgresHighAvailabilityBinding {
    @Volatile
    var isBound: Boolean = true

    fun checkBound() {
        if (!isBound) {
            throw AssertionError("failover/restore/migration partial")
        }
    }
}

enum class NodeRole {
    PRIMARY,
    STANDBY_SYNC,
    STANDBY_ASYNC,
}

enum class NodeHealth {
    HEALTHY,
    DEGRADED,
    UNAVAILABLE,
}

enum class HaClusterState {
    PROVISIONED,
    FAILOVER_IN_PROGRESS,
    PROMOTED,
    RESTORE_RECONCILING,
    DEGRADED,
}

enum class ReconciliationStatus {
    RECONCILED,
    UNRECONCILED,
    PARTIAL,
}

enum class PostgresHaDecision {
    GO,
    NO_GO,
}

enum class PostgresHaReason {
    HA_ACTIVE_AND_RECONCILED,
    FAILOVER_RESTORE_MIGRATION_PARTIAL,
    RPO_RTO_TARGET_EXCEEDED,
    SPLIT_BRAIN_DETECTED,
    MISSING_PROVISIONING,
    NODE_UNAVAILABLE,
}

data class RpoRtoTarget(
    val maxRpoSeconds: Long,
    val maxRtoSeconds: Long,
    val approvedBy: String,
)

data class PostgresNode(
    val nodeId: String,
    val role: NodeRole,
    val endpoint: String,
    val health: NodeHealth,
    val replicationLagBytes: Long = 0L,
)

data class ReconciliationEvidence(
    val journalReconciled: Boolean,
    val projectionsReconciled: Boolean,
    val outboxReconciled: Boolean,
    val reconciledRowsCount: Long,
) {
    val isFullyReconciled: Boolean
        get() = journalReconciled && projectionsReconciled && outboxReconciled

    val isPartial: Boolean
        get() = (journalReconciled || projectionsReconciled || outboxReconciled) && !isFullyReconciled
}

data class PostgresHaClusterEntry(
    val clusterId: UUID,
    val tenantId: String,
    val environment: IacEnvironmentType,
    val nodes: List<PostgresNode>,
    val rpoRtoTarget: RpoRtoTarget,
    val state: HaClusterState,
    val reconciliation: ReconciliationEvidence,
    val evidenceReference: String,
    val version: Long = 1L,
    val updatedAt: Instant,
)

data class ProvisionPostgresHaCommand(
    val principal: AuthenticatedPrincipal?,
    val sessionId: String,
    val tenantId: String,
    val environment: IacEnvironmentType,
    val nodes: List<PostgresNode>,
    val rpoRtoTarget: RpoRtoTarget,
    val idempotencyKey: String,
    val correlationId: String,
    val causationId: String,
    val expectedVersion: Long = 1L,
)

data class ExecuteFailoverAndReconcileCommand(
    val principal: AuthenticatedPrincipal?,
    val sessionId: String,
    val tenantId: String,
    val clusterId: UUID,
    val targetPrimaryNodeId: String,
    val reconciliation: ReconciliationEvidence,
    val failoverReason: String,
    val idempotencyKey: String,
    val correlationId: String,
    val causationId: String,
    val expectedVersion: Long = 1L,
)

data class EvaluatePostgresHaCommand(
    val tenantId: String,
    val clusterId: UUID,
    val correlationId: String,
    val causationId: String,
)

data class PostgresHaOperationResult(
    val resultId: UUID,
    val tenantId: String,
    val clusterId: UUID,
    val state: HaClusterState,
    val reconciliationStatus: ReconciliationStatus,
    val directEligibilityGranted: Boolean = false,
    val financialMutationPermitted: Boolean = false,
    val evidenceReference: String,
    val serverTime: Instant,
    val correlationId: String,
    val causationId: String,
)

data class PostgresHaEvaluationResult(
    val decision: PostgresHaDecision,
    val reason: PostgresHaReason,
    val clusterId: UUID,
    val state: HaClusterState,
    val reconciliationStatus: ReconciliationStatus,
    val directEligibilityGranted: Boolean = false,
    val financialMutationPermitted: Boolean = false,
    val evidenceReference: String,
    val evaluatedAt: Instant,
)

interface PostgresHaStore {
    fun findByIdempotency(tenantId: String, idempotencyKey: String): Pair<String, PostgresHaOperationResult>?
    fun findCluster(tenantId: String, clusterId: UUID): PostgresHaClusterEntry?
    fun findClusterByEnvironment(tenantId: String, environment: IacEnvironmentType): PostgresHaClusterEntry?
    fun saveCluster(
        entry: PostgresHaClusterEntry,
        result: PostgresHaOperationResult,
        idempotencyFingerprint: String,
        idempotencyKey: String,
        audit: AuditEvent,
        outbox: OutboxEvent,
    )
    fun updateCluster(
        entry: PostgresHaClusterEntry,
        result: PostgresHaOperationResult,
        idempotencyFingerprint: String,
        idempotencyKey: String,
        audit: AuditEvent,
        outbox: OutboxEvent,
    ): PostgresHaClusterEntry
}

class InMemoryPostgresHaStore : PostgresHaStore {
    val clusters = ConcurrentHashMap<String, PostgresHaClusterEntry>()
    val clustersByEnv = ConcurrentHashMap<String, PostgresHaClusterEntry>()
    val results = ConcurrentHashMap<String, Pair<String, PostgresHaOperationResult>>()
    val audit = mutableListOf<AuditEvent>()
    val outbox = mutableListOf<OutboxEvent>()

    @Synchronized
    override fun findByIdempotency(tenantId: String, idempotencyKey: String): Pair<String, PostgresHaOperationResult>? =
        results["$tenantId:$idempotencyKey"]

    @Synchronized
    override fun findCluster(tenantId: String, clusterId: UUID): PostgresHaClusterEntry? =
        clusters["$tenantId:$clusterId"]

    @Synchronized
    override fun findClusterByEnvironment(tenantId: String, environment: IacEnvironmentType): PostgresHaClusterEntry? =
        clustersByEnv["$tenantId:${environment.name}"]

    @Synchronized
    override fun saveCluster(
        entry: PostgresHaClusterEntry,
        result: PostgresHaOperationResult,
        idempotencyFingerprint: String,
        idempotencyKey: String,
        audit: AuditEvent,
        outbox: OutboxEvent,
    ) {
        clusters["${entry.tenantId}:${entry.clusterId}"] = entry
        clustersByEnv["${entry.tenantId}:${entry.environment.name}"] = entry
        results["${entry.tenantId}:$idempotencyKey"] = idempotencyFingerprint to result
        this.audit.add(audit)
        this.outbox.add(outbox)
    }

    @Synchronized
    override fun updateCluster(
        entry: PostgresHaClusterEntry,
        result: PostgresHaOperationResult,
        idempotencyFingerprint: String,
        idempotencyKey: String,
        audit: AuditEvent,
        outbox: OutboxEvent,
    ): PostgresHaClusterEntry {
        val existing = clusters["${entry.tenantId}:${entry.clusterId}"]
            ?: throw AuthenticationFailure.Rejected(AuthErrorCode.INVALID)
        if (existing.version != entry.version - 1) {
            throw AuthenticationFailure.Rejected(AuthErrorCode.CONFLICT)
        }
        clusters["${entry.tenantId}:${entry.clusterId}"] = entry
        clustersByEnv["${entry.tenantId}:${entry.environment.name}"] = entry
        results["${entry.tenantId}:$idempotencyKey"] = idempotencyFingerprint to result
        this.audit.add(audit)
        this.outbox.add(outbox)
        return entry
    }
}

class PostgresHighAvailabilityService(
    private val sessions: AdminSessionDirectory,
    private val store: PostgresHaStore,
    private val clock: Clock,
) {
    @Synchronized
    fun provisionHaCluster(command: ProvisionPostgresHaCommand): PostgresHaOperationResult {
        PostgresHighAvailabilityBinding.checkBound()

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

        // Validation: HA topology requires at least 2 nodes (1 PRIMARY and at least 1 STANDBY)
        val primaryCount = command.nodes.count { it.role == NodeRole.PRIMARY }
        val standbyCount = command.nodes.count { it.role == NodeRole.STANDBY_SYNC || it.role == NodeRole.STANDBY_ASYNC }
        if (primaryCount != 1 || standbyCount < 1) {
            throw AuthenticationFailure.Rejected(AuthErrorCode.INVALID)
        }

        // Validate RPO/RTO targets
        if (command.rpoRtoTarget.maxRpoSeconds < 0 ||
            command.rpoRtoTarget.maxRtoSeconds <= 0 ||
            command.rpoRtoTarget.approvedBy.isBlank()) {
            throw AuthenticationFailure.Rejected(AuthErrorCode.INVALID)
        }

        // Validate all nodes are healthy at provisioning
        if (command.nodes.any { it.health != NodeHealth.HEALTHY }) {
            throw AuthenticationFailure.Rejected(AuthErrorCode.INVALID)
        }

        val fp = fingerprintProvisionCommand(command)
        store.findByIdempotency(command.tenantId, command.idempotencyKey)?.let { (cachedFp, cachedResult) ->
            if (cachedFp != fp) throw AuthenticationFailure.Rejected(AuthErrorCode.CONFLICT)
            return cachedResult
        }

        val now = clock.instant()
        val clusterId = UUID.randomUUID()
        val resultId = UUID.randomUUID()
        val evidenceRef = "HA-POSTGRES-${command.tenantId}-${command.environment.name}-$clusterId"

        val reconciliation = ReconciliationEvidence(
            journalReconciled = true,
            projectionsReconciled = true,
            outboxReconciled = true,
            reconciledRowsCount = 0L,
        )

        val entry = PostgresHaClusterEntry(
            clusterId = clusterId,
            tenantId = command.tenantId,
            environment = command.environment,
            nodes = command.nodes,
            rpoRtoTarget = command.rpoRtoTarget,
            state = HaClusterState.PROVISIONED,
            reconciliation = reconciliation,
            evidenceReference = evidenceRef,
            version = 1L,
            updatedAt = now,
        )

        val result = PostgresHaOperationResult(
            resultId = resultId,
            tenantId = command.tenantId,
            clusterId = clusterId,
            state = HaClusterState.PROVISIONED,
            reconciliationStatus = ReconciliationStatus.RECONCILED,
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
            type = "POSTGRES_HA_PROVISIONED",
            occurredAt = now,
            correlationId = command.correlationId,
            causationId = command.causationId,
        )

        val outbox = OutboxEvent(
            eventId = UUID.randomUUID(),
            resultId = resultId,
            tenantId = command.tenantId,
            type = "PostgresHaProvisioned",
            createdAt = now,
        )

        store.saveCluster(entry, result, fp, command.idempotencyKey, audit, outbox)
        return result
    }

    @Synchronized
    fun executeFailoverAndReconcile(command: ExecuteFailoverAndReconcileCommand): PostgresHaOperationResult {
        PostgresHighAvailabilityBinding.checkBound()

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

        if (command.failoverReason.isBlank() || command.targetPrimaryNodeId.isBlank()) {
            throw AuthenticationFailure.Rejected(AuthErrorCode.INVALID)
        }

        val fp = fingerprintFailoverCommand(command)
        store.findByIdempotency(command.tenantId, command.idempotencyKey)?.let { (cachedFp, cachedResult) ->
            if (cachedFp != fp) throw AuthenticationFailure.Rejected(AuthErrorCode.CONFLICT)
            return cachedResult
        }

        val existing = store.findCluster(command.tenantId, command.clusterId)
            ?: throw AuthenticationFailure.Rejected(AuthErrorCode.INVALID)

        if (existing.version != command.expectedVersion) {
            throw AuthenticationFailure.Rejected(AuthErrorCode.CONFLICT)
        }

        val targetNode = existing.nodes.firstOrNull { it.nodeId == command.targetPrimaryNodeId }
            ?: throw AuthenticationFailure.Rejected(AuthErrorCode.INVALID)

        if (targetNode.health != NodeHealth.HEALTHY) {
            throw AuthenticationFailure.Rejected(AuthErrorCode.INVALID)
        }

        val now = clock.instant()
        val resultId = UUID.randomUUID()
        val evidenceRef = "HA-FAILOVER-${command.tenantId}-${existing.clusterId}-$resultId"

        // Demote old primary and promote target standby to primary (preventing split-brain)
        val updatedNodes = existing.nodes.map { node ->
            when (node.nodeId) {
                command.targetPrimaryNodeId -> node.copy(role = NodeRole.PRIMARY)
                else -> if (node.role == NodeRole.PRIMARY) node.copy(role = NodeRole.STANDBY_SYNC) else node
            }
        }

        val reconciliationStatus = when {
            command.reconciliation.isFullyReconciled -> ReconciliationStatus.RECONCILED
            command.reconciliation.isPartial -> ReconciliationStatus.PARTIAL
            else -> ReconciliationStatus.UNRECONCILED
        }

        val nextState = if (reconciliationStatus == ReconciliationStatus.RECONCILED) {
            HaClusterState.PROMOTED
        } else {
            HaClusterState.RESTORE_RECONCILING
        }

        val updatedEntry = existing.copy(
            nodes = updatedNodes,
            state = nextState,
            reconciliation = command.reconciliation,
            evidenceReference = evidenceRef,
            version = existing.version + 1,
            updatedAt = now,
        )

        val result = PostgresHaOperationResult(
            resultId = resultId,
            tenantId = command.tenantId,
            clusterId = existing.clusterId,
            state = nextState,
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
            type = "POSTGRES_HA_FAILOVER_RECONCILED",
            occurredAt = now,
            correlationId = command.correlationId,
            causationId = command.causationId,
        )

        val outbox = OutboxEvent(
            eventId = UUID.randomUUID(),
            resultId = resultId,
            tenantId = command.tenantId,
            type = "PostgresHaFailoverReconciled",
            createdAt = now,
        )

        store.updateCluster(updatedEntry, result, fp, command.idempotencyKey, audit, outbox)
        return result
    }

    @Synchronized
    fun evaluateClusterHaReadiness(command: EvaluatePostgresHaCommand): PostgresHaEvaluationResult {
        PostgresHighAvailabilityBinding.checkBound()

        val now = clock.instant()
        val cluster = store.findCluster(command.tenantId, command.clusterId)

        if (cluster == null) {
            return PostgresHaEvaluationResult(
                decision = PostgresHaDecision.NO_GO,
                reason = PostgresHaReason.MISSING_PROVISIONING,
                clusterId = command.clusterId,
                state = HaClusterState.DEGRADED,
                reconciliationStatus = ReconciliationStatus.UNRECONCILED,
                directEligibilityGranted = false,
                financialMutationPermitted = false,
                evidenceReference = "EVID-HA-MISSING-${command.clusterId}",
                evaluatedAt = now,
            )
        }

        // Check if restore or failover reconciliation is partial or unreconciled
        if (!cluster.reconciliation.isFullyReconciled || cluster.state == HaClusterState.RESTORE_RECONCILING) {
            return PostgresHaEvaluationResult(
                decision = PostgresHaDecision.NO_GO,
                reason = PostgresHaReason.FAILOVER_RESTORE_MIGRATION_PARTIAL,
                clusterId = cluster.clusterId,
                state = cluster.state,
                reconciliationStatus = if (cluster.reconciliation.isPartial) ReconciliationStatus.PARTIAL else ReconciliationStatus.UNRECONCILED,
                directEligibilityGranted = false,
                financialMutationPermitted = false,
                evidenceReference = cluster.evidenceReference,
                evaluatedAt = now,
            )
        }

        // Check node health
        val primary = cluster.nodes.firstOrNull { it.role == NodeRole.PRIMARY }
        if (primary == null || primary.health != NodeHealth.HEALTHY) {
            return PostgresHaEvaluationResult(
                decision = PostgresHaDecision.NO_GO,
                reason = PostgresHaReason.NODE_UNAVAILABLE,
                clusterId = cluster.clusterId,
                state = HaClusterState.DEGRADED,
                reconciliationStatus = ReconciliationStatus.RECONCILED,
                directEligibilityGranted = false,
                financialMutationPermitted = false,
                evidenceReference = cluster.evidenceReference,
                evaluatedAt = now,
            )
        }

        return PostgresHaEvaluationResult(
            decision = PostgresHaDecision.GO,
            reason = PostgresHaReason.HA_ACTIVE_AND_RECONCILED,
            clusterId = cluster.clusterId,
            state = cluster.state,
            reconciliationStatus = ReconciliationStatus.RECONCILED,
            directEligibilityGranted = false,
            financialMutationPermitted = false,
            evidenceReference = cluster.evidenceReference,
            evaluatedAt = now,
        )
    }

    private fun fingerprintProvisionCommand(command: ProvisionPostgresHaCommand): String {
        val raw = "${command.tenantId}|${command.environment.name}|${command.nodes.size}|" +
            "${command.rpoRtoTarget.maxRpoSeconds}|${command.rpoRtoTarget.maxRtoSeconds}|" +
            "${command.rpoRtoTarget.approvedBy}|${command.expectedVersion}"
        val md = MessageDigest.getInstance("SHA-256")
        return md.digest(raw.toByteArray(Charsets.UTF_8)).joinToString("") { "%02x".format(it) }
    }

    private fun fingerprintFailoverCommand(command: ExecuteFailoverAndReconcileCommand): String {
        val raw = "${command.tenantId}|${command.clusterId}|${command.targetPrimaryNodeId}|" +
            "${command.reconciliation.journalReconciled}|${command.reconciliation.projectionsReconciled}|" +
            "${command.reconciliation.outboxReconciled}|${command.expectedVersion}"
        val md = MessageDigest.getInstance("SHA-256")
        return md.digest(raw.toByteArray(Charsets.UTF_8)).joinToString("") { "%02x".format(it) }
    }
}
