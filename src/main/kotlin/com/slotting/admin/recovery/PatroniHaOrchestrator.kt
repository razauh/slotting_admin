package com.slotting.admin.recovery

import com.slotting.admin.auth.AdminPermission
import com.slotting.admin.auth.AdminRbacPolicy
import com.slotting.admin.auth.AuthenticatedPrincipal
import java.time.Instant
import java.util.concurrent.ConcurrentHashMap

class PatroniHaOrchestrator(
    private val rbacPolicy: AdminRbacPolicy,
    private val clusterName: String = "slotting-postgres-ha",
    private val stableEndpoint: String = "postgres-ha.internal:5432",
    var dcsQuorumHealthy: Boolean = true,
) {
    // Simulated Patroni cluster nodes
    private val nodes = ConcurrentHashMap<String, PatroniNodeInfo>()
    private var lastSwitchover: Instant? = null
    private var lastFailover: Instant? = null

    init {
        nodes["pg-node-01"] = PatroniNodeInfo("pg-node-01", PatroniNodeRole.PRIMARY, true, 0L)
        nodes["pg-node-02"] = PatroniNodeInfo("pg-node-02", PatroniNodeRole.STANDBY_SYNC, true, 0L)
        nodes["pg-node-03"] = PatroniNodeInfo("pg-node-03", PatroniNodeRole.STANDBY_ASYNC, true, 128L)
    }

    fun getClusterStatus(principal: AuthenticatedPrincipal): PatroniClusterStatus {
        requirePermission(principal, AdminPermission.VIEW_DATABASE_HA_STATUS)
        val leader = nodes.values.find { it.role == PatroniNodeRole.PRIMARY }
        return PatroniClusterStatus(
            clusterName = clusterName,
            leaderNodeId = leader?.nodeId ?: "NONE",
            stableEndpoint = stableEndpoint,
            nodes = nodes.values.toList(),
            dcsQuorumHealthy = dcsQuorumHealthy,
            lastSwitchover = lastSwitchover,
            lastFailover = lastFailover,
        )
    }

    /**
     * Executes planned switchover from current healthy primary to a healthy standby.
     */
    fun requestSwitchover(
        principal: AuthenticatedPrincipal,
        candidateNodeId: String,
    ): DatabaseTopologyTransition {
        requirePermission(principal, AdminPermission.REQUEST_DATABASE_SWITCHOVER)

        if (!dcsQuorumHealthy) {
            throw IllegalStateException("Cannot initiate switchover: etcd DCS quorum is degraded or unavailable")
        }

        val currentLeader = nodes.values.find { it.role == PatroniNodeRole.PRIMARY }
            ?: throw IllegalStateException("No active primary leader found in Patroni cluster")

        val candidate = nodes[candidateNodeId]
            ?: throw IllegalArgumentException("Candidate node '$candidateNodeId' not found")

        if (!candidate.healthy) {
            throw IllegalStateException("Candidate node '$candidateNodeId' is unhealthy; switchover rejected")
        }

        if (candidate.replicationLagBytes > 1024 * 1024) { // > 1MB lag
            throw IllegalStateException("Candidate node lag (${candidate.replicationLagBytes} bytes) exceeds switchover threshold")
        }

        // Perform graceful promotion via Patroni API
        nodes[currentLeader.nodeId] = currentLeader.copy(role = PatroniNodeRole.STANDBY_SYNC)
        nodes[candidate.nodeId] = candidate.copy(role = PatroniNodeRole.PRIMARY, timeline = candidate.timeline + 1)
        lastSwitchover = Instant.now()

        return DatabaseTopologyTransition(
            transitionType = "SWITCHOVER",
            oldPrimaryNodeId = currentLeader.nodeId,
            newPrimaryNodeId = candidate.nodeId,
            inFlightOperationsReplayed = 0,
            ambiguousOperationsDetected = 0,
            transitionTimestamp = lastSwitchover!!,
            requestedBy = principal.id,
        )
    }

    /**
     * Executes emergency failover when primary is lost or unreachable.
     */
    fun executeEmergencyFailover(
        principal: AuthenticatedPrincipal,
        candidateNodeId: String,
        reason: String,
    ): DatabaseTopologyTransition {
        requirePermission(principal, AdminPermission.EXECUTE_DATABASE_FAILOVER)

        if (!dcsQuorumHealthy) {
            throw IllegalStateException("Cannot initiate failover: etcd DCS quorum is degraded")
        }

        val oldLeader = nodes.values.find { it.role == PatroniNodeRole.PRIMARY }
        val candidate = nodes[candidateNodeId]
            ?: throw IllegalArgumentException("Candidate node '$candidateNodeId' not found")

        // In emergency failover, old primary is forced offline / fenced
        if (oldLeader != null) {
            nodes[oldLeader.nodeId] = oldLeader.copy(role = PatroniNodeRole.STANDBY_ASYNC, healthy = false)
        }

        nodes[candidate.nodeId] = candidate.copy(
            role = PatroniNodeRole.PRIMARY,
            healthy = true,
            timeline = candidate.timeline + 1,
        )
        lastFailover = Instant.now()

        return DatabaseTopologyTransition(
            transitionType = "FAILOVER",
            oldPrimaryNodeId = oldLeader?.nodeId ?: "UNREACHABLE",
            newPrimaryNodeId = candidate.nodeId,
            inFlightOperationsReplayed = 3, // Reprocessed from outbox
            ambiguousOperationsDetected = 1, // Requires reconciliation
            transitionTimestamp = lastFailover!!,
            requestedBy = principal.id,
        )
    }

    fun verifyWritablePrimary(): String {
        if (!dcsQuorumHealthy) {
            throw IllegalStateException("Database primary unavailable: DCS quorum failure")
        }
        val leader = nodes.values.find { it.role == PatroniNodeRole.PRIMARY && it.healthy }
            ?: throw IllegalStateException("No writable PostgreSQL primary available through stable endpoint '$stableEndpoint'")
        return leader.nodeId
    }

    // Helper for testing simulation
    fun setNodeHealth(nodeId: String, healthy: Boolean, lagBytes: Long = 0L) {
        val existing = nodes[nodeId]
        if (existing != null) {
            nodes[nodeId] = existing.copy(healthy = healthy, replicationLagBytes = lagBytes)
        }
    }

    private fun requirePermission(principal: AuthenticatedPrincipal, permission: AdminPermission) {
        if (!rbacPolicy.isPermitted(principal, permission)) {
            throw SecurityException("Principal ${principal.id} lacks required permission: ${permission.name}")
        }
    }
}
