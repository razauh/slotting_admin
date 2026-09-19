package com.slotting.admin.infra

import com.slotting.admin.auth.*
import java.time.Clock
import java.time.Duration
import java.time.Instant
import java.time.ZoneOffset
import java.util.UUID
import java.util.concurrent.Callable
import java.util.concurrent.CountDownLatch
import java.util.concurrent.Executors
import kotlin.test.*
import org.junit.jupiter.api.Test

class PostgresHighAvailabilityTest {
    private val now = Instant.parse("2026-09-19T09:00:00Z")
    private val clock = Clock.fixed(now, ZoneOffset.UTC)

    private val securityAdmin = AuthenticatedPrincipal(
        id = "sec-admin-ha-1",
        tenantId = "tenant-1",
        kind = PrincipalKind.ADMIN,
        roles = setOf(AdminRole.SECURITY),
    )

    private fun sessionDirectory(
        active: Boolean = true,
        expiresAt: Instant = now.plus(Duration.ofHours(1)),
        failing: Boolean = false,
    ) = object : AdminSessionDirectory {
        override fun find(tenantId: String, principalId: String, sessionId: String): AdminSessionStatus? {
            if (failing) throw RuntimeException("Session directory down")
            return AdminSessionStatus(active = active, breakGlass = false, expiresAt = expiresAt)
        }
    }

    private fun sampleNodes() = listOf(
        PostgresNode(
            nodeId = "pg-primary-1",
            role = NodeRole.PRIMARY,
            endpoint = "postgres-primary.internal.slotting.com:5432",
            health = NodeHealth.HEALTHY,
            replicationLagBytes = 0L,
        ),
        PostgresNode(
            nodeId = "pg-standby-1",
            role = NodeRole.STANDBY_SYNC,
            endpoint = "postgres-standby.internal.slotting.com:5432",
            health = NodeHealth.HEALTHY,
            replicationLagBytes = 0L,
        )
    )

    private fun sampleRpoRtoTarget() = RpoRtoTarget(
        maxRpoSeconds = 0L, // Synchronous commit zero data loss target
        maxRtoSeconds = 30L,
        approvedBy = "SecOps Lead & Architecture VP",
    )

    private fun sampleProvisionCommand(
        principal: AuthenticatedPrincipal? = securityAdmin,
        sessionId: String = "sess-ha-1",
        tenantId: String = "tenant-1",
        environment: IacEnvironmentType = IacEnvironmentType.PRODUCTION,
        nodes: List<PostgresNode> = sampleNodes(),
        rpoRtoTarget: RpoRtoTarget = sampleRpoRtoTarget(),
        idempotencyKey: String = "idem-ha-prov-1",
        correlationId: String = "corr-ha-prov-1",
        causationId: String = "cause-ha-prov-1",
        expectedVersion: Long = 1L,
    ) = ProvisionPostgresHaCommand(
        principal = principal,
        sessionId = sessionId,
        tenantId = tenantId,
        environment = environment,
        nodes = nodes,
        rpoRtoTarget = rpoRtoTarget,
        idempotencyKey = idempotencyKey,
        correlationId = correlationId,
        causationId = causationId,
        expectedVersion = expectedVersion,
    )

    private fun service(
        sessionDir: AdminSessionDirectory = sessionDirectory(),
        store: PostgresHaStore = InMemoryPostgresHaStore(),
    ) = PostgresHighAvailabilityService(
        sessions = sessionDir,
        store = store,
        clock = clock,
    )

    @Test
    fun `INFRA-002-01-T001 Provision PostgreSQL high availability produces the required authoritative outcome`() {
        val store = InMemoryPostgresHaStore()
        val s = service(store = store)

        val cmd = sampleProvisionCommand()
        val res = s.provisionHaCluster(cmd)

        // 1. Authoritative outcome verification
        assertEquals(HaClusterState.PROVISIONED, res.state)
        assertEquals(ReconciliationStatus.RECONCILED, res.reconciliationStatus)
        assertEquals("tenant-1", res.tenantId)
        assertFalse(res.directEligibilityGranted, "directEligibilityGranted must be false")
        assertFalse(res.financialMutationPermitted, "financialMutationPermitted must be false")
        assertTrue(res.evidenceReference.startsWith("HA-POSTGRES-tenant-1-PRODUCTION-"))
        assertEquals(now, res.serverTime)

        // 2. Evaluation returns GO
        val eval = s.evaluateClusterHaReadiness(
            EvaluatePostgresHaCommand(
                tenantId = "tenant-1",
                clusterId = res.clusterId,
                correlationId = "corr-eval-ha-1",
                causationId = "cause-eval-ha-1",
            )
        )
        assertEquals(PostgresHaDecision.GO, eval.decision)
        assertEquals(PostgresHaReason.HA_ACTIVE_AND_RECONCILED, eval.reason)
        assertEquals(res.clusterId, eval.clusterId)
        assertEquals(ReconciliationStatus.RECONCILED, eval.reconciliationStatus)
        assertFalse(eval.directEligibilityGranted)
        assertFalse(eval.financialMutationPermitted)

        // 3. Audit & Outbox events emitted
        assertEquals(1, store.audit.size)
        val audit = store.audit[0]
        assertEquals("POSTGRES_HA_PROVISIONED", audit.type)
        assertEquals("tenant-1", audit.tenantId)
        assertEquals("corr-ha-prov-1", audit.correlationId)

        assertEquals(1, store.outbox.size)
        val outbox = store.outbox[0]
        assertEquals("PostgresHaProvisioned", outbox.type)
        assertEquals("tenant-1", outbox.tenantId)
    }

    @Test
    fun `INFRA-002-01-T002 Provision PostgreSQL high availability rejects invalid, boundary, unauthorized, and stale input`() {
        val store = InMemoryPostgresHaStore()
        val s = service(store = store)

        // 1. Unauthenticated principal rejected
        assertFailsWith<AuthenticationFailure.Rejected> {
            s.provisionHaCluster(sampleProvisionCommand(principal = null))
        }

        // 2. Cross-tenant principal rejected
        val crossTenantPrincipal = AuthenticatedPrincipal(
            id = "sec-admin-2",
            tenantId = "tenant-2",
            kind = PrincipalKind.ADMIN,
            roles = setOf(AdminRole.SECURITY),
        )
        assertFailsWith<AuthenticationFailure.Rejected> {
            s.provisionHaCluster(sampleProvisionCommand(principal = crossTenantPrincipal))
        }

        // 3. Missing SECURITY or SUPER_ADMIN role rejected
        val supportPrincipal = AuthenticatedPrincipal(
            id = "supp-admin-1",
            tenantId = "tenant-1",
            kind = PrincipalKind.ADMIN,
            roles = setOf(AdminRole.SUPPORT),
        )
        assertFailsWith<AuthenticationFailure.Rejected> {
            s.provisionHaCluster(sampleProvisionCommand(principal = supportPrincipal))
        }

        // 4. Invalid topology: Only 1 primary with no standby rejected
        val singleNodeList = listOf(
            PostgresNode(
                nodeId = "pg-alone",
                role = NodeRole.PRIMARY,
                endpoint = "pg-alone:5432",
                health = NodeHealth.HEALTHY,
            )
        )
        assertFailsWith<AuthenticationFailure.Rejected> {
            s.provisionHaCluster(sampleProvisionCommand(nodes = singleNodeList))
        }

        // 5. Invalid RPO/RTO target (e.g. negative maxRpo or blank approver) rejected
        assertFailsWith<AuthenticationFailure.Rejected> {
            s.provisionHaCluster(
                sampleProvisionCommand(
                    rpoRtoTarget = sampleRpoRtoTarget().copy(approvedBy = "")
                )
            )
        }
        assertFailsWith<AuthenticationFailure.Rejected> {
            s.provisionHaCluster(
                sampleProvisionCommand(
                    rpoRtoTarget = sampleRpoRtoTarget().copy(maxRtoSeconds = 0L)
                )
            )
        }

        // 6. Partial restore/failover reconciliation yields NO-GO with FAILOVER_RESTORE_MIGRATION_PARTIAL
        val provRes = s.provisionHaCluster(sampleProvisionCommand(idempotencyKey = "idem-partial-test"))
        val failoverPartialCmd = ExecuteFailoverAndReconcileCommand(
            principal = securityAdmin,
            sessionId = "sess-ha-1",
            tenantId = "tenant-1",
            clusterId = provRes.clusterId,
            targetPrimaryNodeId = "pg-standby-1",
            reconciliation = ReconciliationEvidence(
                journalReconciled = true,
                projectionsReconciled = false, // Partial!
                outboxReconciled = true,
                reconciledRowsCount = 100L,
            ),
            failoverReason = "Primary host maintenance",
            idempotencyKey = "idem-failover-partial",
            correlationId = "corr-fo-part",
            causationId = "cause-fo-part",
            expectedVersion = 1L,
        )
        s.executeFailoverAndReconcile(failoverPartialCmd)

        val evalPartial = s.evaluateClusterHaReadiness(
            EvaluatePostgresHaCommand(
                tenantId = "tenant-1",
                clusterId = provRes.clusterId,
                correlationId = "corr-eval-part",
                causationId = "cause-eval-part",
            )
        )
        assertEquals(PostgresHaDecision.NO_GO, evalPartial.decision)
        assertEquals(PostgresHaReason.FAILOVER_RESTORE_MIGRATION_PARTIAL, evalPartial.reason)
        assertEquals(ReconciliationStatus.PARTIAL, evalPartial.reconciliationStatus)
    }

    @Test
    fun `INFRA-002-01-T003 Provision PostgreSQL high availability survives concurrency, duplicate delivery, and dependency failure`() {
        val store = InMemoryPostgresHaStore()
        val s = service(store = store)

        // 1. Initial provision
        val cmd = sampleProvisionCommand(idempotencyKey = "idem-concur-ha")
        val initialRes = s.provisionHaCluster(cmd)
        assertEquals(HaClusterState.PROVISIONED, initialRes.state)

        // 2. Idempotent repeat returns identical cached outcome
        val repeatRes = s.provisionHaCluster(cmd)
        assertEquals(initialRes.resultId, repeatRes.resultId)
        assertEquals(initialRes.clusterId, repeatRes.clusterId)

        // 3. Changed payload with same idempotency key fails with CONFLICT
        assertFailsWith<AuthenticationFailure.Rejected> {
            s.provisionHaCluster(
                cmd.copy(
                    rpoRtoTarget = sampleRpoRtoTarget().copy(maxRtoSeconds = 60L)
                )
            )
        }

        // 4. Dependency failure fails closed
        val failingSessionService = service(
            sessionDir = sessionDirectory(failing = true),
            store = store,
        )
        val exDep = assertFailsWith<AuthenticationFailure.Rejected> {
            failingSessionService.provisionHaCluster(sampleProvisionCommand(idempotencyKey = "idem-dep-fail"))
        }
        assertEquals(AuthErrorCode.DEPENDENCY_UNAVAILABLE, exDep.code)

        // 5. Concurrent failover update with expectedVersion race
        val executor = Executors.newFixedThreadPool(2)
        val latch = CountDownLatch(1)
        val foCmd1 = ExecuteFailoverAndReconcileCommand(
            principal = securityAdmin,
            sessionId = "sess-ha-1",
            tenantId = "tenant-1",
            clusterId = initialRes.clusterId,
            targetPrimaryNodeId = "pg-standby-1",
            reconciliation = ReconciliationEvidence(
                journalReconciled = true,
                projectionsReconciled = true,
                outboxReconciled = true,
                reconciledRowsCount = 50L,
            ),
            failoverReason = "Failover Race 1",
            idempotencyKey = "idem-fo-race-1",
            correlationId = "corr-fo-race-1",
            causationId = "cause-fo-race-1",
            expectedVersion = 1L,
        )
        val foCmd2 = ExecuteFailoverAndReconcileCommand(
            principal = securityAdmin,
            sessionId = "sess-ha-1",
            tenantId = "tenant-1",
            clusterId = initialRes.clusterId,
            targetPrimaryNodeId = "pg-standby-1",
            reconciliation = ReconciliationEvidence(
                journalReconciled = true,
                projectionsReconciled = true,
                outboxReconciled = true,
                reconciledRowsCount = 50L,
            ),
            failoverReason = "Failover Race 2",
            idempotencyKey = "idem-fo-race-2",
            correlationId = "corr-fo-race-2",
            causationId = "cause-fo-race-2",
            expectedVersion = 1L,
        )

        val results = mutableListOf<Result<PostgresHaOperationResult>>()
        val fut1 = executor.submit(Callable {
            latch.await()
            runCatching { s.executeFailoverAndReconcile(foCmd1) }
        })
        val fut2 = executor.submit(Callable {
            latch.await()
            runCatching { s.executeFailoverAndReconcile(foCmd2) }
        })

        latch.countDown()
        results.add(fut1.get())
        results.add(fut2.get())
        executor.shutdown()

        val successCount = results.count { it.isSuccess }
        val conflictCount = results.count { it.isFailure && it.exceptionOrNull() is AuthenticationFailure.Rejected }

        assertEquals(1, successCount, "Exactly one concurrent failover should succeed")
        assertEquals(1, conflictCount, "The conflicting failover must fail with optimistic lock conflict")
    }

    @Test
    fun `INFRA-002-01-T004 Provision PostgreSQL high availability remains compatible, recoverable, observable, and lifecycle-safe`() {
        val store = InMemoryPostgresHaStore()
        val s = service(store = store)

        // 1. Initial provision
        val cmd = sampleProvisionCommand(idempotencyKey = "idem-lifecycle-ha")
        val provRes = s.provisionHaCluster(cmd)
        assertEquals(HaClusterState.PROVISIONED, provRes.state)

        // 2. Full failover and complete reconciliation
        val failoverFullCmd = ExecuteFailoverAndReconcileCommand(
            principal = securityAdmin,
            sessionId = "sess-ha-1",
            tenantId = "tenant-1",
            clusterId = provRes.clusterId,
            targetPrimaryNodeId = "pg-standby-1",
            reconciliation = ReconciliationEvidence(
                journalReconciled = true,
                projectionsReconciled = true,
                outboxReconciled = true,
                reconciledRowsCount = 250L,
            ),
            failoverReason = "Unplanned primary loss simulation",
            idempotencyKey = "idem-failover-full",
            correlationId = "corr-fo-full",
            causationId = "cause-fo-full",
            expectedVersion = 1L,
        )
        val foRes = s.executeFailoverAndReconcile(failoverFullCmd)
        assertEquals(HaClusterState.PROMOTED, foRes.state)
        assertEquals(ReconciliationStatus.RECONCILED, foRes.reconciliationStatus)

        // 3. Evaluation after full failover reconciliation returns GO
        val evalFull = s.evaluateClusterHaReadiness(
            EvaluatePostgresHaCommand(
                tenantId = "tenant-1",
                clusterId = provRes.clusterId,
                correlationId = "corr-eval-post-fo",
                causationId = "cause-eval-post-fo",
            )
        )
        assertEquals(PostgresHaDecision.GO, evalFull.decision)
        assertEquals(PostgresHaReason.HA_ACTIVE_AND_RECONCILED, evalFull.reason)

        // 4. Observability & Redaction checks
        val auditRecords = store.audit
        assertEquals(2, auditRecords.size)
        val foAudit = auditRecords[1]
        assertEquals("POSTGRES_HA_FAILOVER_RECONCILED", foAudit.type)
        assertEquals("corr-fo-full", foAudit.correlationId)

        val outboxRecords = store.outbox
        assertEquals(2, outboxRecords.size)
        val foOutbox = outboxRecords[1]
        assertEquals("PostgresHaFailoverReconciled", foOutbox.type)
    }
}
