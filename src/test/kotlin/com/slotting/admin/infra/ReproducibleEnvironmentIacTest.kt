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

class ReproducibleEnvironmentIacTest {
    private val now = Instant.parse("2026-09-19T09:00:00Z")
    private val clock = Clock.fixed(now, ZoneOffset.UTC)

    private val securityAdmin = AuthenticatedPrincipal(
        id = "sec-admin-infra-1",
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

    private fun sampleResource(
        resourceId: String = "res-db-prod",
        resourceType: String = "DATABASE",
        environment: IacEnvironmentType = IacEnvironmentType.PRODUCTION,
        roleArn: String = "arn:aws:iam::123456789012:role/prod-db-least-privilege",
        properties: Map<String, String> = mapOf("db_endpoint" to "prod-db.internal.slotting.com"),
    ) = IacResource(
        resourceId = resourceId,
        resourceType = resourceType,
        environment = environment,
        leastPrivilegeRoleArn = roleArn,
        properties = properties,
    )

    private fun sampleManifest(
        manifestId: UUID = UUID.randomUUID(),
        environment: IacEnvironmentType = IacEnvironmentType.PRODUCTION,
        version: Long = 1L,
        templateHash: String = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        resources: List<IacResource> = listOf(sampleResource(environment = environment)),
        schemaMigrationVersion: Int = 1,
    ) = IacManifest(
        manifestId = manifestId,
        environment = environment,
        version = version,
        templateHashSha256 = templateHash,
        resources = resources,
        schemaMigrationVersion = schemaMigrationVersion,
    )

    private fun sampleDeployCommand(
        principal: AuthenticatedPrincipal? = securityAdmin,
        sessionId: String = "sess-infra-1",
        tenantId: String = "tenant-1",
        environment: IacEnvironmentType = IacEnvironmentType.PRODUCTION,
        manifest: IacManifest = sampleManifest(environment = environment),
        idempotencyKey: String = "idem-deploy-1",
        correlationId: String = "corr-deploy-1",
        causationId: String = "cause-deploy-1",
        expectedVersion: Long = 1L,
    ) = DeployIacEnvironmentCommand(
        principal = principal,
        sessionId = sessionId,
        tenantId = tenantId,
        environment = environment,
        manifest = manifest,
        idempotencyKey = idempotencyKey,
        correlationId = correlationId,
        causationId = causationId,
        expectedVersion = expectedVersion,
    )

    private fun service(
        sessionDir: AdminSessionDirectory = sessionDirectory(),
        store: IacDeploymentStore = InMemoryIacDeploymentStore(),
    ) = ReproducibleEnvironmentIacService(
        sessions = sessionDir,
        store = store,
        clock = clock,
    )

    @Test
    fun `INFRA-001-T001 Reproducible environments_IaC produces the required authoritative outcome`() {
        val store = InMemoryIacDeploymentStore()
        val s = service(store = store)

        val cmd = sampleDeployCommand()
        val res = s.deployEnvironment(cmd)

        // 1. Authoritative outcome verification
        assertEquals(IacDeploymentStatus.DEPLOYED, res.status)
        assertEquals(IacDriftStatus.CLEAN, res.driftStatus)
        assertEquals("tenant-1", res.tenantId)
        assertEquals(IacEnvironmentType.PRODUCTION, res.environment)
        assertFalse(res.directEligibilityGranted, "directEligibilityGranted must be false")
        assertFalse(res.financialMutationPermitted, "financialMutationPermitted must be false")
        assertTrue(res.evidenceReference.startsWith("IAC-DEPLOY-tenant-1-PRODUCTION-"))
        assertEquals(now, res.serverTime)

        // 2. Evaluation returns GO
        val eval = s.evaluateEnvironmentReadiness(
            EvaluateIacEnvironmentCommand(
                tenantId = "tenant-1",
                environment = IacEnvironmentType.PRODUCTION,
                correlationId = "corr-eval-1",
                causationId = "cause-eval-1",
            )
        )
        assertEquals(IacDecision.GO, eval.decision)
        assertEquals(IacReason.DEPLOYED_AND_VERIFIED, eval.reason)
        assertEquals(res.deploymentId, eval.deploymentId)
        assertEquals(res.manifestHash, eval.manifestHash)
        assertFalse(eval.directEligibilityGranted)
        assertFalse(eval.financialMutationPermitted)

        // 3. Audit & Outbox events emitted
        assertEquals(1, store.audit.size)
        val audit = store.audit[0]
        assertEquals("IAC_ENVIRONMENT_DEPLOYED", audit.type)
        assertEquals("tenant-1", audit.tenantId)
        assertEquals("corr-deploy-1", audit.correlationId)

        assertEquals(1, store.outbox.size)
        val outbox = store.outbox[0]
        assertEquals("IacEnvironmentDeployed", outbox.type)
        assertEquals("tenant-1", outbox.tenantId)
    }

    @Test
    fun `INFRA-001-T002 Reproducible environments_IaC rejects invalid, boundary, unauthorized, and stale input`() {
        val store = InMemoryIacDeploymentStore()
        val s = service(store = store)

        // 1. Unauthenticated principal rejected
        assertFailsWith<AuthenticationFailure.Rejected> {
            s.deployEnvironment(sampleDeployCommand(principal = null))
        }

        // 2. Cross-tenant access rejected
        val otherTenantPrincipal = AuthenticatedPrincipal(
            id = "sec-admin-2",
            tenantId = "tenant-2",
            kind = PrincipalKind.ADMIN,
            roles = setOf(AdminRole.SECURITY),
        )
        assertFailsWith<AuthenticationFailure.Rejected> {
            s.deployEnvironment(sampleDeployCommand(principal = otherTenantPrincipal))
        }

        // 3. Unauthorized role (e.g. SUPPORT) rejected
        val supportPrincipal = AuthenticatedPrincipal(
            id = "supp-admin-1",
            tenantId = "tenant-1",
            kind = PrincipalKind.ADMIN,
            roles = setOf(AdminRole.SUPPORT),
        )
        assertFailsWith<AuthenticationFailure.Rejected> {
            s.deployEnvironment(sampleDeployCommand(principal = supportPrincipal))
        }

        // 4. Mixed environment resources rejected:
        // A PRODUCTION manifest containing a resource designated for DEVELOPMENT
        val mixedResourceManifest = sampleManifest(
            environment = IacEnvironmentType.PRODUCTION,
            resources = listOf(
                sampleResource(resourceId = "prod-db", environment = IacEnvironmentType.PRODUCTION),
                sampleResource(resourceId = "dev-queue", environment = IacEnvironmentType.DEVELOPMENT),
            )
        )
        assertFailsWith<AuthenticationFailure.Rejected> {
            s.deployEnvironment(sampleDeployCommand(manifest = mixedResourceManifest))
        }

        // 5. Cross-environment host/endpoint reference rejected
        val devCrossTalkResource = sampleResource(
            properties = mapOf("endpoint" to "dev-database.internal.slotting.com")
        )
        val foreignEnvManifest = sampleManifest(
            environment = IacEnvironmentType.PRODUCTION,
            resources = listOf(devCrossTalkResource)
        )
        assertFailsWith<AuthenticationFailure.Rejected> {
            s.deployEnvironment(sampleDeployCommand(manifest = foreignEnvManifest))
        }

        // 6. Overly permissive wildcard role rejected
        val wildcardRoleResource = sampleResource(roleArn = "*")
        val wildcardManifest = sampleManifest(
            environment = IacEnvironmentType.PRODUCTION,
            resources = listOf(wildcardRoleResource)
        )
        assertFailsWith<AuthenticationFailure.Rejected> {
            s.deployEnvironment(sampleDeployCommand(manifest = wildcardManifest))
        }

        // 7. Malformed template hash rejected (must be 64-character hex)
        val malformedHashManifest = sampleManifest(templateHash = "too-short")
        assertFailsWith<AuthenticationFailure.Rejected> {
            s.deployEnvironment(sampleDeployCommand(manifest = malformedHashManifest))
        }
    }

    @Test
    fun `INFRA-001-T003 Reproducible environments_IaC survives concurrency, duplicate delivery, and dependency failure`() {
        val store = InMemoryIacDeploymentStore()
        val s = service(store = store)

        // 1. Initial successful deployment
        val cmd = sampleDeployCommand(idempotencyKey = "idem-concur-1")
        val initialRes = s.deployEnvironment(cmd)
        assertEquals(IacDeploymentStatus.DEPLOYED, initialRes.status)

        // 2. Idempotent repeat returns identical cached outcome
        val repeatRes = s.deployEnvironment(cmd)
        assertEquals(initialRes.resultId, repeatRes.resultId)
        assertEquals(initialRes.deploymentId, repeatRes.deploymentId)

        // 3. Changed payload with same idempotency key fails with CONFLICT
        assertFailsWith<AuthenticationFailure.Rejected> {
            s.deployEnvironment(
                cmd.copy(
                    manifest = sampleManifest(
                        templateHash = "1111111111111111111111111111111111111111111111111111111111111111"
                    )
                )
            )
        }

        // 4. Dependency failure (e.g. session store down) fails closed
        val failingSessionService = service(
            sessionDir = sessionDirectory(failing = true),
            store = store,
        )
        val exDep = assertFailsWith<AuthenticationFailure.Rejected> {
            failingSessionService.deployEnvironment(sampleDeployCommand(idempotencyKey = "idem-dep-fail"))
        }
        assertEquals(AuthErrorCode.DEPENDENCY_UNAVAILABLE, exDep.code)

        // 5. Concurrent rollback race with optimistic lock collision
        val executor = Executors.newFixedThreadPool(2)
        val latch = CountDownLatch(1)
        val rollbackCmd1 = RollbackIacDeploymentCommand(
            principal = securityAdmin,
            sessionId = "sess-infra-1",
            tenantId = "tenant-1",
            environment = IacEnvironmentType.PRODUCTION,
            targetDeploymentId = initialRes.deploymentId,
            rollbackReason = "Emergency security update required",
            idempotencyKey = "idem-rollback-race-1",
            correlationId = "corr-roll-1",
            causationId = "cause-roll-1",
            expectedVersion = 1L,
        )
        val rollbackCmd2 = RollbackIacDeploymentCommand(
            principal = securityAdmin,
            sessionId = "sess-infra-1",
            tenantId = "tenant-1",
            environment = IacEnvironmentType.PRODUCTION,
            targetDeploymentId = initialRes.deploymentId,
            rollbackReason = "Secondary emergency trigger",
            idempotencyKey = "idem-rollback-race-2",
            correlationId = "corr-roll-2",
            causationId = "cause-roll-2",
            expectedVersion = 1L,
        )

        val results = mutableListOf<Result<IacDeploymentResult>>()
        val fut1 = executor.submit(Callable {
            latch.await()
            runCatching { s.rollbackDeployment(rollbackCmd1) }
        })
        val fut2 = executor.submit(Callable {
            latch.await()
            runCatching { s.rollbackDeployment(rollbackCmd2) }
        })

        latch.countDown()
        results.add(fut1.get())
        results.add(fut2.get())
        executor.shutdown()

        val successCount = results.count { it.isSuccess }
        val conflictCount = results.count { it.isFailure && it.exceptionOrNull() is AuthenticationFailure.Rejected }

        assertEquals(1, successCount, "Exactly one concurrent rollback update should succeed")
        assertEquals(1, conflictCount, "The conflicting update must fail with optimistic lock conflict")
    }

    @Test
    fun `INFRA-001-T004 Reproducible environments_IaC remains compatible, recoverable, observable, and lifecycle-safe`() {
        val store = InMemoryIacDeploymentStore()
        val s = service(store = store)

        // 1. Initial deployment
        val cmd = sampleDeployCommand(idempotencyKey = "idem-lifecycle-1")
        val deployRes = s.deployEnvironment(cmd)
        assertEquals(IacDeploymentStatus.DEPLOYED, deployRes.status)

        // Evaluate GO
        val evalActive = s.evaluateEnvironmentReadiness(
            EvaluateIacEnvironmentCommand(
                tenantId = "tenant-1",
                environment = IacEnvironmentType.PRODUCTION,
                correlationId = "corr-eval-pre-roll",
                causationId = "cause-eval-pre-roll",
            )
        )
        assertEquals(IacDecision.GO, evalActive.decision)
        assertEquals(IacReason.DEPLOYED_AND_VERIFIED, evalActive.reason)

        // 2. Tested Rollback Mechanism
        val rollbackCmd = RollbackIacDeploymentCommand(
            principal = securityAdmin,
            sessionId = "sess-infra-1",
            tenantId = "tenant-1",
            environment = IacEnvironmentType.PRODUCTION,
            targetDeploymentId = deployRes.deploymentId,
            rollbackReason = "Compatibility testing rollback verification",
            idempotencyKey = "idem-rollback-verify",
            correlationId = "corr-roll-verify",
            causationId = "cause-roll-verify",
            expectedVersion = 1L,
        )
        val rollbackRes = s.rollbackDeployment(rollbackCmd)
        assertEquals(IacDeploymentStatus.ROLLED_BACK, rollbackRes.status)

        // 3. Evaluation after rollback yields NO-GO
        val evalRolledBack = s.evaluateEnvironmentReadiness(
            EvaluateIacEnvironmentCommand(
                tenantId = "tenant-1",
                environment = IacEnvironmentType.PRODUCTION,
                correlationId = "corr-eval-post-roll",
                causationId = "cause-eval-post-roll",
            )
        )
        assertEquals(IacDecision.NO_GO, evalRolledBack.decision)
        assertEquals(IacReason.ROLLED_BACK, evalRolledBack.reason)

        // 4. Observability & Redaction checks
        val auditRecords = store.audit
        assertEquals(2, auditRecords.size)
        val rollAudit = auditRecords[1]
        assertEquals("IAC_DEPLOYMENT_ROLLED_BACK", rollAudit.type)
        assertEquals("corr-roll-verify", rollAudit.correlationId)

        val outboxRecords = store.outbox
        assertEquals(2, outboxRecords.size)
        val rollOutbox = outboxRecords[1]
        assertEquals("IacDeploymentRolledBack", rollOutbox.type)
    }
}
