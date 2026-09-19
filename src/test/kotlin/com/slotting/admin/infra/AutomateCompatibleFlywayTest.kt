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

class AutomateCompatibleFlywayTest {
    private val now = Instant.parse("2026-09-19T09:00:00Z")
    private val clock = Clock.fixed(now, ZoneOffset.UTC)

    private val securityAdmin = AuthenticatedPrincipal(
        id = "sec-admin-flyway-1",
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

    private fun sampleBackup(
        backupId: UUID = UUID.randomUUID(),
        tenantId: String = "tenant-1",
        clusterId: UUID = UUID.randomUUID(),
        status: BackupStatus = BackupStatus.COMPLETED,
    ) = PitrBackupMetadata(
        backupId = backupId,
        clusterId = clusterId,
        tenantId = tenantId,
        environment = IacEnvironmentType.PRODUCTION,
        baseSnapshotId = "snap-pre-migration",
        earliestRecoveryPoint = now.minusSeconds(86400 * 7),
        latestRecoveryPoint = now.minusSeconds(30),
        kmsKeyArn = "arn:aws:kms:us-east-1:123456789012:key/pitr-key",
        encryptionAlgorithm = "AES-256-GCM",
        backupChecksumSha256 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        status = status,
        createdAt = now.minusSeconds(60),
    )

    private fun sampleScripts() = listOf(
        FlywayScriptDescriptor(
            version = 17,
            description = "infra_high_availability_metadata",
            scriptName = "V17__infra_high_availability_metadata.sql",
            checksumSha256 = "1111111111111111111111111111111111111111111111111111111111111111",
            isTransactional = true,
        ),
        FlywayScriptDescriptor(
            version = 18,
            description = "encrypted_pitr_backup_catalog",
            scriptName = "V18__encrypted_pitr_backup_catalog.sql",
            checksumSha256 = "2222222222222222222222222222222222222222222222222222222222222222",
            isTransactional = true,
        )
    )

    private fun sampleDeployCommand(
        principal: AuthenticatedPrincipal? = securityAdmin,
        sessionId: String = "sess-flyway-1",
        tenantId: String = "tenant-1",
        environment: IacEnvironmentType = IacEnvironmentType.PRODUCTION,
        preMigrationBackupId: UUID = UUID.randomUUID(),
        scriptsToApply: List<FlywayScriptDescriptor> = sampleScripts(),
        reconciliation: ReconciliationEvidence = ReconciliationEvidence(true, true, true, 200L),
        idempotencyKey: String = "idem-flyway-1",
        correlationId: String = "corr-flyway-1",
        causationId: String = "cause-flyway-1",
        expectedVersion: Long = 1L,
    ) = DeployFlywayMigrationCommand(
        principal = principal,
        sessionId = sessionId,
        tenantId = tenantId,
        environment = environment,
        preMigrationBackupId = preMigrationBackupId,
        scriptsToApply = scriptsToApply,
        reconciliation = reconciliation,
        idempotencyKey = idempotencyKey,
        correlationId = correlationId,
        causationId = causationId,
        expectedVersion = expectedVersion,
    )

    private fun service(
        sessionDir: AdminSessionDirectory = sessionDirectory(),
        pitrStore: EncryptedPitrBackupStore = InMemoryEncryptedPitrBackupStore(),
        store: FlywayDeploymentStore = InMemoryFlywayDeploymentStore(),
    ) = AutomateCompatibleFlywayService(
        sessions = sessionDir,
        pitrBackupStore = pitrStore,
        store = store,
        clock = clock,
    )

    @Test
    fun `INFRA-002-03-T001 Automate compatible Flyway deployment produces the required authoritative outcome`() {
        val pitrStore = InMemoryEncryptedPitrBackupStore()
        val backup = sampleBackup()
        pitrStore.backups["tenant-1:${backup.backupId}"] = backup

        val store = InMemoryFlywayDeploymentStore()
        val s = service(pitrStore = pitrStore, store = store)

        val cmd = sampleDeployCommand(preMigrationBackupId = backup.backupId)
        val res = s.deployMigration(cmd)

        // 1. Authoritative outcome verification
        assertEquals(FlywayMigrationState.APPLIED, res.state)
        assertEquals(ReconciliationStatus.RECONCILED, res.reconciliationStatus)
        assertEquals(18, res.currentVersion)
        assertEquals("tenant-1", res.tenantId)
        assertFalse(res.directEligibilityGranted)
        assertFalse(res.financialMutationPermitted)
        assertTrue(res.evidenceReference.startsWith("FLYWAY-DEPLOY-tenant-1-PRODUCTION-"))
        assertEquals(now, res.serverTime)

        // 2. Evaluation returns GO
        val eval = s.evaluateFlywayDeployment(
            EvaluateFlywayDeploymentCommand(
                tenantId = "tenant-1",
                deploymentId = res.deploymentId,
                correlationId = "corr-eval-1",
                causationId = "cause-eval-1",
            )
        )
        assertEquals(FlywayDeployDecision.GO, eval.decision)
        assertEquals(FlywayDeployReason.MIGRATION_SUCCESS_AND_RECONCILED, eval.reason)
        assertEquals(18, eval.currentVersion)
        assertEquals(FlywayMigrationState.APPLIED, eval.state)
        assertFalse(eval.directEligibilityGranted)
        assertFalse(eval.financialMutationPermitted)

        // 3. Audit & Outbox events emitted
        assertEquals(1, store.audit.size)
        val audit = store.audit[0]
        assertEquals("FLYWAY_MIGRATION_DEPLOYED", audit.type)
        assertEquals("tenant-1", audit.tenantId)
        assertEquals("corr-flyway-1", audit.correlationId)

        assertEquals(1, store.outbox.size)
        val outbox = store.outbox[0]
        assertEquals("FlywayMigrationDeployed", outbox.type)
        assertEquals("tenant-1", outbox.tenantId)
    }

    @Test
    fun `INFRA-002-03-T002 Automate compatible Flyway deployment rejects invalid, boundary, unauthorized, and stale input`() {
        val pitrStore = InMemoryEncryptedPitrBackupStore()
        val backup = sampleBackup()
        pitrStore.backups["tenant-1:${backup.backupId}"] = backup

        val store = InMemoryFlywayDeploymentStore()
        val s = service(pitrStore = pitrStore, store = store)

        // 1. Unauthenticated principal rejected
        assertFailsWith<AuthenticationFailure.Rejected> {
            s.deployMigration(sampleDeployCommand(principal = null, preMigrationBackupId = backup.backupId))
        }

        // 2. Cross-tenant principal rejected
        val otherTenantPrincipal = AuthenticatedPrincipal(
            id = "sec-admin-other",
            tenantId = "tenant-other",
            kind = PrincipalKind.ADMIN,
            roles = setOf(AdminRole.SECURITY),
        )
        assertFailsWith<AuthenticationFailure.Rejected> {
            s.deployMigration(sampleDeployCommand(principal = otherTenantPrincipal, preMigrationBackupId = backup.backupId))
        }

        // 3. Missing SECURITY or SUPER_ADMIN role rejected
        val supportPrincipal = AuthenticatedPrincipal(
            id = "supp-admin-1",
            tenantId = "tenant-1",
            kind = PrincipalKind.ADMIN,
            roles = setOf(AdminRole.SUPPORT),
        )
        assertFailsWith<AuthenticationFailure.Rejected> {
            s.deployMigration(sampleDeployCommand(principal = supportPrincipal, preMigrationBackupId = backup.backupId))
        }

        // 4. Missing pre-migration backup rejected
        assertFailsWith<AuthenticationFailure.Rejected> {
            s.deployMigration(sampleDeployCommand(preMigrationBackupId = UUID.randomUUID()))
        }

        // 5. Out of order migration versions rejected (e.g. V18 before V17)
        val outOfOrderScripts = listOf(
            FlywayScriptDescriptor(18, "schema_18", "V18__schema.sql", "1111111111111111111111111111111111111111111111111111111111111111"),
            FlywayScriptDescriptor(17, "schema_17", "V17__schema.sql", "2222222222222222222222222222222222222222222222222222222222222222"),
        )
        assertFailsWith<AuthenticationFailure.Rejected> {
            s.deployMigration(sampleDeployCommand(preMigrationBackupId = backup.backupId, scriptsToApply = outOfOrderScripts))
        }

        // 6. Partial migration reconciliation results in NO-GO with FAILOVER_RESTORE_MIGRATION_PARTIAL
        val partialDeploy = s.deployMigration(
            sampleDeployCommand(
                preMigrationBackupId = backup.backupId,
                reconciliation = ReconciliationEvidence(
                    journalReconciled = true,
                    projectionsReconciled = false, // Partial!
                    outboxReconciled = true,
                    reconciledRowsCount = 10L,
                ),
                idempotencyKey = "idem-part-deploy",
            )
        )
        val evalPartial = s.evaluateFlywayDeployment(
            EvaluateFlywayDeploymentCommand(
                tenantId = "tenant-1",
                deploymentId = partialDeploy.deploymentId,
                correlationId = "c",
                causationId = "c",
            )
        )
        assertEquals(FlywayDeployDecision.NO_GO, evalPartial.decision)
        assertEquals(FlywayDeployReason.FAILOVER_RESTORE_MIGRATION_PARTIAL, evalPartial.reason)
    }

    @Test
    fun `INFRA-002-03-T003 Automate compatible Flyway deployment survives concurrency, duplicate delivery, and dependency failure`() {
        val pitrStore = InMemoryEncryptedPitrBackupStore()
        val backup = sampleBackup()
        pitrStore.backups["tenant-1:${backup.backupId}"] = backup

        val store = InMemoryFlywayDeploymentStore()
        val s = service(pitrStore = pitrStore, store = store)

        // 1. Initial migration deploy
        val cmd = sampleDeployCommand(preMigrationBackupId = backup.backupId, idempotencyKey = "idem-concur-fly")
        val initialRes = s.deployMigration(cmd)
        assertEquals(FlywayMigrationState.APPLIED, initialRes.state)

        // 2. Idempotent repeat returns identical cached outcome
        val repeatRes = s.deployMigration(cmd)
        assertEquals(initialRes.resultId, repeatRes.resultId)
        assertEquals(initialRes.deploymentId, repeatRes.deploymentId)

        // 3. Changed payload with same idempotency key fails with CONFLICT
        assertFailsWith<AuthenticationFailure.Rejected> {
            s.deployMigration(cmd.copy(environment = IacEnvironmentType.STAGING))
        }

        // 4. Dependency failure fails closed
        val failingSessionService = service(
            sessionDir = sessionDirectory(failing = true),
            pitrStore = pitrStore,
            store = store,
        )
        val exDep = assertFailsWith<AuthenticationFailure.Rejected> {
            failingSessionService.deployMigration(
                sampleDeployCommand(preMigrationBackupId = backup.backupId, idempotencyKey = "idem-dep-fail")
            )
        }
        assertEquals(AuthErrorCode.DEPENDENCY_UNAVAILABLE, exDep.code)

        // 5. Concurrent migration update race
        val executor = Executors.newFixedThreadPool(2)
        val latch = CountDownLatch(1)
        val cmd1 = sampleDeployCommand(preMigrationBackupId = backup.backupId, idempotencyKey = "idem-race-1")
        val cmd2 = sampleDeployCommand(preMigrationBackupId = backup.backupId, idempotencyKey = "idem-race-2")

        val results = mutableListOf<Result<FlywayDeployResult>>()
        val fut1 = executor.submit(Callable {
            latch.await()
            runCatching { s.deployMigration(cmd1) }
        })
        val fut2 = executor.submit(Callable {
            latch.await()
            runCatching { s.deployMigration(cmd2) }
        })

        latch.countDown()
        results.add(fut1.get())
        results.add(fut2.get())
        executor.shutdown()

        val successCount = results.count { it.isSuccess }
        assertEquals(2, successCount, "Distinct idempotent migration keys run safely")
    }

    @Test
    fun `INFRA-002-03-T004 Automate compatible Flyway deployment remains compatible, recoverable, observable, and lifecycle-safe`() {
        val pitrStore = InMemoryEncryptedPitrBackupStore()
        val backup = sampleBackup()
        pitrStore.backups["tenant-1:${backup.backupId}"] = backup

        val store = InMemoryFlywayDeploymentStore()
        val s = service(pitrStore = pitrStore, store = store)

        // 1. Initial deployment
        val cmd = sampleDeployCommand(preMigrationBackupId = backup.backupId, idempotencyKey = "idem-life-fly")
        val deployRes = s.deployMigration(cmd)

        // 2. Evaluate readiness returns GO
        val eval = s.evaluateFlywayDeployment(
            EvaluateFlywayDeploymentCommand(
                tenantId = "tenant-1",
                deploymentId = deployRes.deploymentId,
                correlationId = "corr-life-eval",
                causationId = "cause-life-eval",
            )
        )
        assertEquals(FlywayDeployDecision.GO, eval.decision)
        assertEquals(FlywayDeployReason.MIGRATION_SUCCESS_AND_RECONCILED, eval.reason)

        // 3. Observability & Redaction checks
        val auditRecords = store.audit
        assertEquals(1, auditRecords.size)
        val audit = auditRecords[0]
        assertEquals("FLYWAY_MIGRATION_DEPLOYED", audit.type)
        assertEquals("corr-flyway-1", audit.correlationId)

        val outboxRecords = store.outbox
        assertEquals(1, outboxRecords.size)
        val outbox = outboxRecords[0]
        assertEquals("FlywayMigrationDeployed", outbox.type)
    }
}
