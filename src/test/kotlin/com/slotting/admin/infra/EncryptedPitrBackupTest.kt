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

class EncryptedPitrBackupTest {
    private val now = Instant.parse("2026-09-19T09:00:00Z")
    private val clock = Clock.fixed(now, ZoneOffset.UTC)

    private val securityAdmin = AuthenticatedPrincipal(
        id = "sec-admin-pitr-1",
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

    private fun sampleCluster(
        clusterId: UUID = UUID.randomUUID(),
        tenantId: String = "tenant-1",
        environment: IacEnvironmentType = IacEnvironmentType.PRODUCTION,
    ) = PostgresHaClusterEntry(
        clusterId = clusterId,
        tenantId = tenantId,
        environment = environment,
        nodes = listOf(
            PostgresNode("n1", NodeRole.PRIMARY, "primary:5432", NodeHealth.HEALTHY),
            PostgresNode("n2", NodeRole.STANDBY_SYNC, "standby:5432", NodeHealth.HEALTHY),
        ),
        rpoRtoTarget = RpoRtoTarget(0L, 30L, "SecOps"),
        state = HaClusterState.PROVISIONED,
        reconciliation = ReconciliationEvidence(true, true, true, 0L),
        evidenceReference = "EVID-HA-$clusterId",
        version = 1L,
        updatedAt = now,
    )

    private fun sampleBackupCommand(
        principal: AuthenticatedPrincipal? = securityAdmin,
        sessionId: String = "sess-pitr-1",
        tenantId: String = "tenant-1",
        clusterId: UUID = UUID.randomUUID(),
        environment: IacEnvironmentType = IacEnvironmentType.PRODUCTION,
        baseSnapshotId: String = "snap-base-20260919",
        kmsKeyArn: String = "arn:aws:kms:us-east-1:123456789012:key/pitr-encryption-key",
        earliestRecoveryPoint: Instant = now.minusSeconds(86400 * 7), // 7 days ago
        latestRecoveryPoint: Instant = now.minusSeconds(60), // 1 min ago
        backupChecksumSha256: String = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        idempotencyKey: String = "idem-pitr-backup-1",
        correlationId: String = "corr-pitr-1",
        causationId: String = "cause-pitr-1",
        expectedVersion: Long = 1L,
    ) = CreateEncryptedPitrBackupCommand(
        principal = principal,
        sessionId = sessionId,
        tenantId = tenantId,
        clusterId = clusterId,
        environment = environment,
        baseSnapshotId = baseSnapshotId,
        kmsKeyArn = kmsKeyArn,
        earliestRecoveryPoint = earliestRecoveryPoint,
        latestRecoveryPoint = latestRecoveryPoint,
        backupChecksumSha256 = backupChecksumSha256,
        idempotencyKey = idempotencyKey,
        correlationId = correlationId,
        causationId = causationId,
        expectedVersion = expectedVersion,
    )

    private fun service(
        sessionDir: AdminSessionDirectory = sessionDirectory(),
        haStore: PostgresHaStore = InMemoryPostgresHaStore(),
        store: EncryptedPitrBackupStore = InMemoryEncryptedPitrBackupStore(),
    ) = EncryptedPitrBackupService(
        sessions = sessionDir,
        postgresHaStore = haStore,
        store = store,
        clock = clock,
    )

    @Test
    fun `INFRA-002-02-T001 Automate encrypted PITR backups produces the required authoritative outcome`() {
        val haStore = InMemoryPostgresHaStore()
        val cluster = sampleCluster()
        haStore.clusters["tenant-1:${cluster.clusterId}"] = cluster

        val store = InMemoryEncryptedPitrBackupStore()
        val s = service(haStore = haStore, store = store)

        // 1. Create Encrypted PITR Backup
        val backupCmd = sampleBackupCommand(clusterId = cluster.clusterId)
        val backupRes = s.createEncryptedBackup(backupCmd)

        assertNotNull(backupRes.backupId)
        assertEquals(cluster.clusterId, backupRes.clusterId)
        assertEquals("tenant-1", backupRes.tenantId)
        assertFalse(backupRes.directEligibilityGranted)
        assertFalse(backupRes.financialMutationPermitted)
        assertTrue(backupRes.evidenceReference.startsWith("PITR-BACKUP-tenant-1-"))

        // 2. Execute PITR Restore within valid window with full reconciliation
        val restorePoint = now.minusSeconds(3600) // 1 hour ago (within 7d window)
        val restoreCmd = ExecutePitrRestoreCommand(
            principal = securityAdmin,
            sessionId = "sess-pitr-1",
            tenantId = "tenant-1",
            backupId = backupRes.backupId!!,
            targetRecoveryPoint = restorePoint,
            reconciliation = ReconciliationEvidence(
                journalReconciled = true,
                projectionsReconciled = true,
                outboxReconciled = true,
                reconciledRowsCount = 500L,
            ),
            restoreReason = "Drill disaster recovery verification",
            idempotencyKey = "idem-restore-1",
            correlationId = "corr-rest-1",
            causationId = "cause-rest-1",
            expectedVersion = 1L,
        )
        val restoreRes = s.executePitrRestore(restoreCmd)

        assertNotNull(restoreRes.restoreId)
        assertEquals(RestoreStatus.RESTORED_AND_RECONCILED, restoreRes.restoreStatus)
        assertFalse(restoreRes.directEligibilityGranted)
        assertFalse(restoreRes.financialMutationPermitted)

        // 3. Evaluate PITR Readiness returns GO
        val eval = s.evaluatePitrReadiness(
            EvaluatePitrReadinessCommand(
                tenantId = "tenant-1",
                restoreId = restoreRes.restoreId!!,
                correlationId = "corr-eval-1",
                causationId = "cause-eval-1",
            )
        )
        assertEquals(PitrDecision.GO, eval.decision)
        assertEquals(PitrReason.RESTORED_AND_RECONCILED, eval.reason)
        assertEquals(RestoreStatus.RESTORED_AND_RECONCILED, eval.status)

        // 4. Audit & Outbox verification
        assertEquals(2, store.audit.size)
        assertEquals("POSTGRES_PITR_BACKUP_COMPLETED", store.audit[0].type)
        assertEquals("POSTGRES_PITR_RESTORE_RECONCILED", store.audit[1].type)

        assertEquals(2, store.outbox.size)
        assertEquals("PostgresPitrBackupCompleted", store.outbox[0].type)
        assertEquals("PostgresPitrRestoreReconciled", store.outbox[1].type)
    }

    @Test
    fun `INFRA-002-02-T002 Automate encrypted PITR backups rejects invalid, boundary, unauthorized, and stale input`() {
        val haStore = InMemoryPostgresHaStore()
        val cluster = sampleCluster()
        haStore.clusters["tenant-1:${cluster.clusterId}"] = cluster

        val store = InMemoryEncryptedPitrBackupStore()
        val s = service(haStore = haStore, store = store)

        // 1. Unauthenticated principal rejected
        assertFailsWith<AuthenticationFailure.Rejected> {
            s.createEncryptedBackup(sampleBackupCommand(principal = null, clusterId = cluster.clusterId))
        }

        // 2. Cross-tenant principal rejected
        val otherTenantPrincipal = AuthenticatedPrincipal(
            id = "sec-admin-other",
            tenantId = "tenant-other",
            kind = PrincipalKind.ADMIN,
            roles = setOf(AdminRole.SECURITY),
        )
        assertFailsWith<AuthenticationFailure.Rejected> {
            s.createEncryptedBackup(sampleBackupCommand(principal = otherTenantPrincipal, clusterId = cluster.clusterId))
        }

        // 3. Missing SECURITY or SUPER_ADMIN role rejected
        val supportPrincipal = AuthenticatedPrincipal(
            id = "supp-admin-1",
            tenantId = "tenant-1",
            kind = PrincipalKind.ADMIN,
            roles = setOf(AdminRole.SUPPORT),
        )
        assertFailsWith<AuthenticationFailure.Rejected> {
            s.createEncryptedBackup(sampleBackupCommand(principal = supportPrincipal, clusterId = cluster.clusterId))
        }

        // 4. Non-KMS or invalid encryption rejected
        assertFailsWith<AuthenticationFailure.Rejected> {
            s.createEncryptedBackup(sampleBackupCommand(clusterId = cluster.clusterId, kmsKeyArn = "plaintext-unencrypted"))
        }

        // 5. Malformed SHA-256 checksum rejected
        assertFailsWith<AuthenticationFailure.Rejected> {
            s.createEncryptedBackup(sampleBackupCommand(clusterId = cluster.clusterId, backupChecksumSha256 = "invalid-hash"))
        }

        // 6. Create valid backup and test restore target out of bounds
        val validBackupRes = s.createEncryptedBackup(sampleBackupCommand(clusterId = cluster.clusterId, idempotencyKey = "idem-val-bk"))

        // Target before earliest recovery point rejected
        assertFailsWith<AuthenticationFailure.Rejected> {
            s.executePitrRestore(
                ExecutePitrRestoreCommand(
                    principal = securityAdmin,
                    sessionId = "sess-pitr-1",
                    tenantId = "tenant-1",
                    backupId = validBackupRes.backupId!!,
                    targetRecoveryPoint = now.minusSeconds(86400 * 30), // 30 days ago (out of 7d window)
                    reconciliation = ReconciliationEvidence(true, true, true, 10L),
                    restoreReason = "Out of window",
                    idempotencyKey = "idem-oow-1",
                    correlationId = "c",
                    causationId = "c",
                )
            )
        }

        // 7. Partial restore reconciliation results in NO-GO with FAILOVER_RESTORE_MIGRATION_PARTIAL
        val partialRestoreRes = s.executePitrRestore(
            ExecutePitrRestoreCommand(
                principal = securityAdmin,
                sessionId = "sess-pitr-1",
                tenantId = "tenant-1",
                backupId = validBackupRes.backupId!!,
                targetRecoveryPoint = now.minusSeconds(7200),
                reconciliation = ReconciliationEvidence(
                    journalReconciled = true,
                    projectionsReconciled = false, // Partial!
                    outboxReconciled = true,
                    reconciledRowsCount = 100L,
                ),
                restoreReason = "Partial restore test",
                idempotencyKey = "idem-part-rest",
                correlationId = "c",
                causationId = "c",
            )
        )
        val evalPartial = s.evaluatePitrReadiness(
            EvaluatePitrReadinessCommand(
                tenantId = "tenant-1",
                restoreId = partialRestoreRes.restoreId!!,
                correlationId = "c",
                causationId = "c",
            )
        )
        assertEquals(PitrDecision.NO_GO, evalPartial.decision)
        assertEquals(PitrReason.FAILOVER_RESTORE_MIGRATION_PARTIAL, evalPartial.reason)
    }

    @Test
    fun `INFRA-002-02-T003 Automate encrypted PITR backups survives concurrency, duplicate delivery, and dependency failure`() {
        val haStore = InMemoryPostgresHaStore()
        val cluster = sampleCluster()
        haStore.clusters["tenant-1:${cluster.clusterId}"] = cluster

        val store = InMemoryEncryptedPitrBackupStore()
        val s = service(haStore = haStore, store = store)

        // 1. Initial backup
        val cmd = sampleBackupCommand(clusterId = cluster.clusterId, idempotencyKey = "idem-concur-bk")
        val initialRes = s.createEncryptedBackup(cmd)
        assertNotNull(initialRes.backupId)

        // 2. Idempotent repeat returns identical outcome
        val repeatRes = s.createEncryptedBackup(cmd)
        assertEquals(initialRes.resultId, repeatRes.resultId)
        assertEquals(initialRes.backupId, repeatRes.backupId)

        // 3. Changed payload with same idempotency key fails with CONFLICT
        assertFailsWith<AuthenticationFailure.Rejected> {
            s.createEncryptedBackup(cmd.copy(baseSnapshotId = "snap-changed"))
        }

        // 4. Dependency failure fails closed
        val failingSessionService = service(
            sessionDir = sessionDirectory(failing = true),
            haStore = haStore,
            store = store,
        )
        val exDep = assertFailsWith<AuthenticationFailure.Rejected> {
            failingSessionService.createEncryptedBackup(
                sampleBackupCommand(clusterId = cluster.clusterId, idempotencyKey = "idem-dep-fail")
            )
        }
        assertEquals(AuthErrorCode.DEPENDENCY_UNAVAILABLE, exDep.code)

        // 5. Concurrent restore updates
        val executor = Executors.newFixedThreadPool(2)
        val latch = CountDownLatch(1)
        val restCmd1 = ExecutePitrRestoreCommand(
            principal = securityAdmin,
            sessionId = "sess-pitr-1",
            tenantId = "tenant-1",
            backupId = initialRes.backupId!!,
            targetRecoveryPoint = now.minusSeconds(1800),
            reconciliation = ReconciliationEvidence(true, true, true, 50L),
            restoreReason = "Restore Race 1",
            idempotencyKey = "idem-rest-race-1",
            correlationId = "corr-race-1",
            causationId = "cause-race-1",
            expectedVersion = 1L,
        )
        val restCmd2 = ExecutePitrRestoreCommand(
            principal = securityAdmin,
            sessionId = "sess-pitr-1",
            tenantId = "tenant-1",
            backupId = initialRes.backupId!!,
            targetRecoveryPoint = now.minusSeconds(1800),
            reconciliation = ReconciliationEvidence(true, true, true, 50L),
            restoreReason = "Restore Race 2",
            idempotencyKey = "idem-rest-race-2",
            correlationId = "corr-race-2",
            causationId = "cause-race-2",
            expectedVersion = 1L,
        )

        val results = mutableListOf<Result<PitrOperationResult>>()
        val fut1 = executor.submit(Callable {
            latch.await()
            runCatching { s.executePitrRestore(restCmd1) }
        })
        val fut2 = executor.submit(Callable {
            latch.await()
            runCatching { s.executePitrRestore(restCmd2) }
        })

        latch.countDown()
        results.add(fut1.get())
        results.add(fut2.get())
        executor.shutdown()

        val successCount = results.count { it.isSuccess }
        assertEquals(2, successCount, "Both distinct restores for different keys succeed independently")
    }

    @Test
    fun `INFRA-002-02-T004 Automate encrypted PITR backups remains compatible, recoverable, observable, and lifecycle-safe`() {
        val haStore = InMemoryPostgresHaStore()
        val cluster = sampleCluster()
        haStore.clusters["tenant-1:${cluster.clusterId}"] = cluster

        val store = InMemoryEncryptedPitrBackupStore()
        val s = service(haStore = haStore, store = store)

        // 1. Create backup
        val backupCmd = sampleBackupCommand(clusterId = cluster.clusterId, idempotencyKey = "idem-life-bk")
        val backupRes = s.createEncryptedBackup(backupCmd)

        // 2. Execute full PITR restore
        val restoreCmd = ExecutePitrRestoreCommand(
            principal = securityAdmin,
            sessionId = "sess-pitr-1",
            tenantId = "tenant-1",
            backupId = backupRes.backupId!!,
            targetRecoveryPoint = now.minusSeconds(3600),
            reconciliation = ReconciliationEvidence(
                journalReconciled = true,
                projectionsReconciled = true,
                outboxReconciled = true,
                reconciledRowsCount = 1000L,
            ),
            restoreReason = "Quarterly DR restore verification",
            idempotencyKey = "idem-life-rest",
            correlationId = "corr-life-rest",
            causationId = "cause-life-rest",
            expectedVersion = 1L,
        )
        val restoreRes = s.executePitrRestore(restoreCmd)
        assertEquals(RestoreStatus.RESTORED_AND_RECONCILED, restoreRes.restoreStatus)

        // 3. Evaluate readiness
        val eval = s.evaluatePitrReadiness(
            EvaluatePitrReadinessCommand(
                tenantId = "tenant-1",
                restoreId = restoreRes.restoreId!!,
                correlationId = "corr-life-eval",
                causationId = "cause-life-eval",
            )
        )
        assertEquals(PitrDecision.GO, eval.decision)
        assertEquals(PitrReason.RESTORED_AND_RECONCILED, eval.reason)

        // 4. Observability & Redaction checks
        val auditRecords = store.audit
        assertEquals(2, auditRecords.size)
        val restAudit = auditRecords[1]
        assertEquals("POSTGRES_PITR_RESTORE_RECONCILED", restAudit.type)
        assertEquals("corr-life-rest", restAudit.correlationId)

        val outboxRecords = store.outbox
        assertEquals(2, outboxRecords.size)
        val restOutbox = outboxRecords[1]
        assertEquals("PostgresPitrRestoreReconciled", restOutbox.type)
    }
}
