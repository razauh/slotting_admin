package com.slotting.admin.recovery

import com.slotting.admin.auth.AdminPermission
import com.slotting.admin.auth.AdminRbacPolicy
import com.slotting.admin.auth.AdminRole
import com.slotting.admin.auth.AuditEvent
import com.slotting.admin.auth.AuthenticatedPrincipal
import com.slotting.admin.auth.PrincipalKind
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test
import java.nio.charset.StandardCharsets
import java.time.Clock
import java.time.Duration
import java.time.Instant
import java.time.ZoneOffset
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue

class RecoveryOrchestrationContractTest {

    private val now = Instant.parse("2026-09-26T18:00:00Z")
    private val clock = Clock.fixed(now, ZoneOffset.UTC)
    private val tenantId = "tenant-recovery-test"

    // RBAC Principals
    private val recoveryAdmin = AuthenticatedPrincipal(
        id = "admin-infra-sec-01",
        tenantId = tenantId,
        kind = PrincipalKind.ADMIN,
        roles = setOf(AdminRole.SECURITY, AdminRole.SUPER_ADMIN),
    )

    private val auditorAdmin = AuthenticatedPrincipal(
        id = "admin-auditor-01",
        tenantId = tenantId,
        kind = PrincipalKind.ADMIN,
        roles = setOf(AdminRole.AUDITOR),
    )

    private val supportAdmin = AuthenticatedPrincipal(
        id = "admin-support-01",
        tenantId = tenantId,
        kind = PrincipalKind.ADMIN,
        roles = setOf(AdminRole.SUPPORT),
    )

    private val rbacPolicy = AdminRbacPolicy(dualControlRequired = true)

    private lateinit var s3StorageAdapter: S3CompatibleStorageAdapter
    private lateinit var filesystemAdapter: FilesystemStorageAdapter
    private lateinit var openBaoProvider: OpenBaoTransitProvider
    private lateinit var envelopeEncryptor: BackupEnvelopeEncryptor
    private lateinit var haOrchestrator: PatroniHaOrchestrator

    private val auditEvents = mutableListOf<AuditEvent>()
    private val alerts = mutableListOf<Pair<String, String>>()
    private lateinit var recoveryService: RecoveryOrchestrationService

    @BeforeEach
    fun setUp() {
        auditEvents.clear()
        alerts.clear()

        s3StorageAdapter = S3CompatibleStorageAdapter()
        filesystemAdapter = FilesystemStorageAdapter()
        openBaoProvider = OpenBaoTransitProvider(environment = "PRODUCTION")
        envelopeEncryptor = BackupEnvelopeEncryptor(openBaoProvider, "backup-master-key", environment = "PRODUCTION")
        haOrchestrator = PatroniHaOrchestrator(rbacPolicy = rbacPolicy)

        recoveryService = RecoveryOrchestrationService(
            rbacPolicy = rbacPolicy,
            storageAdapters = mapOf(
                StorageProviderType.S3_COMPATIBLE to s3StorageAdapter,
                StorageProviderType.LOCAL_FILESYSTEM to filesystemAdapter,
            ),
            envelopeEncryptor = envelopeEncryptor,
            haOrchestrator = haOrchestrator,
            clock = clock,
            auditSink = { auditEvents.add(it) },
            alertSink = { type, msg -> alerts.add(type to msg) },
        )
    }

    private fun configureAndValidateStorage(): BackupStorageConfig {
        val config = recoveryService.saveStorageConfig(
            principal = recoveryAdmin,
            config = BackupStorageConfig(
                endpointUrl = "https://s3.eu-central-1.storage.internal",
                bucket = "slotting-authoritative-backups",
                accessKeyId = "AKIA-BACKUP-TEST-01",
                encryptedSecret = byteArrayOf(10, 20, 30),
                secretIv = byteArrayOf(1, 2, 3),
                objectLockConfigured = true,
                retentionDays = 30,
                updatedBy = recoveryAdmin.id,
            )
        )
        val validation = recoveryService.validateStorageConfig(recoveryAdmin, config.version)
        assertEquals(StorageReadiness.READY, validation.status)
        return config
    }

    @Test
    fun `test 1 - Full Backup - Encrypted upload with OpenBao Transit, server-side digest validation, and truthful stored state`() {
        configureAndValidateStorage()

        val rawDbPayload = "PHYSICAL_BASE_BACKUP_DUMP_STREAM_SIMULATED".toByteArray(StandardCharsets.UTF_8)
        val artifact = recoveryService.createEncryptedBackup(
            principal = recoveryAdmin,
            clusterId = "postgres-prod-cluster-01",
            snapshotPayload = rawDbPayload,
            startLsn = "0/16000000",
            endLsn = "0/160000FF",
        )

        assertNotNull(artifact)
        assertEquals(BackupLifecycleStatus.STORED_ENCRYPTED, artifact.status)
        assertEquals("OPENBAO_TRANSIT", artifact.keyManagementProvider)
        assertEquals(1, artifact.keyVersion)
        assertTrue(artifact.sha256Digest.isNotBlank())
        assertTrue(artifact.immutabilityLockActive)

        // Truthful state: STORED_ENCRYPTED != RECONCILED!
        assertTrue(artifact.status != BackupLifecycleStatus.RECONCILED)

        // Read stored artifact from storage: ciphertext must NOT equal plaintext
        val readBack = s3StorageAdapter.retrieveArtifact(artifact.artifactPath)
        assertFalse(readBack.payload.contentEquals(rawDbPayload))
        assertEquals(artifact.sha256Digest, readBack.sha256Digest)
    }

    @Test
    fun `test 2 - Isolated Restore & Financial Reconciliation - Balanced ledger and projections succeed`() {
        configureAndValidateStorage()

        val rawDbPayload = "PHYSICAL_BASE_BACKUP_SNAPSHOT".toByteArray(StandardCharsets.UTF_8)
        val artifact = recoveryService.createEncryptedBackup(
            principal = recoveryAdmin,
            clusterId = "postgres-prod-cluster-01",
            snapshotPayload = rawDbPayload,
        )

        // Balanced double-entry ledger: credits == debits per currency (EUR)
        val balancedDb = SimulatedRestoreDatabase(
            schemaVersion = "V37",
            flywayClean = true,
            journalEntries = listOf(
                SimulatedJournalEntry("ACC_PLAYER_1", "EUR", debitMinorUnits = 10000, creditMinorUnits = 0),
                SimulatedJournalEntry("ACC_HOUSE_1", "EUR", debitMinorUnits = 0, creditMinorUnits = 10000),
            ),
            projectionBalances = mapOf(
                "ACC_PLAYER_1" to -10000L,
                "ACC_HOUSE_1" to 10000L,
            ),
            outboxPendingCount = 0,
            ambiguousOperationsCount = 0,
        )

        val receipt = recoveryService.executeRestoreDrill(
            principal = recoveryAdmin,
            backupId = artifact.backupId,
            pitrTarget = now.minus(Duration.ofMinutes(2)),
            simulatedDb = balancedDb,
        )

        assertEquals(RestoreDrillStatus.RESTORED_AND_RECONCILED, receipt.status)
        assertTrue(receipt.artifactDigestVerified)
        assertTrue(receipt.decryptionVerified)
        assertTrue(receipt.walContinuityVerified)
        assertTrue(receipt.flywayMigrationVerified)
        assertTrue(receipt.ledgerReconciled)
        assertTrue(receipt.projectionsReconciled)
        assertTrue(receipt.outboxInboxReconciled)
        assertEquals(0, receipt.ambiguousOperationsCount)
        assertTrue(receipt.unresolvedExceptions.isEmpty())

        // Verified backup status transitions to RECONCILED
        val updatedArtifact = recoveryService.listBackups(recoveryAdmin).find { it.backupId == artifact.backupId }
        assertNotNull(updatedArtifact)
        assertEquals(BackupLifecycleStatus.RECONCILED, updatedArtifact.status)
    }

    @Test
    fun `test 3 - Corrupt Backup - Tampered artifact fails SHA-256 digest and GCM authentication`() {
        configureAndValidateStorage()

        val rawDbPayload = "PHYSICAL_BASE_BACKUP_SNAPSHOT".toByteArray(StandardCharsets.UTF_8)
        val artifact = recoveryService.createEncryptedBackup(
            principal = recoveryAdmin,
            clusterId = "postgres-prod-cluster-01",
            snapshotPayload = rawDbPayload,
        )

        // Tamper with ciphertext in storage
        val stored = s3StorageAdapter.retrieveArtifact(artifact.artifactPath)
        val tamperedBytes = stored.payload.clone()
        tamperedBytes[0] = (tamperedBytes[0] + 1).toByte()
        s3StorageAdapter.storeArtifact(artifact.artifactPath, tamperedBytes)

        val validDb = SimulatedRestoreDatabase(
            schemaVersion = "V37",
            journalEntries = emptyList(),
            projectionBalances = emptyMap(),
        )

        val receipt = recoveryService.executeRestoreDrill(
            principal = recoveryAdmin,
            backupId = artifact.backupId,
            pitrTarget = now,
            simulatedDb = validDb,
        )

        assertEquals(RestoreDrillStatus.RESTORE_FAILED, receipt.status)
        assertFalse(receipt.artifactDigestVerified)
        assertFalse(receipt.decryptionVerified)
        assertTrue(receipt.unresolvedExceptions.any { it.contains("SHA-256 digest mismatch") })
    }

    @Test
    fun `test 4 - KMS Outage - OpenBao Transit failure fails safely without dev key fallback in production`() {
        configureAndValidateStorage()

        // Simulate OpenBao Transit offline / sealed
        openBaoProvider.simulatedAvailable = false

        assertFailsWith<IllegalStateException> {
            recoveryService.createEncryptedBackup(
                principal = recoveryAdmin,
                clusterId = "postgres-prod-cluster-01",
                snapshotPayload = "PAYLOAD".toByteArray(StandardCharsets.UTF_8),
            )
        }
    }

    @Test
    fun `test 5 - Partial Restore - Missing WAL segment or ledger imbalance yields PARTIAL_RESTORE_DETECTED`() {
        configureAndValidateStorage()

        val artifact = recoveryService.createEncryptedBackup(
            principal = recoveryAdmin,
            clusterId = "postgres-prod-cluster-01",
            snapshotPayload = "VALID_PAYLOAD".toByteArray(StandardCharsets.UTF_8),
        )

        // Unbalanced ledger (debits != credits)
        val unbalancedDb = SimulatedRestoreDatabase(
            schemaVersion = "V37",
            journalEntries = listOf(
                SimulatedJournalEntry("ACC_PLAYER_1", "EUR", debitMinorUnits = 10000, creditMinorUnits = 0),
                SimulatedJournalEntry("ACC_HOUSE_1", "EUR", debitMinorUnits = 0, creditMinorUnits = 5000), // Missing 5000!
            ),
            projectionBalances = emptyMap(),
        )

        val receipt = recoveryService.executeRestoreDrill(
            principal = recoveryAdmin,
            backupId = artifact.backupId,
            pitrTarget = now,
            simulatedDb = unbalancedDb,
        )

        assertEquals(RestoreDrillStatus.PARTIAL_RESTORE_DETECTED, receipt.status)
        assertFalse(receipt.ledgerReconciled)
        assertTrue(receipt.unresolvedExceptions.any { it.contains("Ledger double-entry imbalance") })
    }

    @Test
    fun `test 6 - Ambiguous Operations - Ambiguous financial operations block recovery completion`() {
        configureAndValidateStorage()

        val artifact = recoveryService.createEncryptedBackup(
            principal = recoveryAdmin,
            clusterId = "postgres-prod-cluster-01",
            snapshotPayload = "VALID_PAYLOAD".toByteArray(StandardCharsets.UTF_8),
        )

        val ambiguousDb = SimulatedRestoreDatabase(
            schemaVersion = "V37",
            journalEntries = listOf(
                SimulatedJournalEntry("ACC_1", "EUR", 100, 0),
                SimulatedJournalEntry("ACC_2", "EUR", 0, 100),
            ),
            projectionBalances = mapOf("ACC_1" to -100L, "ACC_2" to 100L),
            ambiguousOperationsCount = 2, // 2 unacknowledged payouts in-flight during crash
        )

        val receipt = recoveryService.executeRestoreDrill(
            principal = recoveryAdmin,
            backupId = artifact.backupId,
            pitrTarget = now,
            simulatedDb = ambiguousDb,
        )

        assertEquals(RestoreDrillStatus.PARTIAL_RESTORE_DETECTED, receipt.status)
        assertFalse(receipt.outboxInboxReconciled)
        assertEquals(2, receipt.ambiguousOperationsCount)
        assertTrue(receipt.unresolvedExceptions.any { it.contains("Ambiguous financial operations") })
    }

    @Test
    fun `test 7 - RPO and RTO Measurement & Breach Alerts - Target breaches trigger alerts`() {
        configureAndValidateStorage()

        // Configure strict targets: RPO = 1 minute, RTO = 1 minute
        recoveryService.updateRecoveryObjectives(
            principal = recoveryAdmin,
            objectives = RecoveryObjectives(
                rpoTargetMinutes = 1L,
                rtoTargetMinutes = 0L, // will breach
                approvedBy = recoveryAdmin.id,
            )
        )

        val artifact = recoveryService.createEncryptedBackup(
            principal = recoveryAdmin,
            clusterId = "postgres-prod-cluster-01",
            snapshotPayload = "VALID_PAYLOAD".toByteArray(StandardCharsets.UTF_8),
        )

        // PITR target is 10 minutes prior -> 10m RPO > 1m target!
        val db = SimulatedRestoreDatabase(
            schemaVersion = "V37",
            journalEntries = emptyList(),
            projectionBalances = emptyMap(),
        )

        val receipt = recoveryService.executeRestoreDrill(
            principal = recoveryAdmin,
            backupId = artifact.backupId,
            pitrTarget = now.minus(Duration.ofMinutes(10)),
            simulatedDb = db,
        )

        assertTrue(receipt.rpoBreached)
        assertTrue(receipt.rtoBreached)
        assertTrue(alerts.any { it.first == "RPO_TARGET_BREACHED" })
        assertTrue(alerts.any { it.first == "RTO_TARGET_BREACHED" })
    }

    @Test
    fun `test 8 - Patroni HA - Switchover vs Failover distinction and lag observation`() {
        val status = haOrchestrator.getClusterStatus(recoveryAdmin)
        assertEquals("pg-node-01", status.leaderNodeId)
        assertTrue(status.dcsQuorumHealthy)

        // 1. Planned graceful switchover to standby-sync node pg-node-02
        val switchover = haOrchestrator.requestSwitchover(recoveryAdmin, "pg-node-02")
        assertEquals("SWITCHOVER", switchover.transitionType)
        assertEquals("pg-node-01", switchover.oldPrimaryNodeId)
        assertEquals("pg-node-02", switchover.newPrimaryNodeId)
        assertEquals(0, switchover.inFlightOperationsReplayed)

        // Verify primary changed to pg-node-02
        val newStatus = haOrchestrator.getClusterStatus(recoveryAdmin)
        assertEquals("pg-node-02", newStatus.leaderNodeId)

        // 2. Emergency failover when primary pg-node-02 is dead
        haOrchestrator.setNodeHealth("pg-node-02", healthy = false)
        val failover = haOrchestrator.executeEmergencyFailover(
            principal = recoveryAdmin,
            candidateNodeId = "pg-node-03",
            reason = "Node 02 hardware power outage",
        )
        assertEquals("FAILOVER", failover.transitionType)
        assertEquals("pg-node-02", failover.oldPrimaryNodeId)
        assertEquals("pg-node-03", failover.newPrimaryNodeId)
        assertTrue(failover.inFlightOperationsReplayed > 0)
    }

    @Test
    fun `test 9 - Admin Storage Settings - Write-only secrets and versioning preservation`() {
        val v1 = recoveryService.saveStorageConfig(
            principal = recoveryAdmin,
            config = BackupStorageConfig(
                endpointUrl = "https://s3.primary.storage.internal",
                bucket = "bucket-v1",
                accessKeyId = "KEY-V1",
                encryptedSecret = byteArrayOf(99, 100),
                secretIv = byteArrayOf(1, 2),
                updatedBy = recoveryAdmin.id,
            )
        )
        assertEquals(1L, v1.version)

        // Read API must never expose stored secret
        val readConfig = recoveryService.getStorageConfig(recoveryAdmin, v1.version)
        assertNotNull(readConfig)
        assertEquals(0, readConfig.encryptedSecret.size)
        assertEquals(0, readConfig.secretIv.size)

        // Rotate credentials creates v2
        val v2 = recoveryService.rotateStorageCredentials(
            principal = recoveryAdmin,
            version = v1.version,
            newAccessKey = "KEY-V2",
            newEncryptedSecret = byteArrayOf(55, 66),
            newSecretIv = byteArrayOf(3, 4),
        )
        assertEquals(2L, v2.version)

        // Historical v1 configuration is still preserved
        val oldV1 = recoveryService.getStorageConfig(recoveryAdmin, 1L)
        assertNotNull(oldV1)
        assertEquals("KEY-V1", oldV1.accessKeyId)
    }

    @Test
    fun `test 10 - Admin RBAC Isolation - Unauthorized users cannot access backup or HA commands`() {
        // Support role cannot view backup settings
        assertFailsWith<SecurityException> {
            recoveryService.getStorageConfig(supportAdmin)
        }

        // Support role cannot execute restore drill
        assertFailsWith<SecurityException> {
            recoveryService.executeRestoreDrill(
                principal = supportAdmin,
                backupId = java.util.UUID.randomUUID(),
                pitrTarget = now,
                simulatedDb = SimulatedRestoreDatabase("V37", true, emptyList(), emptyMap()),
            )
        }

        // Auditor can view status but cannot trigger failover
        val status = haOrchestrator.getClusterStatus(auditorAdmin)
        assertNotNull(status)

        assertFailsWith<SecurityException> {
            haOrchestrator.executeEmergencyFailover(auditorAdmin, "pg-node-02", "unauthorized")
        }
    }
}
