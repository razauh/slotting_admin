package com.slotting.admin.recovery

import java.time.Instant
import java.util.UUID

enum class StorageProviderType {
    S3_COMPATIBLE,
    LOCAL_FILESYSTEM,
    AWS_S3,
    GCS,
    AZURE_BLOB,
}

enum class StorageReadiness {
    NOT_CONFIGURED,
    CONFIGURED,
    VALIDATING,
    READY,
    DEGRADED,
    INVALID,
    DISABLED,
}

enum class BackupLifecycleStatus {
    PENDING,
    SNAPSHOT_IN_PROGRESS,
    ENCRYPTING,
    UPLOADING,
    STORED_ENCRYPTED,
    VERIFYING_STORAGE,
    STORAGE_VERIFIED,
    RESTORE_DRILL_PENDING,
    RESTORE_DRILL_IN_PROGRESS,
    RECONCILING,
    RECONCILED,
    FAILED,
    CORRUPT,
    UNRECOVERABLE,
    RETENTION_EXPIRED,
}

enum class RestoreDrillStatus {
    RESTORED_AND_RECONCILED,
    PARTIAL_RESTORE_DETECTED,
    RESTORE_FAILED,
}

enum class PatroniNodeRole {
    PRIMARY,
    STANDBY_SYNC,
    STANDBY_ASYNC,
}

data class BackupStorageConfig(
    val configId: UUID = UUID.randomUUID(),
    val version: Long = 1L,
    val enabled: Boolean = true,
    val providerType: StorageProviderType = StorageProviderType.S3_COMPATIBLE,
    val endpointUrl: String,
    val bucket: String,
    val pathPrefix: String = "backups/postgres",
    val region: String? = null,
    val accessKeyId: String,
    val encryptedSecret: ByteArray,
    val secretIv: ByteArray,
    val tlsEnabled: Boolean = true,
    val connectionTimeoutMs: Long = 5000L,
    val uploadTimeoutMs: Long = 30000L,
    val maxRetries: Int = 3,
    val storageSupportsObjectLock: Boolean = false,
    val objectLockConfigured: Boolean = false,
    val objectLockValidated: Boolean = false,
    val retentionDays: Int = 30,
    val status: StorageReadiness = StorageReadiness.CONFIGURED,
    val updatedBy: String,
    val updatedAt: Instant = Instant.now(),
)

data class BackupStorageValidationResult(
    val status: StorageReadiness,
    val reachable: Boolean,
    val authSuccessful: Boolean,
    val bucketExists: Boolean,
    val writeReadVerified: Boolean,
    val objectLockVerified: Boolean,
    val details: String,
    val timestamp: Instant = Instant.now(),
)

data class BackupArtifactMetadata(
    val backupId: UUID = UUID.randomUUID(),
    val backupType: String = "FULL_PHYSICAL_BASE_BACKUP",
    val clusterId: String,
    val postgresMajorVersion: Int = 16,
    val startedAt: Instant,
    val snapshotStartTimestamp: Instant,
    val completedAt: Instant? = null,
    val startLsn: String,
    val endLsn: String,
    val requiredWalRange: Pair<String, String>,
    val storageConfigVersion: Long,
    val artifactPath: String,
    val artifactByteSize: Long,
    val sha256Digest: String,
    val encryptionAlgorithm: String = "AES-256-GCM",
    val keyManagementProvider: String = "OPENBAO_TRANSIT",
    val keyAlias: String,
    val keyVersion: Int,
    val wrappedDekBase64: String,
    val ivBase64: String,
    val authTagBase64: String,
    val walContinuityVerified: Boolean = true,
    val status: BackupLifecycleStatus = BackupLifecycleStatus.STORED_ENCRYPTED,
    val retentionExpiry: Instant,
    val immutabilityLockActive: Boolean = false,
)

data class RecoveryObjectives(
    val rpoTargetMinutes: Long = 5L,
    val rtoTargetMinutes: Long = 15L,
    val restoreDrillCadenceDays: Int = 7,
    val alertOnBreach: Boolean = true,
    val approvedBy: String,
    val updatedAt: Instant = Instant.now(),
)

data class RestoreReconciliationReceipt(
    val drillId: UUID = UUID.randomUUID(),
    val backupId: UUID,
    val pitrTarget: Instant,
    val targetEnvironment: String = "ISOLATED_RECOVERY_TARGET",
    val externalSideEffectsDisabled: Boolean = true,
    val artifactDigestVerified: Boolean,
    val decryptionVerified: Boolean,
    val walContinuityVerified: Boolean,
    val postgresStartupVerified: Boolean,
    val flywayMigrationVerified: Boolean,
    val startingSchemaVersion: String,
    val targetSchemaVersion: String,
    val ledgerReconciled: Boolean,
    val totalDebitsMinorUnits: Long,
    val totalCreditsMinorUnits: Long,
    val projectionsReconciled: Boolean,
    val outboxInboxReconciled: Boolean,
    val ambiguousOperationsCount: Int,
    val unresolvedExceptions: List<String>,
    val measuredRpoMinutes: Long,
    val measuredRtoMinutes: Long,
    val rpoBreached: Boolean,
    val rtoBreached: Boolean,
    val status: RestoreDrillStatus,
    val startedAt: Instant,
    val completedAt: Instant = Instant.now(),
    val evidenceReference: String,
)

data class PatroniNodeInfo(
    val nodeId: String,
    val role: PatroniNodeRole,
    val healthy: Boolean,
    val replicationLagBytes: Long = 0L,
    val timeline: Int = 1,
)

data class PatroniClusterStatus(
    val clusterName: String,
    val leaderNodeId: String,
    val stableEndpoint: String,
    val nodes: List<PatroniNodeInfo>,
    val dcsQuorumHealthy: Boolean,
    val lastSwitchover: Instant? = null,
    val lastFailover: Instant? = null,
)

data class DatabaseTopologyTransition(
    val transitionType: String, // "SWITCHOVER" or "FAILOVER"
    val oldPrimaryNodeId: String,
    val newPrimaryNodeId: String,
    val inFlightOperationsReplayed: Int,
    val ambiguousOperationsDetected: Int,
    val transitionTimestamp: Instant = Instant.now(),
    val requestedBy: String,
    val approvedBy: String? = null,
)
