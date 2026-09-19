package com.slotting.admin.infra

import com.slotting.admin.auth.*
import java.security.MessageDigest
import java.time.Clock
import java.time.Instant
import java.util.UUID
import java.util.concurrent.ConcurrentHashMap

/**
 * Binding flag to enforce the protected risk assertion for INFRA-002-02:
 * "failover/restore/migration partial"
 */
object EncryptedPitrBackupBinding {
    @Volatile
    var isBound: Boolean = true

    fun checkBound() {
        if (!isBound) {
            throw AssertionError("failover/restore/migration partial")
        }
    }
}

enum class BackupStatus {
    PENDING,
    COMPLETED,
    FAILED,
    EXPIRED,
}

enum class RestoreStatus {
    RESTORE_IN_PROGRESS,
    RESTORED_AND_RECONCILED,
    PARTIAL_RESTORE_DETECTED,
    RESTORE_FAILED,
}

enum class PitrDecision {
    GO,
    NO_GO,
}

enum class PitrReason {
    RESTORED_AND_RECONCILED,
    FAILOVER_RESTORE_MIGRATION_PARTIAL,
    TARGET_TIMESTAMP_OUT_OF_BOUNDS,
    BACKUP_UNENCRYPTED_OR_CORRUPT,
    MISSING_BACKUP,
    CLUSTER_NOT_FOUND,
    UNAUTHORIZED_ACCESS,
}

data class PitrBackupMetadata(
    val backupId: UUID,
    val clusterId: UUID,
    val tenantId: String,
    val environment: IacEnvironmentType,
    val baseSnapshotId: String,
    val earliestRecoveryPoint: Instant,
    val latestRecoveryPoint: Instant,
    val kmsKeyArn: String,
    val encryptionAlgorithm: String = "AES-256-GCM",
    val backupChecksumSha256: String,
    val status: BackupStatus,
    val createdAt: Instant,
)

data class PitrRestoreEntry(
    val restoreId: UUID,
    val backupId: UUID,
    val clusterId: UUID,
    val tenantId: String,
    val targetRecoveryPoint: Instant,
    val status: RestoreStatus,
    val reconciliation: ReconciliationEvidence,
    val evidenceReference: String,
    val version: Long = 1L,
    val restoredAt: Instant,
)

data class CreateEncryptedPitrBackupCommand(
    val principal: AuthenticatedPrincipal?,
    val sessionId: String,
    val tenantId: String,
    val clusterId: UUID,
    val environment: IacEnvironmentType,
    val baseSnapshotId: String,
    val kmsKeyArn: String,
    val earliestRecoveryPoint: Instant,
    val latestRecoveryPoint: Instant,
    val backupChecksumSha256: String,
    val idempotencyKey: String,
    val correlationId: String,
    val causationId: String,
    val expectedVersion: Long = 1L,
)

data class ExecutePitrRestoreCommand(
    val principal: AuthenticatedPrincipal?,
    val sessionId: String,
    val tenantId: String,
    val backupId: UUID,
    val targetRecoveryPoint: Instant,
    val reconciliation: ReconciliationEvidence,
    val restoreReason: String,
    val idempotencyKey: String,
    val correlationId: String,
    val causationId: String,
    val expectedVersion: Long = 1L,
)

data class EvaluatePitrReadinessCommand(
    val tenantId: String,
    val restoreId: UUID,
    val correlationId: String,
    val causationId: String,
)

data class PitrOperationResult(
    val resultId: UUID,
    val tenantId: String,
    val backupId: UUID?,
    val restoreId: UUID?,
    val clusterId: UUID,
    val restoreStatus: RestoreStatus?,
    val directEligibilityGranted: Boolean = false,
    val financialMutationPermitted: Boolean = false,
    val evidenceReference: String,
    val serverTime: Instant,
    val correlationId: String,
    val causationId: String,
)

data class PitrEvaluationResult(
    val decision: PitrDecision,
    val reason: PitrReason,
    val restoreId: UUID,
    val clusterId: UUID,
    val status: RestoreStatus,
    val directEligibilityGranted: Boolean = false,
    val financialMutationPermitted: Boolean = false,
    val evidenceReference: String,
    val evaluatedAt: Instant,
)

interface EncryptedPitrBackupStore {
    fun findByIdempotency(tenantId: String, idempotencyKey: String): Pair<String, PitrOperationResult>?
    fun findBackup(tenantId: String, backupId: UUID): PitrBackupMetadata?
    fun findRestore(tenantId: String, restoreId: UUID): PitrRestoreEntry?
    fun saveBackup(
        backup: PitrBackupMetadata,
        result: PitrOperationResult,
        idempotencyFingerprint: String,
        idempotencyKey: String,
        audit: AuditEvent,
        outbox: OutboxEvent,
    )
    fun saveRestore(
        restore: PitrRestoreEntry,
        result: PitrOperationResult,
        idempotencyFingerprint: String,
        idempotencyKey: String,
        audit: AuditEvent,
        outbox: OutboxEvent,
    )
    fun updateRestoreStatus(
        tenantId: String,
        restoreId: UUID,
        newStatus: RestoreStatus,
        expectedVersion: Long,
        result: PitrOperationResult,
        idempotencyFingerprint: String,
        idempotencyKey: String,
        audit: AuditEvent,
        outbox: OutboxEvent,
    ): PitrRestoreEntry
}

class InMemoryEncryptedPitrBackupStore : EncryptedPitrBackupStore {
    val backups = ConcurrentHashMap<String, PitrBackupMetadata>()
    val restores = ConcurrentHashMap<String, PitrRestoreEntry>()
    val results = ConcurrentHashMap<String, Pair<String, PitrOperationResult>>()
    val audit = mutableListOf<AuditEvent>()
    val outbox = mutableListOf<OutboxEvent>()

    @Synchronized
    override fun findByIdempotency(tenantId: String, idempotencyKey: String): Pair<String, PitrOperationResult>? =
        results["$tenantId:$idempotencyKey"]

    @Synchronized
    override fun findBackup(tenantId: String, backupId: UUID): PitrBackupMetadata? =
        backups["$tenantId:$backupId"]

    @Synchronized
    override fun findRestore(tenantId: String, restoreId: UUID): PitrRestoreEntry? =
        restores["$tenantId:$restoreId"]

    @Synchronized
    override fun saveBackup(
        backup: PitrBackupMetadata,
        result: PitrOperationResult,
        idempotencyFingerprint: String,
        idempotencyKey: String,
        audit: AuditEvent,
        outbox: OutboxEvent,
    ) {
        backups["${backup.tenantId}:${backup.backupId}"] = backup
        results["${backup.tenantId}:$idempotencyKey"] = idempotencyFingerprint to result
        this.audit.add(audit)
        this.outbox.add(outbox)
    }

    @Synchronized
    override fun saveRestore(
        restore: PitrRestoreEntry,
        result: PitrOperationResult,
        idempotencyFingerprint: String,
        idempotencyKey: String,
        audit: AuditEvent,
        outbox: OutboxEvent,
    ) {
        restores["${restore.tenantId}:${restore.restoreId}"] = restore
        results["${restore.tenantId}:$idempotencyKey"] = idempotencyFingerprint to result
        this.audit.add(audit)
        this.outbox.add(outbox)
    }

    @Synchronized
    override fun updateRestoreStatus(
        tenantId: String,
        restoreId: UUID,
        newStatus: RestoreStatus,
        expectedVersion: Long,
        result: PitrOperationResult,
        idempotencyFingerprint: String,
        idempotencyKey: String,
        audit: AuditEvent,
        outbox: OutboxEvent,
    ): PitrRestoreEntry {
        val existing = restores["$tenantId:$restoreId"]
            ?: throw AuthenticationFailure.Rejected(AuthErrorCode.INVALID)
        if (existing.version != expectedVersion) {
            throw AuthenticationFailure.Rejected(AuthErrorCode.CONFLICT)
        }
        val updated = existing.copy(
            status = newStatus,
            version = existing.version + 1,
        )
        restores["$tenantId:$restoreId"] = updated
        results["$tenantId:$idempotencyKey"] = idempotencyFingerprint to result
        this.audit.add(audit)
        this.outbox.add(outbox)
        return updated
    }
}

class EncryptedPitrBackupService(
    private val sessions: AdminSessionDirectory,
    private val postgresHaStore: PostgresHaStore,
    private val store: EncryptedPitrBackupStore,
    private val clock: Clock,
) {
    @Synchronized
    fun createEncryptedBackup(command: CreateEncryptedPitrBackupCommand): PitrOperationResult {
        EncryptedPitrBackupBinding.checkBound()

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

        // Validate cluster exists in postgresHaStore (INFRA-002-01 dependency)
        val cluster = postgresHaStore.findCluster(command.tenantId, command.clusterId)
            ?: throw AuthenticationFailure.Rejected(AuthErrorCode.INVALID)

        // Validate strong KMS encryption and SHA-256 checksum
        if (command.kmsKeyArn.isBlank() ||
            !command.kmsKeyArn.startsWith("arn:aws:kms:") ||
            command.backupChecksumSha256.length != 64 ||
            command.earliestRecoveryPoint.isAfter(command.latestRecoveryPoint)) {
            throw AuthenticationFailure.Rejected(AuthErrorCode.INVALID)
        }

        val fp = fingerprintBackupCommand(command)
        store.findByIdempotency(command.tenantId, command.idempotencyKey)?.let { (cachedFp, cachedResult) ->
            if (cachedFp != fp) throw AuthenticationFailure.Rejected(AuthErrorCode.CONFLICT)
            return cachedResult
        }

        val now = clock.instant()
        val backupId = UUID.randomUUID()
        val resultId = UUID.randomUUID()
        val evidenceRef = "PITR-BACKUP-${command.tenantId}-${command.clusterId}-$backupId"

        val backup = PitrBackupMetadata(
            backupId = backupId,
            clusterId = command.clusterId,
            tenantId = command.tenantId,
            environment = command.environment,
            baseSnapshotId = command.baseSnapshotId,
            earliestRecoveryPoint = command.earliestRecoveryPoint,
            latestRecoveryPoint = command.latestRecoveryPoint,
            kmsKeyArn = command.kmsKeyArn,
            encryptionAlgorithm = "AES-256-GCM",
            backupChecksumSha256 = command.backupChecksumSha256,
            status = BackupStatus.COMPLETED,
            createdAt = now,
        )

        val result = PitrOperationResult(
            resultId = resultId,
            tenantId = command.tenantId,
            backupId = backupId,
            restoreId = null,
            clusterId = command.clusterId,
            restoreStatus = null,
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
            type = "POSTGRES_PITR_BACKUP_COMPLETED",
            occurredAt = now,
            correlationId = command.correlationId,
            causationId = command.causationId,
        )

        val outbox = OutboxEvent(
            eventId = UUID.randomUUID(),
            resultId = resultId,
            tenantId = command.tenantId,
            type = "PostgresPitrBackupCompleted",
            createdAt = now,
        )

        store.saveBackup(backup, result, fp, command.idempotencyKey, audit, outbox)
        return result
    }

    @Synchronized
    fun executePitrRestore(command: ExecutePitrRestoreCommand): PitrOperationResult {
        EncryptedPitrBackupBinding.checkBound()

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

        if (command.restoreReason.isBlank()) {
            throw AuthenticationFailure.Rejected(AuthErrorCode.INVALID)
        }

        val backup = store.findBackup(command.tenantId, command.backupId)
            ?: throw AuthenticationFailure.Rejected(AuthErrorCode.INVALID)

        // Validate target recovery point is strictly within backup window
        if (command.targetRecoveryPoint.isBefore(backup.earliestRecoveryPoint) ||
            command.targetRecoveryPoint.isAfter(backup.latestRecoveryPoint)) {
            throw AuthenticationFailure.Rejected(AuthErrorCode.INVALID)
        }

        val fp = fingerprintRestoreCommand(command)
        store.findByIdempotency(command.tenantId, command.idempotencyKey)?.let { (cachedFp, cachedResult) ->
            if (cachedFp != fp) throw AuthenticationFailure.Rejected(AuthErrorCode.CONFLICT)
            return cachedResult
        }

        val now = clock.instant()
        val restoreId = UUID.randomUUID()
        val resultId = UUID.randomUUID()
        val evidenceRef = "PITR-RESTORE-${command.tenantId}-${backup.clusterId}-$restoreId"

        val restoreStatus = when {
            command.reconciliation.isFullyReconciled -> RestoreStatus.RESTORED_AND_RECONCILED
            command.reconciliation.isPartial -> RestoreStatus.PARTIAL_RESTORE_DETECTED
            else -> RestoreStatus.RESTORE_FAILED
        }

        val entry = PitrRestoreEntry(
            restoreId = restoreId,
            backupId = command.backupId,
            clusterId = backup.clusterId,
            tenantId = command.tenantId,
            targetRecoveryPoint = command.targetRecoveryPoint,
            status = restoreStatus,
            reconciliation = command.reconciliation,
            evidenceReference = evidenceRef,
            version = 1L,
            restoredAt = now,
        )

        val result = PitrOperationResult(
            resultId = resultId,
            tenantId = command.tenantId,
            backupId = command.backupId,
            restoreId = restoreId,
            clusterId = backup.clusterId,
            restoreStatus = restoreStatus,
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
            type = if (restoreStatus == RestoreStatus.RESTORED_AND_RECONCILED) "POSTGRES_PITR_RESTORE_RECONCILED" else "POSTGRES_PITR_RESTORE_PARTIAL",
            occurredAt = now,
            correlationId = command.correlationId,
            causationId = command.causationId,
        )

        val outbox = OutboxEvent(
            eventId = UUID.randomUUID(),
            resultId = resultId,
            tenantId = command.tenantId,
            type = if (restoreStatus == RestoreStatus.RESTORED_AND_RECONCILED) "PostgresPitrRestoreReconciled" else "PostgresPitrRestorePartial",
            createdAt = now,
        )

        store.saveRestore(entry, result, fp, command.idempotencyKey, audit, outbox)
        return result
    }

    @Synchronized
    fun evaluatePitrReadiness(command: EvaluatePitrReadinessCommand): PitrEvaluationResult {
        EncryptedPitrBackupBinding.checkBound()

        val now = clock.instant()
        val restore = store.findRestore(command.tenantId, command.restoreId)

        if (restore == null) {
            return PitrEvaluationResult(
                decision = PitrDecision.NO_GO,
                reason = PitrReason.MISSING_BACKUP,
                restoreId = command.restoreId,
                clusterId = UUID.randomUUID(),
                status = RestoreStatus.RESTORE_FAILED,
                directEligibilityGranted = false,
                financialMutationPermitted = false,
                evidenceReference = "EVID-PITR-MISSING-${command.restoreId}",
                evaluatedAt = now,
            )
        }

        if (restore.status != RestoreStatus.RESTORED_AND_RECONCILED || !restore.reconciliation.isFullyReconciled) {
            return PitrEvaluationResult(
                decision = PitrDecision.NO_GO,
                reason = PitrReason.FAILOVER_RESTORE_MIGRATION_PARTIAL,
                restoreId = restore.restoreId,
                clusterId = restore.clusterId,
                status = restore.status,
                directEligibilityGranted = false,
                financialMutationPermitted = false,
                evidenceReference = restore.evidenceReference,
                evaluatedAt = now,
            )
        }

        return PitrEvaluationResult(
            decision = PitrDecision.GO,
            reason = PitrReason.RESTORED_AND_RECONCILED,
            restoreId = restore.restoreId,
            clusterId = restore.clusterId,
            status = restore.status,
            directEligibilityGranted = false,
            financialMutationPermitted = false,
            evidenceReference = restore.evidenceReference,
            evaluatedAt = now,
        )
    }

    private fun fingerprintBackupCommand(command: CreateEncryptedPitrBackupCommand): String {
        val raw = "${command.tenantId}|${command.clusterId}|${command.baseSnapshotId}|" +
            "${command.kmsKeyArn}|${command.backupChecksumSha256}|${command.earliestRecoveryPoint}|" +
            "${command.latestRecoveryPoint}|${command.expectedVersion}"
        val md = MessageDigest.getInstance("SHA-256")
        return md.digest(raw.toByteArray(Charsets.UTF_8)).joinToString("") { "%02x".format(it) }
    }

    private fun fingerprintRestoreCommand(command: ExecutePitrRestoreCommand): String {
        val raw = "${command.tenantId}|${command.backupId}|${command.targetRecoveryPoint}|" +
            "${command.reconciliation.journalReconciled}|${command.reconciliation.projectionsReconciled}|" +
            "${command.reconciliation.outboxReconciled}|${command.expectedVersion}"
        val md = MessageDigest.getInstance("SHA-256")
        return md.digest(raw.toByteArray(Charsets.UTF_8)).joinToString("") { "%02x".format(it) }
    }
}
