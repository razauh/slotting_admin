package com.slotting.admin.secret

import com.slotting.admin.auth.AdminRole
import com.slotting.admin.auth.AuthErrorCode
import com.slotting.admin.auth.AuthenticatedPrincipal
import com.slotting.admin.auth.AuthenticationFailure
import com.slotting.admin.auth.OutboxEvent
import com.slotting.admin.auth.PrincipalKind
import java.security.MessageDigest
import java.time.Clock
import java.time.Instant
import java.util.UUID
import java.util.concurrent.ConcurrentHashMap

/**
 * Traceability binding for SECRET-001-01: Store backend secrets and keys in KMS.
 * Fail-closed assertion gate for RED/GREEN TDD verification.
 * Expected RED failure reason: "expired/single-pin rotation outage and secret leak".
 */
object KmsBackendSecretsBinding {
    @Volatile
    var isBound: Boolean = true

    fun checkBound() {
        if (!isBound) {
            throw AssertionError("expired/single-pin rotation outage and secret leak")
        }
    }
}

/**
 * Outcome-specific semantic contract for SECRET-001-01.
 */
const val KMS_BACKEND_SECRETS_CONTRACT =
    "Emergency rollback documented; key access/audit alerts; no app-embedded secret authority."

/**
 * Cryptographic algorithms supported for KMS-stored backend keys.
 */
enum class BackendKeyAlgorithm {
    AES_256_GCM,
    RSA_4096,
    ECDSA_P256,
    HMAC_SHA256
}

/**
 * Functional category of the backend secret/key stored in KMS.
 */
enum class BackendSecretType {
    DATA_ENCRYPTION_KEY,
    JWT_SIGNING_KEY,
    DATABASE_CREDENTIAL,
    PIN_DERIVATION_SALT,
    API_INTEGRATION_TOKEN
}

/**
 * Lifecycle status of a specific backend secret key version.
 */
enum class BackendSecretStatus {
    ACTIVE,
    ROTATING,     // In overlap grace period: both old and new versions remain simultaneously valid
    ROTATED,      // Successfully rotated; prior version may be retired after overlap
    ROLLED_BACK,  // Rolled back to prior verified version
    COMPROMISED,  // Marked compromised during anomaly or breach
    REVOKED       // Fully revoked, forbidden for any cryptographic operations
}

/**
 * Metadata for a specific version of a KMS-managed backend secret key.
 * Note: Never contains raw plaintext secret bytes or unencrypted private keys.
 */
data class KeyVersionMetadata(
    val version: Int,
    val kmsKeyUri: String,
    val keyDigestSha256: String,
    val status: BackendSecretStatus,
    val createdAt: Instant,
    val retiredAt: Instant? = null,
    val revokedReason: String? = null
)

/**
 * Authoritative server representation of a KMS-backed secret entry.
 */
data class BackendSecretEntry(
    val secretId: String,
    val tenantId: String,
    val secretKeyAlias: String,
    val secretType: BackendSecretType,
    val algorithm: BackendKeyAlgorithm,
    val activeVersion: Int,
    val versions: Map<Int, KeyVersionMetadata>,
    val overlapGracePeriodSeconds: Long,
    val createdAt: Instant,
    val updatedAt: Instant,
    val serverVersion: Long = 1L
) {
    /**
     * Dual-pin / dual-key validation during rotation.
     * Prevents single-pin / expired-key rotation outages by ensuring both the active key
     * and previously rotated keys within the grace period remain simultaneously valid.
     */
    fun isVersionValid(version: Int, now: Instant): Boolean {
        val meta = versions[version] ?: return false
        if (meta.status == BackendSecretStatus.COMPROMISED || meta.status == BackendSecretStatus.REVOKED) {
            return false
        }
        if (meta.status == BackendSecretStatus.ACTIVE || meta.status == BackendSecretStatus.ROTATING) {
            return true
        }
        if (meta.status == BackendSecretStatus.ROTATED) {
            val retirementTime = meta.retiredAt ?: updatedAt
            return now.isBefore(retirementTime.plusSeconds(overlapGracePeriodSeconds))
        }
        return false
    }

    /**
     * Returns all version numbers currently valid under the dual-pin/key overlap rule.
     */
    fun validVersions(now: Instant): List<Int> {
        return versions.keys.filter { isVersionValid(it, now) }.sortedDescending()
    }
}

/**
 * Documented emergency rollback record preserving immutable procedural evidence.
 */
data class EmergencyRollbackRecord(
    val rollbackId: String,
    val tenantId: String,
    val secretKeyAlias: String,
    val fromVersion: Int,
    val targetVersion: Int,
    val reason: String,
    val executedBy: String,
    val executedAt: Instant,
    val evidenceReference: String,
    val correlationId: String
)

/**
 * Event types for KMS secret audit trails.
 */
enum class SecretAuditEventType {
    SECRET_STORED,
    SECRET_ACCESSED,
    SECRET_DECRYPTED,
    SECRET_ROTATION_INITIATED,
    SECRET_ROTATION_COMPLETED,
    SECRET_EMERGENCY_ROLLBACK,
    SECRET_REVOKED,
    SECURITY_ALERT_TRIGGERED
}

/**
 * Structured audit record. Strictly forbids raw secrets or plaintext tokens.
 */
data class SecretAuditRecord(
    val auditId: UUID,
    val tenantId: String,
    val eventType: SecretAuditEventType,
    val principalId: String,
    val secretKeyAlias: String,
    val keyVersion: Int,
    val success: Boolean,
    val timestamp: Instant,
    val correlationId: String,
    val causationId: String,
    val detailsRedacted: String,
    val alertTriggered: Boolean = false
)

/**
 * Actionable security alert notification emitted upon key access, rotation, or emergency rollback.
 */
data class SecretAlertRecord(
    val alertId: String,
    val tenantId: String,
    val severity: String, // "INFO", "WARN", "CRITICAL"
    val alertType: String,
    val message: String,
    val correlationId: String,
    val timestamp: Instant,
    val secretKeyAlias: String
)

/**
 * External KMS key descriptor returned from cloud/HSM KMS provider.
 */
data class ExternalKmsKey(
    val kmsKeyUri: String,
    val keyAlias: String,
    val version: Int,
    val algorithm: BackendKeyAlgorithm,
    val digestSha256: String
)

/**
 * External KMS provider port representing canonical external KMS/HSM integration contract.
 */
interface KmsBackendSecretsProviderPort {
    fun createKey(tenantId: String, alias: String, algorithm: BackendKeyAlgorithm): ExternalKmsKey
    fun rotateKey(tenantId: String, currentKmsUri: String, alias: String, nextVersion: Int, algorithm: BackendKeyAlgorithm): ExternalKmsKey
    fun encrypt(tenantId: String, kmsKeyUri: String, plaintext: ByteArray): ByteArray
    fun decrypt(tenantId: String, kmsKeyUri: String, ciphertext: ByteArray): ByteArray
}

/**
 * In-memory adversarial fake KMS provider adapter for testing failure and timeout scenarios.
 */
class FakeKmsBackendProviderAdapter : KmsBackendSecretsProviderPort {
    private val keys = ConcurrentHashMap<String, ExternalKmsKey>()
    @Volatile var shouldFail: Boolean = false
    @Volatile var simulateTimeout: Boolean = false

    override fun createKey(tenantId: String, alias: String, algorithm: BackendKeyAlgorithm): ExternalKmsKey {
        checkFailure()
        val uri = "kms://$tenantId/keys/$alias/v1"
        val digest = sha256Hex("key-$tenantId-$alias-v1")
        val key = ExternalKmsKey(uri, alias, 1, algorithm, digest)
        keys[uri] = key
        return key
    }

    override fun rotateKey(
        tenantId: String,
        currentKmsUri: String,
        alias: String,
        nextVersion: Int,
        algorithm: BackendKeyAlgorithm
    ): ExternalKmsKey {
        checkFailure()
        val uri = "kms://$tenantId/keys/$alias/v$nextVersion"
        val digest = sha256Hex("key-$tenantId-$alias-v$nextVersion")
        val key = ExternalKmsKey(uri, alias, nextVersion, algorithm, digest)
        keys[uri] = key
        return key
    }

    override fun encrypt(tenantId: String, kmsKeyUri: String, plaintext: ByteArray): ByteArray {
        checkFailure()
        val prefix = "ENC:$kmsKeyUri:".toByteArray(Charsets.UTF_8)
        return prefix + plaintext
    }

    override fun decrypt(tenantId: String, kmsKeyUri: String, ciphertext: ByteArray): ByteArray {
        checkFailure()
        val prefix = "ENC:$kmsKeyUri:".toByteArray(Charsets.UTF_8)
        if (ciphertext.size < prefix.size) {
            throw IllegalArgumentException("Invalid ciphertext payload for KMS decrypt")
        }
        val expectedPrefix = ciphertext.copyOfRange(0, prefix.size)
        if (!expectedPrefix.contentEquals(prefix)) {
            throw IllegalArgumentException("Ciphertext not decryptable with key: $kmsKeyUri")
        }
        return ciphertext.copyOfRange(prefix.size, ciphertext.size)
    }

    private fun checkFailure() {
        if (simulateTimeout) {
            throw IllegalStateException("KMS provider connection timeout")
        }
        if (shouldFail) {
            throw IllegalStateException("KMS provider simulated failure")
        }
    }

    private fun sha256Hex(input: String): String {
        val digest = MessageDigest.getInstance("SHA-256").digest(input.toByteArray(Charsets.UTF_8))
        return digest.joinToString("") { "%02x".format(it) }
    }
}

/**
 * Sandbox KMS provider adapter for environment parity.
 */
class SandboxKmsBackendProviderAdapter : KmsBackendSecretsProviderPort {
    override fun createKey(tenantId: String, alias: String, algorithm: BackendKeyAlgorithm): ExternalKmsKey {
        return ExternalKmsKey(
            kmsKeyUri = "arn:aws:kms:us-east-1:$tenantId:key/$alias-v1",
            keyAlias = alias,
            version = 1,
            algorithm = algorithm,
            digestSha256 = "sandbox-digest-v1"
        )
    }

    override fun rotateKey(
        tenantId: String,
        currentKmsUri: String,
        alias: String,
        nextVersion: Int,
        algorithm: BackendKeyAlgorithm
    ): ExternalKmsKey {
        return ExternalKmsKey(
            kmsKeyUri = "arn:aws:kms:us-east-1:$tenantId:key/$alias-v$nextVersion",
            keyAlias = alias,
            version = nextVersion,
            algorithm = algorithm,
            digestSha256 = "sandbox-digest-v$nextVersion"
        )
    }

    override fun encrypt(tenantId: String, kmsKeyUri: String, plaintext: ByteArray): ByteArray {
        return "SANDBOX-ENC:$kmsKeyUri:".toByteArray(Charsets.UTF_8) + plaintext
    }

    override fun decrypt(tenantId: String, kmsKeyUri: String, ciphertext: ByteArray): ByteArray {
        val prefix = "SANDBOX-ENC:$kmsKeyUri:".toByteArray(Charsets.UTF_8)
        if (ciphertext.size < prefix.size) {
            throw IllegalArgumentException("Invalid ciphertext payload for sandbox KMS decrypt")
        }
        return ciphertext.copyOfRange(prefix.size, ciphertext.size)
    }
}

/**
 * Storage port for KMS backend secrets, audit logs, alerts, outbox, and rollback records.
 */
interface KmsBackendSecretsStore {
    fun saveSecret(entry: BackendSecretEntry)
    fun findSecret(tenantId: String, alias: String): BackendSecretEntry?
    fun saveRollbackRecord(record: EmergencyRollbackRecord)
    fun getRollbackRecords(tenantId: String): List<EmergencyRollbackRecord>
    fun recordAudit(audit: SecretAuditRecord)
    fun getAudits(tenantId: String): List<SecretAuditRecord>
    fun recordAlert(alert: SecretAlertRecord)
    fun getAlerts(tenantId: String): List<SecretAlertRecord>
    fun recordOutbox(outbox: OutboxEvent)
    fun getOutbox(): List<OutboxEvent>
    fun findIdempotentResult(tenantId: String, idempotencyKey: String): Pair<String, Any>?
    fun saveIdempotentResult(tenantId: String, idempotencyKey: String, fingerprint: String, result: Any)
}

/**
 * Thread-safe in-memory store implementation.
 */
class InMemoryKmsBackendSecretsStore : KmsBackendSecretsStore {
    val secrets = ConcurrentHashMap<String, BackendSecretEntry>()
    val rollbacks = ConcurrentHashMap<String, MutableList<EmergencyRollbackRecord>>()
    val audits = ConcurrentHashMap<String, MutableList<SecretAuditRecord>>()
    val alerts = ConcurrentHashMap<String, MutableList<SecretAlertRecord>>()
    val outboxList = mutableListOf<OutboxEvent>()
    val idempotencyStore = ConcurrentHashMap<String, Pair<String, Any>>()

    private fun secretKey(tenantId: String, alias: String) = "$tenantId:$alias"

    override fun saveSecret(entry: BackendSecretEntry) {
        secrets[secretKey(entry.tenantId, entry.secretKeyAlias)] = entry
    }

    override fun findSecret(tenantId: String, alias: String): BackendSecretEntry? {
        return secrets[secretKey(tenantId, alias)]
    }

    override fun saveRollbackRecord(record: EmergencyRollbackRecord) {
        rollbacks.computeIfAbsent(record.tenantId) { mutableListOf() }.add(record)
    }

    override fun getRollbackRecords(tenantId: String): List<EmergencyRollbackRecord> {
        return rollbacks[tenantId]?.toList() ?: emptyList()
    }

    override fun recordAudit(audit: SecretAuditRecord) {
        audits.computeIfAbsent(audit.tenantId) { mutableListOf() }.add(audit)
    }

    override fun getAudits(tenantId: String): List<SecretAuditRecord> {
        return audits[tenantId]?.toList() ?: emptyList()
    }

    override fun recordAlert(alert: SecretAlertRecord) {
        alerts.computeIfAbsent(alert.tenantId) { mutableListOf() }.add(alert)
    }

    override fun getAlerts(tenantId: String): List<SecretAlertRecord> {
        return alerts[tenantId]?.toList() ?: emptyList()
    }

    override fun recordOutbox(outbox: OutboxEvent) {
        synchronized(outboxList) {
            outboxList.add(outbox)
        }
    }

    override fun getOutbox(): List<OutboxEvent> {
        return synchronized(outboxList) { outboxList.toList() }
    }

    override fun findIdempotentResult(tenantId: String, idempotencyKey: String): Pair<String, Any>? {
        return idempotencyStore["$tenantId:$idempotencyKey"]
    }

    override fun saveIdempotentResult(
        tenantId: String,
        idempotencyKey: String,
        fingerprint: String,
        result: Any
    ) {
        idempotencyStore["$tenantId:$idempotencyKey"] = Pair(fingerprint, result)
    }
}

// =============================================================================
// Commands & Results
// =============================================================================

data class StoreSecretKeyCommand(
    val principal: AuthenticatedPrincipal?,
    val tenantId: String,
    val secretKeyAlias: String,
    val secretType: BackendSecretType,
    val algorithm: BackendKeyAlgorithm,
    val overlapGracePeriodSeconds: Long = 86400L,
    val idempotencyKey: String,
    val correlationId: String,
    val causationId: String,
    val expectedVersion: Long = 1L,
    val mutatesMoney: Boolean = false
)

data class RotateSecretKeyCommand(
    val principal: AuthenticatedPrincipal?,
    val tenantId: String,
    val secretKeyAlias: String,
    val idempotencyKey: String,
    val correlationId: String,
    val causationId: String,
    val expectedVersion: Long,
    val mutatesMoney: Boolean = false
)

data class AccessSecretKeyCommand(
    val principal: AuthenticatedPrincipal?,
    val tenantId: String,
    val secretKeyAlias: String,
    val targetVersion: Int? = null,
    val idempotencyKey: String,
    val correlationId: String,
    val causationId: String,
    val mutatesMoney: Boolean = false
)

data class EmergencyRollbackKeyCommand(
    val principal: AuthenticatedPrincipal?,
    val tenantId: String,
    val secretKeyAlias: String,
    val targetVersion: Int,
    val reason: String,
    val idempotencyKey: String,
    val correlationId: String,
    val causationId: String,
    val expectedVersion: Long,
    val mutatesMoney: Boolean = false
)

data class StoreSecretKeyResult(
    val resultId: UUID,
    val tenantId: String,
    val secretKeyAlias: String,
    val activeVersion: Int,
    val kmsKeyUri: String,
    val digestSha256: String,
    val serverTime: Instant,
    val serverVersion: Long,
    val evidenceReference: String,
    val isFinancialAuthorityCreated: Boolean = false
)

data class RotateSecretKeyResult(
    val resultId: UUID,
    val tenantId: String,
    val secretKeyAlias: String,
    val previousVersion: Int,
    val newActiveVersion: Int,
    val overlappingValidVersions: List<Int>,
    val kmsKeyUri: String,
    val overlapGracePeriodSeconds: Long,
    val serverTime: Instant,
    val serverVersion: Long,
    val evidenceReference: String,
    val isFinancialAuthorityCreated: Boolean = false
)

data class AccessSecretKeyResult(
    val resultId: UUID,
    val tenantId: String,
    val secretKeyAlias: String,
    val version: Int,
    val kmsKeyUri: String,
    val digestSha256: String,
    val validVersionsInOverlap: List<Int>,
    val status: BackendSecretStatus,
    val serverTime: Instant,
    val evidenceReference: String,
    val isFinancialAuthorityCreated: Boolean = false
)

data class EmergencyRollbackResult(
    val resultId: UUID,
    val tenantId: String,
    val secretKeyAlias: String,
    val rolledBackFromVersion: Int,
    val restoredVersion: Int,
    val reason: String,
    val compromisedVersionRevoked: Boolean,
    val serverTime: Instant,
    val serverVersion: Long,
    val evidenceReference: String,
    val isFinancialAuthorityCreated: Boolean = false
)

// =============================================================================
// Authoritative Service
// =============================================================================

class KmsBackendSecretsService(
    private val store: KmsBackendSecretsStore,
    private val kmsProvider: KmsBackendSecretsProviderPort,
    private val clock: Clock
) {

    private val lock = Any()

    /**
     * Stores a new KMS backend secret key reference.
     */
    fun storeSecretKey(command: StoreSecretKeyCommand): StoreSecretKeyResult = synchronized(lock) {
        KmsBackendSecretsBinding.checkBound()
        validateAdminPrincipal(command.principal, command.tenantId, requireMutation = true)
        validateCommonInvariants(command.idempotencyKey, command.secretKeyAlias, command.expectedVersion, command.mutatesMoney)

        val fingerprint = "STORE:${command.tenantId}:${command.secretKeyAlias}:${command.secretType}:${command.algorithm}:${command.overlapGracePeriodSeconds}:${command.expectedVersion}"
        val cached = checkIdempotency<StoreSecretKeyResult>(command.tenantId, command.idempotencyKey, fingerprint)
        if (cached != null) return cached

        val existing = store.findSecret(command.tenantId, command.secretKeyAlias)
        if (existing != null) {
            throw AuthenticationFailure.Rejected(AuthErrorCode.CONFLICT)
        }

        val externalKey = try {
            kmsProvider.createKey(command.tenantId, command.secretKeyAlias, command.algorithm)
        } catch (e: Exception) {
            throw AuthenticationFailure.Rejected(AuthErrorCode.DEPENDENCY_UNAVAILABLE)
        }

        val now = clock.instant()
        val versionMeta = KeyVersionMetadata(
            version = 1,
            kmsKeyUri = externalKey.kmsKeyUri,
            keyDigestSha256 = externalKey.digestSha256,
            status = BackendSecretStatus.ACTIVE,
            createdAt = now
        )

        val entry = BackendSecretEntry(
            secretId = "sec-${UUID.randomUUID()}",
            tenantId = command.tenantId,
            secretKeyAlias = command.secretKeyAlias,
            secretType = command.secretType,
            algorithm = command.algorithm,
            activeVersion = 1,
            versions = mapOf(1 to versionMeta),
            overlapGracePeriodSeconds = command.overlapGracePeriodSeconds,
            createdAt = now,
            updatedAt = now,
            serverVersion = 1L
        )

        val resultId = UUID.randomUUID()
        val evidenceRef = "kms-secret:${command.tenantId}:${command.secretKeyAlias}:v1:${resultId}"
        val result = StoreSecretKeyResult(
            resultId = resultId,
            tenantId = command.tenantId,
            secretKeyAlias = command.secretKeyAlias,
            activeVersion = 1,
            kmsKeyUri = externalKey.kmsKeyUri,
            digestSha256 = externalKey.digestSha256,
            serverTime = now,
            serverVersion = 1L,
            evidenceReference = evidenceRef,
            isFinancialAuthorityCreated = false
        )

        store.saveSecret(entry)

        // Structured audit record: zero raw secrets/plaintext tokens
        val auditRecord = SecretAuditRecord(
            auditId = UUID.randomUUID(),
            tenantId = command.tenantId,
            eventType = SecretAuditEventType.SECRET_STORED,
            principalId = command.principal!!.id,
            secretKeyAlias = command.secretKeyAlias,
            keyVersion = 1,
            success = true,
            timestamp = now,
            correlationId = command.correlationId,
            causationId = command.causationId,
            detailsRedacted = "Stored KMS key alias=${command.secretKeyAlias} type=${command.secretType} algo=${command.algorithm} v1 uri=${externalKey.kmsKeyUri}",
            alertTriggered = false
        )
        store.recordAudit(auditRecord)

        // Outbox event
        store.recordOutbox(
            OutboxEvent(
                eventId = UUID.randomUUID(),
                resultId = resultId,
                tenantId = command.tenantId,
                type = "KMS_SECRET_KEY_STORED",
                createdAt = now
            )
        )

        store.saveIdempotentResult(command.tenantId, command.idempotencyKey, fingerprint, result)
        return result
    }

    /**
     * Rotates an existing KMS backend secret key with overlapping validity.
     * Prevents single-pin / expired-key rotation outages.
     */
    fun rotateSecretKey(command: RotateSecretKeyCommand): RotateSecretKeyResult = synchronized(lock) {
        KmsBackendSecretsBinding.checkBound()
        validateAdminPrincipal(command.principal, command.tenantId, requireMutation = true)
        validateCommonInvariants(command.idempotencyKey, command.secretKeyAlias, command.expectedVersion, command.mutatesMoney)

        val fingerprint = "ROTATE:${command.tenantId}:${command.secretKeyAlias}:${command.expectedVersion}"
        val cached = checkIdempotency<RotateSecretKeyResult>(command.tenantId, command.idempotencyKey, fingerprint)
        if (cached != null) return cached

        val existing = store.findSecret(command.tenantId, command.secretKeyAlias)
            ?: throw AuthenticationFailure.Rejected(AuthErrorCode.INVALID)

        if (existing.serverVersion != command.expectedVersion) {
            throw AuthenticationFailure.Rejected(AuthErrorCode.STALE)
        }

        val previousVersion = existing.activeVersion
        val nextVersion = previousVersion + 1

        val currentUri = existing.versions[previousVersion]?.kmsKeyUri ?: ""
        val externalRotatedKey = try {
            kmsProvider.rotateKey(
                command.tenantId,
                currentUri,
                command.secretKeyAlias,
                nextVersion,
                existing.algorithm
            )
        } catch (e: Exception) {
            throw AuthenticationFailure.Rejected(AuthErrorCode.DEPENDENCY_UNAVAILABLE)
        }

        val now = clock.instant()
        val prevMeta = existing.versions[previousVersion]!!.copy(
            status = BackendSecretStatus.ROTATING, // Both versions are simultaneously valid during overlap!
            retiredAt = now
        )

        val newMeta = KeyVersionMetadata(
            version = nextVersion,
            kmsKeyUri = externalRotatedKey.kmsKeyUri,
            keyDigestSha256 = externalRotatedKey.digestSha256,
            status = BackendSecretStatus.ACTIVE,
            createdAt = now
        )

        val updatedVersions = existing.versions.toMutableMap()
        updatedVersions[previousVersion] = prevMeta
        updatedVersions[nextVersion] = newMeta

        val updatedEntry = existing.copy(
            activeVersion = nextVersion,
            versions = updatedVersions,
            updatedAt = now,
            serverVersion = existing.serverVersion + 1
        )

        store.saveSecret(updatedEntry)

        val resultId = UUID.randomUUID()
        val validVersionsInOverlap = updatedEntry.validVersions(now)
        val evidenceRef = "kms-secret:${command.tenantId}:${command.secretKeyAlias}:v${nextVersion}:${resultId}"

        val result = RotateSecretKeyResult(
            resultId = resultId,
            tenantId = command.tenantId,
            secretKeyAlias = command.secretKeyAlias,
            previousVersion = previousVersion,
            newActiveVersion = nextVersion,
            overlappingValidVersions = validVersionsInOverlap,
            kmsKeyUri = externalRotatedKey.kmsKeyUri,
            overlapGracePeriodSeconds = existing.overlapGracePeriodSeconds,
            serverTime = now,
            serverVersion = updatedEntry.serverVersion,
            evidenceReference = evidenceRef,
            isFinancialAuthorityCreated = false
        )

        // Audit log
        val auditRecord = SecretAuditRecord(
            auditId = UUID.randomUUID(),
            tenantId = command.tenantId,
            eventType = SecretAuditEventType.SECRET_ROTATION_COMPLETED,
            principalId = command.principal!!.id,
            secretKeyAlias = command.secretKeyAlias,
            keyVersion = nextVersion,
            success = true,
            timestamp = now,
            correlationId = command.correlationId,
            causationId = command.causationId,
            detailsRedacted = "Rotated KMS key alias=${command.secretKeyAlias} from v$previousVersion to v$nextVersion overlapping=${validVersionsInOverlap.joinToString(",")}",
            alertTriggered = true
        )
        store.recordAudit(auditRecord)

        // Alert notification for key rotation
        val alert = SecretAlertRecord(
            alertId = "alert-${UUID.randomUUID()}",
            tenantId = command.tenantId,
            severity = "WARN",
            alertType = "KMS_KEY_ROTATED",
            message = "KMS backend key rotated for alias=${command.secretKeyAlias} to v$nextVersion; dual-version overlap grace active (${existing.overlapGracePeriodSeconds}s)",
            correlationId = command.correlationId,
            timestamp = now,
            secretKeyAlias = command.secretKeyAlias
        )
        store.recordAlert(alert)

        // Outbox event
        store.recordOutbox(
            OutboxEvent(
                eventId = UUID.randomUUID(),
                resultId = resultId,
                tenantId = command.tenantId,
                type = "KMS_SECRET_KEY_ROTATED",
                createdAt = now
            )
        )

        store.saveIdempotentResult(command.tenantId, command.idempotencyKey, fingerprint, result)
        return result
    }

    /**
     * Authoritatively accesses a KMS-backed secret key reference.
     * Enforces key access alerts and validates dual-pin/key overlap validity.
     */
    fun accessSecretKey(command: AccessSecretKeyCommand): AccessSecretKeyResult = synchronized(lock) {
        KmsBackendSecretsBinding.checkBound()
        validateAdminPrincipal(command.principal, command.tenantId, requireMutation = false)
        validateCommonInvariants(command.idempotencyKey, command.secretKeyAlias, 1L, command.mutatesMoney)

        val targetVerStr = command.targetVersion?.toString() ?: "ACTIVE"
        val fingerprint = "ACCESS:${command.tenantId}:${command.secretKeyAlias}:$targetVerStr"
        val cached = checkIdempotency<AccessSecretKeyResult>(command.tenantId, command.idempotencyKey, fingerprint)
        if (cached != null) return cached

        val entry = store.findSecret(command.tenantId, command.secretKeyAlias)
            ?: throw AuthenticationFailure.Rejected(AuthErrorCode.INVALID)

        val now = clock.instant()
        val versionNumber = command.targetVersion ?: entry.activeVersion
        val versionMeta = entry.versions[versionNumber]
            ?: throw AuthenticationFailure.Rejected(AuthErrorCode.INVALID)

        // Verify version validity under overlap/status rules
        if (!entry.isVersionValid(versionNumber, now)) {
            // Emits security alert for attempt to access expired/revoked/compromised key
            val alert = SecretAlertRecord(
                alertId = "alert-${UUID.randomUUID()}",
                tenantId = command.tenantId,
                severity = "CRITICAL",
                alertType = "UNAUTHORIZED_KEY_VERSION_ACCESS",
                message = "Access attempted on invalid/expired/compromised key version $versionNumber for alias ${command.secretKeyAlias}",
                correlationId = command.correlationId,
                timestamp = now,
                secretKeyAlias = command.secretKeyAlias
            )
            store.recordAlert(alert)

            val auditRecord = SecretAuditRecord(
                auditId = UUID.randomUUID(),
                tenantId = command.tenantId,
                eventType = SecretAuditEventType.SECRET_ACCESSED,
                principalId = command.principal!!.id,
                secretKeyAlias = command.secretKeyAlias,
                keyVersion = versionNumber,
                success = false,
                timestamp = now,
                correlationId = command.correlationId,
                causationId = command.causationId,
                detailsRedacted = "Unauthorized access attempt on invalid or compromised key version $versionNumber for alias=${command.secretKeyAlias}",
                alertTriggered = true
            )
            store.recordAudit(auditRecord)

            throw AuthenticationFailure.Rejected(AuthErrorCode.FORBIDDEN)
        }

        val resultId = UUID.randomUUID()
        val validVersions = entry.validVersions(now)
        val evidenceRef = "kms-access:${command.tenantId}:${command.secretKeyAlias}:v$versionNumber:${resultId}"

        val result = AccessSecretKeyResult(
            resultId = resultId,
            tenantId = command.tenantId,
            secretKeyAlias = command.secretKeyAlias,
            version = versionNumber,
            kmsKeyUri = versionMeta.kmsKeyUri,
            digestSha256 = versionMeta.keyDigestSha256,
            validVersionsInOverlap = validVersions,
            status = versionMeta.status,
            serverTime = now,
            evidenceReference = evidenceRef,
            isFinancialAuthorityCreated = false
        )

        // Audit log
        val auditRecord = SecretAuditRecord(
            auditId = UUID.randomUUID(),
            tenantId = command.tenantId,
            eventType = SecretAuditEventType.SECRET_ACCESSED,
            principalId = command.principal!!.id,
            secretKeyAlias = command.secretKeyAlias,
            keyVersion = versionNumber,
            success = true,
            timestamp = now,
            correlationId = command.correlationId,
            causationId = command.causationId,
            detailsRedacted = "KMS secret accessed alias=${command.secretKeyAlias} v$versionNumber status=${versionMeta.status} uri=${versionMeta.kmsKeyUri}",
            alertTriggered = true
        )
        store.recordAudit(auditRecord)

        // Key access alert notification
        val alert = SecretAlertRecord(
            alertId = "alert-${UUID.randomUUID()}",
            tenantId = command.tenantId,
            severity = "INFO",
            alertType = "KMS_KEY_ACCESSED",
            message = "KMS key accessed for alias=${command.secretKeyAlias} version=$versionNumber by principal=${command.principal.id}",
            correlationId = command.correlationId,
            timestamp = now,
            secretKeyAlias = command.secretKeyAlias
        )
        store.recordAlert(alert)

        store.saveIdempotentResult(command.tenantId, command.idempotencyKey, fingerprint, result)
        return result
    }

    /**
     * Executes a documented, auditable emergency rollback to a prior verified key version.
     * Marks the faulty or compromised version as COMPROMISED / REVOKED.
     * Preserves immutable audit history without altering past records.
     */
    fun emergencyRollback(command: EmergencyRollbackKeyCommand): EmergencyRollbackResult = synchronized(lock) {
        KmsBackendSecretsBinding.checkBound()
        validateAdminPrincipal(command.principal, command.tenantId, requireMutation = true)
        validateCommonInvariants(command.idempotencyKey, command.secretKeyAlias, command.expectedVersion, command.mutatesMoney)

        if (command.reason.isBlank()) {
            throw AuthenticationFailure.Rejected(AuthErrorCode.INVALID)
        }

        val fingerprint = "ROLLBACK:${command.tenantId}:${command.secretKeyAlias}:${command.targetVersion}:${command.reason}:${command.expectedVersion}"
        val cached = checkIdempotency<EmergencyRollbackResult>(command.tenantId, command.idempotencyKey, fingerprint)
        if (cached != null) return cached

        val entry = store.findSecret(command.tenantId, command.secretKeyAlias)
            ?: throw AuthenticationFailure.Rejected(AuthErrorCode.INVALID)

        if (entry.serverVersion != command.expectedVersion) {
            throw AuthenticationFailure.Rejected(AuthErrorCode.STALE)
        }

        val targetMeta = entry.versions[command.targetVersion]
            ?: throw AuthenticationFailure.Rejected(AuthErrorCode.INVALID)

        if (targetMeta.status == BackendSecretStatus.COMPROMISED || targetMeta.status == BackendSecretStatus.REVOKED) {
            throw AuthenticationFailure.Rejected(AuthErrorCode.INVALID)
        }

        val currentVersion = entry.activeVersion
        if (currentVersion == command.targetVersion) {
            throw AuthenticationFailure.Rejected(AuthErrorCode.INVALID)
        }

        val now = clock.instant()
        val currentMeta = entry.versions[currentVersion]!!.copy(
            status = BackendSecretStatus.COMPROMISED,
            revokedReason = "Emergency rollback: ${command.reason}",
            retiredAt = now
        )

        val restoredMeta = targetMeta.copy(
            status = BackendSecretStatus.ACTIVE,
            retiredAt = null
        )

        val updatedVersions = entry.versions.toMutableMap()
        updatedVersions[currentVersion] = currentMeta
        updatedVersions[command.targetVersion] = restoredMeta

        val updatedEntry = entry.copy(
            activeVersion = command.targetVersion,
            versions = updatedVersions,
            updatedAt = now,
            serverVersion = entry.serverVersion + 1
        )

        store.saveSecret(updatedEntry)

        val resultId = UUID.randomUUID()
        val evidenceRef = "kms-rollback:${command.tenantId}:${command.secretKeyAlias}:from-v$currentVersion-to-v${command.targetVersion}:${resultId}"

        val rollbackRecord = EmergencyRollbackRecord(
            rollbackId = "rb-${UUID.randomUUID()}",
            tenantId = command.tenantId,
            secretKeyAlias = command.secretKeyAlias,
            fromVersion = currentVersion,
            targetVersion = command.targetVersion,
            reason = command.reason,
            executedBy = command.principal!!.id,
            executedAt = now,
            evidenceReference = evidenceRef,
            correlationId = command.correlationId
        )
        store.saveRollbackRecord(rollbackRecord)

        val result = EmergencyRollbackResult(
            resultId = resultId,
            tenantId = command.tenantId,
            secretKeyAlias = command.secretKeyAlias,
            rolledBackFromVersion = currentVersion,
            restoredVersion = command.targetVersion,
            reason = command.reason,
            compromisedVersionRevoked = true,
            serverTime = now,
            serverVersion = updatedEntry.serverVersion,
            evidenceReference = evidenceRef,
            isFinancialAuthorityCreated = false
        )

        // Audit record: immutable record of rollback
        val auditRecord = SecretAuditRecord(
            auditId = UUID.randomUUID(),
            tenantId = command.tenantId,
            eventType = SecretAuditEventType.SECRET_EMERGENCY_ROLLBACK,
            principalId = command.principal.id,
            secretKeyAlias = command.secretKeyAlias,
            keyVersion = command.targetVersion,
            success = true,
            timestamp = now,
            correlationId = command.correlationId,
            causationId = command.causationId,
            detailsRedacted = "Emergency rollback executed for alias=${command.secretKeyAlias} from v$currentVersion to v${command.targetVersion} reason=${command.reason}",
            alertTriggered = true
        )
        store.recordAudit(auditRecord)

        // CRITICAL alert on emergency rollback
        val alert = SecretAlertRecord(
            alertId = "alert-${UUID.randomUUID()}",
            tenantId = command.tenantId,
            severity = "CRITICAL",
            alertType = "KMS_EMERGENCY_ROLLBACK",
            message = "EMERGENCY ROLLBACK executed for alias=${command.secretKeyAlias}: v$currentVersion marked COMPROMISED, restored to v${command.targetVersion}. Reason: ${command.reason}",
            correlationId = command.correlationId,
            timestamp = now,
            secretKeyAlias = command.secretKeyAlias
        )
        store.recordAlert(alert)

        // Outbox event
        store.recordOutbox(
            OutboxEvent(
                eventId = UUID.randomUUID(),
                resultId = resultId,
                tenantId = command.tenantId,
                type = "KMS_SECRET_EMERGENCY_ROLLBACK",
                createdAt = now
            )
        )

        store.saveIdempotentResult(command.tenantId, command.idempotencyKey, fingerprint, result)
        return result
    }

    /**
     * Encrypts payload with the active KMS key version.
     */
    fun encryptWithActiveKey(
        tenantId: String,
        secretKeyAlias: String,
        plaintext: ByteArray,
        principal: AuthenticatedPrincipal?
    ): Pair<Int, ByteArray> {
        KmsBackendSecretsBinding.checkBound()
        validateAdminPrincipal(principal, tenantId, requireMutation = false)

        val entry = store.findSecret(tenantId, secretKeyAlias)
            ?: throw AuthenticationFailure.Rejected(AuthErrorCode.INVALID)

        val activeVer = entry.activeVersion
        val meta = entry.versions[activeVer]
            ?: throw AuthenticationFailure.Rejected(AuthErrorCode.INVALID)

        val ciphertext = try {
            kmsProvider.encrypt(tenantId, meta.kmsKeyUri, plaintext)
        } catch (e: Exception) {
            throw AuthenticationFailure.Rejected(AuthErrorCode.DEPENDENCY_UNAVAILABLE)
        }

        return Pair(activeVer, ciphertext)
    }

    /**
     * Decrypts payload using the specified key version, verifying dual-pin / overlapping validity.
     * Prevents single-pin / expired rotation outages by allowing decryption under both active and rotating keys.
     */
    fun decryptWithKeyVersion(
        tenantId: String,
        secretKeyAlias: String,
        version: Int,
        ciphertext: ByteArray,
        principal: AuthenticatedPrincipal?
    ): ByteArray {
        KmsBackendSecretsBinding.checkBound()
        validateAdminPrincipal(principal, tenantId, requireMutation = false)

        val entry = store.findSecret(tenantId, secretKeyAlias)
            ?: throw AuthenticationFailure.Rejected(AuthErrorCode.INVALID)

        val now = clock.instant()
        if (!entry.isVersionValid(version, now)) {
            throw AuthenticationFailure.Rejected(AuthErrorCode.FORBIDDEN)
        }

        val meta = entry.versions[version]
            ?: throw AuthenticationFailure.Rejected(AuthErrorCode.INVALID)

        return try {
            kmsProvider.decrypt(tenantId, meta.kmsKeyUri, ciphertext)
        } catch (e: Exception) {
            throw AuthenticationFailure.Rejected(AuthErrorCode.DEPENDENCY_UNAVAILABLE)
        }
    }

    // =========================================================================
    // Validation Helpers
    // =========================================================================

    private fun validateAdminPrincipal(
        principal: AuthenticatedPrincipal?,
        tenantId: String,
        requireMutation: Boolean
    ) {
        if (principal == null) {
            throw AuthenticationFailure.Rejected(AuthErrorCode.UNAUTHENTICATED)
        }
        // Strict boundary: untrusted player principal has zero secret authority
        if (principal.kind != PrincipalKind.ADMIN) {
            throw AuthenticationFailure.Rejected(AuthErrorCode.FORBIDDEN)
        }
        if (principal.tenantId != tenantId) {
            throw AuthenticationFailure.Rejected(AuthErrorCode.FORBIDDEN)
        }
        if (requireMutation) {
            val hasMutationRole = principal.roles.any {
                it == AdminRole.SUPER_ADMIN || it == AdminRole.SECURITY
            }
            if (!hasMutationRole) {
                throw AuthenticationFailure.Rejected(AuthErrorCode.FORBIDDEN)
            }
        } else {
            val hasAccessRole = principal.roles.any {
                it == AdminRole.SUPER_ADMIN || it == AdminRole.SECURITY || it == AdminRole.AUDITOR
            }
            if (!hasAccessRole) {
                throw AuthenticationFailure.Rejected(AuthErrorCode.FORBIDDEN)
            }
        }
    }

    private fun validateCommonInvariants(
        idempotencyKey: String,
        secretKeyAlias: String,
        expectedVersion: Long,
        mutatesMoney: Boolean
    ) {
        if (idempotencyKey.isBlank()) {
            throw AuthenticationFailure.Rejected(AuthErrorCode.INVALID)
        }
        if (secretKeyAlias.isBlank()) {
            throw AuthenticationFailure.Rejected(AuthErrorCode.INVALID)
        }
        if (expectedVersion < 1L) {
            throw AuthenticationFailure.Rejected(AuthErrorCode.STALE)
        }
        // Strict financial boundary: KMS secret management cannot mutate money
        if (mutatesMoney) {
            throw AuthenticationFailure.Rejected(AuthErrorCode.INVALID)
        }
    }

    @Suppress("UNCHECKED_CAST")
    private fun <T> checkIdempotency(tenantId: String, idempotencyKey: String, fingerprint: String): T? {
        val existing = store.findIdempotentResult(tenantId, idempotencyKey) ?: return null
        if (existing.first != fingerprint) {
            throw AuthenticationFailure.Rejected(AuthErrorCode.CONFLICT)
        }
        return existing.second as T
    }
}
