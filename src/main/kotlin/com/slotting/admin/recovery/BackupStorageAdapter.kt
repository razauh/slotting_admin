package com.slotting.admin.recovery

import java.nio.charset.StandardCharsets
import java.security.MessageDigest
import java.util.concurrent.ConcurrentHashMap

data class StorageWriteResult(
    val path: String,
    val byteSize: Long,
    val sha256Digest: String,
)

data class StorageReadResult(
    val path: String,
    val payload: ByteArray,
    val sha256Digest: String,
)

interface BackupStorageAdapter {
    val providerType: StorageProviderType
    fun storeArtifact(path: String, payload: ByteArray, metadata: Map<String, String> = emptyMap()): StorageWriteResult
    fun retrieveArtifact(path: String): StorageReadResult
    fun validateDestination(config: BackupStorageConfig): BackupStorageValidationResult
    fun checkImmutability(path: String): Boolean
}

class S3CompatibleStorageAdapter(
    var simulatedReachable: Boolean = true,
    var simulatedAuthValid: Boolean = true,
    var simulatedBucketExists: Boolean = true,
    var simulatedObjectLockSupported: Boolean = true,
) : BackupStorageAdapter {
    override val providerType: StorageProviderType = StorageProviderType.S3_COMPATIBLE
    private val storage = ConcurrentHashMap<String, ByteArray>()
    private val lockedObjects = ConcurrentHashMap<String, Boolean>()

    override fun storeArtifact(path: String, payload: ByteArray, metadata: Map<String, String>): StorageWriteResult {
        if (!simulatedReachable) throw IllegalStateException("S3 endpoint unreachable")
        if (!simulatedAuthValid) throw SecurityException("S3 403 Forbidden: Invalid credentials")
        if (!simulatedBucketExists) throw NoSuchElementException("S3 404: Bucket does not exist")

        storage[path] = payload
        if (simulatedObjectLockSupported && metadata["object-lock"] == "true") {
            lockedObjects[path] = true
        }

        val digest = sha256(payload)
        return StorageWriteResult(
            path = path,
            byteSize = payload.size.toLong(),
            sha256Digest = digest,
        )
    }

    override fun retrieveArtifact(path: String): StorageReadResult {
        if (!simulatedReachable) throw IllegalStateException("S3 endpoint unreachable")
        if (!simulatedAuthValid) throw SecurityException("S3 403 Forbidden: Invalid credentials")

        val payload = storage[path] ?: throw NoSuchElementException("Object $path not found in storage")
        return StorageReadResult(
            path = path,
            payload = payload,
            sha256Digest = sha256(payload),
        )
    }

    override fun validateDestination(config: BackupStorageConfig): BackupStorageValidationResult {
        if (!simulatedReachable) {
            return BackupStorageValidationResult(
                status = StorageReadiness.INVALID,
                reachable = false,
                authSuccessful = false,
                bucketExists = false,
                writeReadVerified = false,
                objectLockVerified = false,
                details = "Cannot connect to S3 endpoint ${config.endpointUrl}",
            )
        }
        if (!simulatedAuthValid) {
            return BackupStorageValidationResult(
                status = StorageReadiness.INVALID,
                reachable = true,
                authSuccessful = false,
                bucketExists = false,
                writeReadVerified = false,
                objectLockVerified = false,
                details = "Authentication failed with access key ${config.accessKeyId}",
            )
        }
        if (!simulatedBucketExists) {
            return BackupStorageValidationResult(
                status = StorageReadiness.INVALID,
                reachable = true,
                authSuccessful = true,
                bucketExists = false,
                writeReadVerified = false,
                objectLockVerified = false,
                details = "Bucket ${config.bucket} does not exist",
            )
        }

        // Test roundtrip write/read
        val testPath = "${config.pathPrefix}/.validation_probe_${System.currentTimeMillis()}"
        val testPayload = "BACKUP_STORAGE_VALIDATION_PROBE".toByteArray(StandardCharsets.UTF_8)
        storeArtifact(testPath, testPayload)
        val readBack = retrieveArtifact(testPath)
        storage.remove(testPath)

        val writeReadOk = readBack.payload.contentEquals(testPayload)
        val objectLockOk = !config.objectLockConfigured || simulatedObjectLockSupported

        val status = if (writeReadOk && objectLockOk) StorageReadiness.READY else StorageReadiness.DEGRADED
        return BackupStorageValidationResult(
            status = status,
            reachable = true,
            authSuccessful = true,
            bucketExists = true,
            writeReadVerified = writeReadOk,
            objectLockVerified = objectLockOk,
            details = if (status == StorageReadiness.READY) "Backup storage verified and ready." else "Object lock check failed.",
        )
    }

    override fun checkImmutability(path: String): Boolean = lockedObjects[path] ?: false

    private fun sha256(bytes: ByteArray): String =
        MessageDigest.getInstance("SHA-256").digest(bytes).joinToString("") { "%02x".format(it) }
}

class FilesystemStorageAdapter : BackupStorageAdapter {
    override val providerType: StorageProviderType = StorageProviderType.LOCAL_FILESYSTEM
    private val storage = ConcurrentHashMap<String, ByteArray>()

    override fun storeArtifact(path: String, payload: ByteArray, metadata: Map<String, String>): StorageWriteResult {
        storage[path] = payload
        return StorageWriteResult(
            path = path,
            byteSize = payload.size.toLong(),
            sha256Digest = MessageDigest.getInstance("SHA-256").digest(payload).joinToString("") { "%02x".format(it) }
        )
    }

    override fun retrieveArtifact(path: String): StorageReadResult {
        val payload = storage[path] ?: throw NoSuchElementException("File $path not found")
        return StorageReadResult(
            path = path,
            payload = payload,
            sha256Digest = MessageDigest.getInstance("SHA-256").digest(payload).joinToString("") { "%02x".format(it) }
        )
    }

    override fun validateDestination(config: BackupStorageConfig): BackupStorageValidationResult {
        return BackupStorageValidationResult(
            status = StorageReadiness.READY,
            reachable = true,
            authSuccessful = true,
            bucketExists = true,
            writeReadVerified = true,
            objectLockVerified = false,
            details = "Local filesystem storage verified for testing.",
        )
    }

    override fun checkImmutability(path: String): Boolean = false
}
