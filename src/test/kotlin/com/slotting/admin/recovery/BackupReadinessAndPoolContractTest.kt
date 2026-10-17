package com.slotting.admin.recovery

import org.junit.jupiter.api.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse

class BackupReadinessAndPoolContractTest {
    private val config = BackupStorageConfig(
        endpointUrl = "https://backup.example.test",
        bucket = "backups",
        accessKeyId = "access-id",
        encryptedSecret = byteArrayOf(1),
        secretIv = byteArrayOf(2),
        objectLockConfigured = false,
        updatedBy = "test",
    )

    @Test
    fun localFilesystemNeverReportsImmutableReadiness() {
        val result = FilesystemStorageAdapter().validateDestination(config)
        assertEquals(StorageReadiness.DEGRADED, result.status)
        assertFalse(result.objectLockVerified)
    }

    @Test
    fun reachableS3WithoutConfiguredObjectLockIsDegraded() {
        val result = S3CompatibleStorageAdapter().validateDestination(config)
        assertEquals(StorageReadiness.DEGRADED, result.status)
        assertFalse(result.objectLockVerified)
    }

    @Test
    fun configuredButUnsupportedObjectLockIsDegraded() {
        val adapter = S3CompatibleStorageAdapter(simulatedObjectLockSupported = false)
        val result = adapter.validateDestination(config.copy(objectLockConfigured = true))
        assertEquals(StorageReadiness.DEGRADED, result.status)
        assertFalse(result.objectLockVerified)
    }

    @Test
    fun supportedAndConfiguredObjectLockIsRequiredForReady() {
        val result = S3CompatibleStorageAdapter().validateDestination(config.copy(objectLockConfigured = true))
        assertEquals(StorageReadiness.READY, result.status)
        assertEquals(true, result.objectLockVerified)
    }
}
