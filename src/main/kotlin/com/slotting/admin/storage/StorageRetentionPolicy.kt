package com.slotting.admin.storage

import java.time.Clock
import java.time.Instant

data class StorageRetentionRecord(
    val bucketId: String,
    val objectPath: String,
    val retentionExpiresAt: Instant,
    val legalHold: Boolean,
)

class StorageRetentionPolicy(private val clock: Clock = Clock.systemUTC()) {
    fun isExpired(record: StorageRetentionRecord): Boolean =
        !record.legalHold && !clock.instant().isBefore(record.retentionExpiresAt)
}

interface StorageDeleteTransport {
    fun delete(bucket: String, objectPath: String): Boolean
}

class StorageRetentionService(
    private val transport: StorageDeleteTransport,
    private val policy: StorageRetentionPolicy,
) {
    fun purge(records: List<StorageRetentionRecord>): List<String> {
        val deleted = mutableListOf<String>()
        for (record in records) {
            if (!policy.isExpired(record)) {
                continue
            }
            if (transport.delete(record.bucketId, record.objectPath)) {
                deleted.add(record.objectPath)
            }
        }
        return deleted
    }
}
