package com.slotting.admin.storage

data class SignedUrl(
    val url: String,
    val expiresInSeconds: Long,
)

interface StorageSignTransport {
    fun sign(bucket: String, objectPath: String, expiresInSeconds: Long): String
}

class StorageSignedUrlService(
    private val transport: StorageSignTransport,
    private val allowedBuckets: Set<String> = DEFAULT_BUCKETS,
    private val maxTtlSeconds: Long = 300,
) {
    fun issue(
        tenantId: String,
        playerId: String,
        bucket: String,
        objectPath: String,
        ttlSeconds: Long = 300,
    ): SignedUrl {
        require(tenantId.isNotBlank()) { "tenant id required" }
        require(playerId.isNotBlank()) { "player id required" }
        require(bucket in allowedBuckets) { "bucket not allowed" }
        require(ttlSeconds in 1..maxTtlSeconds) { "ttl out of range" }
        val path = objectPath.trimStart('/')
        require(path.startsWith("$tenantId/$playerId/")) { "object path outside player scope" }
        return SignedUrl(transport.sign(bucket, path, ttlSeconds), ttlSeconds)
    }

    companion object {
        val DEFAULT_BUCKETS: Set<String> = setOf("player-documents", "payment-proofs")
    }
}
