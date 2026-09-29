package com.slotting.admin.recovery

import java.security.SecureRandom
import java.util.Base64
import java.util.concurrent.ConcurrentHashMap
import javax.crypto.Cipher
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.SecretKeySpec

data class DataKeyResult(
    val plaintextDek: ByteArray, // In-memory only; never persist!
    val wrappedDekBase64: String,
    val keyVersion: Int,
)

data class EncryptedEnvelope(
    val ciphertext: ByteArray,
    val wrappedDekBase64: String,
    val ivBase64: String,
    val authTagBase64: String,
    val keyVersion: Int,
    val sha256Digest: String,
)

interface BackupKeyManagementProvider {
    fun generateDataKey(keyAlias: String): DataKeyResult
    fun unwrapDataKey(keyAlias: String, keyVersion: Int, wrappedDekBase64: String): ByteArray
    fun rotateMasterKey(keyAlias: String): Int
    fun isProductionSafe(): Boolean
}

class OpenBaoTransitProvider(
    private val environment: String = "TEST",
    var simulatedAvailable: Boolean = true,
) : BackupKeyManagementProvider {

    private val secureRandom = SecureRandom()

    // Simulated OpenBao transit backend: keyAlias -> (currentVersion, mapOf(version -> masterKeyBytes))
    private val transitKeys = ConcurrentHashMap<String, MutableMap<Int, ByteArray>>()
    private val keyVersions = ConcurrentHashMap<String, Int>()

    init {
        // Initialize default key "backup-master-key" v1
        val initialKey = ByteArray(32).also { secureRandom.nextBytes(it) }
        transitKeys["backup-master-key"] = ConcurrentHashMap<Int, ByteArray>().apply { put(1, initialKey) }
        keyVersions["backup-master-key"] = 1
    }

    override fun generateDataKey(keyAlias: String): DataKeyResult {
        checkAvailability()
        val version = keyVersions[keyAlias] ?: 1
        val masterKey = transitKeys[keyAlias]?.get(version)
            ?: throw IllegalStateException("OpenBao Transit key '$keyAlias' v$version not found")

        // 1. Generate random 256-bit DEK
        val plaintextDek = ByteArray(32).also { secureRandom.nextBytes(it) }

        // 2. Wrap DEK with OpenBao transit master key (AES key wrap / AES-ECB for simulation)
        val wrapCipher = Cipher.getInstance("AES/ECB/PKCS5Padding")
        wrapCipher.init(Cipher.ENCRYPT_MODE, SecretKeySpec(masterKey, "AES"))
        val wrappedBytes = wrapCipher.doFinal(plaintextDek)
        val wrappedDekBase64 = Base64.getEncoder().encodeToString(wrappedBytes)

        return DataKeyResult(
            plaintextDek = plaintextDek,
            wrappedDekBase64 = wrappedDekBase64,
            keyVersion = version,
        )
    }

    override fun unwrapDataKey(keyAlias: String, keyVersion: Int, wrappedDekBase64: String): ByteArray {
        checkAvailability()
        val masterKey = transitKeys[keyAlias]?.get(keyVersion)
            ?: throw IllegalStateException("OpenBao Transit key '$keyAlias' v$keyVersion not found or revoked")

        val wrappedBytes = Base64.getDecoder().decode(wrappedDekBase64)
        val unwrapCipher = Cipher.getInstance("AES/ECB/PKCS5Padding")
        unwrapCipher.init(Cipher.DECRYPT_MODE, SecretKeySpec(masterKey, "AES"))
        return unwrapCipher.doFinal(wrappedBytes)
    }

    override fun rotateMasterKey(keyAlias: String): Int {
        checkAvailability()
        val currentVersion = keyVersions.getOrDefault(keyAlias, 1)
        val nextVersion = currentVersion + 1
        val newKey = ByteArray(32).also { secureRandom.nextBytes(it) }

        transitKeys.computeIfAbsent(keyAlias) { ConcurrentHashMap() }[nextVersion] = newKey
        keyVersions[keyAlias] = nextVersion
        return nextVersion
    }

    override fun isProductionSafe(): Boolean = environment.equals("PRODUCTION", ignoreCase = true)

    private fun checkAvailability() {
        if (!simulatedAvailable) {
            throw IllegalStateException("OpenBao Transit KMS is unavailable (connection refused or sealed)")
        }
    }
}

class BackupEnvelopeEncryptor(
    private val kmsProvider: BackupKeyManagementProvider,
    private val keyAlias: String = "backup-master-key",
    private val environment: String = "TEST",
) {
    private val secureRandom = SecureRandom()

    companion object {
        const val GCM_IV_LENGTH_BYTES = 12
        const val GCM_TAG_LENGTH_BITS = 128
    }

    fun encryptPayload(payload: ByteArray): EncryptedEnvelope {
        if (environment.equals("PRODUCTION", ignoreCase = true) && !kmsProvider.isProductionSafe()) {
            throw SecurityException("Production environment must not use insecure development KMS provider!")
        }

        // 1. Generate fresh DEK via OpenBao Transit
        val dataKey = kmsProvider.generateDataKey(keyAlias)

        // 2. 96-bit cryptographically secure random IV
        val iv = ByteArray(GCM_IV_LENGTH_BYTES).also { secureRandom.nextBytes(it) }

        // 3. Encrypt payload with AES-256-GCM
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        val gcmSpec = GCMParameterSpec(GCM_TAG_LENGTH_BITS, iv)
        val secretKey = SecretKeySpec(dataKey.plaintextDek, "AES")
        cipher.init(Cipher.ENCRYPT_MODE, secretKey, gcmSpec)
        val ciphertext = cipher.doFinal(payload)

        // Zero out plaintext DEK in memory
        dataKey.plaintextDek.fill(0)

        val digest = java.security.MessageDigest.getInstance("SHA-256").digest(ciphertext)
            .joinToString("") { "%02x".format(it) }

        return EncryptedEnvelope(
            ciphertext = ciphertext,
            wrappedDekBase64 = dataKey.wrappedDekBase64,
            ivBase64 = Base64.getEncoder().encodeToString(iv),
            authTagBase64 = Base64.getEncoder().encodeToString(iv), // Reference tag for integrity
            keyVersion = dataKey.keyVersion,
            sha256Digest = digest,
        )
    }

    fun decryptPayload(envelope: EncryptedEnvelope): ByteArray {
        // 1. Unwrap DEK using OpenBao Transit
        val plaintextDek = kmsProvider.unwrapDataKey(keyAlias, envelope.keyVersion, envelope.wrappedDekBase64)

        // 2. Decrypt with AES-256-GCM
        val iv = Base64.getDecoder().decode(envelope.ivBase64)
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        val gcmSpec = GCMParameterSpec(GCM_TAG_LENGTH_BITS, iv)
        val secretKey = SecretKeySpec(plaintextDek, "AES")
        cipher.init(Cipher.DECRYPT_MODE, secretKey, gcmSpec)

        try {
            return cipher.doFinal(envelope.ciphertext)
        } finally {
            plaintextDek.fill(0) // Zero out DEK
        }
    }
}
