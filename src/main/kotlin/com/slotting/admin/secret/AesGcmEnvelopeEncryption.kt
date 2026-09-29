package com.slotting.admin.secret

import java.nio.ByteBuffer
import java.security.SecureRandom
import java.util.Base64
import javax.crypto.Cipher
import javax.crypto.AEADBadTagException
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.SecretKeySpec

data class EncryptedSecretPayload(
    val ciphertextBase64: String,
    val ivBase64: String,
    val keyVersion: Int,
    val formatVersion: Int = 1,
)

interface MasterKeyProvider {
    fun getMasterKey(tenantId: String, keyVersion: Int = 1): ByteArray
    fun isProductionSafe(): Boolean
}

class LocalDevMasterKeyProvider(
    private val keyBytes: ByteArray = ByteArray(32) { 0x42.toByte() }
) : MasterKeyProvider {
    override fun getMasterKey(tenantId: String, keyVersion: Int): ByteArray = keyBytes
    override fun isProductionSafe(): Boolean = false
}

class ExternalKmsMasterKeyProvider(
    private val masterKeys: Map<Pair<String, Int>, ByteArray>
) : MasterKeyProvider {
    override fun getMasterKey(tenantId: String, keyVersion: Int): ByteArray {
        return masterKeys[tenantId to keyVersion]
            ?: throw IllegalStateException("KMS master key not found for tenant: $tenantId v$keyVersion")
    }
    override fun isProductionSafe(): Boolean = true
}

class DecryptionTamperException(message: String, cause: Throwable? = null) : RuntimeException(message, cause)
class ProductionSecurityException(message: String) : RuntimeException(message)

/**
 * Genuine AES-256-GCM Authenticated Envelope Encryptor.
 * Guarantees:
 * - 96-bit cryptographically secure random IV per encryption.
 * - 128-bit authentication tag.
 * - AAD (Associated Authenticated Data) binding to tenantId, context, and keyVersion.
 * - Tamper detection (AEADBadTagException on any modification).
 * - Immediate rejection of dev/test master keys in production mode.
 * - Plaintext is never present in ciphertext.
 */
class AesGcmEnvelopeEncryptor(
    private val masterKeyProvider: MasterKeyProvider,
    private val environment: String = "TEST",
) {
    private val secureRandom = SecureRandom()

    companion object {
        const val GCM_IV_LENGTH_BYTES = 12
        const val GCM_TAG_LENGTH_BITS = 128
        const val FORMAT_VERSION = 1
    }

    private fun checkProductionSafety() {
        if (environment.equals("PRODUCTION", ignoreCase = true) && !masterKeyProvider.isProductionSafe()) {
            throw ProductionSecurityException(
                "Local development master key provider is strictly forbidden in PRODUCTION environment"
            )
        }
    }

    private fun computeAad(tenantId: String, context: String, keyVersion: Int, formatVersion: Int): ByteArray {
        val aadString = "AAD:TENANT=$tenantId|CTX=$context|KVER=$keyVersion|FVER=$formatVersion"
        return aadString.toByteArray(Charsets.UTF_8)
    }

    fun encrypt(tenantId: String, context: String, plaintext: ByteArray, keyVersion: Int = 1): EncryptedSecretPayload {
        checkProductionSafety()
        require(tenantId.isNotBlank()) { "tenantId must not be blank" }
        require(context.isNotBlank()) { "context must not be blank" }

        val masterKey = masterKeyProvider.getMasterKey(tenantId, keyVersion)
        require(masterKey.size == 32) { "AES-256 requires 32-byte (256-bit) master key" }

        val iv = ByteArray(GCM_IV_LENGTH_BYTES)
        secureRandom.nextBytes(iv)

        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        val keySpec = SecretKeySpec(masterKey, "AES")
        val gcmSpec = GCMParameterSpec(GCM_TAG_LENGTH_BITS, iv)
        cipher.init(Cipher.ENCRYPT_MODE, keySpec, gcmSpec)

        val aad = computeAad(tenantId, context, keyVersion, FORMAT_VERSION)
        cipher.updateAAD(aad)

        val ciphertextWithTag = cipher.doFinal(plaintext)

        return EncryptedSecretPayload(
            ciphertextBase64 = Base64.getEncoder().encodeToString(ciphertextWithTag),
            ivBase64 = Base64.getEncoder().encodeToString(iv),
            keyVersion = keyVersion,
            formatVersion = FORMAT_VERSION,
        )
    }

    fun decrypt(tenantId: String, context: String, payload: EncryptedSecretPayload): ByteArray {
        checkProductionSafety()
        require(tenantId.isNotBlank()) { "tenantId must not be blank" }
        require(context.isNotBlank()) { "context must not be blank" }

        val masterKey = masterKeyProvider.getMasterKey(tenantId, payload.keyVersion)
        val iv = try {
            Base64.getDecoder().decode(payload.ivBase64)
        } catch (e: Exception) {
            throw DecryptionTamperException("Invalid Base64 IV", e)
        }
        val ciphertextWithTag = try {
            Base64.getDecoder().decode(payload.ciphertextBase64)
        } catch (e: Exception) {
            throw DecryptionTamperException("Invalid Base64 ciphertext", e)
        }

        val aad = computeAad(tenantId, context, payload.keyVersion, payload.formatVersion)

        return try {
            val cipher = Cipher.getInstance("AES/GCM/NoPadding")
            val keySpec = SecretKeySpec(masterKey, "AES")
            val gcmSpec = GCMParameterSpec(GCM_TAG_LENGTH_BITS, iv)
            cipher.init(Cipher.DECRYPT_MODE, keySpec, gcmSpec)
            cipher.updateAAD(aad)
            cipher.doFinal(ciphertextWithTag)
        } catch (e: AEADBadTagException) {
            throw DecryptionTamperException("Authentication tag verification failed: ciphertext tampered or wrong tenant/context AAD", e)
        } catch (e: Exception) {
            throw DecryptionTamperException("Decryption failed: ${e.message}", e)
        }
    }

    fun encryptString(tenantId: String, context: String, plaintext: String, keyVersion: Int = 1): EncryptedSecretPayload {
        return encrypt(tenantId, context, plaintext.toByteArray(Charsets.UTF_8), keyVersion)
    }

    fun decryptString(tenantId: String, context: String, payload: EncryptedSecretPayload): String {
        return String(decrypt(tenantId, context, payload), Charsets.UTF_8)
    }
}
