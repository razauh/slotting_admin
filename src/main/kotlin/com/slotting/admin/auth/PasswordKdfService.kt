package com.slotting.admin.auth

import java.security.MessageDigest
import java.security.SecureRandom
import java.util.Base64
import javax.crypto.SecretKeyFactory
import javax.crypto.spec.PBEKeySpec

/**
 * Approved adaptive password KDF with per-credential salts and legacy migration policy (TC-004, BE-009).
 */
object PasswordKdfService {

    const val PBKDF2_ALGO = "pbkdf2_sha256"
    const val LEGACY_SHA256_ALGO = "sha256_legacy"
    const val DEFAULT_ITERATIONS = 100_000
    const val KEY_LENGTH_BITS = 256
    const val SALT_LENGTH_BYTES = 16

    private val secureRandom = SecureRandom()

    private val FORBIDDEN_PASSWORDS = setOf(
        "DefaultPass123!",
        "password",
        "12345678",
        "admin123"
    )

    data class HashedPassword(
        val hash: String,
        val salt: String,
        val iterations: Int,
        val algo: String = PBKDF2_ALGO
    )

    data class VerificationResult(
        val valid: Boolean,
        val needsRehash: Boolean = false
    )

    fun hashPassword(password: String, iterations: Int = DEFAULT_ITERATIONS): HashedPassword {
        require(password.isNotBlank()) { "Password cannot be blank" }
        require(password !in FORBIDDEN_PASSWORDS) { "Password cannot be a known default or trivial password" }

        val saltBytes = ByteArray(SALT_LENGTH_BYTES).also { secureRandom.nextBytes(it) }
        val saltHex = bytesToHex(saltBytes)

        val hashBytes = pbkdf2(password.toCharArray(), saltBytes, iterations, KEY_LENGTH_BITS)
        val hashHex = bytesToHex(hashBytes)

        return HashedPassword(
            hash = hashHex,
            salt = saltHex,
            iterations = iterations,
            algo = PBKDF2_ALGO
        )
    }

    fun verifyPassword(
        password: String,
        storedHash: String,
        salt: String,
        iterations: Int,
        algo: String
    ): VerificationResult {
        if (password.isBlank()) {
            return VerificationResult(valid = false)
        }

        return when (algo) {
            PBKDF2_ALGO -> {
                val saltBytes = hexToBytes(salt)
                val computedBytes = pbkdf2(password.toCharArray(), saltBytes, iterations, KEY_LENGTH_BITS)
                val computedHex = bytesToHex(computedBytes)
                val matches = MessageDigest.isEqual(storedHash.toByteArray(Charsets.UTF_8), computedHex.toByteArray(Charsets.UTF_8))
                VerificationResult(valid = matches, needsRehash = iterations < DEFAULT_ITERATIONS)
            }
            LEGACY_SHA256_ALGO -> {
                // Legacy unsalted SHA-256 check
                val digest = MessageDigest.getInstance("SHA-256")
                val computedHex = bytesToHex(digest.digest(password.toByteArray(Charsets.UTF_8)))
                val matches = MessageDigest.isEqual(storedHash.lowercase().toByteArray(Charsets.UTF_8), computedHex.lowercase().toByteArray(Charsets.UTF_8))
                VerificationResult(valid = matches, needsRehash = true)
            }
            else -> VerificationResult(valid = false)
        }
    }

    private fun pbkdf2(chars: CharArray, salt: ByteArray, iterations: Int, keyLengthBits: Int): ByteArray {
        val spec = PBEKeySpec(chars, salt, iterations, keyLengthBits)
        val skf = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256")
        return skf.generateSecret(spec).encoded
    }

    fun bytesToHex(bytes: ByteArray): String =
        bytes.joinToString("") { "%02x".format(it) }

    fun hexToBytes(hex: String): ByteArray {
        val len = hex.length
        val data = ByteArray(len / 2)
        var i = 0
        while (i < len) {
            data[i / 2] = ((Character.digit(hex[i], 16) shl 4) + Character.digit(hex[i + 1], 16)).toByte()
            i += 2
        }
        return data
    }
}
