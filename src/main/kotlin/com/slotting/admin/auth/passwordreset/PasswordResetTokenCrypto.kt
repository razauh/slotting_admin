package com.slotting.admin.auth.passwordreset

import com.slotting.admin.auth.PasswordKdfService
import java.security.MessageDigest
import java.security.SecureRandom
import java.util.Base64
import javax.crypto.Mac
import javax.crypto.spec.SecretKeySpec

object PasswordResetTokenCrypto {
    private val secureRandom = SecureRandom()
    private const val HMAC_ALGORITHM = "HmacSHA256"

    /**
     * Generates a fresh, high-entropy password-reset token with 256 bits of cryptographic entropy.
     * Encoded as an unpadded Base64URL string.
     */
    fun generateResetToken(): String {
        val bytes = ByteArray(32).also { secureRandom.nextBytes(it) }
        return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes)
    }

    /**
     * Generates a CSRF token with 192 bits of cryptographic entropy.
     */
    fun generateCsrfToken(): String {
        val bytes = ByteArray(24).also { secureRandom.nextBytes(it) }
        return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes)
    }

    /**
     * Computes the HMAC-SHA-256 digest of the raw bearer token using the external secret pepper.
     * The raw token is NEVER stored in the database; only this digest is stored.
     */
    fun computeDigest(rawToken: String, hmacSecret: String): String {
        require(rawToken.isNotBlank()) { "rawToken must not be blank" }
        require(hmacSecret.isNotBlank()) { "hmacSecret must not be blank" }

        val mac = Mac.getInstance(HMAC_ALGORITHM)
        val keySpec = SecretKeySpec(hmacSecret.toByteArray(Charsets.UTF_8), HMAC_ALGORITHM)
        mac.init(keySpec)
        val digestBytes = mac.doFinal(rawToken.toByteArray(Charsets.UTF_8))
        return PasswordKdfService.bytesToHex(digestBytes)
    }

    /**
     * Constant-time comparison to protect against timing analysis.
     */
    fun constantTimeEquals(a: String, b: String): Boolean {
        return MessageDigest.isEqual(
            a.toByteArray(Charsets.UTF_8),
            b.toByteArray(Charsets.UTF_8)
        )
    }
}
