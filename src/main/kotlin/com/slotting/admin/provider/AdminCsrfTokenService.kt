package com.slotting.admin.provider

import java.security.MessageDigest
import java.security.SecureRandom
import java.util.Base64
import javax.crypto.Mac
import javax.crypto.spec.SecretKeySpec

class AdminCsrfTokenService(
    private val secret: ByteArray = ByteArray(32).also { SecureRandom().nextBytes(it) },
) {
    fun issue(sessionId: String, principalId: String): String {
        if (sessionId.isBlank() || principalId.isBlank()) return ""
        val mac = Mac.getInstance("HmacSHA256")
        mac.init(SecretKeySpec(secret, "HmacSHA256"))
        val digest = mac.doFinal("$sessionId:$principalId".toByteArray(Charsets.UTF_8))
        return Base64.getUrlEncoder().withoutPadding().encodeToString(digest)
    }

    fun validate(sessionId: String?, principalId: String?, token: String?): Boolean {
        if (sessionId.isNullOrBlank() || principalId.isNullOrBlank() || token.isNullOrBlank()) return false
        val expected = issue(sessionId, principalId)
        return MessageDigest.isEqual(expected.toByteArray(Charsets.UTF_8), token.toByteArray(Charsets.UTF_8))
    }
}
