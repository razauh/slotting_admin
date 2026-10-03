package com.slotting.admin.auth.passwordreset

import java.net.URI
import java.time.Duration

data class PasswordResetRateLimitConfig(
    val perAccountCooldownSeconds: Long = 60L,
    val perAccountMaxRequests: Int = 5,
    val perAccountWindowMinutes: Long = 15L,
    val perIpMaxRequests: Int = 20,
    val perIpWindowMinutes: Long = 15L,
    val tokenVerificationMaxAttemptsPerMin: Int = 10
)

data class PasswordResetConfig(
    val publicOrigin: String = "https://auth.slotting.com",
    val tokenTtl: Duration = Duration.ofSeconds(90),
    val hmacSecret: String = "secure-password-reset-pepper-32-bytes-minimum-entropy",
    val emailFrom: String = "security@auth.slotting.com",
    val maxActiveTokensPerPlayer: Int = 3,
    val isProduction: Boolean = false,
    val rateLimits: PasswordResetRateLimitConfig = PasswordResetRateLimitConfig()
) {
    init {
        validate()
    }

    fun validate() {
        require(publicOrigin.isNotBlank()) { "publicOrigin must not be blank" }
        val uri = try {
            URI(publicOrigin)
        } catch (e: Exception) {
            throw IllegalArgumentException("publicOrigin is malformed: $publicOrigin", e)
        }
        val scheme = uri.scheme?.lowercase()
        val host = uri.host?.lowercase() ?: ""
        val isLocal = host == "localhost" || host == "127.0.0.1" || host == "test"
        if (!isLocal && scheme != "https") {
            throw IllegalArgumentException("Production publicOrigin must use HTTPS: $publicOrigin")
        }
        if (uri.path != null && uri.path.isNotBlank() && uri.path != "/") {
            throw IllegalArgumentException("publicOrigin must be an origin without subpaths: $publicOrigin")
        }
        require(!tokenTtl.isNegative && !tokenTtl.isZero && tokenTtl <= Duration.ofHours(24)) {
            "tokenTtl must be positive and not exceed 24 hours"
        }
        if (isProduction) {
            require(hmacSecret.isNotBlank()) { "hmacSecret must not be blank in production" }
            require(hmacSecret.length >= 32) { "hmacSecret must have at least 256 bits of entropy (>= 32 chars)" }
            val forbiddenSecrets = setOf("default-secret", "secret", "change-me", "password", "12345678", "admin123")
            require(hmacSecret.lowercase() !in forbiddenSecrets) { "hmacSecret must not use insecure default value" }
        }
    }
}
