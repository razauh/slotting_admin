package com.slotting.admin.auth

import java.time.Instant
import java.util.UUID

/**
 * Domain records for durable authentication persistence (TC-004).
 */

enum class SessionState {
    ACTIVE,
    TERMINATED,
    EXPIRED
}

enum class RefreshTokenStatus {
    ACTIVE,
    ROTATED,
    REVOKED,
    EXPIRED
}

data class PlayerCredentialRecord(
    val playerId: UUID,
    val tenantId: String,
    val identifier: String,
    val passwordHash: String,
    val passwordAlgo: String,
    val passwordSalt: String,
    val iterations: Int,
    val status: String = "ACTIVE",
    val version: Long = 1L,
    val createdAt: Instant = Instant.now(),
    val updatedAt: Instant = Instant.now()
)

data class AuthChallengeRecord(
    val challengeId: UUID,
    val tenantId: String,
    val playerId: UUID,
    val purpose: String,
    val codeHash: String,
    val salt: String,
    var attemptsRemaining: Int = 3,
    val maxAttempts: Int = 3,
    val expiresAt: Instant,
    var consumedAt: Instant? = null,
    val createdAt: Instant = Instant.now()
) {
    val isConsumed: Boolean get() = consumedAt != null
}

data class PlayerSessionRecord(
    val sessionId: UUID,
    val tenantId: String,
    val playerId: UUID,
    var state: SessionState = SessionState.ACTIVE,
    val deviceFingerprint: String? = null,
    val ipAddress: String = "127.0.0.1",
    val userAgent: String = "Unknown",
    val createdAt: Instant = Instant.now(),
    val expiresAt: Instant,
    var terminatedAt: Instant? = null,
    var version: Long = 1L
)

data class TokenFamilyRecord(
    val familyId: UUID,
    val tenantId: String,
    val playerId: UUID,
    val sessionId: UUID,
    var isRevoked: Boolean = false,
    var revocationReason: String? = null,
    val createdAt: Instant = Instant.now(),
    var updatedAt: Instant = Instant.now(),
    var version: Long = 1L
)

data class RefreshTokenRecord(
    val tokenId: UUID,
    val familyId: UUID,
    val tokenHash: String,
    val tenantId: String,
    val playerId: UUID,
    val parentTokenHash: String? = null,
    var status: RefreshTokenStatus = RefreshTokenStatus.ACTIVE,
    val issuedAt: Instant = Instant.now(),
    val expiresAt: Instant,
    var rotatedAt: Instant? = null,
    var revokedAt: Instant? = null
)

data class AuthorizationCodeSessionRecord(
    val code: String,
    val codeChallenge: String,
    val codeChallengeMethod: String = "S256",
    val state: String,
    val nonce: String? = null,
    val redirectUri: String,
    val tenantId: String,
    val playerId: UUID,
    val expiresAt: Instant,
    var consumed: Boolean = false,
    var consumedAt: Instant? = null,
    val createdAt: Instant = Instant.now(),
    val clientId: String = "slotting-android",
    val scope: String = "openid profile",
    val authTime: Instant = Instant.now()
)
