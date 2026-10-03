package com.slotting.admin.auth.passwordreset

import java.time.Instant
import java.util.UUID

data class PasswordResetTokenRecord(
    val id: UUID,
    val playerId: UUID,
    val tenantId: String,
    val tokenDigest: String,
    val createdAt: Instant,
    val expiresAt: Instant,
    var usedAt: Instant? = null,
    var revokedAt: Instant? = null,
    val requestCorrelationId: String,
    val ipAddress: String? = null,
    val userAgent: String? = null
) {
    fun isUsable(now: Instant = Instant.now()): Boolean =
        usedAt == null && revokedAt == null && now.isBefore(expiresAt)
}

data class PasswordResetRequestCommand(
    val tenantId: String = "default",
    val email: String,
    val ipAddress: String = "127.0.0.1",
    val userAgent: String = "Unknown",
    val correlationId: String = UUID.randomUUID().toString()
)

data class PasswordResetRequestResult(
    val genericMessage: String,
    val emailQueued: Boolean,
    val correlationId: String
)

data class ResetTokenVerificationResult(
    val valid: Boolean,
    val resetTransactionId: UUID? = null,
    val csrfToken: String? = null,
    val genericErrorMessage: String? = null
)

data class CompletePasswordResetCommand(
    val resetTransactionId: UUID,
    val csrfToken: String,
    val newPassword: String,
    val confirmPassword: String,
    val ipAddress: String = "127.0.0.1",
    val userAgent: String = "Unknown",
    val correlationId: String = UUID.randomUUID().toString()
)

data class CompletePasswordResetResult(
    val success: Boolean,
    val message: String,
    val playerId: UUID? = null,
    val sessionsRevokedCount: Int = 0
)

data class ResetSessionTransaction(
    val transactionId: UUID,
    val tokenId: UUID,
    val playerId: UUID,
    val tenantId: String,
    val verifiedEmail: String,
    val csrfToken: String,
    val createdAt: Instant,
    val expiresAt: Instant
)
