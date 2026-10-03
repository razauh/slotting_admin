package com.slotting.admin.auth.passwordreset

import com.slotting.admin.auth.DurableAuthService
import com.slotting.admin.auth.DurableAuthStore
import com.slotting.admin.auth.PasswordKdfService
import com.slotting.admin.identity.ContactVerificationStatus
import com.slotting.admin.identity.PlayerAccountStatus
import com.slotting.admin.identity.PlayerRegistrationRecord
import com.slotting.admin.identity.PlayerRegistrationStore
import com.slotting.admin.identity.PlayerSessionStore
import com.slotting.admin.identity.TokenRevocationReason
import com.slotting.admin.identity.TokenSecurityStore
import org.slf4j.LoggerFactory
import org.springframework.stereotype.Service
import java.security.MessageDigest
import java.time.Clock
import java.time.Duration
import java.time.Instant
import java.util.UUID
import java.util.concurrent.ConcurrentHashMap

@Service
class PasswordResetService(
    val config: PasswordResetConfig = PasswordResetConfig(),
    val tokenStore: PasswordResetTokenStore = InMemoryPasswordResetTokenStore(),
    val registrationStore: PlayerRegistrationStore,
    val durableAuthStore: DurableAuthStore,
    val durableAuthService: DurableAuthService,
    val emailSender: PasswordResetEmailSender = InMemoryPasswordResetEmailSender(),
    val rateLimiter: PasswordResetRateLimiter = PasswordResetRateLimiter(),
    val playerSessionStore: PlayerSessionStore? = null,
    val tokenSecurityStore: TokenSecurityStore? = null,
    val clock: Clock = Clock.systemUTC()
) {
    private val logger = LoggerFactory.getLogger(javaClass)

    companion object {
        const val GENERIC_REQUEST_RESPONSE =
            "If an account exists for that email address, password reset instructions will be sent shortly."
        const val GENERIC_TOKEN_ERROR =
            "This password reset link is invalid or has expired. Please request a new one."
        private val EMAIL_REGEX = Regex("^[A-Za-z0-9+_.-]+@[A-Za-z0-9.-]+\\.[A-Za-z]{2,}$")
    }

    // Ephemeral in-memory reset transactions bound to verified token visits
    val resetTransactions = ConcurrentHashMap<UUID, ResetSessionTransaction>()

    /**
     * Handles public password-reset requests with strict anti-enumeration and timing protections.
     * Only previously verified, active accounts receive a reset token.
     */
    fun requestPasswordReset(command: PasswordResetRequestCommand): PasswordResetRequestResult {
        logger.info("AUDIT: PASSWORD_RESET_REQUEST_RECEIVED correlationId={}", command.correlationId)

        val normalizedEmail = command.email.trim().lowercase()

        // 1. Basic format validation
        if (!EMAIL_REGEX.matches(normalizedEmail)) {
            // Equalize timing even for malformed inputs
            dummyHmacWork()
            return PasswordResetRequestResult(
                genericMessage = GENERIC_REQUEST_RESPONSE,
                emailQueued = false,
                correlationId = command.correlationId
            )
        }

        // 2. Layered Rate Limiting
        val accountKey = "${command.tenantId}:$normalizedEmail"
        val rateVerdict = rateLimiter.checkAndRecordRequest(accountKey, command.ipAddress, config.rateLimits)
        if (!rateVerdict.allowed) {
            logger.warn("AUDIT: PASSWORD_RESET_RATE_LIMITED reason={} correlationId={}", rateVerdict.reason, command.correlationId)
            dummyHmacWork()
            return PasswordResetRequestResult(
                genericMessage = GENERIC_REQUEST_RESPONSE,
                emailQueued = false,
                correlationId = command.correlationId
            )
        }

        // 3. Authoritative Account Lookup & Verification Check
        val emailHash = sha256(normalizedEmail)
        val playerReg = registrationStore.findByEmailHash(command.tenantId, emailHash)
        val playerCred = durableAuthStore.findCredential(command.tenantId, normalizedEmail)
            ?: durableAuthStore.findCredential(command.tenantId, emailHash)

        // Check if account exists
        if (playerReg == null && playerCred == null) {
            logger.info("AUDIT: PASSWORD_RESET_NOT_SENT_UNKNOWN_ACCOUNT correlationId={}", command.correlationId)
            dummyHmacWork()
            return PasswordResetRequestResult(
                genericMessage = GENERIC_REQUEST_RESPONSE,
                emailQueued = false,
                correlationId = command.correlationId
            )
        }

        // Check if account is suspended or closed
        val status = playerReg?.status ?: when (playerCred?.status) {
            "SUSPENDED" -> PlayerAccountStatus.SUSPENDED
            "CLOSED" -> PlayerAccountStatus.CLOSED
            "LOCKED" -> PlayerAccountStatus.LOCKED
            else -> PlayerAccountStatus.ACTIVE
        }

        if (status == PlayerAccountStatus.SUSPENDED || status == PlayerAccountStatus.CLOSED) {
            logger.warn("AUDIT: PASSWORD_RESET_NOT_SENT_ACCOUNT_SUSPENDED correlationId={}", command.correlationId)
            dummyHmacWork()
            return PasswordResetRequestResult(
                genericMessage = GENERIC_REQUEST_RESPONSE,
                emailQueued = false,
                correlationId = command.correlationId
            )
        }

        // Requirement 3 & 4: Only previously verified emails receive password reset credentials!
        val isEmailVerified = playerReg?.emailVerified ?: (status == PlayerAccountStatus.ACTIVE)
        if (!isEmailVerified) {
            logger.warn("AUDIT: PASSWORD_RESET_NOT_SENT_EMAIL_UNVERIFIED correlationId={}", command.correlationId)
            dummyHmacWork()
            return PasswordResetRequestResult(
                genericMessage = GENERIC_REQUEST_RESPONSE,
                emailQueued = false,
                correlationId = command.correlationId
            )
        }

        val playerId = playerReg?.playerId ?: playerCred!!.playerId
        val now = clock.instant()

        // 4. Generate high-entropy reset token (256 bits)
        val rawToken = PasswordResetTokenCrypto.generateResetToken()
        val tokenDigest = PasswordResetTokenCrypto.computeDigest(rawToken, config.hmacSecret)

        // 5. Bounded active tokens per player
        val activeCount = tokenStore.countActiveTokensForPlayer(command.tenantId, playerId, now)
        if (activeCount >= config.maxActiveTokensPerPlayer) {
            tokenStore.revokeAllActiveTokensForPlayer(command.tenantId, playerId, now)
        }

        // 6. Store protected token digest (raw token is never persisted!)
        val tokenRecord = PasswordResetTokenRecord(
            id = UUID.randomUUID(),
            playerId = playerId,
            tenantId = command.tenantId,
            tokenDigest = tokenDigest,
            createdAt = now,
            expiresAt = now.plus(config.tokenTtl),
            requestCorrelationId = command.correlationId,
            ipAddress = command.ipAddress,
            userAgent = command.userAgent
        )
        tokenStore.saveToken(tokenRecord)

        // 7. Dispatch HTTPS reset link to verified email using configured public origin
        val resetUrl = "${config.publicOrigin}/auth/password-reset?token=$rawToken"
        val sent = emailSender.sendPasswordResetEmail(normalizedEmail, resetUrl, config.tokenTtl.seconds)

        if (sent) {
            logger.info("AUDIT: PASSWORD_RESET_EMAIL_QUEUED correlationId={}", command.correlationId)
        } else {
            logger.error("AUDIT: PASSWORD_RESET_EMAIL_SEND_FAILED correlationId={}", command.correlationId)
        }

        return PasswordResetRequestResult(
            genericMessage = GENERIC_REQUEST_RESPONSE,
            emailQueued = sent,
            correlationId = command.correlationId
        )
    }

    /**
     * Validates presented reset token for initial landing (scanner-safe GET request).
     * Does NOT permanently consume the token on GET.
     */
    fun validateTokenForLanding(rawToken: String, ipAddress: String): ResetTokenVerificationResult {
        val now = clock.instant()

        // Rate limit verification attempts by IP
        if (!rateLimiter.checkAndRecordTokenVerification(ipAddress, config.rateLimits.tokenVerificationMaxAttemptsPerMin)) {
            logger.warn("AUDIT: PASSWORD_RESET_TOKEN_VERIFICATION_RATE_LIMITED ip={}", ipAddress)
            return ResetTokenVerificationResult(
                valid = false,
                genericErrorMessage = GENERIC_TOKEN_ERROR
            )
        }

        if (rawToken.isBlank()) {
            return ResetTokenVerificationResult(
                valid = false,
                genericErrorMessage = GENERIC_TOKEN_ERROR
            )
        }

        val tokenDigest = try {
            PasswordResetTokenCrypto.computeDigest(rawToken, config.hmacSecret)
        } catch (_: Exception) {
            return ResetTokenVerificationResult(
                valid = false,
                genericErrorMessage = GENERIC_TOKEN_ERROR
            )
        }

        val record = tokenStore.findByDigest(tokenDigest)

        if (record == null) {
            logger.warn("AUDIT: PASSWORD_RESET_TOKEN_INVALID")
            return ResetTokenVerificationResult(
                valid = false,
                genericErrorMessage = GENERIC_TOKEN_ERROR
            )
        }

        if (record.usedAt != null) {
            logger.warn("AUDIT: PASSWORD_RESET_TOKEN_REPLAYED tokenId={}", record.id)
            return ResetTokenVerificationResult(
                valid = false,
                genericErrorMessage = GENERIC_TOKEN_ERROR
            )
        }

        if (record.revokedAt != null) {
            logger.warn("AUDIT: PASSWORD_RESET_TOKEN_REVOKED tokenId={}", record.id)
            return ResetTokenVerificationResult(
                valid = false,
                genericErrorMessage = GENERIC_TOKEN_ERROR
            )
        }

        if (now.isAfter(record.expiresAt)) {
            logger.warn("AUDIT: PASSWORD_RESET_TOKEN_EXPIRED tokenId={}", record.id)
            return ResetTokenVerificationResult(
                valid = false,
                genericErrorMessage = GENERIC_TOKEN_ERROR
            )
        }

        logger.info("AUDIT: PASSWORD_RESET_TOKEN_PRESENTED tokenId={}", record.id)

        // Establish ephemeral, short-lived reset transaction (5 minutes or until token expiry)
        val transactionId = UUID.randomUUID()
        val csrfToken = PasswordResetTokenCrypto.generateCsrfToken()
        val txExpiry = if (now.plus(Duration.ofMinutes(5)).isBefore(record.expiresAt)) {
            now.plus(Duration.ofMinutes(5))
        } else {
            record.expiresAt
        }

        // Determine verified email for post-reset notification
        val playerCred = durableAuthStore.findCredentialByPlayerId(record.tenantId, record.playerId)
        val verifiedEmail = playerCred?.identifier ?: ""

        val transaction = ResetSessionTransaction(
            transactionId = transactionId,
            tokenId = record.id,
            playerId = record.playerId,
            tenantId = record.tenantId,
            verifiedEmail = verifiedEmail,
            csrfToken = csrfToken,
            createdAt = now,
            expiresAt = txExpiry
        )
        resetTransactions[transactionId] = transaction

        return ResetTokenVerificationResult(
            valid = true,
            resetTransactionId = transactionId,
            csrfToken = csrfToken
        )
    }

    /**
     * Atomically redeems reset transaction, validates CSRF, updates password,
     * permanently consumes reset token, revokes active player sessions and token families.
     */
    fun completePasswordReset(command: CompletePasswordResetCommand): CompletePasswordResetResult {
        val now = clock.instant()

        // 1. Validate reset transaction
        val tx = resetTransactions[command.resetTransactionId]
        if (tx == null || now.isAfter(tx.expiresAt)) {
            resetTransactions.remove(command.resetTransactionId)
            logger.warn("AUDIT: PASSWORD_RESET_TRANSACTION_EXPIRED correlationId={}", command.correlationId)
            return CompletePasswordResetResult(
                success = false,
                message = "The password reset session has expired or is invalid. Please request a new link."
            )
        }

        // 2. Validate CSRF token bound to this transaction
        if (!PasswordResetTokenCrypto.constantTimeEquals(tx.csrfToken, command.csrfToken)) {
            logger.warn("AUDIT: PASSWORD_RESET_CSRF_INVALID correlationId={}", command.correlationId)
            return CompletePasswordResetResult(
                success = false,
                message = "Invalid CSRF verification token."
            )
        }

        // 3. Enforce strong password policy and compromised blocklist
        val policyVerdict = PasswordPolicyService.validate(command.newPassword, command.confirmPassword)
        if (!policyVerdict.valid) {
            return CompletePasswordResetResult(
                success = false,
                message = policyVerdict.errorMessage ?: "Password does not meet security requirements."
            )
        }

        // 4. Password reuse prevention (cannot reuse currently active password)
        val currentCred = durableAuthStore.findCredentialByPlayerId(tx.tenantId, tx.playerId)
        if (currentCred != null) {
            val check = PasswordKdfService.verifyPassword(
                command.newPassword,
                currentCred.passwordHash,
                currentCred.passwordSalt,
                currentCred.iterations,
                currentCred.passwordAlgo
            )
            if (check.valid) {
                return CompletePasswordResetResult(
                    success = false,
                    message = "New password cannot be the same as your previous password."
                )
            }
        }

        // 5. ATOMIC CONSUMPTION: mark reset token used
        val consumed = tokenStore.markTokenUsed(tx.tokenId, now)
        if (!consumed) {
            // Concurrent redemption detected!
            resetTransactions.remove(command.resetTransactionId)
            logger.warn("AUDIT: PASSWORD_RESET_TOKEN_REPLAYED tokenId={}", tx.tokenId)
            return CompletePasswordResetResult(
                success = false,
                message = "This reset token is invalid or has already been used."
            )
        }

        // 6. Invalidate all other active reset tokens for this player
        tokenStore.revokeAllActiveTokensForPlayer(tx.tenantId, tx.playerId, now)

        // 7. Hash new password with authoritative PBKDF2 KDF
        val hashed = PasswordKdfService.hashPassword(command.newPassword)
        durableAuthStore.updatePassword(
            playerId = tx.playerId,
            newHash = hashed.hash,
            newSalt = hashed.salt,
            iterations = hashed.iterations,
            algo = hashed.algo
        )

        // Update registration store if present
        registrationStore.findById(tx.tenantId, tx.playerId)?.let { regRecord ->
            regRecord.passwordHash = hashed.hash
            regRecord.version++
            regRecord.updatedAt = now
        }

        // 8. Revoke all active sessions, refresh-token families, and cached tokens
        val revokedCount = durableAuthService.revokeAllPlayerSessionsAndTokens(tx.tenantId, tx.playerId)
        playerSessionStore?.revokeAllPlayerSessions(tx.tenantId, tx.playerId, now)
        tokenSecurityStore?.revokeAllFamiliesForPlayer(tx.tenantId, tx.playerId, TokenRevocationReason.SECURITY_POLICY, now)

        // Clean up transaction
        resetTransactions.remove(command.resetTransactionId)

        logger.info("AUDIT: PASSWORD_RESET_COMPLETED playerId={} sessionsRevoked={}", tx.playerId, revokedCount)
        logger.info("AUDIT: PASSWORD_RESET_SESSIONS_REVOKED playerId={}", tx.playerId)

        // 9. Send password changed notification email
        if (tx.verifiedEmail.isNotBlank()) {
            emailSender.sendPasswordChangedNotification(tx.verifiedEmail)
        }

        return CompletePasswordResetResult(
            success = true,
            message = "Password reset successful.",
            playerId = tx.playerId,
            sessionsRevokedCount = revokedCount
        )
    }

    private fun sha256(input: String): String {
        val digest = MessageDigest.getInstance("SHA-256")
        val bytes = digest.digest(input.toByteArray(Charsets.UTF_8))
        return bytes.joinToString("") { "%02x".format(it) }
    }

    private fun dummyHmacWork() {
        try {
            PasswordResetTokenCrypto.computeDigest("dummy-timing-token", config.hmacSecret.ifBlank { "dummy-pepper-padding-at-least-32-bytes" })
        } catch (_: Exception) {}
    }
}
