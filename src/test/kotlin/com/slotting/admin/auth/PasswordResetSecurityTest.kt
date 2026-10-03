package com.slotting.admin.auth

import com.slotting.admin.auth.passwordreset.*
import com.slotting.admin.identity.*
import org.junit.jupiter.api.Assertions.*
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test
import java.time.Clock
import java.time.Duration
import java.time.Instant
import java.time.ZoneOffset
import java.util.UUID
import java.util.concurrent.CountDownLatch
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicInteger

class PasswordResetSecurityTest {

    private lateinit var regStore: InMemoryPlayerRegistrationStore
    private lateinit var durableAuthStore: InMemoryDurableAuthStore
    private lateinit var tokenStore: InMemoryPasswordResetTokenStore
    private lateinit var emailSender: InMemoryPasswordResetEmailSender
    private lateinit var rateLimiter: PasswordResetRateLimiter
    private lateinit var durableAuthService: DurableAuthService
    private lateinit var resetService: PasswordResetService
    private lateinit var resetController: PasswordResetController
    private lateinit var clock: MutableTestClock

    private val tenantId = "default"
    private val hmacSecret = "test-super-secret-hmac-pepper-with-256-bits-entropy!!"
    private val publicOrigin = "https://auth.slotting.com"

    class MutableTestClock(private var currentInstant: Instant) : Clock() {
        override fun getZone(): ZoneOffset = ZoneOffset.UTC
        override fun withZone(zone: java.time.ZoneId): Clock = this
        override fun instant(): Instant = currentInstant
        fun advance(duration: Duration) {
            currentInstant = currentInstant.plus(duration)
        }
    }

    @BeforeEach
    fun setUp() {
        clock = MutableTestClock(Instant.parse("2026-10-03T10:00:00Z"))
        regStore = InMemoryPlayerRegistrationStore()
        durableAuthStore = InMemoryDurableAuthStore()
        tokenStore = InMemoryPasswordResetTokenStore()
        emailSender = InMemoryPasswordResetEmailSender()
        rateLimiter = PasswordResetRateLimiter(clock)
        durableAuthService = DurableAuthService(store = durableAuthStore, clock = clock)

        val config = PasswordResetConfig(
            publicOrigin = publicOrigin,
            tokenTtl = Duration.ofSeconds(90),
            hmacSecret = hmacSecret,
            emailFrom = "security@auth.slotting.com",
            maxActiveTokensPerPlayer = 3,
            isProduction = true,
            rateLimits = PasswordResetRateLimitConfig(
                perAccountCooldownSeconds = 60L,
                perAccountMaxRequests = 5,
                perAccountWindowMinutes = 15L,
                perIpMaxRequests = 20,
                perIpWindowMinutes = 15L,
                tokenVerificationMaxAttemptsPerMin = 10
            )
        )

        resetService = PasswordResetService(
            config = config,
            tokenStore = tokenStore,
            registrationStore = regStore,
            durableAuthStore = durableAuthStore,
            durableAuthService = durableAuthService,
            emailSender = emailSender,
            rateLimiter = rateLimiter,
            clock = clock
        )

        resetController = PasswordResetController(resetService)
    }

    private fun registerVerifiedPlayer(
        email: String = "alice@example.com",
        initialPassword: String = "OldSecurePassword123!"
    ): UUID {
        val playerId = UUID.randomUUID()
        val hashed = PasswordKdfService.hashPassword(initialPassword)

        val cred = PlayerCredentialRecord(
            playerId = playerId,
            tenantId = tenantId,
            identifier = email,
            passwordHash = hashed.hash,
            passwordSalt = hashed.salt,
            iterations = hashed.iterations,
            passwordAlgo = hashed.algo,
            status = "ACTIVE",
            createdAt = clock.instant(),
            updatedAt = clock.instant()
        )
        durableAuthStore.saveCredential(cred)

        val regRecord = PlayerRegistrationRecord(
            playerId = playerId,
            tenantId = tenantId,
            emailHash = sha256(email.trim().lowercase()),
            phoneHash = "",
            maskedEmail = "a***@example.com",
            maskedPhone = "***",
            jurisdiction = "NV",
            riskScore = 0.0,
            mfaRequired = false,
            passwordHash = hashed.hash,
            status = PlayerAccountStatus.ACTIVE,
            emailVerified = true,
            phoneVerified = false,
            createdAt = clock.instant(),
            updatedAt = clock.instant()
        )
        regStore.players[playerId] = regRecord
        regStore.emailIndex["$tenantId:${regRecord.emailHash}"] = playerId

        return playerId
    }

    private fun sha256(input: String): String {
        val digest = java.security.MessageDigest.getInstance("SHA-256")
        val bytes = digest.digest(input.toByteArray(Charsets.UTF_8))
        return bytes.joinToString("") { "%02x".format(it) }
    }

    // =========================================================================
    // 1. HAPPY PATH END-TO-END FLOW
    // =========================================================================

    @Test
    fun `TC-01 happy path end-to-end secure single-use email password reset`() {
        val email = "verified.player@example.com"
        val oldPass = "InitialSecurePassword123!"
        val newPass = "NewSecureReplacementPassphrase2026!"
        val playerId = registerVerifiedPlayer(email, oldPass)

        // Establish an active session & refresh token family beforehand
        val loginResult = durableAuthService.authenticatePlayer(tenantId, email, oldPass)
        assertNotNull(loginResult)
        val authCode = durableAuthService.createAuthorizationCode(
            clientId = "slotting-android",
            redirectUri = "https://app.slotting.internal/auth/callback",
            scope = "openid profile",
            state = "state-123",
            nonce = "nonce-123",
            codeChallenge = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM",
            codeChallengeMethod = "S256",
            tenantId = tenantId,
            playerId = playerId
        )
        val tokenPair = durableAuthService.exchangeAuthorizationCode(
            grantType = "authorization_code",
            code = authCode.code,
            codeVerifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk",
            codeChallengeMethod = "S256",
            state = "state-123",
            redirectUri = "https://app.slotting.internal/auth/callback",
            clientId = "slotting-android"
        )
        assertNotNull(tokenPair.refreshToken)
        assertNotNull(tokenPair.accessToken)

        // 1. Request reset
        val reqResult = resetService.requestPasswordReset(
            PasswordResetRequestCommand(
                tenantId = tenantId,
                email = email,
                ipAddress = "192.168.1.100"
            )
        )
        assertEquals(PasswordResetService.GENERIC_REQUEST_RESPONSE, reqResult.genericMessage)
        assertTrue(reqResult.emailQueued)

        // 2. Email dispatched
        assertEquals(1, emailSender.sentEmails.size)
        val sentEmail = emailSender.sentEmails.first()
        assertEquals(email, sentEmail.toEmail)
        assertNotNull(sentEmail.resetUrl)
        assertTrue(sentEmail.resetUrl!!.startsWith("https://auth.slotting.com/auth/password-reset?token="))
        assertTrue(sentEmail.body.contains("90 seconds"))

        val rawToken = sentEmail.resetUrl!!.substringAfter("token=")
        assertTrue(rawToken.length >= 40, "Token must be at least 256 bits Base64URL encoded")

        // Assert raw token is NOT in database
        val digest = PasswordResetTokenCrypto.computeDigest(rawToken, hmacSecret)
        val storedRecord = tokenStore.findByDigest(digest)
        assertNotNull(storedRecord)
        assertFalse(tokenStore.tokens.values.any { it.tokenDigest == rawToken }, "Raw token must never be in DB")

        // 3. Link scanner / prefetch GET landing page (GET must NOT consume token)
        val landingVerdict = resetService.validateTokenForLanding(rawToken, "192.168.1.50")
        assertTrue(landingVerdict.valid)
        assertNotNull(landingVerdict.resetTransactionId)
        assertNotNull(landingVerdict.csrfToken)

        // Verify token still NOT used
        val recordAfterGet = tokenStore.findByDigest(digest)
        assertNotNull(recordAfterGet)
        assertNull(recordAfterGet!!.usedAt, "GET must not consume token (link scanner protection)")

        // 4. Complete reset: POST new password
        val completeResult = resetService.completePasswordReset(
            CompletePasswordResetCommand(
                resetTransactionId = landingVerdict.resetTransactionId!!,
                csrfToken = landingVerdict.csrfToken!!,
                newPassword = newPass,
                confirmPassword = newPass
            )
        )
        assertTrue(completeResult.success)
        assertEquals("Password reset successful.", completeResult.message)

        // 5. Token is now permanently used
        val recordAfterPost = tokenStore.findByDigest(digest)
        assertNotNull(recordAfterPost!!.usedAt, "Token must be atomically marked used")

        // 6. Token replay fails (single use)
        val secondLanding = resetService.validateTokenForLanding(rawToken, "192.168.1.50")
        assertFalse(secondLanding.valid)
        assertEquals(PasswordResetService.GENERIC_TOKEN_ERROR, secondLanding.genericErrorMessage)

        // 7. Old sessions and refresh tokens are permanently revoked!
        assertThrows(AuthenticationException::class.java) {
            durableAuthService.rotateRefreshToken(tokenPair.refreshToken, "slotting-android")
        }
        val cachedPrincipal = durableAuthService.validateAccessToken(tokenPair.accessToken)
        assertNull(cachedPrincipal, "Cached access tokens must be evicted upon reset")

        // 8. Notification email was sent to verified email
        assertEquals(2, emailSender.sentEmails.size)
        val notificationEmail = emailSender.sentEmails.last()
        assertTrue(notificationEmail.isNotification)
        assertEquals(email, notificationEmail.toEmail)
        assertTrue(notificationEmail.body.contains("all active sessions and refresh tokens have been signed out"))

        // 9. Login with old password fails; login with new password succeeds!
        val oldLogin = durableAuthService.authenticatePlayer(tenantId, email, oldPass)
        assertNull(oldLogin, "Old password must fail authentication")

        val newLogin = durableAuthService.authenticatePlayer(tenantId, email, newPass)
        assertNotNull(newLogin, "New password must succeed authentication")
        assertEquals(playerId, newLogin!!.playerId)
    }

    // =========================================================================
    // 2. ACCOUNT ENUMERATION PROTECTION
    // =========================================================================

    @Test
    fun `TC-02 account enumeration protection returns identical generic response for all conditions`() {
        val verifiedEmail = "verified@example.com"
        registerVerifiedPlayer(verifiedEmail)

        val unverifiedEmail = "unverified@example.com"
        val unverifiedId = UUID.randomUUID()
        regStore.players[unverifiedId] = PlayerRegistrationRecord(
            playerId = unverifiedId,
            tenantId = tenantId,
            emailHash = sha256(unverifiedEmail),
            phoneHash = "",
            maskedEmail = "u***@example.com",
            maskedPhone = "***",
            jurisdiction = "NV",
            riskScore = 0.0,
            mfaRequired = false,
            passwordHash = "hash",
            status = PlayerAccountStatus.PENDING_VERIFICATION,
            emailVerified = false,
            phoneVerified = false,
            createdAt = clock.instant(),
            updatedAt = clock.instant()
        )
        regStore.emailIndex["$tenantId:${sha256(unverifiedEmail)}"] = unverifiedId

        val suspendedEmail = "suspended@example.com"
        val suspendedId = UUID.randomUUID()
        regStore.players[suspendedId] = PlayerRegistrationRecord(
            playerId = suspendedId,
            tenantId = tenantId,
            emailHash = sha256(suspendedEmail),
            phoneHash = "",
            maskedEmail = "s***@example.com",
            maskedPhone = "***",
            jurisdiction = "NV",
            riskScore = 0.0,
            mfaRequired = false,
            passwordHash = "hash",
            status = PlayerAccountStatus.SUSPENDED,
            emailVerified = true,
            phoneVerified = false,
            createdAt = clock.instant(),
            updatedAt = clock.instant()
        )
        regStore.emailIndex["$tenantId:${sha256(suspendedEmail)}"] = suspendedId

        val unknownEmail = "unknown@example.com"
        val malformedEmail = "not-an-email"

        // 1. Existing verified account
        val res1 = resetService.requestPasswordReset(PasswordResetRequestCommand(email = verifiedEmail))
        // 2. Non-existent account
        val res2 = resetService.requestPasswordReset(PasswordResetRequestCommand(email = unknownEmail))
        // 3. Unverified email account
        val res3 = resetService.requestPasswordReset(PasswordResetRequestCommand(email = unverifiedEmail))
        // 4. Suspended account
        val res4 = resetService.requestPasswordReset(PasswordResetRequestCommand(email = suspendedEmail))
        // 5. Malformed email
        val res5 = resetService.requestPasswordReset(PasswordResetRequestCommand(email = malformedEmail))

        // All responses MUST have identical generic message
        assertEquals(PasswordResetService.GENERIC_REQUEST_RESPONSE, res1.genericMessage)
        assertEquals(PasswordResetService.GENERIC_REQUEST_RESPONSE, res2.genericMessage)
        assertEquals(PasswordResetService.GENERIC_REQUEST_RESPONSE, res3.genericMessage)
        assertEquals(PasswordResetService.GENERIC_REQUEST_RESPONSE, res4.genericMessage)
        assertEquals(PasswordResetService.GENERIC_REQUEST_RESPONSE, res5.genericMessage)

        // Only the verified active account should have triggered email dispatch!
        assertEquals(1, emailSender.sentEmails.size)
        assertEquals(verifiedEmail, emailSender.sentEmails.first().toEmail)
    }

    // =========================================================================
    // 3. TOKEN LIFETIME & EXPIRY
    // =========================================================================

    @Test
    fun `TC-03 expired reset token is strictly rejected`() {
        val email = "expiring.user@example.com"
        registerVerifiedPlayer(email)

        resetService.requestPasswordReset(PasswordResetRequestCommand(email = email))
        val rawToken = emailSender.sentEmails.first().resetUrl!!.substringAfter("token=")

        clock.advance(Duration.ofSeconds(80))
        val landingBeforeExpiry = resetService.validateTokenForLanding(rawToken, "127.0.0.1")
        assertTrue(landingBeforeExpiry.valid)

        clock.advance(Duration.ofSeconds(15))
        val landingAfterExpiry = resetService.validateTokenForLanding(rawToken, "127.0.0.1")
        assertFalse(landingAfterExpiry.valid)
        assertEquals(PasswordResetService.GENERIC_TOKEN_ERROR, landingAfterExpiry.genericErrorMessage)
    }

    // =========================================================================
    // 4. CONCURRENT REDEMPTION & SINGLE-USE RACE PROTECTION
    // =========================================================================

    @Test
    fun `TC-04 concurrent redemption of same reset token permits exactly one success`() {
        val email = "concurrent.user@example.com"
        registerVerifiedPlayer(email)

        resetService.requestPasswordReset(PasswordResetRequestCommand(email = email))
        val rawToken = emailSender.sentEmails.first().resetUrl!!.substringAfter("token=")

        val landing = resetService.validateTokenForLanding(rawToken, "127.0.0.1")
        assertTrue(landing.valid)
        val txId = landing.resetTransactionId!!
        val csrf = landing.csrfToken!!

        // Submit from 10 threads concurrently
        val threadCount = 10
        val executor = Executors.newFixedThreadPool(threadCount)
        val latch = CountDownLatch(1)
        val successCount = AtomicInteger(0)
        val failCount = AtomicInteger(0)

        for (i in 0 until threadCount) {
            executor.submit {
                latch.await()
                val res = resetService.completePasswordReset(
                    CompletePasswordResetCommand(
                        resetTransactionId = txId,
                        csrfToken = csrf,
                        newPassword = "ConcurrentSecurePassword$i!2026",
                        confirmPassword = "ConcurrentSecurePassword$i!2026"
                    )
                )
                if (res.success) {
                    successCount.incrementAndGet()
                } else {
                    failCount.incrementAndGet()
                }
            }
        }

        latch.countDown()
        executor.shutdown()
        executor.awaitTermination(5, TimeUnit.SECONDS)

        assertEquals(1, successCount.get(), "Exactly one concurrent redemption must succeed")
        assertEquals(threadCount - 1, failCount.get(), "All conflicting submissions must be rejected")
    }

    // =========================================================================
    // 5. MULTIPLE OUTSTANDING RESET TOKENS INVALIDATION
    // =========================================================================

    @Test
    fun `TC-05 successful password reset invalidates all other active reset tokens for that player`() {
        val email = "multiple.tokens@example.com"
        registerVerifiedPlayer(email)

        // Issue token 1
        resetService.requestPasswordReset(PasswordResetRequestCommand(email = email))
        val token1 = emailSender.sentEmails[0].resetUrl!!.substringAfter("token=")

        clock.advance(Duration.ofSeconds(65))
        resetService.requestPasswordReset(PasswordResetRequestCommand(email = email))
        val token2 = emailSender.sentEmails[1].resetUrl!!.substringAfter("token=")

        // Use token 2 to reset password
        val landing2 = resetService.validateTokenForLanding(token2, "127.0.0.1")
        val reset2 = resetService.completePasswordReset(
            CompletePasswordResetCommand(
                resetTransactionId = landing2.resetTransactionId!!,
                csrfToken = landing2.csrfToken!!,
                newPassword = "BrandNewValidPassphrase123!",
                confirmPassword = "BrandNewValidPassphrase123!"
            )
        )
        assertTrue(reset2.success)

        // Attempt to use token 1 -> MUST be rejected because successful reset revoked it
        val landing1 = resetService.validateTokenForLanding(token1, "127.0.0.1")
        assertFalse(landing1.valid, "Token 1 must be revoked after Token 2 was used")
        assertEquals(PasswordResetService.GENERIC_TOKEN_ERROR, landing1.genericErrorMessage)
    }

    // =========================================================================
    // 6. CSRF PROTECTION
    // =========================================================================

    @Test
    fun `TC-06 CSRF protection rejects mismatched or missing CSRF tokens`() {
        val email = "csrf.test@example.com"
        registerVerifiedPlayer(email)

        resetService.requestPasswordReset(PasswordResetRequestCommand(email = email))
        val rawToken = emailSender.sentEmails.first().resetUrl!!.substringAfter("token=")
        val landing = resetService.validateTokenForLanding(rawToken, "127.0.0.1")

        // 1. Missing / wrong CSRF
        val wrongCsrfRes = resetService.completePasswordReset(
            CompletePasswordResetCommand(
                resetTransactionId = landing.resetTransactionId!!,
                csrfToken = "forged-csrf-token",
                newPassword = "NewValidSecurePassphrase123!",
                confirmPassword = "NewValidSecurePassphrase123!"
            )
        )
        assertFalse(wrongCsrfRes.success)
        assertTrue(wrongCsrfRes.message.contains("CSRF", ignoreCase = true))

        // 2. Valid CSRF succeeds
        val validCsrfRes = resetService.completePasswordReset(
            CompletePasswordResetCommand(
                resetTransactionId = landing.resetTransactionId!!,
                csrfToken = landing.csrfToken!!,
                newPassword = "NewValidSecurePassphrase123!",
                confirmPassword = "NewValidSecurePassphrase123!"
            )
        )
        assertTrue(validCsrfRes.success)
    }

    // =========================================================================
    // 7. PASSWORD POLICY AND COMPROMISED BLOCKLIST
    // =========================================================================

    @Test
    fun `TC-07 password policy enforces min 15 chars, max 64 chars, and blocks common passwords`() {
        val email = "policy.user@example.com"
        registerVerifiedPlayer(email)

        resetService.requestPasswordReset(PasswordResetRequestCommand(email = email))
        val rawToken = emailSender.sentEmails.first().resetUrl!!.substringAfter("token=")
        val landing = resetService.validateTokenForLanding(rawToken, "127.0.0.1")
        val txId = landing.resetTransactionId!!
        val csrf = landing.csrfToken!!

        // 1. Too short (< 15)
        val shortRes = resetService.completePasswordReset(
            CompletePasswordResetCommand(txId, csrf, "Short123!", "Short123!")
        )
        assertFalse(shortRes.success)
        assertTrue(shortRes.message.contains("at least 15 characters"))

        // 2. Too long (> 64)
        val longRes = resetService.completePasswordReset(
            CompletePasswordResetCommand(txId, csrf, "A".repeat(65), "A".repeat(65))
        )
        assertFalse(longRes.success)
        assertTrue(longRes.message.contains("not exceed 64 characters"))

        // 3. Password mismatch
        val mismatchRes = resetService.completePasswordReset(
            CompletePasswordResetCommand(txId, csrf, "ValidLengthPassphrase123!", "DifferentPassphrase123!")
        )
        assertFalse(mismatchRes.success)
        assertTrue(mismatchRes.message.contains("Passwords do not match"))

        // 4. Compromised / known blocklist
        val blocklistRes = resetService.completePasswordReset(
            CompletePasswordResetCommand(txId, csrf, "password12345678", "password12345678")
        )
        assertFalse(blocklistRes.success)
        assertTrue(blocklistRes.message.contains("commonly used or compromised"))

        // 5. Valid passphrase with spaces and symbols succeeds
        val validPass = "correct horse battery staple 2026!"
        val successRes = resetService.completePasswordReset(
            CompletePasswordResetCommand(txId, csrf, validPass, validPass)
        )
        assertTrue(successRes.success)
    }

    // =========================================================================
    // 8. HOST-HEADER INJECTION PROTECTION
    // =========================================================================

    @Test
    fun `TC-08 host header injection defense generates links strictly from configured origin`() {
        val email = "host.injection@example.com"
        registerVerifiedPlayer(email)

        resetService.requestPasswordReset(
            PasswordResetRequestCommand(
                email = email,
                ipAddress = "192.168.1.10"
            )
        )
        val sentEmail = emailSender.sentEmails.first()

        // Link must use configured publicOrigin, NEVER an attacker header
        assertTrue(sentEmail.resetUrl!!.startsWith("https://auth.slotting.com/"))
        assertFalse(sentEmail.resetUrl!!.contains("attacker"))
        assertFalse(sentEmail.resetUrl!!.contains("evil"))
    }

    // =========================================================================
    // 9. RATE LIMITING & EMAIL BOMBING SUPPRESSION
    // =========================================================================

    @Test
    fun `TC-09 rate limiting throttles rapid repeat requests and prevents email bombing`() {
        val email = "victim@example.com"
        registerVerifiedPlayer(email)

        // Request 1: succeeds
        val r1 = resetService.requestPasswordReset(PasswordResetRequestCommand(email = email))
        assertTrue(r1.emailQueued)

        // Request 2 (immediate, within 60s cooldown): throttled! Returns generic message, suppresses email
        val r2 = resetService.requestPasswordReset(PasswordResetRequestCommand(email = email))
        assertFalse(r2.emailQueued, "Email bombing must be suppressed by cooldown")
        assertEquals(PasswordResetService.GENERIC_REQUEST_RESPONSE, r2.genericMessage)

        // Only 1 email was sent
        assertEquals(1, emailSender.sentEmails.size)
    }

    // =========================================================================
    // 10. NO REUSE OF CURRENT PASSWORD
    // =========================================================================

    @Test
    fun `TC-10 immediate reuse of current active password is prevented`() {
        val email = "reuse.check@example.com"
        val currentPass = "ExistingStrongPassphrase2026!"
        registerVerifiedPlayer(email, currentPass)

        resetService.requestPasswordReset(PasswordResetRequestCommand(email = email))
        val rawToken = emailSender.sentEmails.first().resetUrl!!.substringAfter("token=")
        val landing = resetService.validateTokenForLanding(rawToken, "127.0.0.1")

        val reuseRes = resetService.completePasswordReset(
            CompletePasswordResetCommand(
                resetTransactionId = landing.resetTransactionId!!,
                csrfToken = landing.csrfToken!!,
                newPassword = currentPass,
                confirmPassword = currentPass
            )
        )
        assertFalse(reuseRes.success)
        assertTrue(reuseRes.message.contains("cannot be the same as your previous password"))
    }
}
