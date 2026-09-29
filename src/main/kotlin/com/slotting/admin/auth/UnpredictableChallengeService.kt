package com.slotting.admin.auth

import java.security.MessageDigest
import java.security.SecureRandom
import java.time.Duration
import java.time.Instant
import java.util.UUID

/**
 * Unpredictable, one-time, purpose/subject-bound challenge generator and validator (TC-004, BE-009).
 */
object UnpredictableChallengeService {

    private val secureRandom = SecureRandom()

    private val FORBIDDEN_PREDICTABLE_CODES = setOf(
        "EMAIL-123456",
        "PHONE-654321",
        "MFA-654321",
        "CONFIRM-123456",
        "123456",
        "000000"
    )

    data class IssuedChallenge(
        val challengeId: UUID,
        val tenantId: String,
        val playerId: UUID,
        val purpose: String,
        val plaintextCode: String,
        val codeHash: String,
        val salt: String,
        val attemptsRemaining: Int = 3,
        val maxAttempts: Int = 3,
        val expiresAt: Instant,
        val createdAt: Instant = Instant.now()
    )

    sealed class ChallengeValidationResult {
        object Success : ChallengeValidationResult()
        data class Rejected(val reason: String) : ChallengeValidationResult()
    }

    fun generateChallenge(
        tenantId: String,
        playerId: UUID,
        purpose: String,
        ttl: Duration = Duration.ofMinutes(5),
        now: Instant = Instant.now()
    ): IssuedChallenge {
        val codeNum = 100_000 + secureRandom.nextInt(900_000)
        val plaintextCode = codeNum.toString()

        val saltBytes = ByteArray(16).also { secureRandom.nextBytes(it) }
        val saltHex = PasswordKdfService.bytesToHex(saltBytes)

        val codeHash = hashChallengeCode(plaintextCode, saltHex)

        return IssuedChallenge(
            challengeId = UUID.randomUUID(),
            tenantId = tenantId,
            playerId = playerId,
            purpose = purpose,
            plaintextCode = plaintextCode,
            codeHash = codeHash,
            salt = saltHex,
            expiresAt = now.plus(ttl),
            createdAt = now
        )
    }

    fun hashChallengeCode(code: String, saltHex: String): String {
        val combined = "$saltHex:$code"
        val digest = MessageDigest.getInstance("SHA-256").digest(combined.toByteArray(Charsets.UTF_8))
        return PasswordKdfService.bytesToHex(digest)
    }

    fun validateCode(
        submittedCode: String,
        expectedHash: String,
        saltHex: String,
        expectedPurpose: String,
        actualPurpose: String,
        expectedPlayerId: UUID,
        actualPlayerId: UUID,
        expectedTenantId: String,
        actualTenantId: String,
        expiresAt: Instant,
        attemptsRemaining: Int,
        consumed: Boolean,
        now: Instant = Instant.now()
    ): ChallengeValidationResult {
        if (submittedCode in FORBIDDEN_PREDICTABLE_CODES) {
            return ChallengeValidationResult.Rejected("Predictable or default challenge code rejected")
        }
        if (consumed) {
            return ChallengeValidationResult.Rejected("Challenge already consumed (one-time use enforced)")
        }
        if (now.isAfter(expiresAt)) {
            return ChallengeValidationResult.Rejected("Challenge expired")
        }
        if (attemptsRemaining <= 0) {
            return ChallengeValidationResult.Rejected("Maximum attempt limit exceeded")
        }
        if (actualPurpose != expectedPurpose) {
            return ChallengeValidationResult.Rejected("Cross-purpose challenge use prohibited")
        }
        if (actualPlayerId != expectedPlayerId) {
            return ChallengeValidationResult.Rejected("Cross-subject challenge use prohibited")
        }
        if (actualTenantId != expectedTenantId) {
            return ChallengeValidationResult.Rejected("Cross-tenant challenge use prohibited")
        }

        val computedHash = hashChallengeCode(submittedCode, saltHex)
        val matches = MessageDigest.isEqual(expectedHash.toByteArray(Charsets.UTF_8), computedHash.toByteArray(Charsets.UTF_8))
        if (!matches) {
            return ChallengeValidationResult.Rejected("Invalid challenge code")
        }

        return ChallengeValidationResult.Success
    }
}
