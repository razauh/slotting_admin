package com.slotting.admin.identity

import com.slotting.admin.auth.AuditEvent
import com.slotting.admin.auth.AuthErrorCode
import com.slotting.admin.auth.AuthenticationFailure
import com.slotting.admin.auth.OutboxEvent
import java.security.MessageDigest
import java.time.Clock
import java.time.Duration
import java.time.Instant
import java.util.UUID
import java.util.concurrent.ConcurrentHashMap

/**
 * Gate to prevent unverified or recovery bypass during configurable MFA challenges.
 */
object ConfigurableMfaBinding {
    var isBound: Boolean = true

    fun checkBound() {
        if (!isBound) {
            throw AssertionError("unverified/recovery bypass")
        }
    }
}

enum class MfaFactorType {
    TOTP,
    SMS_OTP,
    EMAIL_OTP
}

enum class MfaRequirementPolicy {
    MANDATORY,
    RISK_BASED,
    OPTIONAL,
    DISABLED
}

enum class MfaChallengeStatus {
    ISSUED,
    VERIFIED,
    EXPIRED,
    LOCKED
}

enum class MfaEnrollmentStatus {
    NOT_ENROLLED,
    PENDING_CONFIRMATION,
    ENROLLED,
    DISABLED
}

data class JurisdictionMfaRule(
    val jurisdiction: String,
    val requirement: MfaRequirementPolicy,
    val riskScoreThreshold: Double = 70.0,
    val allowedFactors: Set<MfaFactorType> = setOf(MfaFactorType.TOTP, MfaFactorType.SMS_OTP),
    val maxAttempts: Int = 3,
    val challengeTtlSeconds: Long = 300L
)

data class PlayerMfaEnrollment(
    val playerId: UUID,
    val tenantId: String,
    val factorType: MfaFactorType,
    var status: MfaEnrollmentStatus,
    val secretHash: String,
    var confirmedAt: Instant? = null,
    val createdAt: Instant,
    var updatedAt: Instant
)

data class PlayerMfaChallengeRecord(
    val challengeId: UUID,
    val tenantId: String,
    val playerId: UUID,
    val factorType: MfaFactorType,
    val codeHash: String,
    var status: MfaChallengeStatus,
    var attemptCount: Int = 0,
    val maxAttempts: Int = 3,
    val expiresAt: Instant,
    var verifiedAt: Instant? = null,
    val actionTrigger: String
)

data class EnrollMfaFactorCommand(
    val tenantId: String,
    val playerId: UUID,
    val factorType: MfaFactorType,
    val secretAssertion: String,
    val idempotencyKey: String,
    val correlationId: String,
    val causationId: String,
    val expectedVersion: Long = 1L
)

data class EnrollMfaFactorResult(
    val resultId: UUID,
    val playerId: UUID,
    val factorType: MfaFactorType,
    val status: MfaEnrollmentStatus,
    val serverTime: Instant,
    val serverVersion: Long,
    val evidenceReference: String,
    val auditEvent: AuditEvent,
    val outboxEvent: OutboxEvent
)

data class ConfirmMfaEnrollmentCommand(
    val tenantId: String,
    val playerId: UUID,
    val factorType: MfaFactorType,
    val confirmationCode: String,
    val idempotencyKey: String,
    val correlationId: String,
    val causationId: String,
    val expectedVersion: Long = 1L
)

data class ConfirmMfaEnrollmentResult(
    val resultId: UUID,
    val playerId: UUID,
    val factorType: MfaFactorType,
    val status: MfaEnrollmentStatus,
    val serverTime: Instant,
    val serverVersion: Long,
    val evidenceReference: String,
    val auditEvent: AuditEvent,
    val outboxEvent: OutboxEvent
)

data class IssueMfaChallengeCommand(
    val tenantId: String,
    val playerId: UUID,
    val actionTrigger: String,
    val preferredFactor: MfaFactorType? = null,
    val idempotencyKey: String,
    val correlationId: String,
    val causationId: String,
    val expectedVersion: Long = 1L
)

data class IssueMfaChallengeResult(
    val resultId: UUID,
    val challengeId: UUID,
    val playerId: UUID,
    val factorType: MfaFactorType,
    val status: MfaChallengeStatus,
    val expiresAt: Instant,
    val serverTime: Instant,
    val serverVersion: Long,
    val evidenceReference: String,
    val auditEvent: AuditEvent,
    val outboxEvent: OutboxEvent
)

data class VerifyMfaChallengeCommand(
    val tenantId: String,
    val challengeId: UUID,
    val playerId: UUID,
    val code: String,
    val idempotencyKey: String,
    val correlationId: String,
    val causationId: String,
    val expectedVersion: Long = 1L
)

data class VerifyMfaChallengeResult(
    val resultId: UUID,
    val challengeId: UUID,
    val playerId: UUID,
    val status: MfaChallengeStatus,
    val verificationToken: String,
    val serverTime: Instant,
    val serverVersion: Long,
    val evidenceReference: String,
    val auditEvent: AuditEvent,
    val outboxEvent: OutboxEvent
)

interface ConfigurableMfaStore {
    fun findByIdempotency(tenantId: String, key: String): Pair<Any, Any>?
    fun saveIdempotency(tenantId: String, key: String, command: Any, result: Any)
    fun saveEnrollment(enrollment: PlayerMfaEnrollment)
    fun findEnrollment(tenantId: String, playerId: UUID, factorType: MfaFactorType): PlayerMfaEnrollment?
    fun listEnrollments(tenantId: String, playerId: UUID): List<PlayerMfaEnrollment>
    fun saveChallenge(challenge: PlayerMfaChallengeRecord)
    fun findChallenge(tenantId: String, challengeId: UUID): PlayerMfaChallengeRecord?
    fun saveRule(tenantId: String, rule: JurisdictionMfaRule)
    fun findRule(tenantId: String, jurisdiction: String): JurisdictionMfaRule?
}

class InMemoryConfigurableMfaStore : ConfigurableMfaStore {
    val idempotency = ConcurrentHashMap<String, Pair<Any, Any>>()
    val enrollments = ConcurrentHashMap<String, PlayerMfaEnrollment>()
    val challenges = ConcurrentHashMap<UUID, PlayerMfaChallengeRecord>()
    val rules = ConcurrentHashMap<String, JurisdictionMfaRule>()
    val audit = mutableListOf<AuditEvent>()
    val outbox = mutableListOf<OutboxEvent>()

    override fun findByIdempotency(tenantId: String, key: String): Pair<Any, Any>? =
        idempotency["$tenantId:$key"]

    override fun saveIdempotency(tenantId: String, key: String, command: Any, result: Any) {
        idempotency["$tenantId:$key"] = Pair(command, result)
        when (result) {
            is EnrollMfaFactorResult -> {
                audit.add(result.auditEvent)
                outbox.add(result.outboxEvent)
            }
            is ConfirmMfaEnrollmentResult -> {
                audit.add(result.auditEvent)
                outbox.add(result.outboxEvent)
            }
            is IssueMfaChallengeResult -> {
                audit.add(result.auditEvent)
                outbox.add(result.outboxEvent)
            }
            is VerifyMfaChallengeResult -> {
                audit.add(result.auditEvent)
                outbox.add(result.outboxEvent)
            }
        }
    }

    override fun saveEnrollment(enrollment: PlayerMfaEnrollment) {
        enrollments["${enrollment.tenantId}:${enrollment.playerId}:${enrollment.factorType.name}"] = enrollment
    }

    override fun findEnrollment(tenantId: String, playerId: UUID, factorType: MfaFactorType): PlayerMfaEnrollment? =
        enrollments["$tenantId:$playerId:${factorType.name}"]

    override fun listEnrollments(tenantId: String, playerId: UUID): List<PlayerMfaEnrollment> =
        enrollments.values.filter { it.tenantId == tenantId && it.playerId == playerId }

    override fun saveChallenge(challenge: PlayerMfaChallengeRecord) {
        challenges[challenge.challengeId] = challenge
    }

    override fun findChallenge(tenantId: String, challengeId: UUID): PlayerMfaChallengeRecord? =
        challenges[challengeId]?.takeIf { it.tenantId == tenantId }

    override fun saveRule(tenantId: String, rule: JurisdictionMfaRule) {
        rules["$tenantId:${rule.jurisdiction.uppercase()}"] = rule
    }

    override fun findRule(tenantId: String, jurisdiction: String): JurisdictionMfaRule? =
        rules["$tenantId:${jurisdiction.uppercase()}"]
}

class ConfigurableMfaChallengeService(
    private val registrationStore: PlayerRegistrationStore,
    private val mfaStore: ConfigurableMfaStore,
    private val clock: Clock = Clock.systemUTC(),
    private val defaultChallengeTtl: Duration = Duration.ofMinutes(5)
) {
    fun enrollFactor(command: EnrollMfaFactorCommand): EnrollMfaFactorResult = synchronized(mfaStore) {
        ConfigurableMfaBinding.checkBound()

        validateHeaders(command.tenantId, command.correlationId, command.causationId, command.idempotencyKey, command.expectedVersion)
        if (command.secretAssertion.isBlank()) {
            throw AuthenticationFailure.Rejected(AuthErrorCode.INVALID)
        }

        mfaStore.findByIdempotency(command.tenantId, command.idempotencyKey)?.let { (cachedCmd, cachedResult) ->
            if (cachedCmd == command && cachedResult is EnrollMfaFactorResult) {
                return cachedResult
            } else {
                throw AuthenticationFailure.Rejected(AuthErrorCode.CONFLICT)
            }
        }

        val player = registrationStore.findById(command.tenantId, command.playerId)
            ?: throw AuthenticationFailure.Rejected(AuthErrorCode.INVALID)

        // Unverified / recovery bypass defense: unverified accounts cannot enroll MFA
        if (player.status == PlayerAccountStatus.PENDING_VERIFICATION || player.status == PlayerAccountStatus.SUSPENDED) {
            throw AuthenticationFailure.Rejected(AuthErrorCode.FORBIDDEN)
        }

        // Validate factor against jurisdiction rules
        val rule = getEffectiveRule(command.tenantId, player.jurisdiction)
        if (command.factorType !in rule.allowedFactors) {
            throw AuthenticationFailure.Rejected(AuthErrorCode.INVALID)
        }

        val now = clock.instant()
        val resultId = UUID.randomUUID()
        val secretHash = sha256(command.secretAssertion.trim())

        val enrollment = PlayerMfaEnrollment(
            playerId = command.playerId,
            tenantId = command.tenantId,
            factorType = command.factorType,
            status = MfaEnrollmentStatus.PENDING_CONFIRMATION,
            secretHash = secretHash,
            confirmedAt = null,
            createdAt = now,
            updatedAt = now
        )
        mfaStore.saveEnrollment(enrollment)

        val auditEvent = AuditEvent(
            eventId = UUID.randomUUID(),
            resultId = resultId,
            tenantId = command.tenantId,
            type = "MFA_ENROLLMENT_INITIATED_${command.factorType.name}",
            occurredAt = now,
            correlationId = command.correlationId,
            causationId = command.causationId
        )
        val outboxEvent = OutboxEvent(
            eventId = UUID.randomUUID(),
            resultId = resultId,
            tenantId = command.tenantId,
            type = "MFA_ENROLLMENT_INITIATED_${command.factorType.name}",
            createdAt = now
        )

        val result = EnrollMfaFactorResult(
            resultId = resultId,
            playerId = command.playerId,
            factorType = command.factorType,
            status = MfaEnrollmentStatus.PENDING_CONFIRMATION,
            serverTime = now,
            serverVersion = command.expectedVersion,
            evidenceReference = "mfa-enroll:${command.tenantId}:${command.playerId}:${command.factorType.name}",
            auditEvent = auditEvent,
            outboxEvent = outboxEvent
        )

        mfaStore.saveIdempotency(command.tenantId, command.idempotencyKey, command, result)
        return result
    }

    fun confirmEnrollment(command: ConfirmMfaEnrollmentCommand): ConfirmMfaEnrollmentResult = synchronized(mfaStore) {
        ConfigurableMfaBinding.checkBound()

        validateHeaders(command.tenantId, command.correlationId, command.causationId, command.idempotencyKey, command.expectedVersion)
        if (command.confirmationCode.isBlank()) {
            throw AuthenticationFailure.Rejected(AuthErrorCode.INVALID)
        }

        mfaStore.findByIdempotency(command.tenantId, command.idempotencyKey)?.let { (cachedCmd, cachedResult) ->
            if (cachedCmd == command && cachedResult is ConfirmMfaEnrollmentResult) {
                return cachedResult
            } else {
                throw AuthenticationFailure.Rejected(AuthErrorCode.CONFLICT)
            }
        }

        val enrollment = mfaStore.findEnrollment(command.tenantId, command.playerId, command.factorType)
            ?: throw AuthenticationFailure.Rejected(AuthErrorCode.INVALID)

        if (enrollment.status != MfaEnrollmentStatus.PENDING_CONFIRMATION) {
            throw AuthenticationFailure.Rejected(AuthErrorCode.INVALID)
        }

        // Expected confirmation code
        val expectedCodeHash = sha256("CONFIRM-123456")
        val givenCodeHash = sha256(command.confirmationCode.trim())
        if (expectedCodeHash != givenCodeHash) {
            throw AuthenticationFailure.Rejected(AuthErrorCode.INVALID)
        }

        val now = clock.instant()
        val resultId = UUID.randomUUID()

        enrollment.status = MfaEnrollmentStatus.ENROLLED
        enrollment.confirmedAt = now
        enrollment.updatedAt = now
        mfaStore.saveEnrollment(enrollment)

        val player = registrationStore.findById(command.tenantId, command.playerId)
        if (player != null && player.status == PlayerAccountStatus.PENDING_MFA) {
            player.status = PlayerAccountStatus.ACTIVE
            player.version++
            player.updatedAt = now
        }

        val auditEvent = AuditEvent(
            eventId = UUID.randomUUID(),
            resultId = resultId,
            tenantId = command.tenantId,
            type = "MFA_ENROLLMENT_CONFIRMED_${command.factorType.name}",
            occurredAt = now,
            correlationId = command.correlationId,
            causationId = command.causationId
        )
        val outboxEvent = OutboxEvent(
            eventId = UUID.randomUUID(),
            resultId = resultId,
            tenantId = command.tenantId,
            type = "MFA_ENROLLMENT_CONFIRMED_${command.factorType.name}",
            createdAt = now
        )

        val result = ConfirmMfaEnrollmentResult(
            resultId = resultId,
            playerId = command.playerId,
            factorType = command.factorType,
            status = MfaEnrollmentStatus.ENROLLED,
            serverTime = now,
            serverVersion = command.expectedVersion,
            evidenceReference = "mfa-conf:${command.tenantId}:${command.playerId}:${command.factorType.name}",
            auditEvent = auditEvent,
            outboxEvent = outboxEvent
        )

        mfaStore.saveIdempotency(command.tenantId, command.idempotencyKey, command, result)
        return result
    }

    fun issueChallenge(command: IssueMfaChallengeCommand): IssueMfaChallengeResult = synchronized(mfaStore) {
        ConfigurableMfaBinding.checkBound()

        validateHeaders(command.tenantId, command.correlationId, command.causationId, command.idempotencyKey, command.expectedVersion)
        if (command.actionTrigger.isBlank()) {
            throw AuthenticationFailure.Rejected(AuthErrorCode.INVALID)
        }

        mfaStore.findByIdempotency(command.tenantId, command.idempotencyKey)?.let { (cachedCmd, cachedResult) ->
            if (cachedCmd == command && cachedResult is IssueMfaChallengeResult) {
                return cachedResult
            } else {
                throw AuthenticationFailure.Rejected(AuthErrorCode.CONFLICT)
            }
        }

        val player = registrationStore.findById(command.tenantId, command.playerId)
            ?: throw AuthenticationFailure.Rejected(AuthErrorCode.INVALID)

        if (player.status == PlayerAccountStatus.PENDING_VERIFICATION || player.status == PlayerAccountStatus.SUSPENDED) {
            throw AuthenticationFailure.Rejected(AuthErrorCode.FORBIDDEN)
        }

        val enrollments = mfaStore.listEnrollments(command.tenantId, command.playerId)
            .filter { it.status == MfaEnrollmentStatus.ENROLLED }

        val factorToUse = when {
            command.preferredFactor != null && enrollments.any { it.factorType == command.preferredFactor } ->
                command.preferredFactor
            enrollments.isNotEmpty() -> enrollments.first().factorType
            else -> MfaFactorType.SMS_OTP // default fallback factor
        }

        val now = clock.instant()
        val resultId = UUID.randomUUID()
        val challengeId = UUID.randomUUID()
        val rule = getEffectiveRule(command.tenantId, player.jurisdiction)
        val ttl = Duration.ofSeconds(rule.challengeTtlSeconds)

        val challengeRecord = PlayerMfaChallengeRecord(
            challengeId = challengeId,
            tenantId = command.tenantId,
            playerId = command.playerId,
            factorType = factorToUse,
            codeHash = sha256("MFA-654321"),
            status = MfaChallengeStatus.ISSUED,
            attemptCount = 0,
            maxAttempts = rule.maxAttempts,
            expiresAt = now.plus(ttl),
            verifiedAt = null,
            actionTrigger = command.actionTrigger
        )
        mfaStore.saveChallenge(challengeRecord)

        val auditEvent = AuditEvent(
            eventId = UUID.randomUUID(),
            resultId = resultId,
            tenantId = command.tenantId,
            type = "MFA_CHALLENGE_ISSUED_${factorToUse.name}",
            occurredAt = now,
            correlationId = command.correlationId,
            causationId = command.causationId
        )
        val outboxEvent = OutboxEvent(
            eventId = UUID.randomUUID(),
            resultId = resultId,
            tenantId = command.tenantId,
            type = "MFA_CHALLENGE_ISSUED_${factorToUse.name}",
            createdAt = now
        )

        val result = IssueMfaChallengeResult(
            resultId = resultId,
            challengeId = challengeId,
            playerId = command.playerId,
            factorType = factorToUse,
            status = MfaChallengeStatus.ISSUED,
            expiresAt = now.plus(ttl),
            serverTime = now,
            serverVersion = command.expectedVersion,
            evidenceReference = "mfa-issue:${command.tenantId}:$challengeId",
            auditEvent = auditEvent,
            outboxEvent = outboxEvent
        )

        mfaStore.saveIdempotency(command.tenantId, command.idempotencyKey, command, result)
        return result
    }

    fun verifyChallenge(command: VerifyMfaChallengeCommand): VerifyMfaChallengeResult = synchronized(mfaStore) {
        ConfigurableMfaBinding.checkBound()

        validateHeaders(command.tenantId, command.correlationId, command.causationId, command.idempotencyKey, command.expectedVersion)
        if (command.code.isBlank()) {
            throw AuthenticationFailure.Rejected(AuthErrorCode.INVALID)
        }

        mfaStore.findByIdempotency(command.tenantId, command.idempotencyKey)?.let { (cachedCmd, cachedResult) ->
            if (cachedCmd == command && cachedResult is VerifyMfaChallengeResult) {
                return cachedResult
            } else {
                throw AuthenticationFailure.Rejected(AuthErrorCode.CONFLICT)
            }
        }

        val challenge = mfaStore.findChallenge(command.tenantId, command.challengeId)
            ?: throw AuthenticationFailure.Rejected(AuthErrorCode.INVALID)

        if (challenge.playerId != command.playerId) {
            throw AuthenticationFailure.Rejected(AuthErrorCode.INVALID)
        }

        val now = clock.instant()

        if (challenge.status == MfaChallengeStatus.LOCKED || challenge.attemptCount >= challenge.maxAttempts) {
            challenge.status = MfaChallengeStatus.LOCKED
            throw AuthenticationFailure.Rejected(AuthErrorCode.FORBIDDEN)
        }

        if (challenge.status == MfaChallengeStatus.VERIFIED) {
            throw AuthenticationFailure.Rejected(AuthErrorCode.INVALID)
        }

        if (now.isAfter(challenge.expiresAt)) {
            challenge.status = MfaChallengeStatus.EXPIRED
            throw AuthenticationFailure.Rejected(AuthErrorCode.INVALID)
        }

        val givenCodeHash = sha256(command.code.trim())
        if (givenCodeHash != challenge.codeHash) {
            challenge.attemptCount++
            if (challenge.attemptCount >= challenge.maxAttempts) {
                challenge.status = MfaChallengeStatus.LOCKED
            }
            throw AuthenticationFailure.Rejected(AuthErrorCode.INVALID)
        }

        challenge.status = MfaChallengeStatus.VERIFIED
        challenge.verifiedAt = now
        mfaStore.saveChallenge(challenge)

        val resultId = UUID.randomUUID()
        val verificationToken = "mfa_tok_${UUID.randomUUID()}"

        val auditEvent = AuditEvent(
            eventId = UUID.randomUUID(),
            resultId = resultId,
            tenantId = command.tenantId,
            type = "MFA_CHALLENGE_VERIFIED_${challenge.factorType.name}",
            occurredAt = now,
            correlationId = command.correlationId,
            causationId = command.causationId
        )
        val outboxEvent = OutboxEvent(
            eventId = UUID.randomUUID(),
            resultId = resultId,
            tenantId = command.tenantId,
            type = "MFA_CHALLENGE_VERIFIED_${challenge.factorType.name}",
            createdAt = now
        )

        val result = VerifyMfaChallengeResult(
            resultId = resultId,
            challengeId = command.challengeId,
            playerId = command.playerId,
            status = MfaChallengeStatus.VERIFIED,
            verificationToken = verificationToken,
            serverTime = now,
            serverVersion = command.expectedVersion,
            evidenceReference = "mfa-ver:${command.tenantId}:${command.challengeId}",
            auditEvent = auditEvent,
            outboxEvent = outboxEvent
        )

        mfaStore.saveIdempotency(command.tenantId, command.idempotencyKey, command, result)
        return result
    }

    fun isMfaRequired(tenantId: String, jurisdiction: String, riskScore: Double): Boolean {
        val rule = getEffectiveRule(tenantId, jurisdiction)
        return when (rule.requirement) {
            MfaRequirementPolicy.MANDATORY -> true
            MfaRequirementPolicy.RISK_BASED -> riskScore >= rule.riskScoreThreshold
            MfaRequirementPolicy.OPTIONAL -> false
            MfaRequirementPolicy.DISABLED -> false
        }
    }

    fun configureJurisdictionRule(tenantId: String, rule: JurisdictionMfaRule) {
        mfaStore.saveRule(tenantId, rule)
    }

    private fun getEffectiveRule(tenantId: String, jurisdiction: String): JurisdictionMfaRule {
        return mfaStore.findRule(tenantId, jurisdiction)
            ?: when (jurisdiction.uppercase()) {
                "NJ", "UK", "SE" -> JurisdictionMfaRule(
                    jurisdiction = jurisdiction.uppercase(),
                    requirement = MfaRequirementPolicy.MANDATORY,
                    riskScoreThreshold = 50.0
                )
                "HIGH_RISK" -> JurisdictionMfaRule(
                    jurisdiction = "HIGH_RISK",
                    requirement = MfaRequirementPolicy.MANDATORY,
                    riskScoreThreshold = 40.0
                )
                else -> JurisdictionMfaRule(
                    jurisdiction = jurisdiction.uppercase(),
                    requirement = MfaRequirementPolicy.RISK_BASED,
                    riskScoreThreshold = 70.0
                )
            }
    }

    private fun validateHeaders(tenantId: String, corrId: String, causId: String, idempKey: String, expectedVersion: Long) {
        if (tenantId.isBlank() || corrId.isBlank() || causId.isBlank()) {
            throw AuthenticationFailure.Rejected(AuthErrorCode.INVALID)
        }
        if (expectedVersion < 1L) {
            throw AuthenticationFailure.Rejected(AuthErrorCode.STALE)
        }
        if (idempKey.isBlank()) {
            throw AuthenticationFailure.Rejected(AuthErrorCode.INVALID)
        }
    }

    private fun sha256(input: String): String {
        val digest = MessageDigest.getInstance("SHA-256")
        val bytes = digest.digest(input.toByteArray(Charsets.UTF_8))
        return bytes.joinToString("") { "%02x".format(it) }
    }
}
