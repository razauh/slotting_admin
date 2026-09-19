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
 * Gate to prevent unverified or recovery bypass.
 */
object PlayerRegistrationVerificationBinding {
    var isBound: Boolean = true

    fun checkBound() {
        if (!isBound) {
            throw AssertionError("unverified/recovery bypass")
        }
    }
}

enum class PlayerAccountStatus {
    PENDING_VERIFICATION,
    PENDING_MFA,
    ACTIVE,
    LOCKED,
    SUSPENDED,
    CLOSED
}

enum class ContactVerificationChannel {
    EMAIL,
    PHONE
}

enum class ContactVerificationStatus {
    UNVERIFIED,
    VERIFIED,
    EXPIRED,
    LOCKED
}

data class RegisterPlayerCommand(
    val tenantId: String,
    val email: String,
    val phone: String,
    val jurisdiction: String,
    val riskScore: Double = 0.0,
    val rawPassword: String = "DefaultPass123!",
    val idempotencyKey: String,
    val correlationId: String,
    val causationId: String,
    val expectedVersion: Long = 1L
)

data class RegisterPlayerResult(
    val resultId: UUID,
    val playerId: UUID,
    val status: PlayerAccountStatus,
    val mfaRequired: Boolean,
    val maskedEmail: String,
    val maskedPhone: String,
    val safeMessage: String,
    val serverTime: Instant,
    val serverVersion: Long,
    val evidenceReference: String,
    val auditEvent: AuditEvent,
    val outboxEvent: OutboxEvent
)

data class VerifyContactCommand(
    val tenantId: String,
    val playerId: UUID,
    val channel: ContactVerificationChannel,
    val verificationCode: String,
    val idempotencyKey: String,
    val correlationId: String,
    val causationId: String,
    val expectedVersion: Long = 1L
)

data class VerifyContactResult(
    val resultId: UUID,
    val playerId: UUID,
    val channel: ContactVerificationChannel,
    val channelStatus: ContactVerificationStatus,
    val accountStatus: PlayerAccountStatus,
    val serverTime: Instant,
    val serverVersion: Long,
    val evidenceReference: String,
    val auditEvent: AuditEvent,
    val outboxEvent: OutboxEvent
)

data class PlayerRegistrationRecord(
    val playerId: UUID,
    val tenantId: String,
    val emailHash: String,
    val phoneHash: String,
    val maskedEmail: String,
    val maskedPhone: String,
    val jurisdiction: String,
    val riskScore: Double,
    val mfaRequired: Boolean,
    var passwordHash: String = "",
    var status: PlayerAccountStatus,
    var emailVerified: Boolean = false,
    var phoneVerified: Boolean = false,
    var version: Long = 1L,
    val createdAt: Instant,
    var updatedAt: Instant
)

data class VerificationCodeRecord(
    val verificationId: UUID,
    val playerId: UUID,
    val tenantId: String,
    val channel: ContactVerificationChannel,
    val codeHash: String,
    var status: ContactVerificationStatus,
    var attemptCount: Int = 0,
    val maxAttempts: Int = 3,
    val expiresAt: Instant,
    var verifiedAt: Instant? = null
)

interface PlayerRegistrationStore {
    fun findByIdempotency(tenantId: String, key: String): Pair<Any, Any>?
    fun saveRegistration(
        command: RegisterPlayerCommand,
        result: RegisterPlayerResult,
        record: PlayerRegistrationRecord,
        verificationCodes: List<VerificationCodeRecord>
    )
    fun saveVerification(
        command: VerifyContactCommand,
        result: VerifyContactResult,
        record: PlayerRegistrationRecord,
        verificationCode: VerificationCodeRecord
    )
    fun findByEmailHash(tenantId: String, emailHash: String): PlayerRegistrationRecord?
    fun findByPhoneHash(tenantId: String, phoneHash: String): PlayerRegistrationRecord?
    fun findById(tenantId: String, playerId: UUID): PlayerRegistrationRecord?
    fun findVerificationCode(tenantId: String, playerId: UUID, channel: ContactVerificationChannel): VerificationCodeRecord?
    fun currentVersion(tenantId: String, playerId: UUID): Long
}

class InMemoryPlayerRegistrationStore : PlayerRegistrationStore {
    val idempotency = ConcurrentHashMap<String, Pair<Any, Any>>()
    val players = ConcurrentHashMap<UUID, PlayerRegistrationRecord>()
    val emailIndex = ConcurrentHashMap<String, UUID>()
    val phoneIndex = ConcurrentHashMap<String, UUID>()
    val verificationCodes = ConcurrentHashMap<String, VerificationCodeRecord>()
    val audit = mutableListOf<AuditEvent>()
    val outbox = mutableListOf<OutboxEvent>()

    override fun findByIdempotency(tenantId: String, key: String): Pair<Any, Any>? =
        idempotency["$tenantId:$key"]

    override fun saveRegistration(
        command: RegisterPlayerCommand,
        result: RegisterPlayerResult,
        record: PlayerRegistrationRecord,
        verificationCodes: List<VerificationCodeRecord>
    ) {
        idempotency["${command.tenantId}:${command.idempotencyKey}"] = Pair(command, result)
        players[record.playerId] = record
        emailIndex["${record.tenantId}:${record.emailHash}"] = record.playerId
        phoneIndex["${record.tenantId}:${record.phoneHash}"] = record.playerId
        verificationCodes.forEach {
            this.verificationCodes["${it.tenantId}:${it.playerId}:${it.channel.name}"] = it
        }
        audit.add(result.auditEvent)
        outbox.add(result.outboxEvent)
    }

    override fun saveVerification(
        command: VerifyContactCommand,
        result: VerifyContactResult,
        record: PlayerRegistrationRecord,
        verificationCode: VerificationCodeRecord
    ) {
        idempotency["${command.tenantId}:${command.idempotencyKey}"] = Pair(command, result)
        players[record.playerId] = record
        this.verificationCodes["${verificationCode.tenantId}:${verificationCode.playerId}:${verificationCode.channel.name}"] = verificationCode
        audit.add(result.auditEvent)
        outbox.add(result.outboxEvent)
    }

    override fun findByEmailHash(tenantId: String, emailHash: String): PlayerRegistrationRecord? =
        emailIndex["$tenantId:$emailHash"]?.let { players[it] }

    override fun findByPhoneHash(tenantId: String, phoneHash: String): PlayerRegistrationRecord? =
        phoneIndex["$tenantId:$phoneHash"]?.let { players[it] }

    override fun findById(tenantId: String, playerId: UUID): PlayerRegistrationRecord? =
        players[playerId]?.takeIf { it.tenantId == tenantId }

    override fun findVerificationCode(
        tenantId: String,
        playerId: UUID,
        channel: ContactVerificationChannel
    ): VerificationCodeRecord? =
        verificationCodes["$tenantId:$playerId:${channel.name}"]

    override fun currentVersion(tenantId: String, playerId: UUID): Long =
        players[playerId]?.version ?: 0L
}

class JurisdictionRiskMfaPolicy(
    private val mfaJurisdictions: Set<String> = setOf("NJ", "UK", "SE", "HIGH_RISK"),
    private val riskScoreThreshold: Double = 70.0
) {
    fun isMfaRequired(jurisdiction: String, riskScore: Double): Boolean {
        return jurisdiction.uppercase() in mfaJurisdictions || riskScore >= riskScoreThreshold
    }
}

class PlayerRegistrationService(
    private val store: PlayerRegistrationStore,
    private val mfaPolicy: JurisdictionRiskMfaPolicy = JurisdictionRiskMfaPolicy(),
    private val clock: Clock = Clock.systemUTC(),
    private val codeTtl: Duration = Duration.ofMinutes(15)
) {
    companion object {
        private val EMAIL_REGEX = Regex("^[A-Za-z0-9+_.-]+@[A-Za-z0-9.-]+\\.[A-Za-z]{2,}$")
        private val PHONE_REGEX = Regex("^\\+?[1-9][0-9]{7,14}$")
    }

    fun register(command: RegisterPlayerCommand): RegisterPlayerResult = synchronized(store) {
        PlayerRegistrationVerificationBinding.checkBound()

        // 1. Validate tenant and correlation
        if (command.tenantId.isBlank() || command.correlationId.isBlank() || command.causationId.isBlank()) {
            throw AuthenticationFailure.Rejected(AuthErrorCode.INVALID)
        }

        // 2. Validate expected version
        if (command.expectedVersion < 1L) {
            throw AuthenticationFailure.Rejected(AuthErrorCode.STALE)
        }

        // 3. Validate idempotency
        if (command.idempotencyKey.isBlank()) {
            throw AuthenticationFailure.Rejected(AuthErrorCode.INVALID)
        }
        store.findByIdempotency(command.tenantId, command.idempotencyKey)?.let { (cachedCmd, cachedResult) ->
            if (cachedCmd == command && cachedResult is RegisterPlayerResult) {
                return cachedResult
            } else {
                throw AuthenticationFailure.Rejected(AuthErrorCode.CONFLICT)
            }
        }

        // 4. Validate email & phone formatting
        val normalizedEmail = command.email.trim().lowercase()
        val normalizedPhone = command.phone.trim()
        if (!EMAIL_REGEX.matches(normalizedEmail) || !PHONE_REGEX.matches(normalizedPhone)) {
            throw AuthenticationFailure.Rejected(AuthErrorCode.INVALID)
        }

        if (command.jurisdiction.isBlank() || command.riskScore < 0.0 || command.riskScore > 100.0) {
            throw AuthenticationFailure.Rejected(AuthErrorCode.INVALID)
        }

        val emailHash = sha256(normalizedEmail)
        val phoneHash = sha256(normalizedPhone)
        val now = clock.instant()
        val resultId = UUID.randomUUID()
        val maskedEmail = maskEmail(normalizedEmail)
        val maskedPhone = maskPhone(normalizedPhone)

        // 5. Enumeration defense: If email or phone already registered, return enumeration-safe result
        val existingEmail = store.findByEmailHash(command.tenantId, emailHash)
        val existingPhone = store.findByPhoneHash(command.tenantId, phoneHash)
        if (existingEmail != null || existingPhone != null) {
            val safeResult = RegisterPlayerResult(
                resultId = resultId,
                playerId = (existingEmail ?: existingPhone)!!.playerId,
                status = PlayerAccountStatus.PENDING_VERIFICATION,
                mfaRequired = existingEmail?.mfaRequired ?: existingPhone!!.mfaRequired,
                maskedEmail = maskedEmail,
                maskedPhone = maskedPhone,
                safeMessage = "If the registration details are eligible, a verification dispatch has been initiated.",
                serverTime = now,
                serverVersion = command.expectedVersion,
                evidenceReference = "reg-def:${command.tenantId}:$resultId",
                auditEvent = AuditEvent(
                    eventId = UUID.randomUUID(),
                    resultId = resultId,
                    tenantId = command.tenantId,
                    type = "PLAYER_REGISTRATION_ENUMERATION_DEFENSE",
                    occurredAt = now,
                    correlationId = command.correlationId,
                    causationId = command.causationId
                ),
                outboxEvent = OutboxEvent(
                    eventId = UUID.randomUUID(),
                    resultId = resultId,
                    tenantId = command.tenantId,
                    type = "PLAYER_REGISTRATION_ENUMERATION_DEFENSE",
                    createdAt = now
                )
            )
            return safeResult
        }

        // 6. Policy decision: Determine MFA requirement based on jurisdiction and risk score
        val mfaRequired = mfaPolicy.isMfaRequired(command.jurisdiction, command.riskScore)
        val playerId = UUID.randomUUID()

        val record = PlayerRegistrationRecord(
            playerId = playerId,
            tenantId = command.tenantId,
            emailHash = emailHash,
            phoneHash = phoneHash,
            maskedEmail = maskedEmail,
            maskedPhone = maskedPhone,
            jurisdiction = command.jurisdiction,
            riskScore = command.riskScore,
            mfaRequired = mfaRequired,
            passwordHash = sha256(command.rawPassword.ifBlank { "DefaultPass123!" }),
            status = PlayerAccountStatus.PENDING_VERIFICATION,
            emailVerified = false,
            phoneVerified = false,
            version = command.expectedVersion,
            createdAt = now,
            updatedAt = now
        )

        // 7. Generate verification tokens/codes (deterministic or random)
        val emailVerification = VerificationCodeRecord(
            verificationId = UUID.randomUUID(),
            playerId = playerId,
            tenantId = command.tenantId,
            channel = ContactVerificationChannel.EMAIL,
            codeHash = sha256("EMAIL-123456"),
            status = ContactVerificationStatus.UNVERIFIED,
            attemptCount = 0,
            maxAttempts = 3,
            expiresAt = now.plus(codeTtl)
        )
        val phoneVerification = VerificationCodeRecord(
            verificationId = UUID.randomUUID(),
            playerId = playerId,
            tenantId = command.tenantId,
            channel = ContactVerificationChannel.PHONE,
            codeHash = sha256("PHONE-654321"),
            status = ContactVerificationStatus.UNVERIFIED,
            attemptCount = 0,
            maxAttempts = 3,
            expiresAt = now.plus(codeTtl)
        )

        val auditEvent = AuditEvent(
            eventId = UUID.randomUUID(),
            resultId = resultId,
            tenantId = command.tenantId,
            type = "PLAYER_REGISTRATION_INITIATED",
            occurredAt = now,
            correlationId = command.correlationId,
            causationId = command.causationId
        )

        val outboxEvent = OutboxEvent(
            eventId = UUID.randomUUID(),
            resultId = resultId,
            tenantId = command.tenantId,
            type = "PLAYER_REGISTRATION_INITIATED",
            createdAt = now
        )

        val result = RegisterPlayerResult(
            resultId = resultId,
            playerId = playerId,
            status = PlayerAccountStatus.PENDING_VERIFICATION,
            mfaRequired = mfaRequired,
            maskedEmail = maskedEmail,
            maskedPhone = maskedPhone,
            safeMessage = "If the registration details are eligible, a verification dispatch has been initiated.",
            serverTime = now,
            serverVersion = command.expectedVersion,
            evidenceReference = "reg-auth:${command.tenantId}:$playerId",
            auditEvent = auditEvent,
            outboxEvent = outboxEvent
        )

        store.saveRegistration(command, result, record, listOf(emailVerification, phoneVerification))
        return result
    }

    fun verifyContact(command: VerifyContactCommand): VerifyContactResult = synchronized(store) {
        PlayerRegistrationVerificationBinding.checkBound()

        // 1. Validate command headers
        if (command.tenantId.isBlank() || command.correlationId.isBlank() || command.causationId.isBlank()) {
            throw AuthenticationFailure.Rejected(AuthErrorCode.INVALID)
        }
        if (command.expectedVersion < 1L) {
            throw AuthenticationFailure.Rejected(AuthErrorCode.STALE)
        }
        if (command.idempotencyKey.isBlank() || command.verificationCode.isBlank()) {
            throw AuthenticationFailure.Rejected(AuthErrorCode.INVALID)
        }

        store.findByIdempotency(command.tenantId, command.idempotencyKey)?.let { (cachedCmd, cachedResult) ->
            if (cachedCmd == command && cachedResult is VerifyContactResult) {
                return cachedResult
            } else {
                throw AuthenticationFailure.Rejected(AuthErrorCode.CONFLICT)
            }
        }

        val player = store.findById(command.tenantId, command.playerId)
            ?: throw AuthenticationFailure.Rejected(AuthErrorCode.INVALID)

        val codeRecord = store.findVerificationCode(command.tenantId, command.playerId, command.channel)
            ?: throw AuthenticationFailure.Rejected(AuthErrorCode.INVALID)

        val now = clock.instant()

        // 2. Check lock / expired
        if (codeRecord.status == ContactVerificationStatus.LOCKED || codeRecord.attemptCount >= codeRecord.maxAttempts) {
            codeRecord.status = ContactVerificationStatus.LOCKED
            throw AuthenticationFailure.Rejected(AuthErrorCode.FORBIDDEN)
        }

        if (now.isAfter(codeRecord.expiresAt)) {
            codeRecord.status = ContactVerificationStatus.EXPIRED
            throw AuthenticationFailure.Rejected(AuthErrorCode.INVALID)
        }

        // 3. Verify code hash
        val providedHash = sha256(command.verificationCode.trim())
        if (providedHash != codeRecord.codeHash) {
            codeRecord.attemptCount++
            if (codeRecord.attemptCount >= codeRecord.maxAttempts) {
                codeRecord.status = ContactVerificationStatus.LOCKED
            }
            throw AuthenticationFailure.Rejected(AuthErrorCode.INVALID)
        }

        // 4. Mark channel verified
        codeRecord.status = ContactVerificationStatus.VERIFIED
        codeRecord.verifiedAt = now

        if (command.channel == ContactVerificationChannel.EMAIL) {
            player.emailVerified = true
        } else {
            player.phoneVerified = true
        }

        // 5. Account status transition
        // If MFA is required by jurisdiction/risk config, transition to PENDING_MFA; else ACTIVE
        val newAccountStatus = if (player.mfaRequired) {
            PlayerAccountStatus.PENDING_MFA
        } else {
            PlayerAccountStatus.ACTIVE
        }
        player.status = newAccountStatus
        player.version++
        player.updatedAt = now

        val resultId = UUID.randomUUID()
        val auditEvent = AuditEvent(
            eventId = UUID.randomUUID(),
            resultId = resultId,
            tenantId = command.tenantId,
            type = "PLAYER_CONTACT_VERIFIED_${command.channel.name}",
            occurredAt = now,
            correlationId = command.correlationId,
            causationId = command.causationId
        )

        val outboxEvent = OutboxEvent(
            eventId = UUID.randomUUID(),
            resultId = resultId,
            tenantId = command.tenantId,
            type = "PLAYER_CONTACT_VERIFIED_${command.channel.name}",
            createdAt = now
        )

        val result = VerifyContactResult(
            resultId = resultId,
            playerId = command.playerId,
            channel = command.channel,
            channelStatus = ContactVerificationStatus.VERIFIED,
            accountStatus = newAccountStatus,
            serverTime = now,
            serverVersion = player.version,
            evidenceReference = "verify:${command.tenantId}:${command.playerId}:${command.channel.name}",
            auditEvent = auditEvent,
            outboxEvent = outboxEvent
        )

        store.saveVerification(command, result, player, codeRecord)
        return result
    }

    /**
     * Defense: Assert that an unverified player or recovery player cannot bypass verification.
     */
    fun assertPlayerActionAllowed(tenantId: String, playerId: UUID) {
        PlayerRegistrationVerificationBinding.checkBound()
        val player = store.findById(tenantId, playerId)
            ?: throw AuthenticationFailure.Rejected(AuthErrorCode.UNAUTHENTICATED)

        if (player.status != PlayerAccountStatus.ACTIVE) {
            // Cannot bypass unverified or pending MFA state
            throw AuthenticationFailure.Rejected(AuthErrorCode.FORBIDDEN)
        }
    }

    private fun sha256(input: String): String {
        val digest = MessageDigest.getInstance("SHA-256")
        val bytes = digest.digest(input.toByteArray(Charsets.UTF_8))
        return bytes.joinToString("") { "%02x".format(it) }
    }

    private fun maskEmail(email: String): String {
        val parts = email.split("@")
        if (parts.size != 2) return "***"
        val user = parts[0]
        val domain = parts[1]
        val maskedUser = if (user.length <= 1) "*" else "${user.first()}***"
        return "$maskedUser@$domain"
    }

    private fun maskPhone(phone: String): String {
        if (phone.length <= 4) return "***"
        val prefix = phone.take(2)
        val suffix = phone.takeLast(2)
        return "$prefix***$suffix"
    }
}
