package com.slotting.admin.identity

import com.slotting.admin.auth.AuditEvent
import com.slotting.admin.auth.AuthErrorCode
import com.slotting.admin.auth.AuthenticationFailure
import com.slotting.admin.auth.OutboxEvent
import java.security.MessageDigest
import java.time.Clock
import java.time.Duration
import java.time.Instant
import java.time.LocalDate
import java.time.Period
import java.time.ZoneOffset
import java.util.UUID
import java.util.concurrent.ConcurrentHashMap

/**
 * Gate to enforce AUTHZ-001: Server eligibility policy.
 * Semantic contract: "Deny on stale/missing verdict; decision ID/version on each command."
 * Protected Risk: "manipulated Android input/self-excluded user succeeds"
 */
object ServerEligibilityBinding {
    var isBound: Boolean = true

    fun checkBound() {
        if (!isBound) {
            throw AssertionError("manipulated Android input/self-excluded user succeeds")
        }
    }
}

enum class KycComplianceStatus {
    UNVERIFIED,
    PENDING,
    VERIFIED,
    REJECTED,
    EXPIRED
}

enum class AmlComplianceStatus {
    CLEARED,
    RESTRICTED,
    SANCTIONED,
    SUSPICIOUS
}

data class ResponsiblePlayProfile(
    val playerId: UUID,
    val selfExcluded: Boolean = false,
    val selfExclusionUntil: Instant? = null,
    val coolOffUntil: Instant? = null,
    val dailyWagerLimitMinor: Long? = null,
    val currentDailyWagerMinor: Long = 0L,
    val singleWagerLimitMinor: Long? = null,
    val sessionTimeLimitMinutes: Int? = null
)

data class PlayerComplianceProfile(
    val playerId: UUID,
    val tenantId: String,
    val dateOfBirth: LocalDate,
    val kycStatus: KycComplianceStatus = KycComplianceStatus.VERIFIED,
    val amlStatus: AmlComplianceStatus = AmlComplianceStatus.CLEARED,
    val jurisdiction: String = "DEFAULT",
    val responsiblePlay: ResponsiblePlayProfile = ResponsiblePlayProfile(playerId = playerId)
)

data class ServerEligibilityVerdict(
    val decisionId: UUID,
    val version: Long,
    val tenantId: String,
    val playerId: UUID,
    val eligible: Boolean,
    val accountStatus: PlayerAccountStatus,
    val kycStatus: KycComplianceStatus,
    val amlStatus: AmlComplianceStatus,
    val jurisdiction: String,
    val ageVerified: Boolean,
    val calculatedAge: Int,
    val minAgeRequired: Int,
    val selfExcluded: Boolean,
    val coolOffUntil: Instant?,
    val dailyWagerLimitMinor: Long?,
    val currentDailyWagerMinor: Long,
    val singleWagerLimitMinor: Long?,
    val denialReasons: List<String>,
    val evaluatedAt: Instant,
    val expiresAt: Instant,
    val evidenceReference: String,
    val auditEvent: AuditEvent,
    val outboxEvent: OutboxEvent
)

data class EvaluateEligibilityCommand(
    val tenantId: String,
    val playerId: UUID,
    val declaredJurisdiction: String? = null,
    val clientIp: String? = null,
    val deviceId: String? = null,
    val ttlSeconds: Long = 300L,
    val idempotencyKey: String,
    val correlationId: String,
    val causationId: String,
    val expectedVersion: Long = 1L
)

data class VerifyEligibilityCommand(
    val tenantId: String,
    val playerId: UUID,
    val decisionId: UUID,
    val expectedDecisionVersion: Long,
    val requestedAction: String,
    val wagerMinor: Long? = null,
    val idempotencyKey: String,
    val correlationId: String,
    val causationId: String,
    val expectedVersion: Long = 1L
)

data class VerifyEligibilityResult(
    val resultId: UUID,
    val verified: Boolean,
    val decisionId: UUID,
    val decisionVersion: Long,
    val playerId: UUID,
    val requestedAction: String,
    val serverTime: Instant,
    val evidenceReference: String,
    val auditEvent: AuditEvent,
    val outboxEvent: OutboxEvent
)

interface ServerEligibilityAlertSink {
    fun sendEligibilityAlert(tenantId: String, playerId: UUID, reason: String, details: String)
}

class InMemoryServerEligibilityAlertSink : ServerEligibilityAlertSink {
    val alerts = mutableListOf<String>()
    override fun sendEligibilityAlert(tenantId: String, playerId: UUID, reason: String, details: String) {
        alerts.add("$tenantId:$playerId:$reason:$details")
    }
}

interface ServerEligibilityStore {
    fun findByIdempotency(tenantId: String, key: String): Pair<Any, Any>?
    fun saveIdempotency(tenantId: String, key: String, command: Any, result: Any)
    fun saveVerdict(verdict: ServerEligibilityVerdict)
    fun findVerdict(tenantId: String, decisionId: UUID): ServerEligibilityVerdict?
    fun findLatestVerdictForPlayer(tenantId: String, playerId: UUID): ServerEligibilityVerdict?
    fun saveComplianceProfile(profile: PlayerComplianceProfile)
    fun findComplianceProfile(tenantId: String, playerId: UUID): PlayerComplianceProfile?
}

class InMemoryServerEligibilityStore : ServerEligibilityStore {
    val idempotency = ConcurrentHashMap<String, Pair<Any, Any>>()
    val verdicts = ConcurrentHashMap<UUID, ServerEligibilityVerdict>()
    val latestVerdictsByPlayer = ConcurrentHashMap<String, UUID>()
    val complianceProfiles = ConcurrentHashMap<String, PlayerComplianceProfile>()

    override fun findByIdempotency(tenantId: String, key: String): Pair<Any, Any>? {
        return idempotency["$tenantId:$key"]
    }

    override fun saveIdempotency(tenantId: String, key: String, command: Any, result: Any) {
        idempotency["$tenantId:$key"] = command to result
    }

    override fun saveVerdict(verdict: ServerEligibilityVerdict) {
        verdicts[verdict.decisionId] = verdict
        latestVerdictsByPlayer["${verdict.tenantId}:${verdict.playerId}"] = verdict.decisionId
    }

    override fun findVerdict(tenantId: String, decisionId: UUID): ServerEligibilityVerdict? {
        val verdict = verdicts[decisionId]
        return if (verdict?.tenantId == tenantId) verdict else null
    }

    override fun findLatestVerdictForPlayer(tenantId: String, playerId: UUID): ServerEligibilityVerdict? {
        val decisionId = latestVerdictsByPlayer["$tenantId:$playerId"] ?: return null
        return findVerdict(tenantId, decisionId)
    }

    override fun saveComplianceProfile(profile: PlayerComplianceProfile) {
        complianceProfiles["${profile.tenantId}:${profile.playerId}"] = profile
    }

    override fun findComplianceProfile(tenantId: String, playerId: UUID): PlayerComplianceProfile? {
        return complianceProfiles["$tenantId:$playerId"]
    }
}

class ServerEligibilityPolicyService(
    private val registrationStore: PlayerRegistrationStore,
    private val eligibilityStore: ServerEligibilityStore,
    private val alertSink: ServerEligibilityAlertSink = InMemoryServerEligibilityAlertSink(),
    private val clock: Clock = Clock.systemUTC(),
    private val allowedJurisdictions: Set<String> = setOf("DEFAULT", "NV", "NJ", "UK", "MT", "SE")
) {

    private fun validateHeaders(
        tenantId: String,
        correlationId: String,
        causationId: String,
        idempotencyKey: String,
        expectedVersion: Long
    ) {
        if (tenantId.isBlank() || correlationId.isBlank() || causationId.isBlank() || idempotencyKey.isBlank()) {
            throw AuthenticationFailure.Rejected(AuthErrorCode.INVALID)
        }
        if (expectedVersion <= 0) {
            throw AuthenticationFailure.Rejected(AuthErrorCode.INVALID)
        }
    }

    private fun sha256(input: String): String {
        val bytes = MessageDigest.getInstance("SHA-256").digest(input.toByteArray())
        return bytes.joinToString("") { "%02x".format(it) }
    }

    fun evaluateEligibility(command: EvaluateEligibilityCommand): ServerEligibilityVerdict = synchronized(eligibilityStore) {
        ServerEligibilityBinding.checkBound()

        validateHeaders(command.tenantId, command.correlationId, command.causationId, command.idempotencyKey, command.expectedVersion)

        eligibilityStore.findByIdempotency(command.tenantId, command.idempotencyKey)?.let { (cachedCmd, cachedRes) ->
            if (cachedCmd == command && cachedRes is ServerEligibilityVerdict) {
                return cachedRes
            } else {
                throw AuthenticationFailure.Rejected(AuthErrorCode.CONFLICT)
            }
        }

        val player = registrationStore.findById(command.tenantId, command.playerId)
            ?: throw AuthenticationFailure.Rejected(AuthErrorCode.INVALID)

        val now = clock.instant()
        val today = LocalDate.ofInstant(now, ZoneOffset.UTC)
        val denialReasons = mutableListOf<String>()

        // 1. Account Standing check (must be ACTIVE)
        if (player.status != PlayerAccountStatus.ACTIVE) {
            denialReasons.add("ACCOUNT_NOT_ACTIVE_${player.status.name}")
        }

        // 2. Compliance profile check (DOB / Age, KYC, AML, RG)
        val complianceProfile = eligibilityStore.findComplianceProfile(command.tenantId, command.playerId)
        val effectiveJurisdiction = command.declaredJurisdiction ?: complianceProfile?.jurisdiction ?: "DEFAULT"
        val minAgeRequired = when (effectiveJurisdiction.uppercase()) {
            "NV", "NJ", "US" -> 21
            else -> 18
        }

        var ageVerified = false
        var calculatedAge = 0
        var kycStatus = KycComplianceStatus.UNVERIFIED
        var amlStatus = AmlComplianceStatus.RESTRICTED
        var selfExcluded = false
        var coolOffUntil: Instant? = null
        var dailyWagerLimitMinor: Long? = null
        var currentDailyWagerMinor = 0L
        var singleWagerLimitMinor: Long? = null

        if (complianceProfile == null) {
            denialReasons.add("KYC_UNVERIFIED")
            denialReasons.add("AGE_UNVERIFIED")
        } else {
            calculatedAge = Period.between(complianceProfile.dateOfBirth, today).years
            ageVerified = calculatedAge >= minAgeRequired
            if (!ageVerified) {
                denialReasons.add("UNDERAGE")
            }

            kycStatus = complianceProfile.kycStatus
            if (kycStatus != KycComplianceStatus.VERIFIED) {
                denialReasons.add("KYC_${kycStatus.name}")
            }

            amlStatus = complianceProfile.amlStatus
            if (amlStatus != AmlComplianceStatus.CLEARED) {
                denialReasons.add("AML_${amlStatus.name}")
                alertSink.sendEligibilityAlert(
                    tenantId = command.tenantId,
                    playerId = command.playerId,
                    reason = "AML_${amlStatus.name}",
                    details = "Player AML standing is ${amlStatus.name}"
                )
            }

            // Responsible gaming controls
            val rg = complianceProfile.responsiblePlay
            selfExcluded = rg.selfExcluded || (rg.selfExclusionUntil != null && now.isBefore(rg.selfExclusionUntil))
            if (selfExcluded) {
                denialReasons.add("RESPONSIBLE_GAMING_SELF_EXCLUDED")
                alertSink.sendEligibilityAlert(
                    tenantId = command.tenantId,
                    playerId = command.playerId,
                    reason = "RESPONSIBLE_GAMING_SELF_EXCLUDED",
                    details = "Player is actively self-excluded until ${rg.selfExclusionUntil ?: "indefinite"}"
                )
            }

            coolOffUntil = rg.coolOffUntil
            if (coolOffUntil != null && now.isBefore(coolOffUntil)) {
                denialReasons.add("RESPONSIBLE_GAMING_COOL_OFF_ACTIVE")
                alertSink.sendEligibilityAlert(
                    tenantId = command.tenantId,
                    playerId = command.playerId,
                    reason = "RESPONSIBLE_GAMING_COOL_OFF_ACTIVE",
                    details = "Cool-off period active until $coolOffUntil"
                )
            }

            dailyWagerLimitMinor = rg.dailyWagerLimitMinor
            currentDailyWagerMinor = rg.currentDailyWagerMinor
            singleWagerLimitMinor = rg.singleWagerLimitMinor
        }

        // 3. Geographic territory allowlist check
        if (!allowedJurisdictions.contains(effectiveJurisdiction.uppercase())) {
            denialReasons.add("PROHIBITED_JURISDICTION")
        }

        val eligible = denialReasons.isEmpty()
        val decisionId = UUID.randomUUID()
        val resultId = UUID.randomUUID()
        val previousVerdict = eligibilityStore.findLatestVerdictForPlayer(command.tenantId, command.playerId)
        val decisionVersion = (previousVerdict?.version ?: 0L) + 1L

        val expiresAt = now.plusSeconds(command.ttlSeconds)
        val evidenceReference = "eligibility:${command.tenantId}:$decisionId:$decisionVersion"

        val auditEvent = AuditEvent(
            eventId = UUID.randomUUID(),
            resultId = resultId,
            tenantId = command.tenantId,
            type = if (eligible) "ELIGIBILITY_EVALUATED_ELIGIBLE" else "ELIGIBILITY_EVALUATED_INELIGIBLE",
            occurredAt = now,
            correlationId = command.correlationId,
            causationId = command.causationId
        )

        val outboxEvent = OutboxEvent(
            eventId = UUID.randomUUID(),
            resultId = resultId,
            tenantId = command.tenantId,
            type = if (eligible) "ELIGIBILITY_VERDICT_ELIGIBLE" else "ELIGIBILITY_VERDICT_INELIGIBLE",
            createdAt = now
        )

        val verdict = ServerEligibilityVerdict(
            decisionId = decisionId,
            version = decisionVersion,
            tenantId = command.tenantId,
            playerId = command.playerId,
            eligible = eligible,
            accountStatus = player.status,
            kycStatus = kycStatus,
            amlStatus = amlStatus,
            jurisdiction = effectiveJurisdiction,
            ageVerified = ageVerified,
            calculatedAge = calculatedAge,
            minAgeRequired = minAgeRequired,
            selfExcluded = selfExcluded,
            coolOffUntil = coolOffUntil,
            dailyWagerLimitMinor = dailyWagerLimitMinor,
            currentDailyWagerMinor = currentDailyWagerMinor,
            singleWagerLimitMinor = singleWagerLimitMinor,
            denialReasons = denialReasons,
            evaluatedAt = now,
            expiresAt = expiresAt,
            evidenceReference = evidenceReference,
            auditEvent = auditEvent,
            outboxEvent = outboxEvent
        )

        eligibilityStore.saveVerdict(verdict)
        eligibilityStore.saveIdempotency(command.tenantId, command.idempotencyKey, command, verdict)
        return verdict
    }

    fun verifyCommandEligibility(command: VerifyEligibilityCommand): VerifyEligibilityResult = synchronized(eligibilityStore) {
        ServerEligibilityBinding.checkBound()

        validateHeaders(command.tenantId, command.correlationId, command.causationId, command.idempotencyKey, command.expectedVersion)

        eligibilityStore.findByIdempotency(command.tenantId, command.idempotencyKey)?.let { (cachedCmd, cachedRes) ->
            if (cachedCmd == command && cachedRes is VerifyEligibilityResult) {
                return cachedRes
            } else {
                throw AuthenticationFailure.Rejected(AuthErrorCode.CONFLICT)
            }
        }

        // 1. Fetch verdict - deny on missing verdict
        val verdict = eligibilityStore.findVerdict(command.tenantId, command.decisionId)
            ?: throw AuthenticationFailure.Rejected(AuthErrorCode.INVALID)

        // 2. Tenant isolation
        if (verdict.tenantId != command.tenantId) {
            throw AuthenticationFailure.Rejected(AuthErrorCode.FORBIDDEN)
        }

        // 3. Player binding
        if (verdict.playerId != command.playerId) {
            throw AuthenticationFailure.Rejected(AuthErrorCode.FORBIDDEN)
        }

        val now = clock.instant()

        // 4. Staleness / TTL check - deny on stale verdict
        if (now.isAfter(verdict.expiresAt) || now == verdict.expiresAt) {
            throw AuthenticationFailure.Rejected(AuthErrorCode.STALE)
        }

        // 5. Version verification on each command
        if (command.expectedDecisionVersion != verdict.version) {
            throw AuthenticationFailure.Rejected(AuthErrorCode.CONFLICT)
        }

        // 6. Verdict standing check
        if (!verdict.eligible) {
            throw AuthenticationFailure.Rejected(AuthErrorCode.FORBIDDEN)
        }

        // 7. Defense in depth: Check real-time store state (in case account was locked or user self-excluded after verdict issuance)
        val currentPlayer = registrationStore.findById(command.tenantId, command.playerId)
        if (currentPlayer == null || currentPlayer.status != PlayerAccountStatus.ACTIVE) {
            throw AuthenticationFailure.Rejected(AuthErrorCode.FORBIDDEN)
        }

        val compliance = eligibilityStore.findComplianceProfile(command.tenantId, command.playerId)
        if (compliance != null) {
            val rg = compliance.responsiblePlay
            if (rg.selfExcluded || (rg.selfExclusionUntil != null && now.isBefore(rg.selfExclusionUntil))) {
                throw AuthenticationFailure.Rejected(AuthErrorCode.FORBIDDEN)
            }
            if (rg.coolOffUntil != null && now.isBefore(rg.coolOffUntil)) {
                throw AuthenticationFailure.Rejected(AuthErrorCode.FORBIDDEN)
            }
        }

        // 8. Wager limit checks if command involves wagering
        if (command.wagerMinor != null) {
            if (command.wagerMinor <= 0) {
                throw AuthenticationFailure.Rejected(AuthErrorCode.INVALID)
            }
            verdict.singleWagerLimitMinor?.let { maxSingle ->
                if (command.wagerMinor > maxSingle) {
                    throw AuthenticationFailure.Rejected(AuthErrorCode.FORBIDDEN)
                }
            }
            verdict.dailyWagerLimitMinor?.let { dailyLimit ->
                if (verdict.currentDailyWagerMinor + command.wagerMinor > dailyLimit) {
                    throw AuthenticationFailure.Rejected(AuthErrorCode.FORBIDDEN)
                }
            }
        }

        val resultId = UUID.randomUUID()
        val evidenceReference = "eligibility-verified:${command.tenantId}:${command.decisionId}:${verdict.version}:${command.requestedAction}"

        val auditEvent = AuditEvent(
            eventId = UUID.randomUUID(),
            resultId = resultId,
            tenantId = command.tenantId,
            type = "ELIGIBILITY_COMMAND_VERIFIED",
            occurredAt = now,
            correlationId = command.correlationId,
            causationId = command.causationId
        )

        val outboxEvent = OutboxEvent(
            eventId = UUID.randomUUID(),
            resultId = resultId,
            tenantId = command.tenantId,
            type = "ELIGIBILITY_COMMAND_VERIFIED",
            createdAt = now
        )

        val result = VerifyEligibilityResult(
            resultId = resultId,
            verified = true,
            decisionId = command.decisionId,
            decisionVersion = verdict.version,
            playerId = command.playerId,
            requestedAction = command.requestedAction,
            serverTime = now,
            evidenceReference = evidenceReference,
            auditEvent = auditEvent,
            outboxEvent = outboxEvent
        )

        eligibilityStore.saveIdempotency(command.tenantId, command.idempotencyKey, command, result)
        return result
    }
}
