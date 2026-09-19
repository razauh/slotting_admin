package com.slotting.admin.gameprovider

import com.slotting.admin.auth.*
import java.security.MessageDigest
import java.security.SecureRandom
import java.time.Clock
import java.time.Instant
import java.util.Base64
import java.util.UUID

/**
 * Fail-closed verification gate for GAME-002-02.
 * Throws expected RED failure until contract bindings and invariant protections are verified.
 */
object OperatorJurisdictionEnablementBinding {
    @Volatile
    var isBound: Boolean = false

    fun checkBound() {
        if (!isBound) {
            throw AssertionError("disabled/unlicensed game launches")
        }
    }
}

enum class JurisdictionComplianceStatus {
    ACTIVE,
    SUSPENDED,
    REVOKED,
    EXPIRED,
}

data class JurisdictionCompliancePolicy(
    val policyId: UUID,
    val tenantId: String,
    val jurisdictionCode: String,
    val status: JurisdictionComplianceStatus,
    val allowedGameTypes: Set<CasinoProviderType>,
    val maxBetLimitMinorUnits: Long? = null,
    val rtpFloorPercent: Double? = null,
    val restrictedGameIds: Set<String> = emptySet(),
    val whitelistedGameIds: Set<String>? = null,
    val effectiveFrom: Instant,
    val effectiveUntil: Instant,
    val complianceSigner: String,
    val evidenceReference: String,
    val version: Long = 1L,
)

data class ConfigureJurisdictionPolicyCommand(
    val principal: AuthenticatedPrincipal?,
    val sessionId: String,
    val tenantId: String,
    val jurisdictionCode: String,
    val status: JurisdictionComplianceStatus,
    val allowedGameTypes: Set<CasinoProviderType>,
    val maxBetLimitMinorUnits: Long? = null,
    val rtpFloorPercent: Double? = null,
    val restrictedGameIds: Set<String> = emptySet(),
    val whitelistedGameIds: Set<String>? = null,
    val effectiveFrom: Instant,
    val effectiveUntil: Instant,
    val complianceSigner: String,
    val idempotencyKey: String,
    val correlationId: String,
    val causationId: String,
    val expectedVersion: Long = 1L,
)

data class RevokeJurisdictionPolicyCommand(
    val principal: AuthenticatedPrincipal?,
    val sessionId: String,
    val tenantId: String,
    val jurisdictionCode: String,
    val reason: String,
    val idempotencyKey: String,
    val correlationId: String,
    val causationId: String,
    val expectedVersion: Long,
)

data class EnforceOperatorGameEnablementCommand(
    val principal: AuthenticatedPrincipal?,
    val sessionId: String,
    val tenantId: String,
    val providerId: String,
    val gameId: String,
    val newStatus: GameEnablementStatus,
    val reason: String,
    val idempotencyKey: String,
    val correlationId: String,
    val causationId: String,
    val expectedVersion: Long,
)

data class EvaluateGameLaunchEligibilityCommand(
    val tenantId: String,
    val providerId: String,
    val gameId: String,
    val playerId: String,
    val jurisdictionCode: String,
    val requestedBetMinorUnits: Long,
    val currencyCode: String,
)

data class AuthorizeAuthoritativeGameLaunchCommand(
    val tenantId: String,
    val providerId: String,
    val gameId: String,
    val playerId: String,
    val jurisdictionCode: String,
    val requestedBetMinorUnits: Long,
    val currencyCode: String,
    val idempotencyKey: String,
    val correlationId: String,
    val causationId: String,
    val expectedVersion: Long = 1L,
)

data class JurisdictionPolicyResult(
    val resultId: UUID,
    val policyId: UUID,
    val tenantId: String,
    val jurisdictionCode: String,
    val status: JurisdictionComplianceStatus,
    val serverTime: Instant,
    val evidenceReference: String,
)

data class OperatorEnablementResult(
    val resultId: UUID,
    val tenantId: String,
    val providerId: String,
    val gameId: String,
    val previousStatus: GameEnablementStatus,
    val newStatus: GameEnablementStatus,
    val serverTime: Instant,
    val evidenceReference: String,
)

data class GameLaunchEligibilityResult(
    val eligible: Boolean,
    val rejectionReasonCode: AuthErrorCode?,
    val rejectionDetail: String?,
    val gameId: String,
    val jurisdictionCode: String,
    val staleSyncDetected: Boolean,
    val unlicensedDetected: Boolean,
    val disabledDetected: Boolean,
)

data class AuthoritativeGameLaunchResult(
    val resultId: UUID,
    val tenantId: String,
    val providerId: String,
    val gameId: String,
    val playerId: String,
    val jurisdictionCode: String,
    val authorized: Boolean,
    val launchToken: String?,
    val serverTime: Instant,
    val evidenceReference: String,
)

interface OperatorJurisdictionEnablementStore {
    fun findPolicy(tenantId: String, jurisdictionCode: String): JurisdictionCompliancePolicy?
    fun savePolicy(
        policy: JurisdictionCompliancePolicy,
        result: JurisdictionPolicyResult,
        tenantId: String,
        idempotencyKey: String,
        fingerprint: String,
        audit: AuditEvent,
        outbox: OutboxEvent,
    )
    fun findPolicyByIdempotency(tenantId: String, idempotencyKey: String): Pair<String, JurisdictionPolicyResult>?
    fun findEnablementByIdempotency(tenantId: String, idempotencyKey: String): Pair<String, OperatorEnablementResult>?
    fun saveEnablement(
        result: OperatorEnablementResult,
        tenantId: String,
        idempotencyKey: String,
        fingerprint: String,
        audit: AuditEvent,
        outbox: OutboxEvent,
    )
    fun findLaunchByIdempotency(tenantId: String, idempotencyKey: String): Pair<String, AuthoritativeGameLaunchResult>?
    fun saveLaunch(
        result: AuthoritativeGameLaunchResult,
        tenantId: String,
        idempotencyKey: String,
        fingerprint: String,
        audit: AuditEvent,
        outbox: OutboxEvent,
    )
}

class OperatorJurisdictionEnablementService(
    private val policy: AdminRbacPolicy,
    private val sessions: AdminSessionDirectory,
    private val catalogStore: AuthoritativeCatalogStore,
    private val store: OperatorJurisdictionEnablementStore,
    private val clock: Clock = Clock.systemUTC(),
) {
    private val secureRandom = SecureRandom()

    @Synchronized
    fun configureJurisdictionPolicy(command: ConfigureJurisdictionPolicyCommand): JurisdictionPolicyResult {
        OperatorJurisdictionEnablementBinding.checkBound()

        // 1. Validation
        if (command.jurisdictionCode.isBlank() ||
            command.sessionId.isBlank() ||
            command.correlationId.isBlank() ||
            command.causationId.isBlank() ||
            command.complianceSigner.isBlank() ||
            command.allowedGameTypes.isEmpty() ||
            command.effectiveUntil.isBefore(command.effectiveFrom)
        ) {
            throw AuthenticationFailure.Rejected(AuthErrorCode.INVALID)
        }

        if (command.rtpFloorPercent != null && (command.rtpFloorPercent <= 0.0 || command.rtpFloorPercent > 100.0)) {
            throw AuthenticationFailure.Rejected(AuthErrorCode.INVALID)
        }

        if (command.maxBetLimitMinorUnits != null && command.maxBetLimitMinorUnits <= 0) {
            throw AuthenticationFailure.Rejected(AuthErrorCode.INVALID)
        }

        // 2. Tenancy & Principal Check
        val principal = command.principal ?: throw AuthenticationFailure.Rejected(AuthErrorCode.UNAUTHENTICATED)
        if (principal.kind != PrincipalKind.ADMIN || principal.tenantId != command.tenantId) {
            throw AuthenticationFailure.Rejected(AuthErrorCode.FORBIDDEN)
        }

        // 3. Idempotency Check
        val fp = fingerprintPolicy(command)
        store.findPolicyByIdempotency(command.tenantId, command.idempotencyKey)?.let { (cachedFp, cachedResult) ->
            if (cachedFp != fp) throw AuthenticationFailure.Rejected(AuthErrorCode.CONFLICT)
            return cachedResult
        }

        // 4. Session Check
        val session = try {
            sessions.find(command.tenantId, principal.id, command.sessionId)
        } catch (_: Exception) {
            throw AuthenticationFailure.Rejected(AuthErrorCode.DEPENDENCY_UNAVAILABLE)
        } ?: throw AuthenticationFailure.Rejected(AuthErrorCode.FORBIDDEN)

        if (!session.active || session.expiresAt.isBefore(clock.instant())) {
            throw AuthenticationFailure.Rejected(AuthErrorCode.FORBIDDEN)
        }

        if (!policy.isPermitted(principal, AdminPermission.MANAGE_SECURITY) &&
            !policy.isPermitted(principal, AdminPermission.MANAGE_SUPPORT)
        ) {
            throw AuthenticationFailure.Rejected(AuthErrorCode.FORBIDDEN)
        }

        // 5. Version Check
        val existing = store.findPolicy(command.tenantId, command.jurisdictionCode)
        val targetVersion = if (existing != null) existing.version + 1L else 1L
        if (command.expectedVersion != targetVersion) {
            throw AuthenticationFailure.Rejected(AuthErrorCode.STALE)
        }

        val now = clock.instant()
        val policyId = existing?.policyId ?: UUID.randomUUID()
        val evidenceRef = "EVID-JURISDICTION-POLICY-${command.tenantId}-${command.jurisdictionCode}-v$targetVersion"

        val compliancePolicy = JurisdictionCompliancePolicy(
            policyId = policyId,
            tenantId = command.tenantId,
            jurisdictionCode = command.jurisdictionCode,
            status = command.status,
            allowedGameTypes = command.allowedGameTypes,
            maxBetLimitMinorUnits = command.maxBetLimitMinorUnits,
            rtpFloorPercent = command.rtpFloorPercent,
            restrictedGameIds = command.restrictedGameIds,
            whitelistedGameIds = command.whitelistedGameIds,
            effectiveFrom = command.effectiveFrom,
            effectiveUntil = command.effectiveUntil,
            complianceSigner = command.complianceSigner,
            evidenceReference = evidenceRef,
            version = targetVersion,
        )

        val resultId = UUID.randomUUID()
        val result = JurisdictionPolicyResult(
            resultId = resultId,
            policyId = policyId,
            tenantId = command.tenantId,
            jurisdictionCode = command.jurisdictionCode,
            status = command.status,
            serverTime = now,
            evidenceReference = evidenceRef,
        )

        val audit = AuditEvent(
            eventId = UUID.randomUUID(),
            resultId = resultId,
            tenantId = command.tenantId,
            type = "JURISDICTION_POLICY_CONFIGURED",
            occurredAt = now,
            correlationId = command.correlationId,
            causationId = command.causationId,
        )

        val outbox = OutboxEvent(
            eventId = UUID.randomUUID(),
            resultId = resultId,
            tenantId = command.tenantId,
            type = "JURISDICTION_POLICY_CONFIGURED",
            createdAt = now,
        )

        store.savePolicy(compliancePolicy, result, command.tenantId, command.idempotencyKey, fp, audit, outbox)
        return result
    }

    @Synchronized
    fun revokeJurisdictionPolicy(command: RevokeJurisdictionPolicyCommand): JurisdictionPolicyResult {
        OperatorJurisdictionEnablementBinding.checkBound()

        if (command.jurisdictionCode.isBlank() ||
            command.reason.isBlank() ||
            command.sessionId.isBlank() ||
            command.correlationId.isBlank() ||
            command.causationId.isBlank()
        ) {
            throw AuthenticationFailure.Rejected(AuthErrorCode.INVALID)
        }

        val principal = command.principal ?: throw AuthenticationFailure.Rejected(AuthErrorCode.UNAUTHENTICATED)
        if (principal.kind != PrincipalKind.ADMIN || principal.tenantId != command.tenantId) {
            throw AuthenticationFailure.Rejected(AuthErrorCode.FORBIDDEN)
        }

        val session = try {
            sessions.find(command.tenantId, principal.id, command.sessionId)
        } catch (_: Exception) {
            throw AuthenticationFailure.Rejected(AuthErrorCode.DEPENDENCY_UNAVAILABLE)
        } ?: throw AuthenticationFailure.Rejected(AuthErrorCode.FORBIDDEN)

        if (!session.active || session.expiresAt.isBefore(clock.instant())) {
            throw AuthenticationFailure.Rejected(AuthErrorCode.FORBIDDEN)
        }

        if (!policy.isPermitted(principal, AdminPermission.MANAGE_SECURITY)) {
            throw AuthenticationFailure.Rejected(AuthErrorCode.FORBIDDEN)
        }

        val existing = store.findPolicy(command.tenantId, command.jurisdictionCode)
            ?: throw AuthenticationFailure.Rejected(AuthErrorCode.INVALID)

        if (command.expectedVersion != existing.version + 1L) {
            throw AuthenticationFailure.Rejected(AuthErrorCode.STALE)
        }

        val now = clock.instant()
        val revoked = existing.copy(
            status = JurisdictionComplianceStatus.REVOKED,
            version = existing.version + 1L,
        )

        val resultId = UUID.randomUUID()
        val result = JurisdictionPolicyResult(
            resultId = resultId,
            policyId = existing.policyId,
            tenantId = command.tenantId,
            jurisdictionCode = command.jurisdictionCode,
            status = JurisdictionComplianceStatus.REVOKED,
            serverTime = now,
            evidenceReference = "EVID-JURISDICTION-REVOKED-${command.tenantId}-${command.jurisdictionCode}",
        )

        val audit = AuditEvent(
            eventId = UUID.randomUUID(),
            resultId = resultId,
            tenantId = command.tenantId,
            type = "JURISDICTION_POLICY_REVOKED",
            occurredAt = now,
            correlationId = command.correlationId,
            causationId = command.causationId,
        )

        val outbox = OutboxEvent(
            eventId = UUID.randomUUID(),
            resultId = resultId,
            tenantId = command.tenantId,
            type = "JURISDICTION_POLICY_REVOKED",
            createdAt = now,
        )

        store.savePolicy(revoked, result, command.tenantId, command.idempotencyKey, command.reason, audit, outbox)
        return result
    }

    @Synchronized
    fun updateOperatorGameEnablement(command: EnforceOperatorGameEnablementCommand): OperatorEnablementResult {
        OperatorJurisdictionEnablementBinding.checkBound()

        if (command.providerId.isBlank() ||
            command.gameId.isBlank() ||
            command.sessionId.isBlank() ||
            command.correlationId.isBlank() ||
            command.causationId.isBlank() ||
            command.reason.isBlank()
        ) {
            throw AuthenticationFailure.Rejected(AuthErrorCode.INVALID)
        }

        val principal = command.principal ?: throw AuthenticationFailure.Rejected(AuthErrorCode.UNAUTHENTICATED)
        if (principal.kind != PrincipalKind.ADMIN || principal.tenantId != command.tenantId) {
            throw AuthenticationFailure.Rejected(AuthErrorCode.FORBIDDEN)
        }

        val fp = fingerprintOperatorEnablement(command)
        store.findEnablementByIdempotency(command.tenantId, command.idempotencyKey)?.let { (cachedFp, cachedResult) ->
            if (cachedFp != fp) throw AuthenticationFailure.Rejected(AuthErrorCode.CONFLICT)
            return cachedResult
        }

        val session = try {
            sessions.find(command.tenantId, principal.id, command.sessionId)
        } catch (_: Exception) {
            throw AuthenticationFailure.Rejected(AuthErrorCode.DEPENDENCY_UNAVAILABLE)
        } ?: throw AuthenticationFailure.Rejected(AuthErrorCode.FORBIDDEN)

        if (!session.active || session.expiresAt.isBefore(clock.instant())) {
            throw AuthenticationFailure.Rejected(AuthErrorCode.FORBIDDEN)
        }

        if (!policy.isPermitted(principal, AdminPermission.MANAGE_SECURITY) &&
            !policy.isPermitted(principal, AdminPermission.MANAGE_SUPPORT)
        ) {
            throw AuthenticationFailure.Rejected(AuthErrorCode.FORBIDDEN)
        }

        val game = catalogStore.findGame(command.tenantId, command.providerId, command.gameId)
            ?: throw AuthenticationFailure.Rejected(AuthErrorCode.INVALID)

        if (command.expectedVersion != game.version + 1L) {
            throw AuthenticationFailure.Rejected(AuthErrorCode.STALE)
        }

        val now = clock.instant()
        val previousStatus = game.enablementStatus
        val updatedGame = game.copy(
            enablementStatus = command.newStatus,
            version = game.version + 1L,
        )
        catalogStore.saveGame(updatedGame)

        val resultId = UUID.randomUUID()
        val result = OperatorEnablementResult(
            resultId = resultId,
            tenantId = command.tenantId,
            providerId = command.providerId,
            gameId = command.gameId,
            previousStatus = previousStatus,
            newStatus = command.newStatus,
            serverTime = now,
            evidenceReference = "EVID-OPERATOR-ENABLEMENT-${command.tenantId}-${command.gameId}-v${updatedGame.version}",
        )

        val audit = AuditEvent(
            eventId = UUID.randomUUID(),
            resultId = resultId,
            tenantId = command.tenantId,
            type = "OPERATOR_GAME_ENABLEMENT_UPDATED",
            occurredAt = now,
            correlationId = command.correlationId,
            causationId = command.causationId,
        )

        val outbox = OutboxEvent(
            eventId = UUID.randomUUID(),
            resultId = resultId,
            tenantId = command.tenantId,
            type = "OPERATOR_GAME_ENABLEMENT_UPDATED",
            createdAt = now,
        )

        store.saveEnablement(result, command.tenantId, command.idempotencyKey, fp, audit, outbox)
        return result
    }

    @Synchronized
    fun evaluateEligibility(command: EvaluateGameLaunchEligibilityCommand): GameLaunchEligibilityResult {
        OperatorJurisdictionEnablementBinding.checkBound()

        if (command.tenantId.isBlank() ||
            command.providerId.isBlank() ||
            command.gameId.isBlank() ||
            command.playerId.isBlank() ||
            command.jurisdictionCode.isBlank() ||
            command.requestedBetMinorUnits < 0 ||
            !command.currencyCode.matches(Regex("[A-Z]{3}"))
        ) {
            return GameLaunchEligibilityResult(
                eligible = false,
                rejectionReasonCode = AuthErrorCode.INVALID,
                rejectionDetail = "Malformed request arguments",
                gameId = command.gameId,
                jurisdictionCode = command.jurisdictionCode,
                staleSyncDetected = false,
                unlicensedDetected = false,
                disabledDetected = false,
            )
        }

        val game = catalogStore.findGame(command.tenantId, command.providerId, command.gameId)
            ?: return GameLaunchEligibilityResult(
                eligible = false,
                rejectionReasonCode = AuthErrorCode.INVALID,
                rejectionDetail = "Game not found in catalog",
                gameId = command.gameId,
                jurisdictionCode = command.jurisdictionCode,
                staleSyncDetected = false,
                unlicensedDetected = false,
                disabledDetected = false,
            )

        val now = clock.instant()

        // 1. Stale sync check: Stale sync disables affected launch
        val syncAge = now.epochSecond - game.lastSynchronizedAt.epochSecond
        if (syncAge > game.staleSyncThresholdSeconds) {
            return GameLaunchEligibilityResult(
                eligible = false,
                rejectionReasonCode = AuthErrorCode.FORBIDDEN,
                rejectionDetail = "Catalog synchronization is stale (sync age: $syncAge seconds)",
                gameId = command.gameId,
                jurisdictionCode = command.jurisdictionCode,
                staleSyncDetected = true,
                unlicensedDetected = false,
                disabledDetected = true,
            )
        }

        // 2. Operator Enablement check: Prevent disabled game launches
        if (game.enablementStatus != GameEnablementStatus.ENABLED) {
            return GameLaunchEligibilityResult(
                eligible = false,
                rejectionReasonCode = AuthErrorCode.FORBIDDEN,
                rejectionDetail = "Game is currently disabled (${game.enablementStatus})",
                gameId = command.gameId,
                jurisdictionCode = command.jurisdictionCode,
                staleSyncDetected = false,
                unlicensedDetected = false,
                disabledDetected = true,
            )
        }

        // 3. Game supported jurisdictions check
        if (command.jurisdictionCode !in game.supportedJurisdictions) {
            return GameLaunchEligibilityResult(
                eligible = false,
                rejectionReasonCode = AuthErrorCode.FORBIDDEN,
                rejectionDetail = "Jurisdiction ${command.jurisdictionCode} not licensed for game",
                gameId = command.gameId,
                jurisdictionCode = command.jurisdictionCode,
                staleSyncDetected = false,
                unlicensedDetected = true,
                disabledDetected = false,
            )
        }

        // 4. Jurisdiction Compliance Policy check
        val policy = store.findPolicy(command.tenantId, command.jurisdictionCode)
        if (policy != null) {
            if (policy.status != JurisdictionComplianceStatus.ACTIVE ||
                now.isBefore(policy.effectiveFrom) ||
                now.isAfter(policy.effectiveUntil)
            ) {
                return GameLaunchEligibilityResult(
                    eligible = false,
                    rejectionReasonCode = AuthErrorCode.FORBIDDEN,
                    rejectionDetail = "Jurisdiction policy is not active or effective",
                    gameId = command.gameId,
                    jurisdictionCode = command.jurisdictionCode,
                    staleSyncDetected = false,
                    unlicensedDetected = true,
                    disabledDetected = false,
                )
            }

            if (game.gameType !in policy.allowedGameTypes) {
                return GameLaunchEligibilityResult(
                    eligible = false,
                    rejectionReasonCode = AuthErrorCode.FORBIDDEN,
                    rejectionDetail = "Game type ${game.gameType} is not permitted in jurisdiction ${command.jurisdictionCode}",
                    gameId = command.gameId,
                    jurisdictionCode = command.jurisdictionCode,
                    staleSyncDetected = false,
                    unlicensedDetected = true,
                    disabledDetected = false,
                )
            }

            if (command.gameId in policy.restrictedGameIds) {
                return GameLaunchEligibilityResult(
                    eligible = false,
                    rejectionReasonCode = AuthErrorCode.FORBIDDEN,
                    rejectionDetail = "Game is blacklisted in jurisdiction ${command.jurisdictionCode}",
                    gameId = command.gameId,
                    jurisdictionCode = command.jurisdictionCode,
                    staleSyncDetected = false,
                    unlicensedDetected = true,
                    disabledDetected = false,
                )
            }

            if (policy.whitelistedGameIds != null && command.gameId !in policy.whitelistedGameIds) {
                return GameLaunchEligibilityResult(
                    eligible = false,
                    rejectionReasonCode = AuthErrorCode.FORBIDDEN,
                    rejectionDetail = "Game is not in jurisdiction whitelist",
                    gameId = command.gameId,
                    jurisdictionCode = command.jurisdictionCode,
                    staleSyncDetected = false,
                    unlicensedDetected = true,
                    disabledDetected = false,
                )
            }

            if (policy.rtpFloorPercent != null && game.rtpPercent < policy.rtpFloorPercent) {
                return GameLaunchEligibilityResult(
                    eligible = false,
                    rejectionReasonCode = AuthErrorCode.FORBIDDEN,
                    rejectionDetail = "Game RTP ${game.rtpPercent}% is below jurisdiction floor ${policy.rtpFloorPercent}%",
                    gameId = command.gameId,
                    jurisdictionCode = command.jurisdictionCode,
                    staleSyncDetected = false,
                    unlicensedDetected = true,
                    disabledDetected = false,
                )
            }

            if (policy.maxBetLimitMinorUnits != null && command.requestedBetMinorUnits > policy.maxBetLimitMinorUnits) {
                return GameLaunchEligibilityResult(
                    eligible = false,
                    rejectionReasonCode = AuthErrorCode.INVALID,
                    rejectionDetail = "Bet ${command.requestedBetMinorUnits} exceeds jurisdiction limit ${policy.maxBetLimitMinorUnits}",
                    gameId = command.gameId,
                    jurisdictionCode = command.jurisdictionCode,
                    staleSyncDetected = false,
                    unlicensedDetected = false,
                    disabledDetected = false,
                )
            }
        }

        // 5. Game Bet bounds check
        if (command.requestedBetMinorUnits < game.minBetMinorUnits || command.requestedBetMinorUnits > game.maxBetMinorUnits) {
            return GameLaunchEligibilityResult(
                eligible = false,
                rejectionReasonCode = AuthErrorCode.INVALID,
                rejectionDetail = "Bet ${command.requestedBetMinorUnits} outside game limits [${game.minBetMinorUnits}, ${game.maxBetMinorUnits}]",
                gameId = command.gameId,
                jurisdictionCode = command.jurisdictionCode,
                staleSyncDetected = false,
                unlicensedDetected = false,
                disabledDetected = false,
            )
        }

        return GameLaunchEligibilityResult(
            eligible = true,
            rejectionReasonCode = null,
            rejectionDetail = null,
            gameId = command.gameId,
            jurisdictionCode = command.jurisdictionCode,
            staleSyncDetected = false,
            unlicensedDetected = false,
            disabledDetected = false,
        )
    }

    @Synchronized
    fun authorizeLaunch(command: AuthorizeAuthoritativeGameLaunchCommand): AuthoritativeGameLaunchResult {
        OperatorJurisdictionEnablementBinding.checkBound()

        if (command.tenantId.isBlank() ||
            command.providerId.isBlank() ||
            command.gameId.isBlank() ||
            command.playerId.isBlank() ||
            command.jurisdictionCode.isBlank() ||
            command.correlationId.isBlank() ||
            command.causationId.isBlank() ||
            command.requestedBetMinorUnits < 0 ||
            !command.currencyCode.matches(Regex("[A-Z]{3}"))
        ) {
            throw AuthenticationFailure.Rejected(AuthErrorCode.INVALID)
        }

        if (command.expectedVersion != 1L) {
            throw AuthenticationFailure.Rejected(AuthErrorCode.STALE)
        }

        // Idempotency check
        val fp = fingerprintAuthLaunch(command)
        store.findLaunchByIdempotency(command.tenantId, command.idempotencyKey)?.let { (cachedFp, cachedResult) ->
            if (cachedFp != fp) throw AuthenticationFailure.Rejected(AuthErrorCode.CONFLICT)
            return cachedResult
        }

        // Evaluate eligibility
        val evalCmd = EvaluateGameLaunchEligibilityCommand(
            tenantId = command.tenantId,
            providerId = command.providerId,
            gameId = command.gameId,
            playerId = command.playerId,
            jurisdictionCode = command.jurisdictionCode,
            requestedBetMinorUnits = command.requestedBetMinorUnits,
            currencyCode = command.currencyCode,
        )

        val eligibility = evaluateEligibility(evalCmd)
        val now = clock.instant()

        if (!eligibility.eligible) {
            val eventType = when {
                eligibility.staleSyncDetected -> "AUTHORITATIVE_GAME_LAUNCH_REJECTED_STALE_SYNC"
                eligibility.unlicensedDetected -> "AUTHORITATIVE_GAME_LAUNCH_REJECTED_UNLICENSED"
                eligibility.disabledDetected -> "AUTHORITATIVE_GAME_LAUNCH_REJECTED_DISABLED"
                else -> "AUTHORITATIVE_GAME_LAUNCH_REJECTED_INVALID_BET"
            }

            val audit = AuditEvent(
                eventId = UUID.randomUUID(),
                resultId = UUID.randomUUID(),
                tenantId = command.tenantId,
                type = eventType,
                occurredAt = now,
                correlationId = command.correlationId,
                causationId = command.causationId,
            )

            val outbox = OutboxEvent(
                eventId = UUID.randomUUID(),
                resultId = audit.resultId,
                tenantId = command.tenantId,
                type = eventType,
                createdAt = now,
            )

            val rejectedResult = AuthoritativeGameLaunchResult(
                resultId = audit.resultId,
                tenantId = command.tenantId,
                providerId = command.providerId,
                gameId = command.gameId,
                playerId = command.playerId,
                jurisdictionCode = command.jurisdictionCode,
                authorized = false,
                launchToken = null,
                serverTime = now,
                evidenceReference = "EVID-LAUNCH-REJECTED-${command.tenantId}-${command.gameId}-${audit.resultId}",
            )

            store.saveLaunch(rejectedResult, command.tenantId, command.idempotencyKey, fp, audit, outbox)
            throw AuthenticationFailure.Rejected(eligibility.rejectionReasonCode ?: AuthErrorCode.FORBIDDEN)
        }

        // Authorized: generate secure token
        val resultId = UUID.randomUUID()
        val tokenBytes = ByteArray(32)
        secureRandom.nextBytes(tokenBytes)
        val launchToken = "AUTH-LAUNCH-${Base64.getUrlEncoder().withoutPadding().encodeToString(tokenBytes)}"

        val result = AuthoritativeGameLaunchResult(
            resultId = resultId,
            tenantId = command.tenantId,
            providerId = command.providerId,
            gameId = command.gameId,
            playerId = command.playerId,
            jurisdictionCode = command.jurisdictionCode,
            authorized = true,
            launchToken = launchToken,
            serverTime = now,
            evidenceReference = "EVID-AUTH-LAUNCH-${command.tenantId}-${command.gameId}-$resultId",
        )

        val audit = AuditEvent(
            eventId = UUID.randomUUID(),
            resultId = resultId,
            tenantId = command.tenantId,
            type = "AUTHORITATIVE_GAME_LAUNCH_AUTHORIZED",
            occurredAt = now,
            correlationId = command.correlationId,
            causationId = command.causationId,
        )

        val outbox = OutboxEvent(
            eventId = UUID.randomUUID(),
            resultId = resultId,
            tenantId = command.tenantId,
            type = "AUTHORITATIVE_GAME_LAUNCH_AUTHORIZED",
            createdAt = now,
        )

        store.saveLaunch(result, command.tenantId, command.idempotencyKey, fp, audit, outbox)
        return result
    }

    private fun fingerprintPolicy(cmd: ConfigureJurisdictionPolicyCommand): String {
        val md = MessageDigest.getInstance("SHA-256")
        val raw = "${cmd.tenantId}:${cmd.jurisdictionCode}:${cmd.status}:${cmd.allowedGameTypes}:${cmd.maxBetLimitMinorUnits}:${cmd.rtpFloorPercent}:${cmd.expectedVersion}"
        return md.digest(raw.toByteArray(Charsets.UTF_8)).joinToString("") { "%02x".format(it) }
    }

    private fun fingerprintOperatorEnablement(cmd: EnforceOperatorGameEnablementCommand): String {
        val md = MessageDigest.getInstance("SHA-256")
        val raw = "${cmd.tenantId}:${cmd.providerId}:${cmd.gameId}:${cmd.newStatus}:${cmd.expectedVersion}"
        return md.digest(raw.toByteArray(Charsets.UTF_8)).joinToString("") { "%02x".format(it) }
    }

    private fun fingerprintAuthLaunch(cmd: AuthorizeAuthoritativeGameLaunchCommand): String {
        val md = MessageDigest.getInstance("SHA-256")
        val raw = "${cmd.tenantId}:${cmd.providerId}:${cmd.gameId}:${cmd.playerId}:${cmd.jurisdictionCode}:${cmd.requestedBetMinorUnits}:${cmd.currencyCode}"
        return md.digest(raw.toByteArray(Charsets.UTF_8)).joinToString("") { "%02x".format(it) }
    }
}
