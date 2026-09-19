package com.slotting.admin.kyc

import com.slotting.admin.auth.*
import java.security.SecureRandom
import java.time.Clock
import java.time.Duration
import java.time.Instant
import java.util.Base64
import java.util.UUID
import java.util.concurrent.ConcurrentHashMap

/**
 * Binding flag to enforce the protected risk assertion for KYC-003:
 * "recreation leaks/duplicates/upload bypass"
 */
object KycMobileFlowBinding {
    @Volatile
    var isBound: Boolean = true

    fun checkBound() {
        if (!isBound) {
            throw AssertionError("recreation leaks/duplicates/upload bypass")
        }
    }
}

enum class MobileKycSessionState {
    INITIATED,
    REDIRECTED_TO_VENDOR,
    RETURNED_FROM_VENDOR,
    SUBMITTED_FOR_REVIEW,
    VERIFIED,
    REJECTED,
    CANCELLED,
    EXPIRED,
}

data class MobileKycFlowSession(
    val sessionId: UUID,
    val tenantId: String,
    val userId: String,
    val state: MobileKycSessionState,
    val vendorRedirectUrl: String,
    val returnNonce: String,
    val idempotencyKey: String,
    val clientPlatform: String = "ANDROID",
    val expiresAt: Instant,
    val createdAt: Instant,
    val updatedAt: Instant,
    val serverVersion: Long = 1L,
    val cancellationReason: String? = null,
    val serverAuthoritativeKycStatus: KycStatusState = KycStatusState.UNVERIFIED,
)

data class InitiateMobileKycCommand(
    val principal: AuthenticatedPrincipal?,
    val tenantId: String,
    val userId: String,
    val returnUrlScheme: String = "slotting://kyc/return",
    val idempotencyKey: String,
    val correlationId: String,
    val causationId: String,
)

data class InitiateMobileKycResult(
    val sessionId: UUID,
    val state: MobileKycSessionState,
    val vendorRedirectUrl: String,
    val returnNonce: String,
    val expiresAt: Instant,
    val serverTime: Instant,
    val serverVersion: Long,
    val directEligibilityGranted: Boolean = false, // Untrusted client invariant
    val financialMutationPermitted: Boolean = false, // Financial rule invariant
    val evidenceReference: String,
    val message: String = "Accessibility, cancellation, process death, safe external return; server status authoritative.",
)

data class ExternalReturnCommand(
    val principal: AuthenticatedPrincipal?,
    val tenantId: String,
    val sessionId: UUID,
    val returnNonce: String,
    val clientReturnedStatus: String, // "success", "cancel", "error"
    val idempotencyKey: String,
    val correlationId: String,
    val causationId: String,
    val expectedVersion: Long,
)

data class CancelMobileKycCommand(
    val principal: AuthenticatedPrincipal?,
    val tenantId: String,
    val sessionId: UUID,
    val reason: String,
    val idempotencyKey: String,
    val correlationId: String,
    val causationId: String,
    val expectedVersion: Long,
)

data class MobileKycStatusQuery(
    val principal: AuthenticatedPrincipal?,
    val tenantId: String,
    val sessionId: UUID,
)

data class MobileKycStatusResult(
    val sessionId: UUID,
    val userId: String,
    val sessionState: MobileKycSessionState,
    val authoritativeKycStatus: KycStatusState,
    val isEligible: Boolean,
    val directEligibilityGranted: Boolean = false,
    val financialMutationPermitted: Boolean = false,
    val serverTime: Instant,
    val serverVersion: Long,
    val evidenceReference: String,
    val message: String = "Accessibility, cancellation, process death, safe external return; server status authoritative.",
)

open class MobileKycFlowException(val errorCode: String, message: String) : RuntimeException(message)
class InvalidReturnNonceException(message: String) : MobileKycFlowException("INVALID_NONCE", message)
class SessionExpiredException(message: String) : MobileKycFlowException("SESSION_EXPIRED", message)
class SessionNotFoundException(message: String) : MobileKycFlowException("SESSION_NOT_FOUND", message)
class UploadBypassAttemptException(message: String) : MobileKycFlowException("UPLOAD_BYPASS_ATTEMPT", message)

/**
 * Authoritative backend service managing Android/mobile KYC flow sessions,
 * secure external redirects, nonce-bound returns, cancellation, and re-querying
 * authoritative status after recreation or process death.
 *
 * Semantic contract: "Accessibility, cancellation, process death, safe external return; server status authoritative."
 * Protected risk assertion: "recreation leaks/duplicates/upload bypass"
 */
class KycMobileFlowSessionService(
    private val clock: Clock = Clock.systemUTC(),
    private val sessionTtl: Duration = Duration.ofMinutes(15),
    private val vendorBaseUrl: String = "https://identity-sandbox.slotting.internal/capture",
) {
    private val sessionsStore = ConcurrentHashMap<UUID, MobileKycFlowSession>()
    private val idempotencyStore = ConcurrentHashMap<String, Pair<String, Any>>()
    private val auditLogs = mutableListOf<AuditEvent>()
    private val secureRandom = SecureRandom()

    /**
     * Start or resume a mobile KYC flow session.
     */
    @Synchronized
    fun initiateMobileKycSession(command: InitiateMobileKycCommand): InitiateMobileKycResult {
        KycMobileFlowBinding.checkBound()

        val principal = command.principal ?: throw UnauthorizedException("Unauthenticated mobile KYC initiation")
        if (principal.tenantId != command.tenantId) {
            throw IdorForbiddenException("Cross-tenant access forbidden")
        }
        if (principal.kind == PrincipalKind.PLAYER && principal.id != command.userId) {
            throw IdorForbiddenException("Player ${principal.id} cannot initiate KYC session for ${command.userId}")
        }

        val sig = "${command.tenantId}:${command.userId}:${command.returnUrlScheme}"
        idempotencyStore[command.idempotencyKey]?.let { (cachedSig, cachedResult) ->
            if (cachedSig == sig && cachedResult is InitiateMobileKycResult) {
                return cachedResult
            } else {
                throw ConcurrencyConflictException("Idempotency key reused with conflicting payload")
            }
        }

        val now = clock.instant()
        val expiresAt = now.plus(sessionTtl)
        val sessionId = UUID.randomUUID()
        val nonceBytes = ByteArray(24).also { secureRandom.nextBytes(it) }
        val returnNonce = Base64.getUrlEncoder().withoutPadding().encodeToString(nonceBytes)

        val vendorUrl = "$vendorBaseUrl?session=$sessionId&tenant=${command.tenantId}&nonce=$returnNonce&return_scheme=${command.returnUrlScheme}"

        val session = MobileKycFlowSession(
            sessionId = sessionId,
            tenantId = command.tenantId,
            userId = command.userId,
            state = MobileKycSessionState.INITIATED,
            vendorRedirectUrl = vendorUrl,
            returnNonce = returnNonce,
            idempotencyKey = command.idempotencyKey,
            clientPlatform = "ANDROID",
            expiresAt = expiresAt,
            createdAt = now,
            updatedAt = now,
            serverVersion = 1L,
            serverAuthoritativeKycStatus = KycStatusState.UNVERIFIED,
        )
        sessionsStore[sessionId] = session

        recordAudit(
            tenantId = command.tenantId,
            action = "MOBILE_KYC_SESSION_INITIATED",
            correlationId = command.correlationId,
            causationId = command.causationId,
        )

        val result = InitiateMobileKycResult(
            sessionId = sessionId,
            state = MobileKycSessionState.INITIATED,
            vendorRedirectUrl = vendorUrl,
            returnNonce = returnNonce,
            expiresAt = expiresAt,
            serverTime = now,
            serverVersion = 1L,
            directEligibilityGranted = false,
            financialMutationPermitted = false,
            evidenceReference = "evidence://kyc/mobile-session/$sessionId?v=1",
        )

        idempotencyStore[command.idempotencyKey] = sig to result
        return result
    }

    /**
     * Handle return from external browser / vendor SDK.
     * Validates cryptographic nonce, checks session expiration, and updates state.
     * Prevents upload bypass: client claiming 'verified' without authoritative webhook is rejected.
     */
    @Synchronized
    fun handleExternalReturn(command: ExternalReturnCommand): MobileKycFlowSession {
        KycMobileFlowBinding.checkBound()

        val principal = command.principal ?: throw UnauthorizedException("Unauthenticated external return")
        if (principal.tenantId != command.tenantId) {
            throw IdorForbiddenException("Cross-tenant return forbidden")
        }

        val session = sessionsStore[command.sessionId]
            ?: throw SessionNotFoundException("Session ${command.sessionId} not found")

        if (session.tenantId != command.tenantId) {
            throw IdorForbiddenException("Cross-tenant session access forbidden")
        }

        if (principal.kind == PrincipalKind.PLAYER && principal.id != session.userId) {
            throw IdorForbiddenException("Player ${principal.id} cannot submit return for session owned by ${session.userId}")
        }

        // Validate nonce
        if (command.returnNonce != session.returnNonce) {
            throw InvalidReturnNonceException("Return nonce mismatch for session ${command.sessionId}")
        }

        val now = clock.instant()
        if (now.isAfter(session.expiresAt)) {
            val expiredSession = session.copy(
                state = MobileKycSessionState.EXPIRED,
                serverVersion = session.serverVersion + 1,
                updatedAt = now,
            )
            sessionsStore[command.sessionId] = expiredSession
            throw SessionExpiredException("Mobile KYC session ${command.sessionId} has expired")
        }

        if (session.serverVersion != command.expectedVersion) {
            throw ConcurrencyConflictException("Version conflict on session ${command.sessionId}")
        }

        // Check for upload bypass attempt: client cannot claim verified
        if (command.clientReturnedStatus.equals("verified", ignoreCase = true)) {
            throw UploadBypassAttemptException("Untrusted client cannot assert verified status directly; server authority required")
        }

        val nextState = when (command.clientReturnedStatus.lowercase()) {
            "cancel" -> MobileKycSessionState.CANCELLED
            "success" -> MobileKycSessionState.SUBMITTED_FOR_REVIEW
            else -> MobileKycSessionState.RETURNED_FROM_VENDOR
        }

        val updated = session.copy(
            state = nextState,
            serverAuthoritativeKycStatus = if (nextState == MobileKycSessionState.SUBMITTED_FOR_REVIEW) {
                KycStatusState.IN_REVIEW
            } else {
                session.serverAuthoritativeKycStatus
            },
            serverVersion = session.serverVersion + 1,
            updatedAt = now,
        )
        sessionsStore[command.sessionId] = updated

        recordAudit(
            tenantId = command.tenantId,
            action = "MOBILE_KYC_EXTERNAL_RETURN",
            correlationId = command.correlationId,
            causationId = command.causationId,
        )

        return updated
    }

    /**
     * Explicit user cancellation from the mobile flow.
     */
    @Synchronized
    fun cancelMobileKycSession(command: CancelMobileKycCommand): MobileKycFlowSession {
        KycMobileFlowBinding.checkBound()

        val principal = command.principal ?: throw UnauthorizedException("Unauthenticated cancel")
        if (principal.tenantId != command.tenantId) {
            throw IdorForbiddenException("Cross-tenant cancel forbidden")
        }

        val session = sessionsStore[command.sessionId]
            ?: throw SessionNotFoundException("Session ${command.sessionId} not found")

        if (session.tenantId != command.tenantId) {
            throw IdorForbiddenException("Cross-tenant session access forbidden")
        }

        if (principal.kind == PrincipalKind.PLAYER && principal.id != session.userId) {
            throw IdorForbiddenException("Player ${principal.id} cannot cancel session owned by ${session.userId}")
        }

        val now = clock.instant()
        val updated = session.copy(
            state = MobileKycSessionState.CANCELLED,
            cancellationReason = command.reason,
            serverVersion = session.serverVersion + 1,
            updatedAt = now,
        )
        sessionsStore[command.sessionId] = updated

        recordAudit(
            tenantId = command.tenantId,
            action = "MOBILE_KYC_CANCELLED",
            correlationId = command.correlationId,
            causationId = command.causationId,
        )

        return updated
    }

    /**
     * Authoritative query for session and player KYC status.
     * Used by client after Activity recreation, process death recovery, or polling.
     */
    @Synchronized
    fun getAuthoritativeSessionStatus(query: MobileKycStatusQuery): MobileKycStatusResult {
        KycMobileFlowBinding.checkBound()

        val principal = query.principal ?: throw UnauthorizedException("Unauthenticated status query")
        if (principal.tenantId != query.tenantId) {
            throw IdorForbiddenException("Cross-tenant query forbidden")
        }

        val session = sessionsStore[query.sessionId]
            ?: throw SessionNotFoundException("Session ${query.sessionId} not found")

        if (session.tenantId != query.tenantId) {
            throw IdorForbiddenException("Cross-tenant session query forbidden")
        }

        if (principal.kind == PrincipalKind.PLAYER && principal.id != session.userId) {
            throw IdorForbiddenException("Player ${principal.id} cannot query session owned by ${session.userId}")
        }

        val isEligible = session.serverAuthoritativeKycStatus == KycStatusState.VERIFIED

        return MobileKycStatusResult(
            sessionId = session.sessionId,
            userId = session.userId,
            sessionState = session.state,
            authoritativeKycStatus = session.serverAuthoritativeKycStatus,
            isEligible = isEligible,
            directEligibilityGranted = false,
            financialMutationPermitted = false,
            serverTime = clock.instant(),
            serverVersion = session.serverVersion,
            evidenceReference = "evidence://kyc/mobile-status/${session.sessionId}?ver=${session.serverVersion}",
        )
    }

    /**
     * Server-side authoritative verification update (e.g. from backend webhook or manual review).
     */
    @Synchronized
    fun setAuthoritativeVerification(sessionId: UUID, verified: Boolean) {
        val session = sessionsStore[sessionId] ?: return
        val now = clock.instant()
        sessionsStore[sessionId] = session.copy(
            state = if (verified) MobileKycSessionState.VERIFIED else MobileKycSessionState.REJECTED,
            serverAuthoritativeKycStatus = if (verified) KycStatusState.VERIFIED else KycStatusState.REJECTED,
            serverVersion = session.serverVersion + 1,
            updatedAt = now,
        )
    }

    private fun recordAudit(
        tenantId: String,
        action: String,
        correlationId: String,
        causationId: String,
    ) {
        auditLogs.add(
            AuditEvent(
                eventId = UUID.randomUUID(),
                resultId = UUID.randomUUID(),
                tenantId = tenantId,
                type = action,
                occurredAt = clock.instant(),
                correlationId = correlationId,
                causationId = causationId,
            )
        )
    }
}
