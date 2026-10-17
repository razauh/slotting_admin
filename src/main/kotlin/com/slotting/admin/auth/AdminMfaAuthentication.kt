package com.slotting.admin.auth

import com.fasterxml.jackson.databind.ObjectMapper
import java.time.Clock
import java.time.Duration
import java.time.Instant
import java.security.MessageDigest
import java.util.UUID

enum class PrincipalKind { PLAYER, ADMIN }
enum class AdminRole { SUPPORT, SECURITY, AUDITOR, SUPER_ADMIN }
enum class AuthenticationState { AUTHENTICATED, DENIED, PENDING }
enum class AuthErrorCode { INVALID, UNAUTHENTICATED, FORBIDDEN, CONFLICT, STALE, DEPENDENCY_UNAVAILABLE }

data class AuthenticatedPrincipal(
    val id: String,
    val tenantId: String,
    val kind: PrincipalKind,
    val roles: Set<AdminRole>,
)

data class AdminMfaCommand(
    val principal: AuthenticatedPrincipal?,
    val requestedRole: AdminRole,
    val sessionId: String,
    val idempotencyKey: String,
    val correlationId: String,
    val causationId: String,
    val expectedVersion: Long,
    val mfaAssertion: String,
    val breakGlass: Boolean = false,
    val secondApprover: AuthenticatedPrincipal? = null,
    val secondApproverSessionId: String? = null,
    val secondApproverMfaAssertion: String? = null,
)

data class AuthenticationResult(
    val resultId: UUID,
    val state: AuthenticationState,
    val serverTime: Instant,
    val serverVersion: Long,
    val expiresAt: Instant,
    val reasonCode: AuthErrorCode? = null,
    val evidenceReference: String,
    val approverId: String? = null,
)

data class AuditEvent(
    val eventId: UUID,
    val resultId: UUID,
    val tenantId: String,
    val type: String,
    val occurredAt: Instant,
    val correlationId: String,
    val causationId: String,
)

data class OutboxEvent(
    val eventId: UUID,
    val resultId: UUID,
    val tenantId: String,
    val type: String,
    val createdAt: Instant,
)

/** Minimal forensic metadata only; never include credentials, tokens, or raw provider payloads. */
object RedactedEventJson {
    private val mapper = ObjectMapper().findAndRegisterModules()

    fun audit(event: AuditEvent): String = mapper.writeValueAsString(
        mapOf(
            "eventId" to event.eventId.toString(),
            "resultId" to event.resultId.toString(),
            "tenantId" to event.tenantId,
            "eventType" to event.type,
            "occurredAt" to event.occurredAt.toString(),
            "correlationId" to event.correlationId,
            "causationId" to event.causationId,
        ),
    )

    fun outbox(event: OutboxEvent, audit: AuditEvent): String = mapper.writeValueAsString(
        mapOf(
            "eventId" to event.eventId.toString(),
            "resultId" to event.resultId.toString(),
            "tenantId" to event.tenantId,
            "eventType" to event.type,
            "createdAt" to event.createdAt.toString(),
            "correlationId" to audit.correlationId,
            "causationId" to audit.causationId,
        ),
    )
}

sealed class AuthenticationFailure(val code: AuthErrorCode) : RuntimeException() {
    class Rejected(code: AuthErrorCode) : AuthenticationFailure(code)
}

interface MfaVerifier {
    fun verify(tenantId: String, principalId: String, sessionId: String, assertion: String): Boolean
}

interface AuthenticationStore {
    fun findByIdempotency(tenantId: String, key: String): Pair<String, AuthenticationResult>?
    fun currentVersion(tenantId: String, principalId: String): Long
    fun save(result: AuthenticationResult, tenantId: String, principalId: String, sessionId: String, roles: Set<AdminRole>, idempotencyKey: String, requestFingerprint: String, audit: AuditEvent, outbox: OutboxEvent)
}

interface AlertSink { fun alert(event: AuditEvent) }

class RoleChangePolicy(private val dualControlRequired: Boolean) {
    fun isAllowed(actor: AuthenticatedPrincipal, secondApproverId: String?): Boolean =
        actor.kind == PrincipalKind.ADMIN && (!dualControlRequired || secondApproverId != null && secondApproverId != actor.id)
}

class AdminMfaAuthenticator(
    private val verifier: MfaVerifier,
    private val store: AuthenticationStore,
    private val alerts: AlertSink,
    private val clock: Clock = Clock.systemUTC(),
    private val breakGlassDuration: Duration = Duration.ofMinutes(5),
    private val standardSessionDuration: Duration = Duration.ofHours(2),
    private val roleChangePolicy: RoleChangePolicy = RoleChangePolicy(dualControlRequired = true),
) {
    @Synchronized
    fun authenticate(command: AdminMfaCommand): AuthenticationResult {
        val principal = command.principal ?: throw AuthenticationFailure.Rejected(AuthErrorCode.UNAUTHENTICATED)
        val replay = store.findByIdempotency(principal.tenantId, command.idempotencyKey)
        if (replay != null) {
            if (replay.first != fingerprint(command)) throw AuthenticationFailure.Rejected(AuthErrorCode.CONFLICT)
            return replay.second
        }
        if (principal.kind != PrincipalKind.ADMIN || command.requestedRole !in principal.roles) {
            throw AuthenticationFailure.Rejected(AuthErrorCode.FORBIDDEN)
        }
        if (command.expectedVersion < 0L || command.mfaAssertion.isBlank() || command.sessionId.isBlank()) {
            throw AuthenticationFailure.Rejected(AuthErrorCode.INVALID)
        }
        if (command.expectedVersion != store.currentVersion(principal.tenantId, principal.id)) {
            throw AuthenticationFailure.Rejected(AuthErrorCode.STALE)
        }
        val verified = try {
            verifier.verify(principal.tenantId, principal.id, command.sessionId, command.mfaAssertion)
        } catch (_: Exception) {
            throw AuthenticationFailure.Rejected(AuthErrorCode.DEPENDENCY_UNAVAILABLE)
        }
        if (!verified) {
            throw AuthenticationFailure.Rejected(AuthErrorCode.FORBIDDEN)
        }
        var approverId: String? = null
        if (command.breakGlass) {
            val approver = command.secondApprover ?: throw AuthenticationFailure.Rejected(AuthErrorCode.FORBIDDEN)
            val approverSessionId = command.secondApproverSessionId?.takeIf { it.isNotBlank() }
                ?: throw AuthenticationFailure.Rejected(AuthErrorCode.INVALID)
            val approverAssertion = command.secondApproverMfaAssertion?.takeIf { it.isNotBlank() }
                ?: throw AuthenticationFailure.Rejected(AuthErrorCode.INVALID)
            if (!roleChangePolicy.isAllowed(principal, approver.id) || approver.kind != PrincipalKind.ADMIN ||
                approver.tenantId != principal.tenantId || command.requestedRole !in approver.roles) {
                throw AuthenticationFailure.Rejected(AuthErrorCode.FORBIDDEN)
            }
            val approverVerified = try {
                verifier.verify(approver.tenantId, approver.id, approverSessionId, approverAssertion)
            } catch (_: Exception) {
                throw AuthenticationFailure.Rejected(AuthErrorCode.DEPENDENCY_UNAVAILABLE)
            }
            if (!approverVerified) throw AuthenticationFailure.Rejected(AuthErrorCode.FORBIDDEN)
            approverId = approver.id
        }
        val now = Instant.now(clock)
        val resultId = UUID.randomUUID()
        val result = AuthenticationResult(
            resultId = resultId,
            state = AuthenticationState.AUTHENTICATED,
            serverTime = now,
            serverVersion = command.expectedVersion + 1,
            expiresAt = now.plus(if (command.breakGlass) breakGlassDuration else standardSessionDuration),
            evidenceReference = "admin-auth:$resultId",
            approverId = approverId,
        )
        val eventType = if (command.breakGlass) "ADMIN_BREAK_GLASS_DUAL_APPROVED" else "ADMIN_MFA_ACCEPTED"
        val audit = AuditEvent(UUID.randomUUID(), resultId, principal.tenantId, eventType, now, command.correlationId, command.causationId)
        val outbox = OutboxEvent(UUID.randomUUID(), resultId, principal.tenantId, eventType, now)
        store.save(result, principal.tenantId, principal.id, command.sessionId, setOf(command.requestedRole), command.idempotencyKey, fingerprint(command), audit, outbox)
        if (command.breakGlass) alerts.alert(audit.copy(type = "ADMIN_BREAK_GLASS_STARTED"))
        return result
    }

    private fun fingerprint(command: AdminMfaCommand): String = sha256(listOf(
        command.principal?.tenantId,
        command.principal?.id,
        command.requestedRole,
        command.sessionId,
        command.expectedVersion,
        command.breakGlass,
        command.secondApprover?.id,
        command.secondApproverSessionId,
        command.secondApproverMfaAssertion?.let(::sha256),
        sha256(command.mfaAssertion),
    ).joinToString("|"))

    private fun sha256(value: String): String = MessageDigest.getInstance("SHA-256")
        .digest(value.toByteArray(Charsets.UTF_8))
        .joinToString("") { "%02x".format(it) }
}
