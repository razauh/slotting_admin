package com.slotting.admin.auth

import java.time.Clock
import java.time.Duration
import java.time.Instant
import java.util.UUID

enum class AdminPermission {
    READ_SUPPORT,
    MANAGE_SUPPORT,
    READ_AUDIT,
    MANAGE_SECURITY,
    CHANGE_ROLES,
    FINANCIAL_MUTATION,
}

enum class AuthorizationState { ALLOWED, DENIED }

data class AdminAuthorizationCommand(
    val principal: AuthenticatedPrincipal?,
    val sessionId: String,
    val tenantId: String,
    val resourceReference: String,
    val permission: AdminPermission,
    val idempotencyKey: String,
    val correlationId: String,
    val causationId: String,
    val expectedVersion: Long,
    val secondApproverId: String? = null,
    val breakGlass: Boolean = false,
)

data class AuthorizationResult(
    val resultId: UUID,
    val state: AuthorizationState,
    val serverTime: Instant,
    val expiresAt: Instant,
    val serverVersion: Long,
    val reasonCode: AuthErrorCode? = null,
    val evidenceReference: String,
)

data class AdminSessionStatus(val active: Boolean, val breakGlass: Boolean, val expiresAt: Instant)

interface AdminSessionDirectory {
    fun find(tenantId: String, principalId: String, sessionId: String): AdminSessionStatus?
}

interface ResourceOwnerResolver {
    /** Resolves ownership from authoritative server state; request fields never supply the owner ID. */
    fun resolve(tenantId: String, resourceReference: String): String?
}

interface AuthorizationStore {
    fun findByIdempotency(tenantId: String, key: String): Pair<String, AuthorizationResult>?
    fun currentVersion(tenantId: String, ownerId: String): Long
    fun save(
        result: AuthorizationResult,
        tenantId: String,
        ownerId: String,
        permission: AdminPermission,
        idempotencyKey: String,
        breakGlass: Boolean,
        expiresAt: Instant,
        requestFingerprint: String,
        audit: AuditEvent,
        outbox: OutboxEvent,
    )
}

class AdminRbacPolicy(private val dualControlRequired: Boolean) {
    private val permissionsByRole = mapOf(
        AdminRole.SUPPORT to setOf(AdminPermission.READ_SUPPORT, AdminPermission.MANAGE_SUPPORT),
        AdminRole.SECURITY to setOf(AdminPermission.READ_AUDIT, AdminPermission.MANAGE_SECURITY),
        AdminRole.AUDITOR to setOf(AdminPermission.READ_SUPPORT, AdminPermission.READ_AUDIT),
        AdminRole.SUPER_ADMIN to setOf(
            AdminPermission.READ_SUPPORT,
            AdminPermission.MANAGE_SUPPORT,
            AdminPermission.READ_AUDIT,
            AdminPermission.MANAGE_SECURITY,
            AdminPermission.CHANGE_ROLES,
        ),
    )

    fun isPermitted(principal: AuthenticatedPrincipal, permission: AdminPermission): Boolean =
        principal.kind == PrincipalKind.ADMIN && permission != AdminPermission.FINANCIAL_MUTATION &&
            principal.roles.any { permission in permissionsByRole.getValue(it) }

    fun requiresDistinctSecondApprover(permission: AdminPermission): Boolean =
        dualControlRequired && permission == AdminPermission.CHANGE_ROLES
}

class AdminAuthorizationService(
    private val sessions: AdminSessionDirectory,
    private val store: AuthorizationStore,
    private val owners: ResourceOwnerResolver,
    private val alerts: AlertSink,
    private val policy: AdminRbacPolicy,
    private val clock: Clock = Clock.systemUTC(),
    private val maxBreakGlassDuration: Duration = Duration.ofMinutes(30),
) {
    @Synchronized
    fun authorize(command: AdminAuthorizationCommand): AuthorizationResult {
        val principal = command.principal ?: throw AuthenticationFailure.Rejected(AuthErrorCode.UNAUTHENTICATED)
        val fingerprint = fingerprint(command)
        store.findByIdempotency(command.tenantId, command.idempotencyKey)?.let { replay ->
            if (replay.first != fingerprint) throw AuthenticationFailure.Rejected(AuthErrorCode.CONFLICT)
            return replay.second
        }
        if (principal.kind != PrincipalKind.ADMIN || principal.tenantId != command.tenantId || command.resourceReference.isBlank()) {
            throw AuthenticationFailure.Rejected(AuthErrorCode.FORBIDDEN)
        }
        val ownerId = owners.resolve(command.tenantId, command.resourceReference)
            ?: throw AuthenticationFailure.Rejected(AuthErrorCode.FORBIDDEN)
        if (command.expectedVersion < 0L || command.sessionId.isBlank() || command.correlationId.isBlank() || command.causationId.isBlank()) {
            throw AuthenticationFailure.Rejected(AuthErrorCode.INVALID)
        }
        if (command.expectedVersion != store.currentVersion(command.tenantId, ownerId)) {
            throw AuthenticationFailure.Rejected(AuthErrorCode.STALE)
        }
        val now = Instant.now(clock)
        val session = sessions.find(command.tenantId, principal.id, command.sessionId)
        if (session == null || !session.active || !session.expiresAt.isAfter(now)) {
            throw AuthenticationFailure.Rejected(AuthErrorCode.FORBIDDEN)
        }
        if (command.breakGlass && (!session.breakGlass || session.expiresAt.isAfter(now.plus(maxBreakGlassDuration)))) {
            throw AuthenticationFailure.Rejected(AuthErrorCode.FORBIDDEN)
        }
        if (!policy.isPermitted(principal, command.permission)) {
            throw AuthenticationFailure.Rejected(AuthErrorCode.FORBIDDEN)
        }
        if (policy.requiresDistinctSecondApprover(command.permission) &&
            (command.secondApproverId.isNullOrBlank() || command.secondApproverId == principal.id)) {
            throw AuthenticationFailure.Rejected(AuthErrorCode.FORBIDDEN)
        }
        val resultId = UUID.randomUUID()
        val result = AuthorizationResult(resultId, AuthorizationState.ALLOWED, now, session.expiresAt, command.expectedVersion + 1, evidenceReference = "admin-rbac:$resultId")
        val audit = AuditEvent(UUID.randomUUID(), resultId, command.tenantId, "ADMIN_AUTHZ_ALLOWED", now, command.correlationId, command.causationId)
        val outbox = OutboxEvent(UUID.randomUUID(), resultId, command.tenantId, "ADMIN_AUTHZ_ALLOWED", now)
        store.save(result, command.tenantId, ownerId, command.permission, command.idempotencyKey, command.breakGlass, session.expiresAt, fingerprint, audit, outbox)
        if (command.permission == AdminPermission.CHANGE_ROLES) alerts.alert(audit.copy(type = "ADMIN_ROLE_CHANGE_DUAL_CONTROL"))
        if (command.breakGlass) alerts.alert(audit.copy(type = "ADMIN_BREAK_GLASS_AUTHZ"))
        return result
    }

    private fun fingerprint(command: AdminAuthorizationCommand) = listOf(
        command.principal?.tenantId,
        command.principal?.id,
        command.sessionId,
        command.tenantId,
        command.resourceReference,
        command.permission,
        command.expectedVersion,
        command.secondApproverId,
        command.breakGlass,
    ).joinToString("|")
}
