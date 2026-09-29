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
    PAYMENT_CONFIGURATION,
    RESTRICTIONS_MANAGE,
    FRAUD_CASE_MANAGE,
    ANALYTICS_READ,
    FINANCIAL_REVIEW,
    OPERATIONS_MANAGE,
    WITHDRAWAL_REVIEW,
    VIEW_INTEGRATION_SETTINGS,
    EDIT_INTEGRATION_SETTINGS,
    ROTATE_INTEGRATION_SECRETS,
    ENABLE_DISABLE_PROVIDER,
    TEST_INTEGRATION,
    MANAGE_KEY_CONFIGURATION,
    VIEW_OBSERVABILITY_SETTINGS,
    EDIT_OBSERVABILITY_SETTINGS,
    ROTATE_OBSERVABILITY_SECRETS,
    TEST_OBSERVABILITY_INTEGRATION,
    ENABLE_DISABLE_OBSERVABILITY_PROVIDER,
    MANAGE_ALERT_ROUTING,
    MANAGE_ONCALL_MAPPING,
    VIEW_PRIVACY_POLICY,
    CREATE_PRIVACY_POLICY,
    EDIT_PRIVACY_POLICY,
    APPROVE_PRIVACY_POLICY,
    ACTIVATE_PRIVACY_POLICY,
    RETIRE_PRIVACY_POLICY,
    MANAGE_JURISDICTIONS,
    MANAGE_LEGAL_HOLDS,
    RELEASE_LEGAL_HOLDS,
    VIEW_DSAR,
    EXECUTE_DSAR,
    RETRY_DSAR,
    VIEW_PRIVACY_RECEIPTS,
    MANAGE_EXTERNAL_PRIVACY_INTEGRATIONS,
    VIEW_BACKUP_SETTINGS,
    EDIT_BACKUP_STORAGE,
    ROTATE_BACKUP_STORAGE_CREDENTIAL,
    TEST_BACKUP_STORAGE,
    MANAGE_BACKUP_RETENTION,
    MANAGE_BACKUP_IMMUTABILITY,
    CREATE_BACKUP,
    VIEW_BACKUP_STATUS,
    EXECUTE_RESTORE_DRILL,
    VIEW_DATABASE_HA_STATUS,
    REQUEST_DATABASE_SWITCHOVER,
    EXECUTE_DATABASE_FAILOVER,
    EXECUTE_DATABASE_FAILBACK,
    ACKNOWLEDGE_RECOVERY_INCIDENT,
    VIEW_RELEASES,
    CREATE_RELEASE,
    VERIFY_RELEASE,
    APPROVE_STAGING,
    APPROVE_PRODUCTION,
    PROMOTE_RELEASE,
    EXECUTE_ROLLBACK,
    MANAGE_RELEASE_POLICY,
    MANAGE_REGISTRY,
    MANAGE_DEPLOYMENT_TARGETS,
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
    val dualControlReceipt: DualControlReceipt? = null,
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

data class AdminSessionStatus(
    val active: Boolean,
    val breakGlass: Boolean,
    val expiresAt: Instant,
    val mfaVerified: Boolean = true,
    val mfaExpiresAt: Instant? = null,
)

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
        AdminRole.SUPPORT to setOf(
            AdminPermission.READ_SUPPORT,
            AdminPermission.MANAGE_SUPPORT,
            AdminPermission.RESTRICTIONS_MANAGE,
        ),
        AdminRole.SECURITY to setOf(
            AdminPermission.READ_AUDIT,
            AdminPermission.MANAGE_SECURITY,
            AdminPermission.FRAUD_CASE_MANAGE,
            AdminPermission.OPERATIONS_MANAGE,
            AdminPermission.VIEW_INTEGRATION_SETTINGS,
            AdminPermission.EDIT_INTEGRATION_SETTINGS,
            AdminPermission.ROTATE_INTEGRATION_SECRETS,
            AdminPermission.ENABLE_DISABLE_PROVIDER,
            AdminPermission.TEST_INTEGRATION,
            AdminPermission.MANAGE_KEY_CONFIGURATION,
            AdminPermission.VIEW_OBSERVABILITY_SETTINGS,
            AdminPermission.EDIT_OBSERVABILITY_SETTINGS,
            AdminPermission.ROTATE_OBSERVABILITY_SECRETS,
            AdminPermission.TEST_OBSERVABILITY_INTEGRATION,
            AdminPermission.ENABLE_DISABLE_OBSERVABILITY_PROVIDER,
            AdminPermission.MANAGE_ALERT_ROUTING,
            AdminPermission.MANAGE_ONCALL_MAPPING,
            AdminPermission.VIEW_PRIVACY_POLICY,
            AdminPermission.CREATE_PRIVACY_POLICY,
            AdminPermission.EDIT_PRIVACY_POLICY,
            AdminPermission.APPROVE_PRIVACY_POLICY,
            AdminPermission.ACTIVATE_PRIVACY_POLICY,
            AdminPermission.RETIRE_PRIVACY_POLICY,
            AdminPermission.MANAGE_JURISDICTIONS,
            AdminPermission.MANAGE_LEGAL_HOLDS,
            AdminPermission.RELEASE_LEGAL_HOLDS,
            AdminPermission.VIEW_DSAR,
            AdminPermission.EXECUTE_DSAR,
            AdminPermission.RETRY_DSAR,
            AdminPermission.VIEW_PRIVACY_RECEIPTS,
            AdminPermission.MANAGE_EXTERNAL_PRIVACY_INTEGRATIONS,
            AdminPermission.VIEW_BACKUP_SETTINGS,
            AdminPermission.EDIT_BACKUP_STORAGE,
            AdminPermission.ROTATE_BACKUP_STORAGE_CREDENTIAL,
            AdminPermission.TEST_BACKUP_STORAGE,
            AdminPermission.MANAGE_BACKUP_RETENTION,
            AdminPermission.MANAGE_BACKUP_IMMUTABILITY,
            AdminPermission.CREATE_BACKUP,
            AdminPermission.VIEW_BACKUP_STATUS,
            AdminPermission.EXECUTE_RESTORE_DRILL,
            AdminPermission.VIEW_DATABASE_HA_STATUS,
            AdminPermission.REQUEST_DATABASE_SWITCHOVER,
            AdminPermission.EXECUTE_DATABASE_FAILOVER,
            AdminPermission.EXECUTE_DATABASE_FAILBACK,
            AdminPermission.ACKNOWLEDGE_RECOVERY_INCIDENT,
            AdminPermission.VIEW_RELEASES,
            AdminPermission.CREATE_RELEASE,
            AdminPermission.VERIFY_RELEASE,
            AdminPermission.APPROVE_STAGING,
            AdminPermission.MANAGE_RELEASE_POLICY,
            AdminPermission.MANAGE_REGISTRY,
            AdminPermission.MANAGE_DEPLOYMENT_TARGETS,
        ),
        AdminRole.AUDITOR to setOf(
            AdminPermission.READ_SUPPORT,
            AdminPermission.READ_AUDIT,
            AdminPermission.ANALYTICS_READ,
            AdminPermission.FINANCIAL_REVIEW,
            AdminPermission.VIEW_INTEGRATION_SETTINGS,
            AdminPermission.VIEW_OBSERVABILITY_SETTINGS,
            AdminPermission.VIEW_PRIVACY_POLICY,
            AdminPermission.VIEW_DSAR,
            AdminPermission.VIEW_PRIVACY_RECEIPTS,
            AdminPermission.VIEW_BACKUP_SETTINGS,
            AdminPermission.VIEW_BACKUP_STATUS,
            AdminPermission.VIEW_DATABASE_HA_STATUS,
            AdminPermission.VIEW_RELEASES,
        ),
        AdminRole.SUPER_ADMIN to setOf(
            AdminPermission.READ_SUPPORT,
            AdminPermission.MANAGE_SUPPORT,
            AdminPermission.READ_AUDIT,
            AdminPermission.MANAGE_SECURITY,
            AdminPermission.CHANGE_ROLES,
            AdminPermission.PAYMENT_CONFIGURATION,
            AdminPermission.RESTRICTIONS_MANAGE,
            AdminPermission.FRAUD_CASE_MANAGE,
            AdminPermission.ANALYTICS_READ,
            AdminPermission.FINANCIAL_REVIEW,
            AdminPermission.OPERATIONS_MANAGE,
            AdminPermission.WITHDRAWAL_REVIEW,
            AdminPermission.VIEW_INTEGRATION_SETTINGS,
            AdminPermission.EDIT_INTEGRATION_SETTINGS,
            AdminPermission.ROTATE_INTEGRATION_SECRETS,
            AdminPermission.ENABLE_DISABLE_PROVIDER,
            AdminPermission.TEST_INTEGRATION,
            AdminPermission.MANAGE_KEY_CONFIGURATION,
            AdminPermission.VIEW_OBSERVABILITY_SETTINGS,
            AdminPermission.EDIT_OBSERVABILITY_SETTINGS,
            AdminPermission.ROTATE_OBSERVABILITY_SECRETS,
            AdminPermission.TEST_OBSERVABILITY_INTEGRATION,
            AdminPermission.ENABLE_DISABLE_OBSERVABILITY_PROVIDER,
            AdminPermission.MANAGE_ALERT_ROUTING,
            AdminPermission.MANAGE_ONCALL_MAPPING,
            AdminPermission.VIEW_PRIVACY_POLICY,
            AdminPermission.CREATE_PRIVACY_POLICY,
            AdminPermission.EDIT_PRIVACY_POLICY,
            AdminPermission.APPROVE_PRIVACY_POLICY,
            AdminPermission.ACTIVATE_PRIVACY_POLICY,
            AdminPermission.RETIRE_PRIVACY_POLICY,
            AdminPermission.MANAGE_JURISDICTIONS,
            AdminPermission.MANAGE_LEGAL_HOLDS,
            AdminPermission.RELEASE_LEGAL_HOLDS,
            AdminPermission.VIEW_DSAR,
            AdminPermission.EXECUTE_DSAR,
            AdminPermission.RETRY_DSAR,
            AdminPermission.VIEW_PRIVACY_RECEIPTS,
            AdminPermission.MANAGE_EXTERNAL_PRIVACY_INTEGRATIONS,
            AdminPermission.VIEW_BACKUP_SETTINGS,
            AdminPermission.EDIT_BACKUP_STORAGE,
            AdminPermission.ROTATE_BACKUP_STORAGE_CREDENTIAL,
            AdminPermission.TEST_BACKUP_STORAGE,
            AdminPermission.MANAGE_BACKUP_RETENTION,
            AdminPermission.MANAGE_BACKUP_IMMUTABILITY,
            AdminPermission.CREATE_BACKUP,
            AdminPermission.VIEW_BACKUP_STATUS,
            AdminPermission.EXECUTE_RESTORE_DRILL,
            AdminPermission.VIEW_DATABASE_HA_STATUS,
            AdminPermission.REQUEST_DATABASE_SWITCHOVER,
            AdminPermission.EXECUTE_DATABASE_FAILOVER,
            AdminPermission.EXECUTE_DATABASE_FAILBACK,
            AdminPermission.ACKNOWLEDGE_RECOVERY_INCIDENT,
            AdminPermission.VIEW_RELEASES,
            AdminPermission.CREATE_RELEASE,
            AdminPermission.VERIFY_RELEASE,
            AdminPermission.APPROVE_STAGING,
            AdminPermission.APPROVE_PRODUCTION,
            AdminPermission.PROMOTE_RELEASE,
            AdminPermission.EXECUTE_ROLLBACK,
            AdminPermission.MANAGE_RELEASE_POLICY,
            AdminPermission.MANAGE_REGISTRY,
            AdminPermission.MANAGE_DEPLOYMENT_TARGETS,
        ),
    )

    fun isPermitted(principal: AuthenticatedPrincipal, permission: AdminPermission): Boolean =
        principal.kind == PrincipalKind.ADMIN && permission != AdminPermission.FINANCIAL_MUTATION &&
            principal.roles.any { permission in permissionsByRole.getValue(it) }

    fun requiresDistinctSecondApprover(permission: AdminPermission): Boolean =
        dualControlRequired && (
            permission == AdminPermission.CHANGE_ROLES ||
            permission == AdminPermission.PAYMENT_CONFIGURATION ||
            permission == AdminPermission.WITHDRAWAL_REVIEW ||
            permission == AdminPermission.APPROVE_PRIVACY_POLICY ||
            permission == AdminPermission.ACTIVATE_PRIVACY_POLICY ||
            permission == AdminPermission.MANAGE_BACKUP_IMMUTABILITY ||
            permission == AdminPermission.EXECUTE_DATABASE_FAILOVER ||
            permission == AdminPermission.EXECUTE_DATABASE_FAILBACK ||
            permission == AdminPermission.APPROVE_PRODUCTION ||
            permission == AdminPermission.PROMOTE_RELEASE ||
            permission == AdminPermission.EXECUTE_ROLLBACK
        )
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
        // 1. Authorize principal and context BEFORE checking idempotency store or disclosing cached state
        val principal = command.principal ?: throw AuthenticationFailure.Rejected(AuthErrorCode.UNAUTHENTICATED)
        if (principal.kind != PrincipalKind.ADMIN || principal.tenantId != command.tenantId || command.resourceReference.isBlank()) {
            throw AuthenticationFailure.Rejected(AuthErrorCode.FORBIDDEN)
        }
        val ownerId = owners.resolve(command.tenantId, command.resourceReference)
            ?: throw AuthenticationFailure.Rejected(AuthErrorCode.FORBIDDEN)
        if (command.expectedVersion < 0L || command.sessionId.isBlank() || command.correlationId.isBlank() || command.causationId.isBlank()) {
            throw AuthenticationFailure.Rejected(AuthErrorCode.INVALID)
        }
        val now = Instant.now(clock)
        val session = sessions.find(command.tenantId, principal.id, command.sessionId)
        if (session == null || !session.active || !session.expiresAt.isAfter(now)) {
            throw AuthenticationFailure.Rejected(AuthErrorCode.FORBIDDEN)
        }
        if (!session.mfaVerified || (session.mfaExpiresAt != null && !session.mfaExpiresAt.isAfter(now))) {
            throw AuthenticationFailure.Rejected(AuthErrorCode.FORBIDDEN)
        }
        if (command.breakGlass && (!session.breakGlass || session.expiresAt.isAfter(now.plus(maxBreakGlassDuration)))) {
            throw AuthenticationFailure.Rejected(AuthErrorCode.FORBIDDEN)
        }
        if (!policy.isPermitted(principal, command.permission)) {
            throw AuthenticationFailure.Rejected(AuthErrorCode.FORBIDDEN)
        }
        if (policy.requiresDistinctSecondApprover(command.permission)) {
            if (!command.breakGlass) {
                val receipt = command.dualControlReceipt
                    ?: throw AuthenticationFailure.Rejected(AuthErrorCode.FORBIDDEN)
                if (receipt.tenantId != command.tenantId ||
                    receipt.status != DualControlStatus.APPROVED ||
                    receipt.maker.principalId == receipt.checker.principalId ||
                    !receipt.expiresAt.isAfter(now) ||
                    receipt.requiredPermission != command.permission
                ) {
                    throw AuthenticationFailure.Rejected(AuthErrorCode.FORBIDDEN)
                }
            }
        }

        // 2. Verified caller: now check idempotency cache
        val fingerprint = fingerprint(command)
        store.findByIdempotency(command.tenantId, command.idempotencyKey)?.let { replay ->
            if (replay.first != fingerprint) throw AuthenticationFailure.Rejected(AuthErrorCode.CONFLICT)
            return replay.second
        }

        // 3. Check expected version against current version
        if (command.expectedVersion != store.currentVersion(command.tenantId, ownerId)) {
            throw AuthenticationFailure.Rejected(AuthErrorCode.STALE)
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
        command.dualControlReceipt?.receiptId,
    ).joinToString("|")
}
