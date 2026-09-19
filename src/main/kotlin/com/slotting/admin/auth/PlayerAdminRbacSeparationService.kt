package com.slotting.admin.auth

import java.time.Clock
import java.time.Instant
import java.util.UUID
import java.util.concurrent.ConcurrentHashMap

/**
 * Gate to enforce AUTHZ-002-02: Enforce player and admin RBAC separation.
 * Semantic contract: "Default deny; resource owner resolved server-side; P0/P1 authz tests mandatory."
 * Protected risk: "horizontal/vertical IDOR and role bypass"
 */
object PlayerAdminRbacSeparationBinding {
    var isBound: Boolean = true

    fun checkBound() {
        if (!isBound) {
            throw AssertionError("horizontal/vertical IDOR and role bypass")
        }
    }
}

enum class RbacPermission {
    // Player Plane Permissions
    PLAYER_GAME_PLAY,
    PLAYER_WALLET_VIEW,
    PLAYER_TRANSACTION_HISTORY,
    PLAYER_WITHDRAWAL_REQUEST,
    PLAYER_SELF_LIMIT_UPDATE,
    PLAYER_PROFILE_VIEW,
    PLAYER_PROFILE_UPDATE,

    // Admin Plane Permissions
    ADMIN_SUPPORT_READ,
    ADMIN_SUPPORT_ACTION,
    ADMIN_SECURITY_AUDIT,
    ADMIN_USER_MANAGEMENT,
    ADMIN_ROLE_MANAGEMENT,
    ADMIN_WITHDRAWAL_REVIEW,
    ADMIN_AML_DECISION,
    ADMIN_SYSTEM_CONFIG,
    ADMIN_FINANCIAL_SETTLEMENT
}

data class AuthorizeRbacCommand(
    val principal: AuthenticatedPrincipal?,
    val tenantId: String,
    val permission: RbacPermission,
    val resourceType: ApiResourceType? = null,
    val resourceId: String? = null,
    val secondApproverId: String? = null,
    val adminAccessReason: String? = null,
    val idempotencyKey: String,
    val correlationId: String,
    val causationId: String,
    val expectedVersion: Long
)

data class RbacAuthorizationDecision(
    val resultId: UUID,
    val allowed: Boolean,
    val tenantId: String,
    val principalId: String,
    val principalKind: PrincipalKind,
    val permission: RbacPermission,
    val resourceId: String?,
    val resolvedOwnerId: String?,
    val serverTime: Instant,
    val serverVersion: Long,
    val evidenceReference: String,
    val auditEvent: AuditEvent,
    val outboxEvent: OutboxEvent
)

interface RbacDecisionStore {
    fun findByIdempotency(tenantId: String, idempotencyKey: String): Pair<String, RbacAuthorizationDecision>?
    fun saveDecision(
        decision: RbacAuthorizationDecision,
        idempotencyKey: String,
        requestFingerprint: String
    )
}

class InMemoryRbacDecisionStore : RbacDecisionStore {
    val idempotency = ConcurrentHashMap<String, Pair<String, RbacAuthorizationDecision>>()
    val decisions = mutableListOf<RbacAuthorizationDecision>()

    override fun findByIdempotency(tenantId: String, idempotencyKey: String): Pair<String, RbacAuthorizationDecision>? {
        return idempotency["$tenantId:$idempotencyKey"]
    }

    override fun saveDecision(decision: RbacAuthorizationDecision, idempotencyKey: String, requestFingerprint: String) {
        idempotency["${decision.tenantId}:$idempotencyKey"] = requestFingerprint to decision
        decisions.add(decision)
    }
}

class PlayerAdminRbacSeparationService(
    private val resourceDirectory: ApiResourceDirectory,
    private val decisionStore: RbacDecisionStore,
    private val alertSink: ApiSecurityAlertSink = InMemoryApiSecurityAlertSink(),
    private val clock: Clock = Clock.systemUTC()
) {

    private val playerPermissions = setOf(
        RbacPermission.PLAYER_GAME_PLAY,
        RbacPermission.PLAYER_WALLET_VIEW,
        RbacPermission.PLAYER_TRANSACTION_HISTORY,
        RbacPermission.PLAYER_WITHDRAWAL_REQUEST,
        RbacPermission.PLAYER_SELF_LIMIT_UPDATE,
        RbacPermission.PLAYER_PROFILE_VIEW,
        RbacPermission.PLAYER_PROFILE_UPDATE
    )

    private val adminPermissions = setOf(
        RbacPermission.ADMIN_SUPPORT_READ,
        RbacPermission.ADMIN_SUPPORT_ACTION,
        RbacPermission.ADMIN_SECURITY_AUDIT,
        RbacPermission.ADMIN_USER_MANAGEMENT,
        RbacPermission.ADMIN_ROLE_MANAGEMENT,
        RbacPermission.ADMIN_WITHDRAWAL_REVIEW,
        RbacPermission.ADMIN_AML_DECISION,
        RbacPermission.ADMIN_SYSTEM_CONFIG,
        RbacPermission.ADMIN_FINANCIAL_SETTLEMENT
    )

    private val dualControlRequiredPermissions = setOf(
        RbacPermission.ADMIN_ROLE_MANAGEMENT,
        RbacPermission.ADMIN_FINANCIAL_SETTLEMENT
    )

    private val rolePermissionMatrix = mapOf(
        AdminRole.SUPPORT to setOf(
            RbacPermission.ADMIN_SUPPORT_READ,
            RbacPermission.ADMIN_SUPPORT_ACTION,
            RbacPermission.ADMIN_WITHDRAWAL_REVIEW
        ),
        AdminRole.SECURITY to setOf(
            RbacPermission.ADMIN_SUPPORT_READ,
            RbacPermission.ADMIN_SECURITY_AUDIT,
            RbacPermission.ADMIN_USER_MANAGEMENT,
            RbacPermission.ADMIN_AML_DECISION
        ),
        AdminRole.AUDITOR to setOf(
            RbacPermission.ADMIN_SUPPORT_READ,
            RbacPermission.ADMIN_SECURITY_AUDIT
        ),
        AdminRole.SUPER_ADMIN to adminPermissions
    )

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
        if (expectedVersion < 0L) {
            throw AuthenticationFailure.Rejected(AuthErrorCode.INVALID)
        }
    }

    private fun computeFingerprint(command: AuthorizeRbacCommand): String {
        return listOf(
            command.principal?.tenantId,
            command.principal?.id,
            command.principal?.kind?.name,
            command.principal?.roles?.map { it.name }?.sorted()?.joinToString(","),
            command.tenantId,
            command.permission.name,
            command.resourceType?.name,
            command.resourceId,
            command.secondApproverId,
            command.adminAccessReason,
            command.expectedVersion
        ).joinToString("|")
    }

    fun authorize(command: AuthorizeRbacCommand): RbacAuthorizationDecision = synchronized(decisionStore) {
        // 1. Fail-closed binding check
        PlayerAdminRbacSeparationBinding.checkBound()

        // 2. Validate input and header constraints
        validateHeaders(
            tenantId = command.tenantId,
            correlationId = command.correlationId,
            causationId = command.causationId,
            idempotencyKey = command.idempotencyKey,
            expectedVersion = command.expectedVersion
        )

        // 3. Idempotency replay check
        val fingerprint = computeFingerprint(command)
        decisionStore.findByIdempotency(command.tenantId, command.idempotencyKey)?.let { (cachedFp, cachedDecision) ->
            if (cachedFp == fingerprint) {
                return cachedDecision
            } else {
                throw AuthenticationFailure.Rejected(AuthErrorCode.CONFLICT)
            }
        }

        // 4. Default Deny on unauthenticated principal
        val principal = command.principal ?: throw AuthenticationFailure.Rejected(AuthErrorCode.UNAUTHENTICATED)

        // 5. Cross-tenant isolation check
        if (principal.tenantId != command.tenantId) {
            alertSink.sendSecurityAlert(
                tenantId = command.tenantId,
                alertType = "CROSS_TENANT_RBAC_VIOLATION",
                message = "Principal from tenant ${principal.tenantId} attempted to access tenant ${command.tenantId}"
            )
            throw AuthenticationFailure.Rejected(AuthErrorCode.FORBIDDEN)
        }

        var resolvedOwnerId: String? = null
        var targetResourceVersion: Long = 1L

        // 6. If a resource is specified, resolve owner and version server-side
        if (command.resourceType != null && command.resourceId != null) {
            val resource = resourceDirectory.findResource(command.tenantId, command.resourceType, command.resourceId)
                ?: throw AuthenticationFailure.Rejected(AuthErrorCode.INVALID)

            if (resource.tenantId != command.tenantId) {
                throw AuthenticationFailure.Rejected(AuthErrorCode.FORBIDDEN)
            }

            if (command.expectedVersion != resource.version) {
                throw AuthenticationFailure.Rejected(AuthErrorCode.STALE)
            }

            resolvedOwnerId = resource.ownerId
            targetResourceVersion = resource.version
        }

        // 7. Plane and RBAC Separation Enforcement
        when (principal.kind) {
            PrincipalKind.PLAYER -> {
                // Rule 1: Player tokens cannot claim or hold administrative roles (prevents privilege escalation)
                if (principal.roles.isNotEmpty()) {
                    alertSink.sendSecurityAlert(
                        tenantId = command.tenantId,
                        alertType = "ILLEGAL_PLAYER_ADMIN_ROLE_CLAIM",
                        message = "Player ${principal.id} presented token with administrative roles: ${principal.roles}"
                    )
                    throw AuthenticationFailure.Rejected(AuthErrorCode.FORBIDDEN)
                }

                // Rule 2: Players cannot execute Admin plane permissions
                if (command.permission in adminPermissions) {
                    alertSink.sendSecurityAlert(
                        tenantId = command.tenantId,
                        alertType = "VERTICAL_ROLE_BYPASS_ATTEMPT",
                        message = "Player ${principal.id} attempted to execute admin permission ${command.permission}"
                    )
                    throw AuthenticationFailure.Rejected(AuthErrorCode.FORBIDDEN)
                }

                // Rule 3: Players can only execute authorized player-plane actions on own resources
                if (resolvedOwnerId != null && resolvedOwnerId != principal.id) {
                    alertSink.sendSecurityAlert(
                        tenantId = command.tenantId,
                        alertType = "HORIZONTAL_IDOR_ATTEMPT",
                        message = "Player ${principal.id} attempted to access resource owned by $resolvedOwnerId"
                    )
                    throw AuthenticationFailure.Rejected(AuthErrorCode.FORBIDDEN)
                }
            }

            PrincipalKind.ADMIN -> {
                // Rule 4: Admins cannot execute player gaming / wagering actions as a regular player
                if (command.permission == RbacPermission.PLAYER_GAME_PLAY ||
                    command.permission == RbacPermission.PLAYER_WITHDRAWAL_REQUEST
                ) {
                    alertSink.sendSecurityAlert(
                        tenantId = command.tenantId,
                        alertType = "ADMIN_INSIDER_PLAY_DENIED",
                        message = "Admin ${principal.id} attempted insider gaming action ${command.permission}"
                    )
                    throw AuthenticationFailure.Rejected(AuthErrorCode.FORBIDDEN)
                }

                // Rule 5: Least privilege verification for admin roles
                val isPermitted = principal.roles.any { role ->
                    rolePermissionMatrix[role]?.contains(command.permission) == true
                }
                if (!isPermitted) {
                    alertSink.sendSecurityAlert(
                        tenantId = command.tenantId,
                        alertType = "ADMIN_LEAST_PRIVILEGE_DENIED",
                        message = "Admin ${principal.id} lacking roles for permission ${command.permission}"
                    )
                    throw AuthenticationFailure.Rejected(AuthErrorCode.FORBIDDEN)
                }

                // Rule 6: Dual-control enforcement for high-risk operations
                if (command.permission in dualControlRequiredPermissions) {
                    if (command.secondApproverId.isNullOrBlank() || command.secondApproverId == principal.id) {
                        alertSink.sendSecurityAlert(
                            tenantId = command.tenantId,
                            alertType = "DUAL_CONTROL_REQUIREMENT_FAILED",
                            message = "Admin ${principal.id} attempted dual-controlled action ${command.permission} without distinct second approver"
                        )
                        throw AuthenticationFailure.Rejected(AuthErrorCode.FORBIDDEN)
                    }
                }

                // Rule 7: Admin accessing player resources requires non-blank audit reason
                if (resolvedOwnerId != null && resolvedOwnerId != principal.id) {
                    if (command.adminAccessReason.isNullOrBlank()) {
                        throw AuthenticationFailure.Rejected(AuthErrorCode.INVALID)
                    }
                }
            }
        }

        val resultId = UUID.randomUUID()
        val now = clock.instant()
        val evidenceReference = "rbac-separation:${command.tenantId}:${principal.kind}:${command.permission}:$resultId"

        val auditEvent = AuditEvent(
            eventId = UUID.randomUUID(),
            resultId = resultId,
            tenantId = command.tenantId,
            type = "RBAC_AUTHORIZATION_ALLOWED",
            occurredAt = now,
            correlationId = command.correlationId,
            causationId = command.causationId
        )

        val outboxEvent = OutboxEvent(
            eventId = UUID.randomUUID(),
            resultId = resultId,
            tenantId = command.tenantId,
            type = "RBAC_AUTHORIZATION_ALLOWED",
            createdAt = now
        )

        val decision = RbacAuthorizationDecision(
            resultId = resultId,
            allowed = true,
            tenantId = command.tenantId,
            principalId = principal.id,
            principalKind = principal.kind,
            permission = command.permission,
            resourceId = command.resourceId,
            resolvedOwnerId = resolvedOwnerId,
            serverTime = now,
            serverVersion = targetResourceVersion,
            evidenceReference = evidenceReference,
            auditEvent = auditEvent,
            outboxEvent = outboxEvent
        )

        decisionStore.saveDecision(decision, command.idempotencyKey, fingerprint)
        return decision
    }
}
