package com.slotting.admin.auth

import java.security.MessageDigest
import java.time.Clock
import java.time.Instant
import java.util.UUID
import java.util.concurrent.ConcurrentHashMap

/**
 * Gate to enforce AUTHZ-002-01: Enforce API resource ownership.
 * Semantic contract: "Default deny; resource owner resolved server-side; P0/P1 authz tests mandatory."
 * Protected risk: "horizontal/vertical IDOR and role bypass"
 */
object ApiResourceOwnershipBinding {
    var isBound: Boolean = true

    fun checkBound() {
        if (!isBound) {
            throw AssertionError("horizontal/vertical IDOR and role bypass")
        }
    }
}

enum class ApiResourceType {
    PLAYER_PROFILE,
    PLAYER_WALLET_VIEW,
    PLAYER_SESSION,
    GAME_ROUND,
    PAYMENT_INSTRUMENT,
    KYC_DOCUMENT,
    SUPPORT_TICKET,
    ADMIN_AUDIT_LOG,
    TENANT_CONFIGURATION
}

enum class ApiOperation {
    READ,
    WRITE,
    DELETE,
    EXPORT,
    ADMIN_OVERRIDE
}

data class ApiResourceRecord(
    val resourceId: String,
    val resourceType: ApiResourceType,
    val tenantId: String,
    val ownerId: String,
    val version: Long = 1L,
    val isRestricted: Boolean = false,
    val adminRoleRequired: AdminRole? = null
)

data class EnforceResourceOwnershipCommand(
    val principal: AuthenticatedPrincipal?,
    val tenantId: String,
    val resourceType: ApiResourceType,
    val resourceId: String,
    val operation: ApiOperation,
    val declaredOwnerId: String? = null,
    val adminAccessReason: String? = null,
    val idempotencyKey: String,
    val correlationId: String,
    val causationId: String,
    val expectedVersion: Long
)

data class ResourceOwnershipDecision(
    val resultId: UUID,
    val allowed: Boolean,
    val tenantId: String,
    val resourceId: String,
    val resourceType: ApiResourceType,
    val resolvedOwnerId: String,
    val principalId: String,
    val principalKind: PrincipalKind,
    val serverTime: Instant,
    val serverVersion: Long,
    val evidenceReference: String,
    val auditEvent: AuditEvent,
    val outboxEvent: OutboxEvent
)

interface ApiResourceDirectory {
    /**
     * Resolves resource ownership from authoritative server state.
     * Request fields never define or fabricate the owner.
     */
    fun findResource(tenantId: String, resourceType: ApiResourceType, resourceId: String): ApiResourceRecord?
}

interface ApiResourceOwnershipStore {
    fun findByIdempotency(tenantId: String, idempotencyKey: String): Pair<String, ResourceOwnershipDecision>?
    fun saveDecision(
        decision: ResourceOwnershipDecision,
        idempotencyKey: String,
        requestFingerprint: String
    )
}

interface ApiSecurityAlertSink {
    fun sendSecurityAlert(tenantId: String, alertType: String, message: String)
}

class InMemoryApiSecurityAlertSink : ApiSecurityAlertSink {
    val alerts = mutableListOf<String>()
    override fun sendSecurityAlert(tenantId: String, alertType: String, message: String) {
        alerts.add("$tenantId:$alertType:$message")
    }
}

class InMemoryApiResourceDirectory : ApiResourceDirectory {
    val resources = ConcurrentHashMap<String, ApiResourceRecord>()

    fun registerResource(record: ApiResourceRecord) {
        resources["${record.tenantId}:${record.resourceType}:${record.resourceId}"] = record
    }

    override fun findResource(tenantId: String, resourceType: ApiResourceType, resourceId: String): ApiResourceRecord? {
        return resources["$tenantId:$resourceType:$resourceId"]
    }
}

class InMemoryApiResourceOwnershipStore : ApiResourceOwnershipStore {
    val idempotency = ConcurrentHashMap<String, Pair<String, ResourceOwnershipDecision>>()
    val decisions = mutableListOf<ResourceOwnershipDecision>()

    override fun findByIdempotency(tenantId: String, idempotencyKey: String): Pair<String, ResourceOwnershipDecision>? {
        return idempotency["$tenantId:$idempotencyKey"]
    }

    override fun saveDecision(decision: ResourceOwnershipDecision, idempotencyKey: String, requestFingerprint: String) {
        idempotency["${decision.tenantId}:$idempotencyKey"] = requestFingerprint to decision
        decisions.add(decision)
    }
}

class ApiResourceOwnershipService(
    private val resourceDirectory: ApiResourceDirectory,
    private val store: ApiResourceOwnershipStore,
    private val alertSink: ApiSecurityAlertSink = InMemoryApiSecurityAlertSink(),
    private val clock: Clock = Clock.systemUTC()
) {

    private fun validateHeaders(
        tenantId: String,
        resourceId: String,
        correlationId: String,
        causationId: String,
        idempotencyKey: String,
        expectedVersion: Long
    ) {
        if (tenantId.isBlank() || resourceId.isBlank() || correlationId.isBlank() || causationId.isBlank() || idempotencyKey.isBlank()) {
            throw AuthenticationFailure.Rejected(AuthErrorCode.INVALID)
        }
        if (expectedVersion < 0L) {
            throw AuthenticationFailure.Rejected(AuthErrorCode.INVALID)
        }
    }

    private fun sha256(input: String): String {
        val bytes = MessageDigest.getInstance("SHA-256").digest(input.toByteArray())
        return bytes.joinToString("") { "%02x".format(it) }
    }

    private fun computeFingerprint(command: EnforceResourceOwnershipCommand): String {
        return listOf(
            command.principal?.tenantId,
            command.principal?.id,
            command.principal?.kind?.name,
            command.tenantId,
            command.resourceType.name,
            command.resourceId,
            command.operation.name,
            command.declaredOwnerId,
            command.adminAccessReason,
            command.expectedVersion
        ).joinToString("|")
    }

    fun enforceOwnership(command: EnforceResourceOwnershipCommand): ResourceOwnershipDecision = synchronized(store) {
        // 1. Fail-closed binding check
        ApiResourceOwnershipBinding.checkBound()

        // 2. Validate input and header constraints
        validateHeaders(
            tenantId = command.tenantId,
            resourceId = command.resourceId,
            correlationId = command.correlationId,
            causationId = command.causationId,
            idempotencyKey = command.idempotencyKey,
            expectedVersion = command.expectedVersion
        )

        // 3. Idempotency replay check
        val fingerprint = computeFingerprint(command)
        store.findByIdempotency(command.tenantId, command.idempotencyKey)?.let { (cachedFp, cachedDecision) ->
            if (cachedFp == fingerprint) {
                return cachedDecision
            } else {
                throw AuthenticationFailure.Rejected(AuthErrorCode.CONFLICT)
            }
        }

        // 4. Principal existence check - Default Deny on unauthenticated
        val principal = command.principal ?: throw AuthenticationFailure.Rejected(AuthErrorCode.UNAUTHENTICATED)

        // 5. Tenant isolation check - Default Deny on cross-tenant
        if (principal.tenantId != command.tenantId) {
            alertSink.sendSecurityAlert(
                tenantId = command.tenantId,
                alertType = "CROSS_TENANT_VIOLATION",
                message = "Principal tenant ${principal.tenantId} attempted to access tenant ${command.tenantId}"
            )
            throw AuthenticationFailure.Rejected(AuthErrorCode.FORBIDDEN)
        }

        // 6. Server-side authoritative resource resolution (Request fields never supply owner)
        val resource = resourceDirectory.findResource(command.tenantId, command.resourceType, command.resourceId)
            ?: throw AuthenticationFailure.Rejected(AuthErrorCode.INVALID)

        if (resource.tenantId != command.tenantId) {
            throw AuthenticationFailure.Rejected(AuthErrorCode.FORBIDDEN)
        }

        // 7. Version / staleness check
        if (command.expectedVersion != resource.version) {
            throw AuthenticationFailure.Rejected(AuthErrorCode.STALE)
        }

        // 8. Authorization evaluation based on principal kind
        when (principal.kind) {
            PrincipalKind.PLAYER -> {
                // Vertical Role Bypass Prevention: Players cannot access admin resources or perform admin operations
                if (resource.adminRoleRequired != null ||
                    resource.resourceType == ApiResourceType.ADMIN_AUDIT_LOG ||
                    resource.resourceType == ApiResourceType.TENANT_CONFIGURATION
                ) {
                    alertSink.sendSecurityAlert(
                        tenantId = command.tenantId,
                        alertType = "VERTICAL_ROLE_BYPASS_ATTEMPT",
                        message = "Player ${principal.id} attempted vertical access to admin resource ${resource.resourceType}:${resource.resourceId}"
                    )
                    throw AuthenticationFailure.Rejected(AuthErrorCode.FORBIDDEN)
                }

                if (command.operation == ApiOperation.ADMIN_OVERRIDE || command.operation == ApiOperation.EXPORT) {
                    alertSink.sendSecurityAlert(
                        tenantId = command.tenantId,
                        alertType = "VERTICAL_ROLE_BYPASS_ATTEMPT",
                        message = "Player ${principal.id} attempted admin operation ${command.operation}"
                    )
                    throw AuthenticationFailure.Rejected(AuthErrorCode.FORBIDDEN)
                }

                // Horizontal IDOR Prevention: Player must be the authoritative owner resolved server-side
                if (principal.id != resource.ownerId) {
                    alertSink.sendSecurityAlert(
                        tenantId = command.tenantId,
                        alertType = "HORIZONTAL_IDOR_ATTEMPT",
                        message = "Player ${principal.id} attempted to access resource owned by ${resource.ownerId}"
                    )
                    throw AuthenticationFailure.Rejected(AuthErrorCode.FORBIDDEN)
                }

                // If client provided a declared owner, it must match the server-resolved owner
                if (command.declaredOwnerId != null && command.declaredOwnerId != resource.ownerId) {
                    alertSink.sendSecurityAlert(
                        tenantId = command.tenantId,
                        alertType = "IDOR_SPOOFING_ATTEMPT",
                        message = "Player ${principal.id} declared owner ${command.declaredOwnerId} but server resolved ${resource.ownerId}"
                    )
                    throw AuthenticationFailure.Rejected(AuthErrorCode.FORBIDDEN)
                }
            }

            PrincipalKind.ADMIN -> {
                // Admin access evaluation: Verify required administrative role
                if (resource.adminRoleRequired != null) {
                    val hasRole = principal.roles.contains(resource.adminRoleRequired) ||
                        principal.roles.contains(AdminRole.SUPER_ADMIN)
                    if (!hasRole) {
                        alertSink.sendSecurityAlert(
                            tenantId = command.tenantId,
                            alertType = "ADMIN_ROLE_INSUFFICIENT",
                            message = "Admin ${principal.id} missing required role ${resource.adminRoleRequired}"
                        )
                        throw AuthenticationFailure.Rejected(AuthErrorCode.FORBIDDEN)
                    }
                }

                // When accessing player-owned resources, an admin must supply an audited access reason
                val isPlayerOwnedResource = resource.resourceType in setOf(
                    ApiResourceType.PLAYER_PROFILE,
                    ApiResourceType.PLAYER_WALLET_VIEW,
                    ApiResourceType.PLAYER_SESSION,
                    ApiResourceType.GAME_ROUND,
                    ApiResourceType.PAYMENT_INSTRUMENT,
                    ApiResourceType.KYC_DOCUMENT,
                    ApiResourceType.SUPPORT_TICKET
                )
                if (isPlayerOwnedResource) {
                    if (command.adminAccessReason.isNullOrBlank()) {
                        throw AuthenticationFailure.Rejected(AuthErrorCode.INVALID)
                    }
                }
            }
        }

        val resultId = UUID.randomUUID()
        val now = clock.instant()
        val evidenceReference = "api-resource-authz:${command.tenantId}:${resource.resourceType}:${resource.resourceId}:$resultId"

        val auditEvent = AuditEvent(
            eventId = UUID.randomUUID(),
            resultId = resultId,
            tenantId = command.tenantId,
            type = "API_RESOURCE_ACCESS_AUTHORIZED",
            occurredAt = now,
            correlationId = command.correlationId,
            causationId = command.causationId
        )

        val outboxEvent = OutboxEvent(
            eventId = UUID.randomUUID(),
            resultId = resultId,
            tenantId = command.tenantId,
            type = "API_RESOURCE_ACCESS_AUTHORIZED",
            createdAt = now
        )

        val decision = ResourceOwnershipDecision(
            resultId = resultId,
            allowed = true,
            tenantId = command.tenantId,
            resourceId = resource.resourceId,
            resourceType = resource.resourceType,
            resolvedOwnerId = resource.ownerId,
            principalId = principal.id,
            principalKind = principal.kind,
            serverTime = now,
            serverVersion = resource.version,
            evidenceReference = evidenceReference,
            auditEvent = auditEvent,
            outboxEvent = outboxEvent
        )

        store.saveDecision(decision, command.idempotencyKey, fingerprint)
        return decision
    }
}
