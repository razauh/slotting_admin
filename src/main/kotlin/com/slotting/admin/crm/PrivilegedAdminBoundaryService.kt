package com.slotting.admin.crm

import com.slotting.admin.auth.*
import java.security.MessageDigest
import java.time.Clock
import java.time.Instant
import java.util.UUID

enum class PrivilegedAdminOperation {
    RECORD_SUPPORT_INTERACTION,
    UPDATE_COMMUNICATION_PREFERENCE,
    REQUEST_ACCOUNT_FLAG,
    DIRECT_FINANCIAL_ADJUSTMENT,
    DIRECT_BALANCE_MUTATION,
}

enum class PrivilegedExecutionStatus {
    EXECUTED,
    QUEUED_FOR_REVIEW,
    DENIED,
}

data class PrivilegedAdminCommand(
    val principal: AuthenticatedPrincipal?,
    val sessionId: String,
    val tenantId: String,
    val subjectReference: String,
    val operation: PrivilegedAdminOperation,
    val details: Map<String, String> = emptyMap(),
    val requestedAmountMinorUnits: Long? = null,
    val idempotencyKey: String,
    val correlationId: String,
    val causationId: String,
    val expectedVersion: Long = 1L,
)

data class PrivilegedAdminResult(
    val resultId: UUID,
    val tenantId: String,
    val subjectReference: String,
    val operation: PrivilegedAdminOperation,
    val status: PrivilegedExecutionStatus,
    val financialAuthorityDuplicated: Boolean, // Invariant: Finance authority never duplicated in CRM
    val moneyMutated: Boolean,                 // Invariant: CRM changes money is prohibited
    val evidenceReference: String,
    val serverTime: Instant,
)

interface PrivilegedAdminBoundaryStore {
    fun findByIdempotency(tenantId: String, idempotencyKey: String): Pair<String, PrivilegedAdminResult>?
    fun save(
        result: PrivilegedAdminResult,
        tenantId: String,
        queryFingerprint: String,
        idempotencyKey: String,
        audit: AuditEvent,
        outbox: OutboxEvent,
    )
}

class PrivilegedAdminBoundaryService(
    private val policy: AdminRbacPolicy,
    private val sessions: AdminSessionDirectory,
    private val store: PrivilegedAdminBoundaryStore,
    private val clock: Clock = Clock.systemUTC(),
) {
    @Synchronized
    fun executePrivilegedOperation(command: PrivilegedAdminCommand): PrivilegedAdminResult {
        // Enforce boundary invariant: CRM can never change money or duplicate finance authority
        if (command.operation == PrivilegedAdminOperation.DIRECT_FINANCIAL_ADJUSTMENT ||
            command.operation == PrivilegedAdminOperation.DIRECT_BALANCE_MUTATION ||
            (command.requestedAmountMinorUnits != null && command.requestedAmountMinorUnits > 0L)
        ) {
            throw AuthenticationFailure.Rejected(AuthErrorCode.FORBIDDEN)
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

        val permitted = when (command.operation) {
            PrivilegedAdminOperation.RECORD_SUPPORT_INTERACTION,
            PrivilegedAdminOperation.UPDATE_COMMUNICATION_PREFERENCE ->
                policy.isPermitted(principal, AdminPermission.MANAGE_SUPPORT) ||
                    policy.isPermitted(principal, AdminPermission.MANAGE_SECURITY)
            PrivilegedAdminOperation.REQUEST_ACCOUNT_FLAG ->
                policy.isPermitted(principal, AdminPermission.MANAGE_SECURITY)
            PrivilegedAdminOperation.DIRECT_FINANCIAL_ADJUSTMENT,
            PrivilegedAdminOperation.DIRECT_BALANCE_MUTATION -> false
        }

        if (!permitted) {
            throw AuthenticationFailure.Rejected(AuthErrorCode.FORBIDDEN)
        }

        if (command.subjectReference.isBlank() ||
            command.sessionId.isBlank() ||
            command.correlationId.isBlank() ||
            command.causationId.isBlank()
        ) {
            throw AuthenticationFailure.Rejected(AuthErrorCode.INVALID)
        }

        if (command.expectedVersion != 1L) {
            throw AuthenticationFailure.Rejected(AuthErrorCode.STALE)
        }

        val fp = fingerprint(command)
        store.findByIdempotency(command.tenantId, command.idempotencyKey)?.let { (cachedFp, cachedResult) ->
            if (cachedFp != fp) throw AuthenticationFailure.Rejected(AuthErrorCode.CONFLICT)
            return cachedResult
        }

        val resultId = UUID.randomUUID()
        val now = clock.instant()
        val result = PrivilegedAdminResult(
            resultId = resultId,
            tenantId = command.tenantId,
            subjectReference = command.subjectReference,
            operation = command.operation,
            status = PrivilegedExecutionStatus.EXECUTED,
            financialAuthorityDuplicated = false, // Finance authority never duplicated in CRM
            moneyMutated = false,                 // CRM changes money is prohibited
            evidenceReference = "EVID-CRM-${command.subjectReference}",
            serverTime = now,
        )

        val audit = AuditEvent(
            eventId = UUID.randomUUID(),
            resultId = resultId,
            tenantId = command.tenantId,
            type = "PRIVILEGED_ADMIN_${command.operation.name}",
            occurredAt = now,
            correlationId = command.correlationId,
            causationId = command.causationId,
        )

        val outbox = OutboxEvent(
            eventId = UUID.randomUUID(),
            resultId = resultId,
            tenantId = command.tenantId,
            type = "PRIVILEGED_ADMIN_${command.operation.name}",
            createdAt = now,
        )

        store.save(result, command.tenantId, fp, command.idempotencyKey, audit, outbox)
        return result
    }

    private fun fingerprint(command: PrivilegedAdminCommand): String {
        val md = MessageDigest.getInstance("SHA-256")
        val raw = "${command.tenantId}:${command.subjectReference}:${command.operation}:${command.expectedVersion}:${command.details}"
        return md.digest(raw.toByteArray(Charsets.UTF_8)).joinToString("") { "%02x".format(it) }
    }
}
