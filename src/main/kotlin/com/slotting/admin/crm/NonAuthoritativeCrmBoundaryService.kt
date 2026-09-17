package com.slotting.admin.crm

import com.slotting.admin.auth.*
import java.security.MessageDigest
import java.time.Clock
import java.time.Instant
import java.util.UUID

enum class CrmIntegrationOperation {
    SYNC_CUSTOMER_PROFILE,
    INGEST_EXTERNAL_TICKET,
    QUERY_REDACTED_SUMMARY,
    DIRECT_FINANCIAL_SYNC,
    CREDIT_WALLET_ADJUSTMENT,
}

enum class CrmSyncStatus {
    SYNCHRONIZED,
    ACCEPTED_NON_AUTHORITATIVE,
    REJECTED,
}

data class CrmSyncCommand(
    val principal: AuthenticatedPrincipal?,
    val sessionId: String,
    val tenantId: String,
    val subjectReference: String,
    val operation: CrmIntegrationOperation,
    val externalCrmId: String,
    val payload: Map<String, String> = emptyMap(),
    val financialBalanceMinorUnits: Long? = null, // Prohibited! CRM cannot pass financial balances or money
    val idempotencyKey: String,
    val correlationId: String,
    val causationId: String,
    val expectedVersion: Long = 1L,
)

data class CrmSyncResult(
    val resultId: UUID,
    val tenantId: String,
    val subjectReference: String,
    val externalCrmId: String,
    val operation: CrmIntegrationOperation,
    val status: CrmSyncStatus,
    val isAuthoritative: Boolean,             // Invariant: Always false! CRM is non-authoritative
    val financialAuthorityDuplicated: Boolean, // Invariant: Finance authority never duplicated in CRM
    val moneyMutated: Boolean,                 // Invariant: CRM changes money is prohibited
    val evidenceReference: String,
    val serverTime: Instant,
)

interface NonAuthoritativeCrmStore {
    fun findByIdempotency(tenantId: String, idempotencyKey: String): Pair<String, CrmSyncResult>?
    fun save(
        result: CrmSyncResult,
        tenantId: String,
        queryFingerprint: String,
        idempotencyKey: String,
        audit: AuditEvent,
        outbox: OutboxEvent,
    )
}

class NonAuthoritativeCrmBoundaryService(
    private val policy: AdminRbacPolicy,
    private val sessions: AdminSessionDirectory,
    private val store: NonAuthoritativeCrmStore,
    private val clock: Clock = Clock.systemUTC(),
) {
    @Synchronized
    fun processCrmSync(command: CrmSyncCommand): CrmSyncResult {
        // Enforce boundary invariant: CRM can never change money or duplicate finance authority
        if (command.operation == CrmIntegrationOperation.DIRECT_FINANCIAL_SYNC ||
            command.operation == CrmIntegrationOperation.CREDIT_WALLET_ADJUSTMENT ||
            (command.financialBalanceMinorUnits != null && command.financialBalanceMinorUnits != 0L)
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

        val permitted = policy.isPermitted(principal, AdminPermission.MANAGE_SUPPORT) ||
            policy.isPermitted(principal, AdminPermission.READ_SUPPORT) ||
            policy.isPermitted(principal, AdminPermission.MANAGE_SECURITY)

        if (!permitted) {
            throw AuthenticationFailure.Rejected(AuthErrorCode.FORBIDDEN)
        }

        if (command.subjectReference.isBlank() ||
            command.externalCrmId.isBlank() ||
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
        val result = CrmSyncResult(
            resultId = resultId,
            tenantId = command.tenantId,
            subjectReference = command.subjectReference,
            externalCrmId = command.externalCrmId,
            operation = command.operation,
            status = CrmSyncStatus.SYNCHRONIZED,
            isAuthoritative = false,              // CRM is strictly non-authoritative
            financialAuthorityDuplicated = false, // Finance authority never duplicated in CRM
            moneyMutated = false,                 // CRM changes money is prohibited
            evidenceReference = "EVID-CRM-SYNC-${command.subjectReference}",
            serverTime = now,
        )

        val audit = AuditEvent(
            eventId = UUID.randomUUID(),
            resultId = resultId,
            tenantId = command.tenantId,
            type = "CRM_NON_AUTHORITATIVE_SYNC_${command.operation.name}",
            occurredAt = now,
            correlationId = command.correlationId,
            causationId = command.causationId,
        )

        val outbox = OutboxEvent(
            eventId = UUID.randomUUID(),
            resultId = resultId,
            tenantId = command.tenantId,
            type = "CRM_NON_AUTHORITATIVE_SYNC_${command.operation.name}",
            createdAt = now,
        )

        store.save(result, command.tenantId, fp, command.idempotencyKey, audit, outbox)
        return result
    }

    private fun fingerprint(command: CrmSyncCommand): String {
        val md = MessageDigest.getInstance("SHA-256")
        val raw = "${command.tenantId}:${command.subjectReference}:${command.externalCrmId}:${command.operation}:${command.expectedVersion}:${command.payload}"
        return md.digest(raw.toByteArray(Charsets.UTF_8)).joinToString("") { "%02x".format(it) }
    }
}
