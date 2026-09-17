package com.slotting.admin.reconciliation

import com.slotting.admin.auth.*
import java.security.MessageDigest
import java.time.Clock
import java.time.Instant
import java.util.UUID

enum class ReconciliationExceptionState { OPEN, ASSIGNED, RESOLVED, CLOSED }
enum class ReconciliationExceptionAction { CREATE, ASSIGN, CLOSE, WAIVE }

data class ReconciliationExceptionCommand(
    val principal: AuthenticatedPrincipal?,
    val sessionId: String,
    val tenantId: String,
    val exceptionReference: String,
    val reportReference: String,
    val action: ReconciliationExceptionAction,
    val currencyCode: String,
    val discrepancyMinorUnits: Long,
    val externalReference: String,
    val ledgerEntryReference: String,
    val assigneeId: String? = null,
    val reasonCode: String? = null,
    val resolutionNotes: String? = null,
    val approverId: String? = null,
    val idempotencyKey: String,
    val correlationId: String,
    val causationId: String,
    val expectedVersion: Long,
)

data class ReconciliationException(
    val exceptionReference: String,
    val reportReference: String,
    val currencyCode: String,
    val discrepancyMinorUnits: Long,
    val externalReference: String,
    val ledgerEntryReference: String,
    val state: ReconciliationExceptionState,
    val assigneeId: String?,
    val reasonCode: String?,
    val resolutionNotes: String?,
    val approverId: String?,
    val exportChecksumSha256: String,
    val serverVersion: Long,
)

data class ReconciliationExceptionResult(
    val resultId: UUID,
    val exception: ReconciliationException,
    val serverTime: Instant,
    val evidenceReference: String,
)

interface ReconciliationExceptionStore {
    fun findByIdempotency(tenantId: String, key: String): Pair<String, ReconciliationExceptionResult>?
    fun findException(tenantId: String, exceptionReference: String): ReconciliationException?
    fun save(
        result: ReconciliationExceptionResult,
        tenantId: String,
        queryFingerprint: String,
        idempotencyKey: String,
        audit: AuditEvent,
        outbox: OutboxEvent,
    )
}

class ReconciliationExceptionService(
    private val policy: AdminRbacPolicy,
    private val sessions: AdminSessionDirectory,
    private val store: ReconciliationExceptionStore,
    private val clock: Clock = Clock.systemUTC(),
) {
    @Synchronized
    fun operate(command: ReconciliationExceptionCommand): ReconciliationExceptionResult {
        val principal = command.principal ?: throw AuthenticationFailure.Rejected(AuthErrorCode.UNAUTHENTICATED)
        val fingerprint = fingerprint(command)
        store.findByIdempotency(command.tenantId, command.idempotencyKey)?.let { replay ->
            if (replay.first != fingerprint) throw AuthenticationFailure.Rejected(AuthErrorCode.CONFLICT)
            return replay.second
        }

        if (principal.kind != PrincipalKind.ADMIN || principal.tenantId != command.tenantId) {
            throw AuthenticationFailure.Rejected(AuthErrorCode.FORBIDDEN)
        }

        if (command.exceptionReference.isBlank() || command.exceptionReference.length > 128 ||
            command.reportReference.isBlank() || command.reportReference.length > 128 ||
            command.sessionId.isBlank() || command.correlationId.isBlank() || command.causationId.isBlank() ||
            !command.currencyCode.matches(Regex("[A-Z]{3}")) ||
            command.discrepancyMinorUnits < 0L) {
            throw AuthenticationFailure.Rejected(AuthErrorCode.INVALID)
        }

        val now = Instant.now(clock)
        val session = try {
            sessions.find(command.tenantId, principal.id, command.sessionId)
        } catch (_: Exception) {
            throw AuthenticationFailure.Rejected(AuthErrorCode.DEPENDENCY_UNAVAILABLE)
        }
        if (session == null || !session.active || !session.expiresAt.isAfter(now)) {
            throw AuthenticationFailure.Rejected(AuthErrorCode.FORBIDDEN)
        }

        // Ledger imbalance cannot be waived
        if (command.action == ReconciliationExceptionAction.WAIVE) {
            throw AuthenticationFailure.Rejected(AuthErrorCode.FORBIDDEN)
        }

        val requiredPerm = when (command.action) {
            ReconciliationExceptionAction.CREATE -> AdminPermission.READ_AUDIT
            ReconciliationExceptionAction.ASSIGN -> AdminPermission.MANAGE_SUPPORT
            ReconciliationExceptionAction.CLOSE -> AdminPermission.MANAGE_SUPPORT
            ReconciliationExceptionAction.WAIVE -> AdminPermission.MANAGE_SECURITY
        }
        if (!policy.isPermitted(principal, requiredPerm) &&
            !policy.isPermitted(principal, AdminPermission.READ_SUPPORT) &&
            !policy.isPermitted(principal, AdminPermission.MANAGE_SECURITY)) {
            throw AuthenticationFailure.Rejected(AuthErrorCode.FORBIDDEN)
        }

        val nextException = when (command.action) {
            ReconciliationExceptionAction.CREATE -> {
                val existing = store.findException(command.tenantId, command.exceptionReference)
                if (existing != null) throw AuthenticationFailure.Rejected(AuthErrorCode.CONFLICT)
                val checksum = computeChecksum(command.tenantId, command.exceptionReference, command.reportReference, command.currencyCode, command.discrepancyMinorUnits, ReconciliationExceptionState.OPEN, null)
                ReconciliationException(
                    exceptionReference = command.exceptionReference,
                    reportReference = command.reportReference,
                    currencyCode = command.currencyCode,
                    discrepancyMinorUnits = command.discrepancyMinorUnits,
                    externalReference = command.externalReference,
                    ledgerEntryReference = command.ledgerEntryReference,
                    state = ReconciliationExceptionState.OPEN,
                    assigneeId = command.assigneeId,
                    reasonCode = null,
                    resolutionNotes = null,
                    approverId = null,
                    exportChecksumSha256 = checksum,
                    serverVersion = 1L,
                )
            }
            ReconciliationExceptionAction.ASSIGN -> {
                val existing = store.findException(command.tenantId, command.exceptionReference)
                    ?: throw AuthenticationFailure.Rejected(AuthErrorCode.FORBIDDEN)
                if (existing.serverVersion != command.expectedVersion) throw AuthenticationFailure.Rejected(AuthErrorCode.STALE)
                if (command.assigneeId.isNullOrBlank()) throw AuthenticationFailure.Rejected(AuthErrorCode.INVALID)
                val checksum = computeChecksum(command.tenantId, command.exceptionReference, existing.reportReference, existing.currencyCode, existing.discrepancyMinorUnits, ReconciliationExceptionState.ASSIGNED, existing.reasonCode)
                existing.copy(
                    state = ReconciliationExceptionState.ASSIGNED,
                    assigneeId = command.assigneeId,
                    exportChecksumSha256 = checksum,
                    serverVersion = existing.serverVersion + 1L,
                )
            }
            ReconciliationExceptionAction.CLOSE -> {
                val existing = store.findException(command.tenantId, command.exceptionReference)
                    ?: throw AuthenticationFailure.Rejected(AuthErrorCode.FORBIDDEN)
                if (existing.serverVersion != command.expectedVersion) throw AuthenticationFailure.Rejected(AuthErrorCode.STALE)
                if (command.reasonCode.isNullOrBlank() || command.resolutionNotes.isNullOrBlank() || command.approverId.isNullOrBlank()) {
                    throw AuthenticationFailure.Rejected(AuthErrorCode.INVALID)
                }
                val checksum = computeChecksum(command.tenantId, command.exceptionReference, existing.reportReference, existing.currencyCode, existing.discrepancyMinorUnits, ReconciliationExceptionState.CLOSED, command.reasonCode)
                existing.copy(
                    state = ReconciliationExceptionState.CLOSED,
                    reasonCode = command.reasonCode,
                    resolutionNotes = command.resolutionNotes,
                    approverId = command.approverId,
                    exportChecksumSha256 = checksum,
                    serverVersion = existing.serverVersion + 1L,
                )
            }
            ReconciliationExceptionAction.WAIVE -> throw AuthenticationFailure.Rejected(AuthErrorCode.FORBIDDEN)
        }

        val resultId = UUID.randomUUID()
        val result = ReconciliationExceptionResult(
            resultId = resultId,
            exception = nextException,
            serverTime = now,
            evidenceReference = "reconciliation-exception:$resultId",
        )

        val type = "RECONCILIATION_EXCEPTION_${command.action.name}"
        val audit = AuditEvent(UUID.randomUUID(), resultId, command.tenantId, type, now, command.correlationId, command.causationId)
        val outbox = OutboxEvent(UUID.randomUUID(), resultId, command.tenantId, type, now)
        store.save(result, command.tenantId, fingerprint, command.idempotencyKey, audit, outbox)
        return result
    }

    private fun computeChecksum(
        tenantId: String,
        exceptionRef: String,
        reportRef: String,
        currency: String,
        amount: Long,
        state: ReconciliationExceptionState,
        reason: String?,
    ): String = sha256("$tenantId:$exceptionRef:$reportRef:$currency:$amount:${state.name}:${reason ?: ""}")

    private fun fingerprint(command: ReconciliationExceptionCommand): String = listOf(
        command.tenantId,
        command.exceptionReference,
        command.reportReference,
        command.action,
        command.currencyCode,
        command.discrepancyMinorUnits,
        command.externalReference,
        command.ledgerEntryReference,
        command.assigneeId,
        command.reasonCode,
        command.resolutionNotes,
        command.approverId,
        command.expectedVersion,
    ).joinToString("|") { sha256(it.toString()) }

    private fun sha256(value: String): String = MessageDigest.getInstance("SHA-256")
        .digest(value.toByteArray(Charsets.UTF_8))
        .joinToString("") { "%02x".format(it) }
}
