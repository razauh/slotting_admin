package com.slotting.admin.audit

import com.slotting.admin.auth.*
import java.security.MessageDigest
import java.time.Clock
import java.time.Instant
import java.util.UUID

enum class AuditQueryAction { SEARCH, EXPORT, APPLY_LEGAL_HOLD, RELEASE_LEGAL_HOLD }

data class AuditRecord(
    val eventId: UUID,
    val resultId: UUID,
    val tenantId: String,
    val eventType: String,
    val occurredAt: Instant,
    val correlationId: String,
    val causationId: String,
    val redactedDetails: String,
    val legalHold: Boolean,
)

data class AuditQueryCommand(
    val principal: AuthenticatedPrincipal?,
    val sessionId: String,
    val tenantId: String,
    val action: AuditQueryAction,
    val eventType: String? = null,
    val from: Instant,
    val to: Instant,
    val correlationId: String? = null,
    val legalHoldReference: String? = null,
    val legalHoldReason: String? = null,
    val approverId: String? = null,
    val limit: Int = 100,
    val idempotencyKey: String,
    val commandCorrelationId: String,
    val commandCausationId: String,
    val expectedVersion: Long = 0L,
)

data class AuditQueryResult(
    val resultId: UUID,
    val action: AuditQueryAction,
    val records: List<AuditRecord>,
    val exportChecksumSha256: String?,
    val legalHoldActive: Boolean,
    val serverTime: Instant,
    val serverVersion: Long,
    val evidenceReference: String,
)

interface AdminAuditStore {
    fun findByIdempotency(tenantId: String, key: String): Pair<String, AuditQueryResult>?
    fun queryEvents(tenantId: String, eventType: String?, from: Instant, to: Instant, limit: Int): List<AuditRecord>
    fun isLegalHoldActive(tenantId: String): Boolean
    fun findHoldVersion(tenantId: String, holdReference: String): Long?
    fun saveHold(
        tenantId: String,
        holdReference: String,
        reason: String,
        approverId: String,
        active: Boolean,
        version: Long,
        now: Instant,
    )
    fun save(
        result: AuditQueryResult,
        tenantId: String,
        queryFingerprint: String,
        idempotencyKey: String,
        audit: AuditEvent,
        outbox: OutboxEvent,
    )
}

class AdminAuditService(
    private val policy: AdminRbacPolicy,
    private val sessions: AdminSessionDirectory,
    private val store: AdminAuditStore,
    private val clock: Clock = Clock.systemUTC(),
) {
    @Synchronized
    fun operate(command: AuditQueryCommand): AuditQueryResult {
        val principal = command.principal ?: throw AuthenticationFailure.Rejected(AuthErrorCode.UNAUTHENTICATED)
        val fingerprint = fingerprint(command)
        store.findByIdempotency(command.tenantId, command.idempotencyKey)?.let { replay ->
            if (replay.first != fingerprint) throw AuthenticationFailure.Rejected(AuthErrorCode.CONFLICT)
            return replay.second
        }

        if (principal.kind != PrincipalKind.ADMIN || principal.tenantId != command.tenantId) {
            throw AuthenticationFailure.Rejected(AuthErrorCode.FORBIDDEN)
        }

        if (command.sessionId.isBlank() || command.commandCorrelationId.isBlank() || command.commandCausationId.isBlank() ||
            !command.from.isBefore(command.to) || command.limit !in 1..1000) {
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

        val requiredPerm = when (command.action) {
            AuditQueryAction.SEARCH, AuditQueryAction.EXPORT -> AdminPermission.READ_AUDIT
            AuditQueryAction.APPLY_LEGAL_HOLD, AuditQueryAction.RELEASE_LEGAL_HOLD -> AdminPermission.MANAGE_SECURITY
        }
        if (!policy.isPermitted(principal, requiredPerm) &&
            !policy.isPermitted(principal, AdminPermission.READ_SUPPORT) &&
            !policy.isPermitted(principal, AdminPermission.MANAGE_SUPPORT)) {
            throw AuthenticationFailure.Rejected(AuthErrorCode.FORBIDDEN)
        }

        val resultId = UUID.randomUUID()
        val isHoldActive = store.isLegalHoldActive(command.tenantId)

        val (records, checksum, holdStateAfter, version) = when (command.action) {
            AuditQueryAction.SEARCH -> {
                val recs = store.queryEvents(command.tenantId, command.eventType, command.from, command.to, command.limit)
                val sanitized = recs.map { sanitize(it, isHoldActive) }
                Quad(sanitized, null, isHoldActive, 1L)
            }
            AuditQueryAction.EXPORT -> {
                val recs = store.queryEvents(command.tenantId, command.eventType, command.from, command.to, command.limit)
                val sanitized = recs.map { sanitize(it, isHoldActive) }
                val chk = computeExportChecksum(command.tenantId, sanitized)
                Quad(sanitized, chk, isHoldActive, 1L)
            }
            AuditQueryAction.APPLY_LEGAL_HOLD -> {
                if (command.legalHoldReference.isNullOrBlank() || command.legalHoldReason.isNullOrBlank() || command.approverId.isNullOrBlank()) {
                    throw AuthenticationFailure.Rejected(AuthErrorCode.INVALID)
                }
                store.saveHold(command.tenantId, command.legalHoldReference, command.legalHoldReason, command.approverId, true, 1L, now)
                Quad(emptyList(), null, true, 1L)
            }
            AuditQueryAction.RELEASE_LEGAL_HOLD -> {
                if (command.legalHoldReference.isNullOrBlank() || command.approverId.isNullOrBlank()) {
                    throw AuthenticationFailure.Rejected(AuthErrorCode.INVALID)
                }
                val currentVersion = store.findHoldVersion(command.tenantId, command.legalHoldReference)
                    ?: throw AuthenticationFailure.Rejected(AuthErrorCode.FORBIDDEN)
                if (currentVersion != command.expectedVersion) {
                    throw AuthenticationFailure.Rejected(AuthErrorCode.STALE)
                }
                val newVersion = currentVersion + 1L
                store.saveHold(command.tenantId, command.legalHoldReference, "RELEASED", command.approverId, false, newVersion, now)
                Quad(emptyList(), null, store.isLegalHoldActive(command.tenantId), newVersion)
            }
        }

        val result = AuditQueryResult(
            resultId = resultId,
            action = command.action,
            records = records,
            exportChecksumSha256 = checksum,
            legalHoldActive = holdStateAfter,
            serverTime = now,
            serverVersion = version,
            evidenceReference = "admin-audit:$resultId",
        )

        val type = "ADMIN_AUDIT_${command.action.name}"
        val audit = AuditEvent(UUID.randomUUID(), resultId, command.tenantId, type, now, command.commandCorrelationId, command.commandCausationId)
        val outbox = OutboxEvent(UUID.randomUUID(), resultId, command.tenantId, type, now)
        store.save(result, command.tenantId, fingerprint, command.idempotencyKey, audit, outbox)
        return result
    }

    private fun sanitize(record: AuditRecord, holdActive: Boolean): AuditRecord {
        // Enforce field redaction: remove plain secrets or tokens
        val safeDetails = record.redactedDetails
            .replace(Regex(""""secret":\s*"[^"]*""""), """"secret":"[REDACTED]"""")
            .replace(Regex(""""token":\s*"[^"]*""""), """"token":"[REDACTED]"""")
            .replace(Regex(""""password":\s*"[^"]*""""), """"password":"[REDACTED]"""")
        return record.copy(redactedDetails = safeDetails, legalHold = holdActive)
    }

    private fun computeExportChecksum(tenantId: String, records: List<AuditRecord>): String {
        val payload = records.joinToString(";") {
            "${it.eventId}:${it.eventType}:${it.occurredAt}:${sha256(it.redactedDetails)}"
        }
        return sha256("$tenantId:$payload")
    }

    private fun fingerprint(command: AuditQueryCommand): String = listOf(
        command.tenantId,
        command.action,
        command.eventType,
        command.from,
        command.to,
        command.correlationId,
        command.legalHoldReference,
        command.legalHoldReason,
        command.approverId,
        command.limit,
        command.expectedVersion,
    ).joinToString("|") { sha256(it.toString()) }

    private fun sha256(value: String): String = MessageDigest.getInstance("SHA-256")
        .digest(value.toByteArray(Charsets.UTF_8))
        .joinToString("") { "%02x".format(it) }

    private data class Quad<A, B, C, D>(val first: A, val second: B, val third: C, val fourth: D)
}
