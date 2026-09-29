package com.slotting.admin.ban

import com.slotting.admin.auth.*
import com.slotting.admin.identity.DeviceInventoryStore
import com.slotting.admin.identity.DeviceSessionStatus
import com.slotting.admin.identity.TokenRevocationReason
import com.slotting.admin.restriction.DurableServerRestrictionStore
import com.slotting.admin.restriction.RestrictionScope
import com.slotting.admin.restriction.RestrictionSource
import com.slotting.admin.restriction.ServerRestrictionRecord
import java.security.MessageDigest
import java.time.Clock
import java.time.Instant
import java.util.UUID

/**
 * TC-027 Authoritative Administrative Ban and Unban Service.
 * Implements durable administrative ban management, RBAC enforcement,
 * multi-device session revocation, optimistic concurrency, and TC-026 restriction projection.
 */
class AdministrativeBanService(
    private val policy: AdminRbacPolicy,
    private val sessions: AdminSessionDirectory,
    private val banStore: DurableAdministrativeBanStore,
    private val restrictionStore: DurableServerRestrictionStore,
    private val deviceStore: DeviceInventoryStore? = null,
    private val clock: Clock = Clock.systemUTC()
) {

    @Synchronized
    fun issueBan(command: IssueBanCommand): AdministrativeBanResult {
        val now = clock.instant()
        val principal = validateAuthorization(command.principal, command.sessionId, command.tenantId)

        validateIssueCommand(command, now)

        val fp = issueFingerprint(command)
        banStore.findByIdempotency(command.tenantId, command.idempotencyKey)?.let { (cachedFp, cachedResult) ->
            if (cachedFp != fp) {
                throw AuthenticationFailure.Rejected(AuthErrorCode.CONFLICT)
            }
            return cachedResult
        }

        // Prevent double ban
        val existingActive = banStore.findActiveBanBySubject(command.tenantId, command.subjectReference, now)
        if (existingActive != null) {
            throw AuthenticationFailure.Rejected(AuthErrorCode.CONFLICT)
        }

        val banId = UUID.randomUUID()
        val banRecord = AdministrativeBanRecord(
            banId = banId,
            tenantId = command.tenantId,
            subjectReference = command.subjectReference,
            banType = command.banType,
            reasonCategory = command.reasonCategory,
            reasonCode = command.reasonCode,
            permittedNote = command.permittedNote,
            internalNote = command.internalNote,
            issuerId = principal.id,
            effectiveFrom = command.effectiveFrom,
            expiresAt = command.expiresAt,
            caseReferenceId = command.caseReferenceId,
            status = BanStatus.ACTIVE,
            version = 1L,
            createdAt = now,
            updatedAt = now
        )

        // TC-026 Restriction Record projection
        val restrictionRecord = ServerRestrictionRecord(
            restrictionId = banId,
            tenantId = command.tenantId,
            subjectReference = command.subjectReference,
            source = RestrictionSource.ADMINISTRATIVE_BAN,
            reasonCode = command.reasonCode,
            safeUserMessage = command.permittedNote,
            scope = RestrictionScope.WholeAccount,
            effectiveFrom = command.effectiveFrom,
            expiresAt = command.expiresAt,
            evidenceReference = command.caseReferenceId,
            ruleVersion = 1L,
            issuer = principal.id,
            active = true
        )

        val auditEvent = AuditEvent(
            eventId = UUID.randomUUID(),
            resultId = banId,
            tenantId = command.tenantId,
            type = "ADMIN_BAN_ISSUED",
            occurredAt = now,
            correlationId = command.correlationId,
            causationId = command.causationId
        )

        val outboxEvent = OutboxEvent(
            eventId = UUID.randomUUID(),
            resultId = banId,
            tenantId = command.tenantId,
            type = "ADMIN_BAN_ISSUED",
            createdAt = now
        )

        // Revoke active sessions across all devices for this subject
        var revokedCount = 0
        val subjectAsUuid = runCatching { UUID.fromString(command.subjectReference) }.getOrNull()
        if (subjectAsUuid != null && deviceStore != null) {
            val playerSessions = deviceStore.findSessionsByPlayer(command.tenantId, subjectAsUuid)
            for (sess in playerSessions) {
                if (sess.status == DeviceSessionStatus.ACTIVE) {
                    sess.status = DeviceSessionStatus.REVOKED
                    sess.revocationReason = TokenRevocationReason.SECURITY_POLICY
                    sess.revokedAt = now
                    deviceStore.saveSession(sess)
                    revokedCount++
                }
            }
        }

        banStore.saveBan(banRecord, auditEvent, outboxEvent)
        restrictionStore.saveRestriction(restrictionRecord)

        val result = AdministrativeBanResult(
            ban = banRecord,
            auditEvent = auditEvent,
            outboxEvent = outboxEvent,
            sessionsRevokedCount = revokedCount,
            restrictionRecord = restrictionRecord
        )

        banStore.saveIdempotency(command.tenantId, command.idempotencyKey, fp, result)
        return result
    }

    @Synchronized
    fun reverseBan(command: ReverseBanCommand): AdministrativeBanResult {
        val now = clock.instant()
        val principal = validateAuthorization(command.principal, command.sessionId, command.tenantId)

        validateReverseCommand(command)

        val fp = reverseFingerprint(command)
        banStore.findByIdempotency(command.tenantId, command.idempotencyKey)?.let { (cachedFp, cachedResult) ->
            if (cachedFp != fp) {
                throw AuthenticationFailure.Rejected(AuthErrorCode.CONFLICT)
            }
            return cachedResult
        }

        val existing = banStore.findBanById(command.tenantId, command.banId)
            ?: throw AuthenticationFailure.Rejected(AuthErrorCode.INVALID)

        if (existing.status != BanStatus.ACTIVE) {
            throw AuthenticationFailure.Rejected(AuthErrorCode.CONFLICT)
        }

        if (existing.version != command.expectedVersion) {
            throw AuthenticationFailure.Rejected(AuthErrorCode.STALE)
        }

        val updatedBan = existing.copy(
            status = BanStatus.REVERSED,
            reversedAt = now,
            reversedBy = principal.id,
            reversalReason = command.reversalReason,
            version = existing.version + 1L,
            updatedAt = now
        )

        val auditEvent = AuditEvent(
            eventId = UUID.randomUUID(),
            resultId = updatedBan.banId,
            tenantId = command.tenantId,
            type = "ADMIN_BAN_REVERSED",
            occurredAt = now,
            correlationId = command.correlationId,
            causationId = command.causationId
        )

        val outboxEvent = OutboxEvent(
            eventId = UUID.randomUUID(),
            resultId = updatedBan.banId,
            tenantId = command.tenantId,
            type = "ADMIN_BAN_REVERSED",
            createdAt = now
        )

        banStore.updateBan(updatedBan, auditEvent, outboxEvent)

        // Revoke restriction in TC-026 store so policy matrix allows access
        restrictionStore.revokeRestriction(command.tenantId, existing.banId, principal.id, now)

        val updatedRestriction = ServerRestrictionRecord(
            restrictionId = existing.banId,
            tenantId = command.tenantId,
            subjectReference = command.subjectReference,
            source = RestrictionSource.ADMINISTRATIVE_BAN,
            reasonCode = existing.reasonCode,
            safeUserMessage = existing.permittedNote,
            scope = RestrictionScope.WholeAccount,
            effectiveFrom = existing.effectiveFrom,
            expiresAt = existing.expiresAt,
            evidenceReference = existing.caseReferenceId,
            ruleVersion = updatedBan.version,
            issuer = principal.id,
            active = false
        )

        val result = AdministrativeBanResult(
            ban = updatedBan,
            auditEvent = auditEvent,
            outboxEvent = outboxEvent,
            sessionsRevokedCount = 0,
            restrictionRecord = updatedRestriction
        )

        banStore.saveIdempotency(command.tenantId, command.idempotencyKey, fp, result)
        return result
    }

    @Synchronized
    fun evaluateExpiry(tenantId: String, subjectReference: String, now: Instant): AdministrativeBanRecord? {
        val candidate = banStore.findAllBansForSubject(tenantId, subjectReference)
            .firstOrNull { it.status == BanStatus.ACTIVE } ?: return null

        if (candidate.expiresAt != null && !now.isBefore(candidate.expiresAt)) {
            val expiredBan = candidate.copy(
                status = BanStatus.EXPIRED,
                version = candidate.version + 1L,
                updatedAt = now
            )
            val auditEvent = AuditEvent(
                eventId = UUID.randomUUID(),
                resultId = expiredBan.banId,
                tenantId = tenantId,
                type = "ADMIN_BAN_EXPIRED",
                occurredAt = now,
                correlationId = "expiry-${expiredBan.banId}",
                causationId = "cron-eval"
            )
            val outboxEvent = OutboxEvent(
                eventId = UUID.randomUUID(),
                resultId = expiredBan.banId,
                tenantId = tenantId,
                type = "ADMIN_BAN_EXPIRED",
                createdAt = now
            )
            banStore.updateBan(expiredBan, auditEvent, outboxEvent)
            restrictionStore.revokeRestriction(tenantId, expiredBan.banId, "SYSTEM_EXPIRY", now)
            return expiredBan
        }

        return candidate
    }

    private fun validateAuthorization(
        principal: AuthenticatedPrincipal?,
        sessionId: String,
        tenantId: String
    ): AuthenticatedPrincipal {
        if (principal == null) {
            throw AuthenticationFailure.Rejected(AuthErrorCode.UNAUTHENTICATED)
        }
        if (principal.kind != PrincipalKind.ADMIN || principal.tenantId != tenantId) {
            throw AuthenticationFailure.Rejected(AuthErrorCode.FORBIDDEN)
        }
        val session = sessions.find(tenantId, principal.id, sessionId)
            ?: throw AuthenticationFailure.Rejected(AuthErrorCode.FORBIDDEN)

        if (!session.active || session.expiresAt.isBefore(clock.instant())) {
            throw AuthenticationFailure.Rejected(AuthErrorCode.FORBIDDEN)
        }

        if (!policy.isPermitted(principal, AdminPermission.RESTRICTIONS_MANAGE)) {
            throw AuthenticationFailure.Rejected(AuthErrorCode.FORBIDDEN)
        }

        return principal
    }

    private fun validateIssueCommand(command: IssueBanCommand, now: Instant) {
        if (command.tenantId.isBlank() ||
            command.subjectReference.isBlank() ||
            command.reasonCode.isBlank() ||
            command.permittedNote.isBlank() ||
            command.caseReferenceId.isBlank() ||
            command.correlationId.isBlank() ||
            command.causationId.isBlank() ||
            command.idempotencyKey.isBlank()
        ) {
            throw AuthenticationFailure.Rejected(AuthErrorCode.INVALID)
        }

        if (command.banType == BanType.PERMANENT) {
            if (command.expiresAt != null) {
                throw AuthenticationFailure.Rejected(AuthErrorCode.INVALID)
            }
        } else {
            if (command.expiresAt == null || !command.expiresAt.isAfter(command.effectiveFrom) || !command.expiresAt.isAfter(now)) {
                throw AuthenticationFailure.Rejected(AuthErrorCode.INVALID)
            }
        }
    }

    private fun validateReverseCommand(command: ReverseBanCommand) {
        if (command.tenantId.isBlank() ||
            command.subjectReference.isBlank() ||
            command.reversalReason.isBlank() ||
            command.caseReferenceId.isBlank() ||
            command.correlationId.isBlank() ||
            command.causationId.isBlank() ||
            command.idempotencyKey.isBlank()
        ) {
            throw AuthenticationFailure.Rejected(AuthErrorCode.INVALID)
        }
        if (command.expectedVersion < 1L) {
            throw AuthenticationFailure.Rejected(AuthErrorCode.STALE)
        }
    }

    private fun issueFingerprint(command: IssueBanCommand): String {
        val md = MessageDigest.getInstance("SHA-256")
        val raw = "${command.tenantId}:${command.subjectReference}:${command.banType}:${command.reasonCode}:${command.effectiveFrom}:${command.expiresAt}"
        return md.digest(raw.toByteArray(Charsets.UTF_8)).joinToString("") { "%02x".format(it) }
    }

    private fun reverseFingerprint(command: ReverseBanCommand): String {
        val md = MessageDigest.getInstance("SHA-256")
        val raw = "${command.tenantId}:${command.banId}:${command.reversalReason}:${command.expectedVersion}"
        return md.digest(raw.toByteArray(Charsets.UTF_8)).joinToString("") { "%02x".format(it) }
    }
}
