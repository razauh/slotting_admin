package com.slotting.admin.player

import com.slotting.admin.auth.AdminPermission
import com.slotting.admin.auth.AdminRbacPolicy
import com.slotting.admin.auth.AdminSessionDirectory
import com.slotting.admin.auth.AuthErrorCode
import com.slotting.admin.auth.AuthenticatedPrincipal
import com.slotting.admin.auth.AuthenticationFailure
import com.slotting.admin.auth.AuditEvent
import com.slotting.admin.auth.OutboxEvent
import com.slotting.admin.auth.PrincipalKind
import java.security.MessageDigest
import java.time.Clock
import java.time.Instant
import java.util.UUID

enum class PlayerSearchField { PLAYER_REFERENCE, EMAIL_EXACT }
enum class ProfileSearchState { FOUND, EMPTY }
enum class AccessReasonCode { SUPPORT_REQUEST, SECURITY_INVESTIGATION, AUDIT_REVIEW }

data class PlayerProfileSearchCommand(
    val principal: AuthenticatedPrincipal?,
    val sessionId: String,
    val tenantId: String,
    val field: PlayerSearchField,
    val exactTerm: String,
    val accessReason: AccessReasonCode,
    val idempotencyKey: String,
    val correlationId: String,
    val causationId: String,
    val expectedVersion: Long,
    val limit: Int = 20,
)

data class LedgerLink(val playerReference: String, val ledgerReference: String, val asOf: Instant)

data class PlayerProfileReadModel(
    val playerReference: String,
    val displayName: String?,
    val ledgerLink: LedgerLink,
)

data class ProfileSearchResult(
    val resultId: UUID,
    val state: ProfileSearchState,
    val profiles: List<PlayerProfileReadModel>,
    val serverTime: Instant,
    val serverVersion: Long,
    val evidenceReference: String,
)

interface PlayerProfileReadRepository {
    fun search(tenantId: String, field: PlayerSearchField, exactTerm: String, limit: Int): List<PlayerProfileReadModel>
}

interface ProfileSearchStore {
    fun findByIdempotency(tenantId: String, key: String): Pair<String, ProfileSearchResult>?
    fun currentVersion(tenantId: String): Long
    fun save(
        result: ProfileSearchResult,
        tenantId: String,
        idempotencyKey: String,
        queryFingerprint: String,
        accessReason: AccessReasonCode,
        audit: AuditEvent,
        outbox: OutboxEvent,
    )
}

class ScopedPlayerProfileSearch(
    private val policy: AdminRbacPolicy,
    private val sessions: AdminSessionDirectory,
    private val profiles: PlayerProfileReadRepository,
    private val store: ProfileSearchStore,
    private val clock: Clock = Clock.systemUTC(),
) {
    @Synchronized
    fun search(command: PlayerProfileSearchCommand): ProfileSearchResult {
        val principal = command.principal ?: throw AuthenticationFailure.Rejected(AuthErrorCode.UNAUTHENTICATED)
        val fingerprint = fingerprint(command)
        store.findByIdempotency(command.tenantId, command.idempotencyKey)?.let { replay ->
            if (replay.first != fingerprint) throw AuthenticationFailure.Rejected(AuthErrorCode.CONFLICT)
            return replay.second
        }
        if (principal.kind != PrincipalKind.ADMIN || principal.tenantId != command.tenantId) {
            throw AuthenticationFailure.Rejected(AuthErrorCode.FORBIDDEN)
        }
        if (command.exactTerm.isBlank() || command.exactTerm.length > 128 || command.sessionId.isBlank() ||
            command.correlationId.isBlank() || command.causationId.isBlank() || command.limit !in 1..20) {
            throw AuthenticationFailure.Rejected(AuthErrorCode.INVALID)
        }
        if (command.expectedVersion != store.currentVersion(command.tenantId)) {
            throw AuthenticationFailure.Rejected(AuthErrorCode.STALE)
        }
        val now = Instant.now(clock)
        val session = sessions.find(command.tenantId, principal.id, command.sessionId)
        if (session == null || !session.active || !session.expiresAt.isAfter(now) ||
            !policy.isPermitted(principal, AdminPermission.READ_SUPPORT)) {
            throw AuthenticationFailure.Rejected(AuthErrorCode.FORBIDDEN)
        }
        val rows = try {
            profiles.search(command.tenantId, command.field, command.exactTerm, command.limit)
        } catch (_: Exception) {
            throw AuthenticationFailure.Rejected(AuthErrorCode.DEPENDENCY_UNAVAILABLE)
        }
        val resultId = UUID.randomUUID()
        val result = ProfileSearchResult(
            resultId,
            if (rows.isEmpty()) ProfileSearchState.EMPTY else ProfileSearchState.FOUND,
            rows,
            now,
            command.expectedVersion + 1,
            "player-profile-search:$resultId",
        )
        val audit = AuditEvent(UUID.randomUUID(), resultId, command.tenantId, "PLAYER_PROFILE_SEARCH", now, command.correlationId, command.causationId)
        val outbox = OutboxEvent(UUID.randomUUID(), resultId, command.tenantId, "PLAYER_PROFILE_SEARCH", now)
        store.save(result, command.tenantId, command.idempotencyKey, fingerprint, command.accessReason, audit, outbox)
        return result
    }

    private fun fingerprint(command: PlayerProfileSearchCommand): String = listOf(
        command.tenantId,
        command.field,
        sha256(command.exactTerm),
        command.accessReason,
        command.limit,
    ).joinToString("|")

    private fun sha256(value: String): String = MessageDigest.getInstance("SHA-256")
        .digest(value.toByteArray(Charsets.UTF_8))
        .joinToString("") { "%02x".format(it) }
}
