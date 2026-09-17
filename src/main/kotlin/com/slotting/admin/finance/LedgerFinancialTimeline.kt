package com.slotting.admin.finance

import com.slotting.admin.auth.AdminPermission
import com.slotting.admin.auth.AdminRbacPolicy
import com.slotting.admin.auth.AdminSessionDirectory
import com.slotting.admin.auth.AuthErrorCode
import com.slotting.admin.auth.AuthenticatedPrincipal
import com.slotting.admin.auth.AuthenticationFailure
import com.slotting.admin.auth.AuditEvent
import com.slotting.admin.auth.OutboxEvent
import com.slotting.admin.player.AccessReasonCode
import java.security.MessageDigest
import java.time.Clock
import java.time.Instant
import java.util.UUID

enum class TimelineState { FOUND, EMPTY }

data class LedgerMoney(val minorUnits: Long, val currencyCode: String) {
    init {
        require(currencyCode.matches(Regex("[A-Z]{3}")))
    }
}

data class LedgerEntry(
    val ledgerEntryId: String,
    val playerReference: String,
    val occurredAt: Instant,
    val entryType: String,
    val value: LedgerMoney,
)

data class LedgerTimelineCommand(
    val principal: AuthenticatedPrincipal?,
    val sessionId: String,
    val tenantId: String,
    val playerReference: String,
    val from: Instant,
    val to: Instant,
    val accessReason: AccessReasonCode,
    val idempotencyKey: String,
    val correlationId: String,
    val causationId: String,
    val expectedVersion: Long,
    val limit: Int = 100,
)

data class LedgerTimelinePage(val entries: List<LedgerEntry>, val ledgerVersion: Long)

data class LedgerTimelineResult(
    val resultId: UUID,
    val state: TimelineState,
    val entries: List<LedgerEntry>,
    val ledgerVersion: Long,
    val serverTime: Instant,
    val serverVersion: Long,
    val evidenceReference: String,
)

interface AuthoritativeLedgerReader {
    fun read(tenantId: String, playerReference: String, from: Instant, to: Instant, limit: Int): LedgerTimelinePage
}

interface LedgerTimelineStore {
    fun findByIdempotency(tenantId: String, key: String): Pair<String, LedgerTimelineResult>?
    fun currentVersion(tenantId: String): Long
    fun save(
        result: LedgerTimelineResult,
        tenantId: String,
        idempotencyKey: String,
        queryFingerprint: String,
        accessReason: AccessReasonCode,
        audit: AuditEvent,
        outbox: OutboxEvent,
    )
}

class LedgerFinancialTimeline(
    private val policy: AdminRbacPolicy,
    private val sessions: AdminSessionDirectory,
    private val ledger: AuthoritativeLedgerReader,
    private val store: LedgerTimelineStore,
    private val clock: Clock = Clock.systemUTC(),
) {
    @Synchronized
    fun read(command: LedgerTimelineCommand): LedgerTimelineResult {
        val principal = command.principal ?: throw AuthenticationFailure.Rejected(AuthErrorCode.UNAUTHENTICATED)
        val fingerprint = fingerprint(command)
        store.findByIdempotency(command.tenantId, command.idempotencyKey)?.let { replay ->
            if (replay.first != fingerprint) throw AuthenticationFailure.Rejected(AuthErrorCode.CONFLICT)
            return replay.second
        }
        if (principal.kind != com.slotting.admin.auth.PrincipalKind.ADMIN || principal.tenantId != command.tenantId) {
            throw AuthenticationFailure.Rejected(AuthErrorCode.FORBIDDEN)
        }
        if (
            command.playerReference.isBlank() || command.playerReference.length > 128 ||
            command.from >= command.to || command.limit !in 1..100 ||
            command.correlationId.isBlank() || command.causationId.isBlank() || command.sessionId.isBlank()) {
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
        val page = try {
            ledger.read(command.tenantId, command.playerReference, command.from, command.to, command.limit)
        } catch (_: Exception) {
            throw AuthenticationFailure.Rejected(AuthErrorCode.DEPENDENCY_UNAVAILABLE)
        }
        val resultId = UUID.randomUUID()
        val result = LedgerTimelineResult(
            resultId,
            if (page.entries.isEmpty()) TimelineState.EMPTY else TimelineState.FOUND,
            page.entries,
            page.ledgerVersion,
            now,
            command.expectedVersion + 1,
            "ledger-timeline:$resultId",
        )
        val audit = AuditEvent(UUID.randomUUID(), resultId, command.tenantId, "LEDGER_TIMELINE_READ", now, command.correlationId, command.causationId)
        val outbox = OutboxEvent(UUID.randomUUID(), resultId, command.tenantId, "LEDGER_TIMELINE_READ", now)
        store.save(result, command.tenantId, command.idempotencyKey, fingerprint, command.accessReason, audit, outbox)
        return result
    }

    private fun fingerprint(command: LedgerTimelineCommand): String = listOf(
        command.tenantId,
        command.playerReference,
        command.from,
        command.to,
        command.accessReason,
        command.limit,
    ).joinToString("|") { sha256(it.toString()) }

    private fun sha256(value: String): String = MessageDigest.getInstance("SHA-256")
        .digest(value.toByteArray(Charsets.UTF_8))
        .joinToString("") { "%02x".format(it) }
}
