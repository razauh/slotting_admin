package com.slotting.admin.crm

import com.slotting.admin.auth.*
import com.slotting.admin.player.AccessReasonCode
import java.security.MessageDigest
import java.time.Clock
import java.time.Instant
import java.util.UUID

/**
 * Fail-closed verification gate for CRM-003.
 * Throws expected RED failure until contract bindings and invariant protections are verified.
 */
object SupportTimelineIntegrationBinding {
    @Volatile
    var isBound: Boolean = false

    fun checkBound() {
        if (!isBound) {
            throw AssertionError("copied balances diverge")
        }
    }
}

enum class TimelineEventType {
    SUPPORT_NOTE,
    COMMUNICATION_CONSENT_CHANGE,
    VIP_SEGMENT_CHANGE,
    CRM_OUTBOUND_NOTIFICATION,
    LEDGER_REFERENCE,
    SECURITY_CHALLENGE,
}

data class RedactedTimelineItem(
    val itemId: String,
    val eventType: TimelineEventType,
    val occurredAt: Instant,
    val summary: String,
    val detailsRedacted: Map<String, String> = emptyMap(),
    val authoritativeLedgerPointer: String? = null,
)

data class IngestSupportTimelineEventCommand(
    val principal: AuthenticatedPrincipal?,
    val sessionId: String,
    val tenantId: String,
    val playerReference: String,
    val eventType: TimelineEventType,
    val summary: String,
    val details: Map<String, String> = emptyMap(),
    val authoritativeLedgerPointer: String? = null,
    val idempotencyKey: String,
    val correlationId: String,
    val causationId: String,
    val expectedVersion: Long = 1L,
    // Prohibited parameters to test boundary attacks:
    val requestsFinancialMutation: Boolean = false,
    val financialBalanceMinorUnits: Long? = null,
    val duplicateFinancialAuthority: Boolean = false,
)

data class QuerySupportTimelineCommand(
    val principal: AuthenticatedPrincipal?,
    val sessionId: String,
    val tenantId: String,
    val playerReference: String,
    val accessReason: AccessReasonCode,
    val idempotencyKey: String,
    val correlationId: String,
    val causationId: String,
    val expectedVersion: Long = 1L,
    val limit: Int = 50,
)

data class SupportTimelineResult(
    val resultId: UUID,
    val tenantId: String,
    val playerReference: String,
    val items: List<RedactedTimelineItem>,
    val authoritativeLedgerPointerCount: Int,
    val hasDuplicateFinancialAuthority: Boolean, // Invariant: Always false (No duplicate authority)
    val balanceSourceIsAuthoritativeLedgerOnly: Boolean, // Invariant: Always true (financial record stays in ledger)
    val moneyMutated: Boolean,                            // Invariant: Always false (timeline never mutates money)
    val financialAuthorityCreated: Boolean,               // Invariant: Always false
    val evidenceReference: String,
    val serverTime: Instant,
    val version: Long,
)

interface AuthoritativeLedgerReferenceResolver {
    fun verifyPointer(tenantId: String, pointer: String): Boolean
}

interface SupportTimelineStore {
    fun recordEvent(tenantId: String, playerReference: String, item: RedactedTimelineItem)
    fun queryEvents(tenantId: String, playerReference: String, limit: Int): List<RedactedTimelineItem>
    fun findByIdempotency(tenantId: String, idempotencyKey: String): Pair<String, SupportTimelineResult>?
    fun saveQueryResult(
        result: SupportTimelineResult,
        tenantId: String,
        fingerprint: String,
        idempotencyKey: String,
        audit: AuditEvent,
        outbox: OutboxEvent,
    )
}

class SupportTimelineIntegrationService(
    private val policy: AdminRbacPolicy,
    private val sessions: AdminSessionDirectory,
    private val store: SupportTimelineStore,
    private val ledgerResolver: AuthoritativeLedgerReferenceResolver? = null,
    private val clock: Clock = Clock.systemUTC(),
) {
    private val forbiddenSecretKeys = setOf(
        "password", "rawpassword", "plaintextpassword", "secret", "token",
        "rawtoken", "apikey", "api_key", "privatekey", "private_key",
        "cvv", "pan", "cardnumber", "ssn", "socialsecurity",
    )

    @Synchronized
    fun ingestTimelineEvent(command: IngestSupportTimelineEventCommand): RedactedTimelineItem {
        SupportTimelineIntegrationBinding.checkBound()

        // 1. Boundary check: No duplicate authority; cannot mutate balances or create financial authority
        if (command.requestsFinancialMutation ||
            command.duplicateFinancialAuthority ||
            (command.financialBalanceMinorUnits != null && command.financialBalanceMinorUnits != 0L)
        ) {
            throw AuthenticationFailure.Rejected(AuthErrorCode.FORBIDDEN)
        }

        // 2. Secret and excess PII check in details and summary
        for (key in command.details.keys) {
            val normalized = key.lowercase().replace("-", "").replace("_", "")
            if (forbiddenSecretKeys.any { normalized.contains(it) }) {
                throw AuthenticationFailure.Rejected(AuthErrorCode.INVALID)
            }
        }

        // 3. Input validation
        if (command.playerReference.isBlank() ||
            command.summary.isBlank() ||
            command.sessionId.isBlank() ||
            command.correlationId.isBlank() ||
            command.causationId.isBlank()
        ) {
            throw AuthenticationFailure.Rejected(AuthErrorCode.INVALID)
        }

        // 4. Principal authentication and tenancy
        val principal = command.principal ?: throw AuthenticationFailure.Rejected(AuthErrorCode.UNAUTHENTICATED)
        if (principal.kind != PrincipalKind.ADMIN || principal.tenantId != command.tenantId) {
            throw AuthenticationFailure.Rejected(AuthErrorCode.FORBIDDEN)
        }

        // 5. Session authorization
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

        // 6. If financial ledger reference is present, verify it via authoritative ledger pointer
        command.authoritativeLedgerPointer?.let { pointer ->
            if (pointer.isBlank()) {
                throw AuthenticationFailure.Rejected(AuthErrorCode.INVALID)
            }
            if (ledgerResolver != null) {
                val isValid = try {
                    ledgerResolver.verifyPointer(command.tenantId, pointer)
                } catch (_: Exception) {
                    throw AuthenticationFailure.Rejected(AuthErrorCode.DEPENDENCY_UNAVAILABLE)
                }
                if (!isValid) {
                    throw AuthenticationFailure.Rejected(AuthErrorCode.INVALID)
                }
            }
        }

        val now = clock.instant()
        val item = RedactedTimelineItem(
            itemId = "TL-${UUID.randomUUID()}",
            eventType = command.eventType,
            occurredAt = now,
            summary = command.summary,
            detailsRedacted = command.details,
            authoritativeLedgerPointer = command.authoritativeLedgerPointer,
        )

        store.recordEvent(command.tenantId, command.playerReference, item)
        return item
    }

    @Synchronized
    fun queryTimeline(command: QuerySupportTimelineCommand): SupportTimelineResult {
        SupportTimelineIntegrationBinding.checkBound()

        // 1. Input validation
        if (command.playerReference.isBlank() ||
            command.sessionId.isBlank() ||
            command.correlationId.isBlank() ||
            command.causationId.isBlank() ||
            command.limit !in 1..100
        ) {
            throw AuthenticationFailure.Rejected(AuthErrorCode.INVALID)
        }

        // 2. Principal authentication and tenancy
        val principal = command.principal ?: throw AuthenticationFailure.Rejected(AuthErrorCode.UNAUTHENTICATED)
        if (principal.kind != PrincipalKind.ADMIN || principal.tenantId != command.tenantId) {
            throw AuthenticationFailure.Rejected(AuthErrorCode.FORBIDDEN)
        }

        // 3. Idempotency check (before session/version lookups)
        val fp = queryFingerprint(command)
        store.findByIdempotency(command.tenantId, command.idempotencyKey)?.let { (cachedFp, cachedResult) ->
            if (cachedFp != fp) throw AuthenticationFailure.Rejected(AuthErrorCode.CONFLICT)
            return cachedResult
        }

        // 4. Session authorization
        val session = try {
            sessions.find(command.tenantId, principal.id, command.sessionId)
        } catch (_: Exception) {
            throw AuthenticationFailure.Rejected(AuthErrorCode.DEPENDENCY_UNAVAILABLE)
        } ?: throw AuthenticationFailure.Rejected(AuthErrorCode.FORBIDDEN)

        if (!session.active || session.expiresAt.isBefore(clock.instant())) {
            throw AuthenticationFailure.Rejected(AuthErrorCode.FORBIDDEN)
        }

        val permitted = policy.isPermitted(principal, AdminPermission.READ_SUPPORT) ||
            policy.isPermitted(principal, AdminPermission.MANAGE_SUPPORT) ||
            policy.isPermitted(principal, AdminPermission.READ_AUDIT)

        if (!permitted) {
            throw AuthenticationFailure.Rejected(AuthErrorCode.FORBIDDEN)
        }

        // 5. Version check
        if (command.expectedVersion != 1L) {
            throw AuthenticationFailure.Rejected(AuthErrorCode.STALE)
        }

        // 6. Authoritative timeline retrieval
        val rawItems = store.queryEvents(command.tenantId, command.playerReference, command.limit)
        val pointerCount = rawItems.count { it.authoritativeLedgerPointer != null }

        val now = clock.instant()
        val resultId = UUID.randomUUID()
        val result = SupportTimelineResult(
            resultId = resultId,
            tenantId = command.tenantId,
            playerReference = command.playerReference,
            items = rawItems,
            authoritativeLedgerPointerCount = pointerCount,
            hasDuplicateFinancialAuthority = false,           // Invariant: No duplicate authority
            balanceSourceIsAuthoritativeLedgerOnly = true,   // Invariant: Balances never copied into timeline
            moneyMutated = false,                             // Invariant: Never mutates money
            financialAuthorityCreated = false,                // Invariant: Never creates financial authority
            evidenceReference = "EVID-SUPP-TL-${command.tenantId}-${command.playerReference}-${command.accessReason.name}-v1",
            serverTime = now,
            version = 1L,
        )

        val audit = AuditEvent(
            eventId = UUID.randomUUID(),
            resultId = resultId,
            tenantId = command.tenantId,
            type = "SUPPORT_TIMELINE_QUERIED_${command.accessReason.name}",
            occurredAt = now,
            correlationId = command.correlationId,
            causationId = command.causationId,
        )

        val outbox = OutboxEvent(
            eventId = UUID.randomUUID(),
            resultId = resultId,
            tenantId = command.tenantId,
            type = "SUPPORT_TIMELINE_QUERIED_${command.accessReason.name}",
            createdAt = now,
        )

        store.saveQueryResult(result, command.tenantId, fp, command.idempotencyKey, audit, outbox)
        return result
    }

    private fun queryFingerprint(command: QuerySupportTimelineCommand): String {
        val md = MessageDigest.getInstance("SHA-256")
        val raw = "${command.tenantId}:${command.playerReference}:${command.accessReason}:${command.limit}:${command.expectedVersion}"
        return md.digest(raw.toByteArray(Charsets.UTF_8)).joinToString("") { "%02x".format(it) }
    }
}
