package com.slotting.admin.crm

import com.slotting.admin.auth.*
import java.security.MessageDigest
import java.time.Clock
import java.time.Instant
import java.util.UUID

/**
 * Fail-closed verification gate for CRM-001.
 * Throws expected RED failure until contract bindings and invariant protections are verified.
 */
object ExternalCrmContractBinding {
    @Volatile
    var isBound: Boolean = false

    fun checkBound() {
        if (!isBound) {
            throw AssertionError("CRM can mutate authority/receives excess PII")
        }
    }
}

enum class ExternalCrmEventType {
    PLAYER_REGISTERED,
    PLAYER_TIER_UPDATED,
    COMMUNICATION_PREFERENCE_UPDATED,
    MARKETING_SUPPRESSED,
    ACCOUNT_DELETED,
}

enum class ExternalCrmEventStatus {
    DISPATCHED,
    SUPPRESSED_CONFIRMED,
    DELETED_CONFIRMED,
    REJECTED,
}

data class ExternalCrmEventPayload(
    val externalCrmId: String,
    val playerReference: String,
    val maskedEmail: String? = null,
    val locale: String? = null,
    val countryCode: String? = null,
    val tier: String? = null,
    val marketingConsent: Boolean? = null,
    val suppressionReason: String? = null,
    val attributes: Map<String, String> = emptyMap(),
)

data class PublishExternalCrmEventCommand(
    val principal: AuthenticatedPrincipal?,
    val sessionId: String,
    val tenantId: String,
    val eventType: ExternalCrmEventType,
    val payload: ExternalCrmEventPayload,
    val idempotencyKey: String,
    val correlationId: String,
    val causationId: String,
    val expectedVersion: Long = 1L,
    val financialBalanceMinorUnits: Long? = null,
    val attemptsFinancialMutation: Boolean = false,
)

data class ExternalCrmEventResult(
    val resultId: UUID,
    val tenantId: String,
    val playerReference: String,
    val externalCrmId: String,
    val eventType: ExternalCrmEventType,
    val status: ExternalCrmEventStatus,
    val suppressionPropagated: Boolean,
    val deletionPropagated: Boolean,
    val financialRecordInLedgerOnly: Boolean, // Invariant: Always true (financial authority stays in ledger)
    val moneyMutated: Boolean,                // Invariant: Always false (CRM never mutates money)
    val externalAckToken: String,
    val evidenceReference: String,
    val serverTime: Instant,
    val version: Long,
)

data class ExternalCrmDispatchResult(
    val success: Boolean,
    val ackToken: String,
    val dispatchedAt: Instant,
)

interface ExternalCrmPort {
    fun dispatchEvent(
        tenantId: String,
        eventType: ExternalCrmEventType,
        payload: ExternalCrmEventPayload,
    ): ExternalCrmDispatchResult

    fun propagateSuppression(
        tenantId: String,
        playerReference: String,
        externalCrmId: String,
        reason: String,
    ): ExternalCrmDispatchResult

    fun propagateDeletion(
        tenantId: String,
        playerReference: String,
        externalCrmId: String,
    ): ExternalCrmDispatchResult
}

interface ExternalCrmEventStore {
    fun findByIdempotency(tenantId: String, idempotencyKey: String): Pair<String, ExternalCrmEventResult>?
    fun save(
        result: ExternalCrmEventResult,
        tenantId: String,
        fingerprint: String,
        idempotencyKey: String,
        audit: AuditEvent,
        outbox: OutboxEvent,
    )
}

class ExternalCrmContractService(
    private val policy: AdminRbacPolicy,
    private val sessions: AdminSessionDirectory,
    private val crmPort: ExternalCrmPort,
    private val store: ExternalCrmEventStore,
    private val clock: Clock = Clock.systemUTC(),
) {
    private val forbiddenFinancialKeys = setOf(
        "balance", "minorunit", "amount", "wallet",
        "ledger", "credit", "debit", "bankaccount",
        "accountnumber", "cardnumber", "pan", "cvv",
        "wager", "deposit", "payout"
    )

    private val forbiddenPiiKeys = setOf(
        "ssn", "socialsecurity", "passport", "nationalid",
        "password", "secret", "apikey", "token", "privatekey"
    )

    @Synchronized
    fun publishCrmEvent(command: PublishExternalCrmEventCommand): ExternalCrmEventResult {
        ExternalCrmContractBinding.checkBound()

        // 1. Boundary check: Financial record stays in ledger; CRM cannot mutate money
        if (command.attemptsFinancialMutation ||
            (command.financialBalanceMinorUnits != null && command.financialBalanceMinorUnits != 0L)
        ) {
            throw AuthenticationFailure.Rejected(AuthErrorCode.FORBIDDEN)
        }

        // Check attributes for financial authority leakage
        for (key in command.payload.attributes.keys) {
            val normalizedKey = key.lowercase().replace("-", "").replace("_", "")
            if (forbiddenFinancialKeys.any { normalizedKey.contains(it) }) {
                throw AuthenticationFailure.Rejected(AuthErrorCode.FORBIDDEN)
            }
        }

        // 2. Data minimization check: Prohibit excess PII and raw secrets
        for (key in command.payload.attributes.keys) {
            val normalizedKey = key.lowercase().replace("-", "").replace("_", "")
            if (forbiddenPiiKeys.any { normalizedKey.contains(it) }) {
                throw AuthenticationFailure.Rejected(AuthErrorCode.INVALID)
            }
        }

        // Masked email must not be raw/unmasked email (if present and contains @, must contain *)
        command.payload.maskedEmail?.let { email ->
            if (email.contains("@") && !email.contains("*")) {
                throw AuthenticationFailure.Rejected(AuthErrorCode.INVALID)
            }
        }

        // 3. Input validation
        if (command.payload.playerReference.isBlank() ||
            command.payload.externalCrmId.isBlank() ||
            command.sessionId.isBlank() ||
            command.correlationId.isBlank() ||
            command.causationId.isBlank()
        ) {
            throw AuthenticationFailure.Rejected(AuthErrorCode.INVALID)
        }

        // 4. Authentication & Authorization
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

        // 5. Version check
        if (command.expectedVersion != 1L) {
            throw AuthenticationFailure.Rejected(AuthErrorCode.STALE)
        }

        // 6. Idempotency check
        val fp = fingerprint(command)
        store.findByIdempotency(command.tenantId, command.idempotencyKey)?.let { (cachedFp, cachedResult) ->
            if (cachedFp != fp) throw AuthenticationFailure.Rejected(AuthErrorCode.CONFLICT)
            return cachedResult
        }

        // 7. Dispatch or propagate to external CRM
        val dispatchResult = try {
            when (command.eventType) {
                ExternalCrmEventType.MARKETING_SUPPRESSED -> {
                    crmPort.propagateSuppression(
                        tenantId = command.tenantId,
                        playerReference = command.payload.playerReference,
                        externalCrmId = command.payload.externalCrmId,
                        reason = command.payload.suppressionReason ?: "MARKETING_OPT_OUT",
                    )
                }
                ExternalCrmEventType.ACCOUNT_DELETED -> {
                    crmPort.propagateDeletion(
                        tenantId = command.tenantId,
                        playerReference = command.payload.playerReference,
                        externalCrmId = command.payload.externalCrmId,
                    )
                }
                else -> {
                    crmPort.dispatchEvent(
                        tenantId = command.tenantId,
                        eventType = command.eventType,
                        payload = command.payload,
                    )
                }
            }
        } catch (_: Exception) {
            throw AuthenticationFailure.Rejected(AuthErrorCode.DEPENDENCY_UNAVAILABLE)
        }

        if (!dispatchResult.success) {
            throw AuthenticationFailure.Rejected(AuthErrorCode.DEPENDENCY_UNAVAILABLE)
        }

        val now = clock.instant()
        val resultId = UUID.randomUUID()
        val suppressionPropagated = command.eventType == ExternalCrmEventType.MARKETING_SUPPRESSED
        val deletionPropagated = command.eventType == ExternalCrmEventType.ACCOUNT_DELETED

        val status = when {
            suppressionPropagated -> ExternalCrmEventStatus.SUPPRESSED_CONFIRMED
            deletionPropagated -> ExternalCrmEventStatus.DELETED_CONFIRMED
            else -> ExternalCrmEventStatus.DISPATCHED
        }

        val result = ExternalCrmEventResult(
            resultId = resultId,
            tenantId = command.tenantId,
            playerReference = command.payload.playerReference,
            externalCrmId = command.payload.externalCrmId,
            eventType = command.eventType,
            status = status,
            suppressionPropagated = suppressionPropagated,
            deletionPropagated = deletionPropagated,
            financialRecordInLedgerOnly = true, // Finance authority never duplicated or mutated in CRM
            moneyMutated = false,               // CRM never mutates money
            externalAckToken = dispatchResult.ackToken,
            evidenceReference = "EVID-CRM-EVT-${command.tenantId}-${command.payload.playerReference}-${command.eventType.name}",
            serverTime = now,
            version = 1L,
        )

        val audit = AuditEvent(
            eventId = UUID.randomUUID(),
            resultId = resultId,
            tenantId = command.tenantId,
            type = "CRM_EXTERNAL_EVENT_${command.eventType.name}",
            occurredAt = now,
            correlationId = command.correlationId,
            causationId = command.causationId,
        )

        val outbox = OutboxEvent(
            eventId = UUID.randomUUID(),
            resultId = resultId,
            tenantId = command.tenantId,
            type = "CRM_EXTERNAL_EVENT_${command.eventType.name}",
            createdAt = now,
        )

        store.save(result, command.tenantId, fp, command.idempotencyKey, audit, outbox)
        return result
    }

    private fun fingerprint(command: PublishExternalCrmEventCommand): String {
        val md = MessageDigest.getInstance("SHA-256")
        val raw = "${command.tenantId}:${command.payload.playerReference}:${command.payload.externalCrmId}:${command.eventType}:${command.expectedVersion}:${command.payload}"
        return md.digest(raw.toByteArray(Charsets.UTF_8)).joinToString("") { "%02x".format(it) }
    }
}
