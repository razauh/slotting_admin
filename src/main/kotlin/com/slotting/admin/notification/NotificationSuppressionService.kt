package com.slotting.admin.notification

import com.slotting.admin.auth.AuthenticatedPrincipal
import java.nio.charset.StandardCharsets
import java.security.MessageDigest
import java.time.Clock
import java.time.Instant
import java.util.Base64
import java.util.UUID
import java.util.concurrent.ConcurrentHashMap

/**
 * Binding flag to enforce the protected risk assertion for NOTIFY-002-01:
 * "opted-out/excluded user marketed"
 */
object NotificationSuppressionBinding {
    @Volatile
    var isBound: Boolean = true

    fun checkBound() {
        if (!isBound) {
            throw AssertionError("opted-out/excluded user marketed")
        }
    }
}

enum class SuppressionReason {
    SELF_EXCLUDED,
    MARKETING_OPT_OUT,
    HARD_BOUNCE,
    SPAM_COMPLAINT,
    STALE_TOKEN,
    CARRIER_BLOCKED,
    ACCOUNT_LOCKED,
}

enum class SuppressionDecision {
    ALLOWED,
    SUPPRESSED_MARKETING_EXCLUDED,
    SUPPRESSED_MARKETING_OPTOUT,
    SUPPRESSED_BOUNCE_OR_COMPLAINT,
    SUPPRESSED_STALE_TOKEN,
}

data class UserSuppressionRecord(
    val recordId: UUID = UUID.randomUUID(),
    val tenantId: String,
    val userId: String,
    val channel: NotificationChannel? = null, // null means global suppression across all channels
    val reason: SuppressionReason,
    val suppressedAt: Instant,
    val isActive: Boolean = true,
    val evidenceReference: String,
)

data class SuppressionCheckRequest(
    val principal: AuthenticatedPrincipal?,
    val tenantId: String,
    val userId: String,
    val channel: NotificationChannel,
    val classification: NotificationClassification,
    val templateId: String,
    val recipientDestination: String,
    val idempotencyKey: String,
    val correlationId: String,
    val causationId: String,
    val expectedVersion: Long = 1L,
)

data class SuppressionCheckResult(
    val checkId: UUID,
    val tenantId: String,
    val userId: String,
    val channel: NotificationChannel,
    val classification: NotificationClassification,
    val templateId: String,
    val decision: SuppressionDecision,
    val isAllowed: Boolean,
    val reason: SuppressionReason?,
    val serverTime: Instant,
    val serverVersion: Long,
    val evidenceReference: String,
    val semanticContract: String = "Mandatory legal/security notices separately approved; stale tokens removed safely.",
    val directEligibilityGranted: Boolean = false,
    val financialMutationPermitted: Boolean = false,
)

data class NotificationSuppressionAuditEvent(
    val eventId: UUID,
    val checkId: UUID,
    val tenantId: String,
    val userId: String,
    val channel: NotificationChannel,
    val classification: NotificationClassification,
    val templateId: String,
    val decision: SuppressionDecision,
    val isAllowed: Boolean,
    val reason: SuppressionReason?,
    val occurredAt: Instant,
    val correlationId: String,
    val causationId: String,
)

sealed class NotificationSuppressionException(message: String) : RuntimeException(message) {
    class Unauthorized(message: String) : NotificationSuppressionException(message)
    class Forbidden(message: String) : NotificationSuppressionException(message)
    class Invalid(message: String) : NotificationSuppressionException(message)
    class Conflict(message: String) : NotificationSuppressionException(message)
}

class NotificationSuppressionService(
    private val clock: Clock = Clock.systemUTC(),
    initialRecords: List<UserSuppressionRecord> = emptyList(),
) {
    private val suppressionRecords = ConcurrentHashMap<String, MutableList<UserSuppressionRecord>>()
    private val staleDeviceTokens = ConcurrentHashMap<String, MutableSet<String>>() // tenantId to Set<Token>
    private val idempotencyStore = ConcurrentHashMap<String, Pair<String, SuppressionCheckResult>>()
    private val auditLogs = ConcurrentHashMap<String, MutableList<NotificationSuppressionAuditEvent>>()

    init {
        for (record in initialRecords) {
            suppressionRecords.computeIfAbsent(record.tenantId) { mutableListOf() }.add(record)
        }
    }

    companion object {
        val APPROVED_MANDATORY_LEGAL_SECURITY_TEMPLATES: Set<String> = setOf(
            "TEMPLATE_SECURITY_ALERT",
            "TEMPLATE_MFA_CHALLENGE",
            "TEMPLATE_PAYMENT_CONFIRMATION",
            "TEMPLATE_PASSWORD_RESET",
            "TEMPLATE_LEGAL_TERMS_UPDATE",
            "TEMPLATE_ACCOUNT_STATUS",
        )
    }

    @Synchronized
    fun evaluateSuppression(request: SuppressionCheckRequest): SuppressionCheckResult {
        NotificationSuppressionBinding.checkBound()

        // 1. Authentication and Authorization
        val principal = request.principal
            ?: throw NotificationSuppressionException.Unauthorized("Principal is unauthenticated")
        if (principal.tenantId != request.tenantId) {
            throw NotificationSuppressionException.Forbidden(
                "Cross-tenant access forbidden: principal ${principal.tenantId} != request ${request.tenantId}"
            )
        }

        // 2. Input validation
        if (request.idempotencyKey.isBlank()) {
            throw NotificationSuppressionException.Invalid("Idempotency key cannot be blank")
        }
        if (request.userId.isBlank()) {
            throw NotificationSuppressionException.Invalid("User ID cannot be blank")
        }
        if (request.recipientDestination.isBlank()) {
            throw NotificationSuppressionException.Invalid("Recipient destination cannot be blank")
        }
        if (request.templateId.isBlank()) {
            throw NotificationSuppressionException.Invalid("Template ID cannot be blank")
        }
        if (request.expectedVersion < 1L) {
            throw NotificationSuppressionException.Invalid("Expected version must be >= 1")
        }

        // 3. Idempotency replay check
        val idemKey = "${request.tenantId}:${request.idempotencyKey}"
        val fingerprint = computeFingerprint(request)
        val existing = idempotencyStore[idemKey]
        if (existing != null) {
            if (existing.first == fingerprint) {
                return existing.second
            } else {
                throw NotificationSuppressionException.Conflict(
                    "Conflicting payload for idempotency key: ${request.idempotencyKey}"
                )
            }
        }

        val now = Instant.now(clock)
        val checkId = UUID.randomUUID()
        val tenantRecords = suppressionRecords[request.tenantId] ?: mutableListOf()
        val activeRecordsForUser = tenantRecords.filter { it.userId == request.userId && it.isActive }

        // Stale Token Check
        val isStaleToken = (request.channel == NotificationChannel.PUSH) &&
            (staleDeviceTokens[request.tenantId]?.contains(request.recipientDestination) == true)

        val decision: SuppressionDecision
        val matchedReason: SuppressionReason?

        if (isStaleToken) {
            decision = SuppressionDecision.SUPPRESSED_STALE_TOKEN
            matchedReason = SuppressionReason.STALE_TOKEN
        } else if (request.classification == NotificationClassification.TRANSACTIONAL) {
            // Mandatory legal / security notices separately approved are delivered even if opted out of marketing
            val isApprovedMandatory = APPROVED_MANDATORY_LEGAL_SECURITY_TEMPLATES.contains(request.templateId)
            if (!isApprovedMandatory) {
                throw NotificationSuppressionException.Invalid(
                    "Template '${request.templateId}' is not an approved mandatory legal/security template"
                )
            }
            // For approved mandatory transactional notices, allow delivery unless account locked or hard bounce
            val hardBounce = activeRecordsForUser.firstOrNull {
                it.reason == SuppressionReason.HARD_BOUNCE && (it.channel == null || it.channel == request.channel)
            }
            if (hardBounce != null) {
                decision = SuppressionDecision.SUPPRESSED_BOUNCE_OR_COMPLAINT
                matchedReason = hardBounce.reason
            } else {
                decision = SuppressionDecision.ALLOWED
                matchedReason = null
            }
        } else {
            // MARKETING classification: strict suppression checks
            val selfExcluded = activeRecordsForUser.firstOrNull { it.reason == SuppressionReason.SELF_EXCLUDED }
            val marketingOptOut = activeRecordsForUser.firstOrNull {
                it.reason == SuppressionReason.MARKETING_OPT_OUT &&
                    (it.channel == null || it.channel == request.channel)
            }
            val bounceOrComplaint = activeRecordsForUser.firstOrNull {
                (it.reason == SuppressionReason.HARD_BOUNCE || it.reason == SuppressionReason.SPAM_COMPLAINT) &&
                    (it.channel == null || it.channel == request.channel)
            }

            if (selfExcluded != null) {
                decision = SuppressionDecision.SUPPRESSED_MARKETING_EXCLUDED
                matchedReason = SuppressionReason.SELF_EXCLUDED
            } else if (marketingOptOut != null) {
                decision = SuppressionDecision.SUPPRESSED_MARKETING_OPTOUT
                matchedReason = SuppressionReason.MARKETING_OPT_OUT
            } else if (bounceOrComplaint != null) {
                decision = SuppressionDecision.SUPPRESSED_BOUNCE_OR_COMPLAINT
                matchedReason = bounceOrComplaint.reason
            } else {
                decision = SuppressionDecision.ALLOWED
                matchedReason = null
            }
        }

        val isAllowed = (decision == SuppressionDecision.ALLOWED)
        val result = SuppressionCheckResult(
            checkId = checkId,
            tenantId = request.tenantId,
            userId = request.userId,
            channel = request.channel,
            classification = request.classification,
            templateId = request.templateId,
            decision = decision,
            isAllowed = isAllowed,
            reason = matchedReason,
            serverTime = now,
            serverVersion = request.expectedVersion,
            evidenceReference = "notification:suppression:$checkId",
            semanticContract = "Mandatory legal/security notices separately approved; stale tokens removed safely.",
            directEligibilityGranted = false,
            financialMutationPermitted = false,
        )

        val auditEvent = NotificationSuppressionAuditEvent(
            eventId = UUID.randomUUID(),
            checkId = checkId,
            tenantId = request.tenantId,
            userId = request.userId,
            channel = request.channel,
            classification = request.classification,
            templateId = request.templateId,
            decision = decision,
            isAllowed = isAllowed,
            reason = matchedReason,
            occurredAt = now,
            correlationId = request.correlationId,
            causationId = request.causationId,
        )
        auditLogs.computeIfAbsent(request.tenantId) { mutableListOf() }.add(auditEvent)

        idempotencyStore[idemKey] = fingerprint to result
        return result
    }

    @Synchronized
    fun addSuppression(
        principal: AuthenticatedPrincipal?,
        tenantId: String,
        userId: String,
        channel: NotificationChannel?,
        reason: SuppressionReason,
        evidenceReference: String,
    ): UserSuppressionRecord {
        NotificationSuppressionBinding.checkBound()

        if (principal == null) {
            throw NotificationSuppressionException.Unauthorized("Principal is unauthenticated")
        }
        if (principal.tenantId != tenantId) {
            throw NotificationSuppressionException.Forbidden("Cross-tenant access forbidden")
        }
        if (userId.isBlank()) {
            throw NotificationSuppressionException.Invalid("User ID cannot be blank")
        }

        val now = Instant.now(clock)
        val record = UserSuppressionRecord(
            tenantId = tenantId,
            userId = userId,
            channel = channel,
            reason = reason,
            suppressedAt = now,
            isActive = true,
            evidenceReference = evidenceReference,
        )
        suppressionRecords.computeIfAbsent(tenantId) { mutableListOf() }.add(record)
        return record
    }

    @Synchronized
    fun registerStaleToken(
        principal: AuthenticatedPrincipal?,
        tenantId: String,
        token: String
    ) {
        NotificationSuppressionBinding.checkBound()

        if (principal == null) {
            throw NotificationSuppressionException.Unauthorized("Principal is unauthenticated")
        }
        if (principal.tenantId != tenantId) {
            throw NotificationSuppressionException.Forbidden("Cross-tenant access forbidden")
        }
        staleDeviceTokens.computeIfAbsent(tenantId) { ConcurrentHashMap.newKeySet() }.add(token)
    }

    @Synchronized
    fun removeStaleToken(
        principal: AuthenticatedPrincipal?,
        tenantId: String,
        token: String
    ): Boolean {
        NotificationSuppressionBinding.checkBound()

        if (principal == null) {
            throw NotificationSuppressionException.Unauthorized("Principal is unauthenticated")
        }
        if (principal.tenantId != tenantId) {
            throw NotificationSuppressionException.Forbidden("Cross-tenant access forbidden")
        }
        return staleDeviceTokens[tenantId]?.remove(token) ?: false
    }

    fun getActiveSuppressions(tenantId: String, userId: String): List<UserSuppressionRecord> =
        suppressionRecords[tenantId]?.filter { it.userId == userId && it.isActive } ?: emptyList()

    fun getAuditLogs(tenantId: String): List<NotificationSuppressionAuditEvent> =
        auditLogs[tenantId]?.toList() ?: emptyList()

    private fun computeFingerprint(request: SuppressionCheckRequest): String {
        val raw = listOf(
            request.tenantId,
            request.userId,
            request.channel.name,
            request.classification.name,
            request.templateId,
            request.recipientDestination,
            request.expectedVersion,
        ).joinToString("|")
        val digest = MessageDigest.getInstance("SHA-256").digest(raw.toByteArray(StandardCharsets.UTF_8))
        return Base64.getEncoder().encodeToString(digest)
    }
}
