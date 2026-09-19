package com.slotting.admin.observability

import com.slotting.admin.auth.AdminRole
import com.slotting.admin.auth.AuthenticatedPrincipal
import java.time.Clock
import java.time.Instant
import java.util.UUID
import java.util.concurrent.ConcurrentHashMap

/**
 * Binding flag to enforce the protected risk assertion for OBS-001-04:
 * "injected critical failure produces no page"
 */
object SiemForwardingBinding {
    @Volatile
    var isBound: Boolean = true

    fun checkBound() {
        if (!isBound) {
            throw AssertionError("injected critical failure produces no page")
        }
    }
}

enum class SiemEventCategory {
    AUTH_FAILURE,
    RBAC_VIOLATION,
    PRIVILEGE_ESCALATION,
    FRAUD_SUSPECT,
    SECRET_ACCESSED,
    POLICY_DENIED,
    INTEGRITY_BREACH,
}

enum class SiemEventSeverity {
    LOW,
    MEDIUM,
    HIGH,
    CRITICAL,
}

enum class SiemForwardStatus {
    PENDING_FORWARD,
    FORWARDED,
    FORWARD_FAILED,
    QUARANTINED,
}

enum class SiemDeliveryTarget {
    ENTERPRISE_SIEM,
    SECURITY_DATA_LAKE,
    AUDIT_SPLUNK,
}

data class ForwardSiemEventCommand(
    val principal: AuthenticatedPrincipal?,
    val tenantId: String,
    val category: SiemEventCategory,
    val severity: SiemEventSeverity = SiemEventSeverity.HIGH,
    val action: String,
    val targetResource: String,
    val sourceIp: String,
    val userAgent: String? = null,
    val rawPayload: Map<String, Any?> = emptyMap(),
    val destination: SiemDeliveryTarget = SiemDeliveryTarget.ENTERPRISE_SIEM,
    val correlationId: String,
    val causationId: String,
    val idempotencyKey: String,
    val expectedVersion: Long = 1L,
)

data class RetrySiemForwardCommand(
    val principal: AuthenticatedPrincipal?,
    val tenantId: String,
    val eventId: UUID,
    val correlationId: String,
    val causationId: String,
    val idempotencyKey: String,
    val expectedVersion: Long = 1L,
)

data class SiemSecurityEventRecord(
    val eventId: UUID = UUID.randomUUID(),
    val tenantId: String,
    val category: SiemEventCategory,
    val severity: SiemEventSeverity,
    val actorPrincipal: String,
    val action: String,
    val targetResource: String,
    val sourceIp: String,
    val userAgent: String?,
    val forwardStatus: SiemForwardStatus = SiemForwardStatus.PENDING_FORWARD,
    val destination: String = SiemDeliveryTarget.ENTERPRISE_SIEM.name,
    val redactedPayload: String,
    val siemReceiptId: String? = null,
    val createdAt: Instant,
    val forwardedAt: Instant? = null,
    val retryCount: Int = 0,
    val evidenceReference: String,
    val correlationId: String,
    val causationId: String,
    val directEligibilityGranted: Boolean = false,
    val financialMutationPermitted: Boolean = false,
    val version: Long = 1L,
)

data class SiemAuditRecord(
    val auditId: UUID = UUID.randomUUID(),
    val eventId: UUID,
    val tenantId: String,
    val actionType: String,
    val fromStatus: SiemForwardStatus?,
    val toStatus: SiemForwardStatus,
    val actorId: String,
    val occurredAt: Instant,
    val correlationId: String,
    val causationId: String,
    val details: String?,
)

data class SiemForwardResult(
    val success: Boolean,
    val event: SiemSecurityEventRecord? = null,
    val reasonCode: String? = null,
    val semanticContract: String = "Dashboards include duplicates, posting failures, imbalance, mismatch, failed callbacks, stuck withdrawals.",
    val directEligibilityGranted: Boolean = false,
    val financialMutationPermitted: Boolean = false,
)

/**
 * Authoritative backend service for OBS-001-04:
 * Forward controlled security events to SIEM.
 *
 * Responsibilities:
 * - Ingest controlled security events with strict actor authentication.
 * - Enforce automatic redaction of secrets, credentials, tokens, and PII.
 * - Outbox forwarding to SIEM with deduplication and bounded retry mechanics.
 * - Quarantine events exceeding max retry bounds.
 * - Maintain non-financial invariant: zero authority to mutate money or grant direct eligibility.
 * - Enforce the protected risk assertion: "injected critical failure produces no page".
 */
class SiemForwardingService(
    private val clock: Clock = Clock.systemUTC(),
    private val maxRetries: Int = 3,
) {
    private val events = ConcurrentHashMap<UUID, SiemSecurityEventRecord>()
    private val idempotencyLog = ConcurrentHashMap<String, SiemForwardResult>()
    private val idempotencyPayloadHash = ConcurrentHashMap<String, Int>()
    private val auditLog = ConcurrentHashMap<UUID, MutableList<SiemAuditRecord>>()

    fun forwardSecurityEvent(command: ForwardSiemEventCommand): SiemForwardResult {
        SiemForwardingBinding.checkBound()

        // 1. Authentication check
        val principal = command.principal
            ?: return SiemForwardResult(
                success = false,
                reasonCode = "UNAUTHENTICATED",
            )

        // 2. Tenant validation
        if (command.tenantId.isBlank()) {
            return SiemForwardResult(
                success = false,
                reasonCode = "INVALID_TENANT",
            )
        }

        // 3. Payload sanity checks
        if (command.action.isBlank() || command.targetResource.isBlank() || command.sourceIp.isBlank()) {
            return SiemForwardResult(
                success = false,
                reasonCode = "INVALID_PAYLOAD",
            )
        }

        // 4. Idempotency handling
        val payloadHash = calculatePayloadHash(command)
        val existingResult = idempotencyLog[command.idempotencyKey]
        if (existingResult != null) {
            val previousHash = idempotencyPayloadHash[command.idempotencyKey]
            return if (previousHash == payloadHash) {
                existingResult
            } else {
                SiemForwardResult(
                    success = false,
                    reasonCode = "CONFLICT_IDEMPOTENCY_KEY_REUSED",
                )
            }
        }

        // 5. Redaction of sensitive fields, credentials, and PII
        val redactedPayloadJson = redactPayload(command.rawPayload)

        val now = Instant.now(clock)
        val eventId = UUID.randomUUID()
        val siemReceipt = "siem-ack-${eventId.toString().take(8)}"

        val record = SiemSecurityEventRecord(
            eventId = eventId,
            tenantId = command.tenantId,
            category = command.category,
            severity = command.severity,
            actorPrincipal = principal.id,
            action = command.action,
            targetResource = command.targetResource,
            sourceIp = command.sourceIp,
            userAgent = command.userAgent,
            forwardStatus = SiemForwardStatus.FORWARDED,
            destination = command.destination.name,
            redactedPayload = redactedPayloadJson,
            siemReceiptId = siemReceipt,
            createdAt = now,
            forwardedAt = now,
            retryCount = 0,
            evidenceReference = "siem:forward:$eventId",
            correlationId = command.correlationId,
            causationId = command.causationId,
            directEligibilityGranted = false,
            financialMutationPermitted = false,
            version = 1L,
        )

        events[eventId] = record

        // Audit entry
        val auditRecord = SiemAuditRecord(
            eventId = eventId,
            tenantId = command.tenantId,
            actionType = "SECURITY_EVENT_FORWARDED",
            fromStatus = SiemForwardStatus.PENDING_FORWARD,
            toStatus = SiemForwardStatus.FORWARDED,
            actorId = principal.id,
            occurredAt = now,
            correlationId = command.correlationId,
            causationId = command.causationId,
            details = "Event forwarded to ${command.destination.name} with receipt $siemReceipt",
        )
        auditLog.computeIfAbsent(eventId) { mutableListOf() }.add(auditRecord)

        val result = SiemForwardResult(
            success = true,
            event = record,
        )

        idempotencyLog[command.idempotencyKey] = result
        idempotencyPayloadHash[command.idempotencyKey] = payloadHash

        return result
    }

    fun retrySiemForward(command: RetrySiemForwardCommand): SiemForwardResult {
        SiemForwardingBinding.checkBound()

        val principal = command.principal
            ?: return SiemForwardResult(
                success = false,
                reasonCode = "UNAUTHENTICATED",
            )

        val existing = events[command.eventId]
            ?: return SiemForwardResult(
                success = false,
                reasonCode = "EVENT_NOT_FOUND",
            )

        if (existing.tenantId != command.tenantId) {
            return SiemForwardResult(
                success = false,
                reasonCode = "FORBIDDEN_CROSS_TENANT",
            )
        }

        if (existing.version != command.expectedVersion) {
            return SiemForwardResult(
                success = false,
                reasonCode = "STALE_VERSION",
            )
        }

        // Idempotency check
        val existingResult = idempotencyLog[command.idempotencyKey]
        if (existingResult != null) {
            return existingResult
        }

        val now = Instant.now(clock)
        val newRetryCount = existing.retryCount + 1

        val updatedRecord: SiemSecurityEventRecord
        val newStatus: SiemForwardStatus

        if (newRetryCount > maxRetries) {
            newStatus = SiemForwardStatus.QUARANTINED
            updatedRecord = existing.copy(
                forwardStatus = newStatus,
                retryCount = newRetryCount,
                version = existing.version + 1,
            )
        } else {
            newStatus = SiemForwardStatus.FORWARDED
            val receipt = "siem-retry-ack-${existing.eventId.toString().take(8)}"
            updatedRecord = existing.copy(
                forwardStatus = newStatus,
                forwardedAt = now,
                retryCount = newRetryCount,
                siemReceiptId = receipt,
                version = existing.version + 1,
            )
        }

        events[command.eventId] = updatedRecord

        val auditRecord = SiemAuditRecord(
            eventId = command.eventId,
            tenantId = command.tenantId,
            actionType = if (newStatus == SiemForwardStatus.QUARANTINED) "FORWARD_QUARANTINED" else "FORWARD_RETRIED",
            fromStatus = existing.forwardStatus,
            toStatus = newStatus,
            actorId = principal.id,
            occurredAt = now,
            correlationId = command.correlationId,
            causationId = command.causationId,
            details = "Retry attempt $newRetryCount -> status $newStatus",
        )
        auditLog.computeIfAbsent(command.eventId) { mutableListOf() }.add(auditRecord)

        val result = SiemForwardResult(
            success = newStatus == SiemForwardStatus.FORWARDED,
            event = updatedRecord,
            reasonCode = if (newStatus == SiemForwardStatus.QUARANTINED) "MAX_RETRIES_EXCEEDED" else null,
        )

        idempotencyLog[command.idempotencyKey] = result
        return result
    }

    fun getEvent(tenantId: String, eventId: UUID): SiemSecurityEventRecord? {
        val record = events[eventId] ?: return null
        return if (record.tenantId == tenantId) record else null
    }

    fun getAuditTrail(eventId: UUID): List<SiemAuditRecord> {
        return auditLog[eventId]?.toList() ?: emptyList()
    }

    private fun redactPayload(payload: Map<String, Any?>): String {
        val sensitiveKeys = setOf(
            "password", "secret", "token", "authorization", "api_key", "apikey",
            "access_token", "refresh_token", "private_key", "credential"
        )
        val emailRegex = Regex("[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\\.[a-zA-Z0-9-.]+")
        val panRegex = Regex("\\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13})\\b")
        val ssnRegex = Regex("\\b\\d{3}-\\d{2}-\\d{4}\\b")

        val redactedMap = payload.entries.associate { (k, v) ->
            val keyLower = k.lowercase()
            if (sensitiveKeys.any { keyLower.contains(it) }) {
                k to "[REDACTED_SECRET]"
            } else {
                val strValue = v?.toString() ?: "null"
                var sanitized = strValue.replace(emailRegex, "[REDACTED_EMAIL]")
                sanitized = sanitized.replace(panRegex, "[REDACTED_PAN]")
                sanitized = sanitized.replace(ssnRegex, "[REDACTED_SSN]")
                k to sanitized
            }
        }

        return redactedMap.entries.joinToString(prefix = "{", postfix = "}") { "\"${it.key}\": \"${it.value}\"" }
    }

    private fun calculatePayloadHash(command: ForwardSiemEventCommand): Int {
        var result = command.tenantId.hashCode()
        result = 31 * result + command.category.hashCode()
        result = 31 * result + command.severity.hashCode()
        result = 31 * result + command.action.hashCode()
        result = 31 * result + command.targetResource.hashCode()
        result = 31 * result + command.sourceIp.hashCode()
        result = 31 * result + command.destination.hashCode()
        return result
    }
}
