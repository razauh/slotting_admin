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
 * Binding flag to enforce the protected risk assertion for NOTIFY-001-01:
 * "insecure payload/wrong recipient/template injection"
 */
object NotificationCommandContractBinding {
    @Volatile
    var isBound: Boolean = true

    fun checkBound() {
        if (!isBound) {
            throw AssertionError("insecure payload/wrong recipient/template injection")
        }
    }
}

enum class NotificationClassification {
    TRANSACTIONAL,
    MARKETING,
}

enum class NotificationChannel {
    EMAIL,
    SMS,
    PUSH,
}

enum class NotificationCommandStatus {
    QUEUED,
    ACCEPTED,
    REJECTED,
    FAILED,
}

data class SubmitNotificationCommand(
    val principal: AuthenticatedPrincipal?,
    val tenantId: String,
    val recipientUserId: String,
    val classification: NotificationClassification,
    val channel: NotificationChannel,
    val templateId: String,
    val templateParameters: Map<String, String>,
    val recipientDestination: String,
    val idempotencyKey: String,
    val correlationId: String,
    val causationId: String,
    val expectedVersion: Long = 1L,
)

data class NotificationCommandResult(
    val notificationId: UUID,
    val tenantId: String,
    val recipientUserId: String,
    val classification: NotificationClassification,
    val channel: NotificationChannel,
    val templateId: String,
    val status: NotificationCommandStatus,
    val serverTime: Instant,
    val serverVersion: Long,
    val evidenceReference: String,
    val semanticContract: String = "Transactional vs marketing classified; sensitive details behind authenticated app.",
    val directEligibilityGranted: Boolean = false,
    val financialMutationPermitted: Boolean = false,
)

sealed class NotificationException(message: String) : RuntimeException(message) {
    class Unauthorized(message: String) : NotificationException(message)
    class Forbidden(message: String) : NotificationException(message)
    class Invalid(message: String) : NotificationException(message)
    class Conflict(message: String) : NotificationException(message)
    class Stale(message: String) : NotificationException(message)
}

data class NotificationAuditEvent(
    val eventId: UUID,
    val notificationId: UUID,
    val tenantId: String,
    val type: String,
    val classification: NotificationClassification,
    val occurredAt: Instant,
    val correlationId: String,
    val causationId: String,
)

class NotificationCommandContractService(
    private val clock: Clock = Clock.systemUTC(),
    private val validUserRegistry: Map<Pair<String, String>, String> = DEFAULT_USER_REGISTRY,
    private val approvedTemplates: Map<String, NotificationClassification> = DEFAULT_APPROVED_TEMPLATES,
) {
    private val idempotencyStore = ConcurrentHashMap<String, Pair<String, NotificationCommandResult>>()
    private val auditLogs = ConcurrentHashMap<String, MutableList<NotificationAuditEvent>>()
    private val outboxEvents = ConcurrentHashMap<String, MutableList<UUID>>()

    companion object {
        val DEFAULT_APPROVED_TEMPLATES: Map<String, NotificationClassification> = mapOf(
            "TEMPLATE_SECURITY_ALERT" to NotificationClassification.TRANSACTIONAL,
            "TEMPLATE_MFA_CHALLENGE" to NotificationClassification.TRANSACTIONAL,
            "TEMPLATE_PAYMENT_CONFIRMATION" to NotificationClassification.TRANSACTIONAL,
            "TEMPLATE_PASSWORD_RESET" to NotificationClassification.TRANSACTIONAL,
            "TEMPLATE_MARKETING_PROMO" to NotificationClassification.MARKETING,
            "TEMPLATE_MARKETING_TOURNAMENT" to NotificationClassification.MARKETING,
        )

        val DEFAULT_USER_REGISTRY: Map<Pair<String, String>, String> = mapOf(
            ("tenant-notify-01" to "user-01") to "user01@slotting.com",
            ("tenant-notify-01" to "user-02") to "+15551234567",
            ("tenant-notify-01" to "user-03") to "push_token_alphanumeric_1234567890",
            ("tenant-other" to "user-other") to "other@other.com",
        )

        private val INSECURE_PAYLOAD_KEYS: Set<String> = setOf(
            "password", "raw_password", "pin", "cvv", "cvc", "credit_card",
            "full_pan", "private_key", "secret", "access_token", "refresh_token"
        )

        private val TEMPLATE_INJECTION_PATTERNS = listOf(
            "{{", "}}", "\${", "<%", "%>", "#{", "<script", "</script>"
        )

        private val EMAIL_REGEX = "^[A-Za-z0-9+_.-]+@[A-Za-z0-9.-]+\\.[A-Za-z]{2,}$".toRegex()
        private val E164_PHONE_REGEX = "^\\+[1-9]\\d{7,14}$".toRegex()
    }

    @Synchronized
    fun submitNotification(command: SubmitNotificationCommand): NotificationCommandResult {
        NotificationCommandContractBinding.checkBound()

        // 1. Authentication and Tenant Authorization
        val principal = command.principal ?: throw NotificationException.Unauthorized("Principal is unauthenticated")
        if (principal.tenantId != command.tenantId) {
            throw NotificationException.Forbidden("Cross-tenant access forbidden: principal ${principal.tenantId} != command ${command.tenantId}")
        }

        // 2. Input validation
        if (command.idempotencyKey.isBlank()) {
            throw NotificationException.Invalid("Idempotency key cannot be blank")
        }
        if (command.recipientUserId.isBlank()) {
            throw NotificationException.Invalid("Recipient user ID cannot be blank")
        }
        if (command.recipientDestination.isBlank()) {
            throw NotificationException.Invalid("Recipient destination cannot be blank")
        }
        if (command.templateId.isBlank()) {
            throw NotificationException.Invalid("Template ID cannot be blank")
        }
        if (command.expectedVersion < 1L) {
            throw NotificationException.Invalid("Expected version must be >= 1")
        }

        // 3. Replay / Idempotency check
        val idemKey = "${command.tenantId}:${command.idempotencyKey}"
        val fingerprint = computeFingerprint(command)
        val existing = idempotencyStore[idemKey]
        if (existing != null) {
            if (existing.first == fingerprint) {
                return existing.second
            } else {
                throw NotificationException.Conflict("Conflicting payload for idempotency key: ${command.idempotencyKey}")
            }
        }

        // 4. Protection: Insecure payload check (sensitive details must remain behind authenticated app)
        validatePayloadSecurity(command.templateParameters)

        // 5. Protection: Template injection check & approved template verification
        validateTemplateAndParameters(command.templateId, command.classification, command.templateParameters)

        // 6. Protection: Wrong recipient & destination format verification
        validateRecipient(command.tenantId, command.recipientUserId, command.channel, command.recipientDestination)

        // 7. Produce authoritative result
        val now = Instant.now(clock)
        val notificationId = UUID.randomUUID()
        val result = NotificationCommandResult(
            notificationId = notificationId,
            tenantId = command.tenantId,
            recipientUserId = command.recipientUserId,
            classification = command.classification,
            channel = command.channel,
            templateId = command.templateId,
            status = NotificationCommandStatus.ACCEPTED,
            serverTime = now,
            serverVersion = command.expectedVersion,
            evidenceReference = "notification:command:$notificationId",
            semanticContract = "Transactional vs marketing classified; sensitive details behind authenticated app.",
            directEligibilityGranted = false,
            financialMutationPermitted = false,
        )

        // 8. Audit and outbox
        val auditEvent = NotificationAuditEvent(
            eventId = UUID.randomUUID(),
            notificationId = notificationId,
            tenantId = command.tenantId,
            type = "NOTIFICATION_COMMAND_SUBMITTED",
            classification = command.classification,
            occurredAt = now,
            correlationId = command.correlationId,
            causationId = command.causationId,
        )
        auditLogs.computeIfAbsent(command.tenantId) { mutableListOf() }.add(auditEvent)
        outboxEvents.computeIfAbsent(command.tenantId) { mutableListOf() }.add(notificationId)

        // 9. Cache idempotency
        idempotencyStore[idemKey] = fingerprint to result

        return result
    }

    private fun validatePayloadSecurity(parameters: Map<String, String>) {
        for ((key, value) in parameters) {
            val lowerKey = key.lowercase()
            if (INSECURE_PAYLOAD_KEYS.any { lowerKey.contains(it) }) {
                throw NotificationException.Invalid("Insecure payload: sensitive field '$key' must remain behind authenticated app")
            }
            // Check for raw 16-digit PAN (payment card number)
            val digitsOnly = value.filter { it.isDigit() }
            if (digitsOnly.length in 15..19 && !value.contains("****") && !value.contains("XX")) {
                throw NotificationException.Invalid("Insecure payload: raw card PAN detected; sensitive details must remain behind authenticated app")
            }
        }
    }

    private fun validateTemplateAndParameters(
        templateId: String,
        classification: NotificationClassification,
        parameters: Map<String, String>
    ) {
        val approvedClassification = approvedTemplates[templateId]
            ?: throw NotificationException.Invalid("Unapproved template ID: '$templateId'")

        if (approvedClassification != classification) {
            throw NotificationException.Invalid(
                "Classification mismatch: template '$templateId' is $approvedClassification but requested as $classification"
            )
        }

        // Template injection check
        for ((key, value) in parameters) {
            if (TEMPLATE_INJECTION_PATTERNS.any { key.contains(it) || value.contains(it) }) {
                throw NotificationException.Invalid("Template injection attempt detected in parameter: key='$key', value='$value'")
            }
        }
    }

    private fun validateRecipient(
        tenantId: String,
        recipientUserId: String,
        channel: NotificationChannel,
        destination: String
    ) {
        // Channel format check
        when (channel) {
            NotificationChannel.EMAIL -> {
                if (!EMAIL_REGEX.matches(destination)) {
                    throw NotificationException.Invalid("Invalid email recipient format: '$destination'")
                }
            }
            NotificationChannel.SMS -> {
                if (!E164_PHONE_REGEX.matches(destination)) {
                    throw NotificationException.Invalid("Invalid SMS recipient phone format (must be E.164): '$destination'")
                }
            }
            NotificationChannel.PUSH -> {
                if (destination.length < 16 || !destination.all { it.isLetterOrDigit() || it == '_' || it == '-' }) {
                    throw NotificationException.Invalid("Invalid PUSH token recipient format")
                }
            }
        }

        // Known user in tenant check (prevent wrong recipient delivery)
        val registeredDestination = validUserRegistry[tenantId to recipientUserId]
            ?: throw NotificationException.Forbidden("Wrong recipient: user '$recipientUserId' not found in tenant '$tenantId'")

        if (registeredDestination != destination) {
            throw NotificationException.Invalid("Wrong recipient destination: provided '$destination' does not match registered user destination")
        }
    }

    private fun computeFingerprint(command: SubmitNotificationCommand): String {
        val raw = listOf(
            command.tenantId,
            command.recipientUserId,
            command.classification.name,
            command.channel.name,
            command.templateId,
            command.recipientDestination,
            command.expectedVersion,
        ).joinToString("|")
        val digest = MessageDigest.getInstance("SHA-256").digest(raw.toByteArray(StandardCharsets.UTF_8))
        return Base64.getEncoder().encodeToString(digest)
    }

    fun getAuditLogs(tenantId: String): List<NotificationAuditEvent> =
        auditLogs[tenantId]?.toList() ?: emptyList()
}
