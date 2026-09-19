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
 * Binding flag to enforce the protected risk assertion for NOTIFY-001-02:
 * "insecure payload/wrong recipient/template injection"
 */
object FakeNotificationAdapterBinding {
    @Volatile
    var isBound: Boolean = true

    fun checkBound() {
        if (!isBound) {
            throw AssertionError("insecure payload/wrong recipient/template injection")
        }
    }
}

enum class NotificationAdapterTier {
    PORT_ONLY,
    ADVERSARIAL_FAKE,
    SANDBOX,
    PRODUCTION_CERTIFIED,
}

enum class NotificationSimulationMode {
    NORMAL,
    SIMULATE_TIMEOUT,
    SIMULATE_TRANSIENT_FAILURE,
    SIMULATE_PROVIDER_DOWN,
    SIMULATE_RATE_LIMITED,
}

data class NotificationDispatchRequest(
    val principal: AuthenticatedPrincipal?,
    val tenantId: String,
    val notificationId: UUID,
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

enum class NotificationDeliveryState {
    DELIVERED,
    FAILED,
    PENDING,
}

data class NotificationDispatchResult(
    val dispatchId: UUID,
    val notificationId: UUID,
    val tenantId: String,
    val recipientUserId: String,
    val classification: NotificationClassification,
    val channel: NotificationChannel,
    val templateId: String,
    val providerReference: String,
    val deliveryState: NotificationDeliveryState,
    val serverTime: Instant,
    val serverVersion: Long,
    val evidenceReference: String,
    val semanticContract: String = "Transactional vs marketing classified; sensitive details behind authenticated app.",
    val directEligibilityGranted: Boolean = false,
    val financialMutationPermitted: Boolean = false,
)

sealed class NotificationDispatchException(message: String, val isRetryable: Boolean = false) : RuntimeException(message) {
    class Unauthorized(message: String) : NotificationDispatchException(message, false)
    class Forbidden(message: String) : NotificationDispatchException(message, false)
    class Invalid(message: String) : NotificationDispatchException(message, false)
    class Conflict(message: String) : NotificationDispatchException(message, false)
    class Timeout(message: String) : NotificationDispatchException(message, true)
    class TransientFailure(message: String) : NotificationDispatchException(message, true)
    class ProviderUnavailable(message: String) : NotificationDispatchException(message, true)
    class RateLimited(message: String) : NotificationDispatchException(message, true)
}

interface NotificationProviderPort {
    fun dispatch(request: NotificationDispatchRequest): NotificationDispatchResult
}

data class NotificationDispatchAuditEvent(
    val eventId: UUID,
    val dispatchId: UUID,
    val notificationId: UUID,
    val tenantId: String,
    val type: String,
    val channel: NotificationChannel,
    val classification: NotificationClassification,
    val occurredAt: Instant,
    val correlationId: String,
    val causationId: String,
)

class FakeNotificationAdapterService(
    private val clock: Clock = Clock.systemUTC(),
    private val userRegistry: Map<Pair<String, String>, String> = DEFAULT_USER_REGISTRY,
    private val approvedTemplates: Map<String, NotificationClassification> = DEFAULT_APPROVED_TEMPLATES,
) : NotificationProviderPort {

    private val idempotencyStore = ConcurrentHashMap<String, Pair<String, NotificationDispatchResult>>()
    private val dispatchedJournal = ConcurrentHashMap<String, MutableList<NotificationDispatchResult>>()
    private val auditLogs = ConcurrentHashMap<String, MutableList<NotificationDispatchAuditEvent>>()
    private val outboxEvents = ConcurrentHashMap<String, MutableList<UUID>>()

    @Volatile
    var simulationMode: NotificationSimulationMode = NotificationSimulationMode.NORMAL

    val tier: NotificationAdapterTier = NotificationAdapterTier.ADVERSARIAL_FAKE

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
    override fun dispatch(request: NotificationDispatchRequest): NotificationDispatchResult {
        FakeNotificationAdapterBinding.checkBound()

        // 1. Authentication and Tenant Authorization
        val principal = request.principal
            ?: throw NotificationDispatchException.Unauthorized("Principal is unauthenticated")
        if (principal.tenantId != request.tenantId) {
            throw NotificationDispatchException.Forbidden("Cross-tenant access forbidden: principal ${principal.tenantId} != request ${request.tenantId}")
        }

        // 2. Input validation
        if (request.idempotencyKey.isBlank()) {
            throw NotificationDispatchException.Invalid("Idempotency key cannot be blank")
        }
        if (request.recipientUserId.isBlank()) {
            throw NotificationDispatchException.Invalid("Recipient user ID cannot be blank")
        }
        if (request.recipientDestination.isBlank()) {
            throw NotificationDispatchException.Invalid("Recipient destination cannot be blank")
        }
        if (request.templateId.isBlank()) {
            throw NotificationDispatchException.Invalid("Template ID cannot be blank")
        }
        if (request.expectedVersion < 1L) {
            throw NotificationDispatchException.Invalid("Expected version must be >= 1")
        }

        // 3. Replay / Idempotency check
        val idemKey = "${request.tenantId}:${request.idempotencyKey}"
        val fingerprint = computeFingerprint(request)
        val existing = idempotencyStore[idemKey]
        if (existing != null) {
            if (existing.first == fingerprint) {
                return existing.second
            } else {
                throw NotificationDispatchException.Conflict("Conflicting payload for idempotency key: ${request.idempotencyKey}")
            }
        }

        // 4. Protection: Insecure payload check (sensitive details must stay behind authenticated app)
        validatePayloadSecurity(request.templateParameters)

        // 5. Protection: Template injection check & approved template verification
        validateTemplateAndParameters(request.templateId, request.classification, request.templateParameters)

        // 6. Protection: Wrong recipient & destination format verification
        validateRecipient(request.tenantId, request.recipientUserId, request.channel, request.recipientDestination)

        // 7. Adversarial simulation modes
        when (simulationMode) {
            NotificationSimulationMode.SIMULATE_TIMEOUT ->
                throw NotificationDispatchException.Timeout("Simulated provider timeout during dispatch")
            NotificationSimulationMode.SIMULATE_TRANSIENT_FAILURE ->
                throw NotificationDispatchException.TransientFailure("Simulated transient 503 from provider")
            NotificationSimulationMode.SIMULATE_PROVIDER_DOWN ->
                throw NotificationDispatchException.ProviderUnavailable("Simulated provider total outage")
            NotificationSimulationMode.SIMULATE_RATE_LIMITED ->
                throw NotificationDispatchException.RateLimited("Simulated provider rate limit (429 Too Many Requests)")
            NotificationSimulationMode.NORMAL -> { /* Proceed normally */ }
        }

        // 8. Produce authoritative dispatch result
        val now = Instant.now(clock)
        val dispatchId = UUID.randomUUID()
        val providerReference = "fake-provider-ref:$dispatchId"
        val result = NotificationDispatchResult(
            dispatchId = dispatchId,
            notificationId = request.notificationId,
            tenantId = request.tenantId,
            recipientUserId = request.recipientUserId,
            classification = request.classification,
            channel = request.channel,
            templateId = request.templateId,
            providerReference = providerReference,
            deliveryState = NotificationDeliveryState.DELIVERED,
            serverTime = now,
            serverVersion = request.expectedVersion,
            evidenceReference = "notification:dispatch:$dispatchId",
            semanticContract = "Transactional vs marketing classified; sensitive details behind authenticated app.",
            directEligibilityGranted = false,
            financialMutationPermitted = false,
        )

        // 9. Dispatch journal record
        dispatchedJournal.computeIfAbsent(request.tenantId) { mutableListOf() }.add(result)

        // 10. Audit and outbox
        val auditEvent = NotificationDispatchAuditEvent(
            eventId = UUID.randomUUID(),
            dispatchId = dispatchId,
            notificationId = request.notificationId,
            tenantId = request.tenantId,
            type = "NOTIFICATION_DISPATCHED_FAKE_ADAPTER",
            channel = request.channel,
            classification = request.classification,
            occurredAt = now,
            correlationId = request.correlationId,
            causationId = request.causationId,
        )
        auditLogs.computeIfAbsent(request.tenantId) { mutableListOf() }.add(auditEvent)
        outboxEvents.computeIfAbsent(request.tenantId) { mutableListOf() }.add(dispatchId)

        // 11. Cache idempotency
        idempotencyStore[idemKey] = fingerprint to result

        return result
    }

    private fun validatePayloadSecurity(parameters: Map<String, String>) {
        for ((key, value) in parameters) {
            val lowerKey = key.lowercase()
            if (INSECURE_PAYLOAD_KEYS.any { lowerKey.contains(it) }) {
                throw NotificationDispatchException.Invalid("Insecure payload: sensitive field '$key' must remain behind authenticated app")
            }
            val digitsOnly = value.filter { it.isDigit() }
            if (digitsOnly.length in 15..19 && !value.contains("****") && !value.contains("XX")) {
                throw NotificationDispatchException.Invalid("Insecure payload: raw card PAN detected; sensitive details must remain behind authenticated app")
            }
        }
    }

    private fun validateTemplateAndParameters(
        templateId: String,
        classification: NotificationClassification,
        parameters: Map<String, String>
    ) {
        val approvedClassification = approvedTemplates[templateId]
            ?: throw NotificationDispatchException.Invalid("Unapproved template ID: '$templateId'")

        if (approvedClassification != classification) {
            throw NotificationDispatchException.Invalid(
                "Classification mismatch: template '$templateId' is $approvedClassification but requested as $classification"
            )
        }

        for ((key, value) in parameters) {
            if (TEMPLATE_INJECTION_PATTERNS.any { key.contains(it) || value.contains(it) }) {
                throw NotificationDispatchException.Invalid("Template injection attempt detected in parameter: key='$key', value='$value'")
            }
        }
    }

    private fun validateRecipient(
        tenantId: String,
        recipientUserId: String,
        channel: NotificationChannel,
        destination: String
    ) {
        when (channel) {
            NotificationChannel.EMAIL -> {
                if (!EMAIL_REGEX.matches(destination)) {
                    throw NotificationDispatchException.Invalid("Invalid email recipient format: '$destination'")
                }
            }
            NotificationChannel.SMS -> {
                if (!E164_PHONE_REGEX.matches(destination)) {
                    throw NotificationDispatchException.Invalid("Invalid SMS recipient phone format (must be E.164): '$destination'")
                }
            }
            NotificationChannel.PUSH -> {
                if (destination.length < 16 || !destination.all { it.isLetterOrDigit() || it == '_' || it == '-' }) {
                    throw NotificationDispatchException.Invalid("Invalid PUSH token recipient format")
                }
            }
        }

        val registeredDestination = userRegistry[tenantId to recipientUserId]
            ?: throw NotificationDispatchException.Forbidden("Wrong recipient: user '$recipientUserId' not found in tenant '$tenantId'")

        if (registeredDestination != destination) {
            throw NotificationDispatchException.Invalid("Wrong recipient destination: provided '$destination' does not match registered user destination")
        }
    }

    private fun computeFingerprint(request: NotificationDispatchRequest): String {
        val raw = listOf(
            request.tenantId,
            request.recipientUserId,
            request.classification.name,
            request.channel.name,
            request.templateId,
            request.recipientDestination,
            request.expectedVersion,
        ).joinToString("|")
        val digest = MessageDigest.getInstance("SHA-256").digest(raw.toByteArray(StandardCharsets.UTF_8))
        return Base64.getEncoder().encodeToString(digest)
    }

    fun getDispatchedJournal(tenantId: String): List<NotificationDispatchResult> =
        dispatchedJournal[tenantId]?.toList() ?: emptyList()

    fun getAuditLogs(tenantId: String): List<NotificationDispatchAuditEvent> =
        auditLogs[tenantId]?.toList() ?: emptyList()
}
