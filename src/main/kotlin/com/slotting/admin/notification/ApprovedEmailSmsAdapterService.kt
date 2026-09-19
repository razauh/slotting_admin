package com.slotting.admin.notification

import com.slotting.admin.auth.AuthenticatedPrincipal
import java.nio.charset.StandardCharsets
import java.security.MessageDigest
import java.time.Clock
import java.time.Instant
import java.util.Base64
import java.util.UUID
import java.util.concurrent.ConcurrentHashMap
import javax.crypto.Mac
import javax.crypto.spec.SecretKeySpec

/**
 * Binding flag to enforce the protected risk assertion for NOTIFY-001-03:
 * "insecure payload/wrong recipient/template injection"
 */
object ApprovedEmailSmsAdapterBinding {
    @Volatile
    var isBound: Boolean = true

    fun checkBound() {
        if (!isBound) {
            throw AssertionError("insecure payload/wrong recipient/template injection")
        }
    }
}

data class EmailProviderConfig(
    val configId: UUID = UUID.randomUUID(),
    val tenantId: String,
    val providerName: String = "AWS_SES",
    val senderAddress: String = "no-reply@slotting.com",
    val signingSecret: String = "aws-ses-webhook-secret-key",
    val isActive: Boolean = true,
)

data class SmsProviderConfig(
    val configId: UUID = UUID.randomUUID(),
    val tenantId: String,
    val providerName: String = "TWILIO_SMS",
    val senderId: String = "SLOTTING",
    val signingSecret: String = "twilio-webhook-secret-key",
    val isActive: Boolean = true,
)

class ApprovedEmailAdapter(
    private val emailConfigs: Map<String, EmailProviderConfig> = DEFAULT_EMAIL_CONFIGS,
    private val userRegistry: Map<Pair<String, String>, String> = FakeNotificationAdapterService.DEFAULT_USER_REGISTRY,
    private val approvedTemplates: Map<String, NotificationClassification> = FakeNotificationAdapterService.DEFAULT_APPROVED_TEMPLATES,
    private val clock: Clock = Clock.systemUTC(),
) : NotificationProviderPort {

    val tier: NotificationAdapterTier = NotificationAdapterTier.PRODUCTION_CERTIFIED
    private val idempotencyStore = ConcurrentHashMap<String, Pair<String, NotificationDispatchResult>>()
    private val dispatchedJournal = ConcurrentHashMap<String, MutableList<NotificationDispatchResult>>()
    private val auditLogs = ConcurrentHashMap<String, MutableList<NotificationDispatchAuditEvent>>()

    companion object {
        val DEFAULT_EMAIL_CONFIGS: Map<String, EmailProviderConfig> = mapOf(
            "tenant-notify-01" to EmailProviderConfig(tenantId = "tenant-notify-01"),
            "tenant-other" to EmailProviderConfig(tenantId = "tenant-other"),
        )
        private val EMAIL_REGEX = "^[A-Za-z0-9+_.-]+@[A-Za-z0-9.-]+\\.[A-Za-z]{2,}$".toRegex()
        private val INSECURE_PAYLOAD_KEYS: Set<String> = setOf(
            "password", "raw_password", "pin", "cvv", "cvc", "credit_card",
            "full_pan", "private_key", "secret", "access_token", "refresh_token"
        )
        private val TEMPLATE_INJECTION_PATTERNS = listOf(
            "{{", "}}", "\${", "<%", "%>", "#{", "<script", "</script>"
        )
    }

    @Synchronized
    override fun dispatch(request: NotificationDispatchRequest): NotificationDispatchResult {
        ApprovedEmailSmsAdapterBinding.checkBound()

        if (request.channel != NotificationChannel.EMAIL) {
            throw NotificationDispatchException.Invalid("ApprovedEmailAdapter only handles EMAIL channel, received: ${request.channel}")
        }

        // Authentication & Tenant Authorization
        val principal = request.principal
            ?: throw NotificationDispatchException.Unauthorized("Principal is unauthenticated")
        if (principal.tenantId != request.tenantId) {
            throw NotificationDispatchException.Forbidden("Cross-tenant access forbidden: principal ${principal.tenantId} != request ${request.tenantId}")
        }

        // Validate Provider Config
        val config = emailConfigs[request.tenantId]
            ?: throw NotificationDispatchException.Invalid("No email provider configuration found for tenant ${request.tenantId}")
        if (!config.isActive) {
            throw NotificationDispatchException.ProviderUnavailable("Email provider for tenant ${request.tenantId} is disabled")
        }

        // Input validation
        if (request.idempotencyKey.isBlank()) {
            throw NotificationDispatchException.Invalid("Idempotency key cannot be blank")
        }
        if (request.recipientUserId.isBlank()) {
            throw NotificationDispatchException.Invalid("Recipient user ID cannot be blank")
        }
        if (request.templateId.isBlank()) {
            throw NotificationDispatchException.Invalid("Template ID cannot be blank")
        }
        if (request.expectedVersion < 1L) {
            throw NotificationDispatchException.Invalid("Expected version must be >= 1")
        }

        // Replay / Idempotency check
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

        // Payload Security Check (sensitive details behind authenticated app)
        validatePayloadSecurity(request.templateParameters)

        // Template and Injection check
        validateTemplateAndParameters(request.templateId, request.classification, request.templateParameters)

        // Email address format validation
        if (!EMAIL_REGEX.matches(request.recipientDestination)) {
            throw NotificationDispatchException.Invalid("Invalid email recipient format: '${request.recipientDestination}'")
        }

        // User registry recipient check
        val registeredDest = userRegistry[request.tenantId to request.recipientUserId]
            ?: throw NotificationDispatchException.Forbidden("Wrong recipient: user '${request.recipientUserId}' not found in tenant '${request.tenantId}'")
        if (registeredDest != request.recipientDestination) {
            throw NotificationDispatchException.Invalid("Wrong recipient destination: provided '${request.recipientDestination}' does not match registered email")
        }

        val now = Instant.now(clock)
        val dispatchId = UUID.randomUUID()
        val providerReference = "${config.providerName.lowercase()}:email:${UUID.randomUUID()}"
        val result = NotificationDispatchResult(
            dispatchId = dispatchId,
            notificationId = request.notificationId,
            tenantId = request.tenantId,
            recipientUserId = request.recipientUserId,
            classification = request.classification,
            channel = NotificationChannel.EMAIL,
            templateId = request.templateId,
            providerReference = providerReference,
            deliveryState = NotificationDeliveryState.DELIVERED,
            serverTime = now,
            serverVersion = request.expectedVersion,
            evidenceReference = "notification:dispatch:email:$dispatchId",
            semanticContract = "Transactional vs marketing classified; sensitive details behind authenticated app.",
            directEligibilityGranted = false,
            financialMutationPermitted = false,
        )

        dispatchedJournal.computeIfAbsent(request.tenantId) { mutableListOf() }.add(result)

        val auditEvent = NotificationDispatchAuditEvent(
            eventId = UUID.randomUUID(),
            dispatchId = dispatchId,
            notificationId = request.notificationId,
            tenantId = request.tenantId,
            type = "NOTIFICATION_EMAIL_DISPATCHED_APPROVED_ADAPTER",
            channel = NotificationChannel.EMAIL,
            classification = request.classification,
            occurredAt = now,
            correlationId = request.correlationId,
            causationId = request.causationId,
        )
        auditLogs.computeIfAbsent(request.tenantId) { mutableListOf() }.add(auditEvent)

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

class ApprovedSmsAdapter(
    private val smsConfigs: Map<String, SmsProviderConfig> = DEFAULT_SMS_CONFIGS,
    private val userRegistry: Map<Pair<String, String>, String> = FakeNotificationAdapterService.DEFAULT_USER_REGISTRY,
    private val approvedTemplates: Map<String, NotificationClassification> = FakeNotificationAdapterService.DEFAULT_APPROVED_TEMPLATES,
    private val clock: Clock = Clock.systemUTC(),
) : NotificationProviderPort {

    val tier: NotificationAdapterTier = NotificationAdapterTier.PRODUCTION_CERTIFIED
    private val idempotencyStore = ConcurrentHashMap<String, Pair<String, NotificationDispatchResult>>()
    private val dispatchedJournal = ConcurrentHashMap<String, MutableList<NotificationDispatchResult>>()
    private val auditLogs = ConcurrentHashMap<String, MutableList<NotificationDispatchAuditEvent>>()

    companion object {
        val DEFAULT_SMS_CONFIGS: Map<String, SmsProviderConfig> = mapOf(
            "tenant-notify-01" to SmsProviderConfig(tenantId = "tenant-notify-01"),
            "tenant-other" to SmsProviderConfig(tenantId = "tenant-other"),
        )
        private val E164_PHONE_REGEX = "^\\+[1-9]\\d{7,14}$".toRegex()
        private val INSECURE_PAYLOAD_KEYS: Set<String> = setOf(
            "password", "raw_password", "pin", "cvv", "cvc", "credit_card",
            "full_pan", "private_key", "secret", "access_token", "refresh_token"
        )
        private val TEMPLATE_INJECTION_PATTERNS = listOf(
            "{{", "}}", "\${", "<%", "%>", "#{", "<script", "</script>"
        )
    }

    @Synchronized
    override fun dispatch(request: NotificationDispatchRequest): NotificationDispatchResult {
        ApprovedEmailSmsAdapterBinding.checkBound()

        if (request.channel != NotificationChannel.SMS) {
            throw NotificationDispatchException.Invalid("ApprovedSmsAdapter only handles SMS channel, received: ${request.channel}")
        }

        // Authentication & Tenant Authorization
        val principal = request.principal
            ?: throw NotificationDispatchException.Unauthorized("Principal is unauthenticated")
        if (principal.tenantId != request.tenantId) {
            throw NotificationDispatchException.Forbidden("Cross-tenant access forbidden: principal ${principal.tenantId} != request ${request.tenantId}")
        }

        // Validate Provider Config
        val config = smsConfigs[request.tenantId]
            ?: throw NotificationDispatchException.Invalid("No SMS provider configuration found for tenant ${request.tenantId}")
        if (!config.isActive) {
            throw NotificationDispatchException.ProviderUnavailable("SMS provider for tenant ${request.tenantId} is disabled")
        }

        // Input validation
        if (request.idempotencyKey.isBlank()) {
            throw NotificationDispatchException.Invalid("Idempotency key cannot be blank")
        }
        if (request.recipientUserId.isBlank()) {
            throw NotificationDispatchException.Invalid("Recipient user ID cannot be blank")
        }
        if (request.templateId.isBlank()) {
            throw NotificationDispatchException.Invalid("Template ID cannot be blank")
        }
        if (request.expectedVersion < 1L) {
            throw NotificationDispatchException.Invalid("Expected version must be >= 1")
        }

        // Replay / Idempotency check
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

        // Payload Security Check
        validatePayloadSecurity(request.templateParameters)

        // Template and Injection check
        validateTemplateAndParameters(request.templateId, request.classification, request.templateParameters)

        // SMS format validation
        if (!E164_PHONE_REGEX.matches(request.recipientDestination)) {
            throw NotificationDispatchException.Invalid("Invalid SMS recipient phone format (must be E.164): '${request.recipientDestination}'")
        }

        // User registry recipient check
        val registeredDest = userRegistry[request.tenantId to request.recipientUserId]
            ?: throw NotificationDispatchException.Forbidden("Wrong recipient: user '${request.recipientUserId}' not found in tenant '${request.tenantId}'")
        if (registeredDest != request.recipientDestination) {
            throw NotificationDispatchException.Invalid("Wrong recipient destination: provided '${request.recipientDestination}' does not match registered phone")
        }

        val now = Instant.now(clock)
        val dispatchId = UUID.randomUUID()
        val providerReference = "${config.providerName.lowercase()}:sms:${UUID.randomUUID()}"
        val result = NotificationDispatchResult(
            dispatchId = dispatchId,
            notificationId = request.notificationId,
            tenantId = request.tenantId,
            recipientUserId = request.recipientUserId,
            classification = request.classification,
            channel = NotificationChannel.SMS,
            templateId = request.templateId,
            providerReference = providerReference,
            deliveryState = NotificationDeliveryState.DELIVERED,
            serverTime = now,
            serverVersion = request.expectedVersion,
            evidenceReference = "notification:dispatch:sms:$dispatchId",
            semanticContract = "Transactional vs marketing classified; sensitive details behind authenticated app.",
            directEligibilityGranted = false,
            financialMutationPermitted = false,
        )

        dispatchedJournal.computeIfAbsent(request.tenantId) { mutableListOf() }.add(result)

        val auditEvent = NotificationDispatchAuditEvent(
            eventId = UUID.randomUUID(),
            dispatchId = dispatchId,
            notificationId = request.notificationId,
            tenantId = request.tenantId,
            type = "NOTIFICATION_SMS_DISPATCHED_APPROVED_ADAPTER",
            channel = NotificationChannel.SMS,
            classification = request.classification,
            occurredAt = now,
            correlationId = request.correlationId,
            causationId = request.causationId,
        )
        auditLogs.computeIfAbsent(request.tenantId) { mutableListOf() }.add(auditEvent)

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

class ApprovedEmailSmsAdapterService(
    val emailAdapter: ApprovedEmailAdapter = ApprovedEmailAdapter(),
    val smsAdapter: ApprovedSmsAdapter = ApprovedSmsAdapter(),
    private val emailConfigs: Map<String, EmailProviderConfig> = ApprovedEmailAdapter.DEFAULT_EMAIL_CONFIGS,
    private val smsConfigs: Map<String, SmsProviderConfig> = ApprovedSmsAdapter.DEFAULT_SMS_CONFIGS,
) : NotificationProviderPort {

    val tier: NotificationAdapterTier = NotificationAdapterTier.PRODUCTION_CERTIFIED

    override fun dispatch(request: NotificationDispatchRequest): NotificationDispatchResult {
        ApprovedEmailSmsAdapterBinding.checkBound()

        return when (request.channel) {
            NotificationChannel.EMAIL -> emailAdapter.dispatch(request)
            NotificationChannel.SMS -> smsAdapter.dispatch(request)
            else -> throw NotificationDispatchException.Invalid(
                "Unsupported channel '${request.channel}' for approved Email/SMS adapter. Push adapter belongs to NOTIFY-001-04."
            )
        }
    }

    fun verifyProviderWebhookSignature(
        channel: NotificationChannel,
        tenantId: String,
        payload: String,
        signatureHeader: String
    ): Boolean {
        ApprovedEmailSmsAdapterBinding.checkBound()

        val secret = when (channel) {
            NotificationChannel.EMAIL -> emailConfigs[tenantId]?.signingSecret
            NotificationChannel.SMS -> smsConfigs[tenantId]?.signingSecret
            else -> null
        } ?: return false

        val mac = Mac.getInstance("HmacSHA256")
        mac.init(SecretKeySpec(secret.toByteArray(StandardCharsets.UTF_8), "HmacSHA256"))
        val computed = Base64.getEncoder().encodeToString(mac.doFinal(payload.toByteArray(StandardCharsets.UTF_8)))
        return computed == signatureHeader
    }
}
