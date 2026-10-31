package com.slotting.admin.observability

import com.fasterxml.jackson.databind.JsonNode
import com.fasterxml.jackson.databind.ObjectMapper
import java.nio.charset.StandardCharsets
import java.security.MessageDigest
import java.time.Clock
import java.time.Instant
import java.util.UUID

enum class DiagnosticEventSeverity {
    DEBUG,
    INFO,
    WARN,
    ERROR,
    CRITICAL,
}

enum class DiagnosticEnvelopeRejectionCode {
    UNSUPPORTED_SCHEMA,
    INVALID_PAYLOAD,
    MISSING_REQUIRED_FIELD,
    INVALID_CURRENCY,
    AMOUNT_CURRENCY_MISMATCH,
    CROSS_TENANT,
    PAYLOAD_TOO_LARGE,
}

class DiagnosticEnvelopeRejection(
    val code: DiagnosticEnvelopeRejectionCode,
    message: String,
) : IllegalArgumentException(message)

data class DiagnosticEventEnvelope(
    val schemaVersion: Int,
    val eventId: UUID,
    val occurredAt: Instant,
    val serverReceivedAt: Instant,
    val eventType: String,
    val severity: DiagnosticEventSeverity,
    val sourceApp: String,
    val component: String,
    val environment: String,
    val requestId: String?,
    val correlationId: String,
    val causationId: String?,
    val userId: String?,
    val adminId: String?,
    val sessionId: String?,
    val roundId: String?,
    val betId: String?,
    val paymentId: String?,
    val ledgerId: String?,
    val amountMinorUnits: Long?,
    val currency: String?,
    val message: String?,
    val context: Map<String, String>,
    val stackFrames: List<String>,
) {
    fun payloadDigest(): String {
        val canonical = buildString {
            append(schemaVersion).append('|')
            append(eventId).append('|')
            append(occurredAt.toEpochMilli()).append('|')
            append(eventType).append('|')
            append(severity).append('|')
            append(sourceApp).append('|')
            append(component).append('|')
            append(environment).append('|')
            append(correlationId).append('|')
            append(causationId ?: "").append('|')
            append(amountMinorUnits ?: "").append('|')
            append(currency ?: "").append('|')
            append(message ?: "").append('|')
            context.toSortedMap().forEach { (key, value) -> append(key).append('=').append(value).append(';') }
            stackFrames.forEach { append(it).append('\n') }
        }
        return MessageDigest.getInstance("SHA-256")
            .digest(canonical.toByteArray(StandardCharsets.UTF_8))
            .joinToString("") { "%02x".format(it) }
    }
}

object DiagnosticEnvelopeSerializer {
    private val mapper = ObjectMapper()

    fun toJson(envelope: DiagnosticEventEnvelope): String = mapper.writeValueAsString(
        mapOf(
            "schemaVersion" to envelope.schemaVersion,
            "eventId" to envelope.eventId.toString(),
            "occurredAtMillis" to envelope.occurredAt.toEpochMilli(),
            "serverReceivedAtMillis" to envelope.serverReceivedAt.toEpochMilli(),
            "eventType" to envelope.eventType,
            "severity" to envelope.severity.name,
            "sourceApp" to envelope.sourceApp,
            "component" to envelope.component,
            "environment" to envelope.environment,
            "requestId" to envelope.requestId,
            "correlationId" to envelope.correlationId,
            "causationId" to envelope.causationId,
            "userId" to envelope.userId,
            "adminId" to envelope.adminId,
            "sessionId" to envelope.sessionId,
            "roundId" to envelope.roundId,
            "betId" to envelope.betId,
            "paymentId" to envelope.paymentId,
            "ledgerId" to envelope.ledgerId,
            "amountMinorUnits" to envelope.amountMinorUnits,
            "currency" to envelope.currency,
            "message" to envelope.message,
            "context" to envelope.context,
            "stackFrames" to envelope.stackFrames,
        )
    )
}

object DiagnosticEnvelopeParser {
    const val CURRENT_SCHEMA_VERSION = 2
    private const val MAX_MESSAGE_LENGTH = 2_000
    private const val MAX_CONTEXT_ENTRIES = 32
    private const val MAX_CONTEXT_VALUE_LENGTH = 256
    private const val MAX_STACK_FRAMES = 32
    private const val MAX_STACK_FRAME_LENGTH = 512
    private const val MAX_RAW_LENGTH = 64_000

    private val mapper = ObjectMapper()
    private val allowedContextKeys = setOf(
        "screen",
        "action",
        "phase",
        "networkState",
        "retryCount",
        "qualityTier",
        "rendererState",
        "connectionState",
        "appVersion",
        "deviceClass",
    )
    private val forbiddenKeyFragments = listOf(
        "token",
        "password",
        "otp",
        "authorization",
        "secret",
        "callback",
        "account",
        "card",
        "cvv",
        "pan",
        "merchant",
    )
    private val secretPatterns = listOf(
        Regex("(?i)bearer\\s+[A-Za-z0-9_.-]+"),
        Regex("(?i)(token|password|otp|secret|authorization|api_key)=([^\\s&,;]+)"),
        Regex("(?i)\"(token|password|otp|secret|authorization|api_key)\"\\s*:\\s*\"[^\"]+\""),
    )

    fun parse(
        rawJson: String,
        serverActorId: String,
        serverTenantId: String,
        serverActorIsAdmin: Boolean,
        clock: Clock = Clock.systemUTC(),
    ): DiagnosticEventEnvelope {
        if (rawJson.length > MAX_RAW_LENGTH) {
            reject(DiagnosticEnvelopeRejectionCode.PAYLOAD_TOO_LARGE, "Diagnostic payload exceeds the safe size bound")
        }
        if (serverTenantId.isBlank() || serverActorId.isBlank()) {
            reject(DiagnosticEnvelopeRejectionCode.MISSING_REQUIRED_FIELD, "Authenticated server identity is required")
        }
        val root = try {
            mapper.readTree(rawJson)
        } catch (_: Exception) {
            reject(DiagnosticEnvelopeRejectionCode.INVALID_PAYLOAD, "Diagnostic payload is not valid JSON")
        }
        if (root == null || !root.isObject) {
            reject(DiagnosticEnvelopeRejectionCode.INVALID_PAYLOAD, "Diagnostic payload must be a JSON object")
        }

        val version = root.requiredInt("schemaVersion")
        if (version > CURRENT_SCHEMA_VERSION) {
            reject(DiagnosticEnvelopeRejectionCode.UNSUPPORTED_SCHEMA, "Unsupported future diagnostic schema version: $version")
        }
        if (version !in 1..CURRENT_SCHEMA_VERSION) {
            reject(DiagnosticEnvelopeRejectionCode.UNSUPPORTED_SCHEMA, "Unsupported diagnostic schema version: $version")
        }

        if (version == 1) {
            return parseV1(root, serverActorId, serverTenantId, serverActorIsAdmin, clock)
        }

        val eventId = root.requiredUuid("eventId")
        val occurredAt = Instant.ofEpochMilli(root.requiredLong("occurredAtMillis"))
        val eventType = root.requiredText("eventType")
        val severity = parseSeverity(root.requiredText("severity"))
        val sourceApp = root.requiredText("sourceApp")
        val component = root.requiredText("component")
        val environment = root.requiredText("environment")
        val correlationId = root.requiredText("correlationId")
        val amount = root.optionalLong("amountMinorUnits")
        val currency = root.optionalText("currency")
        validateMoney(amount, currency)

        val clientTenant = root.optionalText("tenantId")
        if (clientTenant != null && clientTenant != serverTenantId) {
            reject(DiagnosticEnvelopeRejectionCode.CROSS_TENANT, "Client tenant does not match the authenticated tenant")
        }

        val context = sanitizeContext(root.optionalObject("context"))
        val message = root.optionalText("message")?.let(::redact)?.take(MAX_MESSAGE_LENGTH)
        val stack = sanitizeStack(root.optionalArray("stackFrames"))

        return DiagnosticEventEnvelope(
            schemaVersion = version,
            eventId = eventId,
            occurredAt = occurredAt,
            serverReceivedAt = clock.instant(),
            eventType = eventType,
            severity = severity,
            sourceApp = sourceApp,
            component = component,
            environment = environment,
            requestId = root.optionalText("requestId"),
            correlationId = correlationId,
            causationId = root.optionalText("causationId"),
            userId = if (serverActorIsAdmin) null else serverActorId,
            adminId = if (serverActorIsAdmin) serverActorId else null,
            sessionId = root.optionalText("sessionId"),
            roundId = root.optionalText("roundId"),
            betId = root.optionalText("betId"),
            paymentId = root.optionalText("paymentId"),
            ledgerId = root.optionalText("ledgerId"),
            amountMinorUnits = amount,
            currency = currency,
            message = message,
            context = context,
            stackFrames = stack,
        )
    }

    private fun parseV1(
        root: JsonNode,
        serverActorId: String,
        serverTenantId: String,
        serverActorIsAdmin: Boolean,
        clock: Clock,
    ): DiagnosticEventEnvelope {
        val eventId = root.optionalText("eventId")?.let { runCatching { UUID.fromString(it) }.getOrNull() }
            ?: UUID.randomUUID()
        val occurredAt = Instant.ofEpochMilli(root.optionalLong("timestampMillis") ?: clock.millis())
        val correlationId = root.requiredText("correlationId")
        val message = root.optionalText("sanitizedMessage")?.let(::redact)?.take(MAX_MESSAGE_LENGTH)
        val context = sanitizeContext(root.optionalObject("attributes"))
        return DiagnosticEventEnvelope(
            schemaVersion = 1,
            eventId = eventId,
            occurredAt = occurredAt,
            serverReceivedAt = clock.instant(),
            eventType = root.optionalText("category") ?: root.optionalText("errorId") ?: "DIAGNOSTIC",
            severity = DiagnosticEventSeverity.ERROR,
            sourceApp = "android",
            component = "legacy-v1",
            environment = "unknown",
            requestId = null,
            correlationId = correlationId,
            causationId = null,
            userId = if (serverActorIsAdmin) null else serverActorId,
            adminId = if (serverActorIsAdmin) serverActorId else null,
            sessionId = null,
            roundId = root.optionalText("gameId"),
            betId = null,
            paymentId = null,
            ledgerId = null,
            amountMinorUnits = null,
            currency = null,
            message = message,
            context = context,
            stackFrames = emptyList(),
        )
    }

    private fun validateMoney(amount: Long?, currency: String?) {
        if (amount != null && currency == null) {
            reject(DiagnosticEnvelopeRejectionCode.AMOUNT_CURRENCY_MISMATCH, "Amount requires an explicit currency")
        }
        if (amount == null && currency != null) {
            reject(DiagnosticEnvelopeRejectionCode.AMOUNT_CURRENCY_MISMATCH, "Currency requires an explicit amount")
        }
        if (amount != null && amount < 0L) {
            reject(DiagnosticEnvelopeRejectionCode.INVALID_PAYLOAD, "Amount must not be negative")
        }
        if (currency != null && currency.uppercase() !in setOf("PKR", "USD")) {
            reject(DiagnosticEnvelopeRejectionCode.INVALID_CURRENCY, "Unsupported diagnostic currency: $currency")
        }
    }

    private fun sanitizeContext(node: JsonNode?): Map<String, String> {
        if (node == null || !node.isObject) return emptyMap()
        val result = linkedMapOf<String, String>()
        val fields = node.fields()
        while (fields.hasNext() && result.size < MAX_CONTEXT_ENTRIES) {
            val (key, value) = fields.next()
            if (key !in allowedContextKeys || isForbidden(key)) continue
            if (!value.isValueNode || value.isNull) continue
            result[key] = redact(value.asText()).take(MAX_CONTEXT_VALUE_LENGTH)
        }
        return result
    }

    private fun sanitizeStack(node: JsonNode?): List<String> {
        if (node == null || !node.isArray) return emptyList()
        return node.take(MAX_STACK_FRAMES).mapNotNull { frame ->
            if (!frame.isValueNode || frame.isNull) null else redact(frame.asText()).take(MAX_STACK_FRAME_LENGTH)
        }
    }

    private fun isForbidden(key: String): Boolean {
        val lower = key.lowercase()
        return forbiddenKeyFragments.any(lower::contains)
    }

    private fun redact(value: String): String {
        var result = value
        for (pattern in secretPatterns) {
            result = pattern.replace(result, "[REDACTED]")
        }
        return result
    }

    private fun parseSeverity(value: String): DiagnosticEventSeverity = try {
        DiagnosticEventSeverity.valueOf(value.uppercase())
    } catch (_: Exception) {
        reject(DiagnosticEnvelopeRejectionCode.INVALID_PAYLOAD, "Unsupported diagnostic severity: $value")
    }

    private fun JsonNode.requiredText(name: String): String =
        optionalText(name) ?: reject(DiagnosticEnvelopeRejectionCode.MISSING_REQUIRED_FIELD, "Missing $name")

    private fun JsonNode.optionalText(name: String): String? {
        val node = get(name) ?: return null
        if (node.isNull) return null
        if (!node.isValueNode) {
            reject(DiagnosticEnvelopeRejectionCode.INVALID_PAYLOAD, "Invalid $name: expected a scalar value")
        }
        return node.asText().takeIf(String::isNotBlank)
    }

    private fun JsonNode.requiredInt(name: String): Int =
        optionalLong(name)?.toInt() ?: reject(DiagnosticEnvelopeRejectionCode.MISSING_REQUIRED_FIELD, "Missing $name")

    private fun JsonNode.requiredLong(name: String): Long =
        optionalLong(name) ?: reject(DiagnosticEnvelopeRejectionCode.MISSING_REQUIRED_FIELD, "Missing $name")

    private fun JsonNode.optionalLong(name: String): Long? {
        val node = get(name) ?: return null
        if (node.isNull) return null
        if (!node.isNumber || !node.canConvertToLong()) {
            reject(DiagnosticEnvelopeRejectionCode.INVALID_PAYLOAD, "Invalid $name: expected an integer")
        }
        return node.asLong()
    }

    private fun JsonNode.requiredUuid(name: String): UUID {
        val value = requiredText(name)
        return try {
            UUID.fromString(value)
        } catch (_: Exception) {
            reject(DiagnosticEnvelopeRejectionCode.INVALID_PAYLOAD, "Invalid $name: expected a UUID")
        }
    }

    private fun JsonNode.optionalObject(name: String): JsonNode? =
        get(name)?.takeUnless { it.isNull }?.also {
            if (!it.isObject) reject(DiagnosticEnvelopeRejectionCode.INVALID_PAYLOAD, "Invalid $name: expected an object")
        }

    private fun JsonNode.optionalArray(name: String): JsonNode? =
        get(name)?.takeUnless { it.isNull }?.also {
            if (!it.isArray) reject(DiagnosticEnvelopeRejectionCode.INVALID_PAYLOAD, "Invalid $name: expected an array")
        }

    private fun reject(code: DiagnosticEnvelopeRejectionCode, message: String): Nothing =
        throw DiagnosticEnvelopeRejection(code, message)
}
