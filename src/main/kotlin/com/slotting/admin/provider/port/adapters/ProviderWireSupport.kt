package com.slotting.admin.provider.port.adapters

import com.fasterxml.jackson.databind.JsonNode
import com.fasterxml.jackson.databind.ObjectMapper
import com.slotting.admin.provider.port.ProviderOutcome
import java.util.UUID

internal object ProviderWireSupport {
    private val mapper = ObjectMapper()

    fun encode(fields: Map<String, Any?>): String = mapper.writeValueAsString(fields)

    fun parse(body: String): JsonNode? = try {
        mapper.readTree(body)
    } catch (_: Exception) {
        null
    }

    fun firstText(node: JsonNode?, vararg names: String): String? {
        if (node == null) return null
        val candidates = buildList {
            add(node)
            node.get("data")?.takeIf(JsonNode::isObject)?.let(::add)
        }
        for (candidate in candidates) {
            for (name in names) {
                val value = candidate.get(name)?.takeIf { !it.isNull }?.asText()?.takeIf(String::isNotBlank)
                if (value != null) return value
            }
        }
        return null
    }

    fun firstLong(node: JsonNode?, vararg names: String): Long? =
        firstText(node, *names)?.toLongOrNull()

    fun status(node: JsonNode?, vararg names: String): String? =
        firstText(node, *names)?.uppercase()

    fun pending(
        operationId: UUID,
        providerReference: String,
        code: String,
        evidence: Map<String, String>,
    ): ProviderOutcome = ProviderOutcome.pending(
        operationId = operationId,
        providerReference = providerReference,
        code = code,
        reason = "Provider accepted the request for asynchronous processing",
        evidence = evidence,
    )

    fun ambiguous(operationId: UUID, code: String, reason: String): ProviderOutcome =
        ProviderOutcome.ambiguous(operationId = operationId, code = code, reason = reason)

    fun malformed(operationId: UUID): ProviderOutcome =
        ProviderOutcome.failed(
            operationId = operationId,
            code = "MALFORMED_PROVIDER_RESPONSE",
            reason = "Provider response could not be safely interpreted",
        )

    fun httpFailure(operationId: UUID, statusCode: Int): ProviderOutcome = when {
        statusCode == 401 || statusCode == 403 -> ProviderOutcome.declined(
            operationId = operationId,
            code = "AUTHENTICATION_REJECTED",
            reason = "Provider rejected the supplied credentials",
        )
        statusCode in 400..499 -> ProviderOutcome.declined(
            operationId = operationId,
            code = "PROVIDER_REJECTED",
            reason = "Provider rejected the request",
        )
        else -> ambiguous(operationId, "PROVIDER_HTTP_$statusCode", "Provider response was not definitive")
    }
}
