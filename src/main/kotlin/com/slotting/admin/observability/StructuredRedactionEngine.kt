package com.slotting.admin.observability

import java.util.regex.Pattern

object StructuredRedactionEngine {

    private val SENSITIVE_KEY_SUBSTRINGS = listOf(
        "password",
        "passwd",
        "secret",
        "token",
        "authorization",
        "auth",
        "api_key",
        "apikey",
        "access_token",
        "refresh_token",
        "private_key",
        "credential",
        "pin",
        "otp",
        "mfa",
        "mfa_code",
        "cvv",
        "cvc",
        "security_code",
        "card",
        "cardnumber",
        "card_number",
        "pan",
        "jwt",
        "bearer",
        "cookie",
        "set-cookie",
        "session_token",
        "session_id",
        "encryption_key"
    )

    private val BEARER_JWT_PATTERN = Pattern.compile("(?i)(bearer\\s+|jwt\\s+)[A-Za-z0-9_\\-\\.]+")
    private val PAN_PATTERN = Pattern.compile("\\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13}|\\d{13,19})\\b")
    private val SSN_PATTERN = Pattern.compile("\\b\\d{3}-\\d{2}-\\d{4}\\b")
    private val EMAIL_PATTERN = Pattern.compile("[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\\.[a-zA-Z0-9-.]+")
    private val QUERY_PARAM_SECRET = Pattern.compile("(?i)(token|jwt|auth|key|secret|password|api_key|pin|otp)=([^\\s&,;]+)")
    private val HEADER_SECRET_PATTERN = Pattern.compile("(?i)(authorization|proxy-authorization|x-api-key|cookie):\\s*([^\\r\\n]+)")

    fun redactMap(input: Map<*, *>): Map<String, Any?> {
        val result = mutableMapOf<String, Any?>()
        for ((k, v) in input) {
            val keyStr = k?.toString() ?: "null"
            val keyLower = keyStr.lowercase()
            if (v is Map<*, *>) {
                result[keyStr] = redactMap(v)
            } else if (v is List<*>) {
                result[keyStr] = redactList(v)
            } else if (isSensitiveKey(keyLower)) {
                result[keyStr] = "[REDACTED_SECRET]"
            } else {
                result[keyStr] = redactValue(v)
            }
        }
        return result
    }

    fun redactList(input: List<*>): List<Any?> {
        return input.map { redactValue(it) }
    }

    fun redactValue(value: Any?): Any? {
        return when (value) {
            null -> null
            is Map<*, *> -> redactMap(value)
            is List<*> -> redactList(value)
            is Set<*> -> redactList(value.toList())
            is Array<*> -> redactList(value.toList())
            is String -> redactString(value)
            is Number, is Boolean -> value
            else -> redactString(value.toString())
        }
    }

    fun redactString(input: String): String {
        var s = input
        s = BEARER_JWT_PATTERN.matcher(s).replaceAll("Bearer [REDACTED_TOKEN]")
        s = HEADER_SECRET_PATTERN.matcher(s).replaceAll("$1: [REDACTED_HEADER]")
        s = QUERY_PARAM_SECRET.matcher(s).replaceAll("$1=[REDACTED_SECRET]")
        s = PAN_PATTERN.matcher(s).replaceAll("[REDACTED_PAN]")
        s = SSN_PATTERN.matcher(s).replaceAll("[REDACTED_SSN]")
        s = EMAIL_PATTERN.matcher(s).replaceAll("[REDACTED_EMAIL]")
        return s
    }

    private fun isSensitiveKey(keyLower: String): Boolean {
        return SENSITIVE_KEY_SUBSTRINGS.any { keyLower.contains(it) }
    }
}
