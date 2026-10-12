package com.slotting.admin.provider

import com.slotting.admin.provider.port.ProviderCallbackPayload
import org.slf4j.LoggerFactory
import java.nio.charset.StandardCharsets
import java.security.MessageDigest
import java.util.concurrent.ConcurrentHashMap
import javax.crypto.Mac
import javax.crypto.spec.SecretKeySpec

data class WebhookSignatureFixture(
    val providerId: String,
    val tenantId: String,
    val eventId: String,
    val rawPayload: String,
    val timestamp: String?,
    val signature: String,
)

enum class WebhookSignatureVerification {
    VALID,
    MISSING_HASH,
    MISSING_SECRET,
    INVALID_SIGNATURE,
    UNKNOWN_PROVIDER,
}

object WebhookSignatureFixtures {
    const val SAFEPAY_RAAST = "SAFEPAY_RAAST"
    const val TIMESTAMPED_DEPOSIT = "TIMESTAMPED_DEPOSIT"

    private val logger = LoggerFactory.getLogger(WebhookSignatureFixtures::class.java)
    private val canonicalizers = mapOf<String, (String, String?) -> String>(
        SAFEPAY_RAAST to { rawPayload, _ -> rawPayload },
        TIMESTAMPED_DEPOSIT to { rawPayload, timestamp ->
            require(!timestamp.isNullOrBlank()) { "TIMESTAMP_REQUIRED" }
            "$timestamp.$rawPayload"
        },
    )

    fun signedCallback(
        providerId: String,
        tenantId: String,
        eventId: String,
        rawPayload: String,
        secret: String?,
        timestamp: String? = null,
    ): WebhookSignatureFixture {
        require(tenantId.isNotBlank()) { "TENANT_REQUIRED" }
        require(eventId.isNotBlank()) { "EVENT_ID_REQUIRED" }
        require(!secret.isNullOrBlank()) { "SIGNING_KEY_UNAVAILABLE" }
        val canonicalizer = canonicalizers[providerId] ?: throw IllegalArgumentException("UNKNOWN_PROVIDER")
        val signature = hmacSha256(canonicalizer(rawPayload, timestamp), secret)
        logger.debug("webhook_fixture_signed provider={} eventId={}", providerId, eventId)
        return WebhookSignatureFixture(providerId, tenantId, eventId, rawPayload, timestamp, signature)
    }

    fun tamperedAmount(fixture: WebhookSignatureFixture): WebhookSignatureFixture {
        val amountPattern = Regex("(\\\"(?:amount|amountMinorUnits)\\\"\\s*:\\s*)(\\d+)")
        val match = amountPattern.find(fixture.rawPayload)
            ?: throw IllegalArgumentException("AMOUNT_FIELD_MISSING")
        val currentAmount = match.groupValues[2].toLongOrNull()
            ?: throw IllegalArgumentException("AMOUNT_FIELD_INVALID")
        val updatedPayload = fixture.rawPayload.replaceRange(
            match.groups[2]!!.range,
            (currentAmount + 1L).toString(),
        )
        return fixture.copy(rawPayload = updatedPayload)
    }

    fun withoutHash(fixture: WebhookSignatureFixture): WebhookSignatureFixture = fixture.copy(signature = "")

    fun verify(
        providerId: String,
        rawPayload: String,
        timestamp: String?,
        providedSignature: String?,
        secret: String?,
    ): WebhookSignatureVerification {
        if (providedSignature.isNullOrBlank()) return WebhookSignatureVerification.MISSING_HASH
        if (secret.isNullOrBlank()) return WebhookSignatureVerification.MISSING_SECRET
        val canonicalizer = canonicalizers[providerId] ?: return WebhookSignatureVerification.UNKNOWN_PROVIDER
        val canonical = try {
            canonicalizer(rawPayload, timestamp)
        } catch (_: IllegalArgumentException) {
            return WebhookSignatureVerification.INVALID_SIGNATURE
        }
        val expected = hmacSha256(canonical, secret)
        return if (MessageDigest.isEqual(
                expected.toByteArray(StandardCharsets.UTF_8),
                providedSignature.toByteArray(StandardCharsets.UTF_8),
            )
        ) {
            WebhookSignatureVerification.VALID
        } else {
            WebhookSignatureVerification.INVALID_SIGNATURE
        }
    }

    fun safepayCallback(fixture: WebhookSignatureFixture): ProviderCallbackPayload {
        require(fixture.providerId == SAFEPAY_RAAST) { "SAFEPAY_PROVIDER_REQUIRED" }
        return ProviderCallbackPayload(
            providerId = fixture.providerId,
            rawBody = fixture.rawPayload,
            headers = if (fixture.signature.isBlank()) emptyMap() else mapOf("x-sfpy-signature" to fixture.signature),
            queryParams = mapOf("event_id" to fixture.eventId),
        )
    }

    private fun hmacSha256(data: String, secret: String): String {
        val mac = Mac.getInstance("HmacSHA256")
        mac.init(SecretKeySpec(secret.toByteArray(StandardCharsets.UTF_8), "HmacSHA256"))
        return mac.doFinal(data.toByteArray(StandardCharsets.UTF_8))
            .joinToString("") { "%02x".format(it) }
    }
}

class WebhookReplayEventRegistry {
    private val processedEvents = ConcurrentHashMap.newKeySet<Pair<String, String>>()

    fun markIfNew(tenantId: String, eventId: String): Boolean {
        require(tenantId.isNotBlank()) { "TENANT_REQUIRED" }
        require(eventId.isNotBlank()) { "EVENT_ID_REQUIRED" }
        return processedEvents.add(tenantId to eventId)
    }
}
