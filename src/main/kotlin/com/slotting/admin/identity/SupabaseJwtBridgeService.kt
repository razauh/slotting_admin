package com.slotting.admin.identity

import com.fasterxml.jackson.databind.ObjectMapper
import java.nio.charset.StandardCharsets
import java.security.MessageDigest
import java.time.Clock
import java.time.Duration
import java.time.Instant
import java.util.Base64
import java.util.UUID
import javax.crypto.Mac
import javax.crypto.spec.SecretKeySpec

data class JwtSigningKey(
    val keyId: String,
    val secret: ByteArray,
)

interface JwtSigningKeyProvider {
    fun activeKey(): JwtSigningKey
    fun verificationKeys(): Map<String, ByteArray>
}

class StaticJwtSigningKeyProvider(
    keyId: String,
    secret: ByteArray,
) : JwtSigningKeyProvider {
    private val key = JwtSigningKey(keyId, secret.copyOf())

    init {
        require(keyId.isNotBlank())
        require(secret.size >= 32)
    }

    override fun activeKey(): JwtSigningKey = JwtSigningKey(key.keyId, key.secret.copyOf())

    override fun verificationKeys(): Map<String, ByteArray> =
        mapOf(key.keyId to key.secret.copyOf())
}

class RotatingJwtSigningKeyProvider(
    private val active: JwtSigningKey,
    previous: List<JwtSigningKey> = emptyList(),
) : JwtSigningKeyProvider {
    private val previousKeys = previous.associate { it.keyId to it.secret.copyOf() }

    init {
        require(active.keyId.isNotBlank())
        require(active.secret.size >= 32)
        previous.forEach {
            require(it.keyId.isNotBlank())
            require(it.secret.size >= 32)
        }
    }

    override fun activeKey(): JwtSigningKey = JwtSigningKey(active.keyId, active.secret.copyOf())

    override fun verificationKeys(): Map<String, ByteArray> =
        previousKeys + mapOf(active.keyId to active.secret.copyOf())
}

class EnvironmentJwtSigningKeyProvider(
    private val environment: Map<String, String> = System.getenv(),
) : JwtSigningKeyProvider {
    private val keyId = environment["SLOTTING_SUPABASE_JWT_KEY_ID"]?.takeIf { it.isNotBlank() } ?: "supabase"
    private val secret = (
        environment["SLOTTING_SUPABASE_JWT_SECRET"]
            ?: environment["SUPABASE_JWT_SECRET"]
            ?: throw IllegalStateException("Missing SLOTTING_SUPABASE_JWT_SECRET or SUPABASE_JWT_SECRET")
        ).toByteArray(StandardCharsets.UTF_8)

    init {
        require(secret.size >= 32) { "JWT signing secret must be at least 32 bytes" }
    }

    override fun activeKey(): JwtSigningKey = JwtSigningKey(keyId, secret.copyOf())

    override fun verificationKeys(): Map<String, ByteArray> =
        mapOf(keyId to secret.copyOf())
}

data class SupabaseJwtIssueResult(
    val token: String,
    val tokenId: String,
    val tenantId: String,
    val playerId: UUID,
    val sessionId: UUID,
    val issuedAt: Instant,
    val expiresAt: Instant,
    val claims: Map<String, Any>,
) {
    override fun toString(): String =
        "SupabaseJwtIssueResult(token=[REDACTED], tokenId=$tokenId, tenantId=$tenantId, playerId=$playerId, sessionId=$sessionId, issuedAt=$issuedAt, expiresAt=$expiresAt, claims=$claims)"
}

data class SupabaseJwtValidationResult(
    val valid: Boolean,
    val tenantId: String? = null,
    val playerId: UUID? = null,
    val sessionId: UUID? = null,
    val expiresAt: Instant? = null,
    val reason: String? = null,
)

class SupabaseJwtBridgeService(
    private val sessionStore: PlayerSessionStore,
    private val signingKeys: JwtSigningKeyProvider,
    private val clock: Clock = Clock.systemUTC(),
    private val ttl: Duration = Duration.ofMinutes(15),
    private val enabled: Boolean = true,
) {
    private val mapper = ObjectMapper()

    fun issueForSession(tenantId: String, sessionId: UUID): SupabaseJwtIssueResult {
        if (!enabled) {
            throw IllegalStateException("Supabase JWT bridge is disabled")
        }
        require(tenantId.isNotBlank()) { "tenantId must not be blank" }
        val session = sessionStore.findSession(tenantId, sessionId)
            ?: throw IllegalArgumentException("session not found")
        if (session.state != SessionState.ACTIVE) {
            throw IllegalArgumentException("session is not active")
        }
        val now = clock.instant()
        if (!now.isBefore(session.expiresAt)) {
            throw IllegalArgumentException("session is expired")
        }
        val expiresAt = minOf(session.expiresAt, now.plus(ttl))
        if (!expiresAt.isAfter(now)) {
            throw IllegalArgumentException("token expiry must be in the future")
        }
        val tokenId = UUID.randomUUID()
        val key = signingKeys.activeKey()
        val claims = buildClaims(tenantId, session, sessionId, tokenId, now, expiresAt)
        val header = linkedMapOf<String, Any>(
            "alg" to "HS256",
            "typ" to "JWT",
        )
        val headerPart = base64Url(mapper.writeValueAsBytes(header))
        val payloadPart = base64Url(mapper.writeValueAsBytes(claims))
        val signature = base64Url(hmacSha256(key.secret, "$headerPart.$payloadPart"))
        return SupabaseJwtIssueResult(
            token = "$headerPart.$payloadPart.$signature",
            tokenId = tokenId.toString(),
            tenantId = tenantId,
            playerId = session.playerId,
            sessionId = sessionId,
            issuedAt = now,
            expiresAt = expiresAt,
            claims = claims,
        )
    }

    fun issueForSession(
        tenantId: String,
        playerId: UUID,
        sessionId: UUID,
        sessionExpiresAt: Instant,
    ): SupabaseJwtIssueResult {
        if (!enabled) {
            throw IllegalStateException("Supabase JWT bridge is disabled")
        }
        require(tenantId.isNotBlank()) { "tenantId must not be blank" }
        val now = clock.instant()
        if (!now.isBefore(sessionExpiresAt)) {
            throw IllegalArgumentException("session is expired")
        }
        val expiresAt = minOf(sessionExpiresAt, now.plus(ttl))
        if (!expiresAt.isAfter(now)) {
            throw IllegalArgumentException("token expiry must be in the future")
        }
        val tokenId = UUID.randomUUID()
        val key = signingKeys.activeKey()
        val claims = buildClaims(tenantId, playerId, sessionId, tokenId, now, expiresAt)
        val header = linkedMapOf<String, Any>(
            "alg" to "HS256",
            "typ" to "JWT",
        )
        val headerPart = base64Url(mapper.writeValueAsBytes(header))
        val payloadPart = base64Url(mapper.writeValueAsBytes(claims))
        val signature = base64Url(hmacSha256(key.secret, "$headerPart.$payloadPart"))
        return SupabaseJwtIssueResult(
            token = "$headerPart.$payloadPart.$signature",
            tokenId = tokenId.toString(),
            tenantId = tenantId,
            playerId = playerId,
            sessionId = sessionId,
            issuedAt = now,
            expiresAt = expiresAt,
            claims = claims,
        )
    }

    fun validate(token: String, expectedTenantId: String? = null): SupabaseJwtValidationResult {
        if (!enabled) {
            return SupabaseJwtValidationResult(valid = false, reason = "DISABLED")
        }
        if (token.isBlank()) {
            return SupabaseJwtValidationResult(valid = false, reason = "INVALID")
        }
        val parts = token.split(".")
        if (parts.size != 3) {
            return SupabaseJwtValidationResult(valid = false, reason = "INVALID")
        }
        val header = decodeJson(parts[0])
            ?: return SupabaseJwtValidationResult(valid = false, reason = "INVALID")
        val claims = decodeJson(parts[1])
            ?: return SupabaseJwtValidationResult(valid = false, reason = "INVALID")
        if (header["alg"] != "HS256") {
            return SupabaseJwtValidationResult(valid = false, reason = "INVALID")
        }
        val keyId = header["kid"] as? String
        val verificationKeys = signingKeys.verificationKeys()
        val signatureValid = if (keyId != null) {
            val key = verificationKeys[keyId] ?: return SupabaseJwtValidationResult(valid = false, reason = "INVALID_SIGNATURE")
            signatureMatches(key, parts)
        } else {
            verificationKeys.values.any { signatureMatches(it, parts) }
        }
        if (!signatureValid) {
            return SupabaseJwtValidationResult(valid = false, reason = "INVALID_SIGNATURE")
        }
        if (claims.keys.any { it in FORBIDDEN_FINANCIAL_CLAIMS }) {
            return SupabaseJwtValidationResult(valid = false, reason = "INVALID_CLAIMS")
        }
        val tenantId = claims["tenant_id"] as? String
        val playerId = (claims["player_id"] as? String)?.let(::parseUuid)
        val subject = (claims["sub"] as? String)?.let(::parseUuid)
        val sessionId = (claims["session_id"] as? String)?.let(::parseUuid)
        val role = claims["role"] as? String
        val issuedAt = (claims["iat"] as? Number)?.toLong()
        val expiresAt = (claims["exp"] as? Number)?.toLong()
        if (tenantId == null || playerId == null || subject == null || sessionId == null || role != "authenticated" || issuedAt == null || expiresAt == null) {
            return SupabaseJwtValidationResult(valid = false, reason = "INVALID_CLAIMS")
        }
        if (subject != playerId) {
            return SupabaseJwtValidationResult(valid = false, reason = "INVALID_CLAIMS")
        }
        if (expectedTenantId != null && expectedTenantId != tenantId) {
            return SupabaseJwtValidationResult(valid = false, reason = "CROSS_TENANT")
        }
        val now = clock.instant()
        if (now.epochSecond >= expiresAt) {
            return SupabaseJwtValidationResult(valid = false, reason = "EXPIRED")
        }
        if (issuedAt > now.epochSecond + CLOCK_SKEW_SECONDS) {
            return SupabaseJwtValidationResult(valid = false, reason = "INVALID_CLAIMS")
        }
        val session = sessionStore.findSession(tenantId, sessionId)
            ?: return SupabaseJwtValidationResult(valid = false, reason = "REVOKED")
        if (session.playerId != playerId || session.state != SessionState.ACTIVE || !now.isBefore(session.expiresAt)) {
            return SupabaseJwtValidationResult(valid = false, reason = "REVOKED")
        }
        return SupabaseJwtValidationResult(
            valid = true,
            tenantId = tenantId,
            playerId = playerId,
            sessionId = sessionId,
            expiresAt = Instant.ofEpochSecond(expiresAt),
        )
    }

    private fun buildClaims(
        tenantId: String,
        session: PlayerSession,
        sessionId: UUID,
        tokenId: UUID,
        issuedAt: Instant,
        expiresAt: Instant,
    ): Map<String, Any> = buildClaims(tenantId, session.playerId, sessionId, tokenId, issuedAt, expiresAt)

    private fun buildClaims(
        tenantId: String,
        playerId: UUID,
        sessionId: UUID,
        tokenId: UUID,
        issuedAt: Instant,
        expiresAt: Instant,
    ): Map<String, Any> = linkedMapOf<String, Any>(
        "sub" to playerId.toString(),
        "tenant_id" to tenantId,
        "role" to "authenticated",
        "player_id" to playerId.toString(),
        "session_id" to sessionId.toString(),
        "jti" to tokenId.toString(),
        "aud" to "authenticated",
        "iat" to issuedAt.epochSecond,
        "exp" to expiresAt.epochSecond,
    )

    @Suppress("UNCHECKED_CAST")
    private fun decodeJson(part: String): Map<String, Any>? =
        runCatching {
            mapper.readValue(Base64.getUrlDecoder().decode(part), Map::class.java) as Map<String, Any>
        }.getOrNull()

    private fun parseUuid(value: String): UUID? =
        runCatching { UUID.fromString(value) }.getOrNull()

    private fun base64Url(bytes: ByteArray): String =
        Base64.getUrlEncoder().withoutPadding().encodeToString(bytes)

    private fun hmacSha256(secret: ByteArray, input: String): ByteArray {
        val mac = Mac.getInstance("HmacSHA256")
        mac.init(SecretKeySpec(secret, "HmacSHA256"))
        return mac.doFinal(input.toByteArray(StandardCharsets.UTF_8))
    }

    private fun signatureMatches(secret: ByteArray, parts: List<String>): Boolean {
        val expected = base64Url(hmacSha256(secret, "${parts[0]}.${parts[1]}"))
        return MessageDigest.isEqual(expected.toByteArray(StandardCharsets.UTF_8), parts[2].toByteArray(StandardCharsets.UTF_8))
    }

    private companion object {
        private val FORBIDDEN_FINANCIAL_CLAIMS = setOf(
            "balance",
            "wallet",
            "amount",
            "currency",
            "ledger",
            "payout",
            "debit",
            "credit",
        )
        private const val CLOCK_SKEW_SECONDS = 60L
    }
}
