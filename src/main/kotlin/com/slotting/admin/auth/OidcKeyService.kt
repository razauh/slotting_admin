package com.slotting.admin.auth

import com.fasterxml.jackson.databind.ObjectMapper
import java.math.BigInteger
import java.nio.charset.StandardCharsets
import java.security.KeyFactory
import java.security.KeyPair
import java.security.KeyPairGenerator
import java.security.Signature
import java.security.interfaces.RSAPrivateKey
import java.security.interfaces.RSAPublicKey
import java.security.spec.RSAPublicKeySpec
import java.time.Clock
import java.time.Duration
import java.time.Instant
import java.util.Base64
import java.util.UUID
import java.util.concurrent.ConcurrentHashMap

data class IdTokenClaims(
    val iss: String,
    val sub: String,
    val aud: String,
    val exp: Long,
    val iat: Long,
    val authTime: Long,
    val nonce: String?,
    val tenantId: String
)

class OidcKeyService(
    private val clock: Clock = Clock.systemUTC(),
    val issuer: String = "https://auth.slotting.com",
    private val idTokenTtl: Duration = Duration.ofHours(1)
) {
    private val mapper = ObjectMapper()

    data class KeyEntry(
        val kid: String,
        val keyPair: KeyPair,
        val createdAt: Instant,
        var retiredAt: Instant? = null
    )

    private val keys = ConcurrentHashMap<String, KeyEntry>()
    @Volatile
    private var activeKid: String

    init {
        val initialEntry = generateNewKeyPair()
        keys[initialEntry.kid] = initialEntry
        activeKid = initialEntry.kid
    }

    private fun generateNewKeyPair(): KeyEntry {
        val kpg = KeyPairGenerator.getInstance("RSA")
        kpg.initialize(2048)
        val kp = kpg.generateKeyPair()
        val kid = "key-${UUID.randomUUID().toString().substring(0, 8)}"
        return KeyEntry(kid = kid, keyPair = kp, createdAt = Instant.now(clock))
    }

    fun rotateActiveKey(): String {
        val newEntry = generateNewKeyPair()
        keys[newEntry.kid] = newEntry
        val oldKid = activeKid
        keys[oldKid]?.retiredAt = Instant.now(clock)
        activeKid = newEntry.kid
        return newEntry.kid
    }

    fun getActiveKid(): String = activeKid

    fun getJwks(): Map<String, Any> {
        val keyList = keys.values.map { entry ->
            val pub = entry.keyPair.public as RSAPublicKey
            mapOf(
                "kty" to "RSA",
                "alg" to "RS256",
                "use" to "sig",
                "kid" to entry.kid,
                "n" to Base64.getUrlEncoder().withoutPadding().encodeToString(pub.modulus.toByteArray().stripLeadingZero()),
                "e" to Base64.getUrlEncoder().withoutPadding().encodeToString(pub.publicExponent.toByteArray().stripLeadingZero())
            )
        }
        return mapOf("keys" to keyList)
    }

    fun issueIdToken(
        playerId: UUID,
        clientId: String,
        tenantId: String,
        nonce: String?,
        authTime: Instant = Instant.now(clock)
    ): String {
        val now = Instant.now(clock)
        val exp = now.plus(idTokenTtl)
        val entry = keys[activeKid] ?: throw IllegalStateException("Active signing key not found")

        val header = mapOf(
            "alg" to "RS256",
            "typ" to "JWT",
            "kid" to entry.kid
        )

        val claims = mutableMapOf<String, Any>(
            "iss" to issuer,
            "sub" to playerId.toString(),
            "aud" to clientId,
            "exp" to exp.epochSecond,
            "iat" to now.epochSecond,
            "auth_time" to authTime.epochSecond,
            "tenant_id" to tenantId
        )
        if (!nonce.isNullOrBlank()) {
            claims["nonce"] = nonce
        }

        val headerJson = mapper.writeValueAsString(header)
        val claimsJson = mapper.writeValueAsString(claims)

        val encodedHeader = Base64.getUrlEncoder().withoutPadding().encodeToString(headerJson.toByteArray(StandardCharsets.UTF_8))
        val encodedPayload = Base64.getUrlEncoder().withoutPadding().encodeToString(claimsJson.toByteArray(StandardCharsets.UTF_8))

        val signingInput = "$encodedHeader.$encodedPayload"
        val privateKey = entry.keyPair.private as RSAPrivateKey
        val signer = Signature.getInstance("SHA256withRSA")
        signer.initSign(privateKey)
        signer.update(signingInput.toByteArray(StandardCharsets.US_ASCII))
        val signatureBytes = signer.sign()
        val encodedSignature = Base64.getUrlEncoder().withoutPadding().encodeToString(signatureBytes)

        return "$signingInput.$encodedSignature"
    }

    fun validateIdToken(
        idToken: String,
        expectedClientId: String,
        expectedNonce: String? = null,
        now: Instant = Instant.now(clock)
    ): IdTokenClaims {
        val parts = idToken.split(".")
        if (parts.size != 3) {
            throw IllegalArgumentException("Malformed ID token: must contain 3 parts")
        }

        val headerJson = String(Base64.getUrlDecoder().decode(parts[0]), StandardCharsets.UTF_8)
        val header = mapper.readValue(headerJson, Map::class.java)

        val alg = header["alg"] as? String
        if (alg != "RS256") {
            throw IllegalArgumentException("Unsupported or dangerous algorithm: $alg")
        }

        val kid = header["kid"] as? String
            ?: throw IllegalArgumentException("Missing kid in token header")

        val entry = keys[kid]
            ?: throw IllegalArgumentException("Unknown signing key kid: $kid")

        // Signature check
        val signingInput = "${parts[0]}.${parts[1]}"
        val signatureBytes = Base64.getUrlDecoder().decode(parts[2])
        val verifier = Signature.getInstance("SHA256withRSA")
        verifier.initVerify(entry.keyPair.public)
        verifier.update(signingInput.toByteArray(StandardCharsets.US_ASCII))
        if (!verifier.verify(signatureBytes)) {
            throw IllegalArgumentException("Invalid ID token signature")
        }

        val payloadJson = String(Base64.getUrlDecoder().decode(parts[1]), StandardCharsets.UTF_8)
        val payload = mapper.readValue(payloadJson, Map::class.java)

        val iss = payload["iss"] as? String
            ?: throw IllegalArgumentException("Missing iss claim")
        if (iss != issuer) {
            throw IllegalArgumentException("Issuer mismatch: expected $issuer, got $iss")
        }

        val aud = payload["aud"] as? String
            ?: throw IllegalArgumentException("Missing aud claim")
        if (aud != expectedClientId) {
            throw IllegalArgumentException("Audience mismatch: expected $expectedClientId, got $aud")
        }

        val exp = (payload["exp"] as? Number)?.toLong()
            ?: throw IllegalArgumentException("Missing exp claim")
        if (now.epochSecond >= exp) {
            throw IllegalArgumentException("ID token expired at $exp (current time ${now.epochSecond})")
        }

        val iat = (payload["iat"] as? Number)?.toLong() ?: 0L
        val authTime = (payload["auth_time"] as? Number)?.toLong() ?: iat
        val sub = payload["sub"] as? String
            ?: throw IllegalArgumentException("Missing sub claim")
        val tenantId = payload["tenant_id"] as? String ?: "default"
        val tokenNonce = payload["nonce"] as? String

        if (expectedNonce != null && tokenNonce != expectedNonce) {
            throw IllegalArgumentException("Nonce mismatch: expected $expectedNonce, got $tokenNonce")
        }

        return IdTokenClaims(
            iss = iss,
            sub = sub,
            aud = aud,
            exp = exp,
            iat = iat,
            authTime = authTime,
            nonce = tokenNonce,
            tenantId = tenantId
        )
    }

    private fun ByteArray.stripLeadingZero(): ByteArray {
        return if (this.isNotEmpty() && this[0] == 0.toByte()) {
            val stripped = ByteArray(this.size - 1)
            System.arraycopy(this, 1, stripped, 0, stripped.size)
            stripped
        } else {
            this
        }
    }
}
