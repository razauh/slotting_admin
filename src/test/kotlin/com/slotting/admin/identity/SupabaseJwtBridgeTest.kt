package com.slotting.admin.identity

import com.fasterxml.jackson.databind.ObjectMapper
import org.junit.jupiter.api.Test
import java.nio.charset.StandardCharsets
import java.nio.file.Files
import java.nio.file.Path
import java.time.Clock
import java.time.Duration
import java.time.Instant
import java.time.ZoneOffset
import java.util.Base64
import java.util.UUID
import javax.crypto.Mac
import javax.crypto.spec.SecretKeySpec
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertTrue

class SupabaseJwtBridgeTest {
    private val now = Instant.parse("2026-11-08T12:00:00Z")
    private val fixedClock = Clock.fixed(now, ZoneOffset.UTC)
    private val secret = "tc13-test-self-hosted-jwt-secret-0123456789".toByteArray(StandardCharsets.UTF_8)
    private val keyId = "tc13-test-key-1"
    private val provider = StaticJwtSigningKeyProvider(keyId, secret)
    private val tenantA = "tenant-tc13-a"
    private val tenantB = "tenant-tc13-b"
    private val playerA = UUID.fromString("00000000-0000-0000-0000-0000000013a1")

    @Test
    fun issuesShortLivedSupabaseCompatibleJwtWithMinimalClaimsAndValidSignature() {
        val store = InMemoryPlayerSessionStore()
        val session = newSession(store, tenantA, playerA)
        val bridge = SupabaseJwtBridgeService(store, provider, fixedClock)
        val result = bridge.issueForSession(tenantA, session.sessionId)
        val parts = result.token.split(".")
        assertEquals(3, parts.size)
        val header = decode(parts[0])
        val claims = decode(parts[1])
        assertEquals("HS256", header["alg"])
        assertEquals("JWT", header["typ"])
        assertFalse(header.containsKey("kid"))
        assertEquals(playerA.toString(), claims["sub"])
        assertEquals(tenantA, claims["tenant_id"])
        assertEquals("authenticated", claims["role"])
        assertEquals(playerA.toString(), claims["player_id"])
        assertEquals(session.sessionId.toString(), claims["session_id"])
        assertEquals("authenticated", claims["aud"])
        assertEquals(now.epochSecond, (claims["iat"] as Number).toLong())
        assertEquals(now.plus(Duration.ofMinutes(15)).epochSecond, (claims["exp"] as Number).toLong())
        assertEquals(base64Url(hmac(secret, "${parts[0]}.${parts[1]}")), parts[2])
        val forbidden = setOf("balance", "wallet", "amount", "currency", "ledger", "payout", "debit", "credit")
        assertTrue(claims.keys.none { it in forbidden })
        val validation = bridge.validate(result.token, tenantA)
        assertTrue(validation.valid)
        assertEquals(playerA, validation.playerId)
        assertEquals(session.sessionId, validation.sessionId)
        writeClaimsEvidence(header, claims)
    }

    @Test
    fun rejectsExpiredToken() {
        val store = InMemoryPlayerSessionStore()
        val session = newSession(store, tenantA, playerA)
        val bridge = SupabaseJwtBridgeService(store, provider, fixedClock)
        val result = bridge.issueForSession(tenantA, session.sessionId)
        val lateBridge = SupabaseJwtBridgeService(store, provider, Clock.fixed(now.plus(Duration.ofMinutes(16)), ZoneOffset.UTC))
        val validation = lateBridge.validate(result.token, tenantA)
        assertFalse(validation.valid)
        assertEquals("EXPIRED", validation.reason)
    }

    @Test
    fun rejectsTokenAfterSessionTermination() {
        val store = InMemoryPlayerSessionStore()
        val session = newSession(store, tenantA, playerA)
        val bridge = SupabaseJwtBridgeService(store, provider, fixedClock)
        val result = bridge.issueForSession(tenantA, session.sessionId)
        session.state = SessionState.TERMINATED
        session.terminatedAt = now.plusSeconds(1)
        val validation = bridge.validate(result.token, tenantA)
        assertFalse(validation.valid)
        assertEquals("REVOKED", validation.reason)
    }

    @Test
    fun rejectsCrossTenantValidation() {
        val store = InMemoryPlayerSessionStore()
        val session = newSession(store, tenantA, playerA)
        val bridge = SupabaseJwtBridgeService(store, provider, fixedClock)
        val result = bridge.issueForSession(tenantA, session.sessionId)
        val validation = bridge.validate(result.token, tenantB)
        assertFalse(validation.valid)
        assertEquals("CROSS_TENANT", validation.reason)
    }

    @Test
    fun rejectsTokenSignedWithDifferentSecret() {
        val store = InMemoryPlayerSessionStore()
        val session = newSession(store, tenantA, playerA)
        val bridge = SupabaseJwtBridgeService(store, provider, fixedClock)
        val otherSecret = "tc13-other-self-hosted-jwt-secret-9876543210".toByteArray(StandardCharsets.UTF_8)
        val otherBridge = SupabaseJwtBridgeService(store, StaticJwtSigningKeyProvider(keyId, otherSecret), fixedClock)
        val otherToken = otherBridge.issueForSession(tenantA, session.sessionId)
        val validation = bridge.validate(otherToken.token, tenantA)
        assertFalse(validation.valid)
        assertEquals("INVALID_SIGNATURE", validation.reason)
    }

    @Test
    fun rejectsFinancialClaimsInForgedToken() {
        val store = InMemoryPlayerSessionStore()
        val session = newSession(store, tenantA, playerA)
        val bridge = SupabaseJwtBridgeService(store, provider, fixedClock)
        val result = bridge.issueForSession(tenantA, session.sessionId)
        val parts = result.token.split(".")
        val header = decode(parts[0])
        val claims = decode(parts[1]) + mapOf("balance" to 100)
        val forged = forgeToken(header, claims, secret)
        val validation = bridge.validate(forged, tenantA)
        assertFalse(validation.valid)
        assertEquals("INVALID_CLAIMS", validation.reason)
    }

    @Test
    fun keepsPreviousSigningKeyValidDuringRotationOverlap() {
        val store = InMemoryPlayerSessionStore()
        val session = newSession(store, tenantA, playerA)
        val oldSecret = "tc13-old-self-hosted-jwt-secret-0123456789".toByteArray(StandardCharsets.UTF_8)
        val newSecret = "tc13-new-self-hosted-jwt-secret-0123456789".toByteArray(StandardCharsets.UTF_8)
        val oldKey = JwtSigningKey("tc13-key-old", oldSecret)
        val newKey = JwtSigningKey("tc13-key-new", newSecret)
        val oldBridge = SupabaseJwtBridgeService(store, StaticJwtSigningKeyProvider(oldKey.keyId, oldKey.secret), fixedClock)
        val rotatingBridge = SupabaseJwtBridgeService(store, RotatingJwtSigningKeyProvider(newKey, listOf(oldKey)), fixedClock)
        val retiredBridge = SupabaseJwtBridgeService(store, StaticJwtSigningKeyProvider(newKey.keyId, newKey.secret), fixedClock)
        val oldToken = oldBridge.issueForSession(tenantA, session.sessionId)
        assertTrue(rotatingBridge.validate(oldToken.token, tenantA).valid)
        val retiredValidation = retiredBridge.validate(oldToken.token, tenantA)
        assertFalse(retiredValidation.valid)
        assertEquals("INVALID_SIGNATURE", retiredValidation.reason)
    }

    @Test
    fun doesNotExposeTokenInResultToString() {
        val store = InMemoryPlayerSessionStore()
        val session = newSession(store, tenantA, playerA)
        val bridge = SupabaseJwtBridgeService(store, provider, fixedClock)
        val result = bridge.issueForSession(tenantA, session.sessionId)
        assertFalse(result.toString().contains(result.token))
    }

    @Test
    fun environmentProviderReadsConfiguredSecret() {
        val environmentSecret = "tc13-environment-self-hosted-secret-0123456789".toByteArray(StandardCharsets.UTF_8)
        val provider = EnvironmentJwtSigningKeyProvider(mapOf(
            "SLOTTING_SUPABASE_JWT_SECRET" to String(environmentSecret, StandardCharsets.UTF_8),
            "SLOTTING_SUPABASE_JWT_KEY_ID" to "env-key",
        ))
        assertEquals("env-key", provider.activeKey().keyId)
        assertTrue(environmentSecret.contentEquals(provider.activeKey().secret))
    }

    @Test
    fun environmentSecretIssuesValidToken() {
        val store = InMemoryPlayerSessionStore()
        val session = newSession(store, tenantA, playerA)
        val provider = EnvironmentJwtSigningKeyProvider()
        val bridge = SupabaseJwtBridgeService(store, provider, fixedClock)
        val result = bridge.issueForSession(tenantA, session.sessionId)
        val parts = result.token.split(".")
        val header = decode(parts[0])
        val claims = decode(parts[1])
        assertEquals("HS256", header["alg"])
        assertFalse(header.containsKey("kid"))
        assertEquals(tenantA, claims["tenant_id"])
        assertEquals("authenticated", claims["role"])
        assertEquals(base64Url(hmac(provider.activeKey().secret, "${parts[0]}.${parts[1]}")), parts[2])
        val validation = bridge.validate(result.token, tenantA)
        assertTrue(validation.valid)
        writeClaimsEvidence(".logs/tc13-real-secret-decoded-claims.json", header, claims)
    }

    @Test
    fun writesRevocationRowOnSessionTermination() {
        val records = mutableListOf<Triple<String, UUID, String>>()
        val writer = SessionRevocationWriter { tenantId, sessionId, _, reason ->
            records.add(Triple(tenantId, sessionId, reason))
        }
        val store = InMemoryPlayerSessionStore(writer)
        val sessionA = newSession(store, tenantA, playerA)
        store.terminateSession(tenantA, sessionA.sessionId, fixedClock.instant())
        assertEquals(listOf(Triple(tenantA, sessionA.sessionId, "LOGOUT")), records)
        val playerB = UUID.fromString("00000000-0000-0000-0000-0000000013b1")
        val sessionB = newSession(store, tenantB, playerB)
        store.revokeAllPlayerSessions(tenantB, playerB, fixedClock.instant())
        assertTrue(records.any { it.second == sessionB.sessionId && it.third == "REVOKE_ALL" })
    }

    @Test
    fun disabledBridgeDoesNotIssueOrValidate() {
        val store = InMemoryPlayerSessionStore()
        val session = newSession(store, tenantA, playerA)
        val bridge = SupabaseJwtBridgeService(store, provider, fixedClock, enabled = false)
        assertFailsWith<IllegalStateException> { bridge.issueForSession(tenantA, session.sessionId) }
        val validation = bridge.validate("not-a-token", tenantA)
        assertFalse(validation.valid)
        assertEquals("DISABLED", validation.reason)
    }

    private fun newSession(store: InMemoryPlayerSessionStore, tenantId: String, playerId: UUID): PlayerSession {
        val session = PlayerSession(
            sessionId = UUID.randomUUID(),
            tenantId = tenantId,
            playerId = playerId,
            accessToken = "opaque-access-${UUID.randomUUID()}",
            refreshToken = "opaque-refresh-${UUID.randomUUID()}",
            state = SessionState.ACTIVE,
            createdAt = now,
            expiresAt = now.plus(Duration.ofHours(1)),
        )
        store.sessions[session.sessionId] = session
        return session
    }

    @Suppress("UNCHECKED_CAST")
    private fun decode(part: String): Map<String, Any> =
        ObjectMapper().readValue(Base64.getUrlDecoder().decode(part), Map::class.java) as Map<String, Any>

    private fun writeClaimsEvidence(header: Map<String, Any>, claims: Map<String, Any>) {
        writeClaimsEvidence(".logs/tc13-decoded-claims.json", header, claims)
    }

    private fun writeClaimsEvidence(path: String, header: Map<String, Any>, claims: Map<String, Any>) {
        Files.createDirectories(Path.of(".logs"))
        val evidence = linkedMapOf(
            "header" to header,
            "claims" to claims,
            "token" to "[REDACTED]",
        )
        Files.writeString(
            Path.of(path),
            ObjectMapper().writerWithDefaultPrettyPrinter().writeValueAsString(evidence),
        )
    }

    private fun forgeToken(header: Map<String, Any>, claims: Map<String, Any>, secret: ByteArray): String {
        val mapper = ObjectMapper()
        val headerPart = base64Url(mapper.writeValueAsBytes(header))
        val payloadPart = base64Url(mapper.writeValueAsBytes(claims))
        val signature = base64Url(hmac(secret, "$headerPart.$payloadPart"))
        return "$headerPart.$payloadPart.$signature"
    }

    private fun base64Url(bytes: ByteArray): String =
        Base64.getUrlEncoder().withoutPadding().encodeToString(bytes)

    private fun hmac(secret: ByteArray, input: String): ByteArray {
        val mac = Mac.getInstance("HmacSHA256")
        mac.init(SecretKeySpec(secret, "HmacSHA256"))
        return mac.doFinal(input.toByteArray(StandardCharsets.UTF_8))
    }

    @Test
    fun issuesForDurableLoginSessionWithoutAPlayerSessionStoreLookup() {
        val sessionId = UUID.fromString("00000000-0000-0000-0000-0000000013b1")
        val bridge = SupabaseJwtBridgeService(InMemoryPlayerSessionStore(), provider, fixedClock)
        val result = bridge.issueForSession(tenantA, playerA, sessionId, now.plus(Duration.ofMinutes(10)))
        val claims = decode(result.token.split(".")[1])
        assertEquals(playerA.toString(), claims["sub"])
        assertEquals(tenantA, claims["tenant_id"])
        assertEquals(sessionId.toString(), claims["session_id"])
        assertEquals("authenticated", claims["aud"])
        assertEquals(now.plus(Duration.ofMinutes(10)).epochSecond, (claims["exp"] as Number).toLong())
    }
}
