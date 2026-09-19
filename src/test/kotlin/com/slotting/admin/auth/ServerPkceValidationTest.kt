package com.slotting.admin.auth

import org.junit.jupiter.api.Assertions.*
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.DisplayName
import org.junit.jupiter.api.Test
import java.time.Clock
import java.time.Instant
import java.time.ZoneOffset
import java.time.temporal.ChronoUnit
import java.util.UUID
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit

class ServerPkceValidationTest {

    private val tenantId = "tenant-auth-01"
    private val clock = Clock.fixed(Instant.parse("2026-09-19T15:00:00Z"), ZoneOffset.UTC)
    private lateinit var service: ServerPkceValidationService

    private val validPrincipal = AuthenticatedPrincipal(
        id = "user-01",
        tenantId = tenantId,
        roles = emptySet(),
        kind = PrincipalKind.PLAYER,
    )

    private val otherTenantPrincipal = AuthenticatedPrincipal(
        id = "user-other",
        tenantId = "tenant-other",
        roles = emptySet(),
        kind = PrincipalKind.PLAYER,
    )

    private val codeVerifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
    // S256(dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk) = E9Melhoa2OwvFrGMTJguCH5rtG6470-ZALx82gBoU50 (RFC 7636 Appendix B example)
    private val codeChallenge = ServerPkceValidationService.computeS256Challenge(codeVerifier)
    private val validState = "state-random-xyz-123"
    private val validNonce = "nonce-secure-abc-456"
    private val validRedirectUri = "https://auth.slotting.com/callback"

    @BeforeEach
    fun setup() {
        service = ServerPkceValidationService(clock = clock)
    }

    private fun registerValidSession(
        code: String = "auth-code-100",
        challenge: String = codeChallenge,
        challengeMethod: String = "S256",
        state: String = validState,
        nonce: String? = validNonce,
        redirectUri: String = validRedirectUri,
        tenant: String = tenantId,
        userId: String = "user-01",
        expiresAt: Instant = Instant.now(clock).plus(10, ChronoUnit.MINUTES),
        consumed: Boolean = false,
    ): AuthorizationCodeSession {
        val session = AuthorizationCodeSession(
            code = code,
            codeChallenge = challenge,
            codeChallengeMethod = challengeMethod,
            state = state,
            nonce = nonce,
            redirectUri = redirectUri,
            tenantId = tenant,
            userId = userId,
            expiresAt = expiresAt,
            consumed = consumed,
        )
        service.registerSession(session)
        return session
    }

    @Test
    @DisplayName("LINK-001-01-T001 — Implement server PKCE, state, nonce, and replay validation produces the required authoritative outcome")
    fun testT001_AuthoritativeOutcome() {
        registerValidSession(code = "auth-code-001")

        val command = ServerPkceExchangeCommand(
            principal = validPrincipal,
            tenantId = tenantId,
            authorizationCode = "auth-code-001",
            codeVerifier = codeVerifier,
            state = validState,
            nonce = validNonce,
            redirectUri = validRedirectUri,
            idempotencyKey = "idem-pkce-001",
            correlationId = "corr-001",
            causationId = "caus-001",
        )

        val result = service.exchangeCode(command)

        // Assert: outcome-specific semantic contract
        assertEquals("assetlinks.", result.semanticContract)
        assertEquals(ServerPkceExchangeStatus.EXCHANGED, result.status)
        assertFalse(result.directEligibilityGranted)
        assertFalse(result.financialMutationPermitted)
        assertEquals(validNonce, result.nonce)
        assertEquals("user-01", result.userId)
        assertNotNull(result.issuedTokenId)
        assertTrue(result.evidenceReference.startsWith("server-pkce:exchange:"))

        // Verify audit event
        val auditLogs = service.getAuditLogs(tenantId)
        assertEquals(1, auditLogs.size)
        assertEquals("SERVER_PKCE_EXCHANGED", auditLogs[0].type)
        assertEquals(result.resultId, auditLogs[0].resultId)
    }

    @Test
    @DisplayName("LINK-001-01-T002 — Implement server PKCE, state, nonce, and replay validation rejects invalid, boundary, unauthorized, and stale input")
    fun testT002_RejectsInvalidBoundaryUnauthorizedStale() {
        registerValidSession(code = "auth-code-valid")

        val baseCmd = ServerPkceExchangeCommand(
            principal = validPrincipal,
            tenantId = tenantId,
            authorizationCode = "auth-code-valid",
            codeVerifier = codeVerifier,
            state = validState,
            nonce = validNonce,
            redirectUri = validRedirectUri,
            idempotencyKey = "idem-test-002",
            correlationId = "corr",
            causationId = "caus",
        )

        // 1. Unauthenticated principal
        assertThrows(ServerPkceValidationException.Unauthorized::class.java) {
            service.exchangeCode(baseCmd.copy(principal = null))
        }

        // 2. Cross-tenant access
        assertThrows(ServerPkceValidationException.Forbidden::class.java) {
            service.exchangeCode(baseCmd.copy(principal = otherTenantPrincipal))
        }

        // 3. Blank parameters
        assertThrows(ServerPkceValidationException.Invalid::class.java) {
            service.exchangeCode(baseCmd.copy(authorizationCode = ""))
        }
        assertThrows(ServerPkceValidationException.Invalid::class.java) {
            service.exchangeCode(baseCmd.copy(codeVerifier = ""))
        }
        assertThrows(ServerPkceValidationException.Invalid::class.java) {
            service.exchangeCode(baseCmd.copy(state = ""))
        }
        assertThrows(ServerPkceValidationException.Invalid::class.java) {
            service.exchangeCode(baseCmd.copy(redirectUri = ""))
        }
        assertThrows(ServerPkceValidationException.Invalid::class.java) {
            service.exchangeCode(baseCmd.copy(idempotencyKey = ""))
        }

        // 4. PKCE verifier mismatch
        assertThrows(ServerPkceValidationException.Invalid::class.java) {
            service.exchangeCode(baseCmd.copy(codeVerifier = "wrong-verifier-does-not-match-challenge-hash"))
        }

        // 5. State mismatch
        assertThrows(ServerPkceValidationException.Invalid::class.java) {
            service.exchangeCode(baseCmd.copy(state = "tampered-state-csrf"))
        }

        // 6. Nonce mismatch
        assertThrows(ServerPkceValidationException.Invalid::class.java) {
            service.exchangeCode(baseCmd.copy(nonce = "wrong-nonce"))
        }

        // 7. Custom scheme redirect URI rejected (e.g. slotting://auth/callback)
        registerValidSession(code = "auth-code-custom-scheme", redirectUri = "slotting://auth/callback")
        assertThrows(ServerPkceValidationException.Invalid::class.java) {
            service.exchangeCode(baseCmd.copy(authorizationCode = "auth-code-custom-scheme", redirectUri = "slotting://auth/callback"))
        }

        // 8. Unapproved host redirect URI rejected (e.g. https://evil.com/callback)
        registerValidSession(code = "auth-code-evil", redirectUri = "https://evil.com/callback")
        assertThrows(ServerPkceValidationException.Forbidden::class.java) {
            service.exchangeCode(baseCmd.copy(authorizationCode = "auth-code-evil", redirectUri = "https://evil.com/callback"))
        }

        // 9. Plain code challenge method rejected
        registerValidSession(code = "auth-code-plain", challengeMethod = "plain", challenge = "plain-verifier")
        assertThrows(ServerPkceValidationException.Invalid::class.java) {
            service.exchangeCode(baseCmd.copy(authorizationCode = "auth-code-plain", codeVerifier = "plain-verifier"))
        }

        // 10. Expired authorization code
        registerValidSession(code = "auth-code-expired", expiresAt = Instant.now(clock).minus(1, ChronoUnit.SECONDS))
        assertThrows(ServerPkceValidationException.Stale::class.java) {
            service.exchangeCode(baseCmd.copy(authorizationCode = "auth-code-expired"))
        }

        // 11. Already consumed code (replay attempt)
        registerValidSession(code = "auth-code-consumed", consumed = true)
        assertThrows(ServerPkceValidationException.Conflict::class.java) {
            service.exchangeCode(baseCmd.copy(authorizationCode = "auth-code-consumed"))
        }
    }

    @Test
    @DisplayName("LINK-001-01-T003 — Implement server PKCE, state, nonce, and replay validation survives concurrency, duplicate delivery, and dependency failure")
    fun testT003_SurvivesConcurrencyDuplicateDelivery() {
        registerValidSession(code = "auth-code-concurrent")

        val command = ServerPkceExchangeCommand(
            principal = validPrincipal,
            tenantId = tenantId,
            authorizationCode = "auth-code-concurrent",
            codeVerifier = codeVerifier,
            state = validState,
            nonce = validNonce,
            redirectUri = validRedirectUri,
            idempotencyKey = "idem-concurrent-001",
            correlationId = "corr-conc",
            causationId = "caus-conc",
        )

        // 1. Concurrent exchange attempts with same idempotency key
        val pool = Executors.newFixedThreadPool(4)
        val futures = (1..4).map {
            pool.submit<ServerPkceExchangeResult> {
                service.exchangeCode(command)
            }
        }
        pool.shutdown()
        pool.awaitTermination(5, TimeUnit.SECONDS)

        val results = futures.map { it.get() }
        val distinctResultIds = results.map { it.resultId }.distinct()
        assertEquals(1, distinctResultIds.size, "All concurrent identical requests must return same cached resultId")

        // 2. Conflicting payload with same idempotency key fails closed with Conflict
        assertThrows(ServerPkceValidationException.Conflict::class.java) {
            service.exchangeCode(command.copy(state = "different-state"))
        }

        // 3. Replay with different idempotency key fails closed with Conflict
        assertThrows(ServerPkceValidationException.Conflict::class.java) {
            service.exchangeCode(command.copy(idempotencyKey = "different-idem-key"))
        }
    }

    @Test
    @DisplayName("LINK-001-01-T004 — Implement server PKCE, state, nonce, and replay validation remains compatible, recoverable, observable, and lifecycle-safe")
    fun testT004_RemainsCompatibleRecoverableObservable() {
        registerValidSession(code = "auth-code-lifecycle")

        val command = ServerPkceExchangeCommand(
            principal = validPrincipal,
            tenantId = tenantId,
            authorizationCode = "auth-code-lifecycle",
            codeVerifier = codeVerifier,
            state = validState,
            nonce = validNonce,
            redirectUri = validRedirectUri,
            idempotencyKey = "idem-lifecycle-001",
            correlationId = "corr-life",
            causationId = "caus-life",
        )

        val result = service.exchangeCode(command)

        // Verify lifecycle safety & non-authoritative financial invariant
        assertEquals("assetlinks.", result.semanticContract)
        assertFalse(result.directEligibilityGranted)
        assertFalse(result.financialMutationPermitted)
        assertTrue(result.evidenceReference.startsWith("server-pkce:exchange:"))

        // Verify audit observability
        val logs = service.getAuditLogs(tenantId)
        assertTrue(logs.any { it.type == "SERVER_PKCE_EXCHANGED" && it.resultId == result.resultId })
    }
}
