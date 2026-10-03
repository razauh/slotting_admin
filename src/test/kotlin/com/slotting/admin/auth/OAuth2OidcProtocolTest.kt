package com.slotting.admin.auth

import com.slotting.admin.contract.auth.AuthContractCodec
import org.junit.jupiter.api.Assertions.*
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.DisplayName
import org.junit.jupiter.api.Test
import org.springframework.http.HttpStatus
import org.springframework.mock.web.MockHttpServletRequest
import java.security.MessageDigest
import java.time.Clock
import java.time.Instant
import java.time.ZoneOffset
import java.util.Base64
import java.util.UUID

class OAuth2OidcProtocolTest {

    private val fixedInstant = Instant.parse("2026-10-03T12:00:00Z")
    private val clock = Clock.fixed(fixedInstant, ZoneOffset.UTC)

    private lateinit var store: InMemoryDurableAuthStore
    private lateinit var authService: DurableAuthService
    private lateinit var controller: OAuth2Controller
    private lateinit var authController: AuthController

    private val clientId = "slotting-android"
    private val redirectUri = "https://app.slotting.internal/auth/callback"
    private val codeVerifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
    private val codeChallenge = Base64.getUrlEncoder().withoutPadding().encodeToString(
        MessageDigest.getInstance("SHA-256").digest(codeVerifier.toByteArray(Charsets.US_ASCII))
    )

    @BeforeEach
    fun setup() {
        OAuthClientRegistry.reset()
        store = InMemoryDurableAuthStore()
        authService = DurableAuthService(store = store, clock = clock)
        controller = OAuth2Controller(authService = authService)
        authController = AuthController(authService = authService)
    }

    @Test
    @DisplayName("OAUTH-001 — Reject authorization request with duplicate query parameters (RFC 9700 4.13)")
    fun testRejectDuplicateQueryParams() {
        val request = MockHttpServletRequest()
        request.queryString = "client_id=$clientId&client_id=$clientId&response_type=code"

        val resp = controller.authorize(
            responseType = "code",
            clientId = clientId,
            redirectUri = redirectUri,
            scope = "openid profile",
            state = "st-12345",
            nonce = "nc-67890",
            codeChallenge = codeChallenge,
            codeChallengeMethod = "S256",
            prompt = null,
            tenantId = "default",
            autoUser = null,
            request = request
        )

        assertEquals(HttpStatus.BAD_REQUEST, resp.statusCode)
        val body = resp.body as Map<*, *>
        assertEquals("invalid_request", body["error"])
        assertTrue((body["error_description"] as String).contains("Duplicate parameter"))
    }

    @Test
    @DisplayName("OAUTH-002 — Reject unknown client and invalid redirect URI without redirecting (RFC 6749 4.1.2.1)")
    fun testRejectUnknownClientAndUnregisteredUriWithoutRedirect() {
        val request = MockHttpServletRequest()

        // 1. Unknown client
        val resp1 = controller.authorize(
            responseType = "code",
            clientId = "unknown-client",
            redirectUri = redirectUri,
            scope = "openid profile",
            state = "st-123",
            nonce = "nc-123",
            codeChallenge = codeChallenge,
            codeChallengeMethod = "S256",
            prompt = null,
            tenantId = "default",
            autoUser = null,
            request = request
        )
        assertEquals(HttpStatus.BAD_REQUEST, resp1.statusCode)

        // 2. Unregistered redirect URI (tampered domain)
        val resp2 = controller.authorize(
            responseType = "code",
            clientId = clientId,
            redirectUri = "https://attacker.slotting.internal/auth/callback",
            scope = "openid profile",
            state = "st-123",
            nonce = "nc-123",
            codeChallenge = codeChallenge,
            codeChallengeMethod = "S256",
            prompt = null,
            tenantId = "default",
            autoUser = null,
            request = request
        )
        assertEquals(HttpStatus.BAD_REQUEST, resp2.statusCode)

        // 3. HTTP scheme downgrade rejected
        val resp3 = controller.authorize(
            responseType = "code",
            clientId = clientId,
            redirectUri = "http://app.slotting.internal/auth/callback",
            scope = "openid profile",
            state = "st-123",
            nonce = "nc-123",
            codeChallenge = codeChallenge,
            codeChallengeMethod = "S256",
            prompt = null,
            tenantId = "default",
            autoUser = null,
            request = request
        )
        assertEquals(HttpStatus.BAD_REQUEST, resp3.statusCode)
    }

    @Test
    @DisplayName("OAUTH-003 — Reject plain PKCE and enforce S256 requirement (RFC 7636 & RFC 9700)")
    fun testRejectPlainPkce() {
        val request = MockHttpServletRequest()
        val resp = controller.authorize(
            responseType = "code",
            clientId = clientId,
            redirectUri = redirectUri,
            scope = "openid profile",
            state = "st-123",
            nonce = "nc-123",
            codeChallenge = codeChallenge,
            codeChallengeMethod = "plain",
            prompt = null,
            tenantId = "default",
            autoUser = null,
            request = request
        )

        assertEquals(HttpStatus.FOUND, resp.statusCode)
        val location = resp.headers.location!!.toString()
        assertTrue(location.contains("error=invalid_request"))
        assertTrue(location.contains("code_challenge_method"))
        assertTrue(location.contains("iss="))
    }

    @Test
    @DisplayName("OAUTH-004 — Reject scopes without 'openid'")
    fun testRejectScopeWithoutOpenid() {
        val request = MockHttpServletRequest()
        val resp = controller.authorize(
            responseType = "code",
            clientId = clientId,
            redirectUri = redirectUri,
            scope = "wallet.read profile",
            state = "st-123",
            nonce = "nc-123",
            codeChallenge = codeChallenge,
            codeChallengeMethod = "S256",
            prompt = null,
            tenantId = "default",
            autoUser = null,
            request = request
        )

        assertEquals(HttpStatus.FOUND, resp.statusCode)
        val location = resp.headers.location!!.toString()
        assertTrue(location.contains("error=invalid_scope"))
    }

    @Test
    @DisplayName("OAUTH-005 — Interactive Server-Hosted Registration and Login creates authorization code and redirects")
    fun testInteractiveRegistrationAndLogin() {
        val tenantId = "tenant-001"
        val state = "state-random-uuid"
        val nonce = "nonce-random-uuid"

        // 1. Register new player via POST /oauth2/register
        val regResp = controller.register(
            csrfTokenParam = null,
            clientId = clientId,
            redirectUri = redirectUri,
            scope = "openid profile wallet.read",
            state = state,
            nonce = nonce,
            codeChallenge = codeChallenge,
            codeChallengeMethod = "S256",
            tenantId = tenantId,
            identifier = "alice@example.com",
            password = "SecurePassword123!"
        )

        assertEquals(HttpStatus.FOUND, regResp.statusCode)
        val regLocation = regResp.headers.location!!.toString()
        assertTrue(regLocation.startsWith(redirectUri))
        assertTrue(regLocation.contains("code="))
        assertTrue(regLocation.contains("state=$state"))
        assertTrue(regLocation.contains("iss="))

        // Extract code
        val code1 = regLocation.substringAfter("code=").substringBefore("&")

        // 2. Exchange code for tokens at /auth/token
        val exchangeJson = """
            {
                "grant_type": "authorization_code",
                "code": "$code1",
                "code_verifier": "$codeVerifier",
                "code_challenge_method": "S256",
                "state": "$state",
                "redirect_uri": "$redirectUri",
                "client_id": "$clientId"
            }
        """.trimIndent()

        val tokenResp = authController.token(exchangeJson)
        assertEquals(HttpStatus.OK, tokenResp.statusCode)
        assertEquals("no-store", tokenResp.headers.getFirst("Cache-Control"))
        assertEquals("no-cache", tokenResp.headers.getFirst("Pragma"))

        val tokenDto = AuthContractCodec.parseTokenResponse(AuthContractCodec.mapper.writeValueAsString(tokenResp.body))
        assertNotNull(tokenDto.accessToken)
        assertNotNull(tokenDto.refreshToken)
        assertNotNull(tokenDto.idToken)

        // Validate OIDC ID Token
        val claims = authService.oidcKeyService.validateIdToken(
            idToken = tokenDto.idToken!!,
            expectedClientId = clientId,
            expectedNonce = nonce,
            now = clock.instant()
        )
        assertEquals(clientId, claims.aud)
        assertEquals(authService.oidcKeyService.issuer, claims.iss)
        assertEquals(nonce, claims.nonce)
        assertEquals(tenantId, claims.tenantId)

        // 3. Test Subsequent Login via POST /oauth2/login
        val loginResp = controller.login(
            csrfTokenParam = null,
            clientId = clientId,
            redirectUri = redirectUri,
            scope = "openid profile",
            state = "state-second-login",
            nonce = "nonce-second-login",
            codeChallenge = codeChallenge,
            codeChallengeMethod = "S256",
            tenantId = tenantId,
            identifier = "alice@example.com",
            password = "SecurePassword123!",
            request = MockHttpServletRequest()
        )

        assertEquals(HttpStatus.FOUND, loginResp.statusCode)
        val loginLocation = loginResp.headers.location!!.toString()
        assertTrue(loginLocation.contains("code="))
        assertTrue(loginLocation.contains("state=state-second-login"))

        // 4. Test Login with bad password fails with 401
        val badLoginResp = controller.login(
            csrfTokenParam = null,
            clientId = clientId,
            redirectUri = redirectUri,
            scope = "openid profile",
            state = "state-fail",
            nonce = "nonce-fail",
            codeChallenge = codeChallenge,
            codeChallengeMethod = "S256",
            tenantId = tenantId,
            identifier = "alice@example.com",
            password = "WrongPassword!",
            request = MockHttpServletRequest()
        )
        assertEquals(HttpStatus.UNAUTHORIZED, badLoginResp.statusCode)
    }

    @Test
    @DisplayName("OAUTH-006 — Refresh token rotation and reuse detection compromise revocation")
    fun testRefreshTokenRotationAndCompromiseRevocation() {
        val tenantId = "tenant-002"
        val state = "state-rtk"
        val nonce = "nonce-rtk"

        val regResp = controller.register(
            csrfTokenParam = null,
            clientId = clientId,
            redirectUri = redirectUri,
            scope = "openid profile",
            state = state,
            nonce = nonce,
            codeChallenge = codeChallenge,
            codeChallengeMethod = "S256",
            tenantId = tenantId,
            identifier = "bob@example.com",
            password = "BobPassword456!"
        )
        val location = regResp.headers.location!!.toString()
        val code = location.substringAfter("code=").substringBefore("&")

        val exchangeJson = """
            {
                "grant_type": "authorization_code",
                "code": "$code",
                "code_verifier": "$codeVerifier",
                "code_challenge_method": "S256",
                "state": "$state",
                "redirect_uri": "$redirectUri",
                "client_id": "$clientId"
            }
        """.trimIndent()
        val initialTokenResp = authController.token(exchangeJson)
        val initialTokens = AuthContractCodec.parseTokenResponse(AuthContractCodec.mapper.writeValueAsString(initialTokenResp.body))

        val rtk1 = initialTokens.refreshToken

        // 1. Normal rotation
        val refreshJson1 = """
            {
                "grant_type": "refresh_token",
                "refresh_token": "$rtk1",
                "client_id": "$clientId"
            }
        """.trimIndent()
        val refreshResp1 = authController.token(refreshJson1)
        assertEquals(HttpStatus.OK, refreshResp1.statusCode)
        val rotatedTokens = AuthContractCodec.parseTokenResponse(AuthContractCodec.mapper.writeValueAsString(refreshResp1.body))
        val rtk2 = rotatedTokens.refreshToken
        assertNotEquals(rtk1, rtk2)

        // 2. Attacker replays compromised rtk1
        val attackResp = authController.token(refreshJson1)
        assertEquals(HttpStatus.BAD_REQUEST, attackResp.statusCode)

        // 3. Legitimate rtk2 is now also revoked due to token family breach!
        val refreshJson2 = """
            {
                "grant_type": "refresh_token",
                "refresh_token": "$rtk2",
                "client_id": "$clientId"
            }
        """.trimIndent()
        val refreshResp2 = authController.token(refreshJson2)
        assertEquals(HttpStatus.BAD_REQUEST, refreshResp2.statusCode)
    }

    @Test
    @DisplayName("OAUTH-007 — Metadata Discovery, JWKS, and Digital Asset Links conform to RFC 8414 and RFC 7517")
    fun testDiscoveryJwksAndAssetLinks() {
        // Discovery metadata
        val disco = controller.openIdConfiguration()
        assertEquals(HttpStatus.OK, disco.statusCode)
        val meta = disco.body!!
        assertEquals("https://auth.slotting.com", meta["issuer"])
        assertTrue((meta["response_types_supported"] as List<*>).contains("code"))
        assertTrue((meta["code_challenge_methods_supported"] as List<*>).contains("S256"))
        assertTrue((meta["grant_types_supported"] as List<*>).contains("authorization_code"))

        // JWKS
        val jwks = controller.jwks()
        assertEquals(HttpStatus.OK, jwks.statusCode)
        val keys = jwks.body!!["keys"] as List<Map<String, Any>>
        assertTrue(keys.isNotEmpty())
        val firstKey = keys.first()
        assertEquals("RSA", firstKey["kty"])
        assertEquals("RS256", firstKey["alg"])
        assertEquals("sig", firstKey["use"])
        assertNotNull(firstKey["kid"])
        assertNotNull(firstKey["n"])
        assertNotNull(firstKey["e"])

        // Digital Asset Links
        val assetLinks = controller.assetLinks()
        assertEquals(HttpStatus.OK, assetLinks.statusCode)
        val bodyStr = assetLinks.body!!
        assertTrue(bodyStr.contains("com.slotting.game"))
        assertTrue(bodyStr.contains("delegate_permission/common.handle_all_urls"))
    }
}
