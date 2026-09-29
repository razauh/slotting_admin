package com.slotting.admin.auth

import com.slotting.admin.contract.auth.*
import org.junit.jupiter.api.Assertions.*
import org.junit.jupiter.api.DisplayName
import org.junit.jupiter.api.Test
import java.io.InputStreamReader
import java.time.Instant

/**
 * TC-003 Contract Test Suite in slotting_admin.
 *
 * Verifies that the authoritative identity and session API contract:
 * 1. Accepts and deserializes canonical JSON fixtures matching Android parser.
 * 2. Enforces PKCE S256, state, and nonce binding without client subject override.
 * 3. Rejects protocol downgrade, replay, foreign tenant, clock skew, and missing eligibility fields.
 * 4. Strictly separates Admin MFA step-up and authorization from player identity.
 */
class IdentitySessionContractTest {

    private fun loadFixture(path: String): String {
        val stream = javaClass.getResourceAsStream(path)
            ?: throw IllegalArgumentException("Fixture not found on classpath: $path")
        return InputStreamReader(stream).readText()
    }

    // =========================================================================
    // Scenario 1: Fresh Install Login (Authorization Code + PKCE S256)
    // =========================================================================
    @Test
    @DisplayName("Scenario 1: Fresh install login - Exchange request and token response with server-derived subject")
    fun testFreshInstallLogin() {
        val reqJson = loadFixture("/fixtures/auth/v1/token_exchange_pkce_request.json")
        val req = AuthContractCodec.parseTokenExchangeRequest(reqJson)

        assertEquals("authorization_code", req.grantType)
        assertEquals("auth-code-valid-998877", req.code)
        assertEquals("S256", req.codeChallengeMethod)
        assertEquals("dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk", req.codeVerifier)
        assertEquals("state-random-uuid-xyz-123", req.state)
        assertEquals("nonce-secure-random-456", req.nonce)
        assertEquals("https://auth.slotting.com/callback", req.redirectUri)
        assertEquals("slotting-android", req.clientId)

        // Validate PKCE calculation RFC 7636: S256(dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk)
        val challenge = AuthContractCodec.computeS256Challenge(req.codeVerifier)
        assertEquals("E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM", challenge)
        assertTrue(AuthContractCodec.validatePkce(req.codeVerifier, challenge, "S256"))

        // Parse token response
        val respJson = loadFixture("/fixtures/auth/v1/token_exchange_success_response.json")
        val resp = AuthContractCodec.parseTokenResponse(respJson)

        assertEquals("Bearer", resp.tokenType)
        assertEquals("c1f7b0a8-3482-4cf4-91fa-404c00000001", resp.playerId)
        assertEquals("tenant-casino-1", resp.tenantId)
        assertEquals("f8a1e2d3-c4b5-4a67-8901-234567890abc", resp.tokenFamilyId)
        assertEquals("e7b0c1a2-9876-4fed-ba98-76543210fedc", resp.sessionId)
        assertEquals(900L, resp.expiresInSeconds)
    }

    // =========================================================================
    // Scenario 2: Process Death Mid-Login (State and Nonce Matching)
    // =========================================================================
    @Test
    @DisplayName("Scenario 2: Process death mid-login - State and nonce must match persisted authorization session")
    fun testProcessDeathMidLogin() {
        val reqJson = loadFixture("/fixtures/auth/v1/token_exchange_pkce_request.json")
        val req = AuthContractCodec.parseTokenExchangeRequest(reqJson)

        // Persisted state simulated from before browser launch
        val persistedState = "state-random-uuid-xyz-123"
        val wrongPersistedState = "state-mismatched-999"

        assertEquals(persistedState, req.state)
        assertNotEquals(wrongPersistedState, req.state)

        // Negative fixture: State or nonce mismatch
        val errJson = loadFixture("/fixtures/auth/v1/error_wrong_state_nonce.json")
        val err = AuthContractCodec.parseAuthErrorResponse(errJson)
        assertEquals("invalid_grant", err.error)
        assertEquals("INVALID_STATE_OR_NONCE", err.errorCode)
        assertFalse(err.retryable)
    }

    // =========================================================================
    // Scenario 3: Refresh Replay (Token Family Rotation & Reuse Detection)
    // =========================================================================
    @Test
    @DisplayName("Scenario 3: Refresh replay - Rotated refresh token reuse revokes family with typed error")
    fun testRefreshReplay() {
        // Valid refresh request and response
        val refreshReqJson = loadFixture("/fixtures/auth/v1/token_refresh_request.json")
        val refreshReq = AuthContractCodec.parseTokenRefreshRequest(refreshReqJson)
        assertEquals("refresh_token", refreshReq.grantType)
        assertEquals("rtk_synthetic_valid_refresh_token_redacted", refreshReq.refreshToken)

        val refreshRespJson = loadFixture("/fixtures/auth/v1/token_refresh_success_response.json")
        val refreshResp = AuthContractCodec.parseTokenResponse(refreshRespJson)
        assertEquals("rtk_synthetic_rotated_refresh_token_redacted", refreshResp.refreshToken)
        assertEquals("f8a1e2d3-c4b5-4a67-8901-234567890abc", refreshResp.tokenFamilyId)

        // Replay negative fixture
        val replayErrJson = loadFixture("/fixtures/auth/v1/error_token_reuse_revoked.json")
        val replayErr = AuthContractCodec.parseAuthErrorResponse(replayErrJson)
        assertEquals("invalid_grant", replayErr.error)
        assertEquals("TOKEN_REUSE_REVOKED", replayErr.errorCode)
        assertFalse(replayErr.retryable)
    }

    // =========================================================================
    // Scenario 4: Logout vs Revocation (Remote Session Termination)
    // =========================================================================
    @Test
    @DisplayName("Scenario 4: Logout race and server-confirmed termination")
    fun testLogoutVsRevocation() {
        // Revoke token
        val revokeReqJson = loadFixture("/fixtures/auth/v1/token_revoke_request.json")
        val revokeReq = AuthContractCodec.parseTokenRevocationRequest(revokeReqJson)
        assertEquals("rtk_synthetic_valid_refresh_token_redacted", revokeReq.token)

        val revokeRespJson = loadFixture("/fixtures/auth/v1/token_revoke_success_response.json")
        val revokeResp = AuthContractCodec.parseTokenRevocationResponse(revokeRespJson)
        assertTrue(revokeResp.revoked)

        // Logout session (requires session_id, idempotency_key, correlation_id)
        val logoutReqJson = loadFixture("/fixtures/auth/v1/session_logout_request.json")
        val logoutReq = AuthContractCodec.parseSessionLogoutRequest(logoutReqJson)
        assertEquals("e7b0c1a2-9876-4fed-ba98-76543210fedc", logoutReq.sessionId)

        val logoutRespJson = loadFixture("/fixtures/auth/v1/session_logout_success_response.json")
        val logoutResp = AuthContractCodec.parseSessionLogoutResponse(logoutRespJson)
        assertTrue(logoutResp.terminated)
        assertEquals("c1f7b0a8-3482-4cf4-91fa-404c00000001", logoutResp.playerId)
        assertEquals("ev-logout-rec-001", logoutResp.evidenceReference)
    }

    // =========================================================================
    // Scenario 5: Authoritative Eligibility (Bearer-derived, Fail-Closed)
    // =========================================================================
    @Test
    @DisplayName("Scenario 5: Eligibility evaluation fails closed on missing fields and enforces restrictions")
    fun testAuthoritativeEligibility() {
        val eligJson = loadFixture("/fixtures/auth/v1/eligibility_success_response.json")
        val elig = AuthContractCodec.parseEligibilityResponse(eligJson)

        assertEquals("d1e2f3a4-b5c6-7d8e-9f0a-1b2c3d4e5f6a", elig.decisionId)
        assertEquals(1L, elig.version)
        assertEquals("tenant-casino-1", elig.tenantId)
        assertEquals("c1f7b0a8-3482-4cf4-91fa-404c00000001", elig.playerId)
        assertTrue(elig.eligible)
        assertEquals("ACTIVE", elig.accountStatus)
        assertEquals("VERIFIED", elig.kycStatus)
        assertEquals("CLEARED", elig.amlStatus)
        assertEquals("NV", elig.jurisdiction)
        assertTrue(elig.ageVerified)
        assertEquals(21, elig.minAgeRequired)
        assertFalse(elig.selfExcluded)
        assertEquals(500000L, elig.dailyWagerLimitMinor)

        // Validate completeness and freshness
        val valid = AuthContractCodec.validateEligibilityCompleteness(elig, nowEpochMs = 1790262100000L)
        assertTrue(valid)

        // Expired verdict fails closed
        val expiredVerdict = AuthContractCodec.validateEligibilityCompleteness(elig, nowEpochMs = 1790262400000L)
        assertFalse(expiredVerdict)

        // Negative fixture: missing fields must fail closed
        val missingFieldsJson = loadFixture("/fixtures/auth/v1/error_missing_eligibility_fields.json")
        assertThrows(Exception::class.java) {
            AuthContractCodec.parseEligibilityResponse(missingFieldsJson)
        }
    }

    // =========================================================================
    // Scenario 6: Admin MFA Expiry & Role Step-Up
    // =========================================================================
    @Test
    @DisplayName("Scenario 6: Admin MFA step-up and expiration strictly separated from player identity")
    fun testAdminMfaStepUpAndExpiry() {
        val reqJson = loadFixture("/fixtures/auth/v1/admin_mfa_step_up_request.json")
        val req = AuthContractCodec.parseAdminMfaStepUpRequest(reqJson)

        assertEquals("adm-sess-uuid-001", req.sessionId)
        assertEquals("tenant-admin-1", req.tenantId)
        assertEquals("admin-principal-01", req.adminId)
        assertEquals("SECURITY", req.requestedRole)
        assertEquals("987654", req.mfaAssertion)

        val respJson = loadFixture("/fixtures/auth/v1/admin_mfa_step_up_success_response.json")
        val resp = AuthContractCodec.parseAdminMfaStepUpResponse(respJson)

        assertEquals("AUTHENTICATED", resp.state)
        assertEquals("SECURITY", resp.grantedRole)
        assertEquals("admin-principal-01", resp.adminId)
        assertEquals(1790263800000L, resp.expiresAtEpochMs)

        // Negative fixture: expired admin MFA
        val errJson = loadFixture("/fixtures/auth/v1/error_admin_mfa_expired.json")
        val err = AuthContractCodec.parseAuthErrorResponse(errJson)
        assertEquals("access_denied", err.error)
        assertEquals("MFA_EXPIRED", err.errorCode)
        assertFalse(err.retryable)
    }

    // =========================================================================
    // Scenario 7: Clock Skew
    // =========================================================================
    @Test
    @DisplayName("Scenario 7: Clock skew validation - Accept <=60s drift, reject excessive drift")
    fun testClockSkewValidation() {
        val now = 1790262000000L

        // Tolerable skew: 30s in the future or past
        assertTrue(AuthContractCodec.validateClockSkew(now + 30000L, now))
        assertTrue(AuthContractCodec.validateClockSkew(now - 30000L, now))

        // Intolerable skew: 5000s in the future
        assertFalse(AuthContractCodec.validateClockSkew(now + 5000000L, now))

        // Negative fixture for clock skew
        val errJson = loadFixture("/fixtures/auth/v1/error_clock_skew.json")
        val err = AuthContractCodec.parseAuthErrorResponse(errJson)
        assertEquals("invalid_request", err.error)
        assertEquals("CLOCK_SKEW_DETECTED", err.errorCode)
        assertTrue(err.retryable)
    }

    // =========================================================================
    // Scenario 8: Unknown Fields Tolerance (Forward Compatibility)
    // =========================================================================
    @Test
    @DisplayName("Scenario 8: Unknown fields are ignored gracefully for forward compatibility")
    fun testUnknownFieldsForwardCompatibility() {
        val jsonWithExtraFields = """
            {
                "access_token": "atk_synthetic_valid_access_token_redacted",
                "token_type": "Bearer",
                "expires_in": 900,
                "refresh_token": "rtk_synthetic_valid_refresh_token_redacted",
                "scope": "player:game player:account",
                "player_id": "c1f7b0a8-3482-4cf4-91fa-404c00000001",
                "tenant_id": "tenant-casino-1",
                "token_family_id": "f8a1e2d3-c4b5-4a67-8901-234567890abc",
                "session_id": "e7b0c1a2-9876-4fed-ba98-76543210fedc",
                "issued_at_epoch_ms": 1790262000000,
                "future_feature_flag": true,
                "server_experimental_field": "v2_preview"
            }
        """.trimIndent()

        val resp = AuthContractCodec.parseTokenResponse(jsonWithExtraFields)
        assertEquals("c1f7b0a8-3482-4cf4-91fa-404c00000001", resp.playerId)
        assertEquals("tenant-casino-1", resp.tenantId)
    }

    // =========================================================================
    // Scenario 9: Protocol Downgrade Rejection
    // =========================================================================
    @Test
    @DisplayName("Scenario 9: Protocol downgrade to plain PKCE challenge is rejected")
    fun testProtocolDowngradeRejection() {
        assertFalse(AuthContractCodec.validatePkce("myverifier", "mychallenge", "plain"))

        val errJson = loadFixture("/fixtures/auth/v1/error_protocol_downgrade.json")
        val err = AuthContractCodec.parseAuthErrorResponse(errJson)
        assertEquals("invalid_request", err.error)
        assertEquals("PROTOCOL_DOWNGRADE_REJECTED", err.errorCode)
        assertFalse(err.retryable)
    }

    // =========================================================================
    // Scenario 10: Foreign Tenant Rejection
    // =========================================================================
    @Test
    @DisplayName("Scenario 10: Foreign tenant access is denied")
    fun testForeignTenantRejection() {
        val errJson = loadFixture("/fixtures/auth/v1/error_foreign_tenant.json")
        val err = AuthContractCodec.parseAuthErrorResponse(errJson)
        assertEquals("access_denied", err.error)
        assertEquals("FOREIGN_TENANT", err.errorCode)
        assertFalse(err.retryable)
    }
}
