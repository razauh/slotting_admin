package com.slotting.admin.contract.auth

import com.fasterxml.jackson.annotation.JsonIgnoreProperties
import com.fasterxml.jackson.annotation.JsonProperty
import com.fasterxml.jackson.databind.DeserializationFeature
import com.fasterxml.jackson.databind.ObjectMapper
import java.nio.charset.StandardCharsets
import java.security.MessageDigest
import java.util.Base64
import java.util.UUID

/**
 * Authoritative Identity and Session API Contract (v1).
 *
 * Implements TC-003:
 * Freezes the authentication, refresh, revocation, eligibility, admin MFA,
 * error, and owner-derivation contract between slotting_admin and slotting.
 */

// =============================================================================
// Player Auth DTOs
// =============================================================================

@JsonIgnoreProperties(ignoreUnknown = true)
data class TokenExchangeRequestDto(
    @JsonProperty("grant_type")
    val grantType: String,
    @JsonProperty("code")
    val code: String,
    @JsonProperty("code_verifier")
    val codeVerifier: String,
    @JsonProperty("code_challenge_method")
    val codeChallengeMethod: String = "S256",
    @JsonProperty("state")
    val state: String,
    @JsonProperty("nonce")
    val nonce: String? = null,
    @JsonProperty("redirect_uri")
    val redirectUri: String,
    @JsonProperty("client_id")
    val clientId: String
)

@JsonIgnoreProperties(ignoreUnknown = true)
data class TokenResponseDto(
    @JsonProperty("access_token")
    val accessToken: String,
    @JsonProperty("token_type")
    val tokenType: String = "Bearer",
    @JsonProperty("expires_in")
    val expiresInSeconds: Long,
    @JsonProperty("refresh_token")
    val refreshToken: String,
    @JsonProperty("scope")
    val scope: String,
    @JsonProperty("player_id")
    val playerId: String,
    @JsonProperty("tenant_id")
    val tenantId: String,
    @JsonProperty("token_family_id")
    val tokenFamilyId: String,
    @JsonProperty("session_id")
    val sessionId: String,
    @JsonProperty("issued_at_epoch_ms")
    val issuedAtEpochMs: Long
)

@JsonIgnoreProperties(ignoreUnknown = true)
data class TokenRefreshRequestDto(
    @JsonProperty("grant_type")
    val grantType: String = "refresh_token",
    @JsonProperty("refresh_token")
    val refreshToken: String,
    @JsonProperty("client_id")
    val clientId: String? = null
)

@JsonIgnoreProperties(ignoreUnknown = true)
data class TokenRevocationRequestDto(
    @JsonProperty("token")
    val token: String,
    @JsonProperty("token_type_hint")
    val tokenTypeHint: String? = null
)

@JsonIgnoreProperties(ignoreUnknown = true)
data class TokenRevocationResponseDto(
    @JsonProperty("revoked")
    val revoked: Boolean,
    @JsonProperty("token_type")
    val tokenType: String,
    @JsonProperty("server_time_epoch_ms")
    val serverTimeEpochMs: Long
)

@JsonIgnoreProperties(ignoreUnknown = true)
data class SessionLogoutRequestDto(
    @JsonProperty("session_id")
    val sessionId: String,
    @JsonProperty("idempotency_key")
    val idempotencyKey: String,
    @JsonProperty("correlation_id")
    val correlationId: String
)

@JsonIgnoreProperties(ignoreUnknown = true)
data class SessionLogoutResponseDto(
    @JsonProperty("terminated")
    val terminated: Boolean,
    @JsonProperty("session_id")
    val sessionId: String,
    @JsonProperty("player_id")
    val playerId: String,
    @JsonProperty("server_time_epoch_ms")
    val serverTimeEpochMs: Long,
    @JsonProperty("evidence_reference")
    val evidenceReference: String
)

// =============================================================================
// Authoritative Eligibility DTO
// =============================================================================

@JsonIgnoreProperties(ignoreUnknown = true)
data class AuthoritativeEligibilityResponseDto(
    @JsonProperty("decision_id")
    val decisionId: String,
    @JsonProperty("version")
    val version: Long,
    @JsonProperty("tenant_id")
    val tenantId: String,
    @JsonProperty("player_id")
    val playerId: String,
    @JsonProperty("eligible")
    val eligible: Boolean,
    @JsonProperty("account_status")
    val accountStatus: String,
    @JsonProperty("kyc_status")
    val kycStatus: String,
    @JsonProperty("aml_status")
    val amlStatus: String,
    @JsonProperty("jurisdiction")
    val jurisdiction: String,
    @JsonProperty("age_verified")
    val ageVerified: Boolean,
    @JsonProperty("min_age_required")
    val minAgeRequired: Int,
    @JsonProperty("self_excluded")
    val selfExcluded: Boolean,
    @JsonProperty("cool_off_until_epoch_ms")
    val coolOffUntilEpochMs: Long? = null,
    @JsonProperty("daily_wager_limit_minor")
    val dailyWagerLimitMinor: Long? = null,
    @JsonProperty("current_daily_wager_minor")
    val currentDailyWagerMinor: Long = 0L,
    @JsonProperty("single_wager_limit_minor")
    val singleWagerLimitMinor: Long? = null,
    @JsonProperty("restrictions")
    val restrictions: List<String> = emptyList(),
    @JsonProperty("evaluated_at_epoch_ms")
    val evaluatedAtEpochMs: Long,
    @JsonProperty("expires_at_epoch_ms")
    val expiresAtEpochMs: Long,
    @JsonProperty("evidence_reference")
    val evidenceReference: String
)

// =============================================================================
// Admin MFA & Session Authorization DTOs
// =============================================================================

@JsonIgnoreProperties(ignoreUnknown = true)
data class AdminMfaStepUpRequestDto(
    @JsonProperty("session_id")
    val sessionId: String,
    @JsonProperty("tenant_id")
    val tenantId: String,
    @JsonProperty("admin_id")
    val adminId: String,
    @JsonProperty("requested_role")
    val requestedRole: String,
    @JsonProperty("mfa_assertion")
    val mfaAssertion: String,
    @JsonProperty("idempotency_key")
    val idempotencyKey: String,
    @JsonProperty("correlation_id")
    val correlationId: String,
    @JsonProperty("causation_id")
    val causationId: String,
    @JsonProperty("expected_version")
    val expectedVersion: Long,
    @JsonProperty("break_glass")
    val breakGlass: Boolean = false
)

@JsonIgnoreProperties(ignoreUnknown = true)
data class AdminMfaStepUpResponseDto(
    @JsonProperty("result_id")
    val resultId: String,
    @JsonProperty("state")
    val state: String,
    @JsonProperty("admin_id")
    val adminId: String,
    @JsonProperty("tenant_id")
    val tenantId: String,
    @JsonProperty("granted_role")
    val grantedRole: String?,
    @JsonProperty("session_id")
    val sessionId: String,
    @JsonProperty("server_time_epoch_ms")
    val serverTimeEpochMs: Long,
    @JsonProperty("server_version")
    val serverVersion: Long,
    @JsonProperty("expires_at_epoch_ms")
    val expiresAtEpochMs: Long,
    @JsonProperty("evidence_reference")
    val evidenceReference: String
)

// =============================================================================
// Typed Auth Error DTO
// =============================================================================

@JsonIgnoreProperties(ignoreUnknown = true)
data class AuthErrorResponseDto(
    @JsonProperty("error")
    val error: String,
    @JsonProperty("error_code")
    val errorCode: String,
    @JsonProperty("error_description")
    val errorDescription: String,
    @JsonProperty("correlation_id")
    val correlationId: String,
    @JsonProperty("timestamp_epoch_ms")
    val timestampEpochMs: Long,
    @JsonProperty("retryable")
    val retryable: Boolean = false
)

// =============================================================================
// Auth Contract Codec & Strict Security Rules
// =============================================================================

object AuthContractCodec {

    val mapper: ObjectMapper = ObjectMapper().apply {
        configure(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES, false)
    }

    const val MAX_CLOCK_SKEW_SECONDS = 60L

    fun computeS256Challenge(codeVerifier: String): String {
        val bytes = codeVerifier.toByteArray(StandardCharsets.US_ASCII)
        val digest = MessageDigest.getInstance("SHA-256").digest(bytes)
        return Base64.getUrlEncoder().withoutPadding().encodeToString(digest)
    }

    fun validatePkce(codeVerifier: String, codeChallenge: String, method: String): Boolean {
        if (method != "S256") {
            // Strictly reject non-S256 challenge methods (protocol downgrade protection)
            return false
        }
        if (codeVerifier.length < 43 || codeVerifier.length > 128) {
            return false
        }
        val computed = computeS256Challenge(codeVerifier)
        return computed == codeChallenge
    }

    fun validateClockSkew(timestampEpochMs: Long, nowEpochMs: Long, toleranceSeconds: Long = MAX_CLOCK_SKEW_SECONDS): Boolean {
        val diffMs = kotlin.math.abs(nowEpochMs - timestampEpochMs)
        return diffMs <= (toleranceSeconds * 1000L)
    }

    fun validateEligibilityCompleteness(dto: AuthoritativeEligibilityResponseDto, nowEpochMs: Long): Boolean {
        if (dto.decisionId.isBlank() || dto.tenantId.isBlank() || dto.playerId.isBlank()) {
            return false
        }
        if (dto.version < 1) {
            return false
        }
        if (nowEpochMs >= dto.expiresAtEpochMs) {
            // Expired verdict fails closed
            return false
        }
        if (dto.selfExcluded || !dto.ageVerified || dto.accountStatus != "ACTIVE") {
            // Must not be eligible if excluded, under-age, or non-active
            if (dto.eligible) return false
        }
        return true
    }

    // JSON serialization / deserialization helpers
    fun parseTokenExchangeRequest(json: String): TokenExchangeRequestDto =
        mapper.readValue(json, TokenExchangeRequestDto::class.java).also {
            require(it.grantType == "authorization_code") { "grant_type must be authorization_code" }
            require(it.code.isNotBlank()) { "code cannot be blank" }
            require(it.codeVerifier.isNotBlank()) { "code_verifier cannot be blank" }
            require(it.codeChallengeMethod == "S256") { "code_challenge_method must be S256" }
            require(it.state.isNotBlank()) { "state cannot be blank" }
            require(it.redirectUri.isNotBlank()) { "redirect_uri cannot be blank" }
            require(it.clientId.isNotBlank()) { "client_id cannot be blank" }
        }

    fun parseTokenResponse(json: String): TokenResponseDto =
        mapper.readValue(json, TokenResponseDto::class.java).also {
            require(it.accessToken.isNotBlank()) { "access_token cannot be blank" }
            require(it.refreshToken.isNotBlank()) { "refresh_token cannot be blank" }
            require(it.playerId.isNotBlank()) { "player_id cannot be blank" }
            require(it.tenantId.isNotBlank()) { "tenant_id cannot be blank" }
            require(it.tokenFamilyId.isNotBlank()) { "token_family_id cannot be blank" }
            require(it.sessionId.isNotBlank()) { "session_id cannot be blank" }
        }

    fun parseTokenRefreshRequest(json: String): TokenRefreshRequestDto =
        mapper.readValue(json, TokenRefreshRequestDto::class.java).also {
            require(it.grantType == "refresh_token") { "grant_type must be refresh_token" }
            require(it.refreshToken.isNotBlank()) { "refresh_token cannot be blank" }
        }

    fun parseTokenRevocationRequest(json: String): TokenRevocationRequestDto =
        mapper.readValue(json, TokenRevocationRequestDto::class.java).also {
            require(it.token.isNotBlank()) { "token cannot be blank" }
        }

    fun parseTokenRevocationResponse(json: String): TokenRevocationResponseDto =
        mapper.readValue(json, TokenRevocationResponseDto::class.java)

    fun parseSessionLogoutRequest(json: String): SessionLogoutRequestDto =
        mapper.readValue(json, SessionLogoutRequestDto::class.java).also {
            require(it.sessionId.isNotBlank()) { "session_id cannot be blank" }
            require(it.idempotencyKey.isNotBlank()) { "idempotency_key cannot be blank" }
            require(it.correlationId.isNotBlank()) { "correlation_id cannot be blank" }
        }

    fun parseSessionLogoutResponse(json: String): SessionLogoutResponseDto =
        mapper.readValue(json, SessionLogoutResponseDto::class.java)

    fun parseEligibilityResponse(json: String): AuthoritativeEligibilityResponseDto =
        mapper.readValue(json, AuthoritativeEligibilityResponseDto::class.java).also {
            require(it.decisionId.isNotBlank()) { "decision_id cannot be blank" }
            require(it.tenantId.isNotBlank()) { "tenant_id cannot be blank" }
            require(it.playerId.isNotBlank()) { "player_id cannot be blank" }
            require(it.accountStatus.isNotBlank()) { "account_status cannot be blank" }
            require(it.kycStatus.isNotBlank()) { "kyc_status cannot be blank" }
            require(it.amlStatus.isNotBlank()) { "aml_status cannot be blank" }
            require(it.jurisdiction.isNotBlank()) { "jurisdiction cannot be blank" }
        }

    fun parseAdminMfaStepUpRequest(json: String): AdminMfaStepUpRequestDto =
        mapper.readValue(json, AdminMfaStepUpRequestDto::class.java).also {
            require(it.sessionId.isNotBlank()) { "session_id cannot be blank" }
            require(it.tenantId.isNotBlank()) { "tenant_id cannot be blank" }
            require(it.adminId.isNotBlank()) { "admin_id cannot be blank" }
            require(it.requestedRole.isNotBlank()) { "requested_role cannot be blank" }
            require(it.mfaAssertion.isNotBlank()) { "mfa_assertion cannot be blank" }
            require(it.idempotencyKey.isNotBlank()) { "idempotency_key cannot be blank" }
        }

    fun parseAdminMfaStepUpResponse(json: String): AdminMfaStepUpResponseDto =
        mapper.readValue(json, AdminMfaStepUpResponseDto::class.java)

    fun parseAuthErrorResponse(json: String): AuthErrorResponseDto =
        mapper.readValue(json, AuthErrorResponseDto::class.java)

    fun toJson(value: Any): String = mapper.writeValueAsString(value)
}
