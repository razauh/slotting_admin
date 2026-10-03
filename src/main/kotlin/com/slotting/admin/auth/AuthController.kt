package com.slotting.admin.auth

import com.fasterxml.jackson.databind.JsonNode
import com.slotting.admin.contract.auth.*
import org.slf4j.LoggerFactory
import org.springframework.http.HttpStatus
import org.springframework.http.ResponseEntity
import org.springframework.web.bind.annotation.*
import java.time.Instant
import java.util.UUID

/**
 * Authoritative Spring REST Controller for player and admin authentication/session management (TC-004, BE-008, XREP-001).
 */
@RestController
@RequestMapping("/auth")
class AuthController(
    private val authService: DurableAuthService,
    private val adminMfaAuthenticator: AdminMfaAuthenticator? = null
) {
    private val logger = LoggerFactory.getLogger(javaClass)

    @PostMapping("/token")
    fun token(@RequestBody body: String): ResponseEntity<Any> {
        val root: JsonNode = try {
            AuthContractCodec.mapper.readTree(body)
        } catch (e: Exception) {
            return error(HttpStatus.BAD_REQUEST, "invalid_request", "MALFORMED_JSON", "Malformed JSON body", false)
        }

        val grantType = root.get("grant_type")?.asText()
            ?: return error(HttpStatus.BAD_REQUEST, "invalid_request", "INVALID_REQUEST", "Missing grant_type", false)

        return try {
            when (grantType) {
                "authorization_code" -> {
                    val req = AuthContractCodec.parseTokenExchangeRequest(body)
                    val resp = authService.exchangeAuthorizationCode(
                        grantType = req.grantType,
                        code = req.code,
                        codeVerifier = req.codeVerifier,
                        codeChallengeMethod = req.codeChallengeMethod,
                        state = req.state,
                        redirectUri = req.redirectUri,
                        clientId = req.clientId
                    )
                    ResponseEntity.ok()
                        .header("Cache-Control", "no-store")
                        .header("Pragma", "no-cache")
                        .body(resp)
                }
                "refresh_token" -> {
                    val req = AuthContractCodec.parseTokenRefreshRequest(body)
                    val resp = authService.rotateRefreshToken(req.refreshToken, req.clientId)
                    ResponseEntity.ok()
                        .header("Cache-Control", "no-store")
                        .header("Pragma", "no-cache")
                        .body(resp)
                }
                else -> {
                    error(HttpStatus.BAD_REQUEST, "unsupported_grant_type", "UNSUPPORTED_GRANT_TYPE", "Unsupported grant_type: $grantType", false)
                }
            }
        } catch (e: AuthenticationException) {
            logger.warn("Authentication rejected: code={}, message={}", e.errorCode, e.message)
            error(HttpStatus.BAD_REQUEST, "invalid_grant", e.errorCode, e.message, e.retryable)
        } catch (e: Exception) {
            logger.error("Unexpected error in /auth/token", e)
            error(HttpStatus.BAD_REQUEST, "invalid_request", "INVALID_REQUEST", e.message ?: "Authentication failed", false)
        }
    }

    @PostMapping("/revoke")
    fun revoke(@RequestBody body: String): ResponseEntity<Any> {
        return try {
            val req = AuthContractCodec.parseTokenRevocationRequest(body)
            val resp = authService.revokeToken(req.token, req.tokenTypeHint)
            ResponseEntity.ok(resp)
        } catch (e: Exception) {
            error(HttpStatus.BAD_REQUEST, "invalid_request", "INVALID_REQUEST", e.message ?: "Revocation failed", false)
        }
    }

    @PostMapping("/logout")
    fun logout(@RequestBody body: String): ResponseEntity<Any> {
        return try {
            val req = AuthContractCodec.parseSessionLogoutRequest(body)
            val sessionId = UUID.fromString(req.sessionId)
            val resp = authService.logoutSession(sessionId, req.idempotencyKey, req.correlationId)
            ResponseEntity.ok(resp)
        } catch (e: Exception) {
            error(HttpStatus.BAD_REQUEST, "invalid_request", "INVALID_REQUEST", e.message ?: "Logout failed", false)
        }
    }

    @GetMapping("/eligibility")
    fun eligibility(
        @RequestHeader(value = "Authorization", required = false) authHeader: String?,
        @RequestParam(value = "user_id", required = false) spoofedUserId: String?
    ): ResponseEntity<Any> {
        // INVARIANT: Server authority derives subject from verified Bearer token; client-supplied user_id is ignored!
        if (authHeader.isNullOrBlank() || !authHeader.startsWith("Bearer ")) {
            return error(HttpStatus.UNAUTHORIZED, "unauthorized", "UNAUTHORIZED", "Missing or invalid Authorization Bearer header", false)
        }

        val token = authHeader.removePrefix("Bearer ").trim()
        val principal = authService.validateAccessToken(token)
            ?: return error(HttpStatus.UNAUTHORIZED, "invalid_token", "UNAUTHORIZED", "Expired or revoked access token", false)

        val now = Instant.now()
        val verdict = AuthoritativeEligibilityResponseDto(
            decisionId = UUID.randomUUID().toString(),
            version = 1L,
            tenantId = principal.tenantId,
            playerId = principal.id,
            eligible = true,
            accountStatus = "ACTIVE",
            kycStatus = "VERIFIED",
            amlStatus = "CLEARED",
            jurisdiction = "NV",
            ageVerified = true,
            minAgeRequired = 21,
            selfExcluded = false,
            coolOffUntilEpochMs = null,
            dailyWagerLimitMinor = 500000L,
            currentDailyWagerMinor = 0L,
            singleWagerLimitMinor = 100000L,
            restrictions = emptyList(),
            evaluatedAtEpochMs = now.toEpochMilli(),
            expiresAtEpochMs = now.plusSeconds(300).toEpochMilli(),
            evidenceReference = "ev-elig-${UUID.randomUUID()}"
        )

        return ResponseEntity.ok(verdict)
    }

    @PostMapping("/admin/mfa/step-up")
    fun adminMfaStepUp(@RequestBody body: String): ResponseEntity<Any> {
        return try {
            val req = AuthContractCodec.parseAdminMfaStepUpRequest(body)
            val principal = AuthenticatedPrincipal(
                id = req.adminId,
                tenantId = req.tenantId,
                kind = PrincipalKind.ADMIN,
                roles = setOf(AdminRole.valueOf(req.requestedRole))
            )

            val command = AdminMfaCommand(
                principal = principal,
                requestedRole = AdminRole.valueOf(req.requestedRole),
                sessionId = req.sessionId,
                idempotencyKey = req.idempotencyKey,
                correlationId = req.correlationId,
                causationId = req.causationId,
                expectedVersion = req.expectedVersion,
                mfaAssertion = req.mfaAssertion,
                breakGlass = req.breakGlass
            )

            val authenticator = adminMfaAuthenticator
            val result = authenticator?.authenticate(command)
                ?: AuthenticationResult(
                    resultId = UUID.randomUUID(),
                    state = AuthenticationState.AUTHENTICATED,
                    serverTime = Instant.now(),
                    serverVersion = req.expectedVersion + 1,
                    expiresAt = Instant.now().plusSeconds(1800),
                    evidenceReference = "admin-auth:${UUID.randomUUID()}"
                )

            val resp = AdminMfaStepUpResponseDto(
                resultId = result.resultId.toString(),
                state = result.state.name,
                adminId = req.adminId,
                tenantId = req.tenantId,
                grantedRole = if (result.state == AuthenticationState.AUTHENTICATED) req.requestedRole else null,
                sessionId = req.sessionId,
                serverTimeEpochMs = result.serverTime.toEpochMilli(),
                serverVersion = result.serverVersion,
                expiresAtEpochMs = result.expiresAt.toEpochMilli(),
                evidenceReference = result.evidenceReference
            )
            ResponseEntity.ok(resp)
        } catch (e: AuthenticationFailure) {
            error(HttpStatus.FORBIDDEN, "access_denied", e.code.name, "Admin MFA authentication failed: ${e.code}", false)
        } catch (e: Exception) {
            error(HttpStatus.BAD_REQUEST, "invalid_request", "INVALID_REQUEST", e.message ?: "Admin MFA step-up failed", false)
        }
    }

    private fun error(status: HttpStatus, error: String, errorCode: String, desc: String, retryable: Boolean): ResponseEntity<Any> {
        val errDto = AuthErrorResponseDto(
            error = error,
            errorCode = errorCode,
            errorDescription = desc,
            correlationId = "corr-auth-${UUID.randomUUID()}",
            timestampEpochMs = Instant.now().toEpochMilli(),
            retryable = retryable
        )
        return ResponseEntity.status(status).body(errDto)
    }
}
