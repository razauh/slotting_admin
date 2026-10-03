package com.slotting.admin.auth.passwordreset

import jakarta.servlet.http.HttpServletRequest
import org.springframework.http.HttpHeaders
import org.springframework.http.HttpStatus
import org.springframework.http.MediaType
import org.springframework.http.ResponseEntity
import org.springframework.web.bind.annotation.*
import java.util.UUID

@RestController
class PasswordResetController(
    val resetService: PasswordResetService
) {

    // CSRF token store for initial forgot-password form
    private val formCsrfTokens = java.util.concurrent.ConcurrentHashMap<String, java.time.Instant>()

    @GetMapping("/auth/forgot-password")
    fun forgotPasswordPage(): ResponseEntity<Any> {
        val csrf = generateFormCsrf()
        val html = PasswordResetHtmlRenderer.renderForgotPasswordFormHtml(csrf)
        return securityResponse(html, HttpStatus.OK)
    }

    @PostMapping("/auth/password-reset/request", consumes = [MediaType.APPLICATION_FORM_URLENCODED_VALUE, MediaType.APPLICATION_JSON_VALUE, "*/*"])
    fun requestReset(
        @RequestParam(name = "email", required = false) formEmail: String?,
        @RequestParam(name = "csrf_token", required = false) csrfToken: String?,
        @RequestBody(required = false) jsonBody: Map<String, Any>?,
        @RequestHeader(name = "Accept", required = false, defaultValue = "text/html") acceptHeader: String,
        request: HttpServletRequest
    ): ResponseEntity<Any> {
        val email = formEmail ?: (jsonBody?.get("email") as? String) ?: ""
        val ipAddress = getClientIp(request)
        val userAgent = request.getHeader("User-Agent") ?: "Unknown"

        val command = PasswordResetRequestCommand(
            email = email,
            ipAddress = ipAddress,
            userAgent = userAgent
        )

        val result = resetService.requestPasswordReset(command)

        if (acceptHeader.contains("application/json")) {
            return ResponseEntity.ok()
                .header(HttpHeaders.CACHE_CONTROL, "no-store")
                .header(HttpHeaders.PRAGMA, "no-cache")
                .header("Referrer-Policy", "no-referrer")
                .body(mapOf(
                    "message" to result.genericMessage,
                    "correlationId" to result.correlationId
                ))
        }

        val html = PasswordResetHtmlRenderer.renderGenericConfirmationHtml(result.genericMessage)
        return securityResponse(html, HttpStatus.OK)
    }

    /**
     * Initial token-bearing landing endpoint reached from the reset email link.
     * GET is scanner-safe: does NOT consume the token.
     * Validates token, generates short-lived reset transaction, and immediately redirects
     * to clean URL /auth/password-reset/new to strip raw token from browser history and Referrer.
     */
    @GetMapping("/auth/password-reset", "/auth/password-reset/continue")
    fun landingPage(
        @RequestParam(name = "token", required = false) token: String?,
        request: HttpServletRequest
    ): ResponseEntity<Any> {
        if (token.isNullOrBlank()) {
            val html = PasswordResetHtmlRenderer.renderErrorHtml(PasswordResetService.GENERIC_TOKEN_ERROR)
            return securityResponse(html, HttpStatus.BAD_REQUEST)
        }

        val ipAddress = getClientIp(request)
        val verification = resetService.validateTokenForLanding(token, ipAddress)

        if (!verification.valid || verification.resetTransactionId == null) {
            val html = PasswordResetHtmlRenderer.renderErrorHtml(
                verification.genericErrorMessage ?: PasswordResetService.GENERIC_TOKEN_ERROR
            )
            return securityResponse(html, HttpStatus.BAD_REQUEST)
        }

        // Redirect to clean reset form with transaction ID and CSRF token
        val cleanUrl = "/auth/password-reset/new?tx=${verification.resetTransactionId}&csrf=${verification.csrfToken}"
        return ResponseEntity.status(HttpStatus.SEE_OTHER)
            .header(HttpHeaders.LOCATION, cleanUrl)
            .header(HttpHeaders.CACHE_CONTROL, "no-store, no-cache, must-revalidate")
            .header(HttpHeaders.PRAGMA, "no-cache")
            .header("Referrer-Policy", "no-referrer")
            .build()
    }

    /**
     * Clean URL rendering the new password form without raw token in address bar.
     */
    @GetMapping("/auth/password-reset/new")
    fun newPasswordForm(
        @RequestParam(name = "tx") transactionIdStr: String,
        @RequestParam(name = "csrf") csrfToken: String
    ): ResponseEntity<Any> {
        val txId = try {
            UUID.fromString(transactionIdStr)
        } catch (_: Exception) {
            val html = PasswordResetHtmlRenderer.renderErrorHtml("Invalid reset session identifier.")
            return securityResponse(html, HttpStatus.BAD_REQUEST)
        }

        val tx = resetService.resetTransactions[txId]
        if (tx == null || java.time.Instant.now().isAfter(tx.expiresAt)) {
            val html = PasswordResetHtmlRenderer.renderErrorHtml("Reset session has expired. Please request a new link.")
            return securityResponse(html, HttpStatus.BAD_REQUEST)
        }

        val html = PasswordResetHtmlRenderer.renderNewPasswordFormHtml(
            csrfToken = csrfToken,
            transactionId = transactionIdStr
        )
        return securityResponse(html, HttpStatus.OK)
    }

    /**
     * Final submission of new password. Atomically updates password and revokes sessions.
     */
    @PostMapping("/auth/password-reset/complete", "/auth/password-reset/submit",
        consumes = [MediaType.APPLICATION_FORM_URLENCODED_VALUE, MediaType.APPLICATION_JSON_VALUE, "*/*"])
    fun completeReset(
        @RequestParam(name = "transaction_id", required = false) formTxId: String?,
        @RequestParam(name = "csrf_token", required = false) formCsrf: String?,
        @RequestParam(name = "new_password", required = false) formNewPassword: String?,
        @RequestParam(name = "confirm_password", required = false) formConfirmPassword: String?,
        @RequestBody(required = false) jsonBody: Map<String, Any>?,
        @RequestHeader(name = "Accept", required = false, defaultValue = "text/html") acceptHeader: String,
        request: HttpServletRequest
    ): ResponseEntity<Any> {
        val txStr = formTxId ?: (jsonBody?.get("transaction_id") as? String) ?: ""
        val csrf = formCsrf ?: (jsonBody?.get("csrf_token") as? String) ?: ""
        val newPassword = formNewPassword ?: (jsonBody?.get("new_password") as? String) ?: ""
        val confirmPassword = formConfirmPassword ?: (jsonBody?.get("confirm_password") as? String) ?: newPassword

        val txId = try {
            UUID.fromString(txStr)
        } catch (_: Exception) {
            if (acceptHeader.contains("application/json")) {
                return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(mapOf("error" to "Invalid reset transaction ID"))
            }
            val html = PasswordResetHtmlRenderer.renderErrorHtml("Invalid reset transaction ID.")
            return securityResponse(html, HttpStatus.BAD_REQUEST)
        }

        val ipAddress = getClientIp(request)
        val userAgent = request.getHeader("User-Agent") ?: "Unknown"

        val command = CompletePasswordResetCommand(
            resetTransactionId = txId,
            csrfToken = csrf,
            newPassword = newPassword,
            confirmPassword = confirmPassword,
            ipAddress = ipAddress,
            userAgent = userAgent
        )

        val result = resetService.completePasswordReset(command)

        if (!result.success) {
            if (acceptHeader.contains("application/json")) {
                return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(mapOf(
                    "error" to "password_reset_failed",
                    "error_description" to result.message
                ))
            }
            val html = PasswordResetHtmlRenderer.renderNewPasswordFormHtml(
                csrfToken = csrf,
                transactionId = txStr,
                errorMessage = result.message
            )
            return securityResponse(html, HttpStatus.BAD_REQUEST)
        }

        if (acceptHeader.contains("application/json")) {
            return ResponseEntity.ok()
                .header(HttpHeaders.CACHE_CONTROL, "no-store")
                .header("Referrer-Policy", "no-referrer")
                .body(mapOf(
                    "success" to true,
                    "message" to result.message,
                    "sessionsRevoked" to result.sessionsRevokedCount
                ))
        }

        val html = PasswordResetHtmlRenderer.renderSuccessHtml()
        return securityResponse(html, HttpStatus.OK)
    }

    private fun generateFormCsrf(): String {
        val token = PasswordResetTokenCrypto.generateCsrfToken()
        formCsrfTokens[token] = java.time.Instant.now().plusSeconds(1800)
        return token
    }

    private fun getClientIp(request: HttpServletRequest): String {
        val forwarded = request.getHeader("X-Forwarded-For")
        if (!forwarded.isNullOrBlank()) {
            return forwarded.split(",").first().trim()
        }
        return request.remoteAddr ?: "127.0.0.1"
    }

    private fun securityResponse(body: String, status: HttpStatus): ResponseEntity<Any> {
        return ResponseEntity.status(status)
            .contentType(MediaType.TEXT_HTML)
            .header(HttpHeaders.CACHE_CONTROL, "no-store, no-cache, must-revalidate")
            .header(HttpHeaders.PRAGMA, "no-cache")
            .header("X-Content-Type-Options", "nosniff")
            .header("X-Frame-Options", "DENY")
            .header("Referrer-Policy", "no-referrer")
            .header("Content-Security-Policy", "default-src 'self'; style-src 'self' 'unsafe-inline'; form-action 'self'; frame-ancestors 'none';")
            .body(body)
    }
}
