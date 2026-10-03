package com.slotting.admin.auth.passwordreset

import org.springframework.web.util.HtmlUtils

object PasswordResetHtmlRenderer {

    private const val COMMON_STYLE = """
        body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; background: #0b0e14; color: #e6edf3; display: flex; justify-content: center; align-items: center; min-height: 100vh; margin: 0; padding: 16px; box-sizing: border-box; }
        .card { background: #161b22; border: 1px solid #30363d; border-radius: 8px; padding: 32px; width: 100%; max-width: 400px; box-shadow: 0 8px 24px rgba(0,0,0,0.5); }
        h1 { font-size: 20px; font-weight: 600; margin-bottom: 8px; text-align: center; color: #58a6ff; }
        p { font-size: 14px; color: #8b949e; text-align: center; margin-bottom: 24px; line-height: 1.5; }
        label { display: block; font-size: 13px; font-weight: 500; margin-bottom: 6px; }
        input[type="email"], input[type="password"] { width: 100%; box-sizing: border-box; padding: 10px; background: #0d1117; border: 1px solid #30363d; border-radius: 6px; color: #e6edf3; font-size: 14px; margin-bottom: 16px; }
        input[type="email"]:focus, input[type="password"]:focus { border-color: #58a6ff; outline: none; }
        button, .btn { display: block; width: 100%; box-sizing: border-box; padding: 12px; background: #238636; border: 1px solid rgba(240,246,252,0.1); border-radius: 6px; color: #fff; font-size: 14px; font-weight: 600; cursor: pointer; text-align: center; text-decoration: none; margin-top: 8px; }
        button:hover, .btn:hover { background: #2ea043; }
        .btn-secondary { background: #21262d; border-color: #30363d; margin-top: 10px; }
        .btn-secondary:hover { background: #30363d; }
        .alert-error { color: #ff7b72; background: rgba(248,81,73,0.1); border: 1px solid rgba(248,81,73,0.4); padding: 10px; border-radius: 6px; margin-bottom: 16px; font-size: 13px; line-height: 1.4; }
        .alert-success { color: #56d364; background: rgba(46,160,67,0.1); border: 1px solid rgba(46,160,67,0.4); padding: 10px; border-radius: 6px; margin-bottom: 16px; font-size: 13px; line-height: 1.4; }
        .note { font-size: 12px; color: #8b949e; text-align: center; margin-top: 16px; }
        .note a { color: #58a6ff; text-decoration: none; }
        .note a:hover { text-decoration: underline; }
    """

    fun renderForgotPasswordFormHtml(
        csrfToken: String,
        errorMessage: String? = null,
        successMessage: String? = null
    ): String {
        val errorHtml = if (errorMessage != null) {
            """<div class="alert-error">${HtmlUtils.htmlEscape(errorMessage)}</div>"""
        } else ""

        val successHtml = if (successMessage != null) {
            """<div class="alert-success">${HtmlUtils.htmlEscape(successMessage)}</div>"""
        } else ""

        return """
        <!DOCTYPE html>
        <html lang="en">
        <head>
            <meta charset="UTF-8">
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <meta name="referrer" content="no-referrer">
            <title>Slotting - Forgot Password</title>
            <style>$COMMON_STYLE</style>
        </head>
        <body>
            <div class="card">
                <h1>Reset Password</h1>
                <p>Enter the email address associated with your verified Slotting account.</p>
                $errorHtml
                $successHtml
                <form method="POST" action="/auth/password-reset/request">
                    <input type="hidden" name="csrf_token" value="${HtmlUtils.htmlEscape(csrfToken)}" />
                    <label for="email">Account Email</label>
                    <input type="email" id="email" name="email" required autocomplete="email" placeholder="player@example.com" />
                    <button type="submit">Send Reset Link</button>
                    <a href="/oauth2/authorize" class="btn btn-secondary">Return to Sign In</a>
                </form>
                <div class="note">
                    Secure account recovery. Reset links expire in 15 minutes.
                </div>
            </div>
        </body>
        </html>
        """.trimIndent()
    }

    fun renderGenericConfirmationHtml(message: String): String {
        return """
        <!DOCTYPE html>
        <html lang="en">
        <head>
            <meta charset="UTF-8">
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <meta name="referrer" content="no-referrer">
            <title>Slotting - Instructions Dispatched</title>
            <style>$COMMON_STYLE</style>
        </head>
        <body>
            <div class="card">
                <h1>Check Your Email</h1>
                <p>${HtmlUtils.htmlEscape(message)}</p>
                <div class="alert-success">
                    If your account and verified email match, an email with a secure single-use reset link has been dispatched.
                </div>
                <a href="/oauth2/authorize" class="btn btn-secondary">Return to Sign In</a>
                <div class="note">
                    Did not receive it? Check your spam folder or wait before requesting another link.
                </div>
            </div>
        </body>
        </html>
        """.trimIndent()
    }

    fun renderNewPasswordFormHtml(
        csrfToken: String,
        transactionId: String,
        errorMessage: String? = null
    ): String {
        val errorHtml = if (errorMessage != null) {
            """<div class="alert-error">${HtmlUtils.htmlEscape(errorMessage)}</div>"""
        } else ""

        return """
        <!DOCTYPE html>
        <html lang="en">
        <head>
            <meta charset="UTF-8">
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <meta name="referrer" content="no-referrer">
            <title>Slotting - Set New Password</title>
            <style>$COMMON_STYLE</style>
        </head>
        <body>
            <div class="card">
                <h1>Choose New Password</h1>
                <p>Enter a new secure password of at least 15 characters.</p>
                $errorHtml
                <form method="POST" action="/auth/password-reset/complete">
                    <input type="hidden" name="csrf_token" value="${HtmlUtils.htmlEscape(csrfToken)}" />
                    <input type="hidden" name="transaction_id" value="${HtmlUtils.htmlEscape(transactionId)}" />
                    
                    <label for="new_password">New Password</label>
                    <input type="password" id="new_password" name="new_password" required minlength="15" maxlength="64" autocomplete="new-password" />
                    
                    <label for="confirm_password">Confirm New Password</label>
                    <input type="password" id="confirm_password" name="confirm_password" required minlength="15" maxlength="64" autocomplete="new-password" />
                    
                    <button type="submit">Update Password</button>
                </form>
                <div class="note">
                    Passphrases with spaces and symbols are accepted.
                </div>
            </div>
        </body>
        </html>
        """.trimIndent()
    }

    fun renderSuccessHtml(): String {
        return """
        <!DOCTYPE html>
        <html lang="en">
        <head>
            <meta charset="UTF-8">
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <meta name="referrer" content="no-referrer">
            <title>Slotting - Password Reset Successful</title>
            <style>$COMMON_STYLE</style>
        </head>
        <body>
            <div class="card">
                <h1>Password Reset Successful</h1>
                <p>Your password has been securely updated.</p>
                <div class="alert-success">
                    For your security, you have been signed out of existing sessions. Please sign in again using your new password.
                </div>
                <a href="/oauth2/authorize" class="btn">Return to Sign In</a>
                <a href="https://app.slotting.internal/auth/callback" class="btn btn-secondary">Return to App</a>
                <div class="note">
                    A confirmation notice has been sent to your verified email address.
                </div>
            </div>
        </body>
        </html>
        """.trimIndent()
    }

    fun renderErrorHtml(message: String): String {
        return """
        <!DOCTYPE html>
        <html lang="en">
        <head>
            <meta charset="UTF-8">
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <meta name="referrer" content="no-referrer">
            <title>Slotting - Password Reset Error</title>
            <style>$COMMON_STYLE</style>
        </head>
        <body>
            <div class="card">
                <h1 style="color: #ff7b72;">Recovery Unavailable</h1>
                <div class="alert-error">
                    ${HtmlUtils.htmlEscape(message)}
                </div>
                <p>This password reset link is invalid or has expired. Please request a new one.</p>
                <a href="/auth/forgot-password" class="btn">Request New Reset Link</a>
                <a href="/oauth2/authorize" class="btn btn-secondary">Return to Sign In</a>
            </div>
        </body>
        </html>
        """.trimIndent()
    }
}
