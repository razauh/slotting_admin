package com.slotting.admin.auth.passwordreset

import java.util.concurrent.CopyOnWriteArrayList

data class SentEmailRecord(
    val toEmail: String,
    val subject: String,
    val body: String,
    val resetUrl: String?,
    val isNotification: Boolean
)

interface PasswordResetEmailSender {
    fun sendPasswordResetEmail(toEmail: String, resetUrl: String, expirySeconds: Long): Boolean
    fun sendPasswordChangedNotification(toEmail: String): Boolean
}

class InMemoryPasswordResetEmailSender : PasswordResetEmailSender {
    val sentEmails = CopyOnWriteArrayList<SentEmailRecord>()

    override fun sendPasswordResetEmail(toEmail: String, resetUrl: String, expirySeconds: Long): Boolean {
        val subject = "Slotting - Password Reset Request"
        val expiryText = if (expirySeconds >= 60 && expirySeconds % 60 == 0L) {
            "${expirySeconds / 60} minutes"
        } else {
            "$expirySeconds seconds"
        }
        val body = """
            Hello,

            A password reset was requested for your verified Slotting account.
            To choose a new password, click the link below or copy and paste it into your browser:

            $resetUrl

            This link will expire in $expiryText and can only be used once.

            If you did not request this password reset, please ignore this email; your password has not been changed.
            Slotting Support will never ask you to send or disclose this link or your password.

            Security Team
            Slotting Authentication Authority
        """.trimIndent()

        sentEmails.add(
            SentEmailRecord(
                toEmail = toEmail,
                subject = subject,
                body = body,
                resetUrl = resetUrl,
                isNotification = false
            )
        )
        return true
    }

    override fun sendPasswordChangedNotification(toEmail: String): Boolean {
        val subject = "Slotting - Your Password Was Changed"
        val body = """
            Hello,

            The password for your Slotting account was recently changed.
            For your security, all active sessions and refresh tokens have been signed out.

            If you performed this password change, no further action is required.
            If you did NOT initiate this change, your account may be compromised. Please contact official Slotting Security Support immediately.

            Security Team
            Slotting Authentication Authority
        """.trimIndent()

        sentEmails.add(
            SentEmailRecord(
                toEmail = toEmail,
                subject = subject,
                body = body,
                resetUrl = null,
                isNotification = true
            )
        )
        return true
    }

    fun clear() {
        sentEmails.clear()
    }
}
