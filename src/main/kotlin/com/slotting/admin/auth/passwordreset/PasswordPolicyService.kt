package com.slotting.admin.auth.passwordreset

object PasswordPolicyService {
    const val MIN_LENGTH = 15
    const val MAX_LENGTH = 64

    private val FORBIDDEN_PASSWORDS = setOf(
        "DefaultPass123!",
        "password",
        "12345678",
        "admin123"
    )

    private val COMPROMISED_BLOCKLIST = setOf(
        "password",
        "password123",
        "password1234",
        "password12345",
        "password123456",
        "password12345678",
        "12345678",
        "123456789",
        "1234567890",
        "123456789012345",
        "admin123",
        "admin1234",
        "admin12345",
        "admin123456",
        "DefaultPass123!",
        "correcthorsebatterystaple1",
        "qwertyuiopasdfgh",
        "letmeinletmein123"
    )

    data class PolicyVerdict(
        val valid: Boolean,
        val errorMessage: String? = null
    )

    fun validate(password: String, confirmPassword: String? = null): PolicyVerdict {
        if (confirmPassword != null && password != confirmPassword) {
            return PolicyVerdict(false, "Passwords do not match.")
        }
        if (password.length < MIN_LENGTH) {
            return PolicyVerdict(false, "Password must be at least $MIN_LENGTH characters in length.")
        }
        if (password.length > MAX_LENGTH) {
            return PolicyVerdict(false, "Password must not exceed $MAX_LENGTH characters.")
        }
        if (password.isBlank()) {
            return PolicyVerdict(false, "Password cannot be blank or contain only whitespace.")
        }
        val lower = password.lowercase().trim()
        if (lower in COMPROMISED_BLOCKLIST || password in FORBIDDEN_PASSWORDS) {
            return PolicyVerdict(false, "This password is known to be commonly used or compromised. Please choose a more unique passphrase.")
        }
        return PolicyVerdict(true)
    }
}
