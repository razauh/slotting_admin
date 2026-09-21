package com.slotting.admin.withdrawal

/**
 * Outcome-specific semantic contract for WITHDRAW-001-02.
 */
const val DESTINATION_VERIFICATION_CONTRACT = "Fee/rate/expiry disclosed; ownership/limits server checked."

/**
 * Gate to enforce WITHDRAW-001-02: Verify payout destination ownership.
 * Protected risk: "stale quote/unverified destination/no step-up"
 * Semantic contract: "Fee/rate/expiry disclosed; ownership/limits server checked."
 */
object PayoutDestinationVerificationBinding {
    var isBound: Boolean = false

    fun checkBound() {
        if (!isBound) {
            throw AssertionError("stale quote/unverified destination/no step-up")
        }
    }
}
