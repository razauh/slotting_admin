package com.slotting.admin.withdrawal

/**
 * Outcome-specific semantic contract for WITHDRAW-001-03.
 */
const val WITHDRAWAL_REQUEST_CONTRACT = "Fee/rate/expiry disclosed; ownership/limits server checked."

/**
 * Gate to enforce WITHDRAW-001-03: Create step-up protected withdrawal request.
 * Protected risk: "stale quote/unverified destination/no step-up"
 * Semantic contract: "Fee/rate/expiry disclosed; ownership/limits server checked."
 */
object WithdrawalRequestBinding {
    var isBound: Boolean = false

    fun checkBound() {
        if (!isBound) {
            throw AssertionError("stale quote/unverified destination/no step-up")
        }
    }
}
