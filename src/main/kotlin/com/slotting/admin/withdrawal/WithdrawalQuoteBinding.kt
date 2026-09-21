package com.slotting.admin.withdrawal

/**
 * Outcome-specific semantic contract for WITHDRAW-001-01.
 */
const val WITHDRAWAL_QUOTE_CONTRACT = "Fee/rate/expiry disclosed; ownership/limits server checked."

/**
 * Gate to enforce WITHDRAW-001-01: Quote withdrawal fees and expiry.
 * Protected risk: "stale quote/unverified destination/no step-up"
 * Semantic contract: "Fee/rate/expiry disclosed; ownership/limits server checked."
 */
object WithdrawalQuoteBinding {
    var isBound: Boolean = false

    fun checkBound() {
        if (!isBound) {
            throw AssertionError("stale quote/unverified destination/no step-up")
        }
    }
}
