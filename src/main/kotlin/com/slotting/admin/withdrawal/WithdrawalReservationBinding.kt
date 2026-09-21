package com.slotting.admin.withdrawal

/**
 * Outcome-specific semantic contract for WITHDRAW-002-01.
 */
const val WITHDRAWAL_RESERVATION_CONTRACT = "One request locks exact funds; rejection/cancel release policy explicit/audited."

/**
 * Gate to enforce WITHDRAW-002-01: Reserve withdrawal funds.
 * Protected risk: "payout without lock/approval"
 * Semantic contract: "One request locks exact funds; rejection/cancel release policy explicit/audited."
 */
object WithdrawalReservationBinding {
    var isBound: Boolean = false

    fun checkBound() {
        if (!isBound) {
            throw AssertionError("payout without lock/approval")
        }
    }
}
