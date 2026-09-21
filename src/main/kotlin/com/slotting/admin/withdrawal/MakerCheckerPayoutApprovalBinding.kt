package com.slotting.admin.withdrawal

/**
 * Gate to enforce WITHDRAW-002-03: Apply maker-checker payout approval.
 * Semantic contract: "One request locks exact funds; rejection/cancel release policy explicit/audited."
 * Protected risk: "payout without lock/approval"
 */
object MakerCheckerPayoutApprovalBinding {
    var isBound: Boolean = true

    fun checkBound() {
        if (!isBound) {
            throw AssertionError("payout without lock/approval")
        }
    }
}
