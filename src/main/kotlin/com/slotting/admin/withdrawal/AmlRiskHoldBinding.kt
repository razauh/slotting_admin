package com.slotting.admin.withdrawal

/**
 * Outcome-specific semantic contract for WITHDRAW-002-02.
 */
const val AML_RISK_HOLD_CONTRACT = "One request locks exact funds; rejection/cancel release policy explicit/audited."

/**
 * Gate to enforce WITHDRAW-002-02: Apply AML risk hold.
 * Protected risk: "payout without lock/approval"
 * Semantic contract: "One request locks exact funds; rejection/cancel release policy explicit/audited."
 */
object AmlRiskHoldBinding {
    var isBound: Boolean = false

    fun checkBound() {
        if (!isBound) {
            throw AssertionError("payout without lock/approval")
        }
    }
}
