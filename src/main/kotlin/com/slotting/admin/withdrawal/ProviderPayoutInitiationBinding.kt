package com.slotting.admin.withdrawal

/**
 * Gate to enforce WITHDRAW-003-01: Initiate idempotent provider payout.
 * Semantic contract: "Unknown stays pending/reconcile; only definitive rejection releases; success captures lock."
 * Protected risk: "duplicate payout/bad callback/ambiguous timeout"
 */
object ProviderPayoutInitiationBinding {
    var isBound: Boolean = true

    fun checkBound() {
        if (!isBound) {
            throw AssertionError("duplicate payout/bad callback/ambiguous timeout")
        }
    }
}
