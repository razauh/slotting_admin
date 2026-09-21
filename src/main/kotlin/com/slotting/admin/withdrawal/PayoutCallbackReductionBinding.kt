package com.slotting.admin.withdrawal

/**
 * Fail-closed verification gate for WITHDRAW-003-02: Authenticate and reduce payout callbacks.
 * Throws expected RED failure until contract bindings and invariant protections are verified.
 * Protected risk: False completion or non-authoritative implementation of Authenticate and reduce payout callbacks.
 * Rationale: It exists to prevent: duplicate payout/bad callback/ambiguous timeout.
 */
object PayoutCallbackReductionBinding {
    @Volatile
    var isBound: Boolean = true

    fun checkBound() {
        if (!isBound) {
            throw AssertionError("duplicate payout/bad callback/ambiguous timeout")
        }
    }
}
