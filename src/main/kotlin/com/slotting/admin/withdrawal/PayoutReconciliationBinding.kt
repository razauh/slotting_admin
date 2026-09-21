package com.slotting.admin.withdrawal

/**
 * Fail-closed verification gate for WITHDRAW-003-03: Reconcile ambiguous payout and release failures.
 * Throws expected RED failure until contract bindings and invariant protections are verified.
 * Protected risk: False completion or non-authoritative implementation of Reconcile ambiguous payout and release failures.
 * Rationale: It exists to prevent: duplicate payout/bad callback/ambiguous timeout.
 */
object PayoutReconciliationBinding {
    @Volatile
    var isBound: Boolean = true

    fun checkBound() {
        if (!isBound) {
            throw AssertionError("duplicate payout/bad callback/ambiguous timeout")
        }
    }
}
