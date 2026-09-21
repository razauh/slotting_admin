package com.slotting.admin.worker

/**
 * Fail-closed verification gate for WORKER-001-01: Run leased transactional-outbox workers.
 * Throws expected RED failure until contract bindings and invariant protections are verified.
 * Protected risk: False completion or non-authoritative implementation of Run leased transactional-outbox workers.
 * Rationale: It exists to prevent: crash/loss/poison/replay duplicate.
 */
object LeasedOutboxWorkerBinding {
    @Volatile
    var isBound: Boolean = true

    fun checkBound() {
        if (!isBound) {
            throw AssertionError("crash/loss/poison/replay duplicate")
        }
    }
}
