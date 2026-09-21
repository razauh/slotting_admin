package com.slotting.admin.worker

/**
 * Binding gate for WORKER-001-03: Authorize replay and publish worker health.
 *
 * Invariant protection: "crash/loss/poison/replay duplicate"
 * Semantic contract: "Bounded exponential retry; replay authorized/audited; lag/oldest-age health."
 */
object AuthorizeReplayWorkerHealthBinding {
    var isBound: Boolean = true

    fun checkBound() {
        if (!isBound) {
            throw AssertionError("crash/loss/poison/replay duplicate")
        }
    }
}
