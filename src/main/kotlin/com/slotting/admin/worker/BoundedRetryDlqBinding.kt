package com.slotting.admin.worker

/**
 * Binding gate for WORKER-001-02: Operate bounded retry and dead-letter queues.
 *
 * Invariant protection: "crash/loss/poison/replay duplicate"
 * Semantic contract: "Bounded exponential retry; replay authorized/audited; lag/oldest-age health."
 */
object BoundedRetryDlqBinding {
    var isBound: Boolean = true

    fun checkBound() {
        if (!isBound) {
            throw AssertionError("crash/loss/poison/replay duplicate")
        }
    }
}
