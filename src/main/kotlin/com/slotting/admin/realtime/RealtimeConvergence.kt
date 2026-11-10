package com.slotting.admin.realtime

data class RealtimeFrame(
    val sequence: Long,
    val payload: Map<String, Any>,
)

enum class ConvergenceAction {
    APPLIED,
    IGNORED_DUPLICATE,
    IGNORED_STALE,
    RECONCILE_REQUIRED,
    IGNORED_DURING_RECONCILE,
    DROPPED_SLOW_CONSUMER,
}

class RealtimeConvergence(private val capacity: Int = 100) {
    private var lastApplied = 0L
    private var reconciling = false
    private val pending = ArrayDeque<RealtimeFrame>()

    fun accept(frame: RealtimeFrame): ConvergenceAction {
        if (reconciling) {
            return ConvergenceAction.IGNORED_DURING_RECONCILE
        }
        if (frame.sequence == lastApplied) {
            return ConvergenceAction.IGNORED_DUPLICATE
        }
        if (frame.sequence < lastApplied) {
            return ConvergenceAction.IGNORED_STALE
        }
        if (frame.sequence > lastApplied + 1) {
            reconciling = true
            return ConvergenceAction.RECONCILE_REQUIRED
        }
        lastApplied = frame.sequence
        return ConvergenceAction.APPLIED
    }

    fun completeReconcile(snapshotSequence: Long) {
        lastApplied = maxOf(lastApplied, snapshotSequence)
        reconciling = false
    }

    fun enqueue(frame: RealtimeFrame): ConvergenceAction {
        if (pending.size >= capacity) {
            pending.removeFirst()
            pending.addLast(frame)
            return ConvergenceAction.DROPPED_SLOW_CONSUMER
        }
        pending.addLast(frame)
        return ConvergenceAction.APPLIED
    }

    fun pendingCount(): Int = pending.size

    fun pendingSequences(): List<Long> = pending.map { it.sequence }
}
