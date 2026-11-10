package com.slotting.admin.realtime

import org.junit.jupiter.api.Test
import kotlin.test.assertEquals

class RealtimeConvergenceTest {
    private fun frame(sequence: Long) = RealtimeFrame(sequence, mapOf("phase" to "BETTING"))

    @Test
    fun `in order frames apply`() {
        val convergence = RealtimeConvergence()

        assertEquals(ConvergenceAction.APPLIED, convergence.accept(frame(1)))
        assertEquals(ConvergenceAction.APPLIED, convergence.accept(frame(2)))
    }

    @Test
    fun `duplicate frame is ignored`() {
        val convergence = RealtimeConvergence()

        convergence.accept(frame(1))
        assertEquals(ConvergenceAction.IGNORED_DUPLICATE, convergence.accept(frame(1)))
    }

    @Test
    fun `stale frame is ignored and never rewinds state`() {
        val convergence = RealtimeConvergence()

        convergence.accept(frame(1))
        convergence.accept(frame(2))
        assertEquals(ConvergenceAction.IGNORED_STALE, convergence.accept(frame(1)))
    }

    @Test
    fun `gap requires exactly one reconcile`() {
        val convergence = RealtimeConvergence()

        convergence.accept(frame(1))
        assertEquals(ConvergenceAction.RECONCILE_REQUIRED, convergence.accept(frame(5)))
        assertEquals(ConvergenceAction.IGNORED_DURING_RECONCILE, convergence.accept(frame(6)))
        assertEquals(ConvergenceAction.IGNORED_DURING_RECONCILE, convergence.accept(frame(7)))
    }

    @Test
    fun `reconcile snapshot resumes without duplicate or rewind`() {
        val convergence = RealtimeConvergence()

        convergence.accept(frame(1))
        convergence.accept(frame(5))
        convergence.completeReconcile(5)

        assertEquals(ConvergenceAction.IGNORED_STALE, convergence.accept(frame(4)))
        assertEquals(ConvergenceAction.APPLIED, convergence.accept(frame(6)))
    }

    @Test
    fun `slow consumer drops the oldest frame without blocking`() {
        val convergence = RealtimeConvergence(capacity = 2)

        assertEquals(ConvergenceAction.APPLIED, convergence.enqueue(frame(1)))
        assertEquals(ConvergenceAction.APPLIED, convergence.enqueue(frame(2)))
        assertEquals(ConvergenceAction.DROPPED_SLOW_CONSUMER, convergence.enqueue(frame(3)))
        assertEquals(2, convergence.pendingCount())
        assertEquals(3, convergence.pendingSequences().last())
    }
}
