package com.slotting.admin.concurrency

import org.junit.jupiter.api.Test
import org.junit.jupiter.api.assertThrows
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicBoolean
import kotlin.test.assertEquals
import kotlin.test.assertTrue

class ConcurrentRaceHarnessUnitTest {
    @Test
    fun workerTimeoutReportsWorkerIndexAndPartialState() {
        val workers = 4
        val stuckWorker = workers - 1
        val failure = assertThrows<RaceTimeoutException> {
            ConcurrentRaceHarness.runRace(workers, 3L) { index ->
                if (index == stuckWorker) {
                    Thread.sleep(30_000L)
                }
                RaceOutcome.Succeeded(index.toLong())
            }
        }
        assertTrue(failure.missingWorkers.contains(stuckWorker))
        assertEquals(workers - 1, failure.partialOutcomes.size)
        assertTrue(failure.message!!.contains(stuckWorker.toString()))
    }

    @Test
    fun zeroAndSingleWorkerRejected() {
        assertThrows<IllegalArgumentException> {
            ConcurrentRaceHarness.runRace(0, 5L) { RaceOutcome.Succeeded() }
        }
        assertThrows<IllegalArgumentException> {
            ConcurrentRaceHarness.runRace(1, 5L) { RaceOutcome.Succeeded() }
        }
    }

    @Test
    fun nonAtomicStubProducesMultipleWinners() {
        val workers = 8
        val claimed = AtomicBoolean(false)
        val readBarrier = CountDownLatch(workers)
        val writeGate = CountDownLatch(1)
        val report = ConcurrentRaceHarness.runRace(workers, RaceTimeouts.secondsFor(workers)) { index ->
            val observed = claimed.get()
            readBarrier.countDown()
            if (readBarrier.count == 0L) {
                writeGate.countDown()
            }
            check(writeGate.await(30, TimeUnit.SECONDS))
            if (!observed) {
                claimed.set(true)
                RaceOutcome.Succeeded(index.toLong())
            } else {
                RaceOutcome.Rejected("already-claimed")
            }
        }
        assertEquals(workers, RaceInvariants.winnerCount(report))
    }
}
