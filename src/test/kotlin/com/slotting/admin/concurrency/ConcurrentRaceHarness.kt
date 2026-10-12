package com.slotting.admin.concurrency

import io.micrometer.core.instrument.Metrics
import org.slf4j.LoggerFactory
import java.util.UUID
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.CountDownLatch
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit

object RaceTenantFactory {
    fun newTenant(prefix: String): String {
        require(prefix.isNotBlank()) { "RaceTenantFactory prefix must not be blank" }
        return prefix + "-" + UUID.randomUUID().toString().take(8)
    }
}

sealed interface RaceOutcome {
    data class Succeeded(val wins: Long = 1L) : RaceOutcome
    data class Rejected(val reason: String) : RaceOutcome
    data class Failed(val error: Throwable) : RaceOutcome
}

data class RaceReport(
    val workers: Int,
    val outcomes: Map<Int, RaceOutcome>,
    val durationMillis: Long,
)

class RaceTimeoutException(
    val workers: Int,
    val timeoutSeconds: Long,
    val missingWorkers: List<Int>,
    val partialOutcomes: Map<Int, RaceOutcome>,
) : RuntimeException(
    "Race timed out after " + timeoutSeconds + "s with " + workers + " workers; " +
        "missing workers=" + missingWorkers + "; " +
        "completed " + partialOutcomes.size + " of " + workers + "; " +
        "winners=" + partialOutcomes.values.filterIsInstance<RaceOutcome.Succeeded>().size + "; " +
        "rejected=" + partialOutcomes.values.filterIsInstance<RaceOutcome.Rejected>().size + "; " +
        "failed=" + partialOutcomes.values.filterIsInstance<RaceOutcome.Failed>().size,
)

object RaceTimeouts {
    fun secondsFor(workers: Int): Long =
        when {
            workers <= 8 -> 60L
            workers <= 16 -> 120L
            else -> 180L
        }
}

object RaceInvariants {
    fun winnerCount(report: RaceReport): Int =
        report.outcomes.values.filterIsInstance<RaceOutcome.Succeeded>().size

    fun requireExactlyOneWinner(report: RaceReport): Int {
        val winners = report.outcomes.entries
            .filter { it.value is RaceOutcome.Succeeded }
            .map { it.key }
        check(winners.size == 1) {
            "Expected exactly one race winner but found " + winners.size +
                " winners=" + winners + " outcomes=" + report.outcomes
        }
        return winners.single()
    }

    fun requireLedgerConserved(totalDebits: Long, totalCredits: Long, expectedTotal: Long) {
        check(totalDebits == totalCredits) {
            "Ledger conservation violated: debits=" + totalDebits + " credits=" + totalCredits
        }
        check(totalDebits == expectedTotal) {
            "Ledger total drifted: posted=" + totalDebits + " expected=" + expectedTotal
        }
    }

    fun requireNoOverdraft(balance: Long, accountReference: String) {
        check(balance >= 0L) {
            "Overdraft detected on " + accountReference + ": balance=" + balance
        }
    }
}

object ConcurrentRaceHarness {
    private val logger = LoggerFactory.getLogger(ConcurrentRaceHarness::class.java)

    fun runRace(workers: Int, timeoutSeconds: Long, task: (Int) -> RaceOutcome): RaceReport {
        require(workers >= 2) { "ConcurrentRaceHarness requires at least 2 workers, got " + workers }
        require(timeoutSeconds > 0) { "ConcurrentRaceHarness requires a positive timeout, got " + timeoutSeconds }
        val startedNanos = System.nanoTime()
        val gate = CountDownLatch(1)
        val done = CountDownLatch(workers)
        val outcomes = ConcurrentHashMap<Int, RaceOutcome>()
        val pool = Executors.newFixedThreadPool(workers)
        try {
            repeat(workers) { index ->
                pool.submit {
                    try {
                        gate.await()
                        outcomes[index] =
                            runCatching { task(index) }.getOrElse { error ->
                                if (error is InterruptedException) {
                                    Thread.currentThread().interrupt()
                                }
                                RaceOutcome.Failed(error)
                            }
                    } catch (error: InterruptedException) {
                        Thread.currentThread().interrupt()
                        outcomes[index] = RaceOutcome.Failed(error)
                    } catch (error: Throwable) {
                        outcomes[index] = RaceOutcome.Failed(error)
                    } finally {
                        done.countDown()
                    }
                }
            }
            gate.countDown()
            val finished = done.await(timeoutSeconds, TimeUnit.SECONDS)
            val durationMillis = TimeUnit.NANOSECONDS.toMillis(System.nanoTime() - startedNanos)
            if (!finished) {
                val missing = (0 until workers).filter { !outcomes.containsKey(it) }
                pool.shutdownNow()
                throw RaceTimeoutException(workers, timeoutSeconds, missing, outcomes.toSortedMap())
            }
            pool.shutdown()
            pool.awaitTermination(30, TimeUnit.SECONDS)
            val report = RaceReport(workers, outcomes.toSortedMap(), durationMillis)
            logger.debug(
                "race_report workers={} winners={} rejected={} failed={} durationMillis={}",
                workers,
                RaceInvariants.winnerCount(report),
                report.outcomes.values.filterIsInstance<RaceOutcome.Rejected>().size,
                report.outcomes.values.filterIsInstance<RaceOutcome.Failed>().size,
                durationMillis,
            )
            Metrics.counter("test.race.workers", "workers", workers.toString()).increment()
            return report
        } catch (error: Throwable) {
            pool.shutdownNow()
            throw error
        }
    }
}
