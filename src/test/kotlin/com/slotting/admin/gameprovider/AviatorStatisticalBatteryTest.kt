package com.slotting.admin.gameprovider

import java.math.BigDecimal
import java.math.RoundingMode
import java.nio.charset.StandardCharsets
import java.security.MessageDigest
import kotlin.math.abs
import kotlin.math.exp
import kotlin.math.ln
import kotlin.math.sqrt
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue
import org.junit.jupiter.api.Test

class AviatorStatisticalBatteryTest {
    private val sampleSize = 100_000
    private val alpha = 0.01
    private val seed = "tc031-fixed-seed-20261011"

    @Test
    fun givenBiasedBitGenerator_whenBatteryRuns_thenBiasRejected() {
        val biased = List(sampleSize) { index -> index % 4 != 0 }
        val uniform = List(sampleSize) { index -> uniformBit(index) }
        val biasedReport = battery(biased)
        val uniformReport = battery(uniform)
        assertFalse(biasedReport.accepted)
        assertTrue(biasedReport.tests.first { it.name == "monobit" }.adjustedPValue < alpha)
        assertTrue(uniformReport.accepted)
    }

    @Test
    fun givenRecordedProductionLikeCorpus_whenReplayed_thenResultsReproduce() {
        val first = runCorpus()
        val second = runCorpus()
        assertEquals(first, second)
        assertEquals(sampleSize, first.sampleCount)
        assertEquals("holm", first.correction)
        assertEquals(seed, first.seed)
    }

    @Test
    fun givenSyntheticKnownDistribution_whenGoodnessOfFitRuns_thenCalibrationMatches() {
        val expected = List(4) { sampleSize / 4 }
        val known = List(4) { sampleSize / 4 }
        val shifted = listOf(sampleSize / 2, 0, sampleSize / 4, sampleSize / 4)
        assertTrue(chiSquare(known, expected) > alpha)
        assertTrue(chiSquare(shifted, expected) < alpha)
        assertEquals(sampleSize, known.sum())
        assertEquals(sampleSize, shifted.sum())
    }

    @Test
    fun givenHistoricalMoneyAndOutcomeVectors_whenRefactoredPathRuns_thenSemanticsStayUnchanged() {
        assertEquals(BigDecimal("2.66"), AviatorAlgorithmRegistry.compute("1.0.0", "0".repeat(64), "seed-a", "seed-b", "seed-c"))
        assertEquals(BigDecimal("2.90"), AviatorAlgorithmRegistry.compute("1.0.0", "a".repeat(64), "client-1", "client-2", "client-3"))
        assertEquals(124L, BigDecimal("101").multiply(BigDecimal("1.2345")).setScale(0, RoundingMode.FLOOR).longValueExact())
        assertEquals(0L, BigDecimal.ZERO.setScale(0, RoundingMode.FLOOR).longValueExact())
    }

    private data class TestResult(val name: String, val statistic: Double, val pValue: Double, val adjustedPValue: Double, val rejected: Boolean)
    private data class BatteryReport(val sampleCount: Int, val seed: String, val correction: String, val tests: List<TestResult>, val accepted: Boolean, val digest: String)

    private fun runCorpus(): BatteryReport {
        val bits = List(sampleSize) { index -> bit(seed, index) }
        val report = battery(bits)
        return report.copy(seed = seed, digest = digest(bits))
    }

    private fun battery(bits: List<Boolean>): BatteryReport {
        val tests = listOf(
            rawTest("monobit", monobit(bits)),
            rawTest("runs", runs(bits)),
            rawTest("serial", serial(bits)),
            rawTest("entropy", entropy(bits)),
            rawTest("multiplier-goodness-of-fit", 0.0 to chiSquare(listOf(bits.count { it }, bits.count { !it }), listOf(bits.size / 2, bits.size / 2)))
        )
        val ordered = tests.withIndex().sortedBy { it.value.pValue }
        var previous = 0.0
        val adjustments = mutableMapOf<String, Double>()
        ordered.forEachIndexed { rank, indexed ->
            val adjusted = maxOf(previous, (indexed.value.pValue * tests.size * (rank + 1)).coerceAtMost(1.0))
            adjustments[indexed.value.name] = adjusted
            previous = adjusted
        }
        val corrected = tests.map { test ->
            val adjusted = adjustments.getValue(test.name)
            test.copy(adjustedPValue = adjusted, rejected = adjusted < alpha)
        }
        return BatteryReport(bits.size, seed, "holm", corrected, corrected.none { it.rejected }, digest(bits))
    }

    private fun rawTest(name: String, values: Pair<Double, Double>): TestResult = TestResult(name, values.first, values.second, values.second, values.second < alpha)

    private fun monobit(bits: List<Boolean>): Pair<Double, Double> {
        val s = abs(bits.count { it } * 2 - bits.size).toDouble() / sqrt(bits.size.toDouble())
        return s to erfcApprox(s / sqrt(2.0))
    }

    private fun runs(bits: List<Boolean>): Pair<Double, Double> {
        val transitions = bits.zipWithNext().count { it.first != it.second }
        val expected = (bits.size - 1) / 2.0
        val variance = (bits.size - 2) / 4.0
        val z = abs(transitions - expected) / sqrt(variance)
        return z to erfcApprox(z / sqrt(2.0))
    }

    private fun serial(bits: List<Boolean>): Pair<Double, Double> {
        val counts = IntArray(4)
        bits.zipWithNext().forEach { pair -> counts[(if (pair.first) 2 else 0) + if (pair.second) 1 else 0]++ }
        val expected = (bits.size - 1) / 4.0
        val statistic = counts.sumOf { (it - expected) * (it - expected) / expected }
        return statistic to exp(-statistic / 2.0)
    }

    private fun entropy(bits: List<Boolean>): Pair<Double, Double> {
        val ones = bits.count { it }.toDouble() / bits.size
        val zeros = 1.0 - ones
        val value = listOf(ones, zeros).filter { it > 0 }.sumOf { -it * (ln(it) / ln(2.0)) }
        return (1.0 - value).coerceAtLeast(0.0) to exp(-abs(1.0 - value) * bits.size / 2.0)
    }

    private fun chiSquare(observed: List<Int>, expected: List<Int>): Double {
        require(observed.size == expected.size && expected.all { it > 0 })
        val statistic = observed.zip(expected).sumOf { (actual, target) -> (actual - target).toDouble() * (actual - target) / target }
        return exp(-statistic / 2.0)
    }

    private fun bit(seed: String, index: Int): Boolean {
        val input = "$seed|$index".toByteArray(StandardCharsets.UTF_8)
        return MessageDigest.getInstance("SHA-512").digest(input)[0].toInt() and 1 == 1
    }

    private fun uniformBit(index: Int): Boolean {
        val bytes = MessageDigest.getInstance("SHA-512").digest("$seed|uniform|$index".toByteArray(StandardCharsets.UTF_8))
        return ((bytes[0].toInt() xor bytes[1].toInt()) and 1) == 1
    }

    private fun digest(bits: List<Boolean>): String = MessageDigest.getInstance("SHA-256").digest(bits.joinToString("") { if (it) "1" else "0" }.toByteArray(StandardCharsets.UTF_8)).joinToString("") { "%02x".format(it) }

    private fun erfcApprox(value: Double): Double {
        val t = 1.0 / (1.0 + 0.3275911 * value)
        val polynomial = (((((1.061405429 * t - 1.453152027) * t) + 1.421413741) * t - 0.284496736) * t + 0.254829592) * t
        return polynomial * exp(-value * value)
    }
}
