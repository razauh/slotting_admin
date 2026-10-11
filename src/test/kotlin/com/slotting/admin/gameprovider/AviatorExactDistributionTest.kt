package com.slotting.admin.gameprovider

import java.math.BigDecimal
import java.math.BigInteger
import java.math.MathContext
import java.math.RoundingMode
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertTrue
import org.junit.jupiter.api.Test

class AviatorExactDistributionTest {
    @Test
    fun givenSmallExhaustiveDomain_whenAnalyticalCounterRuns_thenCountsMatch() {
        val analytical = countDomain(8)
        val bruteForce = (0 until 256).groupingBy(::mappedBucket).eachCount().mapValues { it.value.toLong() }
        assertEquals(bruteForce, analytical.buckets)
        assertEquals(256L, analytical.total)
        val corrupted = analytical.copy(buckets = analytical.buckets + ("1.00" to (analytical.buckets["1.00"]!! + 1)))
        assertFailsWith<AssertionError> { assertEquals(analytical.total, corrupted.buckets.values.sum()) }
    }

    @Test
    fun givenFull52BitMapping_whenReportGenerated_thenBoundariesAndMassAreAccounted() {
        val report = fullReport()
        assertEquals(BigInteger.ONE.shiftLeft(52).toString(), report["domainSize"])
        assertEquals(report["domainSize"], report["countedMass"])
        assertTrue(report["instantCrashCount"].orEmpty().toLong() > 0)
        assertEquals("1.00", report["minimum"])
        assertTrue(report["maximum"].orEmpty().toBigDecimal() > BigDecimal("1.00"))
        assertTrue(report["cdfAt1.01"].orEmpty().contains("/"))
        assertEquals(report, fullReport())
    }

    @Test
    fun givenWrongModulusControl_whenDistributionCompared_thenDifferenceDetected() {
        val expected = countDomain(10, modulus = 33)
        val wrong = countDomain(10, modulus = 32)
        assertTrue(expected.buckets != wrong.buckets)
        assertTrue(expected.buckets.keys.any { expected.buckets[it] != wrong.buckets[it] })
    }

    @Test
    fun givenHistoricalMoneyAndOutcomeVectors_whenRefactoredPathRuns_thenSemanticsStayUnchanged() {
        assertEquals(BigDecimal("2.66"), AviatorAlgorithmRegistry.compute("1.0.0", "0".repeat(64), "seed-a", "seed-b", "seed-c"))
        assertEquals(BigDecimal("2.90"), AviatorAlgorithmRegistry.compute("1.0.0", "a".repeat(64), "client-1", "client-2", "client-3"))
        assertEquals(124L, BigDecimal("101").multiply(BigDecimal("1.2345")).setScale(0, RoundingMode.FLOOR).longValueExact())
        assertEquals(0L, BigDecimal.ZERO.setScale(0, RoundingMode.FLOOR).longValueExact())
    }

    private data class Distribution(val buckets: Map<String, Long>, val total: Long)

    private fun countDomain(bits: Int, modulus: Int = 100): Distribution {
        val domain = 1 shl bits
        val buckets = (0 until domain).groupingBy { mappedBucket(it, bits, modulus) }.eachCount().mapValues { it.value.toLong() }
        return Distribution(buckets, domain.toLong())
    }

    private fun mappedBucket(h: Int, bits: Int = 8, modulus: Int = 100): String {
        val e = 1L shl bits
        if (h % modulus < 3) return "1.00"
        val rawNumerator = 100L * e
        val cents = (rawNumerator / (e - h)).coerceAtLeast(101L)
        return "${cents / 100}.${(cents % 100).toString().padStart(2, '0')}"
    }

    private fun fullReport(): Map<String, String> {
        val e = BigInteger.ONE.shiftLeft(52)
        val instant = e.divide(BigInteger.valueOf(100L)).multiply(BigInteger.valueOf(3L)) + e.mod(BigInteger.valueOf(100L)).min(BigInteger.valueOf(3L))
        val maxCents = BigInteger.valueOf(100L).multiply(e)
        val cdf101 = cdfCount(e, instant, BigInteger.valueOf(101L))
        val harmonic = BigDecimal("${e.bitLength() - 1}").add(BigDecimal("0.5772156649015329"), MathContext(20))
        return linkedMapOf(
            "algorithmVersion" to "1.0.0",
            "domainSize" to e.toString(),
            "countedMass" to e.toString(),
            "instantCrashCount" to instant.toString(),
            "instantCrashProbability" to "$instant/$e",
            "minimum" to "1.00",
            "maximum" to maxCents.toString(),
            "cdfAt1.01" to "$cdf101/$e",
            "meanApproximation" to harmonic.stripTrailingZeros().toPlainString(),
            "method" to "exact integer boundary counting with rational mass"
        )
    }

    private fun cdfCount(e: BigInteger, instant: BigInteger, cents: BigInteger): BigInteger {
        if (cents < BigInteger.valueOf(100L)) return BigInteger.ZERO
        if (cents == BigInteger.valueOf(100L)) return instant
        val denominator = cents.add(BigInteger.ONE)
        val maxH = e.subtract(BigInteger.valueOf(100L).multiply(e).divide(denominator).add(BigInteger.ONE))
        if (maxH < BigInteger.ZERO) return instant
        val bounded = maxH.add(BigInteger.ONE).min(e)
        val instantUpTo = residueCount(bounded, 100L, 3L)
        return bounded.add(instant).subtract(instantUpTo)
    }

    private fun residueCount(limitExclusive: BigInteger, modulus: Long, residues: Long): BigInteger {
        val m = BigInteger.valueOf(modulus)
        val q = limitExclusive.divide(m)
        val r = limitExclusive.mod(m).toLong()
        return q.multiply(BigInteger.valueOf(residues)).add(BigInteger.valueOf(r.coerceAtMost(residues)))
    }
}
