package com.slotting.admin.fairness

import com.slotting.admin.gameprovider.AviatorAlgorithmRegistry
import com.slotting.admin.gameprovider.IndependentFairnessVerifier
import java.math.BigDecimal

data class FairnessVector(
    val serverSeed: String,
    val clientSeed1: String,
    val clientSeed2: String,
    val clientSeed3: String,
    val expectedMultiplier: BigDecimal,
)

data class DistributionReport(
    val sampleSize: Int,
    val instantCrashCount: Int,
    val instantCrashRate: Double,
    val twoXWinCount: Int,
    val twoXHouseEdge: Double,
)

object FairnessPropertyHarness {
    const val DISTRIBUTION_SAMPLE_SIZE = 10_000
    const val MIN_INSTANT_CRASH_RATE = 0.015
    const val MAX_INSTANT_CRASH_RATE = 0.045
    const val MIN_TWO_X_HOUSE_EDGE = 0.0
    const val MAX_TWO_X_HOUSE_EDGE = 0.06
    private const val TWO_X_CASHOUT = 2.0

    fun goldenVectors(): List<FairnessVector> =
        requireNotNull(javaClass.getResourceAsStream("/fairness/golden-vectors.csv"))
            .bufferedReader()
            .useLines { lines ->
                lines.filter(String::isNotBlank).map { line ->
                    val fields = line.split(',')
                    require(fields.size == 5)
                    FairnessVector(
                        serverSeed = fields[0],
                        clientSeed1 = fields[1],
                        clientSeed2 = fields[2],
                        clientSeed3 = fields[3],
                        expectedMultiplier = fields[4].toBigDecimal(),
                    )
                }.toList()
            }

    fun sampleDistribution(sampleSize: Int = DISTRIBUTION_SAMPLE_SIZE): DistributionReport {
        require(sampleSize > 1) { "At least two deterministic seeds are required" }
        var instantCrashCount = 0
        var twoXWinCount = 0
        repeat(sampleSize) { index ->
            val outcome = outcomeFor(index)
            if (outcome.compareTo(BigDecimal("1.00")) == 0) instantCrashCount++
            if (outcome >= BigDecimal("2.00")) twoXWinCount++
        }
        val instantRate = instantCrashCount.toDouble() / sampleSize
        val edge = 1.0 - TWO_X_CASHOUT * twoXWinCount.toDouble() / sampleSize
        return DistributionReport(sampleSize, instantCrashCount, instantRate, twoXWinCount, edge)
    }

    fun verify(
        serverSeed: String,
        clientSeed1: String,
        clientSeed2: String,
        clientSeed3: String,
        commitment: String,
        expectedMultiplier: BigDecimal,
    ): Boolean {
        if (IndependentFairnessVerifier.sha256(serverSeed) != commitment) return false
        val computed = AviatorAlgorithmRegistry.compute(
            AviatorAlgorithmRegistry.VERSION_1_0_0,
            serverSeed,
            clientSeed1,
            clientSeed2,
            clientSeed3,
        )
        return computed.compareTo(expectedMultiplier) == 0
    }

    private fun outcomeFor(index: Int): BigDecimal = AviatorAlgorithmRegistry.compute(
        AviatorAlgorithmRegistry.VERSION_1_0_0,
        "tc05-server-seed-$index",
        "tc05-client-seed-1-$index",
        "tc05-client-seed-2-$index",
        "tc05-client-seed-3-$index",
    )
}
