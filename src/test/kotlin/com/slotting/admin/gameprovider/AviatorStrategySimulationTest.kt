package com.slotting.admin.gameprovider

import com.fasterxml.jackson.databind.ObjectMapper
import java.io.File
import java.math.BigDecimal
import java.math.RoundingMode
import kotlin.test.assertEquals
import kotlin.test.assertTrue
import org.junit.jupiter.api.Test

class AviatorStrategySimulationTest {
    @Test
    fun GivenSyntheticKnownReturn_WhenMeanCalculated_ThenExactMeanIsRecoveredAndBiasDetected() {
        val payouts = listOf(0L, 100L, 100L, 200L)
        val mean = payouts.average()
        assertEquals(100.0, mean)
        assertTrue(payouts.map { it + if (it > 0L) 1L else 0L }.average() != mean)
    }

    @Test
    fun GivenProductionOutcomeAndPayoutVectors_WhenAdapterRuns_ThenHistoricalValuesMatch() {
        assertEquals(
            BigDecimal("2.66"),
            AviatorAlgorithmRegistry.compute("1.0.0", "0".repeat(64), "seed-a", "seed-b", "seed-c"),
        )
        assertEquals(
            BigDecimal("2.90"),
            AviatorAlgorithmRegistry.compute("1.0.0", "a".repeat(64), "client-1", "client-2", "client-3"),
        )
        assertEquals(124L, BigDecimal("101").multiply(BigDecimal("1.2345")).setScale(0, RoundingMode.FLOOR).longValueExact())
    }

    @Test
    fun GivenFixedSeed_WhenOfflineCliRunsTwice_ThenReportsHaveMatchingStrategiesAndProvenance() {
        val first = runSimulation("first")
        val second = runSimulation("second")
        assertEquals(first.path("reportDigest").asText(), second.path("reportDigest").asText())
        assertEquals(12, first.path("strategies").size())
        assertTrue(first.path("strategies").all { it.path("sampleCount").asInt() == 1000 })
        assertEquals("tc032-test", first.path("provenance").path("commitHash").asText())
        assertEquals("1.0.0", first.path("provenance").path("algorithmVersion").asText())
        assertTrue(first.path("provenance").path("configurationFingerprint").asText().isNotBlank())
    }

    private fun runSimulation(label: String) = run {
        val root = File(".").absoluteFile
        val output = File(root, "build/tc032/$label-report.json")
        val processLog = File(root, ".logs/tc032-kotlin-cli-$label.log")
        output.parentFile.mkdirs()
        processLog.parentFile.mkdirs()
        val process = ProcessBuilder(
            "python3",
            "tools/fairness/strategy_simulation.py",
            "--samples", "1000",
            "--batch-size", "100",
            "--bootstrap-resamples", "50",
            "--master-seed", "20261011",
            "--commit-hash", "tc032-test",
            "--manifest", output.path,
            "--markdown", File(root, "build/tc032/$label-report.md").path,
        ).directory(root)
            .redirectErrorStream(true)
            .redirectOutput(processLog)
            .start()
        assertEquals(0, process.waitFor(), processLog.readText())
        ObjectMapper().readTree(output)
    }
}
