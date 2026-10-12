package com.slotting.admin.fairness

import com.slotting.admin.gameprovider.IndependentFairnessVerifier
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertTrue
import org.junit.jupiter.api.Test

class FairnessPropertyHarnessContractTest {
    @Test
    fun goldenVectorsMatchExactlyForFixedSeeds() {
        val vectors = FairnessPropertyHarness.goldenVectors()
        assertTrue(vectors.isNotEmpty())
        vectors.forEach { vector ->
            assertEquals(
                vector.expectedMultiplier,
                IndependentFairnessVerifier.calculateCrashMultiplier(
                    vector.serverSeed,
                    vector.clientSeed1,
                    vector.clientSeed2,
                    vector.clientSeed3,
                ),
            )
        }
    }

    @Test
    fun instantCrashRateFallsInsideDocumentedBounds() {
        val report = FairnessPropertyHarness.sampleDistribution()
        assertEquals(FairnessPropertyHarness.DISTRIBUTION_SAMPLE_SIZE, report.sampleSize)
        assertTrue(report.instantCrashRate in FairnessPropertyHarness.MIN_INSTANT_CRASH_RATE..FairnessPropertyHarness.MAX_INSTANT_CRASH_RATE)
    }

    @Test
    fun houseEdgeBoundHoldsOverSeededSample() {
        val first = FairnessPropertyHarness.sampleDistribution()
        val second = FairnessPropertyHarness.sampleDistribution()
        assertEquals(first, second)
        assertTrue(first.twoXHouseEdge in FairnessPropertyHarness.MIN_TWO_X_HOUSE_EDGE..FairnessPropertyHarness.MAX_TWO_X_HOUSE_EDGE)
    }

    @Test
    fun fairnessVerifyHelperRecomputesOutcome() {
        val vector = FairnessPropertyHarness.goldenVectors().first()
        val commitment = IndependentFairnessVerifier.sha256(vector.serverSeed)
        assertTrue(
            FairnessPropertyHarness.verify(
                vector.serverSeed,
                vector.clientSeed1,
                vector.clientSeed2,
                vector.clientSeed3,
                commitment,
                vector.expectedMultiplier,
            ),
        )
        assertFalse(
            FairnessPropertyHarness.verify(
                "${vector.serverSeed}tampered",
                vector.clientSeed1,
                vector.clientSeed2,
                vector.clientSeed3,
                commitment,
                vector.expectedMultiplier,
            ),
        )
        assertFailsWith<IllegalArgumentException> { FairnessPropertyHarness.sampleDistribution(0) }
        assertFailsWith<IllegalArgumentException> { FairnessPropertyHarness.sampleDistribution(1) }
    }
}
