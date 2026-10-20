package com.slotting.admin.fairness

import com.slotting.admin.gameprovider.AviatorAlgorithmRegistry
import com.slotting.admin.gameprovider.IndependentFairnessVerifier
import java.math.BigDecimal
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith

class CrashFormulaGoldenVectorTest {
    @Test
    fun goldenVectorsMatchIntegerReferenceAndProductionToTheCent() {
        val vectors = FairnessPropertyHarness.goldenVectors()
        assertEquals(3, vectors.size)
        vectors.forEach { vector ->
            val reference = IntegerCrashFormulaReference.calculate(
                vector.serverSeed,
                vector.clientSeed1,
                vector.clientSeed2,
                vector.clientSeed3,
            )
            val production = AviatorAlgorithmRegistry.compute(
                AviatorAlgorithmRegistry.VERSION_1_0_0,
                vector.serverSeed,
                vector.clientSeed1,
                vector.clientSeed2,
                vector.clientSeed3,
            )
            assertEquals(vector.expectedMultiplier, reference)
            assertEquals(vector.expectedMultiplier, production)
        }
    }

    @Test
    fun instantCrashAndFloorBoundariesMatchIntegerReference() {
        assertEquals(BigDecimal("1.00"), IntegerCrashFormulaReference.calculateFromDraw(0L))
        assertEquals(BigDecimal("1.00"), IntegerCrashFormulaReference.calculateFromDraw(2L))
        assertEquals(BigDecimal("1.01"), IntegerCrashFormulaReference.calculateFromDraw(3L))
        assertEquals(BigDecimal("1.01"), IntegerCrashFormulaReference.calculateFromDraw(45_035_996_273_704L))
    }

    @Test
    fun maximumDrawUsesLongIntegerArithmeticWithoutOverflow() {
        assertEquals(BigDecimal("4503599627370496.00"), IntegerCrashFormulaReference.calculateFromDraw((1L shl 52) - 1L))
    }

    @Test
    fun emptySeedsAreRejectedBeforeHashing() {
        assertFailsWith<IllegalArgumentException> {
            IntegerCrashFormulaReference.calculate("", "one", "two", "three")
        }
    }

    @Test
    fun unknownAlgorithmVersionRemainsRejected() {
        assertFailsWith<RuntimeException> {
            AviatorAlgorithmRegistry.compute("99.0.0", "server", "one", "two", "three")
        }
    }

    @Test
    fun productionFormulaRemainsPinnedToExistingVectors() {
        val vectors = FairnessPropertyHarness.goldenVectors()
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
}
