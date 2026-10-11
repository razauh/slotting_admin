package com.slotting.admin.gameprovider

import java.math.BigDecimal
import java.math.RoundingMode
import java.nio.charset.StandardCharsets
import java.security.MessageDigest
import kotlin.test.assertEquals
import kotlin.test.assertNotEquals
import kotlin.test.assertTrue
import org.junit.jupiter.api.Test

class AviatorDifferentialMutationTest {
    private data class Input(val server: String, val client1: String, val client2: String, val client3: String)
    private enum class Mutation { ROUNDING, MODULUS, PREFIX, ENCODING, FLOOR_STAGE }

    @Test
    fun givenFiveDefinedFormulaMutants_whenDifferentialRuns_thenEveryMutantKilled() {
        val vectors = listOf(
            Input("0".repeat(64), "seed-a", "seed-b", "seed-c"),
            Input("a".repeat(64), "client-1", "client-2", "client-3"),
            Input("0123456789abcdef".repeat(4), "cs1", "cs2", "cs3"),
            Input("unicode-🙂", "клиент-1", "クライアント-2", "client-3"),
        ) + (0 until 10_000).map(::input)
        val killed = Mutation.entries.map { mutation ->
            vectors.any { input -> oracle(input) != oracle(input, mutation) }
        }
        assertTrue(killed.all { it }, "mutation kill results=$killed")
        assertEquals(100, killed.count { it } * 100 / Mutation.entries.size)
    }

    @Test
    fun givenMillionRecordedInputs_whenCompared_thenZeroUnexplainedMismatchesAndStableDigest() {
        val first = corpusDigest(1_000_000, true)
        val second = corpusDigest(1_000_000, true)
        assertEquals(first, second)
    }

    @Test
    fun givenMappedValues_whenPropertiesChecked_thenVersion100InvariantsHold() {
        val samples = (0 until 10_000).map(::input)
        samples.forEach { value ->
            val expected = oracle(value)
            val actual = AviatorAlgorithmRegistry.compute("1.0.0", value.server, value.client1, value.client2, value.client3)
            assertEquals(expected, actual)
            assertTrue(actual >= BigDecimal("1.00"))
            assertEquals(2, actual.scale())
            assertEquals(actual, AviatorAlgorithmRegistry.compute("1.0.0", value.server, value.client1, value.client2, value.client3))
        }
        val hashes = samples.map { value -> sha512(value.server + value.client1 + value.client2 + value.client3) }
        assertTrue(hashes.all { it.length == 128 && it.all { character -> character.isLowerCaseOrDigit() } })
        assertTrue(samples.map { oracle(it) }.zipWithNext().any { (left, right) -> left != right })
        assertTrue((0 until 100).any { index -> oracle(input(index)) == BigDecimal("1.00") })
    }

    @Test
    fun givenHistoricalMoneyAndOutcomeVectors_whenRefactoredPathRuns_thenSemanticsStayUnchanged() {
        assertEquals(BigDecimal("2.66"), AviatorAlgorithmRegistry.compute("1.0.0", "0".repeat(64), "seed-a", "seed-b", "seed-c"))
        assertEquals(BigDecimal("2.90"), AviatorAlgorithmRegistry.compute("1.0.0", "a".repeat(64), "client-1", "client-2", "client-3"))
        assertEquals(BigDecimal("1.86"), AviatorAlgorithmRegistry.compute("1.0.0", "0123456789abcdef".repeat(4), "cs1", "cs2", "cs3"))
        assertEquals(124L, BigDecimal("101").multiply(BigDecimal("1.2345")).setScale(0, RoundingMode.FLOOR).longValueExact())
        assertEquals(0L, BigDecimal.ZERO.setScale(0, RoundingMode.FLOOR).longValueExact())
    }

    private fun corpusDigest(count: Int, compareOracle: Boolean): String {
        val digest = MessageDigest.getInstance("SHA-256")
        repeat(count) { index ->
            val value = input(index)
            val result = AviatorAlgorithmRegistry.compute("1.0.0", value.server, value.client1, value.client2, value.client3)
            if (compareOracle) {
                val expected = oracle(value)
                assertEquals(expected, result, "mismatch at index=$index input=$value")
            }
            digest.update("$index|${value.server}|${value.client1}|${value.client2}|${value.client3}|$result\n".toByteArray(StandardCharsets.UTF_8))
        }
        return digest.digest().joinToString("") { "%02x".format(it) }
    }

    private fun input(index: Int): Input = Input(
        server = if (index % 97 == 0) "种子-$index-π-🙂" else "server-seed-$index",
        client1 = if (index % 89 == 0) "клиент-1-$index" else "client-seed-1-$index",
        client2 = if (index % 83 == 0) "クライアント-2-$index" else "client-seed-2-$index",
        client3 = if (index % 79 == 0) "client-seed-3-🙂-$index" else "client-seed-3-$index",
    )

    private fun oracle(input: Input, mutation: Mutation? = null): BigDecimal {
        val combined = input.server + input.client1 + input.client2 + input.client3
        val bytes = if (mutation == Mutation.ENCODING) combined.toByteArray(Charsets.UTF_16) else combined.toByteArray(StandardCharsets.UTF_8)
        val hash = MessageDigest.getInstance("SHA-512").digest(bytes).joinToString("") { "%02x".format(it) }
        val prefixLength = if (mutation == Mutation.PREFIX) 12 else 13
        val h = hash.substring(0, prefixLength).toLong(16)
        val modulus = if (mutation == Mutation.MODULUS) 99L else 100L
        val instant = h % modulus < 3L
        if (instant) return BigDecimal("1.00")
        val e = 4503599627370496.0
        val raw = e / (e - h.toDouble())
        val rounded = if (mutation == Mutation.ROUNDING) kotlin.math.round(raw * 100.0) / 100.0 else kotlin.math.floor(raw * 100.0) / 100.0
        val bounded = maxOf(1.01, rounded)
        return if (mutation == Mutation.FLOOR_STAGE) BigDecimal.valueOf(raw).setScale(2, RoundingMode.FLOOR) else BigDecimal.valueOf(bounded).setScale(2, RoundingMode.FLOOR)
    }

    private fun sha512(value: String): String = MessageDigest.getInstance("SHA-512").digest(value.toByteArray(StandardCharsets.UTF_8)).joinToString("") { "%02x".format(it) }

    private fun Char.isLowerCaseOrDigit(): Boolean = isDigit() || this in 'a'..'f'
}
