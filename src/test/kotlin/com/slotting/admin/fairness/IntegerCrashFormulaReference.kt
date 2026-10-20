package com.slotting.admin.fairness

import java.math.BigDecimal
import java.nio.charset.StandardCharsets
import java.security.MessageDigest

internal object IntegerCrashFormulaReference {
    private const val DRAW_RANGE = 1L shl 52

    fun calculate(serverSeed: String, clientSeed1: String, clientSeed2: String, clientSeed3: String): BigDecimal {
        require(serverSeed.isNotEmpty())
        require(clientSeed1.isNotEmpty())
        require(clientSeed2.isNotEmpty())
        require(clientSeed3.isNotEmpty())
        val combined = serverSeed + clientSeed1 + clientSeed2 + clientSeed3
        val digest = MessageDigest.getInstance("SHA-512")
            .digest(combined.toByteArray(StandardCharsets.UTF_8))
        val hexPrefix = digest.take(7).joinToString("") { "%02x".format(it) }.substring(0, 13)
        return calculateFromDraw(hexPrefix.toLong(16))
    }

    fun calculateFromDraw(draw: Long): BigDecimal {
        require(draw in 0 until DRAW_RANGE)
        if (draw % 100L < 3L) return BigDecimal("1.00")
        val cents = maxOf(101L, DRAW_RANGE * 100L / (DRAW_RANGE - draw))
        return BigDecimal.valueOf(cents, 2)
    }
}
