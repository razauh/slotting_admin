package com.slotting.admin.gameprovider

import java.time.Clock
import java.time.Duration
import java.time.Instant

object FlightClock {
    fun computeElapsedFlightSeconds(round: GameRoundRecord, clock: Clock): Double {
        val now = clock.instant()
        return when (round.phase) {
            GameRoundPhase.FLYING -> {
                val origin = round.flyingAt ?: round.updatedAt
                Duration.between(origin, now).toMillis().coerceAtLeast(0L) / 1000.0
            }
            else -> 0.0
        }
    }

    fun isPhaseDeadlinePassed(round: GameRoundRecord, clock: Clock): Boolean {
        return round.phaseDeadlineAt?.let { deadline ->
            !clock.instant().isBefore(deadline)
        } ?: false
    }

    fun calculateCurveMultiplier(elapsedSeconds: Double): java.math.BigDecimal {
        val clampedSeconds = elapsedSeconds.coerceAtLeast(0.0)
        val calculated = Math.floor(Math.exp(0.06 * clampedSeconds) * 10000.0) / 10000.0
        return java.math.BigDecimal.valueOf(calculated).setScale(4, java.math.RoundingMode.DOWN)
    }

    fun resolveAuthoritativeMultiplier(
        round: GameRoundRecord,
        rulesVersion: String,
        clock: Clock,
    ): java.math.BigDecimal {
        return when (rulesVersion) {
            "2.0.0" -> {
                val elapsed = computeElapsedFlightSeconds(round, clock)
                val curve = calculateCurveMultiplier(elapsed)
                round.crashMultiplier?.let { curve.min(it) } ?: curve
            }
            "1.0.0" -> round.currentMultiplier
            else -> throw UnsupportedRulesVersionException(rulesVersion)
        }
    }
}
