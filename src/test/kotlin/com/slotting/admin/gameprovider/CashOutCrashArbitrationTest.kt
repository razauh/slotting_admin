package com.slotting.admin.gameprovider

import org.junit.jupiter.api.Test
import java.math.BigDecimal
import java.time.Duration
import java.time.Instant
import kotlin.test.assertFalse
import kotlin.test.assertTrue

class CashOutCrashArbitrationTest {
    private val crashTime = Instant.parse("2026-10-15T12:00:00Z")

    @Test
    fun receiveBeforeCrashIsHonoredAfterTheRoundCrashes() {
        assertFalse(
            DurableGameWagerAndSettlementService.cashoutCrashRejected(
                crashTime.minusMillis(1),
                round(GameRoundPhase.CRASHED, crashTime),
                Duration.ZERO,
            ),
        )
    }

    @Test
    fun receiveAtCrashBoundaryIsRejectedWhenGraceIsZero() {
        assertTrue(
            DurableGameWagerAndSettlementService.cashoutCrashRejected(
                crashTime,
                round(GameRoundPhase.CRASHED, crashTime),
                Duration.ZERO,
            ),
        )
    }

    @Test
    fun receiveAtGraceBoundaryIsRejectedDeterministically() {
        val grace = Duration.ofMillis(250)
        assertFalse(
            DurableGameWagerAndSettlementService.cashoutCrashRejected(
                crashTime.plusMillis(249),
                round(GameRoundPhase.CRASHED, crashTime),
                grace,
            ),
        )
        assertTrue(
            DurableGameWagerAndSettlementService.cashoutCrashRejected(
                crashTime.plus(grace),
                round(GameRoundPhase.CRASHED, crashTime),
                grace,
            ),
        )
    }

    @Test
    fun crashedRoundWithoutCrashTimeFailsClosed() {
        assertTrue(
            DurableGameWagerAndSettlementService.cashoutCrashRejected(
                crashTime.minusSeconds(1),
                round(GameRoundPhase.CRASHED, null),
                Duration.ZERO,
            ),
        )
    }

    private fun round(phase: GameRoundPhase, crashedAt: Instant?) = GameRoundRecord(
        tenantId = "tenant",
        gameId = "AVIATOR",
        roundId = "round",
        phase = phase,
        roundVersion = 2,
        currentMultiplier = BigDecimal("2.00"),
        crashMultiplier = crashedAt?.let { BigDecimal("2.00") },
        startedAt = crashTime.minusSeconds(10),
        crashedAt = crashedAt,
        closedAt = null,
        flyingAt = crashTime.minusSeconds(5),
        phaseStartedAt = crashTime.minusSeconds(5),
        phaseDeadlineAt = null,
        lifecycleConfigFingerprint = null,
        scheduledMillis = null,
        bettingMillis = null,
        closedMillis = null,
        tickMillis = null,
        multiplierStep = null,
        rulesVersion = "1.0.0",
        algorithmVersion = "1.0.0",
        publicSalt = "salt",
        serverTime = crashTime,
        createdAt = crashTime.minusSeconds(10),
        updatedAt = crashTime,
    )
}
