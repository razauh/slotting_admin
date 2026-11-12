package com.slotting.admin.ops

import org.junit.jupiter.api.Test
import java.sql.SQLException
import java.time.Clock
import java.time.Instant
import java.time.ZoneOffset
import kotlin.test.assertEquals

class OpsWatchCatchupAvailabilityTest {
    private val clock = Clock.fixed(Instant.parse("2026-11-11T05:00:00Z"), ZoneOffset.UTC)

    private class ThrowingState : OpsWatchState {
        override fun stampDaily(cutoff: Instant): Boolean = throw SQLException("relation \"public.ops_watch_state\" does not exist")
        override fun stampWeekly(cutoff: Instant): Boolean = throw SQLException("relation \"public.ops_watch_state\" does not exist")
    }

    private class CountingScheduler : OpsWatchScheduler(
        runner = OpsDetectorRunner(OpsWatchService(InMemoryOpsNoticeRepository())),
        jwtProbe = { 200 },
        jwksHash = { OpsWatchBaseline.JWKS_HASH },
        exposureProbe = { 401 },
        budgetState = { false },
        retentionCounts = { Triple(0, 0, 0) },
        matrixProbe = null,
    ) {
        var dailyRuns = 0

        override fun runDailyNow() {
            dailyRuns += 1
        }

        override fun runWeeklyNow() {
        }
    }

    @Test
    fun `missing state table skips catch-up without throwing`() {
        val scheduler = CountingScheduler()
        val catchup = OpsWatchCatchup(ThrowingState(), scheduler, enabled = true, clock = clock)

        catchup.run()

        assertEquals(0, scheduler.dailyRuns)
    }
}
