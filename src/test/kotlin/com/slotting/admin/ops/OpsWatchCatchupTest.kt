package com.slotting.admin.ops

import org.junit.jupiter.api.Test
import java.time.Clock
import java.time.Instant
import java.time.ZoneOffset
import kotlin.test.assertEquals

class OpsWatchCatchupTest {
    private val clock = Clock.fixed(Instant.parse("2026-11-11T04:00:00Z"), ZoneOffset.UTC)

    private class FakeState : OpsWatchState {
        var daily: Instant? = null
        var weekly: Instant? = null

        override fun stampDaily(cutoff: Instant): Boolean {
            val last = daily
            if (last == null || last.isBefore(cutoff)) {
                daily = Instant.now()
                return true
            }
            return false
        }

        override fun stampWeekly(cutoff: Instant): Boolean {
            val last = weekly
            if (last == null || last.isBefore(cutoff)) {
                weekly = Instant.now()
                return true
            }
            return false
        }
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
        var weeklyRuns = 0

        override fun runDailyNow() {
            dailyRuns += 1
        }

        override fun runWeeklyNow() {
            weeklyRuns += 1
        }
    }

    private fun catchup(state: FakeState, scheduler: CountingScheduler, enabled: Boolean = true) =
        OpsWatchCatchup(state, scheduler, enabled, clock)

    @Test
    fun `fresh state skips the daily catch-up`() {
        val state = FakeState().apply { daily = Instant.parse("2026-11-10T23:00:00Z") }
        val scheduler = CountingScheduler()

        catchup(state, scheduler).run()

        assertEquals(0, scheduler.dailyRuns)
    }

    @Test
    fun `stale state fires once and stamps`() {
        val state = FakeState().apply { daily = Instant.parse("2026-11-09T00:00:00Z") }
        val scheduler = CountingScheduler()

        catchup(state, scheduler).run()

        assertEquals(1, scheduler.dailyRuns)
        assert(state.daily != null)
    }

    @Test
    fun `null state fires the daily path`() {
        val state = FakeState()
        val scheduler = CountingScheduler()

        catchup(state, scheduler).run()

        assertEquals(1, scheduler.dailyRuns)
    }

    @Test
    fun `double invocation fires only once`() {
        val state = FakeState()
        val scheduler = CountingScheduler()
        val guard = catchup(state, scheduler)

        guard.run()
        guard.run()

        assertEquals(1, scheduler.dailyRuns)
    }

    @Test
    fun `weekly stale state fires the weekly path`() {
        val state = FakeState().apply {
            daily = Instant.parse("2026-11-10T23:00:00Z")
            weekly = Instant.parse("2026-10-01T00:00:00Z")
        }
        val scheduler = CountingScheduler()

        catchup(state, scheduler).run()

        assertEquals(1, scheduler.weeklyRuns)
    }

    @Test
    fun `disabled guard never fires`() {
        val state = FakeState()
        val scheduler = CountingScheduler()

        catchup(state, scheduler, enabled = false).run()

        assertEquals(0, scheduler.dailyRuns)
        assertEquals(0, scheduler.weeklyRuns)
    }
}
