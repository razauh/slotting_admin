package com.slotting.admin.ops

import org.springframework.context.ApplicationListener
import org.springframework.boot.context.event.ApplicationReadyEvent
import org.slf4j.LoggerFactory
import java.time.Clock
import java.time.Instant
import java.time.temporal.ChronoUnit
import java.sql.Timestamp

interface OpsWatchState {
    fun stampDaily(cutoff: Instant): Boolean

    fun stampWeekly(cutoff: Instant): Boolean
}

class JdbcOpsWatchState(
    private val openConnection: () -> java.sql.Connection,
) : OpsWatchState {
    override fun stampDaily(cutoff: Instant): Boolean = stamp("last_daily_run_utc", cutoff)

    override fun stampWeekly(cutoff: Instant): Boolean = stamp("last_weekly_run_utc", cutoff)

    private fun stamp(column: String, cutoff: Instant): Boolean =
        openConnection().use { connection ->
            connection.prepareStatement(
                "update public.ops_watch_state set $column = now(), updated_utc = now() where id = 1 and ($column is null or $column < ?)",
            ).use { statement ->
                statement.setTimestamp(1, Timestamp.from(cutoff))
                statement.executeUpdate() == 1
            }
        }
}

class OpsWatchCatchup(
    private val state: OpsWatchState,
    private val scheduler: OpsWatchScheduler,
    private val enabled: Boolean = true,
    private val clock: Clock = Clock.systemUTC(),
) : ApplicationListener<ApplicationReadyEvent> {
    private val log = LoggerFactory.getLogger(javaClass)

    override fun onApplicationEvent(event: ApplicationReadyEvent) {
        run()
    }

    fun run() {
        if (!enabled) {
            return
        }
        val now = clock.instant()
        if (state.stampDaily(now.minus(26, ChronoUnit.HOURS))) {
            log.info("ops_watch_catchup phase=daily action=fire")
            runCatching { scheduler.runDailyNow() }
                .onFailure { log.warn("ops_watch_catchup phase=daily failed={}", it.javaClass.simpleName) }
        }
        if (state.stampWeekly(now.minus(8, ChronoUnit.DAYS))) {
            log.info("ops_watch_catchup phase=weekly action=fire")
            runCatching { scheduler.runWeeklyNow() }
                .onFailure { log.warn("ops_watch_catchup phase=weekly failed={}", it.javaClass.simpleName) }
        }
    }
}
