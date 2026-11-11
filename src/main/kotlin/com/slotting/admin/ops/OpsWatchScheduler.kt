package com.slotting.admin.ops

import org.slf4j.LoggerFactory
import org.springframework.scheduling.annotation.Scheduled

open class OpsWatchScheduler(
    private val runner: OpsDetectorRunner,
    private val jwtProbe: () -> Int,
    private val jwksHash: () -> String?,
    private val exposureProbe: () -> Int,
    private val budgetState: () -> Boolean,
    private val retentionCounts: () -> Triple<Int, Int, Int> = { Triple(0, 0, 0) },
    private val matrixProbe: (() -> Triple<Boolean, Boolean, Int>)? = null,
) {
    private val log = LoggerFactory.getLogger(javaClass)

    open fun runDailyNow() {
        daily()
    }

    open fun runWeeklyNow() {
        weekly()
    }

    @Scheduled(cron = "\${ops.watch.daily-cron:0 15 2 * * *}", zone = "\${ops.watch.zone:Asia/Karachi}")
    fun daily() {
        val status = try {
            jwtProbe()
        } catch (error: Exception) {
            log.error("ops_watch_daily d1_probe_failed {}", error.javaClass.simpleName)
            return
        }
        val hash = runCatching { jwksHash() }.getOrNull()
        val exposure = runCatching { exposureProbe() }.getOrDefault(0)
        val budget = runCatching { budgetState() }.getOrDefault(false)
        log.info(
            "ops_watch_daily d1_status={} jwks_match={} d1_hash_present={} d2_status={} d5_budget={}",
            status,
            hash == OpsWatchBaseline.JWKS_HASH,
            hash != null,
            exposure,
            budget,
        )
        runCatching {
            val edge = runner.jwtEdge(status, hash ?: "", OpsWatchBaseline.JWKS_HASH)
            val exposureNotice = runner.exposure(exposure, expected = 401)
            val budgetNotice = runner.budgetFlip(budget, expected = false)
            log.info("ops_watch_daily_persist notices={}", listOfNotNull(edge?.cause, exposureNotice?.cause, budgetNotice?.cause))
        }.onFailure { error ->
            log.warn("ops_watch_persist_skipped phase=daily reason={}", error.javaClass.simpleName)
        }
    }

    @Scheduled(cron = "\${ops.watch.weekly-cron:0 30 3 * * MON}", zone = "\${ops.watch.zone:Asia/Karachi}")
    fun weekly() {
        val (rows, oldestDays, stranded) = runCatching { retentionCounts() }.getOrDefault(Triple(0, 0, 0))
        log.info("ops_watch_weekly d4_rows={} d4_oldest_days={} d4_stranded={} d3={}", rows, oldestDays, stranded, if (matrixProbe == null) "not_wired" else "wired")
        runCatching {
            val retention = runner.retentionHygiene(rows, oldestDays, stranded)
            val matrix = matrixProbe?.let { probe ->
                val (passed, leaked, assertions) = probe()
                runner.realtimeMatrix(passed, leaked, assertions)
            }
            val reminder = runner.announcementReminder()
            log.info(
                "ops_watch_weekly_persist d4_notice={} d3={} d6_notice={}",
                retention?.cause,
                if (matrixProbe == null) "not_wired" else (matrix?.cause ?: "quiet"),
                reminder?.cause,
            )
        }.onFailure { error ->
            log.warn("ops_watch_persist_skipped phase=weekly reason={}", error.javaClass.simpleName)
        }
    }
}
