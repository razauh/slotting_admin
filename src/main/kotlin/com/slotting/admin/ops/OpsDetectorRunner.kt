package com.slotting.admin.ops

import java.time.Clock

object OpsWatchCadences {
    const val DAILY = "0 15 2 * * *"
    const val WEEKLY = "0 30 3 * * MON"
    const val TIMEZONE = "Asia/Karachi"
}

class OpsDetectorRunner(
    private val watch: OpsWatchService,
    private val clock: Clock = Clock.systemUTC(),
) {
    fun jwtEdge(status: Int, jwksHash: String, baselineHash: String): OpsNotice? =
        watch.jwtEdge(status, jwksHash, baselineHash)

    fun exposure(status: Int, expected: Int = 200): OpsNotice? = watch.exposure(status, expected)

    fun budgetFlip(current: Boolean, expected: Boolean): OpsNotice? = watch.budgetFlip(current, expected)

    fun realtimeMatrix(passed: Boolean, leaked: Boolean, assertions: Int): OpsNotice? {
        if (passed && !leaked) {
            return null
        }
        return watch.raise(
            "REALTIME_CHANNEL",
            "REALTIME_CHANNEL",
            OpsSeverity.WARNING,
            "realtime matrix deviated passed=$passed leaked=$leaked assertions=$assertions",
        )
    }

    fun retentionHygiene(rows: Int, oldestDays: Int, strandedRevocations: Int): OpsNotice? {
        var raised: OpsNotice? = null
        if (rows > 10_000 || oldestDays > 30) {
            raised = watch.raise(
                "RETENTION_GROWTH",
                "RETENTION_GROWTH",
                OpsSeverity.WARNING,
                "retention rows=$rows oldestDays=$oldestDays",
            )
        }
        if (strandedRevocations > 500) {
            raised = watch.raise(
                "RETENTION_STRANDED",
                "RETENTION_GROWTH",
                OpsSeverity.WARNING,
                "stranded revocations=$strandedRevocations",
            ) ?: raised
        }
        return raised
    }

    fun announcementReminder(): OpsNotice? = watch.raise(
        "ANNOUNCEMENT_REMINDER",
        "ANNOUNCEMENT",
        OpsSeverity.INFO,
        "weekly manual check of platform announcements",
    )
}
