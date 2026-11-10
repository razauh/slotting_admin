package com.slotting.admin.realtime

import java.time.Clock

class RealtimeBudgetGuard(
    private val maxPerPlayerPerSecond: Int = 20,
    private val alert: (String) -> Unit = {},
    private val clock: Clock = Clock.systemUTC(),
) {
    private val windows = mutableMapOf<String, Window>()
    private val alertedWindows = mutableSetOf<String>()
    private var killSwitch = false

    private data class Window(val epochSecond: Long, var count: Int)

    fun setKillSwitch(enabled: Boolean) {
        killSwitch = enabled
    }

    fun allowsPublish(playerId: String): Boolean {
        if (killSwitch) {
            return false
        }
        val window = windowFor(playerId)
        if (window.count >= maxPerPlayerPerSecond) {
            if (alertedWindows.add(playerId + ":" + window.epochSecond)) {
                alert("realtime budget breach player=$playerId second=${window.epochSecond}")
            }
            return false
        }
        window.count++
        return true
    }

    private fun windowFor(playerId: String): Window {
        val second = clock.instant().epochSecond
        val current = windows[playerId]
        if (current == null || current.epochSecond != second) {
            val fresh = Window(second, 0)
            windows[playerId] = fresh
            return fresh
        }
        return current
    }
}
