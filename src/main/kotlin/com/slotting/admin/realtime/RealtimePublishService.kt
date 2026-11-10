package com.slotting.admin.realtime

import java.time.Clock

data class RealtimeHint(
    val channel: String,
    val event: String,
    val payload: Map<String, Any>,
    val eventId: String,
    val sequence: Long,
)

enum class PublishDecision {
    PUBLISHED,
    DROPPED_NOT_COMMITTED,
    DROPPED_DUPLICATE,
    DROPPED_RATE_LIMITED,
}

interface RealtimeHintTransport {
    fun send(channel: String, hints: List<RealtimeHint>)
}

class RealtimePublishService(
    private val transport: RealtimeHintTransport,
    private val maxPerSecondPerChannel: Int = 10,
    private val clock: Clock = Clock.systemUTC(),
    private val maxRememberedEventIds: Int = 10000,
) {
    private val seenEventIds = LinkedHashSet<String>()
    private val channelWindows = mutableMapOf<String, Window>()

    private data class Window(val epochSecond: Long, var count: Int)

    fun publish(committed: Boolean, hint: RealtimeHint): PublishDecision =
        publishBatch(committed, listOf(hint)).single()

    fun publishBatch(committed: Boolean, hints: List<RealtimeHint>): List<PublishDecision> {
        if (!committed) {
            return hints.map { PublishDecision.DROPPED_NOT_COMMITTED }
        }
        val decisions = ArrayList<PublishDecision>(hints.size)
        val accepted = LinkedHashMap<String, MutableList<RealtimeHint>>()
        for (hint in hints) {
            if (!remember(hint.eventId)) {
                decisions.add(PublishDecision.DROPPED_DUPLICATE)
                continue
            }
            val window = windowFor(hint.channel)
            if (window.count >= maxPerSecondPerChannel) {
                decisions.add(PublishDecision.DROPPED_RATE_LIMITED)
                continue
            }
            window.count++
            accepted.getOrPut(hint.channel) { mutableListOf() }.add(hint)
            decisions.add(PublishDecision.PUBLISHED)
        }
        accepted.forEach { (channel, batch) -> transport.send(channel, batch) }
        return decisions
    }

    private fun remember(eventId: String): Boolean {
        if (!seenEventIds.add(eventId)) {
            return false
        }
        if (seenEventIds.size > maxRememberedEventIds) {
            val oldest = seenEventIds.first()
            seenEventIds.remove(oldest)
        }
        return true
    }

    private fun windowFor(channel: String): Window {
        val second = clock.instant().epochSecond
        val current = channelWindows[channel]
        if (current == null || current.epochSecond != second) {
            val fresh = Window(second, 0)
            channelWindows[channel] = fresh
            return fresh
        }
        return current
    }
}
