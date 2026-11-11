package com.slotting.admin.realtime

data class RoundPhaseEvent(
    val tenantId: String,
    val gameId: String,
    val roundId: String,
    val phase: String,
    val phaseVersion: Long,
    val phaseDeadlineHint: Long? = null,
)

class RoundHintPublisher(
    private val publishService: RealtimePublishService,
    private val enabled: Boolean,
    private val budgetGuard: RealtimeBudgetGuard? = null,
    private val maxMessagesPerPost: Int = 500,
) {
    fun publish(
        tenantId: String,
        playerId: String,
        roundId: String,
        phase: String,
        phaseVersion: Long,
        phaseDeadlineHint: Long? = null,
    ): PublishDecision? {
        if (!enabled) {
            return null
        }
        if (budgetGuard != null && !budgetGuard.allowsPublish(playerId)) {
            return PublishDecision.DROPPED_RATE_LIMITED
        }
        val channel = "tenant:$tenantId:player:$playerId"
        val hint = RealtimeHint(
            channel = channel,
            event = "phase",
            payload = mapOf(
                "roundId" to roundId,
                "phase" to phase,
                "phaseVersion" to phaseVersion,
                "phaseDeadlineHint" to (phaseDeadlineHint ?: 0L),
            ),
            eventId = "$roundId:$phase:$phaseVersion",
            sequence = phaseVersion,
        )
        return publishService.publish(committed = true, hint = hint)
    }

    fun publishRoundEvent(committed: Boolean, event: RoundPhaseEvent, players: List<String>): Int {
        if (!committed || !enabled) {
            return 0
        }
        val distinct = players.distinct()
        if (distinct.isEmpty()) {
            return 0
        }
        var published = 0
        distinct.chunked(maxMessagesPerPost).forEach { chunk ->
            val hints = chunk
                .filter { player -> budgetGuard?.allowsPublish(player) ?: true }
                .map { player ->
                    RealtimeHint(
                        channel = "tenant:${event.tenantId}:player:$player",
                        event = "phase",
                        payload = buildMap {
                            put("roundId", event.roundId)
                            put("phase", event.phase)
                            put("phaseVersion", event.phaseVersion)
                            event.phaseDeadlineHint?.let { put("phaseDeadlineHint", it) }
                        },
                        eventId = "${event.roundId}:${event.phase}:${event.phaseVersion}:$player",
                        sequence = event.phaseVersion,
                    )
                }
            if (hints.isNotEmpty()) {
                publishService.publishBatch(committed = true, hints = hints)
                published += hints.size
            }
        }
        return published
    }
}
