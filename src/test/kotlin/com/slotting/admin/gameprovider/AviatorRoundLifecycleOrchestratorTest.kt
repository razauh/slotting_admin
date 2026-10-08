package com.slotting.admin.gameprovider

import org.assertj.core.api.Assertions.assertThat
import org.junit.jupiter.api.Test
import java.math.BigDecimal
import java.time.Clock
import java.time.Instant
import java.time.ZoneId

class AviatorRoundLifecycleOrchestratorTest {
    private val properties = AviatorLifecycleProperties(
        scheduledMillis = 1_000,
        bettingMillis = 2_000,
        closedMillis = 1_000,
        multiplierStep = BigDecimal("0.0500"),
        rulesVersion = "1.0.0",
        algorithmVersion = "1.0.0",
        publicSalt = "test-public-salt",
        configuredTenants = emptySet(),
    )

    @Test
    fun `round progresses commitment before betting then flying crash reveal close and next round`() {
        val clock = MutableClock(Instant.parse("2026-01-01T00:00:00Z"))
        val port = FakeLifecyclePort(clock)
        val orchestrator = AviatorRoundLifecycleOrchestrator(port, properties, clock)

        val scheduled = orchestrator.ensureRunning("tenant-a")
        assertThat(port.operations.take(3)).containsExactly("persist:SCHEDULED", "commitment", "event:SCHEDULED")
        assertThat(scheduled.phase).isEqualTo(GameRoundPhase.SCHEDULED)

        clock.advanceMillis(1_000)
        assertThat(orchestrator.tick("tenant-a").phase).isEqualTo(GameRoundPhase.BET_COUNTDOWN)
        clock.advanceMillis(2_000)
        val flying = orchestrator.tick("tenant-a")
        assertThat(flying.phase).isEqualTo(GameRoundPhase.FLYING)
        assertThat(flying.crashMultiplier).isEqualByComparingTo("1.1000")

        assertThat(orchestrator.tick("tenant-a").currentMultiplier).isEqualByComparingTo("1.0500")
        assertThat(orchestrator.tick("tenant-a").phase).isEqualTo(GameRoundPhase.CRASHED)
        assertThat(orchestrator.tick("tenant-a").phase).isEqualTo(GameRoundPhase.CLOSED)
        assertThat(port.revealCount).isEqualTo(1)
        assertThat(port.events.count { it == GameRoundPhase.CRASHED }).isEqualTo(1)
        assertThat(port.events.last()).isEqualTo(GameRoundPhase.CLOSED)

        clock.advanceMillis(1_000)
        val next = orchestrator.tick("tenant-a")
        assertThat(next.roundId).isNotEqualTo(scheduled.roundId)
        assertThat(next.phase).isEqualTo(GameRoundPhase.SCHEDULED)
    }

    @Test
    fun `restart recovery retains persisted outcome and closes without deriving another result`() {
        val clock = MutableClock(Instant.parse("2026-01-01T00:00:00Z"))
        val port = FakeLifecyclePort(clock)
        val firstOwner = AviatorRoundLifecycleOrchestrator(port, properties, clock)
        firstOwner.ensureRunning("tenant-a")
        clock.advanceMillis(1_000)
        firstOwner.tick("tenant-a")
        clock.advanceMillis(2_000)
        val flying = firstOwner.tick("tenant-a")
        assertThat(port.deriveCount).isEqualTo(1)

        val recoveredOwner = AviatorRoundLifecycleOrchestrator(port, properties, clock)
        recoveredOwner.ensureRunning("tenant-a")
        recoveredOwner.tick("tenant-a")
        val crashed = recoveredOwner.tick("tenant-a")
        assertThat(crashed.crashMultiplier).isEqualByComparingTo(flying.crashMultiplier)
        assertThat(port.deriveCount).isEqualTo(1)

        recoveredOwner.tick("tenant-a")
        assertThat(port.revealCount).isEqualTo(1)
    }

    @Test
    fun `closed is terminal and transition table rejects illegal jumps`() {
        assertThat(AviatorRoundLifecycleOrchestrator.VALID_TRANSITIONS[GameRoundPhase.CLOSED]).isNull()
        assertThat(AviatorRoundLifecycleOrchestrator.VALID_TRANSITIONS[GameRoundPhase.SCHEDULED])
            .isNotEqualTo(GameRoundPhase.CRASHED)
        assertThat(AviatorRoundLifecycleOrchestrator.VALID_TRANSITIONS[GameRoundPhase.CRASHED])
            .isNotEqualTo(GameRoundPhase.BET_COUNTDOWN)
    }

    private class FakeLifecyclePort(private val clock: Clock) : AviatorLifecyclePort {
        var round: GameRoundRecord? = null
        val operations = mutableListOf<String>()
        val events = mutableListOf<GameRoundPhase>()
        var deriveCount = 0
        var revealCount = 0

        override fun latestRound(tenantId: String, gameId: String): GameRoundRecord? = round?.copy()

        override fun createScheduledRoundWithCommitment(
            tenantId: String,
            gameId: String,
            roundId: String,
            properties: AviatorLifecycleProperties,
        ): Pair<GameRoundRecord, String> {
            val round = persistRound(
                CreateOrUpdateRoundCommand(
                    tenantId = tenantId,
                    gameId = gameId,
                    roundId = roundId,
                    phase = GameRoundPhase.SCHEDULED,
                    roundVersion = 1,
                    currentMultiplier = BigDecimal("1.0000"),
                    crashMultiplier = null,
                )
            )
            val commitment = ensureCommitment(tenantId, gameId, roundId, properties)
            return round to commitment
        }

        override fun ensureCommitment(
            tenantId: String,
            gameId: String,
            roundId: String,
            properties: AviatorLifecycleProperties,
        ): String {
            val existing = round
            check(existing != null && existing.roundId == roundId) {
                "Foreign key violation: parent round $roundId does not exist"
            }
            operations += "commitment"
            return "commitment-$roundId"
        }

        override fun deriveOutcome(tenantId: String, gameId: String, roundId: String): LifecycleOutcome {
            deriveCount++
            return LifecycleOutcome(BigDecimal("1.1000"))
        }

        override fun persistRound(command: CreateOrUpdateRoundCommand): GameRoundRecord {
            val now = clock.instant()
            val existing = round
            round = if (existing == null || existing.roundId != command.roundId) {
                GameRoundRecord(
                    tenantId = command.tenantId,
                    gameId = command.gameId,
                    roundId = command.roundId,
                    phase = command.phase,
                    roundVersion = command.roundVersion,
                    currentMultiplier = command.currentMultiplier,
                    crashMultiplier = command.crashMultiplier,
                    startedAt = now,
                    serverTime = now,
                    createdAt = now,
                    updatedAt = now,
                )
            } else {
                existing.copy(
                    phase = command.phase,
                    roundVersion = command.roundVersion,
                    currentMultiplier = command.currentMultiplier,
                    crashMultiplier = command.crashMultiplier ?: existing.crashMultiplier,
                    crashedAt = if (command.phase == GameRoundPhase.CRASHED) now else existing.crashedAt,
                    closedAt = if (command.phase == GameRoundPhase.CLOSED) now else existing.closedAt,
                    serverTime = now,
                    updatedAt = now,
                )
            }
            operations += "persist:${command.phase}"
            return round!!.copy()
        }

        override fun publishState(round: GameRoundRecord, elapsedFlightSeconds: Double): GameEventRecord {
            operations += "event:${round.phase}"
            events += round.phase
            return GameEventRecord(
                eventId = java.util.UUID.randomUUID(), tenantId = round.tenantId, gameId = round.gameId,
                roundId = round.roundId, sequenceId = events.size.toLong(), eventName = "gameState",
                payloadJson = "{}", targetScope = "BROADCAST", targetOwnerId = null,
                timestampMillis = clock.instant().toEpochMilli(), createdAt = clock.instant(),
            )
        }

        override fun hasPublishedState(tenantId: String, gameId: String, roundId: String, phase: GameRoundPhase): Boolean =
            events.contains(phase)

        override fun settleCrash(
            tenantId: String,
            gameId: String,
            roundId: String,
            crashMultiplier: BigDecimal,
        ): GameRoundRecord {
            operations += "settle"
            val existing = checkNotNull(round)
            if (existing.phase == GameRoundPhase.CRASHED) return existing
            val now = clock.instant()
            val crashed = existing.copy(
                phase = GameRoundPhase.CRASHED,
                roundVersion = existing.roundVersion + 1,
                currentMultiplier = crashMultiplier,
                crashMultiplier = crashMultiplier,
                crashedAt = now,
                serverTime = now,
                updatedAt = now,
            )
            round = crashed
            return crashed
        }

        override fun revealIfNeeded(tenantId: String, gameId: String, roundId: String, expectedMultiplier: BigDecimal) {
            check(expectedMultiplier.compareTo(BigDecimal("1.1000")) == 0)
            if (revealCount == 0) revealCount++
        }
    }

    private class MutableClock(private var now: Instant) : Clock() {
        override fun getZone(): ZoneId = ZoneId.of("UTC")
        override fun withZone(zone: ZoneId): Clock = this
        override fun instant(): Instant = now
        fun advanceMillis(millis: Long) { now = now.plusMillis(millis) }
    }
}
