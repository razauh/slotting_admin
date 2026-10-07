package com.slotting.admin.gameprovider

import org.slf4j.LoggerFactory
import org.springframework.beans.factory.annotation.Value
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty
import org.springframework.boot.actuate.info.Info
import org.springframework.boot.actuate.info.InfoContributor
import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Configuration
import org.springframework.scheduling.annotation.EnableScheduling
import org.springframework.scheduling.annotation.Scheduled
import org.springframework.stereotype.Component
import org.springframework.stereotype.Service
import java.math.BigDecimal
import java.math.RoundingMode
import java.time.Clock
import java.time.Duration
import java.time.Instant
import java.util.UUID
import java.util.concurrent.ConcurrentHashMap

data class AviatorLifecycleProperties(
    val scheduledMillis: Long,
    val bettingMillis: Long,
    val closedMillis: Long,
    val multiplierStep: BigDecimal,
    val rulesVersion: String,
    val algorithmVersion: String,
    val publicSalt: String,
    val configuredTenants: Set<String>,
)

data class AviatorLifecycleDiagnostics(
    val running: Boolean,
    val roundId: String?,
    val phase: GameRoundPhase?,
    val roundVersion: Long?,
    val lastTransitionAt: Instant?,
    val nextExpectedTransitionAt: Instant?,
    val lastError: String?,
)

data class LifecycleOutcome(val multiplier: BigDecimal)

interface AviatorLifecyclePort {
    fun latestRound(tenantId: String, gameId: String): GameRoundRecord?
    fun ensureCommitment(tenantId: String, gameId: String, roundId: String, properties: AviatorLifecycleProperties): String
    fun createScheduledRoundWithCommitment(tenantId: String, gameId: String, roundId: String, properties: AviatorLifecycleProperties): Pair<GameRoundRecord, String>
    fun deriveOutcome(tenantId: String, gameId: String, roundId: String): LifecycleOutcome
    fun persistRound(command: CreateOrUpdateRoundCommand): GameRoundRecord
    fun publishState(round: GameRoundRecord, elapsedFlightSeconds: Double): GameEventRecord
    fun settleCrash(tenantId: String, gameId: String, roundId: String, crashMultiplier: BigDecimal)
    fun revealIfNeeded(tenantId: String, gameId: String, roundId: String, expectedMultiplier: BigDecimal)
}

@Component
@ConditionalOnProperty(
    prefix = "slotting.aviator.lifecycle",
    name = ["enabled"],
    havingValue = "true",
    matchIfMissing = false,
)
class ProductionAviatorLifecyclePort(
    private val gameService: DurableGameWagerAndSettlementService,
    private val fairnessAuthority: ProvablyFairOutcomeAuthority,
    private val snapshotService: AuthoritativeGameSnapshotAndEventService,
    private val txManager: org.springframework.transaction.PlatformTransactionManager,
) : AviatorLifecyclePort {
    override fun latestRound(tenantId: String, gameId: String): GameRoundRecord? =
        gameService.store.findLatestRound(tenantId, gameId)

    @org.springframework.transaction.annotation.Transactional
    override fun createScheduledRoundWithCommitment(
        tenantId: String,
        gameId: String,
        roundId: String,
        properties: AviatorLifecycleProperties,
    ): Pair<GameRoundRecord, String> {
        val action = {
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
            round to commitment
        }
        return org.springframework.transaction.support.TransactionTemplate(txManager).execute { action() }
    }

    override fun ensureCommitment(
        tenantId: String,
        gameId: String,
        roundId: String,
        properties: AviatorLifecycleProperties,
    ): String {
        val existing = fairnessAuthority.store.findCommitment(tenantId, gameId, roundId)
        return existing?.commitmentHash ?: fairnessAuthority.publishPreBetCommitment(
            PublishCommitmentCommand(
                tenantId = tenantId,
                gameId = gameId,
                roundId = roundId,
                publicSalt = properties.publicSalt,
                algorithmVersion = properties.algorithmVersion,
                rulesVersion = properties.rulesVersion,
            )
        ).commitmentHash
    }

    override fun deriveOutcome(tenantId: String, gameId: String, roundId: String): LifecycleOutcome {
        val outcome = fairnessAuthority.deriveAuthoritativeOutcome(tenantId, gameId, roundId)
        return LifecycleOutcome(outcome.multiplier)
    }

    override fun persistRound(command: CreateOrUpdateRoundCommand): GameRoundRecord =
        gameService.createOrUpdateRound(command)

    override fun publishState(round: GameRoundRecord, elapsedFlightSeconds: Double): GameEventRecord =
        snapshotService.recordAndBroadcastGameState(
            tenantId = round.tenantId,
            gameId = round.gameId,
            roundId = round.roundId,
            phase = round.phase,
            multiplier = round.currentMultiplier,
            roundVersion = round.roundVersion,
            elapsedFlightSeconds = elapsedFlightSeconds,
        )

    override fun settleCrash(
        tenantId: String,
        gameId: String,
        roundId: String,
        crashMultiplier: BigDecimal,
    ) {
        gameService.settleRoundCrash(SettleRoundCrashCommand(tenantId, gameId, roundId, crashMultiplier))
    }

    override fun revealIfNeeded(tenantId: String, gameId: String, roundId: String, expectedMultiplier: BigDecimal) {
        val existing = fairnessAuthority.store.findReveal(tenantId, gameId, roundId)
        val reveal = existing ?: fairnessAuthority.store.findCommitment(tenantId, gameId, roundId)?.let { commitment ->
            fairnessAuthority.revealAndVerifyOutcome(
                RevealOutcomeCommand(tenantId, gameId, roundId, commitment.encryptedSecretSeed)
            )
        } ?: error("Commitment missing during reveal for round $roundId")
        check(reveal.derivedMultiplier.compareTo(expectedMultiplier) == 0) {
            "Persisted crash multiplier differs from revealed fairness outcome for round $roundId"
        }
    }
}

@Service
@ConditionalOnProperty(
    prefix = "slotting.aviator.lifecycle",
    name = ["enabled"],
    havingValue = "true",
    matchIfMissing = false,
)
class AviatorRoundLifecycleOrchestrator(
    private val port: AviatorLifecyclePort,
    private val properties: AviatorLifecycleProperties,
    private val clock: Clock,
) {
    private val logger = LoggerFactory.getLogger(javaClass)
    private val locks = ConcurrentHashMap<String, Any>()
    private val activeKeys = ConcurrentHashMap.newKeySet<String>()
    private val errors = ConcurrentHashMap<String, String>()
    private val flightStartTimes = ConcurrentHashMap<String, Instant>()
    private val gameId = "AVIATOR"

    init {
        properties.configuredTenants.filter(String::isNotBlank).forEach { activeKeys += key(it, gameId) }
    }

    fun ensureRunning(tenantId: String, requestedGameId: String = gameId): GameRoundRecord {
        require(requestedGameId.equals(gameId, ignoreCase = true)) { "Unsupported lifecycle game: $requestedGameId" }
        val normalizedGameId = gameId
        activeKeys += key(tenantId, normalizedGameId)
        return synchronized(lockFor(tenantId, normalizedGameId)) {
            val latest = port.latestRound(tenantId, normalizedGameId)
            if (latest == null) createRound(tenantId, normalizedGameId) else latest
        }
    }

    @Scheduled(fixedDelayString = "\${slotting.aviator.lifecycle.tick-ms:100}")
    fun scheduledTick() {
        activeKeys.toList().forEach { encoded ->
            val (tenantId, activeGameId) = encoded.split('|', limit = 2)
            runCatching { tick(tenantId, activeGameId) }
                .onFailure { failure ->
                    errors[encoded] = failure.message ?: failure::class.simpleName.orEmpty()
                    logger.error(
                        "AVIATOR_LIFECYCLE_FAILED tenantId={} gameId={} failureType={} message={}",
                        tenantId, activeGameId, failure::class.simpleName, failure.message,
                    )
                }
        }
    }

    fun tick(tenantId: String, requestedGameId: String = gameId): GameRoundRecord =
        synchronized(lockFor(tenantId, gameId)) {
            val round = ensureRunning(tenantId, requestedGameId)
            val next = advance(round)
            errors.remove(key(tenantId, gameId))
            next
        }

    fun diagnostics(tenantId: String): AviatorLifecycleDiagnostics {
        val round = port.latestRound(tenantId, gameId)
        return AviatorLifecycleDiagnostics(
            running = activeKeys.contains(key(tenantId, gameId)),
            roundId = round?.roundId,
            phase = round?.phase,
            roundVersion = round?.roundVersion,
            lastTransitionAt = round?.updatedAt,
            nextExpectedTransitionAt = round?.let(::nextExpectedTransitionAt),
            lastError = errors[key(tenantId, gameId)],
        )
    }

    private fun nextExpectedTransitionAt(round: GameRoundRecord): Instant? = when (round.phase) {
        GameRoundPhase.SCHEDULED -> round.updatedAt.plusMillis(properties.scheduledMillis)
        GameRoundPhase.BET_COUNTDOWN -> round.updatedAt.plusMillis(properties.bettingMillis)
        GameRoundPhase.FLYING, GameRoundPhase.CRASHED -> clock.instant()
        GameRoundPhase.CLOSED -> round.updatedAt.plusMillis(properties.closedMillis)
    }

    private fun advance(round: GameRoundRecord): GameRoundRecord {
        val elapsed = Duration.between(round.updatedAt, clock.instant()).toMillis().coerceAtLeast(0)
        return when (round.phase) {
            GameRoundPhase.SCHEDULED -> if (elapsed >= properties.scheduledMillis) {
                transition(round, GameRoundPhase.BET_COUNTDOWN, round.currentMultiplier, round.crashMultiplier)
            } else round

            GameRoundPhase.BET_COUNTDOWN -> if (elapsed >= properties.bettingMillis) {
                val crash = round.crashMultiplier ?: port.deriveOutcome(round.tenantId, round.gameId, round.roundId).multiplier
                logger.info(
                    "AVIATOR_OUTCOME_READY roundId={} roundVersion={} crashMultiplier={}",
                    round.roundId, round.roundVersion, crash,
                )
                flightStartTimes[round.roundId] = clock.instant()
                transition(round, GameRoundPhase.FLYING, BigDecimal("1.0000"), crash)
            } else round

            GameRoundPhase.FLYING -> progressFlight(round)
            GameRoundPhase.CRASHED -> finishCrashedRound(round)
            GameRoundPhase.CLOSED -> if (elapsed >= properties.closedMillis) {
                flightStartTimes.remove(round.roundId)
                createRound(round.tenantId, round.gameId)
            } else round
        }
    }

    private fun progressFlight(round: GameRoundRecord): GameRoundRecord {
        val crash = requireNotNull(round.crashMultiplier) {
            "Persisted FLYING round ${round.roundId} has no authoritative crash multiplier"
        }
        val flightStart = flightStartTimes.computeIfAbsent(round.roundId) { round.startedAt }
        val elapsedSeconds = Duration.between(flightStart, clock.instant()).toMillis().coerceAtLeast(0) / 1000.0
        val curveMultiplier = BigDecimal.valueOf(Math.floor(Math.exp(0.06 * elapsedSeconds) * 10000.0) / 10000.0)
            .setScale(4, RoundingMode.DOWN)
        val stepMultiplier = round.currentMultiplier.add(properties.multiplierStep).setScale(4, RoundingMode.DOWN)
        val nextMultiplier = curveMultiplier.max(stepMultiplier).min(crash)
        return if (nextMultiplier >= crash) {
            flightStartTimes.remove(round.roundId)
            val crashed = transition(round, GameRoundPhase.CRASHED, crash, crash)
            port.settleCrash(round.tenantId, round.gameId, round.roundId, crash)
            logger.info("AVIATOR_CRASHED roundId={} roundVersion={} crashMultiplier={}", round.roundId, round.roundVersion, crash)
            crashed
        } else {
            persistAndPublish(round, GameRoundPhase.FLYING, nextMultiplier, crash)
        }
    }

    private fun finishCrashedRound(round: GameRoundRecord): GameRoundRecord {
        val crash = requireNotNull(round.crashMultiplier) { "CRASHED round ${round.roundId} has no crash multiplier" }
        port.settleCrash(round.tenantId, round.gameId, round.roundId, crash)
        port.revealIfNeeded(round.tenantId, round.gameId, round.roundId, crash)
        logger.info("AVIATOR_REVEALED roundId={} phase={} roundVersion={}", round.roundId, round.phase, round.roundVersion)
        val current = port.latestRound(round.tenantId, round.gameId) ?: round
        val closed = transition(current, GameRoundPhase.CLOSED, crash, crash)
        logger.info("AVIATOR_CLOSED roundId={} roundVersion={}", closed.roundId, closed.roundVersion)
        return closed
    }

    private fun transition(
        round: GameRoundRecord,
        nextPhase: GameRoundPhase,
        multiplier: BigDecimal,
        crashMultiplier: BigDecimal?,
    ): GameRoundRecord {
        val expected = VALID_TRANSITIONS[round.phase]
        require(expected == nextPhase) { "Illegal Aviator phase transition ${round.phase} -> $nextPhase" }
        val persisted = persistAndPublish(round, nextPhase, multiplier, crashMultiplier)
        logger.info(
            "AVIATOR_PHASE_CHANGED roundId={} previousPhase={} nextPhase={} roundVersion={} currentMultiplier={}",
            round.roundId, round.phase, nextPhase, persisted.roundVersion, persisted.currentMultiplier,
        )
        return persisted
    }

    private fun persistAndPublish(
        round: GameRoundRecord,
        phase: GameRoundPhase,
        multiplier: BigDecimal,
        crashMultiplier: BigDecimal?,
    ): GameRoundRecord {
        var currentRound = round
        var attempts = 0
        val maxAttempts = 3
        while (attempts < maxAttempts) {
            try {
                val persisted = port.persistRound(
                    CreateOrUpdateRoundCommand(
                        tenantId = currentRound.tenantId,
                        gameId = currentRound.gameId,
                        roundId = currentRound.roundId,
                        phase = phase,
                        roundVersion = currentRound.roundVersion + 1,
                        currentMultiplier = multiplier,
                        crashMultiplier = crashMultiplier,
                        expectedVersion = currentRound.roundVersion,
                    )
                )
                port.publishState(persisted, if (phase == GameRoundPhase.FLYING) {
                    Duration.between(persisted.startedAt, clock.instant()).toMillis().coerceAtLeast(0) / 1000.0
                } else 0.0)
                return persisted
            } catch (e: RoundVersionConflictException) {
                attempts++
                if (attempts >= maxAttempts) throw e
                val reRead = port.latestRound(currentRound.tenantId, currentRound.gameId)
                if (reRead == null || reRead.roundId != currentRound.roundId) throw e
                currentRound = reRead
            }
        }
        error("Unreachable retry loop")
    }

    private fun createRound(tenantId: String, activeGameId: String): GameRoundRecord {
        val roundId = "aviator-${UUID.randomUUID()}"
        val (round, commitment) = port.createScheduledRoundWithCommitment(tenantId, activeGameId, roundId, properties)
        logger.info("AVIATOR_COMMITMENT_PUBLISHED roundId={} commitment={}", roundId, commitment)
        port.publishState(round, 0.0)
        logger.info(
            "AVIATOR_ROUND_CREATED roundId={} phase={} roundVersion={} commitment={}",
            round.roundId, round.phase, round.roundVersion, commitment,
        )
        return round
    }

    private fun lockFor(tenantId: String, activeGameId: String): Any =
        locks.computeIfAbsent(key(tenantId, activeGameId)) { Any() }

    private fun key(tenantId: String, activeGameId: String) = "$tenantId|$activeGameId"

    companion object {
        val VALID_TRANSITIONS = mapOf(
            GameRoundPhase.SCHEDULED to GameRoundPhase.BET_COUNTDOWN,
            GameRoundPhase.BET_COUNTDOWN to GameRoundPhase.FLYING,
            GameRoundPhase.FLYING to GameRoundPhase.CRASHED,
            GameRoundPhase.CRASHED to GameRoundPhase.CLOSED,
        )
    }
}

@Configuration
@EnableScheduling
@ConditionalOnProperty(
    prefix = "slotting.aviator.lifecycle",
    name = ["enabled"],
    havingValue = "true",
    matchIfMissing = true,
)
class AviatorLifecycleConfiguration {
    @Bean
    fun aviatorLifecycleProperties(
        @Value("\${slotting.aviator.lifecycle.scheduled-ms:1000}") scheduledMillis: Long,
        @Value("\${slotting.aviator.lifecycle.betting-ms:5000}") bettingMillis: Long,
        @Value("\${slotting.aviator.lifecycle.closed-ms:1000}") closedMillis: Long,
        @Value("\${slotting.aviator.lifecycle.multiplier-step:0.0500}") multiplierStep: BigDecimal,
        @Value("\${slotting.aviator.lifecycle.rules-version:1.0.0}") rulesVersion: String,
        @Value("\${slotting.aviator.lifecycle.algorithm-version:1.0.0}") algorithmVersion: String,
        @Value("\${slotting.aviator.lifecycle.public-salt:aviator-public}") publicSalt: String,
        @Value("#{'\${slotting.aviator.lifecycle.tenants:default}'.split(',')}") tenants: List<String>,
    ) = AviatorLifecycleProperties(
        scheduledMillis = scheduledMillis.coerceAtLeast(0),
        bettingMillis = bettingMillis.coerceAtLeast(0),
        closedMillis = closedMillis.coerceAtLeast(0),
        multiplierStep = multiplierStep.max(BigDecimal("0.0001")),
        rulesVersion = rulesVersion,
        algorithmVersion = algorithmVersion,
        publicSalt = publicSalt,
        configuredTenants = tenants.map(String::trim).filter(String::isNotBlank).toSet(),
    )
}

@Component
@ConditionalOnProperty(
    prefix = "slotting.aviator.lifecycle",
    name = ["enabled"],
    havingValue = "true",
    matchIfMissing = false,
)
class AviatorLifecycleInfoContributor(
    private val orchestrator: AviatorRoundLifecycleOrchestrator,
    private val properties: AviatorLifecycleProperties,
) : InfoContributor {
    override fun contribute(builder: Info.Builder) {
        builder.withDetail(
            "aviatorLifecycle",
            properties.configuredTenants.associateWith { orchestrator.diagnostics(it) },
        )
    }
}
