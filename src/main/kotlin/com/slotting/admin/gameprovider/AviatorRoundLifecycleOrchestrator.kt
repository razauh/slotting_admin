package com.slotting.admin.gameprovider

import org.slf4j.LoggerFactory
import org.springframework.beans.factory.annotation.Value
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty
import org.springframework.boot.actuate.info.Info
import org.springframework.boot.actuate.info.InfoContributor
import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Configuration
import org.springframework.core.env.Environment
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
import java.security.MessageDigest
import java.nio.charset.StandardCharsets

data class AviatorLifecycleProperties(
    val scheduledMillis: Long,
    val bettingMillis: Long,
    val closedMillis: Long,
    val multiplierStep: BigDecimal,
    val rulesVersion: String,
    val algorithmVersion: String,
    val publicSalt: String,
    val configuredTenants: Set<String>,
    val tickMillis: Long = 100L,
    val configFingerprint: String = AviatorLifecycleConfigurationRules.fingerprint(
        scheduledMillis, bettingMillis, closedMillis, tickMillis, multiplierStep, rulesVersion, algorithmVersion, publicSalt
    ),
)

object AviatorLifecycleConfigurationRules {
    fun validate(
        scheduledMillis: Long,
        bettingMillis: Long,
        closedMillis: Long,
        tickMillis: Long,
        multiplierStep: BigDecimal,
        rulesVersion: String,
        algorithmVersion: String,
        publicSalt: String,
    ) {
        require(scheduledMillis > 0) { "slotting.aviator.lifecycle.scheduled-ms must be positive" }
        require(bettingMillis > 0) { "slotting.aviator.lifecycle.betting-ms must be positive" }
        require(closedMillis > 0) { "slotting.aviator.lifecycle.closed-ms must be positive" }
        require(tickMillis > 0) { "slotting.aviator.lifecycle.tick-ms must be positive" }
        require(multiplierStep >= BigDecimal("0.0001")) { "slotting.aviator.lifecycle.multiplier-step must be at least 0.0001" }
        require(rulesVersion.isNotBlank()) { "slotting.aviator.lifecycle.rules-version must not be blank" }
        require(publicSalt.isNotBlank()) { "slotting.aviator.lifecycle.public-salt must not be blank" }
        try {
            AviatorAlgorithmRegistry.requireSupported(algorithmVersion)
        } catch (failure: UnsupportedAlgorithmException) {
            throw IllegalArgumentException("slotting.aviator.lifecycle.algorithm-version is unsupported: $algorithmVersion", failure)
        }
    }

    fun fingerprint(
        scheduledMillis: Long,
        bettingMillis: Long,
        closedMillis: Long,
        tickMillis: Long,
        multiplierStep: BigDecimal,
        rulesVersion: String,
        algorithmVersion: String,
        publicSalt: String,
    ): String {
        val canonical = listOf(
            "scheduled-ms=$scheduledMillis",
            "betting-ms=$bettingMillis",
            "closed-ms=$closedMillis",
            "tick-ms=$tickMillis",
            "multiplier-step=${multiplierStep.stripTrailingZeros().toPlainString()}",
            "rules-version=$rulesVersion",
            "algorithm-version=$algorithmVersion",
            "public-salt=$publicSalt",
        ).joinToString("|")
        return MessageDigest.getInstance("SHA-256")
            .digest(canonical.toByteArray(StandardCharsets.UTF_8))
            .joinToString("") { "%02x".format(it) }
    }
}

data class AviatorLifecycleDiagnostics(
    val running: Boolean,
    val roundId: String?,
    val phase: GameRoundPhase?,
    val roundVersion: Long?,
    val lastTransitionAt: Instant?,
    val nextExpectedTransitionAt: Instant?,
    val lastError: String?,
    val holdsLease: Boolean,
    val ownerId: String?,
    val epoch: Long?,
    val leaseExpiresAt: Instant?,
    val notOwnerOutcomes: Long,
)

data class LifecycleOutcome(val multiplier: BigDecimal)

interface AviatorLifecyclePort {
    fun latestRound(tenantId: String, gameId: String): GameRoundRecord?
    fun ensureCommitment(tenantId: String, gameId: String, roundId: String, properties: AviatorLifecycleProperties): String
    fun createScheduledRoundWithCommitment(
        tenantId: String,
        gameId: String,
        roundId: String,
        properties: AviatorLifecycleProperties,
        token: LifecycleLeaseToken? = null,
    ): Pair<GameRoundRecord, String>
    fun deriveOutcome(tenantId: String, gameId: String, roundId: String, token: LifecycleLeaseToken? = null): LifecycleOutcome
    fun persistRound(command: CreateOrUpdateRoundCommand, token: LifecycleLeaseToken? = null): GameRoundRecord
    fun publishState(round: GameRoundRecord, elapsedFlightSeconds: Double, token: LifecycleLeaseToken? = null): GameEventRecord
    fun hasPublishedState(tenantId: String, gameId: String, roundId: String, phase: GameRoundPhase): Boolean
    fun settleCrash(
        tenantId: String,
        gameId: String,
        roundId: String,
        crashMultiplier: BigDecimal,
        token: LifecycleLeaseToken? = null,
    ): GameRoundRecord
    fun revealIfNeeded(
        tenantId: String,
        gameId: String,
        roundId: String,
        expectedMultiplier: BigDecimal,
        token: LifecycleLeaseToken? = null,
    )
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
    private val leaseStore: GameLifecycleLeaseStore? = null,
    private val clock: Clock = Clock.systemUTC(),
) : AviatorLifecyclePort {
    override fun latestRound(tenantId: String, gameId: String): GameRoundRecord? =
        gameService.store.findLatestRound(tenantId, gameId)

    private fun <T> inTx(action: () -> T): T =
        org.springframework.transaction.support.TransactionTemplate(txManager).execute { action() }
            ?: error("Lifecycle transaction produced no result")

    private fun requireLease(tenantId: String, gameId: String, token: LifecycleLeaseToken?) {
        val store = leaseStore ?: return
        val required = token ?: throw LifecycleNotOwnerException(
            LifecycleNotOwnerReason.LEASE_MISSING,
            "Lifecycle write for $tenantId/$gameId requires an active lease token",
        )
        val lease = store.lockAndVerify(tenantId, gameId, required.ownerId, required.epoch)
            ?: throw LifecycleNotOwnerException(
                LifecycleNotOwnerReason.LEASE_EXPIRED_OR_SUPERSEDED,
                "Lifecycle write for $tenantId/$gameId rejected: lease epoch ${required.epoch} is no longer current",
            )
        check(lease.ownerId == required.ownerId && lease.epoch == required.epoch)
    }

    override fun createScheduledRoundWithCommitment(
        tenantId: String,
        gameId: String,
        roundId: String,
        properties: AviatorLifecycleProperties,
        token: LifecycleLeaseToken?,
    ): Pair<GameRoundRecord, String> {
        val action = {
            requireLease(tenantId, gameId, token)
            val round = try {
                persistRound(
                    CreateOrUpdateRoundCommand(
                        tenantId = tenantId,
                        gameId = gameId,
                        roundId = roundId,
                        phase = GameRoundPhase.SCHEDULED,
                        roundVersion = 1,
                        currentMultiplier = BigDecimal("1.0000"),
                        crashMultiplier = null,
                        phaseStartedAt = clock.instant(),
                        phaseDeadlineAt = clock.instant().plusMillis(properties.scheduledMillis),
                        lifecycleConfigFingerprint = properties.configFingerprint,
                        scheduledMillis = properties.scheduledMillis,
                        bettingMillis = properties.bettingMillis,
                        closedMillis = properties.closedMillis,
                        tickMillis = properties.tickMillis,
                        multiplierStep = properties.multiplierStep,
                        rulesVersion = properties.rulesVersion,
                        algorithmVersion = properties.algorithmVersion,
                        publicSalt = properties.publicSalt,
                    ),
                    token,
                )
            } catch (e: RoundVersionConflictException) {
                if (e.hasUniqueViolationCause()) {
                    throw LifecycleNotOwnerException(
                        LifecycleNotOwnerReason.ROUND_ALREADY_ACTIVE,
                        "Round creation for $tenantId/$gameId lost the active-round race",
                    )
                }
                throw e
            }
            val commitment = ensureCommitment(tenantId, gameId, roundId, properties)
            round to commitment
        }
        val result = org.springframework.transaction.support.TransactionTemplate(txManager).execute { action() }
        return result ?: error("Round creation transaction returned no result for $tenantId/$gameId")
    }

    override fun ensureCommitment(
        tenantId: String,
        gameId: String,
        roundId: String,
        properties: AviatorLifecycleProperties,
    ): String {
        val existing = fairnessAuthority.store.findCommitment(tenantId, gameId, roundId)
        if (existing != null) {
            fairnessAuthority.validateCommitmentForReuse(
                commitment = existing,
                expectedRulesVersion = properties.rulesVersion,
                expectedAlgorithmVersion = properties.algorithmVersion,
                expectedPublicSalt = properties.publicSalt,
            )
            return existing.commitmentHash
        }
        return fairnessAuthority.publishPreBetCommitment(
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

    override fun deriveOutcome(tenantId: String, gameId: String, roundId: String, token: LifecycleLeaseToken?): LifecycleOutcome =
        inTx {
            requireLease(tenantId, gameId, token)
            val outcome = fairnessAuthority.deriveAuthoritativeOutcome(tenantId, gameId, roundId)
            LifecycleOutcome(outcome.multiplier)
        }

    override fun persistRound(command: CreateOrUpdateRoundCommand, token: LifecycleLeaseToken?): GameRoundRecord =
        inTx {
            requireLease(command.tenantId, command.gameId, token)
            gameService.createOrUpdateRound(command)
        }

    override fun publishState(round: GameRoundRecord, elapsedFlightSeconds: Double, token: LifecycleLeaseToken?): GameEventRecord =
        inTx {
            requireLease(round.tenantId, round.gameId, token)
            snapshotService.recordAndBroadcastGameState(
                tenantId = round.tenantId,
                gameId = round.gameId,
                roundId = round.roundId,
                phase = round.phase,
                multiplier = round.currentMultiplier,
                roundVersion = round.roundVersion,
                elapsedFlightSeconds = elapsedFlightSeconds,
            )
        }

    override fun hasPublishedState(tenantId: String, gameId: String, roundId: String, phase: GameRoundPhase): Boolean =
        snapshotService.hasPublishedPhase(tenantId, gameId, roundId, phase)

    override fun settleCrash(
        tenantId: String,
        gameId: String,
        roundId: String,
        crashMultiplier: BigDecimal,
        token: LifecycleLeaseToken?,
    ): GameRoundRecord = inTx {
        requireLease(tenantId, gameId, token)
        gameService.settleRoundCrash(SettleRoundCrashCommand(tenantId, gameId, roundId, crashMultiplier))
        gameService.store.findRound(tenantId, gameId, roundId)
            ?: throw CrashStateIntegrityException("Persisted crash round $roundId was not found after settlement")
    }

    override fun revealIfNeeded(
        tenantId: String,
        gameId: String,
        roundId: String,
        expectedMultiplier: BigDecimal,
        token: LifecycleLeaseToken?,
    ) {
        inTx {
            requireLease(tenantId, gameId, token)
            val existing = fairnessAuthority.store.findReveal(tenantId, gameId, roundId)
            val reveal = existing ?: run {
                fairnessAuthority.store.findCommitment(tenantId, gameId, roundId)
                    ?: error("Commitment missing during reveal for round $roundId")
                fairnessAuthority.revealAndVerifyOutcome(RevealOutcomeCommand(tenantId, gameId, roundId))
            }
            check(reveal.derivedMultiplier.compareTo(expectedMultiplier) == 0) {
                "Persisted crash multiplier differs from revealed fairness outcome for round $roundId"
            }
        }
    }
}

private fun RoundVersionConflictException.hasUniqueViolationCause(): Boolean {
    var current: Throwable? = this
    while (current != null) {
        if (current is java.sql.SQLException && current.sqlState == "23505") return true
        if (current is org.springframework.dao.DuplicateKeyException) return true
        current = current.cause
    }
    return false
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
    private val leaseStore: GameLifecycleLeaseStore? = null,
    @Value("\${slotting.aviator.lifecycle.lease-ttl-ms:3000}") private val leaseTtlMillis: Long = 3_000L,
    private val eventRecovery: AviatorEventDeliveryRecovery? = null,
    private val attemptJournal: LifecycleAttemptJournalStore? = null,
) {
    val ownerId: String = "aviator-" + UUID.randomUUID()
    private val logger = LoggerFactory.getLogger(javaClass)
    private val locks = ConcurrentHashMap<String, Any>()
    private val activeKeys = ConcurrentHashMap.newKeySet<String>()
    private val errors = ConcurrentHashMap<String, String>()
    private val flightStartTimes = ConcurrentHashMap<String, Instant>()
    private val heldTokens = ConcurrentHashMap<String, LifecycleLeaseToken>()
    private val notOwnerCounts = ConcurrentHashMap<String, Long>()
    private val gameId = "AVIATOR"

    init {
        properties.configuredTenants.filter(String::isNotBlank).forEach { activeKeys += key(it, gameId) }
    }

    fun activeTenants(): Set<String> = activeKeys.map { it.substringBefore('|') }.toSet()

    fun ensureRunning(tenantId: String, requestedGameId: String = gameId): GameRoundRecord {
        require(requestedGameId.equals(gameId, ignoreCase = true)) { "Unsupported lifecycle game: $requestedGameId" }
        val normalizedGameId = gameId
        activeKeys += key(tenantId, normalizedGameId)
        val token: LifecycleLeaseToken? = if (leaseStore == null) {
            null
        } else {
            acquireOrRenewLease(tenantId, normalizedGameId)
                ?: return latestOrNotOwner(tenantId, normalizedGameId)
        }
        return synchronized(lockFor(tenantId, normalizedGameId)) {
            val latest = port.latestRound(tenantId, normalizedGameId)
            if (latest == null) createRound(tenantId, normalizedGameId, token) else latest
        }
    }

    @Scheduled(fixedDelayString = "\${slotting.aviator.lifecycle.tick-ms:100}")
    fun scheduledTick() {
        activeKeys.toList().forEach { encoded ->
            val (tenantId, activeGameId) = encoded.split('|', limit = 2)
            runCatching { tick(tenantId, activeGameId) }
                .onFailure { failure ->
                    if (failure is LifecycleNotOwnerException) {
                        recordNotOwnerOutcome(encoded, failure.reason.name)
                        return@onFailure
                    }
                    errors[encoded] = failure.message ?: failure::class.simpleName.orEmpty()
                    logger.error(
                        "AVIATOR_LIFECYCLE_FAILED tenantId={} gameId={} failureType={} message={}",
                        tenantId, activeGameId, failure::class.simpleName, failure.message,
                    )
                }
        }
    }

    fun tick(tenantId: String, requestedGameId: String = gameId): GameRoundRecord {
        require(requestedGameId.equals(gameId, ignoreCase = true)) { "Unsupported lifecycle game: $requestedGameId" }
        val normalizedGameId = gameId
        activeKeys += key(tenantId, normalizedGameId)
        val held = heldTokens[key(tenantId, normalizedGameId)]
        val attempt = attemptJournal?.let { journal ->
            runCatching {
                journal.start(tenantId, normalizedGameId, port.latestRound(tenantId, normalizedGameId)?.roundId, "TICK", ownerId, held?.epoch, clock.instant())
            }.getOrNull()
        }
        return try {
            val token: LifecycleLeaseToken? = if (leaseStore == null) {
                null
            } else {
                acquireOrRenewLease(tenantId, normalizedGameId)
            }
            if (leaseStore != null && token == null) {
                val current = latestOrNotOwner(tenantId, normalizedGameId)
                attempt?.let { journal -> runCatching { attemptJournal?.complete(journal.attemptId, clock.instant(), current.roundVersion) } }
                return current
            }

            val result = synchronized(lockFor(tenantId, normalizedGameId)) {
                eventRecovery?.repairLatest(tenantId, normalizedGameId, token)
                val round = ensureRunningWithToken(tenantId, normalizedGameId, token)
                val next = advance(round, token)
                if (leaseStore != null && !renewLease(tenantId, normalizedGameId, token!!)) {
                    logger.warn(
                        "AVIATOR_LEASE_LOST tenantId={} gameId={} ownerId={} epoch={}",
                        tenantId, normalizedGameId, token.ownerId, token.epoch,
                    )
                    recordNotOwnerOutcome(key(tenantId, normalizedGameId), "RENEWAL_LOST")
                    return@synchronized port.latestRound(tenantId, normalizedGameId) ?: next
                }
                errors.remove(key(tenantId, normalizedGameId))
                next
            }
            attempt?.let { journal -> runCatching { attemptJournal?.complete(journal.attemptId, clock.instant(), result.roundVersion) } }
            result
        } catch (failure: Throwable) {
            attempt?.let { journal ->
                runCatching {
                    attemptJournal?.fail(journal.attemptId, clock.instant(), failure::class.simpleName ?: "lifecycle_failure", failure.message)
                }.onFailure { journalFailure ->
                    logger.warn("AVIATOR_FAILURE_JOURNAL_UNAVAILABLE tenantId={} gameId={} failureType={}", tenantId, normalizedGameId, journalFailure::class.simpleName)
                }
            }
            throw failure
        }
    }

    private fun ensureRunningWithToken(tenantId: String, normalizedGameId: String, token: LifecycleLeaseToken?): GameRoundRecord {
        val latest = port.latestRound(tenantId, normalizedGameId)
        return if (latest == null) createRound(tenantId, normalizedGameId, token) else latest
    }

    private fun acquireOrRenewLease(tenantId: String, activeGameId: String): LifecycleLeaseToken? {
        val store = leaseStore ?: return null
        val encoded = key(tenantId, activeGameId)
        val held = heldTokens[encoded]
        val result = store.acquireOrRenew(
            tenantId = tenantId,
            gameId = activeGameId,
            ownerId = ownerId,
            ttlMillis = leaseTtlMillis,
            expectedEpoch = held?.epoch,
        )
        val lease = result.lease
        if (result.status != LifecycleLeaseAcquireStatus.ACQUIRED || lease == null) {
            heldTokens.remove(encoded)
            recordNotOwnerOutcome(encoded, result.status.name)
            return null
        }
        val token = LifecycleLeaseToken(lease.ownerId, lease.epoch)
        heldTokens[encoded] = token
        return token
    }

    private fun renewLease(tenantId: String, activeGameId: String, token: LifecycleLeaseToken): Boolean {
        val store = leaseStore ?: return true
        val result = store.acquireOrRenew(
            tenantId = tenantId,
            gameId = activeGameId,
            ownerId = token.ownerId,
            ttlMillis = leaseTtlMillis,
            expectedEpoch = token.epoch,
        )
        val renewed = result.status == LifecycleLeaseAcquireStatus.ACQUIRED &&
            result.lease?.ownerId == token.ownerId &&
            result.lease?.epoch == token.epoch
        if (!renewed) heldTokens.remove(key(tenantId, activeGameId))
        return renewed
    }

    fun releaseLease(tenantId: String, requestedGameId: String = gameId) {
        val store = leaseStore ?: return
        val encoded = key(tenantId, gameId)
        val token = heldTokens.remove(encoded) ?: return
        store.release(tenantId, gameId, token.ownerId, token.epoch)
    }

    private fun latestOrNotOwner(tenantId: String, activeGameId: String): GameRoundRecord {
        repeat(25) {
            port.latestRound(tenantId, activeGameId)?.let { return it }
            Thread.sleep(4)
        }
        throw LifecycleNotOwnerException(
            LifecycleNotOwnerReason.LEASE_HELD_BY_OTHER,
            "No durable round for $tenantId/$activeGameId within the bounded wait while another owner holds the lease",
        )
    }

    private fun recordNotOwnerOutcome(encoded: String, reason: String) {
        notOwnerCounts.compute(encoded) { _, value -> (value ?: 0L) + 1L }
        logger.info("AVIATOR_NOT_OWNER tenantId={} reason={}", encoded, reason)
    }

    fun diagnostics(tenantId: String): AviatorLifecycleDiagnostics {
        val encoded = key(tenantId, gameId)
        val round = port.latestRound(tenantId, gameId)
        val held = heldTokens[encoded]
        val durable = leaseStore?.getLease(tenantId, gameId)
        val holdsLease = if (held != null && leaseStore != null) {
            leaseStore.isLeaseValid(tenantId, gameId, held.ownerId, held.epoch)
        } else {
            false
        }
        return AviatorLifecycleDiagnostics(
            running = activeKeys.contains(encoded),
            roundId = round?.roundId,
            phase = round?.phase,
            roundVersion = round?.roundVersion,
            lastTransitionAt = round?.updatedAt,
            nextExpectedTransitionAt = round?.let(::nextExpectedTransitionAt),
            lastError = errors[encoded],
            holdsLease = holdsLease,
            ownerId = durable?.ownerId ?: held?.ownerId,
            epoch = durable?.epoch ?: held?.epoch,
            leaseExpiresAt = durable?.leaseExpiresAt,
            notOwnerOutcomes = notOwnerCounts[encoded] ?: 0L,
        )
    }

    private fun nextExpectedTransitionAt(round: GameRoundRecord): Instant? = when (round.phase) {
        GameRoundPhase.SCHEDULED, GameRoundPhase.BET_COUNTDOWN -> round.phaseDeadlineAt
        GameRoundPhase.FLYING, GameRoundPhase.CRASHED -> clock.instant()
        GameRoundPhase.CLOSED -> round.phaseDeadlineAt ?: round.updatedAt.plusMillis(round.closedMillis ?: properties.closedMillis)
    }

    private fun advance(round: GameRoundRecord, token: LifecycleLeaseToken?): GameRoundRecord {
        val deadlinePassed = FlightClock.isPhaseDeadlinePassed(round, clock)
        val scheduledMillis = round.scheduledMillis ?: properties.scheduledMillis
        val bettingMillis = round.bettingMillis ?: properties.bettingMillis
        return when (round.phase) {
            GameRoundPhase.SCHEDULED -> if (deadlinePassed || Duration.between(round.updatedAt, clock.instant()).toMillis() >= scheduledMillis) {
                transition(round, GameRoundPhase.BET_COUNTDOWN, round.currentMultiplier, round.crashMultiplier, token)
            } else round

            GameRoundPhase.BET_COUNTDOWN -> if (deadlinePassed || Duration.between(round.updatedAt, clock.instant()).toMillis() >= bettingMillis) {
                val crash = round.crashMultiplier ?: port.deriveOutcome(round.tenantId, round.gameId, round.roundId, token).multiplier
                logger.info(
                    "AVIATOR_OUTCOME_READY roundId={} roundVersion={} crashMultiplier={}",
                    round.roundId, round.roundVersion, crash,
                )
                flightStartTimes[round.roundId] = clock.instant()
                transition(round, GameRoundPhase.FLYING, BigDecimal("1.0000"), crash, token)
            } else round

            GameRoundPhase.FLYING -> progressFlight(round, token)
            GameRoundPhase.CRASHED -> finishCrashedRound(round, token)
            GameRoundPhase.CLOSED -> if (deadlinePassed || Duration.between(round.updatedAt, clock.instant()).toMillis() >= properties.closedMillis) {
                flightStartTimes.remove(round.roundId)
                createRound(round.tenantId, round.gameId, token)
            } else round
        }
    }

    private fun progressFlight(round: GameRoundRecord, token: LifecycleLeaseToken?): GameRoundRecord {
        val crash = requireNotNull(round.crashMultiplier) {
            "Persisted FLYING round ${round.roundId} has no authoritative crash multiplier"
        }
        val flightStart = round.flyingAt ?: flightStartTimes.computeIfAbsent(round.roundId) { round.startedAt }
        val elapsedSeconds = Duration.between(flightStart, clock.instant()).toMillis().coerceAtLeast(0) / 1000.0
        val nextMultiplier = when (round.rulesVersion ?: properties.rulesVersion) {
            "2.0.0" -> {
                val curveMultiplier = FlightClock.calculateCurveMultiplier(elapsedSeconds)
                curveMultiplier.min(crash)
            }
            else -> {
                val stepMultiplier = round.currentMultiplier.add(round.multiplierStep ?: properties.multiplierStep).setScale(4, RoundingMode.DOWN)
                stepMultiplier.min(crash)
            }
        }
        return if (nextMultiplier >= crash) {
            flightStartTimes.remove(round.roundId)
            val crashed = port.settleCrash(round.tenantId, round.gameId, round.roundId, crash, token)
            port.publishState(crashed, 0.0, token)
            logger.info("AVIATOR_CRASHED roundId={} roundVersion={} crashMultiplier={}", round.roundId, round.roundVersion, crash)
            crashed
        } else {
            persistAndPublish(round, GameRoundPhase.FLYING, nextMultiplier, crash, token)
        }
    }

    private fun finishCrashedRound(round: GameRoundRecord, token: LifecycleLeaseToken?): GameRoundRecord {
        val crash = requireNotNull(round.crashMultiplier) { "CRASHED round ${round.roundId} has no crash multiplier" }
        val crashed = port.settleCrash(round.tenantId, round.gameId, round.roundId, crash, token)
        if (!port.hasPublishedState(round.tenantId, round.gameId, round.roundId, GameRoundPhase.CRASHED)) {
            port.publishState(crashed, 0.0, token)
        }
        port.revealIfNeeded(round.tenantId, round.gameId, round.roundId, crash, token)
        logger.info("AVIATOR_REVEALED roundId={} phase={} roundVersion={}", round.roundId, crashed.phase, crashed.roundVersion)
        val closed = transition(crashed, GameRoundPhase.CLOSED, crash, crash, token)
        logger.info("AVIATOR_CLOSED roundId={} roundVersion={}", closed.roundId, closed.roundVersion)
        return closed
    }

    private fun transition(
        round: GameRoundRecord,
        nextPhase: GameRoundPhase,
        multiplier: BigDecimal,
        crashMultiplier: BigDecimal?,
        token: LifecycleLeaseToken?,
    ): GameRoundRecord {
        val expected = VALID_TRANSITIONS[round.phase]
        require(expected == nextPhase) { "Illegal Aviator phase transition ${round.phase} -> $nextPhase" }
        val persisted = persistAndPublish(round, nextPhase, multiplier, crashMultiplier, token)
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
        token: LifecycleLeaseToken?,
    ): GameRoundRecord {
        var currentRound = round
        var attempts = 0
        val maxAttempts = 3
        val now = clock.instant()
        val flyingAt = when {
            phase == GameRoundPhase.FLYING && currentRound.phase != GameRoundPhase.FLYING -> now
            else -> currentRound.flyingAt
        }
        val phaseStartedAt = now
        val phaseDeadlineAt = when (phase) {
            GameRoundPhase.SCHEDULED -> now.plusMillis(currentRound.scheduledMillis ?: properties.scheduledMillis)
            GameRoundPhase.BET_COUNTDOWN -> now.plusMillis(currentRound.bettingMillis ?: properties.bettingMillis)
            GameRoundPhase.CLOSED -> now.plusMillis(currentRound.closedMillis ?: properties.closedMillis)
            else -> null
        }
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
                        flyingAt = flyingAt,
                        phaseStartedAt = phaseStartedAt,
                        phaseDeadlineAt = phaseDeadlineAt,
                        lifecycleConfigFingerprint = currentRound.lifecycleConfigFingerprint ?: properties.configFingerprint,
                        scheduledMillis = currentRound.scheduledMillis ?: properties.scheduledMillis,
                        bettingMillis = currentRound.bettingMillis ?: properties.bettingMillis,
                        closedMillis = currentRound.closedMillis ?: properties.closedMillis,
                        tickMillis = currentRound.tickMillis ?: properties.tickMillis,
                        multiplierStep = currentRound.multiplierStep ?: properties.multiplierStep,
                        rulesVersion = currentRound.rulesVersion ?: properties.rulesVersion,
                        algorithmVersion = currentRound.algorithmVersion ?: properties.algorithmVersion,
                        publicSalt = currentRound.publicSalt ?: properties.publicSalt,
                    ),
                    token,
                )
                port.publishState(persisted, FlightClock.computeElapsedFlightSeconds(persisted, clock), token)
                return persisted
            } catch (e: LifecycleNotOwnerException) {
                throw e
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

    private fun createRound(tenantId: String, activeGameId: String, token: LifecycleLeaseToken?): GameRoundRecord {
        val roundId = "aviator-${UUID.randomUUID()}"
        val (round, commitment) = port.createScheduledRoundWithCommitment(tenantId, activeGameId, roundId, properties, token)
        logger.info("AVIATOR_COMMITMENT_PUBLISHED roundId={} commitment={}", roundId, commitment)
        port.publishState(round, 0.0, token)
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
        environment: Environment? = null,
        @Value("\${slotting.aviator.lifecycle.scheduled-ms:1000}") scheduledMillis: Long,
        @Value("\${slotting.aviator.lifecycle.betting-ms:5000}") bettingMillis: Long,
        @Value("\${slotting.aviator.lifecycle.closed-ms:1000}") closedMillis: Long,
        @Value("\${slotting.aviator.lifecycle.multiplier-step:0.0500}") multiplierStep: BigDecimal,
        @Value("\${slotting.aviator.lifecycle.rules-version:1.0.0}") rulesVersion: String,
        @Value("\${slotting.aviator.lifecycle.algorithm-version:1.0.0}") algorithmVersion: String,
        @Value("\${slotting.aviator.lifecycle.public-salt:aviator-public}") publicSalt: String,
        @Value("\${slotting.aviator.lifecycle.tick-ms:100}") tickMillis: Long = 100L,
        @Value("#{'\${slotting.aviator.lifecycle.tenants:default}'.split(',')}") tenants: List<String>,
    ): AviatorLifecycleProperties {
        val production = environment?.activeProfiles?.any { it.equals("prod", true) || it.equals("production", true) } == true
        if (production) {
            listOf("scheduled-ms", "betting-ms", "closed-ms", "tick-ms", "multiplier-step", "rules-version", "algorithm-version", "public-salt")
                .forEach { key -> require(environment?.containsProperty("slotting.aviator.lifecycle.$key") == true) { "slotting.aviator.lifecycle.$key must be explicitly configured in production" } }
        }
        AviatorLifecycleConfigurationRules.validate(
            scheduledMillis, bettingMillis, closedMillis, tickMillis, multiplierStep,
            rulesVersion, algorithmVersion, publicSalt,
        )
        return AviatorLifecycleProperties(
            scheduledMillis = scheduledMillis.coerceAtLeast(0),
            bettingMillis = bettingMillis.coerceAtLeast(0),
            closedMillis = closedMillis.coerceAtLeast(0),
            multiplierStep = multiplierStep,
            rulesVersion = rulesVersion,
            algorithmVersion = algorithmVersion,
            publicSalt = publicSalt,
            configuredTenants = tenants.map(String::trim).filter(String::isNotBlank).toSet(),
            tickMillis = tickMillis,
            configFingerprint = AviatorLifecycleConfigurationRules.fingerprint(
                scheduledMillis, bettingMillis, closedMillis, tickMillis, multiplierStep,
                rulesVersion, algorithmVersion, publicSalt,
            ),
        )
    }
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
        val configured = properties.configuredTenants
        val dynamic = orchestrator.activeTenants() - configured
        val details = linkedMapOf<String, Any>()
        details["instanceOwnerId"] = orchestrator.ownerId
        details["effectiveConfiguration"] = mapOf(
            "scheduledMillis" to properties.scheduledMillis,
            "bettingMillis" to properties.bettingMillis,
            "closedMillis" to properties.closedMillis,
            "tickMillis" to properties.tickMillis,
            "multiplierStep" to properties.multiplierStep,
            "rulesVersion" to properties.rulesVersion,
            "algorithmVersion" to properties.algorithmVersion,
            "configFingerprint" to properties.configFingerprint,
        )
        details["configuredTenants"] = configured.sorted().associateWith { orchestrator.diagnostics(it) }
        details["dynamicTenants"] = dynamic.sorted().associateWith { orchestrator.diagnostics(it) }
        builder.withDetail("aviatorLifecycle", details)
    }
}
