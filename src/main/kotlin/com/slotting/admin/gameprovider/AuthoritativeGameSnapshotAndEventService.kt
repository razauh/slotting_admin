package com.slotting.admin.gameprovider

import com.fasterxml.jackson.databind.ObjectMapper
import com.slotting.admin.auth.AuthErrorCode
import com.slotting.admin.auth.AuthenticatedPrincipal
import com.slotting.admin.auth.AuthenticationFailure
import com.slotting.admin.auth.DurableAuthService
import com.slotting.admin.auth.PrincipalKind
import com.slotting.admin.identity.PlayerRegistrationStore
import com.slotting.admin.ledger.LedgerJournalStore
import com.slotting.admin.wallet.AuthoritativeWalletService
import org.springframework.stereotype.Service
import java.math.BigDecimal
import java.time.Clock
import java.util.UUID

/**
 * Gate to enforce TC-023: Authoritative game snapshots and event ordered delivery.
 * Protected risk: "snapshots fabricate independent financial/game state, independent counters, lost ACK unreconciled"
 * Semantic contract: "REST, socket, snapshot and command lookup reflect consistent durable state from the single ledger authority."
 */
object AuthoritativeGameSnapshotBinding {
    @Volatile
    var isBound: Boolean = true

    fun checkBound() {
        if (!isBound) {
            throw AssertionError("authoritative snapshot service unbound")
        }
    }
}

class AuthoritativeGameSnapshotAndEventService(
    private val gameStore: DurableGameWagerAndSettlementStore,
    private val gameService: DurableGameWagerAndSettlementService,
    private val walletService: AuthoritativeWalletService,
    private val ledgerStore: LedgerJournalStore,
    private val fairnessStore: FairnessEvidenceStore,
    private val eventJournalStore: GameEventJournalStore,
    private val registrationStore: PlayerRegistrationStore,
    private val clock: Clock = Clock.systemUTC(),
    private val authService: DurableAuthService? = null,
) {
    private val objectMapper: ObjectMapper = ObjectMapper().findAndRegisterModules()

    fun getBootstrap(tenantId: String, gameId: String): AviatorBootstrapResponse {
        AuthoritativeGameSnapshotBinding.checkBound()
        val now = clock.instant()
        val activeRound = findActiveRound(tenantId, gameId)

        return AviatorBootstrapResponse(
            schemaVersion = 1,
            gameId = gameId,
            rulesVersion = "1.0.0",
            protocolVersion = "1.2.0",
            minSupportedProtocolVersion = "1.0.0",
            serverTimeMillis = now.toEpochMilli(),
            limits = CrashBetLimits(),
            activeRoundId = activeRound?.roundId,
            phase = activeRound?.phase?.name,
        )
    }

    fun getLimits(): CrashBetLimits {
        return CrashBetLimits()
    }

    fun getMyInfo(tenantId: String, principal: AuthenticatedPrincipal?): SnapshotUser {
        AuthoritativeGameSnapshotBinding.checkBound()
        val p = principal ?: throw AuthenticationFailure.Rejected(AuthErrorCode.UNAUTHENTICATED)
        if (p.tenantId != tenantId) throw AuthenticationFailure.Rejected(AuthErrorCode.FORBIDDEN)
        val balance = ledgerStore.findBalance(tenantId, "PLAYER:${p.id}", "INR")
        val playerUuid = try { UUID.fromString(p.id) } catch (e: Exception) { null }
        val registration = playerUuid?.let { registrationStore.findById(tenantId, it) }
        val userName = registration?.maskedEmail ?: p.id
        return SnapshotUser(
            userId = p.id,
            userName = userName,
            balanceMinor = balance,
            currency = "INR",
        )
    }

    fun getMyBets(tenantId: String, principal: AuthenticatedPrincipal?, limit: Int): List<UserBetHistoryItem> {
        AuthoritativeGameSnapshotBinding.checkBound()
        val p = principal ?: throw AuthenticationFailure.Rejected(AuthErrorCode.UNAUTHENTICATED)
        if (p.tenantId != tenantId) throw AuthenticationFailure.Rejected(AuthErrorCode.FORBIDDEN)
        val boundedLimit = limit.coerceIn(1, 50)
        val bets = gameStore.findBetsForOwner(tenantId, p.id, boundedLimit)
        return bets.map { bet ->
            val settlement = gameStore.findSettlement(tenantId, bet.betId)
            val isCashedOut = bet.status == GameBetStatus.CASHED_OUT || settlement?.outcome == GameSettlementOutcome.PAYOUT_CASH_OUT
            UserBetHistoryItem(
                roundId = bet.roundId,
                wagerMinor = bet.wagerMinorUnits,
                currency = bet.currencyCode,
                cashedOut = isCashedOut,
                cashoutAt = settlement?.multiplier?.toDouble(),
                payoutMinor = settlement?.payoutMinorUnits,
                timestampMillis = bet.createdAt.toEpochMilli(),
            )
        }
    }

    fun getTopHistory(tenantId: String, principal: AuthenticatedPrincipal?, limit: Int = 20): List<TopHistoryItem> {
        AuthoritativeGameSnapshotBinding.checkBound()
        val p = principal ?: throw AuthenticationFailure.Rejected(AuthErrorCode.UNAUTHENTICATED)
        if (p.tenantId != tenantId) throw AuthenticationFailure.Rejected(AuthErrorCode.FORBIDDEN)
        val settlements = gameStore.findTopSettlements(tenantId, limit)
        return settlements.map { settlement ->
            val playerUuid = try { UUID.fromString(settlement.ownerId) } catch (e: Exception) { null }
            val reg = playerUuid?.let { registrationStore.findById(tenantId, it) }
            val userName = reg?.maskedEmail ?: settlement.ownerId
            val bet = gameStore.findBet(tenantId, settlement.gameId, settlement.roundId, settlement.ownerId, settlement.handId)
            TopHistoryItem(
                roundId = settlement.roundId,
                userName = userName,
                wagerMinor = bet?.wagerMinorUnits ?: 0L,
                currency = bet?.currencyCode ?: "INR",
                multiplier = settlement.multiplier.toDouble(),
                payoutMinor = settlement.payoutMinorUnits,
                timestampMillis = settlement.settledAt.toEpochMilli(),
            )
        }
    }

    fun getAuthoritativeSnapshot(
        tenantId: String,
        principal: AuthenticatedPrincipal?,
        gameId: String,
        roundId: String? = null,
    ): FullSnapshot {
        AuthoritativeGameSnapshotBinding.checkBound()
        val p = principal ?: throw AuthenticationFailure.Rejected(AuthErrorCode.UNAUTHENTICATED)
        if (p.tenantId != tenantId) throw AuthenticationFailure.Rejected(AuthErrorCode.FORBIDDEN)
        return getAuthoritativeSnapshotForOwner(tenantId, p, p.id, gameId, roundId)
    }

    fun getAuthoritativeSnapshotForOwner(
        tenantId: String,
        principal: AuthenticatedPrincipal?,
        targetOwnerId: String,
        gameId: String,
        roundId: String? = null,
    ): FullSnapshot {
        AuthoritativeGameSnapshotBinding.checkBound()
        val p = principal ?: throw AuthenticationFailure.Rejected(AuthErrorCode.UNAUTHENTICATED)
        if (p.tenantId != tenantId) throw AuthenticationFailure.Rejected(AuthErrorCode.FORBIDDEN)

        // Strict cross-owner IDOR prevention
        if (p.kind == PrincipalKind.PLAYER && p.id != targetOwnerId) {
            throw AuthenticationFailure.Rejected(AuthErrorCode.FORBIDDEN)
        }

        val now = clock.instant()
        val balance = ledgerStore.findBalance(tenantId, "PLAYER:$targetOwnerId", "INR")

        val round = if (roundId != null) {
            gameStore.findRound(tenantId, gameId, roundId)
        } else {
            findActiveRound(tenantId, gameId)
        }

        val primaryHand = buildHandSnapshot(tenantId, gameId, round?.roundId, targetOwnerId, "hand_primary")
        val secondaryHand = buildHandSnapshot(tenantId, gameId, round?.roundId, targetOwnerId, "hand_secondary")

        val serverSeedHash = round?.let {
            fairnessStore.findCommitment(tenantId, gameId, it.roundId)?.commitmentHash
        } ?: ""

        val historyList = getRecentHistoryMultipliers(tenantId, gameId, 10)
        val seqId = eventJournalStore.latestSequenceId(tenantId, gameId)

        val playerUuid = try { UUID.fromString(targetOwnerId) } catch (e: Exception) { null }
        val registration = playerUuid?.let { registrationStore.findById(tenantId, it) }
        val userName = registration?.maskedEmail ?: targetOwnerId

        return FullSnapshot(
            schemaVersion = 1,
            protocolVersion = "1.2.0",
            roundId = round?.roundId,
            phase = round?.phase?.name ?: "NONE",
            serverTimeMillis = now.toEpochMilli(),
            multiplier = round?.currentMultiplier?.toDouble() ?: 1.00,
            elapsedFlightSeconds = if (round?.phase == GameRoundPhase.FLYING) 2.0 else 0.0,
            sequenceId = seqId,
            roundVersion = round?.roundVersion ?: 1L,
            currency = "INR",
            limits = CrashBetLimits(),
            user = SnapshotUser(
                userId = targetOwnerId,
                userName = userName,
                balanceMinor = balance,
                currency = "INR",
            ),
            primaryHand = primaryHand,
            secondaryHand = secondaryHand,
            history = historyList,
            serverSeedHash = serverSeedHash,
        )
    }

    fun getRoundHistory(tenantId: String, gameId: String, limit: Int): List<RoundHistoryEntry> {
        AuthoritativeGameSnapshotBinding.checkBound()
        val finishedRounds = gameStore.findFinishedRounds(tenantId, gameId, limit)

        return finishedRounds.map { r ->
            val hash = fairnessStore.findCommitment(tenantId, gameId, r.roundId)?.commitmentHash ?: ""
            RoundHistoryEntry(
                roundId = r.roundId,
                crashMultiplier = r.crashMultiplier?.toDouble() ?: 1.00,
                timestampMillis = r.updatedAt.toEpochMilli(),
                serverSeedHash = hash,
            )
        }
    }

    fun getCommandResult(
        tenantId: String,
        principal: AuthenticatedPrincipal?,
        gameId: String,
        roundId: String,
        commandId: String,
    ): AviatorCommandAckResult? {
        AuthoritativeGameSnapshotBinding.checkBound()
        return gameService.getCommandResult(tenantId, principal, roundId, commandId)
    }

    fun recordAndBroadcastGameState(
        tenantId: String,
        gameId: String,
        roundId: String,
        phase: GameRoundPhase,
        multiplier: BigDecimal,
        roundVersion: Long,
        elapsedFlightSeconds: Double,
    ): GameEventRecord {
        AuthoritativeGameSnapshotBinding.checkBound()
        val now = clock.instant()
        val sequenceId = eventJournalStore.nextSequenceId(tenantId, gameId)

        val existingRound = gameStore.findRound(tenantId, gameId, roundId)
        if (existingRound != null && (existingRound.roundVersion < roundVersion || existingRound.phase != phase || existingRound.currentMultiplier != multiplier)) {
            val expectedVer = existingRound.roundVersion
            existingRound.phase = phase
            existingRound.currentMultiplier = multiplier
            existingRound.roundVersion = roundVersion
            existingRound.updatedAt = now
            if (phase == GameRoundPhase.CRASHED) {
                existingRound.crashMultiplier = multiplier
                existingRound.crashedAt = now
            }
            gameStore.updateRound(existingRound, expectedVer, legalPriorPhases(phase))
        }

        val payload = mapOf(
            "schemaVersion" to 1,
            "roundId" to roundId,
            "phase" to phase.name,
            "multiplier" to multiplier.toDouble(),
            "currentMultiplier" to multiplier.toDouble(),
            "crashMultiplier" to if (phase == GameRoundPhase.CRASHED || phase == GameRoundPhase.CLOSED) {
                multiplier.toDouble()
            } else null,
            "serverTimeMillis" to now.toEpochMilli(),
            "elapsedFlightSeconds" to elapsedFlightSeconds,
            "sequenceId" to sequenceId,
        )

        val record = GameEventRecord(
            eventId = UUID.randomUUID(),
            tenantId = tenantId,
            gameId = gameId,
            roundId = roundId,
            sequenceId = sequenceId,
            eventName = "gameState",
            payloadJson = objectMapper.writeValueAsString(payload),
            targetScope = "BROADCAST",
            targetOwnerId = null,
            timestampMillis = now.toEpochMilli(),
            createdAt = now,
        )

        eventJournalStore.saveEvent(record)
        return record
    }

    fun hasPublishedPhase(tenantId: String, gameId: String, roundId: String, phase: GameRoundPhase): Boolean =
        eventJournalStore.findEventsForRound(tenantId, gameId, roundId).any { event ->
            runCatching { objectMapper.readTree(event.payloadJson).path("phase").asText() }.getOrNull() == phase.name
        }

    fun resumeEvents(
        tenantId: String,
        gameId: String,
        lastSeenSequenceId: Long,
        maxGapLimit: Int = 50,
    ): SocketResumeOutcome {
        AuthoritativeGameSnapshotBinding.checkBound()
        val latest = eventJournalStore.latestSequenceId(tenantId, gameId)
        val gap = latest - lastSeenSequenceId

        if (gap > maxGapLimit || gap < 0) {
            return SocketResumeOutcome.ResnapshotRequired(
                "Sequence gap of $gap exceeds maximum allowed gap $maxGapLimit"
            )
        }

        val events = eventJournalStore.findEventsSince(tenantId, gameId, lastSeenSequenceId, maxGapLimit)
        return SocketResumeOutcome.EventsReplayed(events)
    }

    fun authenticateSession(tenantId: String, rawSessionToken: String): AuthenticatedPrincipal {
        AuthoritativeGameSnapshotBinding.checkBound()
        val cleanToken = rawSessionToken.trim().removePrefix("Bearer ").trim()
        if (cleanToken.isBlank()) {
            throw AuthenticationFailure.Rejected(AuthErrorCode.UNAUTHENTICATED)
        }

        val authority = authService
            ?: throw SessionStoreOutageException("Authentication authority unavailable")

        val principal = try {
            authority.validateAccessToken(cleanToken)
        } catch (e: AuthenticationFailure.Rejected) {
            throw e
        } catch (e: SessionStoreOutageException) {
            throw e
        } catch (e: Throwable) {
            throw SessionStoreOutageException("Authentication store error during token validation", e)
        } ?: throw AuthenticationFailure.Rejected(AuthErrorCode.UNAUTHENTICATED)

        if (principal.kind != PrincipalKind.PLAYER || principal.tenantId != tenantId) {
            throw AuthenticationFailure.Rejected(AuthErrorCode.FORBIDDEN)
        }
        return principal
    }

    fun getPrivatePlayerRoom(tenantId: String, playerId: String): String = "tenant:$tenantId:player:$playerId"
    fun getGameRoom(tenantId: String, gameId: String): String = "tenant:$tenantId:game:$gameId"

    private fun findActiveRound(tenantId: String, gameId: String): GameRoundRecord? {
        return gameStore.findLatestRound(tenantId, gameId)
    }

    private fun buildHandSnapshot(
        tenantId: String,
        gameId: String,
        roundId: String?,
        ownerId: String,
        handId: String
    ): SnapshotHand {
        if (roundId == null) {
            return SnapshotHand(handId = handId)
        }
        val bet = gameStore.findBet(tenantId, gameId, roundId, ownerId, handId) ?: return SnapshotHand(handId = handId)
        val settlement = gameStore.findSettlement(tenantId, bet.betId)

        return SnapshotHand(
            handId = handId,
            betted = true,
            cashedOut = bet.status == GameBetStatus.CASHED_OUT,
            wagerMinor = bet.wagerMinorUnits,
            currency = bet.currencyCode,
            cashOutMultiplier = settlement?.multiplier?.toDouble(),
            payoutMinor = settlement?.payoutMinorUnits,
        )
    }

    private fun getRecentHistoryMultipliers(tenantId: String, gameId: String, limit: Int): List<Double> {
        return gameStore.findFinishedRounds(tenantId, gameId, limit).mapNotNull { it.crashMultiplier?.toDouble() }
    }
}
