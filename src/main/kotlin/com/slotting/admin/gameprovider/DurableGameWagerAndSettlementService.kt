package com.slotting.admin.gameprovider

import com.fasterxml.jackson.databind.ObjectMapper

import com.slotting.admin.auth.AuthErrorCode
import com.slotting.admin.auth.AuthenticatedPrincipal
import com.slotting.admin.auth.AuthenticationFailure
import com.slotting.admin.identity.PlayerAccountStatus
import com.slotting.admin.identity.PlayerRegistrationStore
import com.slotting.admin.identity.ServerEligibilityStore
import com.slotting.admin.ledger.JournalEntryDraft
import com.slotting.admin.ledger.JournalEntryDirection
import com.slotting.admin.ledger.LedgerPostingService
import com.slotting.admin.ledger.PostTransactionCommand
import org.springframework.stereotype.Service
import java.math.BigDecimal
import java.math.RoundingMode
import java.nio.charset.StandardCharsets
import java.security.MessageDigest
import java.time.Clock
import java.time.ZoneOffset
import java.util.UUID

/**
 * Gate to enforce TC-021: Durable game wager reservation and once-only settlement authority.
 * Protected risk: "caller-selected refunds/payouts in Aviator, missing compliance evidence, duplicate/unsettled wagers"
 * Semantic contract: "Every accepted wager maps to one durable reservation; every terminal bet to at most one derived settlement."
 */
object DurableGameWagerAndSettlementBinding {
    @Volatile
    var isBound: Boolean = true

    fun checkBound() {
        if (!isBound) {
            throw AssertionError("durable game wager and settlement authority unbound")
        }
    }
}

class DurableGameWagerAndSettlementService(
    val store: DurableGameWagerAndSettlementStore,
    private val ledgerService: LedgerPostingService,
    private val registrationStore: PlayerRegistrationStore,
    private val eligibilityStore: ServerEligibilityStore,
    private val adminPrincipal: AuthenticatedPrincipal,
    private val clock: Clock = Clock.systemUTC(),
    private val fairnessAuthority: ProvablyFairOutcomeAuthority? = null,
    private val houseMaxRoundExposure: Long = DEFAULT_HOUSE_MAX_ROUND_EXPOSURE,
    val txManager: org.springframework.transaction.PlatformTransactionManager? = null,
) {
    private val objectMapper: ObjectMapper = ObjectMapper().findAndRegisterModules()

    companion object {
        val MAX_PAYOUT_PER_BET: BigDecimal = BigDecimal("100.00")
        val MAX_MULTIPLIER: BigDecimal = BigDecimal("100.00")
        const val DEFAULT_HOUSE_MAX_ROUND_EXPOSURE: Long = 100_000_000L
    }

    fun createOrUpdateRound(command: CreateOrUpdateRoundCommand): GameRoundRecord {
        DurableGameWagerAndSettlementBinding.checkBound()
        val action = {
            val now = clock.instant()
            val existing = store.findRoundForUpdate(command.tenantId, command.gameId, command.roundId)
            if (existing == null) {
                val round = GameRoundRecord(
                    tenantId = command.tenantId,
                    gameId = command.gameId,
                    roundId = command.roundId,
                    phase = command.phase,
                    roundVersion = command.roundVersion,
                    currentMultiplier = command.currentMultiplier,
                    crashMultiplier = command.crashMultiplier,
                    startedAt = now,
                    crashedAt = if (command.phase == GameRoundPhase.CRASHED) now else null,
                    closedAt = if (command.phase == GameRoundPhase.CLOSED) now else null,
                    serverTime = now,
                    createdAt = now,
                    updatedAt = now,
                )
                store.insertRound(round)
                round
            } else {
                val expectedVersion = command.expectedVersion ?: existing.roundVersion
                val targetVersion = if (command.roundVersion > expectedVersion) command.roundVersion else expectedVersion + 1
                val allowedPrior = legalPriorPhases(command.phase)
                if (existing.phase !in allowedPrior) {
                    throw RoundVersionConflictException(
                        "Illegal round phase transition for round ${command.roundId}: cannot transition from ${existing.phase} to ${command.phase}"
                    )
                }
                if (command.phase == GameRoundPhase.FLYING && existing.phase == GameRoundPhase.FLYING) {
                    if (command.currentMultiplier < existing.currentMultiplier) {
                        throw RoundVersionConflictException(
                            "Multiplier cannot regress in FLYING phase for round ${command.roundId}: existing ${existing.currentMultiplier} target ${command.currentMultiplier}"
                        )
                    }
                }
                existing.phase = command.phase
                existing.roundVersion = targetVersion
                existing.currentMultiplier = command.currentMultiplier
                existing.crashMultiplier = command.crashMultiplier ?: existing.crashMultiplier
                existing.serverTime = now
                existing.updatedAt = now
                if (command.phase == GameRoundPhase.CRASHED && existing.crashedAt == null) {
                    existing.crashedAt = now
                }
                if (command.phase == GameRoundPhase.CLOSED && existing.closedAt == null) {
                    existing.closedAt = now
                }
                store.updateRound(existing, expectedVersion, allowedPrior)
                existing
            }
        }
        return txManager?.let { org.springframework.transaction.support.TransactionTemplate(it).execute { action() } } ?: action()
    }

    fun settleRoundCrash(command: SettleRoundCrashCommand): SettleRoundCrashResult {
        DurableGameWagerAndSettlementBinding.checkBound()
        val now = clock.instant()
        val round = store.findRound(command.tenantId, command.gameId, command.roundId)
            ?: createOrUpdateRound(
                CreateOrUpdateRoundCommand(
                    tenantId = command.tenantId,
                    gameId = command.gameId,
                    roundId = command.roundId,
                    phase = GameRoundPhase.CRASHED,
                    crashMultiplier = command.crashMultiplier,
                )
            )

        if (round.phase != GameRoundPhase.CRASHED) {
            val expectedVersion = round.roundVersion
            round.phase = GameRoundPhase.CRASHED
            round.roundVersion = expectedVersion + 1
            round.crashMultiplier = command.crashMultiplier
            round.crashedAt = round.crashedAt ?: now
            round.updatedAt = now
            store.updateRound(round, expectedVersion, legalPriorPhases(GameRoundPhase.CRASHED))
        }

        val pendingBets = store.findBetsForRound(command.tenantId, command.gameId, command.roundId)
            .filter { it.status == GameBetStatus.ACCEPTED }

        var settledCount = 0

        for (bet in pendingBets) {
            // Once-only check: verify not already settled
            if (store.findSettlement(command.tenantId, bet.betId) != null) {
                continue
            }

            val settlementId = UUID.randomUUID()
            val txRef = "TX-CRASH-SWEEP-${command.tenantId}-${command.gameId}-${command.roundId}-${bet.handId}-$settlementId"

            // Sweep escrow to house revenue via double-entry ledger
            ledgerService.postTransaction(
                PostTransactionCommand(
                    principal = adminPrincipal,
                    tenantId = command.tenantId,
                    transactionReference = txRef,
                    currencyCode = bet.currencyCode,
                    entries = listOf(
                        JournalEntryDraft("ESCROW:GAME:${command.gameId}", JournalEntryDirection.DEBIT, bet.wagerMinorUnits, bet.currencyCode),
                        JournalEntryDraft("HOUSE:GAME:${command.gameId}", JournalEntryDirection.CREDIT, bet.wagerMinorUnits, bet.currencyCode),
                    ),
                    idempotencyKey = "IDEM-CRASH-SWEEP-$settlementId",
                    correlationId = "corr-crash-${command.roundId}",
                    causationId = "caus-crash-${command.roundId}",
                )
            )

            bet.status = GameBetStatus.LOST
            bet.updatedAt = now
            store.updateBet(bet)

            store.saveSettlement(
                GameBetSettlementRecord(
                    settlementId = settlementId,
                    tenantId = command.tenantId,
                    betId = bet.betId,
                    ownerId = bet.ownerId,
                    gameId = command.gameId,
                    roundId = command.roundId,
                    handId = bet.handId,
                    outcome = GameSettlementOutcome.LOSS_CRASH,
                    multiplier = BigDecimal.ZERO,
                    payoutMinorUnits = 0L,
                    ledgerSettlementRef = txRef,
                    settledAt = now,
                    evidenceReference = sha256("${command.tenantId}:${bet.betId}:$settlementId:${now.toEpochMilli()}"),
                )
            )
            settledCount++
        }

        return SettleRoundCrashResult(
            roundId = command.roundId,
            settledBetsCount = settledCount,
            crashMultiplier = command.crashMultiplier,
        )
    }

    fun processCommand(command: AviatorRestCommand): AviatorCommandAckResult {
        DurableGameWagerAndSettlementBinding.checkBound()
        val action = { executeCommand(command) }
        return txManager?.let { org.springframework.transaction.support.TransactionTemplate(it).execute { action() } } ?: action()
    }

    private fun executeCommand(command: AviatorRestCommand): AviatorCommandAckResult {
        // 1. Authentication & Tenant Authorization Check
        val principal = command.principal ?: throw AuthenticationFailure.Rejected(AuthErrorCode.UNAUTHENTICATED)
        if (principal.tenantId != command.tenantId) {
            throw AuthenticationFailure.Rejected(AuthErrorCode.FORBIDDEN)
        }
        val playerId = principal.id
        val gameId = "AVIATOR"
        val now = clock.instant()
        val todayStr = now.atZone(ZoneOffset.UTC).toLocalDate().toString()

        // 2. Command Idempotency & Exact Cached Replay
        val fp = computeCommandFingerprint(command)
        val existingReceipt = store.findReceipt(command.tenantId, command.commandId)
        if (existingReceipt != null) {
            if (existingReceipt.fingerprint != fp) {
                throw AuthenticationFailure.Rejected(AuthErrorCode.CONFLICT)
            }
            return objectMapper.readValue(existingReceipt.responseJson, AviatorCommandAckResult::class.java)
        }

        // 3. Resolve Round
        val round = store.findRoundForShare(command.tenantId, gameId, command.roundId)
            ?: run {
                return recordAndReturnRejection(
                    command = command,
                    ownerId = playerId,
                    gameId = gameId,
                    code = AviatorCommandRejectionCode.ROUND_CLOSED,
                    message = "Round ${command.roundId} not found",
                    roundVersion = command.expectedRoundVersion ?: 1L,
                    fp = fp,
                )
            }

        // 4. Currency validation (Strict INR for Aviator)
        if (command.currency != "INR") {
            return recordAndReturnRejection(
                command = command,
                ownerId = playerId,
                gameId = gameId,
                code = AviatorCommandRejectionCode.OUT_OF_LIMITS,
                message = "Unsupported currency: ${command.currency}",
                roundVersion = round.roundVersion,
                fp = fp,
            )
        }

        // 5. Optimistic concurrency round version check
        if (command.expectedRoundVersion != null && command.expectedRoundVersion != round.roundVersion) {
            throw AuthenticationFailure.Rejected(AuthErrorCode.STALE)
        }

        val canonicalAction = when (command.action.uppercase().trim()) {
            "BET", "PLACE_BET" -> AviatorCommandAction.PLACE_BET
            "CANCEL", "CANCEL_BET" -> AviatorCommandAction.CANCEL_BET
            "CASH_OUT", "CASHOUT" -> AviatorCommandAction.CASH_OUT
            else -> try {
                AviatorCommandAction.valueOf(command.action.uppercase().trim())
            } catch (e: Exception) {
                return recordAndReturnRejection(
                    command = command,
                    ownerId = playerId,
                    gameId = gameId,
                    code = AviatorCommandRejectionCode.UNKNOWN,
                    message = "Invalid action: ${command.action}",
                    roundVersion = round.roundVersion,
                    fp = fp,
                )
            }
        }

        return when (canonicalAction) {
            AviatorCommandAction.PLACE_BET -> handlePlaceBet(command, playerId, gameId, round, fp, todayStr)
            AviatorCommandAction.CANCEL_BET -> handleCancelBet(command, playerId, gameId, round, fp)
            AviatorCommandAction.CASH_OUT -> handleCashOut(command, playerId, gameId, round, fp)
        }
    }

    private fun handlePlaceBet(
        command: AviatorRestCommand,
        playerId: String,
        gameId: String,
        round: GameRoundRecord,
        fp: String,
        todayStr: String,
    ): AviatorCommandAckResult {
        val now = clock.instant()

        // Phase check
        if (round.phase != GameRoundPhase.BET_COUNTDOWN && round.phase != GameRoundPhase.SCHEDULED) {
            return recordAndReturnRejection(
                command = command,
                ownerId = playerId,
                gameId = gameId,
                code = AviatorCommandRejectionCode.INVALID_PHASE,
                message = "Betting closed for round in phase ${round.phase}",
                roundVersion = round.roundVersion,
                fp = fp,
            )
        }

        val wagerMinor = command.wagerMinor
        if (wagerMinor == null || wagerMinor <= 0L) {
            return recordAndReturnRejection(
                command = command,
                ownerId = playerId,
                gameId = gameId,
                code = AviatorCommandRejectionCode.OUT_OF_LIMITS,
                message = "Wager amount must be positive minor units",
                roundVersion = round.roundVersion,
                fp = fp,
            )
        }

        // Verify no prior bet exists on this hand for this round
        val existingBet = store.findBet(command.tenantId, gameId, command.roundId, playerId, command.handId)
        if (existingBet != null) {
            return recordAndReturnRejection(
                command = command,
                ownerId = playerId,
                gameId = gameId,
                code = AviatorCommandRejectionCode.INVALID_HAND_STATE,
                message = "Hand ${command.handId} already has an active bet for round ${command.roundId}",
                roundVersion = round.roundVersion,
                fp = fp,
            )
        }

        val playerUuid = try {
            UUID.fromString(playerId)
        } catch (e: Exception) {
            return recordAndReturnRejection(
                command = command,
                ownerId = playerId,
                gameId = gameId,
                code = AviatorCommandRejectionCode.AUTHENTICATION_REQUIRED,
                message = "Invalid player identifier format",
                roundVersion = round.roundVersion,
                fp = fp,
            )
        }

        // Check Player Registration Status
        val registration = registrationStore.findById(command.tenantId, playerUuid)
        if (registration == null || registration.status != PlayerAccountStatus.ACTIVE) {
            return recordAndReturnRejection(
                command = command,
                ownerId = playerId,
                gameId = gameId,
                code = AviatorCommandRejectionCode.INELIGIBLE,
                message = "Player account is not active",
                roundVersion = round.roundVersion,
                fp = fp,
            )
        }

        // Check Affirmative Compliance Profile (BE-024)
        val compliance = eligibilityStore.findComplianceProfile(command.tenantId, playerUuid)
        if (compliance == null) {
            return recordAndReturnRejection(
                command = command,
                ownerId = playerId,
                gameId = gameId,
                code = AviatorCommandRejectionCode.INELIGIBLE,
                message = "Missing affirmative compliance evidence",
                roundVersion = round.roundVersion,
                fp = fp,
            )
        }

        if (compliance.responsiblePlay.selfExcluded) {
            return recordAndReturnRejection(
                command = command,
                ownerId = playerId,
                gameId = gameId,
                code = AviatorCommandRejectionCode.INELIGIBLE,
                message = "Player is currently self-excluded",
                roundVersion = round.roundVersion,
                fp = fp,
            )
        }

        compliance.responsiblePlay.selfExclusionUntil?.let { until ->
            if (until.isAfter(now)) {
                return recordAndReturnRejection(
                    command = command,
                    ownerId = playerId,
                    gameId = gameId,
                    code = AviatorCommandRejectionCode.INELIGIBLE,
                    message = "Player self-exclusion active until $until",
                    roundVersion = round.roundVersion,
                    fp = fp,
                )
            }
        }

        compliance.responsiblePlay.coolOffUntil?.let { until ->
            if (until.isAfter(now)) {
                return recordAndReturnRejection(
                    command = command,
                    ownerId = playerId,
                    gameId = gameId,
                    code = AviatorCommandRejectionCode.INELIGIBLE,
                    message = "Player cool-off active until $until",
                    roundVersion = round.roundVersion,
                    fp = fp,
                )
            }
        }

        compliance.responsiblePlay.singleWagerLimitMinor?.let { limit ->
            if (wagerMinor > limit) {
                return recordAndReturnRejection(
                    command = command,
                    ownerId = playerId,
                    gameId = gameId,
                    code = AviatorCommandRejectionCode.OUT_OF_LIMITS,
                    message = "Wager $wagerMinor exceeds single wager limit $limit",
                    roundVersion = round.roundVersion,
                    fp = fp,
                )
            }
        }

        compliance.responsiblePlay.dailyWagerLimitMinor?.let { dailyLimit ->
            val dailyAccumulated = store.findDailyAccumulatedWager(command.tenantId, playerId, command.currency, todayStr)
            val newTotal = try {
                Math.addExact(dailyAccumulated, wagerMinor)
            } catch (e: ArithmeticException) {
                return recordAndReturnRejection(
                    command = command,
                    ownerId = playerId,
                    gameId = gameId,
                    code = AviatorCommandRejectionCode.OUT_OF_LIMITS,
                    message = "Daily wager limit exceeded (arithmetic overflow)",
                    roundVersion = round.roundVersion,
                    fp = fp,
                )
            }
            if (newTotal > dailyLimit) {
                return recordAndReturnRejection(
                    command = command,
                    ownerId = playerId,
                    gameId = gameId,
                    code = AviatorCommandRejectionCode.OUT_OF_LIMITS,
                    message = "Cumulative daily wager $newTotal exceeds daily limit $dailyLimit",
                    roundVersion = round.roundVersion,
                    fp = fp,
                )
            }
        }

        // Aggregate Round Liability Cap Check
        val currentAcceptedBets = store.findBetsForRound(command.tenantId, gameId, command.roundId)
            .filter { it.status == GameBetStatus.ACCEPTED }
        val currentLiability = currentAcceptedBets.sumOf {
            BigDecimal(it.wagerMinorUnits).multiply(MAX_MULTIPLIER).toLong()
        }
        val additionalLiability = BigDecimal(wagerMinor).multiply(MAX_MULTIPLIER).toLong()
        if (currentLiability + additionalLiability > houseMaxRoundExposure) {
            return recordAndReturnRejection(
                command = command,
                ownerId = playerId,
                gameId = gameId,
                code = AviatorCommandRejectionCode.ROUND_CAPACITY_REACHED,
                message = "Round risk capacity reached (exposure limit exceeded)",
                roundVersion = round.roundVersion,
                fp = fp,
            )
        }

        // Solvency Check against Authoritative Double-Entry Ledger
        val playerBalance = ledgerService.store.findBalance(command.tenantId, "PLAYER:$playerId", command.currency)
        if (playerBalance < wagerMinor) {
            return recordAndReturnRejection(
                command = command,
                ownerId = playerId,
                gameId = gameId,
                code = AviatorCommandRejectionCode.INSUFFICIENT_BALANCE,
                message = "Available balance $playerBalance is less than requested wager $wagerMinor",
                roundVersion = round.roundVersion,
                fp = fp,
            )
        }

        val reservationId = UUID.randomUUID()
        val txRef = "TX-WAGER-${command.tenantId}-$gameId-${command.roundId}-${command.handId}-$reservationId"

        // Double-entry ledger reservation: Debit Player, Credit Escrow
        try {
            ledgerService.postTransaction(
                PostTransactionCommand(
                    principal = adminPrincipal,
                    tenantId = command.tenantId,
                    transactionReference = txRef,
                    currencyCode = command.currency,
                    entries = listOf(
                        JournalEntryDraft("PLAYER:$playerId", JournalEntryDirection.DEBIT, wagerMinor, command.currency),
                        JournalEntryDraft("ESCROW:GAME:$gameId", JournalEntryDirection.CREDIT, wagerMinor, command.currency),
                    ),
                    idempotencyKey = "IDEM-WAGER-$reservationId",
                    correlationId = command.correlationId,
                    causationId = command.causationId,
                )
            )
        } catch (e: Exception) {
            return recordAndReturnRejection(
                command = command,
                ownerId = playerId,
                gameId = gameId,
                code = AviatorCommandRejectionCode.UNKNOWN,
                message = "Ledger reservation posting failed: ${e.message}",
                roundVersion = round.roundVersion,
                fp = fp,
            )
        }

        // Persist accepted bet
        val betRecord = GameAcceptedBetRecord(
            betId = reservationId,
            tenantId = command.tenantId,
            ownerId = playerId,
            gameId = gameId,
            roundId = command.roundId,
            handId = command.handId,
            wagerMinorUnits = wagerMinor,
            currencyCode = command.currency,
            reservationId = reservationId,
            ledgerReservationRef = txRef,
            status = GameBetStatus.ACCEPTED,
            createdAt = now,
            updatedAt = now,
        )
        store.saveBet(betRecord)
        fairnessAuthority?.notifyBetAccepted(
            tenantId = command.tenantId,
            gameId = gameId,
            roundId = command.roundId,
            playerId = playerId,
            clientSeed = command.clientSeed,
        )
        store.addDailyAccumulatedWager(command.tenantId, playerId, command.currency, todayStr, wagerMinor)

        val balanceAfter = ledgerService.store.findBalance(command.tenantId, "PLAYER:$playerId", command.currency)
        val seq = store.nextSequenceId(command.tenantId)
        val evidenceRef = sha256("${command.tenantId}:$reservationId:$txRef:${now.toEpochMilli()}")

        val ack = AviatorCommandAckResult(
            schemaVersion = 1,
            commandId = command.commandId,
            roundId = command.roundId,
            handId = command.handId,
            action = AviatorCommandAction.PLACE_BET,
            status = AviatorCommandAckStatus.ACCEPTED,
            timestampMillis = now.toEpochMilli(),
            sequenceId = seq,
            revision = round.roundVersion,
            causationId = command.causationId,
            result = AviatorAuthoritativeResult(
                handStatus = AviatorAuthoritativeHandStatus.ACCEPTED,
                wagerMinor = wagerMinor,
                accountMoneyAfterMinor = balanceAfter,
                currency = command.currency,
            ),
            evidenceReference = evidenceRef,
        )

        recordReceipt(command, playerId, gameId, fp, ack, round.roundVersion)
        return ack
    }

    private fun handleCancelBet(
        command: AviatorRestCommand,
        playerId: String,
        gameId: String,
        round: GameRoundRecord,
        fp: String,
    ): AviatorCommandAckResult {
        val now = clock.instant()

        // Phase check: cancel is only valid during BET_COUNTDOWN
        if (round.phase != GameRoundPhase.BET_COUNTDOWN && round.phase != GameRoundPhase.SCHEDULED) {
            return recordAndReturnRejection(
                command = command,
                ownerId = playerId,
                gameId = gameId,
                code = AviatorCommandRejectionCode.INVALID_PHASE,
                message = "Bet cannot be cancelled during phase ${round.phase}",
                roundVersion = round.roundVersion,
                fp = fp,
            )
        }

        // Retrieve accepted bet
        val bet = store.findBet(command.tenantId, gameId, command.roundId, playerId, command.handId)
        if (bet == null || bet.status != GameBetStatus.ACCEPTED) {
            return recordAndReturnRejection(
                command = command,
                ownerId = playerId,
                gameId = gameId,
                code = AviatorCommandRejectionCode.INVALID_HAND_STATE,
                message = "No active accepted bet to cancel on hand ${command.handId}",
                roundVersion = round.roundVersion,
                fp = fp,
            )
        }

        // Verify once-only settlement constraint
        if (store.findSettlement(command.tenantId, bet.betId) != null) {
            return recordAndReturnRejection(
                command = command,
                ownerId = playerId,
                gameId = gameId,
                code = AviatorCommandRejectionCode.INVALID_HAND_STATE,
                message = "Bet ${bet.betId} has already been settled",
                roundVersion = round.roundVersion,
                fp = fp,
            )
        }

        // Authoritative refund amount is derived strictly from stored wager
        val refundMinor = bet.wagerMinorUnits
        val settlementId = UUID.randomUUID()
        val txRef = "TX-CANCEL-${command.tenantId}-$gameId-${command.roundId}-${command.handId}-$settlementId"

        // Ledger reversal: Debit Escrow, Credit Player
        ledgerService.postTransaction(
            PostTransactionCommand(
                principal = adminPrincipal,
                tenantId = command.tenantId,
                transactionReference = txRef,
                currencyCode = bet.currencyCode,
                entries = listOf(
                    JournalEntryDraft("ESCROW:GAME:$gameId", JournalEntryDirection.DEBIT, refundMinor, bet.currencyCode),
                    JournalEntryDraft("PLAYER:$playerId", JournalEntryDirection.CREDIT, refundMinor, bet.currencyCode),
                ),
                idempotencyKey = "IDEM-CANCEL-$settlementId",
                correlationId = command.correlationId,
                causationId = command.causationId,
            )
        )

        bet.status = GameBetStatus.CANCELLED
        bet.updatedAt = now
        store.updateBet(bet)

        val evidenceRef = sha256("${command.tenantId}:${bet.betId}:$settlementId:${now.toEpochMilli()}")
        store.saveSettlement(
            GameBetSettlementRecord(
                settlementId = settlementId,
                tenantId = command.tenantId,
                betId = bet.betId,
                ownerId = playerId,
                gameId = gameId,
                roundId = command.roundId,
                handId = command.handId,
                outcome = GameSettlementOutcome.REFUND_CANCEL,
                multiplier = BigDecimal.ONE,
                payoutMinorUnits = refundMinor,
                ledgerSettlementRef = txRef,
                settledAt = now,
                evidenceReference = evidenceRef,
            )
        )

        val balanceAfter = ledgerService.store.findBalance(command.tenantId, "PLAYER:$playerId", bet.currencyCode)
        val seq = store.nextSequenceId(command.tenantId)

        val ack = AviatorCommandAckResult(
            schemaVersion = 1,
            commandId = command.commandId,
            roundId = command.roundId,
            handId = command.handId,
            action = AviatorCommandAction.CANCEL_BET,
            status = AviatorCommandAckStatus.ACCEPTED,
            timestampMillis = now.toEpochMilli(),
            sequenceId = seq,
            revision = round.roundVersion,
            causationId = command.causationId,
            result = AviatorAuthoritativeResult(
                handStatus = AviatorAuthoritativeHandStatus.CANCELLED,
                wagerMinor = refundMinor,
                accountMoneyAfterMinor = balanceAfter,
                currency = bet.currencyCode,
            ),
            evidenceReference = evidenceRef,
        )

        recordReceipt(command, playerId, gameId, fp, ack, round.roundVersion)
        return ack
    }

    private fun handleCashOut(
        command: AviatorRestCommand,
        playerId: String,
        gameId: String,
        round: GameRoundRecord,
        fp: String,
    ): AviatorCommandAckResult {
        val now = clock.instant()

        // Phase check: cash-out is only valid during FLYING
        if (round.phase != GameRoundPhase.FLYING) {
            val rejectionCode = if (round.phase in listOf(GameRoundPhase.CRASHED, GameRoundPhase.CLOSED)) {
                AviatorCommandRejectionCode.ROUND_CLOSED
            } else {
                AviatorCommandRejectionCode.INVALID_PHASE
            }
            return recordAndReturnRejection(
                command = command,
                ownerId = playerId,
                gameId = gameId,
                code = rejectionCode,
                message = "Cash out not permitted in phase ${round.phase}",
                roundVersion = round.roundVersion,
                fp = fp,
            )
        }

        // Server tick authority: if server already marked round crashed or current multiplier exceeds crash multiplier
        val currentServerMultiplier = round.currentMultiplier
        if (round.crashMultiplier != null && currentServerMultiplier > round.crashMultiplier!!) {
            return recordAndReturnRejection(
                command = command,
                ownerId = playerId,
                gameId = gameId,
                code = AviatorCommandRejectionCode.ROUND_CLOSED,
                message = "Round has already crashed",
                roundVersion = round.roundVersion,
                fp = fp,
            )
        }

        // Retrieve accepted bet
        val bet = store.findBet(command.tenantId, gameId, command.roundId, playerId, command.handId)
        if (bet == null || bet.status != GameBetStatus.ACCEPTED) {
            return recordAndReturnRejection(
                command = command,
                ownerId = playerId,
                gameId = gameId,
                code = AviatorCommandRejectionCode.INVALID_HAND_STATE,
                message = "No active accepted bet to cash out on hand ${command.handId}",
                roundVersion = round.roundVersion,
                fp = fp,
            )
        }

        // Verify once-only settlement constraint
        if (store.findSettlement(command.tenantId, bet.betId) != null) {
            return recordAndReturnRejection(
                command = command,
                ownerId = playerId,
                gameId = gameId,
                code = AviatorCommandRejectionCode.INVALID_HAND_STATE,
                message = "Bet ${bet.betId} has already been settled",
                roundVersion = round.roundVersion,
                fp = fp,
            )
        }

        // Authoritative multiplier and payout calculation (derived entirely on server, rejecting client-sent multiplier)
        val authoritativeMultiplier = round.currentMultiplier
        val wagerBd = BigDecimal(bet.wagerMinorUnits)
        val calculatedPayout = wagerBd.multiply(authoritativeMultiplier).setScale(0, RoundingMode.FLOOR).toLong()
        val maxAllowedPayout = wagerBd.multiply(MAX_PAYOUT_PER_BET).setScale(0, RoundingMode.FLOOR).toLong()
        val payoutMinor = minOf(calculatedPayout, maxAllowedPayout)

        val settlementId = UUID.randomUUID()
        val txRef = "TX-CASHOUT-${command.tenantId}-$gameId-${command.roundId}-${command.handId}-$settlementId"

        // Authoritative double-entry ledger settlement
        val entries = mutableListOf<JournalEntryDraft>()
        entries.add(JournalEntryDraft("ESCROW:GAME:$gameId", JournalEntryDirection.DEBIT, bet.wagerMinorUnits, bet.currencyCode))

        if (payoutMinor > bet.wagerMinorUnits) {
            val netWin = Math.subtractExact(payoutMinor, bet.wagerMinorUnits)
            entries.add(JournalEntryDraft("HOUSE:GAME:$gameId", JournalEntryDirection.DEBIT, netWin, bet.currencyCode))
            entries.add(JournalEntryDraft("PLAYER:$playerId", JournalEntryDirection.CREDIT, payoutMinor, bet.currencyCode))
        } else if (payoutMinor < bet.wagerMinorUnits) {
            val netLoss = Math.subtractExact(bet.wagerMinorUnits, payoutMinor)
            entries.add(JournalEntryDraft("HOUSE:GAME:$gameId", JournalEntryDirection.CREDIT, netLoss, bet.currencyCode))
            entries.add(JournalEntryDraft("PLAYER:$playerId", JournalEntryDirection.CREDIT, payoutMinor, bet.currencyCode))
        } else {
            entries.add(JournalEntryDraft("PLAYER:$playerId", JournalEntryDirection.CREDIT, payoutMinor, bet.currencyCode))
        }

        ledgerService.postTransaction(
            PostTransactionCommand(
                principal = adminPrincipal,
                tenantId = command.tenantId,
                transactionReference = txRef,
                currencyCode = bet.currencyCode,
                entries = entries,
                idempotencyKey = "IDEM-CASHOUT-$settlementId",
                correlationId = command.correlationId,
                causationId = command.causationId,
            )
        )

        bet.status = GameBetStatus.CASHED_OUT
        bet.updatedAt = now
        store.updateBet(bet)

        val evidenceRef = sha256("${command.tenantId}:${bet.betId}:$settlementId:${now.toEpochMilli()}")
        store.saveSettlement(
            GameBetSettlementRecord(
                settlementId = settlementId,
                tenantId = command.tenantId,
                betId = bet.betId,
                ownerId = playerId,
                gameId = gameId,
                roundId = command.roundId,
                handId = command.handId,
                outcome = GameSettlementOutcome.PAYOUT_CASH_OUT,
                multiplier = authoritativeMultiplier,
                payoutMinorUnits = payoutMinor,
                ledgerSettlementRef = txRef,
                settledAt = now,
                evidenceReference = evidenceRef,
            )
        )

        val balanceAfter = ledgerService.store.findBalance(command.tenantId, "PLAYER:$playerId", bet.currencyCode)
        val seq = store.nextSequenceId(command.tenantId)

        val ack = AviatorCommandAckResult(
            schemaVersion = 1,
            commandId = command.commandId,
            roundId = command.roundId,
            handId = command.handId,
            action = AviatorCommandAction.CASH_OUT,
            status = AviatorCommandAckStatus.ACCEPTED,
            timestampMillis = now.toEpochMilli(),
            sequenceId = seq,
            revision = round.roundVersion,
            causationId = command.causationId,
            result = AviatorAuthoritativeResult(
                handStatus = AviatorAuthoritativeHandStatus.CASHED_OUT,
                wagerMinor = bet.wagerMinorUnits,
                accountMoneyAfterMinor = balanceAfter,
                currency = bet.currencyCode,
                cashOutMultiplier = authoritativeMultiplier.toDouble(),
                payoutMinor = payoutMinor,
            ),
            evidenceReference = evidenceRef,
        )

        recordReceipt(command, playerId, gameId, fp, ack, round.roundVersion)
        return ack
    }

    fun getCommandResult(
        tenantId: String,
        principal: AuthenticatedPrincipal?,
        roundId: String,
        commandId: String,
    ): AviatorCommandAckResult? {
        DurableGameWagerAndSettlementBinding.checkBound()

        val p = principal ?: throw AuthenticationFailure.Rejected(AuthErrorCode.UNAUTHENTICATED)
        if (p.tenantId != tenantId) throw AuthenticationFailure.Rejected(AuthErrorCode.FORBIDDEN)

        val receipt = store.findReceipt(tenantId, commandId) ?: return null
        if (receipt.roundId != roundId) {
            throw AuthenticationFailure.Rejected(AuthErrorCode.INVALID)
        }
        return objectMapper.readValue(receipt.responseJson, AviatorCommandAckResult::class.java)
    }

    private fun recordReceipt(
        command: AviatorRestCommand,
        ownerId: String,
        gameId: String,
        fp: String,
        ack: AviatorCommandAckResult,
        roundVersion: Long,
    ) {
        val now = clock.instant()
        val json = objectMapper.writeValueAsString(ack)
        val receipt = GameCommandReceiptRecord(
            receiptId = UUID.randomUUID(),
            tenantId = command.tenantId,
            ownerId = ownerId,
            gameId = gameId,
            commandId = command.commandId,
            roundId = command.roundId,
            handId = command.handId,
            action = command.action,
            status = ack.status.name,
            fingerprint = fp,
            responseJson = json,
            causationId = command.causationId,
            correlationId = command.correlationId,
            serverSequenceId = ack.sequenceId,
            roundVersion = roundVersion,
            createdAt = now,
        )
        store.saveReceipt(receipt)
    }

    private fun recordAndReturnRejection(
        command: AviatorRestCommand,
        ownerId: String,
        gameId: String,
        code: AviatorCommandRejectionCode,
        message: String,
        roundVersion: Long,
        fp: String,
    ): AviatorCommandAckResult {
        val now = clock.instant()
        val seq = store.nextSequenceId(command.tenantId)
        val canonicalAction = try {
            AviatorCommandAction.valueOf(command.action.uppercase())
        } catch (e: Exception) {
            AviatorCommandAction.PLACE_BET
        }

        val ack = AviatorCommandAckResult(
            schemaVersion = 1,
            commandId = command.commandId,
            roundId = command.roundId,
            handId = command.handId,
            action = canonicalAction,
            status = AviatorCommandAckStatus.REJECTED,
            timestampMillis = now.toEpochMilli(),
            sequenceId = seq,
            revision = roundVersion,
            causationId = command.causationId,
            rejection = AviatorCommandRejection(
                code = code,
                retryable = false,
                safeMessage = message,
            ),
            evidenceReference = sha256("${command.tenantId}:${command.commandId}:$code:${now.toEpochMilli()}"),
        )
        recordReceipt(command, ownerId, gameId, fp, ack, roundVersion)
        return ack
    }

    private fun computeCommandFingerprint(command: AviatorRestCommand): String {
        val raw = "${command.tenantId}:${command.commandId}:${command.roundId}:${command.handId}:${command.action}:${command.wagerMinor}:${command.currency}"
        return sha256(raw)
    }

    private fun sha256(input: String): String {
        val md = MessageDigest.getInstance("SHA-256")
        val bytes = md.digest(input.toByteArray(StandardCharsets.UTF_8))
        return bytes.joinToString("") { "%02x".format(it) }
    }
}
