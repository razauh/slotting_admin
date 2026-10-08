package com.slotting.admin.gameprovider

import java.math.BigDecimal
import java.time.Instant
import java.util.UUID

enum class GameRoundPhase {
    SCHEDULED,
    BET_COUNTDOWN,
    FLYING,
    CRASHED,
    CLOSED
}

enum class GameBetStatus {
    ACCEPTED,
    CANCELLED,
    CASHED_OUT,
    LOST
}

enum class GameSettlementOutcome {
    REFUND_CANCEL,
    PAYOUT_CASH_OUT,
    LOSS_CRASH
}

data class GameRoundRecord(
    val tenantId: String,
    val gameId: String,
    val roundId: String,
    var phase: GameRoundPhase,
    var roundVersion: Long = 1L,
    var currentMultiplier: BigDecimal = BigDecimal("1.0000"),
    var crashMultiplier: BigDecimal? = null,
    val startedAt: Instant,
    var crashedAt: Instant? = null,
    var closedAt: Instant? = null,
    var serverTime: Instant,
    val createdAt: Instant,
    var updatedAt: Instant,
)

data class GameAcceptedBetRecord(
    val betId: UUID,
    val tenantId: String,
    val ownerId: String,
    val gameId: String,
    val roundId: String,
    val handId: String,
    val wagerMinorUnits: Long,
    val currencyCode: String,
    val reservationId: UUID,
    val ledgerReservationRef: String,
    var status: GameBetStatus,
    val createdAt: Instant,
    var updatedAt: Instant,
)

data class GameBetSettlementRecord(
    val settlementId: UUID,
    val tenantId: String,
    val betId: UUID,
    val ownerId: String,
    val gameId: String,
    val roundId: String,
    val handId: String,
    val outcome: GameSettlementOutcome,
    val multiplier: BigDecimal,
    val payoutMinorUnits: Long,
    val ledgerSettlementRef: String?,
    val settledAt: Instant,
    val evidenceReference: String,
)

data class GameCommandReceiptRecord(
    val receiptId: UUID,
    val tenantId: String,
    val ownerId: String,
    val gameId: String,
    val commandId: String,
    val roundId: String,
    val handId: String,
    val action: String,
    val status: String,
    val fingerprint: String,
    val responseJson: String,
    val causationId: String,
    val correlationId: String,
    val serverSequenceId: Long,
    val roundVersion: Long,
    val createdAt: Instant,
)

data class GameCommandReceiptClaim(
    val receiptId: UUID,
    val tenantId: String,
    val ownerId: String,
    val gameId: String,
    val commandId: String,
    val roundId: String,
    val handId: String,
    val action: String,
    val fingerprint: String,
    val causationId: String,
    val correlationId: String,
    val roundVersion: Long,
    val createdAt: Instant,
)

sealed class CommandReceiptClaimResult {
    data object Claimed : CommandReceiptClaimResult()
    data class AlreadyClaimed(val receipt: GameCommandReceiptRecord) : CommandReceiptClaimResult()
}

class CommandClaimConflictException(message: String) : RuntimeException(message)

class CommandAlreadyClaimedException(message: String) : RuntimeException(message)

class CommandReceiptCompletionException(message: String) : RuntimeException(message)

data class CreateOrUpdateRoundCommand(
    val tenantId: String,
    val gameId: String,
    val roundId: String,
    val phase: GameRoundPhase,
    val roundVersion: Long = 1L,
    val currentMultiplier: BigDecimal = BigDecimal("1.0000"),
    val crashMultiplier: BigDecimal? = null,
    val expectedVersion: Long? = null,
)

data class SettleRoundCrashCommand(
    val tenantId: String,
    val gameId: String,
    val roundId: String,
    val crashMultiplier: BigDecimal,
)

data class SettleRoundCrashResult(
    val roundId: String,
    val settledBetsCount: Int,
    val crashMultiplier: BigDecimal,
)

class RoundVersionConflictException(message: String) : RuntimeException(message)

class CrashStateIntegrityException(message: String) : RuntimeException(message)

fun legalPriorPhases(targetPhase: GameRoundPhase): Set<GameRoundPhase> = when (targetPhase) {
    GameRoundPhase.SCHEDULED -> setOf(GameRoundPhase.SCHEDULED)
    GameRoundPhase.BET_COUNTDOWN -> setOf(GameRoundPhase.SCHEDULED, GameRoundPhase.BET_COUNTDOWN)
    GameRoundPhase.FLYING -> setOf(GameRoundPhase.SCHEDULED, GameRoundPhase.BET_COUNTDOWN, GameRoundPhase.FLYING)
    GameRoundPhase.CRASHED -> setOf(GameRoundPhase.SCHEDULED, GameRoundPhase.BET_COUNTDOWN, GameRoundPhase.FLYING)
    GameRoundPhase.CLOSED -> setOf(GameRoundPhase.CRASHED, GameRoundPhase.SCHEDULED, GameRoundPhase.BET_COUNTDOWN)
}
