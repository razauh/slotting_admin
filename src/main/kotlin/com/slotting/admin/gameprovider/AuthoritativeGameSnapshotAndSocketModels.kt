package com.slotting.admin.gameprovider

import java.math.BigDecimal
import java.time.Instant
import java.util.UUID

data class CrashBetLimits(
    val schemaVersion: Int = 1,
    val minWagerMinor: Long = 1000L,
    val maxWagerMinor: Long = 10000000L,
    val currency: String = "INR",
)

data class AviatorBootstrapResponse(
    val schemaVersion: Int = 1,
    val gameId: String = "AVIATOR",
    val rulesVersion: String = "1.0.0",
    val protocolVersion: String = "1.2.0",
    val minSupportedProtocolVersion: String = "1.0.0",
    val serverTimeMillis: Long,
    val limits: CrashBetLimits = CrashBetLimits(),
    val activeRoundId: String? = null,
    val phase: String? = null,
)

data class SnapshotUser(
    val userId: String,
    val userName: String,
    val balanceMinor: Long,
    val currency: String = "INR",
)

data class SnapshotHand(
    val handId: String,
    val betted: Boolean = false,
    val cashedOut: Boolean = false,
    val wagerMinor: Long? = null,
    val currency: String = "INR",
    val cashOutMultiplier: Double? = null,
    val payoutMinor: Long? = null,
)

data class FullSnapshot(
    val schemaVersion: Int = 1,
    val protocolVersion: String = "1.2.0",
    val roundId: String? = null,
    val phase: String = "NONE",
    val serverTimeMillis: Long,
    val multiplier: Double = 1.00,
    val elapsedFlightSeconds: Double = 0.0,
    val sequenceId: Long = 0L,
    val roundVersion: Long = 1L,
    val currency: String = "INR",
    val limits: CrashBetLimits = CrashBetLimits(),
    val user: SnapshotUser,
    val primaryHand: SnapshotHand,
    val secondaryHand: SnapshotHand,
    val history: List<Double> = emptyList(),
    val serverSeedHash: String = "",
)

data class RoundHistoryEntry(
    val roundId: String,
    val crashMultiplier: Double,
    val timestampMillis: Long,
    val serverSeedHash: String,
)

data class GameEventRecord(
    val eventId: UUID,
    val tenantId: String,
    val gameId: String,
    val roundId: String,
    val sequenceId: Long,
    val eventName: String,
    val payloadJson: String,
    val targetScope: String,
    val targetOwnerId: String? = null,
    val timestampMillis: Long,
    val createdAt: Instant,
)

sealed class SocketResumeOutcome {
    data class EventsReplayed(val events: List<GameEventRecord>) : SocketResumeOutcome()
    data class ResnapshotRequired(val reason: String) : SocketResumeOutcome()
}

data class UserBetHistoryItem(
    val roundId: String,
    val wagerMinor: Long,
    val currency: String = "INR",
    val cashedOut: Boolean,
    val cashoutAt: Double? = null,
    val payoutMinor: Long? = null,
    val timestampMillis: Long,
)

data class TopHistoryItem(
    val roundId: String,
    val userName: String,
    val wagerMinor: Long,
    val currency: String = "INR",
    val multiplier: Double,
    val payoutMinor: Long,
    val timestampMillis: Long,
)

