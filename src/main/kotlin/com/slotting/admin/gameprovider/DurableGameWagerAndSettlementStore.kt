package com.slotting.admin.gameprovider

import org.springframework.jdbc.core.JdbcTemplate
import org.springframework.stereotype.Repository
import org.springframework.transaction.annotation.Transactional
import java.math.BigDecimal
import java.sql.ResultSet
import java.sql.Timestamp
import java.time.Instant
import java.util.UUID
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.atomic.AtomicLong

interface DurableGameWagerAndSettlementStore {
    fun findRound(tenantId: String, gameId: String, roundId: String): GameRoundRecord?
    fun findRoundForShare(tenantId: String, gameId: String, roundId: String): GameRoundRecord?
    fun findRoundForUpdate(tenantId: String, gameId: String, roundId: String): GameRoundRecord?
    fun saveRound(round: GameRoundRecord)
    fun insertRound(round: GameRoundRecord)
    fun updateRound(round: GameRoundRecord, expectedVersion: Long, allowedPriorPhases: Set<GameRoundPhase> = emptySet())
    fun findBet(tenantId: String, gameId: String, roundId: String, ownerId: String, handId: String): GameAcceptedBetRecord?
    fun findBetsForRound(tenantId: String, gameId: String, roundId: String): List<GameAcceptedBetRecord>
    fun saveBet(bet: GameAcceptedBetRecord)
    fun updateBet(bet: GameAcceptedBetRecord)
    fun findSettlement(tenantId: String, betId: UUID): GameBetSettlementRecord?
    fun saveSettlement(settlement: GameBetSettlementRecord)
    fun findReceipt(tenantId: String, commandId: String): GameCommandReceiptRecord?
    fun saveReceipt(receipt: GameCommandReceiptRecord)
    fun findDailyAccumulatedWager(tenantId: String, playerId: String, currencyCode: String, dailyDate: String): Long
    fun addDailyAccumulatedWager(tenantId: String, playerId: String, currencyCode: String, dailyDate: String, amountMinor: Long)
    fun nextSequenceId(tenantId: String): Long
    fun findLatestRound(tenantId: String, gameId: String): GameRoundRecord?
    fun findFinishedRounds(tenantId: String, gameId: String, limit: Int): List<GameRoundRecord>
    fun findBetsForOwner(tenantId: String, ownerId: String, limit: Int): List<GameAcceptedBetRecord>
    fun findTopSettlements(tenantId: String, limit: Int): List<GameBetSettlementRecord>
}

open class InMemoryDurableGameWagerAndSettlementStore : DurableGameWagerAndSettlementStore {
    private val rounds = ConcurrentHashMap<String, GameRoundRecord>()
    private val bets = ConcurrentHashMap<String, GameAcceptedBetRecord>()
    private val settlements = ConcurrentHashMap<String, GameBetSettlementRecord>()
    private val receipts = ConcurrentHashMap<String, GameCommandReceiptRecord>()
    private val dailyWagers = ConcurrentHashMap<String, Long>()
    private val sequences = ConcurrentHashMap<String, AtomicLong>()

    private fun roundKey(tenantId: String, gameId: String, roundId: String) = "$tenantId:$gameId:$roundId"
    private fun betKey(tenantId: String, gameId: String, roundId: String, ownerId: String, handId: String) = "$tenantId:$gameId:$roundId:$ownerId:$handId"
    private fun settlementKey(tenantId: String, betId: UUID) = "$tenantId:$betId"
    private fun receiptKey(tenantId: String, commandId: String) = "$tenantId:$commandId"
    private fun dailyKey(tenantId: String, playerId: String, currencyCode: String, dailyDate: String) = "$tenantId:$playerId:$currencyCode:$dailyDate"

    override fun findRound(tenantId: String, gameId: String, roundId: String): GameRoundRecord? {
        return rounds[roundKey(tenantId, gameId, roundId)]?.copy()
    }

    override fun findRoundForShare(tenantId: String, gameId: String, roundId: String): GameRoundRecord? {
        return findRound(tenantId, gameId, roundId)
    }

    override fun findRoundForUpdate(tenantId: String, gameId: String, roundId: String): GameRoundRecord? {
        return findRound(tenantId, gameId, roundId)
    }

    @Synchronized
    override fun insertRound(round: GameRoundRecord) {
        val key = roundKey(round.tenantId, round.gameId, round.roundId)
        if (rounds.containsKey(key)) {
            throw RoundVersionConflictException("Round already exists: ${round.roundId}")
        }
        rounds[key] = round.copy()
    }

    @Synchronized
    override fun updateRound(round: GameRoundRecord, expectedVersion: Long, allowedPriorPhases: Set<GameRoundPhase>) {
        val key = roundKey(round.tenantId, round.gameId, round.roundId)
        val existing = rounds[key] ?: throw RoundVersionConflictException("Round not found: ${round.roundId}")
        if (existing.roundVersion != expectedVersion) {
            throw RoundVersionConflictException(
                "Round version mismatch for ${round.roundId}: expected $expectedVersion but found ${existing.roundVersion}"
            )
        }
        if (allowedPriorPhases.isNotEmpty() && existing.phase !in allowedPriorPhases) {
            throw RoundVersionConflictException(
                "Illegal round phase transition for ${round.roundId}: cannot transition from ${existing.phase} to ${round.phase}"
            )
        }
        rounds[key] = round.copy()
    }

    override fun saveRound(round: GameRoundRecord) {
        val key = roundKey(round.tenantId, round.gameId, round.roundId)
        val existing = rounds[key]
        if (existing == null) {
            insertRound(round)
        } else {
            updateRound(round, existing.roundVersion, emptySet())
        }
    }

    override fun findBet(tenantId: String, gameId: String, roundId: String, ownerId: String, handId: String): GameAcceptedBetRecord? {
        return bets[betKey(tenantId, gameId, roundId, ownerId, handId)]?.copy()
    }

    override fun findBetsForRound(tenantId: String, gameId: String, roundId: String): List<GameAcceptedBetRecord> {
        val prefix = "$tenantId:$gameId:$roundId:"
        return bets.filterKeys { it.startsWith(prefix) }.values.map { it.copy() }
    }

    @Synchronized
    override fun saveBet(bet: GameAcceptedBetRecord) {
        val key = betKey(bet.tenantId, bet.gameId, bet.roundId, bet.ownerId, bet.handId)
        if (bets.containsKey(key)) {
            throw IllegalStateException("Duplicate bet for key: $key")
        }
        bets[key] = bet.copy()
    }

    @Synchronized
    override fun updateBet(bet: GameAcceptedBetRecord) {
        val key = betKey(bet.tenantId, bet.gameId, bet.roundId, bet.ownerId, bet.handId)
        bets[key] = bet.copy()
    }

    override fun findSettlement(tenantId: String, betId: UUID): GameBetSettlementRecord? {
        return settlements[settlementKey(tenantId, betId)]?.copy()
    }

    @Synchronized
    override fun saveSettlement(settlement: GameBetSettlementRecord) {
        val key = settlementKey(settlement.tenantId, settlement.betId)
        if (settlements.containsKey(key)) {
            throw IllegalStateException("Duplicate settlement for bet: ${settlement.betId}")
        }
        settlements[key] = settlement.copy()
    }

    override fun findReceipt(tenantId: String, commandId: String): GameCommandReceiptRecord? {
        return receipts[receiptKey(tenantId, commandId)]?.copy()
    }

    @Synchronized
    override fun saveReceipt(receipt: GameCommandReceiptRecord) {
        val key = receiptKey(receipt.tenantId, receipt.commandId)
        if (receipts.containsKey(key)) {
            throw IllegalStateException("Duplicate receipt for command: ${receipt.commandId}")
        }
        receipts[key] = receipt.copy()
    }

    override fun findDailyAccumulatedWager(tenantId: String, playerId: String, currencyCode: String, dailyDate: String): Long {
        return dailyWagers[dailyKey(tenantId, playerId, currencyCode, dailyDate)] ?: 0L
    }

    @Synchronized
    override fun addDailyAccumulatedWager(tenantId: String, playerId: String, currencyCode: String, dailyDate: String, amountMinor: Long) {
        val key = dailyKey(tenantId, playerId, currencyCode, dailyDate)
        val current = dailyWagers[key] ?: 0L
        dailyWagers[key] = Math.addExact(current, amountMinor)
    }

    override fun nextSequenceId(tenantId: String): Long {
        return sequences.computeIfAbsent(tenantId) { AtomicLong(0L) }.incrementAndGet()
    }

    override fun findLatestRound(tenantId: String, gameId: String): GameRoundRecord? {
        val prefix = "$tenantId:$gameId:"
        return rounds.filterKeys { it.startsWith(prefix) }.values
            .sortedWith(
                compareByDescending<GameRoundRecord> { it.startedAt }
                    .thenByDescending { it.updatedAt }
                    .thenByDescending { it.roundId }
            )
            .firstOrNull()?.copy()
    }

    override fun findFinishedRounds(tenantId: String, gameId: String, limit: Int): List<GameRoundRecord> {
        val prefix = "$tenantId:$gameId:"
        return rounds.filterKeys { it.startsWith(prefix) }.values
            .filter { it.phase == GameRoundPhase.CRASHED || it.phase == GameRoundPhase.CLOSED }
            .sortedWith(
                compareByDescending<GameRoundRecord> { it.startedAt }
                    .thenByDescending { it.updatedAt }
                    .thenByDescending { it.roundId }
            )
            .take(limit)
            .map { it.copy() }
    }

    override fun findBetsForOwner(tenantId: String, ownerId: String, limit: Int): List<GameAcceptedBetRecord> {
        return bets.values
            .filter { it.tenantId == tenantId && it.ownerId == ownerId }
            .sortedByDescending { it.createdAt }
            .take(limit)
            .map { it.copy() }
    }

    override fun findTopSettlements(tenantId: String, limit: Int): List<GameBetSettlementRecord> {
        return settlements.values
            .filter { it.tenantId == tenantId && it.outcome == GameSettlementOutcome.PAYOUT_CASH_OUT }
            .sortedByDescending { it.multiplier }
            .take(limit)
            .map { it.copy() }
    }
}

@Repository
open class JdbcDurableGameWagerAndSettlementStore(
    private val jdbcTemplate: JdbcTemplate
) : DurableGameWagerAndSettlementStore {

    override fun findRound(tenantId: String, gameId: String, roundId: String): GameRoundRecord? {
        val sql = """
            select tenant_id, game_id, round_id, phase, round_version, current_multiplier,
                   crash_multiplier, started_at, crashed_at, closed_at, server_time, created_at, updated_at
            from game_authoritative_round
            where tenant_id = ? and game_id = ? and round_id = ?
        """.trimIndent()
        val list = jdbcTemplate.query(sql, { rs, _ -> mapRound(rs) }, tenantId, gameId, roundId)
        return list.firstOrNull()
    }

    override fun findRoundForShare(tenantId: String, gameId: String, roundId: String): GameRoundRecord? {
        val sql = """
            select tenant_id, game_id, round_id, phase, round_version, current_multiplier,
                   crash_multiplier, started_at, crashed_at, closed_at, server_time, created_at, updated_at
            from game_authoritative_round
            where tenant_id = ? and game_id = ? and round_id = ?
            for share
        """.trimIndent()
        val list = jdbcTemplate.query(sql, { rs, _ -> mapRound(rs) }, tenantId, gameId, roundId)
        return list.firstOrNull()
    }

    override fun findRoundForUpdate(tenantId: String, gameId: String, roundId: String): GameRoundRecord? {
        val sql = """
            select tenant_id, game_id, round_id, phase, round_version, current_multiplier,
                   crash_multiplier, started_at, crashed_at, closed_at, server_time, created_at, updated_at
            from game_authoritative_round
            where tenant_id = ? and game_id = ? and round_id = ?
            for update
        """.trimIndent()
        val list = jdbcTemplate.query(sql, { rs, _ -> mapRound(rs) }, tenantId, gameId, roundId)
        return list.firstOrNull()
    }

    @Transactional
    override fun insertRound(round: GameRoundRecord) {
        val sql = """
            insert into game_authoritative_round (
                tenant_id, game_id, round_id, phase, round_version, current_multiplier,
                crash_multiplier, started_at, crashed_at, closed_at, server_time, created_at, updated_at
            ) values (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """.trimIndent()
        try {
            jdbcTemplate.update(
                sql,
                round.tenantId,
                round.gameId,
                round.roundId,
                round.phase.name,
                round.roundVersion,
                round.currentMultiplier,
                round.crashMultiplier,
                Timestamp.from(round.startedAt),
                round.crashedAt?.let { Timestamp.from(it) },
                round.closedAt?.let { Timestamp.from(it) },
                Timestamp.from(round.serverTime),
                Timestamp.from(round.createdAt),
                Timestamp.from(round.updatedAt),
            )
        } catch (e: org.springframework.dao.DuplicateKeyException) {
            throw RoundVersionConflictException("Round already exists: ${round.roundId}")
        }
    }

    @Transactional
    override fun updateRound(round: GameRoundRecord, expectedVersion: Long, allowedPriorPhases: Set<GameRoundPhase>) {
        val phaseClause = if (allowedPriorPhases.isNotEmpty()) {
            " and phase in (${allowedPriorPhases.joinToString(",") { "'${it.name}'" }})"
        } else ""
        val sql = """
            update game_authoritative_round set
                phase = ?,
                round_version = ?,
                current_multiplier = ?,
                crash_multiplier = ?,
                crashed_at = ?,
                closed_at = ?,
                server_time = ?,
                updated_at = ?
            where tenant_id = ? and game_id = ? and round_id = ?
              and round_version = ?$phaseClause
        """.trimIndent()
        val rows = jdbcTemplate.update(
            sql,
            round.phase.name,
            round.roundVersion,
            round.currentMultiplier,
            round.crashMultiplier,
            round.crashedAt?.let { Timestamp.from(it) },
            round.closedAt?.let { Timestamp.from(it) },
            Timestamp.from(round.serverTime),
            Timestamp.from(round.updatedAt),
            round.tenantId,
            round.gameId,
            round.roundId,
            expectedVersion,
        )
        if (rows == 0) {
            throw RoundVersionConflictException(
                "Round update conflict for tenant=${round.tenantId} roundId=${round.roundId}: expectedVersion=$expectedVersion targetVersion=${round.roundVersion} targetPhase=${round.phase}"
            )
        }
    }

    @Transactional
    override fun saveRound(round: GameRoundRecord) {
        val existing = findRound(round.tenantId, round.gameId, round.roundId)
        if (existing == null) {
            insertRound(round)
        } else {
            updateRound(round, existing.roundVersion, emptySet())
        }
    }

    override fun findBet(tenantId: String, gameId: String, roundId: String, ownerId: String, handId: String): GameAcceptedBetRecord? {
        val sql = """
            select bet_id, tenant_id, owner_id, game_id, round_id, hand_id, wager_minor_units,
                   currency_code, reservation_id, ledger_reservation_ref, status, created_at, updated_at
            from game_accepted_bet
            where tenant_id = ? and game_id = ? and round_id = ? and owner_id = ? and hand_id = ?
        """.trimIndent()
        val list = jdbcTemplate.query(sql, { rs, _ -> mapBet(rs) }, tenantId, gameId, roundId, ownerId, handId)
        return list.firstOrNull()
    }

    override fun findBetsForRound(tenantId: String, gameId: String, roundId: String): List<GameAcceptedBetRecord> {
        val sql = """
            select bet_id, tenant_id, owner_id, game_id, round_id, hand_id, wager_minor_units,
                   currency_code, reservation_id, ledger_reservation_ref, status, created_at, updated_at
            from game_accepted_bet
            where tenant_id = ? and game_id = ? and round_id = ?
        """.trimIndent()
        return jdbcTemplate.query(sql, { rs, _ -> mapBet(rs) }, tenantId, gameId, roundId)
    }

    @Transactional
    override fun saveBet(bet: GameAcceptedBetRecord) {
        val sql = """
            insert into game_accepted_bet (
                bet_id, tenant_id, owner_id, game_id, round_id, hand_id, wager_minor_units,
                currency_code, reservation_id, ledger_reservation_ref, status, created_at, updated_at
            ) values (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """.trimIndent()
        jdbcTemplate.update(
            sql,
            bet.betId,
            bet.tenantId,
            bet.ownerId,
            bet.gameId,
            bet.roundId,
            bet.handId,
            bet.wagerMinorUnits,
            bet.currencyCode,
            bet.reservationId,
            bet.ledgerReservationRef,
            bet.status.name,
            Timestamp.from(bet.createdAt),
            Timestamp.from(bet.updatedAt)
        )
    }

    @Transactional
    override fun updateBet(bet: GameAcceptedBetRecord) {
        val sql = """
            update game_accepted_bet
            set status = ?, updated_at = ?
            where bet_id = ? and tenant_id = ?
        """.trimIndent()
        jdbcTemplate.update(
            sql,
            bet.status.name,
            Timestamp.from(bet.updatedAt),
            bet.betId,
            bet.tenantId
        )
    }

    override fun findSettlement(tenantId: String, betId: UUID): GameBetSettlementRecord? {
        val sql = """
            select settlement_id, tenant_id, bet_id, owner_id, game_id, round_id, hand_id,
                   outcome, multiplier, payout_minor_units, ledger_settlement_ref, settled_at, evidence_reference
            from game_bet_settlement
            where tenant_id = ? and bet_id = ?
        """.trimIndent()
        val list = jdbcTemplate.query(sql, { rs, _ -> mapSettlement(rs) }, tenantId, betId)
        return list.firstOrNull()
    }

    @Transactional
    override fun saveSettlement(settlement: GameBetSettlementRecord) {
        val sql = """
            insert into game_bet_settlement (
                settlement_id, tenant_id, bet_id, owner_id, game_id, round_id, hand_id,
                outcome, multiplier, payout_minor_units, ledger_settlement_ref, settled_at, evidence_reference
            ) values (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """.trimIndent()
        jdbcTemplate.update(
            sql,
            settlement.settlementId,
            settlement.tenantId,
            settlement.betId,
            settlement.ownerId,
            settlement.gameId,
            settlement.roundId,
            settlement.handId,
            settlement.outcome.name,
            settlement.multiplier,
            settlement.payoutMinorUnits,
            settlement.ledgerSettlementRef,
            Timestamp.from(settlement.settledAt),
            settlement.evidenceReference
        )
    }

    override fun findReceipt(tenantId: String, commandId: String): GameCommandReceiptRecord? {
        val sql = """
            select receipt_id, tenant_id, owner_id, game_id, command_id, round_id, hand_id,
                   action, status, fingerprint, response_json, causation_id, correlation_id,
                   server_sequence_id, round_version, created_at
            from game_command_receipt
            where tenant_id = ? and command_id = ?
        """.trimIndent()
        val list = jdbcTemplate.query(sql, { rs, _ -> mapReceipt(rs) }, tenantId, commandId)
        return list.firstOrNull()
    }

    @Transactional
    override fun saveReceipt(receipt: GameCommandReceiptRecord) {
        val sql = """
            insert into game_command_receipt (
                receipt_id, tenant_id, owner_id, game_id, command_id, round_id, hand_id,
                action, status, fingerprint, response_json, causation_id, correlation_id,
                server_sequence_id, round_version, created_at
            ) values (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """.trimIndent()
        jdbcTemplate.update(
            sql,
            receipt.receiptId,
            receipt.tenantId,
            receipt.ownerId,
            receipt.gameId,
            receipt.commandId,
            receipt.roundId,
            receipt.handId,
            receipt.action,
            receipt.status,
            receipt.fingerprint,
            receipt.responseJson,
            receipt.causationId,
            receipt.correlationId,
            receipt.serverSequenceId,
            receipt.roundVersion,
            Timestamp.from(receipt.createdAt)
        )
    }

    override fun findDailyAccumulatedWager(tenantId: String, playerId: String, currencyCode: String, dailyDate: String): Long {
        val sql = """
            select accumulated_wager_minor
            from game_cumulative_player_limit
            where tenant_id = ? and player_id = ? and currency_code = ? and daily_date = ?
        """.trimIndent()
        val list = jdbcTemplate.query(sql, { rs, _ -> rs.getLong("accumulated_wager_minor") }, tenantId, playerId, currencyCode, dailyDate)
        return list.firstOrNull() ?: 0L
    }

    @Transactional
    override fun addDailyAccumulatedWager(tenantId: String, playerId: String, currencyCode: String, dailyDate: String, amountMinor: Long) {
        val sql = """
            insert into game_cumulative_player_limit (
                tenant_id, player_id, currency_code, daily_date, accumulated_wager_minor, accumulated_loss_minor, updated_at
            ) values (?, ?, ?, ?, ?, 0, now())
            on conflict (tenant_id, player_id, currency_code, daily_date) do update set
                accumulated_wager_minor = game_cumulative_player_limit.accumulated_wager_minor + excluded.accumulated_wager_minor,
                updated_at = now()
        """.trimIndent()
        jdbcTemplate.update(sql, tenantId, playerId, currencyCode, dailyDate, amountMinor)
    }

    override fun nextSequenceId(tenantId: String): Long {
        val sql = "select coalesce(max(server_sequence_id), 0) + 1 from game_command_receipt where tenant_id = ?"
        return jdbcTemplate.queryForObject(sql, Long::class.java, tenantId) ?: 1L
    }

    override fun findLatestRound(tenantId: String, gameId: String): GameRoundRecord? {
        val sql = """
            select tenant_id, game_id, round_id, phase, round_version, current_multiplier,
                   crash_multiplier, started_at, crashed_at, closed_at, server_time, created_at, updated_at
            from game_authoritative_round
            where tenant_id = ? and game_id = ?
            order by started_at desc, updated_at desc, round_id desc
            limit 1
        """.trimIndent()
        val list = jdbcTemplate.query(sql, { rs, _ -> mapRound(rs) }, tenantId, gameId)
        return list.firstOrNull()
    }

    override fun findFinishedRounds(tenantId: String, gameId: String, limit: Int): List<GameRoundRecord> {
        val sql = """
            select tenant_id, game_id, round_id, phase, round_version, current_multiplier,
                   crash_multiplier, started_at, crashed_at, closed_at, server_time, created_at, updated_at
            from game_authoritative_round
            where tenant_id = ? and game_id = ? and phase in ('CRASHED', 'CLOSED')
            order by started_at desc, updated_at desc, round_id desc
            limit ?
        """.trimIndent()
        return jdbcTemplate.query(sql, { rs, _ -> mapRound(rs) }, tenantId, gameId, limit)
    }

    override fun findBetsForOwner(tenantId: String, ownerId: String, limit: Int): List<GameAcceptedBetRecord> {
        val sql = """
            select bet_id, tenant_id, owner_id, game_id, round_id, hand_id, wager_minor_units,
                   currency_code, reservation_id, ledger_reservation_ref, status, created_at, updated_at
            from game_accepted_bet
            where tenant_id = ? and owner_id = ?
            order by created_at desc
            limit ?
        """.trimIndent()
        return jdbcTemplate.query(sql, { rs, _ -> mapBet(rs) }, tenantId, ownerId, limit)
    }

    override fun findTopSettlements(tenantId: String, limit: Int): List<GameBetSettlementRecord> {
        val sql = """
            select settlement_id, tenant_id, bet_id, owner_id, game_id, round_id, hand_id,
                   outcome, multiplier, payout_minor_units, ledger_settlement_ref, settled_at, evidence_reference
            from game_bet_settlement
            where tenant_id = ? and outcome = 'PAYOUT_CASH_OUT'
            order by multiplier desc
            limit ?
        """.trimIndent()
        return jdbcTemplate.query(sql, { rs, _ -> mapSettlement(rs) }, tenantId, limit)
    }

    private fun mapRound(rs: ResultSet): GameRoundRecord {
        return GameRoundRecord(
            tenantId = rs.getString("tenant_id"),
            gameId = rs.getString("game_id"),
            roundId = rs.getString("round_id"),
            phase = GameRoundPhase.valueOf(rs.getString("phase")),
            roundVersion = rs.getLong("round_version"),
            currentMultiplier = rs.getBigDecimal("current_multiplier"),
            crashMultiplier = rs.getBigDecimal("crash_multiplier"),
            startedAt = rs.getTimestamp("started_at").toInstant(),
            crashedAt = rs.getTimestamp("crashed_at")?.toInstant(),
            closedAt = rs.getTimestamp("closed_at")?.toInstant(),
            serverTime = rs.getTimestamp("server_time").toInstant(),
            createdAt = rs.getTimestamp("created_at").toInstant(),
            updatedAt = rs.getTimestamp("updated_at").toInstant(),
        )
    }

    private fun mapBet(rs: ResultSet): GameAcceptedBetRecord {
        return GameAcceptedBetRecord(
            betId = rs.getObject("bet_id", UUID::class.java),
            tenantId = rs.getString("tenant_id"),
            ownerId = rs.getString("owner_id"),
            gameId = rs.getString("game_id"),
            roundId = rs.getString("round_id"),
            handId = rs.getString("hand_id"),
            wagerMinorUnits = rs.getLong("wager_minor_units"),
            currencyCode = rs.getString("currency_code"),
            reservationId = rs.getObject("reservation_id", UUID::class.java),
            ledgerReservationRef = rs.getString("ledger_reservation_ref"),
            status = GameBetStatus.valueOf(rs.getString("status")),
            createdAt = rs.getTimestamp("created_at").toInstant(),
            updatedAt = rs.getTimestamp("updated_at").toInstant(),
        )
    }

    private fun mapSettlement(rs: ResultSet): GameBetSettlementRecord {
        return GameBetSettlementRecord(
            settlementId = rs.getObject("settlement_id", UUID::class.java),
            tenantId = rs.getString("tenant_id"),
            betId = rs.getObject("bet_id", UUID::class.java),
            ownerId = rs.getString("owner_id"),
            gameId = rs.getString("game_id"),
            roundId = rs.getString("round_id"),
            handId = rs.getString("hand_id"),
            outcome = GameSettlementOutcome.valueOf(rs.getString("outcome")),
            multiplier = rs.getBigDecimal("multiplier"),
            payoutMinorUnits = rs.getLong("payout_minor_units"),
            ledgerSettlementRef = rs.getString("ledger_settlement_ref"),
            settledAt = rs.getTimestamp("settled_at").toInstant(),
            evidenceReference = rs.getString("evidence_reference"),
        )
    }

    private fun mapReceipt(rs: ResultSet): GameCommandReceiptRecord {
        return GameCommandReceiptRecord(
            receiptId = rs.getObject("receipt_id", UUID::class.java),
            tenantId = rs.getString("tenant_id"),
            ownerId = rs.getString("owner_id"),
            gameId = rs.getString("game_id"),
            commandId = rs.getString("command_id"),
            roundId = rs.getString("round_id"),
            handId = rs.getString("hand_id"),
            action = rs.getString("action"),
            status = rs.getString("status"),
            fingerprint = rs.getString("fingerprint"),
            responseJson = rs.getString("response_json"),
            causationId = rs.getString("causation_id"),
            correlationId = rs.getString("correlation_id"),
            serverSequenceId = rs.getLong("server_sequence_id"),
            roundVersion = rs.getLong("round_version"),
            createdAt = rs.getTimestamp("created_at").toInstant(),
        )
    }
}
