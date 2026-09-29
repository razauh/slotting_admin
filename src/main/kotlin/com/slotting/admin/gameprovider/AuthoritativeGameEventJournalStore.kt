package com.slotting.admin.gameprovider

import org.springframework.jdbc.core.JdbcTemplate
import org.springframework.stereotype.Repository
import org.springframework.transaction.annotation.Transactional
import java.sql.ResultSet
import java.sql.Timestamp
import java.util.UUID
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.CopyOnWriteArrayList
import java.util.concurrent.atomic.AtomicLong

interface GameEventJournalStore {
    fun nextSequenceId(tenantId: String, gameId: String): Long
    fun latestSequenceId(tenantId: String, gameId: String): Long
    fun saveEvent(event: GameEventRecord)
    fun findEventsSince(tenantId: String, gameId: String, sinceSequenceId: Long, limit: Int): List<GameEventRecord>
}

open class InMemoryGameEventJournalStore : GameEventJournalStore {
    private val checkpoints = ConcurrentHashMap<String, AtomicLong>()
    private val events = CopyOnWriteArrayList<GameEventRecord>()

    private fun key(tenantId: String, gameId: String) = "$tenantId:$gameId"

    override fun nextSequenceId(tenantId: String, gameId: String): Long {
        return checkpoints.computeIfAbsent(key(tenantId, gameId)) { AtomicLong(0L) }.incrementAndGet()
    }

    override fun latestSequenceId(tenantId: String, gameId: String): Long {
        return checkpoints[key(tenantId, gameId)]?.get() ?: 0L
    }

    override fun saveEvent(event: GameEventRecord) {
        events.add(event)
    }

    override fun findEventsSince(tenantId: String, gameId: String, sinceSequenceId: Long, limit: Int): List<GameEventRecord> {
        return events
            .filter { it.tenantId == tenantId && it.gameId == gameId && it.sequenceId > sinceSequenceId }
            .sortedBy { it.sequenceId }
            .take(limit)
    }
}

@Repository
open class JdbcGameEventJournalStore(
    private val jdbcTemplate: JdbcTemplate
) : GameEventJournalStore {

    @Transactional
    override fun nextSequenceId(tenantId: String, gameId: String): Long {
        val upsertSql = """
            insert into game_socket_sequence_checkpoint (tenant_id, game_id, last_sequence_id, updated_at)
            values (?, ?, 1, now())
            on conflict (tenant_id, game_id) do update
            set last_sequence_id = game_socket_sequence_checkpoint.last_sequence_id + 1, updated_at = now()
            returning last_sequence_id
        """.trimIndent()
        return jdbcTemplate.queryForObject(upsertSql, Long::class.java, tenantId, gameId) ?: 1L
    }

    override fun latestSequenceId(tenantId: String, gameId: String): Long {
        val sql = "select last_sequence_id from game_socket_sequence_checkpoint where tenant_id = ? and game_id = ?"
        val list = jdbcTemplate.query(sql, { rs, _ -> rs.getLong("last_sequence_id") }, tenantId, gameId)
        return list.firstOrNull() ?: 0L
    }

    @Transactional
    override fun saveEvent(event: GameEventRecord) {
        val sql = """
            insert into game_event_journal (
                event_id, tenant_id, game_id, round_id, sequence_id, event_name,
                payload_json, target_scope, target_owner_id, timestamp_millis, created_at
            ) values (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """.trimIndent()
        jdbcTemplate.update(
            sql,
            event.eventId,
            event.tenantId,
            event.gameId,
            event.roundId,
            event.sequenceId,
            event.eventName,
            event.payloadJson,
            event.targetScope,
            event.targetOwnerId,
            event.timestampMillis,
            Timestamp.from(event.createdAt)
        )
    }

    override fun findEventsSince(tenantId: String, gameId: String, sinceSequenceId: Long, limit: Int): List<GameEventRecord> {
        val sql = """
            select event_id, tenant_id, game_id, round_id, sequence_id, event_name,
                   payload_json, target_scope, target_owner_id, timestamp_millis, created_at
            from game_event_journal
            where tenant_id = ? and game_id = ? and sequence_id > ?
            order by sequence_id asc
            limit ?
        """.trimIndent()
        return jdbcTemplate.query(sql, { rs, _ -> mapEvent(rs) }, tenantId, gameId, sinceSequenceId, limit)
    }

    private fun mapEvent(rs: ResultSet): GameEventRecord {
        return GameEventRecord(
            eventId = rs.getObject("event_id", UUID::class.java),
            tenantId = rs.getString("tenant_id"),
            gameId = rs.getString("game_id"),
            roundId = rs.getString("round_id"),
            sequenceId = rs.getLong("sequence_id"),
            eventName = rs.getString("event_name"),
            payloadJson = rs.getString("payload_json"),
            targetScope = rs.getString("target_scope"),
            targetOwnerId = rs.getString("target_owner_id"),
            timestampMillis = rs.getLong("timestamp_millis"),
            createdAt = rs.getTimestamp("created_at").toInstant(),
        )
    }
}
