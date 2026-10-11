package com.slotting.admin.gameprovider

import org.springframework.jdbc.core.JdbcTemplate
import org.springframework.stereotype.Repository
import org.springframework.stereotype.Service
import org.springframework.transaction.annotation.Transactional
import java.sql.Timestamp
import java.time.Instant
import java.util.UUID
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.atomic.AtomicLong

enum class LifecycleAttemptStatus { STARTED, COMPLETED, FAILED }

data class LifecycleAttemptRecord(
    val attemptId: UUID,
    val tenantId: String,
    val gameId: String,
    val roundId: String?,
    val attemptNumber: Long,
    val stage: String,
    val ownerId: String?,
    val leaseEpoch: Long?,
    val status: LifecycleAttemptStatus,
    val errorType: String?,
    val errorMessage: String?,
    val startedAt: Instant,
    val finishedAt: Instant?,
    val eventSequence: Long?,
    val settlementReference: String?,
)

interface LifecycleAttemptJournalStore {
    fun start(
        tenantId: String,
        gameId: String,
        roundId: String?,
        stage: String,
        ownerId: String?,
        leaseEpoch: Long?,
        startedAt: Instant,
    ): LifecycleAttemptRecord

    fun complete(attemptId: UUID, finishedAt: Instant, eventSequence: Long? = null, settlementReference: String? = null)
    fun fail(attemptId: UUID, finishedAt: Instant, errorType: String, errorMessage: String?)
    fun find(tenantId: String, gameId: String, roundId: String? = null): List<LifecycleAttemptRecord>
}

open class InMemoryLifecycleAttemptJournalStore : LifecycleAttemptJournalStore {
    private val attempts = ConcurrentHashMap<UUID, LifecycleAttemptRecord>()
    private val counters = ConcurrentHashMap<String, AtomicLong>()

    override fun start(
        tenantId: String,
        gameId: String,
        roundId: String?,
        stage: String,
        ownerId: String?,
        leaseEpoch: Long?,
        startedAt: Instant,
    ): LifecycleAttemptRecord {
        val key = "$tenantId:$gameId:${roundId ?: "-"}"
        val number = counters.computeIfAbsent(key) { AtomicLong() }.incrementAndGet()
        return LifecycleAttemptRecord(UUID.randomUUID(), tenantId, gameId, roundId, number, stage, ownerId, leaseEpoch, LifecycleAttemptStatus.STARTED, null, null, startedAt, null, null, null)
            .also { attempts[it.attemptId] = it }
    }

    override fun complete(attemptId: UUID, finishedAt: Instant, eventSequence: Long?, settlementReference: String?) {
        attempts.computeIfPresent(attemptId) { _, current -> current.copy(status = LifecycleAttemptStatus.COMPLETED, finishedAt = finishedAt, eventSequence = eventSequence, settlementReference = settlementReference) }
    }

    override fun fail(attemptId: UUID, finishedAt: Instant, errorType: String, errorMessage: String?) {
        attempts.computeIfPresent(attemptId) { _, current -> current.copy(status = LifecycleAttemptStatus.FAILED, finishedAt = finishedAt, errorType = errorType.take(160), errorMessage = errorMessage?.take(480)) }
    }

    override fun find(tenantId: String, gameId: String, roundId: String?): List<LifecycleAttemptRecord> =
        attempts.values.filter { it.tenantId == tenantId && it.gameId == gameId && (roundId == null || it.roundId == roundId) }.sortedBy { it.attemptNumber }
}

@Repository
open class JdbcLifecycleAttemptJournalStore(private val jdbc: JdbcTemplate) : LifecycleAttemptJournalStore {
    @Transactional
    override fun start(
        tenantId: String,
        gameId: String,
        roundId: String?,
        stage: String,
        ownerId: String?,
        leaseEpoch: Long?,
        startedAt: Instant,
    ): LifecycleAttemptRecord {
        val id = UUID.randomUUID()
        val number = jdbc.queryForObject(
            "select coalesce(max(attempt_number), 0) + 1 from lifecycle_attempt_journal where tenant_id = ? and game_id = ? and round_id is not distinct from ?",
            Long::class.java,
            tenantId,
            gameId,
            roundId,
        ) ?: 1L
        jdbc.update(
            "insert into lifecycle_attempt_journal (attempt_id, tenant_id, game_id, round_id, attempt_number, stage, owner_id, lease_epoch, status, started_at, created_at) values (?, ?, ?, ?, ?, ?, ?, ?, 'STARTED', ?, now())",
            id, tenantId, gameId, roundId, number, stage, ownerId, leaseEpoch, Timestamp.from(startedAt),
        )
        return LifecycleAttemptRecord(id, tenantId, gameId, roundId, number, stage, ownerId, leaseEpoch, LifecycleAttemptStatus.STARTED, null, null, startedAt, null, null, null)
    }

    override fun complete(attemptId: UUID, finishedAt: Instant, eventSequence: Long?, settlementReference: String?) {
        jdbc.update("update lifecycle_attempt_journal set status = 'COMPLETED', finished_at = ?, event_sequence = ?, settlement_reference = ? where attempt_id = ?", Timestamp.from(finishedAt), eventSequence, settlementReference, attemptId)
    }

    override fun fail(attemptId: UUID, finishedAt: Instant, errorType: String, errorMessage: String?) {
        jdbc.update("update lifecycle_attempt_journal set status = 'FAILED', finished_at = ?, error_type = ?, error_message = ? where attempt_id = ?", Timestamp.from(finishedAt), errorType.take(160), errorMessage?.take(480), attemptId)
    }

    override fun find(tenantId: String, gameId: String, roundId: String?): List<LifecycleAttemptRecord> {
        val sql = if (roundId == null) {
            "select * from lifecycle_attempt_journal where tenant_id = ? and game_id = ? order by attempt_number"
        } else {
            "select * from lifecycle_attempt_journal where tenant_id = ? and game_id = ? and round_id = ? order by attempt_number"
        }
        val args = if (roundId == null) arrayOf(tenantId, gameId) else arrayOf(tenantId, gameId, roundId)
        return jdbc.query(sql, { rs, _ -> LifecycleAttemptRecord(rs.getObject("attempt_id", UUID::class.java), rs.getString("tenant_id"), rs.getString("game_id"), rs.getString("round_id"), rs.getLong("attempt_number"), rs.getString("stage"), rs.getString("owner_id"), rs.getObject("lease_epoch")?.let { rs.getLong("lease_epoch") }, LifecycleAttemptStatus.valueOf(rs.getString("status")), rs.getString("error_type"), rs.getString("error_message"), rs.getTimestamp("started_at").toInstant(), rs.getTimestamp("finished_at")?.toInstant(), rs.getObject("event_sequence")?.let { rs.getLong("event_sequence") }, rs.getString("settlement_reference")) }, *args)
    }
}

data class LifecycleReconciliationReport(
    val tenantId: String,
    val gameId: String,
    val roundId: String,
    val attempts: List<LifecycleAttemptRecord>,
    val invariantReport: FinancialInvariantReport,
    val failedAttempts: Long,
    val attemptCount: Long,
    val journalGapCount: Long,
    val latestAttemptLatencyMillis: Long?,
    val latestFailureStage: String?,
    val latestFailureOwnerId: String?,
    val latestFailureEpoch: Long?,
)

@Service
class AviatorLifecycleReconciliationService(
    private val checker: AviatorFinancialInvariantChecker,
    private val attempts: LifecycleAttemptJournalStore,
) {
    fun reconcile(tenantId: String, gameId: String, roundId: String): LifecycleReconciliationReport {
        val rows = attempts.find(tenantId, gameId, roundId)
        val latestFailure = rows.lastOrNull { it.status == LifecycleAttemptStatus.FAILED }
        val invariantReport = checker.check(tenantId, gameId, roundId)
        val latest = rows.lastOrNull()
        val latency = latest?.finishedAt?.let { finished -> java.time.Duration.between(latest.startedAt, finished).toMillis() }
        return LifecycleReconciliationReport(tenantId, gameId, roundId, rows, invariantReport, rows.count { it.status == LifecycleAttemptStatus.FAILED }.toLong(), rows.size.toLong(), invariantReport.violations.count { it.invariantId == "I8" || it.invariantId == "I9" }.toLong(), latency, latestFailure?.stage, latestFailure?.ownerId, latestFailure?.leaseEpoch)
    }
}
