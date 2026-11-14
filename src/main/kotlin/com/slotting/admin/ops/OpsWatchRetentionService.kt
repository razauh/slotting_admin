package com.slotting.admin.ops

import org.slf4j.LoggerFactory
import org.springframework.jdbc.core.JdbcTemplate
import org.springframework.scheduling.annotation.Scheduled
import org.springframework.stereotype.Repository
import org.springframework.stereotype.Service
import java.sql.Timestamp
import java.time.Clock
import java.time.Duration
import java.time.Instant
import java.time.temporal.ChronoUnit

interface RetentionStore {
    fun countRevocations(): Int
    fun countRevocationsBefore(cutoff: Instant): Int
    fun oldestRevocationAt(): Instant?
    fun deleteRevocationsBefore(cutoff: Instant): Int
    fun countExpiredStorage(now: Instant): Int
    fun deleteExpiredStorage(now: Instant): Int
    fun countStorage(): Int
}

@Repository
class JdbcRetentionStore(private val jdbc: JdbcTemplate) : RetentionStore {
    override fun countRevocations(): Int =
        jdbc.queryForObject("select count(*) from public.bridge_session_revocations", Int::class.java) ?: 0

    override fun countRevocationsBefore(cutoff: Instant): Int =
        jdbc.queryForObject(
            "select count(*) from public.bridge_session_revocations where revoked_at < ?",
            Int::class.java,
            Timestamp.from(cutoff)
        ) ?: 0

    override fun oldestRevocationAt(): Instant? =
        jdbc.queryForObject(
            "select min(revoked_at) from public.bridge_session_revocations",
            { rs, _ -> rs.getTimestamp(1)?.toInstant() }
        )

    override fun deleteRevocationsBefore(cutoff: Instant): Int =
        jdbc.update(
            "delete from public.bridge_session_revocations where revoked_at < ?",
            Timestamp.from(cutoff)
        )

    override fun countExpiredStorage(now: Instant): Int =
        jdbc.queryForObject(
            "select count(*) from public.storage_retention where legal_hold = false and retention_expires_at < ?",
            Int::class.java,
            Timestamp.from(now)
        ) ?: 0

    override fun deleteExpiredStorage(now: Instant): Int =
        jdbc.update(
            "delete from public.storage_retention where legal_hold = false and retention_expires_at < ?",
            Timestamp.from(now)
        )

    override fun countStorage(): Int =
        jdbc.queryForObject("select count(*) from public.storage_retention", Int::class.java) ?: 0
}

data class RetentionPruneResult(
    val revocationsDeleted: Int,
    val revocationsRemaining: Int,
    val storageDeleted: Int,
    val storageRemaining: Int,
    val oldestRevocationDays: Int,
    val strandedRevocations: Int,
)

@Service
class OpsWatchRetentionService(
    private val store: RetentionStore,
    private val clock: Clock = Clock.systemUTC(),
    private val revocationTtl: Duration = Duration.ofDays(7),
) {
    private val logger = LoggerFactory.getLogger(javaClass)

    fun prune(): RetentionPruneResult {
        val now = clock.instant()
        val cutoff = now.minus(revocationTtl)
        val beforeRows = store.countRevocations()
        val beforeOldestDays = ageDays(store.oldestRevocationAt(), now)
        val beforeStranded = store.countRevocationsBefore(cutoff)
        val beforeStorage = store.countStorage()
        val revocationsDeleted = store.deleteRevocationsBefore(cutoff)
        val storageDeleted = store.deleteExpiredStorage(now)
        val afterRows = store.countRevocations()
        val afterOldestDays = ageDays(store.oldestRevocationAt(), now)
        val afterStranded = store.countRevocationsBefore(cutoff)
        val afterStorage = store.countStorage()
        logger.info(
            "ops_retention_prune before_rows={} before_oldest_days={} before_stranded={} before_storage={} deleted_revocations={} deleted_storage={} after_rows={} after_oldest_days={} after_stranded={} after_storage={} d4_rows_limit={} d4_age_limit_days={} d4_stranded_limit={}",
            beforeRows,
            beforeOldestDays,
            beforeStranded,
            beforeStorage,
            revocationsDeleted,
            storageDeleted,
            afterRows,
            afterOldestDays,
            afterStranded,
            afterStorage,
            D4_ROW_LIMIT,
            D4_AGE_LIMIT_DAYS,
            D4_STRANDED_LIMIT,
        )
        return RetentionPruneResult(
            revocationsDeleted = revocationsDeleted,
            revocationsRemaining = afterRows,
            storageDeleted = storageDeleted,
            storageRemaining = afterStorage,
            oldestRevocationDays = afterOldestDays,
            strandedRevocations = afterStranded,
        )
    }

    @Scheduled(cron = "\${ops.retention.cron:0 45 2 * * *}", zone = "\${ops.watch.zone:Asia/Karachi}")
    fun pruneScheduled() {
        runCatching { prune() }
            .onFailure { logger.warn("ops_retention_prune_failed reason={}", it.javaClass.simpleName) }
    }

    private fun ageDays(oldest: Instant?, now: Instant): Int =
        if (oldest == null) 0 else ChronoUnit.DAYS.between(oldest, now).coerceAtLeast(0).toInt()

    companion object {
        const val D4_ROW_LIMIT = 10_000
        const val D4_AGE_LIMIT_DAYS = 30
        const val D4_STRANDED_LIMIT = 500
    }
}
