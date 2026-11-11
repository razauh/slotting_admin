package com.slotting.admin.ops

import org.junit.jupiter.api.Test
import java.sql.DriverManager
import java.time.Clock
import java.time.Instant
import java.time.ZoneOffset
import java.util.UUID
import kotlin.test.assertEquals
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue

class JdbcOpsRepositoryRoundTripTest {
    private val url = System.getenv("OPS_WATCH_JDBC_URL") ?: "jdbc:postgresql://127.0.0.1:55433/slotting_restore"
    private val user = System.getenv("OPS_WATCH_JDBC_USER") ?: "ci_runner"
    private fun connection(): java.sql.Connection = DriverManager.getConnection(url, user, "")
    private val repository = JdbcOpsNoticeRepository { connection() }
    private val decisions = JdbcOpsDecisionRepository { connection() }
    private val clock = Clock.fixed(Instant.parse("2026-11-10T12:00:00Z"), ZoneOffset.UTC)
    private val cause = "TEST_DEDUPE_" + UUID.randomUUID()

    private fun cleanup() {
        val connection = connection()
        try {
            val statement = connection.prepareStatement("delete from public.ops_notices where cause like 'TEST_%'")
            statement.executeUpdate()
            statement.close()
        } finally {
            connection.close()
        }
    }

    private fun notice(cause: String) = OpsNotice(
        cause = cause,
        classTag = "TEST",
        severity = OpsSeverity.WARNING,
        text = "test notice",
        createdAt = clock.instant(),
    )

    private fun ackedCount(cause: String): Int {
        val connection = connection()
        try {
            val statement = connection.prepareStatement("select count(*) from public.ops_notices where cause = ? and acknowledged_utc is not null")
            statement.setString(1, cause)
            val rows = statement.executeQuery()
            rows.next()
            val value = rows.getInt(1)
            rows.close()
            statement.close()
            return value
        } finally {
            connection.close()
        }
    }

    @Test
    fun `open dedupes the same cause through JDBC`() {
        cleanup()
        try {
            assertTrue(repository.open(notice(cause)))
            assertTrue(!repository.open(notice(cause)))
            assertEquals(1, repository.list().filter { it.cause == cause }.size)
        } finally {
            cleanup()
        }
    }

    @Test
    fun `ack is idempotent through JDBC`() {
        cleanup()
        try {
            repository.open(notice(cause))
            assertTrue(repository.ack(cause))
            assertTrue(repository.ack(cause))
            assertEquals(1, ackedCount(cause))
        } finally {
            cleanup()
        }
    }

    @Test
    fun `registry escalation causes persist per item`() {
        cleanup()
        try {
            val watch = OpsWatchService(repository, clock)
            val rows = decisions.all()
            assertEquals(5, rows.size)
            val unscheduled = rows.filter { it.status == OpsDecisionStatus.UNSCHEDULED }
            assertEquals(5, unscheduled.size)
            watch.registryEscalations(unscheduled, java.time.LocalDate.parse("2026-11-10")).forEach { repository.open(it) }
            val persisted = repository.list().filter { it.cause.startsWith("DECISION_") }
            assertEquals(5, persisted.size)
            assertTrue(persisted.all { it.classTag == "DECISION" })
        } finally {
            cleanup()
        }
    }

    @Test
    fun `seeded registry rows stay owner absent and unscheduled`() {
        val rows = decisions.all()
        assertEquals(5, rows.size)
        rows.forEach { row ->
            assertNull(row.owner)
            assertEquals(OpsDecisionStatus.UNSCHEDULED, row.status)
            assertNull(row.dueDate)
            assertNotNull(row.reopenTrigger)
        }
    }
}
