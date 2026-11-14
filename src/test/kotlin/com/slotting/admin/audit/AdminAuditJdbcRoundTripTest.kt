package com.slotting.admin.audit

import com.slotting.admin.rails.RailsAuditEntry
import com.slotting.admin.rails.Slf4jRailsAuditRecorder
import org.junit.jupiter.api.Assumptions.assumeTrue
import org.junit.jupiter.api.Test
import org.springframework.jdbc.core.JdbcTemplate
import org.springframework.jdbc.datasource.DriverManagerDataSource
import java.time.Clock
import java.time.Instant
import kotlin.test.assertEquals
import kotlin.test.assertTrue

class AdminAuditJdbcRoundTripTest {
    @Test
    fun `recorder entry becomes a queryable admin audit row`() {
        assumeTrue(System.getenv("BB10_AUDIT_DB") == "1", "BB10_AUDIT_DB not enabled")
        val url = System.getenv("BB10_AUDIT_URL") ?: "jdbc:postgresql://127.0.0.1:5432/slotting_admin_ci"
        val jdbc = JdbcTemplate(DriverManagerDataSource(url, "ci_runner", ""))
        val store = JdbcAdminAuditStore(jdbc)
        val tenant = "tenant-bb10-audit"
        jdbc.update("delete from admin_audit_event where tenant_id = ?", tenant)
        jdbc.update("delete from admin_operation where tenant_id = ?", tenant)
        val recorder = Slf4jRailsAuditRecorder(store, Clock.systemUTC())
        val now = Instant.now()

        recorder.record(
            RailsAuditEntry(
                tenantId = tenant,
                adminId = "admin-bb10",
                action = "DEPOSIT_APPROVED",
                subjectId = "submission-bb10",
                oldValue = "SUBMITTED",
                newValue = "APPROVED",
                occurredAt = now,
            )
        )

        val rows = store.queryEvents(tenant, "RAILS_DEPOSIT_APPROVED", now.minusSeconds(60), now.plusSeconds(60), 10)
        assertEquals(1, rows.size)
        assertTrue(rows.single().redactedDetails.contains("submission-bb10"))
        jdbc.update("delete from admin_audit_event where tenant_id = ?", tenant)
        jdbc.update("delete from admin_operation where tenant_id = ?", tenant)
    }
}
