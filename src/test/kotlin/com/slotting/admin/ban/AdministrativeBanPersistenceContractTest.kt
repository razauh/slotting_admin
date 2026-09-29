package com.slotting.admin.ban

import org.junit.jupiter.api.Assertions.*
import org.junit.jupiter.api.Test
import java.time.Instant
import java.time.temporal.ChronoUnit
import java.util.UUID

/**
 * Verifies V32 migration script and basic store contracts for administrative bans.
 */
class AdministrativeBanPersistenceContractTest {

    @Test
    fun `V32 migration script exists and defines required administrative ban tables`() {
        val stream = javaClass.classLoader.getResourceAsStream("db/migration/V32__durable_administrative_bans.sql")
        assertNotNull(stream, "V32 migration must exist on classpath")

        val sql = stream!!.bufferedReader().use { it.readText() }
        assertTrue(sql.contains("create table if not exists administrative_bans"), "Must create administrative_bans table")
        assertTrue(sql.contains("create table if not exists administrative_ban_idempotency"), "Must create administrative_ban_idempotency table")
        assertTrue(sql.contains("TEMPORARY"), "Must contain TEMPORARY check")
        assertTrue(sql.contains("PERMANENT"), "Must contain PERMANENT check")
        assertTrue(sql.contains("ACTIVE"), "Must contain ACTIVE status check")
        assertTrue(sql.contains("REVERSED"), "Must contain REVERSED status check")
        assertTrue(sql.contains("EXPIRED"), "Must contain EXPIRED status check")
    }

    @Test
    fun `InMemoryAdministrativeBanStore satisfies durable ban CRUD and idempotency contracts`() {
        val store: DurableAdministrativeBanStore = InMemoryAdministrativeBanStore()
        val now = Instant.parse("2026-09-26T12:00:00Z")
        val tenantId = "tenant-prod-charlie"
        val subject = "player-sub-5544"

        val ban = AdministrativeBanRecord(
            banId = UUID.randomUUID(),
            tenantId = tenantId,
            subjectReference = subject,
            banType = BanType.TEMPORARY,
            reasonCategory = BanReasonCategory.TERMS_OF_SERVICE_VIOLATION,
            reasonCode = "TOS_ABUSE",
            permittedNote = "Terms of service abuse",
            issuerId = "admin-1",
            effectiveFrom = now.minus(5, ChronoUnit.MINUTES),
            expiresAt = now.plus(1, ChronoUnit.DAYS),
            caseReferenceId = "CASE-5544",
            createdAt = now,
            updatedAt = now
        )

        val audit = com.slotting.admin.auth.AuditEvent(
            eventId = UUID.randomUUID(),
            resultId = ban.banId,
            tenantId = tenantId,
            type = "ADMIN_BAN_ISSUED",
            occurredAt = now,
            correlationId = "corr-1",
            causationId = "cause-1"
        )
        val outbox = com.slotting.admin.auth.OutboxEvent(
            eventId = UUID.randomUUID(),
            resultId = ban.banId,
            tenantId = tenantId,
            type = "ADMIN_BAN_ISSUED",
            createdAt = now
        )

        store.saveBan(ban, audit, outbox)

        val found = store.findBanById(tenantId, ban.banId)
        assertNotNull(found)
        assertEquals(ban.banId, found?.banId)
        assertEquals(BanStatus.ACTIVE, found?.status)

        val active = store.findActiveBanBySubject(tenantId, subject, now)
        assertNotNull(active)
        assertEquals(ban.banId, active?.banId)

        // Update to reversed
        val reversed = ban.copy(
            status = BanStatus.REVERSED,
            reversedAt = now,
            reversedBy = "admin-1",
            reversalReason = "Restored after appeal",
            version = ban.version + 1L,
            updatedAt = now
        )
        val updated = store.updateBan(reversed, audit, outbox)
        assertTrue(updated)

        val postRevoke = store.findActiveBanBySubject(tenantId, subject, now)
        assertNull(postRevoke, "Reversed ban must not be returned as active")
    }
}
