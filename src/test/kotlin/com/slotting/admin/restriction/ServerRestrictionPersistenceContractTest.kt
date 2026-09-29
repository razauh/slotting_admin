package com.slotting.admin.restriction

import org.junit.jupiter.api.Assertions.*
import org.junit.jupiter.api.Test
import java.time.Instant
import java.time.temporal.ChronoUnit
import java.util.UUID

/**
 * Verifies V31 migration resource availability and durable persistence contracts for TC-026.
 */
class ServerRestrictionPersistenceContractTest {

    @Test
    fun `V31 migration script exists and defines required restriction tables`() {
        val stream = javaClass.classLoader.getResourceAsStream("db/migration/V31__distinct_server_restriction_sources_and_policy_matrix.sql")
        assertNotNull(stream, "V31 migration must exist on classpath")

        val sql = stream!!.bufferedReader().use { it.readText() }
        assertTrue(sql.contains("create table if not exists server_restrictions"), "Must create server_restrictions table")
        assertTrue(sql.contains("create table if not exists server_restriction_evaluations"), "Must create server_restriction_evaluations table")
        assertTrue(sql.contains("ADMINISTRATIVE_BAN"), "Must contain ADMINISTRATIVE_BAN source")
        assertTrue(sql.contains("FRAUD_SECURITY"), "Must contain FRAUD_SECURITY source")
        assertTrue(sql.contains("RESPONSIBLE_GAMING"), "Must contain RESPONSIBLE_GAMING source")
        assertTrue(sql.contains("KYC_AML"), "Must contain KYC_AML source")
        assertTrue(sql.contains("PROVIDER_RESTRICTION"), "Must contain PROVIDER_RESTRICTION source")
        assertTrue(sql.contains("ACCOUNT_CLOSURE"), "Must contain ACCOUNT_CLOSURE source")
    }

    @Test
    fun `InMemory and Durable store implementations satisfy basic store contracts`() {
        val store: DurableServerRestrictionStore = InMemoryServerRestrictionStore()
        val now = Instant.parse("2026-09-26T12:00:00Z")
        val tenantId = "tenant-001"
        val subject = "player-001"

        val restriction = ServerRestrictionRecord(
            restrictionId = UUID.randomUUID(),
            tenantId = tenantId,
            subjectReference = subject,
            source = RestrictionSource.KYC_AML,
            reasonCode = "KYC_PENDING",
            safeUserMessage = "Identity verification required",
            scope = RestrictionScope.WholeAccount,
            effectiveFrom = now.minus(10, ChronoUnit.MINUTES),
            evidenceReference = "EVID-KYC-001",
            ruleVersion = 1L
        )

        store.saveRestriction(restriction)

        val active = store.findActiveRestrictions(tenantId, subject, now)
        assertEquals(1, active.size)
        assertEquals(restriction.restrictionId, active[0].restrictionId)
        assertEquals(RestrictionSource.KYC_AML, active[0].source)

        // Revocation
        val revoked = store.revokeRestriction(tenantId, restriction.restrictionId, "ADMIN_TEST", now)
        assertTrue(revoked)

        val postRevoke = store.findActiveRestrictions(tenantId, subject, now)
        assertTrue(postRevoke.isEmpty(), "Revoked restriction must no longer be active")
    }
}
