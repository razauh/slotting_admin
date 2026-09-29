package com.slotting.admin.rg

import org.junit.jupiter.api.Assertions.*
import org.junit.jupiter.api.Test
import java.time.Instant
import java.time.temporal.ChronoUnit
import java.util.UUID

/**
 * Verifies V33 migration script and basic store contracts for durable responsible gaming.
 */
class DurableResponsibleGamingPersistenceContractTest {

    @Test
    fun `V33 migration script exists and defines required durable RG tables`() {
        val stream = javaClass.classLoader.getResourceAsStream("db/migration/V33__durable_responsible_gaming_limits_and_exclusions.sql")
        assertNotNull(stream, "V33 migration must exist on classpath")

        val sql = stream!!.bufferedReader().use { it.readText() }
        assertTrue(sql.contains("create table if not exists rg_limit_configs"), "Must create rg_limit_configs table")
        assertTrue(sql.contains("create table if not exists rg_limit_usages"), "Must create rg_limit_usages table")
        assertTrue(sql.contains("create table if not exists rg_exclusions"), "Must create rg_exclusions table")
        assertTrue(sql.contains("create table if not exists rg_idempotency"), "Must create rg_idempotency table")
        assertTrue(sql.contains("COOL_OFF"), "Must contain COOL_OFF exclusion check")
        assertTrue(sql.contains("SELF_EXCLUSION_DEFINITE"), "Must contain SELF_EXCLUSION_DEFINITE exclusion check")
        assertTrue(sql.contains("SELF_EXCLUSION_PERMANENT"), "Must contain SELF_EXCLUSION_PERMANENT exclusion check")
    }

    @Test
    fun `InMemoryDurableResponsibleGamingStore satisfies durable RG CRUD and idempotency contracts`() {
        val store: DurableResponsibleGamingStore = InMemoryDurableResponsibleGamingStore()
        val now = Instant.parse("2026-09-26T12:00:00Z")
        val tenantId = "tenant-rg-persistence"
        val playerId = "player-rg-pers-1"

        // 1. Limit Config CRUD
        val config = RgLimitConfig(
            limitId = UUID.randomUUID(),
            tenantId = tenantId,
            playerId = playerId,
            limitType = RgLimitType.WAGER,
            period = RgLimitPeriod.DAILY,
            limitValueMinorUnits = 50000L,
            timezone = "UTC",
            productScope = "ALL_PRODUCTS",
            active = true,
            version = 1L,
            createdAt = now,
            updatedAt = now
        )
        assertTrue(store.saveLimitConfig(config, null))
        val foundConfig = store.findLimitConfig(tenantId, playerId, RgLimitType.WAGER)
        assertNotNull(foundConfig)
        assertEquals(50000L, foundConfig?.limitValueMinorUnits)

        // Stale update fails
        assertFalse(store.saveLimitConfig(config.copy(version = 2L), 999L))

        // 2. Limit Usage CRUD
        val usage = RgLimitUsageRecord(
            usageId = UUID.randomUUID(),
            tenantId = tenantId,
            playerId = playerId,
            limitType = RgLimitType.WAGER,
            period = RgLimitPeriod.DAILY,
            periodStart = now.truncatedTo(ChronoUnit.DAYS),
            periodEnd = now.truncatedTo(ChronoUnit.DAYS).plus(1, ChronoUnit.DAYS),
            timezone = "UTC",
            consumedMinorUnits = 10000L,
            version = 1L,
            updatedAt = now
        )
        assertTrue(store.saveUsage(usage, null))
        val foundUsage = store.findUsage(tenantId, playerId, RgLimitType.WAGER, usage.periodStart)
        assertNotNull(foundUsage)
        assertEquals(10000L, foundUsage?.consumedMinorUnits)

        // 3. Exclusion CRUD
        val exclusion = DurableExclusionRecord(
            exclusionId = UUID.randomUUID(),
            tenantId = tenantId,
            playerId = playerId,
            exclusionType = DurableExclusionType.COOL_OFF,
            status = DurableExclusionStatus.ACTIVE,
            effectiveFrom = now,
            expiresAt = now.plus(1, ChronoUnit.DAYS),
            reason = "Test cool off",
            requestedBy = playerId,
            version = 1L,
            createdAt = now,
            updatedAt = now,
            evidenceReference = "EVID-TEST"
        )
        assertTrue(store.saveExclusion(exclusion))
        val activeExcl = store.findActiveExclusion(tenantId, playerId, now.plus(1, ChronoUnit.HOURS))
        assertNotNull(activeExcl)
        assertEquals(exclusion.exclusionId, activeExcl?.exclusionId)

        val expiredExcl = store.findActiveExclusion(tenantId, playerId, now.plus(2, ChronoUnit.DAYS))
        assertNull(expiredExcl, "Must not return expired exclusion as active")
    }
}
