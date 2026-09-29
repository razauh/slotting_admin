package com.slotting.admin.analytics

import org.junit.jupiter.api.Assertions.*
import org.junit.jupiter.api.Test
import java.time.Instant
import java.time.LocalDate
import java.util.UUID

/**
 * Verifies V37 migration script and persistence contracts for authoritative analytics facts and projections (TC-034).
 */
class AnalyticsPersistenceContractTest {

    @Test
    fun `V37 migration script defines all required schema objects, indexes, and idempotency constraints`() {
        val stream = javaClass.classLoader.getResourceAsStream("db/migration/V37__authoritative_analytics_facts_and_projections.sql")
        assertNotNull(stream, "V37 migration must exist on classpath")

        val sql = stream!!.bufferedReader().use { it.readText() }
        assertTrue(sql.contains("analytics_facts", ignoreCase = true))
        assertTrue(sql.contains("analytics_daily_projections", ignoreCase = true))
        assertTrue(sql.contains("analytics_unique_players", ignoreCase = true))
        assertTrue(sql.contains("uq_analytics_facts_tenant_source", ignoreCase = true))
        assertTrue(sql.contains("uq_analytics_daily_proj", ignoreCase = true))
        assertTrue(sql.contains("ggr_minor", ignoreCase = true))
        assertTrue(sql.contains("chargebacks_unsupported_marker", ignoreCase = true))
    }

    @Test
    fun `InMemoryAnalyticsStore satisfies fact saving, deduplication, projection update, and unique user tracking`() {
        val store: AnalyticsStore = InMemoryAnalyticsStore()
        val now = Instant.parse("2026-09-26T12:00:00Z")
        val date = LocalDate.of(2026, 9, 26)
        val tenantId = "tenant-persist-analytics"

        // 1. Save and deduplicate facts
        val fact = AnalyticsFact(
            factId = UUID.randomUUID(),
            tenantId = tenantId,
            factType = AnalyticsFactType.GAME_ROUND_SETTLED,
            sourceEventId = "evt-persist-1",
            sourceEventType = "GAME_ROUND_SETTLED",
            userId = "player-persist-1",
            currency = "EUR",
            amountMinor = 5000L,
            payoutMinor = 2000L,
            status = FactStatus.SUCCEEDED,
            occurredAt = now,
            recordedAt = now,
            correlationId = "c-1",
            causationId = "cause-1",
        )

        assertTrue(store.saveFact(fact), "Initial fact save must succeed")
        assertFalse(store.saveFact(fact), "Duplicate fact save must fail idempotently")

        val foundFact = store.findFactBySource(tenantId, "evt-persist-1")
        assertNotNull(foundFact)
        assertEquals(fact.factId, foundFact?.factId)

        // 2. Projection update and retrieval
        val projection = DailyProjectionRecord(
            projectionId = UUID.randomUUID(),
            tenantId = tenantId,
            dateBucket = date,
            currency = "EUR",
            totalWagersMinor = 5000L,
            wagerCount = 1L,
            totalPayoutsMinor = 2000L,
            payoutCount = 1L,
            ggrMinor = 3000L,
            lastProcessedFactTime = now,
            updatedAt = now,
        )

        store.saveOrUpdateProjection(projection)

        val foundProj = store.findProjection(tenantId, date, "EUR")
        assertNotNull(foundProj)
        assertEquals(5000L, foundProj?.totalWagersMinor)
        assertEquals(3000L, foundProj?.ggrMinor)

        // 3. Unique user tracking
        assertTrue(store.recordUniquePlayer(tenantId, date, "player-persist-1", now))
        assertFalse(store.recordUniquePlayer(tenantId, date, "player-persist-1", now.plusSeconds(10)))
        assertEquals(1L, store.countUniquePlayers(tenantId, date, date))

        // 4. Query projections range and filters
        val queried = store.queryProjections(tenantId, date.minusDays(1), date.plusDays(1), "EUR")
        assertEquals(1, queried.size)
        assertEquals(projection.projectionId, queried[0].projectionId)

        val nonMatchingCurrency = store.queryProjections(tenantId, date.minusDays(1), date.plusDays(1), "USD")
        assertTrue(nonMatchingCurrency.isEmpty())
    }
}
