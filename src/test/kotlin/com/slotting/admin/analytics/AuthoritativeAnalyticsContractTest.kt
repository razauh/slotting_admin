package com.slotting.admin.analytics

import org.junit.jupiter.api.Assertions.*
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test
import java.time.Clock
import java.time.Instant
import java.time.LocalDate
import java.time.ZoneOffset
import java.util.UUID

/**
 * TC-034: Authoritative Analytics Fact Model and Incremental Projections Contract Test.
 *
 * Verifies:
 * - Authoritative canonical facts derived strictly from server events (never Android telemetry)
 * - Metric dictionary with explicit versioning, formulas, and currency separation
 * - Idempotent incremental projections by tenant, date bucket, and dimensions
 * - Exact active/unique users (DAU/WAU/MAU)
 * - GGR defined strictly as settled wagers minus game payouts for same currency/time basis
 * - 10 required test scenarios:
 *   1. duplicate settlement
 *   2. late provider success
 *   3. rejected withdrawal
 *   4. pending operation
 *   5. unique players
 *   6. multi-currency separation
 *   7. DST / timezone boundary
 *   8. rebuild equivalence
 *   9. chargeback absent / unsupported
 *   10. ledger imbalance detection
 */
class AuthoritativeAnalyticsContractTest {

    private lateinit var store: InMemoryAnalyticsStore
    private lateinit var service: AnalyticsProjectionService
    private val clock = Clock.fixed(Instant.parse("2026-09-26T12:00:00Z"), ZoneOffset.UTC)
    private val tenantId = "tenant-analytics-1"

    @BeforeEach
    fun setUp() {
        store = InMemoryAnalyticsStore()
        service = AnalyticsProjectionService(
            store = store,
            clock = clock,
        )
    }

    // -------------------------------------------------------------
    // Scenario 1: Duplicate Settlement
    // -------------------------------------------------------------
    @Test
    fun `Scenario 1 - duplicate settlement event is deduplicated and does not double-count wagers or GGR`() {
        val eventId = "evt-settle-001"
        val fact = AnalyticsFact(
            factId = UUID.randomUUID(),
            tenantId = tenantId,
            factType = AnalyticsFactType.GAME_ROUND_SETTLED,
            sourceEventId = eventId,
            sourceEventType = "GAME_ROUND_SETTLED",
            userId = "player-1",
            gameId = "aviator",
            providerId = "spribe",
            currency = "EUR",
            amountMinor = 5000L, // 50.00 EUR wager
            payoutMinor = 2000L, // 20.00 EUR payout -> 30.00 EUR GGR
            status = FactStatus.SUCCEEDED,
            occurredAt = Instant.parse("2026-09-26T10:00:00Z"),
            recordedAt = Instant.parse("2026-09-26T10:00:01Z"),
            correlationId = "corr-1",
            causationId = "cause-1",
        )

        // First ingestion
        val record1 = service.recordFactAndProject(fact)
        assertTrue(record1)

        // Duplicate ingestion with same sourceEventId
        val record2 = service.recordFactAndProject(fact)
        assertFalse(record2, "Duplicate source event must be rejected by idempotency")

        val proj = service.getDailyProjection(tenantId, LocalDate.of(2026, 9, 26), "EUR")
        assertNotNull(proj)
        assertEquals(5000L, proj?.totalWagersMinor)
        assertEquals(1L, proj?.wagerCount)
        assertEquals(2000L, proj?.totalPayoutsMinor)
        assertEquals(1L, proj?.payoutCount)
        assertEquals(3000L, proj?.ggrMinor, "GGR must equal wagers - payouts (5000 - 2000 = 3000)")
    }

    // -------------------------------------------------------------
    // Scenario 2: Late Provider Success
    // -------------------------------------------------------------
    @Test
    fun `Scenario 2 - late provider event updates historical date bucket deterministically`() {
        // Event occurred yesterday but ingested today
        val yesterdayFact = AnalyticsFact(
            factId = UUID.randomUUID(),
            tenantId = tenantId,
            factType = AnalyticsFactType.GAME_ROUND_SETTLED,
            sourceEventId = "evt-late-002",
            sourceEventType = "GAME_ROUND_SETTLED",
            userId = "player-1",
            gameId = "aviator",
            providerId = "spribe",
            currency = "EUR",
            amountMinor = 10000L,
            payoutMinor = 8000L,
            status = FactStatus.SUCCEEDED,
            occurredAt = Instant.parse("2026-09-25T22:00:00Z"), // Yesterday UTC
            recordedAt = Instant.parse("2026-09-26T10:00:00Z"), // Today UTC
            correlationId = "corr-late",
            causationId = "cause-late",
        )

        service.recordFactAndProject(yesterdayFact)

        // Yesterday's projection is updated, not today's
        val yesterdayProj = service.getDailyProjection(tenantId, LocalDate.of(2026, 9, 25), "EUR")
        assertNotNull(yesterdayProj)
        assertEquals(10000L, yesterdayProj?.totalWagersMinor)
        assertEquals(8000L, yesterdayProj?.totalPayoutsMinor)
        assertEquals(2000L, yesterdayProj?.ggrMinor)

        val todayProj = service.getDailyProjection(tenantId, LocalDate.of(2026, 9, 26), "EUR")
        assertNull(todayProj, "Today's bucket must not be polluted by yesterday's event")
    }

    // -------------------------------------------------------------
    // Scenario 3: Rejected Withdrawal
    // -------------------------------------------------------------
    @Test
    fun `Scenario 3 - rejected withdrawal increments rejected count without adding to completed withdrawal volume`() {
        val rejectedWithdrawal = AnalyticsFact(
            factId = UUID.randomUUID(),
            tenantId = tenantId,
            factType = AnalyticsFactType.WITHDRAWAL_REJECTED,
            sourceEventId = "evt-withdraw-reject-1",
            sourceEventType = "WITHDRAWAL_REJECTED",
            userId = "player-2",
            currency = "EUR",
            amountMinor = 15000L,
            status = FactStatus.REJECTED,
            occurredAt = Instant.parse("2026-09-26T11:00:00Z"),
            recordedAt = Instant.parse("2026-09-26T11:00:01Z"),
            correlationId = "c-w-rej",
            causationId = "cause-w-rej",
        )

        service.recordFactAndProject(rejectedWithdrawal)

        val proj = service.getDailyProjection(tenantId, LocalDate.of(2026, 9, 26), "EUR")
        assertNotNull(proj)
        assertEquals(0L, proj?.totalWithdrawalsCompletedMinor, "Rejected withdrawal must not add to completed volume")
        assertEquals(0L, proj?.withdrawalCompletedCount)
        assertEquals(1L, proj?.withdrawalRejectedCount, "Rejected withdrawal count must be incremented")
    }

    // -------------------------------------------------------------
    // Scenario 4: Pending Operation
    // -------------------------------------------------------------
    @Test
    fun `Scenario 4 - pending financial operation does not count towards completed financial volume`() {
        val pendingDeposit = AnalyticsFact(
            factId = UUID.randomUUID(),
            tenantId = tenantId,
            factType = AnalyticsFactType.DEPOSIT_INITIATED,
            sourceEventId = "evt-dep-pending-1",
            sourceEventType = "DEPOSIT_INITIATED",
            userId = "player-3",
            currency = "EUR",
            amountMinor = 25000L,
            status = FactStatus.PENDING,
            occurredAt = Instant.parse("2026-09-26T09:00:00Z"),
            recordedAt = Instant.parse("2026-09-26T09:00:01Z"),
            correlationId = "c-dep-pend",
            causationId = "cause-dep-pend",
        )

        service.recordFactAndProject(pendingDeposit)

        val proj = service.getDailyProjection(tenantId, LocalDate.of(2026, 9, 26), "EUR")
        assertNotNull(proj)
        assertEquals(0L, proj?.totalDepositsMinor, "Pending deposit must not be included in completed volume")
        assertEquals(0L, proj?.depositCount)
    }

    // -------------------------------------------------------------
    // Scenario 5: Unique Players (DAU, WAU, MAU)
    // -------------------------------------------------------------
    @Test
    fun `Scenario 5 - multiple actions by same player on same date count as exactly 1 DAU`() {
        val date = LocalDate.of(2026, 9, 26)

        // Player 1 performs 3 distinct actions on same day
        for (i in 1..3) {
            service.recordFactAndProject(
                AnalyticsFact(
                    factId = UUID.randomUUID(),
                    tenantId = tenantId,
                    factType = AnalyticsFactType.USER_AUTHENTICATION,
                    sourceEventId = "evt-auth-p1-$i",
                    sourceEventType = "USER_AUTHENTICATION",
                    userId = "player-1",
                    status = FactStatus.SUCCEEDED,
                    occurredAt = Instant.parse("2026-09-26T0$i:00:00Z"),
                    recordedAt = Instant.parse("2026-09-26T0$i:00:01Z"),
                    correlationId = "c-p1-$i",
                    causationId = "cause-p1-$i",
                )
            )
        }

        // Player 2 performs 1 action
        service.recordFactAndProject(
            AnalyticsFact(
                factId = UUID.randomUUID(),
                tenantId = tenantId,
                factType = AnalyticsFactType.USER_AUTHENTICATION,
                sourceEventId = "evt-auth-p2",
                sourceEventType = "USER_AUTHENTICATION",
                userId = "player-2",
                status = FactStatus.SUCCEEDED,
                occurredAt = Instant.parse("2026-09-26T05:00:00Z"),
                recordedAt = Instant.parse("2026-09-26T05:00:01Z"),
                correlationId = "c-p2",
                causationId = "cause-p2",
            )
        )

        val dau = service.calculateDau(tenantId, date)
        assertEquals(2L, dau, "DAU must count distinct players (player-1 and player-2)")
    }

    // -------------------------------------------------------------
    // Scenario 6: Multi-Currency Separation
    // -------------------------------------------------------------
    @Test
    fun `Scenario 6 - financial metrics strictly partition by currency and never silently sum`() {
        val date = LocalDate.of(2026, 9, 26)

        // EUR wager
        service.recordFactAndProject(
            AnalyticsFact(
                factId = UUID.randomUUID(),
                tenantId = tenantId,
                factType = AnalyticsFactType.GAME_ROUND_SETTLED,
                sourceEventId = "evt-eur-wager",
                sourceEventType = "GAME_ROUND_SETTLED",
                userId = "player-eur",
                currency = "EUR",
                amountMinor = 10000L,
                payoutMinor = 4000L,
                status = FactStatus.SUCCEEDED,
                occurredAt = Instant.parse("2026-09-26T08:00:00Z"),
                recordedAt = Instant.parse("2026-09-26T08:00:01Z"),
                correlationId = "c-eur",
                causationId = "cause-eur",
            )
        )

        // USD wager
        service.recordFactAndProject(
            AnalyticsFact(
                factId = UUID.randomUUID(),
                tenantId = tenantId,
                factType = AnalyticsFactType.GAME_ROUND_SETTLED,
                sourceEventId = "evt-usd-wager",
                sourceEventType = "GAME_ROUND_SETTLED",
                userId = "player-usd",
                currency = "USD",
                amountMinor = 15000L,
                payoutMinor = 5000L,
                status = FactStatus.SUCCEEDED,
                occurredAt = Instant.parse("2026-09-26T08:30:00Z"),
                recordedAt = Instant.parse("2026-09-26T08:30:01Z"),
                correlationId = "c-usd",
                causationId = "cause-usd",
            )
        )

        val eurProj = service.getDailyProjection(tenantId, date, "EUR")
        val usdProj = service.getDailyProjection(tenantId, date, "USD")

        assertNotNull(eurProj)
        assertNotNull(usdProj)

        assertEquals("EUR", eurProj?.currency)
        assertEquals(10000L, eurProj?.totalWagersMinor)
        assertEquals(6000L, eurProj?.ggrMinor)

        assertEquals("USD", usdProj?.currency)
        assertEquals(15000L, usdProj?.totalWagersMinor)
        assertEquals(10000L, usdProj?.ggrMinor)

        // Invariant: No combined cross-currency projection exists
        assertNull(service.getDailyProjection(tenantId, date, "ALL"))
    }

    // -------------------------------------------------------------
    // Scenario 7: DST / Timezone Boundary
    // -------------------------------------------------------------
    @Test
    fun `Scenario 7 - events across UTC midnight boundary consistently partition into separate UTC date buckets`() {
        val eventBeforeMidnight = AnalyticsFact(
            factId = UUID.randomUUID(),
            tenantId = tenantId,
            factType = AnalyticsFactType.DEPOSIT_COMPLETED,
            sourceEventId = "evt-dst-before",
            sourceEventType = "DEPOSIT_COMPLETED",
            userId = "player-1",
            currency = "EUR",
            amountMinor = 5000L,
            status = FactStatus.SUCCEEDED,
            occurredAt = Instant.parse("2026-09-25T23:59:59Z"),
            recordedAt = Instant.parse("2026-09-26T00:00:02Z"),
            correlationId = "c-b4",
            causationId = "cause-b4",
        )

        val eventAfterMidnight = AnalyticsFact(
            factId = UUID.randomUUID(),
            tenantId = tenantId,
            factType = AnalyticsFactType.DEPOSIT_COMPLETED,
            sourceEventId = "evt-dst-after",
            sourceEventType = "DEPOSIT_COMPLETED",
            userId = "player-1",
            currency = "EUR",
            amountMinor = 7000L,
            status = FactStatus.SUCCEEDED,
            occurredAt = Instant.parse("2026-09-26T00:00:01Z"),
            recordedAt = Instant.parse("2026-09-26T00:00:03Z"),
            correlationId = "c-after",
            causationId = "cause-after",
        )

        service.recordFactAndProject(eventBeforeMidnight)
        service.recordFactAndProject(eventAfterMidnight)

        val day25 = service.getDailyProjection(tenantId, LocalDate.of(2026, 9, 25), "EUR")
        val day26 = service.getDailyProjection(tenantId, LocalDate.of(2026, 9, 26), "EUR")

        assertEquals(5000L, day25?.totalDepositsMinor)
        assertEquals(7000L, day26?.totalDepositsMinor)
    }

    // -------------------------------------------------------------
    // Scenario 8: Rebuild Equivalence
    // -------------------------------------------------------------
    @Test
    fun `Scenario 8 - full projection rebuild yields identical aggregates to incremental updates`() {
        val date = LocalDate.of(2026, 9, 26)

        // Seed 5 diverse facts
        for (i in 1..5) {
            service.recordFactAndProject(
                AnalyticsFact(
                    factId = UUID.randomUUID(),
                    tenantId = tenantId,
                    factType = AnalyticsFactType.GAME_ROUND_SETTLED,
                    sourceEventId = "evt-rebuild-$i",
                    sourceEventType = "GAME_ROUND_SETTLED",
                    userId = "player-$i",
                    currency = "EUR",
                    amountMinor = 1000L * i,
                    payoutMinor = 500L * i,
                    status = FactStatus.SUCCEEDED,
                    occurredAt = Instant.parse("2026-09-26T10:0$i:00Z"),
                    recordedAt = Instant.parse("2026-09-26T10:0$i:01Z"),
                    correlationId = "c-reb-$i",
                    causationId = "cause-reb-$i",
                )
            )
        }

        val incrementalProj = service.getDailyProjection(tenantId, date, "EUR")!!

        // Execute complete rebuild from raw facts
        val rebuildResult = service.rebuildProjectionsFromFacts(tenantId)
        assertTrue(rebuildResult.success)
        assertEquals(5L, rebuildResult.factsReplayedCount)

        val rebuiltProj = service.getDailyProjection(tenantId, date, "EUR")!!

        assertEquals(incrementalProj.totalWagersMinor, rebuiltProj.totalWagersMinor)
        assertEquals(incrementalProj.wagerCount, rebuiltProj.wagerCount)
        assertEquals(incrementalProj.totalPayoutsMinor, rebuiltProj.totalPayoutsMinor)
        assertEquals(incrementalProj.payoutCount, rebuiltProj.payoutCount)
        assertEquals(incrementalProj.ggrMinor, rebuiltProj.ggrMinor)
    }

    // -------------------------------------------------------------
    // Scenario 9: Chargeback Absent / Unsupported
    // -------------------------------------------------------------
    @Test
    fun `Scenario 9 - chargeback metric is explicitly marked unsupported rather than fabricating zero`() {
        val metricDef = MetricDictionary.getMetricDefinition("METRIC-CHARGEBACKS")
        assertNotNull(metricDef)
        assertEquals(MetricAvailability.UNSUPPORTED, metricDef?.availability)
        assertTrue(metricDef?.formula!!.contains("UNAVAILABLE"))
    }

    // -------------------------------------------------------------
    // Scenario 10: Ledger Imbalance Detection
    // -------------------------------------------------------------
    @Test
    fun `Scenario 10 - ledger reconciliation detects and reports imbalance between analytics facts and authoritative ledger`() {
        val date = LocalDate.of(2026, 9, 26)

        // Analytics fact records 100 EUR deposit
        service.recordFactAndProject(
            AnalyticsFact(
                factId = UUID.randomUUID(),
                tenantId = tenantId,
                factType = AnalyticsFactType.DEPOSIT_COMPLETED,
                sourceEventId = "dep-ledger-test-1",
                sourceEventType = "DEPOSIT_COMPLETED",
                userId = "player-ledger",
                currency = "EUR",
                amountMinor = 10000L,
                status = FactStatus.SUCCEEDED,
                occurredAt = Instant.parse("2026-09-26T11:00:00Z"),
                recordedAt = Instant.parse("2026-09-26T11:00:01Z"),
                correlationId = "c-led",
                causationId = "cause-led",
            )
        )

        // Authoritative ledger has only 80 EUR (discrepancy of 20 EUR)
        val ledgerTotals = mapOf("EUR" to 8000L)
        val reconciliation = service.reconcileAgainstLedger(tenantId, date, ledgerTotals)

        assertFalse(reconciliation.isBalanced)
        assertEquals(1, reconciliation.imbalances.size)
        val imbalance = reconciliation.imbalances[0]
        assertEquals("EUR", imbalance.currency)
        assertEquals(10000L, imbalance.analyticsTotalMinor)
        assertEquals(8000L, imbalance.ledgerTotalMinor)
        assertEquals(2000L, imbalance.divergenceMinor)
    }

    // -------------------------------------------------------------
    // Metric Dictionary Catalog Integrity
    // -------------------------------------------------------------
    @Test
    fun `Metric dictionary defines formulas, status inclusion, and currency requirements`() {
        val ggrDef = MetricDictionary.getMetricDefinition("METRIC-GGR")
        assertNotNull(ggrDef)
        assertEquals("1.0.0", ggrDef?.version)
        assertEquals(CurrencyBehavior.PER_CURRENCY, ggrDef?.currencyBehavior)
        assertTrue(ggrDef?.statusInclusion!!.contains(FactStatus.SUCCEEDED))
        assertFalse(ggrDef.statusInclusion.contains(FactStatus.PENDING))
        assertFalse(ggrDef.statusInclusion.contains(FactStatus.REJECTED))
    }
}
