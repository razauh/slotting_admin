package com.slotting.admin.analytics

import com.slotting.admin.auth.AdminPermission
import com.slotting.admin.auth.AdminRbacPolicy
import com.slotting.admin.auth.AdminRole
import com.slotting.admin.auth.AdminSessionDirectory
import com.slotting.admin.auth.AdminSessionStatus
import com.slotting.admin.auth.AuthErrorCode
import com.slotting.admin.auth.AuthenticatedPrincipal
import com.slotting.admin.auth.AuthenticationFailure
import com.slotting.admin.auth.PrincipalKind
import com.slotting.admin.fraud.FraudCaseRecord
import com.slotting.admin.fraud.FraudCaseState
import com.slotting.admin.fraud.InMemoryFraudCaseStore
import com.slotting.admin.observability.CriticalIncidentType
import com.slotting.admin.observability.EmitTelemetryCommand
import com.slotting.admin.observability.OperationalObservabilityService
import com.slotting.admin.observability.TelemetrySeverity
import com.slotting.admin.observability.TelemetrySignalType
import com.slotting.admin.restriction.InMemoryServerRestrictionStore
import com.slotting.admin.restriction.ServerRestrictionRecord
import com.slotting.admin.withdrawal.WithdrawalQueueItem
import com.slotting.admin.withdrawal.WithdrawalQueueStore
import com.slotting.admin.withdrawal.WithdrawalReviewReason
import com.slotting.admin.withdrawal.WithdrawalReviewResult
import com.slotting.admin.withdrawal.WithdrawalReviewState
import org.junit.jupiter.api.Assertions.*
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test
import java.time.Clock
import java.time.Duration
import java.time.Instant
import java.time.LocalDate
import java.time.ZoneOffset
import java.util.UUID

class AdminAnalyticsDashboardContractTest {

    private lateinit var store: InMemoryAnalyticsStore
    private lateinit var projectionService: AnalyticsProjectionService
    private lateinit var sessionDirectory: FakeAdminSessionDirectory
    private lateinit var rbacPolicy: AdminRbacPolicy
    private lateinit var fraudStore: InMemoryFraudCaseStore
    private lateinit var restrictionStore: InMemoryServerRestrictionStore
    private lateinit var withdrawalStore: FakeWithdrawalQueueStore
    private lateinit var observabilityService: OperationalObservabilityService
    private lateinit var dashboardService: AdminAnalyticsDashboardService

    private val tenantId = "tenant-prod-1"
    private val otherTenantId = "tenant-other-2"
    private val fixedNow = Instant.parse("2026-09-26T12:00:00Z")
    private val clock = Clock.fixed(fixedNow, ZoneOffset.UTC)

    private val auditorPrincipal = AuthenticatedPrincipal(
        id = "admin-auditor-1",
        tenantId = tenantId,
        kind = PrincipalKind.ADMIN,
        roles = setOf(AdminRole.AUDITOR),
    )

    private val superAdminPrincipal = AuthenticatedPrincipal(
        id = "admin-super-1",
        tenantId = tenantId,
        kind = PrincipalKind.ADMIN,
        roles = setOf(AdminRole.SUPER_ADMIN),
    )

    private val supportPrincipal = AuthenticatedPrincipal(
        id = "admin-support-1",
        tenantId = tenantId,
        kind = PrincipalKind.ADMIN,
        roles = setOf(AdminRole.SUPPORT), // Does not have ANALYTICS_READ
    )

    private val validSessionId = "session-valid-123"

    @BeforeEach
    fun setUp() {
        store = InMemoryAnalyticsStore()
        projectionService = AnalyticsProjectionService(store = store, clock = clock)
        sessionDirectory = FakeAdminSessionDirectory()
        sessionDirectory.registerSession(
            tenantId = tenantId,
            principalId = auditorPrincipal.id,
            sessionId = validSessionId,
            status = AdminSessionStatus(
                active = true,
                breakGlass = false,
                expiresAt = fixedNow.plus(Duration.ofHours(2)),
                mfaVerified = true,
            )
        )
        sessionDirectory.registerSession(
            tenantId = tenantId,
            principalId = superAdminPrincipal.id,
            sessionId = validSessionId,
            status = AdminSessionStatus(
                active = true,
                breakGlass = false,
                expiresAt = fixedNow.plus(Duration.ofHours(2)),
                mfaVerified = true,
            )
        )
        sessionDirectory.registerSession(
            tenantId = tenantId,
            principalId = supportPrincipal.id,
            sessionId = validSessionId,
            status = AdminSessionStatus(
                active = true,
                breakGlass = false,
                expiresAt = fixedNow.plus(Duration.ofHours(2)),
                mfaVerified = true,
            )
        )

        rbacPolicy = AdminRbacPolicy(dualControlRequired = false)
        fraudStore = InMemoryFraudCaseStore()
        restrictionStore = InMemoryServerRestrictionStore()
        withdrawalStore = FakeWithdrawalQueueStore()
        observabilityService = OperationalObservabilityService(clock = clock)

        dashboardService = AdminAnalyticsDashboardService(
            analyticsStore = store,
            sessions = sessionDirectory,
            rbacPolicy = rbacPolicy,
            withdrawalQueueStore = withdrawalStore,
            fraudCaseStore = fraudStore,
            restrictionStore = restrictionStore,
            observabilityService = observabilityService,
            clock = clock,
            staleLagThreshold = Duration.ofMinutes(15),
        )
    }

    // -------------------------------------------------------------
    // Scenario 1: daily/weekly/monthly
    // -------------------------------------------------------------
    @Test
    fun `Scenario 1 - daily weekly monthly queries aggregate period correctly`() {
        // Seed 3 days of facts: today (2026-09-26), 2 days ago (2026-09-24), 10 days ago (2026-09-16)
        seedSettledRound("evt-1", LocalDate.of(2026, 9, 26), 10000L, 4000L, "EUR")
        seedSettledRound("evt-2", LocalDate.of(2026, 9, 24), 20000L, 5000L, "EUR")
        seedSettledRound("evt-3", LocalDate.of(2026, 9, 16), 30000L, 10000L, "EUR")

        // 1. Daily Query (today only: 2026-09-26)
        val dailyResponse = dashboardService.queryDashboard(
            AdminAnalyticsQuery(
                principal = auditorPrincipal,
                sessionId = validSessionId,
                rangePreset = TimeRangePreset.DAILY,
                currency = "EUR",
            )
        )
        assertEquals(TimeRangePreset.DAILY, dailyResponse.timeRange)
        val dailyEur = dailyResponse.financialMetricsByCurrency["EUR"] ?: emptyList()
        val dailyGgr = dailyEur.find { it.metricId == "METRIC-GGR" }
        assertNotNull(dailyGgr)
        assertEquals(6000L, dailyGgr?.amountMinor, "Daily GGR must be 10000 - 4000 = 6000")

        // 2. Weekly Query (last 7 days: 2026-09-20 to 2026-09-26) -> includes evt-1 and evt-2, excludes evt-3
        val weeklyResponse = dashboardService.queryDashboard(
            AdminAnalyticsQuery(
                principal = auditorPrincipal,
                sessionId = validSessionId,
                rangePreset = TimeRangePreset.WEEKLY,
                currency = "EUR",
            )
        )
        val weeklyEur = weeklyResponse.financialMetricsByCurrency["EUR"] ?: emptyList()
        val weeklyWagers = weeklyEur.find { it.metricId == "METRIC-WAGER-VOL" }
        assertEquals(30000L, weeklyWagers?.amountMinor, "Weekly wagers must be 10000 + 20000 = 30000")
        val weeklyGgr = weeklyEur.find { it.metricId == "METRIC-GGR" }
        assertEquals(21000L, weeklyGgr?.amountMinor, "Weekly GGR must be (10000-4000) + (20000-5000) = 21000")

        // 3. Monthly Query (last 30 days: 2026-08-28 to 2026-09-26) -> includes evt-1, evt-2, evt-3
        val monthlyResponse = dashboardService.queryDashboard(
            AdminAnalyticsQuery(
                principal = auditorPrincipal,
                sessionId = validSessionId,
                rangePreset = TimeRangePreset.MONTHLY,
                currency = "EUR",
            )
        )
        val monthlyEur = monthlyResponse.financialMetricsByCurrency["EUR"] ?: emptyList()
        val monthlyWagers = monthlyEur.find { it.metricId == "METRIC-WAGER-VOL" }
        assertEquals(60000L, monthlyWagers?.amountMinor, "Monthly wagers must be 10000 + 20000 + 30000 = 60000")
    }

    // -------------------------------------------------------------
    // Scenario 2: custom range
    // -------------------------------------------------------------
    @Test
    fun `Scenario 2 - custom range query aggregates arbitrary bounded date range`() {
        seedSettledRound("evt-d1", LocalDate.of(2026, 9, 10), 15000L, 5000L, "EUR")
        seedSettledRound("evt-d2", LocalDate.of(2026, 9, 15), 25000L, 10000L, "EUR")
        seedSettledRound("evt-d3", LocalDate.of(2026, 9, 20), 40000L, 12000L, "EUR")

        val response = dashboardService.queryDashboard(
            AdminAnalyticsQuery(
                principal = auditorPrincipal,
                sessionId = validSessionId,
                rangePreset = TimeRangePreset.CUSTOM,
                startDate = LocalDate.of(2026, 9, 12),
                endDate = LocalDate.of(2026, 9, 18),
                currency = "EUR",
            )
        )

        assertEquals(TimeRangePreset.CUSTOM, response.timeRange)
        assertEquals(LocalDate.of(2026, 9, 12), response.startDate)
        assertEquals(LocalDate.of(2026, 9, 18), response.endDate)

        val eurCards = response.financialMetricsByCurrency["EUR"] ?: emptyList()
        val wagerCard = eurCards.find { it.metricId == "METRIC-WAGER-VOL" }
        assertEquals(25000L, wagerCard?.amountMinor, "Only evt-d2 falls in [2026-09-12, 2026-09-18]")
    }

    // -------------------------------------------------------------
    // Scenario 3: multi-currency
    // -------------------------------------------------------------
    @Test
    fun `Scenario 3 - multi-currency preserves strict separation without cross-currency summation`() {
        seedSettledRound("evt-eur", LocalDate.of(2026, 9, 26), 50000L, 10000L, "EUR")
        seedSettledRound("evt-usd", LocalDate.of(2026, 9, 26), 80000L, 20000L, "USD")

        val response = dashboardService.queryDashboard(
            AdminAnalyticsQuery(
                principal = auditorPrincipal,
                sessionId = validSessionId,
                rangePreset = TimeRangePreset.DAILY,
                currency = null, // request all currencies
            )
        )

        assertTrue(response.financialMetricsByCurrency.containsKey("EUR"))
        assertTrue(response.financialMetricsByCurrency.containsKey("USD"))

        val eurWagers = response.financialMetricsByCurrency["EUR"]!!.find { it.metricId == "METRIC-WAGER-VOL" }
        val usdWagers = response.financialMetricsByCurrency["USD"]!!.find { it.metricId == "METRIC-WAGER-VOL" }

        assertEquals(50000L, eurWagers?.amountMinor)
        assertEquals("EUR", eurWagers?.currency)

        assertEquals(80000L, usdWagers?.amountMinor)
        assertEquals("USD", usdWagers?.currency)

        // Ensure no card contains combined 130000L amount
        for ((curr, cards) in response.financialMetricsByCurrency) {
            for (card in cards) {
                assertNotEquals(130000L, card.amountMinor, "Cross-currency sum must never occur")
                assertEquals(curr, card.currency)
            }
        }
    }

    // -------------------------------------------------------------
    // Scenario 4: no data
    // -------------------------------------------------------------
    @Test
    fun `Scenario 4 - no data in range returns zeroed structure with metric definitions without error`() {
        val response = dashboardService.queryDashboard(
            AdminAnalyticsQuery(
                principal = auditorPrincipal,
                sessionId = validSessionId,
                rangePreset = TimeRangePreset.DAILY,
                currency = "EUR",
            )
        )

        assertEquals(tenantId, response.tenantId)
        val eurCards = response.financialMetricsByCurrency["EUR"] ?: emptyList()
        assertFalse(eurCards.isEmpty(), "Zeroed metric cards must be populated with dictionary definitions")

        val ggr = eurCards.find { it.metricId == "METRIC-GGR" }
        assertNotNull(ggr)
        assertEquals(0L, ggr?.amountMinor)
        assertEquals("1.0.0", ggr?.version)
        assertEquals(MetricUnit.MINOR_CURRENCY, ggr?.unit)

        val dau = response.userMetrics.find { it.metricId == "METRIC-DAU" }
        assertNotNull(dau)
        assertEquals(0L, dau?.count)

        // Unsupported metric card present
        val chargebacks = response.unsupportedMetrics.find { it.metricId == "METRIC-CHARGEBACKS" }
        assertNotNull(chargebacks)
        assertEquals(MetricAvailability.UNSUPPORTED, chargebacks?.availability)
        assertNotNull(chargebacks?.unavailableReason)
    }

    // -------------------------------------------------------------
    // Scenario 5: projection lag
    // -------------------------------------------------------------
    @Test
    fun `Scenario 5 - projection lag computes freshness and stale indicator correctly`() {
        // Event occurred 30 minutes ago (1800s ago)
        val pastOccurredAt = fixedNow.minus(Duration.ofMinutes(30))
        val fact = AnalyticsFact(
            factId = UUID.randomUUID(),
            tenantId = tenantId,
            factType = AnalyticsFactType.GAME_ROUND_SETTLED,
            sourceEventId = "evt-lag-1",
            sourceEventType = "GAME_ROUND_SETTLED",
            userId = "player-1",
            currency = "EUR",
            amountMinor = 1000L,
            payoutMinor = 200L,
            status = FactStatus.SUCCEEDED,
            occurredAt = pastOccurredAt,
            recordedAt = pastOccurredAt,
            correlationId = "c-lag",
            causationId = "c-lag",
        )
        projectionService.recordFactAndProject(fact)

        val response = dashboardService.queryDashboard(
            AdminAnalyticsQuery(
                principal = auditorPrincipal,
                sessionId = validSessionId,
                rangePreset = TimeRangePreset.DAILY,
            )
        )

        val freshness = response.freshness
        assertEquals(fixedNow, freshness.queryTimestamp)
        assertEquals(pastOccurredAt, freshness.lastProcessedFactTime)
        assertEquals(1800L, freshness.lagDurationSeconds)
        assertTrue(freshness.isStale, "Lag of 30m must be flagged as stale since threshold is 15m")
    }

    // -------------------------------------------------------------
    // Scenario 6: wrong tenant
    // -------------------------------------------------------------
    @Test
    fun `Scenario 6 - wrong tenant query is rejected and leaks no data`() {
        // Auditor belongs to tenantId ("tenant-prod-1"), but requests "tenant-other-2"
        val ex = assertThrows(AuthenticationFailure.Rejected::class.java) {
            dashboardService.queryDashboard(
                AdminAnalyticsQuery(
                    principal = auditorPrincipal,
                    sessionId = validSessionId,
                    requestedTenantId = otherTenantId,
                    rangePreset = TimeRangePreset.DAILY,
                )
            )
        }
        assertEquals(AuthErrorCode.FORBIDDEN, ex.code)
    }

    // -------------------------------------------------------------
    // Scenario 7: role revoked
    // -------------------------------------------------------------
    @Test
    fun `Scenario 7 - unauthenticated expired session or role without ANALYTICS_READ is rejected`() {
        // 1. Unauthenticated (principal = null)
        val unauthEx = assertThrows(AuthenticationFailure.Rejected::class.java) {
            dashboardService.queryDashboard(
                AdminAnalyticsQuery(
                    principal = null,
                    sessionId = validSessionId,
                    rangePreset = TimeRangePreset.DAILY,
                )
            )
        }
        assertEquals(AuthErrorCode.UNAUTHENTICATED, unauthEx.code)

        // 2. Role without ANALYTICS_READ (Support role has READ_SUPPORT, MANAGE_SUPPORT, RESTRICTIONS_MANAGE only)
        val forbiddenEx = assertThrows(AuthenticationFailure.Rejected::class.java) {
            dashboardService.queryDashboard(
                AdminAnalyticsQuery(
                    principal = supportPrincipal,
                    sessionId = validSessionId,
                    rangePreset = TimeRangePreset.DAILY,
                )
            )
        }
        assertEquals(AuthErrorCode.FORBIDDEN, forbiddenEx.code)

        // 3. Expired / Inactive session
        sessionDirectory.registerSession(
            tenantId = tenantId,
            principalId = auditorPrincipal.id,
            sessionId = "expired-session",
            status = AdminSessionStatus(
                active = true,
                breakGlass = false,
                expiresAt = fixedNow.minus(Duration.ofSeconds(1)), // Expired!
                mfaVerified = true,
            )
        )
        val expiredEx = assertThrows(AuthenticationFailure.Rejected::class.java) {
            dashboardService.queryDashboard(
                AdminAnalyticsQuery(
                    principal = auditorPrincipal,
                    sessionId = "expired-session",
                    rangePreset = TimeRangePreset.DAILY,
                )
            )
        }
        assertEquals(AuthErrorCode.FORBIDDEN, expiredEx.code)
    }

    // -------------------------------------------------------------
    // Scenario 8: large range
    // -------------------------------------------------------------
    @Test
    fun `Scenario 8 - large range exceeding maximum allowed window is bounded or rejected`() {
        val start = LocalDate.of(2024, 1, 1)
        val end = LocalDate.of(2026, 1, 1) // 731 days > 366 limit

        val ex = assertThrows(IllegalArgumentException::class.java) {
            dashboardService.queryDashboard(
                AdminAnalyticsQuery(
                    principal = auditorPrincipal,
                    sessionId = validSessionId,
                    rangePreset = TimeRangePreset.CUSTOM,
                    startDate = start,
                    endDate = end,
                )
            )
        }
        assertTrue(ex.message!!.contains("exceeds maximum"), "Exception message should indicate range limit exceeded")
    }

    // -------------------------------------------------------------
    // Scenario 9: provider filter
    // -------------------------------------------------------------
    @Test
    fun `Scenario 9 - provider filter isolates metrics to requested provider`() {
        // Seed Spribe and Pragmatic facts on same day
        val spribeFact = AnalyticsFact(
            factId = UUID.randomUUID(),
            tenantId = tenantId,
            factType = AnalyticsFactType.GAME_ROUND_SETTLED,
            sourceEventId = "evt-spribe-1",
            sourceEventType = "GAME_ROUND_SETTLED",
            userId = "player-1",
            providerId = "spribe",
            gameId = "aviator",
            currency = "EUR",
            amountMinor = 10000L,
            payoutMinor = 2000L,
            status = FactStatus.SUCCEEDED,
            occurredAt = fixedNow,
            recordedAt = fixedNow,
            correlationId = "corr-spribe",
            causationId = "cause-spribe",
        )
        val pragmaticFact = AnalyticsFact(
            factId = UUID.randomUUID(),
            tenantId = tenantId,
            factType = AnalyticsFactType.GAME_ROUND_SETTLED,
            sourceEventId = "evt-pragmatic-1",
            sourceEventType = "GAME_ROUND_SETTLED",
            userId = "player-2",
            providerId = "pragmatic",
            gameId = "gates-of-olympus",
            currency = "EUR",
            amountMinor = 50000L,
            payoutMinor = 40000L,
            status = FactStatus.SUCCEEDED,
            occurredAt = fixedNow,
            recordedAt = fixedNow,
            correlationId = "corr-prag",
            causationId = "cause-prag",
        )

        projectionService.recordFactAndProject(spribeFact)
        projectionService.recordFactAndProject(pragmaticFact)

        // Query filtered by providerId = "spribe"
        val response = dashboardService.queryDashboard(
            AdminAnalyticsQuery(
                principal = auditorPrincipal,
                sessionId = validSessionId,
                rangePreset = TimeRangePreset.DAILY,
                currency = "EUR",
                providerId = "spribe",
            )
        )

        assertEquals("spribe", response.dimensionFilter?.providerId)
        val eurCards = response.financialMetricsByCurrency["EUR"] ?: emptyList()
        val wagerCard = eurCards.find { it.metricId == "METRIC-WAGER-VOL" }
        assertEquals(10000L, wagerCard?.amountMinor, "Provider filter must only aggregate Spribe (10000), excluding Pragmatic (50000)")
    }

    // -------------------------------------------------------------
    // Scenario 10: case queue
    // -------------------------------------------------------------
    @Test
    fun `Scenario 10 - case queue and operational health summary aggregates operational backlog`() {
        // 1. Withdrawal review queue: 2 queued withdrawals
        withdrawalStore.addItem(tenantId, "wd-1", WithdrawalReviewState.QUEUED)
        withdrawalStore.addItem(tenantId, "wd-2", WithdrawalReviewState.QUEUED)

        // 2. Fraud case store: 1 open fraud case
        fraudStore.saveCase(
            FraudCaseRecord(
                caseReference = "fraud-case-1",
                tenantId = tenantId,
                subjectReference = "player-flagged-1",
                state = FraudCaseState.OPEN,
                severity = com.slotting.admin.fraud.FraudCaseSeverity.HIGH,
                detectedReasons = listOf("VELOCITY_SPIKE"),
                createdAt = fixedNow,
                updatedAt = fixedNow,
            )
        )

        // 3. Restriction store: 1 active restriction
        restrictionStore.saveRestriction(
            ServerRestrictionRecord(
                restrictionId = UUID.randomUUID(),
                tenantId = tenantId,
                subjectReference = "player-restricted-1",
                source = com.slotting.admin.restriction.RestrictionSource.KYC_AML,
                reasonCode = "AML_SANCTION",
                safeUserMessage = "Account restricted",
                scope = com.slotting.admin.restriction.RestrictionScope.WholeAccount,
                effectiveFrom = fixedNow.minus(Duration.ofHours(1)),
                evidenceReference = "evidence-ref-1",
                active = true,
            )
        )

        // 4. Observability telemetry: 1 CRITICAL incident
        observabilityService.emitTelemetry(
            EmitTelemetryCommand(
                principal = superAdminPrincipal,
                tenantId = tenantId,
                serviceName = "payment-gateway",
                signalType = TelemetrySignalType.ALERT,
                incidentType = CriticalIncidentType.POSTING_FAILURE,
                severity = TelemetrySeverity.CRITICAL,
                message = "Ledger posting failure on settlement batch",
                correlationId = "corr-obs-1",
                causationId = "cause-obs-1",
                idempotencyKey = "idem-obs-1",
            )
        )

        // 5. Analytics fact: 1 reconciliation exception
        val reconFact = AnalyticsFact(
            factId = UUID.randomUUID(),
            tenantId = tenantId,
            factType = AnalyticsFactType.RECONCILIATION_EXCEPTION,
            sourceEventId = "evt-recon-1",
            sourceEventType = "RECONCILIATION_EXCEPTION",
            status = FactStatus.FAILED,
            occurredAt = fixedNow,
            recordedAt = fixedNow,
            correlationId = "corr-recon",
            causationId = "cause-recon",
        )
        projectionService.recordFactAndProject(reconFact)

        val response = dashboardService.queryDashboard(
            AdminAnalyticsQuery(
                principal = auditorPrincipal,
                sessionId = validSessionId,
                rangePreset = TimeRangePreset.DAILY,
                includeOperationalHealth = true,
            )
        )

        val health = response.operationalHealth
        assertEquals(tenantId, health.tenantId)
        assertEquals(2L, health.pendingWithdrawalReviewsCount)
        assertEquals(1L, health.openFraudCasesCount)
        assertEquals(1L, health.activeRestrictionsCount)
        assertEquals(1L, health.reconciliationExceptionsCount)
        assertEquals(1L, health.criticalIncidentsCount)
        assertEquals(1L, health.pagedAlertsCount)
    }

    // -------------------------------------------------------------
    // Helper Methods
    // -------------------------------------------------------------
    private fun seedSettledRound(
        sourceId: String,
        date: LocalDate,
        wagerMinor: Long,
        payoutMinor: Long,
        currency: String,
    ) {
        val occurredAt = date.atStartOfDay().toInstant(ZoneOffset.UTC).plus(Duration.ofHours(10))
        val fact = AnalyticsFact(
            factId = UUID.randomUUID(),
            tenantId = tenantId,
            factType = AnalyticsFactType.GAME_ROUND_SETTLED,
            sourceEventId = sourceId,
            sourceEventType = "GAME_ROUND_SETTLED",
            userId = "player-$sourceId",
            currency = currency,
            amountMinor = wagerMinor,
            payoutMinor = payoutMinor,
            status = FactStatus.SUCCEEDED,
            occurredAt = occurredAt,
            recordedAt = occurredAt,
            correlationId = "corr-$sourceId",
            causationId = "cause-$sourceId",
        )
        projectionService.recordFactAndProject(fact)
    }

    private class FakeAdminSessionDirectory : AdminSessionDirectory {
        private val sessions = mutableMapOf<String, AdminSessionStatus>()

        fun registerSession(tenantId: String, principalId: String, sessionId: String, status: AdminSessionStatus) {
            sessions["$tenantId:$principalId:$sessionId"] = status
        }

        override fun find(tenantId: String, principalId: String, sessionId: String): AdminSessionStatus? {
            return sessions["$tenantId:$principalId:$sessionId"]
        }
    }

    private class FakeWithdrawalQueueStore : WithdrawalQueueStore {
        private val items = mutableMapOf<String, WithdrawalQueueItem>()

        fun addItem(tenantId: String, reference: String, state: WithdrawalReviewState) {
            items["$tenantId:$reference"] = WithdrawalQueueItem(
                withdrawalReference = reference,
                state = state,
                claimedBy = null,
                claimExpiresAt = null,
                serverVersion = 1L,
            )
        }

        fun countByState(tenantId: String, state: WithdrawalReviewState): Long {
            return items.values.count { it.state == state }.toLong()
        }

        override fun countPending(tenantId: String): Long {
            return items.values.count { it.state == WithdrawalReviewState.QUEUED || it.state == WithdrawalReviewState.CLAIMED }.toLong()
        }

        override fun findByIdempotency(tenantId: String, key: String): Pair<String, WithdrawalReviewResult>? = null
        override fun findItem(tenantId: String, withdrawalReference: String): WithdrawalQueueItem? =
            items["$tenantId:$withdrawalReference"]

        override fun save(
            result: WithdrawalReviewResult,
            tenantId: String,
            reason: WithdrawalReviewReason,
            secondApproverId: String?,
            queryFingerprint: String,
            idempotencyKey: String,
            audit: com.slotting.admin.auth.AuditEvent,
            outbox: com.slotting.admin.auth.OutboxEvent,
        ) {}
    }
}
