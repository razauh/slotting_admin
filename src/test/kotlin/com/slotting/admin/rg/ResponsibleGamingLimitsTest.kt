package com.slotting.admin.rg

import com.slotting.admin.auth.*
import java.io.File
import java.time.Clock
import java.time.Instant
import java.time.ZoneOffset
import java.util.UUID
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.CountDownLatch
import java.util.concurrent.Executors
import kotlin.test.*
import org.junit.jupiter.api.AfterEach
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test

class ResponsibleGamingLimitsTest {
    private val now = Instant.parse("2026-09-20T12:00:00Z")
    private val clock = Clock.fixed(now, ZoneOffset.UTC)
    private val tenantId = "tenant-rg-1"
    private val playerId = "player-rg-101"

    private val adminPrincipal = AuthenticatedPrincipal(
        id = "admin-rg-01",
        tenantId = tenantId,
        kind = PrincipalKind.ADMIN,
        roles = setOf(AdminRole.SUPER_ADMIN),
    )

    private val auditorPrincipal = AuthenticatedPrincipal(
        id = "auditor-rg-01",
        tenantId = tenantId,
        kind = PrincipalKind.ADMIN,
        roles = setOf(AdminRole.AUDITOR),
    )

    private val securityPrincipal = AuthenticatedPrincipal(
        id = "security-rg-01",
        tenantId = tenantId,
        kind = PrincipalKind.ADMIN,
        roles = setOf(AdminRole.SECURITY),
    )

    private val supportPrincipal = AuthenticatedPrincipal(
        id = "support-rg-01",
        tenantId = tenantId,
        kind = PrincipalKind.ADMIN,
        roles = setOf(AdminRole.SUPPORT),
    )

    private val crossTenantPrincipal = AuthenticatedPrincipal(
        id = "admin-cross-01",
        tenantId = "tenant-other",
        kind = PrincipalKind.ADMIN,
        roles = setOf(AdminRole.SUPER_ADMIN),
    )

    private val playerSelfPrincipal = AuthenticatedPrincipal(
        id = playerId,
        tenantId = tenantId,
        kind = PrincipalKind.PLAYER,
        roles = emptySet(),
    )

    private val playerOtherPrincipal = AuthenticatedPrincipal(
        id = "player-other-888",
        tenantId = tenantId,
        kind = PrincipalKind.PLAYER,
        roles = emptySet(),
    )

    private lateinit var store: InMemoryRgLimitsStore
    private lateinit var alertSink: InMemoryRgLimitsAlertSink
    private lateinit var service: ResponsibleGamingLimitsService

    @BeforeEach
    fun setUp() {
        ResponsibleGamingLimitsBinding.isBound = true
        store = InMemoryRgLimitsStore()
        alertSink = InMemoryRgLimitsAlertSink()
        service = ResponsibleGamingLimitsService(
            store = store,
            alertSink = alertSink,
            clock = clock,
        )
    }

    @AfterEach
    fun tearDown() {
        ResponsibleGamingLimitsBinding.isBound = true
    }

    @Test
    fun `RG-001-T001 — Limits model enforcement produces the required authoritative outcome`() {
        // 1. Expected RED failure verification: Fail-closed gate throws expected assertion when unbound
        ResponsibleGamingLimitsBinding.isBound = false

        val configCmd = ConfigureRgLimitCommand(
            tenantId = tenantId,
            playerId = playerId,
            limitType = RgLimitType.WAGER,
            period = RgLimitPeriod.DAILY,
            limitValueMinorUnits = 10000L, // 100.00 EUR daily wager limit
            timezone = "UTC",
            productScope = "ALL_PRODUCTS",
            idempotencyKey = "key-cfg-wager-01",
            correlationId = "corr-rg-1",
            causationId = "cause-rg-1",
            principal = playerSelfPrincipal,
        )

        val gateError = assertFailsWith<AssertionError> {
            service.configureLimit(configCmd)
        }
        assertEquals("split transactions/product bypass/race", gateError.message)

        // Bind the fail-closed gate
        ResponsibleGamingLimitsBinding.isBound = true

        // 2. Configure authoritative daily wager limit
        val configResult = service.configureLimit(configCmd)
        assertNotNull(configResult)
        assertFalse(configResult.isDuplicate)
        assertFalse(configResult.isFinancialAuthorityCreated, "Limits model cannot create financial authority or mutate money")
        assertEquals(RG_LIMITS_ENFORCEMENT_CONTRACT, configResult.semanticContract)
        assertEquals(10000L, configResult.config.limitValueMinorUnits)
        assertEquals("UTC", configResult.config.timezone)
        assertEquals(RgLimitPeriod.DAILY, configResult.config.period)
        assertEquals(1L, configResult.config.version)

        // 3. Authoritative Limit Enforcement (precedes reservation/credit where applicable)

        // Wager 1 on product SLOTS: 6,000 minor units
        val wager1Cmd = EnforceRgLimitCommand(
            tenantId = tenantId,
            playerId = playerId,
            limitType = RgLimitType.WAGER,
            proposedAmountMinorUnits = 6000L,
            product = "SLOTS",
            referenceId = "tx-spin-001",
            idempotencyKey = "key-enf-wager-01",
            correlationId = "corr-enf-1",
            causationId = "cause-enf-1",
            principal = playerSelfPrincipal,
        )
        val wager1Result = service.enforceLimit(wager1Cmd)
        assertEquals(LimitEnforcementOutcome.ALLOWED, wager1Result.outcome)
        assertEquals(6000L, wager1Result.consumedAfterMinorUnits)
        assertEquals(4000L, wager1Result.remainingMinorUnits)
        assertEquals(10000L, wager1Result.limitValueMinorUnits)
        assertEquals("UTC", wager1Result.timezone)
        assertEquals("SLOTS", wager1Result.product)
        assertEquals(RG_LIMITS_ENFORCEMENT_CONTRACT, wager1Result.semanticContract)

        // Wager 2 on different product CRASH_GAME: 3,000 minor units (cross-product enforcement prevents product bypass)
        val wager2Cmd = EnforceRgLimitCommand(
            tenantId = tenantId,
            playerId = playerId,
            limitType = RgLimitType.WAGER,
            proposedAmountMinorUnits = 3000L,
            product = "CRASH_GAME",
            referenceId = "tx-crash-001",
            idempotencyKey = "key-enf-wager-02",
            correlationId = "corr-enf-2",
            causationId = "cause-enf-2",
            principal = playerSelfPrincipal,
        )
        val wager2Result = service.enforceLimit(wager2Cmd)
        assertEquals(LimitEnforcementOutcome.ALLOWED, wager2Result.outcome)
        assertEquals(9000L, wager2Result.consumedAfterMinorUnits) // 6000 + 3000
        assertEquals(1000L, wager2Result.remainingMinorUnits)
        assertEquals("CRASH_GAME", wager2Result.product)

        // Wager 3 on TABLE_GAMES: 2,000 minor units (split transaction exceeds limit: 9000 + 2000 = 11000 > 10000)
        val wager3Cmd = EnforceRgLimitCommand(
            tenantId = tenantId,
            playerId = playerId,
            limitType = RgLimitType.WAGER,
            proposedAmountMinorUnits = 2000L,
            product = "TABLE_GAMES",
            referenceId = "tx-table-001",
            idempotencyKey = "key-enf-wager-03",
            correlationId = "corr-enf-3",
            causationId = "cause-enf-3",
            principal = playerSelfPrincipal,
        )
        val wager3Result = service.enforceLimit(wager3Cmd)
        assertEquals(LimitEnforcementOutcome.EXCEEDED_LIMIT, wager3Result.outcome)
        assertEquals(9000L, wager3Result.consumedAfterMinorUnits, "Consumed amount must remain unchanged on limit breach")
        assertEquals(1000L, wager3Result.remainingMinorUnits)
        assertTrue(alertSink.alerts.any { it.contains("RG_LIMIT_EXCEEDED") })

        // 4. Configure weekly deposit limit with non-UTC timezone: 50,000 minor units, Europe/Berlin
        val depositLimitCmd = ConfigureRgLimitCommand(
            tenantId = tenantId,
            playerId = playerId,
            limitType = RgLimitType.DEPOSIT,
            period = RgLimitPeriod.WEEKLY,
            limitValueMinorUnits = 50000L,
            timezone = "Europe/Berlin",
            productScope = "ALL_PRODUCTS",
            idempotencyKey = "key-cfg-dep-01",
            correlationId = "corr-rg-dep-1",
            causationId = "cause-rg-dep-1",
            principal = auditorPrincipal,
        )
        val depositConfigResult = service.configureLimit(depositLimitCmd)
        assertEquals("Europe/Berlin", depositConfigResult.config.timezone)
        assertEquals(50000L, depositConfigResult.config.limitValueMinorUnits)

        // Enforce deposit: 30,000 minor units -> ALLOWED
        val dep1Result = service.enforceLimit(
            EnforceRgLimitCommand(
                tenantId = tenantId,
                playerId = playerId,
                limitType = RgLimitType.DEPOSIT,
                proposedAmountMinorUnits = 30000L,
                product = "CASHIER",
                referenceId = "dep-tx-001",
                idempotencyKey = "key-enf-dep-01",
                correlationId = "corr-dep-1",
                causationId = "cause-dep-1",
                principal = playerSelfPrincipal,
            )
        )
        assertEquals(LimitEnforcementOutcome.ALLOWED, dep1Result.outcome)
        assertEquals(30000L, dep1Result.consumedAfterMinorUnits)
        assertEquals(20000L, dep1Result.remainingMinorUnits)
        assertEquals("Europe/Berlin", dep1Result.timezone)

        // Enforce second deposit: 25,000 minor units (30,000 + 25,000 = 55,000 > 50,000) -> EXCEEDED_LIMIT
        val dep2Result = service.enforceLimit(
            EnforceRgLimitCommand(
                tenantId = tenantId,
                playerId = playerId,
                limitType = RgLimitType.DEPOSIT,
                proposedAmountMinorUnits = 25000L,
                product = "CASHIER",
                referenceId = "dep-tx-002",
                idempotencyKey = "key-enf-dep-02",
                correlationId = "corr-dep-2",
                causationId = "cause-dep-2",
                principal = playerSelfPrincipal,
            )
        )
        assertEquals(LimitEnforcementOutcome.EXCEEDED_LIMIT, dep2Result.outcome)
        assertEquals(30000L, dep2Result.consumedAfterMinorUnits)

        // 5. Idempotent replay: Calling again with same idempotency key returns cached duplicate
        val replayedEnforce = service.enforceLimit(wager1Cmd)
        assertTrue(replayedEnforce.isDuplicate)
        assertEquals(wager1Result.evaluationId, replayedEnforce.evaluationId)

        // 6. Verify audit & outbox events
        val auditEvents = store.getAuditEvents()
        assertTrue(auditEvents.size >= 5)
        for (audit in auditEvents) {
            assertEquals(tenantId, audit.tenantId)
            assertNotNull(audit.correlationId)
            assertNotNull(audit.causationId)
            assertFalse(audit.type.contains("secret", ignoreCase = true))
            assertFalse(audit.type.contains("token", ignoreCase = true))
        }

        val outboxEvents = store.getOutboxEvents()
        assertTrue(outboxEvents.size >= 5)
    }

    @Test
    fun `RG-001-T002 — Limits model enforcement rejects invalid, boundary, unauthorized, and stale input`() {
        val validConfig = ConfigureRgLimitCommand(
            tenantId = tenantId,
            playerId = playerId,
            limitType = RgLimitType.WAGER,
            period = RgLimitPeriod.DAILY,
            limitValueMinorUnits = 5000L,
            timezone = "UTC",
            idempotencyKey = "key-val-cfg-01",
            correlationId = "corr-val-1",
            causationId = "cause-val-1",
            principal = playerSelfPrincipal,
        )

        // 1. Blank mandatory fields on configure
        assertFailsWith<AuthenticationFailure.Rejected> {
            service.configureLimit(validConfig.copy(tenantId = "   "))
        }.also { assertEquals(AuthErrorCode.INVALID, it.code) }

        assertFailsWith<AuthenticationFailure.Rejected> {
            service.configureLimit(validConfig.copy(playerId = ""))
        }.also { assertEquals(AuthErrorCode.INVALID, it.code) }

        assertFailsWith<AuthenticationFailure.Rejected> {
            service.configureLimit(validConfig.copy(timezone = ""))
        }.also { assertEquals(AuthErrorCode.INVALID, it.code) }

        assertFailsWith<AuthenticationFailure.Rejected> {
            service.configureLimit(validConfig.copy(idempotencyKey = ""))
        }.also { assertEquals(AuthErrorCode.INVALID, it.code) }

        // 2. Negative limit value or proposed amount
        assertFailsWith<AuthenticationFailure.Rejected> {
            service.configureLimit(validConfig.copy(limitValueMinorUnits = -100L))
        }.also { assertEquals(AuthErrorCode.INVALID, it.code) }

        assertFailsWith<AuthenticationFailure.Rejected> {
            service.enforceLimit(
                EnforceRgLimitCommand(
                    tenantId = tenantId,
                    playerId = playerId,
                    limitType = RgLimitType.WAGER,
                    proposedAmountMinorUnits = -50L,
                    referenceId = "tx-neg-1",
                    idempotencyKey = "key-neg-1",
                    correlationId = "corr-neg",
                    causationId = "cause-neg",
                    principal = playerSelfPrincipal,
                )
            )
        }.also { assertEquals(AuthErrorCode.INVALID, it.code) }

        // 3. Invalid timezone string
        assertFailsWith<AuthenticationFailure.Rejected> {
            service.configureLimit(validConfig.copy(timezone = "INVALID_TIMEZONE_STRING"))
        }.also { assertEquals(AuthErrorCode.INVALID, it.code) }

        // 4. Stale expected version
        assertFailsWith<AuthenticationFailure.Rejected> {
            service.configureLimit(validConfig.copy(expectedVersion = 2L))
        }.also { assertEquals(AuthErrorCode.STALE, it.code) }

        // 5. Principal authorization & Cross-player boundary enforcement
        // Player attempting to configure another player's limit -> FORBIDDEN
        assertFailsWith<AuthenticationFailure.Rejected> {
            service.configureLimit(validConfig.copy(principal = playerOtherPrincipal))
        }.also { assertEquals(AuthErrorCode.FORBIDDEN, it.code) }

        // Player attempting to enforce another player's limit -> FORBIDDEN
        assertFailsWith<AuthenticationFailure.Rejected> {
            service.enforceLimit(
                EnforceRgLimitCommand(
                    tenantId = tenantId,
                    playerId = playerId,
                    limitType = RgLimitType.WAGER,
                    proposedAmountMinorUnits = 100L,
                    referenceId = "tx-other-1",
                    idempotencyKey = "key-other-1",
                    correlationId = "corr-other",
                    causationId = "cause-other",
                    principal = playerOtherPrincipal,
                )
            )
        }.also { assertEquals(AuthErrorCode.FORBIDDEN, it.code) }

        // Cross-tenant principal -> FORBIDDEN
        assertFailsWith<AuthenticationFailure.Rejected> {
            service.configureLimit(validConfig.copy(principal = crossTenantPrincipal))
        }.also { assertEquals(AuthErrorCode.FORBIDDEN, it.code) }

        // Admin without SUPER_ADMIN/AUDITOR/SECURITY (e.g. SUPPORT) -> FORBIDDEN
        assertFailsWith<AuthenticationFailure.Rejected> {
            service.configureLimit(validConfig.copy(principal = supportPrincipal))
        }.also { assertEquals(AuthErrorCode.FORBIDDEN, it.code) }

        // 6. Idempotency conflict: same key with different payload
        service.configureLimit(validConfig)
        assertFailsWith<AuthenticationFailure.Rejected> {
            service.configureLimit(validConfig.copy(limitValueMinorUnits = 9999L))
        }.also { assertEquals(AuthErrorCode.CONFLICT, it.code) }
    }

    @Test
    fun `RG-001-T003 — Limits model enforcement survives concurrency, duplicate delivery, and dependency failure`() {
        // 1. Setup a limit with 6,000 minor units limit
        service.configureLimit(
            ConfigureRgLimitCommand(
                tenantId = tenantId,
                playerId = playerId,
                limitType = RgLimitType.WAGER,
                period = RgLimitPeriod.DAILY,
                limitValueMinorUnits = 6000L,
                timezone = "UTC",
                idempotencyKey = "key-conc-setup-01",
                correlationId = "corr-conc-setup",
                causationId = "cause-conc-setup",
                principal = playerSelfPrincipal,
            )
        )

        // 2. Race condition & split transaction prevention under high concurrency:
        // 8 threads race concurrently, each attempting to wager 2,000 minor units (totaling 16,000 against 6,000 limit).
        // Exactly 3 threads must succeed (ALLOWED, consuming 6,000 total), and 5 must be rejected (EXCEEDED_LIMIT).
        val threadCount = 8
        val executor = Executors.newFixedThreadPool(threadCount)
        val startLatch = CountDownLatch(1)
        val endLatch = CountDownLatch(threadCount)

        val results = ConcurrentHashMap<Int, EnforceRgLimitResult>()
        val exceptions = ConcurrentHashMap<Int, Throwable>()

        for (i in 0 until threadCount) {
            val cmd = EnforceRgLimitCommand(
                tenantId = tenantId,
                playerId = playerId,
                limitType = RgLimitType.WAGER,
                proposedAmountMinorUnits = 2000L,
                product = "SLOTS",
                referenceId = "tx-conc-$i",
                idempotencyKey = "key-conc-race-$i",
                correlationId = "corr-race-$i",
                causationId = "cause-race-$i",
                principal = playerSelfPrincipal,
            )
            executor.submit {
                try {
                    startLatch.await()
                    val res = service.enforceLimit(cmd)
                    results[i] = res
                } catch (t: Throwable) {
                    exceptions[i] = t
                } finally {
                    endLatch.countDown()
                }
            }
        }

        startLatch.countDown()
        endLatch.await()
        executor.shutdown()

        assertTrue(exceptions.isEmpty(), "Concurrent race must not throw unhandled exceptions: ${exceptions.values}")
        assertEquals(threadCount, results.size)

        val allowedCount = results.values.count { it.outcome == LimitEnforcementOutcome.ALLOWED }
        val exceededCount = results.values.count { it.outcome == LimitEnforcementOutcome.EXCEEDED_LIMIT }

        // Invariant: Exactly 3 allowed and 5 exceeded
        assertEquals(3, allowedCount, "Exactly 3 wagers of 2,000 must be allowed within 6,000 limit")
        assertEquals(5, exceededCount, "Exactly 5 wagers must be rejected to prevent race/split-transaction limit overrun")

        // 3. Storage dependency failure handling
        class FailingRgStore : InMemoryRgLimitsStore() {
            var shouldFail = true
            override fun saveUsageAndResult(
                usage: RgLimitUsageRecord,
                result: EnforceRgLimitResult,
                idempotencyKey: String,
                fingerprint: String,
                audit: AuditEvent,
                outbox: OutboxEvent,
            ) {
                if (shouldFail) {
                    throw RuntimeException("RG database connection timeout")
                }
                super.saveUsageAndResult(usage, result, idempotencyKey, fingerprint, audit, outbox)
            }
        }

        val failingStore = FailingRgStore()
        val retryService = ResponsibleGamingLimitsService(
            store = failingStore,
            alertSink = alertSink,
            clock = clock,
        )

        // Seed config into failing store
        failingStore.saveConfig(
            RgLimitConfig(
                limitId = UUID.randomUUID(),
                tenantId = tenantId,
                playerId = playerId,
                limitType = RgLimitType.WAGER,
                period = RgLimitPeriod.DAILY,
                limitValueMinorUnits = 10000L,
                timezone = "UTC",
                version = 1L,
                createdAt = now,
                updatedAt = now,
            ),
            ConfigureRgLimitResult(UUID.randomUUID(), RgLimitConfig(UUID.randomUUID(), tenantId, playerId, RgLimitType.WAGER, RgLimitPeriod.DAILY, 10000L, "UTC", version = 1L, createdAt = now, updatedAt = now), now, false, "evid"),
            "key-seed",
            "fp",
            AuditEvent(UUID.randomUUID(), UUID.randomUUID(), tenantId, "SEED", now, "c", "c"),
            OutboxEvent(UUID.randomUUID(), UUID.randomUUID(), tenantId, "SEED", now),
        )

        val retryCmd = EnforceRgLimitCommand(
            tenantId = tenantId,
            playerId = playerId,
            limitType = RgLimitType.WAGER,
            proposedAmountMinorUnits = 1000L,
            product = "SLOTS",
            referenceId = "tx-retry-01",
            idempotencyKey = "key-enf-retry-01",
            correlationId = "corr-retry-1",
            causationId = "cause-retry-1",
            principal = playerSelfPrincipal,
        )

        val depError = assertFailsWith<AuthenticationFailure.Rejected> {
            retryService.enforceLimit(retryCmd)
        }
        assertEquals(AuthErrorCode.DEPENDENCY_UNAVAILABLE, depError.code)
        assertTrue(alertSink.alerts.any { it.contains("RG_LIMIT_STORAGE_FAILED") })

        // Dependency recovers: Retry succeeds cleanly
        failingStore.shouldFail = false
        val recoveredResult = retryService.enforceLimit(retryCmd)
        assertNotNull(recoveredResult)
        assertEquals(LimitEnforcementOutcome.ALLOWED, recoveredResult.outcome)
    }

    @Test
    fun `RG-001-T004 — Limits model enforcement remains compatible, recoverable, observable, and lifecycle-safe`() {
        // 1. Schema migration contract: V16 Flyway migration exists, no rogue V17
        val migrationsDir = File("src/main/resources/db/migration")
        val sqlFiles = migrationsDir.listFiles { _, name -> name.endsWith(".sql") } ?: emptyArray()
        assertTrue(sqlFiles.isNotEmpty(), "Migrations directory must contain Flyway files")
        val migrationVersions = sqlFiles.map { it.name.substringBefore("__") }
        assertTrue(migrationVersions.contains("V16"), "V16 must be present")
        assertFalse(migrationVersions.contains("V17"), "V17 must not be created prematurely")

        // 2. Lifecycle safety: Confirm no Android lifecycle surface is claimed
        val androidActivityClass = runCatching { Class.forName("android.app.Activity") }
        assertTrue(androidActivityClass.isFailure, "Authoritative backend must not link Android framework lifecycle")

        // 3. State recovery across restart
        val cfgCmd = ConfigureRgLimitCommand(
            tenantId = tenantId,
            playerId = playerId,
            limitType = RgLimitType.LOSS,
            period = RgLimitPeriod.MONTHLY,
            limitValueMinorUnits = 20000L,
            timezone = "Europe/Paris",
            idempotencyKey = "key-cfg-restart-01",
            correlationId = "corr-restart-1",
            causationId = "cause-restart-1",
            principal = playerSelfPrincipal,
        )

        val initialResult = service.configureLimit(cfgCmd)
        assertNotNull(initialResult)
        assertFalse(initialResult.isDuplicate)

        // Export snapshot and import into fresh store instance simulating server restart
        val snapshot = store.exportSnapshot()
        val rehydratedStore = InMemoryRgLimitsStore()
        rehydratedStore.importSnapshot(snapshot)
        val restartedService = ResponsibleGamingLimitsService(
            store = rehydratedStore,
            alertSink = alertSink,
            clock = clock,
        )

        // Calling with same idempotency key on rehydrated store returns identical cached outcome
        val replayedResult = restartedService.configureLimit(cfgCmd)
        assertEquals(initialResult.resultId, replayedResult.resultId)
        assertTrue(replayedResult.isDuplicate)
        assertEquals(RG_LIMITS_ENFORCEMENT_CONTRACT, replayedResult.semanticContract)

        // 4. Observability: structured audit & outbox records contain zero credentials or PII
        val auditEvents = rehydratedStore.getAuditEvents()
        assertTrue(auditEvents.isNotEmpty())
        for (audit in auditEvents) {
            assertEquals(tenantId, audit.tenantId)
            assertNotNull(audit.correlationId)
            assertNotNull(audit.causationId)
            assertFalse(audit.type.contains("secret", ignoreCase = true))
            assertFalse(audit.type.contains("token", ignoreCase = true))
            assertFalse(audit.type.contains("password", ignoreCase = true))
        }

        val outboxEvents = rehydratedStore.getOutboxEvents()
        assertTrue(outboxEvents.isNotEmpty())
    }
}
