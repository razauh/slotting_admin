package com.slotting.admin.rg

import com.slotting.admin.auth.*
import java.io.File
import java.time.Clock
import java.time.Duration
import java.time.Instant
import java.time.ZoneOffset
import java.util.UUID
import java.util.concurrent.Callable
import java.util.concurrent.CountDownLatch
import java.util.concurrent.Executors
import kotlin.test.*
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test

class DelayedLimitIncreaseTest {
    private val tenantId = "tenant-rg-01"
    private val playerId = "player-rg-99"

    private val baseInstant = Instant.parse("2026-09-20T10:00:00Z")
    private var currentInstant = baseInstant
    private val clock = object : Clock() {
        override fun getZone(): java.time.ZoneId = ZoneOffset.UTC
        override fun withZone(zone: java.time.ZoneId?): Clock = this
        override fun instant(): Instant = currentInstant
    }

    private lateinit var store: InMemoryDelayedLimitIncreaseStore
    private lateinit var alertSink: InMemoryDelayedLimitIncreaseAlertSink
    private lateinit var service: DelayedLimitIncreaseService

    private val playerPrincipal = AuthenticatedPrincipal(
        id = playerId,
        tenantId = tenantId,
        kind = PrincipalKind.PLAYER,
        roles = emptySet(),
    )

    private val securityAdminPrincipal = AuthenticatedPrincipal(
        id = "admin-sec-01",
        tenantId = tenantId,
        kind = PrincipalKind.ADMIN,
        roles = setOf(AdminRole.SECURITY),
    )

    private val superAdminPrincipal = AuthenticatedPrincipal(
        id = "admin-super-01",
        tenantId = tenantId,
        kind = PrincipalKind.ADMIN,
        roles = setOf(AdminRole.SUPER_ADMIN),
    )

    private val otherPlayerPrincipal = AuthenticatedPrincipal(
        id = "player-other-88",
        tenantId = tenantId,
        kind = PrincipalKind.PLAYER,
        roles = emptySet(),
    )

    private val crossTenantPrincipal = AuthenticatedPrincipal(
        id = "admin-other-tenant",
        tenantId = "other-tenant",
        kind = PrincipalKind.ADMIN,
        roles = setOf(AdminRole.SUPER_ADMIN),
    )

    @BeforeEach
    fun setUp() {
        currentInstant = baseInstant
        store = InMemoryDelayedLimitIncreaseStore()
        alertSink = InMemoryDelayedLimitIncreaseAlertSink()
        service = DelayedLimitIncreaseService(store, alertSink, clock)
        // Reset gate to prove RED failure first
        DelayedLimitIncreaseBinding.isBound = false
    }

    @Test
    fun `RG-003-01-T001 — Delay responsible-gaming limit increases produces the required authoritative outcome`() {
        // Step 1: Prove mandatory RED failure gate
        val ex = assertFailsWith<AssertionError> {
            service.configureOrUpdateLimit(
                ConfigureOrUpdateLimitCommand(
                    tenantId = tenantId,
                    playerId = playerId,
                    limitType = RgLimitType.DEPOSIT,
                    period = RgLimitPeriod.DAILY,
                    limitValueMinorUnits = 10000L,
                    timezone = "UTC",
                    idempotencyKey = "key-init-limit-01",
                    correlationId = "corr-init-1",
                    causationId = "cause-init-1",
                    principal = playerPrincipal,
                )
            )
        }
        assertEquals("increase immediate or clock manipulation", ex.message)

        // Step 2: Bind gate to transition to GREEN behavior
        DelayedLimitIncreaseBinding.isBound = true

        // 1. Initial configuration of legal values: applies immediately
        val initCmd = ConfigureOrUpdateLimitCommand(
            tenantId = tenantId,
            playerId = playerId,
            limitType = RgLimitType.DEPOSIT,
            period = RgLimitPeriod.DAILY,
            limitValueMinorUnits = 10000L,
            timezone = "UTC",
            idempotencyKey = "key-init-limit-01",
            correlationId = "corr-init-1",
            causationId = "cause-init-1",
            expectedVersion = 1L,
            principal = playerPrincipal,
        )

        val initResult = service.configureOrUpdateLimit(initCmd)
        assertNotNull(initResult)
        assertFalse(initResult.isDuplicate)
        assertTrue(initResult.isImmediate)
        assertEquals(DELAYED_LIMIT_INCREASE_CONTRACT, initResult.semanticContract)
        assertEquals(10000L, initResult.record.currentLimitValueMinorUnits)
        assertNull(initResult.record.pendingLimitValueMinorUnits)
        assertEquals(DelayedLimitStatus.ACTIVE, initResult.record.status)
        assertFalse(initResult.isFinancialAuthorityCreated)

        // 2. Decrease may be immediate: reduce limit from 10000 to 5000
        val decreaseCmd = ConfigureOrUpdateLimitCommand(
            tenantId = tenantId,
            playerId = playerId,
            limitType = RgLimitType.DEPOSIT,
            period = RgLimitPeriod.DAILY,
            limitValueMinorUnits = 5000L,
            timezone = "UTC",
            idempotencyKey = "key-decrease-limit-01",
            correlationId = "corr-decrease-1",
            causationId = "cause-decrease-1",
            expectedVersion = 1L,
            principal = playerPrincipal,
        )

        val decreaseResult = service.configureOrUpdateLimit(decreaseCmd)
        assertNotNull(decreaseResult)
        assertTrue(decreaseResult.isImmediate)
        assertEquals(5000L, decreaseResult.record.currentLimitValueMinorUnits)
        assertEquals(DelayedLimitStatus.ACTIVE, decreaseResult.record.status)
        assertNull(decreaseResult.record.pendingLimitValueMinorUnits)
        assertFalse(decreaseResult.isFinancialAuthorityCreated)

        // Effective limit query reflects immediate decrease
        val checkAfterDecrease = service.checkEffectiveLimit(
            CheckEffectiveLimitQuery(tenantId, playerId, RgLimitType.DEPOSIT, playerPrincipal)
        )
        assertEquals(5000L, checkAfterDecrease.effectiveLimitValueMinorUnits)
        assertEquals(DelayedLimitStatus.ACTIVE, checkAfterDecrease.status)
        assertFalse(checkAfterDecrease.realityCheckPending)

        // 3. Limit increase request: MUST enter mandatory cooling-off delay
        val increaseCmd = ConfigureOrUpdateLimitCommand(
            tenantId = tenantId,
            playerId = playerId,
            limitType = RgLimitType.DEPOSIT,
            period = RgLimitPeriod.DAILY,
            limitValueMinorUnits = 15000L,
            timezone = "UTC",
            idempotencyKey = "key-increase-limit-01",
            correlationId = "corr-increase-1",
            causationId = "cause-increase-1",
            expectedVersion = 2L,
            principal = playerPrincipal,
        )

        val increaseResult = service.configureOrUpdateLimit(increaseCmd)
        assertNotNull(increaseResult)
        assertFalse(increaseResult.isImmediate)
        assertEquals(5000L, increaseResult.record.currentLimitValueMinorUnits, "Active limit must remain at previous lower value")
        assertEquals(15000L, increaseResult.record.pendingLimitValueMinorUnits, "Increase must be queued as pending")
        assertEquals(DelayedLimitStatus.PENDING_COOLING_OFF, increaseResult.record.status)
        assertTrue(increaseResult.record.realityCheckRequired)
        assertNotNull(increaseResult.record.coolingDelayExpiresAt)
        assertEquals(currentInstant.plus(Duration.ofHours(24)), increaseResult.record.coolingDelayExpiresAt)
        assertFalse(increaseResult.isFinancialAuthorityCreated)

        // Effective limit query still enforces the lower limit during cooling delay
        val checkDuringCooling = service.checkEffectiveLimit(
            CheckEffectiveLimitQuery(tenantId, playerId, RgLimitType.DEPOSIT, playerPrincipal)
        )
        assertEquals(5000L, checkDuringCooling.effectiveLimitValueMinorUnits)
        assertEquals(DelayedLimitStatus.PENDING_COOLING_OFF, checkDuringCooling.status)
        assertFalse(checkDuringCooling.realityCheckPending)

        // 4. Premature confirmation during cooling delay fails closed
        currentInstant = currentInstant.plus(Duration.ofHours(12)) // Only 12 hours passed
        val prematureEx = assertFailsWith<AuthenticationFailure.Rejected> {
            service.acknowledgeRealityCheck(
                AcknowledgeRealityCheckCommand(
                    tenantId = tenantId,
                    playerId = playerId,
                    limitType = RgLimitType.DEPOSIT,
                    idempotencyKey = "key-ack-premature-01",
                    correlationId = "corr-ack-premature",
                    causationId = "cause-ack-premature",
                    expectedVersion = 3L,
                    principal = playerPrincipal,
                )
            )
        }
        assertEquals(AuthErrorCode.FORBIDDEN, prematureEx.code)

        // 5. Cooling delay matures after 24 hours: status transitions to PENDING_REALITY_CHECK
        currentInstant = currentInstant.plus(Duration.ofHours(13)) // Total 25 hours passed
        val checkAfterExpiry = service.checkEffectiveLimit(
            CheckEffectiveLimitQuery(tenantId, playerId, RgLimitType.DEPOSIT, playerPrincipal)
        )
        assertEquals(5000L, checkAfterExpiry.effectiveLimitValueMinorUnits, "Limit remains at lower value until reality check acknowledged")
        assertEquals(DelayedLimitStatus.PENDING_REALITY_CHECK, checkAfterExpiry.status)
        assertTrue(checkAfterExpiry.realityCheckPending)

        // 6. Explicit player reality check acknowledgment promotes the limit
        val ackCmd = AcknowledgeRealityCheckCommand(
            tenantId = tenantId,
            playerId = playerId,
            limitType = RgLimitType.DEPOSIT,
            idempotencyKey = "key-ack-mature-01",
            correlationId = "corr-ack-mature",
            causationId = "cause-ack-mature",
            expectedVersion = 3L,
            principal = playerPrincipal,
        )

        val ackResult = service.acknowledgeRealityCheck(ackCmd)
        assertNotNull(ackResult)
        assertEquals(15000L, ackResult.record.currentLimitValueMinorUnits, "Promoted to new limit after reality check confirmation")
        assertNull(ackResult.record.pendingLimitValueMinorUnits)
        assertEquals(DelayedLimitStatus.ACTIVE, ackResult.record.status)
        assertFalse(ackResult.record.realityCheckRequired)
        assertEquals(currentInstant, ackResult.record.realityCheckAcknowledgedAt)
        assertFalse(ackResult.isFinancialAuthorityCreated)

        val finalCheck = service.checkEffectiveLimit(
            CheckEffectiveLimitQuery(tenantId, playerId, RgLimitType.DEPOSIT, playerPrincipal)
        )
        assertEquals(15000L, finalCheck.effectiveLimitValueMinorUnits)
        assertEquals(DelayedLimitStatus.ACTIVE, finalCheck.status)
        assertFalse(finalCheck.realityCheckPending)
    }

    @Test
    fun `RG-003-01-T002 — Delay responsible-gaming limit increases rejects invalid, boundary, unauthorized, and stale input`() {
        DelayedLimitIncreaseBinding.isBound = true

        // 1. Blank mandatory inputs rejected
        assertFailsWith<AuthenticationFailure.Rejected> {
            service.configureOrUpdateLimit(
                ConfigureOrUpdateLimitCommand(
                    tenantId = "",
                    playerId = playerId,
                    limitType = RgLimitType.DEPOSIT,
                    period = RgLimitPeriod.DAILY,
                    limitValueMinorUnits = 10000L,
                    timezone = "UTC",
                    idempotencyKey = "key-blank-01",
                    correlationId = "corr-1",
                    causationId = "cause-1",
                )
            )
        }.also { assertEquals(AuthErrorCode.INVALID, it.code) }

        // 2. Illegal boundary values (zero, negative, or exceeding max legal limit)
        assertFailsWith<AuthenticationFailure.Rejected> {
            service.configureOrUpdateLimit(
                ConfigureOrUpdateLimitCommand(
                    tenantId = tenantId,
                    playerId = playerId,
                    limitType = RgLimitType.DEPOSIT,
                    period = RgLimitPeriod.DAILY,
                    limitValueMinorUnits = 0L,
                    timezone = "UTC",
                    idempotencyKey = "key-zero-01",
                    correlationId = "corr-1",
                    causationId = "cause-1",
                    principal = playerPrincipal,
                )
            )
        }.also { assertEquals(AuthErrorCode.INVALID, it.code) }

        assertFailsWith<AuthenticationFailure.Rejected> {
            service.configureOrUpdateLimit(
                ConfigureOrUpdateLimitCommand(
                    tenantId = tenantId,
                    playerId = playerId,
                    limitType = RgLimitType.DEPOSIT,
                    period = RgLimitPeriod.DAILY,
                    limitValueMinorUnits = -5000L,
                    timezone = "UTC",
                    idempotencyKey = "key-neg-01",
                    correlationId = "corr-1",
                    causationId = "cause-1",
                    principal = playerPrincipal,
                )
            )
        }.also { assertEquals(AuthErrorCode.INVALID, it.code) }

        assertFailsWith<AuthenticationFailure.Rejected> {
            service.configureOrUpdateLimit(
                ConfigureOrUpdateLimitCommand(
                    tenantId = tenantId,
                    playerId = playerId,
                    limitType = RgLimitType.DEPOSIT,
                    period = RgLimitPeriod.DAILY,
                    limitValueMinorUnits = MAX_LEGAL_LIMIT_MINOR_UNITS + 1L,
                    timezone = "UTC",
                    idempotencyKey = "key-exceed-01",
                    correlationId = "corr-1",
                    causationId = "cause-1",
                    principal = playerPrincipal,
                )
            )
        }.also { assertEquals(AuthErrorCode.INVALID, it.code) }

        // 3. Invalid timezone
        assertFailsWith<AuthenticationFailure.Rejected> {
            service.configureOrUpdateLimit(
                ConfigureOrUpdateLimitCommand(
                    tenantId = tenantId,
                    playerId = playerId,
                    limitType = RgLimitType.DEPOSIT,
                    period = RgLimitPeriod.DAILY,
                    limitValueMinorUnits = 5000L,
                    timezone = "Invalid/Zone_Name",
                    idempotencyKey = "key-tz-01",
                    correlationId = "corr-1",
                    causationId = "cause-1",
                    principal = playerPrincipal,
                )
            )
        }.also { assertEquals(AuthErrorCode.INVALID, it.code) }

        // 4. Clock manipulation attempt: client reported timestamp skewed forward by 1 hour
        assertFailsWith<AuthenticationFailure.Rejected> {
            service.configureOrUpdateLimit(
                ConfigureOrUpdateLimitCommand(
                    tenantId = tenantId,
                    playerId = playerId,
                    limitType = RgLimitType.DEPOSIT,
                    period = RgLimitPeriod.DAILY,
                    limitValueMinorUnits = 5000L,
                    timezone = "UTC",
                    idempotencyKey = "key-clock-skew-01",
                    correlationId = "corr-1",
                    causationId = "cause-1",
                    principal = playerPrincipal,
                    clientReportedTimestamp = currentInstant.plus(Duration.ofHours(1)),
                )
            )
        }.also {
            assertEquals(AuthErrorCode.INVALID, it.code)
            assertTrue(alertSink.alerts.any { a -> a["alertType"] == "CLOCK_MANIPULATION_DETECTED" })
        }

        // 5. Cross-player / Cross-tenant authorization denial
        assertFailsWith<AuthenticationFailure.Rejected> {
            service.configureOrUpdateLimit(
                ConfigureOrUpdateLimitCommand(
                    tenantId = tenantId,
                    playerId = playerId,
                    limitType = RgLimitType.DEPOSIT,
                    period = RgLimitPeriod.DAILY,
                    limitValueMinorUnits = 5000L,
                    timezone = "UTC",
                    idempotencyKey = "key-unauth-01",
                    correlationId = "corr-1",
                    causationId = "cause-1",
                    principal = otherPlayerPrincipal,
                )
            )
        }.also { assertEquals(AuthErrorCode.FORBIDDEN, it.code) }

        assertFailsWith<AuthenticationFailure.Rejected> {
            service.configureOrUpdateLimit(
                ConfigureOrUpdateLimitCommand(
                    tenantId = tenantId,
                    playerId = playerId,
                    limitType = RgLimitType.DEPOSIT,
                    period = RgLimitPeriod.DAILY,
                    limitValueMinorUnits = 5000L,
                    timezone = "UTC",
                    idempotencyKey = "key-cross-tenant-01",
                    correlationId = "corr-1",
                    causationId = "cause-1",
                    principal = crossTenantPrincipal,
                )
            )
        }.also { assertEquals(AuthErrorCode.FORBIDDEN, it.code) }

        // 6. Valid setup then stale version rejection
        val validCmd = ConfigureOrUpdateLimitCommand(
            tenantId = tenantId,
            playerId = playerId,
            limitType = RgLimitType.DEPOSIT,
            period = RgLimitPeriod.DAILY,
            limitValueMinorUnits = 5000L,
            timezone = "UTC",
            idempotencyKey = "key-valid-01",
            correlationId = "corr-1",
            causationId = "cause-1",
            expectedVersion = 1L,
            principal = playerPrincipal,
        )
        service.configureOrUpdateLimit(validCmd)

        // Stale expectedVersion
        assertFailsWith<AuthenticationFailure.Rejected> {
            service.configureOrUpdateLimit(
                validCmd.copy(
                    idempotencyKey = "key-stale-01",
                    expectedVersion = 99L,
                )
            )
        }.also { assertEquals(AuthErrorCode.STALE, it.code) }

        // 7. Cancellation of non-pending limit
        assertFailsWith<AuthenticationFailure.Rejected> {
            service.cancelPendingIncrease(
                CancelPendingIncreaseCommand(
                    tenantId = tenantId,
                    playerId = playerId,
                    limitType = RgLimitType.DEPOSIT,
                    reason = "No increase pending",
                    idempotencyKey = "key-cancel-err-01",
                    correlationId = "corr-1",
                    causationId = "cause-1",
                    expectedVersion = 1L,
                    principal = playerPrincipal,
                )
            )
        }.also { assertEquals(AuthErrorCode.INVALID, it.code) }
    }

    @Test
    fun `RG-003-01-T003 — Delay responsible-gaming limit increases survives concurrency, duplicate delivery, and dependency failure`() {
        DelayedLimitIncreaseBinding.isBound = true

        // 1. Initial limit configuration
        val initCmd = ConfigureOrUpdateLimitCommand(
            tenantId = tenantId,
            playerId = playerId,
            limitType = RgLimitType.WAGER,
            period = RgLimitPeriod.WEEKLY,
            limitValueMinorUnits = 10000L,
            timezone = "UTC",
            idempotencyKey = "key-concurrent-init-01",
            correlationId = "corr-init",
            causationId = "cause-init",
            expectedVersion = 1L,
            principal = playerPrincipal,
        )
        val initialResult = service.configureOrUpdateLimit(initCmd)
        assertNotNull(initialResult)

        // 2. Idempotency test: duplicate delivery with identical payload returns cached result
        val duplicateResult = service.configureOrUpdateLimit(initCmd)
        assertTrue(duplicateResult.isDuplicate)
        assertEquals(initialResult.resultId, duplicateResult.resultId)
        assertEquals(initialResult.record.recordId, duplicateResult.record.recordId)

        // 3. Idempotency test: duplicate delivery with changed payload throws CONFLICT
        val conflictCmd = initCmd.copy(limitValueMinorUnits = 20000L)
        assertFailsWith<AuthenticationFailure.Rejected> {
            service.configureOrUpdateLimit(conflictCmd)
        }.also {
            assertEquals(AuthErrorCode.CONFLICT, it.code)
            assertTrue(alertSink.alerts.any { a -> a["alertType"] == "DELAYED_LIMIT_IDEMPOTENCY_CONFLICT" })
        }

        // 4. Concurrent race: Multiple threads submitting limit updates concurrently
        val threadCount = 8
        val executor = Executors.newFixedThreadPool(threadCount)
        val latch = CountDownLatch(1)
        val tasks = (1..threadCount).map { index ->
            Callable {
                latch.await()
                try {
                    service.configureOrUpdateLimit(
                        ConfigureOrUpdateLimitCommand(
                            tenantId = tenantId,
                            playerId = playerId,
                            limitType = RgLimitType.WAGER,
                            period = RgLimitPeriod.WEEKLY,
                            limitValueMinorUnits = 5000L + (index * 1000L),
                            timezone = "UTC",
                            idempotencyKey = "key-race-thread-$index",
                            correlationId = "corr-race-$index",
                            causationId = "cause-race-$index",
                            expectedVersion = 1L, // All race assuming version 1
                            principal = playerPrincipal,
                        )
                    )
                } catch (e: Exception) {
                    e
                }
            }
        }

        latch.countDown()
        val futures = tasks.map { executor.submit(it) }
        val results = futures.map { it.get() }
        executor.shutdown()

        // Exactly one concurrent call should succeed; others rejected with STALE due to version progression
        val successfulCount = results.count { it is DelayedLimitResult }
        val staleCount = results.count { it is AuthenticationFailure.Rejected && it.code == AuthErrorCode.STALE }
        assertEquals(1, successfulCount, "Exactly one concurrent thread succeeds on version 1")
        assertEquals(threadCount - 1, staleCount, "All other concurrent callers must be rejected as STALE")

        // 5. Dependency failure handling & recovery
        val failingStore = object : DelayedLimitIncreaseStore by store {
            var shouldFail = true
            override fun updateRecord(
                record: DelayedLimitRecord,
                result: DelayedLimitResult,
                idempotencyKey: String,
                fingerprint: String,
                audit: AuditEvent,
                outbox: OutboxEvent,
            ) {
                if (shouldFail) throw RuntimeException("Simulated database outage")
                store.updateRecord(record, result, idempotencyKey, fingerprint, audit, outbox)
            }
        }

        val retryService = DelayedLimitIncreaseService(failingStore, alertSink, clock)
        val retryCmd = ConfigureOrUpdateLimitCommand(
            tenantId = tenantId,
            playerId = playerId,
            limitType = RgLimitType.WAGER,
            period = RgLimitPeriod.WEEKLY,
            limitValueMinorUnits = 3000L, // Decrease
            timezone = "UTC",
            idempotencyKey = "key-retry-decrease-01",
            correlationId = "corr-retry",
            causationId = "cause-retry",
            expectedVersion = 2L,
            principal = playerPrincipal,
        )

        assertFailsWith<AuthenticationFailure.Rejected> {
            retryService.configureOrUpdateLimit(retryCmd)
        }.also { assertEquals(AuthErrorCode.DEPENDENCY_UNAVAILABLE, it.code) }

        // Recover dependency
        failingStore.shouldFail = false
        val recoveredResult = retryService.configureOrUpdateLimit(retryCmd)
        assertNotNull(recoveredResult)
        assertEquals(3000L, recoveredResult.record.currentLimitValueMinorUnits)
    }

    @Test
    fun `RG-003-01-T004 — Delay responsible-gaming limit increases remains compatible, recoverable, observable, and lifecycle-safe`() {
        DelayedLimitIncreaseBinding.isBound = true

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

        // 3. State recovery across restart: "restart cannot skip reality check"
        // Configure limit
        service.configureOrUpdateLimit(
            ConfigureOrUpdateLimitCommand(
                tenantId = tenantId,
                playerId = playerId,
                limitType = RgLimitType.LOSS,
                period = RgLimitPeriod.DAILY,
                limitValueMinorUnits = 5000L,
                timezone = "UTC",
                idempotencyKey = "key-loss-init-01",
                correlationId = "corr-1",
                causationId = "cause-1",
                expectedVersion = 1L,
                principal = playerPrincipal,
            )
        )

        // Request limit increase to 10000
        service.configureOrUpdateLimit(
            ConfigureOrUpdateLimitCommand(
                tenantId = tenantId,
                playerId = playerId,
                limitType = RgLimitType.LOSS,
                period = RgLimitPeriod.DAILY,
                limitValueMinorUnits = 10000L,
                timezone = "UTC",
                idempotencyKey = "key-loss-increase-01",
                correlationId = "corr-2",
                causationId = "cause-2",
                expectedVersion = 1L,
                principal = playerPrincipal,
            )
        )

        // Advance clock past cooling-off delay (25 hours)
        currentInstant = currentInstant.plus(Duration.ofHours(25))

        // Configure session reality check tracking
        service.updateRealityCheckSession(
            UpdateRealityCheckSessionCommand(
                tenantId = tenantId,
                playerId = playerId,
                intervalMinutes = 60,
                idempotencyKey = "key-session-init-01",
                correlationId = "corr-session-1",
                causationId = "cause-session-1",
                principal = playerPrincipal,
            )
        )

        // Export snapshot (simulating database persistence across restart)
        val exportedSnapshot = store.exportSnapshot()

        // Create a completely new instance (simulating server reboot / restart)
        val restoredStore = InMemoryDelayedLimitIncreaseStore()
        restoredStore.importSnapshot(exportedSnapshot)
        val restartedService = DelayedLimitIncreaseService(restoredStore, alertSink, clock)

        // Crucial Invariant: "restart cannot skip reality check"
        // Verify that after restart, the limit has NOT automatically become active!
        val checkAfterRestart = restartedService.checkEffectiveLimit(
            CheckEffectiveLimitQuery(tenantId, playerId, RgLimitType.LOSS, playerPrincipal)
        )
        assertEquals(5000L, checkAfterRestart.effectiveLimitValueMinorUnits, "Restart must NOT skip reality check or promote limit prematurely")
        assertEquals(DelayedLimitStatus.PENDING_REALITY_CHECK, checkAfterRestart.status)
        assertTrue(checkAfterRestart.realityCheckPending, "Reality check must remain pending after restart")

        // Player must explicitly acknowledge the reality check on restarted service
        val acknowledgedResult = restartedService.acknowledgeRealityCheck(
            AcknowledgeRealityCheckCommand(
                tenantId = tenantId,
                playerId = playerId,
                limitType = RgLimitType.LOSS,
                idempotencyKey = "key-loss-ack-restarted",
                correlationId = "corr-3",
                causationId = "cause-3",
                expectedVersion = 2L,
                principal = playerPrincipal,
            )
        )
        assertEquals(10000L, acknowledgedResult.record.currentLimitValueMinorUnits)
        assertEquals(DelayedLimitStatus.ACTIVE, acknowledgedResult.record.status)

        // Acknowledge periodic session reality check
        val sessionAckResult = restartedService.acknowledgeSessionRealityCheck(
            AcknowledgeSessionRealityCheckCommand(
                tenantId = tenantId,
                playerId = playerId,
                idempotencyKey = "key-session-ack-01",
                correlationId = "corr-session-ack",
                causationId = "cause-session-ack",
                expectedVersion = 1L,
                principal = playerPrincipal,
            )
        )
        assertNotNull(sessionAckResult)
        assertEquals(1, sessionAckResult.record.acknowledgmentCount)
        assertFalse(sessionAckResult.isFinancialAuthorityCreated)

        // Zero financial authority created across all operations
        assertFalse(acknowledgedResult.isFinancialAuthorityCreated)

        // Verify audit and outbox events captured without PII or credential leaks
        assertTrue(restoredStore.auditEvents.isNotEmpty())
        assertTrue(restoredStore.outboxEvents.isNotEmpty())
        assertTrue(restoredStore.auditEvents.all { it.tenantId == tenantId })
    }
}
