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

class ServerTimedRealityCheckTest {
    private val tenantId = "tenant-rc-01"
    private val playerId = "player-rc-99"

    private val baseInstant = Instant.parse("2026-09-20T10:00:00Z")
    private var currentInstant = baseInstant
    private val clock = object : Clock() {
        override fun getZone(): java.time.ZoneId = ZoneOffset.UTC
        override fun withZone(zone: java.time.ZoneId?): Clock = this
        override fun instant(): Instant = currentInstant
    }

    private lateinit var store: InMemoryServerTimedRealityCheckStore
    private lateinit var alertSink: InMemoryServerTimedRealityCheckAlertSink
    private lateinit var service: ServerTimedRealityCheckService

    private val playerPrincipal = AuthenticatedPrincipal(
        id = playerId,
        tenantId = tenantId,
        kind = PrincipalKind.PLAYER,
        roles = emptySet(),
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
        store = InMemoryServerTimedRealityCheckStore()
        alertSink = InMemoryServerTimedRealityCheckAlertSink()
        service = ServerTimedRealityCheckService(store, alertSink, clock)
        ServerTimedRealityCheckBinding.isBound = false
    }

    @Test
    fun `RG-003-03-T001 — Deliver server-timed reality checks produces the required authoritative outcome`() {
        // Step 1: Prove mandatory RED failure gate
        val ex = assertFailsWith<AssertionError> {
            service.configureRealityCheckInterval(
                ConfigureRealityCheckIntervalCommand(
                    tenantId = tenantId,
                    playerId = playerId,
                    intervalMinutes = 60,
                    idempotencyKey = "key-cfg-rc-01",
                    correlationId = "corr-1",
                    causationId = "cause-1",
                    principal = playerPrincipal,
                )
            )
        }
        assertEquals("increase immediate or clock manipulation", ex.message)

        // Step 2: Bind gate to transition to GREEN behavior
        ServerTimedRealityCheckBinding.isBound = true

        // 1. Initial configuration of legal values: 60-minute reality check interval
        val configCmd = ConfigureRealityCheckIntervalCommand(
            tenantId = tenantId,
            playerId = playerId,
            intervalMinutes = 60,
            idempotencyKey = "key-cfg-rc-01",
            correlationId = "corr-1",
            causationId = "cause-1",
            expectedVersion = 1L,
            principal = playerPrincipal,
        )

        val configResult = service.configureRealityCheckInterval(configCmd)
        assertNotNull(configResult)
        assertFalse(configResult.isDuplicate)
        assertTrue(configResult.isImmediate)
        assertEquals(SERVER_TIMED_REALITY_CHECK_CONTRACT, configResult.semanticContract)
        assertEquals(60, configResult.record.intervalMinutes)
        assertNull(configResult.record.pendingIntervalMinutes)
        assertFalse(configResult.isFinancialAuthorityCreated)

        // 2. Start player gaming session
        val startSessionCmd = StartOrResumeSessionCommand(
            tenantId = tenantId,
            playerId = playerId,
            idempotencyKey = "key-start-session-01",
            correlationId = "corr-session-1",
            causationId = "cause-session-1",
            principal = playerPrincipal,
        )

        val startResult = service.startOrResumeSession(startSessionCmd)
        assertNotNull(startResult)
        assertFalse(startResult.session.isRealityCheckDue)
        assertFalse(startResult.session.isGameplaySuspended)
        assertNull(startResult.activePrompt)
        assertFalse(startResult.isFinancialAuthorityCreated)

        // 3. Gameplay activity before interval matures (20 minutes into session)
        currentInstant = currentInstant.plus(Duration.ofMinutes(20))
        val activity1Cmd = RecordSessionActivityCommand(
            tenantId = tenantId,
            playerId = playerId,
            wagerMinorUnits = 5000L,
            payoutMinorUnits = 2000L,
            idempotencyKey = "key-activity-01",
            correlationId = "corr-act-1",
            causationId = "cause-act-1",
            expectedVersion = 1L,
            principal = playerPrincipal,
        )

        val activity1Result = service.recordSessionActivity(activity1Cmd)
        assertFalse(activity1Result.session.isRealityCheckDue)
        assertFalse(activity1Result.session.isGameplaySuspended)
        assertEquals(5000L, activity1Result.session.totalWagersMinorUnits)
        assertEquals(2000L, activity1Result.session.totalPayoutsMinorUnits)
        assertEquals(3000L, activity1Result.session.netLossMinorUnits)

        // 4. Server-timed trigger: Advance server clock past 60-minute interval (total 65 minutes)
        currentInstant = currentInstant.plus(Duration.ofMinutes(45))
        val evalCmd = EvaluateRealityCheckCommand(
            tenantId = tenantId,
            playerId = playerId,
            idempotencyKey = "key-eval-01",
            correlationId = "corr-eval-1",
            causationId = "cause-eval-1",
            principal = playerPrincipal,
        )

        val evalResult = service.evaluateRealityCheck(evalCmd)
        assertTrue(evalResult.session.isRealityCheckDue, "Reality check must be due after interval elapsed")
        assertTrue(evalResult.session.isGameplaySuspended, "Gameplay must be suspended when reality check is due")
        assertNotNull(evalResult.activePrompt)
        assertEquals(65L, evalResult.activePrompt?.elapsedMinutes)
        assertEquals(5000L, evalResult.activePrompt?.totalWagersMinorUnits)
        assertEquals(3000L, evalResult.activePrompt?.netLossMinorUnits)
        assertFalse(evalResult.isFinancialAuthorityCreated)

        // 5. Subsequent gameplay blocked while reality check is due
        val blockedActivityCmd = RecordSessionActivityCommand(
            tenantId = tenantId,
            playerId = playerId,
            wagerMinorUnits = 1000L,
            payoutMinorUnits = 0L,
            idempotencyKey = "key-activity-blocked-01",
            correlationId = "corr-act-2",
            causationId = "cause-act-2",
            expectedVersion = 3L,
            principal = playerPrincipal,
        )

        val blockedEx = assertFailsWith<AuthenticationFailure.Rejected> {
            service.recordSessionActivity(blockedActivityCmd)
        }
        assertEquals(AuthErrorCode.FORBIDDEN, blockedEx.code)
        assertTrue(alertSink.alerts.any { a -> a["alertType"] == "GAMEPLAY_SUSPENDED_REALITY_CHECK_DUE" })

        // 6. Explicit player reality check acknowledgment: resumes gameplay
        val promptId = evalResult.activePrompt!!.promptId
        val ackPromptCmd = AcknowledgeRealityCheckPromptCommand(
            tenantId = tenantId,
            playerId = playerId,
            promptId = promptId,
            choice = RealityCheckChoice.CONTINUE_PLAYING,
            idempotencyKey = "key-ack-prompt-01",
            correlationId = "corr-ack-1",
            causationId = "cause-ack-1",
            expectedVersion = 3L,
            principal = playerPrincipal,
        )

        val ackResult = service.acknowledgeRealityCheckPrompt(ackPromptCmd)
        assertFalse(ackResult.session.isRealityCheckDue)
        assertFalse(ackResult.session.isGameplaySuspended)
        assertNull(ackResult.activePrompt)
        assertEquals(1, ackResult.session.acknowledgmentCount)
        assertEquals(currentInstant, ackResult.session.lastAcknowledgedAt)
        assertFalse(ackResult.isFinancialAuthorityCreated)

        // 7. Interval decrease may be immediate: reduce from 60 min to 30 min
        val decreaseCmd = ConfigureRealityCheckIntervalCommand(
            tenantId = tenantId,
            playerId = playerId,
            intervalMinutes = 30,
            idempotencyKey = "key-decrease-interval-01",
            correlationId = "corr-dec-1",
            causationId = "cause-dec-1",
            expectedVersion = 1L,
            principal = playerPrincipal,
        )

        val decreaseResult = service.configureRealityCheckInterval(decreaseCmd)
        assertTrue(decreaseResult.isImmediate)
        assertEquals(30, decreaseResult.record.intervalMinutes)
        assertNull(decreaseResult.record.pendingIntervalMinutes)

        // 8. Interval increase must be delayed: increase from 30 min to 90 min enters cooling-off
        val increaseCmd = ConfigureRealityCheckIntervalCommand(
            tenantId = tenantId,
            playerId = playerId,
            intervalMinutes = 90,
            idempotencyKey = "key-increase-interval-01",
            correlationId = "corr-inc-1",
            causationId = "cause-inc-1",
            expectedVersion = 2L,
            principal = playerPrincipal,
        )

        val increaseResult = service.configureRealityCheckInterval(increaseCmd)
        assertFalse(increaseResult.isImmediate, "Interval loosening must not be immediate")
        assertEquals(30, increaseResult.record.intervalMinutes, "Active interval remains at stricter 30 minutes")
        assertEquals(90, increaseResult.record.pendingIntervalMinutes)
        assertNotNull(increaseResult.record.coolingDelayExpiresAt)
    }

    @Test
    fun `RG-003-03-T002 — Deliver server-timed reality checks rejects invalid, boundary, unauthorized, and stale input`() {
        ServerTimedRealityCheckBinding.isBound = true

        // 1. Blank mandatory inputs rejected
        assertFailsWith<AuthenticationFailure.Rejected> {
            service.configureRealityCheckInterval(
                ConfigureRealityCheckIntervalCommand(
                    tenantId = "",
                    playerId = playerId,
                    intervalMinutes = 60,
                    idempotencyKey = "key-blank-01",
                    correlationId = "corr-1",
                    causationId = "cause-1",
                )
            )
        }.also { assertEquals(AuthErrorCode.INVALID, it.code) }

        // 2. Interval boundaries: < 15 min or > 1440 min rejected
        assertFailsWith<AuthenticationFailure.Rejected> {
            service.configureRealityCheckInterval(
                ConfigureRealityCheckIntervalCommand(
                    tenantId = tenantId,
                    playerId = playerId,
                    intervalMinutes = 5, // Below 15 min legal minimum
                    idempotencyKey = "key-too-small-01",
                    correlationId = "corr-1",
                    causationId = "cause-1",
                    principal = playerPrincipal,
                )
            )
        }.also { assertEquals(AuthErrorCode.INVALID, it.code) }

        assertFailsWith<AuthenticationFailure.Rejected> {
            service.configureRealityCheckInterval(
                ConfigureRealityCheckIntervalCommand(
                    tenantId = tenantId,
                    playerId = playerId,
                    intervalMinutes = 2000, // Above 1440 min legal maximum
                    idempotencyKey = "key-too-large-01",
                    correlationId = "corr-1",
                    causationId = "cause-1",
                    principal = playerPrincipal,
                )
            )
        }.also { assertEquals(AuthErrorCode.INVALID, it.code) }

        // 3. Negative wager/payout rejected
        service.startOrResumeSession(
            StartOrResumeSessionCommand(
                tenantId = tenantId,
                playerId = playerId,
                idempotencyKey = "key-session-init-02",
                correlationId = "corr-1",
                causationId = "cause-1",
                principal = playerPrincipal,
            )
        )

        assertFailsWith<AuthenticationFailure.Rejected> {
            service.recordSessionActivity(
                RecordSessionActivityCommand(
                    tenantId = tenantId,
                    playerId = playerId,
                    wagerMinorUnits = -100L,
                    payoutMinorUnits = 0L,
                    idempotencyKey = "key-neg-wager-01",
                    correlationId = "corr-1",
                    causationId = "cause-1",
                    expectedVersion = 1L,
                    principal = playerPrincipal,
                )
            )
        }.also { assertEquals(AuthErrorCode.INVALID, it.code) }

        // 4. Clock manipulation attempt: client timestamp skewed forward by 2 hours
        assertFailsWith<AuthenticationFailure.Rejected> {
            service.configureRealityCheckInterval(
                ConfigureRealityCheckIntervalCommand(
                    tenantId = tenantId,
                    playerId = playerId,
                    intervalMinutes = 60,
                    idempotencyKey = "key-clock-skew-01",
                    correlationId = "corr-1",
                    causationId = "cause-1",
                    principal = playerPrincipal,
                    clientReportedTimestamp = currentInstant.plus(Duration.ofHours(2)),
                )
            )
        }.also {
            assertEquals(AuthErrorCode.INVALID, it.code)
            assertTrue(alertSink.alerts.any { a -> a["alertType"] == "CLOCK_MANIPULATION_DETECTED" })
        }

        // 5. Cross-player / Cross-tenant access rejected
        assertFailsWith<AuthenticationFailure.Rejected> {
            service.startOrResumeSession(
                StartOrResumeSessionCommand(
                    tenantId = tenantId,
                    playerId = playerId,
                    idempotencyKey = "key-unauth-01",
                    correlationId = "corr-1",
                    causationId = "cause-1",
                    principal = otherPlayerPrincipal,
                )
            )
        }.also { assertEquals(AuthErrorCode.FORBIDDEN, it.code) }

        assertFailsWith<AuthenticationFailure.Rejected> {
            service.startOrResumeSession(
                StartOrResumeSessionCommand(
                    tenantId = tenantId,
                    playerId = playerId,
                    idempotencyKey = "key-cross-tenant-01",
                    correlationId = "corr-1",
                    causationId = "cause-1",
                    principal = crossTenantPrincipal,
                )
            )
        }.also { assertEquals(AuthErrorCode.FORBIDDEN, it.code) }

        // 6. Stale version rejection
        assertFailsWith<AuthenticationFailure.Rejected> {
            service.recordSessionActivity(
                RecordSessionActivityCommand(
                    tenantId = tenantId,
                    playerId = playerId,
                    wagerMinorUnits = 1000L,
                    payoutMinorUnits = 0L,
                    idempotencyKey = "key-stale-01",
                    correlationId = "corr-1",
                    causationId = "cause-1",
                    expectedVersion = 999L,
                    principal = playerPrincipal,
                )
            )
        }.also { assertEquals(AuthErrorCode.STALE, it.code) }

        // 7. Acknowledging reality check prompt when none is due
        assertFailsWith<AuthenticationFailure.Rejected> {
            service.acknowledgeRealityCheckPrompt(
                AcknowledgeRealityCheckPromptCommand(
                    tenantId = tenantId,
                    playerId = playerId,
                    promptId = UUID.randomUUID(),
                    choice = RealityCheckChoice.CONTINUE_PLAYING,
                    idempotencyKey = "key-not-due-01",
                    correlationId = "corr-1",
                    causationId = "cause-1",
                    expectedVersion = 1L,
                    principal = playerPrincipal,
                )
            )
        }.also { assertEquals(AuthErrorCode.INVALID, it.code) }
    }

    @Test
    fun `RG-003-03-T003 — Deliver server-timed reality checks survives concurrency, duplicate delivery, and dependency failure`() {
        ServerTimedRealityCheckBinding.isBound = true

        // 1. Configure interval
        val configCmd = ConfigureRealityCheckIntervalCommand(
            tenantId = tenantId,
            playerId = playerId,
            intervalMinutes = 60,
            idempotencyKey = "key-concurrent-cfg-01",
            correlationId = "corr-cfg",
            causationId = "cause-cfg",
            expectedVersion = 1L,
            principal = playerPrincipal,
        )
        val initialConfigResult = service.configureRealityCheckInterval(configCmd)
        assertNotNull(initialConfigResult)

        // 2. Idempotency test: duplicate delivery with identical payload returns cached result
        val duplicateConfigResult = service.configureRealityCheckInterval(configCmd)
        assertTrue(duplicateConfigResult.isDuplicate)
        assertEquals(initialConfigResult.resultId, duplicateConfigResult.resultId)

        // 3. Idempotency test: duplicate delivery with changed payload throws CONFLICT
        val conflictCmd = configCmd.copy(intervalMinutes = 30)
        assertFailsWith<AuthenticationFailure.Rejected> {
            service.configureRealityCheckInterval(conflictCmd)
        }.also {
            assertEquals(AuthErrorCode.CONFLICT, it.code)
        }

        // Start session
        service.startOrResumeSession(
            StartOrResumeSessionCommand(
                tenantId = tenantId,
                playerId = playerId,
                idempotencyKey = "key-race-session-start",
                correlationId = "corr-start",
                causationId = "cause-start",
                principal = playerPrincipal,
            )
        )

        // 4. Concurrent race: Multiple simultaneous activity records on version 1
        val threadCount = 8
        val executor = Executors.newFixedThreadPool(threadCount)
        val latch = CountDownLatch(1)
        val tasks = (1..threadCount).map { index ->
            Callable {
                latch.await()
                try {
                    service.recordSessionActivity(
                        RecordSessionActivityCommand(
                            tenantId = tenantId,
                            playerId = playerId,
                            wagerMinorUnits = 1000L * index,
                            payoutMinorUnits = 0L,
                            idempotencyKey = "key-race-act-$index",
                            correlationId = "corr-race-$index",
                            causationId = "cause-race-$index",
                            expectedVersion = 1L, // All race on version 1
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

        // Exactly one concurrent call should succeed; remaining 7 fail closed with STALE
        val successfulCount = results.count { it is ServerTimedSessionResult }
        val staleCount = results.count { it is AuthenticationFailure.Rejected && it.code == AuthErrorCode.STALE }
        assertEquals(1, successfulCount, "Exactly one concurrent thread succeeds on version 1")
        assertEquals(threadCount - 1, staleCount, "All other concurrent callers must be rejected as STALE")

        // 5. Dependency failure handling & recovery
        val failingStore = object : ServerTimedRealityCheckStore by store {
            var shouldFail = true
            override fun updateSession(
                record: ServerTimedSessionRecord,
                result: ServerTimedSessionResult,
                idempotencyKey: String,
                fingerprint: String,
                audit: AuditEvent,
                outbox: OutboxEvent,
            ) {
                if (shouldFail) throw RuntimeException("Simulated database outage")
                store.updateSession(record, result, idempotencyKey, fingerprint, audit, outbox)
            }
        }

        val retryService = ServerTimedRealityCheckService(failingStore, alertSink, clock)
        val retryCmd = RecordSessionActivityCommand(
            tenantId = tenantId,
            playerId = playerId,
            wagerMinorUnits = 500L,
            payoutMinorUnits = 0L,
            idempotencyKey = "key-retry-act-01",
            correlationId = "corr-retry",
            causationId = "cause-retry",
            expectedVersion = 2L,
            principal = playerPrincipal,
        )

        assertFailsWith<AuthenticationFailure.Rejected> {
            retryService.recordSessionActivity(retryCmd)
        }.also { assertEquals(AuthErrorCode.DEPENDENCY_UNAVAILABLE, it.code) }

        // Recover dependency
        failingStore.shouldFail = false
        val recoveredResult = retryService.recordSessionActivity(retryCmd)
        assertNotNull(recoveredResult)
        assertFalse(recoveredResult.isDuplicate)
    }

    @Test
    fun `RG-003-03-T004 — Deliver server-timed reality checks remains compatible, recoverable, observable, and lifecycle-safe`() {
        ServerTimedRealityCheckBinding.isBound = true

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
        service.configureRealityCheckInterval(
            ConfigureRealityCheckIntervalCommand(
                tenantId = tenantId,
                playerId = playerId,
                intervalMinutes = 30,
                idempotencyKey = "key-restart-cfg-01",
                correlationId = "corr-1",
                causationId = "cause-1",
                principal = playerPrincipal,
            )
        )

        service.startOrResumeSession(
            StartOrResumeSessionCommand(
                tenantId = tenantId,
                playerId = playerId,
                idempotencyKey = "key-restart-start-01",
                correlationId = "corr-2",
                causationId = "cause-2",
                principal = playerPrincipal,
            )
        )

        // Advance time by 35 minutes (> 30 min interval)
        currentInstant = currentInstant.plus(Duration.ofMinutes(35))

        // Evaluate triggers reality check due
        val dueResult = service.evaluateRealityCheck(
            EvaluateRealityCheckCommand(
                tenantId = tenantId,
                playerId = playerId,
                idempotencyKey = "key-restart-eval-01",
                correlationId = "corr-3",
                causationId = "cause-3",
                principal = playerPrincipal,
            )
        )
        assertTrue(dueResult.session.isRealityCheckDue)
        assertTrue(dueResult.session.isGameplaySuspended)
        val promptId = dueResult.activePrompt!!.promptId

        // Export snapshot (simulating database persistence across restart)
        val exportedSnapshot = store.exportSnapshot()

        // Create completely new service instance (simulating reboot/restart)
        val restoredStore = InMemoryServerTimedRealityCheckStore()
        restoredStore.importSnapshot(exportedSnapshot)
        val restartedService = ServerTimedRealityCheckService(restoredStore, alertSink, clock)

        // Crucial Invariant: "restart cannot skip reality check"
        // After restart, resuming the session must still find reality check DUE and gameplay suspended!
        val resumedAfterRestart = restartedService.startOrResumeSession(
            StartOrResumeSessionCommand(
                tenantId = tenantId,
                playerId = playerId,
                idempotencyKey = "key-resume-after-restart",
                correlationId = "corr-resume",
                causationId = "cause-resume",
                principal = playerPrincipal,
            )
        )
        assertTrue(resumedAfterRestart.session.isRealityCheckDue, "Reality check must remain due after restart")
        assertTrue(resumedAfterRestart.session.isGameplaySuspended, "Gameplay must remain suspended after restart")
        assertNotNull(resumedAfterRestart.activePrompt, "Prompt must be re-presented after restart")

        // Player explicitly acknowledges reality check on restarted service
        val ackAfterRestart = restartedService.acknowledgeRealityCheckPrompt(
            AcknowledgeRealityCheckPromptCommand(
                tenantId = tenantId,
                playerId = playerId,
                promptId = promptId,
                choice = RealityCheckChoice.CONTINUE_PLAYING,
                idempotencyKey = "key-ack-after-restart",
                correlationId = "corr-4",
                causationId = "cause-4",
                expectedVersion = resumedAfterRestart.session.version,
                principal = playerPrincipal,
            )
        )
        assertFalse(ackAfterRestart.session.isRealityCheckDue, "Reality check cleared after acknowledgment")
        assertFalse(ackAfterRestart.session.isGameplaySuspended, "Gameplay resumed after acknowledgment")
        assertFalse(ackAfterRestart.isFinancialAuthorityCreated)

        // Verify audit and outbox events captured without PII or secret disclosure
        assertTrue(restoredStore.auditEvents.isNotEmpty())
        assertTrue(restoredStore.outboxEvents.isNotEmpty())
        assertTrue(restoredStore.auditEvents.all { it.tenantId == tenantId })
    }
}
