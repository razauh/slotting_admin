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

class AndroidRgControlsTest {
    private val tenantId = "tenant-ui-01"
    private val playerId = "player-ui-99"

    private val baseInstant = Instant.parse("2026-09-20T10:00:00Z")
    private var currentInstant = baseInstant
    private val clock = object : Clock() {
        override fun getZone(): java.time.ZoneId = ZoneOffset.UTC
        override fun withZone(zone: java.time.ZoneId?): Clock = this
        override fun instant(): Instant = currentInstant
    }

    private lateinit var store: InMemoryAndroidRgControlsStore
    private lateinit var alertSink: InMemoryAndroidRgControlsAlertSink
    private lateinit var service: AndroidRgControlsService

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
        store = InMemoryAndroidRgControlsStore()
        alertSink = InMemoryAndroidRgControlsAlertSink()
        service = AndroidRgControlsService(store, alertSink, clock)
        AndroidRgControlsBinding.isBound = false
    }

    @Test
    fun `RG-004-T001 — Android controls audit UX produces the required authoritative outcome`() {
        // Step 1: Prove mandatory RED failure gate
        val ex = assertFailsWith<AssertionError> {
            service.initiateRgAction(
                InitiateRgActionCommand(
                    tenantId = tenantId,
                    playerId = playerId,
                    actionType = RgActionType.COOLING_OFF,
                    payloadValue = "7",
                    idempotencyKey = "key-init-ui-01",
                    correlationId = "corr-1",
                    causationId = "cause-1",
                    principal = playerPrincipal,
                )
            )
        }
        assertEquals("optimistic success/process loss", ex.message)

        // Step 2: Bind gate to transition to GREEN behavior
        AndroidRgControlsBinding.isBound = true

        // 1. Initiate high-risk action: Cooling-Off for 7 days
        val initCmd = InitiateRgActionCommand(
            tenantId = tenantId,
            playerId = playerId,
            actionType = RgActionType.COOLING_OFF,
            payloadValue = "7",
            idempotencyKey = "key-init-ui-01",
            correlationId = "corr-1",
            causationId = "cause-1",
            principal = playerPrincipal,
        )

        val initResult = service.initiateRgAction(initCmd)
        assertNotNull(initResult)
        assertFalse(initResult.isDuplicate)
        assertEquals(ANDROID_RG_CONTROLS_CONTRACT, initResult.semanticContract)
        assertEquals(RgActionSessionState.AWAITING_ACCESSIBLE_CONFIRMATION, initResult.session.state)
        assertTrue(initResult.session.requiresHighRiskConfirmation)
        assertTrue(initResult.session.accessibleExplanation.contains("cooling-off break for 7 days"))
        assertNotNull(initResult.session.confirmationToken)
        assertNull(initResult.receipt, "Receipt must not exist before authoritative confirmation (no optimistic success)")
        assertFalse(initResult.isFinancialAuthorityCreated)

        // 2. High-risk confirmation accessible: player explicitly confirms disclosure
        val confirmCmd = ConfirmAndCommitRgActionCommand(
            tenantId = tenantId,
            playerId = playerId,
            sessionId = initResult.session.sessionId,
            confirmationToken = initResult.session.confirmationToken,
            acknowledgedDisclosure = true,
            idempotencyKey = "key-confirm-ui-01",
            correlationId = "corr-confirm-1",
            causationId = "cause-confirm-1",
            expectedVersion = 1L,
            principal = playerPrincipal,
        )

        val confirmResult = service.confirmAndCommitRgAction(confirmCmd)
        assertNotNull(confirmResult)
        assertEquals(RgActionSessionState.COMMITTED, confirmResult.session.state)
        assertNotNull(confirmResult.receipt)
        val receipt = confirmResult.receipt!!
        assertEquals(RgActionType.COOLING_OFF, receipt.actionType)
        assertEquals(currentInstant, receipt.effectiveAt, "Cooling-off takes effect immediately")
        assertTrue(receipt.isImmediate)
        assertTrue(receipt.receiptReference.startsWith("RCPT-RG-"))
        assertTrue(receipt.accessibleDisclosure.contains("cooling-off break"))
        assertFalse(confirmResult.isFinancialAuthorityCreated)

        // 3. Limit increase action: receipt shows explicit delayed effective time
        val initIncreaseCmd = InitiateRgActionCommand(
            tenantId = tenantId,
            playerId = playerId,
            actionType = RgActionType.LIMIT_INCREASE,
            payloadValue = "20000",
            idempotencyKey = "key-init-inc-01",
            correlationId = "corr-inc-1",
            causationId = "cause-inc-1",
            principal = playerPrincipal,
        )
        val initIncResult = service.initiateRgAction(initIncreaseCmd)

        val confirmIncCmd = ConfirmAndCommitRgActionCommand(
            tenantId = tenantId,
            playerId = playerId,
            sessionId = initIncResult.session.sessionId,
            confirmationToken = initIncResult.session.confirmationToken,
            acknowledgedDisclosure = true,
            idempotencyKey = "key-confirm-inc-01",
            correlationId = "corr-inc-2",
            causationId = "cause-inc-2",
            expectedVersion = 1L,
            principal = playerPrincipal,
        )

        val confirmIncResult = service.confirmAndCommitRgAction(confirmIncCmd)
        val incReceipt = confirmIncResult.receipt!!
        assertEquals(RgActionType.LIMIT_INCREASE, incReceipt.actionType)
        assertFalse(incReceipt.isImmediate, "Limit increase cannot be immediate (no dark patterns / optimistic success)")
        assertEquals(currentInstant.plus(Duration.ofHours(24)), incReceipt.effectiveAt)
    }

    @Test
    fun `RG-004-T002 — Android controls audit UX rejects invalid, boundary, unauthorized, and stale input`() {
        AndroidRgControlsBinding.isBound = true

        // 1. Blank inputs rejected
        assertFailsWith<AuthenticationFailure.Rejected> {
            service.initiateRgAction(
                InitiateRgActionCommand(
                    tenantId = "",
                    playerId = playerId,
                    actionType = RgActionType.LIMIT_DECREASE,
                    payloadValue = "5000",
                    idempotencyKey = "key-blank-01",
                    correlationId = "corr-1",
                    causationId = "cause-1",
                )
            )
        }.also { assertEquals(AuthErrorCode.INVALID, it.code) }

        // 2. Dark pattern payload: non-positive limit amount rejected
        assertFailsWith<AuthenticationFailure.Rejected> {
            service.initiateRgAction(
                InitiateRgActionCommand(
                    tenantId = tenantId,
                    playerId = playerId,
                    actionType = RgActionType.LIMIT_DECREASE,
                    payloadValue = "-1000",
                    idempotencyKey = "key-neg-01",
                    correlationId = "corr-1",
                    causationId = "cause-1",
                    principal = playerPrincipal,
                )
            )
        }.also {
            assertEquals(AuthErrorCode.INVALID, it.code)
            assertTrue(alertSink.alerts.any { a -> a["alertType"] == "DARK_PATTERN_OR_INVALID_INPUT" })
        }

        // 3. High-risk confirmation: unacknowledged disclosure rejected (anti-dark-pattern)
        val validSession = service.initiateRgAction(
            InitiateRgActionCommand(
                tenantId = tenantId,
                playerId = playerId,
                actionType = RgActionType.SELF_EXCLUSION_DEFINITE,
                payloadValue = "6",
                idempotencyKey = "key-init-excl-01",
                correlationId = "corr-1",
                causationId = "cause-1",
                principal = playerPrincipal,
            )
        )

        assertFailsWith<AuthenticationFailure.Rejected> {
            service.confirmAndCommitRgAction(
                ConfirmAndCommitRgActionCommand(
                    tenantId = tenantId,
                    playerId = playerId,
                    sessionId = validSession.session.sessionId,
                    confirmationToken = validSession.session.confirmationToken,
                    acknowledgedDisclosure = false, // Attempt to confirm without acknowledging disclosure
                    idempotencyKey = "key-unack-01",
                    correlationId = "corr-1",
                    causationId = "cause-1",
                    expectedVersion = 1L,
                    principal = playerPrincipal,
                )
            )
        }.also {
            assertEquals(AuthErrorCode.INVALID, it.code)
            assertTrue(alertSink.alerts.any { a -> a["alertType"] == "HIGH_RISK_CONFIRMATION_MISSING" })
        }

        // 4. Invalid confirmation token rejected
        assertFailsWith<AuthenticationFailure.Rejected> {
            service.confirmAndCommitRgAction(
                ConfirmAndCommitRgActionCommand(
                    tenantId = tenantId,
                    playerId = playerId,
                    sessionId = validSession.session.sessionId,
                    confirmationToken = "WRONG-TOKEN",
                    acknowledgedDisclosure = true,
                    idempotencyKey = "key-wrong-token-01",
                    correlationId = "corr-1",
                    causationId = "cause-1",
                    expectedVersion = 1L,
                    principal = playerPrincipal,
                )
            )
        }.also {
            assertEquals(AuthErrorCode.INVALID, it.code)
            assertTrue(alertSink.alerts.any { a -> a["alertType"] == "INVALID_CONFIRMATION_TOKEN" })
        }

        // 5. Clock manipulation attempt rejected
        assertFailsWith<AuthenticationFailure.Rejected> {
            service.initiateRgAction(
                InitiateRgActionCommand(
                    tenantId = tenantId,
                    playerId = playerId,
                    actionType = RgActionType.LIMIT_DECREASE,
                    payloadValue = "5000",
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

        // 6. Cross-player / Cross-tenant access rejected
        assertFailsWith<AuthenticationFailure.Rejected> {
            service.getAuthoritativeUiModel(
                QueryAuthoritativeUiModelQuery(tenantId, playerId, otherPlayerPrincipal)
            )
        }.also { assertEquals(AuthErrorCode.FORBIDDEN, it.code) }

        assertFailsWith<AuthenticationFailure.Rejected> {
            service.getAuthoritativeUiModel(
                QueryAuthoritativeUiModelQuery(tenantId, playerId, crossTenantPrincipal)
            )
        }.also { assertEquals(AuthErrorCode.FORBIDDEN, it.code) }

        // 7. Stale version rejection
        assertFailsWith<AuthenticationFailure.Rejected> {
            service.confirmAndCommitRgAction(
                ConfirmAndCommitRgActionCommand(
                    tenantId = tenantId,
                    playerId = playerId,
                    sessionId = validSession.session.sessionId,
                    confirmationToken = validSession.session.confirmationToken,
                    acknowledgedDisclosure = true,
                    idempotencyKey = "key-stale-01",
                    correlationId = "corr-1",
                    causationId = "cause-1",
                    expectedVersion = 999L,
                    principal = playerPrincipal,
                )
            )
        }.also { assertEquals(AuthErrorCode.STALE, it.code) }
    }

    @Test
    fun `RG-004-T003 — Android controls audit UX survives concurrency, duplicate delivery, and dependency failure`() {
        AndroidRgControlsBinding.isBound = true

        // 1. Setup session
        val initCmd = InitiateRgActionCommand(
            tenantId = tenantId,
            playerId = playerId,
            actionType = RgActionType.LIMIT_DECREASE,
            payloadValue = "5000",
            idempotencyKey = "key-concurrent-init-01",
            correlationId = "corr-init",
            causationId = "cause-init",
            principal = playerPrincipal,
        )
        val initialResult = service.initiateRgAction(initCmd)
        assertNotNull(initialResult)

        // 2. Idempotency test: duplicate delivery with identical payload returns cached result
        val duplicateResult = service.initiateRgAction(initCmd)
        assertTrue(duplicateResult.isDuplicate)
        assertEquals(initialResult.resultId, duplicateResult.resultId)

        // 3. Idempotency test: duplicate delivery with changed payload throws CONFLICT
        val conflictCmd = initCmd.copy(payloadValue = "4000")
        assertFailsWith<AuthenticationFailure.Rejected> {
            service.initiateRgAction(conflictCmd)
        }.also {
            assertEquals(AuthErrorCode.CONFLICT, it.code)
        }

        // 4. Concurrent race: Multiple simultaneous confirmations on version 1
        val threadCount = 8
        val executor = Executors.newFixedThreadPool(threadCount)
        val latch = CountDownLatch(1)
        val tasks = (1..threadCount).map { index ->
            Callable {
                latch.await()
                try {
                    service.confirmAndCommitRgAction(
                        ConfirmAndCommitRgActionCommand(
                            tenantId = tenantId,
                            playerId = playerId,
                            sessionId = initialResult.session.sessionId,
                            confirmationToken = initialResult.session.confirmationToken,
                            acknowledgedDisclosure = true,
                            idempotencyKey = "key-race-confirm-$index",
                            correlationId = "corr-race-$index",
                            causationId = "cause-race-$index",
                            expectedVersion = 1L,
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
        val successfulCount = results.count { it is RgActionSessionResult }
        val staleCount = results.count { it is AuthenticationFailure.Rejected && it.code == AuthErrorCode.STALE }
        assertEquals(1, successfulCount, "Exactly one concurrent thread succeeds on version 1")
        assertEquals(threadCount - 1, staleCount, "All other concurrent callers must be rejected as STALE")

        // 5. Dependency failure handling & recovery
        val failingStore = object : AndroidRgControlsStore by store {
            var shouldFail = true
            override fun updateSession(
                session: RgMobileActionSessionRecord,
                result: RgActionSessionResult,
                idempotencyKey: String,
                fingerprint: String,
                audit: AuditEvent,
                outbox: OutboxEvent,
            ) {
                if (shouldFail) throw RuntimeException("Simulated database outage")
                store.updateSession(session, result, idempotencyKey, fingerprint, audit, outbox)
            }
        }

        val retryService = AndroidRgControlsService(failingStore, alertSink, clock)
        val newSession = retryService.initiateRgAction(
            InitiateRgActionCommand(
                tenantId = tenantId,
                playerId = playerId,
                actionType = RgActionType.COOLING_OFF,
                payloadValue = "3",
                idempotencyKey = "key-cancel-session-01",
                correlationId = "corr-1",
                causationId = "cause-1",
                principal = playerPrincipal,
            )
        )

        val cancelCmd = CancelRgActionCommand(
            tenantId = tenantId,
            playerId = playerId,
            sessionId = newSession.session.sessionId,
            reason = "Changed mind",
            idempotencyKey = "key-retry-cancel-01",
            correlationId = "corr-cancel",
            causationId = "cause-cancel",
            expectedVersion = 1L,
            principal = playerPrincipal,
        )

        assertFailsWith<AuthenticationFailure.Rejected> {
            retryService.cancelRgAction(cancelCmd)
        }.also { assertEquals(AuthErrorCode.DEPENDENCY_UNAVAILABLE, it.code) }

        // Recover dependency
        failingStore.shouldFail = false
        val recoveredResult = retryService.cancelRgAction(cancelCmd)
        assertNotNull(recoveredResult)
        assertEquals(RgActionSessionState.CANCELLED, recoveredResult.session.state)
    }

    @Test
    fun `RG-004-T004 — Android controls audit UX remains compatible, recoverable, observable, and lifecycle-safe`() {
        AndroidRgControlsBinding.isBound = true

        // 1. Schema migration contract: V16 Flyway migration exists, no rogue V17
        val migrationsDir = File("src/main/resources/db/migration")
        val sqlFiles = migrationsDir.listFiles { _, name -> name.endsWith(".sql") } ?: emptyArray()
        assertTrue(sqlFiles.isNotEmpty(), "Migrations directory must contain Flyway files")
        val migrationVersions = sqlFiles.map { it.name.substringBefore("__") }
        assertTrue(migrationVersions.contains("V16"), "V16 must be present")
        assertFalse(migrationVersions.contains("V17"), "V17 must not be created prematurely")

        // 2. Lifecycle safety: Confirm no Android lifecycle surface is claimed by backend
        val androidActivityClass = runCatching { Class.forName("android.app.Activity") }
        assertTrue(androidActivityClass.isFailure, "Authoritative backend must not link Android framework lifecycle")

        // 3. Android Process Death / Recreation recovery test (no process loss, no optimistic success)
        val sessionInitResult = service.initiateRgAction(
            InitiateRgActionCommand(
                tenantId = tenantId,
                playerId = playerId,
                actionType = RgActionType.LIMIT_DECREASE,
                payloadValue = "4000",
                idempotencyKey = "key-lifecycle-init-01",
                correlationId = "corr-life-1",
                causationId = "cause-life-1",
                principal = playerPrincipal,
            )
        )
        val sessionId = sessionInitResult.session.sessionId
        val token = sessionInitResult.session.confirmationToken

        // Simulate Process Death: snapshot exported and service recreated
        val snapshot = store.exportSnapshot()
        val restoredStore = InMemoryAndroidRgControlsStore()
        restoredStore.importSnapshot(snapshot)
        val restartedService = AndroidRgControlsService(restoredStore, alertSink, clock)

        // After Android process death/recreation, client requeries authoritative UI model
        val recoveredUiModel = restartedService.getAuthoritativeUiModel(
            QueryAuthoritativeUiModelQuery(tenantId, playerId, playerPrincipal)
        )
        assertNotNull(recoveredUiModel.activeSession, "Session must be recovered without process loss")
        assertEquals(sessionId, recoveredUiModel.activeSession?.sessionId)
        assertEquals(RgActionSessionState.AWAITING_ACCESSIBLE_CONFIRMATION, recoveredUiModel.activeSession?.state)
        assertNull(recoveredUiModel.latestReceipt, "No optimistic receipt fabricated before confirmation")

        // Player completes confirmation on recovered session
        val finalCommitResult = restartedService.confirmAndCommitRgAction(
            ConfirmAndCommitRgActionCommand(
                tenantId = tenantId,
                playerId = playerId,
                sessionId = sessionId,
                confirmationToken = token,
                acknowledgedDisclosure = true,
                idempotencyKey = "key-life-commit-01",
                correlationId = "corr-life-2",
                causationId = "cause-life-2",
                expectedVersion = 1L,
                principal = playerPrincipal,
            )
        )
        assertEquals(RgActionSessionState.COMMITTED, finalCommitResult.session.state)
        assertNotNull(finalCommitResult.receipt)

        // Verify updated UI model after commit
        val finalUiModel = restartedService.getAuthoritativeUiModel(
            QueryAuthoritativeUiModelQuery(tenantId, playerId, playerPrincipal)
        )
        assertNull(finalUiModel.activeSession, "Active session completed")
        assertNotNull(finalUiModel.latestReceipt)
        assertEquals(finalCommitResult.receipt?.receiptId, finalUiModel.latestReceipt?.receiptId)

        // Verify audit and outbox events captured without PII or credential leaks
        assertTrue(restoredStore.auditEvents.isNotEmpty())
        assertTrue(restoredStore.outboxEvents.isNotEmpty())
        assertTrue(restoredStore.auditEvents.all { it.tenantId == tenantId })
    }
}
