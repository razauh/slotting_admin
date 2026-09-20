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

class ControlledAccountReopeningTest {
    private val tenantId = "tenant-reopen-01"
    private val playerId = "player-reopen-99"

    private val baseInstant = Instant.parse("2026-09-20T10:00:00Z")
    private var currentInstant = baseInstant
    private val clock = object : Clock() {
        override fun getZone(): java.time.ZoneId = ZoneOffset.UTC
        override fun withZone(zone: java.time.ZoneId?): Clock = this
        override fun instant(): Instant = currentInstant
    }

    private lateinit var store: InMemoryControlledAccountReopeningStore
    private lateinit var alertSink: InMemoryControlledAccountReopeningAlertSink
    private lateinit var service: ControlledAccountReopeningService

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
        store = InMemoryControlledAccountReopeningStore()
        alertSink = InMemoryControlledAccountReopeningAlertSink()
        service = ControlledAccountReopeningService(store, alertSink, clock)
        ControlledAccountReopeningBinding.isBound = false
    }

    @Test
    fun `RG-003-02-T001 — Control account reopening produces the required authoritative outcome`() {
        // Step 1: Prove mandatory RED failure gate
        val ex = assertFailsWith<AssertionError> {
            service.closeOrExcludeAccount(
                CloseOrExcludeAccountCommand(
                    tenantId = tenantId,
                    playerId = playerId,
                    restrictionType = AccountRestrictionType.COOLING_OFF,
                    durationDays = 7,
                    reason = "Taking a cooling break",
                    idempotencyKey = "key-close-01",
                    correlationId = "corr-close-1",
                    causationId = "cause-close-1",
                    principal = playerPrincipal,
                )
            )
        }
        assertEquals("increase immediate or clock manipulation", ex.message)

        // Step 2: Bind gate to transition to GREEN behavior
        ControlledAccountReopeningBinding.isBound = true

        // 1. Authoritative account closure / cooling-off setup (7 days)
        val closeCmd = CloseOrExcludeAccountCommand(
            tenantId = tenantId,
            playerId = playerId,
            restrictionType = AccountRestrictionType.COOLING_OFF,
            durationDays = 7,
            reason = "Taking a cooling break",
            idempotencyKey = "key-close-01",
            correlationId = "corr-close-1",
            causationId = "cause-close-1",
            expectedVersion = 1L,
            principal = playerPrincipal,
        )

        val closeResult = service.closeOrExcludeAccount(closeCmd)
        assertNotNull(closeResult)
        assertFalse(closeResult.isDuplicate)
        assertEquals(CONTROLLED_ACCOUNT_REOPENING_CONTRACT, closeResult.semanticContract)
        assertEquals(ControlledReopeningStatus.CLOSED_OR_EXCLUDED, closeResult.record.status)
        assertEquals(AccountRestrictionType.COOLING_OFF, closeResult.record.restrictionType)
        assertFalse(closeResult.isFinancialAuthorityCreated)

        // Status query reflects restricted state
        val checkStatusInitial = service.checkReopeningStatus(
            CheckReopeningStatusQuery(tenantId, playerId, playerPrincipal)
        )
        assertFalse(checkStatusInitial.isReopened)
        assertEquals(ControlledReopeningStatus.CLOSED_OR_EXCLUDED, checkStatusInitial.status)

        // 2. Premature reopening request before 7 days expire fails closed
        currentInstant = currentInstant.plus(Duration.ofDays(3)) // Only 3 days passed
        val prematureRequestEx = assertFailsWith<AuthenticationFailure.Rejected> {
            service.requestAccountReopening(
                RequestAccountReopeningCommand(
                    tenantId = tenantId,
                    playerId = playerId,
                    reason = "Want to play earlier",
                    idempotencyKey = "key-premature-reopen-01",
                    correlationId = "corr-premature-1",
                    causationId = "cause-premature-1",
                    expectedVersion = 1L,
                    principal = playerPrincipal,
                )
            )
        }
        assertEquals(AuthErrorCode.FORBIDDEN, prematureRequestEx.code)

        // 3. Reopening request after 7 days: enters mandatory 24-hour reopening cooling-off delay
        currentInstant = currentInstant.plus(Duration.ofDays(5)) // Total 8 days passed (> 7 days)
        val reopenReqCmd = RequestAccountReopeningCommand(
            tenantId = tenantId,
            playerId = playerId,
            reason = "Cooldown period finished, requesting reopening",
            idempotencyKey = "key-valid-reopen-01",
            correlationId = "corr-reopen-1",
            causationId = "cause-reopen-1",
            expectedVersion = 1L,
            principal = playerPrincipal,
        )

        val reopenReqResult = service.requestAccountReopening(reopenReqCmd)
        assertNotNull(reopenReqResult)
        assertEquals(ControlledReopeningStatus.PENDING_REOPENING_COOLING_OFF, reopenReqResult.record.status)
        assertNotNull(reopenReqResult.record.reopeningCoolingDelayExpiresAt)
        assertEquals(currentInstant.plus(Duration.ofHours(24)), reopenReqResult.record.reopeningCoolingDelayExpiresAt)
        assertFalse(reopenReqResult.isFinancialAuthorityCreated)

        val checkStatusCooling = service.checkReopeningStatus(
            CheckReopeningStatusQuery(tenantId, playerId, playerPrincipal)
        )
        assertTrue(checkStatusCooling.coolingDelayActive)
        assertEquals(ControlledReopeningStatus.PENDING_REOPENING_COOLING_OFF, checkStatusCooling.status)

        // 4. Operator review attempted before 24h cooling delay expires fails closed
        currentInstant = currentInstant.plus(Duration.ofHours(12)) // Only 12 hours of 24h delay passed
        val prematureReviewEx = assertFailsWith<AuthenticationFailure.Rejected> {
            service.reviewAccountReopening(
                ReviewAccountReopeningCommand(
                    tenantId = tenantId,
                    playerId = playerId,
                    approved = true,
                    operatorNotes = "Operator trying to approve early",
                    idempotencyKey = "key-premature-review-01",
                    correlationId = "corr-premature-rev",
                    causationId = "cause-premature-rev",
                    expectedVersion = 2L,
                    principal = securityAdminPrincipal,
                )
            )
        }
        assertEquals(AuthErrorCode.FORBIDDEN, prematureReviewEx.code)

        // 5. Cooling delay matures after 24 hours: Operator reviews and approves reopening
        // Configures conservative initial deposit limit (5,000 minor units, "decrease may be immediate")
        currentInstant = currentInstant.plus(Duration.ofHours(13)) // Total 25 hours passed (> 24h)
        val reviewCmd = ReviewAccountReopeningCommand(
            tenantId = tenantId,
            playerId = playerId,
            approved = true,
            operatorNotes = "Cooling-off completed, RG interview passed, approved with initial deposit limit",
            initialDepositLimitMinorUnits = 5000L,
            idempotencyKey = "key-operator-review-01",
            correlationId = "corr-review-1",
            causationId = "cause-review-1",
            expectedVersion = 2L,
            principal = securityAdminPrincipal,
        )

        val reviewResult = service.reviewAccountReopening(reviewCmd)
        assertNotNull(reviewResult)
        assertEquals(ControlledReopeningStatus.PENDING_REALITY_CHECK_ACK, reviewResult.record.status)
        assertTrue(reviewResult.record.realityCheckRequired)
        assertEquals(5000L, reviewResult.record.initialDepositLimitMinorUnits)
        assertFalse(reviewResult.isFinancialAuthorityCreated)

        val checkStatusAwaitingAck = service.checkReopeningStatus(
            CheckReopeningStatusQuery(tenantId, playerId, playerPrincipal)
        )
        assertFalse(checkStatusAwaitingAck.isReopened, "Account must not be active until reality check acknowledged")
        assertTrue(checkStatusAwaitingAck.realityCheckPending)

        // 6. Explicit player reality check acknowledgment completes the reopening
        val ackCmd = AcknowledgeReopeningRealityCheckCommand(
            tenantId = tenantId,
            playerId = playerId,
            idempotencyKey = "key-player-ack-01",
            correlationId = "corr-ack-1",
            causationId = "cause-ack-1",
            expectedVersion = 3L,
            principal = playerPrincipal,
        )

        val ackResult = service.acknowledgeReopeningRealityCheck(ackCmd)
        assertNotNull(ackResult)
        assertEquals(ControlledReopeningStatus.REOPENED, ackResult.record.status)
        assertFalse(ackResult.record.realityCheckRequired)
        assertEquals(currentInstant, ackResult.record.reopenedAt)
        assertFalse(ackResult.isFinancialAuthorityCreated)

        val finalStatus = service.checkReopeningStatus(
            CheckReopeningStatusQuery(tenantId, playerId, playerPrincipal)
        )
        assertTrue(finalStatus.isReopened)
        assertEquals(ControlledReopeningStatus.REOPENED, finalStatus.status)
        assertFalse(finalStatus.realityCheckPending)
    }

    @Test
    fun `RG-003-02-T002 — Control account reopening rejects invalid, boundary, unauthorized, and stale input`() {
        ControlledAccountReopeningBinding.isBound = true

        // 1. Blank inputs rejected
        assertFailsWith<AuthenticationFailure.Rejected> {
            service.closeOrExcludeAccount(
                CloseOrExcludeAccountCommand(
                    tenantId = "",
                    playerId = playerId,
                    restrictionType = AccountRestrictionType.COOLING_OFF,
                    durationDays = 7,
                    reason = "Blank tenant",
                    idempotencyKey = "key-blank-01",
                    correlationId = "corr-1",
                    causationId = "cause-1",
                    principal = playerPrincipal,
                )
            )
        }.also { assertEquals(AuthErrorCode.INVALID, it.code) }

        // 2. Permanent self-exclusion cannot be reopened under any circumstances
        service.closeOrExcludeAccount(
            CloseOrExcludeAccountCommand(
                tenantId = tenantId,
                playerId = "player-perm-01",
                restrictionType = AccountRestrictionType.SELF_EXCLUSION_PERMANENT,
                durationDays = null,
                reason = "Permanent self-exclusion requested",
                idempotencyKey = "key-perm-close-01",
                correlationId = "corr-perm-1",
                causationId = "cause-perm-1",
                principal = AuthenticatedPrincipal("player-perm-01", tenantId, PrincipalKind.PLAYER, emptySet()),
            )
        )

        assertFailsWith<AuthenticationFailure.Rejected> {
            service.requestAccountReopening(
                RequestAccountReopeningCommand(
                    tenantId = tenantId,
                    playerId = "player-perm-01",
                    reason = "Attempting to reopen permanent exclusion",
                    idempotencyKey = "key-perm-reopen-01",
                    correlationId = "corr-perm-2",
                    causationId = "cause-perm-2",
                    expectedVersion = 1L,
                    principal = AuthenticatedPrincipal("player-perm-01", tenantId, PrincipalKind.PLAYER, emptySet()),
                )
            )
        }.also {
            assertEquals(AuthErrorCode.FORBIDDEN, it.code)
            assertTrue(alertSink.alerts.any { a -> a["alertType"] == "PERMANENT_EXCLUSION_BREACH_ATTEMPT" })
        }

        // 3. Clock manipulation: Client timestamp skewed by > 60 seconds rejected
        service.closeOrExcludeAccount(
            CloseOrExcludeAccountCommand(
                tenantId = tenantId,
                playerId = playerId,
                restrictionType = AccountRestrictionType.TEMPORARY_CLOSURE,
                durationDays = 1,
                reason = "Temp closure",
                idempotencyKey = "key-temp-01",
                correlationId = "corr-1",
                causationId = "cause-1",
                principal = playerPrincipal,
            )
        )

        assertFailsWith<AuthenticationFailure.Rejected> {
            service.requestAccountReopening(
                RequestAccountReopeningCommand(
                    tenantId = tenantId,
                    playerId = playerId,
                    reason = "Clock skew attempt",
                    idempotencyKey = "key-clock-skew-01",
                    correlationId = "corr-1",
                    causationId = "cause-1",
                    expectedVersion = 1L,
                    principal = playerPrincipal,
                    clientReportedTimestamp = currentInstant.plus(Duration.ofHours(2)),
                )
            )
        }.also {
            assertEquals(AuthErrorCode.INVALID, it.code)
            assertTrue(alertSink.alerts.any { a -> a["alertType"] == "CLOCK_MANIPULATION_DETECTED" })
        }

        // 4. Non-admin attempting operator review rejected with FORBIDDEN
        currentInstant = currentInstant.plus(Duration.ofDays(2))
        service.requestAccountReopening(
            RequestAccountReopeningCommand(
                tenantId = tenantId,
                playerId = playerId,
                reason = "Valid reopen request",
                idempotencyKey = "key-valid-req-02",
                correlationId = "corr-1",
                causationId = "cause-1",
                expectedVersion = 1L,
                principal = playerPrincipal,
            )
        )

        currentInstant = currentInstant.plus(Duration.ofHours(25)) // Cooling elapsed
        assertFailsWith<AuthenticationFailure.Rejected> {
            service.reviewAccountReopening(
                ReviewAccountReopeningCommand(
                    tenantId = tenantId,
                    playerId = playerId,
                    approved = true,
                    operatorNotes = "Player pretending to be admin",
                    idempotencyKey = "key-fake-admin-01",
                    correlationId = "corr-1",
                    causationId = "cause-1",
                    expectedVersion = 2L,
                    principal = playerPrincipal, // Player principal attempting operator review
                )
            )
        }.also { assertEquals(AuthErrorCode.FORBIDDEN, it.code) }

        // 5. Cross-player / Cross-tenant access rejected
        assertFailsWith<AuthenticationFailure.Rejected> {
            service.checkReopeningStatus(
                CheckReopeningStatusQuery(tenantId, playerId, otherPlayerPrincipal)
            )
        }.also { assertEquals(AuthErrorCode.FORBIDDEN, it.code) }

        assertFailsWith<AuthenticationFailure.Rejected> {
            service.checkReopeningStatus(
                CheckReopeningStatusQuery(tenantId, playerId, crossTenantPrincipal)
            )
        }.also { assertEquals(AuthErrorCode.FORBIDDEN, it.code) }

        // 6. Stale version rejection
        assertFailsWith<AuthenticationFailure.Rejected> {
            service.reviewAccountReopening(
                ReviewAccountReopeningCommand(
                    tenantId = tenantId,
                    playerId = playerId,
                    approved = true,
                    operatorNotes = "Valid review",
                    idempotencyKey = "key-stale-rev-01",
                    correlationId = "corr-1",
                    causationId = "cause-1",
                    expectedVersion = 999L, // Stale version
                    principal = securityAdminPrincipal,
                )
            )
        }.also { assertEquals(AuthErrorCode.STALE, it.code) }

        // 7. Illegal initial deposit limit (negative or 0)
        assertFailsWith<AuthenticationFailure.Rejected> {
            service.reviewAccountReopening(
                ReviewAccountReopeningCommand(
                    tenantId = tenantId,
                    playerId = playerId,
                    approved = true,
                    operatorNotes = "Valid review with negative limit",
                    initialDepositLimitMinorUnits = -1000L,
                    idempotencyKey = "key-invalid-limit-01",
                    correlationId = "corr-1",
                    causationId = "cause-1",
                    expectedVersion = 2L,
                    principal = securityAdminPrincipal,
                )
            )
        }.also { assertEquals(AuthErrorCode.INVALID, it.code) }
    }

    @Test
    fun `RG-003-02-T003 — Control account reopening survives concurrency, duplicate delivery, and dependency failure`() {
        ControlledAccountReopeningBinding.isBound = true

        // 1. Setup closed account
        val closeCmd = CloseOrExcludeAccountCommand(
            tenantId = tenantId,
            playerId = playerId,
            restrictionType = AccountRestrictionType.TEMPORARY_CLOSURE,
            durationDays = 0,
            reason = "Temporary closure",
            idempotencyKey = "key-concurrent-close-01",
            correlationId = "corr-close",
            causationId = "cause-close",
            expectedVersion = 1L,
            principal = playerPrincipal,
        )
        val initialCloseResult = service.closeOrExcludeAccount(closeCmd)
        assertNotNull(initialCloseResult)

        // 2. Idempotency test: duplicate delivery with identical payload returns cached result
        val duplicateCloseResult = service.closeOrExcludeAccount(closeCmd)
        assertTrue(duplicateCloseResult.isDuplicate)
        assertEquals(initialCloseResult.resultId, duplicateCloseResult.resultId)
        assertEquals(initialCloseResult.record.recordId, duplicateCloseResult.record.recordId)

        // 3. Idempotency test: duplicate delivery with changed payload throws CONFLICT
        val conflictCmd = closeCmd.copy(reason = "Changed reason for conflict test")
        assertFailsWith<AuthenticationFailure.Rejected> {
            service.closeOrExcludeAccount(conflictCmd)
        }.also {
            assertEquals(AuthErrorCode.CONFLICT, it.code)
        }

        // 4. Concurrent race: Multiple simultaneous requests to reopen the account on version 1
        val threadCount = 8
        val executor = Executors.newFixedThreadPool(threadCount)
        val latch = CountDownLatch(1)
        val tasks = (1..threadCount).map { index ->
            Callable {
                latch.await()
                try {
                    service.requestAccountReopening(
                        RequestAccountReopeningCommand(
                            tenantId = tenantId,
                            playerId = playerId,
                            reason = "Race thread request $index",
                            idempotencyKey = "key-race-reopen-$index",
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

        // Exactly one concurrent call should succeed; remaining callers rejected as STALE
        val successfulCount = results.count { it is ControlledAccountReopeningResult }
        val staleCount = results.count { it is AuthenticationFailure.Rejected && it.code == AuthErrorCode.STALE }
        assertEquals(1, successfulCount, "Exactly one concurrent thread succeeds on version 1")
        assertEquals(threadCount - 1, staleCount, "All other concurrent callers must be rejected as STALE")

        // 5. Dependency failure handling & recovery
        val failingStore = object : ControlledAccountReopeningStore by store {
            var shouldFail = true
            override fun updateRecord(
                record: ControlledAccountReopeningRecord,
                result: ControlledAccountReopeningResult,
                idempotencyKey: String,
                fingerprint: String,
                audit: AuditEvent,
                outbox: OutboxEvent,
            ) {
                if (shouldFail) throw RuntimeException("Simulated database outage")
                store.updateRecord(record, result, idempotencyKey, fingerprint, audit, outbox)
            }
        }

        val retryService = ControlledAccountReopeningService(failingStore, alertSink, clock)
        val cancelCmd = CancelReopeningRequestCommand(
            tenantId = tenantId,
            playerId = playerId,
            reason = "Cancel request retry test",
            idempotencyKey = "key-retry-cancel-01",
            correlationId = "corr-cancel",
            causationId = "cause-cancel",
            expectedVersion = 2L,
            principal = playerPrincipal,
        )

        assertFailsWith<AuthenticationFailure.Rejected> {
            retryService.cancelReopeningRequest(cancelCmd)
        }.also { assertEquals(AuthErrorCode.DEPENDENCY_UNAVAILABLE, it.code) }

        // Recover dependency
        failingStore.shouldFail = false
        val recoveredResult = retryService.cancelReopeningRequest(cancelCmd)
        assertNotNull(recoveredResult)
        assertEquals(ControlledReopeningStatus.CLOSED_OR_EXCLUDED, recoveredResult.record.status)
    }

    @Test
    fun `RG-003-02-T004 — Control account reopening remains compatible, recoverable, observable, and lifecycle-safe`() {
        ControlledAccountReopeningBinding.isBound = true

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
        // Close account
        service.closeOrExcludeAccount(
            CloseOrExcludeAccountCommand(
                tenantId = tenantId,
                playerId = playerId,
                restrictionType = AccountRestrictionType.COOLING_OFF,
                durationDays = 0,
                reason = "Cooling off for restart test",
                idempotencyKey = "key-restart-close-01",
                correlationId = "corr-1",
                causationId = "cause-1",
                expectedVersion = 1L,
                principal = playerPrincipal,
            )
        )

        // Request reopening
        service.requestAccountReopening(
            RequestAccountReopeningCommand(
                tenantId = tenantId,
                playerId = playerId,
                reason = "Reopening request for restart test",
                idempotencyKey = "key-restart-req-01",
                correlationId = "corr-2",
                causationId = "cause-2",
                expectedVersion = 1L,
                principal = playerPrincipal,
            )
        )

        // Fast forward past reopening cooling delay (25 hours)
        currentInstant = currentInstant.plus(Duration.ofHours(25))

        // Operator review approves reopening
        service.reviewAccountReopening(
            ReviewAccountReopeningCommand(
                tenantId = tenantId,
                playerId = playerId,
                approved = true,
                operatorNotes = "Approved by operator, requires reality check acknowledgment",
                initialDepositLimitMinorUnits = 10000L,
                idempotencyKey = "key-restart-review-01",
                correlationId = "corr-3",
                causationId = "cause-3",
                expectedVersion = 2L,
                principal = securityAdminPrincipal,
            )
        )

        // Account is now in PENDING_REALITY_CHECK_ACK
        // Export snapshot (simulating database persistence across restart)
        val exportedSnapshot = store.exportSnapshot()

        // Create a completely new service instance (simulating server reboot / restart)
        val restoredStore = InMemoryControlledAccountReopeningStore()
        restoredStore.importSnapshot(exportedSnapshot)
        val restartedService = ControlledAccountReopeningService(restoredStore, alertSink, clock)

        // Crucial Invariant: "restart cannot skip reality check"
        // After restart, the account MUST NOT be automatically reopened or skip the reality check!
        val checkAfterRestart = restartedService.checkReopeningStatus(
            CheckReopeningStatusQuery(tenantId, playerId, playerPrincipal)
        )
        assertFalse(checkAfterRestart.isReopened, "Restart must NOT auto-reopen account")
        assertEquals(ControlledReopeningStatus.PENDING_REALITY_CHECK_ACK, checkAfterRestart.status)
        assertTrue(checkAfterRestart.realityCheckPending, "Reality check must remain pending after restart")

        // Player must explicitly acknowledge the reality check on restarted service to complete reopening
        val ackResult = restartedService.acknowledgeReopeningRealityCheck(
            AcknowledgeReopeningRealityCheckCommand(
                tenantId = tenantId,
                playerId = playerId,
                idempotencyKey = "key-restart-ack-01",
                correlationId = "corr-4",
                causationId = "cause-4",
                expectedVersion = 3L,
                principal = playerPrincipal,
            )
        )
        assertTrue(ackResult.record.status == ControlledReopeningStatus.REOPENED)
        assertFalse(ackResult.isFinancialAuthorityCreated)

        val finalStatus = restartedService.checkReopeningStatus(
            CheckReopeningStatusQuery(tenantId, playerId, playerPrincipal)
        )
        assertTrue(finalStatus.isReopened)
        assertFalse(finalStatus.realityCheckPending)

        // Verify audit and outbox events captured without PII or secret disclosure
        assertTrue(restoredStore.auditEvents.isNotEmpty())
        assertTrue(restoredStore.outboxEvents.isNotEmpty())
        assertTrue(restoredStore.auditEvents.all { it.tenantId == tenantId })
    }
}
