package com.slotting.admin.rg

import com.slotting.admin.auth.*
import java.io.File
import java.time.Clock
import java.time.Duration
import java.time.Instant
import java.time.ZoneId
import java.time.ZoneOffset
import java.util.UUID
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.CountDownLatch
import java.util.concurrent.Executors
import kotlin.test.*
import org.junit.jupiter.api.AfterEach
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test

class CoolingOffSelfExclusionTest {
    private var now = Instant.parse("2026-09-20T12:00:00Z")
    private val clock = object : Clock() {
        override fun getZone(): ZoneId = ZoneOffset.UTC
        override fun withZone(zone: ZoneId): Clock = this
        override fun instant(): Instant = now
    }
    private val tenantId = "tenant-rg-2"
    private val playerId = "player-excl-201"

    private val adminPrincipal = AuthenticatedPrincipal(
        id = "admin-rg-02",
        tenantId = tenantId,
        kind = PrincipalKind.ADMIN,
        roles = setOf(AdminRole.SUPER_ADMIN),
    )

    private val auditorPrincipal = AuthenticatedPrincipal(
        id = "auditor-rg-02",
        tenantId = tenantId,
        kind = PrincipalKind.ADMIN,
        roles = setOf(AdminRole.AUDITOR),
    )

    private val securityPrincipal = AuthenticatedPrincipal(
        id = "security-rg-02",
        tenantId = tenantId,
        kind = PrincipalKind.ADMIN,
        roles = setOf(AdminRole.SECURITY),
    )

    private val supportPrincipal = AuthenticatedPrincipal(
        id = "support-rg-02",
        tenantId = tenantId,
        kind = PrincipalKind.ADMIN,
        roles = setOf(AdminRole.SUPPORT),
    )

    private val crossTenantPrincipal = AuthenticatedPrincipal(
        id = "admin-cross-02",
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
        id = "player-other-777",
        tenantId = tenantId,
        kind = PrincipalKind.PLAYER,
        roles = emptySet(),
    )

    private lateinit var store: InMemoryCoolingOffSelfExclusionStore
    private lateinit var alertSink: InMemoryCoolingOffSelfExclusionAlertSink
    private lateinit var service: CoolingOffSelfExclusionService

    @BeforeEach
    fun setUp() {
        CoolingOffSelfExclusionBinding.isBound = true
        store = InMemoryCoolingOffSelfExclusionStore()
        alertSink = InMemoryCoolingOffSelfExclusionAlertSink()
        service = CoolingOffSelfExclusionService(
            store = store,
            alertSink = alertSink,
            clock = clock,
        )
    }

    @AfterEach
    fun tearDown() {
        CoolingOffSelfExclusionBinding.isBound = true
    }

    @Test
    fun `RG-002-T001 — Cooling-off self-exclusion produces the required authoritative outcome`() {
        // 1. Expected RED failure verification: Fail-closed gate throws expected assertion when unbound
        CoolingOffSelfExclusionBinding.isBound = false

        val coolingOffCmd = ApplyCoolingOffCommand(
            tenantId = tenantId,
            playerId = playerId,
            durationDays = 7,
            reason = "Take a break from gaming",
            idempotencyKey = "key-cooloff-01",
            correlationId = "corr-cooloff-1",
            causationId = "cause-cooloff-1",
            principal = playerSelfPrincipal,
        )

        val gateError = assertFailsWith<AssertionError> {
            service.applyCoolingOff(coolingOffCmd)
        }
        assertEquals("existing session/alternate game continues", gateError.message)

        // Bind the fail-closed gate
        CoolingOffSelfExclusionBinding.isBound = true

        // 2. Authoritative Cooling-Off application
        val coolResult = service.applyCoolingOff(coolingOffCmd)
        assertNotNull(coolResult)
        assertFalse(coolResult.isDuplicate)
        assertFalse(coolResult.isFinancialAuthorityCreated, "Exclusion cannot create financial authority or mutate money")
        assertEquals(COOLING_OFF_SELF_EXCLUSION_CONTRACT, coolResult.semanticContract)
        assertEquals(ExclusionType.COOLING_OFF, coolResult.record.type)
        assertEquals(ExclusionStatus.ACTIVE, coolResult.record.status)
        assertTrue(coolResult.record.sessionsRevokedCount > 0, "Existing sessions must be terminated immediately")
        assertTrue(alertSink.alerts.any { it.contains("COOLING_OFF_APPLIED") })

        // Check exclusion immediate cross-product enforcement (prevents alternate game / existing session continuation)
        val checkSlots = service.checkExclusion(CheckExclusionQuery(tenantId, playerId, targetProduct = "SLOTS"))
        assertTrue(checkSlots.isExcluded, "SLOTS must be blocked immediately upon cooling-off")

        val checkLive = service.checkExclusion(CheckExclusionQuery(tenantId, playerId, targetProduct = "LIVE_CASINO"))
        assertTrue(checkLive.isExcluded, "Alternate product LIVE_CASINO must be blocked immediately")

        val checkCrash = service.checkExclusion(CheckExclusionQuery(tenantId, playerId, targetProduct = "CRASH_GAME"))
        assertTrue(checkCrash.isExcluded, "Alternate product CRASH_GAME must be blocked immediately")

        // 3. Fast-forward past cooling-off expiry (7 days later)
        now = now.plus(Duration.ofDays(8))
        val checkAfterExpiry = service.checkExclusion(CheckExclusionQuery(tenantId, playerId))
        assertFalse(checkAfterExpiry.isExcluded, "Player should no longer be excluded after cooling-off term expires")
        assertEquals(ExclusionStatus.EXPIRED, checkAfterExpiry.status)

        // 4. Authoritative Self-Exclusion with Formal Reopening Workflow
        val player2 = "player-excl-202"
        val player2Self = AuthenticatedPrincipal(id = player2, tenantId = tenantId, kind = PrincipalKind.PLAYER, roles = emptySet())

        val selfExclCmd = ApplySelfExclusionCommand(
            tenantId = tenantId,
            playerId = player2,
            durationMonths = 6,
            isPermanent = false,
            reason = "Long term responsible play break",
            idempotencyKey = "key-selfexcl-01",
            correlationId = "corr-selfexcl-1",
            causationId = "cause-selfexcl-1",
            principal = player2Self,
        )
        val selfExclResult = service.applySelfExclusion(selfExclCmd)
        assertNotNull(selfExclResult)
        assertEquals(ExclusionType.SELF_EXCLUSION_TEMPORARY, selfExclResult.record.type)
        assertEquals(ExclusionStatus.ACTIVE, selfExclResult.record.status)
        assertTrue(alertSink.alerts.any { it.contains("SELF_EXCLUSION_APPLIED") })

        // Immediate cross-product enforcement
        val checkP2 = service.checkExclusion(CheckExclusionQuery(tenantId, player2, targetProduct = "SLOTS"))
        assertTrue(checkP2.isExcluded)

        // Irreversibility rule: Reopening request BEFORE term expiration is strictly rejected
        val prematureReopenCmd = RequestReopeningCommand(
            tenantId = tenantId,
            playerId = player2,
            exclusionId = selfExclResult.record.exclusionId,
            requestNotes = "I want to gamble again early",
            idempotencyKey = "key-reopen-early",
            correlationId = "corr-reopen-early",
            causationId = "cause-reopen-early",
            principal = player2Self,
        )
        val earlyReopenError = assertFailsWith<AuthenticationFailure.Rejected> {
            service.requestReopening(prematureReopenCmd)
        }
        assertEquals(AuthErrorCode.FORBIDDEN, earlyReopenError.code)
        assertTrue(alertSink.alerts.any { it.contains("REOPENING_PREMATURE_FORBIDDEN") })

        // Fast-forward past the 6-month term
        now = now.plus(Duration.ofDays(190))

        // Expiry alone does NOT reopen self-exclusion automatically (still requires formal reopening procedure)
        val checkStillExcluded = service.checkExclusion(CheckExclusionQuery(tenantId, player2))
        assertTrue(checkStillExcluded.isExcluded, "Self-exclusion requires approved reopening even after term expiration")

        // Player submits formal reopening request
        val validReopenCmd = RequestReopeningCommand(
            tenantId = tenantId,
            playerId = player2,
            exclusionId = selfExclResult.record.exclusionId,
            requestNotes = "Completed self-exclusion term, requesting account reopening",
            idempotencyKey = "key-reopen-valid",
            correlationId = "corr-reopen-1",
            causationId = "cause-reopen-1",
            principal = player2Self,
        )
        val reopenReqResult = service.requestReopening(validReopenCmd)
        assertEquals(ExclusionStatus.PENDING_REOPENING_REVIEW, reopenReqResult.record.status)
        assertNotNull(reopenReqResult.record.reopeningCoolOffExpiresAt)
        assertTrue(alertSink.alerts.any { it.contains("REOPENING_REQUESTED") })

        // Operator attempts to approve BEFORE 24-hour cool-off has elapsed -> FORBIDDEN
        val approveCmd = ApproveReopeningCommand(
            tenantId = tenantId,
            playerId = player2,
            exclusionId = selfExclResult.record.exclusionId,
            approverId = "rg-officer-01",
            approvalNotes = "Verified player assessment and cooling off completed",
            idempotencyKey = "key-approve-reopen-01",
            correlationId = "corr-app-1",
            causationId = "cause-app-1",
            expectedVersion = reopenReqResult.record.version,
            principal = securityPrincipal,
        )
        val coolOffActiveError = assertFailsWith<AuthenticationFailure.Rejected> {
            service.approveReopening(approveCmd)
        }
        assertEquals(AuthErrorCode.FORBIDDEN, coolOffActiveError.code)
        assertTrue(alertSink.alerts.any { it.contains("REOPENING_APPROVAL_COOL_OFF_ACTIVE") })

        // Advance past the 24-hour reopening cool-off
        now = now.plus(Duration.ofHours(25))

        // Operator approval succeeds
        val approvalResult = service.approveReopening(approveCmd)
        assertEquals(ExclusionStatus.REOPENED, approvalResult.record.status)
        assertEquals("rg-officer-01", approvalResult.record.reopenedBy)
        assertTrue(alertSink.alerts.any { it.contains("REOPENING_APPROVED") })

        // Now player is no longer excluded
        val checkReopened = service.checkExclusion(CheckExclusionQuery(tenantId, player2))
        assertFalse(checkReopened.isExcluded)

        // 5. Idempotent replay: Calling again with same idempotency key returns cached duplicate
        val replayedCoolingOff = service.applyCoolingOff(coolingOffCmd)
        assertTrue(replayedCoolingOff.isDuplicate)
        assertEquals(coolResult.resultId, replayedCoolingOff.resultId)
    }

    @Test
    fun `RG-002-T002 — Cooling-off self-exclusion rejects invalid, boundary, unauthorized, and stale input`() {
        val validCmd = ApplyCoolingOffCommand(
            tenantId = tenantId,
            playerId = playerId,
            durationDays = 7,
            reason = "Break",
            idempotencyKey = "key-val-01",
            correlationId = "corr-val-1",
            causationId = "cause-val-1",
            principal = playerSelfPrincipal,
        )

        // 1. Blank mandatory fields
        assertFailsWith<AuthenticationFailure.Rejected> {
            service.applyCoolingOff(validCmd.copy(tenantId = "   "))
        }.also { assertEquals(AuthErrorCode.INVALID, it.code) }

        assertFailsWith<AuthenticationFailure.Rejected> {
            service.applyCoolingOff(validCmd.copy(playerId = ""))
        }.also { assertEquals(AuthErrorCode.INVALID, it.code) }

        assertFailsWith<AuthenticationFailure.Rejected> {
            service.applyCoolingOff(validCmd.copy(reason = ""))
        }.also { assertEquals(AuthErrorCode.INVALID, it.code) }

        assertFailsWith<AuthenticationFailure.Rejected> {
            service.applyCoolingOff(validCmd.copy(idempotencyKey = ""))
        }.also { assertEquals(AuthErrorCode.INVALID, it.code) }

        // 2. Zero or negative duration
        assertFailsWith<AuthenticationFailure.Rejected> {
            service.applyCoolingOff(validCmd.copy(durationDays = 0))
        }.also { assertEquals(AuthErrorCode.INVALID, it.code) }

        assertFailsWith<AuthenticationFailure.Rejected> {
            service.applyCoolingOff(validCmd.copy(durationDays = -5))
        }.also { assertEquals(AuthErrorCode.INVALID, it.code) }

        // 3. Principal authorization: Player applying for another player -> FORBIDDEN
        assertFailsWith<AuthenticationFailure.Rejected> {
            service.applyCoolingOff(validCmd.copy(principal = playerOtherPrincipal))
        }.also { assertEquals(AuthErrorCode.FORBIDDEN, it.code) }

        // Cross-tenant principal -> FORBIDDEN
        assertFailsWith<AuthenticationFailure.Rejected> {
            service.applyCoolingOff(validCmd.copy(principal = crossTenantPrincipal))
        }.also { assertEquals(AuthErrorCode.FORBIDDEN, it.code) }

        // Admin without SUPER_ADMIN/SECURITY/AUDITOR (e.g. SUPPORT) -> FORBIDDEN
        assertFailsWith<AuthenticationFailure.Rejected> {
            service.applyCoolingOff(validCmd.copy(principal = supportPrincipal))
        }.also { assertEquals(AuthErrorCode.FORBIDDEN, it.code) }

        // 4. Permanent self-exclusion cannot be reopened
        val permCmd = ApplySelfExclusionCommand(
            tenantId = tenantId,
            playerId = "player-perm-01",
            isPermanent = true,
            reason = "Permanent exclusion",
            idempotencyKey = "key-perm-01",
            correlationId = "corr-perm",
            causationId = "cause-perm",
            principal = adminPrincipal,
        )
        val permResult = service.applySelfExclusion(permCmd)

        val reopenPermCmd = RequestReopeningCommand(
            tenantId = tenantId,
            playerId = "player-perm-01",
            exclusionId = permResult.record.exclusionId,
            requestNotes = "Reopen permanent",
            idempotencyKey = "key-reopen-perm-fail",
            correlationId = "corr-perm-fail",
            causationId = "cause-perm-fail",
            principal = adminPrincipal,
        )
        val permReopenError = assertFailsWith<AuthenticationFailure.Rejected> {
            service.requestReopening(reopenPermCmd)
        }
        assertEquals(AuthErrorCode.FORBIDDEN, permReopenError.code)
        assertTrue(alertSink.alerts.any { it.contains("REOPENING_FORBIDDEN_PERMANENT") })

        // 5. Stale expected version on approval
        val tempExcl = service.applySelfExclusion(
            ApplySelfExclusionCommand(
                tenantId = tenantId,
                playerId = "player-stale-01",
                durationMonths = 6,
                isPermanent = false,
                reason = "Break",
                idempotencyKey = "key-stale-excl",
                correlationId = "corr-stale",
                causationId = "cause-stale",
                principal = adminPrincipal,
            )
        )
        now = now.plus(Duration.ofDays(200)) // Past term
        val reqResult = service.requestReopening(
            RequestReopeningCommand(
                tenantId = tenantId,
                playerId = "player-stale-01",
                exclusionId = tempExcl.record.exclusionId,
                requestNotes = "Reopening request",
                idempotencyKey = "key-req-stale",
                correlationId = "corr-req",
                causationId = "cause-req",
                principal = adminPrincipal,
            )
        )
        now = now.plus(Duration.ofHours(25)) // Past cool-off

        assertFailsWith<AuthenticationFailure.Rejected> {
            service.approveReopening(
                ApproveReopeningCommand(
                    tenantId = tenantId,
                    playerId = "player-stale-01",
                    exclusionId = tempExcl.record.exclusionId,
                    approverId = "officer-01",
                    approvalNotes = "Notes",
                    idempotencyKey = "key-app-stale",
                    correlationId = "corr-app",
                    causationId = "cause-app",
                    expectedVersion = 999L, // Stale version
                    principal = securityPrincipal,
                )
            )
        }.also { assertEquals(AuthErrorCode.STALE, it.code) }

        // 6. Idempotency conflict: same key with different payload
        service.applyCoolingOff(validCmd)
        assertFailsWith<AuthenticationFailure.Rejected> {
            service.applyCoolingOff(validCmd.copy(durationDays = 30))
        }.also { assertEquals(AuthErrorCode.CONFLICT, it.code) }
    }

    @Test
    fun `RG-002-T003 — Cooling-off self-exclusion survives concurrency, duplicate delivery, and dependency failure`() {
        val threadCount = 8
        val executor = Executors.newFixedThreadPool(threadCount)
        val startLatch = CountDownLatch(1)
        val endLatch = CountDownLatch(threadCount)

        val results = ConcurrentHashMap<Int, ExclusionResult>()
        val exceptions = ConcurrentHashMap<Int, Throwable>()

        val cmd = ApplyCoolingOffCommand(
            tenantId = tenantId,
            playerId = playerId,
            durationDays = 14,
            reason = "Taking 2 weeks break",
            idempotencyKey = "key-conc-cooloff-01",
            correlationId = "corr-conc-1",
            causationId = "cause-conc-1",
            principal = playerSelfPrincipal,
        )

        for (i in 0 until threadCount) {
            executor.submit {
                try {
                    startLatch.await()
                    val res = service.applyCoolingOff(cmd)
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

        assertTrue(exceptions.isEmpty(), "Concurrent executions must not throw errors: ${exceptions.values}")
        assertEquals(threadCount, results.size)

        // All threads converge on the identical exclusion ID
        val distinctExclusionIds = results.values.map { it.record.exclusionId }.toSet()
        assertEquals(1, distinctExclusionIds.size, "All threads must return identical exclusion ID")

        // Exactly 1 primary creation and 7 duplicate responses
        val duplicateCount = results.values.count { it.isDuplicate }
        assertEquals(threadCount - 1, duplicateCount)

        // Storage dependency failure handling
        class FailingExclusionStore : InMemoryCoolingOffSelfExclusionStore() {
            var shouldFail = true
            override fun saveExclusion(
                record: ExclusionRecord,
                result: ExclusionResult,
                idempotencyKey: String,
                fingerprint: String,
                audit: AuditEvent,
                outbox: OutboxEvent,
            ) {
                if (shouldFail) {
                    throw RuntimeException("Exclusion database timeout")
                }
                super.saveExclusion(record, result, idempotencyKey, fingerprint, audit, outbox)
            }
        }

        val failingStore = FailingExclusionStore()
        val retryService = CoolingOffSelfExclusionService(
            store = failingStore,
            alertSink = alertSink,
            clock = clock,
        )

        val retryCmd = ApplyCoolingOffCommand(
            tenantId = tenantId,
            playerId = "player-retry-01",
            durationDays = 3,
            reason = "Break",
            idempotencyKey = "key-retry-cooloff",
            correlationId = "corr-retry",
            causationId = "cause-retry",
            principal = adminPrincipal,
        )

        val depError = assertFailsWith<AuthenticationFailure.Rejected> {
            retryService.applyCoolingOff(retryCmd)
        }
        assertEquals(AuthErrorCode.DEPENDENCY_UNAVAILABLE, depError.code)
        assertTrue(alertSink.alerts.any { it.contains("EXCLUSION_STORAGE_FAILED") })

        // Zero corrupt state committed on storage failure
        assertNull(failingStore.findActiveExclusion(tenantId, "player-retry-01"))

        // Dependency recovers: Retry succeeds cleanly
        failingStore.shouldFail = false
        val recoveredResult = retryService.applyCoolingOff(retryCmd)
        assertNotNull(recoveredResult)
        assertFalse(recoveredResult.isDuplicate)
        assertNotNull(failingStore.findActiveExclusion(tenantId, "player-retry-01"))
    }

    @Test
    fun `RG-002-T004 — Cooling-off self-exclusion remains compatible, recoverable, observable, and lifecycle-safe`() {
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
        val exclCmd = ApplyCoolingOffCommand(
            tenantId = tenantId,
            playerId = playerId,
            durationDays = 7,
            reason = "Restart test break",
            idempotencyKey = "key-restart-excl-01",
            correlationId = "corr-restart-1",
            causationId = "cause-restart-1",
            principal = playerSelfPrincipal,
        )

        val initialResult = service.applyCoolingOff(exclCmd)
        assertNotNull(initialResult)
        assertFalse(initialResult.isDuplicate)

        // Export snapshot and import into fresh store instance simulating server restart
        val snapshot = store.exportSnapshot()
        val rehydratedStore = InMemoryCoolingOffSelfExclusionStore()
        rehydratedStore.importSnapshot(snapshot)
        val restartedService = CoolingOffSelfExclusionService(
            store = rehydratedStore,
            alertSink = alertSink,
            clock = clock,
        )

        // Calling with same idempotency key on rehydrated store returns identical cached outcome
        val replayedResult = restartedService.applyCoolingOff(exclCmd)
        assertEquals(initialResult.resultId, replayedResult.resultId)
        assertTrue(replayedResult.isDuplicate)
        assertEquals(COOLING_OFF_SELF_EXCLUSION_CONTRACT, replayedResult.semanticContract)

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
