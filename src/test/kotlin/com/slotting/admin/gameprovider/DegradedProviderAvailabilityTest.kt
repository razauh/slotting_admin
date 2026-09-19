package com.slotting.admin.gameprovider

import com.slotting.admin.auth.AdminPermission
import com.slotting.admin.auth.AdminRbacPolicy
import com.slotting.admin.auth.AdminRole
import com.slotting.admin.auth.AuthErrorCode
import com.slotting.admin.auth.AuthenticatedPrincipal
import com.slotting.admin.auth.AuthenticationFailure
import com.slotting.admin.auth.PrincipalKind
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test
import java.time.Clock
import java.time.Instant
import java.time.ZoneOffset
import java.util.concurrent.Callable
import java.util.concurrent.Executors
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertNotNull
import kotlin.test.assertTrue

class DegradedProviderAvailabilityTest {

    private val fixedInstant = Instant.parse("2026-09-19T08:00:00Z")
    private val clock = Clock.fixed(fixedInstant, ZoneOffset.UTC)

    private val tenantId = "tenant-casino-alpha"
    private val providerId = "prv-pragmatic"

    private lateinit var store: InMemoryProviderAvailabilityStore
    private lateinit var alertSink: InMemoryProviderAvailabilityAlertSink
    private lateinit var rbacPolicy: AdminRbacPolicy
    private lateinit var service: DegradedProviderAvailabilityService

    private val authorizedAdmin = AuthenticatedPrincipal(
        id = "admin-sec-ops",
        tenantId = tenantId,
        roles = setOf(AdminRole.SUPER_ADMIN),
        kind = PrincipalKind.ADMIN,
    )

    private val unauthorizedPlayer = AuthenticatedPrincipal(
        id = "player-123",
        tenantId = tenantId,
        roles = emptySet(),
        kind = PrincipalKind.PLAYER,
    )

    @BeforeEach
    fun setUp() {
        DegradedProviderAvailabilityBinding.isBound = true
        store = InMemoryProviderAvailabilityStore()
        alertSink = InMemoryProviderAvailabilityAlertSink()
        rbacPolicy = AdminRbacPolicy(true)

        service = DegradedProviderAvailabilityService(
            store = store,
            rbacPolicy = rbacPolicy,
            alertSink = alertSink,
            clock = clock,
        )
    }

    // =========================================================================
    // GAME-009-02-T001: Authoritative Availability Transition & Semantic Contract
    // =========================================================================

    @Test
    fun `GAME-009-02-T001 Control degraded provider availability produces the required authoritative outcome`() {
        DegradedProviderAvailabilityBinding.checkBound()

        // Initially AVAILABLE: launch is permitted
        service.assertLaunchPermitted(tenantId, providerId)
        assertTrue(service.assertSettlementPermitted(tenantId, providerId))

        // 1. Transition provider to DEGRADED
        val degradeCmd = UpdateProviderAvailabilityCommand(
            principal = authorizedAdmin,
            tenantId = tenantId,
            providerId = providerId,
            targetStatus = ProviderAvailabilityStatus.DEGRADED,
            reason = "Spike in callback timeout latency detected by monitoring",
            idempotencyKey = "k-avail-001",
            correlationId = "c-avail-001",
            causationId = "cause-avail-001",
            expectedVersion = 1L,
        )

        val degradeResult = service.updateProviderAvailability(degradeCmd)

        assertEquals(ProviderAvailabilityStatus.DEGRADED, degradeResult.status)
        assertFalse(degradeResult.newLaunchPermitted)
        assertTrue(degradeResult.inFlightSettlementPermitted)
        assertEquals(2L, degradeResult.version)
        assertNotNull(degradeResult.evidenceReference)

        // Exact assertion: "Disabled/degraded provider blocks new launch while settling safe known outcomes."
        // A) Launch is blocked!
        assertFailsWith<AuthenticationFailure.Rejected> {
            service.assertLaunchPermitted(tenantId, providerId)
        }.also { assertEquals(AuthErrorCode.FORBIDDEN, it.code) }

        assertTrue(alertSink.alerts.any { it.contains("PROVIDER_LAUNCH_BLOCKED_UNAVAILABLE") })

        // B) Settlement is STILL permitted!
        assertTrue(service.assertSettlementPermitted(tenantId, providerId))

        // 2. Audit and outbox events recorded
        val audits = store.auditEvents.filter { it.resultId == degradeResult.resultId }
        assertEquals(1, audits.size)
        assertEquals("PROVIDER_AVAILABILITY_CHANGED_DEGRADED", audits[0].type)
        assertEquals("c-avail-001", audits[0].correlationId)

        val outboxes = store.outboxEvents.filter { it.resultId == degradeResult.resultId }
        assertEquals(1, outboxes.size)

        // 3. Automatic Health Trip: Consecutive probe failures trip to DEGRADED
        val autoTripService = DegradedProviderAvailabilityService(
            store = store,
            rbacPolicy = rbacPolicy,
            alertSink = alertSink,
            clock = clock,
        )

        val autoProvider = "prv-evolution"
        for (i in 1..2) {
            autoTripService.recordHealthSignal(
                RecordProviderHealthSignalCommand(tenantId, autoProvider, success = false, latencyMs = 5000, errorReason = "Timeout", failureThreshold = 3)
            )
        }
        // After 2 failures, still AVAILABLE
        autoTripService.assertLaunchPermitted(tenantId, autoProvider)

        // 3rd failure reaches threshold of 3 -> trips to DEGRADED
        autoTripService.recordHealthSignal(
            RecordProviderHealthSignalCommand(tenantId, autoProvider, success = false, latencyMs = 5000, errorReason = "Timeout", failureThreshold = 3)
        )
        assertFailsWith<AuthenticationFailure.Rejected> {
            autoTripService.assertLaunchPermitted(tenantId, autoProvider)
        }.also { assertEquals(AuthErrorCode.FORBIDDEN, it.code) }
        assertTrue(alertSink.alerts.any { it.contains("PROVIDER_AUTOMATIC_TRIP_DEGRADED") })
    }

    // =========================================================================
    // GAME-009-02-T002: Negative, Boundary, Security & Authorization Rejection
    // =========================================================================

    @Test
    fun `GAME-009-02-T002 Control degraded provider availability rejects invalid, boundary, unauthorized, and stale input`() {
        DegradedProviderAvailabilityBinding.checkBound()

        val baseCmd = UpdateProviderAvailabilityCommand(
            principal = authorizedAdmin,
            tenantId = tenantId,
            providerId = providerId,
            targetStatus = ProviderAvailabilityStatus.DISABLED,
            reason = "Emergency operator kill switch",
            idempotencyKey = "k-sec-001",
            correlationId = "c-sec",
            causationId = "cause-sec",
            expectedVersion = 1L,
        )

        // 1. Unauthorized caller (Player principal) -> FORBIDDEN
        assertFailsWith<AuthenticationFailure.Rejected> {
            service.updateProviderAvailability(baseCmd.copy(principal = unauthorizedPlayer, idempotencyKey = "k-unauth"))
        }.also { assertEquals(AuthErrorCode.FORBIDDEN, it.code) }

        // 2. Unauthenticated principal -> UNAUTHENTICATED
        assertFailsWith<AuthenticationFailure.Rejected> {
            service.updateProviderAvailability(baseCmd.copy(principal = null, idempotencyKey = "k-null-princ"))
        }.also { assertEquals(AuthErrorCode.UNAUTHENTICATED, it.code) }

        // 3. Cross-tenant attempt -> FORBIDDEN
        val crossTenantAdmin = authorizedAdmin.copy(tenantId = "other-tenant")
        assertFailsWith<AuthenticationFailure.Rejected> {
            service.updateProviderAvailability(baseCmd.copy(principal = crossTenantAdmin, idempotencyKey = "k-cross-tenant"))
        }.also { assertEquals(AuthErrorCode.FORBIDDEN, it.code) }

        // 4. Stale Version: expectedVersion = 99L -> STALE
        assertFailsWith<AuthenticationFailure.Rejected> {
            service.updateProviderAvailability(baseCmd.copy(expectedVersion = 99L, idempotencyKey = "k-stale-ver"))
        }.also { assertEquals(AuthErrorCode.STALE, it.code) }

        // 5. Blank required parameter -> INVALID
        assertFailsWith<AuthenticationFailure.Rejected> {
            service.updateProviderAvailability(baseCmd.copy(reason = "", idempotencyKey = "k-blank-reason"))
        }.also { assertEquals(AuthErrorCode.INVALID, it.code) }

        // Verify zero unauthorized mutations occurred
        assertEquals(0, store.listAll(tenantId).size)
    }

    // =========================================================================
    // GAME-009-02-T003: Concurrency, Duplicate Delivery, and Idempotency
    // =========================================================================

    @Test
    fun `GAME-009-02-T003 Control degraded provider availability survives concurrency and duplicate delivery`() {
        DegradedProviderAvailabilityBinding.checkBound()

        val cmd = UpdateProviderAvailabilityCommand(
            principal = authorizedAdmin,
            tenantId = tenantId,
            providerId = providerId,
            targetStatus = ProviderAvailabilityStatus.DEGRADED,
            reason = "Latency threshold excursion",
            idempotencyKey = "k-conc-avail-01",
            correlationId = "c-conc",
            causationId = "cause-conc",
            expectedVersion = 1L,
        )

        // 1. Idempotent replay: exact same command returns identical result
        val res1 = service.updateProviderAvailability(cmd)
        val res2 = service.updateProviderAvailability(cmd)

        assertEquals(res1.resultId, res2.resultId)
        assertEquals(res1.status, res2.status)
        assertEquals(res1.version, res2.version)
        assertEquals(1, store.listAll(tenantId).size)

        // 2. Conflicting payload under same idempotency key throws CONFLICT
        assertFailsWith<AuthenticationFailure.Rejected> {
            service.updateProviderAvailability(cmd.copy(targetStatus = ProviderAvailabilityStatus.DISABLED))
        }.also { assertEquals(AuthErrorCode.CONFLICT, it.code) }

        // 3. Concurrent conflicting updates race condition: exactly one succeeds
        val concurrentProvider = "prv-race-provider"
        val executor = Executors.newFixedThreadPool(8)
        val tasks = (1..8).map { i ->
            Callable {
                try {
                    service.updateProviderAvailability(
                        UpdateProviderAvailabilityCommand(
                            principal = authorizedAdmin,
                            tenantId = tenantId,
                            providerId = concurrentProvider,
                            targetStatus = if (i % 2 == 0) ProviderAvailabilityStatus.DEGRADED else ProviderAvailabilityStatus.DISABLED,
                            reason = "Concurrent test race $i",
                            idempotencyKey = "k-race-$i",
                            correlationId = "c-race-$i",
                            causationId = "cause-race-$i",
                            expectedVersion = 1L, // All expect version 1L
                        )
                    )
                } catch (e: Exception) {
                    null
                }
            }
        }

        val results = executor.invokeAll(tasks).mapNotNull { it.get() }
        executor.shutdown()

        // Exactly one concurrent update succeeds from version 1L!
        assertEquals(1, results.size)
        val finalRecord = store.findAvailability(tenantId, concurrentProvider)!!
        assertEquals(2L, finalRecord.version)
    }

    // =========================================================================
    // GAME-009-02-T004: Lifecycle, Observability, and Redaction
    // =========================================================================

    @Test
    fun `GAME-009-02-T004 Control degraded provider availability remains compatible, recoverable, observable, and lifecycle-safe`() {
        DegradedProviderAvailabilityBinding.checkBound()

        // 1. Service Recreation / Restart preserves provider availability status
        val cmd = UpdateProviderAvailabilityCommand(
            principal = authorizedAdmin,
            tenantId = tenantId,
            providerId = providerId,
            targetStatus = ProviderAvailabilityStatus.DISABLED,
            reason = "Planned maintenance window",
            idempotencyKey = "k-life-001",
            correlationId = "c-life",
            causationId = "cause-life",
            expectedVersion = 1L,
        )

        val res = service.updateProviderAvailability(cmd)

        val restartedService = DegradedProviderAvailabilityService(
            store = store,
            rbacPolicy = rbacPolicy,
            alertSink = alertSink,
            clock = clock,
        )

        // After restart, disabled provider STILL blocks launches!
        assertFailsWith<AuthenticationFailure.Rejected> {
            restartedService.assertLaunchPermitted(tenantId, providerId)
        }.also { assertEquals(AuthErrorCode.FORBIDDEN, it.code) }

        // But settlement is STILL permitted
        assertTrue(restartedService.assertSettlementPermitted(tenantId, providerId))

        // Replay under new instance
        val replay = restartedService.updateProviderAvailability(cmd)
        assertEquals(res.resultId, replay.resultId)

        // 2. Actionable alerts generated
        assertTrue(alertSink.alerts.any { it.contains("PROVIDER_AVAILABILITY_ALERT") })

        // 3. Zero secrets or PII in audit events or alerts
        for (a in store.auditEvents) {
            assertFalse(a.type.contains("secret"))
            assertFalse(a.correlationId.contains("secret"))
        }
        for (alert in alertSink.alerts) {
            assertFalse(alert.contains("password"))
            assertFalse(alert.contains("secret"))
        }
    }
}
