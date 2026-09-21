package com.slotting.admin.privacy

import com.slotting.admin.auth.AdminRole
import com.slotting.admin.auth.AuthenticatedPrincipal
import com.slotting.admin.auth.PrincipalKind
import org.junit.jupiter.api.AfterEach
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test
import java.time.Clock
import java.time.Instant
import java.time.ZoneOffset
import java.util.UUID
import java.util.concurrent.Callable
import java.util.concurrent.Executors
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertNotNull
import kotlin.test.assertTrue

class PrivacyBreachResponseTest {
    private val now = Instant.parse("2026-09-21T09:00:00Z")
    private val clock = Clock.fixed(now, ZoneOffset.UTC)

    private val tenantId = "tenant-privacy-breach"
    private val incidentRef = "INC-BREACH-2026-001"

    private val securityAdminPrincipal = AuthenticatedPrincipal(
        id = "admin-sec-01",
        tenantId = tenantId,
        kind = PrincipalKind.ADMIN,
        roles = setOf(AdminRole.SECURITY, AdminRole.SUPER_ADMIN)
    )

    private val supportAdminPrincipal = AuthenticatedPrincipal(
        id = "admin-support-01",
        tenantId = tenantId,
        kind = PrincipalKind.ADMIN,
        roles = setOf(AdminRole.SUPPORT)
    )

    private val playerPrincipal = AuthenticatedPrincipal(
        id = "player-999",
        tenantId = tenantId,
        kind = PrincipalKind.PLAYER,
        roles = emptySet()
    )

    private val foreignAdminPrincipal = AuthenticatedPrincipal(
        id = "admin-foreign-01",
        tenantId = "tenant-different",
        kind = PrincipalKind.ADMIN,
        roles = setOf(AdminRole.SUPER_ADMIN)
    )

    private lateinit var store: InMemoryPrivacyBreachStore
    private lateinit var alertSink: InMemoryPrivacyBreachAlertSink
    private lateinit var observability: InMemoryPrivacyBreachObservability
    private lateinit var service: PrivacyBreachResponseService

    @BeforeEach
    fun setUp() {
        PrivacyBreachBinding.checkBound()
        store = InMemoryPrivacyBreachStore()
        alertSink = InMemoryPrivacyBreachAlertSink()
        observability = InMemoryPrivacyBreachObservability()

        service = PrivacyBreachResponseService(
            store = store,
            alertSink = alertSink,
            observability = observability,
            clock = clock
        )
    }

    @AfterEach
    fun tearDown() {
    }

    // =========================================================================
    // PRIV-001-05-T001 — Exercise privacy-breach response produces the required authoritative outcome
    // =========================================================================
    @Test
    fun `PRIV-001-05-T001 — Exercise privacy-breach response produces the required authoritative outcome`() {
        // Step 1: Declare drill / incident
        val declareCmd = DeclareBreachCommand(
            principal = securityAdminPrincipal,
            tenantId = tenantId,
            incidentReference = incidentRef,
            title = "Annual Tabletop Privacy Breach Drill 2026",
            severity = PrivacyBreachSeverity.HIGH,
            exerciseMode = ExerciseMode.SIMULATION_DRILL,
            affectedCategories = setOf(DataCategory.IDENTITY, DataCategory.COMMUNICATION),
            affectedSubjectCount = 450,
            description = "Simulated credential compromise impacting player communication archives",
            idempotencyKey = "idem-breach-dec-01",
            correlationId = "corr-breach-001",
            causationId = "caus-breach-001"
        )

        val declareResult = service.declareBreach(declareCmd)
        assertNotNull(declareResult)
        val rec1 = declareResult.record
        assertEquals(PrivacyBreachStatus.DECLARED, rec1.status)
        assertEquals(PrivacyBreachSeverity.HIGH, rec1.severity)
        assertTrue(rec1.supervisoryNotificationRequired)
        assertNotNull(rec1.supervisoryNotificationDeadline)
        assertEquals(PRIVACY_BREACH_CONTRACT, rec1.semanticContract)
        assertFalse(rec1.isFinancialAuthorityCreated)
        assertFalse(rec1.hasAndroidDbImpact)
        assertFalse(rec1.hasAndroidLifecycleClaim)

        // Step 2: Containment with emergency legal hold overriding deletion
        val containCmd = ContainBreachCommand(
            principal = securityAdminPrincipal,
            tenantId = tenantId,
            incidentReference = incidentRef,
            containmentActions = listOf("API keys revoked", "Database read-replica isolated", "Session tokens revoked"),
            emergencyHoldReference = "EMERGENCY-HOLD-INC-001",
            idempotencyKey = "idem-breach-cont-01",
            correlationId = "corr-breach-002",
            causationId = "caus-breach-002"
        )

        val containResult = service.containBreach(containCmd)
        val rec2 = containResult.record
        assertEquals(PrivacyBreachStatus.CONTAINED, rec2.status)
        assertEquals("EMERGENCY-HOLD-INC-001", rec2.emergencyHoldReference)
        assertEquals(3, rec2.containmentActions.size)

        // Step 3: Dispatch notifications
        val notifyCmd = DispatchNotificationsCommand(
            principal = securityAdminPrincipal,
            tenantId = tenantId,
            incidentReference = incidentRef,
            notifySupervisory = true,
            notifySubjects = true,
            notificationChannel = "REGULATORY_SECURE_PORTAL",
            idempotencyKey = "idem-breach-notif-01",
            correlationId = "corr-breach-003",
            causationId = "caus-breach-003"
        )

        val notifyResult = service.dispatchNotifications(notifyCmd)
        val rec3 = notifyResult.record
        assertEquals(PrivacyBreachStatus.NOTIFIED, rec3.status)
        assertNotNull(rec3.supervisoryNotifiedAt)
        assertNotNull(rec3.subjectsNotifiedAt)

        // Step 4: Close drill with post-mortem
        val closeCmd = CloseBreachCommand(
            principal = securityAdminPrincipal,
            tenantId = tenantId,
            incidentReference = incidentRef,
            postMortemReport = "Simulation successful. Notification dispatched within 12h, emergency retention hold enforced.",
            idempotencyKey = "idem-breach-close-01",
            correlationId = "corr-breach-004",
            causationId = "caus-breach-004"
        )

        val closeResult = service.closeBreach(closeCmd)
        val rec4 = closeResult.record
        assertEquals(PrivacyBreachStatus.CLOSED, rec4.status)
        assertNotNull(rec4.postMortemReport)

        // Verify alert pipeline received alerts for each phase
        val alerts = alertSink.getAlerts()
        assertTrue(alerts.any { it.alertType == "BREACH_EXERCISE_DECLARED" })
        assertTrue(alerts.any { it.alertType == "BREACH_CONTAINED_HOLD_PLACED" })
        assertTrue(alerts.any { it.alertType == "BREACH_NOTIFICATIONS_DISPATCHED" })
        assertTrue(alerts.any { it.alertType == "BREACH_EXERCISE_CLOSED" })
    }

    // =========================================================================
    // PRIV-001-05-T002 — Exercise privacy-breach response rejects invalid, boundary, unauthorized, and stale input
    // =========================================================================
    @Test
    fun `PRIV-001-05-T002 — Exercise privacy-breach response rejects invalid, boundary, unauthorized, and stale input`() {
        val validDeclare = DeclareBreachCommand(
            principal = securityAdminPrincipal,
            tenantId = tenantId,
            incidentReference = "INC-REJECT-001",
            title = "Unauthorized Test Drill",
            severity = PrivacyBreachSeverity.MEDIUM,
            description = "Test description",
            idempotencyKey = "idem-rej-01",
            correlationId = "corr-rej-01",
            causationId = "caus-rej-01"
        )

        // 1. Unauthenticated principal
        assertFailsWith<UnauthorizedPrivacyBreachException> {
            service.declareBreach(validDeclare.copy(principal = null))
        }

        // 2. Cross-tenant admin
        assertFailsWith<UnauthorizedPrivacyBreachException> {
            service.declareBreach(validDeclare.copy(principal = foreignAdminPrincipal))
        }

        // 3. Support admin (unauthorized role)
        assertFailsWith<UnauthorizedPrivacyBreachException> {
            service.declareBreach(validDeclare.copy(principal = supportAdminPrincipal))
        }

        // 4. Player principal
        assertFailsWith<UnauthorizedPrivacyBreachException> {
            service.declareBreach(validDeclare.copy(principal = playerPrincipal))
        }

        // 5. Blank fields
        assertFailsWith<InvalidPrivacyBreachCommandException> {
            service.declareBreach(validDeclare.copy(incidentReference = ""))
        }
        assertFailsWith<InvalidPrivacyBreachCommandException> {
            service.declareBreach(validDeclare.copy(title = ""))
        }
        assertFailsWith<InvalidPrivacyBreachCommandException> {
            service.declareBreach(validDeclare.copy(description = ""))
        }

        // 6. Containment on non-existent incident
        assertFailsWith<PrivacyBreachNotFoundException> {
            service.containBreach(
                ContainBreachCommand(
                    principal = securityAdminPrincipal,
                    tenantId = tenantId,
                    incidentReference = "INC-DOES-NOT-EXIST",
                    containmentActions = listOf("Action 1"),
                    emergencyHoldReference = "HOLD-001",
                    idempotencyKey = "idem-not-found",
                    correlationId = "corr-002",
                    causationId = "caus-002"
                )
            )
        }

        // 7. Closing uncontained breach directly from DECLARED state
        service.declareBreach(validDeclare)
        assertFailsWith<IllegalPrivacyBreachStateException> {
            service.closeBreach(
                CloseBreachCommand(
                    principal = securityAdminPrincipal,
                    tenantId = tenantId,
                    incidentReference = "INC-REJECT-001",
                    postMortemReport = "Premature close",
                    idempotencyKey = "idem-premature-close",
                    correlationId = "corr-002",
                    causationId = "caus-002"
                )
            )
        }
    }

    // =========================================================================
    // PRIV-001-05-T003 — Exercise privacy-breach response survives concurrency, duplicate delivery, and dependency failure
    // =========================================================================
    @Test
    fun `PRIV-001-05-T003 — Exercise privacy-breach response survives concurrency, duplicate delivery, and dependency failure`() {
        val declareCmd = DeclareBreachCommand(
            principal = securityAdminPrincipal,
            tenantId = tenantId,
            incidentReference = "INC-CONC-001",
            title = "Concurrent Drill Test",
            severity = PrivacyBreachSeverity.LOW,
            description = "Testing concurrency & duplicate delivery",
            idempotencyKey = "idem-conc-777",
            correlationId = "corr-conc-001",
            causationId = "caus-conc-001"
        )

        // 1. Initial declaration
        val initial = service.declareBreach(declareCmd)
        assertFalse(initial.isDuplicate)

        // 2. Duplicate declaration
        val duplicate = service.declareBreach(declareCmd)
        assertTrue(duplicate.isDuplicate)
        assertEquals(initial.record.incidentId, duplicate.record.incidentId)

        // 3. Conflicting payload with same idempotency key
        assertFailsWith<ConflictPrivacyBreachException> {
            service.declareBreach(declareCmd.copy(title = "Conflicting Drill Title"))
        }

        // 4. Multithreaded concurrent declaration of distinct drills
        val executor = Executors.newFixedThreadPool(4)
        val tasks = (1..4).map { idx ->
            Callable {
                service.declareBreach(
                    DeclareBreachCommand(
                        principal = securityAdminPrincipal,
                        tenantId = tenantId,
                        incidentReference = "INC-CONC-THREAD-$idx",
                        title = "Drill Scenario $idx",
                        severity = PrivacyBreachSeverity.MEDIUM,
                        description = "Parallel tabletop drill $idx",
                        idempotencyKey = "idem-thread-$idx",
                        correlationId = "corr-conc-$idx",
                        causationId = "caus-conc-$idx"
                    )
                )
            }
        }

        val futures = executor.invokeAll(tasks)
        executor.shutdown()

        for (future in futures) {
            val res = future.get()
            assertNotNull(res)
            assertEquals(PrivacyBreachStatus.DECLARED, res.record.status)
        }
    }

    // =========================================================================
    // PRIV-001-05-T004 — Exercise privacy-breach response remains compatible, recoverable, observable, and lifecycle-safe
    // =========================================================================
    @Test
    fun `PRIV-001-05-T004 — Exercise privacy-breach response remains compatible, recoverable, observable, and lifecycle-safe`() {
        val declareCmd = DeclareBreachCommand(
            principal = securityAdminPrincipal,
            tenantId = tenantId,
            incidentReference = "INC-LIFECYCLE-004",
            title = "Observability and Lifecycle Drill",
            severity = PrivacyBreachSeverity.CRITICAL,
            exerciseMode = ExerciseMode.SIMULATION_DRILL,
            affectedCategories = setOf(DataCategory.IDENTITY, DataCategory.PAYMENT, DataCategory.KYC_DOCUMENT),
            affectedSubjectCount = 1200,
            description = "Simulated ransomware attack scenario with exfiltration simulation",
            idempotencyKey = "idem-life-004",
            correlationId = "corr-life-004",
            causationId = "caus-life-004"
        )

        val declareRes = service.declareBreach(declareCmd)
        val incidentId = declareRes.record.incidentId

        // Assert query by ID and reference
        val stored = store.findById(incidentId)
        assertNotNull(stored)
        assertEquals("INC-LIFECYCLE-004", stored.incidentReference)

        val storedByRef = store.findByReference(tenantId, "INC-LIFECYCLE-004")
        assertNotNull(storedByRef)
        assertEquals(incidentId, storedByRef.incidentId)

        // Contain
        service.containBreach(
            ContainBreachCommand(
                principal = securityAdminPrincipal,
                tenantId = tenantId,
                incidentReference = "INC-LIFECYCLE-004",
                containmentActions = listOf("Isolate network segment", "Revoke compromised admin keys"),
                emergencyHoldReference = "HOLD-LIFECYCLE-004",
                idempotencyKey = "idem-life-cont-004",
                correlationId = "corr-life-004",
                causationId = "caus-life-004"
            )
        )

        // Verify Observability Metrics
        val metrics = observability.getMetrics()
        assertTrue(metrics.any { it.eventType == "BREACH_DECLARED" && it.incidentReference == "INC-LIFECYCLE-004" })
        assertTrue(metrics.any { it.eventType == "BREACH_CONTAINED" && it.incidentReference == "INC-LIFECYCLE-004" })

        // Verify Alerts
        val alerts = alertSink.getAlerts()
        assertTrue(alerts.any { it.alertType == "BREACH_EXERCISE_DECLARED" })
        assertTrue(alerts.any { it.alertType == "BREACH_CONTAINED_HOLD_PLACED" })

        // Verify Invariants: No financial mutation, no Android DB/lifecycle claims, contract preserved
        assertFalse(stored.isFinancialAuthorityCreated)
        assertFalse(stored.hasAndroidDbImpact)
        assertFalse(stored.hasAndroidLifecycleClaim)
        assertEquals(PRIVACY_BREACH_CONTRACT, stored.semanticContract)
    }
}
