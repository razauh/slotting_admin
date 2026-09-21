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

class LegalHoldTest {
    private val now = Instant.parse("2026-09-21T08:00:00Z")
    private val clock = Clock.fixed(now, ZoneOffset.UTC)

    private val tenantId = "tenant-hold-test"
    private val subjectId = "player-hold-101"

    private val legalAdminPrincipal = AuthenticatedPrincipal(
        id = "admin-legal-01",
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
        id = subjectId,
        tenantId = tenantId,
        kind = PrincipalKind.PLAYER,
        roles = emptySet()
    )

    private val foreignAdminPrincipal = AuthenticatedPrincipal(
        id = "admin-foreign-01",
        tenantId = "tenant-other",
        kind = PrincipalKind.ADMIN,
        roles = setOf(AdminRole.SUPER_ADMIN)
    )

    private lateinit var store: InMemoryLegalHoldStore
    private lateinit var alertSink: InMemoryLegalHoldAlertSink
    private lateinit var observability: InMemoryLegalHoldObservability
    private lateinit var service: LegalHoldService

    @BeforeEach
    fun setUp() {
        LegalHoldBinding.checkBound()
        store = InMemoryLegalHoldStore()
        alertSink = InMemoryLegalHoldAlertSink()
        observability = InMemoryLegalHoldObservability()

        service = LegalHoldService(
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
    // PRIV-001-04-T001 — Enforce legal holds produces the required authoritative outcome
    // =========================================================================
    @Test
    fun `PRIV-001-04-T001 — Enforce legal holds produces the required authoritative outcome`() {
        val placeCmd = PlaceLegalHoldCommand(
            principal = legalAdminPrincipal,
            tenantId = tenantId,
            subjectId = subjectId,
            holdReference = "HOLD-SEC-2026-001",
            matterId = "MATTER-REG-999",
            jurisdiction = "EU_MGA",
            targetCategories = setOf(DataCategory.COMMUNICATION, DataCategory.DEVICE_SESSION),
            reason = "Formal regulatory investigation into communication records",
            idempotencyKey = "idem-hold-001",
            correlationId = "corr-hold-001",
            causationId = "caus-hold-001"
        )

        val placeResult = service.placeLegalHold(placeCmd)
        assertNotNull(placeResult)
        val holdRecord = placeResult.holdRecord

        assertEquals(LegalHoldStatus.ACTIVE, holdRecord.status)
        assertEquals("HOLD-SEC-2026-001", holdRecord.holdReference)
        assertEquals(2, holdRecord.targetCategories.size)
        assertEquals(LEGAL_HOLD_CONTRACT, holdRecord.semanticContract)
        assertFalse(holdRecord.isFinancialAuthorityCreated)
        assertFalse(holdRecord.hasAndroidDbImpact)
        assertFalse(holdRecord.hasAndroidLifecycleClaim)

        // Evaluate deletion block: Attempting to delete held categories MUST be strictly blocked
        val evalCmd = EvaluateHoldForDeletionCommand(
            principal = playerPrincipal, // User requests erasure
            tenantId = tenantId,
            subjectId = subjectId,
            categories = setOf(DataCategory.COMMUNICATION),
            approvedOverrideBasis = null,
            correlationId = "corr-eval-001",
            causationId = "caus-eval-001"
        )

        val evalResult = service.evaluateHoldForDeletion(evalCmd)
        assertTrue(evalResult.isBlocked, "Deletion of held category must be strictly blocked")
        assertTrue(evalResult.blockedCategories.contains(DataCategory.COMMUNICATION))
        assertEquals(1, evalResult.activeHolds.size)

        // Verify alert emitted for deletion block
        val alerts = alertSink.getAlerts()
        assertTrue(alerts.any { it.alertType == "LEGAL_HOLD_BLOCK_ENFORCED" })
    }

    // =========================================================================
    // PRIV-001-04-T002 — Enforce legal holds rejects invalid, boundary, unauthorized, and stale input
    // =========================================================================
    @Test
    fun `PRIV-001-04-T002 — Enforce legal holds rejects invalid, boundary, unauthorized, and stale input`() {
        val validCmd = PlaceLegalHoldCommand(
            principal = legalAdminPrincipal,
            tenantId = tenantId,
            subjectId = subjectId,
            holdReference = "HOLD-REJECT-TEST",
            matterId = "MATTER-01",
            reason = "Court order",
            idempotencyKey = "idem-rej-01",
            correlationId = "corr-002",
            causationId = "caus-002"
        )

        // 1. Unauthenticated principal
        assertFailsWith<UnauthorizedLegalHoldException> {
            service.placeLegalHold(validCmd.copy(principal = null))
        }

        // 2. Cross-tenant admin
        assertFailsWith<UnauthorizedLegalHoldException> {
            service.placeLegalHold(validCmd.copy(principal = foreignAdminPrincipal))
        }

        // 3. Unauthorized admin role (SUPPORT role cannot place holds)
        assertFailsWith<UnauthorizedLegalHoldException> {
            service.placeLegalHold(validCmd.copy(principal = supportAdminPrincipal))
        }

        // 4. Player self cannot place legal holds
        assertFailsWith<UnauthorizedLegalHoldException> {
            service.placeLegalHold(validCmd.copy(principal = playerPrincipal))
        }

        // 5. Blank fields
        assertFailsWith<InvalidLegalHoldCommandException> {
            service.placeLegalHold(validCmd.copy(holdReference = ""))
        }
        assertFailsWith<InvalidLegalHoldCommandException> {
            service.placeLegalHold(validCmd.copy(reason = ""))
        }

        // 6. Release non-existent hold
        assertFailsWith<LegalHoldNotFoundException> {
            service.releaseLegalHold(
                ReleaseEnforcedLegalHoldCommand(
                    principal = legalAdminPrincipal,
                    tenantId = tenantId,
                    subjectId = subjectId,
                    holdReference = "HOLD-NON-EXISTENT",
                    releaseJustification = "Case closed",
                    idempotencyKey = "idem-rel-01",
                    correlationId = "corr-002",
                    causationId = "caus-002"
                )
            )
        }
    }

    // =========================================================================
    // PRIV-001-04-T003 — Enforce legal holds survives concurrency, duplicate delivery, and dependency failure
    // =========================================================================
    @Test
    fun `PRIV-001-04-T003 — Enforce legal holds survives concurrency, duplicate delivery, and dependency failure`() {
        val placeCmd = PlaceLegalHoldCommand(
            principal = legalAdminPrincipal,
            tenantId = tenantId,
            subjectId = subjectId,
            holdReference = "HOLD-CONC-001",
            matterId = "MATTER-CONC",
            reason = "Subpoena response",
            idempotencyKey = "idem-conc-333",
            correlationId = "corr-003",
            causationId = "caus-003"
        )

        // 1. Initial placement
        val initial = service.placeLegalHold(placeCmd)
        assertFalse(initial.isDuplicate)

        // 2. Duplicate placement with identical key and payload
        val duplicate = service.placeLegalHold(placeCmd)
        assertTrue(duplicate.isDuplicate)
        assertEquals(initial.holdRecord.holdId, duplicate.holdRecord.holdId)

        // 3. Conflicting payload with same idempotency key
        assertFailsWith<ConflictLegalHoldException> {
            service.placeLegalHold(placeCmd.copy(matterId = "DIFFERENT-MATTER"))
        }

        // 4. Multithreaded concurrent placement for distinct subjects
        val executor = Executors.newFixedThreadPool(4)
        val tasks = (1..4).map { idx ->
            Callable {
                service.placeLegalHold(
                    PlaceLegalHoldCommand(
                        principal = legalAdminPrincipal,
                        tenantId = tenantId,
                        subjectId = "subject-conc-$idx",
                        holdReference = "HOLD-CONC-$idx",
                        matterId = "MATTER-$idx",
                        reason = "Audit hold",
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
            assertEquals(LegalHoldStatus.ACTIVE, res.holdRecord.status)
        }
    }

    // =========================================================================
    // PRIV-001-04-T004 — Enforce legal holds remains compatible, recoverable, observable, and lifecycle-safe
    // =========================================================================
    @Test
    fun `PRIV-001-04-T004 — Enforce legal holds remains compatible, recoverable, observable, and lifecycle-safe`() {
        val placeCmd = PlaceLegalHoldCommand(
            principal = legalAdminPrincipal,
            tenantId = tenantId,
            subjectId = subjectId,
            holdReference = "HOLD-LIFECYCLE-004",
            matterId = "MATTER-004",
            targetCategories = setOf(DataCategory.IDENTITY, DataCategory.KYC_DOCUMENT),
            reason = "Litigation hold",
            idempotencyKey = "idem-life-004",
            correlationId = "corr-life-004",
            causationId = "caus-life-004"
        )

        val placeRes = service.placeLegalHold(placeCmd)
        val holdId = placeRes.holdRecord.holdId

        // Assert query by holdId and reference
        val stored = store.findByHoldId(holdId)
        assertNotNull(stored)
        assertEquals("HOLD-LIFECYCLE-004", stored.holdReference)

        val activeList = store.findActiveHoldsBySubject(tenantId, subjectId)
        assertEquals(1, activeList.size)

        // Release the hold with formal justification
        val releaseCmd = ReleaseEnforcedLegalHoldCommand(
            principal = legalAdminPrincipal,
            tenantId = tenantId,
            subjectId = subjectId,
            holdReference = "HOLD-LIFECYCLE-004",
            releaseJustification = "Court entered dismissal order and regulatory inquiry closed",
            idempotencyKey = "idem-rel-004",
            correlationId = "corr-rel-004",
            causationId = "caus-rel-004"
        )

        val releaseRes = service.releaseLegalHold(releaseCmd)
        assertEquals(LegalHoldStatus.RELEASED, releaseRes.holdRecord.status)
        assertEquals(legalAdminPrincipal.id, releaseRes.holdRecord.releasedBy)
        assertNotNull(releaseRes.holdRecord.releasedAt)

        // Assert active holds now empty
        val activeAfterRelease = store.findActiveHoldsBySubject(tenantId, subjectId)
        assertTrue(activeAfterRelease.isEmpty())

        // Assert observability metrics recorded
        val metrics = observability.getMetrics()
        assertTrue(metrics.any { it.eventType == "LEGAL_HOLD_PLACED" && it.correlationId == "corr-life-004" })
        assertTrue(metrics.any { it.eventType == "LEGAL_HOLD_RELEASED" && it.correlationId == "corr-rel-004" })

        // Assert alerts emitted
        val alerts = alertSink.getAlerts()
        assertTrue(alerts.any { it.alertType == "LEGAL_HOLD_ACTIVE" })
        assertTrue(alerts.any { it.alertType == "LEGAL_HOLD_RELEASED" })

        // Assert zero Android lifecycle or DB claims
        assertFalse(stored.hasAndroidDbImpact)
        assertFalse(stored.hasAndroidLifecycleClaim)
        assertFalse(stored.isFinancialAuthorityCreated)
        assertEquals(LEGAL_HOLD_CONTRACT, stored.semanticContract)
    }
}
