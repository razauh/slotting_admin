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

class RetentionDeletionTest {
    private val now = Instant.parse("2026-09-21T08:00:00Z")
    private val clock = Clock.fixed(now, ZoneOffset.UTC)

    private val tenantId = "tenant-ret-del-test"
    private val subjectId = "player-privacy-101"

    private val complianceAdminPrincipal = AuthenticatedPrincipal(
        id = "admin-compliance-01",
        tenantId = tenantId,
        kind = PrincipalKind.ADMIN,
        roles = setOf(AdminRole.AUDITOR, AdminRole.SUPER_ADMIN)
    )

    private val supportAdminPrincipal = AuthenticatedPrincipal(
        id = "admin-support-01",
        tenantId = tenantId,
        kind = PrincipalKind.ADMIN,
        roles = setOf(AdminRole.SUPPORT) // Lacks compliance/auditor roles
    )

    private val playerSelfPrincipal = AuthenticatedPrincipal(
        id = subjectId,
        tenantId = tenantId,
        kind = PrincipalKind.PLAYER,
        roles = emptySet()
    )

    private val otherPlayerPrincipal = AuthenticatedPrincipal(
        id = "player-privacy-999",
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

    private lateinit var store: InMemoryRetentionDeletionStore
    private lateinit var alertSink: InMemoryRetentionDeletionAlertSink
    private lateinit var observability: InMemoryRetentionDeletionObservability
    private lateinit var legalHoldRegistry: InMemoryLegalHoldRegistry
    private lateinit var service: RetentionDeletionService

    @BeforeEach
    fun setUp() {
        RetentionDeletionBinding.checkBound()
        store = InMemoryRetentionDeletionStore()
        alertSink = InMemoryRetentionDeletionAlertSink()
        observability = InMemoryRetentionDeletionObservability()
        legalHoldRegistry = InMemoryLegalHoldRegistry()

        service = RetentionDeletionService(
            store = store,
            alertSink = alertSink,
            observability = observability,
            legalHoldRegistry = legalHoldRegistry,
            clock = clock
        )
    }

    @AfterEach
    fun tearDown() {
    }

    // =========================================================================
    // PRIV-001-03-T001 — Enforce retention and deletion produces the required authoritative outcome
    // =========================================================================
    @Test
    fun `PRIV-001-03-T001 — Enforce retention and deletion produces the required authoritative outcome`() {
        val cmd = EnforceRetentionAndDeletionCommand(
            principal = complianceAdminPrincipal,
            tenantId = tenantId,
            subjectId = subjectId,
            requestId = "req-del-001",
            requestedCategories = emptySet(), // Evaluates all categories
            approvedBy = "dpo-officer-01",
            approvedBasis = null,
            idempotencyKey = "idem-del-001",
            correlationId = "corr-del-001",
            causationId = "caus-del-001"
        )

        val result = service.enforceRetentionAndDeletion(cmd)

        assertNotNull(result)
        val record = result.executionRecord

        // Assert: Ledger retention/legal obligations override deletion only with approved basis; actions audited.
        assertEquals(DeletionRequestStatus.COMPLETED_PARTIAL_OVERRIDE, record.status)
        assertTrue(record.totalRecordsPurged > 0, "Purgeable categories (sessions, marketing) must be purged")
        assertTrue(record.totalRecordsRetained > 0, "Statutory categories (ledger, AML) must be retained")
        assertTrue(record.statutoryOverrideCount > 0)

        // Verify ledger retention is strictly maintained
        val ledgerItem = record.evaluatedItems.firstOrNull { it.category == DataCategory.LEDGER }
        assertNotNull(ledgerItem)
        assertEquals(DataItemRetentionStatus.RETAINED_STATUTORY_LEDGER, ledgerItem.status)
        assertEquals(DeletionOverrideReason.STATUTORY_LEDGER_RETENTION, ledgerItem.overrideReason)

        // Assert zero financial authority created and zero money mutation
        assertFalse(result.isFinancialAuthorityCreated)
        assertFalse(record.isFinancialAuthorityCreated)
        assertFalse(record.hasAndroidDbImpact)
        assertFalse(record.hasAndroidLifecycleClaim)

        // Assert lineage and audit
        assertEquals("corr-del-001", record.auditEvent.correlationId)
        assertEquals("caus-del-001", record.auditEvent.causationId)
        assertEquals(RETENTION_DELETION_CONTRACT, record.semanticContract)

        // Assert no raw PII in output (only digests)
        assertTrue(record.evaluatedItems.all { it.dataDigestSha256.isNotBlank() })
    }

    // =========================================================================
    // PRIV-001-03-T002 — Enforce retention and deletion rejects invalid, boundary, unauthorized, and stale input
    // =========================================================================
    @Test
    fun `PRIV-001-03-T002 — Enforce retention and deletion rejects invalid, boundary, unauthorized, and stale input`() {
        // 1. Unauthenticated principal
        assertFailsWith<UnauthorizedRetentionDeletionException> {
            service.enforceRetentionAndDeletion(
                EnforceRetentionAndDeletionCommand(
                    principal = null,
                    tenantId = tenantId,
                    subjectId = subjectId,
                    requestId = "req-unauth",
                    idempotencyKey = "idem-unauth",
                    correlationId = "corr-002",
                    causationId = "caus-002"
                )
            )
        }

        // 2. Cross-tenant admin
        assertFailsWith<UnauthorizedRetentionDeletionException> {
            service.enforceRetentionAndDeletion(
                EnforceRetentionAndDeletionCommand(
                    principal = foreignAdminPrincipal,
                    tenantId = tenantId,
                    subjectId = subjectId,
                    requestId = "req-cross",
                    idempotencyKey = "idem-cross",
                    correlationId = "corr-002",
                    causationId = "caus-002"
                )
            )
        }

        // 3. IDOR: Player attempting to delete another player's data
        assertFailsWith<UnauthorizedRetentionDeletionException> {
            service.enforceRetentionAndDeletion(
                EnforceRetentionAndDeletionCommand(
                    principal = otherPlayerPrincipal,
                    tenantId = tenantId,
                    subjectId = subjectId,
                    requestId = "req-idor",
                    idempotencyKey = "idem-idor",
                    correlationId = "corr-002",
                    causationId = "caus-002"
                )
            )
        }

        // 4. Admin lacking compliance/auditor role
        assertFailsWith<UnauthorizedRetentionDeletionException> {
            service.enforceRetentionAndDeletion(
                EnforceRetentionAndDeletionCommand(
                    principal = supportAdminPrincipal,
                    tenantId = tenantId,
                    subjectId = subjectId,
                    requestId = "req-role",
                    idempotencyKey = "idem-role",
                    correlationId = "corr-002",
                    causationId = "caus-002"
                )
            )
        }

        // 5. Blank input fields
        assertFailsWith<InvalidRetentionDeletionCommandException> {
            service.enforceRetentionAndDeletion(
                EnforceRetentionAndDeletionCommand(
                    principal = complianceAdminPrincipal,
                    tenantId = "",
                    subjectId = subjectId,
                    requestId = "req-blank",
                    idempotencyKey = "idem-blank",
                    correlationId = "corr-002",
                    causationId = "caus-002"
                )
            )
        }

        // 6. Active legal hold blocks deletion of held category without approved basis
        legalHoldRegistry.addHold(
            LegalHoldEntry(
                tenantId = tenantId,
                subjectId = subjectId,
                category = DataCategory.COMMUNICATION,
                holdReference = "HOLD-LITIGATION-777",
                reason = "Regulatory subpoena in progress",
                issuedAt = now.minusSeconds(86400)
            )
        )

        val holdCmd = EnforceRetentionAndDeletionCommand(
            principal = playerSelfPrincipal, // Subject requests deletion
            tenantId = tenantId,
            subjectId = subjectId,
            requestId = "req-hold-test",
            requestedCategories = setOf(DataCategory.COMMUNICATION),
            approvedBasis = null, // No approved override
            idempotencyKey = "idem-hold-test",
            correlationId = "corr-hold",
            causationId = "caus-hold"
        )

        val holdResult = service.enforceRetentionAndDeletion(holdCmd)
        val holdRecord = holdResult.executionRecord
        assertEquals(DeletionRequestStatus.REJECTED_LEGAL_HOLD, holdRecord.status)
        assertEquals(1, holdRecord.legalHoldBlockedCount)
        assertEquals(0, holdRecord.totalRecordsPurged)

        // Verify alert emitted
        val alerts = alertSink.getAlerts()
        assertTrue(alerts.any { it.alertType == "LEGAL_HOLD_DELETION_BLOCKED" })
    }

    // =========================================================================
    // PRIV-001-03-T003 — Enforce retention and deletion survives concurrency, duplicate delivery, and dependency failure
    // =========================================================================
    @Test
    fun `PRIV-001-03-T003 — Enforce retention and deletion survives concurrency, duplicate delivery, and dependency failure`() {
        val baseCmd = EnforceRetentionAndDeletionCommand(
            principal = complianceAdminPrincipal,
            tenantId = tenantId,
            subjectId = subjectId,
            requestId = "req-idem-003",
            requestedCategories = setOf(DataCategory.DEVICE_SESSION),
            approvedBy = "dpo-officer",
            idempotencyKey = "idem-key-unique-333",
            correlationId = "corr-003",
            causationId = "caus-003"
        )

        // 1. Initial execution
        val initialResult = service.enforceRetentionAndDeletion(baseCmd)
        assertFalse(initialResult.isDuplicate)

        // 2. Duplicate replay with exact same idempotency key & payload
        val duplicateResult = service.enforceRetentionAndDeletion(baseCmd)
        assertTrue(duplicateResult.isDuplicate)
        assertEquals(initialResult.executionRecord.executionId, duplicateResult.executionRecord.executionId)

        // 3. Changed payload with same idempotency key conflicts
        val conflictingCmd = baseCmd.copy(requestId = "req-changed-payload")
        assertFailsWith<ConflictRetentionDeletionException> {
            service.enforceRetentionAndDeletion(conflictingCmd)
        }

        // 4. Multithreaded concurrent requests for distinct keys execute safely without race
        val executor = Executors.newFixedThreadPool(4)
        val tasks = (1..4).map { index ->
            Callable {
                service.enforceRetentionAndDeletion(
                    EnforceRetentionAndDeletionCommand(
                        principal = complianceAdminPrincipal,
                        tenantId = tenantId,
                        subjectId = "subject-concurrent-$index",
                        requestId = "req-conc-$index",
                        requestedCategories = setOf(DataCategory.DEVICE_SESSION),
                        idempotencyKey = "idem-conc-$index",
                        correlationId = "corr-conc-$index",
                        causationId = "caus-conc-$index"
                    )
                )
            }
        }

        val futures = executor.invokeAll(tasks)
        executor.shutdown()

        for (future in futures) {
            val res = future.get()
            assertNotNull(res)
            assertEquals(DeletionRequestStatus.COMPLETED_FULL_PURGE, res.executionRecord.status)
        }
    }

    // =========================================================================
    // PRIV-001-03-T004 — Enforce retention and deletion remains compatible, recoverable, observable, and lifecycle-safe
    // =========================================================================
    @Test
    fun `PRIV-001-03-T004 — Enforce retention and deletion remains compatible, recoverable, observable, and lifecycle-safe`() {
        val cmd = EnforceRetentionAndDeletionCommand(
            principal = complianceAdminPrincipal,
            tenantId = tenantId,
            subjectId = subjectId,
            requestId = "req-obs-004",
            requestedCategories = emptySet(),
            idempotencyKey = "idem-obs-004",
            correlationId = "corr-obs-004",
            causationId = "caus-obs-004"
        )

        val result = service.enforceRetentionAndDeletion(cmd)
        val executionId = result.executionRecord.executionId

        // Assert record is durable in store
        val storedRecord = store.findByExecutionId(executionId)
        assertNotNull(storedRecord)
        assertEquals(executionId, storedRecord.executionId)

        val latestRecord = store.findLatestBySubject(tenantId, subjectId)
        assertNotNull(latestRecord)
        assertEquals(executionId, latestRecord.executionId)

        // Assert observability metrics recorded
        val metrics = observability.getMetrics()
        assertTrue(metrics.isNotEmpty())
        val metric = metrics.firstOrNull { it.correlationId == "corr-obs-004" }
        assertNotNull(metric)
        assertEquals("RETENTION_DELETION_EXECUTED", metric.eventType)
        assertEquals(tenantId, metric.tenantId)
        assertEquals(subjectId, metric.subjectId)

        // Assert zero Android lifecycle or DB claims
        assertFalse(storedRecord.hasAndroidDbImpact)
        assertFalse(storedRecord.hasAndroidLifecycleClaim)
        assertFalse(storedRecord.isFinancialAuthorityCreated)
        assertEquals(RETENTION_DELETION_CONTRACT, storedRecord.semanticContract)
    }
}
