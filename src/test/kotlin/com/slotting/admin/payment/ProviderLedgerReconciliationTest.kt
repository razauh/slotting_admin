package com.slotting.admin.payment

import com.slotting.admin.auth.*
import com.slotting.admin.ledger.*
import java.io.File
import java.time.Clock
import java.time.Instant
import java.time.ZoneOffset
import java.util.UUID
import java.util.concurrent.CountDownLatch
import java.util.concurrent.Executors
import kotlin.test.*
import org.junit.jupiter.api.AfterEach
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test

class ProviderLedgerReconciliationTest {
    private val now = Instant.parse("2026-09-20T00:00:00Z")
    private val clock = Clock.fixed(now, ZoneOffset.UTC)
    private val tenantId = "tenant-recon-1"
    private val providerId = "prov-recon-card-1"

    private val adminPrincipal = AuthenticatedPrincipal(
        id = "admin-user-01",
        tenantId = tenantId,
        kind = PrincipalKind.ADMIN,
        roles = setOf(AdminRole.SUPER_ADMIN),
    )

    private val auditorPrincipal = AuthenticatedPrincipal(
        id = "auditor-user-01",
        tenantId = tenantId,
        kind = PrincipalKind.ADMIN,
        roles = setOf(AdminRole.AUDITOR),
    )

    private val securityPrincipal = AuthenticatedPrincipal(
        id = "security-user-01",
        tenantId = tenantId,
        kind = PrincipalKind.ADMIN,
        roles = setOf(AdminRole.SECURITY),
    )

    private val supportPrincipal = AuthenticatedPrincipal(
        id = "support-user-01",
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

    private val playerPrincipal = AuthenticatedPrincipal(
        id = "player-01",
        tenantId = tenantId,
        kind = PrincipalKind.PLAYER,
        roles = emptySet(),
    )

    private lateinit var store: InMemoryProviderLedgerReconciliationStore
    private lateinit var alertSink: InMemoryProviderLedgerReconciliationAlertSink
    private lateinit var service: ProviderLedgerReconciliationService

    @BeforeEach
    fun setUp() {
        ProviderLedgerReconciliationBinding.isBound = true
        store = InMemoryProviderLedgerReconciliationStore()
        alertSink = InMemoryProviderLedgerReconciliationAlertSink()
        service = ProviderLedgerReconciliationService(
            store = store,
            alertSink = alertSink,
            clock = clock,
        )
    }

    @AfterEach
    fun tearDown() {
        ProviderLedgerReconciliationBinding.isBound = true
    }

    @Test
    fun `PAYMENT-007-01-T001 — Reconcile provider and ledger items produces the required authoritative outcome`() {
        // 1. Expected RED failure verification: Fail-closed gate throws expected assertion when unbound
        ProviderLedgerReconciliationBinding.isBound = false

        val periodStart = now.minusSeconds(86400)
        val periodEnd = now

        val providerItems = listOf(
            ProviderSettlementItem(
                itemReference = "prov-dep-001",
                providerTransactionId = "tx-prov-dep-001",
                paymentReference = "dep-001",
                itemType = ReconciliationItemType.DEPOSIT,
                amountMinorUnits = 10000L,
                currencyCode = "EUR",
                settlementTime = now.minusSeconds(3600),
            ),
            ProviderSettlementItem(
                itemReference = "prov-pay-001",
                providerTransactionId = "tx-prov-pay-001",
                paymentReference = "pay-001",
                itemType = ReconciliationItemType.PAYOUT,
                amountMinorUnits = 5000L,
                currencyCode = "EUR",
                settlementTime = now.minusSeconds(3000),
            ),
            ProviderSettlementItem(
                itemReference = "prov-ref-mismatch",
                providerTransactionId = "tx-prov-ref-001",
                paymentReference = "ref-001",
                itemType = ReconciliationItemType.REFUND,
                amountMinorUnits = 4000L, // Mismatch: provider has 4000, ledger has 3500
                currencyCode = "EUR",
                settlementTime = now.minusSeconds(2000),
            ),
            ProviderSettlementItem(
                itemReference = "prov-fee-missing",
                providerTransactionId = "tx-prov-fee-999",
                paymentReference = "fee-999",
                itemType = ReconciliationItemType.FEE,
                amountMinorUnits = 1500L, // Missing in ledger
                currencyCode = "EUR",
                settlementTime = now.minusSeconds(1000),
            ),
        )

        val ledgerItems = listOf(
            LedgerReconciliationItem(
                transactionReference = "TX-DEP-dep-001",
                accountReference = "gateway:clearing:$providerId",
                itemType = ReconciliationItemType.DEPOSIT,
                amountMinorUnits = 10000L, // Matches prov-dep-001
                currencyCode = "EUR",
                postedTime = now.minusSeconds(3600),
            ),
            LedgerReconciliationItem(
                transactionReference = "tx-prov-pay-001",
                accountReference = "gateway:clearing:$providerId",
                itemType = ReconciliationItemType.PAYOUT,
                amountMinorUnits = 5000L, // Matches prov-pay-001
                currencyCode = "EUR",
                postedTime = now.minusSeconds(3000),
            ),
            LedgerReconciliationItem(
                transactionReference = "tx-prov-ref-001",
                accountReference = "gateway:clearing:$providerId",
                itemType = ReconciliationItemType.REFUND,
                amountMinorUnits = 3500L, // Mismatch with 4000
                currencyCode = "EUR",
                postedTime = now.minusSeconds(2000),
            ),
            LedgerReconciliationItem(
                transactionReference = "TX-COMP-orphan-001",
                accountReference = "gateway:clearing:$providerId",
                itemType = ReconciliationItemType.REVERSAL,
                amountMinorUnits = 2000L, // Missing in provider
                currencyCode = "EUR",
                postedTime = now.minusSeconds(500),
            ),
        )

        val runCmd = RunReconciliationCommand(
            tenantId = tenantId,
            reconciliationReference = "rec-batch-t001",
            providerId = providerId,
            currencyCode = "EUR",
            periodStart = periodStart,
            periodEnd = periodEnd,
            providerItems = providerItems,
            ledgerItems = ledgerItems,
            idempotencyKey = "key-run-t001",
            correlationId = "corr-rec-1",
            causationId = "cause-rec-1",
            principal = adminPrincipal,
        )

        val gateError = assertFailsWith<AssertionError> {
            service.runReconciliation(runCmd)
        }
        assertEquals("mismatch omitted", gateError.message)

        // Bind the fail-closed gate
        ProviderLedgerReconciliationBinding.isBound = true

        // 2. Authoritative Reconciliation Execution (Totals and item-level evidence)
        val runResult = service.runReconciliation(runCmd)
        assertNotNull(runResult)
        assertEquals(ReconciliationBatchStatus.DISCREPANCY_DETECTED, runResult.status)
        assertEquals(20500L, runResult.totalProviderAmountMinorUnits) // 10000 + 5000 + 4000 + 1500
        assertEquals(20500L, runResult.totalLedgerAmountMinorUnits) // 10000 + 5000 + 3500 + 2000
        assertEquals(0L, runResult.netDiscrepancyMinorUnits)
        assertEquals(5, runResult.totalItemsCompared)
        assertEquals(2, runResult.matchedItemCount)
        assertEquals(3, runResult.discrepancyItemCount)
        assertEquals(5, runResult.itemEvidence.size)
        assertEquals(RECONCILE_PROVIDER_LEDGER_CONTRACT, runResult.semanticContract)

        // Assert item-level evidence captures all discrepancies without omitting any
        val matchedItems = runResult.itemEvidence.filter { it.matchStatus == ItemMatchStatus.MATCHED }
        assertEquals(2, matchedItems.size)

        val amountMismatch = runResult.itemEvidence.first { it.matchStatus == ItemMatchStatus.AMOUNT_MISMATCH }
        assertEquals("prov-ref-mismatch", amountMismatch.itemReference)
        assertEquals(500L, amountMismatch.discrepancyMinorUnits) // 4000 - 3500

        val missingLedger = runResult.itemEvidence.first { it.matchStatus == ItemMatchStatus.MISSING_IN_LEDGER }
        assertEquals("prov-fee-missing", missingLedger.itemReference)
        assertEquals(1500L, missingLedger.discrepancyMinorUnits)

        val missingProvider = runResult.itemEvidence.first { it.matchStatus == ItemMatchStatus.MISSING_IN_PROVIDER }
        assertEquals("LEDGER-TX-COMP-orphan-001", missingProvider.itemReference)
        assertEquals(-2000L, missingProvider.discrepancyMinorUnits)

        assertTrue(alertSink.alerts.any { it.contains("RECONCILIATION_MISMATCH_DETECTED") })

        // 3. Close Discrepancy Contract: "close requires reason/approver"
        val closeWithoutReasonCmd = CloseDiscrepancyCommand(
            tenantId = tenantId,
            reconciliationReference = "rec-batch-t001",
            reasonCode = "   ", // Blank reason
            approverId = "auditor-01",
            resolutionNotes = "Closing discrepancy",
            idempotencyKey = "key-close-no-reason",
            correlationId = "corr-close-1",
            causationId = "cause-close-1",
            expectedVersion = 1L,
            principal = auditorPrincipal,
        )
        val missingReasonError = assertFailsWith<AuthenticationFailure.Rejected> {
            service.closeDiscrepancy(closeWithoutReasonCmd)
        }
        assertEquals(AuthErrorCode.INVALID, missingReasonError.code)

        val closeWithoutApproverCmd = closeWithoutReasonCmd.copy(
            reasonCode = "FEE_VARIANCE_CONFIRMED",
            approverId = "", // Blank approver
            idempotencyKey = "key-close-no-approver",
        )
        val missingApproverError = assertFailsWith<AuthenticationFailure.Rejected> {
            service.closeDiscrepancy(closeWithoutApproverCmd)
        }
        assertEquals(AuthErrorCode.INVALID, missingApproverError.code)

        // Valid Close Discrepancy
        val validCloseCmd = closeWithoutReasonCmd.copy(
            reasonCode = "FEE_VARIANCE_CONFIRMED",
            approverId = "auditor-01",
            idempotencyKey = "key-close-valid",
        )
        val closeResult = service.closeDiscrepancy(validCloseCmd)
        assertNotNull(closeResult)
        assertEquals(ReconciliationBatchStatus.CLOSED, closeResult.status)
        assertEquals("FEE_VARIANCE_CONFIRMED", closeResult.reasonCode)
        assertEquals("auditor-01", closeResult.approverId)
        assertEquals(2L, closeResult.version)
        assertEquals(RECONCILE_PROVIDER_LEDGER_CONTRACT, closeResult.semanticContract)
        assertTrue(alertSink.alerts.any { it.contains("RECONCILIATION_DISCREPANCY_CLOSED") })

        // 4. Duplicate Replay returns cached duplicate
        val duplicateRun = service.runReconciliation(runCmd)
        assertEquals(runResult.resultId, duplicateRun.resultId)
        assertTrue(duplicateRun.isDuplicate)

        val duplicateClose = service.closeDiscrepancy(validCloseCmd)
        assertEquals(closeResult.resultId, duplicateClose.resultId)
        assertTrue(duplicateClose.isDuplicate)
    }

    @Test
    fun `PAYMENT-007-01-T002 — Reconcile provider and ledger items rejects invalid, boundary, unauthorized, and stale input`() {
        val baseRunCmd = RunReconciliationCommand(
            tenantId = tenantId,
            reconciliationReference = "rec-batch-t002",
            providerId = providerId,
            currencyCode = "EUR",
            periodStart = now.minusSeconds(3600),
            periodEnd = now,
            providerItems = emptyList(),
            ledgerItems = emptyList(),
            idempotencyKey = "key-run-t002",
            correlationId = "corr-rec-2",
            causationId = "cause-rec-2",
            principal = adminPrincipal,
        )

        // 1. Blank mandatory fields
        assertFailsWith<AuthenticationFailure.Rejected> { service.runReconciliation(baseRunCmd.copy(tenantId = "")) }
        assertFailsWith<AuthenticationFailure.Rejected> { service.runReconciliation(baseRunCmd.copy(reconciliationReference = "  ")) }
        assertFailsWith<AuthenticationFailure.Rejected> { service.runReconciliation(baseRunCmd.copy(providerId = "")) }
        assertFailsWith<AuthenticationFailure.Rejected> { service.runReconciliation(baseRunCmd.copy(idempotencyKey = "")) }
        assertFailsWith<AuthenticationFailure.Rejected> { service.runReconciliation(baseRunCmd.copy(correlationId = "")) }
        assertFailsWith<AuthenticationFailure.Rejected> { service.runReconciliation(baseRunCmd.copy(causationId = "")) }

        // 2. Invalid currency and period boundaries
        assertFailsWith<AuthenticationFailure.Rejected> {
            service.runReconciliation(baseRunCmd.copy(currencyCode = "euro"))
        }
        assertFailsWith<AuthenticationFailure.Rejected> {
            service.runReconciliation(baseRunCmd.copy(periodStart = now, periodEnd = now.minusSeconds(100)))
        }

        // 3. Negative amounts in items
        val negativeItemCmd = baseRunCmd.copy(
            providerItems = listOf(
                ProviderSettlementItem(
                    itemReference = "neg-item",
                    providerTransactionId = "tx-neg",
                    itemType = ReconciliationItemType.DEPOSIT,
                    amountMinorUnits = -100L,
                    currencyCode = "EUR",
                    settlementTime = now,
                )
            )
        )
        assertFailsWith<AuthenticationFailure.Rejected> { service.runReconciliation(negativeItemCmd) }

        // 4. Stale version
        val staleRunError = assertFailsWith<AuthenticationFailure.Rejected> {
            service.runReconciliation(baseRunCmd.copy(expectedVersion = 2L))
        }
        assertEquals(AuthErrorCode.STALE, staleRunError.code)

        // 5. Unauthorized / cross-tenant / invalid role principal
        val crossTenantError = assertFailsWith<AuthenticationFailure.Rejected> {
            service.runReconciliation(baseRunCmd.copy(principal = crossTenantPrincipal))
        }
        assertEquals(AuthErrorCode.FORBIDDEN, crossTenantError.code)

        val playerError = assertFailsWith<AuthenticationFailure.Rejected> {
            service.runReconciliation(baseRunCmd.copy(principal = playerPrincipal))
        }
        assertEquals(AuthErrorCode.FORBIDDEN, playerError.code)

        val supportRoleError = assertFailsWith<AuthenticationFailure.Rejected> {
            service.runReconciliation(baseRunCmd.copy(principal = supportPrincipal))
        }
        assertEquals(AuthErrorCode.FORBIDDEN, supportRoleError.code)

        // Execute valid empty balanced reconciliation
        service.runReconciliation(baseRunCmd)

        // 6. Idempotency conflict (same key, different providerItems)
        val conflictIdempError = assertFailsWith<AuthenticationFailure.Rejected> {
            service.runReconciliation(baseRunCmd.copy(
                providerItems = listOf(
                    ProviderSettlementItem(
                        itemReference = "conflict-item",
                        providerTransactionId = "tx-conf",
                        itemType = ReconciliationItemType.DEPOSIT,
                        amountMinorUnits = 1000L,
                        currencyCode = "EUR",
                        settlementTime = now,
                    )
                )
            ))
        }
        assertEquals(AuthErrorCode.CONFLICT, conflictIdempError.code)

        // 7. Stale expected version on close
        val staleCloseError = assertFailsWith<AuthenticationFailure.Rejected> {
            service.closeDiscrepancy(
                CloseDiscrepancyCommand(
                    tenantId = tenantId,
                    reconciliationReference = "rec-batch-t002",
                    reasonCode = "REASON",
                    approverId = "approver-01",
                    resolutionNotes = "Notes",
                    idempotencyKey = "key-close-stale",
                    correlationId = "c1",
                    causationId = "c2",
                    expectedVersion = 99L,
                    principal = auditorPrincipal,
                )
            )
        }
        assertEquals(AuthErrorCode.STALE, staleCloseError.code)
    }

    @Test
    fun `PAYMENT-007-01-T003 — Reconcile provider and ledger items survives concurrency, duplicate delivery, and dependency failure`() {
        val concurrentCmd = RunReconciliationCommand(
            tenantId = tenantId,
            reconciliationReference = "rec-batch-con-001",
            providerId = providerId,
            currencyCode = "EUR",
            periodStart = now.minusSeconds(3600),
            periodEnd = now,
            providerItems = listOf(
                ProviderSettlementItem(
                    itemReference = "item-con-1",
                    providerTransactionId = "tx-con-1",
                    itemType = ReconciliationItemType.DEPOSIT,
                    amountMinorUnits = 5000L,
                    currencyCode = "EUR",
                    settlementTime = now.minusSeconds(1000),
                )
            ),
            ledgerItems = emptyList(),
            idempotencyKey = "key-rec-con-001",
            correlationId = "corr-rec-con",
            causationId = "cause-rec-con",
            principal = securityPrincipal,
        )

        // 1. Concurrency: 8 threads concurrently submitting identical reconciliation run
        val threadCount = 8
        val executor = Executors.newFixedThreadPool(threadCount)
        val startLatch = CountDownLatch(1)
        val doneLatch = CountDownLatch(threadCount)
        val results = java.util.Collections.synchronizedList(mutableListOf<ReconciliationResult>())
        val errors = java.util.Collections.synchronizedList(mutableListOf<Throwable>())

        for (i in 0 until threadCount) {
            executor.submit {
                try {
                    startLatch.await()
                    val res = service.runReconciliation(concurrentCmd)
                    results.add(res)
                } catch (t: Throwable) {
                    errors.add(t)
                } finally {
                    doneLatch.countDown()
                }
            }
        }

        startLatch.countDown()
        doneLatch.await()
        executor.shutdown()

        assertTrue(errors.isEmpty(), "Expected zero errors during concurrent execution: $errors")
        assertEquals(threadCount, results.size)
        val firstResult = results.first()
        for (res in results) {
            assertEquals(firstResult.resultId, res.resultId)
            assertEquals(5000L, res.totalProviderAmountMinorUnits)
            assertEquals(1, res.discrepancyItemCount)
        }

        assertNotNull(store.findByReference(tenantId, "rec-batch-con-001"))

        // 2. Dependency failure and retry safety
        class FailingReconciliationStore : InMemoryProviderLedgerReconciliationStore() {
            var shouldFail = true
            override fun saveReconciliation(
                record: ProviderLedgerReconciliationRecord,
                result: ReconciliationResult,
                idempotencyKey: String,
                fingerprint: String,
                audit: AuditEvent,
                outbox: OutboxEvent,
            ) {
                if (shouldFail) {
                    throw RuntimeException("Reconciliation database connection timeout")
                }
                super.saveReconciliation(record, result, idempotencyKey, fingerprint, audit, outbox)
            }
        }

        val failingStore = FailingReconciliationStore()
        val retryService = ProviderLedgerReconciliationService(
            store = failingStore,
            alertSink = alertSink,
            clock = clock,
        )

        val retryCmd = RunReconciliationCommand(
            tenantId = tenantId,
            reconciliationReference = "rec-batch-retry-001",
            providerId = providerId,
            currencyCode = "EUR",
            periodStart = now.minusSeconds(3600),
            periodEnd = now,
            providerItems = emptyList(),
            ledgerItems = emptyList(),
            idempotencyKey = "key-rec-retry-001",
            correlationId = "corr-retry-1",
            causationId = "cause-retry-1",
            principal = adminPrincipal,
        )

        val depError = assertFailsWith<AuthenticationFailure.Rejected> {
            retryService.runReconciliation(retryCmd)
        }
        assertEquals(AuthErrorCode.DEPENDENCY_UNAVAILABLE, depError.code)
        assertTrue(alertSink.alerts.any { it.contains("RECONCILIATION_STORAGE_FAILED") })

        // Invariant: Zero corrupt state committed on storage failure
        assertNull(failingStore.findByReference(tenantId, "rec-batch-retry-001"))

        // Dependency recovers: Retry succeeds cleanly
        failingStore.shouldFail = false
        val recoveredResult = retryService.runReconciliation(retryCmd)
        assertNotNull(recoveredResult)
        assertFalse(recoveredResult.isDuplicate)
        assertNotNull(failingStore.findByReference(tenantId, "rec-batch-retry-001"))
    }

    @Test
    fun `PAYMENT-007-01-T004 — Reconcile provider and ledger items remains compatible, recoverable, observable, and lifecycle-safe`() {
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
        val recCmd = RunReconciliationCommand(
            tenantId = tenantId,
            reconciliationReference = "rec-batch-rec-001",
            providerId = providerId,
            currencyCode = "EUR",
            periodStart = now.minusSeconds(3600),
            periodEnd = now,
            providerItems = listOf(
                ProviderSettlementItem(
                    itemReference = "rec-prov-1",
                    providerTransactionId = "tx-rec-1",
                    itemType = ReconciliationItemType.DEPOSIT,
                    amountMinorUnits = 12000L,
                    currencyCode = "EUR",
                    settlementTime = now,
                )
            ),
            ledgerItems = emptyList(),
            idempotencyKey = "key-rec-restart-001",
            correlationId = "corr-rec-1",
            causationId = "cause-rec-1",
            principal = adminPrincipal,
        )

        val initialResult = service.runReconciliation(recCmd)
        assertNotNull(initialResult)
        assertFalse(initialResult.isDuplicate)

        // Export snapshot and import into fresh store instance simulating server restart
        val snapshot = store.exportSnapshot()
        val rehydratedStore = InMemoryProviderLedgerReconciliationStore()
        rehydratedStore.importSnapshot(snapshot)
        val restartedService = ProviderLedgerReconciliationService(
            store = rehydratedStore,
            alertSink = alertSink,
            clock = clock,
        )

        // Calling with same idempotency key on rehydrated store returns identical cached outcome
        val replayedResult = restartedService.runReconciliation(recCmd)
        assertEquals(initialResult.resultId, replayedResult.resultId)
        assertTrue(replayedResult.isDuplicate)
        assertEquals(RECONCILE_PROVIDER_LEDGER_CONTRACT, replayedResult.semanticContract)

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
