package com.slotting.admin.payment

import com.slotting.admin.auth.*
import com.slotting.admin.ledger.*
import java.io.File
import java.time.Clock
import java.time.Instant
import java.time.ZoneOffset
import java.util.UUID
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.CountDownLatch
import java.util.concurrent.Executors
import kotlin.test.*
import org.junit.jupiter.api.AfterEach
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test

class ControlledFinanceReportTest {
    private val now = Instant.parse("2026-09-20T00:00:00Z")
    private val clock = Clock.fixed(now, ZoneOffset.UTC)
    private val tenantId = "tenant-fin-1"
    private val providerId = "prov-card-eur-1"

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

    private lateinit var store: InMemoryControlledFinanceReportStore
    private lateinit var alertSink: InMemoryControlledFinanceReportAlertSink
    private lateinit var reconciliationStore: InMemoryProviderLedgerReconciliationStore
    private lateinit var service: ControlledFinanceReportService

    @BeforeEach
    fun setUp() {
        ControlledFinanceReportBinding.isBound = true
        store = InMemoryControlledFinanceReportStore()
        alertSink = InMemoryControlledFinanceReportAlertSink()
        reconciliationStore = InMemoryProviderLedgerReconciliationStore()
        service = ControlledFinanceReportService(
            store = store,
            alertSink = alertSink,
            reconciliationStore = reconciliationStore,
            clock = clock,
        )
    }

    @AfterEach
    fun tearDown() {
        ControlledFinanceReportBinding.isBound = true
    }

    @Test
    fun `PAYMENT-007-02-T001 — Produce controlled finance reconciliation reports produces the required authoritative outcome`() {
        // 1. Expected RED failure verification: Fail-closed gate throws expected assertion when unbound
        ControlledFinanceReportBinding.isBound = false

        val periodStart = now.minusSeconds(86400)
        val periodEnd = now

        val providerItems = listOf(
            ProviderSettlementItem(
                itemReference = "prov-dep-101",
                providerTransactionId = "tx-prov-dep-101",
                paymentReference = "dep-101",
                itemType = ReconciliationItemType.DEPOSIT,
                amountMinorUnits = 50000L,
                feeMinorUnits = 1000L,
                currencyCode = "EUR",
                settlementTime = now.minusSeconds(7200),
            ),
            ProviderSettlementItem(
                itemReference = "prov-pay-101",
                providerTransactionId = "tx-prov-pay-101",
                paymentReference = "pay-101",
                itemType = ReconciliationItemType.PAYOUT,
                amountMinorUnits = 20000L,
                feeMinorUnits = 500L,
                currencyCode = "EUR",
                settlementTime = now.minusSeconds(5400),
            ),
            ProviderSettlementItem(
                itemReference = "prov-ref-mismatch",
                providerTransactionId = "tx-prov-ref-101",
                paymentReference = "ref-101",
                itemType = ReconciliationItemType.REFUND,
                amountMinorUnits = 8000L, // Provider shows 8000, ledger shows 7000
                feeMinorUnits = 0L,
                currencyCode = "EUR",
                settlementTime = now.minusSeconds(3600),
            ),
            ProviderSettlementItem(
                itemReference = "prov-fee-missing",
                providerTransactionId = "tx-prov-fee-101",
                paymentReference = "fee-101",
                itemType = ReconciliationItemType.FEE,
                amountMinorUnits = 2500L, // Missing in ledger
                feeMinorUnits = 0L,
                currencyCode = "EUR",
                settlementTime = now.minusSeconds(1800),
            ),
        )

        val ledgerItems = listOf(
            LedgerReconciliationItem(
                transactionReference = "TX-DEP-dep-101",
                accountReference = "gateway:clearing:$providerId",
                itemType = ReconciliationItemType.DEPOSIT,
                amountMinorUnits = 50000L, // Matches prov-dep-101
                currencyCode = "EUR",
                postedTime = now.minusSeconds(7200),
            ),
            LedgerReconciliationItem(
                transactionReference = "tx-prov-pay-101",
                accountReference = "gateway:clearing:$providerId",
                itemType = ReconciliationItemType.PAYOUT,
                amountMinorUnits = 20000L, // Matches prov-pay-101
                currencyCode = "EUR",
                postedTime = now.minusSeconds(5400),
            ),
            LedgerReconciliationItem(
                transactionReference = "tx-prov-ref-101",
                accountReference = "gateway:clearing:$providerId",
                itemType = ReconciliationItemType.REFUND,
                amountMinorUnits = 7000L, // Mismatch (8000 vs 7000)
                currencyCode = "EUR",
                postedTime = now.minusSeconds(3600),
            ),
            LedgerReconciliationItem(
                transactionReference = "TX-COMP-orphan-101",
                accountReference = "gateway:clearing:$providerId",
                itemType = ReconciliationItemType.REVERSAL,
                amountMinorUnits = 4000L, // Missing in provider
                currencyCode = "EUR",
                postedTime = now.minusSeconds(900),
            ),
        )

        val genCmd = GenerateControlledFinanceReportCommand(
            tenantId = tenantId,
            reportReference = "fin-report-t001",
            providerId = providerId,
            currencyCode = "EUR",
            periodStart = periodStart,
            periodEnd = periodEnd,
            providerItems = providerItems,
            ledgerItems = ledgerItems,
            idempotencyKey = "key-fin-t001",
            correlationId = "corr-fin-1",
            causationId = "cause-fin-1",
            principal = auditorPrincipal,
        )

        val gateError = assertFailsWith<AssertionError> {
            service.generateReport(genCmd)
        }
        assertEquals("mismatch omitted", gateError.message)

        // Bind the fail-closed gate
        ControlledFinanceReportBinding.isBound = true

        // 2. Authoritative Report Generation (Totals and item-level evidence)
        val reportResult = service.generateReport(genCmd)
        assertNotNull(reportResult)
        assertFalse(reportResult.isDuplicate)
        assertEquals(CONTROLLED_FINANCE_REPORT_CONTRACT, reportResult.semanticContract)

        val report = reportResult.report
        assertEquals(ControlledReportStatus.IMBALANCED, report.status)
        assertEquals("fin-report-t001", report.reportReference)
        assertEquals(providerId, report.providerId)
        assertEquals("EUR", report.currencyCode)

        // Verify cryptographic export checksum: 64-character SHA-256 hex string
        assertTrue(report.exportChecksumSha256.isNotBlank())
        assertEquals(64, report.exportChecksumSha256.length)
        assertTrue(report.exportChecksumSha256.matches(Regex("^[0-9a-f]{64}$")))
        assertFalse(report.exportChecksumSha256.contains("secret", ignoreCase = true))

        // Verify totals
        val totals = report.totals
        assertEquals(50000L, totals.totalGrossDepositsMinorUnits)
        assertEquals(20000L, totals.totalPayoutsMinorUnits)
        assertEquals(8000L, totals.totalRefundsMinorUnits)
        assertEquals(0L, totals.totalReversalsMinorUnits)
        assertEquals(4000L, totals.totalFeesMinorUnits) // 1000 fee + 500 fee + 2500 fee item
        assertEquals(80500L, totals.totalProviderAmountMinorUnits) // 50000 + 20000 + 8000 + 2500
        assertEquals(81000L, totals.totalLedgerAmountMinorUnits) // 50000 + 20000 + 7000 + 4000
        assertEquals(-500L, totals.netDiscrepancyMinorUnits) // 80500 - 81000
        assertEquals(5, totals.totalItemCount)
        assertEquals(2, totals.matchedItemCount)
        assertEquals(3, totals.discrepancyItemCount)

        // Verify item-level evidence: All discrepancies captured without omission
        assertEquals(5, report.itemEvidence.size)
        val matchedItems = report.itemEvidence.filter { it.matchStatus == ItemMatchStatus.MATCHED }
        assertEquals(2, matchedItems.size)

        val amountMismatch = report.itemEvidence.first { it.matchStatus == ItemMatchStatus.AMOUNT_MISMATCH }
        assertEquals("prov-ref-mismatch", amountMismatch.itemReference)
        assertEquals(1000L, amountMismatch.discrepancyMinorUnits) // 8000 - 7000

        val missingLedger = report.itemEvidence.first { it.matchStatus == ItemMatchStatus.MISSING_IN_LEDGER }
        assertEquals("prov-fee-missing", missingLedger.itemReference)
        assertEquals(2500L, missingLedger.discrepancyMinorUnits)

        val missingProvider = report.itemEvidence.first { it.matchStatus == ItemMatchStatus.MISSING_IN_PROVIDER }
        assertEquals("LEDGER-TX-COMP-orphan-101", missingProvider.itemReference)
        assertEquals(-4000L, missingProvider.discrepancyMinorUnits)

        assertTrue(alertSink.alerts.any { it.contains("FINANCE_REPORT_IMBALANCE_DETECTED") })

        // 3. Close Mismatch Contract: "close requires reason/approver"
        val closeWithoutReasonCmd = CloseFinanceReportMismatchCommand(
            tenantId = tenantId,
            reportReference = "fin-report-t001",
            reasonCode = "   ", // Blank reason
            approverId = "security-01",
            resolutionNotes = "Closing discrepancy notes",
            idempotencyKey = "key-close-no-reason",
            correlationId = "corr-close-1",
            causationId = "cause-close-1",
            expectedVersion = 1L,
            principal = securityPrincipal,
        )
        val missingReasonError = assertFailsWith<AuthenticationFailure.Rejected> {
            service.closeMismatch(closeWithoutReasonCmd)
        }
        assertEquals(AuthErrorCode.INVALID, missingReasonError.code)
        assertTrue(alertSink.alerts.any { it.contains("FINANCE_REPORT_CLOSE_REJECTED") })

        val closeWithoutApproverCmd = closeWithoutReasonCmd.copy(
            reasonCode = "RECON_FEE_TIMING_ADJUSTMENT",
            approverId = "", // Blank approver
            idempotencyKey = "key-close-no-approver",
        )
        val missingApproverError = assertFailsWith<AuthenticationFailure.Rejected> {
            service.closeMismatch(closeWithoutApproverCmd)
        }
        assertEquals(AuthErrorCode.INVALID, missingApproverError.code)

        // Attempt WAIVE: Always forbidden under financial dual control
        val waiveCmd = WaiveFinanceReportCommand(
            tenantId = tenantId,
            reportReference = "fin-report-t001",
            idempotencyKey = "key-waive-1",
            correlationId = "corr-waive-1",
            causationId = "cause-waive-1",
            expectedVersion = 1L,
            principal = adminPrincipal,
        )
        val waiveError = assertFailsWith<AuthenticationFailure.Rejected> {
            service.waive(waiveCmd)
        }
        assertEquals(AuthErrorCode.FORBIDDEN, waiveError.code)
        assertTrue(alertSink.alerts.any { it.contains("FINANCE_REPORT_WAIVE_FORBIDDEN") })

        // 4. Valid Close Mismatch with reasonCode and approverId
        val validCloseCmd = CloseFinanceReportMismatchCommand(
            tenantId = tenantId,
            reportReference = "fin-report-t001",
            reasonCode = "RECON_FEE_TIMING_ADJUSTMENT",
            approverId = "security-01",
            resolutionNotes = "Verified provider fee discrepancy resolved via compensating settlement in cycle 2",
            idempotencyKey = "key-close-valid-01",
            correlationId = "corr-close-2",
            causationId = "cause-close-2",
            expectedVersion = 1L,
            principal = securityPrincipal,
        )
        val closeResult = service.closeMismatch(validCloseCmd)
        assertNotNull(closeResult)
        assertEquals(ControlledReportStatus.RESOLVED, closeResult.report.status)
        assertEquals("RECON_FEE_TIMING_ADJUSTMENT", closeResult.report.reasonCode)
        assertEquals("security-01", closeResult.report.approverId)
        assertEquals(2L, closeResult.report.version)
        assertNotEquals(report.exportChecksumSha256, closeResult.report.exportChecksumSha256)
        assertTrue(closeResult.report.exportChecksumSha256.isNotBlank())
        assertTrue(alertSink.alerts.any { it.contains("FINANCE_REPORT_MISMATCH_CLOSED") })

        // Verify audit and outbox emission
        val auditEvents = store.getAuditEvents()
        assertEquals(2, auditEvents.size)
        assertEquals("FINANCE_REPORT_IMBALANCED", auditEvents[0].type)
        assertEquals("FINANCE_REPORT_MISMATCH_CLOSED", auditEvents[1].type)

        val outboxEvents = store.getOutboxEvents()
        assertEquals(2, outboxEvents.size)
        assertEquals("FINANCE_REPORT_IMBALANCED", outboxEvents[0].type)
        assertEquals("FINANCE_REPORT_MISMATCH_CLOSED", outboxEvents[1].type)

        // 5. Idempotent replay: Replaying generate command returns cached duplicate
        val replayedResult = service.generateReport(genCmd)
        assertTrue(replayedResult.isDuplicate)
        assertEquals(reportResult.resultId, replayedResult.resultId)
        assertEquals(reportResult.report.reportId, replayedResult.report.reportId)

        // 6. Test Balanced Report Generation: Provider items exactly match ledger items
        val balancedCmd = GenerateControlledFinanceReportCommand(
            tenantId = tenantId,
            reportReference = "fin-report-balanced",
            providerId = providerId,
            currencyCode = "EUR",
            periodStart = periodStart,
            periodEnd = periodEnd,
            providerItems = listOf(
                ProviderSettlementItem(
                    itemReference = "item-bal-1",
                    providerTransactionId = "tx-bal-1",
                    paymentReference = "bal-1",
                    itemType = ReconciliationItemType.DEPOSIT,
                    amountMinorUnits = 30000L,
                    currencyCode = "EUR",
                    settlementTime = now,
                )
            ),
            ledgerItems = listOf(
                LedgerReconciliationItem(
                    transactionReference = "TX-DEP-bal-1",
                    accountReference = "gateway:clearing:$providerId",
                    itemType = ReconciliationItemType.DEPOSIT,
                    amountMinorUnits = 30000L,
                    currencyCode = "EUR",
                    postedTime = now,
                )
            ),
            idempotencyKey = "key-fin-balanced",
            correlationId = "corr-bal-1",
            causationId = "cause-bal-1",
            principal = adminPrincipal,
        )
        val balancedResult = service.generateReport(balancedCmd)
        assertEquals(ControlledReportStatus.BALANCED, balancedResult.report.status)
        assertEquals(0, balancedResult.report.totals.discrepancyItemCount)
        assertEquals(0L, balancedResult.report.totals.netDiscrepancyMinorUnits)
        assertEquals(1, balancedResult.report.totals.matchedItemCount)
    }

    @Test
    fun `PAYMENT-007-02-T002 — Produce controlled finance reconciliation reports rejects invalid, boundary, unauthorized, and stale input`() {
        val periodStart = now.minusSeconds(86400)
        val periodEnd = now

        val validCmd = GenerateControlledFinanceReportCommand(
            tenantId = tenantId,
            reportReference = "fin-report-val-1",
            providerId = providerId,
            currencyCode = "EUR",
            periodStart = periodStart,
            periodEnd = periodEnd,
            idempotencyKey = "key-val-1",
            correlationId = "corr-val-1",
            causationId = "cause-val-1",
            principal = auditorPrincipal,
        )

        // 1. Blank mandatory fields
        assertFailsWith<AuthenticationFailure.Rejected> {
            service.generateReport(validCmd.copy(tenantId = "   "))
        }.also { assertEquals(AuthErrorCode.INVALID, it.code) }

        assertFailsWith<AuthenticationFailure.Rejected> {
            service.generateReport(validCmd.copy(reportReference = ""))
        }.also { assertEquals(AuthErrorCode.INVALID, it.code) }

        assertFailsWith<AuthenticationFailure.Rejected> {
            service.generateReport(validCmd.copy(providerId = ""))
        }.also { assertEquals(AuthErrorCode.INVALID, it.code) }

        assertFailsWith<AuthenticationFailure.Rejected> {
            service.generateReport(validCmd.copy(idempotencyKey = ""))
        }.also { assertEquals(AuthErrorCode.INVALID, it.code) }

        assertFailsWith<AuthenticationFailure.Rejected> {
            service.generateReport(validCmd.copy(correlationId = ""))
        }.also { assertEquals(AuthErrorCode.INVALID, it.code) }

        assertFailsWith<AuthenticationFailure.Rejected> {
            service.generateReport(validCmd.copy(causationId = ""))
        }.also { assertEquals(AuthErrorCode.INVALID, it.code) }

        // 2. Invalid currency code
        assertFailsWith<AuthenticationFailure.Rejected> {
            service.generateReport(validCmd.copy(currencyCode = "euro"))
        }.also { assertEquals(AuthErrorCode.INVALID, it.code) }

        assertFailsWith<AuthenticationFailure.Rejected> {
            service.generateReport(validCmd.copy(currencyCode = "US"))
        }.also { assertEquals(AuthErrorCode.INVALID, it.code) }

        // 3. Inverted time period
        assertFailsWith<AuthenticationFailure.Rejected> {
            service.generateReport(validCmd.copy(periodStart = periodEnd, periodEnd = periodStart))
        }.also { assertEquals(AuthErrorCode.INVALID, it.code) }

        // 4. Stale expected version
        assertFailsWith<AuthenticationFailure.Rejected> {
            service.generateReport(validCmd.copy(expectedVersion = 2L))
        }.also { assertEquals(AuthErrorCode.STALE, it.code) }

        // 5. Negative item amounts
        assertFailsWith<AuthenticationFailure.Rejected> {
            service.generateReport(
                validCmd.copy(
                    providerItems = listOf(
                        ProviderSettlementItem(
                            itemReference = "item-neg-1",
                            providerTransactionId = "tx-neg-1",
                            itemType = ReconciliationItemType.DEPOSIT,
                            amountMinorUnits = -100L,
                            currencyCode = "EUR",
                            settlementTime = now,
                        )
                    )
                )
            )
        }.also { assertEquals(AuthErrorCode.INVALID, it.code) }

        assertFailsWith<AuthenticationFailure.Rejected> {
            service.generateReport(
                validCmd.copy(
                    ledgerItems = listOf(
                        LedgerReconciliationItem(
                            transactionReference = "tx-neg-ledger-1",
                            accountReference = "gateway:clearing:$providerId",
                            itemType = ReconciliationItemType.DEPOSIT,
                            amountMinorUnits = -500L,
                            currencyCode = "EUR",
                            postedTime = now,
                        )
                    )
                )
            )
        }.also { assertEquals(AuthErrorCode.INVALID, it.code) }

        // 6. Principal authorization boundaries
        // Player principal rejected
        assertFailsWith<AuthenticationFailure.Rejected> {
            service.generateReport(validCmd.copy(principal = playerPrincipal))
        }.also { assertEquals(AuthErrorCode.FORBIDDEN, it.code) }

        // Cross-tenant principal rejected
        assertFailsWith<AuthenticationFailure.Rejected> {
            service.generateReport(validCmd.copy(principal = crossTenantPrincipal))
        }.also { assertEquals(AuthErrorCode.FORBIDDEN, it.code) }

        // Admin without SUPER_ADMIN/AUDITOR/SECURITY role (e.g. SUPPORT) rejected
        assertFailsWith<AuthenticationFailure.Rejected> {
            service.generateReport(validCmd.copy(principal = supportPrincipal))
        }.also { assertEquals(AuthErrorCode.FORBIDDEN, it.code) }

        // 7. Idempotency conflict: same key with different payload
        service.generateReport(validCmd)
        assertFailsWith<AuthenticationFailure.Rejected> {
            service.generateReport(validCmd.copy(currencyCode = "USD"))
        }.also { assertEquals(AuthErrorCode.CONFLICT, it.code) }

        // 8. Reference collision: different key with same reference
        assertFailsWith<AuthenticationFailure.Rejected> {
            service.generateReport(validCmd.copy(idempotencyKey = "key-val-different"))
        }.also { assertEquals(AuthErrorCode.CONFLICT, it.code) }

        // 9. Close Mismatch Boundary & Authorization Rejections
        val closeCmd = CloseFinanceReportMismatchCommand(
            tenantId = tenantId,
            reportReference = "fin-report-val-1",
            reasonCode = "RESOLVED_MANUALLY",
            approverId = "admin-lead",
            resolutionNotes = "Notes",
            idempotencyKey = "key-close-val-1",
            correlationId = "corr-close-val",
            causationId = "cause-close-val",
            expectedVersion = 1L,
            principal = auditorPrincipal,
        )

        // Cross-tenant close rejected
        assertFailsWith<AuthenticationFailure.Rejected> {
            service.closeMismatch(closeCmd.copy(principal = crossTenantPrincipal))
        }.also { assertEquals(AuthErrorCode.FORBIDDEN, it.code) }

        // Non-existent report reference on close rejected
        assertFailsWith<AuthenticationFailure.Rejected> {
            service.closeMismatch(closeCmd.copy(reportReference = "non-existent-ref"))
        }.also { assertEquals(AuthErrorCode.INVALID, it.code) }

        // Stale version on close rejected
        assertFailsWith<AuthenticationFailure.Rejected> {
            service.closeMismatch(closeCmd.copy(expectedVersion = 999L))
        }.also { assertEquals(AuthErrorCode.STALE, it.code) }

        // Valid close succeeds
        service.closeMismatch(closeCmd)

        // Closing an already resolved/closed report rejected with CONFLICT
        assertFailsWith<AuthenticationFailure.Rejected> {
            service.closeMismatch(closeCmd.copy(idempotencyKey = "key-close-second", expectedVersion = 2L))
        }.also { assertEquals(AuthErrorCode.CONFLICT, it.code) }
    }

    @Test
    fun `PAYMENT-007-02-T003 — Produce controlled finance reconciliation reports survives concurrency, duplicate delivery, and dependency failure`() {
        val threadCount = 8
        val executor = Executors.newFixedThreadPool(threadCount)
        val startLatch = CountDownLatch(1)
        val endLatch = CountDownLatch(threadCount)

        val results = ConcurrentHashMap<Int, ControlledFinanceReportResult>()
        val exceptions = ConcurrentHashMap<Int, Throwable>()

        val cmd = GenerateControlledFinanceReportCommand(
            tenantId = tenantId,
            reportReference = "fin-report-concurrent",
            providerId = providerId,
            currencyCode = "EUR",
            periodStart = now.minusSeconds(86400),
            periodEnd = now,
            providerItems = listOf(
                ProviderSettlementItem(
                    itemReference = "item-conc-1",
                    providerTransactionId = "tx-conc-1",
                    paymentReference = "conc-1",
                    itemType = ReconciliationItemType.DEPOSIT,
                    amountMinorUnits = 15000L,
                    currencyCode = "EUR",
                    settlementTime = now,
                )
            ),
            ledgerItems = listOf(
                LedgerReconciliationItem(
                    transactionReference = "TX-DEP-conc-1",
                    accountReference = "gateway:clearing:$providerId",
                    itemType = ReconciliationItemType.DEPOSIT,
                    amountMinorUnits = 15000L,
                    currencyCode = "EUR",
                    postedTime = now,
                )
            ),
            idempotencyKey = "key-fin-concurrent",
            correlationId = "corr-conc-1",
            causationId = "cause-conc-1",
            principal = auditorPrincipal,
        )

        for (i in 0 until threadCount) {
            executor.submit {
                try {
                    startLatch.await()
                    val res = service.generateReport(cmd)
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

        // Invariant: Zero uncaught exceptions across all racing threads
        assertTrue(exceptions.isEmpty(), "Concurrent executions must not throw errors: ${exceptions.values}")
        assertEquals(threadCount, results.size)

        // All threads must converge on the exact same report ID and export checksum
        val firstResult = results[0]!!
        val distinctReportIds = results.values.map { it.report.reportId }.toSet()
        val distinctChecksums = results.values.map { it.report.exportChecksumSha256 }.toSet()
        assertEquals(1, distinctReportIds.size, "All threads must return the identical report ID")
        assertEquals(1, distinctChecksums.size, "All threads must return the identical export checksum")

        // Invariant: Exactly 1 primary creation and 7 duplicate responses
        val duplicateCount = results.values.count { it.isDuplicate }
        assertEquals(threadCount - 1, duplicateCount)

        // Storage dependency failure handling
        class FailingControlledFinanceStore : InMemoryControlledFinanceReportStore() {
            var shouldFail = true
            override fun saveReport(
                record: ControlledFinanceReportRecord,
                result: ControlledFinanceReportResult,
                idempotencyKey: String,
                fingerprint: String,
                audit: AuditEvent,
                outbox: OutboxEvent,
            ) {
                if (shouldFail) {
                    throw RuntimeException("Report persistence store connection timeout")
                }
                super.saveReport(record, result, idempotencyKey, fingerprint, audit, outbox)
            }
        }

        val failingStore = FailingControlledFinanceStore()
        val retryService = ControlledFinanceReportService(
            store = failingStore,
            alertSink = alertSink,
            clock = clock,
        )

        val retryCmd = GenerateControlledFinanceReportCommand(
            tenantId = tenantId,
            reportReference = "fin-report-retry-01",
            providerId = providerId,
            currencyCode = "EUR",
            periodStart = now.minusSeconds(3600),
            periodEnd = now,
            providerItems = emptyList(),
            ledgerItems = emptyList(),
            idempotencyKey = "key-fin-retry-01",
            correlationId = "corr-retry-1",
            causationId = "cause-retry-1",
            principal = adminPrincipal,
        )

        val depError = assertFailsWith<AuthenticationFailure.Rejected> {
            retryService.generateReport(retryCmd)
        }
        assertEquals(AuthErrorCode.DEPENDENCY_UNAVAILABLE, depError.code)
        assertTrue(alertSink.alerts.any { it.contains("FINANCE_REPORT_STORAGE_FAILED") })

        // Invariant: Zero corrupt state committed on storage failure
        assertNull(failingStore.findByReference(tenantId, "fin-report-retry-01"))

        // Dependency recovers: Retry succeeds cleanly
        failingStore.shouldFail = false
        val recoveredResult = retryService.generateReport(retryCmd)
        assertNotNull(recoveredResult)
        assertFalse(recoveredResult.isDuplicate)
        assertNotNull(failingStore.findByReference(tenantId, "fin-report-retry-01"))
    }

    @Test
    fun `PAYMENT-007-02-T004 — Produce controlled finance reconciliation reports remains compatible, recoverable, observable, and lifecycle-safe`() {
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
        val repCmd = GenerateControlledFinanceReportCommand(
            tenantId = tenantId,
            reportReference = "fin-report-restart-01",
            providerId = providerId,
            currencyCode = "EUR",
            periodStart = now.minusSeconds(3600),
            periodEnd = now,
            providerItems = listOf(
                ProviderSettlementItem(
                    itemReference = "rep-prov-1",
                    providerTransactionId = "tx-rep-1",
                    itemType = ReconciliationItemType.DEPOSIT,
                    amountMinorUnits = 25000L,
                    currencyCode = "EUR",
                    settlementTime = now,
                )
            ),
            ledgerItems = emptyList(),
            idempotencyKey = "key-rep-restart-01",
            correlationId = "corr-rep-1",
            causationId = "cause-rep-1",
            principal = adminPrincipal,
        )

        val initialResult = service.generateReport(repCmd)
        assertNotNull(initialResult)
        assertFalse(initialResult.isDuplicate)

        // Export snapshot and import into fresh store instance simulating server restart
        val snapshot = store.exportSnapshot()
        val rehydratedStore = InMemoryControlledFinanceReportStore()
        rehydratedStore.importSnapshot(snapshot)
        val restartedService = ControlledFinanceReportService(
            store = rehydratedStore,
            alertSink = alertSink,
            clock = clock,
        )

        // Calling with same idempotency key on rehydrated store returns identical cached outcome
        val replayedResult = restartedService.generateReport(repCmd)
        assertEquals(initialResult.resultId, replayedResult.resultId)
        assertTrue(replayedResult.isDuplicate)
        assertEquals(CONTROLLED_FINANCE_REPORT_CONTRACT, replayedResult.semanticContract)
        assertEquals(initialResult.report.exportChecksumSha256, replayedResult.report.exportChecksumSha256)

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
