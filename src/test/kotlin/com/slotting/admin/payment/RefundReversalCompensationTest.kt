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

class RefundReversalCompensationTest {
    private val now = Instant.parse("2026-09-20T00:00:00Z")
    private val clock = Clock.fixed(now, ZoneOffset.UTC)
    private val tenantId = "tenant-reversal-1"
    private val providerId = "prov-card-reversal-1"
    private val playerId = UUID.fromString("22222222-2222-2222-2222-222222222222")

    private val adminPrincipal = AuthenticatedPrincipal(
        id = "admin-user-01",
        tenantId = tenantId,
        kind = PrincipalKind.ADMIN,
        roles = setOf(AdminRole.SUPER_ADMIN),
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

    private lateinit var depositStore: InMemoryServerDepositCreditStore
    private lateinit var compensationStore: InMemoryRefundReversalStore
    private lateinit var alertSink: InMemoryRefundReversalAlertSink
    private lateinit var ledgerService: LedgerPostingService
    private lateinit var service: RefundReversalCompensationService

    @BeforeEach
    fun setUp() {
        RefundReversalCompensationBinding.isBound = true
        depositStore = InMemoryServerDepositCreditStore()
        compensationStore = InMemoryRefundReversalStore()
        alertSink = InMemoryRefundReversalAlertSink()
        ledgerService = LedgerPostingService(clock = clock)
        service = RefundReversalCompensationService(
            depositCreditStore = depositStore,
            ledgerPostingService = ledgerService,
            store = compensationStore,
            alertSink = alertSink,
            clock = clock,
        )
    }

    @AfterEach
    fun tearDown() {
        RefundReversalCompensationBinding.isBound = true
    }

    private fun seedOriginalDeposit(paymentRef: String, amountMinorUnits: Long = 10000L) {
        val creditRecord = ServerDepositCreditRecord(
            creditId = UUID.randomUUID(),
            tenantId = tenantId,
            playerId = playerId,
            paymentReference = paymentRef,
            providerTransactionId = "tx-prov-$paymentRef",
            amountMinorUnits = amountMinorUnits,
            currencyCode = "EUR",
            ledgerTransactionReference = "TX-DEP-$paymentRef",
            source = CreditSource.SERVER_VERIFIED_WEBHOOK,
            debitMinorUnits = amountMinorUnits,
            creditMinorUnits = amountMinorUnits,
            conserved = true,
            evidenceReference = "EVID-$paymentRef",
            idempotencyKey = "key-dep-$paymentRef",
            createdAt = now,
            version = 1L,
        )
        val result = CreditDepositResult(
            resultId = UUID.randomUUID(),
            tenantId = tenantId,
            playerId = playerId,
            paymentReference = paymentRef,
            providerTransactionId = "tx-prov-$paymentRef",
            creditedAmountMinorUnits = amountMinorUnits,
            currencyCode = "EUR",
            ledgerTransactionReference = "TX-DEP-$paymentRef",
            isDuplicate = false,
            conserved = true,
            debitMinorUnits = amountMinorUnits,
            creditMinorUnits = amountMinorUnits,
            evidenceReference = "EVID-$paymentRef",
            serverTime = now,
        )
        val audit = AuditEvent(UUID.randomUUID(), creditRecord.creditId, tenantId, "SERVER_DEPOSIT_CREDITED", now, "corr-seed", "cause-seed")
        val outbox = OutboxEvent(UUID.randomUUID(), creditRecord.creditId, tenantId, "SERVER_DEPOSIT_CREDITED", now)
        depositStore.saveCredit(creditRecord, result, "key-dep-$paymentRef", "fp-seed", audit, outbox)
    }

    @Test
    fun `PAYMENT-006-01-T001 — Post refund and reversal compensation produces the required authoritative outcome`() {
        // 1. Expected RED failure verification: Fail-closed gate throws expected assertion when unbound
        RefundReversalCompensationBinding.isBound = false

        val baseCmd = PostCompensationCommand(
            tenantId = tenantId,
            playerId = playerId,
            originalPaymentReference = "dep-rev-t001",
            compensationReference = "rev-comp-001",
            providerId = providerId,
            providerTransactionId = "tx-rev-001",
            amountMinorUnits = 4000L,
            currencyCode = "EUR",
            type = CompensationType.REVERSAL,
            reason = "Customer disputed charge with issuing bank",
            availablePlayerWalletBalanceMinorUnits = 10000L,
            idempotencyKey = "key-rev-t001",
            correlationId = "corr-rev-1",
            causationId = "cause-rev-1",
            principal = adminPrincipal,
        )

        val gateError = assertFailsWith<AssertionError> {
            service.postCompensation(baseCmd)
        }
        assertEquals("edit/delete credit or duplicate reversal", gateError.message)

        // Bind the fail-closed gate
        RefundReversalCompensationBinding.isBound = true

        // 2. Seed original deposit (EUR 100.00 = 10000 minor units)
        seedOriginalDeposit("dep-rev-t001", 10000L)

        // 3. Normal Reversal with Sufficient Funds (EUR 40.00 out of 100.00 available)
        val normalResult = service.postCompensation(baseCmd)
        assertNotNull(normalResult)
        assertEquals(CompensationStatus.COMPLETED, normalResult.status)
        assertFalse(normalResult.isDeficitRiskCase)
        assertEquals(0L, normalResult.deficitMinorUnits)
        assertEquals(4000L, normalResult.recoveredFromWalletMinorUnits)
        assertNull(normalResult.recoveryCaseReference)
        assertTrue(normalResult.conserved)
        assertEquals(4000L, normalResult.totalDebitsMinorUnits)
        assertEquals(4000L, normalResult.totalCreditsMinorUnits)
        assertEquals(REFUND_REVERSAL_COMPENSATION_CONTRACT, normalResult.semanticContract)
        assertFalse(normalResult.isDuplicate)

        // Assert original deposit record is never edited or deleted (immutable finance history)
        val originalDepositAfter = depositStore.findCreditByPaymentRef(tenantId, "dep-rev-t001")
        assertNotNull(originalDepositAfter)
        assertEquals(10000L, originalDepositAfter.amountMinorUnits)

        // 4. Outcome-specific semantic contract:
        // "Insufficient funds becomes risk/recovery case, never hidden negative mutation."
        // Player has only EUR 15.00 (1500 minor units) left, reversal arrives for EUR 50.00 (5000 minor units)
        val insufficientFundsCmd = baseCmd.copy(
            compensationReference = "rev-comp-deficit-002",
            providerTransactionId = "tx-rev-deficit-002",
            amountMinorUnits = 5000L,
            availablePlayerWalletBalanceMinorUnits = 1500L,
            idempotencyKey = "key-rev-deficit-002",
            correlationId = "corr-rev-2",
            causationId = "cause-rev-2",
        )

        val deficitResult = service.postCompensation(insufficientFundsCmd)
        assertNotNull(deficitResult)
        assertEquals(CompensationStatus.RECOVERY_CASE_OPENED, deficitResult.status)
        assertTrue(deficitResult.isDeficitRiskCase)
        assertEquals(3500L, deficitResult.deficitMinorUnits)
        assertEquals(1500L, deficitResult.recoveredFromWalletMinorUnits)
        assertNotNull(deficitResult.recoveryCaseReference)
        assertTrue(deficitResult.recoveryCaseReference!!.startsWith("RCV-CASE-"))
        assertTrue(deficitResult.conserved)
        assertEquals(5000L, deficitResult.totalDebitsMinorUnits) // 1500 (wallet) + 3500 (risk recovery)
        assertEquals(5000L, deficitResult.totalCreditsMinorUnits)
        assertEquals(REFUND_REVERSAL_COMPENSATION_CONTRACT, deficitResult.semanticContract)

        // Verify alert emitted for recovery case creation
        assertTrue(alertSink.alerts.any { it.contains("INSUFFICIENT_FUNDS_RECOVERY_CASE_CREATED") })

        // 5. Exact duplicate replay returns identical cached outcome without double-crediting/debiting
        val duplicateResult = service.postCompensation(insufficientFundsCmd)
        assertEquals(deficitResult.compensationId, duplicateResult.compensationId)
        assertEquals(deficitResult.ledgerTransactionReference, duplicateResult.ledgerTransactionReference)
        assertTrue(duplicateResult.isDuplicate)
        assertEquals(deficitResult.deficitMinorUnits, duplicateResult.deficitMinorUnits)
    }

    @Test
    fun `PAYMENT-006-01-T002 — Post refund and reversal compensation rejects invalid, boundary, unauthorized, and stale input`() {
        seedOriginalDeposit("dep-rev-t002", 10000L)

        val baseCmd = PostCompensationCommand(
            tenantId = tenantId,
            playerId = playerId,
            originalPaymentReference = "dep-rev-t002",
            compensationReference = "rev-comp-t002",
            providerId = providerId,
            providerTransactionId = "tx-rev-t002",
            amountMinorUnits = 3000L,
            currencyCode = "EUR",
            type = CompensationType.CHARGEBACK,
            reason = "Suspected fraud chargeback",
            availablePlayerWalletBalanceMinorUnits = 5000L,
            idempotencyKey = "key-rev-t002",
            correlationId = "corr-rev-t002",
            causationId = "cause-rev-t002",
            principal = adminPrincipal,
        )

        // 1. Blank mandatory fields
        assertFailsWith<AuthenticationFailure.Rejected> { service.postCompensation(baseCmd.copy(tenantId = "")) }
        assertFailsWith<AuthenticationFailure.Rejected> { service.postCompensation(baseCmd.copy(originalPaymentReference = "  ")) }
        assertFailsWith<AuthenticationFailure.Rejected> { service.postCompensation(baseCmd.copy(compensationReference = "")) }
        assertFailsWith<AuthenticationFailure.Rejected> { service.postCompensation(baseCmd.copy(providerId = "")) }
        assertFailsWith<AuthenticationFailure.Rejected> { service.postCompensation(baseCmd.copy(providerTransactionId = "")) }
        assertFailsWith<AuthenticationFailure.Rejected> { service.postCompensation(baseCmd.copy(reason = "")) }
        assertFailsWith<AuthenticationFailure.Rejected> { service.postCompensation(baseCmd.copy(idempotencyKey = "")) }
        assertFailsWith<AuthenticationFailure.Rejected> { service.postCompensation(baseCmd.copy(correlationId = "")) }
        assertFailsWith<AuthenticationFailure.Rejected> { service.postCompensation(baseCmd.copy(causationId = "")) }

        // 2. Invalid amount & currency
        val zeroAmtError = assertFailsWith<AuthenticationFailure.Rejected> {
            service.postCompensation(baseCmd.copy(amountMinorUnits = 0L))
        }
        assertEquals(AuthErrorCode.INVALID, zeroAmtError.code)

        val negAmtError = assertFailsWith<AuthenticationFailure.Rejected> {
            service.postCompensation(baseCmd.copy(amountMinorUnits = -500L))
        }
        assertEquals(AuthErrorCode.INVALID, negAmtError.code)

        val invalidCurrError = assertFailsWith<AuthenticationFailure.Rejected> {
            service.postCompensation(baseCmd.copy(currencyCode = "eur"))
        }
        assertEquals(AuthErrorCode.INVALID, invalidCurrError.code)

        val mismatchCurrError = assertFailsWith<AuthenticationFailure.Rejected> {
            service.postCompensation(baseCmd.copy(currencyCode = "USD"))
        }
        assertEquals(AuthErrorCode.INVALID, mismatchCurrError.code)

        // 3. Stale version
        val staleError = assertFailsWith<AuthenticationFailure.Rejected> {
            service.postCompensation(baseCmd.copy(expectedVersion = 2L))
        }
        assertEquals(AuthErrorCode.STALE, staleError.code)

        // 4. Unauthorized / cross-tenant / invalid role principal
        val crossTenantError = assertFailsWith<AuthenticationFailure.Rejected> {
            service.postCompensation(baseCmd.copy(principal = crossTenantPrincipal))
        }
        assertEquals(AuthErrorCode.FORBIDDEN, crossTenantError.code)

        val playerError = assertFailsWith<AuthenticationFailure.Rejected> {
            service.postCompensation(baseCmd.copy(principal = playerPrincipal))
        }
        assertEquals(AuthErrorCode.FORBIDDEN, playerError.code)

        val supportRoleError = assertFailsWith<AuthenticationFailure.Rejected> {
            service.postCompensation(baseCmd.copy(principal = supportPrincipal))
        }
        assertEquals(AuthErrorCode.FORBIDDEN, supportRoleError.code)

        // 5. Unknown original deposit
        val missingDepError = assertFailsWith<AuthenticationFailure.Rejected> {
            service.postCompensation(baseCmd.copy(originalPaymentReference = "dep-non-existent"))
        }
        assertEquals(AuthErrorCode.INVALID, missingDepError.code)

        // Execute valid base compensation of 3000L
        service.postCompensation(baseCmd)

        // 6. Cumulative Over-Reversal Protection (deposit was 10000L, 3000L already reversed, attempting 8000L)
        val overReversalError = assertFailsWith<AuthenticationFailure.Rejected> {
            service.postCompensation(baseCmd.copy(
                compensationReference = "rev-comp-over",
                providerTransactionId = "tx-rev-over",
                amountMinorUnits = 8000L,
                idempotencyKey = "key-rev-over",
            ))
        }
        assertEquals(AuthErrorCode.CONFLICT, overReversalError.code)
        assertTrue(alertSink.alerts.any { it.contains("OVER_REVERSAL_EXCEEDS_DEPOSIT_DENIED") })

        // 7. Idempotency conflict (same key, modified amount)
        val conflictIdempError = assertFailsWith<AuthenticationFailure.Rejected> {
            service.postCompensation(baseCmd.copy(amountMinorUnits = 2000L))
        }
        assertEquals(AuthErrorCode.CONFLICT, conflictIdempError.code)
        assertTrue(alertSink.alerts.any { it.contains("COMPENSATION_IDEMPOTENCY_CONFLICT") })
    }

    @Test
    fun `PAYMENT-006-01-T003 — Post refund and reversal compensation survives concurrency, duplicate delivery, and dependency failure`() {
        seedOriginalDeposit("dep-rev-con-001", 20000L)

        val concurrentCmd = PostCompensationCommand(
            tenantId = tenantId,
            playerId = playerId,
            originalPaymentReference = "dep-rev-con-001",
            compensationReference = "rev-comp-con-001",
            providerId = providerId,
            providerTransactionId = "tx-rev-con-001",
            amountMinorUnits = 8000L,
            currencyCode = "EUR",
            type = CompensationType.REFUND,
            reason = "Customer returned purchased item",
            availablePlayerWalletBalanceMinorUnits = 10000L,
            idempotencyKey = "key-rev-con-001",
            correlationId = "corr-rev-con",
            causationId = "cause-rev-con",
            principal = securityPrincipal,
        )

        // 1. Concurrency: 8 threads concurrently submitting identical compensation
        val threadCount = 8
        val executor = Executors.newFixedThreadPool(threadCount)
        val startLatch = CountDownLatch(1)
        val doneLatch = CountDownLatch(threadCount)
        val results = java.util.Collections.synchronizedList(mutableListOf<CompensationResult>())
        val errors = java.util.Collections.synchronizedList(mutableListOf<Throwable>())

        for (i in 0 until threadCount) {
            executor.submit {
                try {
                    startLatch.await()
                    val res = service.postCompensation(concurrentCmd)
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

        assertTrue(errors.isEmpty(), "Zero errors expected on concurrent execution: $errors")
        assertEquals(threadCount, results.size)
        val firstResult = results.first()
        for (res in results) {
            assertEquals(firstResult.compensationId, res.compensationId)
            assertEquals(firstResult.ledgerTransactionReference, res.ledgerTransactionReference)
            assertEquals(8000L, res.amountMinorUnits)
            assertTrue(res.conserved)
        }

        // Exactly one compensation in store
        assertEquals(1, compensationStore.listCompensationsForDeposit(tenantId, "dep-rev-con-001").size)

        // 2. Dependency failure and retry safety: "callback failure retries safely"
        class FailingLedgerService : LedgerPostingService(clock = clock) {
            var shouldFail = true
            override fun postTransaction(command: PostTransactionCommand): PostingResult {
                if (shouldFail) {
                    throw RuntimeException("Ledger journal cluster unavailable")
                }
                return super.postTransaction(command)
            }
        }

        val failingLedger = FailingLedgerService()
        val retryService = RefundReversalCompensationService(
            depositCreditStore = depositStore,
            ledgerPostingService = failingLedger,
            store = compensationStore,
            alertSink = alertSink,
            clock = clock,
        )

        seedOriginalDeposit("dep-rev-retry-001", 15000L)
        val retryCmd = PostCompensationCommand(
            tenantId = tenantId,
            playerId = playerId,
            originalPaymentReference = "dep-rev-retry-001",
            compensationReference = "rev-comp-retry-001",
            providerId = providerId,
            providerTransactionId = "tx-rev-retry-001",
            amountMinorUnits = 6000L,
            currencyCode = "EUR",
            type = CompensationType.REVERSAL,
            reason = "Bank clearing reversal",
            availablePlayerWalletBalanceMinorUnits = 10000L,
            idempotencyKey = "key-rev-retry-001",
            correlationId = "corr-retry-1",
            causationId = "cause-retry-1",
            principal = adminPrincipal,
        )

        // Fails closed on dependency failure
        val depError = assertFailsWith<AuthenticationFailure.Rejected> {
            retryService.postCompensation(retryCmd)
        }
        assertEquals(AuthErrorCode.DEPENDENCY_UNAVAILABLE, depError.code)
        assertTrue(alertSink.alerts.any { it.contains("COMPENSATION_LEDGER_POSTING_FAILED") })

        // Invariant: Zero local compensation committed on dependency failure
        assertNull(compensationStore.findCompensationByRef(tenantId, "rev-comp-retry-001"))

        // Dependency recovers: Safe retry succeeds
        failingLedger.shouldFail = false
        val recoveredResult = retryService.postCompensation(retryCmd)
        assertNotNull(recoveredResult)
        assertFalse(recoveredResult.isDuplicate)
        assertEquals(6000L, recoveredResult.amountMinorUnits)
        assertTrue(recoveredResult.conserved)
        assertNotNull(compensationStore.findCompensationByRef(tenantId, "rev-comp-retry-001"))
    }

    @Test
    fun `PAYMENT-006-01-T004 — Post refund and reversal compensation remains compatible, recoverable, observable, and lifecycle-safe`() {
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
        seedOriginalDeposit("dep-rev-rec-001", 30000L)
        val recCmd = PostCompensationCommand(
            tenantId = tenantId,
            playerId = playerId,
            originalPaymentReference = "dep-rev-rec-001",
            compensationReference = "rev-comp-rec-001",
            providerId = providerId,
            providerTransactionId = "tx-rev-rec-001",
            amountMinorUnits = 12000L,
            currencyCode = "EUR",
            type = CompensationType.CHARGEBACK,
            reason = "Issuer chargeback notification",
            availablePlayerWalletBalanceMinorUnits = 20000L,
            idempotencyKey = "key-rev-rec-001",
            correlationId = "corr-rec-1",
            causationId = "cause-rec-1",
            principal = adminPrincipal,
        )

        val initialResult = service.postCompensation(recCmd)
        assertNotNull(initialResult)
        assertFalse(initialResult.isDuplicate)

        // Export snapshot and import into fresh store instance simulating server restart
        val snapshot = compensationStore.exportSnapshot()
        val rehydratedStore = InMemoryRefundReversalStore()
        rehydratedStore.importSnapshot(snapshot)
        val restartedService = RefundReversalCompensationService(
            depositCreditStore = depositStore,
            ledgerPostingService = ledgerService,
            store = rehydratedStore,
            alertSink = alertSink,
            clock = clock,
        )

        // Calling with same idempotency key on rehydrated store returns identical cached outcome
        val replayedResult = restartedService.postCompensation(recCmd)
        assertEquals(initialResult.compensationId, replayedResult.compensationId)
        assertEquals(initialResult.ledgerTransactionReference, replayedResult.ledgerTransactionReference)
        assertTrue(replayedResult.isDuplicate)
        assertEquals(REFUND_REVERSAL_COMPENSATION_CONTRACT, replayedResult.semanticContract)

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
