package com.slotting.admin.withdrawal

import com.slotting.admin.auth.AdminRole
import com.slotting.admin.auth.AuthenticatedPrincipal
import com.slotting.admin.auth.PrincipalKind
import com.slotting.admin.wallet.BonusBuckets
import com.slotting.admin.wallet.CashBuckets
import com.slotting.admin.wallet.InMemoryBalanceBucketsStore
import com.slotting.admin.wallet.WalletBalanceBucketsRecord
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

class PayoutReconciliationTest {
    private val now = Instant.parse("2026-09-20T20:35:00Z")
    private val clock = Clock.fixed(now, ZoneOffset.UTC)

    private val tenantId = "tenant-recon-test"
    private val playerAId = UUID.randomUUID()
    private val playerBId = UUID.randomUUID()
    private val playerCId = UUID.randomUUID()

    private val adminOperatorPrincipal = AuthenticatedPrincipal(
        id = "admin-recon-op-01",
        tenantId = tenantId,
        kind = PrincipalKind.ADMIN,
        roles = setOf(AdminRole.SUPPORT, AdminRole.SUPER_ADMIN)
    )

    private val playerPrincipal = AuthenticatedPrincipal(
        id = playerAId.toString(),
        tenantId = tenantId,
        kind = PrincipalKind.PLAYER,
        roles = emptySet()
    )

    private val foreignAdminPrincipal = AuthenticatedPrincipal(
        id = "foreign-admin-01",
        tenantId = "tenant-foreign",
        kind = PrincipalKind.ADMIN,
        roles = setOf(AdminRole.SUPER_ADMIN)
    )

    private lateinit var reconStore: InMemoryPayoutReconciliationStore
    private lateinit var payoutStore: InMemoryPayoutExecutionStore
    private lateinit var reservationStore: InMemoryWithdrawalReservationStore
    private lateinit var bucketStore: InMemoryBalanceBucketsStore
    private lateinit var fakeProviderPort: FakePayoutReconciliationProviderAdapter
    private lateinit var observability: InMemoryPayoutReconciliationObservability
    private lateinit var service: PayoutReconciliationService

    @BeforeEach
    fun setUp() {
        PayoutReconciliationBinding.isBound = true
        reconStore = InMemoryPayoutReconciliationStore()
        payoutStore = InMemoryPayoutExecutionStore()
        reservationStore = InMemoryWithdrawalReservationStore()
        bucketStore = InMemoryBalanceBucketsStore()
        fakeProviderPort = FakePayoutReconciliationProviderAdapter()
        observability = InMemoryPayoutReconciliationObservability()

        service = PayoutReconciliationService(
            reconciliationStore = reconStore,
            payoutStore = payoutStore,
            reservationStore = reservationStore,
            bucketStore = bucketStore,
            providerPort = fakeProviderPort,
            observability = observability,
            clock = clock
        )
    }

    @AfterEach
    fun tearDown() {
        PayoutReconciliationBinding.isBound = true
    }

    private fun setupWallet(ownerId: UUID, availableMinorUnits: Long, pendingMinorUnits: Long): WalletBalanceBucketsRecord {
        val wallet = WalletBalanceBucketsRecord(
            walletId = UUID.randomUUID(),
            tenantId = tenantId,
            ownerId = ownerId,
            currencyCode = "USD",
            cash = CashBuckets(
                availableMinorUnits = availableMinorUnits,
                lockedMinorUnits = 0L,
                pendingWithdrawalMinorUnits = pendingMinorUnits
            ),
            bonus = BonusBuckets(0L, 0L, 0L),
            version = 1L,
            createdAt = now.minusSeconds(3600),
            updatedAt = now
        )
        bucketStore.saveWallet(wallet)
        return wallet
    }

    private fun setupReservation(
        ownerId: UUID,
        walletId: UUID,
        amountMinorUnits: Long,
        state: WithdrawalReservationState = WithdrawalReservationState.RESERVED
    ): WithdrawalReservationRecord {
        val reservation = WithdrawalReservationRecord(
            reservationId = UUID.randomUUID(),
            tenantId = tenantId,
            ownerId = ownerId,
            walletId = walletId,
            requestId = UUID.randomUUID(),
            currencyCode = "USD",
            grossAmountMinorUnits = amountMinorUnits,
            state = state,
            reservedAt = now.minusSeconds(300),
            expiresAt = now.plusSeconds(86400),
            idempotencyKey = "res-idemp-${UUID.randomUUID()}",
            correlationId = "corr-res-${UUID.randomUUID()}",
            causationId = "caus-res-${UUID.randomUUID()}",
            evidenceReference = "ev-res-${UUID.randomUUID()}"
        )
        reservationStore.save(reservation)
        return reservation
    }

    private fun setupPayout(
        ownerId: UUID,
        walletId: UUID,
        reservationId: UUID,
        amountMinorUnits: Long,
        status: PayoutExecutionStatus = PayoutExecutionStatus.PENDING_RECONCILIATION
    ): PayoutExecutionRecord {
        val payout = PayoutExecutionRecord(
            payoutId = UUID.randomUUID(),
            tenantId = tenantId,
            ownerId = ownerId,
            walletId = walletId,
            requestId = UUID.randomUUID(),
            reservationId = reservationId,
            approvalId = UUID.randomUUID(),
            currencyCode = "USD",
            grossAmountMinorUnits = amountMinorUnits,
            status = status,
            providerTransactionId = "tx-prov-${UUID.randomUUID()}",
            providerReason = "Initial status: $status",
            initiatedAt = now.minusSeconds(200),
            completedAt = if (status in setOf(PayoutExecutionStatus.CAPTURED, PayoutExecutionStatus.RELEASED)) now.minusSeconds(100) else null,
            idempotencyKey = "init-idemp-${UUID.randomUUID()}",
            correlationId = "corr-payout-${UUID.randomUUID()}",
            causationId = "caus-payout-${UUID.randomUUID()}",
            evidenceReference = "ev-payout-${UUID.randomUUID()}"
        )
        payoutStore.save(payout)
        return payout
    }

    // =========================================================================
    // WITHDRAW-003-03-T001 — Produces required authoritative outcome
    // =========================================================================
    @Test
    fun `WITHDRAW-003-03-T001 — Reconcile ambiguous payout and release failures produces the required authoritative outcome`() {
        val walletA = setupWallet(playerAId, availableMinorUnits = 100_000L, pendingMinorUnits = 50_000L)
        val resA = setupReservation(playerAId, walletA.walletId, 50_000L)
        val payoutA = setupPayout(playerAId, walletA.walletId, resA.reservationId, 50_000L)

        // 1. Upstream bank inquiry confirms SUCCESS_CONFIRMED: "success captures lock"
        fakeProviderPort.forcedStatus = ProviderReconciliationStatus.SUCCESS_CONFIRMED
        val cmdSuccess = ReconcileAmbiguousPayoutCommand(
            principal = adminOperatorPrincipal,
            tenantId = tenantId,
            payoutId = payoutA.payoutId,
            idempotencyKey = "recon-succ-001",
            correlationId = "corr-recon-001",
            causationId = "caus-recon-001"
        )
        val resultSuccess = service.reconcilePayout(cmdSuccess)

        assertEquals(PayoutExecutionStatus.CAPTURED, resultSuccess.currentStatus)
        assertEquals(WithdrawalReservationState.CAPTURED, resultSuccess.reservationState)
        assertEquals(PayoutReconciliationAction.CAPTURED, resultSuccess.action)
        assertFalse(resultSuccess.isDuplicate)
        assertTrue(resultSuccess.debitsEqualCredits)
        assertFalse(resultSuccess.hasAndroidDbImpact)
        assertFalse(resultSuccess.hasAndroidLifecycleClaim)
        assertEquals("PAYOUT_RECONCILED_AND_CAPTURED", resultSuccess.auditEvent.type)
        assertEquals("payout.reconciliation.captured", resultSuccess.outboxEvent.type)

        // Wallet balance check: pending deduction permanently captured; available untouched
        assertEquals(0L, resultSuccess.walletBalance?.cash?.pendingWithdrawalMinorUnits)
        assertEquals(100_000L, resultSuccess.walletBalance?.cash?.availableMinorUnits)

        // 2. Upstream bank inquiry confirms REJECTION_CONFIRMED: "only definitive rejection releases"
        val walletB = setupWallet(playerBId, availableMinorUnits = 80_000L, pendingMinorUnits = 40_000L)
        val resB = setupReservation(playerBId, walletB.walletId, 40_000L)
        val payoutB = setupPayout(playerBId, walletB.walletId, resB.reservationId, 40_000L)

        fakeProviderPort.forcedStatus = ProviderReconciliationStatus.REJECTION_CONFIRMED
        val cmdReject = ReconcileAmbiguousPayoutCommand(
            principal = adminOperatorPrincipal,
            tenantId = tenantId,
            payoutId = payoutB.payoutId,
            idempotencyKey = "recon-rej-001",
            correlationId = "corr-recon-002",
            causationId = "caus-recon-002"
        )
        val resultReject = service.reconcilePayout(cmdReject)

        assertEquals(PayoutExecutionStatus.RELEASED, resultReject.currentStatus)
        assertEquals(WithdrawalReservationState.RELEASED, resultReject.reservationState)
        assertEquals(PayoutReconciliationAction.RELEASED, resultReject.action)
        assertTrue(resultReject.debitsEqualCredits)
        assertEquals("PAYOUT_RECONCILED_AND_RELEASED", resultReject.auditEvent.type)
        assertEquals("payout.reconciliation.released", resultReject.outboxEvent.type)

        // Wallet balance check: pending refunded back to available
        assertEquals(0L, resultReject.walletBalance?.cash?.pendingWithdrawalMinorUnits)
        assertEquals(120_000L, resultReject.walletBalance?.cash?.availableMinorUnits)

        val updatedResB = reservationStore.findById(resB.reservationId)
        assertNotNull(updatedResB)
        assertEquals(WithdrawalReleaseReason.PROVIDER_REJECTED, updatedResB.releaseReason)

        // 3. Upstream bank inquiry confirms STILL_UNKNOWN_PENDING: "Unknown stays pending/reconcile"
        val walletC = setupWallet(playerCId, availableMinorUnits = 60_000L, pendingMinorUnits = 25_000L)
        val resC = setupReservation(playerCId, walletC.walletId, 25_000L)
        val payoutC = setupPayout(playerCId, walletC.walletId, resC.reservationId, 25_000L)

        fakeProviderPort.forcedStatus = ProviderReconciliationStatus.STILL_UNKNOWN_PENDING
        val cmdPending = ReconcileAmbiguousPayoutCommand(
            principal = adminOperatorPrincipal,
            tenantId = tenantId,
            payoutId = payoutC.payoutId,
            idempotencyKey = "recon-pend-001",
            correlationId = "corr-recon-003",
            causationId = "caus-recon-003"
        )
        val resultPending = service.reconcilePayout(cmdPending)

        assertEquals(PayoutExecutionStatus.PENDING_RECONCILIATION, resultPending.currentStatus)
        assertEquals(WithdrawalReservationState.RESERVED, resultPending.reservationState)
        assertEquals(PayoutReconciliationAction.REMAINED_PENDING, resultPending.action)
        assertTrue(resultPending.debitsEqualCredits)

        // Wallet untouched
        val currentWalletC = bucketStore.findWalletById(tenantId, walletC.walletId)
        assertEquals(25_000L, currentWalletC?.cash?.pendingWithdrawalMinorUnits)
        assertEquals(60_000L, currentWalletC?.cash?.availableMinorUnits)
    }

    // =========================================================================
    // WITHDRAW-003-03-T002 — Rejects invalid, boundary, unauthorized, and stale input
    // =========================================================================
    @Test
    fun `WITHDRAW-003-03-T002 — Reconcile ambiguous payout and release failures rejects invalid, boundary, unauthorized, and stale input`() {
        val wallet = setupWallet(playerAId, 100_000L, 50_000L)
        val res = setupReservation(playerAId, wallet.walletId, 50_000L)
        val payout = setupPayout(playerAId, wallet.walletId, res.reservationId, 50_000L)

        val validCmd = ReconcileAmbiguousPayoutCommand(
            principal = adminOperatorPrincipal,
            tenantId = tenantId,
            payoutId = payout.payoutId,
            idempotencyKey = "cmd-valid-001",
            correlationId = "corr-001",
            causationId = "caus-001"
        )

        // 1. Unauthenticated principal
        assertFailsWith<UnauthorizedPayoutReconciliationException> {
            service.reconcilePayout(validCmd.copy(principal = null))
        }

        // 2. Unauthorized principal (Player role)
        assertFailsWith<UnauthorizedPayoutReconciliationException> {
            service.reconcilePayout(validCmd.copy(principal = playerPrincipal))
        }

        // 3. Cross-tenant access forbidden
        assertFailsWith<UnauthorizedPayoutReconciliationException> {
            service.reconcilePayout(validCmd.copy(principal = foreignAdminPrincipal))
        }

        // 4. Unknown payout ID
        assertFailsWith<PayoutReconciliationNotFoundException> {
            service.reconcilePayout(validCmd.copy(payoutId = UUID.randomUUID()))
        }

        // 5. Blank headers
        assertFailsWith<IllegalArgumentException> {
            service.reconcilePayout(validCmd.copy(tenantId = " "))
        }
        assertFailsWith<IllegalArgumentException> {
            service.reconcilePayout(validCmd.copy(idempotencyKey = " "))
        }

        // 6. Terminal state conflict: cannot release already CAPTURED payout
        fakeProviderPort.forcedStatus = ProviderReconciliationStatus.SUCCESS_CONFIRMED
        service.reconcilePayout(validCmd) // Payout is now CAPTURED

        fakeProviderPort.forcedStatus = ProviderReconciliationStatus.REJECTION_CONFIRMED
        val conflictCmd = validCmd.copy(idempotencyKey = "conflict-key-002")
        assertFailsWith<PayoutReconciliationConflictException> {
            service.reconcilePayout(conflictCmd)
        }

        // State remains CAPTURED, no money altered
        val postConflictPayout = payoutStore.findById(tenantId, payout.payoutId)
        assertEquals(PayoutExecutionStatus.CAPTURED, postConflictPayout?.status)
    }

    // =========================================================================
    // WITHDRAW-003-03-T003 — Survives concurrency, duplicate delivery, and dependency failure
    // =========================================================================
    @Test
    fun `WITHDRAW-003-03-T003 — Reconcile ambiguous payout and release failures survives concurrency, duplicate delivery, and dependency failure`() {
        val wallet = setupWallet(playerAId, 100_000L, 50_000L)
        val res = setupReservation(playerAId, wallet.walletId, 50_000L)
        val payout = setupPayout(playerAId, wallet.walletId, res.reservationId, 50_000L)

        // 1. Concurrent duplicate reconciliation attempts
        fakeProviderPort.forcedStatus = ProviderReconciliationStatus.SUCCESS_CONFIRMED
        val cmd = ReconcileAmbiguousPayoutCommand(
            principal = adminOperatorPrincipal,
            tenantId = tenantId,
            payoutId = payout.payoutId,
            idempotencyKey = "shared-recon-idemp-001",
            correlationId = "corr-race-001",
            causationId = "caus-race-001"
        )

        val executor = Executors.newFixedThreadPool(4)
        val tasks = (1..8).map {
            Callable { service.reconcilePayout(cmd) }
        }
        val futures = executor.invokeAll(tasks)
        executor.shutdown()

        val results = futures.map { it.get() }
        assertEquals(8, results.size)
        assertTrue(results.all { it.currentStatus == PayoutExecutionStatus.CAPTURED })

        // Check wallet was deducted exactly once, never double-debited
        val finalWallet = bucketStore.findWalletById(tenantId, wallet.walletId)
        assertEquals(0L, finalWallet?.cash?.pendingWithdrawalMinorUnits)
        assertEquals(100_000L, finalWallet?.cash?.availableMinorUnits)

        // 2. Changed payload with same idempotency key conflicts
        val conflictCmd = cmd.copy(trigger = ReconciliationTrigger.OPERATOR_MANUAL, manualResolution = ProviderReconciliationStatus.REJECTION_CONFIRMED)
        assertFailsWith<PayoutReconciliationConflictException> {
            service.reconcilePayout(conflictCmd)
        }

        // 3. Upstream dependency timeout / failure handling:
        val walletB = setupWallet(playerBId, 80_000L, 30_000L)
        val resB = setupReservation(playerBId, walletB.walletId, 30_000L)
        val payoutB = setupPayout(playerBId, walletB.walletId, resB.reservationId, 30_000L)

        fakeProviderPort.shouldFail = true
        val cmdFail = ReconcileAmbiguousPayoutCommand(
            principal = adminOperatorPrincipal,
            tenantId = tenantId,
            payoutId = payoutB.payoutId,
            idempotencyKey = "recon-fail-001",
            correlationId = "corr-fail-001",
            causationId = "caus-fail-001"
        )

        // Survives failure gracefully: stays pending reconciliation, does not fail open or claim false success
        val failResult = service.reconcilePayout(cmdFail)
        assertEquals(PayoutExecutionStatus.PENDING_RECONCILIATION, failResult.currentStatus)
        assertEquals(WithdrawalReservationState.RESERVED, failResult.reservationState)
        assertEquals(PayoutReconciliationAction.REMAINED_PENDING, failResult.action)

        val walletAfterFail = bucketStore.findWalletById(tenantId, walletB.walletId)
        assertEquals(30_000L, walletAfterFail?.cash?.pendingWithdrawalMinorUnits)
        assertEquals(80_000L, walletAfterFail?.cash?.availableMinorUnits)
    }

    // =========================================================================
    // WITHDRAW-003-03-T004 — Remains compatible, recoverable, observable, and lifecycle-safe
    // =========================================================================
    @Test
    fun `WITHDRAW-003-03-T004 — Reconcile ambiguous payout and release failures remains compatible, recoverable, observable, and lifecycle-safe`() {
        val wallet = setupWallet(playerAId, 100_000L, 50_000L)
        val res = setupReservation(playerAId, wallet.walletId, 50_000L)
        val payout = setupPayout(playerAId, wallet.walletId, res.reservationId, 50_000L)

        fakeProviderPort.forcedStatus = ProviderReconciliationStatus.SUCCESS_CONFIRMED
        val cmd = ReconcileAmbiguousPayoutCommand(
            principal = adminOperatorPrincipal,
            tenantId = tenantId,
            payoutId = payout.payoutId,
            idempotencyKey = "recon-lifecycle-001",
            correlationId = "corr-life-001",
            causationId = "caus-life-001"
        )
        val result = service.reconcilePayout(cmd)

        // 1. Simulated restart / service recreation from store
        val restartedService = PayoutReconciliationService(
            reconciliationStore = reconStore,
            payoutStore = payoutStore,
            reservationStore = reservationStore,
            bucketStore = bucketStore,
            providerPort = fakeProviderPort,
            observability = observability,
            clock = clock
        )

        val recoveredPayout = payoutStore.findById(tenantId, payout.payoutId)
        assertNotNull(recoveredPayout)
        assertEquals(PayoutExecutionStatus.CAPTURED, recoveredPayout.status)
        assertEquals(result.currentStatus, recoveredPayout.status)

        // Replay through restarted service returns duplicate accepted
        val replayResult = restartedService.reconcilePayout(cmd)
        assertEquals(PayoutExecutionStatus.CAPTURED, replayResult.currentStatus)

        // 2. Observability checks
        val metrics = observability.getMetrics()
        assertTrue(metrics.isNotEmpty())
        assertTrue(metrics.any { it.eventType == "accept" })
        assertTrue(metrics.any { it.eventType == "duplicate" })

        metrics.forEach { event ->
            assertNotNull(event.correlationId)
            assertNotNull(event.causationId)
            assertFalse(event.details.toString().contains("password"))
            assertFalse(event.details.toString().contains("secret"))
        }

        // 3. Android DB & lifecycle claim checks
        assertFalse(result.hasAndroidDbImpact)
        assertFalse(result.hasAndroidLifecycleClaim)
    }
}
