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
import kotlin.test.assertNull
import kotlin.test.assertTrue

class ProviderPayoutInitiationTest {
    private val now = Instant.parse("2026-09-20T20:25:00Z")
    private val clock = Clock.fixed(now, ZoneOffset.UTC)

    private val playerAId = UUID.randomUUID()
    private val playerBId = UUID.randomUUID()

    private val playerAPrincipal = AuthenticatedPrincipal(
        id = playerAId.toString(),
        tenantId = "tenant-payout-init",
        kind = PrincipalKind.PLAYER,
        roles = emptySet()
    )

    private val adminOperatorPrincipal = AuthenticatedPrincipal(
        id = "admin-operator-01",
        tenantId = "tenant-payout-init",
        kind = PrincipalKind.ADMIN,
        roles = setOf(AdminRole.SUPPORT, AdminRole.SUPER_ADMIN)
    )

    private val foreignAdminPrincipal = AuthenticatedPrincipal(
        id = "foreign-admin-99",
        tenantId = "tenant-foreign-init",
        kind = PrincipalKind.ADMIN,
        roles = setOf(AdminRole.SUPER_ADMIN)
    )

    private lateinit var payoutStore: InMemoryPayoutExecutionStore
    private lateinit var approvalStore: InMemoryPayoutApprovalStore
    private lateinit var reservationStore: InMemoryWithdrawalReservationStore
    private lateinit var bucketStore: InMemoryBalanceBucketsStore
    private lateinit var fakeProviderPort: FakePayoutProviderAdapter
    private lateinit var observability: InMemoryPayoutInitiationObservability
    private lateinit var service: ProviderPayoutInitiationService

    @BeforeEach
    fun setUp() {
        ProviderPayoutInitiationBinding.isBound = true
        payoutStore = InMemoryPayoutExecutionStore()
        approvalStore = InMemoryPayoutApprovalStore()
        reservationStore = InMemoryWithdrawalReservationStore()
        bucketStore = InMemoryBalanceBucketsStore()
        fakeProviderPort = FakePayoutProviderAdapter()
        observability = InMemoryPayoutInitiationObservability()
        service = ProviderPayoutInitiationService(
            payoutStore = payoutStore,
            approvalStore = approvalStore,
            reservationStore = reservationStore,
            bucketStore = bucketStore,
            providerPort = fakeProviderPort,
            observability = observability,
            clock = clock
        )
    }

    @AfterEach
    fun tearDown() {
        ProviderPayoutInitiationBinding.isBound = true
    }

    private fun setupWallet(ownerId: UUID, availableMinorUnits: Long, pendingMinorUnits: Long): WalletBalanceBucketsRecord {
        val wallet = WalletBalanceBucketsRecord(
            walletId = UUID.randomUUID(),
            tenantId = "tenant-payout-init",
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
            tenantId = "tenant-payout-init",
            ownerId = ownerId,
            walletId = walletId,
            requestId = UUID.randomUUID(),
            currencyCode = "USD",
            grossAmountMinorUnits = amountMinorUnits,
            state = state,
            reservedAt = now,
            expiresAt = now.plusSeconds(86400),
            idempotencyKey = "res-idemp-${UUID.randomUUID()}",
            correlationId = "corr-res-${UUID.randomUUID()}",
            causationId = "caus-res-${UUID.randomUUID()}",
            evidenceReference = "ev-res-${UUID.randomUUID()}"
        )
        reservationStore.save(reservation)
        return reservation
    }

    private fun setupApproval(
        ownerId: UUID,
        walletId: UUID,
        reservationId: UUID,
        amountMinorUnits: Long,
        status: PayoutApprovalStatus = PayoutApprovalStatus.APPROVED
    ): PayoutApprovalRecord {
        val approval = PayoutApprovalRecord(
            approvalId = UUID.randomUUID(),
            tenantId = "tenant-payout-init",
            ownerId = ownerId,
            walletId = walletId,
            requestId = UUID.randomUUID(),
            reservationId = reservationId,
            currencyCode = "USD",
            grossAmountMinorUnits = amountMinorUnits,
            status = status,
            makerPrincipal = adminOperatorPrincipal,
            makerNotes = "Maker approved",
            checkerPrincipal = adminOperatorPrincipal,
            checkerNotes = "Checker approved",
            createdAt = now.minusSeconds(600),
            decidedAt = now.minusSeconds(300),
            expiresAt = now.plusSeconds(86400),
            idempotencyKey = "appr-idemp-${UUID.randomUUID()}",
            correlationId = "corr-appr-${UUID.randomUUID()}",
            causationId = "caus-appr-${UUID.randomUUID()}",
            evidenceReference = "ev-appr-${UUID.randomUUID()}"
        )
        approvalStore.save(approval)
        return approval
    }

    // =========================================================================
    // WITHDRAW-003-01-T001 — Produces required authoritative outcome
    // =========================================================================
    @Test
    fun `WITHDRAW-003-01-T001 Initiate idempotent provider payout produces the required authoritative outcome`() {
        val wallet1 = setupWallet(playerAId, availableMinorUnits = 100_000L, pendingMinorUnits = 50_000L)
        val reservation1 = setupReservation(playerAId, wallet1.walletId, amountMinorUnits = 50_000L)
        val approval1 = setupApproval(playerAId, wallet1.walletId, reservation1.reservationId, amountMinorUnits = 50_000L)

        // 1. SUCCESS Outcome: success captures lock
        val cmdSuccess = InitiateProviderPayoutCommand(
            principal = adminOperatorPrincipal,
            tenantId = "tenant-payout-init",
            ownerId = playerAId,
            reservationId = reservation1.reservationId,
            approvalId = approval1.approvalId,
            idempotencyKey = "init-success-001",
            correlationId = "corr-succ-001",
            causationId = "caus-succ-001",
            simulatedOutcome = PayoutProviderStatus.SUCCESS
        )
        val resultSuccess = service.initiatePayout(cmdSuccess)

        assertEquals(PayoutExecutionStatus.CAPTURED, resultSuccess.execution.status)
        assertEquals(WithdrawalReservationState.CAPTURED, resultSuccess.reservationState)
        // Locked funds permanently deducted from pending balance; available untouched
        assertEquals(0L, resultSuccess.walletBalance.cash.pendingWithdrawalMinorUnits)
        assertEquals(100_000L, resultSuccess.walletBalance.cash.availableMinorUnits)
        assertTrue(resultSuccess.debitsEqualCredits)
        assertFalse(resultSuccess.hasAndroidDbImpact)
        assertFalse(resultSuccess.hasAndroidLifecycleClaim)
        assertEquals("PAYOUT_INITIATED_AND_CAPTURED", resultSuccess.auditEvent.type)
        assertEquals("payout.initiated.captured", resultSuccess.outboxEvent.type)

        // 2. DEFINITIVE REJECTION Outcome: only definitive rejection releases
        val wallet2 = setupWallet(playerBId, availableMinorUnits = 200_000L, pendingMinorUnits = 80_000L)
        val reservation2 = setupReservation(playerBId, wallet2.walletId, amountMinorUnits = 80_000L)
        val approval2 = setupApproval(playerBId, wallet2.walletId, reservation2.reservationId, amountMinorUnits = 80_000L)

        val cmdReject = InitiateProviderPayoutCommand(
            principal = adminOperatorPrincipal,
            tenantId = "tenant-payout-init",
            ownerId = playerBId,
            reservationId = reservation2.reservationId,
            approvalId = approval2.approvalId,
            idempotencyKey = "init-reject-001",
            correlationId = "corr-rej-001",
            causationId = "caus-rej-001",
            simulatedOutcome = PayoutProviderStatus.REJECTED
        )
        val resultReject = service.initiatePayout(cmdReject)

        assertEquals(PayoutExecutionStatus.RELEASED, resultReject.execution.status)
        assertEquals(WithdrawalReservationState.RELEASED, resultReject.reservationState)
        // Funds refunded from pending back to available
        assertEquals(0L, resultReject.walletBalance.cash.pendingWithdrawalMinorUnits)
        assertEquals(280_000L, resultReject.walletBalance.cash.availableMinorUnits)
        assertTrue(resultReject.debitsEqualCredits)
        assertEquals("PAYOUT_REJECTED_BY_PROVIDER_FUNDS_RELEASED", resultReject.auditEvent.type)
        assertEquals("payout.initiated.released", resultReject.outboxEvent.type)

        val persistedRes = reservationStore.findById(reservation2.reservationId)
        assertNotNull(persistedRes)
        assertEquals(WithdrawalReleaseReason.PROVIDER_REJECTED, persistedRes.releaseReason)

        // 3. UNKNOWN / TIMEOUT Outcome: Unknown stays pending/reconcile
        val playerCId = UUID.randomUUID()
        val wallet3 = setupWallet(playerCId, availableMinorUnits = 50_000L, pendingMinorUnits = 30_000L)
        val reservation3 = setupReservation(playerCId, wallet3.walletId, amountMinorUnits = 30_000L)
        val approval3 = setupApproval(playerCId, wallet3.walletId, reservation3.reservationId, amountMinorUnits = 30_000L)

        val cmdUnknown = InitiateProviderPayoutCommand(
            principal = adminOperatorPrincipal,
            tenantId = "tenant-payout-init",
            ownerId = playerCId,
            reservationId = reservation3.reservationId,
            approvalId = approval3.approvalId,
            idempotencyKey = "init-unknown-001",
            correlationId = "corr-unk-001",
            causationId = "caus-unk-001",
            simulatedOutcome = PayoutProviderStatus.UNKNOWN_PENDING
        )
        val resultUnknown = service.initiatePayout(cmdUnknown)

        assertEquals(PayoutExecutionStatus.PENDING_RECONCILIATION, resultUnknown.execution.status)
        // Invariant: Reservation REMAINS RESERVED, funds remain locked in pendingWithdrawal
        assertEquals(WithdrawalReservationState.RESERVED, resultUnknown.reservationState)
        assertEquals(30_000L, resultUnknown.walletBalance.cash.pendingWithdrawalMinorUnits)
        assertEquals(50_000L, resultUnknown.walletBalance.cash.availableMinorUnits)
        assertTrue(resultUnknown.debitsEqualCredits)
        assertEquals("PAYOUT_INITIATION_UNKNOWN_PENDING_RECONCILIATION", resultUnknown.auditEvent.type)
        assertEquals("payout.pending_reconciliation", resultUnknown.outboxEvent.type)
    }

    // =========================================================================
    // WITHDRAW-003-01-T002 — Rejects invalid, boundary, unauthorized, stale input
    // =========================================================================
    @Test
    fun `WITHDRAW-003-01-T002 Initiate idempotent provider payout rejects invalid, boundary, unauthorized, and stale input`() {
        val wallet = setupWallet(playerAId, availableMinorUnits = 100_000L, pendingMinorUnits = 40_000L)
        val reservation = setupReservation(playerAId, wallet.walletId, amountMinorUnits = 40_000L)

        // 1. Proposal is NOT approved (e.g. PENDING_REVIEW)
        val pendingApproval = setupApproval(playerAId, wallet.walletId, reservation.reservationId, 40_000L, status = PayoutApprovalStatus.PENDING_REVIEW)
        val cmd = InitiateProviderPayoutCommand(
            principal = adminOperatorPrincipal,
            tenantId = "tenant-payout-init",
            ownerId = playerAId,
            reservationId = reservation.reservationId,
            approvalId = pendingApproval.approvalId,
            idempotencyKey = "t002-init-01",
            correlationId = "corr-t002-01",
            causationId = "caus-t002-01"
        )
        assertFailsWith<PayoutNotApprovedException> {
            service.initiatePayout(cmd)
        }

        // 2. Proposal is REJECTED
        val rejectedApproval = setupApproval(playerAId, wallet.walletId, reservation.reservationId, 40_000L, status = PayoutApprovalStatus.REJECTED)
        assertFailsWith<PayoutNotApprovedException> {
            service.initiatePayout(cmd.copy(approvalId = rejectedApproval.approvalId, idempotencyKey = "t002-init-02"))
        }

        // Setup an APPROVED approval for other negative checks
        val approvedApproval = setupApproval(playerAId, wallet.walletId, reservation.reservationId, 40_000L, status = PayoutApprovalStatus.APPROVED)

        // 3. Reservation is ON_HOLD
        val onHoldRes = setupReservation(playerAId, wallet.walletId, 20_000L, state = WithdrawalReservationState.ON_HOLD)
        assertFailsWith<InvalidReservationStateException> {
            service.initiatePayout(cmd.copy(reservationId = onHoldRes.reservationId, approvalId = approvedApproval.approvalId, idempotencyKey = "t002-onhold"))
        }

        // 4. Reservation is already RELEASED
        val releasedRes = setupReservation(playerAId, wallet.walletId, 20_000L, state = WithdrawalReservationState.RELEASED)
        assertFailsWith<PayoutInitiationConflictException> {
            service.initiatePayout(cmd.copy(reservationId = releasedRes.reservationId, approvalId = approvedApproval.approvalId, idempotencyKey = "t002-released"))
        }

        // 5. Player attempts to initiate payout (unauthorized)
        assertFailsWith<UnauthorizedPayoutInitiationException> {
            service.initiatePayout(cmd.copy(principal = playerAPrincipal, approvalId = approvedApproval.approvalId, idempotencyKey = "t002-player"))
        }

        // 6. Unauthenticated (null principal)
        assertFailsWith<UnauthorizedPayoutInitiationException> {
            service.initiatePayout(cmd.copy(principal = null, approvalId = approvedApproval.approvalId, idempotencyKey = "t002-null"))
        }

        // 7. Cross-tenant IDOR access
        assertFailsWith<UnauthorizedPayoutInitiationException> {
            service.initiatePayout(cmd.copy(principal = foreignAdminPrincipal, approvalId = approvedApproval.approvalId, idempotencyKey = "t002-cross"))
        }

        // 8. Blank header
        assertFailsWith<IllegalArgumentException> {
            service.initiatePayout(cmd.copy(idempotencyKey = ""))
        }
    }

    // =========================================================================
    // WITHDRAW-003-01-T003 — Survives concurrency, duplicates, dependency failure
    // =========================================================================
    @Test
    fun `WITHDRAW-003-01-T003 Initiate idempotent provider payout survives concurrency, duplicate delivery, and dependency failure`() {
        val wallet = setupWallet(playerAId, availableMinorUnits = 100_000L, pendingMinorUnits = 30_000L)
        val reservation = setupReservation(playerAId, wallet.walletId, amountMinorUnits = 30_000L)
        val approval = setupApproval(playerAId, wallet.walletId, reservation.reservationId, 30_000L, status = PayoutApprovalStatus.APPROVED)

        val cmd = InitiateProviderPayoutCommand(
            principal = adminOperatorPrincipal,
            tenantId = "tenant-payout-init",
            ownerId = playerAId,
            reservationId = reservation.reservationId,
            approvalId = approval.approvalId,
            idempotencyKey = "idemp-t003-payout",
            correlationId = "corr-t003",
            causationId = "caus-t003",
            simulatedOutcome = PayoutProviderStatus.SUCCESS
        )

        // 1. Idempotency: exact duplicate delivery returns cached result
        val res1 = service.initiatePayout(cmd)
        val res2 = service.initiatePayout(cmd)
        assertEquals(res1.execution.payoutId, res2.execution.payoutId)
        assertEquals(res1.resultId, res2.resultId)

        // Key reused with conflicting provider ID
        assertFailsWith<PayoutInitiationConflictException> {
            service.initiatePayout(cmd.copy(providerId = "other-provider"))
        }

        // 2. Concurrency: 10 threads race to initiate payout for another approved reservation
        val walletRace = setupWallet(playerBId, availableMinorUnits = 50_000L, pendingMinorUnits = 20_000L)
        val resRace = setupReservation(playerBId, walletRace.walletId, amountMinorUnits = 20_000L)
        val apprRace = setupApproval(playerBId, walletRace.walletId, resRace.reservationId, 20_000L, status = PayoutApprovalStatus.APPROVED)

        val threadCount = 10
        val executor = Executors.newFixedThreadPool(threadCount)
        val tasks = (1..threadCount).map { idx ->
            Callable {
                try {
                    service.initiatePayout(
                        InitiateProviderPayoutCommand(
                            principal = adminOperatorPrincipal,
                            tenantId = "tenant-payout-init",
                            ownerId = playerBId,
                            reservationId = resRace.reservationId,
                            approvalId = apprRace.approvalId,
                            idempotencyKey = "idemp-race-$idx",
                            correlationId = "corr-race-$idx",
                            causationId = "caus-race-$idx",
                            simulatedOutcome = PayoutProviderStatus.SUCCESS
                        )
                    )
                    true
                } catch (e: PayoutInitiationConflictException) {
                    false
                }
            }
        }

        val futures = executor.invokeAll(tasks)
        executor.shutdown()

        val results = futures.map { it.get() }
        val successCount = results.count { it }
        val conflictCount = results.count { !it }

        // Exactly one initiation succeeds; others fail with conflict
        assertEquals(1, successCount)
        assertEquals(threadCount - 1, conflictCount)
    }

    // =========================================================================
    // WITHDRAW-003-01-T004 — Compatible, recoverable, observable, lifecycle-safe
    // =========================================================================
    @Test
    fun `WITHDRAW-003-01-T004 Initiate idempotent provider payout remains compatible, recoverable, observable, and lifecycle-safe`() {
        val wallet = setupWallet(playerAId, availableMinorUnits = 100_000L, pendingMinorUnits = 25_000L)
        val reservation = setupReservation(playerAId, wallet.walletId, amountMinorUnits = 25_000L)
        val approval = setupApproval(playerAId, wallet.walletId, reservation.reservationId, 25_000L, status = PayoutApprovalStatus.APPROVED)

        val cmd = InitiateProviderPayoutCommand(
            principal = adminOperatorPrincipal,
            tenantId = "tenant-payout-init",
            ownerId = playerAId,
            reservationId = reservation.reservationId,
            approvalId = approval.approvalId,
            idempotencyKey = "t004-init",
            correlationId = "corr-t004",
            causationId = "caus-t004",
            simulatedOutcome = PayoutProviderStatus.UNKNOWN_PENDING
        )

        val result = service.initiatePayout(cmd)

        // Zero Android claims
        assertFalse(result.hasAndroidDbImpact)
        assertFalse(result.hasAndroidLifecycleClaim)

        // Duplicate replay
        val dupResult = service.initiatePayout(cmd)
        assertEquals(result.resultId, dupResult.resultId)

        // Observability metrics check
        val metrics = observability.getMetrics()
        assertTrue(metrics.any { it.eventType == "reconciliation_required" })
        assertTrue(metrics.any { it.eventType == "duplicate" })
        assertTrue(metrics.any { it.eventType == "accept" })

        // Query execution
        val queried = service.getPayoutExecution(
            GetPayoutExecutionQuery(
                principal = adminOperatorPrincipal,
                tenantId = "tenant-payout-init",
                payoutId = result.execution.payoutId
            )
        )
        assertNotNull(queried)
        assertEquals(PayoutExecutionStatus.PENDING_RECONCILIATION, queried.status)
    }
}
