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

class MakerCheckerPayoutApprovalTest {
    private val now = Instant.parse("2026-09-20T20:20:00Z")
    private val clock = Clock.fixed(now, ZoneOffset.UTC)

    private val playerAId = UUID.randomUUID()
    private val playerBId = UUID.randomUUID()

    private val playerAPrincipal = AuthenticatedPrincipal(
        id = playerAId.toString(),
        tenantId = "tenant-payout-prod",
        kind = PrincipalKind.PLAYER,
        roles = emptySet()
    )

    private val makerOperatorPrincipal = AuthenticatedPrincipal(
        id = "operator-maker-01",
        tenantId = "tenant-payout-prod",
        kind = PrincipalKind.ADMIN,
        roles = setOf(AdminRole.SUPPORT)
    )

    private val checkerAuditorPrincipal = AuthenticatedPrincipal(
        id = "auditor-checker-02",
        tenantId = "tenant-payout-prod",
        kind = PrincipalKind.ADMIN,
        roles = setOf(AdminRole.AUDITOR)
    )

    private val superAdminPrincipal = AuthenticatedPrincipal(
        id = "superadmin-03",
        tenantId = "tenant-payout-prod",
        kind = PrincipalKind.ADMIN,
        roles = setOf(AdminRole.SUPER_ADMIN, AdminRole.AUDITOR)
    )

    private val foreignAdminPrincipal = AuthenticatedPrincipal(
        id = "foreign-admin-99",
        tenantId = "tenant-foreign-payout",
        kind = PrincipalKind.ADMIN,
        roles = setOf(AdminRole.SUPER_ADMIN)
    )

    private lateinit var approvalStore: InMemoryPayoutApprovalStore
    private lateinit var reservationStore: InMemoryWithdrawalReservationStore
    private lateinit var bucketStore: InMemoryBalanceBucketsStore
    private lateinit var observability: InMemoryPayoutApprovalObservability
    private lateinit var service: MakerCheckerPayoutApprovalService

    @BeforeEach
    fun setUp() {
        MakerCheckerPayoutApprovalBinding.isBound = true
        approvalStore = InMemoryPayoutApprovalStore()
        reservationStore = InMemoryWithdrawalReservationStore()
        bucketStore = InMemoryBalanceBucketsStore()
        observability = InMemoryPayoutApprovalObservability()
        service = MakerCheckerPayoutApprovalService(
            approvalStore = approvalStore,
            reservationStore = reservationStore,
            bucketStore = bucketStore,
            observability = observability,
            clock = clock
        )
    }

    @AfterEach
    fun tearDown() {
        MakerCheckerPayoutApprovalBinding.isBound = true
    }

    private fun setupPlayerWallet(ownerId: UUID, availableMinorUnits: Long, pendingMinorUnits: Long = 0L): WalletBalanceBucketsRecord {
        val wallet = WalletBalanceBucketsRecord(
            walletId = UUID.randomUUID(),
            tenantId = "tenant-payout-prod",
            ownerId = ownerId,
            currencyCode = "USD",
            cash = CashBuckets(
                availableMinorUnits = availableMinorUnits,
                lockedMinorUnits = 0L,
                pendingWithdrawalMinorUnits = pendingMinorUnits
            ),
            bonus = BonusBuckets(activeMinorUnits = 0L, lockedMinorUnits = 0L, pendingMinorUnits = 0L),
            version = 1L,
            createdAt = now.minusSeconds(3600),
            updatedAt = now
        )
        bucketStore.saveWallet(wallet)
        return wallet
    }

    private fun createReservation(
        ownerId: UUID,
        amountMinorUnits: Long,
        state: WithdrawalReservationState = WithdrawalReservationState.RESERVED
    ): WithdrawalReservationRecord {
        val reservation = WithdrawalReservationRecord(
            reservationId = UUID.randomUUID(),
            tenantId = "tenant-payout-prod",
            ownerId = ownerId,
            walletId = UUID.randomUUID(),
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

    // =========================================================================
    // WITHDRAW-002-03-T001 — Produces required authoritative outcome
    // =========================================================================
    @Test
    fun `WITHDRAW-002-03-T001 Apply maker-checker payout approval produces the required authoritative outcome`() {
        // Precondition: Wallet has 50000 minor units locked in pending withdrawal
        setupPlayerWallet(playerAId, availableMinorUnits = 100000L, pendingMinorUnits = 50000L)
        val reservation = createReservation(playerAId, amountMinorUnits = 50000L, state = WithdrawalReservationState.RESERVED)

        // 1. Maker proposes payout approval
        val proposeCmd = ProposePayoutApprovalCommand(
            principal = makerOperatorPrincipal,
            tenantId = "tenant-payout-prod",
            ownerId = playerAId,
            reservationId = reservation.reservationId,
            makerNotes = "Player KYC verified, withdrawal within daily limit",
            idempotencyKey = "prop-idemp-001",
            correlationId = "corr-prop-001",
            causationId = "caus-prop-001"
        )
        val proposeResult = service.proposePayout(proposeCmd)

        assertEquals(PayoutApprovalStatus.PENDING_REVIEW, proposeResult.approval.status)
        assertEquals(makerOperatorPrincipal.id, proposeResult.approval.makerPrincipal.id)
        assertEquals(reservation.reservationId, proposeResult.approval.reservationId)
        assertEquals(WithdrawalReservationState.RESERVED, proposeResult.reservationState)
        assertTrue(proposeResult.debitsEqualCredits)
        assertFalse(proposeResult.hasAndroidDbImpact)
        assertFalse(proposeResult.hasAndroidLifecycleClaim)
        assertEquals("PAYOUT_APPROVAL_PROPOSED", proposeResult.auditEvent.type)

        // 2. Checker approves payout
        val approveCmd = ReviewPayoutApprovalCommand(
            principal = checkerAuditorPrincipal,
            tenantId = "tenant-payout-prod",
            approvalId = proposeResult.approval.approvalId,
            action = PayoutDecisionAction.APPROVE,
            checkerNotes = "Confirmed destination verified and risk score low. Approved.",
            idempotencyKey = "rev-idemp-001",
            correlationId = "corr-rev-001",
            causationId = "caus-rev-001"
        )
        val approveResult = service.reviewPayout(approveCmd)

        assertEquals(PayoutApprovalStatus.APPROVED, approveResult.approval.status)
        assertEquals(checkerAuditorPrincipal.id, approveResult.approval.checkerPrincipal?.id)
        assertEquals(WithdrawalReservationState.RESERVED, approveResult.reservationState)
        // Funds remain locked in pendingWithdrawal awaiting provider dispatch
        assertEquals(50000L, approveResult.walletBalance.cash.pendingWithdrawalMinorUnits)
        assertEquals(100000L, approveResult.walletBalance.cash.availableMinorUnits)
        assertTrue(approveResult.debitsEqualCredits)
        assertEquals("PAYOUT_APPROVED_BY_CHECKER", approveResult.auditEvent.type)
        assertEquals("payout.approved", approveResult.outboxEvent.type)

        // 3. Test Rejection flow on a second reservation with explicit release policy
        val res2 = createReservation(playerAId, amountMinorUnits = 30000L, state = WithdrawalReservationState.RESERVED)
        setupPlayerWallet(playerAId, availableMinorUnits = 100000L, pendingMinorUnits = 30000L)

        val prop2Cmd = ProposePayoutApprovalCommand(
            principal = makerOperatorPrincipal,
            tenantId = "tenant-payout-prod",
            ownerId = playerAId,
            reservationId = res2.reservationId,
            makerNotes = "Proposing review for res2",
            idempotencyKey = "prop-idemp-002",
            correlationId = "corr-prop-002",
            causationId = "caus-prop-002"
        )
        val prop2Result = service.proposePayout(prop2Cmd)

        val rejectCmd = ReviewPayoutApprovalCommand(
            principal = checkerAuditorPrincipal,
            tenantId = "tenant-payout-prod",
            approvalId = prop2Result.approval.approvalId,
            action = PayoutDecisionAction.REJECT,
            checkerNotes = "Suspected fraud ring; rejecting payout and releasing funds",
            idempotencyKey = "rev-idemp-002",
            correlationId = "corr-rev-002",
            causationId = "caus-rev-002"
        )
        val rejectResult = service.reviewPayout(rejectCmd)

        assertEquals(PayoutApprovalStatus.REJECTED, rejectResult.approval.status)
        assertEquals(WithdrawalReservationState.RELEASED, rejectResult.reservationState)
        // Explicit release: pendingWithdrawal decremented to 0, available incremented from 100000 to 130000
        assertEquals(0L, rejectResult.walletBalance.cash.pendingWithdrawalMinorUnits)
        assertEquals(130000L, rejectResult.walletBalance.cash.availableMinorUnits)
        assertTrue(rejectResult.debitsEqualCredits)
        assertEquals("PAYOUT_REJECTED_BY_CHECKER_FUNDS_RELEASED", rejectResult.auditEvent.type)
        assertEquals("payout.rejected", rejectResult.outboxEvent.type)

        // Verify persisted reservation record reflects MAKER_CHECKER_REJECTED release reason
        val persistedRes = reservationStore.findById(res2.reservationId)
        assertNotNull(persistedRes)
        assertEquals(WithdrawalReservationState.RELEASED, persistedRes.state)
        assertEquals(WithdrawalReleaseReason.MAKER_CHECKER_REJECTED, persistedRes.releaseReason)
    }

    // =========================================================================
    // WITHDRAW-002-03-T002 — Rejects invalid, boundary, unauthorized, stale input
    // =========================================================================
    @Test
    fun `WITHDRAW-002-03-T002 Apply maker-checker payout approval rejects invalid, boundary, unauthorized, and stale input`() {
        setupPlayerWallet(playerAId, availableMinorUnits = 50000L, pendingMinorUnits = 20000L)
        val reservation = createReservation(playerAId, amountMinorUnits = 20000L, state = WithdrawalReservationState.RESERVED)

        // 1. Propose payout successfully
        val proposeCmd = ProposePayoutApprovalCommand(
            principal = makerOperatorPrincipal,
            tenantId = "tenant-payout-prod",
            ownerId = playerAId,
            reservationId = reservation.reservationId,
            makerNotes = "Standard payout review",
            idempotencyKey = "prop-t002-001",
            correlationId = "corr-t002-001",
            causationId = "caus-t002-001"
        )
        val propResult = service.proposePayout(proposeCmd)

        // 2. FOUR-EYES VIOLATION: Maker attempts to self-approve as Checker
        val selfApproveCmd = ReviewPayoutApprovalCommand(
            principal = makerOperatorPrincipal, // Same principal as Maker!
            tenantId = "tenant-payout-prod",
            approvalId = propResult.approval.approvalId,
            action = PayoutDecisionAction.APPROVE,
            checkerNotes = "Trying to self-approve",
            idempotencyKey = "rev-t002-self",
            correlationId = "corr-t002-self",
            causationId = "caus-t002-self"
        )
        assertFailsWith<MakerSelfApprovalForbiddenException> {
            service.reviewPayout(selfApproveCmd)
        }
        // Verify violation was recorded in observability
        assertTrue(observability.getMetrics().any { it.eventType == "violation" })

        // 3. Player unauthorized to propose or review
        assertFailsWith<UnauthorizedApprovalAccessException> {
            service.proposePayout(proposeCmd.copy(principal = playerAPrincipal, idempotencyKey = "prop-t002-player"))
        }
        assertFailsWith<UnauthorizedApprovalAccessException> {
            service.reviewPayout(
                ReviewPayoutApprovalCommand(
                    principal = playerAPrincipal,
                    tenantId = "tenant-payout-prod",
                    approvalId = propResult.approval.approvalId,
                    action = PayoutDecisionAction.APPROVE,
                    checkerNotes = "Player self-approval attempt",
                    idempotencyKey = "rev-t002-player",
                    correlationId = "corr-player",
                    causationId = "caus-player"
                )
            )
        }

        // 4. Unauthenticated (null principal)
        assertFailsWith<UnauthorizedApprovalAccessException> {
            service.proposePayout(proposeCmd.copy(principal = null, idempotencyKey = "prop-null"))
        }

        // 5. Cross-tenant isolation (IDOR)
        assertFailsWith<UnauthorizedApprovalAccessException> {
            service.reviewPayout(
                ReviewPayoutApprovalCommand(
                    principal = foreignAdminPrincipal,
                    tenantId = "tenant-payout-prod",
                    approvalId = propResult.approval.approvalId,
                    action = PayoutDecisionAction.APPROVE,
                    checkerNotes = "Cross tenant approval",
                    idempotencyKey = "rev-foreign",
                    correlationId = "corr-foreign",
                    causationId = "caus-foreign"
                )
            )
        }

        // 6. Reservation in ON_HOLD state (AML hold active) cannot be proposed
        val onHoldRes = createReservation(playerAId, amountMinorUnits = 10000L, state = WithdrawalReservationState.ON_HOLD)
        assertFailsWith<InvalidReservationStateException> {
            service.proposePayout(
                ProposePayoutApprovalCommand(
                    principal = makerOperatorPrincipal,
                    tenantId = "tenant-payout-prod",
                    ownerId = playerAId,
                    reservationId = onHoldRes.reservationId,
                    makerNotes = "Attempting to propose while on AML hold",
                    idempotencyKey = "prop-on-hold",
                    correlationId = "corr-hold",
                    causationId = "caus-hold"
                )
            )
        }

        // 7. Blank notes rejected
        assertFailsWith<IllegalArgumentException> {
            service.proposePayout(proposeCmd.copy(makerNotes = "  ", idempotencyKey = "prop-blank"))
        }
        assertFailsWith<IllegalArgumentException> {
            service.reviewPayout(
                ReviewPayoutApprovalCommand(
                    principal = checkerAuditorPrincipal,
                    tenantId = "tenant-payout-prod",
                    approvalId = propResult.approval.approvalId,
                    action = PayoutDecisionAction.APPROVE,
                    checkerNotes = "",
                    idempotencyKey = "rev-blank",
                    correlationId = "corr-blank",
                    causationId = "caus-blank"
                )
            )
        }
    }

    // =========================================================================
    // WITHDRAW-002-03-T003 — Survives concurrency, duplicates, dependency failure
    // =========================================================================
    @Test
    fun `WITHDRAW-002-03-T003 Apply maker-checker payout approval survives concurrency, duplicate delivery, and dependency failure`() {
        setupPlayerWallet(playerAId, availableMinorUnits = 100000L, pendingMinorUnits = 40000L)
        val reservation = createReservation(playerAId, amountMinorUnits = 40000L, state = WithdrawalReservationState.RESERVED)

        // 1. Idempotency: Propose duplicate delivery returns exact original result
        val cmd = ProposePayoutApprovalCommand(
            principal = makerOperatorPrincipal,
            tenantId = "tenant-payout-prod",
            ownerId = playerAId,
            reservationId = reservation.reservationId,
            makerNotes = "First submission",
            idempotencyKey = "idemp-t003-prop",
            correlationId = "corr-t003",
            causationId = "caus-t003"
        )
        val res1 = service.proposePayout(cmd)
        val res2 = service.proposePayout(cmd)
        assertEquals(res1.approval.approvalId, res2.approval.approvalId)
        assertEquals(res1.resultId, res2.resultId)

        // Changed payload with same idempotency key fails with conflict
        assertFailsWith<PayoutApprovalConflictException> {
            service.proposePayout(cmd.copy(makerNotes = "Different notes on re-delivery"))
        }

        // 2. Concurrency: 10 threads race to review the proposal
        val threadCount = 10
        val executor = Executors.newFixedThreadPool(threadCount)
        val checkers = (1..threadCount).map { i ->
            AuthenticatedPrincipal(
                id = "checker-$i",
                tenantId = "tenant-payout-prod",
                kind = PrincipalKind.ADMIN,
                roles = setOf(AdminRole.AUDITOR)
            )
        }

        val tasks = checkers.mapIndexed { idx, checker ->
            Callable {
                try {
                    service.reviewPayout(
                        ReviewPayoutApprovalCommand(
                            principal = checker,
                            tenantId = "tenant-payout-prod",
                            approvalId = res1.approval.approvalId,
                            action = if (idx % 2 == 0) PayoutDecisionAction.APPROVE else PayoutDecisionAction.REJECT,
                            checkerNotes = "Concurrent review attempt by ${checker.id}",
                            idempotencyKey = "rev-race-$idx",
                            correlationId = "corr-race-$idx",
                            causationId = "caus-race-$idx"
                        )
                    )
                    true
                } catch (e: PayoutApprovalConflictException) {
                    false
                }
            }
        }

        val futures = executor.invokeAll(tasks)
        executor.shutdown()

        val results = futures.map { it.get() }
        val successCount = results.count { it }
        val conflictCount = results.count { !it }

        // Exactly one concurrent review must succeed; others must receive conflict
        assertEquals(1, successCount)
        assertEquals(threadCount - 1, conflictCount)

        // Proposal is in definitive terminal status
        val finalRecord = approvalStore.findById("tenant-payout-prod", res1.approval.approvalId)
        assertNotNull(finalRecord)
        assertTrue(finalRecord.status in setOf(PayoutApprovalStatus.APPROVED, PayoutApprovalStatus.REJECTED))
    }

    // =========================================================================
    // WITHDRAW-002-03-T004 — Compatible, recoverable, observable, lifecycle-safe
    // =========================================================================
    @Test
    fun `WITHDRAW-002-03-T004 Apply maker-checker payout approval remains compatible, recoverable, observable, and lifecycle-safe`() {
        setupPlayerWallet(playerAId, availableMinorUnits = 80000L, pendingMinorUnits = 25000L)
        val reservation = createReservation(playerAId, amountMinorUnits = 25000L, state = WithdrawalReservationState.RESERVED)

        // 1. Propose payout
        val proposeCmd = ProposePayoutApprovalCommand(
            principal = makerOperatorPrincipal,
            tenantId = "tenant-payout-prod",
            ownerId = playerAId,
            reservationId = reservation.reservationId,
            makerNotes = "Lifecycle test proposal",
            idempotencyKey = "prop-life-001",
            correlationId = "corr-life-001",
            causationId = "caus-life-001"
        )
        val propResult = service.proposePayout(proposeCmd)

        // Zero Android claims
        assertFalse(propResult.hasAndroidDbImpact)
        assertFalse(propResult.hasAndroidLifecycleClaim)

        // 2. Cancellation by Maker triggers explicit release of locked funds
        val cancelCmd = CancelPayoutApprovalCommand(
            principal = makerOperatorPrincipal,
            tenantId = "tenant-payout-prod",
            approvalId = propResult.approval.approvalId,
            cancellationReason = "Customer requested withdrawal cancellation before approval",
            idempotencyKey = "cancel-001",
            correlationId = "corr-cancel",
            causationId = "caus-cancel"
        )
        val cancelResult = service.cancelPayoutProposal(cancelCmd)

        assertEquals(PayoutApprovalStatus.CANCELLED, cancelResult.approval.status)
        assertEquals(WithdrawalReservationState.RELEASED, cancelResult.reservationState)
        // Funds restored to available balance
        assertEquals(0L, cancelResult.walletBalance.cash.pendingWithdrawalMinorUnits)
        assertEquals(105000L, cancelResult.walletBalance.cash.availableMinorUnits)
        assertTrue(cancelResult.debitsEqualCredits)
        assertEquals("PAYOUT_CANCELLED_BY_OPERATOR_FUNDS_RELEASED", cancelResult.auditEvent.type)
        assertEquals("payout.cancelled", cancelResult.outboxEvent.type)

        // Duplicate cancellation returns identical cached result
        val dupCancelResult = service.cancelPayoutProposal(cancelCmd)
        assertEquals(cancelResult.resultId, dupCancelResult.resultId)

        // Cannot review cancelled proposal
        assertFailsWith<PayoutApprovalConflictException> {
            service.reviewPayout(
                ReviewPayoutApprovalCommand(
                    principal = checkerAuditorPrincipal,
                    tenantId = "tenant-payout-prod",
                    approvalId = propResult.approval.approvalId,
                    action = PayoutDecisionAction.APPROVE,
                    checkerNotes = "Cannot approve cancelled",
                    idempotencyKey = "rev-cancelled",
                    correlationId = "corr-rev-can",
                    causationId = "caus-rev-can"
                )
            )
        }

        // 3. Expiry handling: proposal past TTL cannot be approved
        val resExp = createReservation(playerAId, amountMinorUnits = 10000L, state = WithdrawalReservationState.RESERVED)
        setupPlayerWallet(playerAId, availableMinorUnits = 50000L, pendingMinorUnits = 10000L)

        val expPropCmd = ProposePayoutApprovalCommand(
            principal = makerOperatorPrincipal,
            tenantId = "tenant-payout-prod",
            ownerId = playerAId,
            reservationId = resExp.reservationId,
            makerNotes = "Short TTL proposal",
            ttlSeconds = 10L, // 10 seconds TTL
            idempotencyKey = "prop-exp-001",
            correlationId = "corr-exp",
            causationId = "caus-exp"
        )
        val expPropResult = service.proposePayout(expPropCmd)

        // Service with clock advanced past TTL (20 seconds later)
        val futureClock = Clock.fixed(now.plusSeconds(20), ZoneOffset.UTC)
        val futureService = MakerCheckerPayoutApprovalService(
            approvalStore = approvalStore,
            reservationStore = reservationStore,
            bucketStore = bucketStore,
            observability = observability,
            clock = futureClock
        )

        assertFailsWith<PayoutApprovalConflictException> {
            futureService.reviewPayout(
                ReviewPayoutApprovalCommand(
                    principal = checkerAuditorPrincipal,
                    tenantId = "tenant-payout-prod",
                    approvalId = expPropResult.approval.approvalId,
                    action = PayoutDecisionAction.APPROVE,
                    checkerNotes = "Attempting to approve expired proposal",
                    idempotencyKey = "rev-expired",
                    correlationId = "corr-rev-exp",
                    causationId = "caus-rev-exp"
                )
            )
        }

        val expiredRecord = approvalStore.findById("tenant-payout-prod", expPropResult.approval.approvalId)
        assertNotNull(expiredRecord)
        assertEquals(PayoutApprovalStatus.EXPIRED, expiredRecord.status)

        // 4. Observability verification
        val metrics = observability.getMetrics()
        assertTrue(metrics.any { it.eventType == "accept" })
        assertTrue(metrics.any { it.eventType == "duplicate" })
    }
}
