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

class WithdrawalReservationTest {
    private val now = Instant.parse("2026-09-20T20:00:00Z")
    private val clock = Clock.fixed(now, ZoneOffset.UTC)

    private val playerAId = UUID.randomUUID()
    private val playerBId = UUID.randomUUID()

    private val playerAPrincipal = AuthenticatedPrincipal(
        id = playerAId.toString(),
        tenantId = "tenant-res-prod",
        kind = PrincipalKind.PLAYER,
        roles = emptySet()
    )

    private val playerBPrincipal = AuthenticatedPrincipal(
        id = playerBId.toString(),
        tenantId = "tenant-res-prod",
        kind = PrincipalKind.PLAYER,
        roles = emptySet()
    )

    private val adminPrincipal = AuthenticatedPrincipal(
        id = "admin-res-user",
        tenantId = "tenant-res-prod",
        kind = PrincipalKind.ADMIN,
        roles = setOf(AdminRole.SUPER_ADMIN, AdminRole.AUDITOR)
    )

    private val foreignTenantPrincipal = AuthenticatedPrincipal(
        id = "admin-foreign-res",
        tenantId = "tenant-foreign-res",
        kind = PrincipalKind.ADMIN,
        roles = setOf(AdminRole.SUPER_ADMIN)
    )

    private lateinit var reservationStore: InMemoryWithdrawalReservationStore
    private lateinit var requestStore: InMemoryWithdrawalRequestStore
    private lateinit var bucketStore: InMemoryBalanceBucketsStore
    private lateinit var observability: InMemoryWithdrawalReservationObservability
    private lateinit var service: WithdrawalReservationService

    @BeforeEach
    fun setUp() {
        WithdrawalReservationBinding.isBound = true
        reservationStore = InMemoryWithdrawalReservationStore()
        requestStore = InMemoryWithdrawalRequestStore()
        bucketStore = InMemoryBalanceBucketsStore()
        observability = InMemoryWithdrawalReservationObservability()
        service = WithdrawalReservationService(
            reservationStore = reservationStore,
            requestStore = requestStore,
            bucketStore = bucketStore,
            clock = clock,
            observability = observability
        )
    }

    @AfterEach
    fun tearDown() {
        WithdrawalReservationBinding.isBound = true
    }

    private fun setupWallet(ownerId: UUID, cashAvailable: Long = 500_000L): WalletBalanceBucketsRecord {
        val wallet = WalletBalanceBucketsRecord(
            walletId = UUID.randomUUID(),
            tenantId = "tenant-res-prod",
            ownerId = ownerId,
            currencyCode = "EUR",
            cash = CashBuckets(availableMinorUnits = cashAvailable, lockedMinorUnits = 0L, pendingWithdrawalMinorUnits = 0L),
            bonus = BonusBuckets(activeMinorUnits = 0L, lockedMinorUnits = 0L, pendingMinorUnits = 0L),
            version = 1L,
            createdAt = now.minusSeconds(3600),
            updatedAt = now
        )
        bucketStore.saveWallet(wallet)
        return wallet
    }

    private fun setupWithdrawalRequest(
        ownerId: UUID,
        grossAmount: Long = 100_000L,
        status: WithdrawalRequestStatus = WithdrawalRequestStatus.REQUESTED
    ): WithdrawalRequestRecord {
        val requestId = UUID.randomUUID()
        val request = WithdrawalRequestRecord(
            requestId = requestId,
            tenantId = "tenant-res-prod",
            ownerId = ownerId,
            quoteId = UUID.randomUUID(),
            currencyCode = "EUR",
            grossAmountMinorUnits = grossAmount,
            feeMinorUnits = 150L,
            netPayoutAmountMinorUnits = grossAmount - 150L,
            paymentMethod = WithdrawalPaymentMethod.SEPA_INSTANT,
            destinationId = UUID.randomUUID(),
            destinationReference = "DE89370400440532013000",
            stepUpAuthenticated = false,
            stepUpEvidenceReference = null,
            status = status,
            requestedAt = now.minusSeconds(60),
            idempotencyKey = "req-idemp-${UUID.randomUUID()}",
            correlationId = "corr-req",
            causationId = "caus-req",
            evidenceReference = "EVID-REQ-TEST",
            version = 1L
        )
        requestStore.save(request)
        return request
    }

    // =========================================================================
    // WITHDRAW-002-01-T001: Authoritative Outcome Verification
    // =========================================================================

    @Test
    fun `WITHDRAW-002-01-T001 Reserve withdrawal funds produces the required authoritative outcome`() {
        WithdrawalReservationBinding.checkBound()

        // 1. Semantic contract assertion
        assertEquals(
            "One request locks exact funds; rejection/cancel release policy explicit/audited.",
            WITHDRAWAL_RESERVATION_CONTRACT
        )

        val wallet = setupWallet(playerAId, cashAvailable = 500_000L)
        val request = setupWithdrawalRequest(playerAId, grossAmount = 100_000L)

        // 2. Exact fund locking
        val reserveCmd = ReserveWithdrawalFundsCommand(
            principal = playerAPrincipal,
            tenantId = "tenant-res-prod",
            ownerId = playerAId,
            requestId = request.requestId,
            ttlSeconds = 86400L,
            idempotencyKey = "idemp-res-001",
            correlationId = "corr-res-001",
            causationId = "caus-res-001"
        )
        val reserveResult = service.reserveFunds(reserveCmd)

        val res = reserveResult.reservation
        assertNotNull(res.reservationId)
        assertEquals(request.requestId, res.requestId)
        assertEquals(playerAId, res.ownerId)
        assertEquals("tenant-res-prod", res.tenantId)
        assertEquals(100_000L, res.grossAmountMinorUnits)
        assertEquals(WithdrawalReservationState.RESERVED, res.state)
        assertNull(res.releaseReason)
        assertEquals(now, res.reservedAt)
        assertEquals(now.plusSeconds(86400L), res.expiresAt)
        assertNull(res.releasedAt)

        // Assert balance bucket exact lock
        val updatedWallet = reserveResult.walletBalance
        assertEquals(400_000L, updatedWallet.cash.availableMinorUnits)
        assertEquals(100_000L, updatedWallet.cash.pendingWithdrawalMinorUnits)
        assertEquals(500_000L, updatedWallet.cash.totalCashMinorUnits) // Total cash conserved!
        assertTrue(reserveResult.debitsEqualCredits)
        assertEquals(2L, updatedWallet.version)
        assertFalse(reserveResult.hasAndroidDbImpact)
        assertFalse(reserveResult.hasAndroidLifecycleClaim)
        assertEquals("WITHDRAWAL_FUNDS_RESERVED", reserveResult.auditEvent.type)
        assertEquals("corr-res-001", reserveResult.auditEvent.correlationId)

        // 3. Explicit release policy: Player cancellation
        val releaseCmd = ReleaseWithdrawalFundsCommand(
            principal = playerAPrincipal,
            tenantId = "tenant-res-prod",
            ownerId = playerAId,
            reservationId = res.reservationId,
            reason = WithdrawalReleaseReason.PLAYER_CANCELLED,
            idempotencyKey = "idemp-rel-001",
            correlationId = "corr-rel-001",
            causationId = "caus-rel-001"
        )
        val releaseResult = service.releaseFunds(releaseCmd)

        val releasedRes = releaseResult.reservation
        assertEquals(WithdrawalReservationState.RELEASED, releasedRes.state)
        assertEquals(WithdrawalReleaseReason.PLAYER_CANCELLED, releasedRes.releaseReason)
        assertEquals(now, releasedRes.releasedAt)
        assertEquals(2L, releasedRes.version)

        // Assert balance bucket exact unlock
        val restoredWallet = releaseResult.walletBalance
        assertEquals(500_000L, restoredWallet.cash.availableMinorUnits)
        assertEquals(0L, restoredWallet.cash.pendingWithdrawalMinorUnits)
        assertEquals(500_000L, restoredWallet.cash.totalCashMinorUnits) // Conserved!
        assertEquals("WITHDRAWAL_FUNDS_RELEASED", releaseResult.auditEvent.type)
    }

    // =========================================================================
    // WITHDRAW-002-01-T002: Rejection of Invalid, Boundary, Unauthorized, and Stale Input
    // =========================================================================

    @Test
    fun `WITHDRAW-002-01-T002 Reserve withdrawal funds rejects invalid, boundary, unauthorized, and stale input`() {
        WithdrawalReservationBinding.checkBound()

        setupWallet(playerAId, cashAvailable = 100_000L)
        val request = setupWithdrawalRequest(playerAId, grossAmount = 100_000L)

        // 1. Unauthenticated request
        assertFailsWith<UnauthorizedWithdrawalAccessException> {
            service.reserveFunds(
                ReserveWithdrawalFundsCommand(
                    principal = null,
                    tenantId = "tenant-res-prod",
                    ownerId = playerAId,
                    requestId = request.requestId,
                    idempotencyKey = "k1",
                    correlationId = "c1",
                    causationId = "c2"
                )
            )
        }

        // 2. Cross-tenant request
        assertFailsWith<CrossTenantWithdrawalAccessException> {
            service.reserveFunds(
                ReserveWithdrawalFundsCommand(
                    principal = foreignTenantPrincipal,
                    tenantId = "tenant-res-prod",
                    ownerId = playerAId,
                    requestId = request.requestId,
                    idempotencyKey = "k2",
                    correlationId = "c1",
                    causationId = "c2"
                )
            )
        }

        // 3. IDOR / Cross-owner request: Player B tries to reserve Player A's funds
        val idorEx = assertFailsWith<IdorWithdrawalForbiddenException> {
            service.reserveFunds(
                ReserveWithdrawalFundsCommand(
                    principal = playerBPrincipal,
                    tenantId = "tenant-res-prod",
                    ownerId = playerAId, // Player B targeting Player A!
                    requestId = request.requestId,
                    idempotencyKey = "k3",
                    correlationId = "c1",
                    causationId = "c2"
                )
            )
        }
        assertTrue(idorEx.message!!.contains("payout without lock/approval"))

        // 4. Non-existent withdrawal request
        val notFoundEx = assertFailsWith<WithdrawalRequestNotFoundException> {
            service.reserveFunds(
                ReserveWithdrawalFundsCommand(
                    principal = playerAPrincipal,
                    tenantId = "tenant-res-prod",
                    ownerId = playerAId,
                    requestId = UUID.randomUUID(), // non-existent!
                    idempotencyKey = "k4",
                    correlationId = "c1",
                    causationId = "c2"
                )
            )
        }
        assertTrue(notFoundEx.message!!.contains("payout without lock/approval"))

        // 5. Withdrawal request in invalid state (e.g. CANCELLED)
        val cancelledRequest = setupWithdrawalRequest(playerAId, grossAmount = 50_000L, status = WithdrawalRequestStatus.CANCELLED)
        val invalidStateEx = assertFailsWith<WithdrawalRequestInvalidStateException> {
            service.reserveFunds(
                ReserveWithdrawalFundsCommand(
                    principal = playerAPrincipal,
                    tenantId = "tenant-res-prod",
                    ownerId = playerAId,
                    requestId = cancelledRequest.requestId,
                    idempotencyKey = "k5",
                    correlationId = "c1",
                    causationId = "c2"
                )
            )
        }
        assertTrue(invalidStateEx.message!!.contains("payout without lock/approval"))

        // 6. Insufficient funds (wallet has 100_000, request needs 200_000)
        val hugeRequest = setupWithdrawalRequest(playerAId, grossAmount = 200_000L)
        val fundsEx = assertFailsWith<InsufficientWithdrawableFundsException> {
            service.reserveFunds(
                ReserveWithdrawalFundsCommand(
                    principal = playerAPrincipal,
                    tenantId = "tenant-res-prod",
                    ownerId = playerAId,
                    requestId = hugeRequest.requestId,
                    idempotencyKey = "k6",
                    correlationId = "c1",
                    causationId = "c2"
                )
            )
        }
        assertTrue(fundsEx.message!!.contains("payout without lock/approval"))

        // 7. Successful reservation followed by duplicate reservation attempt
        val res = service.reserveFunds(
            ReserveWithdrawalFundsCommand(
                principal = playerAPrincipal,
                tenantId = "tenant-res-prod",
                ownerId = playerAId,
                requestId = request.requestId,
                idempotencyKey = "k7-first",
                correlationId = "c1",
                causationId = "c2"
            )
        )
        val alreadyReservedEx = assertFailsWith<AlreadyReservedException> {
            service.reserveFunds(
                ReserveWithdrawalFundsCommand(
                    principal = playerAPrincipal,
                    tenantId = "tenant-res-prod",
                    ownerId = playerAId,
                    requestId = request.requestId,
                    idempotencyKey = "k7-second", // different idempotency key!
                    correlationId = "c1",
                    causationId = "c2"
                )
            )
        }
        assertTrue(alreadyReservedEx.message!!.contains("payout without lock/approval"))

        // 8. Player trying to release with operator reason (AML_REJECTED) -> Forbidden
        val operatorReasonEx = assertFailsWith<IdorWithdrawalForbiddenException> {
            service.releaseFunds(
                ReleaseWithdrawalFundsCommand(
                    principal = playerAPrincipal,
                    tenantId = "tenant-res-prod",
                    ownerId = playerAId,
                    reservationId = res.reservation.reservationId,
                    reason = WithdrawalReleaseReason.AML_REJECTED, // Player cannot declare AML reject!
                    idempotencyKey = "k8",
                    correlationId = "c1",
                    causationId = "c2"
                )
            )
        }
        assertTrue(operatorReasonEx.message!!.contains("payout without lock/approval"))

        // 9. Release reservation once, then attempting to release again
        service.releaseFunds(
            ReleaseWithdrawalFundsCommand(
                principal = playerAPrincipal,
                tenantId = "tenant-res-prod",
                ownerId = playerAId,
                reservationId = res.reservation.reservationId,
                reason = WithdrawalReleaseReason.PLAYER_CANCELLED,
                idempotencyKey = "k9-release",
                correlationId = "c1",
                causationId = "c2"
            )
        )
        val conflictEx = assertFailsWith<WithdrawalReservationConflictException> {
            service.releaseFunds(
                ReleaseWithdrawalFundsCommand(
                    principal = playerAPrincipal,
                    tenantId = "tenant-res-prod",
                    ownerId = playerAId,
                    reservationId = res.reservation.reservationId,
                    reason = WithdrawalReleaseReason.PLAYER_CANCELLED,
                    idempotencyKey = "k9-release-again",
                    correlationId = "c1",
                    causationId = "c2"
                )
            )
        }
        assertTrue(conflictEx.message!!.contains("payout without lock/approval"))
    }

    // =========================================================================
    // WITHDRAW-002-01-T003: Concurrency, Duplicate Delivery, and Overdraft Prevention
    // =========================================================================

    @Test
    fun `WITHDRAW-002-01-T003 Reserve withdrawal funds survives concurrency, duplicate delivery, and dependency failure`() {
        WithdrawalReservationBinding.checkBound()

        // 1. Idempotency exact replay
        setupWallet(playerAId, cashAvailable = 300_000L)
        val request = setupWithdrawalRequest(playerAId, grossAmount = 50_000L)

        val cmd = ReserveWithdrawalFundsCommand(
            principal = playerAPrincipal,
            tenantId = "tenant-res-prod",
            ownerId = playerAId,
            requestId = request.requestId,
            idempotencyKey = "idemp-replay-001",
            correlationId = "c1",
            causationId = "c2"
        )
        val firstResult = service.reserveFunds(cmd)
        val duplicateResult = service.reserveFunds(cmd)

        assertEquals(firstResult.reservation.reservationId, duplicateResult.reservation.reservationId)
        assertEquals(firstResult.resultId, duplicateResult.resultId)
        assertEquals(firstResult.serverTime, duplicateResult.serverTime)
        // Wallet should only have been deducted ONCE (300_000 - 50_000 = 250_000)
        assertEquals(250_000L, duplicateResult.walletBalance.cash.availableMinorUnits)

        // 2. Idempotency conflict with modified payload
        val conflictingCmd = cmd.copy(ttlSeconds = 9999L)
        val conflictEx = assertFailsWith<IdempotencyConflictException> {
            service.reserveFunds(conflictingCmd)
        }
        assertTrue(conflictEx.message!!.contains("payout without lock/approval"))

        // 3. Multi-threaded race condition / overdraft prevention
        // Wallet has 120_000 available cash. Two concurrent requests for 80_000 each.
        // Exactly one MUST succeed, and the other MUST fail with InsufficientWithdrawableFundsException.
        setupWallet(playerBId, cashAvailable = 120_000L)
        val req1 = setupWithdrawalRequest(playerBId, grossAmount = 80_000L)
        val req2 = setupWithdrawalRequest(playerBId, grossAmount = 80_000L)

        val executor = Executors.newFixedThreadPool(2)
        val task1 = Callable {
            runCatching {
                service.reserveFunds(
                    ReserveWithdrawalFundsCommand(
                        principal = playerBPrincipal,
                        tenantId = "tenant-res-prod",
                        ownerId = playerBId,
                        requestId = req1.requestId,
                        idempotencyKey = "race-1",
                        correlationId = "c1",
                        causationId = "c2"
                    )
                )
            }
        }
        val task2 = Callable {
            runCatching {
                service.reserveFunds(
                    ReserveWithdrawalFundsCommand(
                        principal = playerBPrincipal,
                        tenantId = "tenant-res-prod",
                        ownerId = playerBId,
                        requestId = req2.requestId,
                        idempotencyKey = "race-2",
                        correlationId = "c1",
                        causationId = "c2"
                    )
                )
            }
        }

        val outcomes = executor.invokeAll(listOf(task1, task2)).map { it.get() }
        executor.shutdown()

        val successes = outcomes.filter { it.isSuccess }
        val failures = outcomes.filter { it.isFailure }

        assertEquals(1, successes.size, "Exactly one withdrawal reservation must succeed")
        assertEquals(1, failures.size, "The competing reservation must fail due to overdraft protection")
        assertTrue(failures[0].exceptionOrNull() is InsufficientWithdrawableFundsException)

        // Verify final wallet balance: 120_000 - 80_000 = 40_000 available, 80_000 pending withdrawal
        val finalWallet = bucketStore.findWalletByOwnerAndCurrency("tenant-res-prod", playerBId, "EUR")!!
        assertEquals(40_000L, finalWallet.cash.availableMinorUnits)
        assertEquals(80_000L, finalWallet.cash.pendingWithdrawalMinorUnits)
        assertEquals(120_000L, finalWallet.cash.totalCashMinorUnits)
    }

    // =========================================================================
    // WITHDRAW-002-01-T004: Compatibility, Recovery, Observability, and Lifecycle
    // =========================================================================

    @Test
    fun `WITHDRAW-002-01-T004 Reserve withdrawal funds remains compatible, recoverable, observable, and lifecycle-safe`() {
        WithdrawalReservationBinding.checkBound()

        setupWallet(playerAId, cashAvailable = 500_000L)
        val request = setupWithdrawalRequest(playerAId, grossAmount = 75_000L)

        // 1. Observability events emitted
        val cmd = ReserveWithdrawalFundsCommand(
            principal = playerAPrincipal,
            tenantId = "tenant-res-prod",
            ownerId = playerAId,
            requestId = request.requestId,
            idempotencyKey = "idemp-obs-res-001",
            correlationId = "corr-obs-001",
            causationId = "caus-obs-001"
        )
        val result = service.reserveFunds(cmd)

        val metrics = observability.getMetrics()
        assertTrue(metrics.any { it.eventType == "attempt" && it.correlationId == "corr-obs-001" })
        assertTrue(metrics.any { it.eventType == "accept" && it.correlationId == "corr-obs-001" })

        // 2. Recovery across service restart with same stores
        val recoveredService = WithdrawalReservationService(
            reservationStore = reservationStore,
            requestStore = requestStore,
            bucketStore = bucketStore,
            clock = clock,
            observability = observability
        )
        val queried = recoveredService.getReservation(
            GetWithdrawalReservationQuery(
                principal = playerAPrincipal,
                tenantId = "tenant-res-prod",
                reservationId = result.reservation.reservationId
            )
        )
        assertEquals(result.reservation.reservationId, queried.reservationId)
        assertEquals(WithdrawalReservationState.RESERVED, queried.state)
        assertEquals(75_000L, queried.grossAmountMinorUnits)

        // 3. No Android database impact or lifecycle claims
        assertFalse(result.hasAndroidDbImpact)
        assertFalse(result.hasAndroidLifecycleClaim)
    }
}
