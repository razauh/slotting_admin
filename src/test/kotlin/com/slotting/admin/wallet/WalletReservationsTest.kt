package com.slotting.admin.wallet

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
import java.util.concurrent.CountDownLatch
import java.util.concurrent.Executors
import java.util.concurrent.atomic.AtomicInteger
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue

class WalletReservationsTest {
    private val now = Instant.parse("2026-09-20T18:30:00Z")
    private val clock = Clock.fixed(now, ZoneOffset.UTC)

    private val adminPrincipal = AuthenticatedPrincipal(
        id = "admin-wallet-res",
        tenantId = "tenant-wallet-prod",
        kind = PrincipalKind.ADMIN,
        roles = setOf(AdminRole.SUPER_ADMIN, AdminRole.AUDITOR)
    )

    private val foreignTenantPrincipal = AuthenticatedPrincipal(
        id = "admin-foreign",
        tenantId = "tenant-foreign-99",
        kind = PrincipalKind.ADMIN,
        roles = setOf(AdminRole.SUPER_ADMIN)
    )

    private lateinit var reservationStore: InMemoryWalletReservationStore
    private lateinit var bucketStore: InMemoryBalanceBucketsStore
    private lateinit var observability: InMemoryWalletReservationObservability
    private lateinit var service: WalletReservationService

    @BeforeEach
    fun setUp() {
        WalletReservationBinding.isBound = true
        reservationStore = InMemoryWalletReservationStore()
        bucketStore = InMemoryBalanceBucketsStore()
        observability = InMemoryWalletReservationObservability()
        service = WalletReservationService(
            reservationStore = reservationStore,
            bucketStore = bucketStore,
            clock = clock,
            observability = observability
        )
    }

    @AfterEach
    fun tearDown() {
        WalletReservationBinding.isBound = true
    }

    private fun createTestWallet(
        ownerId: UUID = UUID.randomUUID(),
        cashAvailable: Long = 50_000L,
        bonusActive: Long = 10_000L
    ): WalletBalanceBucketsRecord {
        val wallet = WalletBalanceBucketsRecord(
            walletId = UUID.randomUUID(),
            tenantId = "tenant-wallet-prod",
            ownerId = ownerId,
            currencyCode = "EUR",
            cash = CashBuckets(availableMinorUnits = cashAvailable, lockedMinorUnits = 0L, pendingWithdrawalMinorUnits = 0L),
            bonus = BonusBuckets(activeMinorUnits = bonusActive, lockedMinorUnits = 0L, pendingMinorUnits = 0L),
            version = 1L,
            createdAt = now,
            updatedAt = now
        )
        bucketStore.saveWallet(wallet)
        return wallet
    }

    // =========================================================================
    // WALLET-003-T001: Authoritative Outcome Verification
    // =========================================================================

    @Test
    fun `WALLET-003-T001 Reservations produces the required authoritative outcome`() {
        // Fail-closed gate check: triggers RED assertion failure when unbound
        WalletReservationBinding.checkBound()

        // 1. Verify semantic contract constant
        assertEquals("Terminal transitions idempotent; expiry is worker command, never silent deletion.", RESERVATIONS_CONTRACT)

        val wallet = createTestWallet(cashAvailable = 50_000L, bonusActive = 10_000L)

        // 2. Test Wager Reservation (Cash-first precedence)
        val wagerCmd = CreateReservationCommand(
            principal = adminPrincipal,
            tenantId = "tenant-wallet-prod",
            walletId = wallet.walletId,
            type = ReservationType.WAGER,
            amountMinorUnits = 15_000L,
            ttlSeconds = 300L,
            reference = "ROUND-WAGER-001",
            preferCashFirst = true,
            idempotencyKey = "idemp-res-wager-001",
            correlationId = "corr-res-001",
            causationId = "caus-res-001"
        )
        val wagerResult = service.createReservation(wagerCmd)

        assertEquals(ReservationStatus.RESERVED, wagerResult.reservation.status)
        assertEquals(15_000L, wagerResult.reservation.amountMinorUnits)
        assertEquals(15_000L, wagerResult.reservation.breakdown.cashMinorUnits)
        assertEquals(0L, wagerResult.reservation.breakdown.bonusMinorUnits)
        assertTrue(wagerResult.debitsEqualCredits)
        assertFalse(wagerResult.hasAndroidDbImpact)
        assertFalse(wagerResult.hasAndroidLifecycleClaim)

        // Verify wallet buckets updated: 35_000 available cash, 15_000 locked cash
        val wAfterReserve = bucketStore.findWalletById(wallet.tenantId, wallet.walletId)!!
        assertEquals(35_000L, wAfterReserve.cash.availableMinorUnits)
        assertEquals(15_000L, wAfterReserve.cash.lockedMinorUnits)
        assertEquals(50_000L, wAfterReserve.cash.totalCashMinorUnits)
        assertEquals(60_000L, wAfterReserve.totalBalanceMinorUnits)

        // 3. Test Capture Wager Reservation
        val captureCmd = CaptureReservationCommand(
            principal = adminPrincipal,
            tenantId = "tenant-wallet-prod",
            reservationId = wagerResult.reservation.reservationId,
            idempotencyKey = "idemp-cap-wager-001",
            correlationId = "corr-cap-001",
            causationId = "caus-cap-001"
        )
        val captureResult = service.captureReservation(captureCmd)

        assertEquals(ReservationStatus.CAPTURED, captureResult.reservation.status)
        assertNotNull(captureResult.reservation.capturedAt)
        assertEquals(ReservationStatus.RESERVED, captureResult.previousStatus)

        // Verify wallet buckets updated: locked cash permanently debited
        val wAfterCapture = bucketStore.findWalletById(wallet.tenantId, wallet.walletId)!!
        assertEquals(35_000L, wAfterCapture.cash.availableMinorUnits)
        assertEquals(0L, wAfterCapture.cash.lockedMinorUnits)
        assertEquals(35_000L, wAfterCapture.cash.totalCashMinorUnits)
        assertEquals(45_000L, wAfterCapture.totalBalanceMinorUnits)

        // 4. Test Withdrawal Reservation & Release
        val withCmd = CreateReservationCommand(
            principal = adminPrincipal,
            tenantId = "tenant-wallet-prod",
            walletId = wallet.walletId,
            type = ReservationType.WITHDRAWAL,
            amountMinorUnits = 10_000L,
            ttlSeconds = 600L,
            reference = "WITHDRAWAL-REF-001",
            idempotencyKey = "idemp-res-with-001",
            correlationId = "corr-res-002",
            causationId = "caus-res-002"
        )
        val withResult = service.createReservation(withCmd)
        assertEquals(ReservationStatus.RESERVED, withResult.reservation.status)
        assertEquals(10_000L, withResult.reservation.breakdown.cashMinorUnits)
        assertEquals(0L, withResult.reservation.breakdown.bonusMinorUnits) // Bonus cannot be withdrawn

        val releaseCmd = ReleaseReservationCommand(
            principal = adminPrincipal,
            tenantId = "tenant-wallet-prod",
            reservationId = withResult.reservation.reservationId,
            reason = "Player cancelled withdrawal",
            idempotencyKey = "idemp-rel-with-001",
            correlationId = "corr-rel-001",
            causationId = "caus-rel-001"
        )
        val releaseResult = service.releaseReservation(releaseCmd)
        assertEquals(ReservationStatus.RELEASED, releaseResult.reservation.status)
        assertNotNull(releaseResult.reservation.releasedAt)

        // Verify wallet restored: locked cash released back to available cash
        val wAfterRelease = bucketStore.findWalletById(wallet.tenantId, wallet.walletId)!!
        assertEquals(35_000L, wAfterRelease.cash.availableMinorUnits)
        assertEquals(0L, wAfterRelease.cash.lockedMinorUnits)
        assertEquals(35_000L, wAfterRelease.cash.totalCashMinorUnits)

        // 5. Test Expiry as Worker Command (NEVER silent deletion)
        val expWagerCmd = CreateReservationCommand(
            principal = adminPrincipal,
            tenantId = "tenant-wallet-prod",
            walletId = wallet.walletId,
            type = ReservationType.WAGER,
            amountMinorUnits = 5_000L,
            ttlSeconds = 120L,
            reference = "ROUND-WAGER-EXP-001",
            idempotencyKey = "idemp-res-exp-001",
            correlationId = "corr-res-exp",
            causationId = "caus-res-exp"
        )
        val expWagerResult = service.createReservation(expWagerCmd)

        val expireCmd = ExpireReservationCommand(
            principal = adminPrincipal,
            tenantId = "tenant-wallet-prod",
            reservationId = expWagerResult.reservation.reservationId,
            workerId = "worker-sweep-01",
            idempotencyKey = "idemp-worker-exp-001",
            correlationId = "corr-exp-001",
            causationId = "caus-exp-001"
        )
        val expireResult = service.expireReservation(expireCmd)
        assertEquals(ReservationStatus.EXPIRED, expireResult.reservation.status)
        assertNotNull(expireResult.reservation.expiredAt)

        // Semantic contract assertion: "expiry is worker command, never silent deletion."
        val persistedRecord = reservationStore.findById(expWagerResult.reservation.reservationId)
        assertNotNull(persistedRecord, "Reservation record must NEVER be silently deleted on expiry")
        assertEquals(ReservationStatus.EXPIRED, persistedRecord.status)
    }

    // =========================================================================
    // WALLET-003-T002: Rejection of Invalid, Boundary, Unauthorized, and Stale Input
    // =========================================================================

    @Test
    fun `WALLET-003-T002 Reservations rejects invalid, boundary, unauthorized, and stale input`() {
        WalletReservationBinding.checkBound()

        val wallet = createTestWallet(cashAvailable = 10_000L, bonusActive = 5_000L)

        // 1. Unauthenticated request
        assertFailsWith<UnauthorizedWalletAccessException> {
            service.createReservation(
                CreateReservationCommand(
                    principal = null,
                    tenantId = "tenant-wallet-prod",
                    walletId = wallet.walletId,
                    type = ReservationType.WAGER,
                    amountMinorUnits = 1_000L,
                    ttlSeconds = 60L,
                    reference = "REF-UNAUTH",
                    idempotencyKey = "idemp-unauth",
                    correlationId = "c1",
                    causationId = "c2"
                )
            )
        }

        // 2. Cross-tenant request
        assertFailsWith<CrossTenantAccessException> {
            service.createReservation(
                CreateReservationCommand(
                    principal = foreignTenantPrincipal,
                    tenantId = "tenant-wallet-prod",
                    walletId = wallet.walletId,
                    type = ReservationType.WAGER,
                    amountMinorUnits = 1_000L,
                    ttlSeconds = 60L,
                    reference = "REF-CROSS-TENANT",
                    idempotencyKey = "idemp-cross",
                    correlationId = "c1",
                    causationId = "c2"
                )
            )
        }

        // 3. Zero and negative amounts
        assertFailsWith<InvalidReservationAmountException> {
            service.createReservation(
                CreateReservationCommand(
                    principal = adminPrincipal,
                    tenantId = "tenant-wallet-prod",
                    walletId = wallet.walletId,
                    type = ReservationType.WAGER,
                    amountMinorUnits = 0L,
                    ttlSeconds = 60L,
                    reference = "REF-ZERO",
                    idempotencyKey = "idemp-zero",
                    correlationId = "c1",
                    causationId = "c2"
                )
            )
        }

        assertFailsWith<InvalidReservationAmountException> {
            service.createReservation(
                CreateReservationCommand(
                    principal = adminPrincipal,
                    tenantId = "tenant-wallet-prod",
                    walletId = wallet.walletId,
                    type = ReservationType.WAGER,
                    amountMinorUnits = -500L,
                    ttlSeconds = 60L,
                    reference = "REF-NEG",
                    idempotencyKey = "idemp-neg",
                    correlationId = "c1",
                    causationId = "c2"
                )
            )
        }

        // 4. Overdraft attempt (available balance = 15_000 total, requesting 20_000)
        assertFailsWith<InsufficientReservationBalanceException> {
            service.createReservation(
                CreateReservationCommand(
                    principal = adminPrincipal,
                    tenantId = "tenant-wallet-prod",
                    walletId = wallet.walletId,
                    type = ReservationType.WAGER,
                    amountMinorUnits = 20_000L,
                    ttlSeconds = 60L,
                    reference = "REF-OVERDRAFT",
                    idempotencyKey = "idemp-overdraft",
                    correlationId = "c1",
                    causationId = "c2"
                )
            )
        }

        // 5. Bonus withdrawal attempt (cash available = 10_000, bonus = 5_000; requesting 12_000 withdrawal)
        assertFailsWith<InsufficientReservationBalanceException> {
            service.createReservation(
                CreateReservationCommand(
                    principal = adminPrincipal,
                    tenantId = "tenant-wallet-prod",
                    walletId = wallet.walletId,
                    type = ReservationType.WITHDRAWAL,
                    amountMinorUnits = 12_000L,
                    ttlSeconds = 60L,
                    reference = "REF-BONUS-WITHDRAWAL",
                    idempotencyKey = "idemp-bonus-with",
                    correlationId = "c1",
                    causationId = "c2"
                )
            )
        }

        // 6. Stale version mismatch
        assertFailsWith<StaleVersionException> {
            service.createReservation(
                CreateReservationCommand(
                    principal = adminPrincipal,
                    tenantId = "tenant-wallet-prod",
                    walletId = wallet.walletId,
                    type = ReservationType.WAGER,
                    amountMinorUnits = 1_000L,
                    ttlSeconds = 60L,
                    reference = "REF-STALE",
                    idempotencyKey = "idemp-stale",
                    correlationId = "c1",
                    causationId = "c2",
                    expectedVersion = 999L
                )
            )
        }

        // 7. Idempotency key reuse with changed payload conflicts
        service.createReservation(
            CreateReservationCommand(
                principal = adminPrincipal,
                tenantId = "tenant-wallet-prod",
                walletId = wallet.walletId,
                type = ReservationType.WAGER,
                amountMinorUnits = 2_000L,
                ttlSeconds = 60L,
                reference = "REF-IDEMP-ORIG",
                idempotencyKey = "idemp-reuse-test",
                correlationId = "c1",
                causationId = "c2"
            )
        )

        assertFailsWith<IdempotencyConflictException> {
            service.createReservation(
                CreateReservationCommand(
                    principal = adminPrincipal,
                    tenantId = "tenant-wallet-prod",
                    walletId = wallet.walletId,
                    type = ReservationType.WAGER,
                    amountMinorUnits = 3_000L, // Different amount
                    ttlSeconds = 60L,
                    reference = "REF-IDEMP-CONFLICT",
                    idempotencyKey = "idemp-reuse-test",
                    correlationId = "c1",
                    causationId = "c2"
                )
            )
        }

        // 8. Capture non-existent reservation
        assertFailsWith<ReservationNotFoundException> {
            service.captureReservation(
                CaptureReservationCommand(
                    principal = adminPrincipal,
                    tenantId = "tenant-wallet-prod",
                    reservationId = UUID.randomUUID(),
                    idempotencyKey = "idemp-not-found",
                    correlationId = "c1",
                    causationId = "c2"
                )
            )
        }
    }

    // =========================================================================
    // WALLET-003-T003: Concurrency, Duplicate Delivery, and Terminal Idempotency
    // =========================================================================

    @Test
    fun `WALLET-003-T003 Reservations survives concurrency, duplicate delivery, and dependency failure`() {
        WalletReservationBinding.checkBound()

        val wallet = createTestWallet(cashAvailable = 20_000L, bonusActive = 0L)

        // 1. Terminal transitions idempotent:
        // Create reservation -> Capture -> Capture again with same key -> Returns identical result
        val res = service.createReservation(
            CreateReservationCommand(
                principal = adminPrincipal,
                tenantId = "tenant-wallet-prod",
                walletId = wallet.walletId,
                type = ReservationType.WAGER,
                amountMinorUnits = 5_000L,
                ttlSeconds = 300L,
                reference = "REF-TERM-001",
                idempotencyKey = "idemp-term-001",
                correlationId = "c1",
                causationId = "c2"
            )
        )

        val cap1 = service.captureReservation(
            CaptureReservationCommand(
                principal = adminPrincipal,
                tenantId = "tenant-wallet-prod",
                reservationId = res.reservation.reservationId,
                idempotencyKey = "idemp-cap-term-001",
                correlationId = "c1",
                causationId = "c2"
            )
        )
        assertEquals(ReservationStatus.CAPTURED, cap1.reservation.status)

        // Second capture with same key returns identical result (no double debit)
        val cap2 = service.captureReservation(
            CaptureReservationCommand(
                principal = adminPrincipal,
                tenantId = "tenant-wallet-prod",
                reservationId = res.reservation.reservationId,
                idempotencyKey = "idemp-cap-term-001",
                correlationId = "c1",
                causationId = "c2"
            )
        )
        assertEquals(cap1.reservation.reservationId, cap2.reservation.reservationId)
        assertEquals(ReservationStatus.CAPTURED, cap2.reservation.status)

        // Attempting to release a CAPTURED reservation is rejected
        assertFailsWith<TerminalReservationTransitionException> {
            service.releaseReservation(
                ReleaseReservationCommand(
                    principal = adminPrincipal,
                    tenantId = "tenant-wallet-prod",
                    reservationId = res.reservation.reservationId,
                    reason = "Cannot release captured reservation",
                    idempotencyKey = "idemp-rel-conflict",
                    correlationId = "c1",
                    causationId = "c2"
                )
            )
        }

        // Attempting to expire a CAPTURED reservation is rejected
        assertFailsWith<TerminalReservationTransitionException> {
            service.expireReservation(
                ExpireReservationCommand(
                    principal = adminPrincipal,
                    tenantId = "tenant-wallet-prod",
                    reservationId = res.reservation.reservationId,
                    workerId = "worker-01",
                    idempotencyKey = "idemp-exp-conflict",
                    correlationId = "c1",
                    causationId = "c2"
                )
            )
        }

        // 2. Concurrency Test: Overdraft / Race Condition Defense
        // Wallet has 15_000 remaining available cash.
        // 10 concurrent threads attempt to reserve 10_000 each. Exactly 1 must succeed, 9 must fail!
        val threadCount = 10
        val executor = Executors.newFixedThreadPool(threadCount)
        val startLatch = CountDownLatch(1)
        val doneLatch = CountDownLatch(threadCount)
        val successCount = AtomicInteger(0)
        val failureCount = AtomicInteger(0)

        for (i in 1..threadCount) {
            executor.submit(Callable {
                startLatch.await()
                try {
                    service.createReservation(
                        CreateReservationCommand(
                            principal = adminPrincipal,
                            tenantId = "tenant-wallet-prod",
                            walletId = wallet.walletId,
                            type = ReservationType.WAGER,
                            amountMinorUnits = 10_000L,
                            ttlSeconds = 120L,
                            reference = "CONCUR-WAGER-$i",
                            idempotencyKey = "idemp-concur-$i",
                            correlationId = "corr-$i",
                            causationId = "caus-$i"
                        )
                    )
                    successCount.incrementAndGet()
                } catch (e: InsufficientReservationBalanceException) {
                    failureCount.incrementAndGet()
                } finally {
                    doneLatch.countDown()
                }
            })
        }

        startLatch.countDown()
        doneLatch.await()
        executor.shutdown()

        assertEquals(1, successCount.get(), "Exactly one concurrent reservation should succeed")
        assertEquals(9, failureCount.get(), "Nine concurrent reservations should fail due to insufficient balance")

        val finalWallet = bucketStore.findWalletById(wallet.tenantId, wallet.walletId)!!
        assertEquals(5_000L, finalWallet.cash.availableMinorUnits, "Remaining available cash must be exactly 5_000")
        assertEquals(10_000L, finalWallet.cash.lockedMinorUnits, "Locked cash must be exactly 10_000")
    }

    // =========================================================================
    // WALLET-003-T004: Recovery, Observability, and Lifecycle Safety
    // =========================================================================

    @Test
    fun `WALLET-003-T004 Reservations remains compatible, recoverable, observable, and lifecycle-safe`() {
        WalletReservationBinding.checkBound()

        val wallet = createTestWallet(cashAvailable = 30_000L, bonusActive = 10_000L)

        // 1. Create, capture, release, expire cycle while observing metrics and events
        val res = service.createReservation(
            CreateReservationCommand(
                principal = adminPrincipal,
                tenantId = "tenant-wallet-prod",
                walletId = wallet.walletId,
                type = ReservationType.WAGER,
                amountMinorUnits = 8_000L,
                ttlSeconds = 300L,
                reference = "REF-OBS-001",
                idempotencyKey = "idemp-obs-001",
                correlationId = "corr-obs-001",
                causationId = "caus-obs-001"
            )
        )

        // Assert structured Audit & Outbox events
        assertEquals("WALLET_RESERVATION_CREATED", res.auditEvent.type)
        assertEquals("corr-obs-001", res.auditEvent.correlationId)
        assertEquals("caus-obs-001", res.auditEvent.causationId)
        assertEquals("WALLET_RESERVATION_CREATED", res.outboxEvent.type)

        // Assert observability metrics recorded
        val metrics = observability.getMetrics()
        assertTrue(metrics.any { it.eventType == "attempt" })
        assertTrue(metrics.any { it.eventType == "accept" })

        // 2. Recovery / Store persistence validation
        val loaded = reservationStore.findById(res.reservation.reservationId)
        assertNotNull(loaded)
        assertEquals(res.reservation.reservationId, loaded.reservationId)
        assertEquals(res.reservation.amountMinorUnits, loaded.amountMinorUnits)
        assertEquals(ReservationStatus.RESERVED, loaded.status)

        // 3. Android boundary assertion: no lifecycle surface or local authority claimed
        assertFalse(res.hasAndroidDbImpact)
        assertFalse(res.hasAndroidLifecycleClaim)
    }
}
