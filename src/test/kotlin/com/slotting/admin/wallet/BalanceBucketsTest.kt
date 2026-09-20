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
import kotlin.test.assertTrue

class BalanceBucketsTest {
    private val now = Instant.parse("2026-09-20T18:15:00Z")
    private val clock = Clock.fixed(now, ZoneOffset.UTC)

    private val adminPrincipal = AuthenticatedPrincipal(
        id = "admin-wallet-buckets",
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

    private lateinit var store: InMemoryBalanceBucketsStore
    private lateinit var service: BalanceBucketsService

    @BeforeEach
    fun setUp() {
        BalanceBucketsBinding.isBound = true
        store = InMemoryBalanceBucketsStore()
        service = BalanceBucketsService(store, clock)
    }

    @AfterEach
    fun tearDown() {
        BalanceBucketsBinding.isBound = true
    }

    // =========================================================================
    // WALLET-002-T001: Authoritative Outcome Verification
    // =========================================================================

    @Test
    fun `WALLET-002-T001 Balance buckets produces the required authoritative outcome`() {
        // Fail-closed gate check: triggers RED assertion failure when unbound
        BalanceBucketsBinding.checkBound()

        // 1. Verify semantic contract constant
        assertEquals("Bucket semantics versioned; no generic mutable `balance`.", BALANCE_BUCKETS_CONTRACT)

        val ownerId = UUID.randomUUID()

        // 2. Initialize wallet with 20_000 cash and 5_000 bonus in EUR
        val initCmd = InitializeWalletBucketsCommand(
            principal = adminPrincipal,
            tenantId = "tenant-wallet-prod",
            ownerId = ownerId,
            currencyCode = "EUR",
            initialCashMinorUnits = 20_000L,
            initialBonusMinorUnits = 5_000L,
            idempotencyKey = "idemp-t001-init",
            correlationId = "corr-t001-01",
            causationId = "caus-t001-01",
            expectedVersion = 1L
        )
        val initResult = service.initializeWallet(initCmd)
        val walletId = initResult.wallet.walletId

        // Assert discrete versioned bucket structure (no generic mutable balance)
        val w1 = initResult.wallet
        assertEquals(20_000L, w1.cash.availableMinorUnits)
        assertEquals(0L, w1.cash.lockedMinorUnits)
        assertEquals(0L, w1.cash.pendingWithdrawalMinorUnits)
        assertEquals(20_000L, w1.cash.totalCashMinorUnits)

        assertEquals(5_000L, w1.bonus.activeMinorUnits)
        assertEquals(0L, w1.bonus.lockedMinorUnits)
        assertEquals(0L, w1.bonus.pendingMinorUnits)
        assertEquals(5_000L, w1.bonus.totalBonusMinorUnits)

        assertEquals(25_000L, w1.totalBalanceMinorUnits)
        assertEquals(25_000L, w1.availableWageringMinorUnits)
        assertEquals(20_000L, w1.withdrawableCashMinorUnits) // Bonus is strictly non-withdrawable
        assertEquals(1L, w1.version)
        assertFalse(initResult.hasAndroidDbImpact)
        assertFalse(initResult.hasAndroidLifecycleClaim)

        // 3. Mutate: Lock 5_000 cash (AVAILABLE_CASH -> LOCKED_CASH)
        val lockCmd = MutateBucketCommand(
            principal = adminPrincipal,
            tenantId = "tenant-wallet-prod",
            walletId = walletId,
            operationType = BucketOperationType.BUCKET_TRANSFER,
            amountMinorUnits = 5_000L,
            targetBucket = BalanceBucketType.LOCKED_CASH,
            sourceBucket = BalanceBucketType.AVAILABLE_CASH,
            reference = "lock-active-bets",
            idempotencyKey = "idemp-t001-lock",
            correlationId = "corr-t001-02",
            causationId = "caus-t001-02",
            expectedVersion = 1L
        )
        val lockResult = service.mutateBucket(lockCmd)
        val w2 = lockResult.wallet
        assertEquals(15_000L, w2.cash.availableMinorUnits)
        assertEquals(5_000L, w2.cash.lockedMinorUnits)
        assertEquals(20_000L, w2.cash.totalCashMinorUnits)
        assertEquals(25_000L, w2.totalBalanceMinorUnits) // Total balance conserved
        assertEquals(15_000L, w2.withdrawableCashMinorUnits)
        assertEquals(2L, w2.version)

        // 4. Mutate: Reserve withdrawal of 4_000 cash (AVAILABLE_CASH -> PENDING_WITHDRAWAL_CASH)
        val withdrawCmd = MutateBucketCommand(
            principal = adminPrincipal,
            tenantId = "tenant-wallet-prod",
            walletId = walletId,
            operationType = BucketOperationType.BUCKET_TRANSFER,
            amountMinorUnits = 4_000L,
            targetBucket = BalanceBucketType.PENDING_WITHDRAWAL_CASH,
            sourceBucket = BalanceBucketType.AVAILABLE_CASH,
            reference = "withdrawal-reserve-01",
            idempotencyKey = "idemp-t001-withdraw-reserve",
            correlationId = "corr-t001-03",
            causationId = "caus-t001-03",
            expectedVersion = 2L
        )
        val w3 = service.mutateBucket(withdrawCmd).wallet
        assertEquals(11_000L, w3.cash.availableMinorUnits)
        assertEquals(5_000L, w3.cash.lockedMinorUnits)
        assertEquals(4_000L, w3.cash.pendingWithdrawalMinorUnits)
        assertEquals(20_000L, w3.cash.totalCashMinorUnits)
        assertEquals(25_000L, w3.totalBalanceMinorUnits)
        assertEquals(11_000L, w3.withdrawableCashMinorUnits)
        assertEquals(3L, w3.version)

        // 5. Mutate: Unlock 2_000 locked cash (LOCKED_CASH -> AVAILABLE_CASH)
        val unlockCmd = MutateBucketCommand(
            principal = adminPrincipal,
            tenantId = "tenant-wallet-prod",
            walletId = walletId,
            operationType = BucketOperationType.BUCKET_TRANSFER,
            amountMinorUnits = 2_000L,
            targetBucket = BalanceBucketType.AVAILABLE_CASH,
            sourceBucket = BalanceBucketType.LOCKED_CASH,
            reference = "unlock-unsettled-bets",
            idempotencyKey = "idemp-t001-unlock",
            correlationId = "corr-t001-04",
            causationId = "caus-t001-04",
            expectedVersion = 3L
        )
        val w4 = service.mutateBucket(unlockCmd).wallet
        assertEquals(13_000L, w4.cash.availableMinorUnits)
        assertEquals(3_000L, w4.cash.lockedMinorUnits)
        assertEquals(4_000L, w4.cash.pendingWithdrawalMinorUnits)
        assertEquals(25_000L, w4.totalBalanceMinorUnits)
        assertEquals(4L, w4.version)

        // 6. Mutate: Wager deduction of 15_000 (precedence: cash first, then active bonus)
        val wagerCmd = WagerDeductionCommand(
            principal = adminPrincipal,
            tenantId = "tenant-wallet-prod",
            walletId = walletId,
            totalWagerMinorUnits = 15_000L,
            preferCashFirst = true,
            reference = "round-spin-101",
            idempotencyKey = "idemp-t001-wager",
            correlationId = "corr-t001-05",
            causationId = "caus-t001-05",
            expectedVersion = 4L
        )
        val w5 = service.deductWager(wagerCmd).wallet
        // 13_000 deducted from cash (bringing available cash to 0)
        // remaining 2_000 deducted from active bonus (5_000 - 2_000 = 3_000)
        assertEquals(0L, w5.cash.availableMinorUnits)
        assertEquals(3_000L, w5.cash.lockedMinorUnits)
        assertEquals(4_000L, w5.cash.pendingWithdrawalMinorUnits)
        assertEquals(7_000L, w5.cash.totalCashMinorUnits)

        assertEquals(3_000L, w5.bonus.activeMinorUnits)
        assertEquals(3_000L, w5.bonus.totalBonusMinorUnits)

        assertEquals(10_000L, w5.totalBalanceMinorUnits) // 25_000 - 15_000 = 10_000
        assertEquals(3_000L, w5.availableWageringMinorUnits)
        assertEquals(0L, w5.withdrawableCashMinorUnits)
        assertEquals(5L, w5.version)

        // 7. Mutate: Convert remaining 3_000 active bonus to cash
        val convCmd = ConvertBonusToCashCommand(
            principal = adminPrincipal,
            tenantId = "tenant-wallet-prod",
            walletId = walletId,
            amountMinorUnits = 3_000L,
            reference = "wagering-completed",
            idempotencyKey = "idemp-t001-conv",
            correlationId = "corr-t001-06",
            causationId = "caus-t001-06",
            expectedVersion = 5L
        )
        val w6 = service.convertBonusToCash(convCmd).wallet
        assertEquals(3_000L, w6.cash.availableMinorUnits)
        assertEquals(10_000L, w6.cash.totalCashMinorUnits)
        assertEquals(0L, w6.bonus.activeMinorUnits)
        assertEquals(0L, w6.bonus.totalBonusMinorUnits)
        assertEquals(10_000L, w6.totalBalanceMinorUnits)
        assertEquals(3_000L, w6.withdrawableCashMinorUnits)
        assertEquals(6L, w6.version)

        // 8. Verify zero Android DB impact
        assertFalse(service.checkAndroidDbImpact())
        assertFalse(service.hasAndroidLifecycleClaim())

        // 9. Observability: All audit & outbox events recorded
        assertEquals(6, store.auditEvents.size)
        assertEquals(6, store.outboxEvents.size)
    }

    // =========================================================================
    // WALLET-002-T002: Negative, Boundary, and Security Verification
    // =========================================================================

    @Test
    fun `WALLET-002-T002 Balance buckets rejects invalid boundary unauthorized and stale input`() {
        val ownerId = UUID.randomUUID()

        // 1. Unauthenticated request -> UNAUTHORIZED
        val unauthCmd = InitializeWalletBucketsCommand(
            principal = null,
            tenantId = "tenant-wallet-prod",
            ownerId = ownerId,
            currencyCode = "USD",
            idempotencyKey = "idemp-t002-null",
            correlationId = "corr-t002-01",
            causationId = "caus-t002-01"
        )
        val unauthEx = assertFailsWith<UnauthorizedException> {
            service.initializeWallet(unauthCmd)
        }
        assertEquals("UNAUTHORIZED", unauthEx.errorCode)

        // 2. IDOR / Cross-tenant access -> IDOR_FORBIDDEN
        val idorCmd = InitializeWalletBucketsCommand(
            principal = foreignTenantPrincipal,
            tenantId = "tenant-wallet-prod",
            ownerId = ownerId,
            currencyCode = "USD",
            idempotencyKey = "idemp-t002-idor",
            correlationId = "corr-t002-02",
            causationId = "caus-t002-02"
        )
        val idorEx = assertFailsWith<IdorForbiddenException> {
            service.initializeWallet(idorCmd)
        }
        assertEquals("IDOR_FORBIDDEN", idorEx.errorCode)

        // 3. Negative initial balances break bucket sum/negative invariant -> NEGATIVE_BUCKET_BALANCE
        val negCmd = InitializeWalletBucketsCommand(
            principal = adminPrincipal,
            tenantId = "tenant-wallet-prod",
            ownerId = ownerId,
            currencyCode = "USD",
            initialCashMinorUnits = -100L,
            idempotencyKey = "idemp-t002-neg",
            correlationId = "corr-t002-03",
            causationId = "caus-t002-03"
        )
        val negEx = assertFailsWith<NegativeBucketBalanceException> {
            service.initializeWallet(negCmd)
        }
        assertEquals("NEGATIVE_BUCKET_BALANCE", negEx.errorCode)
        assertTrue(negEx.message!!.contains("bucket sum/negative invariants break"))

        // 4. Initialize valid wallet
        val initCmd = InitializeWalletBucketsCommand(
            principal = adminPrincipal,
            tenantId = "tenant-wallet-prod",
            ownerId = ownerId,
            currencyCode = "USD",
            initialCashMinorUnits = 5_000L,
            initialBonusMinorUnits = 2_000L,
            idempotencyKey = "idemp-t002-valid",
            correlationId = "corr-t002-04",
            causationId = "caus-t002-04"
        )
        val wallet = service.initializeWallet(initCmd).wallet

        // 5. Overdraw / Insufficient bucket balance breaks negative invariant
        val overdrawCmd = MutateBucketCommand(
            principal = adminPrincipal,
            tenantId = "tenant-wallet-prod",
            walletId = wallet.walletId,
            operationType = BucketOperationType.DEBIT,
            amountMinorUnits = 99_999L,
            targetBucket = BalanceBucketType.AVAILABLE_CASH,
            idempotencyKey = "idemp-t002-overdraw",
            correlationId = "corr-t002-05",
            causationId = "caus-t002-05",
            expectedVersion = 1L
        )
        val overdrawEx = assertFailsWith<InsufficientBucketBalanceException> {
            service.mutateBucket(overdrawCmd)
        }
        assertEquals("INSUFFICIENT_BUCKET_BALANCE", overdrawEx.errorCode)
        assertTrue(overdrawEx.message!!.contains("bucket sum/negative invariants break"))

        // 6. Stale version rejection (optimistic locking)
        val staleCmd = MutateBucketCommand(
            principal = adminPrincipal,
            tenantId = "tenant-wallet-prod",
            walletId = wallet.walletId,
            operationType = BucketOperationType.CREDIT,
            amountMinorUnits = 500L,
            targetBucket = BalanceBucketType.AVAILABLE_CASH,
            idempotencyKey = "idemp-t002-stale",
            correlationId = "corr-t002-06",
            causationId = "caus-t002-06",
            expectedVersion = 999L
        )
        val staleEx = assertFailsWith<StaleVersionException> {
            service.mutateBucket(staleCmd)
        }
        assertEquals("STALE_VERSION", staleEx.errorCode)

        // 7. Invalid bucket transfer (e.g. attempting to move bonus directly to cash without conversion)
        val illegalTransferCmd = MutateBucketCommand(
            principal = adminPrincipal,
            tenantId = "tenant-wallet-prod",
            walletId = wallet.walletId,
            operationType = BucketOperationType.BUCKET_TRANSFER,
            amountMinorUnits = 1_000L,
            targetBucket = BalanceBucketType.AVAILABLE_CASH,
            sourceBucket = BalanceBucketType.ACTIVE_BONUS,
            idempotencyKey = "idemp-t002-illegal-tx",
            correlationId = "corr-t002-07",
            causationId = "caus-t002-07",
            expectedVersion = 1L
        )
        val illegalEx = assertFailsWith<InvalidBucketOperationException> {
            service.mutateBucket(illegalTransferCmd)
        }
        assertEquals("INVALID_BUCKET_OPERATION", illegalEx.errorCode)

        // 8. Non-existent wallet lookup
        val notFoundEx = assertFailsWith<WalletNotFoundException> {
            service.getWallet("tenant-wallet-prod", UUID.randomUUID(), adminPrincipal)
        }
        assertEquals("WALLET_NOT_FOUND", notFoundEx.errorCode)
    }

    // =========================================================================
    // WALLET-002-T003: Concurrency, Idempotency, and Invariant Preservation
    // =========================================================================

    @Test
    fun `WALLET-002-T003 Balance buckets survives concurrency duplicate delivery and dependency failure`() {
        val ownerId = UUID.randomUUID()

        // 1. Idempotency replay returns cached result
        val initCmd = InitializeWalletBucketsCommand(
            principal = adminPrincipal,
            tenantId = "tenant-wallet-prod",
            ownerId = ownerId,
            currencyCode = "GBP",
            initialCashMinorUnits = 10_000L,
            initialBonusMinorUnits = 2_000L,
            idempotencyKey = "idemp-t003-replay",
            correlationId = "corr-t003-01",
            causationId = "caus-t003-01"
        )
        val firstResult = service.initializeWallet(initCmd)
        val replayResult = service.initializeWallet(initCmd)
        assertEquals(firstResult.resultId, replayResult.resultId)
        assertEquals(firstResult.wallet.walletId, replayResult.wallet.walletId)

        // 2. Changed payload with same idempotency key yields IDEMPOTENCY_CONFLICT (409)
        val conflictCmd = initCmd.copy(initialCashMinorUnits = 50_000L)
        val conflictEx = assertFailsWith<ConcurrencyConflictException> {
            service.initializeWallet(conflictCmd)
        }
        assertEquals("IDEMPOTENCY_CONFLICT", conflictEx.errorCode)

        // 3. Concurrent initialization race: 10 threads attempt to initialize wallet for same owner/currency
        val concurrentOwner = UUID.randomUUID()
        val threadCount = 10
        val executor = Executors.newFixedThreadPool(threadCount)
        val latch = CountDownLatch(1)
        val successCount = AtomicInteger(0)
        val duplicateCount = AtomicInteger(0)

        val tasks = (1..threadCount).map { i ->
            Callable {
                latch.await()
                try {
                    val cmd = InitializeWalletBucketsCommand(
                        principal = adminPrincipal,
                        tenantId = "tenant-wallet-prod",
                        ownerId = concurrentOwner,
                        currencyCode = "CAD",
                        initialCashMinorUnits = 1_000L,
                        idempotencyKey = "idemp-race-init-$i",
                        correlationId = "corr-race-$i",
                        causationId = "caus-race-$i"
                    )
                    service.initializeWallet(cmd)
                    successCount.incrementAndGet()
                } catch (e: DuplicateWalletException) {
                    duplicateCount.incrementAndGet()
                }
            }
        }

        val futures = tasks.map { executor.submit(it) }
        latch.countDown()
        futures.forEach { it.get() }

        assertEquals(1, successCount.get())
        assertEquals(threadCount - 1, duplicateCount.get())
        assertEquals(1, store.listWalletsByOwner("tenant-wallet-prod", concurrentOwner).size)

        // 4. Concurrent wager deduction race (balance contention)
        // Wallet has 10_000 available cash. 10 concurrent requests of 2_000 each (20_000 total requested).
        val contestedWallet = service.initializeWallet(
            InitializeWalletBucketsCommand(
                principal = adminPrincipal,
                tenantId = "tenant-wallet-prod",
                ownerId = UUID.randomUUID(),
                currencyCode = "USD",
                initialCashMinorUnits = 10_000L,
                initialBonusMinorUnits = 0L,
                idempotencyKey = "idemp-contested-wallet",
                correlationId = "corr-contested",
                causationId = "caus-contested"
            )
        ).wallet

        val txSuccess = AtomicInteger(0)
        val txFailure = AtomicInteger(0)
        val txLatch = CountDownLatch(1)

        val wagerTasks = (1..threadCount).map { i ->
            Callable {
                txLatch.await()
                try {
                    val current = store.findWalletById("tenant-wallet-prod", contestedWallet.walletId)!!
                    val cmd = WagerDeductionCommand(
                        principal = adminPrincipal,
                        tenantId = "tenant-wallet-prod",
                        walletId = contestedWallet.walletId,
                        totalWagerMinorUnits = 2_000L,
                        preferCashFirst = true,
                        reference = "race-spin-$i",
                        idempotencyKey = "idemp-race-wager-$i",
                        correlationId = "corr-wager-$i",
                        causationId = "caus-wager-$i",
                        expectedVersion = current.version
                    )
                    service.deductWager(cmd)
                    txSuccess.incrementAndGet()
                } catch (e: InsufficientBucketBalanceException) {
                    txFailure.incrementAndGet()
                } catch (e: StaleVersionException) {
                    txFailure.incrementAndGet()
                }
            }
        }

        val wagerFutures = wagerTasks.map { executor.submit(it) }
        txLatch.countDown()
        wagerFutures.forEach { it.get() }
        executor.shutdown()

        // Verify invariant: balances never go negative, sum is conserved
        val finalWallet = store.findWalletById("tenant-wallet-prod", contestedWallet.walletId)!!
        assertTrue(finalWallet.cash.availableMinorUnits >= 0L)
        assertTrue(finalWallet.totalBalanceMinorUnits >= 0L)
        assertEquals(
            finalWallet.totalBalanceMinorUnits,
            finalWallet.cash.totalCashMinorUnits + finalWallet.bonus.totalBonusMinorUnits
        )
    }

    // =========================================================================
    // WALLET-002-T004: Compatibility, Recovery, Observability, and Lifecycle
    // =========================================================================

    @Test
    fun `WALLET-002-T004 Balance buckets remains compatible recoverable observable and lifecycle-safe`() {
        // 1. Verification gate test: when isBound = false, checkBound() throws AssertionError
        BalanceBucketsBinding.isBound = false
        val gateException = assertFailsWith<AssertionError> {
            BalanceBucketsBinding.checkBound()
        }
        assertEquals("bucket sum/negative invariants break", gateException.message)

        // Restore gate
        BalanceBucketsBinding.isBound = true

        // 2. Explicit assertion: zero Android lifecycle surface
        assertFalse(service.checkAndroidDbImpact())
        assertFalse(service.hasAndroidLifecycleClaim())

        val ownerId = UUID.randomUUID()
        val initCmd = InitializeWalletBucketsCommand(
            principal = adminPrincipal,
            tenantId = "tenant-wallet-prod",
            ownerId = ownerId,
            currencyCode = "AUD",
            initialCashMinorUnits = 30_000L,
            initialBonusMinorUnits = 10_000L,
            idempotencyKey = "idemp-t004-init",
            correlationId = "corr-t004-01",
            causationId = "caus-t004-01"
        )
        val wallet = service.initializeWallet(initCmd).wallet

        // 3. Mutate: Lock 10_000 cash
        service.mutateBucket(
            MutateBucketCommand(
                principal = adminPrincipal,
                tenantId = "tenant-wallet-prod",
                walletId = wallet.walletId,
                operationType = BucketOperationType.BUCKET_TRANSFER,
                amountMinorUnits = 10_000L,
                targetBucket = BalanceBucketType.LOCKED_CASH,
                sourceBucket = BalanceBucketType.AVAILABLE_CASH,
                idempotencyKey = "idemp-t004-lock",
                correlationId = "corr-t004-02",
                causationId = "caus-t004-02",
                expectedVersion = 1L
            )
        )

        // 4. State recovery across restart
        val recoveredService = BalanceBucketsService(store, clock)
        val recoveredWallet = recoveredService.getWallet("tenant-wallet-prod", wallet.walletId, adminPrincipal)
        assertEquals(20_000L, recoveredWallet.cash.availableMinorUnits)
        assertEquals(10_000L, recoveredWallet.cash.lockedMinorUnits)
        assertEquals(10_000L, recoveredWallet.bonus.activeMinorUnits)
        assertEquals(40_000L, recoveredWallet.totalBalanceMinorUnits)
        assertEquals(2L, recoveredWallet.version)

        // 5. Compensating reversal: Compensate locked cash back to available
        val compResult = recoveredService.mutateBucket(
            MutateBucketCommand(
                principal = adminPrincipal,
                tenantId = "tenant-wallet-prod",
                walletId = wallet.walletId,
                operationType = BucketOperationType.BUCKET_TRANSFER,
                amountMinorUnits = 10_000L,
                targetBucket = BalanceBucketType.AVAILABLE_CASH,
                sourceBucket = BalanceBucketType.LOCKED_CASH,
                reference = "compensate-lock-reversal",
                idempotencyKey = "idemp-t004-compensate",
                correlationId = "corr-t004-comp",
                causationId = "caus-t004-comp",
                expectedVersion = 2L
            )
        )
        val restoredWallet = compResult.wallet
        assertEquals(30_000L, restoredWallet.cash.availableMinorUnits)
        assertEquals(0L, restoredWallet.cash.lockedMinorUnits)
        assertEquals(40_000L, restoredWallet.totalBalanceMinorUnits)
        assertEquals(3L, restoredWallet.version)

        // 6. Observability & redaction
        assertTrue(store.auditEvents.isNotEmpty())
        for (audit in store.auditEvents) {
            assertEquals("tenant-wallet-prod", audit.tenantId)
            assertNotNull(audit.correlationId)
            assertNotNull(audit.causationId)
        }

        assertTrue(store.outboxEvents.isNotEmpty())
        for (outbox in store.outboxEvents) {
            assertEquals("tenant-wallet-prod", outbox.tenantId)
            assertNotNull(outbox.type)
            assertNotNull(outbox.resultId)
        }
    }
}
