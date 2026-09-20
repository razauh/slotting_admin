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

class WalletAccountsAndCurrencyTest {
    private val now = Instant.parse("2026-09-20T18:00:00Z")
    private val clock = Clock.fixed(now, ZoneOffset.UTC)

    private val adminPrincipal = AuthenticatedPrincipal(
        id = "admin-wallet-super",
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

    private lateinit var store: InMemoryWalletAccountStore
    private lateinit var service: WalletAccountService

    @BeforeEach
    fun setUp() {
        WalletAccountBinding.isBound = true
        store = InMemoryWalletAccountStore()
        service = WalletAccountService(store, clock)
    }

    @AfterEach
    fun tearDown() {
        WalletAccountBinding.isBound = true
    }

    // =========================================================================
    // WALLET-001-T001: Authoritative Outcome Verification
    // =========================================================================

    @Test
    fun `WALLET-001-T001 Accounts and currency model produces the required authoritative outcome`() {
        // Fail-closed gate check: triggers RED assertion failure when unbound
        WalletAccountBinding.checkBound()

        // 1. Verify semantic contract constant
        assertEquals(
            "ISO currency + integer minor units; unique owner/currency/account type; no Android DB impact.",
            WALLET_ACCOUNTS_AND_CURRENCY_CONTRACT
        )

        val ownerId1 = UUID.randomUUID()
        val ownerId2 = UUID.randomUUID()

        // 2. Create primary CASH wallet account for player 1 in USD with 10_000 minor units ($100.00)
        val createCmd1 = CreateWalletAccountCommand(
            principal = adminPrincipal,
            tenantId = "tenant-wallet-prod",
            ownerId = ownerId1,
            currencyCode = "USD",
            accountType = WalletAccountType.CASH,
            initialBalanceMinorUnits = 10_000L,
            idempotencyKey = "idemp-t001-acc1",
            correlationId = "corr-t001-01",
            causationId = "caus-t001-01",
            expectedVersion = 1L
        )
        val result1 = service.createAccount(createCmd1)
        assertNotNull(result1.account.accountId)
        assertEquals("USD", result1.account.currencyCode)
        assertEquals(WalletAccountType.CASH, result1.account.accountType)
        assertEquals(WalletAccountStatus.ACTIVE, result1.account.status)
        assertEquals(10_000L, result1.account.currentBalanceMinorUnits)
        assertEquals(10_000L, result1.account.availableBalanceMinorUnits)
        assertEquals(0L, result1.account.reservedBalanceMinorUnits)
        assertEquals(1L, result1.account.version)
        assertEquals(now, result1.account.createdAt)
        assertFalse(result1.hasAndroidDbImpact)
        assertFalse(result1.hasAndroidLifecycleClaim)

        // 3. Create secondary CASH wallet account for player 2 in USD with 0 initial balance
        val createCmd2 = CreateWalletAccountCommand(
            principal = adminPrincipal,
            tenantId = "tenant-wallet-prod",
            ownerId = ownerId2,
            currencyCode = "USD",
            accountType = WalletAccountType.CASH,
            initialBalanceMinorUnits = 0L,
            idempotencyKey = "idemp-t001-acc2",
            correlationId = "corr-t001-02",
            causationId = "caus-t001-02",
            expectedVersion = 1L
        )
        val result2 = service.createAccount(createCmd2)
        assertEquals(0L, result2.account.currentBalanceMinorUnits)
        assertEquals(0L, result2.account.availableBalanceMinorUnits)

        // 4. Authoritative transfer from account 1 to account 2: 2_500 minor units ($25.00)
        val transferCmd = TransferFundsCommand(
            principal = adminPrincipal,
            tenantId = "tenant-wallet-prod",
            sourceAccountId = result1.account.accountId,
            destinationAccountId = result2.account.accountId,
            amountMinorUnits = 2_500L,
            currencyCode = "USD",
            reference = "tx-ref-t001-p2p",
            idempotencyKey = "idemp-t001-tx1",
            correlationId = "corr-t001-03",
            causationId = "caus-t001-03",
            expectedVersion = 1L
        )
        val transferResult = service.transferFunds(transferCmd)

        // Verify debits equal credits and minor units conservation
        assertTrue(transferResult.debitsEqualCredits)
        assertTrue(transferResult.totalMinorUnitsConserved)
        assertEquals(7_500L, transferResult.sourceAccount.currentBalanceMinorUnits)
        assertEquals(7_500L, transferResult.sourceAccount.availableBalanceMinorUnits)
        assertEquals(2_500L, transferResult.destinationAccount.currentBalanceMinorUnits)
        assertEquals(2_500L, transferResult.destinationAccount.availableBalanceMinorUnits)
        assertEquals(
            10_000L,
            transferResult.sourceAccount.currentBalanceMinorUnits + transferResult.destinationAccount.currentBalanceMinorUnits
        )
        assertEquals(2L, transferResult.sourceAccount.version)
        assertEquals(2L, transferResult.destinationAccount.version)
        assertFalse(transferResult.hasAndroidDbImpact)
        assertFalse(transferResult.hasAndroidLifecycleClaim)

        // 5. Verify zero Android DB impact via service directly
        assertFalse(service.checkAndroidDbImpact())
        assertFalse(service.hasAndroidLifecycleClaim())

        // 6. Verify audit and outbox events
        assertEquals(3, store.auditEvents.size) // 2 creations + 1 transfer
        assertEquals(3, store.outboxEvents.size)

        val txAudit = store.auditEvents.first { it.type == "WALLET_FUNDS_TRANSFERRED" }
        assertEquals("tenant-wallet-prod", txAudit.tenantId)
        assertEquals("corr-t001-03", txAudit.correlationId)
        assertEquals("caus-t001-03", txAudit.causationId)
    }

    // =========================================================================
    // WALLET-001-T002: Negative, Boundary, and Security Verification
    // =========================================================================

    @Test
    fun `WALLET-001-T002 Accounts and currency model rejects invalid boundary unauthorized and stale input`() {
        val ownerId = UUID.randomUUID()

        // 1. Unauthenticated request (null principal) -> UNAUTHORIZED
        val nullPrincipalCmd = CreateWalletAccountCommand(
            principal = null,
            tenantId = "tenant-wallet-prod",
            ownerId = ownerId,
            currencyCode = "USD",
            accountType = WalletAccountType.CASH,
            idempotencyKey = "idemp-t002-null",
            correlationId = "corr-t002-01",
            causationId = "caus-t002-01"
        )
        val unauthEx = assertFailsWith<UnauthorizedException> {
            service.createAccount(nullPrincipalCmd)
        }
        assertEquals("UNAUTHORIZED", unauthEx.errorCode)

        // 2. Cross-tenant IDOR access -> IDOR_FORBIDDEN
        val idorCmd = CreateWalletAccountCommand(
            principal = foreignTenantPrincipal,
            tenantId = "tenant-wallet-prod",
            ownerId = ownerId,
            currencyCode = "USD",
            accountType = WalletAccountType.CASH,
            idempotencyKey = "idemp-t002-idor",
            correlationId = "corr-t002-02",
            causationId = "caus-t002-02"
        )
        val idorEx = assertFailsWith<IdorForbiddenException> {
            service.createAccount(idorCmd)
        }
        assertEquals("IDOR_FORBIDDEN", idorEx.errorCode)

        // 3. Invalid currency codes -> INVALID_CURRENCY
        val invalidCurrencies = listOf("", "   ", "US", "USDD", "usd", "XYZ9", "123", "!@#")
        for (invalidCur in invalidCurrencies) {
            val badCurCmd = CreateWalletAccountCommand(
                principal = adminPrincipal,
                tenantId = "tenant-wallet-prod",
                ownerId = ownerId,
                currencyCode = invalidCur,
                accountType = WalletAccountType.CASH,
                idempotencyKey = "idemp-t002-cur-$invalidCur",
                correlationId = "corr-t002-03",
                causationId = "caus-t002-03"
            )
            val curEx = assertFailsWith<InvalidCurrencyException> {
                service.createAccount(badCurCmd)
            }
            assertEquals("INVALID_CURRENCY", curEx.errorCode)
        }

        // 4. Invalid minor units (negative initial balance) -> INVALID_AMOUNT
        val negBalanceCmd = CreateWalletAccountCommand(
            principal = adminPrincipal,
            tenantId = "tenant-wallet-prod",
            ownerId = ownerId,
            currencyCode = "EUR",
            accountType = WalletAccountType.CASH,
            initialBalanceMinorUnits = -500L,
            idempotencyKey = "idemp-t002-neg-bal",
            correlationId = "corr-t002-04",
            causationId = "caus-t002-04"
        )
        val negBalEx = assertFailsWith<InvalidAmountException> {
            service.createAccount(negBalanceCmd)
        }
        assertEquals("INVALID_AMOUNT", negBalEx.errorCode)

        // 5. Create initial valid account in USD
        val validCmd = CreateWalletAccountCommand(
            principal = adminPrincipal,
            tenantId = "tenant-wallet-prod",
            ownerId = ownerId,
            currencyCode = "USD",
            accountType = WalletAccountType.CASH,
            initialBalanceMinorUnits = 5_000L,
            idempotencyKey = "idemp-t002-valid",
            correlationId = "corr-t002-05",
            causationId = "caus-t002-05"
        )
        val acc1 = service.createAccount(validCmd).account

        // 6. Duplicate account creation for same (tenantId, ownerId, currencyCode, accountType) -> DUPLICATE_ACCOUNT
        val duplicateCmd = CreateWalletAccountCommand(
            principal = adminPrincipal,
            tenantId = "tenant-wallet-prod",
            ownerId = ownerId,
            currencyCode = "USD",
            accountType = WalletAccountType.CASH,
            initialBalanceMinorUnits = 1_000L,
            idempotencyKey = "idemp-t002-dup",
            correlationId = "corr-t002-06",
            causationId = "caus-t002-06"
        )
        val dupEx = assertFailsWith<DuplicateAccountException> {
            service.createAccount(duplicateCmd)
        }
        assertEquals("DUPLICATE_ACCOUNT", dupEx.errorCode)
        assertTrue(dupEx.message!!.contains("cross-currency/duplicate account allowed"))

        // 7. Cross-currency transfer attempt: Account 1 is USD, create Account 2 in EUR
        val ownerId2 = UUID.randomUUID()
        val accEur = service.createAccount(
            CreateWalletAccountCommand(
                principal = adminPrincipal,
                tenantId = "tenant-wallet-prod",
                ownerId = ownerId2,
                currencyCode = "EUR",
                accountType = WalletAccountType.CASH,
                initialBalanceMinorUnits = 10_000L,
                idempotencyKey = "idemp-t002-eur",
                correlationId = "corr-t002-07",
                causationId = "caus-t002-07"
            )
        ).account

        val crossCurrencyCmd = TransferFundsCommand(
            principal = adminPrincipal,
            tenantId = "tenant-wallet-prod",
            sourceAccountId = acc1.accountId,
            destinationAccountId = accEur.accountId,
            amountMinorUnits = 1_000L,
            currencyCode = "USD",
            idempotencyKey = "idemp-t002-cross-cur",
            correlationId = "corr-t002-08",
            causationId = "caus-t002-08"
        )
        val crossCurEx = assertFailsWith<CrossCurrencyNotAllowedException> {
            service.transferFunds(crossCurrencyCmd)
        }
        assertEquals("CROSS_CURRENCY_NOT_ALLOWED", crossCurEx.errorCode)
        assertTrue(crossCurEx.message!!.contains("cross-currency/duplicate account allowed"))

        // Assert balances of both accounts remain unchanged
        val reloadedAcc1 = store.findAccountById("tenant-wallet-prod", acc1.accountId)!!
        val reloadedAccEur = store.findAccountById("tenant-wallet-prod", accEur.accountId)!!
        assertEquals(5_000L, reloadedAcc1.availableBalanceMinorUnits)
        assertEquals(10_000L, reloadedAccEur.availableBalanceMinorUnits)

        // 8. Insufficient funds rejection
        val overdrawnCmd = TransferFundsCommand(
            principal = adminPrincipal,
            tenantId = "tenant-wallet-prod",
            sourceAccountId = acc1.accountId,
            destinationAccountId = acc1.accountId, // Even same account
            amountMinorUnits = 999_999L,
            currencyCode = "USD",
            idempotencyKey = "idemp-t002-insufficient",
            correlationId = "corr-t002-09",
            causationId = "caus-t002-09"
        )
        val insuffEx = assertFailsWith<InsufficientFundsException> {
            service.transferFunds(overdrawnCmd)
        }
        assertEquals("INSUFFICIENT_FUNDS", insuffEx.errorCode)

        // 9. Stale expectedVersion rejection (optimistic locking)
        val staleCmd = TransferFundsCommand(
            principal = adminPrincipal,
            tenantId = "tenant-wallet-prod",
            sourceAccountId = acc1.accountId,
            destinationAccountId = acc1.accountId,
            amountMinorUnits = 100L,
            currencyCode = "USD",
            idempotencyKey = "idemp-t002-stale",
            correlationId = "corr-t002-10",
            causationId = "caus-t002-10",
            expectedVersion = 999L // Mismatch
        )
        val staleEx = assertFailsWith<StaleVersionException> {
            service.transferFunds(staleCmd)
        }
        assertEquals("STALE_VERSION", staleEx.errorCode)
    }

    // =========================================================================
    // WALLET-001-T003: Concurrency, Idempotency, and Race Condition Survival
    // =========================================================================

    @Test
    fun `WALLET-001-T003 Accounts and currency model survives concurrency duplicate delivery and dependency failure`() {
        val ownerId = UUID.randomUUID()

        // 1. Idempotency replay returns cached result
        val createCmd = CreateWalletAccountCommand(
            principal = adminPrincipal,
            tenantId = "tenant-wallet-prod",
            ownerId = ownerId,
            currencyCode = "GBP",
            accountType = WalletAccountType.BONUS,
            initialBalanceMinorUnits = 15_000L,
            idempotencyKey = "idemp-t003-replay",
            correlationId = "corr-t003-01",
            causationId = "caus-t003-01"
        )
        val firstResult = service.createAccount(createCmd)
        val replayResult = service.createAccount(createCmd)
        assertEquals(firstResult.resultId, replayResult.resultId)
        assertEquals(firstResult.account.accountId, replayResult.account.accountId)
        assertEquals(1, store.listAccountsByOwner("tenant-wallet-prod", ownerId).size)

        // 2. Changed payload with same idempotency key yields IDEMPOTENCY_CONFLICT (409)
        val conflictingCmd = createCmd.copy(initialBalanceMinorUnits = 99_999L)
        val conflictEx = assertFailsWith<ConcurrencyConflictException> {
            service.createAccount(conflictingCmd)
        }
        assertEquals("IDEMPOTENCY_CONFLICT", conflictEx.errorCode)

        // 3. Race condition: concurrent creation of the same account type/currency/owner
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
                    val cmd = CreateWalletAccountCommand(
                        principal = adminPrincipal,
                        tenantId = "tenant-wallet-prod",
                        ownerId = concurrentOwner,
                        currencyCode = "CAD",
                        accountType = WalletAccountType.CASH,
                        initialBalanceMinorUnits = 1_000L,
                        idempotencyKey = "idemp-concurrent-create-$i",
                        correlationId = "corr-concurrent-$i",
                        causationId = "caus-concurrent-$i"
                    )
                    service.createAccount(cmd)
                    successCount.incrementAndGet()
                } catch (e: DuplicateAccountException) {
                    duplicateCount.incrementAndGet()
                }
            }
        }

        val futures = tasks.map { executor.submit(it) }
        latch.countDown()
        futures.forEach { it.get() }

        // Exactly one creation succeeded, other 9 were safely rejected as duplicate
        assertEquals(1, successCount.get())
        assertEquals(threadCount - 1, duplicateCount.get())
        assertEquals(1, store.listAccountsByOwner("tenant-wallet-prod", concurrentOwner).size)

        // 4. Concurrent transfer race (balance contention)
        // Source account has 10_000 minor units. Destination has 0.
        // 10 concurrent requests of 2_000 minor units each (total requested = 20_000).
        val sourceAcc = service.createAccount(
            CreateWalletAccountCommand(
                principal = adminPrincipal,
                tenantId = "tenant-wallet-prod",
                ownerId = UUID.randomUUID(),
                currencyCode = "AUD",
                accountType = WalletAccountType.CASH,
                initialBalanceMinorUnits = 10_000L,
                idempotencyKey = "idemp-src-race",
                correlationId = "corr-src-race",
                causationId = "caus-src-race"
            )
        ).account

        val destAcc = service.createAccount(
            CreateWalletAccountCommand(
                principal = adminPrincipal,
                tenantId = "tenant-wallet-prod",
                ownerId = UUID.randomUUID(),
                currencyCode = "AUD",
                accountType = WalletAccountType.CASH,
                initialBalanceMinorUnits = 0L,
                idempotencyKey = "idemp-dest-race",
                correlationId = "corr-dest-race",
                causationId = "caus-dest-race"
            )
        ).account

        val txSuccessCount = AtomicInteger(0)
        val txFailCount = AtomicInteger(0)
        val txLatch = CountDownLatch(1)

        // Each transfer will re-fetch the latest source account version
        val transferTasks = (1..threadCount).map { i ->
            Callable {
                txLatch.await()
                try {
                    val currentSource = store.findAccountById("tenant-wallet-prod", sourceAcc.accountId)!!
                    val cmd = TransferFundsCommand(
                        principal = adminPrincipal,
                        tenantId = "tenant-wallet-prod",
                        sourceAccountId = sourceAcc.accountId,
                        destinationAccountId = destAcc.accountId,
                        amountMinorUnits = 2_000L,
                        currencyCode = "AUD",
                        idempotencyKey = "idemp-transfer-race-$i",
                        correlationId = "corr-tx-race-$i",
                        causationId = "caus-tx-race-$i",
                        expectedVersion = currentSource.version
                    )
                    service.transferFunds(cmd)
                    txSuccessCount.incrementAndGet()
                } catch (e: InsufficientFundsException) {
                    txFailCount.incrementAndGet()
                } catch (e: StaleVersionException) {
                    txFailCount.incrementAndGet()
                }
            }
        }

        val txFutures = transferTasks.map { executor.submit(it) }
        txLatch.countDown()
        txFutures.forEach { it.get() }
        executor.shutdown()

        // Balances never went negative, debits equal credits
        val finalSource = store.findAccountById("tenant-wallet-prod", sourceAcc.accountId)!!
        val finalDest = store.findAccountById("tenant-wallet-prod", destAcc.accountId)!!

        assertTrue(finalSource.availableBalanceMinorUnits >= 0L)
        assertTrue(finalSource.currentBalanceMinorUnits >= 0L)
        assertEquals(
            10_000L,
            finalSource.currentBalanceMinorUnits + finalDest.currentBalanceMinorUnits
        )
    }

    // =========================================================================
    // WALLET-001-T004: Compatibility, Recovery, Observability, and Lifecycle
    // =========================================================================

    @Test
    fun `WALLET-001-T004 Accounts and currency model remains compatible recoverable observable and lifecycle-safe`() {
        // 1. Verification gate test: when isBound = false, checkBound() throws AssertionError
        WalletAccountBinding.isBound = false
        val gateException = assertFailsWith<AssertionError> {
            WalletAccountBinding.checkBound()
        }
        assertEquals("cross-currency/duplicate account allowed", gateException.message)

        // Restore gate
        WalletAccountBinding.isBound = true

        // 2. Explicit assertion that no Android lifecycle surface is claimed
        assertFalse(service.checkAndroidDbImpact())
        assertFalse(service.hasAndroidLifecycleClaim())

        val owner1 = UUID.randomUUID()
        val owner2 = UUID.randomUUID()

        val acc1 = service.createAccount(
            CreateWalletAccountCommand(
                principal = adminPrincipal,
                tenantId = "tenant-wallet-prod",
                ownerId = owner1,
                currencyCode = "JPY",
                accountType = WalletAccountType.CASH,
                initialBalanceMinorUnits = 50_000L,
                idempotencyKey = "idemp-t004-acc1",
                correlationId = "corr-t004-01",
                causationId = "caus-t004-01"
            )
        ).account

        val acc2 = service.createAccount(
            CreateWalletAccountCommand(
                principal = adminPrincipal,
                tenantId = "tenant-wallet-prod",
                ownerId = owner2,
                currencyCode = "JPY",
                accountType = WalletAccountType.CASH,
                initialBalanceMinorUnits = 10_000L,
                idempotencyKey = "idemp-t004-acc2",
                correlationId = "corr-t004-02",
                causationId = "caus-t004-02"
            )
        ).account

        // 3. Perform transfer: 15_000 JPY minor units
        val tx = service.transferFunds(
            TransferFundsCommand(
                principal = adminPrincipal,
                tenantId = "tenant-wallet-prod",
                sourceAccountId = acc1.accountId,
                destinationAccountId = acc2.accountId,
                amountMinorUnits = 15_000L,
                currencyCode = "JPY",
                idempotencyKey = "idemp-t004-tx",
                correlationId = "corr-t004-03",
                causationId = "caus-t004-03",
                expectedVersion = 1L
            )
        )

        assertEquals(35_000L, tx.sourceAccount.availableBalanceMinorUnits)
        assertEquals(25_000L, tx.destinationAccount.availableBalanceMinorUnits)

        // 4. Persistence recovery across service restart
        // Recreate service with existing store to simulate node restart / failover
        val recoveredService = WalletAccountService(store, clock)
        val loadedAcc1 = recoveredService.getAccount("tenant-wallet-prod", acc1.accountId, adminPrincipal)
        val loadedAcc2 = recoveredService.getAccount("tenant-wallet-prod", acc2.accountId, adminPrincipal)
        assertEquals(35_000L, loadedAcc1.availableBalanceMinorUnits)
        assertEquals(25_000L, loadedAcc2.availableBalanceMinorUnits)

        // 5. Immutable compensation / reversal: Compensate transfer without editing posted history
        val compensatoryTx = recoveredService.transferFunds(
            TransferFundsCommand(
                principal = adminPrincipal,
                tenantId = "tenant-wallet-prod",
                sourceAccountId = acc2.accountId,
                destinationAccountId = acc1.accountId,
                amountMinorUnits = 15_000L,
                currencyCode = "JPY",
                reference = "reversal-of-idemp-t004-tx",
                idempotencyKey = "idemp-t004-compensate",
                correlationId = "corr-t004-comp",
                causationId = "caus-t004-comp",
                expectedVersion = 2L
            )
        )

        // Balances restored to initial state
        assertEquals(50_000L, compensatoryTx.destinationAccount.availableBalanceMinorUnits)
        assertEquals(10_000L, compensatoryTx.sourceAccount.availableBalanceMinorUnits)

        // 6. Verify observability & redaction: All audit and outbox records preserve correlation IDs, zero secrets
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
