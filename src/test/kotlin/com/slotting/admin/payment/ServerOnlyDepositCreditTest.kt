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

class ServerOnlyDepositCreditTest {
    private val now = Instant.parse("2026-09-20T00:00:00Z")
    private val clock = Clock.fixed(now, ZoneOffset.UTC)
    private val tenantId = "tenant-credit-1"
    private val providerId = "prov-credit-card-1"
    private val playerId = UUID.fromString("11111111-1111-1111-1111-111111111111")

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
        id = "admin-user-cross",
        tenantId = "tenant-other",
        kind = PrincipalKind.ADMIN,
        roles = setOf(AdminRole.SUPER_ADMIN),
    )

    private val playerPrincipal = AuthenticatedPrincipal(
        id = "player-principal-01",
        tenantId = tenantId,
        kind = PrincipalKind.PLAYER,
        roles = emptySet(),
    )

    private lateinit var store: InMemoryServerDepositCreditStore
    private lateinit var alertSink: InMemoryServerDepositCreditAlertSink
    private lateinit var ledgerService: LedgerPostingService
    private lateinit var service: ServerOnlyDepositCreditService

    @BeforeEach
    fun setUp() {
        ServerOnlyDepositCreditBinding.isBound = true
        store = InMemoryServerDepositCreditStore()
        alertSink = InMemoryServerDepositCreditAlertSink()
        ledgerService = LedgerPostingService(clock = clock)
        service = ServerOnlyDepositCreditService(
            ledgerPostingService = ledgerService,
            store = store,
            alertSink = alertSink,
            clock = clock,
        )
    }

    @AfterEach
    fun tearDown() {
        ServerOnlyDepositCreditBinding.isBound = true
    }

    @Test
    fun `PAYMENT-005-T001 — Server-only deposit credit produces the required authoritative outcome`() {
        // 1. Expected RED failure verification: Fail-closed gate throws expected assertion when unbound
        ServerOnlyDepositCreditBinding.isBound = false

        val validServerCmd = CreditDepositCommand(
            tenantId = tenantId,
            playerId = playerId,
            paymentReference = "dep-credit-t001",
            providerId = providerId,
            providerTransactionId = "tx-prov-t001",
            amountMinorUnits = 10000L,
            currencyCode = "EUR",
            source = CreditSource.SERVER_VERIFIED_WEBHOOK,
            idempotencyKey = "key-credit-t001",
            correlationId = "corr-cred-1",
            causationId = "cause-cred-1",
            principal = adminPrincipal,
        )

        val gateError = assertFailsWith<AssertionError> {
            service.creditDeposit(validServerCmd)
        }
        assertEquals("app return/client request credits", gateError.message)

        // Bind the fail-closed gate
        ServerOnlyDepositCreditBinding.isBound = true

        // 2. Untrusted client defense: APP_RETURN_URL and CLIENT_REQUEST must NEVER credit balances!
        val appReturnCmd = validServerCmd.copy(
            source = CreditSource.APP_RETURN_URL,
            returnUrlParameters = "status=success&txId=tx-prov-t001",
            idempotencyKey = "key-app-return-t001",
        )
        val appReturnError = assertFailsWith<AuthenticationFailure.Rejected> {
            service.creditDeposit(appReturnCmd)
        }
        assertEquals(AuthErrorCode.FORBIDDEN, appReturnError.code)

        val clientRequestCmd = validServerCmd.copy(
            source = CreditSource.CLIENT_REQUEST,
            idempotencyKey = "key-client-req-t001",
        )
        val clientRequestError = assertFailsWith<AuthenticationFailure.Rejected> {
            service.creditDeposit(clientRequestCmd)
        }
        assertEquals(AuthErrorCode.FORBIDDEN, clientRequestError.code)

        // Verify alert emitted and zero credit persisted
        assertTrue(alertSink.alerts.any { it.contains("CLIENT_CREDIT_ATTEMPT_DENIED") })
        assertNull(store.findCreditByPaymentRef(tenantId, "dep-credit-t001"))
        assertNull(store.findCreditByProviderTxId(tenantId, "tx-prov-t001"))

        // 3. Authoritative server execution: SERVER_VERIFIED_WEBHOOK credits player
        val result = service.creditDeposit(validServerCmd)
        assertNotNull(result)
        assertEquals(tenantId, result.tenantId)
        assertEquals(playerId, result.playerId)
        assertEquals("dep-credit-t001", result.paymentReference)
        assertEquals("tx-prov-t001", result.providerTransactionId)
        assertEquals(10000L, result.creditedAmountMinorUnits)
        assertEquals("EUR", result.currencyCode)
        assertEquals("TX-DEP-dep-credit-t001", result.ledgerTransactionReference)
        assertFalse(result.isDuplicate)
        assertTrue(result.conserved)
        assertEquals(10000L, result.debitMinorUnits)
        assertEquals(10000L, result.creditMinorUnits)
        assertEquals(SERVER_ONLY_DEPOSIT_CREDIT_CONTRACT, result.semanticContract)

        // Verify persisted record in store
        val storedRecord = store.findCreditByPaymentRef(tenantId, "dep-credit-t001")
        assertNotNull(storedRecord)
        assertEquals(10000L, storedRecord.amountMinorUnits)
        assertEquals(CreditSource.SERVER_VERIFIED_WEBHOOK, storedRecord.source)
        assertTrue(storedRecord.conserved)

        val recordByTx = store.findCreditByProviderTxId(tenantId, "tx-prov-t001")
        assertNotNull(recordByTx)
        assertEquals(storedRecord.creditId, recordByTx.creditId)

        // 4. Exact duplicate replay returns identical cached result without double-crediting
        val duplicateResult = service.creditDeposit(validServerCmd)
        assertEquals(result.resultId, duplicateResult.resultId)
        assertEquals(result.ledgerTransactionReference, duplicateResult.ledgerTransactionReference)
        assertTrue(duplicateResult.isDuplicate)
        assertEquals(10000L, duplicateResult.creditedAmountMinorUnits)
    }

    @Test
    fun `PAYMENT-005-T002 — Server-only deposit credit rejects invalid, boundary, unauthorized, and stale input`() {
        val baseCmd = CreditDepositCommand(
            tenantId = tenantId,
            playerId = playerId,
            paymentReference = "dep-credit-t002",
            providerId = providerId,
            providerTransactionId = "tx-prov-t002",
            amountMinorUnits = 10000L,
            currencyCode = "EUR",
            source = CreditSource.SERVER_VERIFIED_WEBHOOK,
            idempotencyKey = "key-credit-t002",
            correlationId = "corr-cred-2",
            causationId = "cause-cred-2",
            principal = adminPrincipal,
        )

        // 1. Blank mandatory fields
        assertFailsWith<AuthenticationFailure.Rejected> { service.creditDeposit(baseCmd.copy(tenantId = "")) }
        assertFailsWith<AuthenticationFailure.Rejected> { service.creditDeposit(baseCmd.copy(paymentReference = "  ")) }
        assertFailsWith<AuthenticationFailure.Rejected> { service.creditDeposit(baseCmd.copy(providerId = "")) }
        assertFailsWith<AuthenticationFailure.Rejected> { service.creditDeposit(baseCmd.copy(providerTransactionId = "")) }
        assertFailsWith<AuthenticationFailure.Rejected> { service.creditDeposit(baseCmd.copy(idempotencyKey = "")) }
        assertFailsWith<AuthenticationFailure.Rejected> { service.creditDeposit(baseCmd.copy(correlationId = "")) }
        assertFailsWith<AuthenticationFailure.Rejected> { service.creditDeposit(baseCmd.copy(causationId = "")) }

        // 2. Invalid amount & currency
        val zeroAmtError = assertFailsWith<AuthenticationFailure.Rejected> {
            service.creditDeposit(baseCmd.copy(amountMinorUnits = 0L))
        }
        assertEquals(AuthErrorCode.INVALID, zeroAmtError.code)

        val negAmtError = assertFailsWith<AuthenticationFailure.Rejected> {
            service.creditDeposit(baseCmd.copy(amountMinorUnits = -100L))
        }
        assertEquals(AuthErrorCode.INVALID, negAmtError.code)

        val lowerCurrError = assertFailsWith<AuthenticationFailure.Rejected> {
            service.creditDeposit(baseCmd.copy(currencyCode = "eur"))
        }
        assertEquals(AuthErrorCode.INVALID, lowerCurrError.code)

        val longCurrError = assertFailsWith<AuthenticationFailure.Rejected> {
            service.creditDeposit(baseCmd.copy(currencyCode = "EURO"))
        }
        assertEquals(AuthErrorCode.INVALID, longCurrError.code)

        // 3. Stale version
        val staleError = assertFailsWith<AuthenticationFailure.Rejected> {
            service.creditDeposit(baseCmd.copy(expectedVersion = 2L))
        }
        assertEquals(AuthErrorCode.STALE, staleError.code)

        // 4. Unauthorized / cross-tenant / invalid role principal
        val crossTenantError = assertFailsWith<AuthenticationFailure.Rejected> {
            service.creditDeposit(baseCmd.copy(principal = crossTenantPrincipal))
        }
        assertEquals(AuthErrorCode.FORBIDDEN, crossTenantError.code)

        val playerError = assertFailsWith<AuthenticationFailure.Rejected> {
            service.creditDeposit(baseCmd.copy(principal = playerPrincipal))
        }
        assertEquals(AuthErrorCode.FORBIDDEN, playerError.code)

        val supportRoleError = assertFailsWith<AuthenticationFailure.Rejected> {
            service.creditDeposit(baseCmd.copy(principal = supportPrincipal))
        }
        assertEquals(AuthErrorCode.FORBIDDEN, supportRoleError.code)

        // Successful execution of base command to seed state
        service.creditDeposit(baseCmd)

        // 5. Idempotency conflict (same idempotency key, different amount)
        val conflictIdempError = assertFailsWith<AuthenticationFailure.Rejected> {
            service.creditDeposit(baseCmd.copy(amountMinorUnits = 25000L))
        }
        assertEquals(AuthErrorCode.CONFLICT, conflictIdempError.code)
        assertTrue(alertSink.alerts.any { it.contains("DEPOSIT_CREDIT_IDEMPOTENCY_CONFLICT") })

        // 6. Provider transaction conflict (same providerTransactionId, different paymentReference or amount under new idempotency key)
        val conflictTxError = assertFailsWith<AuthenticationFailure.Rejected> {
            service.creditDeposit(baseCmd.copy(
                paymentReference = "dep-credit-other",
                idempotencyKey = "key-credit-different",
            ))
        }
        assertEquals(AuthErrorCode.CONFLICT, conflictTxError.code)
        assertTrue(alertSink.alerts.any { it.contains("PROVIDER_TRANSACTION_CONFLICT") })
    }

    @Test
    fun `PAYMENT-005-T003 — Server-only deposit credit survives concurrency, duplicate delivery, and dependency failure`() {
        val concurrentCmd = CreditDepositCommand(
            tenantId = tenantId,
            playerId = playerId,
            paymentReference = "dep-credit-con-001",
            providerId = providerId,
            providerTransactionId = "tx-prov-con-001",
            amountMinorUnits = 15000L,
            currencyCode = "EUR",
            source = CreditSource.SERVER_VERIFIED_WEBHOOK,
            idempotencyKey = "key-credit-con-001",
            correlationId = "corr-cred-con",
            causationId = "cause-cred-con",
            principal = securityPrincipal,
        )

        // 1. Concurrency: 8 threads concurrently submitting identical deposit credit
        val threadCount = 8
        val executor = Executors.newFixedThreadPool(threadCount)
        val startLatch = CountDownLatch(1)
        val doneLatch = CountDownLatch(threadCount)
        val results = java.util.Collections.synchronizedList(mutableListOf<CreditDepositResult>())
        val errors = java.util.Collections.synchronizedList(mutableListOf<Throwable>())

        for (i in 0 until threadCount) {
            executor.submit {
                try {
                    startLatch.await()
                    val res = service.creditDeposit(concurrentCmd)
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
        // All threads get identical result
        val firstResult = results.first()
        for (res in results) {
            assertEquals(firstResult.resultId, res.resultId)
            assertEquals(firstResult.ledgerTransactionReference, res.ledgerTransactionReference)
            assertEquals(15000L, res.creditedAmountMinorUnits)
            assertTrue(res.conserved)
        }

        // Exactly one record in store
        val storedRecord = store.findCreditByPaymentRef(tenantId, "dep-credit-con-001")
        assertNotNull(storedRecord)
        assertEquals("tx-prov-con-001", storedRecord.providerTransactionId)

        // 2. Dependency failure and retry safety: "callback failure retries safely"
        class FailingLedgerService : LedgerPostingService(clock = clock) {
            var shouldFail = true
            override fun postTransaction(command: PostTransactionCommand): PostingResult {
                if (shouldFail) {
                    throw RuntimeException("Database timeout while acquiring ledger row lock")
                }
                return super.postTransaction(command)
            }
        }

        val failingLedger = FailingLedgerService()
        val retryTestService = ServerOnlyDepositCreditService(
            ledgerPostingService = failingLedger,
            store = store,
            alertSink = alertSink,
            clock = clock,
        )

        val retryCmd = CreditDepositCommand(
            tenantId = tenantId,
            playerId = playerId,
            paymentReference = "dep-credit-retry-001",
            providerId = providerId,
            providerTransactionId = "tx-prov-retry-001",
            amountMinorUnits = 20000L,
            currencyCode = "EUR",
            source = CreditSource.SERVER_VERIFIED_WEBHOOK,
            idempotencyKey = "key-credit-retry-001",
            correlationId = "corr-retry-1",
            causationId = "cause-retry-1",
            principal = adminPrincipal,
        )

        // First attempt fails closed when ledger is down
        val depError = assertFailsWith<AuthenticationFailure.Rejected> {
            retryTestService.creditDeposit(retryCmd)
        }
        assertEquals(AuthErrorCode.DEPENDENCY_UNAVAILABLE, depError.code)
        assertTrue(alertSink.alerts.any { it.contains("DEPOSIT_CREDIT_LEDGER_POSTING_FAILED") })

        // Invariant: Zero local credit record committed on ledger failure
        assertNull(store.findCreditByPaymentRef(tenantId, "dep-credit-retry-001"))
        assertNull(store.findCreditByProviderTxId(tenantId, "tx-prov-retry-001"))

        // Dependency recovers: Safe callback retry
        failingLedger.shouldFail = false
        val recoveredResult = retryTestService.creditDeposit(retryCmd)
        assertNotNull(recoveredResult)
        assertFalse(recoveredResult.isDuplicate)
        assertEquals(20000L, recoveredResult.creditedAmountMinorUnits)
        assertTrue(recoveredResult.conserved)
        assertNotNull(store.findCreditByPaymentRef(tenantId, "dep-credit-retry-001"))
    }

    @Test
    fun `PAYMENT-005-T004 — Server-only deposit credit remains compatible, recoverable, observable, and lifecycle-safe`() {
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
        val baseCmd = CreditDepositCommand(
            tenantId = tenantId,
            playerId = playerId,
            paymentReference = "dep-credit-rec-001",
            providerId = providerId,
            providerTransactionId = "tx-prov-rec-001",
            amountMinorUnits = 30000L,
            currencyCode = "EUR",
            source = CreditSource.SERVER_VERIFIED_WEBHOOK,
            idempotencyKey = "key-credit-rec-001",
            correlationId = "corr-rec-1",
            causationId = "cause-rec-1",
            principal = adminPrincipal,
        )

        val initialResult = service.creditDeposit(baseCmd)
        assertNotNull(initialResult)
        assertFalse(initialResult.isDuplicate)

        // Export snapshot and import into fresh store instance simulating server restart
        val snapshot = store.exportSnapshot()
        val rehydratedStore = InMemoryServerDepositCreditStore()
        rehydratedStore.importSnapshot(snapshot)
        val restartedService = ServerOnlyDepositCreditService(
            ledgerPostingService = ledgerService,
            store = rehydratedStore,
            alertSink = alertSink,
            clock = clock,
        )

        // Calling with same idempotency key on rehydrated store returns identical cached outcome
        val replayedResult = restartedService.creditDeposit(baseCmd)
        assertEquals(initialResult.resultId, replayedResult.resultId)
        assertEquals(initialResult.ledgerTransactionReference, replayedResult.ledgerTransactionReference)
        assertTrue(replayedResult.isDuplicate)
        assertEquals(SERVER_ONLY_DEPOSIT_CREDIT_CONTRACT, replayedResult.semanticContract)

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
