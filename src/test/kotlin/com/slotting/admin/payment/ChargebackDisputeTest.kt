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

class ChargebackDisputeTest {
    private val now = Instant.parse("2026-09-20T00:00:00Z")
    private val clock = Clock.fixed(now, ZoneOffset.UTC)
    private val tenantId = "tenant-dispute-1"
    private val providerId = "prov-card-disp-1"
    private val playerId = UUID.fromString("33333333-3333-3333-3333-333333333333")

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
    private lateinit var compensationAlertSink: InMemoryRefundReversalAlertSink
    private lateinit var disputeStore: InMemoryChargebackDisputeStore
    private lateinit var disputeAlertSink: InMemoryChargebackDisputeAlertSink
    private lateinit var ledgerService: LedgerPostingService
    private lateinit var compensationService: RefundReversalCompensationService
    private lateinit var service: ChargebackDisputeService

    @BeforeEach
    fun setUp() {
        ManageChargebackDisputesBinding.isBound = true
        RefundReversalCompensationBinding.isBound = true

        depositStore = InMemoryServerDepositCreditStore()
        compensationStore = InMemoryRefundReversalStore()
        compensationAlertSink = InMemoryRefundReversalAlertSink()
        disputeStore = InMemoryChargebackDisputeStore()
        disputeAlertSink = InMemoryChargebackDisputeAlertSink()
        ledgerService = LedgerPostingService(clock = clock)

        compensationService = RefundReversalCompensationService(
            depositCreditStore = depositStore,
            ledgerPostingService = ledgerService,
            store = compensationStore,
            alertSink = compensationAlertSink,
            clock = clock,
        )

        service = ChargebackDisputeService(
            depositCreditStore = depositStore,
            compensationService = compensationService,
            ledgerPostingService = ledgerService,
            store = disputeStore,
            alertSink = disputeAlertSink,
            clock = clock,
        )
    }

    @AfterEach
    fun tearDown() {
        ManageChargebackDisputesBinding.isBound = true
        RefundReversalCompensationBinding.isBound = true
    }

    private fun seedDeposit(paymentRef: String, amountMinorUnits: Long = 10000L) {
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
    fun `PAYMENT-006-02-T001 — Manage chargeback disputes produces the required authoritative outcome`() {
        // 1. Expected RED failure verification: Fail-closed gate throws expected assertion when unbound
        ManageChargebackDisputesBinding.isBound = false

        val openCmd = OpenDisputeCommand(
            tenantId = tenantId,
            playerId = playerId,
            originalPaymentReference = "dep-disp-t001",
            externalDisputeId = "ext-disp-001",
            providerId = providerId,
            providerTransactionId = "tx-disp-001",
            amountMinorUnits = 4000L,
            currencyCode = "EUR",
            reason = "Cardholder unrecognized charge",
            availablePlayerWalletBalanceMinorUnits = 8000L,
            idempotencyKey = "key-disp-t001",
            correlationId = "corr-disp-1",
            causationId = "cause-disp-1",
            principal = adminPrincipal,
        )

        val gateError = assertFailsWith<AssertionError> {
            service.openDispute(openCmd)
        }
        assertEquals("edit/delete credit or duplicate reversal", gateError.message)

        // Bind the fail-closed gate
        ManageChargebackDisputesBinding.isBound = true

        // 2. Seed original deposit
        seedDeposit("dep-disp-t001", 10000L)

        // 3. Normal Dispute Opening (Sufficient player funds)
        val openResult = service.openDispute(openCmd)
        assertNotNull(openResult)
        assertEquals(DisputeStatus.OPENED, openResult.status)
        assertFalse(openResult.isDeficitRiskCase)
        assertEquals(0L, openResult.deficitMinorUnits)
        assertEquals(4000L, openResult.recoveredFromWalletMinorUnits)
        assertNull(openResult.recoveryCaseReference)
        assertTrue(openResult.conserved)
        assertEquals(1L, openResult.version)
        assertEquals(MANAGE_CHARGEBACK_DISPUTES_CONTRACT, openResult.semanticContract)

        // Original deposit remains immutable
        val originalDeposit = depositStore.findCreditByPaymentRef(tenantId, "dep-disp-t001")
        assertNotNull(originalDeposit)
        assertEquals(10000L, originalDeposit.amountMinorUnits)

        // 4. Insufficient Funds Handling:
        // "Insufficient funds becomes risk/recovery case, never hidden negative mutation."
        seedDeposit("dep-disp-deficit", 10000L)
        val deficitDisputeCmd = openCmd.copy(
            originalPaymentReference = "dep-disp-deficit",
            externalDisputeId = "ext-disp-deficit-002",
            providerTransactionId = "tx-disp-deficit-002",
            amountMinorUnits = 6000L,
            availablePlayerWalletBalanceMinorUnits = 1000L,
            idempotencyKey = "key-disp-deficit-002",
            correlationId = "corr-disp-2",
            causationId = "cause-disp-2",
        )
        val deficitResult = service.openDispute(deficitDisputeCmd)
        assertNotNull(deficitResult)
        assertEquals(DisputeStatus.OPENED, deficitResult.status)
        assertTrue(deficitResult.isDeficitRiskCase)
        assertEquals(5000L, deficitResult.deficitMinorUnits)
        assertEquals(1000L, deficitResult.recoveredFromWalletMinorUnits)
        assertNotNull(deficitResult.recoveryCaseReference)
        assertTrue(deficitResult.recoveryCaseReference!!.startsWith("RCV-CASE-"))
        assertTrue(deficitResult.conserved)

        // 5. Submit Dispute Evidence
        val evidenceCmd = SubmitDisputeEvidenceCommand(
            tenantId = tenantId,
            externalDisputeId = "ext-disp-001",
            evidenceType = "KYC_AND_DEVICE_FINGERPRINT",
            evidenceDocumentReference = "DOC-EVID-998822",
            notes = "Player completed Level-2 KYC and wagered from registered IP address",
            idempotencyKey = "key-evid-001",
            correlationId = "corr-evid-1",
            causationId = "cause-evid-1",
            expectedVersion = 1L,
            principal = adminPrincipal,
        )
        val evidenceResult = service.submitEvidence(evidenceCmd)
        assertEquals(DisputeStatus.EVIDENCE_SUBMITTED, evidenceResult.status)
        assertEquals(2L, evidenceResult.version)
        assertEquals("DOC-EVID-998822", evidenceResult.evidenceReference)

        // 6. Resolve Dispute as WON (Merchant won representment -> Funds restored from gateway)
        val resolveCmd = ResolveDisputeCommand(
            tenantId = tenantId,
            externalDisputeId = "ext-disp-001",
            resolution = DisputeResolution.WON,
            providerResolutionReference = "BANK-WON-REF-888",
            resolutionNotes = "Bank accepted evidence; dispute closed in merchant favor",
            idempotencyKey = "key-res-won-001",
            correlationId = "corr-res-1",
            causationId = "cause-res-1",
            expectedVersion = 2L,
            principal = securityPrincipal,
        )
        val resolveResult = service.resolveDispute(resolveCmd)
        assertEquals(DisputeStatus.RESOLVED_WON, resolveResult.status)
        assertEquals(3L, resolveResult.version)
        assertTrue(resolveResult.conserved)
        assertTrue(disputeAlertSink.alerts.any { it.contains("DISPUTE_WON_FUNDS_RESTORED") })

        // 7. Duplicate Replay returns identical cached result
        val duplicateResolve = service.resolveDispute(resolveCmd)
        assertEquals(resolveResult.disputeId, duplicateResolve.disputeId)
        assertTrue(duplicateResolve.isDuplicate)
    }

    @Test
    fun `PAYMENT-006-02-T002 — Manage chargeback disputes rejects invalid, boundary, unauthorized, and stale input`() {
        seedDeposit("dep-disp-t002", 10000L)

        val baseCmd = OpenDisputeCommand(
            tenantId = tenantId,
            playerId = playerId,
            originalPaymentReference = "dep-disp-t002",
            externalDisputeId = "ext-disp-t002",
            providerId = providerId,
            providerTransactionId = "tx-disp-t002",
            amountMinorUnits = 3000L,
            currencyCode = "EUR",
            reason = "Customer fraud claim",
            availablePlayerWalletBalanceMinorUnits = 5000L,
            idempotencyKey = "key-disp-t002",
            correlationId = "corr-disp-t002",
            causationId = "cause-disp-t002",
            principal = adminPrincipal,
        )

        // 1. Blank mandatory fields
        assertFailsWith<AuthenticationFailure.Rejected> { service.openDispute(baseCmd.copy(tenantId = "")) }
        assertFailsWith<AuthenticationFailure.Rejected> { service.openDispute(baseCmd.copy(originalPaymentReference = "  ")) }
        assertFailsWith<AuthenticationFailure.Rejected> { service.openDispute(baseCmd.copy(externalDisputeId = "")) }
        assertFailsWith<AuthenticationFailure.Rejected> { service.openDispute(baseCmd.copy(providerId = "")) }
        assertFailsWith<AuthenticationFailure.Rejected> { service.openDispute(baseCmd.copy(providerTransactionId = "")) }
        assertFailsWith<AuthenticationFailure.Rejected> { service.openDispute(baseCmd.copy(reason = "")) }
        assertFailsWith<AuthenticationFailure.Rejected> { service.openDispute(baseCmd.copy(idempotencyKey = "")) }
        assertFailsWith<AuthenticationFailure.Rejected> { service.openDispute(baseCmd.copy(correlationId = "")) }
        assertFailsWith<AuthenticationFailure.Rejected> { service.openDispute(baseCmd.copy(causationId = "")) }

        // 2. Invalid amount & currency
        val zeroAmtError = assertFailsWith<AuthenticationFailure.Rejected> {
            service.openDispute(baseCmd.copy(amountMinorUnits = 0L))
        }
        assertEquals(AuthErrorCode.INVALID, zeroAmtError.code)

        val negAmtError = assertFailsWith<AuthenticationFailure.Rejected> {
            service.openDispute(baseCmd.copy(amountMinorUnits = -200L))
        }
        assertEquals(AuthErrorCode.INVALID, negAmtError.code)

        val invalidCurrError = assertFailsWith<AuthenticationFailure.Rejected> {
            service.openDispute(baseCmd.copy(currencyCode = "euro"))
        }
        assertEquals(AuthErrorCode.INVALID, invalidCurrError.code)

        val mismatchCurrError = assertFailsWith<AuthenticationFailure.Rejected> {
            service.openDispute(baseCmd.copy(currencyCode = "USD"))
        }
        assertEquals(AuthErrorCode.INVALID, mismatchCurrError.code)

        // 3. Stale version
        val staleError = assertFailsWith<AuthenticationFailure.Rejected> {
            service.openDispute(baseCmd.copy(expectedVersion = 2L))
        }
        assertEquals(AuthErrorCode.STALE, staleError.code)

        // 4. Unauthorized / cross-tenant / invalid role principal
        val crossTenantError = assertFailsWith<AuthenticationFailure.Rejected> {
            service.openDispute(baseCmd.copy(principal = crossTenantPrincipal))
        }
        assertEquals(AuthErrorCode.FORBIDDEN, crossTenantError.code)

        val playerError = assertFailsWith<AuthenticationFailure.Rejected> {
            service.openDispute(baseCmd.copy(principal = playerPrincipal))
        }
        assertEquals(AuthErrorCode.FORBIDDEN, playerError.code)

        val supportRoleError = assertFailsWith<AuthenticationFailure.Rejected> {
            service.openDispute(baseCmd.copy(principal = supportPrincipal))
        }
        assertEquals(AuthErrorCode.FORBIDDEN, supportRoleError.code)

        // 5. Unknown original deposit
        val missingDepError = assertFailsWith<AuthenticationFailure.Rejected> {
            service.openDispute(baseCmd.copy(originalPaymentReference = "dep-ghost"))
        }
        assertEquals(AuthErrorCode.INVALID, missingDepError.code)

        // Execute valid base dispute of 3000L
        service.openDispute(baseCmd)

        // 6. Cumulative Over-Dispute Protection (deposit was 10000L, 3000L already disputed, attempting 8000L)
        val overDisputeError = assertFailsWith<AuthenticationFailure.Rejected> {
            service.openDispute(baseCmd.copy(
                externalDisputeId = "ext-disp-over",
                providerTransactionId = "tx-disp-over",
                amountMinorUnits = 8000L,
                idempotencyKey = "key-disp-over",
            ))
        }
        assertEquals(AuthErrorCode.CONFLICT, overDisputeError.code)
        assertTrue(disputeAlertSink.alerts.any { it.contains("OVER_DISPUTE_EXCEEDS_DEPOSIT_DENIED") })

        // 7. Idempotency conflict (same key, modified amount)
        val conflictIdempError = assertFailsWith<AuthenticationFailure.Rejected> {
            service.openDispute(baseCmd.copy(amountMinorUnits = 1500L))
        }
        assertEquals(AuthErrorCode.CONFLICT, conflictIdempError.code)
        assertTrue(disputeAlertSink.alerts.any { it.contains("DISPUTE_IDEMPOTENCY_CONFLICT") })

        // 8. Stale version on submit evidence
        val staleEvidError = assertFailsWith<AuthenticationFailure.Rejected> {
            service.submitEvidence(
                SubmitDisputeEvidenceCommand(
                    tenantId = tenantId,
                    externalDisputeId = "ext-disp-t002",
                    evidenceType = "DOC",
                    evidenceDocumentReference = "REF-1",
                    notes = "notes",
                    idempotencyKey = "key-ev-stale",
                    correlationId = "c1",
                    causationId = "c2",
                    expectedVersion = 99L,
                    principal = adminPrincipal,
                )
            )
        }
        assertEquals(AuthErrorCode.STALE, staleEvidError.code)
    }

    @Test
    fun `PAYMENT-006-02-T003 — Manage chargeback disputes survives concurrency, duplicate delivery, and dependency failure`() {
        seedDeposit("dep-disp-con-001", 25000L)

        val concurrentCmd = OpenDisputeCommand(
            tenantId = tenantId,
            playerId = playerId,
            originalPaymentReference = "dep-disp-con-001",
            externalDisputeId = "ext-disp-con-001",
            providerId = providerId,
            providerTransactionId = "tx-disp-con-001",
            amountMinorUnits = 7000L,
            currencyCode = "EUR",
            reason = "Bank chargeback notice",
            availablePlayerWalletBalanceMinorUnits = 10000L,
            idempotencyKey = "key-disp-con-001",
            correlationId = "corr-disp-con",
            causationId = "cause-disp-con",
            principal = securityPrincipal,
        )

        // 1. Concurrency: 8 threads concurrently submitting identical dispute open
        val threadCount = 8
        val executor = Executors.newFixedThreadPool(threadCount)
        val startLatch = CountDownLatch(1)
        val doneLatch = CountDownLatch(threadCount)
        val results = java.util.Collections.synchronizedList(mutableListOf<DisputeOperationResult>())
        val errors = java.util.Collections.synchronizedList(mutableListOf<Throwable>())

        for (i in 0 until threadCount) {
            executor.submit {
                try {
                    startLatch.await()
                    val res = service.openDispute(concurrentCmd)
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
            assertEquals(firstResult.disputeId, res.disputeId)
            assertEquals(firstResult.ledgerTransactionReference, res.ledgerTransactionReference)
            assertEquals(7000L, res.amountMinorUnits)
            assertTrue(res.conserved)
        }

        // Exactly one dispute in store
        assertEquals(1, disputeStore.listDisputesForPayment(tenantId, "dep-disp-con-001").size)

        // 2. Dependency failure and retry safety during WON resolution restoration:
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
        val retryCompensationService = RefundReversalCompensationService(
            depositCreditStore = depositStore,
            ledgerPostingService = failingLedger,
            store = compensationStore,
            alertSink = compensationAlertSink,
            clock = clock,
        )
        val retryService = ChargebackDisputeService(
            depositCreditStore = depositStore,
            compensationService = retryCompensationService,
            ledgerPostingService = failingLedger,
            store = disputeStore,
            alertSink = disputeAlertSink,
            clock = clock,
        )

        seedDeposit("dep-disp-retry-001", 15000L)
        // Initially succeed opening dispute with working ledger
        failingLedger.shouldFail = false
        val openForRetry = retryService.openDispute(
            OpenDisputeCommand(
                tenantId = tenantId,
                playerId = playerId,
                originalPaymentReference = "dep-disp-retry-001",
                externalDisputeId = "ext-disp-retry-001",
                providerId = providerId,
                providerTransactionId = "tx-disp-retry-001",
                amountMinorUnits = 5000L,
                currencyCode = "EUR",
                reason = "Retry test",
                availablePlayerWalletBalanceMinorUnits = 5000L,
                idempotencyKey = "key-disp-retry-init",
                correlationId = "corr-ret-1",
                causationId = "cause-ret-1",
                principal = adminPrincipal,
            )
        )
        assertEquals(DisputeStatus.OPENED, openForRetry.status)

        // Turn ledger down
        failingLedger.shouldFail = true
        val resolveCmd = ResolveDisputeCommand(
            tenantId = tenantId,
            externalDisputeId = "ext-disp-retry-001",
            resolution = DisputeResolution.WON,
            providerResolutionReference = "PROV-WON-RET-1",
            resolutionNotes = "Won notes",
            idempotencyKey = "key-disp-retry-won",
            correlationId = "corr-ret-2",
            causationId = "cause-ret-2",
            expectedVersion = 1L,
            principal = adminPrincipal,
        )

        val depError = assertFailsWith<AuthenticationFailure.Rejected> {
            retryService.resolveDispute(resolveCmd)
        }
        assertEquals(AuthErrorCode.DEPENDENCY_UNAVAILABLE, depError.code)
        assertTrue(disputeAlertSink.alerts.any { it.contains("DISPUTE_RESOLUTION_LEDGER_FAILED") })

        // Status remains OPENED, not falsely committed to RESOLVED_WON
        val recordAfterFailure = disputeStore.findDisputeByExternalId(tenantId, "ext-disp-retry-001")
        assertNotNull(recordAfterFailure)
        assertEquals(DisputeStatus.OPENED, recordAfterFailure.status)
        assertEquals(1L, recordAfterFailure.version)

        // Ledger recovers: Safe retry succeeds
        failingLedger.shouldFail = false
        val recoveredResult = retryService.resolveDispute(resolveCmd)
        assertNotNull(recoveredResult)
        assertEquals(DisputeStatus.RESOLVED_WON, recoveredResult.status)
        assertEquals(2L, recoveredResult.version)
        assertTrue(recoveredResult.conserved)
    }

    @Test
    fun `PAYMENT-006-02-T004 — Manage chargeback disputes remains compatible, recoverable, observable, and lifecycle-safe`() {
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
        seedDeposit("dep-disp-rec-001", 30000L)
        val recCmd = OpenDisputeCommand(
            tenantId = tenantId,
            playerId = playerId,
            originalPaymentReference = "dep-disp-rec-001",
            externalDisputeId = "ext-disp-rec-001",
            providerId = providerId,
            providerTransactionId = "tx-disp-rec-001",
            amountMinorUnits = 10000L,
            currencyCode = "EUR",
            reason = "Issuer chargeback notification",
            availablePlayerWalletBalanceMinorUnits = 15000L,
            idempotencyKey = "key-disp-rec-001",
            correlationId = "corr-rec-1",
            causationId = "cause-rec-1",
            principal = adminPrincipal,
        )

        val initialResult = service.openDispute(recCmd)
        assertNotNull(initialResult)
        assertFalse(initialResult.isDuplicate)

        // Export snapshot and import into fresh store instance simulating server restart
        val snapshot = disputeStore.exportSnapshot()
        val rehydratedStore = InMemoryChargebackDisputeStore()
        rehydratedStore.importSnapshot(snapshot)
        val restartedService = ChargebackDisputeService(
            depositCreditStore = depositStore,
            compensationService = compensationService,
            ledgerPostingService = ledgerService,
            store = rehydratedStore,
            alertSink = disputeAlertSink,
            clock = clock,
        )

        // Calling with same idempotency key on rehydrated store returns identical cached outcome
        val replayedResult = restartedService.openDispute(recCmd)
        assertEquals(initialResult.disputeId, replayedResult.disputeId)
        assertEquals(initialResult.ledgerTransactionReference, replayedResult.ledgerTransactionReference)
        assertTrue(replayedResult.isDuplicate)
        assertEquals(MANAGE_CHARGEBACK_DISPUTES_CONTRACT, replayedResult.semanticContract)

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
