package com.slotting.admin.withdrawal

import com.slotting.admin.auth.*
import com.slotting.admin.ledger.*
import com.slotting.admin.provider.port.*
import com.slotting.admin.provider.port.adapters.*
import org.junit.jupiter.api.Test
import java.time.Clock
import java.time.Duration
import java.time.Instant
import java.time.ZoneOffset
import java.util.UUID
import java.util.concurrent.CountDownLatch
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit
import kotlin.test.*

/**
 * TC-015 TDD Contract Test Suite:
 * Dispatch payouts from durable intent and reconcile ambiguous outcomes.
 */
class DurablePayoutDispatchContractTest {

    private val now = Instant.parse("2026-09-25T14:00:00Z")
    private val clock = Clock.fixed(now, ZoneOffset.UTC)

    private val playerAId = UUID.fromString("00000000-0000-0000-0000-000000000001")

    private val adminPrincipal = AuthenticatedPrincipal(
        id = "admin-payout-1",
        tenantId = "tenant-pk-1",
        kind = PrincipalKind.ADMIN,
        roles = setOf(AdminRole.SUPER_ADMIN),
    )

    private val auditorPrincipal = AuthenticatedPrincipal(
        id = "auditor-read-only",
        tenantId = "tenant-pk-1",
        kind = PrincipalKind.ADMIN,
        roles = setOf(AdminRole.AUDITOR),
    )

    private val sampleConfig = ProviderConfiguration(
        providerId = "ADVERSARIAL_TEST",
        environment = ProviderEnvironment.SANDBOX,
        baseUrl = "https://sandbox.api.test/v1",
    )

    private val sampleCredentials = ProviderCredentials(
        merchantId = "MERCHANT-01",
        apiKey = "api-key-test",
    )

    private fun sampleApprovedRequest(
        requestId: UUID = UUID.randomUUID(),
        reservationId: UUID = UUID.randomUUID(),
        grossAmount: Long = 50_000L,
        netPayout: Long = 47_500L,
        fee: Long = 2_500L,
    ) = AuthoritativeWithdrawalRequest(
        requestId = requestId,
        tenantId = "tenant-pk-1",
        ownerId = playerAId,
        quoteId = UUID.randomUUID(),
        reservationId = reservationId,
        methodId = "BANK_PK",
        destinationId = UUID.randomUUID(),
        destinationReference = "PK36SCBL0000001123456701",
        grossAmountMinorUnits = grossAmount,
        feeMinorUnits = fee,
        netPayoutAmountMinorUnits = netPayout,
        currencyCode = "PKR",
        stepUpAssertionId = UUID.randomUUID(),
        immutableDigest = "digest-$requestId",
        status = WithdrawalRequestStatus.REQUESTED,
        reviewState = WithdrawalReviewState.APPROVED,
        dualControlReceiptId = UUID.randomUUID(),
        idempotencyKey = "req-idemp-$requestId",
        requestVersion = 2L,
        createdAt = now.minus(Duration.ofMinutes(10)),
        updatedAt = now.minus(Duration.ofMinutes(5)),
    )

    // =========================================================================
    // 1. Pre-dispatch Persistence Invariant
    // =========================================================================

    @Test
    fun `test01 no provider call occurs until durable dispatch intent is committed`() {
        val dispatchStore = InMemoryPayoutDispatchStore()
        val withdrawalStore = InMemoryAuthoritativeWithdrawalStore()
        withdrawalStore.setAuthoritativeBalance("tenant-pk-1", playerAId, "PKR", 100_000L)
        val ledgerService = LedgerPostingService(InMemoryLedgerJournalStore(), clock = clock)

        val adapter = AdversarialTestPaymentAdapter("ADVERSARIAL_TEST")
        var providerCallCount = 0
        val wrappedAdapter = object : PaymentProviderPort by adapter {
            override fun payout(
                command: ProviderPayoutCommand,
                config: ProviderConfiguration,
                credentials: ProviderCredentials?
            ): ProviderOutcome {
                // Assert that the intent MUST already exist in the store BEFORE this call is made
                val existing = dispatchStore.findIntentByRequestId("tenant-pk-1", UUID.fromString(command.metadata["requestId"]))
                assertNotNull(existing, "Intent must exist in durable store before provider call")
                assertEquals(PayoutDispatchStatus.SENT_PENDING, existing.status)
                providerCallCount++
                return adapter.payout(command, config, credentials)
            }
        }

        val service = DurablePayoutDispatchService(
            dispatchStore = dispatchStore,
            withdrawalStore = withdrawalStore,
            ledgerPostingService = ledgerService,
            providerPorts = mapOf("ONE_LINK_IBFT" to wrappedAdapter),
            credentialsResolver = { _, _ -> sampleCredentials },
            configResolver = { _, _ -> sampleConfig },
            clock = clock,
        )

        val request = sampleApprovedRequest()
        withdrawalStore.saveRequest(request)

        // Stage intent
        val staged = service.stageDispatchIntent(
            StagePayoutDispatchCommand(
                tenantId = "tenant-pk-1",
                requestId = request.requestId,
                providerId = "ONE_LINK_IBFT",
                idempotencyKey = "stage-payout-1",
            )
        )

        assertEquals(PayoutDispatchStatus.DISPATCH_READY, staged.status)
        assertEquals(0, providerCallCount, "No provider call occurred during staging")

        // Now dispatch via worker
        val dispatchResult = service.dispatchNext(workerId = "worker-1", leaseDuration = Duration.ofMinutes(5))
        assertNotNull(dispatchResult)
        assertEquals(PayoutDispatchStatus.SUCCEEDED, dispatchResult.status)
        assertEquals(1, providerCallCount)
    }

    // =========================================================================
    // 2. Timeout & Ambiguity Invariant: Funds Remain Reserved
    // =========================================================================

    @Test
    fun `test02 provider timeout keeps funds reserved and transitions to AMBIGUOUS_RECONCILING`() {
        val dispatchStore = InMemoryPayoutDispatchStore()
        val withdrawalStore = InMemoryAuthoritativeWithdrawalStore()
        withdrawalStore.setAuthoritativeBalance("tenant-pk-1", playerAId, "PKR", 100_000L)
        val ledgerService = LedgerPostingService(InMemoryLedgerJournalStore(), clock = clock)

        val adapter = AdversarialTestPaymentAdapter(
            providerId = "ADVERSARIAL_TEST",
            simulationMode = AdversarialSimulationMode.TIMEOUT_AFTER_DISPATCH,
        )

        val service = DurablePayoutDispatchService(
            dispatchStore = dispatchStore,
            withdrawalStore = withdrawalStore,
            ledgerPostingService = ledgerService,
            providerPorts = mapOf("ONE_LINK_IBFT" to adapter),
            credentialsResolver = { _, _ -> sampleCredentials },
            configResolver = { _, _ -> sampleConfig },
            clock = clock,
        )

        val request = sampleApprovedRequest()
        withdrawalStore.saveRequest(request)

        service.stageDispatchIntent(
            StagePayoutDispatchCommand(
                tenantId = "tenant-pk-1",
                requestId = request.requestId,
                providerId = "ONE_LINK_IBFT",
                idempotencyKey = "stage-timeout-1",
            )
        )

        val result = service.dispatchNext(workerId = "worker-1", leaseDuration = Duration.ofMinutes(5))
        assertNotNull(result)
        assertEquals(PayoutDispatchStatus.AMBIGUOUS_RECONCILING, result.status)

        // Verify stored intent status
        val stored = dispatchStore.findIntentByRequestId("tenant-pk-1", request.requestId)!!
        assertEquals(PayoutDispatchStatus.AMBIGUOUS_RECONCILING, stored.status)
        assertNull(stored.ledgerTransactionReference, "No terminal ledger transaction on timeout")

        // Verify funds remain reserved (not released)
        val availableBal = withdrawalStore.getAuthoritativeBalance("tenant-pk-1", playerAId, "PKR")
        assertEquals(100_000L, availableBal) // not credited back to available
    }

    // =========================================================================
    // 3. Late Success via Reconciliation
    // =========================================================================

    @Test
    fun `test03 reconciliation resolves ambiguous intent on late success and finalizes ledger once`() {
        val dispatchStore = InMemoryPayoutDispatchStore()
        val withdrawalStore = InMemoryAuthoritativeWithdrawalStore()
        val ledgerStore = InMemoryLedgerJournalStore()
        val ledgerService = LedgerPostingService(ledgerStore, clock = clock)

        val adapter = AdversarialTestPaymentAdapter("ADVERSARIAL_TEST")
        adapter.simulationMode = AdversarialSimulationMode.TIMEOUT_AFTER_DISPATCH

        val service = DurablePayoutDispatchService(
            dispatchStore = dispatchStore,
            withdrawalStore = withdrawalStore,
            ledgerPostingService = ledgerService,
            providerPorts = mapOf("ONE_LINK_IBFT" to adapter),
            credentialsResolver = { _, _ -> sampleCredentials },
            configResolver = { _, _ -> sampleConfig },
            clock = clock,
        )

        val request = sampleApprovedRequest()
        withdrawalStore.saveRequest(request)

        val staged = service.stageDispatchIntent(
            StagePayoutDispatchCommand(
                tenantId = "tenant-pk-1",
                requestId = request.requestId,
                providerId = "ONE_LINK_IBFT",
                idempotencyKey = "stage-late-success",
            )
        )

        service.dispatchNext(workerId = "worker-1", leaseDuration = Duration.ofMinutes(5))

        // Upstream provider now confirms payment succeeded
        adapter.simulationMode = AdversarialSimulationMode.NORMAL_SUCCESS

        val reconcileResult = service.reconcilePayout(
            tenantId = "tenant-pk-1",
            intentId = staged.intentId,
            actorId = "reconcile-worker",
        )

        assertEquals(PayoutDispatchStatus.SUCCEEDED, reconcileResult.newStatus)
        assertNotNull(reconcileResult.ledgerTransactionReference)

        // Verify stored intent is SUCCEEDED
        val stored = dispatchStore.findIntent("tenant-pk-1", staged.intentId)!!
        assertEquals(PayoutDispatchStatus.SUCCEEDED, stored.status)
        assertEquals(reconcileResult.ledgerTransactionReference, stored.ledgerTransactionReference)

        // Reconciling again does not duplicate ledger posting
        val secondReconcile = service.reconcilePayout(
            tenantId = "tenant-pk-1",
            intentId = staged.intentId,
            actorId = "reconcile-worker",
        )
        assertEquals(PayoutDispatchStatus.SUCCEEDED, secondReconcile.newStatus)
        assertEquals(reconcileResult.ledgerTransactionReference, secondReconcile.ledgerTransactionReference)
    }

    // =========================================================================
    // 4. Late Failure via Reconciliation (Compensating Release)
    // =========================================================================

    @Test
    fun `test04 reconciliation resolves ambiguous intent on late failure and releases reserved funds`() {
        val dispatchStore = InMemoryPayoutDispatchStore()
        val withdrawalStore = InMemoryAuthoritativeWithdrawalStore()
        withdrawalStore.setAuthoritativeBalance("tenant-pk-1", playerAId, "PKR", 50_000L)
        val ledgerService = LedgerPostingService(InMemoryLedgerJournalStore(), clock = clock)

        val adapter = AdversarialTestPaymentAdapter("ADVERSARIAL_TEST")
        adapter.simulationMode = AdversarialSimulationMode.TIMEOUT_AFTER_DISPATCH

        val service = DurablePayoutDispatchService(
            dispatchStore = dispatchStore,
            withdrawalStore = withdrawalStore,
            ledgerPostingService = ledgerService,
            providerPorts = mapOf("ONE_LINK_IBFT" to adapter),
            credentialsResolver = { _, _ -> sampleCredentials },
            configResolver = { _, _ -> sampleConfig },
            clock = clock,
        )

        val request = sampleApprovedRequest()
        withdrawalStore.saveRequest(request)

        val staged = service.stageDispatchIntent(
            StagePayoutDispatchCommand(
                tenantId = "tenant-pk-1",
                requestId = request.requestId,
                providerId = "ONE_LINK_IBFT",
                idempotencyKey = "stage-late-failure",
            )
        )

        service.dispatchNext(workerId = "worker-1", leaseDuration = Duration.ofMinutes(5))

        // Upstream provider confirms definitive decline
        adapter.simulationMode = AdversarialSimulationMode.EXPLICIT_DECLINE

        val reconcileResult = service.reconcilePayout(
            tenantId = "tenant-pk-1",
            intentId = staged.intentId,
            actorId = "reconcile-worker",
        )

        assertEquals(PayoutDispatchStatus.FAILED_FINAL, reconcileResult.newStatus)

        // Stored intent is FAILED_FINAL
        val stored = dispatchStore.findIntent("tenant-pk-1", staged.intentId)!!
        assertEquals(PayoutDispatchStatus.FAILED_FINAL, stored.status)

        // Compensating release: 50,000 gross amount returned to available balance (50,000 + 50,000 = 100,000)
        val availableBal = withdrawalStore.getAuthoritativeBalance("tenant-pk-1", playerAId, "PKR")
        assertEquals(100_000L, availableBal)
    }

    // =========================================================================
    // 5. Worker Crash & Lease Expiry Recovery
    // =========================================================================

    @Test
    fun `test05 worker crash and lease expiry allows secondary worker to safely recover intent`() {
        val dispatchStore = InMemoryPayoutDispatchStore(clock = clock)
        val withdrawalStore = InMemoryAuthoritativeWithdrawalStore()
        val ledgerService = LedgerPostingService(InMemoryLedgerJournalStore(), clock = clock)

        val service = DurablePayoutDispatchService(
            dispatchStore = dispatchStore,
            withdrawalStore = withdrawalStore,
            ledgerPostingService = ledgerService,
            providerPorts = mapOf("ONE_LINK_IBFT" to AdversarialTestPaymentAdapter("ADVERSARIAL_TEST")),
            credentialsResolver = { _, _ -> sampleCredentials },
            configResolver = { _, _ -> sampleConfig },
            clock = clock,
        )

        val request = sampleApprovedRequest()
        withdrawalStore.saveRequest(request)

        val staged = service.stageDispatchIntent(
            StagePayoutDispatchCommand(
                tenantId = "tenant-pk-1",
                requestId = request.requestId,
                providerId = "ONE_LINK_IBFT",
                idempotencyKey = "stage-crash-1",
            )
        )

        // Worker 1 acquires lease with 2-second timeout, but crashes before dispatch completes
        dispatchStore.acquireLease(
            tenantId = "tenant-pk-1",
            intentId = staged.intentId,
            workerId = "worker-crashed",
            leaseExpiresAt = now.plusSeconds(2),
        )

        // Worker 2 cannot immediately steal active lease
        val attemptWhileLeased = dispatchStore.acquireLease(
            tenantId = "tenant-pk-1",
            intentId = staged.intentId,
            workerId = "worker-2",
            leaseExpiresAt = now.plus(Duration.ofMinutes(5)),
        )
        assertFalse(attemptWhileLeased, "Worker 2 cannot acquire actively leased intent")

        // Fast-forward clock past lease expiration
        val futureClock = Clock.fixed(now.plusSeconds(10), ZoneOffset.UTC)
        val recoveredService = DurablePayoutDispatchService(
            dispatchStore = dispatchStore,
            withdrawalStore = withdrawalStore,
            ledgerPostingService = ledgerService,
            providerPorts = mapOf("ONE_LINK_IBFT" to AdversarialTestPaymentAdapter("ADVERSARIAL_TEST")),
            credentialsResolver = { _, _ -> sampleCredentials },
            configResolver = { _, _ -> sampleConfig },
            clock = futureClock,
        )

        // Worker 2 safely acquires expired lease and finishes dispatch
        val result = recoveredService.dispatchNext(workerId = "worker-2", leaseDuration = Duration.ofMinutes(5))
        assertNotNull(result)
        assertEquals(PayoutDispatchStatus.SUCCEEDED, result.status)
    }

    // =========================================================================
    // 6. Manual Review Escalation by Authorized Operator
    // =========================================================================

    @Test
    fun `test06 stuck ambiguous payout enters MANUAL_REVIEW and operator escalates without balance write`() {
        val dispatchStore = InMemoryPayoutDispatchStore()
        val withdrawalStore = InMemoryAuthoritativeWithdrawalStore()
        val ledgerService = LedgerPostingService(InMemoryLedgerJournalStore(), clock = clock)

        val service = DurablePayoutDispatchService(
            dispatchStore = dispatchStore,
            withdrawalStore = withdrawalStore,
            ledgerPostingService = ledgerService,
            providerPorts = mapOf("ONE_LINK_IBFT" to AdversarialTestPaymentAdapter("ADVERSARIAL_TEST")),
            credentialsResolver = { _, _ -> sampleCredentials },
            configResolver = { _, _ -> sampleConfig },
            clock = clock,
        )

        val request = sampleApprovedRequest()
        withdrawalStore.saveRequest(request)

        val staged = service.stageDispatchIntent(
            StagePayoutDispatchCommand(
                tenantId = "tenant-pk-1",
                requestId = request.requestId,
                providerId = "ONE_LINK_IBFT",
                idempotencyKey = "stage-manual-review",
            )
        )

        // Mark intent as stuck in AMBIGUOUS_RECONCILING with attemptCount >= threshold (e.g. 5)
        dispatchStore.updateIntent(
            staged.copy(
                status = PayoutDispatchStatus.AMBIGUOUS_RECONCILING,
                attemptCount = 5,
            ),
            expectedVersion = staged.serverVersion,
        )

        // Escalation to MANUAL_REVIEW
        val escalation = service.escalateStuckIntent(staged.intentId, "tenant-pk-1")
        assertEquals(PayoutDispatchStatus.MANUAL_REVIEW, escalation.status)

        // Auditor cannot resolve manual review
        assertFailsWith<AuthenticationFailure.Rejected> {
            service.operatorResolveManualReview(
                OperatorPayoutResolutionCommand(
                    principal = auditorPrincipal,
                    sessionId = "sess-aud",
                    tenantId = "tenant-pk-1",
                    intentId = staged.intentId,
                    resolution = OperatorResolutionAction.FORCE_SUCCESS,
                    notes = "Auditor attempt",
                )
            )
        }.also { assertEquals(AuthErrorCode.FORBIDDEN, it.code) }

        // Super Admin resolves manual review to FORCE_SUCCESS
        val resolved = service.operatorResolveManualReview(
            OperatorPayoutResolutionCommand(
                principal = adminPrincipal,
                sessionId = "sess-admin",
                tenantId = "tenant-pk-1",
                intentId = staged.intentId,
                resolution = OperatorResolutionAction.FORCE_SUCCESS,
                notes = "Bank statement confirmed manual settlement",
            )
        )

        assertEquals(PayoutDispatchStatus.SUCCEEDED, resolved.status)
        assertNotNull(resolved.ledgerTransactionReference)
    }

    // =========================================================================
    // 7. Concurrent Worker Dispatch Safety
    // =========================================================================

    @Test
    fun `test07 concurrent workers dispatch intent exactly once without double dispatch`() {
        val dispatchStore = InMemoryPayoutDispatchStore()
        val withdrawalStore = InMemoryAuthoritativeWithdrawalStore()
        val ledgerService = LedgerPostingService(InMemoryLedgerJournalStore(), clock = clock)

        var dispatchInvocations = 0
        val countingAdapter = object : PaymentProviderPort by AdversarialTestPaymentAdapter("ADVERSARIAL_TEST") {
            override fun payout(
                command: ProviderPayoutCommand,
                config: ProviderConfiguration,
                credentials: ProviderCredentials?
            ): ProviderOutcome {
                synchronized(this) {
                    dispatchInvocations++
                }
                return ProviderOutcome.accepted(command.operationId, "ref-${command.operationId}")
            }
        }

        val service = DurablePayoutDispatchService(
            dispatchStore = dispatchStore,
            withdrawalStore = withdrawalStore,
            ledgerPostingService = ledgerService,
            providerPorts = mapOf("ONE_LINK_IBFT" to countingAdapter),
            credentialsResolver = { _, _ -> sampleCredentials },
            configResolver = { _, _ -> sampleConfig },
            clock = clock,
        )

        val request = sampleApprovedRequest()
        withdrawalStore.saveRequest(request)

        service.stageDispatchIntent(
            StagePayoutDispatchCommand(
                tenantId = "tenant-pk-1",
                requestId = request.requestId,
                providerId = "ONE_LINK_IBFT",
                idempotencyKey = "stage-conc-worker",
            )
        )

        val threadCount = 6
        val executor = Executors.newFixedThreadPool(threadCount)
        val latch = CountDownLatch(1)

        val tasks = (1..threadCount).map { i ->
            {
                latch.await()
                try {
                    service.dispatchNext(workerId = "worker-$i", leaseDuration = Duration.ofMinutes(5))
                } catch (e: Exception) {
                    e
                }
            }
        }

        val futures = tasks.map { executor.submit(it) }
        latch.countDown()
        val results = futures.map { it.get() }
        executor.shutdown()
        executor.awaitTermination(5, TimeUnit.SECONDS)

        val successfulDispatches = results.filterIsInstance<PayoutDispatchResult>()
        assertEquals(1, successfulDispatches.size, "Exactly one worker leased and dispatched the intent")
        assertEquals(1, dispatchInvocations, "Provider payout endpoint was invoked exactly once")
    }
}
