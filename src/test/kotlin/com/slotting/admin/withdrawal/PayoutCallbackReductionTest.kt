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

class PayoutCallbackReductionTest {
    private val now = Instant.parse("2026-09-20T20:30:00Z")
    private val clock = Clock.fixed(now, ZoneOffset.UTC)

    private val tenantId = "tenant-cb-test"
    private val providerId = "provider-clearstream"
    private val providerSecret = "secret-super-safe-payout-webhook-key-99"

    private val playerAId = UUID.randomUUID()
    private val playerBId = UUID.randomUUID()
    private val playerCId = UUID.randomUUID()

    private lateinit var callbackStore: InMemoryPayoutCallbackStore
    private lateinit var payoutStore: InMemoryPayoutExecutionStore
    private lateinit var reservationStore: InMemoryWithdrawalReservationStore
    private lateinit var bucketStore: InMemoryBalanceBucketsStore
    private lateinit var secretResolver: InMemoryProviderSecretResolver
    private lateinit var observability: InMemoryPayoutCallbackObservability
    private lateinit var service: PayoutCallbackReductionService

    @BeforeEach
    fun setUp() {
        PayoutCallbackReductionBinding.isBound = true
        callbackStore = InMemoryPayoutCallbackStore()
        payoutStore = InMemoryPayoutExecutionStore()
        reservationStore = InMemoryWithdrawalReservationStore()
        bucketStore = InMemoryBalanceBucketsStore()
        secretResolver = InMemoryProviderSecretResolver()
        secretResolver.registerSecret(tenantId, providerId, providerSecret)
        observability = InMemoryPayoutCallbackObservability()

        service = PayoutCallbackReductionService(
            callbackStore = callbackStore,
            payoutStore = payoutStore,
            reservationStore = reservationStore,
            bucketStore = bucketStore,
            secretResolver = secretResolver,
            observability = observability,
            clock = clock
        )
    }

    @AfterEach
    fun tearDown() {
        PayoutCallbackReductionBinding.isBound = true
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
        status: PayoutExecutionStatus = PayoutExecutionStatus.PENDING_RECONCILIATION,
        providerTxId: String? = null
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
            providerTransactionId = providerTxId ?: "tx-ext-${UUID.randomUUID()}",
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

    private fun buildCallbackCommand(
        payoutId: UUID,
        statusStr: String,
        deliverySequence: Long = 1L,
        idempotencyKey: String = "cb-idemp-${UUID.randomUUID()}",
        timestamp: Instant = now,
        tamperedSignature: String? = null
    ): ProcessPayoutCallbackCommand {
        val payload = """{"payoutId":"$payoutId","status":"$statusStr","eventTimestamp":"$timestamp"}"""
        val tsStr = timestamp.epochSecond.toString()
        val signature = tamperedSignature ?: PayoutCallbackReductionService.computeHmacSha256(providerSecret, "$tsStr.$payload")

        return ProcessPayoutCallbackCommand(
            tenantId = tenantId,
            providerId = providerId,
            signatureHeader = signature,
            timestampHeader = tsStr,
            rawPayload = payload,
            deliverySequence = deliverySequence,
            idempotencyKey = idempotencyKey,
            correlationId = "corr-cb-${UUID.randomUUID()}",
            causationId = "caus-cb-${UUID.randomUUID()}"
        )
    }

    // =========================================================================
    // WITHDRAW-003-02-T001 — Produces required authoritative outcome
    // =========================================================================
    @Test
    fun `WITHDRAW-003-02-T001 — Authenticate and reduce payout callbacks produces the required authoritative outcome`() {
        val walletA = setupWallet(playerAId, availableMinorUnits = 100_000L, pendingMinorUnits = 50_000L)
        val resA = setupReservation(playerAId, walletA.walletId, 50_000L)
        val payoutA = setupPayout(playerAId, walletA.walletId, resA.reservationId, 50_000L)

        // 1. Definitive SUCCESS callback -> captures lock
        val cmdSuccess = buildCallbackCommand(payoutA.payoutId, "COMPLETED", deliverySequence = 1L)
        val resultSuccess = service.processCallback(cmdSuccess)

        assertEquals(PayoutExecutionStatus.CAPTURED, resultSuccess.currentStatus)
        assertEquals(WithdrawalReservationState.CAPTURED, resultSuccess.reservationState)
        assertEquals(PayoutCallbackAction.CAPTURED, resultSuccess.action)
        assertFalse(resultSuccess.isDuplicate)
        assertTrue(resultSuccess.debitsEqualCredits)
        assertFalse(resultSuccess.hasAndroidDbImpact)
        assertFalse(resultSuccess.hasAndroidLifecycleClaim)
        assertEquals("PAYOUT_CALLBACK_AUTHENTICATED_AND_CAPTURED", resultSuccess.auditEvent.type)
        assertEquals("payout.callback.captured", resultSuccess.outboxEvent.type)

        // Wallet check: pending funds permanently deducted; available untouched
        assertEquals(0L, resultSuccess.walletBalance?.cash?.pendingWithdrawalMinorUnits)
        assertEquals(100_000L, resultSuccess.walletBalance?.cash?.availableMinorUnits)

        // 2. Definitive REJECTION callback -> only definitive rejection releases
        val walletB = setupWallet(playerBId, availableMinorUnits = 80_000L, pendingMinorUnits = 40_000L)
        val resB = setupReservation(playerBId, walletB.walletId, 40_000L)
        val payoutB = setupPayout(playerBId, walletB.walletId, resB.reservationId, 40_000L)

        val cmdReject = buildCallbackCommand(payoutB.payoutId, "REJECTED", deliverySequence = 1L)
        val resultReject = service.processCallback(cmdReject)

        assertEquals(PayoutExecutionStatus.RELEASED, resultReject.currentStatus)
        assertEquals(WithdrawalReservationState.RELEASED, resultReject.reservationState)
        assertEquals(PayoutCallbackAction.RELEASED, resultReject.action)
        assertTrue(resultReject.debitsEqualCredits)
        assertEquals("PAYOUT_CALLBACK_AUTHENTICATED_AND_RELEASED", resultReject.auditEvent.type)
        assertEquals("payout.callback.released", resultReject.outboxEvent.type)

        // Wallet check: pending funds refunded back to available
        assertEquals(0L, resultReject.walletBalance?.cash?.pendingWithdrawalMinorUnits)
        assertEquals(120_000L, resultReject.walletBalance?.cash?.availableMinorUnits)

        val persistedResB = reservationStore.findById(resB.reservationId)
        assertNotNull(persistedResB)
        assertEquals(WithdrawalReleaseReason.PROVIDER_REJECTED, persistedResB.releaseReason)

        // 3. Transient / IN_FLIGHT callback -> Unknown stays pending/reconcile
        val walletC = setupWallet(playerCId, availableMinorUnits = 60_000L, pendingMinorUnits = 20_000L)
        val resC = setupReservation(playerCId, walletC.walletId, 20_000L)
        val payoutC = setupPayout(playerCId, walletC.walletId, resC.reservationId, 20_000L)

        val cmdInFlight = buildCallbackCommand(payoutC.payoutId, "IN_FLIGHT", deliverySequence = 1L)
        val resultInFlight = service.processCallback(cmdInFlight)

        assertEquals(PayoutExecutionStatus.PENDING_RECONCILIATION, resultInFlight.currentStatus)
        assertEquals(WithdrawalReservationState.RESERVED, resultInFlight.reservationState)
        assertEquals(PayoutCallbackAction.HELD_PENDING, resultInFlight.action)
        assertTrue(resultInFlight.debitsEqualCredits)
        // No balance change
        val currentWalletC = bucketStore.findWalletById(tenantId, walletC.walletId)
        assertEquals(20_000L, currentWalletC?.cash?.pendingWithdrawalMinorUnits)
        assertEquals(60_000L, currentWalletC?.cash?.availableMinorUnits)
    }

    // =========================================================================
    // WITHDRAW-003-02-T002 — Rejects invalid, boundary, unauthorized, and stale input
    // =========================================================================
    @Test
    fun `WITHDRAW-003-02-T002 — Authenticate and reduce payout callbacks rejects invalid, boundary, unauthorized, and stale input`() {
        val wallet = setupWallet(playerAId, 100_000L, 50_000L)
        val res = setupReservation(playerAId, wallet.walletId, 50_000L)
        val payout = setupPayout(playerAId, wallet.walletId, res.reservationId, 50_000L)

        // 1. Tampered / invalid HMAC signature
        val cmdTampered = buildCallbackCommand(payout.payoutId, "COMPLETED", tamperedSignature = "invalid-signature-hash")
        assertFailsWith<BadCallbackSignatureException> {
            service.processCallback(cmdTampered)
        }

        // 2. Blank signature
        val cmdBlankSig = cmdTampered.copy(signatureHeader = " ")
        assertFailsWith<BadCallbackSignatureException> {
            service.processCallback(cmdBlankSig)
        }

        // 3. Expired timestamp (> 300s old)
        val cmdExpired = buildCallbackCommand(payout.payoutId, "COMPLETED", timestamp = now.minusSeconds(305))
        assertFailsWith<ExpiredCallbackTimestampException> {
            service.processCallback(cmdExpired)
        }

        // 4. Future timestamp (> 60s in future)
        val cmdFuture = buildCallbackCommand(payout.payoutId, "COMPLETED", timestamp = now.plusSeconds(70))
        assertFailsWith<ExpiredCallbackTimestampException> {
            service.processCallback(cmdFuture)
        }

        // 5. Unknown provider ID
        val cmdUnknownProv = buildCallbackCommand(payout.payoutId, "COMPLETED").copy(providerId = "unknown-payout-provider")
        assertFailsWith<UnknownPayoutProviderException> {
            service.processCallback(cmdUnknownProv)
        }

        // 6. Unknown payout execution
        val cmdUnknownPayout = buildCallbackCommand(UUID.randomUUID(), "COMPLETED")
        assertFailsWith<PayoutExecutionNotFoundException> {
            service.processCallback(cmdUnknownPayout)
        }

        // 7. Stale sequence reduction: process seq 2 then seq 1
        val cmdSeq2 = buildCallbackCommand(payout.payoutId, "COMPLETED", deliverySequence = 2L)
        service.processCallback(cmdSeq2)

        val cmdSeq1Stale = buildCallbackCommand(payout.payoutId, "IN_FLIGHT", deliverySequence = 1L)
        assertFailsWith<StaleCallbackSequenceException> {
            service.processCallback(cmdSeq1Stale)
        }

        // 8. Terminal state conflict: cannot release already CAPTURED payout
        val cmdConflictReject = buildCallbackCommand(payout.payoutId, "REJECTED", deliverySequence = 3L)
        assertFailsWith<PayoutCallbackConflictException> {
            service.processCallback(cmdConflictReject)
        }

        // Verify authoritative state and balance were preserved under conflict
        val currentPayout = payoutStore.findById(tenantId, payout.payoutId)
        assertEquals(PayoutExecutionStatus.CAPTURED, currentPayout?.status)
    }

    // =========================================================================
    // WITHDRAW-003-02-T003 — Survives concurrency, duplicate delivery, and dependency failure
    // =========================================================================
    @Test
    fun `WITHDRAW-003-02-T003 — Authenticate and reduce payout callbacks survives concurrency, duplicate delivery, and dependency failure`() {
        val wallet = setupWallet(playerAId, 100_000L, 50_000L)
        val res = setupReservation(playerAId, wallet.walletId, 50_000L)
        val payout = setupPayout(playerAId, wallet.walletId, res.reservationId, 50_000L)

        // 1. Concurrent duplicate delivery race
        val executor = Executors.newFixedThreadPool(4)
        val cmd = buildCallbackCommand(payout.payoutId, "COMPLETED", deliverySequence = 1L, idempotencyKey = "shared-cb-idemp-001")

        val tasks = (1..8).map {
            Callable { service.processCallback(cmd) }
        }
        val futures = executor.invokeAll(tasks)
        executor.shutdown()

        val results = futures.map { it.get() }
        assertEquals(8, results.size)
        // All results point to the same CAPTURED state
        assertTrue(results.all { it.currentStatus == PayoutExecutionStatus.CAPTURED })

        // Check wallet balance was deducted exactly once, never double-debited
        val finalWallet = bucketStore.findWalletById(tenantId, wallet.walletId)
        assertEquals(0L, finalWallet?.cash?.pendingWithdrawalMinorUnits)
        assertEquals(100_000L, finalWallet?.cash?.availableMinorUnits)

        // 2. Changed payload with same idempotency key causes conflict
        val conflictingPayload = """{"payoutId":"${payout.payoutId}","status":"REJECTED","eventTimestamp":"$now"}"""
        val conflictingSig = PayoutCallbackReductionService.computeHmacSha256(providerSecret, "${now.epochSecond}.$conflictingPayload")
        val conflictingCmd = cmd.copy(
            rawPayload = conflictingPayload,
            signatureHeader = conflictingSig
        )
        assertFailsWith<PayoutCallbackConflictException> {
            service.processCallback(conflictingCmd)
        }

        // 3. Out-of-order delivery sequence reduction:
        // Create another payout
        val walletB = setupWallet(playerBId, 200_000L, 80_000L)
        val resB = setupReservation(playerBId, walletB.walletId, 80_000L)
        val payoutB = setupPayout(playerBId, walletB.walletId, resB.reservationId, 80_000L)

        // Callback 2 (COMPLETED) arrives before Callback 1 (IN_FLIGHT)
        val cmdBSeq2 = buildCallbackCommand(payoutB.payoutId, "COMPLETED", deliverySequence = 2L)
        val resBResult = service.processCallback(cmdBSeq2)
        assertEquals(PayoutExecutionStatus.CAPTURED, resBResult.currentStatus)

        // Delayed Callback 1 arrives later -> stale sequence dropped safely
        val cmdBSeq1 = buildCallbackCommand(payoutB.payoutId, "IN_FLIGHT", deliverySequence = 1L)
        assertFailsWith<StaleCallbackSequenceException> {
            service.processCallback(cmdBSeq1)
        }

        // State remains CAPTURED, no regression
        val payoutBRecord = payoutStore.findById(tenantId, payoutB.payoutId)
        assertEquals(PayoutExecutionStatus.CAPTURED, payoutBRecord?.status)
    }

    // =========================================================================
    // WITHDRAW-003-02-T004 — Remains compatible, recoverable, observable, and lifecycle-safe
    // =========================================================================
    @Test
    fun `WITHDRAW-003-02-T004 — Authenticate and reduce payout callbacks remains compatible, recoverable, observable, and lifecycle-safe`() {
        val wallet = setupWallet(playerAId, 100_000L, 50_000L)
        val res = setupReservation(playerAId, wallet.walletId, 50_000L)
        val payout = setupPayout(playerAId, wallet.walletId, res.reservationId, 50_000L)

        // 1. Process valid callback
        val cmd = buildCallbackCommand(payout.payoutId, "COMPLETED", deliverySequence = 1L)
        val result = service.processCallback(cmd)

        // 2. Simulated restart / recreation of service from stores
        val restartedService = PayoutCallbackReductionService(
            callbackStore = callbackStore,
            payoutStore = payoutStore,
            reservationStore = reservationStore,
            bucketStore = bucketStore,
            secretResolver = secretResolver,
            observability = observability,
            clock = clock
        )

        // State is recovered without mutation or history editing
        val recoveredPayout = payoutStore.findById(tenantId, payout.payoutId)
        assertNotNull(recoveredPayout)
        assertEquals(PayoutExecutionStatus.CAPTURED, recoveredPayout.status)
        assertEquals(result.currentStatus, recoveredPayout.status)

        // Replay through restarted service returns duplicate accepted
        val duplicateResult = restartedService.processCallback(cmd)
        assertEquals(PayoutExecutionStatus.CAPTURED, duplicateResult.currentStatus)

        // 3. Observability checks: redacted, structured metrics recorded
        val metrics = observability.getMetrics()
        assertTrue(metrics.isNotEmpty())
        assertTrue(metrics.any { it.eventType == "accept" })
        assertTrue(metrics.any { it.eventType == "duplicate" })

        // Check that secrets are NEVER leaked in metric event details or fields
        metrics.forEach { event ->
            assertFalse(event.details.toString().contains(providerSecret))
            assertFalse(event.details.toString().contains("secret-super-safe"))
            assertNotNull(event.correlationId)
            assertNotNull(event.causationId)
        }

        // 4. Android lifecycle & DB checks
        assertFalse(result.hasAndroidDbImpact)
        assertFalse(result.hasAndroidLifecycleClaim)
    }
}
