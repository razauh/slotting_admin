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

class AmlRiskHoldTest {
    private val now = Instant.parse("2026-09-20T20:15:00Z")
    private val clock = Clock.fixed(now, ZoneOffset.UTC)

    private val playerAId = UUID.randomUUID()
    private val playerBId = UUID.randomUUID()

    private val playerAPrincipal = AuthenticatedPrincipal(
        id = playerAId.toString(),
        tenantId = "tenant-aml-prod",
        kind = PrincipalKind.PLAYER,
        roles = emptySet()
    )

    private val playerBPrincipal = AuthenticatedPrincipal(
        id = playerBId.toString(),
        tenantId = "tenant-aml-prod",
        kind = PrincipalKind.PLAYER,
        roles = emptySet()
    )

    private val complianceOfficerPrincipal = AuthenticatedPrincipal(
        id = "compliance-officer-007",
        tenantId = "tenant-aml-prod",
        kind = PrincipalKind.ADMIN,
        roles = setOf(AdminRole.AUDITOR, AdminRole.SUPER_ADMIN)
    )

    private val foreignCompliancePrincipal = AuthenticatedPrincipal(
        id = "foreign-compliance-99",
        tenantId = "tenant-foreign-aml",
        kind = PrincipalKind.ADMIN,
        roles = setOf(AdminRole.SUPER_ADMIN)
    )

    private lateinit var holdStore: InMemoryAmlRiskHoldStore
    private lateinit var reservationStore: InMemoryWithdrawalReservationStore
    private lateinit var bucketStore: InMemoryBalanceBucketsStore
    private lateinit var observability: InMemoryAmlRiskHoldObservability
    private lateinit var service: AmlRiskHoldService

    @BeforeEach
    fun setUp() {
        AmlRiskHoldBinding.isBound = true
        holdStore = InMemoryAmlRiskHoldStore()
        reservationStore = InMemoryWithdrawalReservationStore()
        bucketStore = InMemoryBalanceBucketsStore()
        observability = InMemoryAmlRiskHoldObservability()
        service = AmlRiskHoldService(
            holdStore = holdStore,
            reservationStore = reservationStore,
            bucketStore = bucketStore,
            clock = clock,
            observability = observability
        )
    }

    @AfterEach
    fun tearDown() {
        AmlRiskHoldBinding.isBound = true
    }

    private fun setupWallet(ownerId: UUID, cashAvailable: Long = 400_000L, pendingWithdrawal: Long = 100_000L): WalletBalanceBucketsRecord {
        val wallet = WalletBalanceBucketsRecord(
            walletId = UUID.randomUUID(),
            tenantId = "tenant-aml-prod",
            ownerId = ownerId,
            currencyCode = "EUR",
            cash = CashBuckets(
                availableMinorUnits = cashAvailable,
                lockedMinorUnits = 0L,
                pendingWithdrawalMinorUnits = pendingWithdrawal
            ),
            bonus = BonusBuckets(activeMinorUnits = 0L, lockedMinorUnits = 0L, pendingMinorUnits = 0L),
            version = 2L,
            createdAt = now.minusSeconds(7200),
            updatedAt = now.minusSeconds(1800)
        )
        bucketStore.saveWallet(wallet)
        return wallet
    }

    private fun setupReservation(
        ownerId: UUID,
        walletId: UUID,
        grossAmount: Long = 100_000L,
        state: WithdrawalReservationState = WithdrawalReservationState.RESERVED
    ): WithdrawalReservationRecord {
        val reservationId = UUID.randomUUID()
        val record = WithdrawalReservationRecord(
            reservationId = reservationId,
            tenantId = "tenant-aml-prod",
            ownerId = ownerId,
            walletId = walletId,
            requestId = UUID.randomUUID(),
            currencyCode = "EUR",
            grossAmountMinorUnits = grossAmount,
            state = state,
            releaseReason = null,
            reservedAt = now.minusSeconds(1800),
            expiresAt = now.plusSeconds(84600),
            releasedAt = null,
            idempotencyKey = "idemp-res-${UUID.randomUUID()}",
            correlationId = "corr-res",
            causationId = "caus-res",
            evidenceReference = "EVID-RES-TEST",
            version = 1L
        )
        reservationStore.save(record)
        return record
    }

    // =========================================================================
    // WITHDRAW-002-02-T001: Authoritative Outcome Verification
    // =========================================================================

    @Test
    fun `WITHDRAW-002-02-T001 Apply AML risk hold produces the required authoritative outcome`() {
        AmlRiskHoldBinding.checkBound()

        // 1. Semantic contract assertion
        assertEquals(
            "One request locks exact funds; rejection/cancel release policy explicit/audited.",
            AML_RISK_HOLD_CONTRACT
        )

        val wallet = setupWallet(playerAId, cashAvailable = 400_000L, pendingWithdrawal = 100_000L)
        val reservation = setupReservation(playerAId, wallet.walletId, grossAmount = 100_000L)

        // 2. Apply AML Risk Hold
        val applyCmd = ApplyAmlRiskHoldCommand(
            principal = complianceOfficerPrincipal,
            tenantId = "tenant-aml-prod",
            ownerId = playerAId,
            reservationId = reservation.reservationId,
            reason = AmlHoldReason.LARGE_TRANSACTION_STRUCTURING,
            riskScore = 88,
            breachedRules = listOf("VELOCITY_THRESHOLD_BREACH", "STRUCTURING_RULE_900K"),
            idempotencyKey = "idemp-aml-hold-001",
            correlationId = "corr-aml-001",
            causationId = "caus-aml-001"
        )
        val applyResult = service.applyRiskHold(applyCmd)

        val hold = applyResult.hold
        assertNotNull(hold.holdId)
        assertEquals(reservation.reservationId, hold.reservationId)
        assertEquals(AmlHoldStatus.ACTIVE, hold.status)
        assertEquals(AmlHoldReason.LARGE_TRANSACTION_STRUCTURING, hold.reason)
        assertEquals(88, hold.riskScore)
        assertEquals(now, hold.heldAt)
        assertNull(hold.clearedAt)
        assertNull(hold.rejectedAt)

        // Reservation transitioned to ON_HOLD
        val updatedRes = applyResult.reservation
        assertEquals(WithdrawalReservationState.ON_HOLD, updatedRes.state)

        // Funds remain locked (exact funds locked, total cash conserved)
        val balance = applyResult.walletBalance
        assertEquals(400_000L, balance.cash.availableMinorUnits)
        assertEquals(100_000L, balance.cash.pendingWithdrawalMinorUnits)
        assertEquals(500_000L, balance.cash.totalCashMinorUnits)
        assertTrue(applyResult.debitsEqualCredits)
        assertFalse(applyResult.hasAndroidDbImpact)
        assertFalse(applyResult.hasAndroidLifecycleClaim)
        assertEquals("WITHDRAWAL_AML_HOLD_APPLIED", applyResult.auditEvent.type)

        // 3. Clear AML Risk Hold (Compliance Clearance)
        val clearCmd = ClearAmlRiskHoldCommand(
            principal = complianceOfficerPrincipal,
            tenantId = "tenant-aml-prod",
            holdId = hold.holdId,
            justification = "Player provided verified source of wealth documentation; SAR cleared",
            idempotencyKey = "idemp-aml-clear-001",
            correlationId = "corr-aml-002",
            causationId = "caus-aml-002"
        )
        val clearResult = service.clearRiskHold(clearCmd)

        val clearedHold = clearResult.hold
        assertEquals(AmlHoldStatus.CLEARED, clearedHold.status)
        assertEquals(now, clearedHold.clearedAt)
        assertEquals("compliance-officer-007", clearedHold.complianceOfficerId)
        assertEquals(2L, clearedHold.version)

        // Reservation restored to RESERVED (eligible for maker-checker approval)
        val clearedRes = clearResult.reservation
        assertEquals(WithdrawalReservationState.RESERVED, clearedRes.state)
        assertEquals("WITHDRAWAL_AML_HOLD_CLEARED", clearResult.auditEvent.type)

        // 4. Reject AML Risk Hold with Explicit Rejection Release Policy
        val wallet2 = setupWallet(playerBId, cashAvailable = 300_000L, pendingWithdrawal = 200_000L)
        val reservation2 = setupReservation(playerBId, wallet2.walletId, grossAmount = 200_000L)
        val hold2Result = service.applyRiskHold(
            ApplyAmlRiskHoldCommand(
                principal = complianceOfficerPrincipal,
                tenantId = "tenant-aml-prod",
                ownerId = playerBId,
                reservationId = reservation2.reservationId,
                reason = AmlHoldReason.SANCTIONS_PEP_MATCH,
                riskScore = 99,
                breachedRules = listOf("OFAC_SDN_LIST_MATCH"),
                idempotencyKey = "idemp-aml-hold-002",
                correlationId = "corr-aml-003",
                causationId = "caus-aml-003"
            )
        )

        val rejectCmd = RejectAmlRiskHoldCommand(
            principal = complianceOfficerPrincipal,
            tenantId = "tenant-aml-prod",
            holdId = hold2Result.hold.holdId,
            reason = "Sanctions match confirmed; payout rejected and funds refunded to wallet account",
            releaseFundsBackToWallet = true,
            idempotencyKey = "idemp-aml-reject-001",
            correlationId = "corr-aml-004",
            causationId = "caus-aml-004"
        )
        val rejectResult = service.rejectRiskHold(rejectCmd)

        val rejectedHold = rejectResult.hold
        assertEquals(AmlHoldStatus.REJECTED, rejectedHold.status)
        assertEquals(now, rejectedHold.rejectedAt)

        // Explicit release policy verified: reservation is RELEASED and funds restored
        val releasedRes = rejectResult.reservation
        assertEquals(WithdrawalReservationState.RELEASED, releasedRes.state)
        assertEquals(WithdrawalReleaseReason.AML_REJECTED, releasedRes.releaseReason)

        val releasedWallet = rejectResult.walletBalance
        assertEquals(500_000L, releasedWallet.cash.availableMinorUnits)
        assertEquals(0L, releasedWallet.cash.pendingWithdrawalMinorUnits)
        assertEquals(500_000L, releasedWallet.cash.totalCashMinorUnits)
        assertEquals("WITHDRAWAL_AML_HOLD_REJECTED_RELEASED", rejectResult.auditEvent.type)
    }

    // =========================================================================
    // WITHDRAW-002-02-T002: Rejection of Invalid, Boundary, Unauthorized, and Stale Input
    // =========================================================================

    @Test
    fun `WITHDRAW-002-02-T002 Apply AML risk hold rejects invalid, boundary, unauthorized, and stale input`() {
        AmlRiskHoldBinding.checkBound()

        val wallet = setupWallet(playerAId, cashAvailable = 400_000L, pendingWithdrawal = 100_000L)
        val reservation = setupReservation(playerAId, wallet.walletId, grossAmount = 100_000L)

        // 1. Unauthenticated request
        assertFailsWith<UnauthorizedWithdrawalAccessException> {
            service.applyRiskHold(
                ApplyAmlRiskHoldCommand(
                    principal = null,
                    tenantId = "tenant-aml-prod",
                    ownerId = playerAId,
                    reservationId = reservation.reservationId,
                    reason = AmlHoldReason.SUSPICIOUS_VELOCITY,
                    riskScore = 75,
                    breachedRules = listOf("RULE_VELOCITY"),
                    idempotencyKey = "k1",
                    correlationId = "c1",
                    causationId = "c2"
                )
            )
        }

        // 2. Cross-tenant request
        assertFailsWith<CrossTenantWithdrawalAccessException> {
            service.applyRiskHold(
                ApplyAmlRiskHoldCommand(
                    principal = foreignCompliancePrincipal,
                    tenantId = "tenant-aml-prod",
                    ownerId = playerAId,
                    reservationId = reservation.reservationId,
                    reason = AmlHoldReason.SUSPICIOUS_VELOCITY,
                    riskScore = 75,
                    breachedRules = listOf("RULE_VELOCITY"),
                    idempotencyKey = "k2",
                    correlationId = "c1",
                    causationId = "c2"
                )
            )
        }

        // 3. Player attempting compliance action (apply hold) -> Forbidden
        val playerEx = assertFailsWith<UnauthorizedComplianceAccessException> {
            service.applyRiskHold(
                ApplyAmlRiskHoldCommand(
                    principal = playerAPrincipal,
                    tenantId = "tenant-aml-prod",
                    ownerId = playerAId,
                    reservationId = reservation.reservationId,
                    reason = AmlHoldReason.SUSPICIOUS_VELOCITY,
                    riskScore = 75,
                    breachedRules = listOf("RULE_VELOCITY"),
                    idempotencyKey = "k3",
                    correlationId = "c1",
                    causationId = "c2"
                )
            )
        }
        assertTrue(playerEx.message!!.contains("payout without lock/approval"))

        // 4. Non-existent reservation ID
        val missingResEx = assertFailsWith<WithdrawalReservationNotFoundException> {
            service.applyRiskHold(
                ApplyAmlRiskHoldCommand(
                    principal = complianceOfficerPrincipal,
                    tenantId = "tenant-aml-prod",
                    ownerId = playerAId,
                    reservationId = UUID.randomUUID(),
                    reason = AmlHoldReason.SUSPICIOUS_VELOCITY,
                    riskScore = 75,
                    breachedRules = listOf("RULE_VELOCITY"),
                    idempotencyKey = "k4",
                    correlationId = "c1",
                    causationId = "c2"
                )
            )
        }
        assertTrue(missingResEx.message!!.contains("payout without lock/approval"))

        // 5. Apply hold on reservation that is already RELEASED
        val releasedRes = setupReservation(playerAId, wallet.walletId, state = WithdrawalReservationState.RELEASED)
        val conflictEx = assertFailsWith<AmlHoldConflictException> {
            service.applyRiskHold(
                ApplyAmlRiskHoldCommand(
                    principal = complianceOfficerPrincipal,
                    tenantId = "tenant-aml-prod",
                    ownerId = playerAId,
                    reservationId = releasedRes.reservationId,
                    reason = AmlHoldReason.SUSPICIOUS_VELOCITY,
                    riskScore = 75,
                    breachedRules = listOf("RULE_VELOCITY"),
                    idempotencyKey = "k5",
                    correlationId = "c1",
                    causationId = "c2"
                )
            )
        }
        assertTrue(conflictEx.message!!.contains("payout without lock/approval"))

        // 6. Player attempting to clear compliance hold -> Forbidden
        val holdResult = service.applyRiskHold(
            ApplyAmlRiskHoldCommand(
                principal = complianceOfficerPrincipal,
                tenantId = "tenant-aml-prod",
                ownerId = playerAId,
                reservationId = reservation.reservationId,
                reason = AmlHoldReason.SUSPICIOUS_VELOCITY,
                riskScore = 75,
                breachedRules = listOf("RULE_VELOCITY"),
                idempotencyKey = "k6",
                correlationId = "c1",
                causationId = "c2"
            )
        )
        val playerClearEx = assertFailsWith<UnauthorizedComplianceAccessException> {
            service.clearRiskHold(
                ClearAmlRiskHoldCommand(
                    principal = playerAPrincipal,
                    tenantId = "tenant-aml-prod",
                    holdId = holdResult.hold.holdId,
                    justification = "Player claims everything is fine",
                    idempotencyKey = "k7",
                    correlationId = "c1",
                    causationId = "c2"
                )
            )
        }
        assertTrue(playerClearEx.message!!.contains("payout without lock/approval"))

        // 7. Non-existent hold ID on clear
        val missingHoldEx = assertFailsWith<AmlHoldNotFoundException> {
            service.clearRiskHold(
                ClearAmlRiskHoldCommand(
                    principal = complianceOfficerPrincipal,
                    tenantId = "tenant-aml-prod",
                    holdId = UUID.randomUUID(),
                    justification = "Clear non-existent",
                    idempotencyKey = "k8",
                    correlationId = "c1",
                    causationId = "c2"
                )
            )
        }
        assertTrue(missingHoldEx.message!!.contains("payout without lock/approval"))
    }

    // =========================================================================
    // WITHDRAW-002-02-T003: Concurrency, Duplicate Delivery, and Idempotency
    // =========================================================================

    @Test
    fun `WITHDRAW-002-02-T003 Apply AML risk hold survives concurrency, duplicate delivery, and dependency failure`() {
        AmlRiskHoldBinding.checkBound()

        val wallet = setupWallet(playerAId, cashAvailable = 400_000L, pendingWithdrawal = 100_000L)
        val reservation = setupReservation(playerAId, wallet.walletId, grossAmount = 100_000L)

        // 1. Idempotency exact replay
        val cmd = ApplyAmlRiskHoldCommand(
            principal = complianceOfficerPrincipal,
            tenantId = "tenant-aml-prod",
            ownerId = playerAId,
            reservationId = reservation.reservationId,
            reason = AmlHoldReason.FRAUD_SIGNAL_DETECTED,
            riskScore = 80,
            breachedRules = listOf("DEVICE_SPOOF_SIGNAL"),
            idempotencyKey = "idemp-exact-replay-001",
            correlationId = "c1",
            causationId = "c2"
        )
        val firstResult = service.applyRiskHold(cmd)
        val duplicateResult = service.applyRiskHold(cmd)

        assertEquals(firstResult.hold.holdId, duplicateResult.hold.holdId)
        assertEquals(firstResult.resultId, duplicateResult.resultId)
        assertEquals(firstResult.serverTime, duplicateResult.serverTime)

        // 2. Idempotency conflict with altered payload
        val conflictingCmd = cmd.copy(riskScore = 95)
        val conflictEx = assertFailsWith<IdempotencyConflictException> {
            service.applyRiskHold(conflictingCmd)
        }
        assertTrue(conflictEx.message!!.contains("payout without lock/approval"))

        // 3. Multi-threaded race condition protection
        val wallet2 = setupWallet(playerBId, cashAvailable = 200_000L, pendingWithdrawal = 100_000L)
        val reservation2 = setupReservation(playerBId, wallet2.walletId, grossAmount = 100_000L)

        val executor = Executors.newFixedThreadPool(2)
        val task1 = Callable {
            runCatching {
                service.applyRiskHold(
                    ApplyAmlRiskHoldCommand(
                        principal = complianceOfficerPrincipal,
                        tenantId = "tenant-aml-prod",
                        ownerId = playerBId,
                        reservationId = reservation2.reservationId,
                        reason = AmlHoldReason.FRAUD_SIGNAL_DETECTED,
                        riskScore = 80,
                        breachedRules = listOf("SIGNAL_1"),
                        idempotencyKey = "race-aml-1",
                        correlationId = "c1",
                        causationId = "c2"
                    )
                )
            }
        }
        val task2 = Callable {
            runCatching {
                service.applyRiskHold(
                    ApplyAmlRiskHoldCommand(
                        principal = complianceOfficerPrincipal,
                        tenantId = "tenant-aml-prod",
                        ownerId = playerBId,
                        reservationId = reservation2.reservationId,
                        reason = AmlHoldReason.FRAUD_SIGNAL_DETECTED,
                        riskScore = 80,
                        breachedRules = listOf("SIGNAL_2"),
                        idempotencyKey = "race-aml-2",
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

        assertEquals(1, successes.size, "Exactly one AML hold can be successfully applied to the reservation")
        assertEquals(1, failures.size, "The competing hold application must be rejected due to state conflict")
        assertTrue(failures[0].exceptionOrNull() is AmlHoldConflictException)
    }

    // =========================================================================
    // WITHDRAW-002-02-T004: Compatibility, Recovery, Observability, and Lifecycle
    // =========================================================================

    @Test
    fun `WITHDRAW-002-02-T004 Apply AML risk hold remains compatible, recoverable, observable, and lifecycle-safe`() {
        AmlRiskHoldBinding.checkBound()

        val wallet = setupWallet(playerAId, cashAvailable = 400_000L, pendingWithdrawal = 100_000L)
        val reservation = setupReservation(playerAId, wallet.walletId, grossAmount = 100_000L)

        // 1. Observability events emitted
        val cmd = ApplyAmlRiskHoldCommand(
            principal = complianceOfficerPrincipal,
            tenantId = "tenant-aml-prod",
            ownerId = playerAId,
            reservationId = reservation.reservationId,
            reason = AmlHoldReason.COMPLIANCE_MANUAL_HOLD,
            riskScore = 70,
            breachedRules = listOf("MANUAL_AUDIT_REQUIRED"),
            idempotencyKey = "idemp-obs-aml-001",
            correlationId = "corr-obs-aml-001",
            causationId = "caus-obs-aml-001"
        )
        val result = service.applyRiskHold(cmd)

        val metrics = observability.getMetrics()
        assertTrue(metrics.any { it.eventType == "attempt" && it.correlationId == "corr-obs-aml-001" })
        assertTrue(metrics.any { it.eventType == "accept" && it.correlationId == "corr-obs-aml-001" })

        // 2. Recovery across service restart with same stores
        val recoveredService = AmlRiskHoldService(
            holdStore = holdStore,
            reservationStore = reservationStore,
            bucketStore = bucketStore,
            clock = clock,
            observability = observability
        )
        val queried = recoveredService.getRiskHold(
            GetAmlRiskHoldQuery(
                principal = complianceOfficerPrincipal,
                tenantId = "tenant-aml-prod",
                holdId = result.hold.holdId
            )
        )
        assertEquals(result.hold.holdId, queried.holdId)
        assertEquals(AmlHoldStatus.ACTIVE, queried.status)

        // 3. No Android database impact or lifecycle claims
        assertFalse(result.hasAndroidDbImpact)
        assertFalse(result.hasAndroidLifecycleClaim)
    }
}
